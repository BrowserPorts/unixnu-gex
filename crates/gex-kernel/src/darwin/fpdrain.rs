//! A descriptor's calls and its close: the I/O reference a call holds on
//! the fileproc it looked up (`fp_iocount`), and a close's drain of them
//! (`fp_close_and_unlock` and `fileproc_drain`, `kern_descrip.c`).
//!
//! A call holds its reference from its lookup to its `fp_drop`. Only one
//! that sleeps can be in its descriptor while another thread closes it,
//! since every other call runs to its end with the kernel locked; so a
//! thread notes the fileprocs of its call as it blocks, and lets them go
//! when the call returns.
//!
//! A close of a descriptor another thread is in a call on takes it out of
//! the table with its number held (`UF_RESERVED`), drops its knotes
//! (`knote_fdclose`), and drains it: its type's `fo_drain` wakes the
//! call, and the close sleeps until the calls have left. Then the number
//! is free again (`fdrelse`) and the file is let go (`fg_drop`).
//!
//! A call the drain wakes in the host (a stream's read or write, a
//! socket's accept) is marked with what the drain makes of it
//! ([`Drained`]) and ended as a signal ends a wait; its result is then
//! the drain's. A `select` asleep in the kernel is woken there.

use super::procinfo::dtype;
use super::sysno as sys;
use super::thread::Finish;
use super::wait::{Wait, WaitResult};
use crate::file::OpenFile;
use crate::syscalls::{Kernel, SyscallOutcome};
use crate::GuestMem;
use std::sync::Arc;

/// The calls whose first argument is the descriptor they hold.
const ON_FD: &[u64] = &[
    sys::READ, sys::READ_NOCANCEL, sys::READV, sys::READV_NOCANCEL, sys::PREAD, sys::PREAD_NOCANCEL,
    sys::WRITE, sys::WRITE_NOCANCEL, sys::WRITEV, sys::WRITEV_NOCANCEL, sys::PWRITE, sys::PWRITE_NOCANCEL,
    sys::GUARDED_WRITE_NP, sys::GUARDED_PWRITE_NP, sys::GUARDED_WRITEV_NP,
    sys::RECVFROM, sys::RECVFROM_NOCANCEL, sys::RECVMSG, sys::RECVMSG_NOCANCEL,
    sys::SENDTO, sys::SENDTO_NOCANCEL, sys::SENDMSG, sys::SENDMSG_NOCANCEL,
    sys::ACCEPT, sys::ACCEPT_NOCANCEL, sys::CONNECT, sys::CONNECT_NOCANCEL,
    sys::FCNTL, sys::FCNTL_NOCANCEL, sys::FLOCK, sys::IOCTL, sys::KEVENT, sys::KEVENT64, sys::KEVENT_QOS,
];

/// `KEVENT_FLAG_WORKQ`: a kevent call on the process's workqueue kqueue,
/// which no descriptor names.
const KEVENT_FLAG_WORKQ: u64 = 0x020;

/// The calls `select` makes its scan in, which mark each descriptor of
/// their sets `FP_INSELECT`.
const SELECTS: &[u64] = &[sys::SELECT, sys::SELECT_NOCANCEL, sys::PSELECT, sys::PSELECT_NOCANCEL];

/// What a drain makes of a call it wakes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drained {
    /// A pipe read with nothing to read (`pipe_read`'s break on
    /// `FPV_DRAIN`): 0.
    Eof,
    /// A pipe write (`pipe_write`'s `FPV_DRAIN`): EPIPE.
    Epipe,
    /// A socket's `sbwait` (`SS_DRAINING`), and a `select`, whose scan
    /// after the wakeup finds the descriptor gone: EBADF.
    Ebadf,
    /// `accept`'s and `connect`'s sleep on `so_timeo` (`SS_DRAINING`):
    /// ECONNABORTED.
    Econnaborted,
}

impl Drained {
    /// The call's result.
    pub fn result(self) -> crate::errno::SysResult {
        match self {
            Drained::Eof => Ok(0),
            Drained::Epipe => Err(crate::errno::Errno::EPIPE),
            Drained::Ebadf => Err(crate::errno::Errno::EBADF),
            Drained::Econnaborted => Err(crate::errno::Errno::ECONNABORTED),
        }
    }
}

/// The calls that write (a pipe's drain is EPIPE for them).
const WRITES: &[u64] = &[
    sys::WRITE, sys::WRITE_NOCANCEL, sys::WRITEV, sys::WRITEV_NOCANCEL, sys::PWRITE, sys::PWRITE_NOCANCEL,
    sys::GUARDED_WRITE_NP, sys::GUARDED_PWRITE_NP, sys::GUARDED_WRITEV_NP,
    sys::SENDTO, sys::SENDTO_NOCANCEL, sys::SENDMSG, sys::SENDMSG_NOCANCEL,
];

/// The calls that wait in a socket's buffers (`sbwait`): its reads and
/// writes.
fn sbwaits(code: u64) -> bool {
    WRITES.contains(&code)
        || [sys::READ, sys::READ_NOCANCEL, sys::READV, sys::READV_NOCANCEL, sys::RECVFROM, sys::RECVFROM_NOCANCEL, sys::RECVMSG, sys::RECVMSG_NOCANCEL].contains(&code)
}

/// A close draining its descriptor: the number it holds back and the file
/// it holds until `fg_drop`.
#[derive(Debug)]
pub struct Closing {
    pub fd: i32,
    pub file: Arc<OpenFile>,
}

/// What names a fileproc: its descriptor, and the file the descriptor
/// named when the call looked it up.
fn key(fd: i32, file: &Arc<OpenFile>) -> (i32, usize) {
    (fd, Arc::as_ptr(file) as usize)
}

impl Kernel {
    /// The calling thread blocks in its call: the fileprocs it holds I/O
    /// references on (`fp_lookup`'s, `select`'s), noted the first time.
    pub(crate) fn darwin_fp_enter(&mut self, m: &mut GuestMem<'_>) {
        if !self.darwin_me().fp_call.is_empty() {
            return;
        }
        let code = self.darwin_uu_syscall_code();
        let a = self.darwin_me().syscall_args;
        let fds: Vec<i32> = if ON_FD.contains(&code) {
            let workq = match code {
                sys::KEVENT64 => a[5] & KEVENT_FLAG_WORKQ != 0,
                // kevent_qos's flags are its eighth argument.
                sys::KEVENT_QOS => {
                    let at = self.ctx_addr + gex_abi::ctx::x(self.darwin_arg_base + 7) as u64;
                    m.read_u64(at).unwrap_or(0) & KEVENT_FLAG_WORKQ != 0
                }
                _ => false,
            };
            if workq {
                return;
            }
            vec![a[0] as i32]
        } else if SELECTS.contains(&code) {
            select_fds(m, &a)
        } else {
            return;
        };
        let files: Vec<(i32, Arc<OpenFile>)> = fds.into_iter().filter_map(|fd| self.fds.get(fd).ok().map(|f| (fd, f))).collect();
        // sbwait on a socket already draining fails at once (EBADF); a
        // call with data or room has not come to it.
        if sbwaits(code) && files.iter().any(|(_, f)| f.darwin_so_draining.load(std::sync::atomic::Ordering::Acquire)) {
            self.darwin_me().fp_drained = Some(Drained::Ebadf);
        }
        self.darwin_me().fp_call = files.iter().map(|(fd, f)| key(*fd, f)).collect();
    }

    /// The result a drain gives the calling thread's call, which the host
    /// ended as a signal does (`r` EINTR), the drain's mark taken. A call
    /// asleep in the kernel takes its mark where its wait ends.
    pub(crate) fn darwin_fp_drained_result(&mut self, r: crate::errno::SysResult) -> crate::errno::SysResult {
        if r != Err(crate::errno::Errno::EINTR) || self.darwin_finish.is_some() {
            return r;
        }
        match self.darwin_me().fp_drained.take() {
            Some(d) => d.result(),
            None => r,
        }
    }

    /// Whether thread `tid`'s call, waiting in the host, has been drained
    /// (which ends its wait as a pending signal would).
    pub(crate) fn darwin_fp_drained(&self, tid: i32) -> bool {
        !self.dtask.waits.waiting(tid) && self.dtask.threads.map.get(&tid).is_some_and(|t| t.fp_drained.is_some())
    }

    /// Mark thread `tid`'s call with what the drain makes of it, and wake
    /// it: one asleep in the kernel by its wait queue, one in the host by
    /// the readiness wake that has it look at its signals.
    fn darwin_fp_mark(&mut self, m: &mut GuestMem<'_>, tid: i32, d: Drained) {
        if let Some(t) = self.dtask.threads.map.get_mut(&tid) {
            t.fp_drained = Some(d);
        }
        if self.dtask.waits.waiting(tid) {
            self.darwin_wake(m, tid, WaitResult::Interrupted);
        }
        self.fd_activity = true;
    }

    /// The threads other than the caller in a call holding fileproc `k`
    /// (or, `any_fd`, any descriptor of the file `k` names), with their
    /// calls.
    fn darwin_fp_holders(&self, k: (i32, usize), any_fd: bool) -> Vec<(i32, u64)> {
        let me = self.tid;
        self.dtask
            .threads
            .map
            .iter()
            .filter(|(&tid, t)| tid != me && t.fp_call.iter().any(|&h| h == k || (any_fd && h.1 == k.1)))
            .map(|(&tid, t)| (tid, t.syscall_code))
            .collect()
    }

    /// The calling thread's call has returned (`fp_drop`): a close waiting
    /// for the calls in one of its fileprocs to leave looks again.
    pub(crate) fn darwin_fp_leave(&mut self, m: &mut GuestMem<'_>) {
        self.darwin_me().fp_drained = None;
        let held = std::mem::take(&mut self.darwin_me().fp_call);
        if held.is_empty() {
            return;
        }
        let closers: Vec<i32> = self
            .dtask
            .threads
            .map
            .iter()
            .filter(|(_, t)| t.fp_closing.as_ref().is_some_and(|c| held.contains(&key(c.fd, &c.file))))
            .map(|(&tid, _)| tid)
            .collect();
        for tid in closers {
            self.darwin_wake(m, tid, WaitResult::Awakened);
        }
    }

    /// How many threads other than the caller are in a call on fileproc
    /// `k` (its `fp_iocount` less the caller's own).
    fn darwin_fp_callers(&self, k: (i32, usize)) -> usize {
        let me = self.tid;
        self.dtask.threads.map.iter().filter(|(&tid, t)| tid != me && t.fp_call.contains(&k)).count()
    }

    /// Whether another thread is in a call on descriptor `fd` (its
    /// fileproc's `fp_iocount` above one). A terminal's descriptor is not
    /// asked: its close drains its vnode ([`super::tty`]).
    pub(crate) fn darwin_fp_busy(&mut self, fd: i32) -> bool {
        let Ok(file) = self.fds.get(fd) else { return false };
        if self.darwin_tty_of(fd as u64).is_some() {
            return false;
        }
        self.darwin_fp_callers(key(fd, &file)) > 0
    }

    /// `close` of descriptor `fd`, which another thread is in a call on:
    /// `fp_close_and_unlock`'s `knote_fdclose` and `fileproc_drain`, then
    /// (once the calls have left) its `fdrelse` and `fg_drop`. None where
    /// the drain of the file's type is not done here: reported, and the
    /// close made as one without a drain.
    pub(crate) fn darwin_close_drain(&mut self, m: &mut GuestMem<'_>, fd: i32) -> Option<SyscallOutcome> {
        let file = self.fds.get(fd).ok()?;
        let k = key(fd, &file);
        let ty = super::procinfo::fdtype(&file);
        let last = file.fg_count() == 1;
        // UF_RESERVED|UF_CLOSING: lookups of it fail, its number is kept;
        // the fileproc's hold on the file stays until fg_drop.
        file.fg_retain();
        if self.fds.close_reserving(fd).is_err() {
            file.fg_drop();
            return None;
        }
        self.darwin_knote_fdclose(fd);
        // FPV_DRAIN, then fo_drain as the file's type has it.
        let pipe = file.handle.pipe_end().filter(|(p, _)| p.is_xnu());
        for (tid, code) in self.darwin_fp_holders(k, ty == dtype::SOCKET) {
            // A select's wakeup (FP_INSELECT): its scan finds the
            // descriptor gone.
            if SELECTS.contains(&code) {
                self.darwin_fp_mark(m, tid, Drained::Ebadf);
                continue;
            }
            let d = match ty {
                // pipe_drain of its last descriptor drains the pipe itself,
                // which ends the call; else FPV_DRAIN ends the call in this
                // descriptor.
                dtype::PIPE if pipe.is_some() && last => None,
                dtype::PIPE => Some(if WRITES.contains(&code) { Drained::Epipe } else { Drained::Eof }),
                // soo_drain: SS_DRAINING, every sleeper on the socket woken.
                dtype::SOCKET if [sys::ACCEPT, sys::ACCEPT_NOCANCEL, sys::CONNECT, sys::CONNECT_NOCANCEL].contains(&code) => Some(Drained::Econnaborted),
                dtype::SOCKET if sbwaits(code) => Some(Drained::Ebadf),
                dtype::SOCKET => {
                    self.darwin_unimplemented(format!("close of descriptor {fd}, a socket, while another thread is in call {code} on it (soo_drain's wakeup of it)"));
                    None
                }
                // kqueue_drain, below, wakes the kqueue's kevent calls.
                dtype::KQUEUE => None,
                // fo_no_drain: nothing wakes the call; the close waits.
                _ => None,
            };
            if let Some(d) = d {
                self.darwin_fp_mark(m, tid, d);
            }
        }
        if ty == dtype::SOCKET {
            file.darwin_so_draining.store(true, std::sync::atomic::Ordering::Release);
        }
        // kqueue_drain: KQ_DRAIN, its kevent calls woken to fail (EBADF).
        if ty == dtype::KQUEUE {
            self.darwin_kqueue_drain(m, &file);
        }
        if let (Some((p, write)), true) = (&pipe, last) {
            p.drain(*write);
        }
        self.darwin_me().fp_closing = Some(Closing { fd, file });
        Some(self.darwin_fpdrain_wait(m))
    }

    /// fileproc_drain's loop: while a call is in the fileproc, its
    /// `fo_drain` again and a sleep (`msleep(&fd_fpdrainwait, PRIBIO)`,
    /// which no signal ends) until a call's `fp_drop` wakes it; then the
    /// close's end.
    fn darwin_fpdrain_wait(&mut self, m: &mut GuestMem<'_>) -> SyscallOutcome {
        let Some(c) = self.darwin_me().fp_closing.as_ref() else { return SyscallOutcome::Continue };
        let (fd, file) = (c.fd, Arc::clone(&c.file));
        if self.darwin_fp_callers(key(fd, &file)) > 0 {
            // pipe_drain again: the close's hold is the fileproc's, so a
            // count of one is still its last descriptor's.
            if let Some((p, write)) = file.handle.pipe_end().filter(|(p, _)| p.is_xnu() && file.fg_count() == 1) {
                p.drain(write);
            }
            // kqueue_drain again, as each pass of the loop has it.
            if super::procinfo::fdtype(&file) == dtype::KQUEUE {
                self.darwin_kqueue_drain(m, &file);
            }
            return self.darwin_block(m, Wait { deadline: None, cont: Finish::FpDrain });
        }
        // fdrelse, then fg_drop: closef_locked's release of the process's
        // POSIX locks on the file, and the file's own close with its last
        // hold.
        let c = self.darwin_me().fp_closing.take().expect("taken above");
        self.fds.release_reserved(c.fd);
        // procfdtbl_releasefd's wakeup of a dup2 waiting for it.
        let waiting: Vec<i32> = self.dtask.threads.map.iter().filter(|(_, t)| t.dup2_wait == Some(c.fd)).map(|(&tid, _)| tid).collect();
        for tid in waiting {
            self.darwin_wake(m, tid, WaitResult::Awakened);
        }
        self.darwin_closing_file(&c.file);
        let settle = c.file.undoes_on_last_close();
        c.file.fg_drop();
        drop(c);
        if settle {
            self.fds.settle();
        }
        let _ = super::set_result(m, self.ctx_addr, 0);
        SyscallOutcome::Continue
    }

    /// `dup2(old, new)` with `new` held reserved by a close draining it:
    /// `procfdtbl_waitfd`'s sleep (`UF_RESVWAIT`, which no signal ends)
    /// until the close releases it, then `dup2` from its start.
    pub(crate) fn darwin_dup2_wait(&mut self, m: &mut GuestMem<'_>, old: i32, new: i32) -> SyscallOutcome {
        self.darwin_me().dup2_wait = Some(new);
        self.darwin_block(m, Wait { deadline: None, cont: Finish::Dup2Wait { old, new } })
    }

    /// A `dup2`'s wait for a reserved descriptor has ended: `startover`.
    pub(crate) fn darwin_dup2_wait_done(&mut self, m: &mut GuestMem<'_>, old: i32, new: i32) -> Option<SyscallOutcome> {
        self.darwin_me().dup2_wait = None;
        if self.fds.is_reserved(new) && self.fds.get(old).is_ok() {
            return Some(self.darwin_dup2_wait(m, old, new));
        }
        let r = self.darwin_dup2_guards(old, new).and_then(|()| {
            // The descriptor it replaces is closed (closef_locked).
            if self.fds.get(old).is_ok() {
                self.darwin_closing(new);
            }
            self.canonical(m, crate::syscalls::nr::DUP3, [old as u64, new as u64, 0, 0, 0, 0])
        });
        super::thread::bsd_result(m, self.ctx_addr, r, false);
        Some(SyscallOutcome::Continue)
    }

    /// The close's sleep has ended (only a wakeup ends it).
    pub(crate) fn darwin_fpdrain_done(&mut self, m: &mut GuestMem<'_>, _res: WaitResult) -> Option<SyscallOutcome> {
        Some(self.darwin_fpdrain_wait(m))
    }
}

/// The descriptors of a `select`'s three sets (`nd`, `in`, `ou`, `ex`):
/// each `fd_set` a bit per descriptor below `nd`, in 32-bit words.
fn select_fds(m: &mut GuestMem<'_>, a: &[u64; 6]) -> Vec<i32> {
    let nd = (a[0] as i32).clamp(0, 1 << 16) as usize;
    let bytes = nd.div_ceil(32) * 4;
    let mut fds = Vec::new();
    for &set in &a[1..4] {
        if set == 0 || bytes == 0 {
            continue;
        }
        let Ok(b) = m.read(set, bytes) else { continue };
        for fd in 0..nd {
            if b[fd / 8] & (1 << (fd % 8)) != 0 && !fds.contains(&(fd as i32)) {
                fds.push(fd as i32);
            }
        }
    }
    fds
}
