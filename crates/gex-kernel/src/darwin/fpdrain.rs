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
        let held: Vec<(i32, usize)> = fds.into_iter().filter_map(|fd| self.fds.get(fd).ok().map(|f| key(fd, &f))).collect();
        self.darwin_me().fp_call = held;
    }

    /// The calling thread's call has returned (`fp_drop`): a close waiting
    /// for the calls in one of its fileprocs to leave looks again.
    pub(crate) fn darwin_fp_leave(&mut self, m: &mut GuestMem<'_>) {
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

    /// The threads other than the caller in a call on fileproc `k`, and
    /// whether any of them holds it from `select`.
    fn darwin_fp_callers(&mut self, k: (i32, usize)) -> (usize, bool) {
        let me = self.tid;
        let mut n = 0;
        let mut select = false;
        for (&tid, t) in &self.dtask.threads.map {
            if tid != me && t.fp_call.contains(&k) {
                n += 1;
                select |= SELECTS.contains(&t.syscall_code);
            }
        }
        (n, select)
    }

    /// Whether another thread is in a call on descriptor `fd` (its
    /// fileproc's `fp_iocount` above one). A terminal's descriptor is not
    /// asked: its close drains its vnode ([`super::tty`]).
    pub(crate) fn darwin_fp_busy(&mut self, fd: i32) -> bool {
        let Ok(file) = self.fds.get(fd) else { return false };
        if self.darwin_tty_of(fd as u64).is_some() {
            return false;
        }
        self.darwin_fp_callers(key(fd, &file)).0 > 0
    }

    /// `close` of descriptor `fd`, which another thread is in a call on:
    /// `fp_close_and_unlock`'s `knote_fdclose` and `fileproc_drain`, then
    /// (once the calls have left) its `fdrelse` and `fg_drop`. None where
    /// the drain of the file's type is not done here: reported, and the
    /// close made as one without a drain.
    pub(crate) fn darwin_close_drain(&mut self, m: &mut GuestMem<'_>, fd: i32) -> Option<SyscallOutcome> {
        let file = self.fds.get(fd).ok()?;
        let (_, select) = self.darwin_fp_callers(key(fd, &file));
        if select {
            self.darwin_unimplemented(format!("close of descriptor {fd} while another thread's select has it in its sets (fileproc_drain's wakeup of the select, FP_INSELECT): the select is not woken"));
            return None;
        }
        // fo_drain, as the file's type has it.
        let last = file.fg_count() == 1;
        let drain: Option<Arc<crate::pipe::Pipe>> = match super::procinfo::fdtype(&file) {
            dtype::PIPE => match file.handle.pipe_end() {
                // pipe_drain: the pipe's last descriptor is going, so both
                // sides drain.
                Some((p, _)) if p.is_xnu() && last => Some(p),
                Some((p, _)) if p.is_xnu() => {
                    self.darwin_unimplemented(format!("close of descriptor {fd} while another thread is in a call on it, its pipe end also held elsewhere (fileproc_drain's FPV_DRAIN alone): the call is not woken"));
                    return None;
                }
                _ => {
                    self.darwin_unimplemented(format!("close of descriptor {fd}, a pipe the page's global kernel holds, while another thread is in a call on it (pipe_drain): the call is not woken"));
                    return None;
                }
            },
            dtype::SOCKET => {
                self.darwin_unimplemented(format!("close of descriptor {fd}, a socket, while another thread is in a call on it (soo_drain, SS_DRAINING): the call is not woken"));
                return None;
            }
            dtype::KQUEUE => {
                self.darwin_unimplemented(format!("close of descriptor {fd}, a kqueue, while another thread is in a call on it (kqueue_drain, KQ_DRAIN): the call is not woken"));
                return None;
            }
            // fo_no_drain (a vnode's, a POSIX semaphore's or shared memory
            // object's): nothing wakes the call; the close waits for it.
            _ => None,
        };
        // UF_RESERVED|UF_CLOSING: lookups of it fail, its number is kept;
        // the fileproc's hold on the file stays until fg_drop.
        file.fg_retain();
        if self.fds.close_reserving(fd).is_err() {
            file.fg_drop();
            return None;
        }
        self.darwin_knote_fdclose(fd);
        if let (Some(p), Some((_, write))) = (&drain, file.handle.pipe_end()) {
            p.drain(write);
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
        if self.darwin_fp_callers(key(fd, &file)).0 > 0 {
            // pipe_drain again: the close's hold is the fileproc's, so a
            // count of one is still its last descriptor's.
            if let Some((p, write)) = file.handle.pipe_end().filter(|(p, _)| p.is_xnu() && file.fg_count() == 1) {
                p.drain(write);
            }
            return self.darwin_block(m, Wait { deadline: None, cont: Finish::FpDrain });
        }
        // fdrelse, then fg_drop: closef_locked's release of the process's
        // POSIX locks on the file, and the file's own close with its last
        // hold.
        let c = self.darwin_me().fp_closing.take().expect("taken above");
        self.fds.release_reserved(c.fd);
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
