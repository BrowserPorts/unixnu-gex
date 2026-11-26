//! Pipes as XNU makes them (`bsd/kern/sys_pipe.c`): `pipe()`, a write
//! with `pipe_write`'s rules and `fp_writev`'s answer, and `pipe_stat`.
//! The buffer itself is [`crate::pipe::Pipe`] with XNU's rules
//! ([`crate::pipe::Pipe::new_xnu`]).

use super::sysno as sys;
use crate::errno::Errno;
use crate::file::{OpenFile, PipeEnd};
use crate::fs::oflags;
use crate::pipe::{xnu, Pipe};
use crate::syscalls::{BlockOp, Kernel, SyscallOutcome};
use crate::GuestMem;
use gex_abi::ctx;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Whether `file` is a pipe the page's global kernel holds (a page
/// program's standard streams among them), not one of this kernel's: a
/// pipe, with no vnode, which no Darwin pipe call reaches here.
pub(crate) fn held_elsewhere(file: &OpenFile) -> bool {
    file.path.starts_with("pipe:[") && file.handle.pipe_end().is_none() && file.handle.pipe_state().is_some()
}

/// `FG_NOSIGPIPE`.
pub const FG_NOSIGPIPE: u32 = 0x40;

thread_local! {
    /// The process whose call is running on this thread: what a pipe's
    /// SIGIO is sent from (`pipeselwakeup` in the caller's context).
    static CALLER: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
}

/// Note the process whose call runs on this thread.
pub fn set_caller(pid: i32) {
    CALLER.with(|c| c.set(pid));
}

/// The process whose call runs on this thread.
pub fn caller() -> i32 {
    CALLER.with(|c| c.get())
}

/// `UIO_MAXIOV`.
const UIO_MAXIOV: u64 = 1024;

/// `sizeof(struct pipe_info)`: a `vinfo_stat`, the two handles, the
/// status and a reserved word.
pub const PIPE_INFO_SIZE: usize = 160;

/// A Darwin call's wait on the stream `handle` sleeps (`pipe_read`'s
/// `piperd` or `pipe_write`'s `pipewr` msleep, the first time or again): a
/// pipe's read side marks it as they do, `PIPE_WANTR` for a reader and
/// `PIPE_WANTW` for a writer (the side that holds the buffer, which the
/// next write or read clears).
pub fn sleeps(handle: &dyn crate::vfs::FileHandle, write: bool) {
    let bit = if write { xnu::state::WANTW } else { xnu::state::WANTR };
    if let Some((pipe, _)) = handle.pipe_end() {
        if pipe.is_xnu() {
            pipe.mark(false, bit);
        }
    } else if let Some(r) = handle.as_remote_pipe() {
        (r.remote.mark)(r.id, 0, bit);
    }
}

/// `pipe_select` of pipe end `handle` for writing: `PIPE_WSELECT` in its
/// peer's state, while it has one.
pub fn selected_for_write(handle: &dyn crate::vfs::FileHandle) {
    if let Some((pipe, write)) = handle.pipe_end() {
        if pipe.is_xnu() {
            pipe.mark(!write, xnu::state::WSELECT);
        }
    } else if let Some(r) = handle.as_remote_pipe() {
        (r.remote.mark)(r.id, i32::from(!r.write), xnu::state::WSELECT);
    }
}

/// A Darwin pipe's next number in the process that makes it
/// ([`crate::pipe::Pipe::set_ident`]).
static SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `pipe_stat` of a pipe the page's global kernel holds
/// ([`held_elsewhere`]), for a caller of ids `uid`, `gid`: a FIFO of the
/// caller's, whose size is what is buffered and whose block size is the
/// size of its buffer (`MAX_PIPESIZE` of a Darwin process's pipe there,
/// else the global kernel's pipe's, [`crate::pipe::PIPE_BUF`]); for the
/// write end, its peer's while it has a reader, else none (the default
/// size). Its times are none, as an iOS pipe's (`pipe_touch` is macOS's
/// only).
pub(crate) fn held_pipe_stat(file: &OpenFile, uid: u32, gid: u32) -> Option<crate::fs::Stat> {
    if !held_elsewhere(file) {
        return None;
    }
    let st = file.handle.pipe_state()?;
    let md = file.handle.metadata().ok()?;
    // A Darwin process's pipe there keeps XNU's sizes: MAX_PIPESIZE.
    let max = file.handle.as_remote_pipe().and_then(|r| r.xnu_sizes()).map_or(crate::pipe::PIPE_BUF, |(_, max, _)| max);
    let (count, size) = if !file.writable || !st.closed { (st.buffered as usize, max) } else { (0, xnu::PIPE_SIZE.max(xnu::BLOCKS[0])) };
    Some(crate::fs::Stat {
        ino: md.ino,
        mode: 0o010000 | 0o660,
        uid,
        gid,
        size: count as i64,
        blksize: size as i32,
        blocks: count.div_ceil(size) as i64,
        ..Default::default()
    })
}

/// `mac_pipe_check_stat`, which `pipe_stat` and `fill_pipeinfo` make
/// before they read the pipe: the policies' `mpo_pipe_check_stat`. None
/// of this kernel's policies has one: AMFI's operations (filled in by its
/// start, `0xfffffff005ab4b2c` on), Sandbox's (`0xfffffff006f8b9b8`) and
/// AppleImage4's (`0xfffffff006cf33a8`, its sysctl check alone) leave
/// slot 105 of `struct mac_policy_ops` NULL, so the check allows.
pub(crate) fn mac_pipe_check_stat() -> Result<(), Errno> {
    Ok(())
}

impl Kernel {
    /// `pipe()`: the read end in x0, the write end in x1. In the page the
    /// pipe is the global kernel's, with XNU's rules there, as every pipe
    /// of the page is: another process (a posix_spawn's child) may hold an
    /// end of it, in a memory of its own.
    pub(crate) fn darwin_pipe(&mut self, m: &mut GuestMem<'_>) -> Result<u64, Errno> {
        let (r, w) = if let Some(remote) = self.pipes {
            // pipepair_alloc's failure.
            let id = (remote.new_xnu)(self.pid);
            if id < 0 {
                return Err(Errno::ENOMEM);
            }
            let end = |write: bool| Arc::new(crate::pipe::RemotePipeEnd { id, write, remote });
            let path = format!("pipe:[{id}]");
            (OpenFile::new(end(false), path.clone(), oflags::O_RDONLY, true, false), OpenFile::new(end(true), path, oflags::O_WRONLY, false, true))
        } else {
            let p = Arc::new(Pipe::new_xnu());
            p.set_ident([self.dtask.uniqueid, SERIAL.fetch_add(1, Ordering::Relaxed)]);
            let r = OpenFile::new(Arc::new(PipeEnd { pipe: Arc::clone(&p), write: false }), "pipe:[0]".into(), oflags::O_RDONLY, true, false);
            (r, OpenFile::new(Arc::new(PipeEnd { pipe: p, write: true }), "pipe:[0]".into(), oflags::O_WRONLY, false, true))
        };
        let rfd = self.fds.insert(r, false)?;
        let wfd = match self.fds.insert(w, false) {
            Ok(fd) => fd,
            Err(e) => {
                let _ = self.fds.close(rfd as i32);
                return Err(e);
            }
        };
        m.write_u64(self.ctx_addr + ctx::x(1) as u64, wfd)?;
        Ok(rfd)
    }

    /// The Darwin pipe descriptor `fd` is on, if it is one.
    pub(crate) fn darwin_pipe_of(&self, fd: u64) -> Option<(Arc<OpenFile>, Arc<Pipe>, bool)> {
        let file = self.fds.get(fd as i32).ok()?;
        let (pipe, write) = file.handle.pipe_end()?;
        pipe.is_xnu().then_some((file, pipe, write))
    }

    /// The Darwin pipe descriptor `fd` is on, this kernel's or one the
    /// page's global kernel holds with XNU's rules, if it is one.
    pub(crate) fn darwin_xnu_pipe_of(&self, fd: u64) -> Option<Arc<OpenFile>> {
        if let Some((file, ..)) = self.darwin_pipe_of(fd) {
            return Some(file);
        }
        let file = self.fds.get(fd as i32).ok()?;
        (held_elsewhere(&file) && file.handle.as_remote_pipe()?.xnu_sizes().is_some()).then_some(file)
    }

    /// `write` or `writev` (`raw`) to a Darwin pipe.
    pub(crate) fn darwin_pipe_write(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> SyscallOutcome {
        match self.darwin_pipe_write_inner(m, raw, a) {
            Ok(out) => out,
            Err(e) => {
                let _ = super::set_result(m, self.ctx_addr, e.as_return());
                SyscallOutcome::Continue
            }
        }
    }

    fn darwin_pipe_write_inner(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Result<SyscallOutcome, Errno> {
        let file = self.darwin_xnu_pipe_of(a[0]).ok_or(Errno::EBADF)?;
        if !file.writable {
            return Err(Errno::EBADF);
        }
        // The bytes, a uio of one vector or of writev's.
        let data = if raw == sys::WRITE || raw == sys::WRITE_NOCANCEL {
            if a[2] > i32::MAX as u64 {
                return Err(Errno::EINVAL);
            }
            m.read(a[1], a[2] as usize)?.to_vec()
        } else {
            let (iov, cnt) = (a[1], a[2] as u32 as u64);
            if cnt == 0 || cnt > UIO_MAXIOV {
                return Err(Errno::EINVAL);
            }
            let mut total = 0u64;
            let mut v = Vec::new();
            for i in 0..cnt {
                let (base, len) = (m.read_u64(iov + 16 * i)?, m.read_u64(iov + 16 * i + 8)?);
                total += len;
                if len > i64::MAX as u64 || total > i32::MAX as u64 {
                    return Err(Errno::EINVAL);
                }
                v.extend_from_slice(m.read(base, len as usize)?);
            }
            v
        };
        let orig = data.len();
        let nosigpipe = file.darwin_lflags.load(Ordering::Acquire) & FG_NOSIGPIPE != 0;
        let begun = match (file.handle.pipe_end(), file.handle.as_remote_pipe()) {
            (Some((pipe, _)), _) => pipe.xnu_begin_write(orig),
            (None, Some(r)) => match (r.remote.xnu_begin)(r.id, orig as u32) {
                0 => Ok(()),
                e => Err(Errno(-e)),
            },
            (None, None) => Err(Errno::EBADF),
        };
        if let Err(e) = begun {
            return Err(self.darwin_write_error(e, nosigpipe));
        }
        let mut done = 0usize;
        // One pass: what fits (pipe_write sleeps when that is not all).
        if orig > 0 {
            match file.handle.write_part(&data, orig) {
                Ok(n) => done = n as usize,
                Err(Errno::EAGAIN) => {}
                Err(e) => return Err(self.darwin_write_error(e, nosigpipe)),
            }
        }
        if done == orig {
            super::set_result(m, self.ctx_addr, done as u64)?;
            return Ok(SyscallOutcome::Continue);
        }
        // pipe_write's EAGAIN on a non-blocking descriptor, the bytes it put
        // in counted (fp_writev).
        if file.flags() & oflags::O_NONBLOCK != 0 {
            if done == 0 {
                return Err(Errno::EAGAIN);
            }
            super::set_result(m, self.ctx_addr, done as u64)?;
            return Ok(SyscallOutcome::Continue);
        }
        // It sleeps for room and goes on, until all of it is in.
        self.darwin_pipe_sigpipe = Some(!nosigpipe);
        Ok(SyscallOutcome::Blocking(BlockOp::WriteStream {
            handle: Arc::clone(&file.handle),
            buf: 0,
            len: orig - done,
            gathered: Some(data[done..].into()),
            xnu: Some((orig, done as u64)),
        }))
    }

    /// fp_writev's EPIPE: the process takes SIGPIPE unless the descriptor
    /// asked not to.
    fn darwin_write_error(&mut self, e: Errno, nosigpipe: bool) -> Errno {
        if e == Errno::EPIPE && !nosigpipe {
            self.darwin_send_sigpipe();
        }
        e
    }

    /// `psignal(p, SIGPIPE)`.
    pub(crate) fn darwin_send_sigpipe(&mut self) {
        let source = crate::signal::Source { code: crate::signal::SI_USER, pid: self.pid, uid: self.creds.uid() };
        let note = self.darwin_signal_reason(super::signal::dsig::SIGPIPE);
        self.signals.process().raise_noted(crate::signal::sig::SIGPIPE, Some(source), Some(note));
    }

    /// `pipe_stat` for a Darwin pipe descriptor: a FIFO whose size is what
    /// is buffered and whose block size is `MAX_PIPESIZE`.
    pub(crate) fn darwin_pipe_stat(&mut self, m: &mut GuestMem<'_>, fd: u64, buf: u64) -> Result<u64, Errno> {
        let (_, pipe, write) = self.darwin_pipe_of(fd).ok_or(Errno::EBADF)?;
        mac_pipe_check_stat()?;
        let (readers, _) = pipe.ends();
        let (size, max, cnt) = pipe.xnu_sizes().expect("a Darwin pipe");
        // The write end has no buffer: its peer's, while there is one.
        let _ = size;
        let (pipe_size, pipe_count) = if !write || readers > 0 { (max, cnt) } else { (0, 0) };
        let pipe_size = if pipe_size == 0 { xnu::PIPE_SIZE.max(xnu::BLOCKS[0]) } else { pipe_size };
        let st = crate::fs::Stat {
            ino: crate::vfs::anon_ino((Arc::as_ptr(&pipe) as usize + usize::from(write)) as *const u8),
            mode: 0o010000 | 0o660,
            uid: self.creds.uid(),
            gid: self.creds.gid(),
            size: pipe_count as i64,
            blksize: pipe_size as i32,
            blocks: ((pipe_count + pipe_size - 1) / pipe_size) as i64,
            ..Default::default()
        };
        m.write(buf, &if self.darwin_stat_ino32 { st.encode_darwin_ino32() } else { st.encode_darwin() })?;
        Ok(0)
    }

    /// `fill_pipeinfo` of the pipe end `file` is: its `struct pipe_info`,
    /// for the caller. The read side holds the buffer; the write side
    /// describes its peer's while it has one, else none (`PIPE_SIZE`,
    /// nothing buffered). Its status is the side's `pipe_state`
    /// ([`crate::pipe::Pipe::pipe_status`]). None for a file that is no
    /// pipe gex keeps (the host's own streams, which the host's XNU
    /// describes); a BSD errno where the salt cannot be drawn.
    pub(crate) fn darwin_pipe_info(&mut self, file: &OpenFile) -> Result<Option<[u8; PIPE_INFO_SIZE]>, i32> {
        // The end: what names its pipe, its side, what the read side's
        // buffer holds and its MAX_PIPESIZE, and the side's state.
        let (ident, write, count, max, status) = if let Some((pipe, write)) = file.handle.pipe_end() {
            let Some((_, max, cnt)) = pipe.xnu_sizes() else { return Ok(None) };
            mac_pipe_check_stat().map_err(|e| super::errno::to_darwin(e.0))?;
            let [owner, serial] = pipe.ident();
            ([0, owner, serial], write, cnt, max, pipe.pipe_status(write))
        } else if let Some(r) = file.handle.as_remote_pipe() {
            // The global kernel's pipe: a Darwin process's keeps XNU's
            // MAX_PIPESIZE; another's buffer is the size of the pipe's
            // (crate::pipe::PIPE_BUF), which MAX_PIPESIZE is.
            mac_pipe_check_stat().map_err(|e| super::errno::to_darwin(e.0))?;
            let status = (r.remote.status)(r.id, i32::from(r.write));
            if status < 0 {
                return Err(super::errno::to_darwin(-status));
            }
            let (cnt, max) = match r.xnu_sizes() {
                Some((_, max, cnt)) => (cnt, max),
                None => ((r.remote.buffered)(r.id).max(0) as usize, crate::pipe::PIPE_BUF.max(xnu::PIPE_SIZE)),
            };
            ([1, r.id as u64, 0], r.write, cnt, max, status as u32)
        } else {
            return Ok(None);
        };
        let peer = status & xnu::state::EOF == 0;
        let (pipe_size, pipe_count) = if !write || peer { (max, count) } else { (0, 0) };
        // (A peer's buffer caught in a transient state.)
        let pipe_size = if pipe_size == 0 { xnu::PIPE_SIZE } else { pipe_size };
        let mut b = [0u8; PIPE_INFO_SIZE];
        // vst_mode, vst_nlink, then the caller's ids (kauth_getuid,
        // kauth_getgid).
        b[4..6].copy_from_slice(&((0o010000 | 0o660) as u16).to_le_bytes());
        b[6..8].copy_from_slice(&1u16.to_le_bytes());
        b[16..20].copy_from_slice(&self.creds.uid().to_le_bytes());
        b[20..24].copy_from_slice(&self.creds.gid().to_le_bytes());
        // nanotime: the access, modification and status change times.
        let now = crate::darwin::time::realtime().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        for at in [24, 40, 56] {
            b[at..at + 8].copy_from_slice(&(now.as_secs() as i64).to_le_bytes());
            b[at + 8..at + 16].copy_from_slice(&i64::from(now.subsec_nanos()).to_le_bytes());
        }
        b[88..96].copy_from_slice(&(pipe_count as i64).to_le_bytes());
        b[96..104].copy_from_slice(&(pipe_count.div_ceil(pipe_size) as i64).to_le_bytes());
        b[104..108].copy_from_slice(&(pipe_size as i32).to_le_bytes());
        // VM_KERNEL_ADDRHASH of this end's struct and of its peer's (0 for
        // none).
        let salt = self.darwin_addrhash_salt()?;
        self.darwin_stand_in("pipe_handle and pipe_peerhandle, VM_KERNEL_ADDRHASH of each pipe end's struct pipe, a kernel address gex has none of (stand-in: SHA-256 of the system's salt and what names the end, which is the same end's in every process; 0 for a peer that has closed)");
        b[136..144].copy_from_slice(&addrhash(salt, ident, write).to_le_bytes());
        b[144..152].copy_from_slice(&if peer { addrhash(salt, ident, !write) } else { 0 }.to_le_bytes());
        b[152..156].copy_from_slice(&status.to_le_bytes());
        Ok(Some(b))
    }

    /// `vm_kernel_addrhash_salt`: `early_random()`, once a boot, the
    /// system's (the global kernel keeps the page's).
    fn darwin_addrhash_salt(&mut self) -> Result<u64, i32> {
        static SALT: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        if let Some(&s) = SALT.get() {
            return Ok(s);
        }
        let drawn = match self.darwin_read_random() {
            Ok(v) => v,
            Err(e) => {
                self.darwin_unimplemented(format!("vm_kernel_addrhash_salt's early_random (the kernel's random source failed: errno {})", e.0));
                return Err(5);
            }
        };
        let salt = super::share::value(super::share::Value::AddrHashSalt, 2, drawn).unwrap_or(drawn);
        Ok(*SALT.get_or_init(|| salt))
    }
}

/// What stands in for `VM_KERNEL_ADDRHASH` of a pipe end's `struct pipe`
/// (`vm_kernel_addrhash_internal`: the first word of SHA-256 of the salt
/// and the address): the first word of SHA-256 of the salt, what names the
/// end's pipe and its side.
fn addrhash(salt: u64, ident: [u64; 3], write: bool) -> u64 {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(salt.to_le_bytes());
    for w in ident {
        h.update(w.to_le_bytes());
    }
    h.update([u8::from(write)]);
    u64::from_le_bytes(h.finalize()[..8].try_into().unwrap())
}
