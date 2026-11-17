//! XNU's answers to `gex_kernel::hostos`'s calls, which the kernel and the
//! native host (no unsafe code in either) take as hooks. A Linux host keeps
//! the kernel's own, read from `/proc`.

#[cfg(not(target_os = "macos"))]
pub fn install() {}

#[cfg(target_os = "macos")]
pub use xnu::install;

#[cfg(target_os = "macos")]
mod xnu {
    use gex_kernel::errno::Errno;
    use gex_kernel::hostos::{Calls, Ids};
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    /// `PROC_PIDTHREADID64INFO` (sys/proc_info.h), which the libc crate lacks:
    /// a thread's `proc_threadinfo` by its 64-bit id.
    const PROC_PIDTHREADID64INFO: libc::c_int = 15;

    pub fn install() {
        gex_kernel::hostos::install(Calls { ids, fd_path, thread_id, thread_cpu_ns, alive, name_thread });
    }

    fn ids() -> Option<Ids> {
        // SAFETY: plain id calls; the group buffer is sized by the first call.
        unsafe {
            let n = libc::getgroups(0, std::ptr::null_mut());
            let mut groups = vec![0 as libc::gid_t; n.max(0) as usize];
            let got = libc::getgroups(n, groups.as_mut_ptr());
            if got < 0 {
                return None;
            }
            groups.truncate(got as usize);
            Some(Ids { uid: libc::getuid(), euid: libc::geteuid(), gid: libc::getgid(), egid: libc::getegid(), groups })
        }
    }

    /// `F_GETPATH`, which follows renames but goes on naming the path a
    /// file had once it is removed: the file is still there only when that
    /// path is still it (its device and inode).
    fn fd_path(fd: i32) -> Option<Result<PathBuf, Errno>> {
        let mut buf = [0 as libc::c_char; libc::PATH_MAX as usize];
        // SAFETY: F_GETPATH writes at most MAXPATHLEN (PATH_MAX) bytes.
        if unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) } < 0 {
            return None;
        }
        // SAFETY: the call wrote a NUL-terminated path into the buffer.
        let now = PathBuf::from(std::ffi::OsStr::from_bytes(unsafe { CStr::from_ptr(buf.as_ptr()) }.to_bytes()));
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: a stat buffer the call fills.
        if unsafe { libc::fstat(fd, st.as_mut_ptr()) } < 0 {
            return None;
        }
        // SAFETY: filled by the call that just succeeded.
        let st = unsafe { st.assume_init() };
        use std::os::unix::fs::MetadataExt;
        match std::fs::symlink_metadata(&now) {
            Ok(m) if m.dev() == st.st_dev as u64 && m.ino() == st.st_ino => Some(Ok(now)),
            _ => Some(Err(Errno::ENOENT)),
        }
    }

    fn thread_id() -> u64 {
        let mut id = 0u64;
        // SAFETY: the calling thread's id into a live u64.
        unsafe { libc::pthread_threadid_np(0 as libc::pthread_t, &mut id) };
        id
    }

    /// The thread's user and system time (`proc_threadinfo`, nanoseconds).
    fn thread_cpu_ns(tid: Option<u64>) -> Option<u64> {
        let tid = tid.unwrap_or_else(thread_id);
        let mut info = std::mem::MaybeUninit::<libc::proc_threadinfo>::uninit();
        let size = std::mem::size_of::<libc::proc_threadinfo>() as libc::c_int;
        // SAFETY: a buffer of the size passed, filled by the call.
        let n = unsafe {
            libc::proc_pidinfo(libc::getpid(), PROC_PIDTHREADID64INFO, tid, info.as_mut_ptr() as *mut libc::c_void, size)
        };
        if n != size {
            return None;
        }
        // SAFETY: filled whole by the call that just succeeded.
        let info = unsafe { info.assume_init() };
        Some(info.pth_user_time + info.pth_system_time)
    }

    /// `kill(pid, 0)`: there when it is signalled, or there but not ours.
    fn alive(pid: u32) -> bool {
        let Ok(pid) = libc::pid_t::try_from(pid) else { return false };
        // SAFETY: signal 0 checks and sends nothing.
        let r = unsafe { libc::kill(pid, 0) };
        r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    fn name_thread(name: &str) {
        if let Ok(n) = CString::new(name) {
            // SAFETY: a live CString; XNU names only the calling thread.
            unsafe { libc::pthread_setname_np(n.as_ptr()) };
        }
    }
}
