//! The host's word on a whole path at once for gex-kernel's HostFs walk,
//! which forbids `unsafe` and so takes it as a hook (`set_host_no_links`):
//! one call says whether a path has a link on it, where the walk would
//! otherwise ask about each component. Linux's is `openat2` with
//! `RESOLVE_NO_SYMLINKS`, XNU's `fstatat` with `AT_SYMLINK_NOFOLLOW_ANY`.

use gex_kernel::vfs::hostfs::host_walk::set_host_no_links;
use std::ffi::CString;

pub fn install() {
    set_host_no_links(no_links);
}

/// `struct open_how` (linux/openat2.h).
#[cfg(target_os = "linux")]
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[cfg(target_os = "linux")]
const RESOLVE_NO_SYMLINKS: u64 = 0x04;

#[cfg(target_os = "linux")]
fn no_links(root: i32, rel: &str) -> bool {
    if rel.is_empty() {
        return true;
    }
    let Ok(path) = CString::new(rel) else { return false };
    let how = OpenHow { flags: (libc::O_PATH | libc::O_CLOEXEC) as u64, mode: 0, resolve: RESOLVE_NO_SYMLINKS };
    // SAFETY: a live CString and struct for the call's length.
    let fd = unsafe {
        libc::syscall(libc::SYS_openat2, root, path.as_ptr(), &how as *const OpenHow, std::mem::size_of::<OpenHow>())
    };
    if fd >= 0 {
        // SAFETY: the descriptor just opened, closed once.
        unsafe { libc::close(fd as i32) };
        return true;
    }
    stopped_before_a_link(std::io::Error::last_os_error())
}

/// XNU's `AT_SYMLINK_NOFOLLOW_ANY` (sys/fcntl.h), which the libc crate lacks.
#[cfg(target_os = "macos")]
const AT_SYMLINK_NOFOLLOW_ANY: libc::c_int = 0x0800;

/// `AT_SYMLINK_NOFOLLOW_ANY` refuses a link on the way (`ELOOP`) but, like
/// `lstat`, answers for a link that ends the path, which `openat2` refuses:
/// that one is a link met too.
#[cfg(target_os = "macos")]
fn no_links(root: i32, rel: &str) -> bool {
    if rel.is_empty() {
        return true;
    }
    let Ok(path) = CString::new(rel) else { return false };
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: a live CString, and a stat buffer the call fills.
    let r = unsafe { libc::fstatat(root, path.as_ptr(), st.as_mut_ptr(), AT_SYMLINK_NOFOLLOW_ANY) };
    if r == 0 {
        // SAFETY: filled by the call that just succeeded.
        let mode = unsafe { st.assume_init() }.st_mode;
        return mode & libc::S_IFMT != libc::S_IFLNK;
    }
    stopped_before_a_link(std::io::Error::last_os_error())
}

/// The walk stops at the first component missing, or not a directory,
/// before any link: there is none to follow up to there (`ELOOP` for a
/// link; `ENOSYS` and the rest cannot say).
fn stopped_before_a_link(e: std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::ENOTDIR))
}
