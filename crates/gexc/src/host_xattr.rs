//! The host's `l*xattr`/`f*xattr` calls for gex-kernel's HostFs, which
//! forbids `unsafe` and so takes them as a hook (`set_host_xattr`).

use gex_kernel::errno::Errno;
use gex_kernel::vfs::hostfs::host_xattr::{set_host_xattr, On};
use gex_kernel::vfs::XattrOp;
use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;

pub fn install() {
    set_host_xattr(call);
    gex_kernel::vfs::hostfs::host_swap::set_host_swap(swap);
    gex_kernel::vfs::hostfs::host_identity::set_host_identity(identity);
    gex_kernel::darwin::pagecache::set_data_probe(data_in);
}

/// The bytes of `[a, b)` of the file open at `fd` that hold data
/// (`SEEK_DATA`, `SEEK_HOLE`); none where the host cannot tell. The
/// descriptor's offset is put back: gex reads and writes it positioned.
fn data_in(fd: i32, a: u64, b: u64) -> Option<u64> {
    // SAFETY: lseek on a descriptor the caller holds open.
    unsafe {
        let cur = libc::lseek(fd, 0, libc::SEEK_CUR);
        if cur < 0 {
            return None;
        }
        let mut n = 0u64;
        let mut at = a;
        let mut ok = true;
        while at < b {
            let d = libc::lseek(fd, at as libc::off_t, libc::SEEK_DATA);
            if d < 0 {
                // ENXIO: no data from here to the end.
                ok = std::io::Error::last_os_error().raw_os_error() == Some(libc::ENXIO);
                break;
            }
            let d = d as u64;
            if d >= b {
                break;
            }
            let h = libc::lseek(fd, d as libc::off_t, libc::SEEK_HOLE);
            if h < 0 {
                ok = false;
                break;
            }
            let h = (h as u64).min(b);
            n += h - d;
            at = h;
        }
        libc::lseek(fd, cur, libc::SEEK_SET);
        ok.then_some(n)
    }
}

/// The effective user and group this process checks access as, and its
/// groups.
fn identity() -> (u32, u32, Vec<u32>) {
    // SAFETY: a count of zero only asks for the size, and the second call
    // writes at most `n` entries into a vector of that length.
    unsafe {
        let n = libc::getgroups(0, std::ptr::null_mut()).max(0);
        let mut groups = vec![0; n as usize];
        let got = libc::getgroups(n, groups.as_mut_ptr()).max(0);
        groups.truncate(got as usize);
        (libc::geteuid(), libc::getegid(), groups)
    }
}

/// `RENAME_SWAP` and `RENAME_EXCHANGE`: the two names exchanged at once.
fn swap(a: &std::path::Path, b: &std::path::Path) -> Result<(), Errno> {
    let a = CString::new(a.as_os_str().as_bytes()).map_err(|_| Errno::EINVAL)?;
    let b = CString::new(b.as_os_str().as_bytes()).map_err(|_| Errno::EINVAL)?;
    // SAFETY: both are live CStrings for the call.
    #[cfg(target_os = "macos")]
    let r = unsafe { libc::renamex_np(a.as_ptr(), b.as_ptr(), libc::RENAME_SWAP) };
    // SAFETY: as above.
    #[cfg(not(target_os = "macos"))]
    let r = unsafe { libc::syscall(libc::SYS_renameat2, libc::AT_FDCWD, a.as_ptr(), libc::AT_FDCWD, b.as_ptr(), libc::RENAME_EXCHANGE) as i32 };
    if r != 0 {
        return Err(Errno::from_io(&std::io::Error::last_os_error()));
    }
    Ok(())
}

fn call(on: &On<'_>, op: XattrOp<'_>) -> Result<usize, Errno> {
    let path = match on {
        On::Path(p) => Some(CString::new(p.as_os_str().as_bytes()).map_err(|_| Errno::EINVAL)?),
        On::Fd(_) => None,
    };
    let fd = match on { On::Fd(f) => f.as_raw_fd(), On::Path(_) => -1 };
    let name_c = |n: &str| CString::new(n).map_err(|_| Errno::EINVAL);
    // SAFETY: every pointer is a live CString or slice for the call's length.
    #[cfg(not(target_os = "macos"))]
    let r: isize = unsafe {
        match op {
            XattrOp::Get { name, buf } => {
                let n = name_c(name)?;
                // No buffer asks for the size; macOS takes one of length
                // zero as too small.
                let (b, l) = (if buf.is_empty() { std::ptr::null_mut() } else { buf.as_mut_ptr() as *mut libc::c_void }, buf.len());
                sys::get(path.as_deref(), fd, &n, b, l)
            }
            XattrOp::Set { name, value, flags } => {
                let n = name_c(name)?;
                let (v, l) = (value.as_ptr() as *const libc::c_void, value.len());
                sys::set(path.as_deref(), fd, &n, v, l, sys::set_flags(flags)) as isize
            }
            XattrOp::List { buf } => {
                let (b, l) = (if buf.is_empty() { std::ptr::null_mut() } else { buf.as_mut_ptr() as *mut libc::c_char }, buf.len());
                sys::list(path.as_deref(), fd, b, l)
            }
            XattrOp::Remove { name } => {
                let n = name_c(name)?;
                sys::remove(path.as_deref(), fd, &n) as isize
            }
        }
    };
    // SAFETY: as above. macOS spells the l* calls as the path calls with
    // XATTR_NOFOLLOW, and takes a position (resource forks only) and options.
    #[cfg(target_os = "macos")]
    let r: isize = unsafe {
        let nofollow = libc::XATTR_NOFOLLOW;
        match op {
            XattrOp::Get { name, buf } => {
                let n = name_c(name)?;
                // No buffer asks for the size; macOS takes one of length
                // zero as too small.
                let (b, l) = (if buf.is_empty() { std::ptr::null_mut() } else { buf.as_mut_ptr() as *mut libc::c_void }, buf.len());
                match &path {
                    Some(p) => libc::getxattr(p.as_ptr(), n.as_ptr(), b, l, 0, nofollow),
                    None => libc::fgetxattr(fd, n.as_ptr(), b, l, 0, 0),
                }
            }
            XattrOp::Set { name, value, flags } => {
                let n = name_c(name)?;
                let (v, l) = (value.as_ptr() as *const libc::c_void, value.len());
                // Linux's XATTR_CREATE (1) and XATTR_REPLACE (2) are macOS's 2 and 4.
                let f = ((flags as i32 & 1) << 1) | ((flags as i32 & 2) << 1);
                (match &path {
                    Some(p) => libc::setxattr(p.as_ptr(), n.as_ptr(), v, l, 0, f | nofollow),
                    None => libc::fsetxattr(fd, n.as_ptr(), v, l, 0, f),
                }) as isize
            }
            XattrOp::List { buf } => {
                let (b, l) = (if buf.is_empty() { std::ptr::null_mut() } else { buf.as_mut_ptr() as *mut libc::c_char }, buf.len());
                match &path {
                    Some(p) => libc::listxattr(p.as_ptr(), b, l, nofollow),
                    None => libc::flistxattr(fd, b, l, 0),
                }
            }
            XattrOp::Remove { name } => {
                let n = name_c(name)?;
                (match &path {
                    Some(p) => libc::removexattr(p.as_ptr(), n.as_ptr(), nofollow),
                    None => libc::fremovexattr(fd, n.as_ptr(), 0),
                }) as isize
            }
        }
    };
    if r < 0 {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
        // Linux has one name for a missing attribute.
        #[cfg(target_os = "macos")]
        if e == libc::ENOATTR {
            return Err(Errno(61));
        }
        return Err(Errno::from_host(e));
    }
    Ok(r as usize)
}

/// Linux's calls: `l*` on a path, `f*` on a descriptor.
#[cfg(target_os = "linux")]
mod sys {
    use std::ffi::CStr;

    /// Linux's `XATTR_CREATE` and `XATTR_REPLACE` are the guest's.
    pub fn set_flags(flags: u32) -> i32 {
        flags as i32
    }

    pub unsafe fn get(path: Option<&CStr>, fd: i32, n: &CStr, b: *mut libc::c_void, l: usize) -> isize {
        match path {
            Some(p) => libc::lgetxattr(p.as_ptr(), n.as_ptr(), b, l),
            None => libc::fgetxattr(fd, n.as_ptr(), b, l),
        }
    }

    pub unsafe fn set(path: Option<&CStr>, fd: i32, n: &CStr, v: *const libc::c_void, l: usize, flags: i32) -> i32 {
        match path {
            Some(p) => libc::lsetxattr(p.as_ptr(), n.as_ptr(), v, l, flags),
            None => libc::fsetxattr(fd, n.as_ptr(), v, l, flags),
        }
    }

    pub unsafe fn list(path: Option<&CStr>, fd: i32, b: *mut libc::c_char, l: usize) -> isize {
        match path {
            Some(p) => libc::llistxattr(p.as_ptr(), b, l),
            None => libc::flistxattr(fd, b, l),
        }
    }

    pub unsafe fn remove(path: Option<&CStr>, fd: i32, n: &CStr) -> i32 {
        match path {
            Some(p) => libc::lremovexattr(p.as_ptr(), n.as_ptr()),
            None => libc::fremovexattr(fd, n.as_ptr()),
        }
    }
}

/// XNU's calls (sys/xattr.h): one call for a path and one for a
/// descriptor, a resource-fork `position` (0 for every other attribute) and
/// an options word, where `XATTR_NOFOLLOW` is what Linux's `l*` names mean.
#[cfg(target_os = "macos")]
mod sys {
    use std::ffi::CStr;

    /// The guest's `XATTR_CREATE` (1) and `XATTR_REPLACE` (2) as XNU's (2, 4).
    pub fn set_flags(flags: u32) -> i32 {
        let mut o = 0;
        if flags & gex_kernel::vfs::XATTR_CREATE != 0 {
            o |= libc::XATTR_CREATE;
        }
        if flags & gex_kernel::vfs::XATTR_REPLACE != 0 {
            o |= libc::XATTR_REPLACE;
        }
        o
    }

    pub unsafe fn get(path: Option<&CStr>, fd: i32, n: &CStr, b: *mut libc::c_void, l: usize) -> isize {
        match path {
            Some(p) => libc::getxattr(p.as_ptr(), n.as_ptr(), b, l, 0, libc::XATTR_NOFOLLOW),
            None => libc::fgetxattr(fd, n.as_ptr(), b, l, 0, 0),
        }
    }

    pub unsafe fn set(path: Option<&CStr>, fd: i32, n: &CStr, v: *const libc::c_void, l: usize, flags: i32) -> i32 {
        match path {
            Some(p) => libc::setxattr(p.as_ptr(), n.as_ptr(), v, l, 0, flags | libc::XATTR_NOFOLLOW),
            None => libc::fsetxattr(fd, n.as_ptr(), v, l, 0, flags),
        }
    }

    pub unsafe fn list(path: Option<&CStr>, fd: i32, b: *mut libc::c_char, l: usize) -> isize {
        match path {
            Some(p) => libc::listxattr(p.as_ptr(), b, l, libc::XATTR_NOFOLLOW),
            None => libc::flistxattr(fd, b, l, 0),
        }
    }

    pub unsafe fn remove(path: Option<&CStr>, fd: i32, n: &CStr) -> i32 {
        match path {
            Some(p) => libc::removexattr(p.as_ptr(), n.as_ptr(), libc::XATTR_NOFOLLOW),
            None => libc::fremovexattr(fd, n.as_ptr(), 0),
        }
    }
}
