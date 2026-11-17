//! `F_FREEZE_FS` and `F_THAW_FS` on an APFS volume (APFS 2236.140.6, the
//! kernelcache's kext).
//!
//! XNU's `fcntl` passes both to the vnode's `VNOP_IOCTL` once the
//! descriptor is a vnode (EBADF otherwise, `kern_descrip.c`); XNU keeps
//! no freeze of its own. `apfs_vnop_ioctl` (0xfffffff0066d3d04) sends 53
//! to its freeze (0xfffffff0066d9160) and 54 to its thaw
//! (0xfffffff0066d91f0). Each lets in the superuser or the mount's owner
//! (`vfs_statfs(mp)->f_owner` against `kauth_cred_getuid`, EACCES
//! otherwise). Then:
//!
//! - the freeze (`fs_tx_freeze`, 0xfffffff0067135f4) freezes the
//!   container's transactions (`tx_freeze(nx, 0)`, 0xfffffff00675c9dc): a
//!   freeze already held waits (`nx_tx_wait_frozen`) until it is thawed;
//!   otherwise the pending transactions are flushed and from then on every
//!   transaction of every volume of the container waits for the thaw. The
//!   volume records the freezing process (its +0x3a0), and the kext sends
//!   its volume's IOKit clients message 0xe0084006 (`sendIONotification`,
//!   0xfffffff00668062c, through 0xfffffff0066e8b30);
//! - the thaw (`fs_tx_thaw`, 0xfffffff006713670) is EINVAL unless the
//!   calling process is the one the volume recorded; it clears the record,
//!   thaws the container (0xfffffff00675d210) and sends 0xe0084007.
//!
//! `apfs_vnop_close` (0xfffffff006690b04) thaws a volume whose freezer is
//! closing one of its vnodes while it exits.
//!
//! Here every APFS mount is a volume of disk0's one container. Nothing can
//! have registered for a volume's IOKit messages (interest notifications
//! are not served), so the messages reach no one. The writers a freeze
//! holds, and a second freeze, wait on the device; that wait is not
//! modelled and is reported ([`writer_waits`]).

use super::kern::{Fs, Mount};
use crate::errno::Errno;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// The container's freeze: the volume (by its mount's fsid) whose freezer
/// field holds the process, and that process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Freeze {
    pub fsid: u64,
    pub pid: i32,
}

static FROZEN: Mutex<Option<Freeze>> = Mutex::new(None);

/// Whether [`FROZEN`] holds one: what every call's check reads first.
static ANY: AtomicBool = AtomicBool::new(false);

/// The container's freeze, if one is held.
pub fn frozen() -> Option<Freeze> {
    if !ANY.load(Ordering::Acquire) {
        return None;
    }
    *FROZEN.lock().unwrap_or_else(|e| e.into_inner())
}

/// What the ioctl does that is not modelled.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    Errno(Errno),
    Unmodelled(String),
}

/// `fcntl(fd, 53 | 54)` by process `pid` with effective user `euid` on a
/// vnode of `mnt` (an APFS mount), `alive` saying whether a process still
/// runs.
pub fn ioctl(mnt: &Mount, thaw: bool, pid: i32, euid: u32, alive: &dyn Fn(i32) -> bool) -> Result<(), Refused> {
    debug_assert_eq!(mnt.fs, Fs::Apfs);
    // kauth_cred_issuser, else the mount's owner.
    if euid != 0 && euid != mnt.owner {
        return Err(Refused::Errno(Errno::EACCES));
    }
    let mut f = FROZEN.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(cur) = *f {
        if !alive(cur.pid) {
            return Err(Refused::Unmodelled(format!(
                "the container's freeze by process {} that has exited: whether its exit thawed it (apfs_vnop_close thaws only for a vnode of the frozen volume the exiting process closes)",
                cur.pid
            )));
        }
    }
    if thaw {
        // fs_tx_thaw: only the volume's own freezer.
        return match *f {
            Some(cur) if cur.fsid == mnt.fsid && cur.pid == pid => {
                *f = None;
                ANY.store(false, Ordering::Release);
                Ok(())
            }
            _ => Err(Refused::Errno(Errno::EINVAL)),
        };
    }
    match *f {
        Some(cur) => Err(Refused::Unmodelled(format!(
            "F_FREEZE_FS of {} while process {} holds the container frozen: the freeze waits for its thaw (nx_tx_wait_frozen)",
            mnt.on, cur.pid
        ))),
        None => {
            *f = Some(Freeze { fsid: mnt.fsid, pid });
            ANY.store(true, Ordering::Release);
            Ok(())
        }
    }
}

/// What a change to a file of `mnt` meets while the container is frozen:
/// the transaction it needs waits for the thaw, which is not modelled.
pub fn writer_waits(mnt: &Mount) -> Option<String> {
    if mnt.fs != Fs::Apfs {
        return None;
    }
    frozen().map(|f| format!("a change to a file on {} while process {} holds the container frozen (F_FREEZE_FS): the change's transaction waits for the thaw", mnt.on, f.pid))
}

/// `O_TRUNC`, `O_CREAT` (Darwin's).
const O_CREAT: u64 = 0x200;
const O_TRUNC: u64 = 0x400;

impl crate::syscalls::Kernel {
    /// Darwin call `raw` (arguments `a`) changes a file of a frozen
    /// container: the files it changes, by descriptor or by path, checked
    /// for an APFS mount ([`writer_waits`]). Reported, and the call fails
    /// EINTR in place of its wait.
    pub(crate) fn darwin_frozen_writer(&mut self, m: &crate::GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Option<Errno> {
        frozen()?;
        let name = super::sysno::name(raw)?;
        let cwd = super::bsd::AT_FDCWD as u64;
        // (descriptor) or (directory descriptor, path) pairs the call changes.
        let mut fds: Vec<u64> = Vec::new();
        let mut paths: Vec<(u64, u64)> = Vec::new();
        match name {
            "write" | "write_nocancel" | "writev" | "writev_nocancel" | "pwrite" | "pwrite_nocancel" | "pwritev" | "pwritev_nocancel" | "ftruncate" | "fchmod" | "fchmod_extended" | "fchown" | "fchflags" | "futimes" | "fsetxattr" | "fremovexattr" | "fsetattrlist" => fds.push(a[0]),
            "unlink" | "rmdir" | "mkdir" | "mkdir_extended" | "chmod" | "chmod_extended" | "chown" | "lchown" | "chflags" | "utimes" | "truncate" | "setxattr" | "removexattr" | "setattrlist" | "mkfifo" | "mkfifo_extended" | "mknod" => paths.push((cwd, a[0])),
            "exchangedata" | "rename" => paths.extend([(cwd, a[0]), (cwd, a[1])]),
            "link" | "symlink" => paths.push((cwd, a[1])),
            "unlinkat" | "mkdirat" | "fchmodat" | "fchownat" | "setattrlistat" | "mkfifoat" | "mknodat" => paths.push((a[0], a[1])),
            "renameat" | "renameatx_np" => paths.extend([(a[0], a[1]), (a[2], a[3])]),
            "linkat" | "clonefileat" => paths.push((a[2], a[3])),
            "symlinkat" => paths.push((a[1], a[2])),
            "fclonefileat" => paths.push((a[1], a[2])),
            "open" | "open_nocancel" | "open_extended" | "open_dprotected_np" if a[1] & (O_CREAT | O_TRUNC) != 0 => paths.push((cwd, a[0])),
            "openat" | "openat_nocancel" | "openat_dprotected_np" if a[2] & (O_CREAT | O_TRUNC) != 0 => paths.push((a[0], a[1])),
            _ => return None,
        }
        let mut mounts = Vec::new();
        for fd in fds {
            if let Ok(file) = self.fds.get(fd as i32) {
                if self.darwin_vnode_of(&file).is_some() {
                    mounts.push(super::kern::mount_of_file(&file));
                }
            }
        }
        for (dirfd, path) in paths {
            let Ok(raw) = m.read_cstr(path, 1024 /* MAXPATHLEN */) else { continue };
            let Ok(raw) = String::from_utf8(raw) else { continue };
            let start = if raw.starts_with('/') { None } else { self.darwin_sb_start(dirfd) };
            let abs = crate::vfs::normalize(&raw, start.as_ref().map_or("/", |s| s.path.as_str()));
            mounts.push(super::kern::mount_of(&abs));
        }
        let why = mounts.into_iter().find_map(writer_waits)?;
        self.darwin_unimplemented(format!("{name}: {why}"));
        Some(Errno::EINTR)
    }
}

#[cfg(test)]
pub(crate) fn reset() {
    *FROZEN.lock().unwrap_or_else(|e| e.into_inner()) = None;
    ANY.store(false, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::darwin::kern::From;

    #[test]
    fn freeze_and_thaw() {
        reset();
        let root: &'static Mount = Box::leak(Box::new(Mount::new("/", From::Snapshot(0), 0x1000004, 0, Fs::Apfs, None, 0, Some(true))));
        let pre: &'static Mount = Box::leak(Box::new(Mount::new("/private/preboot", From::Volume(4), 0x1000005, 0, Fs::Apfs, None, 0, Some(false))));
        let alive = |_: i32| true;
        // Not root and not the owner.
        assert_eq!(ioctl(root, false, 10, 501, &alive), Err(Refused::Errno(Errno::EACCES)));
        // Nothing to thaw.
        assert_eq!(ioctl(root, true, 10, 0, &alive), Err(Refused::Errno(Errno::EINVAL)));
        ioctl(root, false, 10, 0, &alive).unwrap();
        assert!(writer_waits(pre).is_some());
        // Another freeze waits; another process or volume cannot thaw.
        assert!(matches!(ioctl(pre, false, 11, 0, &alive), Err(Refused::Unmodelled(_))));
        assert_eq!(ioctl(root, true, 11, 0, &alive), Err(Refused::Errno(Errno::EINVAL)));
        assert_eq!(ioctl(pre, true, 10, 0, &alive), Err(Refused::Errno(Errno::EINVAL)));
        ioctl(root, true, 10, 0, &alive).unwrap();
        assert_eq!(frozen(), None);
        assert!(writer_waits(pre).is_none());
        // A freezer that exited.
        ioctl(root, false, 12, 0, &alive).unwrap();
        assert!(matches!(ioctl(root, true, 13, 0, &|p| p != 12), Err(Refused::Unmodelled(_))));
        reset();
    }
}
