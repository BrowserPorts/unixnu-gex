//! APFS's mount of a volume from its device: `apfs_vfsop_mount`
//! (0xfffffff0066c5fac, the `vfs_mount` of APFS's vfsops 0xfffffff006f2b3c8)
//! for a fresh mount, mode 1, of a volume of the container APFS loaded for
//! the root.

use super::storage::Media;

/// The size of the arguments APFS copies in after the device's path
/// (`copyin` of 0x144 bytes; "failed to copy mount arguments").
pub const ARGS_SIZE: usize = 0x144;

/// The arguments' fields APFS reads for a mode-1 mount: the mode (u16 at
/// +0x8), and the owner and group a mount that ignores ownership gives
/// its files (+0x13c, +0x140; -1 for 99).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Args {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
}

impl Args {
    pub fn parse(b: &[u8; ARGS_SIZE]) -> Args {
        let u32_at = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        Args { mode: u16::from_le_bytes([b[8], b[9]]), uid: u32_at(0x13c), gid: u32_at(0x140) }
    }
}

/// `MNT_RDONLY`, `MNT_CPROTECT`, `MNT_DOVOLFS`, `MNT_DONTBROWSE`,
/// `MNT_IGNORE_OWNERSHIP`, `MNT_JOURNALED`, `MNT_NOATIME`, `MNT_STRICTATIME`.
pub mod mnt {
    pub const RDONLY: u32 = 0x1;
    pub const CPROTECT: u32 = 0x80;
    pub const DOVOLFS: u32 = 0x8000;
    pub const DONTBROWSE: u32 = 0x10_0000;
    pub const IGNORE_OWNERSHIP: u32 = 0x20_0000;
    pub const JOURNALED: u32 = 0x80_0000;
    pub const NOATIME: u32 = 0x1000_0000;
    pub const STRICTATIME: u32 = 0x8000_0000;
}

/// `EINVAL`, `EPERM`.
const EINVAL: i32 = 22;
const EPERM: i32 = 1;

/// What the mount gives the mount: the volume, its flags, and the first
/// word of its `f_fsid` (the second is APFS's type number).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mounted {
    pub volume: u32,
    pub flags: u32,
    pub fsid0: u32,
}

/// Why APFS did not mount: an error it returns, or a part of the mount
/// that is not modelled.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    Errno(i32),
    Unmodelled(String),
}

/// The APFS roles whose live mounts are not browsable (the role mask
/// 0x100010110 at 0xfffffff0066cd3e0: Recovery 0x4, VM 0x8, Preboot 0x10,
/// Installer 0x20).
fn dontbrowse_role(role: u16) -> bool {
    role <= 0x20 && (1u64 << role) & 0x1_0001_0110 != 0
}

/// `apfs_vfsop_mount` of a fresh mount, the mount's flags `flags` as
/// mount_common leaves them, from the block device `devvp` of medium
/// `medium` (its `dev_t` `dev`) named `from` (`f_mntfromname`).
///
/// - Every mount: `vfs_setflags(MNT_NOATIME)` and
///   `vfs_clearflags(MNT_STRICTATIME)` (0xfffffff0066c6254); a mount that
///   ignores ownership has its files' owner set (`vfs_setowner`), not
///   modelled here; J120's device tree has no `/options`
///   `enable-remap-mode`, so the remap mode is 1.
/// - The mode: above 8 is EINVAL ("invalid mount mode"); 0, the root's,
///   only from the kernel task (EPERM "not allowed to mount as root");
///   modes 2-8 (snapshot, crypto, conversion and verification mounts) are
///   not modelled.
/// - Mode 1: `vfs_iterate` for an APFS mount of the device (none: the
///   device is not mounted on, mount_common's `vfs_setmounting` saw to
///   that), then 0xfffffff0066d1934: the container's path and the volume's
///   index from `f_mntfromname` (0xfffffff0066d2cb8: past its last "@",
///   the digits after an "s" that does not follow a "/", less one), and
///   `container_load_with_callback`, which finds the root's container by
///   that path (strcmp at 0xfffffff0066709e0). A writing mount of the
///   container loaded read-only for the root updates it to read-write
///   (`nx_rw_update`), which needs its device writable (the container
///   device's writability, 0xfffffff006670b80: EROFS otherwise) and no
///   read-only-compatible container features (the APFS reference defines
///   none). Then `apfs_mount` (0xfffffff006716274) and the live mount: the
///   device's dev in the volume (0xfffffff0066c7104), `vfs_setlocklocal`,
///   `MNT_JOURNALED` (0xfffffff0066c7128, 0xfffffff0066cd314),
///   `f_fsid` = { that dev, APFS's type number } (0xfffffff0066c7134),
///   `MNT_CPROTECT` for a volume that is neither unencrypted nor one-key
///   (0xfffffff0066cd370), `MNT_RDONLY` for a volume that must be read
///   only (+0x354, a sealed one: not a volume the restore makes with
///   `newfs_apfs -A`), `MNT_DONTBROWSE` by role, and `MNT_DOVOLFS` once
///   its private directories load (0xfffffff0066cd50c).
pub fn vfsop_mount(args: &Args, mut flags: u32, medium: Media, dev: u32, from: &str) -> Result<Mounted, Refused> {
    flags |= mnt::NOATIME;
    flags &= !mnt::STRICTATIME;
    if flags & mnt::IGNORE_OWNERSHIP != 0 {
        return Err(Refused::Unmodelled(format!("an APFS mount that ignores ownership (owner {}, group {}: vfs_setowner)", args.uid as i32, args.gid as i32)));
    }
    match args.mode {
        m if m > 8 => return Err(Refused::Errno(EINVAL)),
        0 => return Err(Refused::Errno(EPERM)),
        1 => {}
        m => return Err(Refused::Unmodelled(format!("APFS mount mode {m} (snapshot, crypto, conversion and verification mounts)"))),
    }
    // The container's path and the volume's index, as APFS splits them.
    let (path, index) = split_device_path(from);
    let container = format!("/dev/{}", super::storage::container_bsd_name());
    if path != container {
        return Err(Refused::Unmodelled(format!("an APFS mount from {from}: loading a container from {path} (container_load_with_callback's vnode_open of a container not loaded)")));
    }
    let Media::Volume(v) = medium else {
        return Err(Refused::Unmodelled(format!("an APFS mount from {from}, a medium that is no volume")));
    };
    if index != Some(v) {
        return Err(Refused::Unmodelled(format!("an APFS mount from {from}: a device whose name gives the volume index {index:?}, not its own {v}")));
    }
    let Some(vol) = super::storage::volume(v) else {
        return Err(Refused::Unmodelled(format!("an APFS mount from {from}: no volume at index {v}")));
    };
    if flags & mnt::RDONLY == 0 && !super::storage::disk_writable() {
        // nx_rw_update of a container whose device is not writable.
        return Err(Refused::Errno(30));
    }
    if vol.role == super::storage::role::SYSTEM {
        // The System volume is the root's, mounted from its snapshot:
        // apfs_mount answers EALREADY ("rooted from snap").
        return Err(Refused::Unmodelled(format!("an APFS mount of the System volume from {from}, which the root is mounted from a snapshot of (apfs_mount's EALREADY)")));
    }
    flags |= mnt::JOURNALED;
    let Some(unencrypted) = super::storage::volume_unencrypted(v) else {
        return Err(Refused::Unmodelled(format!("an APFS mount of the {} volume: whether it is encrypted (its apfs_fs_flags)", vol.name)));
    };
    let encrypted = !unencrypted;
    if flags & mnt::CPROTECT != 0 && !encrypted {
        return Err(Refused::Errno(EINVAL));
    }
    if flags & mnt::CPROTECT == 0 && encrypted {
        flags |= mnt::CPROTECT;
    }
    if dontbrowse_role(vol.role) {
        flags |= mnt::DONTBROWSE;
    }
    flags |= mnt::DOVOLFS;
    Ok(Mounted { volume: v, flags, fsid0: dev })
}

/// 0xfffffff0066d2cb8: a device path's container path and volume index:
/// past the path's last "@", digits at its end after an "s" that does not
/// follow a "/" give the index (less one) and end the container's path.
pub fn split_device_path(from: &str) -> (String, Option<u32>) {
    let path = from.rsplit('@').next().unwrap_or(from);
    let digits = path.len() - path.trim_end_matches(|c: char| c.is_ascii_digit()).len();
    if digits == 0 {
        return (path.to_string(), None);
    }
    let head = &path[..path.len() - digits];
    if head.len() >= 2 && head.ends_with('s') && !head[..head.len() - 1].ends_with('/') {
        let n: u32 = path[head.len()..].parse().unwrap_or(0);
        return (head[..head.len() - 1].to_string(), n.checked_sub(1));
    }
    (path.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_paths() {
        assert_eq!(split_device_path("/dev/disk1s5"), ("/dev/disk1".to_string(), Some(4)));
        assert_eq!(split_device_path("com.apple.os.update-X@/dev/disk1s1"), ("/dev/disk1".to_string(), Some(0)));
        assert_eq!(split_device_path("/dev/disk1"), ("/dev/disk1".to_string(), None));
        assert!(dontbrowse_role(0x10) && dontbrowse_role(0x4) && !dontbrowse_role(0x1) && !dontbrowse_role(0x40));
    }

    #[test]
    fn preboot_mode_1() {
        let args = Args { mode: 1, uid: 0, gid: 0 };
        let dev = (1 << 24) | 7;
        let m = vfsop_mount(&args, 0x10_0000 | 0x1000 | 0x8, Media::Volume(4), dev, "/dev/disk1s5").unwrap();
        assert_eq!(m.volume, 4);
        assert_eq!(m.fsid0, dev);
        assert_eq!(m.flags, 0x10_0000 | 0x1000 | 0x8 | mnt::NOATIME | mnt::JOURNALED | mnt::DOVOLFS | if super::super::storage::volume_unencrypted(4) == Some(true) { 0 } else { mnt::CPROTECT });
        assert_eq!(vfsop_mount(&Args { mode: 9, uid: 0, gid: 0 }, 0, Media::Volume(4), dev, "/dev/disk1s5"), Err(Refused::Errno(EINVAL)));
    }
}
