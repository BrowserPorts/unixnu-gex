//! Darwin calls that have no Linux counterpart to renumber onto, or whose
//! results or structures need the kernel's state to translate.

use super::sysctl;
use super::bsd::sys;
use crate::errno::Errno;
use super::ipc::{KQueue, Kq, WorkQueue, Wq};
use crate::syscalls::{nr, Kernel};
use crate::GuestMem;

fn neg(e: Errno) -> u64 {
    (-(e.0 as i64)) as u64
}

/// Darwin's `O_CREAT`.
pub(crate) const DARWIN_O_CREAT: u64 = 0x200;

fn res(r: Result<u64, Errno>) -> u64 {
    r.unwrap_or_else(neg)
}

/// Darwin signal `d` as Linux's number, or 0 where Linux has none (SIGEMT,
/// SIGINFO).
pub fn signal_to_linux(d: u32) -> u32 {
    match d {
        7 | 29 => 0,
        10 => 7,
        12 => 31,
        16 => 23,
        17 => 19,
        18 => 20,
        19 => 18,
        20 => 17,
        23 => 29,
        30 => 10,
        31 => 12,
        s => s,
    }
}

/// A Darwin signal mask (`sigset_t`, 32 bits) as a Linux one, and back.
pub fn mask_to_linux(m: u32) -> u64 {
    (1..=31u32).filter(|s| m & (1 << (s - 1)) != 0).map(signal_to_linux).filter(|&l| l != 0).fold(0, |acc, l| acc | 1u64 << (l - 1))
}

pub fn mask_from_linux(m: u64) -> u32 {
    (1..=31u32).filter(|&d| {
        let l = signal_to_linux(d);
        l != 0 && m & (1 << (l - 1)) != 0
    })
    .fold(0, |acc, d| acc | 1 << (d - 1))
}

/// `fcntl` commands Darwin and Linux number differently, and Darwin's own.
mod f {
    pub const GETFL: u64 = 3;
    pub const SETFL: u64 = 4;
    pub const GETOWN: u64 = 5;
    pub const SETOWN: u64 = 6;
    pub const GETLK: u64 = 7;
    pub const SETLK: u64 = 8;
    pub const SETLKW: u64 = 9;
    pub const PREALLOCATE: u64 = 42;
    pub const RDADVISE: u64 = 44;
    pub const NOCACHE: u64 = 48;
    pub const GETPATH: u64 = 50;
    pub const FULLFSYNC: u64 = 51;
    pub const ADDSIGS: u64 = 59;
    pub const ADDFILESIGS: u64 = 61;
    pub const GETPROTECTIONCLASS: u64 = 63;
    pub const SETPROTECTIONCLASS: u64 = 64;
    pub const DUPFD_CLOEXEC: u64 = 67;
    pub const SETNOSIGPIPE: u64 = 73;
    pub const GETNOSIGPIPE: u64 = 74;
    pub const BARRIERFSYNC: u64 = 85;
    pub const ADDFILESIGS_RETURN: u64 = 97;
    pub const CHECK_LV: u64 = 98;
    pub const SPECULATIVE_READ: u64 = 101;
    pub const RDAHEAD: u64 = 45;
    pub const ADDFILESIGS_FOR_DYLD_SIM: u64 = 83;
    pub const ADDFILESIGS_INFO: u64 = 103;
    pub const NODIRECT: u64 = 62;
    pub const SINGLE_WRITER: u64 = 76;
}

/// AMFI's `__mac_syscall` calls: dyld's policy for the caller, and for
/// another process; whether a cdhash is in a trust cache; the local
/// signing keys and trust cache loading, and launch constraints.
mod amfi_call {
    pub const DYLD_POLICY_SELF: u64 = 90;
    pub const DYLD_POLICY_FOR_PID: u64 = 91;
    pub const CHECK_TRUST_CACHE: u64 = 95;
    pub const GET_LOCAL_SIGNING_PRIVATE_KEY: u64 = 97;
    pub const LOAD_TRUST_CACHE: u64 = 101;
}

/// The Sandbox policy's `__mac_syscall` calls: `sandbox_init` of a builtin
/// profile, `sandbox_check` and its variants, whether a builtin profile is
/// named so (libsandbox's `sandbox_compile_named`), and
/// `sandbox_get_container_expected`.
const SANDBOX_APPLY_BUILTIN: u64 = 1;
const SANDBOX_CHECK: u64 = 2;
const SANDBOX_BUILTIN_EXISTS: u64 = 22;
const SANDBOX_CONTAINER_EXPECTED: u64 = 67;

/// `CS_OPS_*`.
mod csop {
    pub const STATUS: u32 = 0;
    pub const MARKINVALID: u32 = 1;
    pub const MARKHARD: u32 = 2;
    pub const MARKKILL: u32 = 3;
    pub const CDHASH: u32 = 5;
    pub const PIDOFFSET: u32 = 6;
    pub const ENTITLEMENTS_BLOB: u32 = 7;
    pub const MARKRESTRICT: u32 = 8;
    pub const SET_STATUS: u32 = 9;
    pub const BLOB: u32 = 10;
    pub const IDENTITY: u32 = 11;
    pub const CLEARINSTALLER: u32 = 12;
    pub const CLEARPLATFORM: u32 = 13;
    pub const TEAMID: u32 = 14;
    pub const CLEAR_LV: u32 = 15;
    pub const DER_ENTITLEMENTS_BLOB: u32 = 16;
    pub const VALIDATION_CATEGORY: u32 = 17;
}

/// `MAC_MAX_POLICY_NAME`.
const MAC_MAX_POLICY_NAME: usize = 32;

/// `ENOPOLICY`, `ENOSYS` and `ENOTSUP` as Darwin numbers them.
const ENOPOLICY: i32 = 103;

/// A mount, as `getfsstat64` reports it, and the sealed volume whose
/// image gives its files' owners, modes and flags, if one does. What an
/// update changes ([`MountState`]) is behind its lock.
#[derive(Debug)]
pub struct Mount {
    pub on: &'static str,
    pub from: From,
    pub fsid: u64,
    pub fs: Fs,
    pub vol: Option<super::volattrs::Vol>,
    /// `mnt_vfsstat.f_owner`: the user whose mount it is, whom
    /// `mount_common` lets update it besides root.
    pub owner: u32,
    state: std::sync::Mutex<MountState>,
}

/// What of a mount changes after it is made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountState {
    /// `mnt_flag`.
    pub flags: u32,
    /// `mnt_lflag`'s `MNT_LMOUNT` and `MNT_LUNMOUNT`: a mount or unmount
    /// under way.
    pub lflag: u32,
    /// The `f_mntfromname` an update that named a device gave it (the
    /// path as the call gave it, `cn_pnbuf`), in place of [`mount_from`]'s.
    pub from_name: Option<String>,
    /// APFS's read-only state of a volume's mount (its `fs + 0x354`):
    /// set for a snapshot mount (0xfffffff0066ccb24), and for a live one
    /// read-only or of a read-only container (0xfffffff0067155e0); none
    /// for a mount that is not APFS's.
    pub apfs_ro: Option<bool>,
    /// `mnt_vfsstat`'s counts as `vfs_update_vfsstat` (or the mount) last
    /// left them: `f_blocks`, `f_bfree`, `f_bavail`, `f_files`, `f_ffree`;
    /// none before it was first refreshed.
    pub stat: Option<[u64; 5]>,
    /// `mnt_kern_flag`'s `MNTK_SYSTEM` (kept through the shutdown's first
    /// `vfs_unmountall`) and `MNTK_UNMOUNT`.
    pub kern_flag: u32,
}

/// `MNT_LUNMOUNT`, `MNT_LFORCE`, `MNT_LMOUNT`, `MNT_LDEAD`
/// (`mount_internal.h`).
pub const MNT_LUNMOUNT: u32 = 0x2;
pub const MNT_LFORCE: u32 = 0x4;
pub const MNT_LMOUNT: u32 = 0x80;
pub const MNT_LDEAD: u32 = 0x100;

/// `MNTK_SYSTEM`, `MNTK_UNMOUNT` (`mount_internal.h`).
pub const MNTK_SYSTEM: u32 = 0x40;
pub const MNTK_UNMOUNT: u32 = 0x0100_0000;

/// `MNT_ASYNC` (`mount.h`).
pub const MNT_ASYNC: u32 = 0x40;

impl Mount {
    pub fn new(on: &'static str, from: From, fsid: u64, flags: u32, fs: Fs, vol: Option<super::volattrs::Vol>, owner: u32, apfs_ro: Option<bool>) -> Mount {
        Mount { on, from, fsid, fs, vol, owner, state: std::sync::Mutex::new(MountState { flags, lflag: 0, from_name: None, apfs_ro, stat: None, kern_flag: 0 }) }
    }

    /// `mnt_flag`.
    pub fn flags(&self) -> u32 {
        self.state().flags
    }

    /// What of it changes, locked.
    pub fn state(&self) -> std::sync::MutexGuard<'_, MountState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// What a mount is of: its `f_mntfromname`'s source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum From {
    /// devfs, "devfs".
    Devfs,
    /// The sealed system snapshot of the container's volume at this slot,
    /// which the root is mounted from.
    Snapshot(u32),
    /// The container's volume at this slot.
    Volume(u32),
}

/// The filesystem a mount is of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fs {
    Apfs,
    Devfs,
}

/// `MNT_RDONLY`, `MNT_NOSUID`, `MNT_LOCAL`, `MNT_ROOTFS`, `MNT_DOVOLFS`,
/// `MNT_DONTBROWSE`, `MNT_JOURNALED`, `MNT_MULTILABEL`, `MNT_NOATIME`,
/// `MNT_SNAPSHOT`, `MNT_CPROTECT`.
pub(crate) const MNT_RDONLY: u32 = 0x1;
pub(crate) const MNT_NOSUID: u32 = 0x8;
pub(crate) const MNT_LOCAL: u32 = 0x1000;
pub(crate) const MNT_ROOTFS: u32 = 0x4000;
const MNT_DOVOLFS: u32 = 0x8000;
const MNT_DONTBROWSE: u32 = 0x10_0000;
const MNT_JOURNALED: u32 = 0x80_0000;
const MNT_MULTILABEL: u32 = 0x400_0000;
const MNT_NOATIME: u32 = 0x1000_0000;
const MNT_SNAPSHOT: u32 = 0x4000_0000;
const MNT_CPROTECT: u32 = 0x80;

/// The root's flags, as mounting it leaves them:
/// - `vfs_rootmountalloc_internal`: `MNT_RDONLY | MNT_ROOTFS`, and the
///   `vfc_flags` of APFS's vfsconf entry within `MNT_VISFLAGMASK`. Those are
///   `MNT_LOCAL` alone: APFS's `vfs_fsadd` (0xfffffff00666aa6c) passes
///   `vfe_flags` 0x16479, with `VFS_TBLLOCALVOL`, which `vfs_fsadd` turns
///   into `MNT_LOCAL`; nothing in `vfs_fsadd` sets `MNT_MULTILABEL`.
/// - `apfs_vfsop_mount`, for every mount: `vfs_setflags(MNT_NOATIME)`
///   (0xfffffff0066c6254), then `vfs_clearflags(MNT_STRICTATIME)`.
/// - APFS's mount of a live volume: `vfs_setflags(MNT_JOURNALED)`
///   (0xfffffff0066cd314), and `MNT_DOVOLFS` once the volume's private
///   vnodes load (0xfffffff0066cd50c). `MNT_CPROTECT` only for a volume
///   whose `apfs_fs_flags` have neither `APFS_FS_UNENCRYPTED` nor
///   `APFS_FS_ONEKEY` (0xfffffff0066cd35c), which the System volume has
///   ([`super::storage::SYSTEM_UNENCRYPTED`]). `MNT_DONTBROWSE` only for the
///   Recovery, VM, Preboot, Installer, Sidecar and Enterprise roles
///   (0xfffffff0066cd3c4), not the System's.
/// - No `MNT_NOSUID`: on a `SECURE_KERNEL` without `CONFIG_MNT_SUID` (the
///   iOS release configuration) `mount_common` sets it on every mount it
///   makes or updates, but `vfs_mountroot` does not go through it.
/// - `MNT_SNAPSHOT`: `handle_snapshot_mount` (0xfffffff0066cc5e8), which
///   mounts the root from the System volume's sealed snapshot, sets it on
///   every mount it makes, past the root hash's authentication and the
///   filesystem id (0xfffffff0066ccecc, before the volume's mount body at
///   0xfffffff0066cd1b4); the covered vnode, none for the root, only goes
///   to `mac_mount_check_snapshot_mount`. Neither APFS (its
///   `vfs_clearflags` calls clear `MNT_STRICTATIME`, `MNT_IGNORE_OWNERSHIP`
///   and `MNT_LOCAL`) nor an update's `mount_common` clears it.
///   libignition reads it as a sealed boot (an unset one is its "livefs
///   boot").
const ROOT_FLAGS: u32 = MNT_RDONLY | MNT_LOCAL | MNT_ROOTFS | MNT_DOVOLFS | MNT_JOURNALED | MNT_NOATIME | MNT_SNAPSHOT | if super::storage::SYSTEM_UNENCRYPTED { 0 } else { MNT_CPROTECT };

/// The root's flags on a system launchd has booted: launchd's boot task
/// mount-phase-1 runs `/sbin/mount -P 1`, whose entry for "/" in the
/// device tree's fstab (`fs_spec` the System volume's device, as
/// `vfs.generic.apfs.edt_fstab` gives it to libsystem_info's `_fsi_get_fs`
/// at 0x197316110, type "ro") is not mounted by `ismounted`'s test (the
/// root's `f_mntfromname` has the snapshot's name before the device's),
/// so `mountfs` runs `mount_apfs -o ro,update`: mount(2) with
/// `MNT_RDONLY | MNT_UPDATE` (mount_apfs's option table at 0x100008030
/// and 0x1000081c8). `mount_common`'s update clears the settable flags,
/// sets `MNT_NOSUID` (SECURE_KERNEL without CONFIG_MNT_SUID) and none of
/// the others; `apfs_vfsop_mount` sets `MNT_NOATIME` again and leaves the
/// rest ([`super::apfsmount::vfsop_update`]).
const ROOT_FLAGS_BOOTED: u32 = ROOT_FLAGS | MNT_NOSUID;


/// `nblkdev`, the size of `bdevsw`: `vfs_getnewfsid` adds it to the type
/// number for its major (folded to 0x18000000 at 0xfffffff0073769ac).
pub const NBLKDEV: u32 = 24;

/// The root's `f_fsid.val[0]`: APFS's `handle_snapshot_mount`, mounting
/// the sealed snapshot, gives the mount a virtual device's only when
/// 0xfffffff0066812b4 matches the volume to `/chosen`'s `apfs-preboot-uuid`
/// or `boot-uuid` ([`super::storage::BOOT_UUID_MATCHES`]); else
/// (0xfffffff0066ccdb4) `vfs_getnewfsid`: `makedev(nblkdev + vfc_typenum,
/// ++mntid_gen)`, the first since boot (no mount precedes the root), with
/// the type number in `val[1]`.
pub const ROOT_FSID: u32 = (NBLKDEV + vfsstat::APFS_TYPENUM) << 24 | 1;

// The root on a virtual snapshot device is not modelled.
const _: () = assert!(!super::storage::BOOT_UUID_MATCHES, "the root's virtual snapshot device (0xfffffff00667f0a0)");

/// `FT_DEVFS`, devfs's `vfc_typenum`.
pub const DEVFS_TYPENUM: u32 = 19;

/// devfs's `f_fsid.val[0]` (and its nodes' `st_dev`):
/// `VM_KERNEL_ADDRHASH` of the mount's `devfsmount`, a salted hash of a
/// kernel address that each boot makes anew; this is this boot's.
pub const DEVFS_FSID: u32 = 0x9a3c_51e7;

/// What the system has mounted when its first program starts, in the order
/// of the mount list: the system volume, then devfs (`devfs_kernel_mount`
/// in `bsd_init`, right after the root: MNT_DONTBROWSE, MNT_LOCAL from
/// `devfs_mount`, MNT_MULTILABEL from its MACF `vfc_flags`), both the
/// kernel's (`f_owner` 0). On a system launchd has booted, `/sbin/mount -P
/// 1` has updated the root ([`ROOT_FLAGS_BOOTED`]), and the Preboot volume
/// is mounted where libignition's preboot stage mounted it
/// ([`booted_preboot_mount`]), the first mount after the kernel's; the
/// volumes launchd mounts after it are not in the list.
fn boot_mounts() -> Vec<Mount> {
    let root_flags = match boot_state() {
        BootState::Kernel => ROOT_FLAGS,
        BootState::Booted => ROOT_FLAGS_BOOTED,
    };
    let mut mounts = vec![
        Mount::new("/", From::Snapshot(0), ROOT_FSID as u64, root_flags, Fs::Apfs, Some(super::volattrs::Vol::System), 0, Some(true)),
        Mount::new("/dev", From::Devfs, DEVFS_FSID as u64, MNT_LOCAL | MNT_DONTBROWSE | MNT_MULTILABEL, Fs::Devfs, None, 0, None),
    ];
    // devfs_mount's devfs_statfs left devfs's counts as they were at its
    // mount in bsd_init ([`DEVFS_STAT_STAND_IN`]).
    refresh_stat(&mounts[1]);
    // devfs_kernel_mount's KERNEL_MOUNT_DEVFS: mount_common marks the
    // kernel's devfs a system mount.
    mounts[1].state().kern_flag |= MNTK_SYSTEM;
    if boot_state() == BootState::Booted {
        match booted_preboot_mount() {
            Ok(m) => mounts.push(m),
            Err(why) => super::note_unimplemented(format!("the booted system's mount of the Preboot volume: {why}")),
        }
    }
    mounts
}

/// Where libignition's preboot stage mounts the Preboot volume (dyld's
/// `_preboot_fire`, 0x62d44): from its device by role (0x10,
/// `ignition_get_devnode_by_role`), on the mount point of its role.
pub const PREBOOT_ON: &str = "/private/preboot";

/// libignition's `fmount("apfs", fd, MNT_DONTBROWSE, args)` of the Preboot
/// volume (0x62fa8..0x62fc0): its arguments are of mode 1, with owner and
/// group 99 (0x62ddc..0x62df0).
const PREBOOT_ARGS: super::apfsmount::Args = super::apfsmount::Args { mode: 1, uid: 99, gid: 99 };
const PREBOOT_FMOUNT_FLAGS: u32 = MNT_DONTBROWSE;

/// What stands in for the flags of a booted system's Preboot mount.
pub const PREBOOT_BOOTED_FLAGS_STAND_IN: &str = "the flags of a booted system's Preboot mount (stand-in: libignition's preboot stage's read-write fmount of it, read-only once booted as the device tree's fstab names it, by an update not traced, whose own writes are not made: the kernel's container keeps the volume mounted read-write with the mount's and the grafts' writes in its open transaction; measure statfs(\"/private/preboot\").f_flags on the device)";

/// The Preboot volume's mount on a booted system: libignition's, made by
/// launchd (root, `f_owner` 0) ([`ignition_preboot_mount`]), read-only
/// once booted as the device tree's fstab names it: neither libignition
/// (its only mount calls are this `fmount` and the root's) nor what makes
/// it read-only later is traced ([`PREBOOT_BOOTED_FLAGS_STAND_IN`]).
fn booted_preboot_mount() -> Result<Mount, String> {
    let m = ignition_preboot_mount()?;
    {
        let mut st = m.state();
        st.flags |= MNT_RDONLY;
        st.apfs_ro = Some(true);
    }
    Ok(m)
}

/// libignition's mount of the Preboot volume as it made it: `mount_common`
/// gives a new mount `MNT_LOCAL` and, on a SECURE_KERNEL without
/// CONFIG_MNT_SUID, `MNT_NOSUID`; APFS's live mount the rest
/// ([`super::apfsmount::vfsop_mount`]), its `f_fsid.val[0]` the device's.
pub fn ignition_preboot_mount() -> Result<Mount, String> {
    let v = super::storage::volume_with_role(super::storage::role::PREBOOT).ok_or("the container has no Preboot volume")?;
    let name = super::storage::volume_bsd_name(v.index);
    let (_, minor) = super::storage::media_by_name(&name).ok_or_else(|| format!("no medium is named {name}"))?;
    let dev = (super::storage::DISK_MAJOR << 24) | minor;
    let flags = MNT_LOCAL | MNT_NOSUID | PREBOOT_FMOUNT_FLAGS;
    let m = super::apfsmount::vfsop_mount(&PREBOOT_ARGS, flags, super::storage::Media::Volume(v.index), dev, &format!("/dev/{name}")).map_err(|r| format!("{r:?}"))?;
    let ro = m.flags & MNT_RDONLY != 0;
    Ok(Mount::new(PREBOOT_ON, From::Volume(m.volume), u64::from(m.fsid0), m.flags, Fs::Apfs, None, 0, Some(ro)))
}

/// devfs's counts as its mount at boot left them in `mnt_vfsstat`, which a
/// getfsstat that does not refresh reports.
pub const DEVFS_STAT_STAND_IN: &str = "devfs's statfs counts as its mount at boot left them (stand-in: its counts when the mount list is first read; measure getfsstat(MNT_NOWAIT) on the device before anything statfs's /dev)";

/// The mount list (`mountlist`): the boot's mounts, then each one mounted
/// since, in the order they were (`mount_list_add` puts a new mount at the
/// end). One for the whole system, as XNU keeps it: every process sees a
/// mount made by any. A mount's record lives as long as the system.
static MOUNT_LIST: std::sync::RwLock<Vec<&'static Mount>> = std::sync::RwLock::new(Vec::new());

/// Every mount ever made, in the order they were: the mount list with the
/// mounts the shutdown's `vfs_unmountall` took off it ([`MNT_LDEAD`])
/// still in their places, so an index into it names one mount for good.
fn every_mount() -> Vec<&'static Mount> {
    {
        let l = MOUNT_LIST.read().unwrap_or_else(|e| e.into_inner());
        if !l.is_empty() {
            return l.clone();
        }
    }
    let mut l = MOUNT_LIST.write().unwrap_or_else(|e| e.into_inner());
    if l.is_empty() {
        l.extend(boot_mounts().into_iter().map(|m| &*Box::leak(Box::new(m))));
    }
    l.clone()
}

/// The mounts, in the order of the mount list (`mount_list_remove` has
/// taken the unmounted ones off it).
pub fn mounts() -> Vec<&'static Mount> {
    every_mount().into_iter().filter(|m| m.state().lflag & MNT_LDEAD == 0).collect()
}

/// How many mounts have been made.
pub fn mount_count() -> usize {
    {
        let l = MOUNT_LIST.read().unwrap_or_else(|e| e.into_inner());
        if !l.is_empty() {
            return l.len();
        }
    }
    every_mount().len()
}

/// The mount `path` was on when [`mount_count`] was `seen`: a vnode
/// looked up then keeps the mount it is on (`v_mount`), whatever has been
/// mounted on its path since, even once that mount is gone.
pub fn mount_of_seen(path: &str, seen: usize) -> &'static Mount {
    let l = every_mount();
    let n = seen.clamp(1, l.len());
    l[..n]
        .iter()
        .copied()
        .filter(|mt| path == mt.on || path.starts_with(&format!("{}/", mt.on.trim_end_matches('/'))))
        .max_by_key(|mt| mt.on.len())
        .unwrap_or(l[0])
}

/// `mount_list_remove` at the end of an unmount: the mount is off the
/// list, `MNT_LDEAD`, and the list's generation moves.
pub fn mount_list_remove(mnt: &Mount) {
    mnt.state().lflag |= MNT_LDEAD;
    MOUNT_GENERATION.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
}

/// The mount the vnode an open file is on is on (`v_mount`): the one its
/// path was on when it was opened.
pub fn mount_of_file(file: &crate::file::OpenFile) -> &'static Mount {
    mount_of_seen(&file.path, file.darwin_mounts_seen)
}

/// Put `mnt` at the end of the mount list (`mount_list_add`).
pub fn mount_list_add(mnt: Mount) -> &'static Mount {
    every_mount();
    let mnt: &'static Mount = Box::leak(Box::new(mnt));
    MOUNT_LIST.write().unwrap_or_else(|e| e.into_inner()).push(mnt);
    MOUNT_GENERATION.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    mnt
}

/// `mount_generation`: how many times the mount list has changed.
static MOUNT_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// `mount_generation++`: an unmount under way makes the name cache's
/// copies of mount points stale.
pub fn bump_mount_generation() {
    MOUNT_GENERATION.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
}

/// How many times the mount list has changed.
pub fn mount_generation() -> u64 {
    MOUNT_GENERATION.load(std::sync::atomic::Ordering::Acquire)
}

/// Whether something is mounted on `path` (a covered vnode's
/// `v_mountedhere`).
pub fn is_mount_point(path: &str) -> bool {
    mounts().iter().any(|m| m.on == path)
}

/// What the system has mounted when its first program starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootState {
    /// The kernel's mounts alone ([`boot_mounts`]): launchd, the first
    /// process, mounts the other volumes itself.
    Kernel,
    /// A system launchd has booted, where gexc runs another program in its
    /// place: the volumes the device tree's fstab names (the Data volume and
    /// the others) are in place over the system volume's directories,
    /// which their owners, modes and flags follow ([`super::vattr`]).
    Booted,
}

static BOOT_STATE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set what the system has mounted at start: [`BootState::Kernel`] when
/// launchd is the first program.
pub fn set_boot_state(state: BootState) {
    BOOT_STATE.store(state == BootState::Kernel, std::sync::atomic::Ordering::Release);
}

/// What the system had mounted at start.
pub fn boot_state() -> BootState {
    if BOOT_STATE.load(std::sync::atomic::Ordering::Acquire) {
        BootState::Kernel
    } else {
        BootState::Booted
    }
}

/// The volume the preboot cryptexes are on: what `vnode_lookup` of
/// `/private/preboot/Cryptexes` finds the mount of, for the shared region's
/// check of where a cache is (devices without SIP): the Preboot volume's
/// mount once one covers it. Before that the system volume's
/// `/private/preboot` is empty and the lookup fails: none.
pub fn preboot_cryptex_volume() -> Option<&'static str> {
    let m = mount_of("/private/preboot/Cryptexes");
    is_preboot(m).then_some(m.on)
}

/// A mount's `f_mntfromname`. A volume's is its device's path (what
/// mount_common copies from the path given). The root's: APFS's
/// `container_rootmount` copies the System volume's device's path into it
/// (0xfffffff00667fcc4), and `handle_snapshot_mount`, mounting the sealed
/// snapshot [`super::storage::ROOT_SNAPSHOT`] without a virtual device
/// ([`ROOT_FSID`]), puts the snapshot's name and "@" before it
/// (0xfffffff0066d0d0c: `"%s%s%s"`). An update that names a device renames it
/// ([`MountState::from_name`]).
pub fn mount_from(mnt: &Mount) -> String {
    if let Some(name) = mnt.state().from_name.clone() {
        return name;
    }
    match mnt.from {
        From::Devfs => "devfs".to_string(),
        From::Volume(i) => format!("/dev/{}", super::storage::volume_bsd_name(i)),
        From::Snapshot(i) => format!("{}@/dev/{}", super::storage::ROOT_SNAPSHOT, super::storage::volume_bsd_name(i)),
    }
}

/// Whether a mount is of the Preboot volume.
pub fn is_preboot(mnt: &Mount) -> bool {
    matches!(mnt.from, From::Volume(i) if super::storage::volume(i).is_some_and(|v| v.role == super::storage::role::PREBOOT))
}

/// Whether a volume of role `role` has its files served as the disk0
/// image holds them ([`super::graftfs::GraftFs::live`]): the Preboot
/// volume's (the restore's Cryptex1, boot objects, firmware and `active`)
/// and the xART volume's (its gigalocker file).
pub fn served_from_disk0(role: u16) -> bool {
    role == super::storage::role::XART || role == super::storage::role::PREBOOT
}

/// Whether mount `mnt` is of a volume served from the disk0 image
/// ([`served_from_disk0`]): one there is an image to serve it from.
pub fn is_disk0_served(mnt: &Mount) -> bool {
    super::disknode::installed() && matches!(mnt.from, From::Volume(i) if super::storage::volume(i).is_some_and(|v| served_from_disk0(v.role)))
}

/// What of a mount's files is not modelled, if any: a volume mounted at
/// run time holds its own files, which this root does not have, but for
/// those served from the disk0 image ([`is_disk0_served`]).
pub fn unmodelled_files(mnt: &Mount) -> Option<String> {
    match mnt.from {
        From::Volume(_) if is_disk0_served(mnt) => None,
        From::Volume(i) => {
            let name = super::storage::volume(i).map_or("?", |v| v.name);
            let without = if super::storage::volume(i).is_some_and(|v| served_from_disk0(v.role)) { " (served from the disk0 image: none is given, GEX_DARWIN_DISK0)" } else { "" };
            Some(format!("the files of the {name} volume mounted on {}{without}", mnt.on))
        }
        _ => None,
    }
}

/// The mount with files not modelled that canonical path `path` is
/// below (or, with `at_root`, at the root of: a listing of it), with what
/// is not.
pub fn unmodelled_files_at(path: &str, at_root: bool) -> Option<String> {
    unmodelled_files_on(mount_of(path), path, at_root)
}

/// [`unmodelled_files_at`] of a vnode on mount `mnt` (an open file's).
pub fn unmodelled_files_on(mnt: &Mount, path: &str, at_root: bool) -> Option<String> {
    let below = path != mnt.on;
    if !below && !at_root {
        return None;
    }
    unmodelled_files(mnt)
}

/// The container's volume a mount is on (APFS's source volume for its
/// ioctls), if it is on one.
pub fn mount_volume(mnt: &Mount) -> Option<u32> {
    match mnt.from {
        From::Snapshot(i) | From::Volume(i) => Some(i),
        From::Devfs => None,
    }
}

/// A mount's `vfsstatfs` counts and type: `f_bsize`, `f_iosize`,
/// `f_blocks`, `f_bfree`, `f_bavail`, `f_files`, `f_ffree`, its
/// `vfs_typenum`, its name.
struct Counts {
    bsize: u32,
    iosize: u32,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    typenum: u32,
    name: &'static [u8],
}

/// A mount's filesystem's name (`vfs_name`, its `vfc_name`).
pub fn fs_name(mnt: &Mount) -> &'static [u8] {
    match mnt.fs {
        Fs::Apfs => b"apfs",
        Fs::Devfs => b"devfs",
    }
}

/// `vfs_update_vfsstat`: the mount's counts asked of its filesystem anew
/// and kept.
fn refresh_stat(mnt: &Mount) -> Counts {
    let c = counts(mnt);
    mnt.state().stat = Some([c.blocks, c.bfree, c.bavail, c.files, c.ffree]);
    c
}

/// A mount's counts as `mnt_vfsstat` has them: refreshed first with
/// `refresh` (or when they never were), else as they were last.
fn stat_counts(mnt: &Mount, refresh: bool) -> Counts {
    let cached = mnt.state().stat;
    match cached {
        Some([blocks, bfree, bavail, files, ffree]) if !refresh => Counts { blocks, bfree, bavail, files, ffree, ..counts(mnt) },
        _ => refresh_stat(mnt),
    }
}

fn counts(mnt: &Mount) -> Counts {
    match mnt.fs {
        Fs::Apfs => {
            let a = apfs_counts(mnt);
            Counts { bsize: vfsstat::BSIZE, iosize: vfsstat::IOSIZE, blocks: a.blocks, bfree: a.bfree, bavail: a.bavail, files: a.files, ffree: a.ffree, typenum: vfsstat::APFS_TYPENUM, name: fs_name(mnt) }
        }
        // devfs_statfs: 512-byte blocks of its bookkeeping, nothing free.
        Fs::Devfs => Counts {
            bsize: 512,
            iosize: 512,
            blocks: super::devfs::statfs_blocks(),
            bfree: 0,
            bavail: 0,
            files: super::devfs::stats().0,
            ffree: 0,
            typenum: DEVFS_TYPENUM,
            name: fs_name(mnt),
        },
    }
}

/// An APFS volume's counts, as `apfs_vfsop_getattr` gives them: blocks of
/// the container, free and available, and its files and free ones.
pub struct ApfsCounts {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
}

/// The counts of the APFS volume `mnt` is of: stand-ins while disk0's
/// capacity is unmeasured ([`super::storage::unmeasured`]); exact ones need
/// the capacity and APFS's space accounting (its spaceman) of the
/// container after the restore and first boot.
pub fn apfs_counts(_mnt: &Mount) -> ApfsCounts {
    ApfsCounts { blocks: 8 << 20, bfree: 4 << 20, bavail: 4 << 20, files: 1 << 24, ffree: 1 << 23 }
}

/// `sizeof(struct statfs64)`.
pub const STATFS64_SIZE: usize = 2168;

/// What the volumes report of themselves, in `statfs` and `getattrlist`
/// alike: the block size and the preferred transfer size (the counts are
/// [`apfs_counts`]').
pub mod vfsstat {
    pub const BSIZE: u32 = 4096;
    pub const IOSIZE: u32 = 1 << 20;
    /// `vfs_typenum` of APFS: `f_type`, and the second word of `f_fsid`.
    pub const APFS_TYPENUM: u32 = 0x1a;
}

/// The mount a path is on: the one with the longest mount point that
/// holds it.
pub fn mount_of(path: &str) -> &'static Mount {
    let l = mounts();
    l.iter()
        .copied()
        .filter(|mt| path == mt.on || path.starts_with(&format!("{}/", mt.on.trim_end_matches('/'))))
        .max_by_key(|mt| mt.on.len())
        .or_else(|| l.first().copied())
        .unwrap_or_else(|| every_mount()[0])
}

/// The mount the vnode `mnt` covers is on (`vfs_vnodecovered`'s
/// `v_mount`): among the mounts before it in the list, the one with the
/// longest mount point that holds its own. The root covers none: itself.
pub fn covered_mount(mnt: &Mount) -> &'static Mount {
    let l = every_mount();
    let n = l.iter().position(|m| std::ptr::eq(*m, mnt)).unwrap_or(l.len());
    l[..n]
        .iter()
        .copied()
        .filter(|mt| mnt.on == mt.on || mnt.on.starts_with(&format!("{}/", mt.on.trim_end_matches('/'))))
        .max_by_key(|mt| mt.on.len())
        .unwrap_or(l[0])
}

/// `MNT_WAIT`, `MNT_NOWAIT`, `MNT_DWAIT` (`sys/mount.h`).
pub const MNT_WAIT: u32 = 1;
pub const MNT_NOWAIT: u32 = 2;
pub const MNT_DWAIT: u32 = 4;

/// Whether `getfsstat` and `getfsstat64` with `flags` refresh a mount's
/// counts before copying them out (`getfsstat_callback`): unless
/// `MNT_NOWAIT` is asked without `MNT_WAIT` or `MNT_DWAIT` (both of which
/// override it, MNT_DWAIT as MNT_WAIT), and not while it is being
/// unmounted.
pub fn getfsstat_refreshes(mnt: &Mount, flags: u32) -> bool {
    (flags & MNT_NOWAIT == 0 || flags & (MNT_WAIT | MNT_DWAIT) != 0) && mnt.state().lflag & MNT_LUNMOUNT == 0
}

/// One `struct statfs64` for `mnt`, its counts refreshed first with
/// `refresh`.
pub fn statfs64(mnt: &Mount, refresh: bool) -> Vec<u8> {
    let c = stat_counts(mnt, refresh);
    let from = mount_from(mnt);
    let mut b = vec![0u8; STATFS64_SIZE];
    let mut put = |o: usize, v: &[u8]| b[o..o + v.len()].copy_from_slice(v);
    put(0, &c.bsize.to_le_bytes());
    put(4, &c.iosize.to_le_bytes());
    put(8, &c.blocks.to_le_bytes());
    put(16, &c.bfree.to_le_bytes());
    put(24, &c.bavail.to_le_bytes());
    put(32, &c.files.to_le_bytes());
    put(40, &c.ffree.to_le_bytes());
    // The mount's device number, and the filesystem type beside it.
    put(48, &(mnt.fsid as u32).to_le_bytes());
    put(52, &c.typenum.to_le_bytes());
    put(60, &c.typenum.to_le_bytes());
    put(64, &mnt.flags().to_le_bytes());
    put(72, c.name);
    put(88, mnt.on.as_bytes());
    put(1112, from.as_bytes());
    b
}

/// `sizeof(struct user64_statfs)`, the struct of 32-bit inodes, and what
/// `statfs` and `fstatfs` copy of it (`munge_statfs`'s partial copy: not
/// `f_reserved3` and `f_reserved4`); its MFSNAMELEN and MNAMELEN.
pub const STATFS_SIZE: usize = 336;
const STATFS_PARTIAL: usize = STATFS_SIZE - 33;
const MFSNAMELEN: usize = 15;
const MNAMELEN_INO32: usize = 90;

/// One `struct user64_statfs` for `mnt` (`munge_statfs`): the counts as
/// longs, the type beside the subtype, and the names cut to fit, as
/// `strlcpy` cuts them.
pub fn statfs_ino32(mnt: &Mount, refresh: bool) -> [u8; STATFS_SIZE] {
    let c = stat_counts(mnt, refresh);
    let from = mount_from(mnt);
    let mut b = [0u8; STATFS_SIZE];
    let mut put = |o: usize, v: &[u8]| b[o..o + v.len()].copy_from_slice(v);
    put(8, &u64::from(c.bsize).to_le_bytes());
    put(16, &u64::from(c.iosize).to_le_bytes());
    put(24, &c.blocks.to_le_bytes());
    put(32, &c.bfree.to_le_bytes());
    put(40, &c.bavail.to_le_bytes());
    put(48, &c.files.to_le_bytes());
    put(56, &c.ffree.to_le_bytes());
    put(64, &(mnt.fsid as u32).to_le_bytes());
    put(68, &c.typenum.to_le_bytes());
    put(78, &(c.typenum as u16).to_le_bytes());
    put(80, &u64::from(mnt.flags()).to_le_bytes());
    let mut name = |o: usize, size: usize, v: &[u8]| {
        let n = v.len().min(size - 1);
        b[o..o + n].copy_from_slice(&v[..n]);
    };
    name(104, MFSNAMELEN, c.name);
    name(119, MNAMELEN_INO32, mnt.on.as_bytes());
    name(209, MNAMELEN_INO32, from.as_bytes());
    b
}

/// `gettimeofday(tp, tzp, mach_absolute_time)`: a 64-bit `timeval` (seconds,
/// then 32-bit microseconds), a zero timezone, and the absolute time taken
/// with it.
fn darwin_gettimeofday(m: &mut GuestMem<'_>, tp: u64, tzp: u64, abs: u64) -> Result<u64, Errno> {
    if tp != 0 {
        // clock_gettimeofday_and_absolute_time: the moment it read, which
        // the commpage's fast path extrapolates from for the next second.
        let tbr = super::mach::absolute_time();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let frac = (u128::from(now.subsec_nanos()) << 64) / 1_000_000_000;
        super::commpage::set_timestamp(m, tbr, now.as_secs(), frac as u64);
        let mut tv = [0u8; 16];
        tv[..8].copy_from_slice(&(now.as_secs() as i64).to_le_bytes());
        tv[8..12].copy_from_slice(&(now.subsec_micros() as i32).to_le_bytes());
        m.write(tp, &tv)?;
        if abs != 0 {
            m.write_u64(abs, tbr)?;
        }
    }
    if tzp != 0 {
        m.write(tzp, &[0u8; 8])?;
    }
    Ok(0)
}

/// `MAXPATHLEN`.
const MAXPATHLEN: usize = 1024;

/// `securelevel`: the system never raises it.
pub(crate) const DARWIN_SECURELEVEL: i32 = 0;

/// A sysctl's numbers, as `int`s.
fn oid_bytes(oid: &[i32]) -> Vec<u8> {
    oid.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// A sysctl request (`struct sysctl_req`): the caller's buffers and how far
/// each has been used.
pub(crate) struct SysctlReq {
    pub(crate) old: u64,
    pub(crate) oldlen: u64,
    pub(crate) oldidx: u64,
    new: u64,
    newlen: u64,
    newidx: u64,
}

impl SysctlReq {
    /// `SYSCTL_OUT` (`sysctl_old_user`): short of room, nothing is copied
    /// and nothing counted; without a buffer it only counts.
    fn out(&mut self, m: &mut GuestMem<'_>, bytes: &[u8]) -> Result<(), Errno> {
        if self.old != 0 {
            if self.oldlen - self.oldidx < bytes.len() as u64 {
                return Err(Errno::ENOMEM);
            }
            m.write(self.old + self.oldidx, bytes)?;
        }
        self.oldidx += bytes.len() as u64;
        Ok(())
    }

    /// `SYSCTL_IN` (`sysctl_new_user`): the next `n` bytes of the new value.
    fn input(&mut self, m: &mut GuestMem<'_>, n: usize) -> Result<Vec<u8>, Errno> {
        if self.new == 0 {
            return Ok(Vec::new());
        }
        if self.newlen - self.newidx < n as u64 {
            return Err(Errno::EINVAL);
        }
        let v = m.read(self.new + self.newidx, n)?.to_vec();
        self.newidx += n as u64;
        Ok(v)
    }

    /// `sysctl_io_number` of an `int`: the value out (4 bytes to a buffer
    /// of 4, the same 4 otherwise), and a new one in when there is one (a
    /// 64-bit one taken when it fits, ERANGE when it does not).
    fn io_int(&mut self, m: &mut GuestMem<'_>, cur: i32) -> Result<Option<i32>, Errno> {
        self.out(m, &cur.to_le_bytes())?;
        if self.new == 0 {
            return Ok(None);
        }
        if self.newlen == 8 {
            let b = self.input(m, 8)?;
            let big = i64::from_le_bytes(b[..8].try_into().expect("8 bytes"));
            return i32::try_from(big).map(Some).map_err(|_| Errno::ERANGE);
        }
        let b = self.input(m, 4)?;
        Ok(Some(i32::from_le_bytes(b[..4].try_into().expect("4 bytes"))))
    }

    /// `sysctl_io_string`: the value out (cut to the room there is when
    /// `trunc`), and any new one in, of less than `size` bytes.
    fn io_string(&mut self, m: &mut GuestMem<'_>, cur: &[u8], size: usize, trunc: bool) -> Result<Option<Vec<u8>>, Errno> {
        let mut bytes = cur.to_vec();
        bytes.push(0);
        if trunc && self.old != 0 && self.oldlen != 0 && self.oldlen < bytes.len() as u64 {
            self.out(m, &bytes[..self.oldlen as usize - 1])?;
            self.out(m, b"\0")?;
        } else {
            self.out(m, &bytes)?;
        }
        if self.new == 0 {
            return Ok(None);
        }
        if size == 0 {
            return Err(Errno::EPERM);
        }
        if self.newlen as usize >= size {
            return Err(Errno::EINVAL);
        }
        let mut v = self.input(m, self.newlen as usize)?;
        // What strlen sees after the terminator the kernel places.
        if let Some(i) = v.iter().position(|&b| b == 0) {
            v.truncate(i);
        }
        Ok(Some(v))
    }
}

impl Kernel {
    /// Answer a Darwin call that the renumbering in
    /// [`super::bsd::translate`] cannot, or `None` to leave it to that.
    /// The result is in the canonical encoding (`-errno` on failure).
    pub(crate) fn darwin_call(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Option<u64> {
        if let Some(r) = self.darwin_cred_syscall(m, raw, a) {
            return Some(res(r));
        }
        if let Some(r) = self.darwin_fs_call(m, raw, a) {
            return Some(res(r));
        }
        if raw == sys::REBOOT {
            return Some(res(self.darwin_reboot(m, a[0] as i32, a[1])));
        }
        if let Some(r) = self.darwin_fixed_call(raw, a) {
            return Some(res(r));
        }
        if let Some(r) = self.darwin_aio_call(m, raw, a) {
            return Some(res(r));
        }
        if let Some(r) = self.darwin_work_interval_call(m, raw, a) {
            return Some(res(r));
        }
        if let Some(r) = self.darwin_coalition_call(m, raw, a) {
            return Some(res(r));
        }
        if let Some(r) = self.darwin_psem_call(m, raw, a) {
            return Some(res(r));
        }
        if let Some(r) = self.darwin_filesec_call(m, raw, a) {
            return Some(res(r));
        }
        if let Some(e) = self.darwin_sb_socket_call(m, raw, a) {
            return Some(neg(e));
        }
        if let Some(e) = self.darwin_sock_refused(raw, a) {
            return Some(neg(e));
        }
        if let Some(r) = self.darwin_tcp_oob(m, raw, a) {
            return Some(res(r));
        }
        if let Some(r) = self.darwin_tcp_shutdown(raw, a) {
            return Some(res(r));
        }
        if let Some(write) = super::fsops::vectored(raw) {
            if let Err(e) = self.darwin_uio_check(m, write, a) {
                return Some(neg(e));
            }
        }
        if let Some(r) = self.darwin_inet6_call(m, raw, a) {
            return Some(res(r));
        }
        Some(match raw {
            // A unix socket's bind, which makes its name's socket file: its
            // record once made.
            sys::BIND if self.darwin_creation.is_some() => {
                let r = self.canonical(m, nr::BIND, *a);
                if let (Ok(_), Some(c)) = (&r, self.darwin_creation.take()) {
                    self.darwin_created(&c, None);
                }
                res(r)
            }
            sys::SHARED_REGION_CHECK_NP => res(self.darwin_shared_region_check_np(m, a[0])),
            sys::SHARED_REGION_MAP_AND_SLIDE_2_NP => res(self.darwin_shared_region_map_and_slide_2_np(m, a)),
            sys::MAP_WITH_LINKING_NP => res(self.darwin_map_with_linking(m, a)),
            sys::GETENTROPY => res(self.canonical(m, nr::GETRANDOM, [a[0], a[1], 0, 0, 0, 0]).map(|_| 0)),
            sys::GETHOSTUUID => res(self.darwin_gethostuuid(m, a)),
            sys::FCNTL | sys::FCNTL_NOCANCEL => self.darwin_fcntl(m, a),
            sys::FSGETPATH => res(self.darwin_fsgetpath(m, a)),
            sys::PROC_INFO => res(self.darwin_proc_info(m, a)),
            sys::PROC_INFO_EXTENDED_ID => res(self.darwin_proc_info_extended_id(m, a)),
            sys::FSGETPATH_EXT => res(self.darwin_fsgetpath_ext(m, a)),
            sys::PROCESS_POLICY => res(self.darwin_process_policy(m, a)),
            sys::MEMORYSTATUS_CONTROL => res(self.darwin_memorystatus_control(m, a)),
            sys::GETTIMEOFDAY => res(darwin_gettimeofday(m, a[0], a[1], a[2])),
            sys::GETRLIMIT => res(self.darwin_getrlimit(m, a[0], a[1])),
            sys::SETRLIMIT => res(self.darwin_setrlimit(m, a[0], a[1])),
            sys::MMAP => res(self.darwin_mmap(m, a)),
            sys::MADVISE => res(self.darwin_madvise(m, a)),
            sys::MSYNC | sys::MSYNC_NOCANCEL => res(self.darwin_msync(m, a)),
            // sync: VFS_SYNC of each writable mount (super::reboot).
            sys::SYNC => {
                self.darwin_sync();
                0
            }
            sys::IOPOLICYSYS => res(self.darwin_iopolicysys(m, a[0] as i32, a[1])),
            sys::FSYNC | sys::FSYNC_NOCANCEL | sys::FDATASYNC => res(self.darwin_fsync(m, a[0] as i32)),
            sys::MOUNT => res(self.darwin_mount(m, a)),
            sys::FMOUNT => res(self.darwin_fmount(m, a)),
            sys::GETXATTR => res(self.darwin_getxattr(m, false, a)),
            sys::FGETXATTR => res(self.darwin_getxattr(m, true, a)),
            sys::SETATTRLIST => res(self.darwin_setattrlist(m, a)),
            sys::FSETATTRLIST => res(self.darwin_fsetattrlist(m, a)),
            sys::SETATTRLISTAT => res(self.darwin_setattrlistat(m, a)),
            sys::SETXATTR => res(self.darwin_setxattr(m, false, a)),
            sys::FSETXATTR => res(self.darwin_setxattr(m, true, a)),
            sys::REMOVEXATTR => res(self.darwin_removexattr(m, false, a)),
            sys::FREMOVEXATTR => res(self.darwin_removexattr(m, true, a)),
            sys::LISTXATTR => res(self.darwin_listxattr(m, false, a)),
            sys::FLISTXATTR => res(self.darwin_listxattr(m, true, a)),
            sys::FILEPORT_MAKEPORT => res(self.darwin_fileport_makeport(m, a[0] as i32, a[1])),
            sys::FILEPORT_MAKEFD => res(self.darwin_fileport_makefd(a[0] as u32)),
            // kdebug_enable is off, so the events go nowhere (kdebug.c).
            sys::KDEBUG_TRACE | sys::KDEBUG_TRACE64 | sys::KDEBUG_TRACE_STRING => 0,
            sys::KDEBUG_TYPEFILTER => res(self.darwin_kdebug_typefilter(m, a[0], a[1])),
            sys::FSCTL => res(self.darwin_fsctl(m, a)),
            sys::GRAFTDMG => res(self.darwin_graftdmg(m, a)),
            sys::UNGRAFTDMG => res(self.darwin_ungraftdmg(m, a)),
            sys::PROC_RLIMIT_CONTROL => res(self.darwin_proc_rlimit_control(m, a)),
            sys::FFSCTL => res(self.darwin_ffsctl(m, a)),
            sys::GETRUSAGE => res(self.darwin_getrusage(m, a[0] as i32, a[1])),
            sys::THREAD_SELFUSAGE => res(self.darwin_thread_selfusage()),
            sys::MINHERIT => res(self.darwin_minherit(a)),
            // munmap and mprotect (`kern_mman.c`) are mach_vm_deallocate
            // and mach_vm_protect, with the address page aligned.
            sys::MUNMAP => {
                use super::mach::PAGE_MASK;
                if a[0] & PAGE_MASK != 0 || a[0].checked_add(a[1]).is_none() || a[1] == 0 {
                    return Some(neg(Errno::EINVAL));
                }
                match self.darwin_vm_deallocate(m, a[0], a[1]) {
                    0 => 0,
                    _ => neg(Errno::EINVAL),
                }
            }
            sys::MPROTECT => {
                use super::mach::{prot, PAGE_MASK};
                const VM_PROT_TRUSTED: u64 = 0x20;
                const VM_PROT_STRIP_READ: u64 = 0x80;
                let mut p = a[2] as u32 as u64 & (prot::ALL | VM_PROT_TRUSTED | VM_PROT_STRIP_READ);
                if a[0].checked_add(a[1]).is_none() || a[0] & PAGE_MASK != 0 {
                    return Some(neg(Errno::EINVAL));
                }
                if p & (prot::EXECUTE | prot::WRITE) != 0 {
                    p |= prot::READ;
                }
                // CONFIG_DYNAMIC_CODE_SIGNING is not in a RELEASE kernel.
                if p & VM_PROT_TRUSTED != 0 {
                    return Some(neg(Errno::EOPNOTSUPP));
                }
                // VM_PROT_STRIP_READ goes on to mach_vm_protect, which takes
                // no such bit.
                match self.vm_protect(m, a[0], a[1], false, p) {
                    0 => 0,
                    2 => neg(Errno::EACCES),
                    1 => neg(Errno::ENOMEM),
                    _ => neg(Errno::EINVAL),
                }
            }
            // No descriptor is a terminal to a Darwin process yet: stdio
            // buffers fully, and termios structures need not be converted.
            sys::IOCTL => res(self.darwin_ioctl(m, a)),
            sys::PERSONA => res(self.darwin_persona(m, a)),
            // thread_selfid: the calling thread's id (`thread_tid`).
            sys::THREAD_SELFID => self.signals.thread().darwin_id(),
            // gettid(uidp, gidp): a thread's own credentials, which only
            // settid gives it (settid is not served, so none has them).
            sys::GETTID => neg(Errno::ESRCH),
            // kill(pid, signum, posix): a process or a group as Linux's
            // kill reaches them, the signal renumbered. A broadcast is
            // killpg1's, which includes the caller only when posix is set.
            sys::KILL => {
                let (pid, signum, posix) = (a[0] as i32, a[1] as u32, a[2] as i32);
                if signum >= 32 {
                    neg(Errno::EINVAL)
                } else if signum != 0 && signal_to_linux(signum) == 0 {
                    self.darwin_unimplemented(format!("kill with Darwin signal {signum}, which Linux has no number for"));
                    neg(Errno::EINVAL)
                } else {
                    res(self.darwin_kill(pid, signum, posix != 0))
                }
            }
            sys::KQUEUE => res(<Kq as KQueue>::kqueue(self)),
            sys::PATHCONF => res(self.darwin_pathconf(m, a[0], a[1] as i32)),
            sys::FPATHCONF => res(self.darwin_fpathconf(a[0] as i32, a[1] as i32)),
            sys::FREADLINK => res(self.darwin_freadlink(m, a[0] as i32, a[1], a[2])),
            sys::GETDTABLESIZE => self.fds.limit() as u64,
            // CONFIG_AUDIT is not in an arm64 kernel: these are its stubs.
            sys::AUDIT | sys::AUDITON | sys::GETAUID | sys::SETAUID | sys::GETAUDIT_ADDR | sys::SETAUDIT_ADDR | sys::AUDITCTL | sys::AUDIT_SESSION_SELF | sys::AUDIT_SESSION_JOIN | sys::AUDIT_SESSION_PORT => neg(Errno::ENOSYS),
            sys::PTRACE => res(self.darwin_ptrace(a)),
            sys::PID_SUSPEND => res(self.darwin_pid_suspend(a[0] as i32)),
            sys::PID_RESUME => res(self.darwin_pid_resume(a[0] as i32)),
            sys::MEMORYSTATUS_AVAILABLE_MEMORY => res(self.darwin_available_memory(m)),
            sys::CLONEFILEAT => res(self.darwin_clonefileat(m, a)),
            sys::FCLONEFILEAT => res(self.darwin_fclonefileat(m, a)),
            sys::EXCHANGEDATA => res(self.darwin_exchangedata(m, a)),
            sys::PTHREAD_CHDIR => res(self.darwin_pthread_chdir(m, a[0])),
            sys::PTHREAD_FCHDIR => res(self.darwin_pthread_fchdir(m, a[0] as i32)),
            sys::MLOCK => res(self.darwin_mlock(a[0], a[1])),
            sys::MUNLOCK => res(self.darwin_munlock(a[0], a[1])),
            // mlockall and munlockall are unimplemented in the kernel.
            sys::MLOCKALL | sys::MUNLOCKALL => neg(Errno::ENOSYS),
            sys::GUARDED_KQUEUE_NP => res(self.darwin_guarded_kqueue(m, a)),
            sys::GUARDED_CLOSE_NP => res(self.darwin_guarded_close(m, a)),
            sys::CHANGE_FDGUARD_NP => res(self.darwin_change_fdguard(m, a)),
            sys::KQUEUE_WORKLOOP_CTL => {
                let r = <Kq as KQueue>::workloop_ctl(self, m, a);
                <Kq as KQueue>::settle(self, m);
                res(r)
            }
            sys::BSDTHREAD_REGISTER => res(self.darwin_bsdthread_register(m, a)),
            sys::PTHREAD_MARKCANCEL => res(self.darwin_markcancel(m, a[0] as u32)),
            sys::PTHREAD_CANCELED => res(self.darwin_canceled(a[0])),
            // A thread on its way out takes no more signals or cancels.
            sys::DISABLE_THREADSIGNAL => {
                let c = &mut self.dtask.threads.map.entry(self.tid).or_default().cancel;
                c.no_sigmask = true;
                c.disable = true;
                0
            }
            // QoS overrides and the like: no scheduler classes to apply.
            sys::BSDTHREAD_CTL => res(<Wq as WorkQueue>::bsdthread_ctl(self, m, a)),
            // A signal to a thread by its Mach port; signal 0 only asks
            // whether the thread is there.
            sys::PTHREAD_KILL => {
                let sig = signal_to_linux(a[1] as u32);
                let target = self.darwin_name_to_thread(a[0] as u32);
                let no_sigmask = target.is_some_and(|t| self.dtask.threads.map.get(&t).is_some_and(|d| d.cancel.no_sigmask));
                // A workqueue thread takes signals only if it allowed it, or
                // the process allowed some (BSDTHREAD_CTL_WORKQ_ALLOW_*).
                let workq_refuses = target.is_some_and(|t| self.darwin_workq_refuses_kill(t));
                match target {
                    Some(_) if (a[1] as u32) >= 32 => neg(Errno::EINVAL),
                    _ if no_sigmask => neg(Errno::ESRCH),
                    Some(_) if workq_refuses => neg(Errno::EOPNOTSUPP),
                    // SIGEMT and SIGINFO, which the signal machinery here
                    // has no number for (as kill says).
                    Some(_) if sig == 0 && a[1] as u32 != 0 => {
                        self.darwin_unimplemented(format!("__pthread_kill with Darwin signal {}, which Linux has no number for", a[1] as u32));
                        neg(Errno::EINVAL)
                    }
                    Some(_) if sig == 0 => 0,
                    Some(tid) => {
                        self.darwin_thread_reason(tid, a[1] as u32);
                        let r = self.canonical(m, nr::TGKILL, [self.pid as u64, tid as u64, u64::from(sig), 0, 0, 0]);
                        // psignal_uthread's record, for a target that takes it.
                        if r.is_ok() && self.thread_signals.get(tid).is_some_and(|t| t.blocked() & (1u64 << (sig - 1)) == 0) {
                            self.darwin_note_sender(sig, Some(crate::signal::Source { code: 0, pid: self.pid, uid: self.creds.uid() }));
                        }
                        if r.is_ok() {
                            self.darwin_psignal(tid, sig, true);
                        }
                        res(r)
                    }
                    None => neg(Errno::ESRCH),
                }
            }
            sys::SETITIMER => res(self.darwin_setitimer(m, a[0] as u32, a[1], a[2])),
            sys::GETITIMER => res(self.darwin_getitimer(m, a[0] as u32, a[1])),
            sys::PIPE => res(self.darwin_pipe(m)),
            sys::SIGPENDING => res(self.darwin_sigpending(m, a[0])),
            // Process groups and sessions: the same rules as Linux's, but
            // setpgid's target may be any descendant (inferior()) that has
            // not exec'd, where Linux's must be a child.
            sys::GETPGRP => res(self.canonical(m, nr::GETPGID, [0, 0, 0, 0, 0, 0])),
            sys::GETPGID => res(self.canonical(m, nr::GETPGID, [a[0] as i32 as i64 as u64, 0, 0, 0, 0, 0])),
            sys::GETSID => res(self.canonical(m, nr::GETSID, [a[0] as i32 as i64 as u64, 0, 0, 0, 0, 0])),
            sys::SETSID => res(self.canonical(m, nr::SETSID, [0; 6])),
            sys::SETPGID => res(self.procs.darwin_setpgid(self.pid, a[0] as i32, a[1] as i32).map(|()| 0)),
            // unlink(path) and unlinkat(fd, path, flag): Linux's unlinkat,
            // but a directory is EPERM (vn_authorize_unlink), and
            // AT_REMOVEDIR is rmdirat_internal.
            sys::UNLINK | sys::UNLINKAT => {
                const AT_REMOVEDIR: u64 = 0x80;
                const AT_REMOVEDIR_DATALESS: u64 = 0x100;
                const AT_SYMLINK_NOFOLLOW_ANY: u64 = 0x800;
                let (fd, path, flag) = if raw == sys::UNLINK { (super::bsd::dirfd(super::bsd::AT_FDCWD as u64), a[0], 0) } else { (super::bsd::dirfd(a[0]), a[1], a[2] as u32 as u64) };
                if flag & !(AT_REMOVEDIR | AT_REMOVEDIR_DATALESS | AT_SYMLINK_NOFOLLOW_ANY) != 0 {
                    neg(Errno::EINVAL)
                } else if flag & AT_REMOVEDIR_DATALESS != 0 {
                    self.darwin_unimplemented(format!("unlinkat flags {flag:#x} (dataless directories)"));
                    neg(Errno::EINVAL)
                } else if let Err(e) = if flag & AT_SYMLINK_NOFOLLOW_ANY != 0 { self.darwin_no_link_on_the_way(m, a[0], a[1]) } else { Ok(()) } {
                    // VNODE_REMOVE_NOFOLLOW_ANY: no link on the way.
                    neg(e)
                } else if flag & AT_REMOVEDIR != 0 {
                    res(self.canonical(m, nr::UNLINKAT, [fd, path, 0x200, 0, 0, 0]))
                } else {
                    match self.canonical(m, nr::UNLINKAT, [fd, path, 0, 0, 0, 0]) {
                        // unlinkat_internal: a mount point (VROOT) is EBUSY
                        // before a directory's EPERM.
                        Err(Errno::EISDIR) if self.path_io().at_path(m, fd as i32, path).is_ok_and(|p| self.vfs.is_mount_point(&p)) => neg(Errno::EBUSY),
                        Err(Errno::EISDIR) => neg(Errno::EPERM),
                        r => res(r),
                    }
                }
            }
            sys::STAT | sys::LSTAT | sys::FSTAT | sys::FSTATAT => res(self.darwin_stat_ino32(m, raw, a)),
            sys::FSTAT64 if self.darwin_pipe_of(a[0]).is_some() => res(self.darwin_pipe_stat(m, a[0], a[1])),
            sys::FSTAT64 if self.darwin_shm_fd(a[0]) => res(self.darwin_shm_stat(m, a[0], a[1])),
            sys::FSTATAT64 => res(self.darwin_fstatat64(m, a)),
            sys::FACCESSAT => res(self.darwin_faccessat(m, a)),
            sys::SIGACTION => res(self.darwin_sigaction(m, a[0], a[1], a[2])),
            sys::SIGALTSTACK => res(self.darwin_sigaltstack(m, a[0], a[1])),
            sys::GETFSSTAT64 => res(self.darwin_getfsstat(m, a[0], a[1], a[2] as u32)),
            sys::SHM_OPEN => res(self.darwin_shm_open(m, a)),
            sys::SHM_UNLINK => res(self.darwin_shm_unlink(m, a)),
            // An object takes one size and has no read or write; a mapping
            // of it is checked before it is made.
            sys::FTRUNCATE if self.darwin_shm_fd(a[0]) => res(self.darwin_shm_ftruncate(a)),
            sys::READ | sys::READ_NOCANCEL | sys::PREAD | sys::PREAD_NOCANCEL | sys::READV | sys::READV_NOCANCEL | sys::PREADV | sys::PREADV_NOCANCEL
                if self.darwin_shm_fd(a[0]) =>
            {
                neg(self.darwin_shm_io(a[0], false))
            }
            sys::WRITE | sys::WRITE_NOCANCEL | sys::PWRITE | sys::PWRITE_NOCANCEL | sys::WRITEV | sys::WRITEV_NOCANCEL | sys::PWRITEV | sys::PWRITEV_NOCANCEL
                if self.darwin_shm_fd(a[0]) =>
            {
                neg(self.darwin_shm_io(a[0], true))
            }
            sys::PREADV | sys::PREADV_NOCANCEL => res(self.darwin_prwv(m, false, a)),
            sys::PWRITEV | sys::PWRITEV_NOCANCEL => res(self.darwin_prwv(m, true, a)),
            // A family or an option this kernel has no Linux counterpart for
            // is refused where the caller is told, and said.
            // The unix domain's protocols are a stream and a datagram one,
            // of protocol 0 (socreate_internal's EPROTONOSUPPORT for any
            // other).
            sys::SOCKET | sys::SOCKETPAIR if a[0] == 1 && (!matches!(a[1], 1 | 2) || a[2] != 0) => neg(Errno::EPROTONOSUPPORT),
            sys::SOCKET | sys::SOCKETPAIR if !matches!(a[0], 0..=2) => {
                if super::sockaddr::family_exists(a[0]) {
                    self.darwin_unimplemented(format!("socket domain {} (AF_* of Darwin's bsd/sys/socket.h)", a[0]));
                }
                neg(Errno::EAFNOSUPPORT)
            }
            // lookup_validate_creation_path: a name made with a trailing
            // slash that is not to be a directory, where nothing is, is
            // ENOENT (Linux says ENOTDIR or EISDIR).
            // A bind the protocols might have shared, refused: said.
            sys::BIND => {
                let mut la = *a;
                let n = super::bsd::translate(raw, &mut la);
                let r = self.canonical(m, n, la);
                if r == Err(Errno::EADDRINUSE) {
                    self.darwin_bind_refused(a[0] as i32);
                }
                res(r)
            }
            // A connection the host carries with SO_KEEPALIVE asked for: the
            // probes are TCP's own, which the host's connection does not send.
            sys::CONNECT | sys::CONNECT_NOCANCEL if self.darwin_keepalive_off_host(m, a[0] as i32, a[1], a[2]) => {
                self.darwin_unimplemented("SO_KEEPALIVE on a TCP connection (TCPT_KEEP's probes and the peer's SO_FILT_HINT_KEEPALIVE)".into());
                neg(Errno::ENOPROTOOPT)
            }
            // The new connection takes SO_KEEPALIVE from its listener: one
            // the global kernel carries runs no TCP timers here.
            sys::ACCEPT | sys::ACCEPT_NOCANCEL if self.fds.get(a[0] as i32).ok().and_then(|f| f.handle.xnu_sockopts()).is_some_and(|o| o.options & super::sockopt::so::KEEPALIVE != 0) && self.darwin_sock_proto(a[0] as i32) == Some(super::sockerr::Proto::Tcp) && self.socket_of(a[0] as i32).is_ok_and(|s| !s.tcp_here()) => {
                self.darwin_unimplemented("accept from a TCP listener with SO_KEEPALIVE whose connections the global kernel carries (TCPT_KEEP's probes on the new connection)".into());
                return None;
            }
            sys::CONNECT | sys::CONNECT_NOCANCEL if self.darwin_async_off_host(m, a[0] as i32, a[1], a[2]) => {
                self.darwin_unimplemented("an SS_ASYNC socket's connection the host carries (its sowakeup's SIGIO)".into());
                return None;
            }
            // connectit for an internet socket: soconnectlock and the
            // protocol's connect here; a blocking call still connecting
            // then sleeps (`connect_wait`, the call's BlockOp::Connect),
            // and reports so_error when it wakes (`connect_waited`).
            sys::CONNECT | sys::CONNECT_NOCANCEL if let Ok(s) = self.socket_of(a[0] as i32) => {
                let (ip, port) = match self.fd_io().inet_addr(m, a[1], a[2]) {
                    Ok(v) => v,
                    Err(e) => return Some(neg(e)),
                };
                // SS_NBIO: the descriptor's FNONBLOCK (fcntl and FIONBIO
                // set both).
                let nbio = self.fds.get(a[0] as i32).is_ok_and(|f| f.flags() & crate::fs::oflags::O_NONBLOCK != 0);
                let r = s.xnu_connect(ip, port, nbio);
                // The new connection's timers, for the thread calls.
                self.dtask.timers.bell().ring();
                match r {
                    crate::net::XnuConnect::Done(r) => res(r.map(|()| 0)),
                    crate::net::XnuConnect::Wait => {
                        self.dtask.connect_wait = Some(s);
                        return None;
                    }
                    crate::net::XnuConnect::Unmodelled(what) => {
                        self.darwin_unimplemented(what.into());
                        neg(Errno::EOPNOTSUPP)
                    }
                }
            }
            // A datagram to the limited broadcast address: delivery to an
            // interface's broadcast domain is not modelled.
            sys::SENDTO | sys::SENDTO_NOCANCEL if super::sockopt::is_broadcast(m, a[4], a[5]) => {
                self.darwin_unimplemented("a datagram to the broadcast address (INADDR_BROADCAST)".into());
                neg(Errno::EACCES)
            }
            // Control on a unix datagram socket: its descriptors are not
            // carried (unp_internalize for SOCK_DGRAM).
            sys::SENDMSG | sys::SENDMSG_NOCANCEL if self.darwin_dgram_control(m, a[0], a[1]) => {
                self.darwin_unimplemented("a control message on a unix datagram socket (its descriptors, unp_internalize)".into());
                neg(Errno::EOPNOTSUPP)
            }
            sys::SENDTO | sys::SENDTO_NOCANCEL | sys::RECVFROM | sys::RECVFROM_NOCANCEL | sys::SENDMSG | sys::SENDMSG_NOCANCEL | sys::RECVMSG | sys::RECVMSG_NOCANCEL
                if super::sockaddr::msg_flags_unported(if matches!(raw, sys::SENDMSG | sys::SENDMSG_NOCANCEL | sys::RECVMSG | sys::RECVMSG_NOCANCEL) { a[2] } else { a[3] }).is_some() =>
            {
                let f = if matches!(raw, sys::SENDMSG | sys::SENDMSG_NOCANCEL | sys::RECVMSG | sys::RECVMSG_NOCANCEL) { a[2] } else { a[3] };
                let name = super::sockaddr::msg_flags_unported(f).unwrap_or_default();
                self.darwin_unimplemented(format!("socket message flag {name}"));
                neg(Errno::EOPNOTSUPP)
            }
            sys::SETSOCKOPT if let Some(r) = self.darwin_setsockopt(m, a) => res(r),
            sys::GETSOCKOPT if let Some(r) = self.darwin_getsockopt(m, a) => res(r),
            sys::SETSOCKOPT | sys::GETSOCKOPT => match super::sockaddr::sockopt_to_linux(a[1], a[2]) {
                Ok(_) => return None,
                Err(what) => {
                    self.darwin_unimplemented(format!("{} {what}", if raw == sys::SETSOCKOPT { "setsockopt" } else { "getsockopt" }));
                    neg(Errno::ENOPROTOOPT)
                }
            },
            sys::GETATTRLIST => res(self.darwin_getattrlist(m, a)),
            sys::FGETATTRLIST => res(self.darwin_fgetattrlist(m, a)),
            sys::GETATTRLISTAT => res(self.darwin_getattrlistat(m, a)),
            sys::GETATTRLISTBULK => res(self.darwin_getattrlistbulk(m, a)),
            sys::STATFS64 => res(self.darwin_statfs(m, Some(a[0]), 0, a[1])),
            sys::FSTATFS64 => res(self.darwin_statfs(m, None, a[0], a[1])),
            sys::STATFS => res(self.darwin_statfs_ino32(m, Some(a[0]), 0, a[1])),
            sys::FSTATFS => res(self.darwin_statfs_ino32(m, None, a[0], a[1])),
            sys::GETFSSTAT => res(self.darwin_getfsstat_ino32(m, a[0], a[1], 0, 0, a[2] as u32)),
            sys::MAC_GETFSSTAT => res(self.darwin_getfsstat_ino32(m, a[0], a[1], a[2], a[3], a[4] as u32)),
            sys::SYSCTL => res(self.darwin_sysctl(m, a)),
            sys::SYSCTLBYNAME => res(self.darwin_sysctlbyname(m, a)),
            // dup3 refuses to copy a descriptor onto itself; dup2 checks it
            // is open and returns it.
            sys::DUP2 if a[0] == a[1] => match self.canonical(m, nr::FCNTL, [a[0], 1, 0, 0, 0, 0]) {
                Ok(_) => a[1],
                Err(e) => neg(e),
            },
            sys::DUP2 => {
                // The descriptor it replaces is closed (closef_locked).
                if self.fds.get(a[0] as i32).is_ok() {
                    self.darwin_closing(a[1] as i32);
                }
                res(self.canonical(m, nr::DUP3, [a[0], a[1], 0, 0, 0, 0]))
            }
            sys::CLOSE | sys::CLOSE_NOCANCEL if self.dtask.ladvlock => {
                self.darwin_closing(a[0] as i32);
                return None;
            }
            sys::SIGPROCMASK | sys::PTHREAD_SIGMASK => res(self.darwin_sigprocmask(m, a[0], a[1], a[2], raw == sys::SIGPROCMASK)),
            sys::TASK_READ_FOR_PID => res(self.darwin_task_flavor_for_pid(m, a[0] as u32, a[1] as i32, a[2], super::amfi::flavor::READ)),
            sys::TASK_INSPECT_FOR_PID => res(self.darwin_task_flavor_for_pid(m, a[0] as u32, a[1] as i32, a[2], super::amfi::flavor::INSPECT)),
            sys::CSOPS => res(self.darwin_csops(m, a[0] as i32, a[1] as u32, a[2], a[3], None)),
            // csops_audittoken: a null token is EINVAL.
            sys::CSOPS_AUDITTOKEN if a[4] == 0 => res(Err(Errno::EINVAL)),
            sys::CSOPS_AUDITTOKEN => res(self.darwin_csops(m, a[0] as i32, a[1] as u32, a[2], a[3], Some(a[4]))),
            sys::MAC_SYSCALL => res(self.darwin_mac_syscall(m, a[0], a[1], a[2])),
            // abort_with_payload: the call itself always returns 0.
            sys::ABORT_WITH_PAYLOAD => {
                let _ = self.darwin_abort_with_payload(m, a);
                0
            }
            sys::TERMINATE_WITH_PAYLOAD => {
                // The seventh argument, reason_flags, is in x6.
                let flags = m.read_u64(self.ctx_addr + gex_abi::ctx::x(6) as u64).unwrap_or(0);
                res(self.darwin_terminate_with_payload(m, a, flags))
            }
            _ => return None,
        })
    }

    fn darwin_fcntl(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> u64 {
        let fd = a[0];
        let canon = |k: &mut Kernel, m: &mut GuestMem<'_>, cmd: u64, arg: u64| res(k.canonical(m, nr::FCNTL, [fd, cmd, arg, 0, 0, 0]));
        match a[1] {
            // F_DUPFD, F_GETFD, F_SETFD: the same on both sides.
            c @ 0..=2 => canon(self, m, c, a[2]),
            f::GETFL => res(self.darwin_getfl(fd as i32)),
            f::SETFL => res(self.darwin_setfl(fd as i32, a[2])),
            f::GETOWN => res(self.fds.get(fd as i32).and_then(|file| self.darwin_getown(&file)).map(|v| v as u32 as u64)),
            f::SETOWN => res(self.fds.get(fd as i32).and_then(|file| self.darwin_setown(m, &file, a[2] as i32))),
            f::DUPFD_CLOEXEC => canon(self, m, 1030, a[2]),
            f::GETPATH => {
                let path = self.fds.list().into_iter().find(|&(n, _)| n as u64 == fd).map(|(_, p)| p);
                match path {
                    Some(p) if p.len() < MAXPATHLEN => {
                        let mut b = p.into_bytes();
                        b.push(0);
                        res(m.write(a[2], &b).map(|_| 0))
                    }
                    Some(_) => neg(Errno::ENAMETOOLONG),
                    None => neg(Errno::EBADF),
                }
            }
            // A signature covering the whole file: fs_file_start, the end
            // of what the signature covers, is the largest offset.
            f::ADDSIGS | f::ADDFILESIGS | f::ADDFILESIGS_RETURN => res(self.darwin_addsigs(m, fd as i32, a[1], a[2])),
            f::CHECK_LV => res(self.darwin_check_lv(m, fd as i32, a[2])),
            // The simulator's form, and the form that also returns the
            // cdhash (a SHA digest of the CodeDirectory).
            f::ADDFILESIGS_FOR_DYLD_SIM | f::ADDFILESIGS_INFO => {
                self.darwin_unimplemented(format!("fcntl {} (F_ADDFILESIGS_FOR_DYLD_SIM, F_ADDFILESIGS_INFO)", a[1]));
                neg(Errno::EINVAL)
            }
            f::NOCACHE | f::RDAHEAD | f::NODIRECT | f::SINGLE_WRITER | f::RDADVISE | f::FULLFSYNC | f::BARRIERFSYNC | f::PREALLOCATE | f::SPECULATIVE_READ | f::GETPROTECTIONCLASS | f::SETPROTECTIONCLASS => {
                res(self.darwin_fcntl_vnode(m, fd as i32, a[1], a[2]))
            }
            // FG_NOSIGPIPE on the open file; a socket's is its SO_NOSIGPIPE.
            f::SETNOSIGPIPE | f::GETNOSIGPIPE => match self.fds.get(fd as i32) {
                Err(e) => neg(e),
                // sock_setsockopt and sock_getsockopt of SO_NOSIGPIPE, the
                // argument cut to an int.
                Ok(file) if file.handle.metadata().is_ok_and(|md| md.file_type == crate::vfs::FileType::Socket) => {
                    if a[1] == f::SETNOSIGPIPE {
                        res(self.darwin_so_set_nosigpipe(fd as i32, a[2] as i32 != 0).map(|()| 0))
                    } else {
                        u64::from(self.darwin_so_nosigpipe(fd as i32))
                    }
                }
                Ok(file) => {
                    use std::sync::atomic::Ordering::AcqRel;
                    let bit = super::pipe::FG_NOSIGPIPE;
                    if a[1] == f::SETNOSIGPIPE {
                        if a[2] as i32 != 0 {
                            file.darwin_lflags.fetch_or(bit, AcqRel);
                        } else {
                            file.darwin_lflags.fetch_and(!bit, AcqRel);
                        }
                        0
                    } else {
                        u64::from(file.darwin_lflags.load(std::sync::atomic::Ordering::Acquire) & bit != 0)
                    }
                }
            },
            c => res(self.darwin_fcntl_other(fd as i32, c as u32)),
        }
    }

    /// A command `darwin_fcntl` does not serve: one XNU's switch does is
    /// reported; any other goes down as an ioctl of the vnode, where the
    /// answers were measured on APFS and of a device.
    fn darwin_fcntl_other(&mut self, fd: i32, c: u32) -> Result<u64, Errno> {
        const IOC_VOID: u32 = 0x2000_0000;
        const IOC_INOUT: u32 = 0xc000_0000;
        const F_FREEZE_FS: u32 = 53;
        const F_THAW_FS: u32 = 54;
        const SERVED: &[u32] = &[40, 41, 43, 49, 52, 55, 56, 57, 58, 60, 65, 66, 68, 69, 70, 71, 72, 75, 77, 78, 79, 80, 81, 82, 84, 90, 91, 92, 93, 94, 95, 96, 99, 100, 102, 104, 105, 106, 107, 108, 109, 110, 111];
        if SERVED.contains(&c) {
            self.darwin_unimplemented(format!("fcntl {c} (bsd/sys/fcntl.h)"));
            return Err(Errno::EINVAL);
        }
        if c & IOC_VOID != 0 && c & IOC_INOUT != 0 {
            return Err(Errno::EINVAL);
        }
        if c & (IOC_VOID | IOC_INOUT) != 0 {
            self.darwin_unimplemented(format!("fcntl {c:#x} (an ioctl of the vnode)"));
            return Err(Errno::EINVAL);
        }
        let file = self.fds.get(fd)?;
        if self.darwin_vnode_of(&file).is_none() || file.handle.metadata().is_ok_and(|md| md.file_type == crate::vfs::FileType::Socket) {
            return Err(Errno::EBADF);
        }
        if let Some(r) = self.darwin_tty_vnop_ioctl(fd, c) {
            return r;
        }
        // APFS's VNOP_IOCTL ([`super::fsfreeze`]).
        let mnt = super::kern::mount_of_file(&file);
        if matches!(c, F_FREEZE_FS | F_THAW_FS) && mnt.fs == Fs::Apfs {
            let procs = std::sync::Arc::clone(&self.procs);
            return match super::fsfreeze::ioctl(mnt, c == F_THAW_FS, self.pid, self.dtask.cred.uid, &|p| procs.alive(p)) {
                Ok(()) => Ok(0),
                Err(super::fsfreeze::Refused::Errno(e)) => Err(e),
                Err(super::fsfreeze::Refused::Unmodelled(why)) => {
                    self.darwin_unimplemented(why);
                    Err(Errno::EINTR)
                }
            };
        }
        if file.is_tty() {
            self.darwin_unimplemented(format!("fcntl {c} of a terminal that is not a Darwin one"));
            return Err(Errno::EINVAL);
        }
        match file.metadata()?.file_type {
            crate::vfs::FileType::CharDevice => Err(Errno::ENODEV),
            _ => Err(Errno::ENOTTY),
        }
    }

    /// `stat`, `lstat`, `fstat` and `fstatat`: their `64` forms' lookup
    /// (`fstatat_internal`, `fstat1` with `isstat64` 0), the `struct stat`
    /// written the one with a 32-bit inode number.
    fn darwin_stat_ino32(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Result<u64, Errno> {
        let wide = match raw {
            sys::STAT => sys::STAT64,
            sys::LSTAT => sys::LSTAT64,
            sys::FSTAT => sys::FSTAT64,
            _ => sys::FSTATAT64,
        };
        self.darwin_stat_ino32 = true;
        let r = self.darwin_plain_call(m, wide, *a);
        self.darwin_stat_ino32 = false;
        r
    }

    /// `proc_info(callnum, pid, flavor, arg, buffer, buffersize)`.
    /// `fstatat64(fd, path, ub, flag)`: its flags checked; AT_FDONLY
    /// stats the descriptor (a vnode's: ENOTSUP for any other); with
    /// AT_SYMLINK_NOFOLLOW_ANY no link on the way, the last not followed.
    fn darwin_fstatat64(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        const AT_SYMLINK_NOFOLLOW: u64 = 0x20;
        const AT_REALDEV: u64 = 0x200;
        const AT_FDONLY: u64 = 0x400;
        const AT_SYMLINK_NOFOLLOW_ANY: u64 = 0x800;
        let flag = a[3] as u32 as u64;
        if flag & !(AT_SYMLINK_NOFOLLOW | AT_REALDEV | AT_FDONLY | AT_SYMLINK_NOFOLLOW_ANY) != 0 {
            return Err(Errno::EINVAL);
        }
        // AT_REALDEV (VA_REALFSID): the device is the vnode's mount's
        // f_fsid.val[0], which every stat here reports (no filesystem here
        // gives one of its own with VA_USEFSID).
        if flag & AT_FDONLY != 0 {
            // fp_getfvp: a vnode's descriptor.
            let file = self.fds.get(a[0] as i32)?;
            let h = &file.handle;
            if h.pipe_end().is_some() || std::sync::Arc::clone(h).as_kqueue().is_some() || std::sync::Arc::clone(h).as_posix_shm().is_some() || h.metadata().is_ok_and(|md| md.file_type == crate::vfs::FileType::Socket) {
                return Err(super::errno::errno_of(45));
            }
            return self.canonical(m, nr::FSTAT, [a[0], a[2], 0, 0, 0, 0]);
        }
        if flag & AT_SYMLINK_NOFOLLOW_ANY != 0 {
            self.darwin_no_link_on_the_way(m, a[0], a[1])?;
        }
        let nofollow = if flag & (AT_SYMLINK_NOFOLLOW | AT_SYMLINK_NOFOLLOW_ANY) != 0 { 0x100 } else { 0 };
        self.canonical(m, nr::NEWFSTATAT, [super::bsd::dirfd(a[0]), a[1], a[2], nofollow, 0, 0])
    }

    /// `faccessat(fd, path, amode, flag)`: its flags checked; with
    /// AT_SYMLINK_NOFOLLOW_ANY no link on the way, the last not followed.
    /// What the mode asks was authorized with Sandbox's check
    /// (`darwin_sb_access_call`): the lookup is what is left to fail.
    fn darwin_faccessat(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        const AT_EACCESS: u64 = 0x10;
        const AT_SYMLINK_NOFOLLOW: u64 = 0x20;
        const AT_SYMLINK_NOFOLLOW_ANY: u64 = 0x800;
        let flag = a[3] as u32 as u64;
        if flag & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_SYMLINK_NOFOLLOW_ANY) != 0 {
            return Err(Errno::EINVAL);
        }
        if flag & AT_SYMLINK_NOFOLLOW_ANY != 0 {
            self.darwin_no_link_on_the_way(m, a[0], a[1])?;
        }
        let mut f = flag & !AT_SYMLINK_NOFOLLOW_ANY;
        if flag & AT_SYMLINK_NOFOLLOW_ANY != 0 {
            f |= AT_SYMLINK_NOFOLLOW;
        }
        self.canonical(m, nr::FACCESSAT, [super::bsd::dirfd(a[0]), a[1], 0, super::bsd::at_flags(f), 0, 0])
    }

    /// `kill(pid, signum, posix)`: one process (a zombie succeeds unsignalled),
    /// EPERM unless the caller may signal it; a broadcast (-1), the caller's
    /// group (0) or another group (`killpg1`).
    fn darwin_kill(&mut self, pid: i32, signum: u32, posix: bool) -> Result<u64, Errno> {
        if pid > 0 {
            // proc_find, else pzfind.
            match self.procs.listing().into_iter().find(|e| e.0 == pid) {
                None => return Err(Errno::ESRCH),
                Some((_, _, _, true)) => return Ok(0),
                Some(_) => {}
            }
            if !self.darwin_cansignal(pid, signum, true) {
                return Err(Errno::EPERM);
            }
            if signum != 0 {
                self.darwin_kill_post(pid, signum);
            }
            return Ok(0);
        }
        match pid {
            -1 => self.darwin_killpg1_all(signum, posix),
            0 => {
                let pgid = self.procs.pgid(self.pid, self.pid)?;
                self.darwin_killpg1_group(signum, pgid, posix)
            }
            _ => {
                // pgrp_find: a group with members.
                if self.procs.pgrp_members(-pid).is_empty() {
                    return Err(Errno::ESRCH);
                }
                self.darwin_killpg1_group(signum, -pid, posix)
            }
        }
    }

    /// `psignal(p, signum)` from this process: the signal and the reason it
    /// carries (`build_signal_reason`), then any of it for this process
    /// collected, as `kill` leaves it pending before it returns.
    pub(crate) fn darwin_kill_post(&mut self, pid: i32, signum: u32) {
        let note = self.darwin_signal_reason(signum);
        let _ = self.procs.kill_noted(self.pid, pid, signal_to_linux(signum), Some(note));
        self.signals.process().collect(&self.procs, self.pid, self.creds.uid());
    }

    /// `killpg1` broadcasting (kill's pid -1): every process past init
    /// (none is a system process here), the caller only under POSIX
    /// semantics, that the caller may signal (`cansignal`; for a zombie,
    /// which counts as found but is not signalled, `cansignal_nomac`).
    /// EPERM (POSIX) or ESRCH when none was.
    fn darwin_killpg1_all(&mut self, signum: u32, posix: bool) -> Result<u64, Errno> {
        let mut nfound = 0;
        for (pid, _, _, zombie) in self.procs.listing() {
            if pid <= 1 || (!posix && pid == self.pid) {
                continue;
            }
            if zombie {
                if self.darwin_cansignal(pid, signum, false) {
                    nfound += 1;
                }
            } else if self.darwin_cansignal(pid, signum, true) {
                nfound += 1;
                if signum != 0 {
                    self.darwin_kill_post(pid, signum);
                }
            }
        }
        match nfound {
            0 if posix => Err(Errno::EPERM),
            0 => Err(Errno::ESRCH),
            _ => Ok(0),
        }
    }

    /// `killpg1` of group `pgid`: each live member but the kernel's and
    /// init (none is a system process here) that the caller may signal.
    /// EPERM (POSIX) or ESRCH when none was.
    fn darwin_killpg1_group(&mut self, signum: u32, pgid: i32, posix: bool) -> Result<u64, Errno> {
        let mut nfound = 0;
        for (pid, _, _, live) in self.procs.pgrp_members(pgid) {
            if pid <= 1 || !live {
                continue;
            }
            if self.darwin_cansignal(pid, signum, true) {
                nfound += 1;
                if signum != 0 {
                    self.darwin_kill_post(pid, signum);
                }
            }
        }
        match nfound {
            0 if posix => Err(Errno::EPERM),
            0 => Err(Errno::ESRCH),
            _ => Ok(0),
        }
    }

    /// `cansignal` (`mac`: the policies' `mac_proc_check_signal` first) or
    /// `cansignal_nomac`: whether this process may send `signum` to process
    /// `pid`. Itself; never SIGKILL to init; root anything; SIGCONT within
    /// its session; a third-party debuggable driver (iOS); else a real or
    /// effective uid of the caller's that is the target's real or saved.
    pub(crate) fn darwin_cansignal(&mut self, pid: i32, signum: u32, mac: bool) -> bool {
        use super::signal::dsig;
        if mac && self.darwin_mac_check_signal(pid, signum) != 0 {
            return false;
        }
        if pid == self.pid {
            return true;
        }
        if signum == dsig::SIGKILL && pid == crate::proc::INIT_PID {
            return false;
        }
        let (ruid, uid) = (self.dtask.cred.ruid, self.dtask.cred.uid);
        if uid == 0 {
            return true;
        }
        if signum == dsig::SIGCONT && self.procs.sid(self.pid, self.pid).ok() == self.procs.sid(self.pid, pid).ok() {
            return true;
        }
        if self.darwin_third_party_debuggable_driver(pid) {
            return true;
        }
        let Some((dst, _)) = self.darwin_public(pid) else { return false };
        let d = &dst.cred;
        ruid == d.ruid || ruid == d.svuid || uid == d.ruid || uid == d.svuid
    }

    /// `fsgetpath(buf, size, fsid, objid)`: the path of a file named by its
    /// filesystem and object ids: a volume's root, the shared cache, the
    /// task's images, and a file the root filesystem finds by number (an
    /// overlay's, `OverlayFs`); the root's other files are looked up by
    /// name only, and reported.
    fn darwin_fsgetpath(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        const FSGETPATH_MAXBUFLEN: u64 = 8192;
        const ROOT_OBJID: u64 = 2;
        if a[1] > FSGETPATH_MAXBUFLEN || a[1] == 0 {
            return Err(Errno::EINVAL);
        }
        let fs = u64::from(m.read_u32(a[2])?) | u64::from(m.read_u32(a[2] + 4)?) << 32;
        // mount_lookupby_volfsid, by the first half.
        let Some(mnt) = mounts().into_iter().find(|mnt| mnt.fsid as u32 == fs as u32) else {
            return Err(Errno::EOPNOTSUPP);
        };
        let image = self.dtask.image_files.iter().find(|f| (f.0, f.1) == (fs, a[3])).map(|f| f.2.clone());
        let path = if a[3] == ROOT_OBJID {
            mnt.on.to_string()
        } else if let Some(path) = super::shregion::file_path(fs as u32, a[3]) {
            path
        } else if let Some(path) = image {
            path
        } else if let Some(path) = self.vfs.root_path_of_ino(a[3]).filter(|p| mount_of(p).fsid as u32 == fs as u32) {
            path
        } else {
            self.darwin_unimplemented(format!("fsgetpath of object {:#x} (VFS_VGET: the filesystems here look files up by name only)", a[3]));
            return Err(Errno::ENOENT);
        };
        // fsgetpath_internal's MAC check of the vnode found.
        let md = self.vfs.metadata_nofollow(&path)?;
        let e = self.darwin_mac_check_vnode_fsgetpath(super::macvfs::sb_vnode(&path, &md));
        if e != 0 {
            return Err(super::errno::errno_of(e as i32));
        }
        let mut b = path.as_bytes().to_vec();
        b.push(0);
        if (a[1] as usize) < b.len() {
            return Err(Errno::ENOSPC);
        }
        m.write(a[0], &b)?;
        Ok(b.len() as u64)
    }

    /// `fsgetpath_ext(buf, bufsize, fsid, objid, options)`: there are no
    /// firmlinks to leave out of a path, and the file system's own ID is the
    /// one its path is found by.
    fn darwin_fsgetpath_ext(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        const FSOPT_NOFIRMLINKPATH: u64 = 0x80;
        const FSOPT_ISREALFSID: u64 = 0x200;
        if a[4] as u32 as u64 & !(FSOPT_NOFIRMLINKPATH | FSOPT_ISREALFSID) != 0 {
            return Err(Errno::EINVAL);
        }
        self.darwin_fsgetpath(m, a)
    }

    /// `proc_info_extended_id(callnum, pid, flavor, flags, ext_id, arg,
    /// buffer, buffersize)`.
    fn darwin_proc_info_extended_id(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        const PIF_COMPARE_IDVERSION: u64 = 1;
        const PIF_COMPARE_UNIQUEID: u64 = 2;
        let flags = a[3] as u32 as u64;
        if flags & (PIF_COMPARE_IDVERSION | PIF_COMPARE_UNIQUEID) == PIF_COMPARE_IDVERSION | PIF_COMPARE_UNIQUEID {
            return Err(Errno::EINVAL);
        }
        if flags != 0 {
            self.darwin_unimplemented(format!("proc_info_extended_id with flags {flags:#x} (comparing the process's identity)"));
            return Err(Errno::EINVAL);
        }
        let buffer = m.read_u64(self.ctx_addr + gex_abi::ctx::x(6) as u64)?;
        let size = m.read_u64(self.ctx_addr + gex_abi::ctx::x(7) as u64)?;
        self.darwin_proc_info(m, &[a[0], a[1], a[2], a[5], buffer, size])
    }

    /// `getfsstat64(buf, bufsize, flags)`: the mounts, or how many there
    /// are when `buf` is null. Each mount copied out has its counts
    /// refreshed first ([`getfsstat_refreshes`]); `mac_mount_check_stat`
    /// has no hook in Sandbox (slot 90 is null) or AMFI.
    fn darwin_getfsstat(&mut self, m: &mut GuestMem<'_>, buf: u64, size: u64, flags: u32) -> Result<u64, Errno> {
        let mounts = mounts();
        if buf == 0 {
            return Ok(mounts.len() as u64);
        }
        let n = (size as usize / STATFS64_SIZE).min(mounts.len());
        for (i, mnt) in mounts.iter().take(n).enumerate() {
            let refresh = getfsstat_refreshes(mnt, flags);
            m.write(buf + (i * STATFS64_SIZE) as u64, &statfs64(mnt, refresh))?;
        }
        Ok(n as u64)
    }

    /// The mount `statfs64` and `statfs` find: that of the vnode the path
    /// names (`namei`, FOLLOW), or of the descriptor's for `fstatfs64` and
    /// `fstatfs` (`file_vnode`: EINVAL for what is no vnode).
    fn darwin_statfs_mount(&mut self, m: &GuestMem<'_>, path: Option<u64>, fd: u64) -> Result<&'static Mount, Errno> {
        let canon = match path {
            Some(at) => {
                let mut b = [0u8; MAXPATHLEN];
                let n = m.read_cstr_into(at, &mut b)?.ok_or(Errno::ENAMETOOLONG)?;
                let given = std::str::from_utf8(&b[..n]).map_err(|_| Errno::EINVAL)?;
                let abs = self.path_io().at_path_str(super::bsd::dirfd(super::bsd::AT_FDCWD as u64) as i32, given)?;
                self.vfs.metadata(&abs)?;
                self.vfs.canonical(&abs)
            }
            None => {
                let file = self.fds.get(fd as i32)?;
                if self.darwin_vnode_of(&file).is_none() || std::sync::Arc::clone(&file.handle).as_posix_sem().is_some() {
                    return Err(Errno::EINVAL);
                }
                return Ok(mount_of_seen(&file.path, file.darwin_mounts_seen));
            }
        };
        Ok(mount_of(&canon))
    }

    /// `statfs64(path, buf)` or `fstatfs64(fd, buf)`.
    fn darwin_statfs(&mut self, m: &mut GuestMem<'_>, path: Option<u64>, fd: u64, buf: u64) -> Result<u64, Errno> {
        let mnt = self.darwin_statfs_mount(m, path, fd)?;
        m.write(buf, &statfs64(mnt, true))?;
        Ok(0)
    }

    /// `statfs(path, buf)` or `fstatfs(fd, buf)` (`statfs_internal`): the
    /// struct of 32-bit inodes, but for its last reserved fields.
    fn darwin_statfs_ino32(&mut self, m: &mut GuestMem<'_>, path: Option<u64>, fd: u64, buf: u64) -> Result<u64, Errno> {
        let mnt = self.darwin_statfs_mount(m, path, fd)?;
        m.write(buf, &statfs_ino32(mnt, true)[..STATFS_PARTIAL])?;
        Ok(0)
    }

    /// `__mac_getfsstat(buf, bufsize, mac, macsize, flags)`, and `getfsstat`
    /// with no labels: a whole struct of 32-bit inodes for each mount there
    /// is room for, and the count of them all with no buffer. A mount's MAC
    /// label is reported.
    fn darwin_getfsstat_ino32(&mut self, m: &mut GuestMem<'_>, buf: u64, bufsize: u64, mac: u64, macsize: u64, flags: u32) -> Result<u64, Errno> {
        let (bufsize, macsize) = (bufsize as u32, macsize as u32);
        if bufsize > i32::MAX as u32 || macsize > i32::MAX as u32 {
            return Err(Errno::EINVAL);
        }
        let maxcount = bufsize as usize / STATFS_SIZE;
        if mac != 0 {
            if macsize as usize / 8 != maxcount {
                return Err(Errno::EINVAL);
            }
            m.read(mac, macsize as usize)?;
            if buf != 0 && maxcount > 0 {
                self.darwin_unimplemented("__mac_getfsstat with labels (mac_mount_label_get)".into());
                return Err(Errno::EINVAL);
            }
        }
        let mounts = mounts();
        if buf == 0 {
            return Ok(mounts.len() as u64);
        }
        let n = maxcount.min(mounts.len());
        for (i, mnt) in mounts.iter().take(n).enumerate() {
            m.write(buf + (i * STATFS_SIZE) as u64, &statfs_ino32(mnt, getfsstat_refreshes(mnt, flags)))?;
        }
        Ok(n as u64)
    }

    /// `sysctl(name, namelen, old, oldlenp, new, newlen)`. A write to a node
    /// whose value is only read here is reported.
    fn darwin_sysctl(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let n = a[1] as usize;
        if !(2..=sysctl::CTL_MAXNAME).contains(&n) {
            return Err(Errno::EINVAL);
        }
        let mut oid = Vec::with_capacity(n);
        for i in 0..n {
            oid.push(m.read_u32(a[0] + 4 * i as u64)? as i32);
        }
        self.darwin_sysctl_req(m, None, oid, a)
    }

    /// `sysctlbyname(name, namelen, old, oldlenp, new, newlen)`.
    fn darwin_sysctlbyname(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let len = a[1] as usize;
        if len >= MAXPATHLEN {
            return Err(Errno::ENAMETOOLONG);
        }
        let name = String::from_utf8_lossy(m.read(a[0], len)?).trim_end_matches('\0').to_string();
        self.darwin_sysctl_req(m, Some(name), Vec::new(), a)
    }

    /// What `sysctl` and `sysctlbyname` share (`userland_sysctl`): the
    /// request, its error (ENOMEM still reports the size), the size out.
    fn darwin_sysctl_req(&mut self, m: &mut GuestMem<'_>, name: Option<String>, oid: Vec<i32>, a: &[u64; 6]) -> Result<u64, Errno> {
        // fuulong: an address that faults reads as all ones, and the write
        // at the end fails it.
        let oldlen = if a[3] != 0 { m.read_u64(a[3]).unwrap_or(u64::MAX) } else { 0 };
        let mut req = SysctlReq { old: a[2], oldlen, oldidx: 0, new: if a[5] != 0 { a[4] } else { 0 }, newlen: a[5], newidx: 0 };
        let r = self.darwin_sysctl_root(m, name, oid, &mut req);
        if let Err(e) = r {
            if e != Errno::ENOMEM {
                return Err(e);
            }
        }
        if a[3] != 0 {
            let n = if req.old != 0 && req.oldidx > req.oldlen { req.oldlen } else { req.oldidx };
            m.write_u64(a[3], n).map_err(|_| Errno::EFAULT)?;
        }
        r.map(|()| 0)
    }

    /// `sysctl_root`: the walk, the node's write permissions, the MAC
    /// check, and its handler.
    fn darwin_sysctl_root(&mut self, m: &mut GuestMem<'_>, name: Option<String>, oid: Vec<i32>, req: &mut SysctlReq) -> Result<(), Errno> {
        use sysctl::ctl;
        let oid = match &name {
            Some(n) => sysctl::name2oid(n)?,
            None => oid,
        };
        let (node, tail) = sysctl::find(&oid)?;
        // The name it is checked under, as the walk builds it.
        let namestring = name.unwrap_or_else(|| sysctl::name_of(&oid));
        if req.new != 0 && (node.kind & ctl::WR == 0 || (node.kind & ctl::SECURE != 0 && DARWIN_SECURELEVEL > 0)) {
            return Err(Errno::EPERM);
        }
        if req.new != 0 {
            if node.kind & ctl::EXPERIMENT != 0 {
                if !self.darwin_task_entitled("com.apple.private.write-kr-experiment-factors") {
                    return Err(Errno::EPERM);
                }
            } else if node.kind & ctl::ANYBODY == 0 {
                self.darwin_suser()?;
            }
        }
        let e = self.darwin_mac_check_sysctl(namestring.as_bytes(), &oid, req.new, req.newlen);
        if e != 0 {
            return Err(super::errno::errno_of(e as i32));
        }
        self.darwin_sysctl_handle(m, node, tail, req)
    }

    /// A node's handler.
    fn darwin_sysctl_handle(&mut self, m: &mut GuestMem<'_>, node: &sysctl::Node, tail: &[i32], req: &mut SysctlReq) -> Result<(), Errno> {
        match node.path {
            "sysctl.name" => req.out(m, sysctl::name_of(tail).as_bytes()).and_then(|()| req.out(m, b"\0")),
            "sysctl.next" => match sysctl::next(tail) {
                Some(o) => req.out(m, &oid_bytes(&o)),
                None => Err(Errno::ENOENT),
            },
            "sysctl.name2oid" => {
                if req.newlen == 0 {
                    return Err(Errno::ENOENT);
                }
                if req.newlen as usize >= MAXPATHLEN {
                    return Err(Errno::ENAMETOOLONG);
                }
                let bytes = req.input(m, req.newlen as usize)?;
                let n = String::from_utf8_lossy(&bytes).trim_end_matches('\0').to_string();
                let o = sysctl::name2oid(&n)?;
                req.out(m, &oid_bytes(&o))
            }
            "vfs.generic.apfs.edt_fstab" => self.darwin_sysctl_edt_fstab(m, req),
            "sysctl.oidfmt" => {
                let (kind, fmt) = sysctl::oid_fmt(tail)?;
                req.out(m, &kind.to_le_bytes())?;
                let mut f = fmt.as_bytes().to_vec();
                f.push(0);
                req.out(m, &f)
            }
            "kern.hostname" => self.darwin_sysctl_hostname(m, req),
            "net.inet.tcp.keepidle" | "net.inet.tcp.keepintvl" | "net.inet.tcp.keepinit" | "net.inet.tcp.msl" | "net.inet.tcp.keepcnt" | "net.inet.tcp.always_keepalive" | "net.inet.tcp.fin_timeout" => self.darwin_sysctl_tcp(m, node.path, req),
            p if p.starts_with("kern.proc.") => self.darwin_sysctl_proc(m, p, tail, req),
            "kern.procargs2" => self.darwin_sysctl_procargs2(m, tail, req),
            "kern.osreleasetype" => self.darwin_sysctl_osreleasetype(m, req),
            "kern.initproc_spawned" => self.darwin_sysctl_initproc_spawned(m, req),
            "kern.delayterm" => self.darwin_sysctl_delayterm(m, req),
            // sysctl_bootobjectspath: on an embedded platform, the boot
            // manifest's hash in hexadecimal.
            "kern.bootobjectspath" => match super::iokit::boot_manifest_hash() {
                Some(h) => {
                    let mut s: Vec<u8> = h.iter().flat_map(|b| format!("{b:02X}").into_bytes()).collect();
                    s.push(0);
                    req.out(m, &s)
                }
                None => Err(Errno::ENOENT),
            },
            // sysctl_hw_generic's HW_TARGET: PEGetTargetName into 64 bytes,
            // EINVAL when it has none, out with its terminator.
            "hw.target" => match super::iokit::target_name() {
                Some(mut s) => {
                    s.push(0);
                    req.out(m, &s)
                }
                None => Err(Errno::EINVAL),
            },
            "security.mac.img4.ignition_blob" => self.darwin_sysctl_ignition_blob(m, req),
            "security.mac.img4.ignition_failure_blob" => self.darwin_sysctl_ignition_failure_blob(m, req),
            "kern.dyld_flags" => self.darwin_sysctl_dyld_flags(m, req),
            "kern.progressoptions" | "kern.consoleoptions" => self.darwin_sysctl_progressoptions(m, node.path, req),
            "vm.loadavg" => self.darwin_sysctl_loadavg(m, req),
            // SYSCTL_QUADs of vm_map_corpse_footprint_count, _size_avg,
            // _size_max, _full and _no_buf.
            p if p.starts_with("vm.corpse_footprint_") => {
                let v = super::corpse::footprint_stat(&p["vm.corpse_footprint_".len()..]).ok_or(Errno::ENOENT)?;
                let b = sysctl::sized(node.path, node.kind, v.to_le_bytes().to_vec(), req.old, req.oldlen)?;
                req.out(m, &b)
            }
            _ => match sysctl::value(node.path) {
                Some(_) if req.new != 0 => {
                    self.darwin_unimplemented(format!("sysctl write of {}", node.path));
                    Err(Errno::EOPNOTSUPP)
                }
                Some(v) => {
                    let b = sysctl::sized(node.path, node.kind, v.bytes(self.darwin_user_stack), req.old, req.oldlen)?;
                    req.out(m, &b)
                }
                None => {
                    self.darwin_unimplemented(format!("sysctl node {}", node.path));
                    Err(Errno::EOPNOTSUPP)
                }
            },
        }
    }

    /// Whether a `sendmsg` on `fd` with the `struct msghdr` at `msg` carries
    /// control to a unix datagram socket (`msg_control`, `msg_controllen`).
    fn darwin_dgram_control(&self, m: &GuestMem<'_>, fd: u64, msg: u64) -> bool {
        if self.fd_io().dgram_of(fd as i32).is_err() {
            return false;
        }
        let control = m.read_u64(msg + 32).unwrap_or(0);
        let controllen = m.read_u32(msg + 40).unwrap_or(0);
        control != 0 && controllen != 0
    }

    /// `vfs.generic.apfs.edt_fstab` ([`super::apfs::edt_fstab`]): the size
    /// with no room given, else the entries copied out as they are.
    fn darwin_sysctl_edt_fstab(&mut self, m: &mut GuestMem<'_>, req: &mut SysctlReq) -> Result<(), Errno> {
        match super::apfs::edt_fstab(req.oldlen)? {
            super::apfs::Fstab::Size(n) => {
                req.oldidx = n;
                Ok(())
            }
            super::apfs::Fstab::Entries(b) => {
                req.oldidx = b.len() as u64;
                if b.is_empty() {
                    return Ok(());
                }
                m.write(req.old, &b).map_err(|_| Errno::EFAULT)
            }
        }
    }

    /// `sysctl_loadavg`: `averunnable` as a 64-bit process's `struct
    /// user64_loadavg` (every process here is one): the three averages,
    /// padding, and `fscale` as a 64-bit `long`.
    fn darwin_sysctl_loadavg(&mut self, m: &mut GuestMem<'_>, req: &mut SysctlReq) -> Result<(), Errno> {
        let ldavg = match self.procs.darwin_loadavg() {
            Ok(l) => l,
            Err(why) => {
                self.darwin_unimplemented(why.into());
                return Err(Errno::EOPNOTSUPP);
            }
        };
        let mut b = Vec::with_capacity(24);
        for v in ldavg {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&i64::from(super::sched::FSCALE).to_le_bytes());
        req.out(m, &b)
    }

    /// `sysctl_hostname`: a platform binary (or an entitled one) sees and
    /// sets the name; anyone else reads "localhost" and may not write.
    fn darwin_sysctl_hostname(&mut self, m: &mut GuestMem<'_>, req: &mut SysctlReq) -> Result<(), Errno> {
        const ENTITLEMENT: &str = "com.apple.developer.device-information.user-assigned-device-name";
        let allowed = self.darwin_task_platform_binary() || self.darwin_task_entitled(ENTITLEMENT);
        if !allowed && req.new != 0 {
            return Err(Errno::EPERM);
        }
        let name = if allowed { sysctl::hostname() } else { b"localhost".to_vec() };
        let new = req.io_string(m, &name, sysctl::MAXHOSTNAMELEN, true)?;
        if let Some(v) = new {
            sysctl::set_hostname(v);
        }
        Ok(())
    }

    /// AppleImage4's `security.mac.img4.ignition_blob` (0xfffffff005a948ec):
    /// for a task with its entitlement or the init process, else EPERM;
    /// then `sysctl_handle_opaque` of the blob (its 0x84 bytes out, and a
    /// new value of as many in, which the node's ANYBODY write lets such a
    /// caller give). A blob the kext's start could not make is its panic.
    fn darwin_sysctl_ignition_blob(&mut self, m: &mut GuestMem<'_>, req: &mut SysctlReq) -> Result<(), Errno> {
        if !self.darwin_task_entitled(super::img4::IGNITION_BLOB_ENTITLEMENT) && self.pid != 1 {
            return Err(Errno::EPERM);
        }
        let blob = match super::img4::ignition_blob() {
            Ok(b) => b,
            Err(why) => {
                self.darwin_unimplemented(why);
                return Err(Errno::EIO);
            }
        };
        req.out(m, &blob)?;
        if req.new != 0 {
            let b = req.input(m, blob.len())?;
            super::img4::set_ignition_blob(b.try_into().expect("the blob's size"));
        }
        Ok(())
    }

    /// AppleImage4's `security.mac.img4.ignition_failure_blob`
    /// (0xfffffff005a94a9c): the ignition blob's callers alone, else EPERM;
    /// `sysctl_handle_opaque` of the failure blob (its 0xa0 bytes out, and
    /// a new value of as many in), whose error is the call's; then, read or
    /// written, the blob's NVRAM keys go to IODTNVRAM ([`super::img4`]):
    /// its runtime (0xfffffff005a92c60) waits for the IONVRAM resource and
    /// IODTNVRAM, then gives each key `setProperties` of a one-key
    /// dictionary of an OSData of its bytes, in the calling task (whose
    /// permission IODTNVRAM checks; a failure is only logged), and forces
    /// a sync (0xfffffff005a92f70, type 3: `setProperty` of
    /// `IONVRAM-FORCESYNCNOW-PROPERTY` to the symbol "1", its result not
    /// looked at).
    fn darwin_sysctl_ignition_failure_blob(&mut self, m: &mut GuestMem<'_>, req: &mut SysctlReq) -> Result<(), Errno> {
        if !self.darwin_task_entitled(super::img4::IGNITION_BLOB_ENTITLEMENT) && self.pid != 1 {
            return Err(Errno::EPERM);
        }
        let blob = super::img4::ignition_failure_blob();
        req.out(m, &blob)?;
        if req.new != 0 {
            let b = req.input(m, blob.len())?;
            super::img4::set_ignition_failure_blob(b.try_into().expect("the failure blob's size"));
        }
        let blob = super::img4::ignition_failure_blob();
        let task = self.darwin_nvram_task();
        let wrote = super::nvram::with(|n| {
            use super::nvram::{key, Given, Uptime, Value};
            for (k, v) in super::img4::ignition_failure_nvram(&blob) {
                let _ = n.set_property_clocked(&task, k.as_bytes(), &Given::Value(Value::Data(v)), None, &Uptime);
            }
            let _ = n.set_property_clocked(&task, key::FORCE_SYNC_NOW, &Given::Value(Value::Symbol(b"1".to_vec())), None, &Uptime);
        });
        if let Err(why) = wrote {
            let keys: Vec<String> = super::img4::ignition_failure_nvram(&blob).into_iter().map(|(k, v)| format!("{k} ({} bytes)", v.len())).collect();
            self.darwin_unimplemented(format!("AppleImage4's NVRAM write of the ignition failure blob ({}): IODTNVRAM::setProperties of {}, then its forced sync: {why}", super::img4::ignition_failure_summary(&blob), keys.join(", ")));
            return Err(Errno::EOPNOTSUPP);
        }
        self.darwin_nvram_report();
        Ok(())
    }

    /// `sysctl_dyld_flags`: launchd's to set, and the commpage says it.
    fn darwin_sysctl_dyld_flags(&mut self, m: &mut GuestMem<'_>, req: &mut SysctlReq) -> Result<(), Errno> {
        if req.new != 0 && self.pid != 1 {
            return Err(Errno::EPERM);
        }
        req.out(m, &super::commpage::dyld_flags().to_le_bytes())?;
        if req.new != 0 {
            let b = req.input(m, 8)?;
            super::commpage::set_dyld_flags(u64::from_le_bytes(b[..8].try_into().unwrap()));
        }
        Ok(())
    }

    /// IOPMrootDomain's `sysctl_progressoptions` (`sysctl_io_opaque` of the
    /// video console's `vc_user_options`, which anybody may write) and
    /// `sysctl_consoleoptions` (`sysctl_io_number` of their options word).
    fn darwin_sysctl_progressoptions(&mut self, m: &mut GuestMem<'_>, path: &str, req: &mut SysctlReq) -> Result<(), Errno> {
        let mut v = super::vconsole::user_options();
        let n = if path == "kern.consoleoptions" { 4 } else { v.len() };
        req.out(m, &v[..n])?;
        if req.new != 0 {
            let b = req.input(m, n)?;
            v[..n].copy_from_slice(&b[..n]);
            super::vconsole::set_user_options(v);
        }
        Ok(())
    }

    /// `sysctl_initproc_spawned`: launchd says it has reached main, once.
    fn darwin_sysctl_initproc_spawned(&mut self, m: &mut GuestMem<'_>, req: &mut SysctlReq) -> Result<(), Errno> {
        use std::sync::atomic::Ordering::Relaxed;
        if req.new != 0 && (self.pid != 1 || SPAWNED.load(Relaxed) != 0) {
            return Err(Errno::EPERM);
        }
        req.out(m, &SPAWNED.load(Relaxed).to_le_bytes())?;
        if req.new != 0 {
            let b = req.input(m, 4)?;
            SPAWNED.store(i32::from_le_bytes([b[0], b[1], b[2], b[3]]), Relaxed);
        }
        Ok(())
    }

    /// `sysctl_delayterm`: the caller's `P_LDELAYTERM` as an `int`
    /// (`sysctl_io_number` of an `int`: a 64-bit new value is taken when it
    /// fits, ERANGE when it does not), set by any new value but 0.
    fn darwin_sysctl_delayterm(&mut self, m: &mut GuestMem<'_>, req: &mut SysctlReq) -> Result<(), Errno> {
        let cur = i32::from(self.procs.delayterm(self.pid));
        req.out(m, &cur.to_le_bytes())?;
        if req.new == 0 {
            return Ok(());
        }
        let new = if req.newlen == 8 {
            let b = req.input(m, 8)?;
            let big = i64::from_le_bytes(b[..8].try_into().expect("8 bytes"));
            i32::try_from(big).map_err(|_| Errno::ERANGE)?
        } else {
            let b = req.input(m, 4)?;
            i32::from_le_bytes(b[..4].try_into().expect("4 bytes"))
        };
        self.procs.set_delayterm(self.pid, new != 0);
        Ok(())
    }

    /// TCP's timer sysctls ([`crate::tcploop::sysctl`]): `keepidle`,
    /// `keepintvl`, `keepinit` and `msl` by `sysctl_msec_to_ticks`
    /// (milliseconds in and out, TCP_RETRANSHZ being 1000; a new value
    /// under 1 is EINVAL); `keepcnt` and `always_keepalive` by
    /// `skmem_sysctl_handle_int` (any `int`); `fin_timeout` by
    /// `sysctl_tcp_fin_timeout` (-1 restores TCPTV_FINWAIT2, a negative
    /// value otherwise is EINVAL). A value whose timers this kernel's
    /// clock cannot keep is said, and not taken.
    fn darwin_sysctl_tcp(&mut self, m: &mut GuestMem<'_>, path: &str, req: &mut SysctlReq) -> Result<(), Errno> {
        use crate::tcploop::sysctl as t;
        let var = match path {
            "net.inet.tcp.keepidle" => &t::KEEPIDLE,
            "net.inet.tcp.keepintvl" => &t::KEEPINTVL,
            "net.inet.tcp.keepinit" => &t::KEEPINIT,
            "net.inet.tcp.msl" => &t::MSL,
            "net.inet.tcp.keepcnt" => &t::KEEPCNT,
            "net.inet.tcp.always_keepalive" => &t::ALWAYS_KEEPALIVE,
            _ => &t::FIN_TIMEOUT,
        };
        let cur = t::get(var);
        let msec = matches!(path, "net.inet.tcp.keepidle" | "net.inet.tcp.keepintvl" | "net.inet.tcp.keepinit" | "net.inet.tcp.msl");
        // sysctl_msec_to_ticks: a negative value is not shown.
        if msec && cur < 0 {
            return Err(Errno::EINVAL);
        }
        let Some(new) = req.io_int(m, cur)? else { return Ok(()) };
        let new = if msec {
            if new < 1 {
                return Err(Errno::EINVAL);
            }
            new
        } else if path == "net.inet.tcp.fin_timeout" {
            match new {
                -1 => t::TCPTV_FINWAIT2,
                v if v < 0 => return Err(Errno::EINVAL),
                v => v,
            }
        } else {
            new
        };
        t::set(var, new);
        if !crate::tcploop::offsets_fit(&crate::tcploop::TcpOpts::default()) {
            t::set(var, cur);
            self.darwin_unimplemented(format!("{path} {new}: a TCP timer offset of 2^31 ms or more (tcp_now's 32-bit wraparound)"));
            return Err(Errno::EOPNOTSUPP);
        }
        // Connections' deadlines may have moved: the thread calls look.
        self.dtask.timers.bell().ring();
        Ok(())
    }

    /// `sysctl_osreleasetype`: launchd sets it, once.
    fn darwin_sysctl_osreleasetype(&mut self, m: &mut GuestMem<'_>, req: &mut SysctlReq) -> Result<(), Errno> {
        let cur = sysctl::os_release_type();
        if req.new != 0 && (self.pid != 1 || !cur.is_empty()) {
            return Err(Errno::EPERM);
        }
        const SIZE: usize = 48;
        if let Some(v) = req.io_string(m, &cur, SIZE, false)? {
            sysctl::set_os_release_type(v);
        }
        Ok(())
    }

    /// `sigprocmask` (`process`): the process's mask, which is every
    /// thread's (`block_procsigmask`, `unblock_procsigmask`,
    /// `set_procsigmask` walk `p_uthlist`); `__pthread_sigmask` changes the
    /// calling thread's alone.
    fn darwin_sigprocmask(&mut self, m: &mut GuestMem<'_>, how: u64, set: u64, old: u64, process: bool) -> Result<u64, Errno> {
        // The old mask is the calling thread's before the call, copied out
        // after the new one is read (they may be the same word).
        let blocked = self.signals.blocked();
        if set != 0 {
            let mask = mask_to_linux(m.read_u32(set)?);
            if !(1..=3).contains(&how) {
                return Err(Errno::EINVAL);
            }
            let unblockable = (1u64 << (crate::signal::sig::SIGKILL - 1)) | (1u64 << (crate::signal::sig::SIGSTOP - 1));
            let next = |was: u64| {
                let n = match how {
                    1 => was | mask,
                    2 => was & !mask,
                    _ => (was & !mask_to_linux(!0)) | mask,
                };
                n & !unblockable
            };
            if process {
                for tid in self.thread_signals.tids_in_order() {
                    if let Some(t) = self.thread_signals.get(tid) {
                        t.set_blocked(next(t.blocked()));
                    }
                }
            }
            self.signals.set_blocked(next(blocked));
        }
        if old != 0 {
            m.write_u32(old, mask_from_linux(blocked))?;
        }
        Ok(0)
    }

    /// Whether a creating call's name ends in a slash and names nothing:
    /// `lookup_validate_creation_path`'s case.
    pub(crate) fn darwin_slash_creation(&mut self, m: &GuestMem<'_>, dirfd: u64, path: u64) -> bool {
        const MAXPATHLEN: usize = 1024;
        let Ok(raw) = m.read_cstr(path, MAXPATHLEN) else { return false };
        if raw.len() < 2 || !raw.ends_with(b"/") {
            return false;
        }
        let Ok(given) = std::str::from_utf8(&raw) else { return false };
        let Ok(abs) = self.path_io().at_path_str(super::bsd::dirfd(dirfd) as i32, given.trim_end_matches('/')) else { return false };
        self.vfs.metadata_nofollow(&abs).is_err_and(|e| e == Errno::ENOENT) && self.vfs.metadata(&crate::vfs::parent_of(&abs)).is_ok_and(|md| md.file_type == crate::vfs::FileType::Directory)
    }

    /// Whether the name is a directory (a rename's source: `WILLBEDIR`).
    pub(crate) fn darwin_is_dir(&mut self, m: &GuestMem<'_>, dirfd: u64, path: u64) -> bool {
        self.path_io().at_path(m, super::bsd::dirfd(dirfd) as i32, path).is_ok_and(|p| self.vfs.metadata_nofollow(&p).is_ok_and(|md| md.file_type == crate::vfs::FileType::Directory))
    }

    /// `csops_internal(pid, ops, uaddr, usersize, uaudittoken)`: a
    /// process's code signing state, read or changed. Another process's
    /// state may be changed only by root; the audit token, when given, must
    /// name the process (its pid and its idversion); Sandbox judges each
    /// operation (`mac_proc_check_get_cs_info`, `_set_cs_info`).
    fn darwin_csops(&mut self, m: &mut GuestMem<'_>, pid: i32, ops: u32, uaddr: u64, usize: u64, token: Option<u64>) -> Result<u64, Errno> {
        use super::amfi::cs;
        use std::sync::atomic::Ordering;
        let pid = if pid == 0 { self.pid } else { pid };
        let forself = pid == self.pid;
        let reads = matches!(ops, csop::STATUS | csop::CDHASH | csop::PIDOFFSET | csop::ENTITLEMENTS_BLOB | csop::DER_ENTITLEMENTS_BLOB | csop::IDENTITY | csop::BLOB | csop::TEAMID | csop::CLEAR_LV | csop::VALIDATION_CATEGORY);
        if !reads && !forself && self.creds.uid() != 0 {
            return Err(Errno::EPERM);
        }
        // proc_find: this process, or another that has not exited (one
        // being spawned is found, with what its spawn has made of it).
        let (sig, flags, pidversion, textoff) = if forself {
            (self.dtask.codesign.clone().map(std::sync::Arc::new), std::sync::Arc::clone(&self.dtask.csflags), self.dtask.pidversion, self.dtask.textoff)
        } else {
            let Some(p) = self.darwin_proc_find(pid) else { return Err(Errno::ESRCH) };
            (p.codesign, p.csflags, p.pidversion, p.textoff)
        };
        if let Some(t) = token {
            let tok = m.read(t, 32)?;
            let word = |i: usize| i32::from_le_bytes(tok[4 * i..4 * i + 4].try_into().unwrap());
            if word(5) != pid || word(7) != pidversion {
                return Err(Errno::ESRCH);
            }
        }
        let e = if matches!(ops, csop::MARKINVALID | csop::MARKHARD | csop::MARKKILL | csop::MARKRESTRICT | csop::SET_STATUS | csop::CLEARINSTALLER | csop::CLEARPLATFORM | csop::CLEAR_LV) {
            self.darwin_mac_check_set_cs_info(pid, ops)
        } else {
            self.darwin_mac_check_get_cs_info(pid, ops)
        };
        if e != 0 {
            return Err(super::errno::errno_of(e as i32));
        }
        let valid = || flags.load(Ordering::Acquire) & (cs::VALID | cs::DEBUGGED) != 0;
        match ops {
            csop::STATUS => {
                let f = flags.load(Ordering::Acquire);
                // cs_process_enforcement: always on this system.
                let mut ret = f | cs::ENFORCEMENT;
                if sig.as_ref().is_some_and(|c| c.platform_binary) {
                    ret |= cs::PLATFORM_BINARY;
                }
                if f & cs::FORCED_LV != 0 {
                    ret &= !cs::REQUIRE_LV;
                }
                if uaddr != 0 {
                    m.write_u32(uaddr, ret)?;
                }
                Ok(0)
            }
            csop::MARKINVALID => {
                let f = flags.load(Ordering::Acquire);
                if f & cs::VALID != 0 {
                    flags.fetch_and(!cs::VALID, Ordering::AcqRel);
                    if f & cs::KILL != 0 {
                        flags.fetch_or(cs::KILLED, Ordering::AcqRel);
                        let note = self.darwin_signal_reason(super::signal::dsig::SIGKILL);
                        self.procs.post_kernel_noted(pid, signal_to_linux(super::signal::dsig::SIGKILL), Some(note));
                    }
                }
                Ok(0)
            }
            csop::MARKHARD => {
                let f = flags.fetch_or(cs::HARD, Ordering::AcqRel);
                if f & cs::VALID == 0 { Err(Errno::EINVAL) } else { Ok(0) }
            }
            csop::MARKKILL => {
                let f = flags.fetch_or(cs::KILL, Ordering::AcqRel);
                if f & cs::VALID == 0 {
                    let note = self.darwin_signal_reason(super::signal::dsig::SIGKILL);
                    self.procs.post_kernel_noted(pid, signal_to_linux(super::signal::dsig::SIGKILL), Some(note));
                }
                Ok(0)
            }
            csop::PIDOFFSET => {
                m.write_u64(uaddr, textoff as u64)?;
                Ok(0)
            }
            // vn_getcdhash: the blob that covers the image's offset.
            csop::CDHASH => {
                if usize != 20 {
                    return Err(Errno::EINVAL);
                }
                let Some(h) = sig.as_ref().and_then(|c| c.cdhash) else { return Err(super::errno::EBADEXEC) };
                m.write(uaddr, &h)?;
                Ok(0)
            }
            csop::ENTITLEMENTS_BLOB | csop::DER_ENTITLEMENTS_BLOB | csop::BLOB => {
                if !valid() {
                    return Err(Errno::EINVAL);
                }
                let Some(c) = sig.as_ref() else { return Err(super::errno::EBADEXEC) };
                let blob = match ops {
                    csop::BLOB => Some(c.blob.clone()),
                    csop::DER_ENTITLEMENTS_BLOB => c.der.clone(),
                    // AMFI's XML form of the entitlements: the signature's
                    // own XML blob.
                    _ => match (&c.xml, &c.der) {
                        (Some(x), _) => Some(x.clone()),
                        (None, None) => None,
                        (None, Some(_)) => {
                            self.darwin_unimplemented("csops CS_OPS_ENTITLEMENTS_BLOB of a signature with DER entitlements only (AMFI's XML from DER)".into());
                            return Err(Errno::EINVAL);
                        }
                    },
                };
                self.darwin_csops_copy_token(m, blob.as_deref(), usize, uaddr)
            }
            csop::VALIDATION_CATEGORY => {
                if !valid() {
                    return Err(Errno::EINVAL);
                }
                let Some(c) = sig.as_ref() else { return Err(super::errno::EBADEXEC) };
                m.write_u32(uaddr, c.category)?;
                Ok(0)
            }
            csop::MARKRESTRICT => {
                flags.fetch_or(cs::RESTRICT, Ordering::AcqRel);
                Ok(0)
            }
            csop::SET_STATUS => {
                if usize < 4 {
                    return Err(Errno::ERANGE);
                }
                let want = m.read_u32(uaddr)? & (cs::HARD | cs::EXEC_SET_HARD | cs::KILL | cs::EXEC_SET_KILL | cs::RESTRICT | cs::REQUIRE_LV | cs::ENFORCEMENT | cs::EXEC_SET_ENFORCEMENT);
                if flags.load(Ordering::Acquire) & cs::VALID == 0 {
                    return Err(Errno::EINVAL);
                }
                flags.fetch_or(want, Ordering::AcqRel);
                Ok(0)
            }
            // Library validation is dropped on macOS only; platform status
            // is cleared on development kernels only.
            csop::CLEAR_LV | csop::CLEARPLATFORM => Err(super::errno::errno_of(45)),
            csop::IDENTITY | csop::TEAMID => {
                if usize < 8 {
                    return Err(Errno::ERANGE);
                }
                if !valid() {
                    return Err(Errno::EINVAL);
                }
                let id = sig.as_ref().and_then(|c| if ops == csop::TEAMID { c.team_id.clone() } else { c.identity.clone() });
                let Some(id) = id else { return Err(Errno::ENOENT) };
                let length = id.len() + 1;
                let mut header = [0u8; 8];
                header[4..8].copy_from_slice(&((length + 8) as u32).to_be_bytes());
                m.write(uaddr, &header)?;
                if usize < 8 + length as u64 {
                    return Err(Errno::ERANGE);
                }
                let mut v = id;
                v.push(0);
                m.write(uaddr + 8, &v)?;
                Ok(0)
            }
            csop::CLEARINSTALLER => {
                flags.fetch_and(!(cs::INSTALLER | cs::DATAVAULT_CONTROLLER | cs::EXEC_INHERIT_SIP), Ordering::AcqRel);
                Ok(0)
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// `csops_copy_token`: a blob, or a zero header for none; for a buffer
    /// too small, its header with the blob's length, and ERANGE.
    fn darwin_csops_copy_token(&mut self, m: &mut GuestMem<'_>, blob: Option<&[u8]>, usize: u64, uaddr: u64) -> Result<u64, Errno> {
        if usize < 8 {
            return Err(Errno::ERANGE);
        }
        let Some(b) = blob else {
            m.write(uaddr, &[0u8; 8])?;
            return Ok(0);
        };
        if usize < b.len() as u64 {
            let mut header = [0u8; 8];
            header[4..8].copy_from_slice(&(b.len() as u32).to_be_bytes());
            m.write(uaddr, &header)?;
            return Err(Errno::ERANGE);
        }
        m.write(uaddr, b)?;
        Ok(0)
    }

    /// `__mac_syscall(policy, call, arg)`: the policy's name, Sandbox's
    /// check of the call (`mac_proc_check_syscall_mac`), then the named
    /// policy's `mpo_policy_syscall`; ENOPOLICY for one not loaded.
    fn darwin_mac_syscall(&mut self, m: &mut GuestMem<'_>, policy: u64, call: u64, arg: u64) -> Result<u64, Errno> {
        let mut buf = [0u8; MAC_MAX_POLICY_NAME];
        let name = match m.read_cstr_into(policy, &mut buf)? {
            Some(n) => buf[..n].to_vec(),
            None => return Err(Errno::ENAMETOOLONG),
        };
        let e = self.darwin_mac_check_syscall_mac(&name, call as u32);
        if e != 0 {
            return Err(super::errno::errno_of(e as i32));
        }
        let r = match name.as_slice() {
            b"AMFI" => self.darwin_amfi_syscall(m, call, arg),
            b"Sandbox" => self.darwin_sandbox_syscall(m, call, arg),
            _ => Err(ENOPOLICY),
        };
        r.map(|()| 0).map_err(super::errno::errno_of)
    }

    /// AMFI's `mpo_policy_syscall` (`0x...b72a8`); its error, a Darwin
    /// errno.
    fn darwin_amfi_syscall(&mut self, m: &mut GuestMem<'_>, call: u64, arg: u64) -> Result<(), i32> {
        const EINVAL: i32 = 22;
        let fault = |_| 14;
        match call {
            amfi_call::DYLD_POLICY_SELF | amfi_call::DYLD_POLICY_FOR_PID | amfi_call::CHECK_TRUST_CACHE | amfi_call::LOAD_TRUST_CACHE if arg == 0 => Err(EINVAL),
            // {flags, &output}: the caller's policy.
            amfi_call::DYLD_POLICY_SELF => {
                let out = m.read_u64(arg + 8).map_err(fault)?;
                let p = self.darwin_dyld_policy();
                m.write_u64(out, p).map_err(fault)
            }
            // {flags, &output, pid}: another process's.
            amfi_call::DYLD_POLICY_FOR_PID => {
                let out = m.read_u64(arg + 8).map_err(fault)?;
                let pid = m.read_u32(arg + 16).map_err(fault)? as i32;
                if pid == 0 {
                    return Err(EINVAL);
                }
                let p = if pid == self.pid {
                    self.darwin_dyld_policy()
                } else {
                    // proc_find: one that has not exited.
                    let Some(t) = self.darwin_proc_find(pid) else { return Err(3) };
                    let ents = t.codesign.as_ref().map(|c| c.ents.clone()).unwrap_or_default();
                    super::amfi::dyld_policy(t.sugid, t.csflags.load(std::sync::atomic::Ordering::Acquire), &ents)
                };
                m.write_u64(out, p).map_err(fault)
            }
            // {cdhash, ..., result at 0x18} (0xfffffff005ab73a8): the
            // result zeroed, then bit 0 if the static trust cache has the
            // cdhash (query type 1) and bit 1 if a loaded one has it (type
            // 2); for an entitled caller.
            amfi_call::CHECK_TRUST_CACHE => {
                if !self.darwin_task_entitled("com.apple.private.amfi.can-check-trust-cache") {
                    return Err(13);
                }
                let mut q = [0u8; 0x20];
                q.copy_from_slice(m.read(arg, 0x20).map_err(fault)?);
                let cdhash: [u8; 20] = q[..20].try_into().unwrap();
                use super::trustcache::{query, Query};
                let found = u64::from(query(Query::Static, &cdhash).is_some()) | u64::from(query(Query::Loadable, &cdhash).is_some()) << 1;
                q[0x18..0x20].copy_from_slice(&found.to_le_bytes());
                m.write(arg, &q).map_err(fault)
            }
            // Not on this platform.
            amfi_call::GET_LOCAL_SIGNING_PRIVATE_KEY => Err(1),
            amfi_call::LOAD_TRUST_CACHE => self.darwin_amfi_load_trust_cache(m, arg),
            98..=100 | 102 => {
                self.darwin_unimplemented(format!("AMFI __mac_syscall {call} (local signing, launch constraints)"));
                Err(EINVAL)
            }
            _ => Err(78),
        }
    }

    /// AMFI's `_load_trust_cache` (0xfffffff005ab7550): the request copied
    /// in, {u8 type, the IM4P's address and u32 length at 8 and 0x10, the
    /// manifest's at 0x18 and 0x20, the auxiliary manifest's at 0x28 and
    /// 0x30}; an IM4P is required (EINVAL with none or of length 0), a
    /// manifest or auxiliary manifest of a nonzero length needs its address
    /// (EINVAL); each is copied in, then loaded
    /// ([`Kernel::darwin_load_trust_cache`]) and the load's
    /// `kern_return_t` made an errno ([`super::trustcache::amfi_errno`]).
    fn darwin_amfi_load_trust_cache(&mut self, m: &mut GuestMem<'_>, arg: u64) -> Result<(), i32> {
        const EINVAL: i32 = 22;
        let fault = |_| 14;
        let req = m.read(arg, 0x38).map_err(fault)?.to_vec();
        let q = |o: usize| u64::from_le_bytes(req[o..o + 8].try_into().unwrap());
        let w = |o: usize| u64::from(u32::from_le_bytes(req[o..o + 4].try_into().unwrap()));
        let ty = req[0];
        let (payload_at, payload_len) = (q(8), w(0x10));
        if payload_at == 0 || payload_len == 0 {
            return Err(EINVAL);
        }
        let payload = m.read(payload_at, payload_len as usize).map_err(fault)?.to_vec();
        let mut copy = |at: u64, len: u64| -> Result<Vec<u8>, i32> {
            match (at, len) {
                (_, 0) => Ok(Vec::new()),
                (0, _) => Err(EINVAL),
                _ => Ok(m.read(at, len as usize).map_err(fault)?.to_vec()),
            }
        };
        let manifest = copy(q(0x18), w(0x20))?;
        let aux = copy(q(0x28), w(0x30))?;
        match self.darwin_load_trust_cache(ty, &payload, &manifest, &aux) {
            Some(k) => match super::trustcache::amfi_errno(k) {
                0 => Ok(()),
                e => Err(e),
            },
            None => Err(EINVAL),
        }
    }

    /// AMFI's `loadTrustCacheWithType` (0xfffffff005aad464): a cache whose
    /// UUID the runtime has already is loaded
    /// ([`super::trustcache::is_duplicate_img4`]); a type other than the
    /// Cryptex1 boot and preboot ones needs the device unlocked, asked of
    /// AppleKeyStore (`deviceUnlocked`, 0xfffffff005aab7f0), which is not
    /// implemented (reported); then the kernel's
    /// [`Kernel::darwin_load_trust_cache_with_type`], whose duplicate
    /// (KERN_ALREADY_IN_SET) is success too. `None` where it is stopped
    /// (reported).
    fn darwin_load_trust_cache(&mut self, ty: u8, payload: &[u8], manifest: &[u8], aux: &[u8]) -> Option<i32> {
        use super::trustcache::{kr, tc_type};
        match super::trustcache::is_duplicate_img4(payload) {
            Ok(true) => return Some(kr::SUCCESS),
            Ok(false) => {}
            Err(why) => {
                self.darwin_unimplemented(why);
                return None;
            }
        }
        if !(tc_type::CRYPTEX1_BOOT_OS..=tc_type::CRYPTEX1_PREBOOT_APP).contains(&ty) {
            self.darwin_unimplemented(format!("loadTrustCacheWithType of a trust cache of type {ty:#x}: whether AMFI's system state allows it (its flag at 0xfffffff006cfc3d8, AppleKeyStore's lock state through deviceUnlocked, 0xfffffff005aab7f0)"));
            return None;
        }
        match self.darwin_load_trust_cache_with_type(ty, payload, manifest, aux)? {
            kr::ALREADY_IN_SET => Some(kr::SUCCESS),
            k => Some(k),
        }
    }

    /// `load_trust_cache_with_type` (bsd/kern/kern_trustcache.c 745-880,
    /// 0xfffffff007662e1c): an object with no external manifest is an
    /// Image4 object whose payload and manifest AppleImage4 takes out
    /// (`img4_get_payload`, `img4_get_manifest`), which is not implemented
    /// (reported); the type checked; the caller's
    /// `com.apple.private.pmap.load-trust-cache` entitlement must allow
    /// the type's value (`IOCurrentTaskHasStringEntitlement`, DENIED); a
    /// second Cryptex1 boot cache of a type is DENIED; then, with no PPL or
    /// TXM on this chip, `xnu_load_trust_cache`: AMFI's `trustCacheLoad`,
    /// the IM4P evaluated against the manifest for the type's chip
    /// ([`Kernel::darwin_trust_cache_img4`]) and its module loaded
    /// ([`super::trustcache::load_module`]); its duplicate is
    /// KERN_ALREADY_IN_SET, any other error KERN_FAILURE. The auxiliary
    /// manifest is ignored (497-499).
    fn darwin_load_trust_cache_with_type(&mut self, ty: u8, payload: &[u8], manifest: &[u8], _aux: &[u8]) -> Option<i32> {
        use super::trustcache::{self as tc, kr};
        if manifest.is_empty() {
            self.darwin_unimplemented(format!("load_trust_cache_with_type of an Image4 object of type {ty:#x} with no external manifest (img4_get_payload and img4_get_manifest)"));
            return None;
        }
        if let Err(k) = tc::check_type(ty) {
            return Some(k);
        }
        let (fourcc, value) = tc::config(ty)?;
        let allowed = self.dtask.codesign.as_ref().is_some_and(|c| c.ents.string_allowed(tc::LOAD_ENTITLEMENT.as_bytes(), value.as_bytes()));
        if !allowed || tc::boot_type_loaded(ty) {
            return Some(kr::DENIED);
        }
        let authenticated = self.darwin_trust_cache_img4(ty, fourcc, payload, manifest)?;
        match tc::load_module(ty, authenticated) {
            Ok(()) => {
                tc::mark_loaded(ty);
                Some(kr::SUCCESS)
            }
            Err(tc::LoadError::Duplicate) => Some(kr::ALREADY_IN_SET),
            Err(tc::LoadError::Failed(_)) => Some(kr::FAILURE),
        }
    }

    /// libTrustCache's Image4 evaluation of a cache of type `ty`
    /// (0x...bb060): its type's chip (`TCTypeConfig`'s first function:
    /// `CHIP_CRYPTEX1_BOOT_AP`, 0xfffffff005a93908, for the Cryptex1 boot
    /// types; 0xfffffff005a93920 for the preboot app type), no nonce
    /// (types 0xd to 0xf are in the nonce-free set, 0xcffc0f), firmware
    /// flags from the type's third function (0 for these), the type's 4CC;
    /// `img4_firmware_new`, `attach_manifest`, `execute`
    /// ([`Kernel::darwin_img4_firmware_execute`]), whose callback
    /// (0x...bb2f8) leaves the authenticated payload or the status.
    fn darwin_trust_cache_img4(&mut self, ty: u8, fourcc: u32, payload: &[u8], manifest: &[u8]) -> Option<Result<Vec<u8>, i32>> {
        use super::graft::{Chip, Selection};
        use super::trustcache::tc_type;
        let chip = match ty {
            tc_type::CRYPTEX1_BOOT_OS | tc_type::CRYPTEX1_BOOT_APP => Chip::Cryptex1BootAp,
            tc_type::CRYPTEX1_PREBOOT_APP => Chip::ApPlus148,
            _ => {
                self.darwin_unimplemented(format!("trustCacheLoad's Image4 chip and nonce for a trust cache of type {ty:#x}"));
                return None;
            }
        };
        self.darwin_img4_firmware_execute(Selection { chip, pdi_nonce: false, firmware_flags: 0 }, fourcc, payload, manifest)
    }

    /// Sandbox's `sandbox_check` (`0x...a15fcc`): whether the target process
    /// may do an operation on a filter's object. The request: the result's
    /// address, the pid, the operation's name, the filter's type and
    /// argument, the flags (the target selector in bits 30-31), the
    /// selector's id; the answer, 0 allowed or the denial's errno, goes to
    /// the result, the call's own error being only the request's.
    fn darwin_sandbox_check(&mut self, m: &mut GuestMem<'_>, arg: u64) -> Result<(), i32> {
        const EPERM: i32 = 1;
        const ENOENT: i32 = 2;
        const EINVAL: i32 = 22;
        const ENAMETOOLONG: i32 = 63;
        let fault = |_| 14;
        let req = m.read(arg, 0x80).map_err(fault)?.to_vec();
        let q = |o: usize| u64::from_le_bytes(req[o..o + 8].try_into().unwrap());
        let (result_at, pid, op_at, ftype, farg, flags, id) = (q(0), q(8) as i64, q(0x10), q(0x18), q(0x20), q(0x28), q(0x30));
        let answer = |m: &mut GuestMem<'_>, r: u64| m.write_u64(result_at, r).map_err(fault);
        // The target.
        let selector = flags >> 30 & 3;
        if selector == 3 {
            if !self.darwin_task_entitled("com.apple.private.security.sandbox-reference") {
                return Err(EPERM);
            }
            if id == 0 || id > 0xffff_ffff {
                return Err(EINVAL);
            }
            // A reference is made by Sandbox's calls that make one, which
            // are not served (each is refused loudly): none names this id.
            return Err(ENOENT);
        }
        // The process by pid, with its pidversion or its unique id to match:
        // its credential's sandbox.
        let found = |k: &mut Kernel, pid: i64, version: Option<u64>, unique: Option<u64>| -> Option<Option<std::sync::Arc<super::sandboxes::Sandbox>>> {
            let pid = i32::try_from(pid).ok()?;
            let (v, u, sb) = if pid == k.pid {
                (k.dtask.pidversion, k.dtask.uniqueid, k.darwin_sandbox())
            } else {
                let p = k.darwin_proc_find(pid)?;
                (p.pidversion, p.uniqueid, super::sandboxes::of(&p.sandbox))
            };
            (version.is_none_or(|w| i64::from(v) == w as i64) && unique.is_none_or(|w| u == w)).then_some(sb)
        };
        let Some(sandbox) = found(self, pid, (selector == 1).then_some(id), (selector == 2).then_some(id)) else { return answer(m, 3) };
        if flags & 0x100_0000 != 0 && found(self, q(0x70) as i64, Some(q(0x78)), None).is_none() {
            return answer(m, 3);
        }
        // With no operation, the answer is whether the target has a sandbox.
        if op_at == 0 {
            return answer(m, u64::from(sandbox.is_some()));
        }
        let mut buf = [0u8; 0x35];
        let name = match m.read_cstr_into(op_at, &mut buf).map_err(fault)? {
            Some(n) => buf[..n].to_vec(),
            None => return Err(ENAMETOOLONG),
        };
        // A forbidden- pseudo-operation: allowed without a sandbox; denied
        // with one, and reported unless quiet.
        let forbidden = name.starts_with(b"forbidden-");
        if forbidden && sandbox.is_none() {
            return answer(m, 0);
        }
        let mut s = [0u8; 0x400];
        let mut string = |m: &mut GuestMem<'_>, at: u64| -> Result<Vec<u8>, i32> {
            match m.read_cstr_into(at, &mut s).map_err(fault)? {
                Some(n) => Ok(s[..n].to_vec()),
                None => Err(ENAMETOOLONG),
            }
        };
        use super::sandbox::kind;
        let mut a = super::mac::SbArgs { quiet: flags & 1 != 0, ..Default::default() };
        match ftype {
            0 => {}
            5 => (a.kind, a.string) = (kind::POSIX_IPC, Some(string(m, farg)?)),
            6 | 7 | 50 => {
                (a.kind, a.string) = (kind::HOST_SPECIAL_PORT, Some(string(m, farg)?));
                a.global = ftype != 7;
                a.xpc = ftype == 50;
            }
            25 | 27 | 28 | 33 | 34 | 38 | 45 => {
                a.kind = match ftype {
                    25 => 9,
                    27 => 10,
                    28 => 11,
                    33 => 12,
                    34 => 13,
                    38 => 15,
                    _ => 17,
                };
                a.string = Some(string(m, farg)?);
            }
            // {name, flag}
            35 => {
                let (n, f) = (m.read_u64(farg).map_err(fault)?, m.read_u32(farg + 8).map_err(fault)?);
                (a.kind, a.string, a.global) = (14, Some(string(m, n)?), f != 0);
            }
            52 if flags & 0x100_0000 == 0 => return answer(m, 3),
            65 if farg > u64::from(u32::MAX) => return answer(m, EINVAL as u64),
            65 => (a.kind, a.number) = (kind::SYSCALL_UNIX, farg as u32),
            75 => return answer(m, EINVAL as u64),
            1 | 19 | 52 | 240 | 241 => {
                self.darwin_unimplemented(format!("sandbox_check with filter type {ftype} (vnodes, IOKit entries, signal targets)"));
                return Err(EINVAL);
            }
            _ => {
                self.darwin_unimplemented(format!("sandbox_check with filter type {ftype}"));
                return Err(EINVAL);
            }
        }
        if forbidden {
            if flags & 1 == 0 {
                self.darwin_sb_report(&String::from_utf8_lossy(&name));
            }
            return answer(m, 1);
        }
        let Some(op) = super::mac::OPERATION_NAMES.iter().position(|n| n.as_bytes() == name.as_slice()) else { return Err(EINVAL) };
        if pid != i64::from(self.pid) {
            self.darwin_unimplemented("sandbox_check of another process (its credential as the subject)".into());
            return Err(EINVAL);
        }
        let r = self.darwin_sb_evaluate(op, &a);
        // The POSIX access checks want a vnode.
        if r == 0 && flags & 0x60 != 0 {
            return Err(EINVAL);
        }
        answer(m, u64::from(r))?;
        // The answers asked for besides: no deny message, no extension
        // consumed, no extension flags.
        if flags & 0x1000_0000 != 0 {
            let size_at = q(0x48);
            if size_at != 0 {
                m.write_u64(size_at, 0).map_err(fault)?;
            }
        }
        if flags & 0x800_0000 != 0 && q(0x50) != 0 {
            m.write_u64(q(0x50), 0).map_err(fault)?;
        }
        if flags & 0x200_0000 != 0 && q(0x68) != 0 {
            m.write_u64(q(0x68), 1).map_err(fault)?;
        }
        Ok(())
    }

    /// AMFI's dyld policy for this process.
    fn darwin_dyld_policy(&self) -> u64 {
        let flags = self.dtask.csflags.load(std::sync::atomic::Ordering::Acquire);
        let ents = self.dtask.codesign.as_ref().map(|c| c.ents.clone()).unwrap_or_default();
        // P_SUGID: a credential changed since the last exec.
        super::amfi::dyld_policy(self.dtask.sugid, flags, &ents)
    }

    /// Sandbox's `mpo_policy_syscall` (`0x...69f7e50`); its error, a Darwin
    /// errno.
    fn darwin_sandbox_syscall(&mut self, m: &mut GuestMem<'_>, call: u64, arg: u64) -> Result<(), i32> {
        let fault = |_| 14;
        match call {
            SANDBOX_APPLY_BUILTIN => self.darwin_sb_apply_builtin(m, arg),
            SANDBOX_CHECK => self.darwin_sandbox_check(m, arg),
            SANDBOX_BUILTIN_EXISTS => self.darwin_sb_builtin_exists(m, arg),
            // {&expected, &has_container} (`0x...a0fbf0`): what the process's
            // sandbox says; a process without one has neither.
            SANDBOX_CONTAINER_EXPECTED => {
                let (a, b) = (m.read_u64(arg).map_err(fault)?, m.read_u64(arg + 8).map_err(fault)?);
                let sb = self.darwin_sandbox();
                let expected = sb.as_ref().is_some_and(|s| s.container_expected);
                let has = sb.as_ref().is_some_and(|s| s.container.is_some());
                for (out, v) in [(a, expected), (b, has)] {
                    if out != 0 {
                        m.write_u64(out, u64::from(v)).map_err(fault)?;
                    }
                }
                Ok(())
            }
            _ => {
                self.darwin_unimplemented(format!("Sandbox __mac_syscall {call}"));
                Err(45)
            }
        }
    }
}

/// `initproc_spawned`, which launchd sets through `kern.initproc_spawned`.
static SPAWNED: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// Whether launchd has said it reached main (`initproc_spawned != 0`).
pub(crate) fn initproc_spawned() -> bool {
    SPAWNED.load(std::sync::atomic::Ordering::Relaxed) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// csops finds a process as `proc_find` does: not while its fork makes
    /// it, then (with what that made of it) until it has exited; ESRCH
    /// before the policies are asked, which here, with no Sandbox profile,
    /// refuse what it finds.
    #[test]
    fn csops_finds_what_proc_find_finds() {
        const STATUS: u32 = 0;
        let mut buf = vec![0u8; 0x10000];
        let mut k = Kernel::new(0x1000, 0x10000, "/prog".into());
        k.darwin = true;
        k.darwin_task_enable();
        let mut c = k.fork_kernel();
        c.pid = k.procs.spawn(k.pid);
        c.tid = c.pid;
        let pid = c.pid;
        let mut csops = |k: &mut Kernel, pid: i32| {
            let mut m = GuestMem::new(&mut buf);
            let r = k.darwin_csops(&mut m, pid, STATUS, 0x8000, 4, None);
            k.darwin_ipc_leave();
            r
        };
        assert_eq!(csops(&mut k, pid), Err(Errno::ESRCH), "being made");
        c.darwin_publish();
        let found = csops(&mut k, pid);
        assert!(found.is_err_and(|e| e != Errno::ESRCH), "found, then judged: {found:?}");
        assert_eq!(csops(&mut k, 0), csops(&mut k, 1), "pid 0 is the caller");
        k.procs.set_exited(pid);
        assert_eq!(csops(&mut k, pid), Err(Errno::ESRCH), "exited");
        k.procs.exit(pid, 0);
        assert_eq!(csops(&mut k, pid), Err(Errno::ESRCH), "a zombie");
        k.procs.reap(pid);
        assert_eq!(csops(&mut k, pid), Err(Errno::ESRCH), "reaped");
    }

    #[test]
    fn signal_masks_round_trip() {
        // SIGUSR1 (30) and SIGCHLD (20) on Darwin are 10 and 17 on Linux.
        let d = (1 << 29) | (1 << 19);
        let l = mask_to_linux(d);
        assert_eq!(l, (1 << 9) | (1 << 16));
        assert_eq!(mask_from_linux(l), d);
    }

    /// getfsstat's flags: MNT_NOWAIT alone keeps a mount's counts as they
    /// were; MNT_WAIT and MNT_DWAIT override it; a mount being unmounted
    /// is not refreshed.
    #[test]
    fn getfsstat_flags_choose_a_refresh() {
        let m = Mount::new("/x", From::Devfs, 0, 0, Fs::Devfs, None, 0, None);
        assert!(getfsstat_refreshes(&m, 0));
        assert!(!getfsstat_refreshes(&m, MNT_NOWAIT));
        assert!(getfsstat_refreshes(&m, MNT_NOWAIT | MNT_WAIT));
        assert!(getfsstat_refreshes(&m, MNT_NOWAIT | MNT_DWAIT));
        assert!(getfsstat_refreshes(&m, MNT_DWAIT));
        m.state().stat = Some([1, 2, 3, 4, 5]);
        let c = stat_counts(&m, false);
        assert_eq!((c.blocks, c.bfree, c.bavail, c.files, c.ffree), (1, 2, 3, 4, 5));
        m.state().lflag |= MNT_LUNMOUNT;
        assert!(!getfsstat_refreshes(&m, MNT_WAIT));
    }

    /// The root, mounted from the System volume's sealed snapshot with no
    /// virtual device: its device's path after the snapshot's name, and
    /// the first fsid `vfs_getnewfsid` gives an APFS mount.
    #[test]
    fn the_root_is_named_for_its_snapshot() {
        let root = &boot_mounts()[0];
        assert_eq!(mount_from(root), format!("{}@/dev/disk1s1", super::super::storage::ROOT_SNAPSHOT));
        assert_eq!(root.fsid, 0x3200_0001);
    }

    /// libignition mounts the Preboot volume read-write, nosuid (every
    /// mount on a release kernel), not browsable (asked, and the Preboot
    /// role's), from the volume's device, whose number is its fsid
    /// (disk1s5, the eighth medium, while the minors stand in); a booted
    /// system has it read-only.
    #[test]
    fn the_booted_preboot_mount_is_libignitions() {
        let m = ignition_preboot_mount().unwrap();
        assert_eq!(m.on, "/private/preboot");
        assert_eq!(mount_from(&m), "/dev/disk1s5");
        assert_eq!(m.flags(), MNT_LOCAL | MNT_NOSUID | MNT_DONTBROWSE | MNT_NOATIME | MNT_JOURNALED | MNT_DOVOLFS);
        assert_eq!(m.fsid, 0x0100_0007);
        assert_eq!(m.state().apfs_ro, Some(false));
        assert!(is_preboot(&m));
        let b = booted_preboot_mount().unwrap();
        assert_eq!(b.flags(), m.flags() | MNT_RDONLY);
        assert_eq!((b.fsid, b.state().apfs_ro), (m.fsid, Some(true)));
    }

    /// The Preboot and xART volumes' files are the disk0 image's; with no
    /// image (as in these tests) a path below their mounts, or a listing
    /// of their roots, is reported, as any other volume's is.
    #[test]
    fn the_preboot_volumes_files_are_the_disk0_images() {
        use super::super::storage::role;
        assert!(served_from_disk0(role::PREBOOT) && served_from_disk0(role::XART));
        assert!(!served_from_disk0(role::DATA) && !served_from_disk0(role::SYSTEM));
        assert!(!super::super::disknode::installed());
        let m = ignition_preboot_mount().unwrap();
        assert!(!is_disk0_served(&m));
        let why = unmodelled_files_on(&m, "/private/preboot/cryptex1/current/os.dmg", false).unwrap();
        assert!(why.contains("Preboot") && why.contains("GEX_DARWIN_DISK0"), "{why}");
        assert!(unmodelled_files_on(&m, "/private/preboot", true).is_some());
        assert_eq!(unmodelled_files_on(&m, "/private/preboot", false), None);
    }
}
