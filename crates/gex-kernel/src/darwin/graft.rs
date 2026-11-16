//! `graftdmg` and `ungraftdmg` (xnu-10063.141.1 `bsd/vfs/vfs_syscalls.c`
//! 475-786): a cryptex disk image, a file of a volume, grafted onto a
//! directory of the same volume by the volume's filesystem (`VNOP_IOCTL`
//! `FSIOC_GRAFT_FS` and `FSIOC_UNGRAFT_FS`), and APFS's handling of the two
//! commands (apfs.kext 2236.140.6 of iPad7,1 21H461, `apfs_vnop_ioctl`'s
//! cases at 0xfffffff0066d50a4 and 0xfffffff0066d58b0).
//!
//! libignition in launchd's dyld grafts the SystemOS cryptex this way:
//! `/private/preboot/cryptex1/current/os.dmg` onto
//! `/private/preboot/Cryptexes/OS`, graft type 1 (`GRAFTDMG_CRYPTEX_BOOT`),
//! with `{version 1, 'cssy', the Cryptex1 ticket, -1, os.dmg.root_hash,
//! 0x2d}` (and the AppOS cryptex with `'casy'` and 0x2e).
//!
//! APFS's `handle_fsioc_graft` (0xfffffff0066e3af4) checks the caller and
//! the flags, has AppleImage4 evaluate the payload against the manifest
//! (`validate_payload_and_manifest`, 0xfffffff0066809a0), and grafts
//! (`apfs_graft`, 0xfffffff00668611c) whatever the evaluation said: its
//! status is what the graft's root hash authentication
//! (0xfffffff0066cdaec) is given, after the container in the image is
//! mounted. The evaluation is AppleImage4's
//! ([`Kernel::darwin_img4_firmware_execute`], [`super::image4`]); the
//! image's container is read by [`super::apfsread`] and the graft served by
//! [`super::graftfs`].

use super::graftfs;
use super::macvfs::Found;
use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::GuestMem;

/// `GRAFTDMG_ENTITLEMENT`: what a task needs to graft or ungraft.
pub const GRAFTDMG_ENTITLEMENT: &str = "com.apple.private.vfs.graftdmg";

/// `MAX_GRAFT_ARGS_SIZE`: `graftdmg_args_un`, copied in whole.
pub const MAX_GRAFT_ARGS_SIZE: usize = 512;

/// `GRAFTDMG_SECURE_BOOT_CRYPTEX_ARGS_VERSION`.
pub const SECURE_BOOT_CRYPTEX_ARGS_VERSION: u32 = 1;

/// `GRAFTDMG_CRYPTEX_MAX` (`bsd/sys/mount.h`): the graft types are 1
/// (`GRAFTDMG_CRYPTEX_BOOT`) to 7 (`GRAFTDMG_CRYPTEX_EFFECTIVE_AP`).
pub const GRAFTDMG_CRYPTEX_MAX: u32 = 7;

/// `MAX_GRAFT_METADATA_SIZE`: the most a manifest or payload file holds.
pub const MAX_GRAFT_METADATA_SIZE: u64 = 16384;

/// `FSIOC_GRAFT_VERSION`.
pub const FSIOC_GRAFT_VERSION: u32 = 2;

/// `secure_boot_cryptex_args.sbc_flags` (`bsd/sys/_types/_graftdmg_un.h`).
pub mod sbc {
    pub const PRESERVE_MOUNT: u64 = 0x0001;
    pub const ALTERNATE_SHARED_REGION: u64 = 0x0002;
    pub const SYSTEM_CONTENT: u64 = 0x0004;
    pub const PANIC_ON_AUTHFAIL: u64 = 0x0008;
    pub const STRICT_AUTH: u64 = 0x0010;
    pub const PRESERVE_GRAFT: u64 = 0x0020;
}

/// `FSCTL_GRAFT_*` (`bsd/sys/fsctl.h`), what the filesystem is given.
pub mod fsctl {
    pub const PRESERVE_MOUNT: u64 = 0x0001;
    pub const ALTERNATE_SHARED_REGION: u64 = 0x0002;
    pub const SYSTEM_CONTENT: u64 = 0x0004;
    pub const PANIC_ON_AUTHFAIL: u64 = 0x0008;
    pub const STRICT_AUTH: u64 = 0x0010;
    pub const PRESERVE_GRAFT: u64 = 0x0020;
}

/// The entitlement APFS's `validate_grafting_cred_and_flags` asks of a
/// caller that would keep the volume mounted until shutdown
/// (`FSCTL_GRAFT_PRESERVE_MOUNT`).
pub const EARLY_BOOT_MOUNT_ENTITLEMENT: &str = "com.apple.rootless.storage.early_boot_mount";

/// Darwin's errno numbers these paths return.
mod e {
    pub const EPERM: i32 = 1;
    pub const EIO: i32 = 5;
    pub const EACCES: i32 = 13;
    pub const EXDEV: i32 = 18;
    pub const ENODEV: i32 = 19;
    pub const ENOTDIR: i32 = 20;
    pub const EBUSY: i32 = 16;
    pub const EINVAL: i32 = 22;
    pub const EFBIG: i32 = 27;
    pub const EALREADY: i32 = 37;
    pub const EAUTH: i32 = 80;
    pub const ENOTSUP: i32 = 45;
    pub const ENODATA: i32 = 96;
}

fn err(darwin: i32) -> Errno {
    super::errno::errno_of(darwin)
}

/// A payload four-character code as AppleImage4 compares it.
const fn fourcc(s: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*s)
}

/// The payload types `validate_payload_and_manifest` knows.
pub mod cc {
    use super::fourcc;
    /// The SystemOS cryptex's root hash.
    pub const CSSY: u32 = fourcc(b"cssy");
    /// The AppOS cryptex's root hash.
    pub const CASY: u32 = fourcc(b"casy");
    pub const EXVL: u32 = fourcc(b"exvl");
    pub const GTGV: u32 = fourcc(b"gtgv");
    pub const SYAB: u32 = fourcc(b"syab");
    pub const XSYS: u32 = fourcc(b"xsys");
}

/// `secure_boot_cryptex_args_t`, the start of the copied-in
/// `graftdmg_args_un` (packed, aligned 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SbcArgs {
    pub version: u32,
    pub fourcc: u32,
    pub manifest_fd: i32,
    pub user_manifest_fd: i32,
    pub payload_fd: i32,
    pub flags: u64,
}

impl SbcArgs {
    pub fn parse(b: &[u8; MAX_GRAFT_ARGS_SIZE]) -> SbcArgs {
        let u = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        SbcArgs {
            version: u(0),
            fourcc: u(4),
            manifest_fd: u(8) as i32,
            user_manifest_fd: u(12) as i32,
            payload_fd: u(16) as i32,
            flags: u64::from_le_bytes(b[20..28].try_into().unwrap()),
        }
    }
}

/// graftdmg's check of the graft type (vfs_syscalls.c:724).
pub fn graft_type_ok(graft_type: u32) -> bool {
    graft_type != 0 && graft_type <= GRAFTDMG_CRYPTEX_MAX
}

/// The directory to graft on, as `graft_secureboot_cryptex` checks it:
/// whether it is on the image's mount, and whether it is a directory.
#[derive(Clone, Copy, Debug)]
pub struct MountOn {
    pub same_mount: bool,
    pub is_dir: bool,
}

/// `graft_secureboot_cryptex`'s pre-flight (vfs_syscalls.c:593-605), in its
/// order: the arguments' version (ENOTSUP), the image and the directory on
/// one mount (EXDEV), the directory one (ENOTDIR), a manifest and a
/// payload descriptor (EINVAL). Without a directory only the version and
/// the descriptors are checked.
pub fn preflight(args: &SbcArgs, on: Option<MountOn>) -> Result<(), i32> {
    if args.version != SECURE_BOOT_CRYPTEX_ARGS_VERSION {
        return Err(e::ENOTSUP);
    }
    if let Some(on) = on {
        if !on.same_mount {
            return Err(e::EXDEV);
        }
        if !on.is_dir {
            return Err(e::ENOTDIR);
        }
    }
    if args.manifest_fd < 0 || args.payload_fd < 0 {
        return Err(e::EINVAL);
    }
    Ok(())
}

/// `get_and_verify_graft_metadata_vp_size` of a file of `st_size` bytes:
/// none is ENODATA, more than [`MAX_GRAFT_METADATA_SIZE`] EFBIG.
pub fn metadata_size(st_size: u64) -> Result<usize, i32> {
    if st_size == 0 {
        Err(e::ENODATA)
    } else if st_size > MAX_GRAFT_METADATA_SIZE {
        Err(e::EFBIG)
    } else {
        Ok(st_size as usize)
    }
}

/// The filesystem's flags for `sbc_flags` (vfs_syscalls.c:637-654): each
/// `SBC_*` its `FSCTL_GRAFT_*`, any other bit dropped.
pub fn graft_flags(sbc_flags: u64) -> u64 {
    [
        (sbc::PRESERVE_MOUNT, fsctl::PRESERVE_MOUNT),
        (sbc::ALTERNATE_SHARED_REGION, fsctl::ALTERNATE_SHARED_REGION),
        (sbc::SYSTEM_CONTENT, fsctl::SYSTEM_CONTENT),
        (sbc::PANIC_ON_AUTHFAIL, fsctl::PANIC_ON_AUTHFAIL),
        (sbc::STRICT_AUTH, fsctl::STRICT_AUTH),
        (sbc::PRESERVE_GRAFT, fsctl::PRESERVE_GRAFT),
    ]
    .iter()
    .filter(|(s, _)| sbc_flags & s != 0)
    .fold(0, |f, (_, g)| f | g)
}

/// APFS's `validate_grafting_cred_and_flags` (inlined in
/// `handle_fsioc_graft`, 0xfffffff0066e3b28..0xfffffff0066e3b64): the
/// superuser (`kauth_cred_issuser`, else EACCES); to keep the volume
/// mounted until shutdown, the early-boot-mount entitlement (the boolean
/// true, else EACCES) and a volume of the Preboot role (the superblock's
/// `apfs_role`, else ENOTSUP).
pub fn cred_and_flags(issuser: bool, flags: u64, early_boot_mount: bool, role: u16) -> Result<(), i32> {
    if !issuser {
        return Err(e::EACCES);
    }
    if flags & fsctl::PRESERVE_MOUNT != 0 {
        if !early_boot_mount {
            return Err(e::EACCES);
        }
        if role != super::storage::role::PREBOOT {
            return Err(e::ENOTSUP);
        }
    }
    Ok(())
}

/// `handle_fsioc_graft`'s checks of `fsioc_graft_fs_t` after the caller's
/// (0xfffffff0066e3b68..0xfffffff0066e3b90): its version (ENOTSUP), then a
/// manifest and a payload, each with a size (EINVAL).
pub fn graft_args_ok(version: u32, manifest_size: usize, payload_size: usize) -> Result<(), i32> {
    if version != FSIOC_GRAFT_VERSION {
        return Err(e::ENOTSUP);
    }
    if manifest_size == 0 || payload_size == 0 {
        return Err(e::EINVAL);
    }
    Ok(())
}

/// The AppleImage4 chip `validate_payload_and_manifest` evaluates a graft
/// against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chip {
    /// Graft type 1 (`GRAFTDMG_CRYPTEX_BOOT`): the AP chip's +0x138
    /// (0xfffffff005a93908), `CHIP_CRYPTEX1_BOOT_AP` ('c1bt',
    /// 0xfffffff006cf29b0).
    Cryptex1BootAp,
    /// Graft type 2 (`GRAFTDMG_CRYPTEX_PREBOOT`): the AP chip's +0x148
    /// (0xfffffff005a93920).
    ApPlus148,
    /// Graft type 3 (`GRAFTDMG_CRYPTEX_DOWNLEVEL`): the chip at
    /// 0xfffffff006cf13a8.
    Downlevel,
    /// Graft type 7 (`GRAFTDMG_CRYPTEX_EFFECTIVE_AP`) with 'exvl', and a
    /// graft of no type with 'xsys': the AP chip (0xfffffff005a91d14).
    Ap,
    /// 'gtgv' with graft type 4: the chip at 0xfffffff006cf5f48.
    Gtgv4,
    /// 'gtgv' with graft type 5: the chip at 0xfffffff006cf9808.
    Gtgv5,
    /// 'syab': the chip at 0xfffffff006cf7b40.
    Syab,
}

impl Chip {
    pub fn describe(self) -> &'static str {
        match self {
            Chip::Cryptex1BootAp => "CHIP_CRYPTEX1_BOOT_AP ('c1bt', the AP chip's +0x138)",
            Chip::ApPlus148 => "the AP chip's +0x148",
            Chip::Downlevel => "the chip at 0xfffffff006cf13a8",
            Chip::Ap => "the AP chip",
            Chip::Gtgv4 => "the chip at 0xfffffff006cf5f48",
            Chip::Gtgv5 => "the chip at 0xfffffff006cf9808",
            Chip::Syab => "the chip at 0xfffffff006cf7b40",
        }
    }
}

/// What `validate_payload_and_manifest` evaluates a graft with: the chip,
/// whether the PDI nonce is given (`img4_nonce_domain_copy_nonce` of the
/// nonce domain at 0xfffffff0052d0138; NULL otherwise), and
/// `img4_firmware_new`'s flags (4 for 'exvl').
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    pub chip: Chip,
    pub pdi_nonce: bool,
    pub firmware_flags: u32,
}

/// `validate_payload_and_manifest`'s choice for graft type `graft_type`
/// and payload type `fourcc` (0xfffffff006680a80..0xfffffff006680d08,
/// the type's jump table at 0xfffffff0055aee83): 'xsys' only with no
/// type, 'exvl' only with type 7 (EINVAL otherwise); 'cssy', 'casy' and
/// 'exvl' with types 1, 2, 3 and 7; 'gtgv' with types 4 and 5; 'syab' with
/// any, the PDI nonce with type 6; anything else EINVAL.
pub fn chip_for(graft_type: u32, payload: u32) -> Result<Selection, i32> {
    if (graft_type != 0) == (payload == cc::XSYS) {
        return Err(e::EINVAL);
    }
    if (graft_type != 7) == (payload == cc::EXVL) {
        return Err(e::EINVAL);
    }
    let sel = |chip| Ok(Selection { chip, pdi_nonce: false, firmware_flags: if payload == cc::EXVL { 4 } else { 0 } });
    match payload {
        cc::CASY | cc::CSSY | cc::EXVL => match graft_type {
            1 => sel(Chip::Cryptex1BootAp),
            2 => sel(Chip::ApPlus148),
            3 => sel(Chip::Downlevel),
            7 => sel(Chip::Ap),
            _ => Err(e::EINVAL),
        },
        cc::GTGV => match graft_type {
            4 => sel(Chip::Gtgv4),
            5 => sel(Chip::Gtgv5),
            _ => Err(e::EINVAL),
        },
        cc::SYAB => Ok(Selection { chip: Chip::Syab, pdi_nonce: graft_type == 6, firmware_flags: 0 }),
        cc::XSYS => sel(Chip::Ap),
        _ => Err(e::EINVAL),
    }
}

/// `fsioc_graft_fs_t` as `graft_secureboot_cryptex` fills it, with the
/// directory `dir_ino` names (what APFS's `vget` of it finds: the one the
/// lookup found, on the image's volume), none when no directory was given.
pub struct GraftFs {
    pub version: u32,
    pub graft_type: u32,
    pub fourcc: u32,
    pub flags: u64,
    pub dir_ino: u64,
    pub dir: Option<Found>,
    pub manifest: Vec<u8>,
    pub payload: Vec<u8>,
}

/// A four-character code as text.
fn fourcc_str(c: u32) -> String {
    c.to_be_bytes().iter().map(|&b| if b.is_ascii_graphic() { b as char } else { '?' }).collect()
}

impl Kernel {
    /// `graftdmg(dmg_fd, mountdir, graft_type, gda)`: the caller's
    /// entitlement (EPERM), the arguments copied in, the directory looked
    /// up (following a link at its end), the image's descriptor, the graft
    /// type (EINVAL), then `graft_secureboot_cryptex`.
    pub(crate) fn darwin_graftdmg(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        let (dmg_fd, mountdir, graft_type, gda) = (a[0] as i32, a[1], a[2] as u32, a[3]);
        if !self.darwin_entitled(GRAFTDMG_ENTITLEMENT) {
            return Err(err(e::EPERM));
        }
        let raw: [u8; MAX_GRAFT_ARGS_SIZE] = m.read(gda, MAX_GRAFT_ARGS_SIZE)?.try_into().map_err(|_| Errno::EFAULT)?;
        let mounton = if mountdir != 0 { Some(self.darwin_graft_namei(m, mountdir)?) } else { None };
        let cryptex = self.darwin_graft_vnode_of_fd(dmg_fd)?;
        if !graft_type_ok(graft_type) {
            return Err(err(e::EINVAL));
        }
        self.darwin_graft_secureboot_cryptex(graft_type, &SbcArgs::parse(&raw), cryptex, mounton)?;
        Ok(0)
    }

    /// `ungraftdmg(mountdir, flags)`: the caller's entitlement (EPERM), no
    /// flags and a directory (EINVAL), its lookup, and the filesystem's
    /// `FSIOC_UNGRAFT_FS` with no flags.
    pub(crate) fn darwin_ungraftdmg(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> Result<u64, Errno> {
        if !self.darwin_entitled(GRAFTDMG_ENTITLEMENT) {
            return Err(err(e::EPERM));
        }
        if a[1] != 0 || a[0] == 0 {
            return Err(err(e::EINVAL));
        }
        let dir = self.darwin_graft_namei(m, a[0])?;
        self.darwin_vnop_ioctl_ungraft(&dir)?;
        Ok(0)
    }

    /// `namei` of a graft's directory (`LOOKUP`, `OP_MOUNT`, `FOLLOW`):
    /// Sandbox's lookup checks, then the lookup's own errors.
    fn darwin_graft_namei(&mut self, m: &mut GuestMem<'_>, path: u64) -> Result<Found, Errno> {
        const MAXPATHLEN: usize = 1024;
        self.darwin_sb_namei(m, super::bsd::AT_FDCWD as u64, path, true, false)?;
        let raw = m.read_cstr(path, MAXPATHLEN)?;
        let given = std::str::from_utf8(&raw).map_err(|_| Errno::EINVAL)?;
        let abs = self.path_io().at_path_str(super::bsd::dirfd(super::bsd::AT_FDCWD as u64) as i32, given)?;
        let md = self.vfs.metadata(&abs)?;
        let at = self.vfs.canonical(&abs);
        let mnt = super::kern::mount_of(&at);
        Ok(Found { path: at, md, parent: None, mnt: Some(mnt) })
    }

    /// `vnode_getfromfd`: the vnode an open descriptor is of
    /// (`fp_getfvp`: EBADF for no descriptor, ENOTSUP for one that is no
    /// vnode's), on the mount it was opened on.
    fn darwin_graft_vnode_of_fd(&mut self, fd: i32) -> Result<Found, Errno> {
        let file = self.fds.get(fd)?;
        if self.darwin_vnode_of(&file).is_none() {
            return Err(err(e::ENOTSUP));
        }
        self.darwin_sb_fd_vnode(fd).ok_or(Errno::EBADF)
    }

    /// `vn_stat` of a vnode for its inode number and size: the MAC
    /// policies' stat check (with no file credential), then
    /// `vnode_authorize` of reading its attributes and its security.
    fn darwin_graft_vn_stat(&mut self, f: &Found) -> Result<(u64, u64), Errno> {
        let refused = self.darwin_mac_check_vnode_stat(f.sb());
        if refused != 0 {
            return Err(err(refused as i32));
        }
        let node = self.darwin_found_node(f);
        let cred = self.dtask.cred.clone();
        use super::vauth::kauth;
        self.darwin_authorize(&cred, &node, None, kauth::READ_ATTRIBUTES | kauth::READ_SECURITY)?;
        let mut st = Kernel::stat_from(&f.md);
        if f.mnt.is_some_and(|mnt| mnt.fs == super::kern::Fs::Devfs) {
            super::devfs::stat_fixup(&mut st, &f.md, &f.path);
        }
        Ok((st.ino, st.size as u64))
    }

    /// `graft_secureboot_read_fd`: the file a descriptor is of, its size
    /// checked ([`metadata_size`]), read whole from its start
    /// (`vn_rdwr`, `IO_UNIT`: EIO when less is read). `vn_rdwr` reads the
    /// vnode whatever the descriptor was opened for.
    fn darwin_graft_read_fd(&mut self, fd: i32) -> Result<Vec<u8>, Errno> {
        let f = self.darwin_graft_vnode_of_fd(fd)?;
        let (_, st_size) = self.darwin_graft_vn_stat(&f)?;
        let size = metadata_size(st_size).map_err(err)?;
        let file = self.fds.get(fd)?;
        // A descriptor open only to write holds a handle that cannot read:
        // the vnode is opened again by its path, while that names it.
        let handle = if file.readable {
            std::sync::Arc::clone(&file.handle)
        } else {
            match self.vfs.open(&f.path, 0, 0) {
                Ok(h) if h.metadata().is_ok_and(|md| md.ino == f.md.ino) => h,
                _ => {
                    self.darwin_unimplemented(format!("reading {} for a graft through a descriptor open only to write, which its path no longer names", f.path));
                    return Err(Errno::EINVAL);
                }
            }
        };
        let mut buf = vec![0u8; size];
        let mut done = 0;
        while done < size {
            let n = handle.read_at(done as u64, &mut buf[done..])? as usize;
            if n == 0 {
                break;
            }
            done += n;
        }
        if done < size {
            return Err(err(e::EIO));
        }
        Ok(buf)
    }

    /// `graft_secureboot_cryptex`: the pre-flight ([`preflight`]), the
    /// directory's inode number (`vn_stat`; 0 without one), the manifest
    /// then the payload read in (the user manifest is not), the request
    /// filled in, and `VNOP_IOCTL(FSIOC_GRAFT_FS)` of the image.
    fn darwin_graft_secureboot_cryptex(&mut self, graft_type: u32, args: &SbcArgs, cryptex: Found, mounton: Option<Found>) -> Result<(), Errno> {
        let on = mounton.as_ref().map(|d| MountOn {
            same_mount: matches!((cryptex.mnt, d.mnt), (Some(a), Some(b)) if std::ptr::eq(a, b)),
            is_dir: d.is_dir(),
        });
        preflight(args, on).map_err(err)?;
        let dir_ino = match &mounton {
            Some(d) => self.darwin_graft_vn_stat(d)?.0,
            None => 0,
        };
        let manifest = self.darwin_graft_read_fd(args.manifest_fd)?;
        let payload = self.darwin_graft_read_fd(args.payload_fd)?;
        let gfs = GraftFs { version: FSIOC_GRAFT_VERSION, graft_type, fourcc: args.fourcc, flags: graft_flags(args.flags), dir_ino, dir: mounton, manifest, payload };
        self.darwin_vnop_ioctl_graft(&cryptex, gfs)
    }

    /// `VNOP_IOCTL(FSIOC_GRAFT_FS)` of the image's vnode (APFS and devfs
    /// are both `VFC_VFS64BITREADY`): APFS's for a file of one of the
    /// container's volumes; devfs's `err_ioctl` (ENOTSUP) for a
    /// directory or link of it, and the driver's `d_ioctl` for a device.
    fn darwin_vnop_ioctl_graft(&mut self, vp: &Found, gfs: GraftFs) -> Result<(), Errno> {
        let mnt = vp.mnt.unwrap_or_else(|| super::kern::mount_of(&vp.path));
        match mnt.fs {
            super::kern::Fs::Devfs => self.darwin_devfs_vnop_ioctl(vp, "FSIOC_GRAFT_FS"),
            super::kern::Fs::Apfs => match super::kern::mount_volume(mnt) {
                Some(volume) => self.darwin_apfs_handle_fsioc_graft(volume, vp, gfs),
                None => {
                    self.darwin_unimplemented(format!("APFS's FSIOC_GRAFT_FS of {}, on the mount standing for the OS cryptex's graft", vp.path));
                    Err(Errno::EINVAL)
                }
            },
        }
    }

    /// `VNOP_IOCTL(FSIOC_UNGRAFT_FS)` of the directory's vnode, as
    /// [`Kernel::darwin_vnop_ioctl_graft`] sends it.
    fn darwin_vnop_ioctl_ungraft(&mut self, vp: &Found) -> Result<(), Errno> {
        let mnt = vp.mnt.unwrap_or_else(|| super::kern::mount_of(&vp.path));
        match mnt.fs {
            super::kern::Fs::Devfs => self.darwin_devfs_vnop_ioctl(vp, "FSIOC_UNGRAFT_FS"),
            super::kern::Fs::Apfs => match super::kern::mount_volume(mnt) {
                Some(volume) => self.darwin_apfs_handle_fsioc_ungraft(volume, vp),
                None => {
                    self.darwin_unimplemented(format!("APFS's FSIOC_UNGRAFT_FS of {}, on the mount standing for the OS cryptex's graft", vp.path));
                    Err(Errno::EINVAL)
                }
            },
        }
    }

    /// devfs's `vnop_ioctl`: `err_ioctl` (ENOTSUP) for its own nodes,
    /// `spec_ioctl` (the driver's `d_ioctl`) for a device.
    fn darwin_devfs_vnop_ioctl(&mut self, vp: &Found, what: &str) -> Result<(), Errno> {
        use crate::vfs::FileType;
        match vp.md.file_type {
            FileType::CharDevice | FileType::BlockDevice => {
                self.darwin_unimplemented(format!("{what} of {}: its driver's d_ioctl", vp.path));
                Err(Errno::EINVAL)
            }
            _ => Err(err(e::ENOTSUP)),
        }
    }

    /// APFS's `handle_fsioc_graft` (0xfffffff0066e3af4) for an image on the
    /// volume at slot `volume`: the caller and the flags
    /// ([`cred_and_flags`]), the request ([`graft_args_ok`]), the
    /// evaluation of the payload against the manifest, and `apfs_graft`
    /// with its status, whatever it is (a failure is logged first).
    fn darwin_apfs_handle_fsioc_graft(&mut self, volume: u32, file: &Found, gfs: GraftFs) -> Result<(), Errno> {
        let issuser = self.dtask.cred.uid == 0;
        let early = self.darwin_entitled(EARLY_BOOT_MOUNT_ENTITLEMENT);
        let role = super::storage::volume(volume).map_or(0, |v| v.role);
        cred_and_flags(issuser, gfs.flags, early, role).map_err(err)?;
        graft_args_ok(gfs.version, gfs.manifest.len(), gfs.payload.len()).map_err(err)?;
        let Some(status) = self.darwin_apfs_validate_payload_and_manifest(gfs.graft_type, gfs.fourcc, &gfs.payload, &gfs.manifest) else {
            return Err(Errno::EINVAL);
        };
        self.darwin_apfs_graft(volume, file, gfs.dir.as_ref(), gfs.flags, status)
    }

    /// `validate_payload_and_manifest` (0xfffffff0066809a0): AppleImage4's
    /// service waited for (this kernel's own, [`super::img4`]), the chip
    /// for the graft ([`chip_for`]), and AppleImage4's evaluation of the
    /// payload, the root hash, against the manifest. The status is 0 with
    /// the authenticated payload, or the error; `None` where what decides
    /// it is not implemented (reported).
    fn darwin_apfs_validate_payload_and_manifest(&mut self, graft_type: u32, fourcc: u32, payload: &[u8], manifest: &[u8]) -> Option<Result<Vec<u8>, i32>> {
        let sel = match chip_for(graft_type, fourcc) {
            Ok(sel) => sel,
            Err(status) => return Some(Err(status)),
        };
        if sel.pdi_nonce {
            self.darwin_unimplemented(format!("img4_nonce_domain_copy_nonce of the PDI nonce domain (0xfffffff0052d0138) for a graft of '{}'", fourcc_str(fourcc)));
            return None;
        }
        // (img4_firmware_new fails, ENOMEM, only when it cannot allocate.)
        self.darwin_img4_firmware_execute(sel, fourcc, payload, manifest)
    }

    /// `apfs_graft` (0xfffffff00668611c) of the image `file` on the volume
    /// at slot `volume` onto directory `dir` (none: the image's own
    /// directory), with the evaluation's `status`. In its order: the image
    /// a regular file (ENODEV); the volume unencrypted, with no
    /// encryption rolling (ENOTSUP: `APFS_FS_UNENCRYPTED` in its
    /// superblock's `apfs_fs_flags` and no `apfs_er_state_oid`, which
    /// [`super::storage::volume_unencrypted`] answers for the volumes the
    /// restore makes, none of them rolling); under the graft lock, the
    /// volume's grafts ([`Kernel::darwin_apfs_graft_checks`]); the image's
    /// size (`apfs_get_file_size`) not 0 (EINVAL). Then the container in
    /// the image is mounted and its sealed volume's root hash
    /// authenticated with `status` ([`graftfs::authenticate_root_hash`]),
    /// and the graft is made ([`Kernel::darwin_apfs_graft_make`]).
    fn darwin_apfs_graft(&mut self, volume: u32, file: &Found, dir: Option<&Found>, flags: u64, status: Result<Vec<u8>, i32>) -> Result<(), Errno> {
        use crate::vfs::FileType;
        if file.md.file_type != FileType::Regular {
            return Err(err(e::ENODEV));
        }
        match super::storage::volume_unencrypted(volume) {
            Some(true) => {}
            Some(false) => return Err(err(e::ENOTSUP)),
            None => {
                let name = super::storage::volume(volume).map_or("?", |v| v.name);
                self.darwin_unimplemented(format!("apfs_graft on the {name} volume: whether it is unencrypted"));
                return Err(Errno::EINVAL);
            }
        }
        let dir = match dir {
            Some(d) => d.clone(),
            None => {
                let parent = crate::vfs::normalize("..", &file.path);
                let md = self.vfs.metadata(&parent)?;
                Found { mnt: file.mnt, path: parent, md, parent: None }
            }
        };
        self.darwin_apfs_graft_checks(volume, file, &dir)?;
        if file.md.size == 0 {
            return Err(err(e::EINVAL));
        }
        // The blockmap: the image's blocks, the file's own on the volume.
        let medium = self.darwin_graft_medium(file)?;
        let image = match graftfs::mount_image(medium) {
            Ok(Ok(v)) => v,
            // "No fs oid at fs index 0 for graft".
            Ok(Err(errno)) => return Err(err(errno)),
            Err(why) => {
                self.darwin_unimplemented(format!("APFS's error for a graft of {} whose container does not mount here: {why}", file.path));
                return Err(Errno::EIO);
            }
        };
        let vtype = if flags & fsctl::STRICT_AUTH != 0 { 5 } else { 4 };
        let panic_flag = flags & fsctl::PANIC_ON_AUTHFAIL != 0;
        let Some(required) = graftfs::authentication_required(image.sb.role) else {
            self.darwin_unimplemented(format!("apfs_graft of {}: whether root hash authentication is required of a Recovery volume (the boot-args' arp0)", file.path));
            return Err(Errno::EINVAL);
        };
        if !image.sb.sealed() {
            if required {
                let why = format!("Graft of an unsealed image (volume type: {vtype}) is not allowed");
                if panic_flag {
                    self.darwin_unimplemented(format!("the kernel panics: {why}"));
                    return Err(Errno::EIO);
                }
                return Err(err(e::EAUTH));
            }
        } else {
            let im = match image.integrity() {
                Ok(Some(im)) => im,
                Ok(None) => unreachable!("a sealed volume has integrity metadata"),
                Err(why) => {
                    self.darwin_unimplemented(format!("APFS's error for a graft of {} whose integrity object is not read here (\"Fetching the integrity object for the graft failed\"): {why}", file.path));
                    return Err(Errno::EIO);
                }
            };
            let case_insensitive = image.sb.incompat & super::apfsread::incompat::CASE_INSENSITIVE != 0;
            let (payload, st) = match &status {
                Ok(p) => (Some(&p[..]), 0),
                Err(errno) => (None, *errno),
            };
            match graftfs::authenticate_root_hash(required, panic_flag, &im, payload, st, image.container.block_size(), case_insensitive) {
                graftfs::Auth::Ok => {}
                graftfs::Auth::Eauth(_) => return Err(err(e::EAUTH)),
                graftfs::Auth::Panic(why) => {
                    self.darwin_unimplemented(format!("the kernel panics: {why}"));
                    return Err(Errno::EIO);
                }
            }
        }
        self.darwin_apfs_graft_make(volume, file, &dir, flags, image)
    }

    /// The image's blocks as the graft reads them: a Preboot file the
    /// restore copied from the host's IPSW is read there, any other through
    /// its own handle.
    fn darwin_graft_medium(&mut self, file: &Found) -> Result<std::sync::Arc<dyn super::apfsread::Medium>, Errno> {
        let mnt = file.mnt.unwrap_or_else(|| super::kern::mount_of(&file.path));
        if super::kern::is_preboot(mnt) {
            let rel = file.path.strip_prefix(mnt.on.trim_end_matches('/')).unwrap_or(&file.path);
            if let (Some(fs), Some(host)) = (super::preboot::made(), super::preboot::host()) {
                if let Some((url, size)) = fs.lazy_source(rel) {
                    return Ok(std::sync::Arc::new(graftfs::ImageMedium::Host { url, size, read: host.read }));
                }
            }
        }
        let handle = self.vfs.open(&file.path, 0, 0)?;
        let size = handle.metadata()?.size;
        Ok(std::sync::Arc::new(graftfs::ImageMedium::Handle { handle, size }))
    }

    /// `apfs_graft`'s checks of the volume's grafts, under the graft lock
    /// (0xfffffff006686290..0xfffffff006686800), in their order: the count
    /// (EBUSY at [`graftfs::MAX_GRAFTS`]); the directory inside a graft
    /// (EBUSY); the directory one (ENOTDIR); the image compressed (ENOTSUP);
    /// the image inside a graft (EBUSY); the image already grafted, or the
    /// directory grafted on (EALREADY).
    ///
    /// A booted system's Preboot volume has the grafts its boot made, which
    /// the mount at `/System/Cryptexes/OS` stands for: there they are
    /// reported where they decide.
    fn darwin_apfs_graft_checks(&mut self, volume: u32, file: &Found, dir: &Found) -> Result<(), Errno> {
        if self.darwin_volume_has_cryptex_grafts(volume) {
            self.darwin_unimplemented(format!("apfs_graft of {} onto {}: the booted system's grafts of the Preboot volume", file.path, dir.path));
            return Err(Errno::EINVAL);
        }
        let on = graftfs::grafts_on(volume);
        if on.len() >= graftfs::MAX_GRAFTS {
            return Err(err(e::EBUSY));
        }
        if graftfs::graft_at(&dir.path).is_some_and(|g| g.dir_path != dir.path) {
            return Err(err(e::EBUSY));
        }
        if !dir.is_dir() {
            return Err(err(e::ENOTDIR));
        }
        match self.darwin_found_node(file).attrs {
            Ok(o) if o.flags & super::vattr::flags::UF_COMPRESSED != 0 => return Err(err(e::ENOTSUP)),
            Ok(_) => {}
            Err(why) => {
                self.darwin_unimplemented(format!("apfs_graft of {}: whether it is compressed ({why})", file.path));
                return Err(Errno::EINVAL);
            }
        }
        if graftfs::graft_at(&file.path).is_some() {
            return Err(err(e::EBUSY));
        }
        if on.iter().any(|g| g.file_ino == file.md.ino && g.file_path == file.path) || on.iter().any(|g| g.dir_ino == dir.md.ino && g.dir_path == dir.path) {
            return Err(err(e::EALREADY));
        }
        Ok(())
    }

    /// The graft made (0xfffffff006686a40..0xfffffff006686e30): its range
    /// of the host volume's object identifiers, as long as the image
    /// volume's `apfs_next_obj_id` (`allocate_graft_jobj_range`: from the
    /// host's next identifier, ERANGE past the system identifiers; a
    /// read-only host hands them out in memory, a writable one takes them
    /// from its superblock and records them in the image file's attributes);
    /// its device ([`graftfs::graft_devt`], EBUSY); and its volume served
    /// at the directory ([`graftfs::GraftMount`]). `FSCTL_GRAFT_PRESERVE_MOUNT`
    /// marks the host mount a system mount (`vfs_setmntsystem`), which only
    /// an unmount reads, and this kernel unmounts nothing; the graft's
    /// fsevent goes to no reader, the fsevents device being reported where
    /// it is opened.
    fn darwin_apfs_graft_make(&mut self, volume: u32, file: &Found, dir: &Found, flags: u64, image: super::apfsread::Volume) -> Result<(), Errno> {
        let mnt = file.mnt.unwrap_or_else(|| super::kern::mount_of(&file.path));
        let Some(host) = super::preboot::made().filter(|_| super::kern::is_preboot(mnt)) else {
            self.darwin_unimplemented(format!("apfs_graft of {} on the volume mounted on {}: its next object identifier", file.path, mnt.on));
            return Err(Errno::EINVAL);
        };
        let len = image.sb.next_obj_id;
        let (devc, handed) = graftfs::counters(volume);
        // The host's next object identifier: the Preboot volume's
        // (super::preboot::NEXT_OBJ_ID_STAND_IN).
        let next = host.next_ino();
        graftfs::jobj_range_ok(next, len).map_err(err)?;
        let read_only = mnt.state().apfs_ro == Some(true);
        let (base, handed) = if read_only {
            (next + handed, handed + len)
        } else {
            self.darwin_unimplemented(format!(
                "write_graft_file_xattrs: the graft range {}+{len} of {} recorded in its com.apple.fs.graft-vol-uuid, -jobj-id-base and -jobj-id-len attributes on the writable Preboot volume",
                next, file.path
            ));
            (host.take_inos(len), handed)
        };
        let host_devt = mnt.fsid as u32;
        let taken: Vec<u32> = graftfs::grafts_on(volume).iter().map(|g| g.fs.devt).collect();
        let (devt, devc) = graftfs::graft_devt(host_devt, devc, &taken);
        let Some(devt) = devt else {
            return Err(err(e::EBUSY));
        };
        let parent = crate::vfs::normalize("..", &dir.path);
        let dir_parent_ino = self.vfs.metadata(&parent)?.ino;
        let fs = std::sync::Arc::new(graftfs::GraftFs { vol: image, base, len, dir_ino: dir.md.ino, dir_parent_ino, devt });
        self.vfs.mount(&dir.path, std::sync::Arc::new(graftfs::GraftMount(std::sync::Arc::clone(&fs))));
        graftfs::add(graftfs::Graft { host_volume: volume, host_devt, file_path: file.path.clone(), file_ino: file.md.ino, dir_path: dir.path.clone(), dir_ino: dir.md.ino, flags, fs }, devc, handed);
        Ok(())
    }

    /// Whether the volume at slot `volume` has grafts this kernel does not
    /// hold: a booted system's Preboot volume, which has its cryptexes'.
    fn darwin_volume_has_cryptex_grafts(&self, volume: u32) -> bool {
        super::storage::volume(volume).is_some_and(|v| v.role == super::storage::role::PREBOOT) && super::kern::boot_state() == super::kern::BootState::Booted
    }

    /// APFS's `handle_fsioc_ungraft` (0xfffffff0066e3d1c) of a directory
    /// on the volume at slot `volume`, with no flags: the superuser
    /// (EACCES), then `apfs_ungraft_by_ino`: EINVAL for a directory that
    /// is no graft's ("inode %llu is not a graft host dir!"); the ungraft
    /// of one is not implemented (reported).
    fn darwin_apfs_handle_fsioc_ungraft(&mut self, volume: u32, dir: &Found) -> Result<(), Errno> {
        if self.dtask.cred.uid != 0 {
            return Err(err(e::EACCES));
        }
        if self.darwin_volume_has_cryptex_grafts(volume) {
            self.darwin_unimplemented(format!("apfs_ungraft_by_ino of {}: the booted system's grafts of the Preboot volume", dir.path));
            return Err(Errno::EINVAL);
        }
        if graftfs::grafts_on(volume).iter().any(|g| g.dir_path == dir.path) {
            self.darwin_unimplemented(format!("apfs_ungraft_by_ino of the graft on {}", dir.path));
            return Err(Errno::EINVAL);
        }
        Err(err(e::EINVAL))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(version: u32, manifest_fd: i32, payload_fd: i32) -> SbcArgs {
        SbcArgs { version, fourcc: cc::CSSY, manifest_fd, user_manifest_fd: -1, payload_fd, flags: 0x2d }
    }

    /// libignition's arguments for the SystemOS cryptex, at their packed
    /// offsets.
    #[test]
    fn the_arguments_are_packed() {
        let mut b = [0u8; MAX_GRAFT_ARGS_SIZE];
        b[0..4].copy_from_slice(&1u32.to_le_bytes());
        b[4..8].copy_from_slice(&cc::CSSY.to_le_bytes());
        b[8..12].copy_from_slice(&5i32.to_le_bytes());
        b[12..16].copy_from_slice(&(-1i32).to_le_bytes());
        b[16..20].copy_from_slice(&6i32.to_le_bytes());
        b[20..28].copy_from_slice(&0x2du64.to_le_bytes());
        assert_eq!(SbcArgs::parse(&b), SbcArgs { version: 1, fourcc: cc::CSSY, manifest_fd: 5, user_manifest_fd: -1, payload_fd: 6, flags: 0x2d });
        assert_eq!(cc::CSSY, 0x6373_7379);
        assert_eq!(cc::CASY, 0x6361_7379);
    }

    #[test]
    fn graft_types_are_one_to_seven() {
        assert!(!graft_type_ok(0));
        assert!((1..=7).all(graft_type_ok));
        assert!(!graft_type_ok(8));
        assert!(!graft_type_ok(u32::MAX));
    }

    /// The version first, then the directory's mount, then its type, then
    /// the descriptors.
    #[test]
    fn the_preflight_goes_in_its_order() {
        let other = Some(MountOn { same_mount: false, is_dir: false });
        let file = Some(MountOn { same_mount: true, is_dir: false });
        let dir = Some(MountOn { same_mount: true, is_dir: true });
        assert_eq!(preflight(&args(2, -1, -1), other), Err(e::ENOTSUP));
        assert_eq!(preflight(&args(1, -1, -1), other), Err(e::EXDEV));
        assert_eq!(preflight(&args(1, -1, -1), file), Err(e::ENOTDIR));
        assert_eq!(preflight(&args(1, -1, 4), dir), Err(e::EINVAL));
        assert_eq!(preflight(&args(1, 3, -1), dir), Err(e::EINVAL));
        assert_eq!(preflight(&args(1, 3, 4), dir), Ok(()));
        // No directory: no mount or type to check.
        assert_eq!(preflight(&args(1, 3, 4), None), Ok(()));
        assert_eq!(preflight(&args(0, 3, 4), None), Err(e::ENOTSUP));
        assert_eq!(preflight(&args(1, -1, 4), None), Err(e::EINVAL));
    }

    #[test]
    fn a_manifest_or_payload_holds_one_to_16384_bytes() {
        assert_eq!(metadata_size(0), Err(e::ENODATA));
        assert_eq!(metadata_size(1), Ok(1));
        assert_eq!(metadata_size(16384), Ok(16384));
        assert_eq!(metadata_size(16385), Err(e::EFBIG));
        assert_eq!(metadata_size(u64::MAX), Err(e::EFBIG));
    }

    /// libignition's 0x2d and 0x2e go through as they are; bits past
    /// SBC_PRESERVE_GRAFT are dropped.
    #[test]
    fn each_flag_is_its_filesystem_flag() {
        assert_eq!(graft_flags(0x2d), fsctl::PRESERVE_GRAFT | fsctl::PANIC_ON_AUTHFAIL | fsctl::SYSTEM_CONTENT | fsctl::PRESERVE_MOUNT);
        assert_eq!(graft_flags(0x2e), fsctl::PRESERVE_GRAFT | fsctl::PANIC_ON_AUTHFAIL | fsctl::SYSTEM_CONTENT | fsctl::ALTERNATE_SHARED_REGION);
        assert_eq!(graft_flags(sbc::STRICT_AUTH), fsctl::STRICT_AUTH);
        assert_eq!(graft_flags(!0x3f), 0);
        assert_eq!(graft_flags(u64::MAX), 0x3f);
    }

    #[test]
    fn apfs_asks_for_root_then_the_entitlement_then_preboot() {
        use crate::darwin::storage::role;
        assert_eq!(cred_and_flags(false, 0, true, role::PREBOOT), Err(e::EACCES));
        assert_eq!(cred_and_flags(true, 0, false, role::SYSTEM), Ok(()));
        assert_eq!(cred_and_flags(true, fsctl::PRESERVE_MOUNT, false, role::PREBOOT), Err(e::EACCES));
        assert_eq!(cred_and_flags(true, fsctl::PRESERVE_MOUNT, true, role::SYSTEM), Err(e::ENOTSUP));
        assert_eq!(cred_and_flags(true, fsctl::PRESERVE_MOUNT, true, role::PREBOOT), Ok(()));
        // The AppOS cryptex's 0x2e keeps no mount.
        assert_eq!(cred_and_flags(true, graft_flags(0x2e), false, role::SYSTEM), Ok(()));
    }

    #[test]
    fn apfs_takes_version_two_with_a_manifest_and_a_payload() {
        assert_eq!(graft_args_ok(1, 10, 10), Err(e::ENOTSUP));
        assert_eq!(graft_args_ok(2, 0, 10), Err(e::EINVAL));
        assert_eq!(graft_args_ok(2, 10, 0), Err(e::EINVAL));
        assert_eq!(graft_args_ok(2, 10, 10), Ok(()));
    }

    #[test]
    fn each_payload_type_takes_its_graft_types() {
        let chip = |t, c| chip_for(t, c).map(|s| s.chip);
        // The cryptexes' root hashes, with the boot, preboot and downlevel
        // types.
        for c in [cc::CSSY, cc::CASY] {
            assert_eq!(chip(1, c), Ok(Chip::Cryptex1BootAp));
            assert_eq!(chip(2, c), Ok(Chip::ApPlus148));
            assert_eq!(chip(3, c), Ok(Chip::Downlevel));
            for t in [4, 5, 6, 7, 8] {
                assert_eq!(chip(t, c), Err(e::EINVAL), "type {t}");
            }
        }
        // 'exvl' with type 7 alone, its firmware flag set.
        assert_eq!(chip_for(7, cc::EXVL), Ok(Selection { chip: Chip::Ap, pdi_nonce: false, firmware_flags: 4 }));
        for t in 1..=6 {
            assert_eq!(chip(t, cc::EXVL), Err(e::EINVAL));
        }
        assert_eq!(chip(4, cc::GTGV), Ok(Chip::Gtgv4));
        assert_eq!(chip(5, cc::GTGV), Ok(Chip::Gtgv5));
        assert_eq!(chip(1, cc::GTGV), Err(e::EINVAL));
        // 'syab' with any type, the PDI nonce with type 6.
        assert_eq!(chip_for(6, cc::SYAB), Ok(Selection { chip: Chip::Syab, pdi_nonce: true, firmware_flags: 0 }));
        assert_eq!(chip_for(1, cc::SYAB), Ok(Selection { chip: Chip::Syab, pdi_nonce: false, firmware_flags: 0 }));
        // 'xsys' only with no type, which graftdmg never gives.
        assert_eq!(chip(1, cc::XSYS), Err(e::EINVAL));
        assert_eq!(chip(0, cc::XSYS), Ok(Chip::Ap));
        assert_eq!(chip(0, cc::CSSY), Err(e::EINVAL));
        assert_eq!(chip(1, fourcc(b"abcd")), Err(e::EINVAL));
    }
}
