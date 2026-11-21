//! A cryptex graft as APFS makes and serves it (apfs.kext 2236.140.6 of
//! iPad7,1 21H461, `apfs_graft` at 0xfffffff00668611c and the vnode
//! operations' graft cases): the container in the image mounted from the
//! image file's own blocks, its sealed volume's root hash authenticated
//! against the payload AppleImage4 evaluated ([`authenticate_root_hash`]),
//! and the volume's files served at the graft directory ([`GraftFs`]),
//! with the host volume's inode numbers and a device of the graft's own.
//!
//! A graft adds no mount: its vnodes are on the host volume's mount (the
//! graft's `fs + 0x370` is the host's), so `statfs` of a grafted file
//! answers for the Preboot volume; `stat`'s device is the graft's
//! (`apfs_vnop_getattr`'s `va_fsid` takes the graft's `fs + 0x3a8` for a
//! vnode of a graft, 0xfffffff00668e0f4).

use super::apfsread::{self, fs as afs, Container, IntegrityMeta, Medium, Volume};
use crate::errno::Errno;
use crate::vfs::{DirEntry, FileHandle, FileSystem, FileType, Metadata, Times, VnodeAttrs, XattrOp};
use std::sync::{Arc, Mutex};

/// The image's bytes as APFS reads them: through the graft's blockmap, the
/// image file's own blocks on the host volume (0xfffffff0067227fc), not
/// the file's cached pages. A Preboot file the restore copied from the
/// host is read where the host has it; another, through its handle.
pub enum ImageMedium {
    Host { url: String, size: u64, read: crate::vfs::tmpfs::LazyFetch },
    Handle { handle: Arc<dyn FileHandle>, size: u64 },
}

impl Medium for ImageMedium {
    fn size(&self) -> u64 {
        match self {
            ImageMedium::Host { size, .. } | ImageMedium::Handle { size, .. } => *size,
        }
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), String> {
        let end = off.checked_add(buf.len() as u64).ok_or("an offset past the end")?;
        if end > self.size() {
            return Err(format!("bytes {off}..{end} past the image's {} bytes", self.size()));
        }
        match self {
            ImageMedium::Host { url, read, .. } => {
                if read(url, off, buf) {
                    Ok(())
                } else {
                    Err(format!("{url}: not readable at {off}"))
                }
            }
            ImageMedium::Handle { handle, .. } => {
                let mut done = 0;
                while done < buf.len() {
                    let n = handle.read_at(off + done as u64, &mut buf[done..]).map_err(|e| format!("{e:?}"))? as usize;
                    if n == 0 {
                        return Err(format!("the image ends at {}", off + done as u64));
                    }
                    done += n;
                }
                Ok(())
            }
        }
    }
}

/// `validate_on_disk_root_hash`'s payload: the evaluated `cssy`/`casy`
/// IM4P's data, exactly 0xd0 bytes: `u32` version, `u32` (not read),
/// `u32` hash type, `u32` hash size, then three 64-byte root hashes, for
/// containers of 4 KiB, 8 KiB and 16 KiB blocks (`authapfs_select_root_hash`,
/// 0xfffffff006643424: +0x10, +0x50 for 0x2000, +0x90 for 0x4000).
pub const ROOT_HASH_PAYLOAD_SIZE: usize = 0xd0;

/// The root hash of `payload` for a container of `block_size`-byte blocks.
pub fn select_root_hash(payload: &[u8], block_size: u32) -> &[u8] {
    let at = match block_size {
        0x2000 => 0x50,
        0x4000 => 0x90,
        _ => 0x10,
    };
    &payload[at..]
}

/// `validate_on_disk_root_hash` (in `authenticate_root_hash`,
/// 0xfffffff0066cdcac..0xfffffff0066cde48): the payload's size, then its
/// version, hash type and hash size against the integrity metadata's,
/// then the hash; each mismatch is EAUTH, with what APFS logs.
pub fn validate_on_disk_root_hash(im: &IntegrityMeta, payload: &[u8], block_size: u32) -> Result<(), String> {
    let u32_at = |o: usize| u32::from_le_bytes(payload[o..o + 4].try_into().unwrap());
    if payload.len() != ROOT_HASH_PAYLOAD_SIZE {
        return Err(format!("root_hash size mismatch, expected {} but got {}", payload.len(), im.hash_type.size()));
    }
    if u32_at(0) != im.version {
        return Err(format!("invalid root_hash header - payload version <{}> != on-disk version <{}>", u32_at(0), im.version));
    }
    if u32_at(8) != im.hash_type.code() {
        return Err(format!("invalid root_hash header - payload hash type <{}> != on-disk hash type <{}>", u32_at(8), im.hash_type.code()));
    }
    let size = u32_at(0xc);
    if size as usize != im.hash_type.size() {
        return Err(format!("invalid root_hash header - payload hash size <{size}> != on-disk hash size <{}>", im.hash_type.size()));
    }
    let hash = &select_root_hash(payload, block_size)[..size as usize];
    if hash != &im.root_hash[..] {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        return Err(format!("root_hash mismatch, expected {} but got {}", hex(&im.root_hash), hex(hash)));
    }
    Ok(())
}

/// What `authenticate_root_hash` decides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Auth {
    Ok,
    /// EAUTH (80), and what APFS logs.
    Eauth(String),
    /// The kernel panics with this message.
    Panic(String),
}

/// `authenticate_root_hash` (0xfffffff0066cdaec) of a graft (volume type 4,
/// or 5 for `FSCTL_GRAFT_STRICT_AUTH`, both of the types it authenticates
/// whatever the mount): whether authentication is required
/// (`is_root_hash_authentication_required`, [`authentication_required`]);
/// a broken seal (`authapfs_seal_is_broken_full`: `APFS_SEAL_BROKEN`);
/// no authenticated payload (the evaluation failed: "could not authenticate
/// personalized root hash"); then [`validate_on_disk_root_hash`]. Each
/// failure is EAUTH when required (success when not), and the kernel's
/// panic when required with `FSCTL_GRAFT_PANIC_ON_AUTHFAIL`.
pub fn authenticate_root_hash(required: bool, panic_on_authfail: bool, im: &IntegrityMeta, payload: Option<&[u8]>, status: i32, block_size: u32, case_insensitive: bool) -> Auth {
    let fail = |log: String, panic: String| {
        if required && panic_on_authfail {
            Auth::Panic(panic)
        } else if required {
            Auth::Eauth(log)
        } else {
            Auth::Ok
        }
    };
    if im.seal_broken() {
        return fail("volume seal is broken".into(), "volume seal is broken".into());
    }
    let Some(payload) = payload.filter(|p| !p.is_empty()) else {
        return fail("could not authenticate personalized root hash, skipping verification".into(), format!("could not authenticate personalized root hash! ({status}) (0x0, 0)"));
    };
    match validate_on_disk_root_hash(im, payload, block_size) {
        Ok(()) => Auth::Ok,
        Err(why) => {
            // The panic names the error: EAUTH's string. A case-insensitive
            // volume's panics as "APFSX".
            let prefix = if case_insensitive { "APFSX: " } else { "" };
            fail(format!("validate_on_disk_root_hash failed with error: Authentication error (80): {why}"), format!("{prefix}could not validate root hash Authentication error (80)"))
        }
    }
}

/// `is_root_hash_authentication_required_ios` (0xfffffff0066cd968): always,
/// but for a Recovery volume (role 4) booted with the `arp0` boot-arg
/// (NeRD), whose boot-args are not modelled (`None`: reported).
pub fn authentication_required(role: u16) -> Option<bool> {
    const APFS_VOL_ROLE_RECOVERY: u16 = 0x0004;
    if role == APFS_VOL_ROLE_RECOVERY {
        return None;
    }
    Some(true)
}

/// The kernel's errno of a read failure in `place` ([`GraftFs::place`]),
/// and the gap to report where this reader does not implement what the
/// image holds.
fn errno_of(e: &apfsread::Error, what: &str, place: &str) -> Errno {
    match e {
        apfsread::Error::Unsupported(u) => {
            super::note_unimplemented(format!("APFS's {what} in {place}: {u}"));
            Errno::EIO
        }
        apfsread::Error::Integrity(i) => {
            super::note_unimplemented(format!("APFS's error for {what} in {place} whose sealed data does not match its hashes ({i})"));
            Errno::EIO
        }
        apfsread::Error::Io(_) | apfsread::Error::Malformed(_) => {
            super::note_unimplemented(format!("APFS's error for {what} in {place}: {e}"));
            Errno::EIO
        }
        apfsread::Error::Decmpfs { errno, why } => {
            // decmpfs_read_compressed zero-fills the UPL a failed fetch was
            // to fill and answers with its copy's result; a pagein
            // returns the fetch's error.
            super::note_unimplemented(format!("APFS's {what} in {place} of a compressed file whose decmpfs fetch fails ({why}, errno {errno})"));
            Errno::EIO
        }
    }
}

/// `VNODE_ATTR` flags the graft's vnodes answer (`apfs_vnop_getattr`'s
/// `va_flags`, 0xfffffff00668e134): the inode's BSD flags, the top two
/// bits cleared, or the top one alone for a compressed file.
pub fn va_flags(bsd_flags: u32) -> u32 {
    bsd_flags & if bsd_flags & afs::UF_COMPRESSED != 0 { 0x7fff_ffff } else { 0x3fff_ffff }
}

/// The graft's volume, served at the graft directory: the image's files
/// under the host's inode numbers (an object `n` of the image is the host's
/// `base + n`, the image's root the graft directory's own,
/// 0xfffffff00668de64..0xfffffff00668de88 and 0xfffffff00668e270) and the
/// graft's device.
///
/// Or (`live`) a volume of disk0's container (Preboot, xART), served at
/// its mount point as the kernel's container holds it
/// ([`super::disknode::volume`]): its own object identifiers as its inode
/// numbers (`base` 0, its root 2 and the root's parent 1, as
/// `apfs_vnop_getattr`'s `va_fileid` gives them), and its mount's device,
/// its records read through the container's object cache as the open
/// transaction leaves them, so what the container writes (a writing
/// mount's changes, a graft's range and the attributes recording it, a
/// commit) is what this view reads. Each inode a path lookup reaches is
/// brought into the kernel with a vnode ([`super::disknode::vnode_get`]),
/// the order a sync's vnode pass visits them in. A change of a file's
/// owner, group, mode, flags or times is the container's `VNOP_SETATTR`
/// ([`super::disknode::setattr`]), which this view then reads; a change
/// to its data, its names or its extended attributes is reported.
pub struct GraftFs {
    pub vol: Volume,
    /// The first of the host volume's object identifiers the graft holds
    /// (the graft state's +0x20), and how many (+0x28).
    pub base: u64,
    pub len: u64,
    /// The graft directory's inode number, and its parent's.
    pub dir_ino: u64,
    pub dir_parent_ino: u64,
    /// The graft's device (its `fs + 0x3a8`).
    pub devt: u32,
    /// The sealed volume's root hash, which names its contents (none for
    /// an unsealed one).
    pub seal: Option<Vec<u8>>,
    /// A live volume's name and slot; none for a graft.
    pub live: Option<Live>,
}

/// A volume of disk0's container served live: its name, its slot in the
/// container, and the kernel that holds the container.
#[derive(Clone)]
pub struct Live {
    pub name: &'static str,
    pub slot: u32,
    pub kernel: Arc<dyn LiveKernel>,
}

/// What a live volume's calls ask of the kernel's container: an inode
/// brought into the kernel ([`super::disknode::vnode_get`]), the times
/// its in-memory object holds unwritten, if any
/// ([`super::disknode::held_times`]), and `VNOP_SETATTR` of an inode,
/// `fd` when through an open descriptor ([`super::disknode::setattr`];
/// `Ok(Err(errno))` is the call's own error).
pub trait LiveKernel: Send + Sync {
    fn vnode_get(&self, slot: u32, ino: u64) -> Result<(), String>;
    fn held_times(&self, slot: u32, ino: u64) -> Result<Option<(u64, u64)>, String>;
    fn setattr(&self, slot: u32, ino: u64, a: &VnodeAttrs, fd: bool) -> Result<Result<(), i32>, String>;
}

/// A container no kernel holds (a test's view of a checkpoint): no vnode
/// table counts its lookups, and nothing writes it.
#[cfg(test)]
pub(crate) struct Unheld;

#[cfg(test)]
impl LiveKernel for Unheld {
    fn vnode_get(&self, _: u32, _: u64) -> Result<(), String> {
        Ok(())
    }
    fn held_times(&self, _: u32, _: u64) -> Result<Option<(u64, u64)>, String> {
        Ok(None)
    }
    fn setattr(&self, slot: u32, ino: u64, _: &VnodeAttrs, _: bool) -> Result<Result<(), i32>, String> {
        Err(format!("a setattr of inode {ino:#x} of volume slot {slot}, which no kernel holds"))
    }
}

/// The kernel's container in the disk0 image ([`super::disknode`]).
pub struct Disk0;

impl LiveKernel for Disk0 {
    fn vnode_get(&self, slot: u32, ino: u64) -> Result<(), String> {
        super::disknode::vnode_get(slot, ino)
    }
    fn held_times(&self, slot: u32, ino: u64) -> Result<Option<(u64, u64)>, String> {
        super::disknode::held_times(slot, ino)
    }
    fn setattr(&self, slot: u32, ino: u64, a: &VnodeAttrs, fd: bool) -> Result<Result<(), i32>, String> {
        super::disknode::setattr(slot, ino, a, fd)
    }
}

/// What the writer of the kernel's container does not implement of an
/// open to write on a live volume: the open's own writes
/// (`apfs_vnop_create` with the caller's credential for `O_CREAT`, the
/// size change of `O_TRUNC`) and the file's data writes through the UBC
/// (`cluster_write`'s delayed allocation, the blocks mapped and written at
/// the push); the writer's data paths are the restore's own call
/// sequences.
const OPEN_WRITE_GAP: &str = "the open's own writes (apfs_vnop_create with the caller's owner and group for O_CREAT, apfs_vnop_setattr's va_data_size for O_TRUNC) and the data writes through the UBC (cluster_write's delayed allocation, VNOP_BLOCKMAP and the extents at the push) are not implemented";

/// What the writer does not implement of `setxattr`: apfs_vnop_setxattr (K
/// 0x6699610) → apfs_setxattr_internal (K 0x6765cc4), which before its
/// record calls K 0x66b9ef4: for an in-memory object with jobj + 0x98 bit
/// 1 set that writes in a file-system transaction of its own (K 0x66fbf98,
/// type 4), and bit 0 is EPERM; what sets those bits is not traced.
const SETXATTR_GAP: &str = "apfs_vnop_setxattr (K 0x6699610) and apfs_setxattr_internal (K 0x6765cc4) are not implemented: before its record K 0x66b9ef4 writes, for an in-memory object with jobj + 0x98 bit 1 set, in a file-system transaction of its own (K 0x66fbf98 type 4), and answers EPERM for bit 0, and what sets those bits is not traced";

/// What the writer does not implement of `removexattr`.
const REMOVEXATTR_GAP: &str = "apfs_vnop_removexattr is not traced";

impl GraftFs {
    /// Where its files are, for what is reported: a cryptex graft, or a
    /// live volume.
    pub fn place(&self) -> String {
        match &self.live {
            Some(l) => format!("the {} volume", l.name),
            None => "a cryptex graft".to_string(),
        }
    }

    /// The error of `change` (what a call would change of a file): a
    /// graft's read-only sealed volume refuses it (EROFS); on a live volume
    /// `kernel` names what of the kernel's path for it the writer of the
    /// kernel's container does not implement (EIO). Either is reported.
    fn refuse_change(&self, change: &str, kernel: &str) -> Errno {
        match &self.live {
            None => {
                super::note_unimplemented(format!("APFS's error for {change} in a cryptex graft (its read-only sealed volume)"));
                Errno::EROFS
            }
            Some(l) => {
                super::note_unimplemented(format!("{change} on the {} volume, written to the kernel's container in the disk0 image: {kernel}", l.name));
                Errno::EIO
            }
        }
    }

    /// What of path `rel` (its path below the root; `listing` a listing
    /// of it) the disk0 image does not hold because the restore step that
    /// writes there is missing from it: on the Preboot volume, in the
    /// firmware directory (`<nsih>/usr/standalone/firmware`), what
    /// update_iBoot's update_sep writes (sep-firmware.img4, sep-patches.img4)
    /// and what install_fud writes (FUD and what is in it) when the image
    /// lacks that step, and the directory's listing when it lacks either.
    fn unwritten(&self, rel: &str, listing: bool) -> Option<String> {
        use super::apfswrite::restore::{nsih, INSTALL_FUD_MISSING, UPDATE_SEP_MISSING};
        if self.live.as_ref().map(|l| l.name) != Some("Preboot") {
            return None;
        }
        // The directory the boot's AP ticket names: /chosen's
        // boot-manifest-hash, as kern.bootobjectspath gives it.
        let dir = match super::iokit::boot_manifest_hash().filter(|h| h.iter().any(|&b| b != 0)) {
            Some(h) => h.iter().map(|b| format!("{b:02X}")).collect(),
            None => nsih(None),
        };
        let fw = format!("{dir}/usr/standalone/firmware");
        let rel = rel.trim_matches('/');
        let Some(below) = rel.strip_prefix(fw.as_str()) else { return None };
        let name = below.strip_prefix('/');
        if !(name.is_some() || (listing && below.is_empty())) {
            return None;
        }
        let sep = matches!(name, Some("sep-firmware.img4" | "sep-patches.img4"));
        let fud = name.is_some_and(|n| n == "FUD" || n.starts_with("FUD/"));
        let lacking: Vec<&str> = [(UPDATE_SEP_MISSING, sep), (INSTALL_FUD_MISSING, fud)]
            .into_iter()
            .filter(|&(m, writes)| (writes || name.is_none()) && super::disknode::lacks(m))
            .map(|(m, _)| m)
            .collect();
        (!lacking.is_empty()).then(|| format!("{rel} on the Preboot volume, which the disk0 image does not hold as the restore leaves it: the image lacks {}", lacking.join("; and ")))
    }

    /// [`GraftFs::unwritten`], reported: EIO.
    fn check_written(&self, rel: &str, listing: bool) -> Result<(), Errno> {
        match self.unwritten(rel, listing) {
            Some(why) => {
                super::note_unimplemented(why);
                Err(Errno::EIO)
            }
            None => Ok(()),
        }
    }

    /// Volume `vol` of disk0's container, in slot `slot`, named `name`,
    /// mounted at run time: unsealed, its own identifiers its inode
    /// numbers, on its mount's device `devt`.
    pub fn live(vol: Volume, name: &'static str, slot: u32, devt: u32) -> GraftFs {
        Self::live_on(vol, name, slot, devt, Arc::new(Disk0))
    }

    /// [`GraftFs::live`] of a container `kernel` holds.
    pub fn live_on(vol: Volume, name: &'static str, slot: u32, devt: u32, kernel: Arc<dyn LiveKernel>) -> GraftFs {
        GraftFs { vol, base: 0, len: u64::MAX, dir_ino: afs::ROOT_DIR_INO_NUM, dir_parent_ino: afs::ROOT_DIR_PARENT, devt, seal: None, live: Some(Live { name, slot, kernel }) }
    }

    /// Image object `oid`, reached by a lookup, brought into the kernel: a
    /// live volume's inode gets its vnode in the kernel's container's
    /// table. A graft's vnodes, on its host's mount, are not counted there:
    /// its sealed read-only inodes hold no unwritten times for a vnode pass
    /// to write, and the count stays a lower bound of the vnodes in use.
    fn looked_up(&self, oid: u64) -> Result<(), Errno> {
        let Some(l) = &self.live else { return Ok(()) };
        l.kernel.vnode_get(l.slot, oid).map_err(|why| {
            super::note_unimplemented(format!("the vnode of inode {oid:#x} of the {} volume: {why}", l.name));
            Errno::EIO
        })
    }

    /// `VNOP_SETATTR` of `a` on image object `oid` of a live volume
    /// (`fd`: through an open descriptor), written to the kernel's
    /// container as apfs_vnop_setattr writes it
    /// ([`super::disknode::setattr`]); none for a graft, whose attributes
    /// the caller keeps (its read-only volume refuses a change).
    fn setattr(&self, oid: u64, a: &VnodeAttrs, fd: bool) -> Option<Result<(), Errno>> {
        let l = self.live.as_ref()?;
        Some(match l.kernel.setattr(l.slot, oid, a, fd) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(super::errno::errno_of(e)),
            Err(why) => {
                super::note_unimplemented(format!("a setattr of inode {oid:#x} of the {} volume: {why}", l.name));
                Err(Errno::EIO)
            }
        })
    }

    /// The host's inode number of image object `oid`.
    pub fn ino_of(&self, oid: u64) -> u64 {
        match oid {
            afs::ROOT_DIR_INO_NUM => self.dir_ino,
            afs::ROOT_DIR_PARENT => self.dir_parent_ino,
            o => self.base + o,
        }
    }

    /// The image object an inode number names, if it is the graft's.
    pub fn oid_of(&self, ino: u64) -> Option<u64> {
        if ino == self.dir_ino {
            return Some(afs::ROOT_DIR_INO_NUM);
        }
        ino.checked_sub(self.base).filter(|o| *o < self.len && *o > afs::ROOT_DIR_INO_NUM)
    }

    /// The inode `rel` names (relative to the graft's root), the final
    /// link followed with `follow`. A link among the directories, or at
    /// the end, is followed where its target is inside the graft.
    fn resolve(&self, rel: &str, follow: bool) -> Result<afs::Inode, Errno> {
        let mut parts: Vec<String> = rel.split('/').filter(|p| !p.is_empty() && *p != ".").map(str::to_string).collect();
        let mut hops = 0;
        'again: loop {
            let mut stack: Vec<afs::Inode> = Vec::new();
            let mut cur = self.inode(afs::ROOT_DIR_INO_NUM)?;
            // VFS_ROOT: the mount's root vnode, made at the first path
            // through the mount point.
            self.looked_up(cur.oid)?;
            for (i, p) in parts.iter().enumerate() {
                if p == ".." {
                    if let Some(up) = stack.pop() {
                        cur = up;
                    }
                    continue;
                }
                if !cur.is_dir() {
                    return Err(Errno::ENOTDIR);
                }
                let e = self.vol.lookup(cur.oid, p).map_err(|e| errno_of(&e, "lookup", &self.place()))?.ok_or(Errno::ENOENT)?;
                let next = self.inode(e.file_id)?;
                self.looked_up(next.oid)?;
                let last = i + 1 == parts.len();
                if next.kind() == afs::mode::S_IFLNK && (!last || follow) {
                    hops += 1;
                    if hops > 32 {
                        return Err(Errno::ELOOP);
                    }
                    let target = self.vol.symlink_target(&next).map_err(|e| errno_of(&e, "readlink", &self.place()))?;
                    if target.starts_with('/') {
                        super::note_unimplemented(format!("a link in {} to {target}, outside it", self.place()));
                        return Err(Errno::ENOENT);
                    }
                    let mut base: Vec<String> = parts[..i].to_vec();
                    base.extend(target.split('/').filter(|p| !p.is_empty() && *p != ".").map(str::to_string));
                    base.extend(parts[i + 1..].iter().cloned());
                    parts = base;
                    continue 'again;
                }
                stack.push(std::mem::replace(&mut cur, next));
            }
            return Ok(cur);
        }
    }

    /// Image object `oid`'s inode as its in-memory object holds it: on a
    /// live volume with the modification and change times the object holds
    /// unwritten (`apfs_vnop_getattr` reads the object).
    fn inode(&self, oid: u64) -> Result<afs::Inode, Errno> {
        let mut ino = self.vol.inode(oid).map_err(|e| errno_of(&e, "inode read", &self.place()))?.ok_or_else(|| {
            super::note_unimplemented(format!("APFS's error for a directory entry of {} naming the missing inode {oid:#x}", self.place()));
            Errno::EIO
        })?;
        if let Some(l) = &self.live {
            match l.kernel.held_times(l.slot, oid) {
                Ok(Some((m, c))) => (ino.mod_time, ino.change_time) = (m, c),
                Ok(None) => {}
                Err(why) => {
                    super::note_unimplemented(format!("the in-memory object of inode {oid:#x} of the {} volume: {why}", l.name));
                    return Err(Errno::EIO);
                }
            }
        }
        Ok(ino)
    }

    /// What `stat` says of an inode ([`va_flags`] aside): its type and
    /// permissions, size, inode number, times, links.
    pub fn metadata_of(&self, ino: &afs::Inode) -> Result<Metadata, Errno> {
        let file_type = match ino.kind() {
            afs::mode::S_IFREG => FileType::Regular,
            afs::mode::S_IFDIR => FileType::Directory,
            afs::mode::S_IFLNK => FileType::Symlink,
            afs::mode::S_IFIFO => FileType::Fifo,
            afs::mode::S_IFSOCK => FileType::Socket,
            k => {
                super::note_unimplemented(format!("an inode {:#x} of {} of type {k:#o} (a device node: its rdev)", ino.oid, self.place()));
                return Err(Errno::EIO);
            }
        };
        let size = self.vol.file_size(ino).map_err(|e| errno_of(&e, "getattr", &self.place()))?;
        let nlink = if ino.is_dir() {
            // 0xfffffff00669f2d8: a directory's children and two, unless
            // the volume keeps its links another way.
            if self.vol.sb.incompat & 0x200 != 0 || self.vol.sb.ro_compat & 0x2 != 0 {
                super::note_unimplemented(format!("a directory's link count in {} on a volume with features {:#x}/{:#x}", self.place(), self.vol.sb.incompat, self.vol.sb.ro_compat));
                return Err(Errno::EIO);
            }
            (i64::from(ino.nchildren_or_nlink) + 2) as u32
        } else {
            ino.nchildren_or_nlink as u32
        };
        let t = |ns: u64| ((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as u32);
        let (m, mn) = t(ino.mod_time);
        let (a, an) = t(ino.access_time);
        let (c, cn) = t(ino.change_time);
        let birth = Some(t(ino.create_time));
        Ok(Metadata {
            file_type,
            size,
            mode: u32::from(ino.mode) & 0o7777,
            ino: self.ino_of(ino.oid),
            mtime: m,
            nlink,
            rdev: 0,
            dev: 0,
            times: Times { mtime_ns: mn, atime: a, atime_ns: an, ctime: c, ctime_ns: cn, birth },
        })
    }

    /// The record of an inode's owner, group, mode and flags
    /// ([`super::vattr::RECORD`]): the image's.
    pub fn owned_of(ino: &afs::Inode) -> super::vattr::Owned {
        super::vattr::Owned { uid: ino.owner, gid: ino.group, mode: u32::from(ino.mode) & 0o7777, flags: va_flags(ino.bsd_flags) }
    }

    /// An inode's extended attributes a caller sees: none the file system
    /// owns (`XATTR_FILE_SYSTEM_OWNED`: APFS's getxattr answers ENOATTR for
    /// one, 0xfffffff0067657f8, and its listing skips it), and decmpfs hides
    /// a compressed file's own (`decmpfs_hides_xattr`: `com.apple.decmpfs`
    /// and the resource fork).
    fn visible_xattrs(&self, ino: &afs::Inode) -> Result<Vec<afs::Xattr>, Errno> {
        let all = self.vol.xattrs(ino.oid).map_err(|e| errno_of(&e, "listxattr", &self.place()))?;
        Ok(all.into_iter().filter(|x| x.flags & XATTR_FILE_SYSTEM_OWNED == 0 && !(ino.compressed() && (x.name == afs::DECMPFS_XATTR_NAME || x.name == afs::RESOURCEFORK_NAME))).collect())
    }

    fn xattr_op(&self, ino: &afs::Inode, op: XattrOp<'_>) -> Result<usize, Errno> {
        fn out(buf: &mut [u8], bytes: &[u8]) -> Result<usize, Errno> {
            if buf.is_empty() {
                return Ok(bytes.len());
            }
            if buf.len() < bytes.len() {
                return Err(Errno::ERANGE);
            }
            buf[..bytes.len()].copy_from_slice(bytes);
            Ok(bytes.len())
        }
        match op {
            XattrOp::Get { name, buf } if name == super::vattr::RECORD => out(buf, Self::owned_of(ino).record().as_bytes()),
            XattrOp::Get { name, buf } => {
                let Some(name) = name.strip_prefix("user.") else { return Err(Errno::ENODATA) };
                let x = self.visible_xattrs(ino)?.into_iter().find(|x| x.name == name).ok_or(Errno::ENODATA)?;
                let v = self.vol.xattr_value(&x).map_err(|e| errno_of(&e, "getxattr", &self.place()))?;
                out(buf, &v)
            }
            XattrOp::List { buf } => {
                let mut all = Vec::new();
                for x in self.visible_xattrs(ino)? {
                    all.extend_from_slice(b"user.");
                    all.extend_from_slice(x.name.as_bytes());
                    all.push(0);
                }
                out(buf, &all)
            }
            XattrOp::Set { name, .. } => Err(self.refuse_change(&format!("a setxattr of {name} on inode {:#x}", ino.oid), SETXATTR_GAP)),
            XattrOp::Remove { name } => Err(self.refuse_change(&format!("a removexattr of {name} on inode {:#x}", ino.oid), REMOVEXATTR_GAP)),
        }
    }

    fn entries(&self, dir: &afs::Inode) -> Result<Vec<DirEntry>, Errno> {
        let mut out = vec![
            DirEntry { name: ".".into(), file_type: FileType::Directory, ino: self.ino_of(dir.oid) },
            DirEntry { name: "..".into(), file_type: FileType::Directory, ino: self.ino_of(dir.parent_id) },
        ];
        for e in self.vol.dir_entries(dir.oid).map_err(|e| errno_of(&e, "readdir", &self.place()))? {
            let file_type = match e.dtype {
                8 => FileType::Regular,
                4 => FileType::Directory,
                10 => FileType::Symlink,
                1 => FileType::Fifo,
                12 => FileType::Socket,
                2 => FileType::CharDevice,
                6 => FileType::BlockDevice,
                t => {
                    super::note_unimplemented(format!("a directory entry {:?} of {} of type {t}", e.name, self.place()));
                    return Err(Errno::EIO);
                }
            };
            out.push(DirEntry { name: e.name, file_type, ino: self.ino_of(e.file_id) });
        }
        Ok(out)
    }
}

/// An open file or directory of a graft.
pub struct GraftHandle {
    fs: Arc<GraftFs>,
    ino: afs::Inode,
}

/// Where the host keeps a sealed graft's files as files of its own
/// ([`set_file_dir`]).
static FILE_DIR: std::sync::OnceLock<fn() -> Option<std::path::PathBuf>> = std::sync::OnceLock::new();

/// Where the host keeps the files of sealed grafts it can map: each a
/// regular file's bytes as the graft serves them (its data checked
/// against the volume's data hashes as it was read), named by the
/// volume's root hash, which seals every file's data hashes, and the
/// file's data stream: what a mapping of the file pages in, which the host
/// then maps from there rather than reading it into memory.
pub fn set_file_dir(f: fn() -> Option<std::path::PathBuf>) {
    let _ = FILE_DIR.set(f);
}

/// The host's files of sealed grafts, kept open while the system runs.
static HOST_FILES: Mutex<Vec<(std::path::PathBuf, Arc<std::fs::File>)>> = Mutex::new(Vec::new());

impl GraftHandle {
    /// The inode as it stands: a graft's never changes; a live volume's is
    /// read again, as the vnode's in-memory object follows every change.
    fn current(&self) -> Result<afs::Inode, Errno> {
        match self.fs.live {
            None => Ok(self.ino.clone()),
            Some(_) => self.fs.inode(self.ino.oid),
        }
    }

    /// The host's file of this regular file of a sealed graft, made once
    /// from the graft's bytes; none where there is no place for it, or
    /// the graft cannot serve the file whole (its reads report why).
    fn host_file(&self) -> Option<Arc<std::fs::File>> {
        use sha2::Digest;
        use std::io::Write;
        if self.ino.kind() != afs::mode::S_IFREG {
            return None;
        }
        let seal = self.fs.seal.as_ref()?;
        let dir = FILE_DIR.get()?()?;
        let size = self.fs.vol.file_size(&self.ino).ok()?;
        let mut h = sha2::Sha256::new();
        h.update(b"gex graft file 1\0");
        h.update(seal);
        h.update(self.ino.oid.to_le_bytes());
        h.update(self.ino.private_id.to_le_bytes());
        h.update(size.to_le_bytes());
        let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        let path = dir.join(format!("{hex}.file"));
        if let Some(f) = HOST_FILES.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|(p, _)| *p == path).map(|(_, f)| Arc::clone(f)) {
            return Some(f);
        }
        let kept = std::fs::File::open(&path).ok().filter(|f| f.metadata().is_ok_and(|m| m.len() == size));
        let f = match kept {
            Some(f) => f,
            None => {
                std::fs::create_dir_all(&dir).ok()?;
                let tmp = path.with_extension(format!("tmp{}", std::process::id()));
                let mut out = std::fs::File::create(&tmp).ok()?;
                let mut buf = vec![0u8; 4 << 20];
                let mut at = 0u64;
                while at < size {
                    let n = match self.fs.vol.read_file(&self.ino, at, &mut buf) {
                        Ok(n) if n > 0 => n,
                        _ => {
                            let _ = std::fs::remove_file(&tmp);
                            return None;
                        }
                    };
                    if out.write_all(&buf[..n]).is_err() {
                        let _ = std::fs::remove_file(&tmp);
                        return None;
                    }
                    at += n as u64;
                }
                drop(out);
                if std::fs::rename(&tmp, &path).is_err() {
                    let _ = std::fs::remove_file(&tmp);
                    return None;
                }
                std::fs::File::open(&path).ok()?
            }
        };
        let f = Arc::new(f);
        HOST_FILES.lock().unwrap_or_else(|e| e.into_inner()).push((path, Arc::clone(&f)));
        Some(f)
    }
}

impl std::fmt::Debug for GraftHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GraftHandle({:#x})", self.ino.oid)
    }
}

impl FileHandle for GraftHandle {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> crate::errno::SysResult {
        let ino = self.current()?;
        match ino.kind() {
            afs::mode::S_IFDIR => Err(Errno::EISDIR),
            afs::mode::S_IFREG => self.fs.vol.read_file(&ino, offset, buf).map(|n| n as u64).map_err(|e| errno_of(&e, "read", &self.fs.place())),
            _ => Err(Errno::EINVAL),
        }
    }
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> crate::errno::SysResult {
        Err(Errno::EBADF)
    }
    fn metadata(&self) -> Result<Metadata, Errno> {
        self.fs.metadata_of(&self.current()?)
    }
    #[cfg(unix)]
    fn host_fd(&self) -> Option<i32> {
        use std::os::fd::AsRawFd;
        self.host_file().map(|f| f.as_raw_fd())
    }
    fn host_id(&self) -> Option<(u64, u64, u64)> {
        self.host_file().and_then(|f| f.metadata().ok()).map(|md| crate::vfs::host_id_of(&md))
    }
    fn read_dir(&self) -> Result<Vec<DirEntry>, Errno> {
        let ino = self.current()?;
        if !ino.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        self.fs.entries(&ino)
    }
    fn xattr(&self, op: XattrOp<'_>) -> Option<Result<usize, Errno>> {
        Some(self.current().and_then(|ino| self.fs.xattr_op(&ino, op)))
    }
    fn chmod(&self, mode: u32) -> Option<Result<(), Errno>> {
        let a = VnodeAttrs { mode: Some(mode & 0o7777), ..Default::default() };
        self.fs.setattr(self.ino.oid, &a, true).or_else(|| Some(Err(self.fs.refuse_change(&format!("a chmod of inode {:#x}", self.ino.oid), ""))))
    }
    fn set_times(&self, atime: Option<(i64, u32)>, mtime: Option<(i64, u32)>) -> Result<(), Errno> {
        let a = VnodeAttrs { atime, mtime, ..Default::default() };
        self.fs.setattr(self.ino.oid, &a, true).unwrap_or_else(|| Err(self.fs.refuse_change(&format!("a change of the times of inode {:#x}", self.ino.oid), "")))
    }
    fn vnode_setattr(&self, a: &VnodeAttrs) -> Option<Result<(), Errno>> {
        self.fs.setattr(self.ino.oid, a, true)
    }
}

/// The graft as a filesystem of the namespace, mounted on the graft
/// directory's path.
pub struct GraftMount(pub Arc<GraftFs>);

impl FileSystem for GraftMount {
    fn fs_type(&self) -> &'static str {
        "apfs"
    }
    fn open(&self, path: &str, flags: u64, _mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        self.0.check_written(path, true)?;
        if flags & crate::fs::oflags::O_CREAT != 0 || crate::vfs::writes(flags) {
            let ino = self.0.resolve(path, true);
            if ino.is_err() && flags & crate::fs::oflags::O_CREAT == 0 {
                return Err(ino.err().unwrap());
            }
            if ino.as_ref().is_ok_and(|i| i.is_dir()) {
                return Err(Errno::EISDIR);
            }
            return Err(self.0.refuse_change(&format!("an open of {path} to write"), OPEN_WRITE_GAP));
        }
        let ino = self.0.resolve(path, true)?;
        if ino.kind() == afs::mode::S_IFREG && ino.compressed() {
            // apfs_vnop_open checks a compressed file opened to read
            // (decmpfs_validate_compressed_file, 0xfffffff0066901d8).
            match self.0.vol.decmpfs_validate(&ino) {
                Ok(()) => {}
                Err(apfsread::Error::Decmpfs { errno, why }) => {
                    super::note_unimplemented(format!("APFS's open of {path}, whose decmpfs validation fails ({why}): the conditions on apfs_vnop_open's way to it are not traced; answered with its errno {errno}"));
                    return Err(super::errno::errno_of(errno));
                }
                Err(e) => return Err(errno_of(&e, "open", &self.0.place())),
            }
        }
        Ok(Arc::new(GraftHandle { fs: Arc::clone(&self.0), ino }))
    }
    fn metadata(&self, path: &str) -> Result<Metadata, Errno> {
        self.0.check_written(path, false)?;
        let ino = self.0.resolve(path, true)?;
        self.0.metadata_of(&ino)
    }
    fn metadata_nofollow(&self, path: &str) -> Result<Metadata, Errno> {
        self.0.check_written(path, false)?;
        let ino = self.0.resolve(path, false)?;
        self.0.metadata_of(&ino)
    }
    fn read_link(&self, path: &str) -> Result<String, Errno> {
        self.0.check_written(path, false)?;
        let ino = self.0.resolve(path, false)?;
        if ino.kind() != afs::mode::S_IFLNK {
            return Err(Errno::EINVAL);
        }
        self.0.vol.symlink_target(&ino).map_err(|e| errno_of(&e, "readlink", &self.0.place()))
    }
    fn xattr(&self, path: &str, op: XattrOp<'_>) -> Result<usize, Errno> {
        self.0.check_written(path, false)?;
        let ino = self.0.resolve(path, false)?;
        self.0.xattr_op(&ino, op)
    }
    fn chmod(&self, path: &str, mode: u32) -> Result<(), Errno> {
        let ino = self.0.resolve(path, true)?;
        let a = VnodeAttrs { mode: Some(mode & 0o7777), ..Default::default() };
        self.0.setattr(ino.oid, &a, false).unwrap_or_else(|| Err(self.0.refuse_change(&format!("a chmod of {path}"), "")))
    }
    fn set_mtime(&self, path: &str, secs: i64) -> Result<(), Errno> {
        self.set_times(path, None, Some((secs, 0)))
    }
    /// The times of the file `path` names (the caller has followed its
    /// links): a live volume's `VNOP_SETATTR` of them.
    fn set_times(&self, path: &str, atime: Option<(i64, u32)>, mtime: Option<(i64, u32)>) -> Result<(), Errno> {
        let ino = self.0.resolve(path, false)?;
        let a = VnodeAttrs { atime, mtime, ..Default::default() };
        self.0.setattr(ino.oid, &a, false).unwrap_or_else(|| Err(self.0.refuse_change(&format!("a change of the times of {path}"), "")))
    }
    fn vnode_setattr(&self, path: &str, a: &VnodeAttrs) -> Option<Result<(), Errno>> {
        self.0.live.as_ref()?;
        match self.0.resolve(path, false) {
            Ok(ino) => self.0.setattr(ino.oid, a, false),
            Err(e) => Some(Err(e)),
        }
    }
    fn path_of_ino(&self, ino: u64) -> Option<String> {
        let oid = self.0.oid_of(ino)?;
        let p = self.0.vol.path_of(oid).ok().flatten()?;
        Some(p.trim_start_matches('/').to_string())
    }
    /// A bind mount of directory `rel` (bindfs): its files as this volume
    /// serves them ([`GraftSub`]).
    fn bound_subtree(&self, rel: &str) -> Option<Arc<dyn FileSystem>> {
        let rel = rel.trim_matches('/');
        let ino = self.0.resolve(rel, true).ok()?;
        ino.is_dir().then(|| Arc::new(GraftSub { fs: GraftMount(Arc::clone(&self.0)), prefix: rel.to_string() }) as Arc<dyn FileSystem>)
    }
}

/// The files below directory `prefix` of a volume a [`GraftFs`] serves,
/// as a bind mount of that directory shows them (bindfs passes each call
/// to the vnode below it): the same files, inode numbers and attributes,
/// and what the volume reports of them reported the same way.
pub struct GraftSub {
    fs: GraftMount,
    prefix: String,
}

impl GraftSub {
    fn at(&self, path: &str) -> String {
        let path = path.trim_matches('/');
        match (self.prefix.as_str(), path) {
            ("", p) => p.to_string(),
            (pre, "") => pre.to_string(),
            (pre, p) => format!("{pre}/{p}"),
        }
    }
}

impl FileSystem for GraftSub {
    fn fs_type(&self) -> &'static str {
        self.fs.fs_type()
    }
    fn bound_subtree(&self, rel: &str) -> Option<Arc<dyn FileSystem>> {
        self.fs.bound_subtree(&self.at(rel))
    }
    fn open(&self, path: &str, flags: u64, mode: u32) -> Result<Arc<dyn FileHandle>, Errno> {
        self.fs.open(&self.at(path), flags, mode)
    }
    fn metadata(&self, path: &str) -> Result<Metadata, Errno> {
        self.fs.metadata(&self.at(path))
    }
    fn metadata_nofollow(&self, path: &str) -> Result<Metadata, Errno> {
        self.fs.metadata_nofollow(&self.at(path))
    }
    fn read_link(&self, path: &str) -> Result<String, Errno> {
        self.fs.read_link(&self.at(path))
    }
    fn xattr(&self, path: &str, op: XattrOp<'_>) -> Result<usize, Errno> {
        self.fs.xattr(&self.at(path), op)
    }
    fn chmod(&self, path: &str, mode: u32) -> Result<(), Errno> {
        self.fs.chmod(&self.at(path), mode)
    }
    fn set_mtime(&self, path: &str, secs: i64) -> Result<(), Errno> {
        self.fs.set_mtime(&self.at(path), secs)
    }
    fn set_times(&self, path: &str, atime: Option<(i64, u32)>, mtime: Option<(i64, u32)>) -> Result<(), Errno> {
        self.fs.set_times(&self.at(path), atime, mtime)
    }
    fn vnode_setattr(&self, path: &str, a: &VnodeAttrs) -> Option<Result<(), Errno>> {
        self.fs.vnode_setattr(&self.at(path), a)
    }
    fn path_of_ino(&self, ino: u64) -> Option<String> {
        let p = self.fs.path_of_ino(ino)?;
        if self.prefix.is_empty() {
            return Some(p);
        }
        if p == self.prefix {
            return Some(String::new());
        }
        p.strip_prefix(&format!("{}/", self.prefix)).map(str::to_string)
    }
}

/// A graft made: what APFS keeps of it (`apfs_graft_state_t`, 0x50 bytes,
/// and the graft's fs).
pub struct Graft {
    /// The host volume's slot in the container, and its device.
    pub host_volume: u32,
    pub host_devt: u32,
    /// The image file (canonical path, inode number) and the graft
    /// directory (canonical path, inode number).
    pub file_path: String,
    pub file_ino: u64,
    pub dir_path: String,
    pub dir_ino: u64,
    /// `FSCTL_GRAFT_*`.
    pub flags: u64,
    pub fs: Arc<GraftFs>,
}

/// The grafts made, in the order they were (APFS keeps each host volume's
/// in its `fs + 0x2228` list, sorted by range: the order here is not
/// asked of it).
static GRAFTS: Mutex<Vec<Arc<Graft>>> = Mutex::new(Vec::new());

/// Each host volume's graft device counter (its `fs + 0x2224`) and the
/// identifiers a read-only host has handed out to grafts (`fs + 0x2240`).
static COUNTERS: Mutex<Vec<(u32, u8, u64)>> = Mutex::new(Vec::new());

/// `MAX_GRAFTS`: `apfs_graft`'s limit of grafts on a volume (EBUSY at it).
pub const MAX_GRAFTS: usize = 255;

/// Every graft made.
pub fn grafts() -> Vec<Arc<Graft>> {
    GRAFTS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// The grafts on host volume `volume`.
pub fn grafts_on(volume: u32) -> Vec<Arc<Graft>> {
    grafts().into_iter().filter(|g| g.host_volume == volume).collect()
}

fn within(path: &str, at: &str) -> bool {
    path == at || path.strip_prefix(at).is_some_and(|r| r.starts_with('/'))
}

/// The graft canonical path `path` is in (the graft directory itself
/// included).
pub fn graft_at(path: &str) -> Option<Arc<Graft>> {
    grafts().into_iter().filter(|g| within(path, &g.dir_path)).max_by_key(|g| g.dir_path.len())
}

/// The device `stat` gives a vnode at canonical path `path` in a graft.
pub fn devt_at(path: &str) -> Option<u32> {
    graft_at(path).map(|g| g.fs.devt)
}

/// A graft's device (0xfffffff0066876fc): the host's, its second byte the
/// host's next graft number (1 to 255, 0 skipped), tried once for each
/// graft the host has and once more, skipping a number a graft has; EBUSY
/// when every try is taken. Returns the device and the counter left.
pub fn graft_devt(host_devt: u32, counter: u8, taken: &[u32]) -> (Option<u32>, u8) {
    let mut c = counter;
    let mut dev = 0;
    for _ in 0..=taken.len() {
        c = if c == 0xff { 1 } else { c + 1 };
        dev = (host_devt & 0xff00_ffff) | (u32::from(c) << 16);
        if !taken.contains(&dev) {
            return (Some(dev), c);
        }
    }
    let _ = dev;
    (None, c)
}

/// `allocate_graft_jobj_range` (0xfffffff00668747c)'s check of a range of
/// `len` after the host's next object identifier `next`: ERANGE when it
/// overflows or passes `0x0fffffff00000000`.
pub fn jobj_range_ok(next: u64, len: u64) -> Result<(), i32> {
    match next.checked_add(len) {
        Some(end) if end < 0x0fff_ffff_0000_0001 => Ok(()),
        _ => Err(34),
    }
}

/// The attributes in which a writable host records a graft's range on its
/// image file (`write_graft_file_xattrs`, 0xfffffff006687934), each added
/// file-system owned (`XATTR_FILE_SYSTEM_OWNED`, 4), so that no attribute
/// call reads or lists them (APFS's getxattr answers ENOATTR for such a
/// record, 0xfffffff0067657f8): the host volume's UUID, then the range's
/// first identifier and its length, each a little-endian `u64`.
pub mod graft_xattr {
    pub const VOL_UUID: &str = "com.apple.fs.graft-vol-uuid";
    pub const JOBJ_ID_BASE: &str = "com.apple.fs.graft-jobj-id-base";
    pub const JOBJ_ID_LEN: &str = "com.apple.fs.graft-jobj-id-len";
}

/// `XATTR_FILE_SYSTEM_OWNED`.
const XATTR_FILE_SYSTEM_OWNED: u16 = 4;

/// The values `write_graft_file_xattrs` adds, in its order.
pub fn graft_file_xattrs(host_uuid: [u8; 16], base: u64, len: u64) -> [(&'static str, Vec<u8>); 3] {
    [(graft_xattr::VOL_UUID, host_uuid.to_vec()), (graft_xattr::JOBJ_ID_BASE, base.to_le_bytes().to_vec()), (graft_xattr::JOBJ_ID_LEN, len.to_le_bytes().to_vec())]
}

/// `get_graft_jobj_range` (0xfffffff006687094): the range an image file's
/// attributes record (`get` reads one), for a host whose volume UUID is
/// `host_uuid` and whose next object identifier is `host_next`, `ge` the
/// least object identifier at or above one (`apfs_lookup_ge_jobj_id`). No
/// volume UUID is no range; then, in order: a UUID shorter than 16 bytes
/// or not the host's is EINVAL; no first identifier, or no length, ENOENT;
/// either shorter than 8 bytes EINVAL; a length of 0 or a range that ends
/// past `host_next` EINVAL; an identifier in the range EINVAL.
pub fn recorded_jobj_range(get: &dyn Fn(&str) -> Option<Vec<u8>>, host_uuid: &[u8; 16], host_next: u64, ge: &dyn Fn(u64) -> Option<u64>) -> Result<Option<(u64, u64)>, i32> {
    const ENOENT: i32 = 2;
    const EINVAL: i32 = 22;
    let Some(uuid) = get(graft_xattr::VOL_UUID) else { return Ok(None) };
    if uuid.len() < 16 || uuid[..16] != host_uuid[..] {
        return Err(EINVAL);
    }
    let word = |name: &str| -> Result<u64, i32> {
        let v = get(name).ok_or(ENOENT)?;
        v.get(..8).map(|b| u64::from_le_bytes(b.try_into().unwrap())).ok_or(EINVAL)
    };
    let base = word(graft_xattr::JOBJ_ID_BASE)?;
    let len = word(graft_xattr::JOBJ_ID_LEN)?;
    let end = base.wrapping_add(len);
    if len == 0 || end > host_next {
        return Err(EINVAL);
    }
    if ge(base).is_some_and(|id| id < end) {
        return Err(EINVAL);
    }
    Ok(Some((base, len)))
}

/// `apfs_graft`'s use of a recorded range (0xfffffff006686a84..
/// 0xfffffff006686c30): one at least as long as the image volume's next
/// object identifier `need` is the graft's; none, an error (logged) or a
/// shorter one ("Graft jobj id range length %llu is smaller than graft
/// next_obj_id %llu") has a range allocated instead.
pub fn reused_jobj_range(recorded: Result<Option<(u64, u64)>, i32>, need: u64) -> Option<(u64, u64)> {
    recorded.ok().flatten().filter(|&(_, len)| len >= need)
}

/// The host volume's graft counters: its device counter and what a
/// read-only mount has handed out.
pub fn counters(volume: u32) -> (u8, u64) {
    let g = COUNTERS.lock().unwrap_or_else(|e| e.into_inner());
    g.iter().find(|c| c.0 == volume).map_or((0, 0), |c| (c.1, c.2))
}

fn set_counters(volume: u32, devc: u8, handed: u64) {
    let mut g = COUNTERS.lock().unwrap_or_else(|e| e.into_inner());
    match g.iter_mut().find(|c| c.0 == volume) {
        Some(c) => (c.1, c.2) = (devc, handed),
        None => g.push((volume, devc, handed)),
    }
}

/// Record a graft made, with the host volume's counters as it left them.
pub fn add(g: Graft, devc: u8, handed: u64) -> Arc<Graft> {
    set_counters(g.host_volume, devc, handed);
    let g = Arc::new(g);
    GRAFTS.lock().unwrap_or_else(|e| e.into_inner()).push(Arc::clone(&g));
    g
}

/// Open the container in an image and its volume at fs index 0
/// (`apfs_graft`'s nx mount, 0xfffffff006738928, and apfs mount,
/// 0xfffffff006716274): none at index 0 is ENOENT.
pub fn mount_image(medium: Arc<dyn Medium>) -> Result<Result<Volume, i32>, apfsread::Error> {
    let c = Arc::new(Container::open(medium)?);
    match c.volume(0)? {
        Some(v) => Ok(Ok(v)),
        None => Ok(Err(2)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apfsread::HashType;

    fn im(version: u32, hash: Vec<u8>) -> IntegrityMeta {
        IntegrityMeta { version, flags: 0, hash_type: HashType::Sha256, broken_xid: 0, root_hash: hash }
    }

    fn payload(version: u32, t: u32, size: u32, at: usize, hash: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; ROOT_HASH_PAYLOAD_SIZE];
        p[0..4].copy_from_slice(&version.to_le_bytes());
        p[8..12].copy_from_slice(&t.to_le_bytes());
        p[12..16].copy_from_slice(&size.to_le_bytes());
        p[at..at + hash.len()].copy_from_slice(hash);
        p
    }

    /// The header first (version, type, size), then the hash of the
    /// container's block size.
    #[test]
    fn the_payload_is_checked_in_its_order() {
        let h = vec![7u8; 32];
        let m = im(2, h.clone());
        assert_eq!(validate_on_disk_root_hash(&m, &payload(2, 1, 32, 0x10, &h), 4096), Ok(()));
        assert!(validate_on_disk_root_hash(&m, &payload(2, 1, 32, 0x10, &h)[..0xcf], 4096).unwrap_err().contains("size mismatch"));
        assert!(validate_on_disk_root_hash(&m, &payload(1, 1, 32, 0x10, &h), 4096).unwrap_err().contains("payload version <1>"));
        assert!(validate_on_disk_root_hash(&m, &payload(2, 3, 32, 0x10, &h), 4096).unwrap_err().contains("hash type <3>"));
        assert!(validate_on_disk_root_hash(&m, &payload(2, 1, 48, 0x10, &h), 4096).unwrap_err().contains("hash size <48>"));
        assert!(validate_on_disk_root_hash(&m, &payload(2, 1, 32, 0x10, &[8u8; 32]), 4096).unwrap_err().contains("root_hash mismatch"));
        // 8 KiB and 16 KiB containers read their own slots.
        assert_eq!(validate_on_disk_root_hash(&m, &payload(2, 1, 32, 0x50, &h), 0x2000), Ok(()));
        assert_eq!(validate_on_disk_root_hash(&m, &payload(2, 1, 32, 0x90, &h), 0x4000), Ok(()));
        assert!(validate_on_disk_root_hash(&m, &payload(2, 1, 32, 0x50, &h), 4096).is_err());
    }

    /// libignition's 0x2d asks for a panic on failure; without it the
    /// failure is EAUTH; a volume that needs none passes.
    #[test]
    fn a_failure_panics_or_is_eauth() {
        let h = vec![7u8; 32];
        let m = im(2, h.clone());
        let good = payload(2, 1, 32, 0x10, &h);
        assert_eq!(authenticate_root_hash(true, true, &m, Some(&good), 0, 4096, false), Auth::Ok);
        assert!(matches!(authenticate_root_hash(true, true, &m, None, 79, 4096, false), Auth::Panic(p) if p.contains("could not authenticate personalized root hash! (79)")));
        assert!(matches!(authenticate_root_hash(true, false, &m, None, 79, 4096, false), Auth::Eauth(_)));
        assert_eq!(authenticate_root_hash(false, true, &m, None, 79, 4096, false), Auth::Ok);
        let bad = payload(2, 1, 32, 0x10, &[8u8; 32]);
        assert!(matches!(authenticate_root_hash(true, true, &m, Some(&bad), 0, 4096, false), Auth::Panic(p) if p == "could not validate root hash Authentication error (80)"));
        assert!(matches!(authenticate_root_hash(true, false, &m, Some(&bad), 0, 4096, false), Auth::Eauth(_)));
        let mut broken = m.clone();
        broken.flags = apfsread::APFS_SEAL_BROKEN;
        assert!(matches!(authenticate_root_hash(true, false, &broken, Some(&good), 0, 4096, false), Auth::Eauth(e) if e.contains("seal is broken")));
    }

    #[test]
    fn graft_devices_take_the_hosts_next_number() {
        let host = 0x0100_0005;
        assert_eq!(graft_devt(host, 0, &[]), (Some(0x0101_0005), 1));
        assert_eq!(graft_devt(host, 1, &[0x0101_0005]), (Some(0x0102_0005), 2));
        // Past 255 the number starts over at 1, skipping 0 and what is taken.
        assert_eq!(graft_devt(host, 0xff, &[]), (Some(0x0101_0005), 1));
        assert_eq!(graft_devt(host, 0xfe, &[0x01ff_0005]), (Some(0x0101_0005), 1));
        assert_eq!(graft_devt(host, 0, &[0x0101_0005]), (Some(0x0102_0005), 2));
        assert_eq!(graft_devt(0x01ab_0005, 0, &[]), (Some(0x0101_0005), 1));
    }

    #[test]
    fn graft_ranges_stay_below_the_system_identifiers() {
        assert_eq!(jobj_range_ok(0x1000, 0x2000), Ok(()));
        assert_eq!(jobj_range_ok(0x0fff_fff0_0000_0000, 0x1_0000_0000), Ok(()));
        assert_eq!(jobj_range_ok(0x0fff_fff0_0000_0000, 0xf_0000_0001), Err(34));
        assert_eq!(jobj_range_ok(u64::MAX, 1), Err(34));
        // The range may end at 0x0fffffff00000000, not past it.
        assert_eq!(jobj_range_ok(0x0fff_fffe_ffff_ffff, 1), Ok(()));
        assert_eq!(jobj_range_ok(0x0fff_ffff_0000_0000, 1), Err(34));
    }

    /// A writable host's record of a graft's range is read back only when
    /// it is whole, the host's and clear of the volume's identifiers.
    #[test]
    fn a_recorded_range_is_the_hosts_and_free() {
        let host = [0x61u8; 16];
        let rec = |uuid: Option<Vec<u8>>, base: Option<Vec<u8>>, len: Option<Vec<u8>>| {
            move |name: &str| match name {
                graft_xattr::VOL_UUID => uuid.clone(),
                graft_xattr::JOBJ_ID_BASE => base.clone(),
                graft_xattr::JOBJ_ID_LEN => len.clone(),
                _ => None,
            }
        };
        let w = |v: u64| Some(v.to_le_bytes().to_vec());
        let none = |_: u64| None;
        let all = graft_file_xattrs(host, 17, 3403);
        assert_eq!(all[0], (graft_xattr::VOL_UUID, host.to_vec()));
        assert_eq!(all[1].1, 17u64.to_le_bytes());
        assert_eq!(all[2].1, 3403u64.to_le_bytes());
        assert_eq!(recorded_jobj_range(&rec(None, w(17), w(3403)), &host, 4000, &none), Ok(None));
        assert_eq!(recorded_jobj_range(&rec(Some(host.to_vec()), w(17), w(3403)), &host, 3420, &none), Ok(Some((17, 3403))));
        assert_eq!(recorded_jobj_range(&rec(Some(host[..15].to_vec()), w(17), w(3403)), &host, 4000, &none), Err(22));
        assert_eq!(recorded_jobj_range(&rec(Some([0u8; 16].to_vec()), w(17), w(3403)), &host, 4000, &none), Err(22));
        assert_eq!(recorded_jobj_range(&rec(Some(host.to_vec()), None, w(3403)), &host, 4000, &none), Err(2));
        assert_eq!(recorded_jobj_range(&rec(Some(host.to_vec()), w(17), None), &host, 4000, &none), Err(2));
        assert_eq!(recorded_jobj_range(&rec(Some(host.to_vec()), Some(vec![1; 7]), w(3403)), &host, 4000, &none), Err(22));
        assert_eq!(recorded_jobj_range(&rec(Some(host.to_vec()), w(17), w(0)), &host, 4000, &none), Err(22));
        // The range may end at the host's next identifier, not past it.
        assert_eq!(recorded_jobj_range(&rec(Some(host.to_vec()), w(17), w(3403)), &host, 3419, &none), Err(22));
        assert_eq!(recorded_jobj_range(&rec(Some(host.to_vec()), w(17), w(3403)), &host, 4000, &|_| Some(3419)), Err(22));
        assert_eq!(recorded_jobj_range(&rec(Some(host.to_vec()), w(17), w(3403)), &host, 4000, &|_| Some(3420)), Ok(Some((17, 3403))));
        assert_eq!(reused_jobj_range(Ok(Some((17, 3403))), 3403), Some((17, 3403)));
        assert_eq!(reused_jobj_range(Ok(Some((17, 3403))), 3404), None);
        assert_eq!(reused_jobj_range(Ok(None), 1), None);
        assert_eq!(reused_jobj_range(Err(22), 1), None);
    }

    #[test]
    fn flags_keep_their_low_bits() {
        assert_eq!(va_flags(0xffff_ffff), 0x7fff_ffff);
        assert_eq!(va_flags(0xffff_ffdf), 0x3fff_ffdf);
        assert_eq!(va_flags(0x20), 0x20);
        assert_eq!(va_flags(0), 0);
    }

    fn os_image() -> (Volume, Vec<u8>) {
        let dir = std::env::var("GEX_DARWIN_RESTORE").expect("GEX_DARWIN_RESTORE");
        let f = std::fs::File::open(format!("{dir}/044-76034-038.dmg")).unwrap();
        let n = f.metadata().unwrap().len();
        let v = mount_image(Arc::new(super::super::apfsread::tests_support::HostFile(f, n))).unwrap().unwrap();
        let im4p = std::fs::read(format!("{dir}/Firmware/044-76034-038.dmg.root_hash")).unwrap();
        (v, im4p)
    }

    /// The SystemOS cryptex's sealed volume against the IPSW's
    /// os.dmg.root_hash payload (the IM4P's data, which is what a ticket's
    /// evaluation authenticates): the root hash validates, and a payload
    /// with one bit changed does not.
    #[test]
    #[ignore = "needs GEX_DARWIN_RESTORE's 044-76034-038.dmg and its root_hash (21H461)"]
    fn the_os_cryptex_root_hash_validates() {
        let (v, im4p) = os_image();
        let p = super::super::image4::init_as_payload(&im4p).unwrap().data.unwrap().to_vec();
        assert_eq!(p.len(), ROOT_HASH_PAYLOAD_SIZE);
        let m = v.integrity().unwrap().unwrap();
        let bs = v.container.block_size();
        assert_eq!(validate_on_disk_root_hash(&m, &p, bs), Ok(()));
        assert_eq!(authenticate_root_hash(true, true, &m, Some(&p), 0, bs, false), Auth::Ok);
        let mut bad = p.clone();
        bad[0x20] ^= 1;
        assert!(matches!(authenticate_root_hash(true, true, &m, Some(&bad), 0, bs, false), Auth::Panic(_)));
        // The root hash is the SHA-256 of the file-system tree's root node.
        assert_eq!(m.root_hash, HashType::Sha256.digest(&v.container.read_raw(v.omap.as_ref().unwrap().lookup(&v.container, v.sb.root_tree_oid, v.container.xid()).unwrap().unwrap().paddr).unwrap()));
    }

    /// The graft's files as the namespace sees them: the shared cache's
    /// header read, owners and modes from the image, inode numbers in the
    /// host's range, a listing with the dots, links followed.
    #[test]
    #[ignore = "needs GEX_DARWIN_RESTORE's 044-76034-038.dmg (21H461)"]
    fn the_graft_serves_the_images_files() {
        let (vol, _) = os_image();
        let len = vol.sb.next_obj_id;
        let g = Arc::new(GraftFs { vol, base: 1000, len, dir_ino: 20, dir_parent_ino: 19, devt: 0x0101_0005, seal: None, live: None });
        let m = GraftMount(Arc::clone(&g));
        let root = m.metadata("").unwrap();
        assert_eq!((root.ino, root.file_type), (20, FileType::Directory));
        let path = "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64";
        let md = m.metadata(path).unwrap();
        assert!(md.ino > 1000 && md.ino < 1000 + len);
        assert_eq!(md.mode, 0o755);
        let h = m.open(path, 0, 0).unwrap();
        let mut b = [0u8; 16];
        assert_eq!(h.read_at(0, &mut b).unwrap(), 16);
        assert_eq!(&b, b"dyld_v1   arm64\0");
        let mut rec = [0u8; 64];
        let n = m.xattr(path, XattrOp::Get { name: super::super::vattr::RECORD, buf: &mut rec }).unwrap();
        assert_eq!(super::super::vattr::Owned::parse(&rec[..n]).unwrap(), super::super::vattr::Owned { uid: 0, gid: 80, mode: 0o755, flags: 0 });
        let list = m.open("System/Library/Caches/com.apple.dyld", 0, 0).unwrap().read_dir().unwrap();
        assert_eq!(&list[0].name, ".");
        assert_eq!(&list[1].name, "..");
        assert!(list.iter().any(|e| e.name == "dyld_shared_cache_arm64" && e.ino == md.ino));
        assert_eq!(m.path_of_ino(md.ino).as_deref(), Some(path));
        assert_eq!(m.read_link("usr/lib/libstdc++.dylib").unwrap(), "libstdc++.6.dylib");
        let lib = m.metadata("usr/lib/libstdc++.dylib").unwrap();
        let real = m.metadata("usr/lib/libstdc++.6.0.9.dylib").unwrap();
        assert_eq!((lib.ino, lib.size, lib.file_type), (real.ino, real.size, FileType::Regular));
        assert_eq!(m.metadata_nofollow("usr/lib/libstdc++.dylib").unwrap().file_type, FileType::Symlink);
        assert_eq!(m.metadata("no/such").unwrap_err(), Errno::ENOENT);
        assert_eq!(m.metadata(&format!("{path}/x")).unwrap_err(), Errno::ENOTDIR);
        assert_eq!(m.open(path, crate::fs::oflags::O_RDWR, 0).unwrap_err(), Errno::EROFS);
        // A compressed file's size is its decmpfs size, and its own
        // attributes are hidden.
        let ctx = "System/Library/PrivateFrameworks/WebCore.framework/ContentFilterBlockedPage.html";
        let cmd = m.metadata(ctx).unwrap();
        assert!(cmd.size > 0);
        let mut names = vec![0u8; 256];
        let n = m.xattr(ctx, XattrOp::List { buf: &mut names }).unwrap();
        assert!(!String::from_utf8_lossy(&names[..n]).contains("decmpfs"));
        let mut page = vec![0u8; cmd.size as usize];
        assert_eq!(m.open(ctx, 0, 0).unwrap().read_at(0, &mut page).unwrap(), cmd.size);
        // An LZBITMAP subcache, opened (validated) and read across a
        // chunk's end.
        let linkedit = "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64.34.dyldlinkedit";
        assert_eq!(m.metadata(linkedit).unwrap().size, 27_410_432);
        let h = m.open(linkedit, 0, 0).unwrap();
        assert_eq!(h.read_at(0, &mut b).unwrap(), 16);
        assert_eq!(&b, b"dyld_v1   arm64\0");
        let mut across = vec![0u8; 100];
        assert_eq!(h.read_at(0x10000 - 50, &mut across).unwrap(), 100);
        assert_eq!(h.read_at(27_410_432 - 10, &mut across).unwrap(), 10);
    }
}
