//! What an open disk node does (IOStorageFamily 317.40.2, the device's:
//! `dkread`, `dkwrite`, `dkioctl`, `dkclose` in IOMediaBSDClient.cpp, and
//! XNU's specfs under them), served from the web device's disk0 image,
//! the disk its restore made ([`super::apfswrite::restore`]).
//!
//! Where each medium's bytes are: disk0's at their offset; the GPT
//! partition's at its base (`IOPartitionScheme::read` adds it); the
//! container's (`AppleAPFSMedia`) are the partition's at the same offsets
//! (the container scheme's read and write, 0xfffffff00668390c and
//! 0xfffffff0066839f4, add none). A volume's medium
//! (`AppleAPFSVolume::read`/`write`, 0xfffffff00666d248, 0xfffffff00666d33c)
//! refuses I/O to every process but the one that set its crypto state
//! (`setCrypto`, 0xfffffff00667e050), which nothing at boot does: reads
//! fail EACCES (`kIOReturnNotReadable`), writes EROFS.
//!
//! The character node's I/O (`dkreadwrite` of the uio, no buffering): an
//! unformatted medium is ENXIO; at or past the end a read gives 0 bytes
//! and a write EIO; an offset or length not a multiple of the preferred
//! block size is EINVAL (checked after the end); a transfer past the end
//! is cut short. The block node's reads go through the buffer cache in
//! 16 KiB buffers of its block size (`spec_read`, PAGE_SIZE 16 KiB with
//! more than 1 GiB of memory), which stay valid until the vnode's last
//! close, with the next buffer read ahead on a sequential read: a buffer
//! the medium gives short whose part the read wants starts past is EINVAL.
//! Its writes (the buffer cache's read-modify-write, delayed and
//! asynchronous writes) are not modelled.
//!
//! Each request that reaches the medium is counted in the storage
//! drivers' statistics ([`super::storagestack::stats`]).

use super::apfswrite::Sink;
use super::devfs::{Kind, Node};
use super::storage::{self, Media};
use crate::errno::Errno;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// The disk image, and the restore steps it does not have.
struct Disk {
    sink: Arc<dyn Sink>,
    missing: Vec<String>,
}

static DISK: OnceLock<Disk> = OnceLock::new();

/// The disk0 image the disk nodes serve (the host's file or the page's
/// store), with what its build reported missing.
pub fn install(sink: Arc<dyn Sink>, missing: Vec<String>) -> Result<(), String> {
    if sink.size() != storage::disk0_bytes() {
        return Err(format!("a disk0 image of {} bytes for disk0's {}", sink.size(), storage::disk0_bytes()));
    }
    DISK.set(Disk { sink, missing }).map_err(|_| "a disk0 image is installed already".to_string())?;
    // The stand-in the kernel's container takes at run time, once.
    crate::darwin_say!("[gex] Darwin: the disk0 image served with a stand-in: {VNODE_STAND_IN}");
    Ok(())
}

/// What is not right about serving the disk nodes: no image, or an image
/// without some of the restore's steps.
pub fn gaps() -> Option<String> {
    match DISK.get() {
        None => Some("the disk nodes' I/O: no disk0 image (GEX_DARWIN_DISK0; gexc darwin-disk0 makes one)".into()),
        Some(d) if !d.missing.is_empty() => Some(format!("the disk0 image lacks restore steps: {}", d.missing.join("; "))),
        Some(_) => None,
    }
}

/// A medium's geometry: where its bytes start on disk0, its size
/// (`getSize`), its preferred block size, and whether its I/O is a
/// volume's (refused without crypto state).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub base: u64,
    pub size: u64,
    pub block: u64,
    pub volume: bool,
}

/// The container's block size and block count, from its superblock in
/// the image (block 0's: what a probe reads).
fn container_blocks(d: &Disk) -> Result<(u64, u64), String> {
    let (base, _) = storage::partition_extent();
    let mut b = [0u8; 0x30];
    d.sink.read_at(base, &mut b)?;
    if &b[0x20..0x24] != b"NXSB" {
        return Ok((0, 0));
    }
    Ok((u64::from(u32::from_le_bytes(b[0x24..0x28].try_into().unwrap())), u64::from_le_bytes(b[0x28..0x30].try_into().unwrap())))
}

/// Whether the container in the image has a valid volume in slot `index`
/// (`AppleAPFSVolume::init`'s states 5 and 6: its superblock's magic and
/// slot right, no incompatible feature outside 0x3fb).
fn volume_valid(d: &Disk, index: u32) -> Result<bool, String> {
    let (base, size) = storage::partition_extent();
    let c = super::apfsread::Container::open(Arc::new(PartMedium(Arc::clone(&d.sink), base, size))).map_err(|e| e.to_string())?;
    let Some(&oid) = c.nx.fs_oid.get(index as usize) else { return Ok(false) };
    if oid == 0 {
        return Ok(false);
    }
    let omap = c.omap().map_err(|e| e.to_string())?;
    let Some(v) = omap.lookup(&c, oid, c.xid()).map_err(|e| e.to_string())? else { return Ok(false) };
    let sb = c.read_raw(v.paddr).map_err(|e| e.to_string())?;
    let magic = &sb[0x20..0x24] == b"APSB";
    let slot = u32::from_le_bytes(sb[0x24..0x28].try_into().unwrap()) == index;
    let incompat = u64::from_le_bytes(sb[0x38..0x40].try_into().unwrap());
    Ok(magic && slot && incompat & !0x3fb == 0)
}

/// The `apfs_fs_flags` of the volume in slot `index` of the container in
/// the image (none for an empty slot); an error without an image.
pub fn volume_fs_flags(index: u32) -> Result<Option<u64>, String> {
    let d = DISK.get().ok_or("no disk0 image")?;
    let (base, size) = storage::partition_extent();
    let c = super::apfsread::Container::open(Arc::new(PartMedium(Arc::clone(&d.sink), base, size))).map_err(|e| e.to_string())?;
    let Some(&oid) = c.nx.fs_oid.get(index as usize) else { return Ok(None) };
    if oid == 0 {
        return Ok(None);
    }
    let omap = c.omap().map_err(|e| e.to_string())?;
    let Some(v) = omap.lookup(&c, oid, c.xid()).map_err(|e| e.to_string())? else { return Ok(None) };
    let sb = c.read_raw(v.paddr).map_err(|e| e.to_string())?;
    Ok(Some(u64::from_le_bytes(sb[0x108..0x110].try_into().unwrap())))
}

/// The volume in slot `index` of the container in the image, for a mount
/// of it at run time, read as the kernel's container holds it
/// ([`KERNEL_NX`]): its file-system tree's nodes from the container's object
/// cache, through the volume's object map's newest mappings, so that what
/// a file-system call changes reads back at once, committed or not, and a
/// block a commit freed is never read for the tree; its file data from the
/// image, where the container writes it as it writes it. An error without
/// an image, for an empty slot, or where the image cannot be read.
pub fn volume(index: u32) -> Result<super::apfsread::Volume, String> {
    let d = DISK.get().ok_or("no disk0 image (GEX_DARWIN_DISK0)")?;
    let (base, size) = storage::partition_extent();
    let c = Arc::new(super::apfsread::Container::open(Arc::new(PartMedium(Arc::clone(&d.sink), base, size))).map_err(|e| format!("the container in the disk0 image: {e}"))?);
    let sb = match super::share::remote() {
        Some(r) => through(r, Call::VolSb, index, &[])?,
        None => vol_sb_here(index)?,
    };
    super::apfsread::Volume::live(c, &sb, Arc::new(KernelTree(index))).map_err(|e| format!("volume {index} of the container in the disk0 image: {e}"))
}

/// Volume `index`'s file-system tree as the kernel's container holds it.
struct KernelTree(u32);

impl super::apfsread::btree::LiveNodes for KernelTree {
    fn root(&self) -> super::apfsread::Result<u64> {
        match super::share::remote() {
            Some(r) => through(r, Call::Root, self.0, &[]).map(|b| u64::from_le_bytes(b[..8].try_into().unwrap())),
            None => with_container(|nx| nx.fs_tree_root(self.0 as usize)),
        }
        .map_err(super::apfsread::Error::Io)
    }
    fn node(&self, oid: u64) -> super::apfsread::Result<Arc<[u8]>> {
        match super::share::remote() {
            Some(r) => through(r, Call::Node, self.0, &oid.to_le_bytes()).map(Into::into),
            None => with_container(|nx| nx.fs_tree_node(self.0 as usize, oid)).map(Into::into),
        }
        .map_err(super::apfsread::Error::Io)
    }
}

/// Volume `index`'s superblock as the kernel's container holds it.
fn vol_sb_here(index: u32) -> Result<Vec<u8>, String> {
    with_container(|nx| {
        if nx.vol_oid(index as usize).is_none() {
            return Err(format!("the container in the disk0 image has no volume in slot {index}"));
        }
        Ok(nx.vol_sb_read(index as usize)?.0.to_vec())
    })
}

/// The calls on the kernel's container a process of the page makes of the
/// global kernel's ([`serve`]): in the page the container's state in
/// memory (its object cache, space manager and open transaction) is the
/// system's, as it is natively, not each process's copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Call {
    Root = 1,
    Node = 2,
    VolSb = 3,
    MountRw = 4,
    VfsSync = 5,
    UnmountForced = 6,
    VnodeGet = 7,
    Setattr = 8,
    HeldTimes = 9,
    HoldsRw = 10,
    CapsFacts = 11,
    VolumeIds = 12,
    Xattr = 13,
    JobjGe = 14,
    AllocJobj = 15,
}

impl Call {
    fn of(n: u8) -> Option<Call> {
        use Call::*;
        Some(match n {
            1 => Root,
            2 => Node,
            3 => VolSb,
            4 => MountRw,
            5 => VfsSync,
            6 => UnmountForced,
            7 => VnodeGet,
            8 => Setattr,
            9 => HeldTimes,
            10 => HoldsRw,
            11 => CapsFacts,
            12 => VolumeIds,
            13 => Xattr,
            14 => JobjGe,
            15 => AllocJobj,
            _ => return None,
        })
    }

    /// Whether the call changes the container: its answer is never asked
    /// for twice (a short one: an error said within [`SAID_MAX`]).
    fn changes(self) -> bool {
        matches!(self, Call::MountRw | Call::VfsSync | Call::UnmountForced | Call::VnodeGet | Call::Setattr | Call::AllocJobj)
    }
}

/// The longest error a changing call's answer carries: the answer always
/// fits the first room [`super::share::call_read`] gives it.
const SAID_MAX: usize = 3800;

/// Call `c` on volume slot `index` with `args`, of the global kernel's
/// container, the caller's clock carried: its answer, or its error.
fn through(r: super::share::Remote, c: Call, index: u32, args: &[u8]) -> Result<Vec<u8>, String> {
    let mut q = vec![c as u8];
    q.extend_from_slice(&index.to_le_bytes());
    q.extend_from_slice(&clock_now().to_le_bytes());
    q.extend_from_slice(args);
    let b = super::share::call_read(r, super::share::op::NX, &q);
    match b.split_first() {
        Some((0, rest)) => Ok(rest.to_vec()),
        Some((_, said)) => Err(String::from_utf8_lossy(said).into_owned()),
        None => Err("the global kernel's container gave no answer".into()),
    }
}

fn put_attrs(q: &mut Vec<u8>, a: &crate::vfs::VnodeAttrs) {
    let mut some = 0u8;
    for (i, on) in [a.uid.is_some(), a.gid.is_some(), a.mode.is_some(), a.flags.is_some(), a.atime.is_some(), a.mtime.is_some()].into_iter().enumerate() {
        some |= (on as u8) << i;
    }
    q.push(some);
    for v in [a.uid, a.gid, a.mode, a.flags] {
        q.extend_from_slice(&v.unwrap_or(0).to_le_bytes());
    }
    for t in [a.atime, a.mtime] {
        let (s, ns) = t.unwrap_or((0, 0));
        q.extend_from_slice(&s.to_le_bytes());
        q.extend_from_slice(&ns.to_le_bytes());
    }
}

fn get_attrs(b: &[u8]) -> Option<crate::vfs::VnodeAttrs> {
    let (&some, b) = b.split_first()?;
    if b.len() != 16 + 24 {
        return None;
    }
    let w = |i: usize| u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
    let t = |o: usize| (i64::from_le_bytes(b[o..o + 8].try_into().unwrap()), u32::from_le_bytes(b[o + 8..o + 12].try_into().unwrap()));
    let on = |i: u8| some & (1 << i) != 0;
    Some(crate::vfs::VnodeAttrs {
        uid: on(0).then(|| w(0)),
        gid: on(1).then(|| w(1)),
        mode: on(2).then(|| w(2)),
        flags: on(3).then(|| w(3)),
        atime: on(4).then(|| t(16)),
        mtime: on(5).then(|| t(28)),
    })
}

/// A call on the kernel's container from a process of the page, served on
/// this (the global kernel's) container, the caller's clock read where
/// APFS reads `nanotime`: the answer's length (all of it, written as far
/// as `out` holds it), or `-EINVAL` for a request that is not one.
pub(crate) fn serve(req: &[u8], out: &mut [u8]) -> i64 {
    const EINVAL: i64 = 22;
    let (Some(c), 13..) = (req.first().and_then(|&n| Call::of(n)), req.len()) else { return -EINVAL };
    let index = u32::from_le_bytes(req[1..5].try_into().unwrap());
    let now = u64::from_le_bytes(req[5..13].try_into().unwrap());
    let a = &req[13..];
    let u = |o: usize| a.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()));
    CARRIED_NOW.with(|t| t.set(Some(now)));
    let answer: Result<Vec<u8>, String> = (|| {
        Ok(match c {
            Call::Root => with_container(|nx| nx.fs_tree_root(index as usize))?.to_le_bytes().to_vec(),
            Call::Node => with_container(|nx| nx.fs_tree_node(index as usize, u(0).ok_or("no oid")?))?.to_vec(),
            Call::VolSb => vol_sb_here(index)?,
            Call::MountRw => mount_rw(index).map(|()| Vec::new())?,
            Call::VfsSync => vfs_sync(index, a.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).ok_or("no waitfor")?).map(|()| Vec::new())?,
            Call::UnmountForced => unmount_forced(index).map(|()| Vec::new())?,
            Call::VnodeGet => vnode_get(index, u(0).ok_or("no inode")?).map(|()| Vec::new())?,
            Call::Setattr => {
                let ino = u(0).ok_or("no inode")?;
                let fd = *a.get(8).ok_or("no fd flag")? != 0;
                let attrs = get_attrs(&a[9..]).ok_or("no attributes")?;
                match setattr(index, ino, &attrs, fd)? {
                    Ok(()) => vec![0],
                    Err(e) => [&[1u8][..], &e.to_le_bytes()].concat(),
                }
            }
            Call::HeldTimes => match held_times(index, u(0).ok_or("no inode")?)? {
                Some((m, c)) => [&[1u8][..], &m.to_le_bytes(), &c.to_le_bytes()].concat(),
                None => vec![0],
            },
            Call::HoldsRw => vec![holds_rw(index) as u8],
            Call::CapsFacts => {
                let f = caps_facts(index)?;
                [&f.role.to_le_bytes()[..], &f.incompat.to_le_bytes(), &f.ro_compat.to_le_bytes(), &f.fs_flags.to_le_bytes(), &[f.grouped as u8]].concat()
            }
            Call::VolumeIds => {
                let (next, uuid) = volume_ids(index)?;
                [&next.to_le_bytes()[..], &uuid].concat()
            }
            Call::Xattr => match xattr(index, u(0).ok_or("no inode")?, std::str::from_utf8(&a[8..]).map_err(|_| "a name that is not UTF-8")?)? {
                Some(v) => [&[1u8][..], &v].concat(),
                None => vec![0],
            },
            Call::JobjGe => match jobj_at_or_above(index, u(0).ok_or("no identifier")?)? {
                Some(v) => [&[1u8][..], &v.to_le_bytes()].concat(),
                None => vec![0],
            },
            Call::AllocJobj => match allocate_graft_jobj_range(index, u(0).ok_or("no inode")?, u(8).ok_or("no length")?)? {
                Ok(base) => [&[0u8][..], &base.to_le_bytes()].concat(),
                Err(e) => [&[1u8][..], &e.to_le_bytes()].concat(),
            },
        })
    })();
    CARRIED_NOW.with(|t| t.set(None));
    let b = match answer {
        Ok(v) => [&[0u8][..], &v].concat(),
        Err(why) => {
            let mut said = why.into_bytes();
            if c.changes() {
                said.truncate(SAID_MAX);
            }
            [&[1u8][..], &said].concat()
        }
    };
    let n = b.len().min(out.len());
    out[..n].copy_from_slice(&b[..n]);
    b.len() as i64
}

/// Whether a disk0 image is served.
pub fn installed() -> bool {
    DISK.get().is_some()
}

/// Whether the image served lacks restore step `step` (as its build named
/// it in what it reported missing).
pub fn lacks(step: &str) -> bool {
    DISK.get().is_some_and(|d| d.missing.iter().any(|m| m == step))
}

/// The kernel's APFS container on the image (`nx_mount`'s state: its
/// object cache, space manager and open transaction), the writer the
/// restore model writes with ([`super::apfswrite::tx::Nx`]): mounted from
/// the image's latest checkpoint the first time the kernel needs its
/// state, kept for the system's life. Its writes go to the image as the
/// kernel's reach the device (block 0 at its read-write update, a
/// checkpoint when a transaction commits); what a file-system call changes
/// stays in the open transaction until a sync, an unmount or the
/// transaction's own close rule commits it, as on internal storage nothing
/// commits on a timer. The volumes served from the image read through it
/// ([`volume`]).
static KERNEL_NX: Mutex<Option<super::apfswrite::tx::Nx<'static>>> = Mutex::new(None);

/// `f` on the kernel's container, mounted first when it is not.
fn with_container<R>(f: impl FnOnce(&mut super::apfswrite::tx::Nx<'static>) -> Result<R, String>) -> Result<R, String> {
    use super::apfswrite::tx::{Mode, Nx};
    let d = DISK.get().ok_or("no disk0 image (GEX_DARWIN_DISK0)")?;
    let mut g = KERNEL_NX.lock().unwrap_or_else(|e| e.into_inner());
    if g.is_none() {
        let (base, size) = storage::partition_extent();
        let part: &'static PartMedium = Box::leak(Box::new(PartMedium(Arc::clone(&d.sink), base, size)));
        let mut nx = Nx::mounted(part, Mode::Kernel).map_err(|e| format!("the kernel's mount of the container in the disk0 image: {e}"))?;
        // The device's DK_FEATURE_BARRIER and DKIOCISSOLIDSTATE answers.
        nx.set_barrier(super::storagestack::container_barrier());
        nx.set_solid_state(super::storagestack::container_solid_state());
        *g = Some(nx);
    }
    f(g.as_mut().expect("mounted above"))
}

/// The running system's vnode table as the kernel's container sees it:
/// the vnodes the model counts are the disk0 volumes' that its lookups
/// reached ([`super::apfswrite::tx::Nx::vnode_get`]); every other
/// filesystem's (the root volume's, devfs's, the grafts') is not counted.
/// Below XNU's desiredvnodes (10,000, the J120 device tree's /defaults
/// kern.maxvnodes) no disk0 vnode is taken to be recycled, so an inode's
/// unwritten times wait for its next write or a sync, and its in-memory
/// object keeps its leaf hint.
pub const VNODE_STAND_IN: &str = "the running system's vnode table (stand-in: only the disk0 volumes' vnodes the lookups reach are counted, the root volume's, devfs's and the grafts' leave room below desiredvnodes 10,000, so no disk0 vnode is recycled: unwritten times wait for the inode's next write or a sync, and an in-memory object keeps its leaf hint; measure vfs.vnstats.num_vnodes and num_recycledvnodes on the device during boot)";

/// File-system call `f` on the kernel's container: what it left undecided
/// ([`super::apfswrite::fsops::run_time_gaps`]) is its error.
fn kernel_op<R>(f: impl FnOnce(&mut super::apfswrite::tx::Nx<'static>) -> Result<R, String>) -> Result<R, String> {
    with_container(|nx| {
        let r = f(nx);
        let gaps = super::apfswrite::fsops::run_time_gaps(nx);
        let r = r?;
        gaps.map(|()| r)
    })
}

/// The kernel's clock as APFS reads it (`nanotime`): nanoseconds since
/// 1970. In the global kernel, which reads no clock, the calling
/// process's reading, carried with its call ([`serve`]).
fn nanotime() -> u64 {
    if let Some(t) = CARRIED_NOW.with(std::cell::Cell::get) {
        return t;
    }
    clock_now()
}

fn clock_now() -> u64 {
    crate::darwin::time::realtime().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

thread_local! {
    /// The calling process's `nanotime`, while the global kernel serves its
    /// call on the container.
    static CARRIED_NOW: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// A writing mount of the volume in slot `index` (`apfs_vfsop_mount`):
/// the container updated to read-write when it is not yet
/// (`nx_rw_update`'s `nx_ro_to_rw`: block 0 rewritten, the allocation
/// zones and cursors set up, [`super::apfswrite::tx::Nx::mount_rw`]), then
/// the volume's read-write mount and the writes it makes
/// ([`super::apfswrite::fsops::mount_rw`]).
pub fn mount_rw(index: u32) -> Result<(), String> {
    if let Some(r) = super::share::remote() {
        return through(r, Call::MountRw, index, &[]).map(|_| ());
    }
    kernel_op(|nx| {
        nx.mount_rw()?;
        super::apfswrite::fsops::mount_rw(nx, index as usize, &mut nanotime)
    })
}

/// `VFS_SYNC(mp, waitfor)` of the volume in slot `index`, which the
/// kernel's container holds mounted read-write: apfs_vfsop_sync's vnode
/// pass and the commit of the container's open transaction
/// ([`super::apfswrite::fsops::vfs_sync`]).
pub fn vfs_sync(index: u32, waitfor: u32) -> Result<(), String> {
    if let Some(r) = super::share::remote() {
        return through(r, Call::VfsSync, index, &waitfor.to_le_bytes()).map(|_| ());
    }
    kernel_op(|nx| super::apfswrite::fsops::vfs_sync(nx, index as usize, waitfor, &mut nanotime))
}

/// `dounmount(mp, MNT_FORCE)` of the volume in slot `index`, which the
/// kernel's container holds mounted read-write: no `VFS_SYNC`; `vflush`'s
/// reclaims, each vnode's `VNOP_FSYNC` writing the times its inode holds;
/// then `VFS_UNMOUNT`, apfs_vfsop_unmount's commit and its writes in the
/// next transaction, left open ([`super::apfswrite::fsops::unmount`]). On
/// a content-protected volume its teardown of the crypto-state caches
/// (the ep cache's invalidation, K 0x66cbc24) is not implemented.
pub fn unmount_forced(index: u32) -> Result<(), String> {
    if let Some(r) = super::share::remote() {
        return through(r, Call::UnmountForced, index, &[]).map(|_| ());
    }
    kernel_op(|nx| {
        let (sb, _) = nx.vol_sb_read(index as usize)?;
        if u64::from_le_bytes(sb[0x108..0x110].try_into().unwrap()) & super::apfsread::APFS_FS_UNENCRYPTED == 0 {
            return Err(format!("not implemented: apfs_vfsop_unmount's teardown of the crypto-state caches of volume slot {index}, which is encrypted (the ep cache's invalidation, K 0x66cbc24)"));
        }
        super::apfswrite::fsops::unmount(nx, index as usize, true, &mut nanotime)
    })
}

/// Inode `ino` of the volume in slot `index` brought into the kernel by a
/// lookup (`VNOP_LOOKUP`'s `vnode_create`, at the head of the mount's
/// vnode list), unless it has a vnode: the order a vnode pass visits the
/// volume's inodes in, and the leaf hint its in-memory object holds from
/// its load, which its updates start from
/// ([`super::apfswrite::fsops::vnode_load`]).
pub fn vnode_get(index: u32, ino: u64) -> Result<(), String> {
    if let Some(r) = super::share::remote() {
        return through(r, Call::VnodeGet, index, &ino.to_le_bytes()).map(|_| ());
    }
    kernel_op(|nx| super::apfswrite::fsops::vnode_load(nx, index as usize, ino, &|| format!("a lookup of inode {ino:#x} on volume slot {index} at run time")))
}

/// `VNOP_SETATTR` of `a` on inode `ino` of the volume in slot `index`
/// (`fd`: through an open descriptor), its checks passed: apfs_vnop_setattr
/// on the kernel's container ([`super::apfswrite::fsops::vnode_setattr`],
/// at the system's securelevel). A volume the container does not hold
/// mounted read-write is not written. `Ok(Err(errno))` is the call's own
/// error.
pub fn setattr(index: u32, ino: u64, a: &crate::vfs::VnodeAttrs, fd: bool) -> Result<Result<(), i32>, String> {
    if let Some(r) = super::share::remote() {
        let mut q = ino.to_le_bytes().to_vec();
        q.push(fd as u8);
        put_attrs(&mut q, a);
        let b = through(r, Call::Setattr, index, &q)?;
        return Ok(if b[0] == 0 { Ok(()) } else { Err(i32::from_le_bytes(b[1..5].try_into().unwrap())) });
    }
    kernel_op(|nx| {
        if !nx.mounted.contains(&(index as usize)) {
            return Err(format!("a setattr of inode {ino:#x} of volume slot {index}, which the kernel's container does not hold mounted read-write"));
        }
        super::apfswrite::fsops::vnode_setattr(nx, index as usize, ino, a, fd, super::kern::DARWIN_SECURELEVEL, &mut nanotime)
    })
}

/// The modification and change times inode `ino` of the volume in slot
/// `index` holds unwritten in its in-memory object, if any.
pub fn held_times(index: u32, ino: u64) -> Result<Option<(u64, u64)>, String> {
    if let Some(r) = super::share::remote() {
        let b = through(r, Call::HeldTimes, index, &ino.to_le_bytes())?;
        return Ok((b[0] == 1).then(|| (u64::from_le_bytes(b[1..9].try_into().unwrap()), u64::from_le_bytes(b[9..17].try_into().unwrap()))));
    }
    with_container(|nx| Ok(nx.jobj_times.get(&(index as usize, ino)).copied()))
}

/// Whether the kernel's container holds the volume in slot `index`
/// mounted read-write.
pub fn holds_rw(index: u32) -> bool {
    if let Some(r) = super::share::remote() {
        return through(r, Call::HoldsRw, index, &[]).is_ok_and(|b| b[0] == 1);
    }
    KERNEL_NX.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_some_and(|nx| nx.mounted.contains(&(index as usize)))
}

/// What of the volume in slot `index`'s superblock, as the kernel holds
/// it, `apfs_vfsop_getattr` makes its capabilities of.
pub fn caps_facts(index: u32) -> Result<super::attrcall::CapsFacts, String> {
    if let Some(r) = super::share::remote() {
        let b = through(r, Call::CapsFacts, index, &[])?;
        let q = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        return Ok(super::attrcall::CapsFacts { role: u16::from_le_bytes([b[0], b[1]]), incompat: q(2), ro_compat: q(10), fs_flags: q(18), grouped: b[26] != 0 });
    }
    with_container(|nx| {
        let (sb, _) = nx.vol_sb_read(index as usize)?;
        let q = |o: usize| u64::from_le_bytes(sb[o..o + 8].try_into().unwrap());
        Ok(super::attrcall::CapsFacts { role: u16::from_le_bytes([sb[0x3c4], sb[0x3c5]]), incompat: q(0x38), ro_compat: q(0x30), fs_flags: q(0x108), grouped: sb[0x3f0..0x400].iter().any(|&b| b != 0) })
    })
}

/// The volume in slot `index` as the kernel holds it: its next object
/// identifier (`apfs_next_obj_id`) and its UUID.
pub fn volume_ids(index: u32) -> Result<(u64, [u8; 16]), String> {
    if let Some(r) = super::share::remote() {
        let b = through(r, Call::VolumeIds, index, &[])?;
        return Ok((u64::from_le_bytes(b[..8].try_into().unwrap()), b[8..24].try_into().unwrap()));
    }
    with_container(|nx| {
        let (sb, _) = nx.vol_sb_read(index as usize)?;
        Ok((u64::from_le_bytes(sb[0xb0..0xb8].try_into().unwrap()), sb[0xf0..0x100].try_into().unwrap()))
    })
}

/// The value of attribute `name` of object `ino` on the volume in slot
/// `index` as the kernel holds it, file-system owned or not; none when
/// the object has no such record. A value kept in a data stream is not
/// read here (reported).
pub fn xattr(index: u32, ino: u64, name: &str) -> Result<Option<Vec<u8>>, String> {
    if let Some(r) = super::share::remote() {
        let mut q = ino.to_le_bytes().to_vec();
        q.extend_from_slice(name.as_bytes());
        let b = through(r, Call::Xattr, index, &q)?;
        return Ok((b[0] == 1).then(|| b[1..].to_vec()));
    }
    with_container(|nx| {
        let Some(v) = super::apfswrite::fsops::xattr_record(nx, index as usize, ino, name)? else { return Ok(None) };
        let flags = u16::from_le_bytes([v[0], v[1]]);
        if flags & 2 == 0 {
            return Err(format!("not implemented: attribute {name} of object {ino:#x}, kept in a data stream"));
        }
        let len = u16::from_le_bytes([v[2], v[3]]) as usize;
        v.get(4..4 + len).map(<[u8]>::to_vec).map(Some).ok_or_else(|| format!("attribute {name} of object {ino:#x}: a record shorter than its length"))
    })
}

/// `apfs_lookup_ge_jobj_id`: the least object identifier at or above
/// `from` that a record of the volume in slot `index`'s file-system tree
/// is keyed by, if any.
pub fn jobj_at_or_above(index: u32, from: u64) -> Result<Option<u64>, String> {
    if let Some(r) = super::share::remote() {
        let b = through(r, Call::JobjGe, index, &from.to_le_bytes())?;
        return Ok((b[0] == 1).then(|| u64::from_le_bytes(b[1..9].try_into().unwrap())));
    }
    with_container(|nx| {
        let (t, mut st) = nx.fs_tree(index as usize)?;
        Ok(t.get_gt(&mut st, &from.to_le_bytes())?.map(|(k, _)| u64::from_le_bytes(k[..8].try_into().unwrap()) & 0x0fff_ffff_ffff_ffff))
    })
}

/// `allocate_graft_jobj_range` on the volume in slot `index`, mounted
/// read-write, for image file `ino`'s graft of a volume whose next object
/// identifier is `len` ([`super::apfswrite::fsops::allocate_graft_jobj_range`]).
pub fn allocate_graft_jobj_range(index: u32, ino: u64, len: u64) -> Result<Result<u64, i32>, String> {
    if let Some(r) = super::share::remote() {
        let mut q = ino.to_le_bytes().to_vec();
        q.extend_from_slice(&len.to_le_bytes());
        let b = through(r, Call::AllocJobj, index, &q)?;
        return Ok(if b[0] == 0 { Ok(u64::from_le_bytes(b[1..9].try_into().unwrap())) } else { Err(i32::from_le_bytes(b[1..5].try_into().unwrap())) });
    }
    kernel_op(|nx| super::apfswrite::fsops::allocate_graft_jobj_range(nx, index as usize, ino, len, &mut nanotime))
}

/// The partition's bytes as a medium of their own.
struct PartMedium(Arc<dyn Sink>, u64, u64);

impl Sink for PartMedium {
    fn write_at(&self, off: u64, buf: &[u8]) -> Result<(), String> {
        if off + buf.len() as u64 > self.2 {
            return Err(format!("a write of {off}+{} past the partition's {} bytes", buf.len(), self.2));
        }
        self.0.write_at(self.1 + off, buf)
    }
}

impl super::apfsread::Medium for PartMedium {
    fn size(&self) -> u64 {
        self.2
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), String> {
        if off + buf.len() as u64 > self.2 {
            return Err(format!("a read of {off}+{} past the partition's {} bytes", buf.len(), self.2));
        }
        self.0.read_at(self.1 + off, buf)
    }
}

/// Medium `m`'s geometry in the image.
pub fn geometry(m: Media) -> Result<Geometry, String> {
    let d = DISK.get().ok_or("no disk0 image")?;
    let n = storage::nvme();
    let lba = u64::from(n.block_size);
    let (pbase, psize) = storage::partition_extent();
    Ok(match m {
        Media::Whole => Geometry { base: 0, size: storage::disk0_bytes(), block: lba, volume: false },
        Media::Partition => Geometry { base: pbase, size: psize, block: lba, volume: false },
        // AppleAPFSMedia::init: the partition's size, min(nx_block_size,
        // 4096) (NX_MINIMUM_BLOCK_SIZE) its block.
        Media::Container => {
            let (bs, _) = container_blocks(d)?;
            Geometry { base: pbase, size: psize, block: bs.min(4096), volume: false }
        }
        // AppleAPFSVolume::init: the space manager's blocks of its block
        // size (main device and tier 2), min(block, 4096); 0 for a slot
        // with no valid volume.
        Media::Volume(i) => {
            let (bs, count) = container_blocks(d)?;
            let size = if volume_valid(d, i)? { bs * count } else { 0 };
            Geometry { base: pbase, size, block: bs.min(4096), volume: true }
        }
        #[allow(unreachable_patterns)]
        _ => return Err(format!("the geometry of {m:?}")),
    })
}

/// `errnoFromReturn` of the volumes' refusals.
const EACCES: i32 = 13;
const EROFS: i32 = 30;
const EINVAL: i32 = 22;
const EIO: i32 = 5;
const ENXIO: i32 = 6;

fn e(darwin: i32) -> Errno {
    super::errno::errno_of(darwin)
}

/// The medium of a disk node.
fn media_of(n: &Node) -> Result<Media, Errno> {
    storage::media_by_name(n.name.trim_start_matches('r')).map(|(m, _)| m).ok_or(Errno::ENXIO)
}

/// `dkreadwrite` of a character node's uio: `buf.len()` bytes at `off`.
fn dkreadwrite(n: &Node, off: u64, read: Option<&mut [u8]>, write: Option<&[u8]>) -> Result<usize, Errno> {
    let d = DISK.get().ok_or(Errno::ENXIO)?;
    let g = geometry(media_of(n)?).map_err(|_| Errno::EIO)?;
    if g.size == 0 || g.block == 0 {
        return Err(e(ENXIO));
    }
    let count = read.as_ref().map_or_else(|| write.map_or(0, <[u8]>::len), |b| b.len()) as u64;
    if off >= g.size {
        return if read.is_some() { Ok(0) } else { Err(e(EIO)) };
    }
    if off % g.block != 0 || count % g.block != 0 {
        return Err(e(EINVAL));
    }
    let n_bytes = count.min(g.size - off) as usize;
    if g.volume {
        return Err(e(if read.is_some() { EACCES } else { EROFS }));
    }
    let m = media_of(n)?;
    match (read, write) {
        (Some(b), _) => request(d, m, g.base + off, Io::Read(&mut b[..n_bytes]))?,
        (_, Some(b)) => request(d, m, g.base + off, Io::Write(&b[..n_bytes]))?,
        _ => {}
    }
    Ok(n_bytes)
}

/// A transfer a medium passes down to the storage driver.
enum Io<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

/// The namespace whose storage driver serves disk0 and the media above it.
const MAIN_NSID: u32 = 1;

/// One request of medium `m` at disk0 offset `at`, as it goes down the
/// stack to the medium, counted where its drivers count it: the container
/// scheme's read and write (0xfffffff00668390c, 0xfffffff0066839f4) add
/// one operation and the buffer's length before passing it on, and a write
/// marks the scheme dirty (its +0xe0 bits, which DKIOCSYNCHRONIZECACHE
/// consults); `IOBlockStorageDriver::prepareRequestCompletion` adds the
/// bytes moved and the time since `prepareRequest` (latency 0), and an
/// error for a failed or short transfer.
fn request(d: &Disk, m: Media, at: u64, io: Io<'_>) -> Result<(), Errno> {
    use super::storagestack::stats;
    let write = matches!(io, Io::Write(_));
    let len = match &io {
        Io::Read(b) => b.len(),
        Io::Write(b) => b.len(),
    } as u64;
    if m == Media::Container {
        stats::scheme_transfer(len, write);
    }
    let start = crate::darwin::time::Instant::now();
    let r = match io {
        Io::Read(b) => d.sink.read_at(at, b),
        Io::Write(b) => d.sink.write_at(at, b),
    };
    if write && m == Media::Container {
        SCHEME_DIRTY.fetch_or(3, std::sync::atomic::Ordering::AcqRel);
    }
    let ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let moved = if r.is_ok() { len } else { 0 };
    stats::driver_transfer(MAIN_NSID, moved, ns, 0, write);
    if r.is_err() {
        stats::driver_error(MAIN_NSID, write);
    }
    r.map_err(|_| e(EIO))
}

/// The container scheme's dirty bits (its +0xe0, ORed with 3 by each write
/// it passes down, cleared by the synchronize that passes on).
static SCHEME_DIRTY: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// `PAGE_SIZE` on the device (16 KiB pages: the boot's memory size is
/// over 1 GiB).
const PAGE_SIZE: u64 = 16384;

/// A block node's vnode in the buffer cache: its valid buffers by block
/// number (each its bytes, `bsize - b_resid` of them), and `v_speclastr`,
/// the last buffer `spec_read` read (-1 for a new vnode, `checkalias`).
struct BlockVnode {
    bufs: HashMap<u64, Vec<u8>>,
    lastr: i64,
}

/// The block nodes' vnodes, by minor. Their buffers stay valid until the
/// vnode's last close invalidates them (`spec_close`'s
/// `buf_invalidateblks`).
static BLOCK_VNODES: Mutex<Option<HashMap<u32, BlockVnode>>> = Mutex::new(None);

/// How many buffers the block nodes may hold before the buffer cache could
/// have to reuse one: `CONFIG_MIN_NBUF`, the fewest buffer headers the
/// kernel makes (`bsd_get_bufferhdr_map_size`). Which buffer `getnewbuf`
/// would take past that depends on every other user of the cache.
const BUFFERS_HELD: usize = 256;

/// One buffer of a block node read from the medium (`buf_strategy` to
/// `dkreadwrite` of the buffer): its valid bytes, cut at the end of the
/// medium, none at or past it.
fn bdev_fill(d: &Disk, m: Media, g: Geometry, bn: u64, bsize: u64) -> Result<Vec<u8>, Errno> {
    let start = bn * g.block;
    if start >= g.size {
        return Ok(Vec::new());
    }
    if g.volume {
        return Err(e(EACCES));
    }
    let mut b = vec![0u8; bsize.min(g.size - start) as usize];
    request(d, m, g.base + start, Io::Read(&mut b))?;
    Ok(b)
}

/// `spec_read` of a block node: buffers of `PAGE_SIZE / bsize` blocks,
/// read through the buffer cache (`buf_bread`), and when the read follows
/// the last one, the next buffer read ahead too (`buf_breadn`, which skips
/// a buffer already valid).
fn bdev_read(n: &Node, mut off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
    let d = DISK.get().ok_or(Errno::ENXIO)?;
    let m = media_of(n)?;
    let g = geometry(m).map_err(|_| Errno::EIO)?;
    // v_specsize: the minor's block size, its preferred block size until
    // DKIOCSETBLOCKSIZE (which a process cannot issue).
    let spec = g.block;
    if spec == 0 || spec > PAGE_SIZE {
        return Err(e(EINVAL));
    }
    let bscale = PAGE_SIZE / spec;
    let bsize = bscale * spec;
    let mut cache = BLOCK_VNODES.lock().unwrap_or_else(|e| e.into_inner());
    let cache = cache.get_or_insert_with(HashMap::new);
    let held: usize = cache.values().map(|v| v.bufs.len()).sum();
    let vn = cache.entry(n.minor).or_insert_with(|| BlockVnode { bufs: HashMap::new(), lastr: -1 });
    let mut held = held;
    let mut done = 0usize;
    loop {
        let bn = (off / spec) & !(bscale - 1);
        let on = (off % bsize) as usize;
        let ahead = vn.lastr >= 0 && vn.lastr as u64 + bscale == bn;
        let mut failed = None;
        for (b, wanted) in [(bn, true), (bn + bscale, ahead)] {
            // The read ahead is issued before the wanted buffer's read is
            // waited for, whatever that read's outcome.
            if !wanted || vn.bufs.contains_key(&b) {
                continue;
            }
            if held >= BUFFERS_HELD {
                super::note_unimplemented(format!(
                    "a read of /dev/{} needing more than {BUFFERS_HELD} buffers in the buffer cache: which one getnewbuf reuses",
                    n.name
                ));
                failed = failed.or(Some(e(EIO)));
                continue;
            }
            // bio_doread: a buffer whose data is not valid is read, and the
            // read paid for in the caller's ru_inblock.
            super::pagecache::count_ru(super::ru::l::INBLOCK);
            match bdev_fill(d, m, g, b, bsize) {
                Ok(bytes) => {
                    vn.bufs.insert(b, bytes);
                    held += 1;
                }
                // A failed read-ahead leaves no buffer and fails nothing.
                Err(_) if b != bn => {}
                Err(err) => failed = failed.or(Some(err)),
            }
        }
        // spec_read records the buffer it asked for whether or not the
        // read worked.
        vn.lastr = bn as i64;
        if let Some(err) = failed {
            return Err(err);
        }
        let have = vn.bufs[&bn].len();
        if on > have {
            return Err(e(EINVAL));
        }
        let take = (have - on).min(buf.len() - done);
        buf[done..done + take].copy_from_slice(&vn.bufs[&bn][on..on + take]);
        done += take;
        off += take as u64;
        if done == buf.len() || take == 0 {
            break;
        }
    }
    Ok(done)
}

/// How many open files each disk vnode has (by minor and node kind): the
/// node's `dkclose` comes at the last one's close.
static VNODES: Mutex<Option<HashMap<(u32, bool), u32>>> = Mutex::new(None);

/// A disk node's open file.
#[derive(Debug)]
pub struct DiskDev {
    pub node: &'static Node,
    opened: std::sync::atomic::AtomicBool,
}

impl DiskDev {
    pub fn new(node: &'static Node) -> DiskDev {
        DiskDev { node, opened: std::sync::atomic::AtomicBool::new(false) }
    }

    fn block(&self) -> bool {
        matches!(self.node.kind, Kind::Disk { block: true })
    }

    /// The node's open succeeded (`dkopen`): one more open file of its
    /// vnode.
    pub fn opened(&self) {
        self.opened.store(true, std::sync::atomic::Ordering::Release);
        let mut g = VNODES.lock().unwrap_or_else(|e| e.into_inner());
        *g.get_or_insert_with(HashMap::new).entry((self.node.minor, self.block())).or_default() += 1;
    }
}

impl crate::vfs::FileHandle for DiskDev {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> crate::errno::SysResult {
        if !self.opened.load(std::sync::atomic::Ordering::Acquire) {
            return Err(Errno::ENXIO);
        }
        // devfsspec_read: the access time, then spec_read (0 at once for an
        // empty read).
        super::devfs::touch(self.node, super::devfs::UPDATE_ACCESS);
        if buf.is_empty() {
            return Ok(0);
        }
        if self.block() {
            bdev_read(self.node, offset, buf).map(|n| n as u64)
        } else {
            dkreadwrite(self.node, offset, Some(buf), None).map(|n| n as u64)
        }
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> crate::errno::SysResult {
        if !self.opened.load(std::sync::atomic::Ordering::Acquire) {
            return Err(Errno::ENXIO);
        }
        super::devfs::touch(self.node, super::devfs::UPDATE_CHANGE | super::devfs::UPDATE_MOD);
        if self.block() {
            // Reported at the open (the buffer cache's writes).
            return Err(e(EIO));
        }
        dkreadwrite(self.node, offset, None, Some(buf)).map(|n| n as u64)
    }

    fn metadata(&self) -> Result<crate::vfs::Metadata, Errno> {
        Ok(super::devfs::metadata(self.node))
    }

    fn darwin_devnode(&self) -> Option<&'static Node> {
        Some(self.node)
    }

    fn darwin_disk(&self) -> Option<&DiskDev> {
        Some(self)
    }

    /// The vnode's last close: `dkclose` (the block node's buffers, none
    /// dirty here, flushed and invalidated first).
    fn vn_close(&self) {
        if !self.opened.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        let key = (self.node.minor, self.block());
        let last = {
            let mut g = VNODES.lock().unwrap_or_else(|e| e.into_inner());
            let m = g.get_or_insert_with(HashMap::new);
            let c = m.entry(key).or_default();
            *c = c.saturating_sub(1);
            *c == 0
        };
        if last {
            if self.block() {
                if let Some(v) = BLOCK_VNODES.lock().unwrap_or_else(|e| e.into_inner()).as_mut().and_then(|c| c.get_mut(&self.node.minor)) {
                    v.bufs.clear();
                }
            }
            // dkclose returns 0; what of the stack it does not model was
            // reported at the open.
            let _ = super::dkopen::dkclose(self.node.minor, self.block());
        }
    }
}

/// `kIOStorageSynchronizeOptionReserved`, `kIOStorageUnmapOptionReserved`.
const SYNCHRONIZE_RESERVED: u32 = 0xffff_fffd;
const UNMAP_RESERVED: u32 = 0xffff_fffe;
/// `kIOStorageSynchronizeOptionBarrier`.
const SYNCHRONIZE_BARRIER: u32 = 0x2;
const ENOTSUP: i32 = 45;

/// What a storage request down the stack answers: an errno, or what is
/// not modelled.
enum Down {
    Errno(i32),
    Unmodelled(String),
}

/// `IOMedia`'s checks of a synchronize or unmap of medium `g` (it is open:
/// the node's minor holds it, and the media under it are held by their
/// clients): writable (`kIOReturnLockedWrite`, EACCES), formatted
/// (`kIOReturnUnformattedMedia`, ENXIO), and each extent within it
/// (`kIOReturnBadArgument`, EINVAL).
fn media_checks(g: Geometry, extents: &[(u64, u64)]) -> Result<(), Down> {
    if !storage::disk_writable() {
        return Err(Down::Errno(EACCES));
    }
    if g.size == 0 || g.block == 0 {
        return Err(Down::Errno(ENXIO));
    }
    if extents.iter().any(|&(start, count)| g.size < start || g.size - start < count) {
        return Err(Down::Errno(EINVAL));
    }
    Ok(())
}

/// A key of `IOStorageFeatures` the container scheme copied from its
/// provider at its start (0xfffffff006682bac..0xfffffff006682c74: Unmap
/// to its +0x108, Barrier to its +0x10c).
fn scheme_feature(key: &str) -> Result<bool, Down> {
    match property_up("disk0s1", "IOStorageFeatures") {
        Ok(p) => Ok(matches!(dict_get(&p, key), Some(super::iokit::Prop::Bool(true)))),
        Err(why) => Err(Down::Unmodelled(why)),
    }
}

/// `synchronize(byteStart, byteCount, options)` of medium `m` down its
/// stack: `IOMedia::synchronize`'s checks at each medium; the container
/// scheme's (0xfffffff006683d90) passes on only if a write set the dirty
/// bits it clears (3, or 1 for a barrier when its device has Barrier),
/// else succeeds; `IOBlockStorageDriver::synchronize` refuses a reserved
/// option and passes the blocks to NS_01's `doSynchronize`, which succeeds
/// (the image's bytes are written already).
fn synchronize(m: Media, start: u64, count: u64, options: u32) -> Result<(), Down> {
    let geo = |m: Media| geometry(m).map_err(Down::Unmodelled);
    media_checks(geo(m)?, &[(start, count)])?;
    if matches!(m, Media::Volume(_) | Media::Container) {
        if let Media::Volume(_) = m {
            // AppleAPFSContainer (IOPartitionScheme::synchronize) to the
            // container's medium, at the same offset.
            media_checks(geo(Media::Container)?, &[(start, count)])?;
        }
        let mask = if options & SYNCHRONIZE_BARRIER != 0 && scheme_feature("Barrier")? { 1 } else { 3 };
        let old = SCHEME_DIRTY.fetch_and(!mask, std::sync::atomic::Ordering::AcqRel);
        if old & mask == 0 {
            return Ok(());
        }
        // The scheme's provider: the partition's medium, the same offset.
        media_checks(geo(Media::Partition)?, &[(start, count)])?;
        let base = geo(Media::Partition)?.base;
        media_checks(geo(Media::Whole)?, &[(start + base, count)])?;
    } else if m == Media::Partition {
        let base = geo(Media::Partition)?.base;
        media_checks(geo(Media::Whole)?, &[(start + base, count)])?;
    }
    if options & SYNCHRONIZE_RESERVED != 0 {
        return Err(Down::Errno(EINVAL));
    }
    Ok(())
}

/// `unmap(extents, options)` of medium `m` down its stack: `IOMedia::unmap`'s
/// checks at each medium (and the base added); a volume's container
/// (0xfffffff00666b378) drops the extents with bit 63 of their start set;
/// the container scheme (0xfffffff006683af8) passes them on only when its
/// device has Unmap, else succeeds; `IOBlockStorageDriver::unmap` refuses a
/// reserved option, rounds each extent inward to whole blocks and drops the
/// empty ones, and gives the rest to NS_01's `doUnmap` (a Dataset
/// Management deallocate), what the controller then reads back for those
/// blocks not being measured.
fn unmap(m: Media, extents: &[(u64, u64)], options: u32) -> Result<(), Down> {
    let geo = |m: Media| geometry(m).map_err(Down::Unmodelled);
    media_checks(geo(m)?, extents)?;
    let mut ext: Vec<(u64, u64)> = extents.to_vec();
    if matches!(m, Media::Volume(_) | Media::Container) {
        if let Media::Volume(_) = m {
            ext.retain(|&(start, _)| start & (1 << 63) == 0);
            media_checks(geo(Media::Container)?, &ext)?;
        }
        if !scheme_feature("Unmap")? {
            return Ok(());
        }
        media_checks(geo(Media::Partition)?, &ext)?;
    }
    if matches!(m, Media::Volume(_) | Media::Container | Media::Partition) {
        let base = geo(Media::Partition)?.base;
        for e in &mut ext {
            e.0 += base;
        }
        media_checks(geo(Media::Whole)?, &ext)?;
    }
    if options & UNMAP_RESERVED != 0 {
        return Err(Down::Errno(EINVAL));
    }
    let bs = u64::from(storage::nvme().block_size);
    let blocks: Vec<(u64, u64)> = ext.iter().filter_map(|&(start, count)| {
        let (first, end) = (start.div_ceil(bs), (start + count) / bs);
        (end > first).then_some((first, end - first))
    }).collect();
    if blocks.is_empty() {
        return Ok(());
    }
    Err(Down::Unmodelled(format!("DKIOCUNMAP of {} block extents of disk0 (NS_01's doUnmap: what the controller reads back for deallocated blocks is not measured)", blocks.len())))
}

/// `DKIOCUNMAP`'s extents in a batch: `dk_extent_t` {offset, length}.
pub fn unmap_batch(n: &Node, extents: &[u8], options: u32) -> Answer {
    let Ok(m) = media_of(n) else { return Answer::Err(Errno::EBADF) };
    let ext: Vec<(u64, u64)> = extents.chunks_exact(16).map(|c| (u64::from_le_bytes(c[..8].try_into().unwrap()), u64::from_le_bytes(c[8..].try_into().unwrap()))).collect();
    down(unmap(m, &ext, options))
}

fn down(r: Result<(), Down>) -> Answer {
    match r {
        Ok(()) => Answer::Done,
        Err(Down::Errno(n)) => Answer::Err(e(n)),
        Err(Down::Unmodelled(why)) => Answer::Unmodelled(why),
    }
}

/// `DKIOC*` commands (`bsd/sys/disk.h`).
pub mod dkioc {
    pub const EJECT: u64 = 0x2000_6415;
    pub const SYNCHRONIZECACHE: u64 = 0x2000_6416;
    pub const SYNCHRONIZE: u64 = 0x8018_6416;
    pub const ISFORMATTED: u64 = 0x4004_6417;
    pub const GETBLOCKSIZE: u64 = 0x4004_6418;
    pub const SETBLOCKSIZE: u64 = 0x8004_6418;
    pub const GETBLOCKCOUNT: u64 = 0x4008_6419;
    pub const FORMAT: u64 = 0x8010_641a;
    pub const GETFORMATCAPACITIES: u64 = 0xc010_641a;
    pub const GETBSDUNIT: u64 = 0x4004_641b;
    pub const GETFIRMWAREPATH: u64 = 0x4080_641c;
    pub const ISWRITABLE: u64 = 0x4004_641d;
    pub const REQUESTIDLE: u64 = 0x2000_641e;
    pub const UNMAP: u64 = 0x8010_641f;
    pub const GETLOCATION: u64 = 0x4008_6421;
    pub const GETMAXBLOCKCOUNTREAD: u64 = 0x4008_6440;
    pub const GETMAXBLOCKCOUNTWRITE: u64 = 0x4008_6441;
    pub const GETMAXSEGMENTCOUNTREAD: u64 = 0x4008_6442;
    pub const GETMAXSEGMENTCOUNTWRITE: u64 = 0x4008_6443;
    pub const GETMAXSEGMENTBYTECOUNTREAD: u64 = 0x4008_6444;
    pub const GETMAXSEGMENTBYTECOUNTWRITE: u64 = 0x4008_6445;
    pub const GETMAXBYTECOUNTREAD: u64 = 0x4008_6446;
    pub const GETMAXBYTECOUNTWRITE: u64 = 0x4008_6447;
    pub const ISVIRTUAL: u64 = 0x4004_6448;
    pub const GETBASE: u64 = 0x4008_6449;
    pub const GETMINSEGMENTALIGNMENTBYTECOUNT: u64 = 0x4008_644a;
    pub const GETMAXSEGMENTADDRESSABLEBITCOUNT: u64 = 0x4008_644b;
    pub const GETFEATURES: u64 = 0x4004_644c;
    pub const GETPHYSICALBLOCKSIZE: u64 = 0x4004_644d;
    pub const GETCOMMANDPOOLSIZE: u64 = 0x4004_644e;
    pub const ISSOLIDSTATE: u64 = 0x4004_644f;
    pub const GETPROVISIONSTATUS: u64 = 0xc028_644f;
    pub const GETTHROTTLEMASK: u64 = 0x4008_6450;
    pub const GETERRORDESCRIPTION: u64 = 0x4020_6450;
    pub const LOCKPHYSICALEXTENTS: u64 = 0x2000_6451;
    pub const GETPHYSICALEXTENT: u64 = 0xc020_6452;
    pub const UNLOCKPHYSICALEXTENTS: u64 = 0x2000_6453;
    pub const SETSTATIC: u64 = 0x2000_6454;
    pub const SETTIER: u64 = 0x8010_6455;
    pub const GETENCRYPTIONTYPE: u64 = 0x4004_6456;
    pub const ISLOWPOWERMODE: u64 = 0x4004_6457;
    pub const GETIOMINSATURATIONBYTECOUNT: u64 = 0x4004_6458;
    pub const GETAPFSFLAVOUR: u64 = 0x4004_645b;
    pub const GETMAXSWAPWRITE: u64 = 0x4008_645e;
}

/// `D_DISK`, FIODTYPE's answer for a disk (`d_type` of `bdevsw`/`cdevsw`).
pub const D_DISK: i32 = 2;

/// A property as `getProperty(key, gIOServicePlane)` finds it from the
/// medium's registry entry: the entry's, else each provider's in turn.
/// `Err` names a key an entry on the way may have that is not modelled.
fn property_up(name: &str, key: &str) -> Result<Option<super::iokit::Prop>, String> {
    let t = super::iokit::tree();
    let start = t.iter().position(|n| matches!(super::iokit::service_prop(n, "BSD Name"), Some(super::iokit::Prop::Sym(s) | super::iokit::Prop::Str(s)) if s == name));
    let mut at = start.map(|i| i as u32);
    while let Some(i) = at {
        let n = &t[i as usize];
        if let Some(p) = super::iokit::service_prop(n, key) {
            return Ok(Some(p.clone()));
        }
        if super::iokit::property_unknown(t, i, key) {
            return Err(format!("{key} of {} ({}), which its drivers may set", n.name, n.class));
        }
        at = n.nub.map(|(_, p)| p).or(n.parent);
    }
    Ok(None)
}

fn num_of(p: &Option<super::iokit::Prop>) -> u64 {
    match p {
        Some(super::iokit::Prop::Num(v, _)) => *v,
        _ => 0,
    }
}

fn dict_get<'a>(p: &'a Option<super::iokit::Prop>, key: &str) -> Option<&'a super::iokit::Prop> {
    match p {
        Some(super::iokit::Prop::Dict(d)) => d.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn is_str(p: Option<&super::iokit::Prop>, s: &str) -> bool {
    matches!(p, Some(super::iokit::Prop::Str(v) | super::iokit::Prop::Sym(v)) if v == s)
}

/// What a disk's ioctl answers (`dkioctl`, `dkioctl_cdev`, `dkioctl_bdev`,
/// and the APFS BSD clients' `ioctl`), or why it cannot be answered here.
pub enum Answer {
    Done,
    Err(Errno),
    Unmodelled(String),
}

/// `ioctl(com, data)` on disk node `n`.
pub fn ioctl(n: &'static Node, com: u64, data: &mut [u8]) -> Answer {
    use dkioc::*;
    let block = matches!(n.kind, Kind::Disk { block: true });
    let Ok(m) = media_of(n) else { return Answer::Err(Errno::EBADF) };
    let g = match geometry(m) {
        Ok(g) => g,
        Err(why) => return Answer::Unmodelled(format!("the geometry of /dev/{}: {why}", n.name)),
    };
    let bsd = n.name.trim_start_matches('r');
    let put32 = |data: &mut [u8], v: u32| data[..4].copy_from_slice(&v.to_le_bytes());
    let put64 = |data: &mut [u8], v: u64| data[..8].copy_from_slice(&v.to_le_bytes());
    let prop = |key: &str| property_up(bsd, key);
    macro_rules! recursive_u64 {
        ($key:expr) => {
            match prop($key) {
                Ok(p) => {
                    put64(data, num_of(&p));
                    Answer::Done
                }
                Err(why) => Answer::Unmodelled(why),
            }
        };
    }
    match com {
        // The block size: the preferred one (a block node's minor block
        // size is the same until DKIOCSETBLOCKSIZE, which no process can
        // issue: EPERM in vn_ioctl).
        GETBLOCKSIZE => {
            put32(data, g.block as u32);
            Answer::Done
        }
        GETBLOCKCOUNT => {
            put64(data, if g.block == 0 { 0 } else { g.size / g.block });
            Answer::Done
        }
        ISFORMATTED => {
            put32(data, u32::from(g.size != 0 && g.block != 0));
            Answer::Done
        }
        ISWRITABLE => {
            put32(data, u32::from(storage::disk_writable()));
            Answer::Done
        }
        GETBASE => {
            // getBase: the partition's offset on disk0; the container's
            // medium and the volumes' are 0.
            put64(data, if m == Media::Partition { g.base } else { 0 });
            Answer::Done
        }
        GETBSDUNIT => {
            let unit = if matches!(m, Media::Whole | Media::Partition) { storage::units().main } else { storage::units().container };
            put32(data, unit);
            Answer::Done
        }
        GETMAXBLOCKCOUNTREAD => recursive_u64!("IOMaximumBlockCountRead"),
        GETMAXBLOCKCOUNTWRITE => recursive_u64!("IOMaximumBlockCountWrite"),
        GETMAXSEGMENTCOUNTREAD => recursive_u64!("IOMaximumSegmentCountRead"),
        GETMAXSEGMENTCOUNTWRITE => recursive_u64!("IOMaximumSegmentCountWrite"),
        GETMAXSEGMENTBYTECOUNTREAD => recursive_u64!("IOMaximumSegmentByteCountRead"),
        GETMAXSEGMENTBYTECOUNTWRITE => recursive_u64!("IOMaximumSegmentByteCountWrite"),
        GETMAXBYTECOUNTREAD => recursive_u64!("IOMaximumByteCountRead"),
        GETMAXBYTECOUNTWRITE => recursive_u64!("IOMaximumByteCountWrite"),
        GETMINSEGMENTALIGNMENTBYTECOUNT => recursive_u64!("IOMinimumSegmentAlignmentByteCount"),
        GETMAXSEGMENTADDRESSABLEBITCOUNT => recursive_u64!("IOMaximumSegmentAddressableBitCount"),
        GETMAXSWAPWRITE => recursive_u64!("IOMaximumSwapWrite"),
        GETCOMMANDPOOLSIZE | GETIOMINSATURATIONBYTECOUNT => match prop(if com == GETCOMMANDPOOLSIZE { "IOCommandPoolSize" } else { "IOMinimumSaturationByteCount" }) {
            Ok(p) => {
                put32(data, num_of(&p) as u32);
                Answer::Done
            }
            Err(why) => Answer::Unmodelled(why),
        },
        GETPHYSICALBLOCKSIZE => match prop("Physical Block Size") {
            Ok(p) => {
                put32(data, if p.is_some() { num_of(&p) as u32 } else { g.block as u32 });
                Answer::Done
            }
            Err(why) => Answer::Unmodelled(why),
        },
        // IOStorageFeatures: Force Unit Access 0x1, Barrier 0x2, Priority
        // 0x4, Unmap 0x10.
        GETFEATURES => match prop("IOStorageFeatures") {
            Ok(p) => {
                let on = |k: &str| matches!(dict_get(&p, k), Some(super::iokit::Prop::Bool(true)));
                let f = u32::from(on("Force Unit Access")) | u32::from(on("Barrier")) << 1 | u32::from(on("Priority")) << 2 | u32::from(on("Unmap")) << 4;
                put32(data, f);
                Answer::Done
            }
            Err(why) => Answer::Unmodelled(why),
        },
        ISSOLIDSTATE => match prop("Device Characteristics") {
            Ok(p) => {
                put32(data, u32::from(is_str(dict_get(&p, "Medium Type"), "Solid State")));
                Answer::Done
            }
            Err(why) => Answer::Unmodelled(why),
        },
        GETLOCATION => match prop("Protocol Characteristics") {
            Ok(p) => {
                put64(data, u64::from(is_str(dict_get(&p, "Physical Interconnect Location"), "External")));
                Answer::Done
            }
            Err(why) => Answer::Unmodelled(why),
        },
        // The minor's isVirtual, set when its nodes were made: a
        // "Virtual Interface" interconnect.
        ISVIRTUAL => match prop("Protocol Characteristics") {
            Ok(p) => {
                put32(data, u32::from(is_str(dict_get(&p, "Physical Interconnect"), "Virtual Interface")));
                Answer::Done
            }
            Err(why) => Answer::Unmodelled(why),
        },
        GETENCRYPTIONTYPE | ISLOWPOWERMODE => match prop("Controller Characteristics") {
            Ok(p) => {
                let v = if com == GETENCRYPTIONTYPE {
                    match dict_get(&p, "Encryption Type") {
                        Some(s) if is_str(Some(s), "AES-CBC") => 1,
                        Some(s) if is_str(Some(s), "AES-XEX") => 2,
                        Some(s) if is_str(Some(s), "AES-XTS") => 3,
                        _ => 0,
                    }
                } else {
                    u32::from(matches!(dict_get(&p, "Low Power Mode"), Some(super::iokit::Prop::Bool(true))))
                };
                put32(data, v);
                Answer::Done
            }
            Err(why) => Answer::Unmodelled(why),
        },
        // _IOMediaBSDClientGetThrottleMask: a bit for the BSD unit of each
        // medium under the first IOBlockStorageDevice above (NS_01's: disk0
        // and the container's disk1), no "throttle-unit".
        GETTHROTTLEMASK => {
            let u = storage::units();
            put64(data, (1u64 << (u.main % 64)) | (1u64 << (u.container % 64)));
            Answer::Done
        }
        // DKIOCGETAPFSFLAVOUR: the APFS BSD clients' (single device: 1);
        // IOMediaBSDClient has none.
        GETAPFSFLAVOUR if matches!(m, Media::Container | Media::Volume(_)) => {
            put32(data, 1);
            Answer::Done
        }
        // Only disk0 is an IOBlockStorageDriver's medium.
        EJECT | FORMAT | GETFORMATCAPACITIES | REQUESTIDLE if m != Media::Whole => Answer::Err(Errno::ENOTTY),
        // The device tree path: only disk0 and its partition are in the
        // IODeviceTree plane.
        GETFIRMWAREPATH if !matches!(m, Media::Whole | Media::Partition) => Answer::Err(e(EINVAL)),
        SETSTATIC if block => Answer::Err(Errno::ENOTTY),
        SETSTATIC => Answer::Unmodelled("_DKIOCSETSTATIC: the static-content option a character node's later I/O passes down".into()),
        SETBLOCKSIZE | LOCKPHYSICALEXTENTS | GETPHYSICALEXTENT | UNLOCKPHYSICALEXTENTS | SETTIER if !block => Answer::Err(Errno::ENOTTY),
        // dkioctl: synchronize(0, 0, 0), or the request's after its
        // reserved bytes (20 to 23) are checked.
        SYNCHRONIZECACHE => down(synchronize(m, 0, 0, 0)),
        SYNCHRONIZE => {
            if data[20..24].iter().any(|&b| b != 0) {
                return Answer::Err(e(EINVAL));
            }
            let (off, len, opt) = (u64::from_le_bytes(data[..8].try_into().unwrap()), u64::from_le_bytes(data[8..16].try_into().unwrap()), u32::from_le_bytes(data[16..20].try_into().unwrap()));
            down(synchronize(m, off, len, opt))
        }
        // The count cut to a page of extents; IOMedia::getProvisionStatus's
        // checks (options, as the 32-bit IOStorageGetProvisionStatusOptions,
        // the range, a count of 0), then every provider's answer is
        // kIOReturnUnsupported: NS_01's doGetProvisionStatus is
        // IOBlockStorageDevice's (0xfffffff00596f08c), the container scheme's
        // IOStorage's (0xfffffff00597dc64).
        GETPROVISIONSTATUS => {
            let (off, len) = (u64::from_le_bytes(data[..8].try_into().unwrap()), u64::from_le_bytes(data[8..16].try_into().unwrap()));
            let options = u32::from_le_bytes(data[16..20].try_into().unwrap());
            let count = u32::from_le_bytes(data[28..32].try_into().unwrap()).min((PAGE_SIZE / 24) as u32);
            data[28..32].copy_from_slice(&count.to_le_bytes());
            if options != 0 || g.size < off || g.size - off < len || count == 0 {
                return Answer::Err(e(EINVAL));
            }
            Answer::Err(e(ENOTSUP))
        }
        // Its extents are copied in by the caller ([`unmap_batch`]).
        UNMAP => Answer::Unmodelled("DKIOCUNMAP without its extents".into()),
        GETERRORDESCRIPTION | EJECT | FORMAT | GETFORMATCAPACITIES | REQUESTIDLE | GETFIRMWAREPATH | SETBLOCKSIZE | LOCKPHYSICALEXTENTS | GETPHYSICALEXTENT | UNLOCKPHYSICALEXTENTS | SETTIER => Answer::Unmodelled(format!("ioctl {com:#x} on /dev/{} (dkioctl: what the storage stack under it does)", n.name)),
        _ => Answer::Err(Errno::ENOTTY),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A setattr's attributes cross the channel whole, each one there or
    /// not; a request that is not one is refused; a call on the container
    /// with no disk0 image is its error, with its clock carried and let go.
    #[test]
    fn calls_on_the_container_cross_the_channel() {
        let a = crate::vfs::VnodeAttrs { uid: Some(501), gid: None, mode: Some(0o640), flags: Some(2), atime: None, mtime: Some((1_700_000_000, 5)) };
        let mut q = Vec::new();
        put_attrs(&mut q, &a);
        let b = get_attrs(&q).unwrap();
        assert_eq!((b.uid, b.gid, b.mode, b.flags, b.atime, b.mtime), (a.uid, a.gid, a.mode, a.flags, a.atime, a.mtime));
        assert!(get_attrs(&q[..q.len() - 1]).is_none());
        let mut out = [0u8; 64];
        assert_eq!(serve(&[99], &mut out), -22);
        assert_eq!(serve(&[Call::HoldsRw as u8, 0, 0, 0, 0], &mut out), -22);
        let mut req = vec![Call::VolumeIds as u8];
        req.extend_from_slice(&4u32.to_le_bytes());
        req.extend_from_slice(&7u64.to_le_bytes());
        let n = serve(&req, &mut out) as usize;
        if !installed() {
            assert_eq!(out[0], 1, "an error without an image");
            assert!(String::from_utf8_lossy(&out[1..n]).contains("no disk0 image"));
        }
        assert_eq!(CARRIED_NOW.with(std::cell::Cell::get), None);
    }

    /// A disk of `n` bytes in memory, which fails I/O at or past `bad`.
    struct Mem(Mutex<Vec<u8>>, u64);

    impl super::super::apfsread::Medium for Mem {
        fn size(&self) -> u64 {
            self.0.lock().unwrap().len() as u64
        }
        fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), String> {
            if off >= self.1 {
                return Err("medium error".into());
            }
            buf.copy_from_slice(&self.0.lock().unwrap()[off as usize..off as usize + buf.len()]);
            Ok(())
        }
    }

    impl Sink for Mem {
        fn write_at(&self, off: u64, buf: &[u8]) -> Result<(), String> {
            if off >= self.1 {
                return Err("medium error".into());
            }
            self.0.lock().unwrap()[off as usize..off as usize + buf.len()].copy_from_slice(buf);
            Ok(())
        }
    }

    fn counts() -> Vec<(String, u64)> {
        let mut out = Vec::new();
        for (who, p) in [("driver", super::super::storagestack::stats::driver(1)), ("scheme", super::super::storagestack::stats::scheme())] {
            let super::super::iokit::Prop::Dict(d) = p else { panic!("statistics not a dictionary") };
            for (k, v) in d {
                if let super::super::iokit::Prop::Num(n, _) = v {
                    out.push((format!("{who} {k}"), n));
                }
            }
        }
        out
    }

    fn delta(before: &[(String, u64)], key: &str) -> u64 {
        let now = counts();
        let at = |c: &[(String, u64)]| c.iter().find(|(k, _)| k == key).map(|(_, v)| *v).unwrap();
        at(&now) - at(before)
    }

    /// Each request counts once in the driver's statistics with the bytes
    /// moved; the container's also in the scheme's (before it goes down,
    /// so a failed one too); a failed one is a driver error with no bytes.
    #[test]
    fn requests_counted() {
        let d = Disk { sink: Arc::new(Mem(Mutex::new(vec![0u8; 1 << 20]), 1 << 19)), missing: Vec::new() };
        let before = counts();
        let mut b = vec![0u8; 8192];
        request(&d, Media::Whole, 4096, Io::Read(&mut b)).unwrap();
        request(&d, Media::Container, 0, Io::Write(&b[..4096])).unwrap();
        assert!(request(&d, Media::Container, 1 << 19, Io::Read(&mut b)).is_err());
        assert_eq!(delta(&before, "driver Operations (Read)"), 2);
        assert_eq!(delta(&before, "driver Bytes (Read)"), 8192);
        assert_eq!(delta(&before, "driver Errors (Read)"), 1);
        assert_eq!(delta(&before, "driver Operations (Write)"), 1);
        assert_eq!(delta(&before, "driver Bytes (Write)"), 4096);
        assert_eq!(delta(&before, "scheme Operations (Read)"), 1);
        assert_eq!(delta(&before, "scheme Bytes (Read)"), 8192);
        assert_eq!(delta(&before, "scheme Operations (Write)"), 1);
        assert_eq!(delta(&before, "scheme Bytes (Write)"), 4096);
        assert_eq!(SCHEME_DIRTY.load(std::sync::atomic::Ordering::Acquire) & 3, 3);
    }

    #[test]
    fn ioctl_numbers() {
        // _IOR('d', 24, uint32_t), _IOR('d', 25, uint64_t),
        // _IOW('d', 22, dk_synchronize_t) (24 bytes).
        let ior = |n: u64, size: u64| 0x4000_0000 | (size << 16) | (u64::from(b'd') << 8) | n;
        let iow = |n: u64, size: u64| 0x8000_0000 | (size << 16) | (u64::from(b'd') << 8) | n;
        assert_eq!(dkioc::GETBLOCKSIZE, ior(24, 4));
        assert_eq!(dkioc::GETBLOCKCOUNT, ior(25, 8));
        assert_eq!(dkioc::SYNCHRONIZE, iow(22, 24));
        assert_eq!(dkioc::GETFEATURES, ior(76, 4));
        assert_eq!(dkioc::ISSOLIDSTATE, ior(79, 4));
        assert_eq!(dkioc::GETAPFSFLAVOUR, ior(91, 4));
    }
}
