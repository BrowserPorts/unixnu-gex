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
//! more than 1 GiB of memory): a buffer the medium gives short whose part
//! the read wants starts past is EINVAL. Its writes (the buffer cache's
//! read-modify-write, delayed and asynchronous writes) are not modelled.

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
    DISK.set(Disk { sink, missing }).map_err(|_| "a disk0 image is installed already".to_string())
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

/// The partition's bytes as a medium of their own.
struct PartMedium(Arc<dyn Sink>, u64, u64);

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
    match (read, write) {
        (Some(b), _) => d.sink.read_at(g.base + off, &mut b[..n_bytes]).map_err(|_| e(EIO))?,
        (_, Some(b)) => d.sink.write_at(g.base + off, &b[..n_bytes]).map_err(|_| e(EIO))?,
        _ => {}
    }
    Ok(n_bytes)
}

/// `PAGE_SIZE` on the device (16 KiB pages: the boot's memory size is
/// over 1 GiB).
const PAGE_SIZE: u64 = 16384;

/// `spec_read` of a block node: buffers of `PAGE_SIZE / bsize` blocks.
fn bdev_read(n: &Node, mut off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
    let d = DISK.get().ok_or(Errno::ENXIO)?;
    let g = geometry(media_of(n)?).map_err(|_| Errno::EIO)?;
    // v_specsize: the minor's block size, its preferred block size until
    // DKIOCSETBLOCKSIZE (which a process cannot issue).
    let spec = g.block;
    if spec == 0 || spec > PAGE_SIZE {
        return Err(e(EINVAL));
    }
    let bscale = PAGE_SIZE / spec;
    let bsize = bscale * spec;
    let mut done = 0usize;
    while done < buf.len() {
        let bn = (off / spec) & !(bscale - 1);
        let on = (off % bsize) as usize;
        // dkreadwrite of the buffer: nothing at or past the end, cut at it.
        let start = bn * spec;
        let have = if start >= g.size { 0 } else { bsize.min(g.size - start) as usize };
        if have > 0 && g.volume {
            return Err(e(EACCES));
        }
        if on > have {
            return Err(e(EINVAL));
        }
        let take = (have - on).min(buf.len() - done);
        if take > 0 {
            d.sink.read_at(g.base + start + on as u64, &mut buf[done..done + take]).map_err(|_| e(EIO))?;
        }
        done += take;
        off += take as u64;
        if have == 0 {
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
            // dkclose returns 0; what of the stack it does not model was
            // reported at the open.
            let _ = super::dkopen::dkclose(self.node.minor, self.block());
        }
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
        SYNCHRONIZE | SYNCHRONIZECACHE | UNMAP | GETPROVISIONSTATUS | GETERRORDESCRIPTION | EJECT | FORMAT | GETFORMATCAPACITIES | REQUESTIDLE | GETFIRMWAREPATH | SETBLOCKSIZE | LOCKPHYSICALEXTENTS | GETPHYSICALEXTENT | UNLOCKPHYSICALEXTENTS | SETTIER => Answer::Unmodelled(format!("ioctl {com:#x} on /dev/{} (dkioctl: what the storage stack under it does)", n.name)),
        _ => Answer::Err(Errno::ENOTTY),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
