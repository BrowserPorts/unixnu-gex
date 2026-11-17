//! APFS's transactions on a mounted container, as APFS 2236.140.6 runs
//! them (the erase ramdisk's `newfs_apfs` and `apfs_invert` carry the
//! library the kernelcache's kext has; addresses are `apfs_invert`'s, I:,
//! unless named): the object cache's copy-on-write, the space manager's
//! allocation and free queues, the object maps, and the checkpoint each
//! transaction ends with.
//!
//! Objects:
//!
//! - a physical object (an object map, its tree's nodes, a volume's
//!   extent-reference and snapshot trees' nodes) takes a block when it is
//!   made and, at its first change in a transaction, a new block, the old
//!   one going to the main free queue at once (`obj_modify`, I:0x10003ae80);
//! - a virtual object (a volume superblock, a file-system tree's nodes)
//!   keeps its identifier and takes a block only at the flush
//!   (`obj_write_prepare`, I:0x100035c88), in the order the transaction
//!   first changed it, objects of encrypted volumes first and volume
//!   superblocks last; its object map gets the new mapping and loses the
//!   old one, whose block is freed;
//! - an ephemeral object (the space manager, the reaper, the free queues'
//!   nodes) is written to the checkpoint data ring.
//!
//! Space (`spaceman_alloc`, I:0x100044290): metadata from a metazone
//! class's cursor (the lower half for encrypted volumes' objects, the upper
//! half for the rest; object maps read the upper cursor but do not move
//! it), first fit around the whole device; a chunk's first change in a
//! transaction moves its chunk-info block and bitmap to the internal pool,
//! by the pool's roving cursor (I:0x1000405fc), the old blocks going to the
//! pool's free queue; the pool's bitmap moves to its ring's next block at
//! its first change in a transaction. Freed blocks wait in the free
//! queues, merged with their neighbours of the same transaction
//! (I:0x1000484d8), until a later transaction releases them
//! (`spaceman_free_completed`, I:0x100040f68): at its start, those more
//! than the age limit older, and whatever keeps the queues under their
//! limits (I:0x100041860).
//!
//! `nx_counters[0]` (`NX_CNTR_OBJ_CKSUM_SET`) counts the checksums set at
//! three sites: objects written through the object cache (A), ephemeral
//! objects and the superblock written to block 0 (B, the value stored
//! including its own count), and raw buffers, the superblock copy and
//! checkpoint maps among them (C, the copy stored before its own count). A
//! mount takes the count from the newest checkpoint's copy.
//!
//! The container's reaper (`nx_reaper`, I:0x1000176a4) takes the trees
//! queued for it at the next mount, a step at a time inside the open
//! transaction, which `tx_leave`'s rules close when they bind.
//!
//! What is not implemented is refused: metadata of more than one block,
//! data allocations the allocation zones or the space checks serve, a
//! free queue drained for an allocation or for its size, snapshots, chunk-info address blocks, Fusion.

use super::btree::{self, Store, Tree};
use super::fxc::{self, Fxc};
use super::container::{Formatted, Layout, NX_CLEANLY_UNMOUNTED};
use super::node::{flags as node_flags, tree_flags, Node, Shape};
use super::{put_header, set_checksum, Put, Sink};
use crate::darwin::apfsread::{omap_val, otype};
use std::collections::{BTreeMap, HashMap};

/// `nx_newest_mounted_version` APFS 2236.140.6 writes
/// (2236 * 10^12 + 140 * 10^9 + 6 * 10^6).
pub const APFS_VERSION: u64 = 2_236_140_006_000_000;
/// `apfs_formatted_by`'s id: "newfs_apfs (%s)" of its version.
pub const FORMATTED_BY: &str = "newfs_apfs (2236.140.6)";

const OID_SPACEMAN: u64 = 0x400;
const OID_REAPER: u64 = 0x401;
const IP_BM_INDEX_INVALID: u16 = 0xffff;
const SPACEMAN_FREE_QUEUE: u32 = 0x09;
const BLOCKREFTREE: u32 = 0x0f;
const SNAPMETATREE: u32 = 0x10;
const FSTREE: u32 = 0x0e;
/// `CHECKPOINT_MAP_LAST`.
const CHECKPOINT_MAP_LAST: u32 = 1;
/// `APFS_FS_UNENCRYPTED`.
const APFS_FS_UNENCRYPTED: u64 = 1;

/// Where the checksums are counted (see the module's notes).
#[derive(Clone, Copy)]
enum Site {
    Cached,
    Ephemeral,
    Raw,
}

/// Whose transactions these are: `newfs_apfs`'s own (a mount, one
/// transaction, an unmount per run), or the kernel's (the container
/// mounted once; block 0 written at the read-write mount and at the
/// unmount only; volume creation fills the meta crypto state).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Userspace,
    Kernel,
}

/// The free queues (`sm_fq`): the internal pool's and the main device's.
const FQ_IP: usize = 0;
const FQ_MAIN: usize = 1;

/// A free queue's state (`spaceman_free_queue_t`).
#[derive(Default)]
struct FreeQueue {
    tree: Option<Tree>,
    count: u64,
    oldest_xid: u64,
    limit: u16,
}

/// A chunk's state (`chunk_info_t`) and its bitmap once read.
struct Chunk {
    xid: u64,
    free: u64,
    bitmap_addr: u64,
    bitmap: Option<Vec<u8>>,
    dirty: bool,
}

/// A metazone class (`sm + 0x3f0 + 0x20 * class`): its blocks, cursor and
/// state.
#[derive(Clone, Copy, Default)]
struct Class {
    start: u64,
    end: u64,
    cursor: u64,
    state: i16,
    enabled: bool,
}

/// An allocation zone (`sm + 0x4c0 + 0x20 * (count - 1)`) and its
/// persisted slot (`spaceman_allocation_zone_info_phys_t`): the chunk it
/// allocates from, and the ring of the chunks it left, oldest at `index`.
#[derive(Clone, Copy, Default)]
struct Zone {
    start: u64,
    end: u64,
    enabled: bool,
    prev: [(u64, u64); 7],
    index: u16,
}

/// A chunk word's flags (`sm + 0x5d0`, I:0x1000497ac): a metazone chunk,
/// an allocation zone's current chunk.
const WORD_METAZONE: u32 = 0x400_0000;
const WORD_ZONE: u32 = 0x800_0000;

/// An object in the cache: its bytes (header included) and what it is.
struct Obj {
    b: Vec<u8>,
    /// `o_type`'s storage bits and subtype (a B-tree node's type is set
    /// from its root flag when it is written).
    storage: u32,
    subtype: u32,
    /// The metazone class its blocks come from.
    class: usize,
}

/// Who maps a virtual object: the container (volume superblocks) or a
/// volume (by slot).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Owner {
    Container,
    Volume(usize),
}

/// A virtual object's state in this mount: its bytes, and its mapping as
/// of the last flush.
struct VObj {
    b: Vec<u8>,
    mapped: Option<(u64, u64)>,
}

/// An object map: its `omap_phys_t`'s block and its tree.
#[derive(Clone, Copy)]
struct Omap {
    phys: u64,
    tree: Tree,
}

/// A volume as the container holds it.
pub struct Vol {
    pub oid: u64,
    omap: Omap,
    pub encrypted: bool,
    pub fs_tree: Tree,
    pub extentref: Tree,
    pub snapmeta: Tree,
}

/// A mounted container.
pub struct Nx<'a> {
    sink: &'a dyn Sink,
    pub l: Layout,
    pub uuid: [u8; 16],
    pub mode: Mode,
    /// The transaction in progress (one past the last checkpoint's when
    /// none is), and whether it has started.
    pub xid: u64,
    in_tx: bool,
    pub next_oid: u64,
    counter: u64,
    newest_mounted: u64,
    desc_index: u64,
    desc_len: u64,
    data_index: u64,
    data_len: u64,
    /// A checkpoint was written in this mount.
    wrote_checkpoint: bool,
    chunks: Vec<Chunk>,
    cib_addr: Vec<u64>,
    cib_xid: Vec<u64>,
    cib_dirty: Vec<bool>,
    ip_used: Vec<bool>,
    ip_cursor: u64,
    ipbm_index: u16,
    ipbm_xid: u64,
    ipbm_next: Vec<u16>,
    ipbm_head: u16,
    ipbm_tail: u16,
    fq: [FreeQueue; 2],
    sm_free: u64,
    /// `sm_fs_reserve_block_count`, `sm_fs_reserve_alloc_count`.
    reserve: (u64, u64),
    /// The allocation zones for data allocations of 1 to 4 blocks
    /// (`sm + 0x4c0`, their persisted slots `sm_datazone`).
    zones: [Zone; 4],
    classes: [Class; 3],
    /// The free queues' age limit (`sm + 0x5f8`: 8, or 2 on a device with
    /// `DK_FEATURE_BARRIER`) and the main queue's count limit (`sm +
    /// 0x5e8`).
    pub age_limit: u64,
    main_count_limit: u64,
    omap: Omap,
    phys: HashMap<u64, Obj>,
    phys_dirty: Vec<u64>,
    eph: HashMap<u64, Obj>,
    eph_order: Vec<u64>,
    virt: HashMap<(Owner, u64), VObj>,
    virt_dirty: Vec<(Owner, u64)>,
    pub fs_oid: Vec<u64>,
    pub vols: BTreeMap<usize, Vol>,
    rw_mounted: bool,
    sb_copy: Vec<u8>,
    /// The free-extent cache (built at the read-write mount) and the
    /// roving data pointer (`sm + 0x3e0`, zero at each mount).
    fxc: Option<Fxc>,
    rove: u64,
    reaper: Reaper,
    /// Blocks each volume's metadata gained or lost since its superblock
    /// was last written (`fs_alloc_count`'s upkeep: a node made or deleted
    /// counts, a node's copy-on-write does not), and the virtual objects a
    /// volume's creation counted itself.
    alloc_delta: BTreeMap<usize, i64>,
    precounted: std::collections::HashSet<(Owner, u64)>,
    /// The reap lists (`nx_reap_list_phys_t`), ephemeral, by identifier.
    reap_lists: BTreeMap<u64, Vec<u8>>,
    /// The open transaction's operation count (`tx + 0x20`: one per
    /// `tx_enter` that opened or joined it).
    tx_ops: u64,
    /// Whether the device is solid state (DKIOCISSOLIDSTATE, a failed
    /// query counting as yes): the object cache's limit of changed objects.
    solid_state: bool,
    /// When kept, every data allocation: the blocks asked for, where they
    /// went, how many, and the roving pointer after it.
    pub alloc_log: Option<Vec<(u64, u64, u64, u64)>>,
}

/// The container's reaper (`nx_reaper_phys_t`): its lists, and the entry
/// it is working on (`nr_type` to `nr_rlflags`, left as the last entry's
/// once it is done, its identifier cleared).
#[derive(Clone, Copy, Debug)]
struct Reaper {
    next_reap_id: u64,
    completed_id: u64,
    head: u64,
    tail: u64,
    flags: u32,
    rlcount: u32,
    ty: u32,
    size: u32,
    fs_oid: u64,
    oid: u64,
    xid: u64,
    nrle_flags: u32,
}

const OBJECT_TYPE_NX_REAP_LIST: u32 = 0x12;
const NRL_NONE: u32 = 0xffff_ffff;
/// `nr_flags`' `NR_CONTINUE`; `nrle_flags`' `NRLE_VALID`,
/// `NRLE_REAP_ID_RECORD`, `NRLE_CALL`.
const NR_CONTINUE: u32 = 0x2;
const NRLE_VALID: u32 = 0x1;
const NRLE_REAP_ID_RECORD: u32 = 0x2;
const NRLE_CALL: u32 = 0x4;

fn u32a(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn u64a(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// The object map trees' shape: physical, fixed 16-byte keys and values.
fn omap_shape(bs: u64) -> Shape {
    Shape { bt_flags: tree_flags::SEQUENTIAL_INSERT | tree_flags::PHYSICAL, node_size: bs as usize, key_size: 16, val_size: 16, hash_size: 0 }
}
/// The free queues': ephemeral, ghosts allowed, 16-byte keys, 8-byte
/// values.
fn fq_shape(bs: u64) -> Shape {
    Shape { bt_flags: tree_flags::SEQUENTIAL_INSERT | tree_flags::ALLOW_GHOSTS | tree_flags::EPHEMERAL, node_size: bs as usize, key_size: 16, val_size: 8, hash_size: 0 }
}
/// A volume's file-system, extent-reference and snapshot trees'.
fn jtree_shape(bs: u64, physical: bool) -> Shape {
    let f = tree_flags::SEQUENTIAL_INSERT | tree_flags::KV_NONALIGNED | if physical { tree_flags::PHYSICAL } else { 0 };
    Shape { bt_flags: f, node_size: bs as usize, key_size: 0, val_size: 0, hash_size: 0 }
}

impl<'a> Nx<'a> {
    /// The container `newfs_apfs -C` just made (its state is [`Formatted`]'s,
    /// the counter its checkpoint copy's).
    pub fn formatted(sink: &'a dyn Sink, f: &Formatted, uuid: [u8; 16], mode: Mode) -> Result<Nx<'a>, String> {
        let l = f.layout;
        let bs = l.bs;
        let mut chunks = Vec::with_capacity(l.chunks as usize);
        let mut cib_addr = Vec::new();
        for i in 0..l.cibs {
            let addr = l.ip_base + i;
            let mut b = vec![0u8; bs as usize];
            sink.read_at(addr * bs, &mut b)?;
            let n = u32::from_le_bytes(b[0x24..0x28].try_into().unwrap()) as usize;
            for j in 0..n {
                let o = 0x28 + 32 * j;
                chunks.push(Chunk { xid: u64a(&b, o), free: u64::from(u32::from_le_bytes(b[o + 20..o + 24].try_into().unwrap())), bitmap_addr: u64a(&b, o + 24), bitmap: None, dirty: false });
            }
            cib_addr.push(addr);
        }
        let mut ip_used = vec![false; l.ip_blocks as usize];
        let mut ipbm = vec![0u8; bs as usize];
        sink.read_at(l.ip_bm_base * bs, &mut ipbm)?;
        for (i, u) in ip_used.iter_mut().enumerate() {
            *u = ipbm[i / 8] & (1 << (i % 8)) != 0;
        }
        if l.ip_bm_size != 1 {
            return Err("not implemented: an internal pool bitmap of more than one block".into());
        }
        if l.cabs != 0 {
            return Err("not implemented: chunk-info address blocks".into());
        }
        let ipbm_next: Vec<u16> = (0..l.ip_bm_count).map(|i| if i == 0 || i + 1 == l.ip_bm_count { IP_BM_INDEX_INVALID } else { (i + 1) as u16 }).collect();
        let sm_free = chunks.iter().map(|c| c.free).sum();
        let mut sb_copy = vec![0u8; bs as usize];
        sink.read_at((l.desc_base + 1) * bs, &mut sb_copy)?;
        let omap_tree = Tree { root: f.omap_tree, shape: omap_shape(bs), cmp: btree::cmp_omap };
        Ok(Nx {
            sink,
            l,
            uuid,
            mode,
            xid: 2,
            in_tx: false,
            next_oid: 0x402,
            counter: super::container::format_copy_count(&l)?,
            newest_mounted: 0,
            desc_index: 0,
            desc_len: 2,
            data_index: 0,
            data_len: l.sm_bytes / bs + 1,
            wrote_checkpoint: false,
            chunks,
            cib_xid: vec![1; l.cibs as usize],
            cib_dirty: vec![false; l.cibs as usize],
            cib_addr,
            ip_used,
            ip_cursor: 0,
            ipbm_index: 0,
            ipbm_xid: 1,
            ipbm_next,
            ipbm_head: 1,
            ipbm_tail: (l.ip_bm_count - 1) as u16,
            fq: [FreeQueue { limit: l.fq_ip_limit as u16, ..Default::default() }, FreeQueue { limit: l.fq_main_limit as u16, ..Default::default() }],
            sm_free,
            reserve: (0, 0),
            zones: [Zone::default(); 4],
            classes: [Class::default(); 3],
            age_limit: 8,
            main_count_limit: l.blocks >> 5,
            omap: Omap { phys: f.omap, tree: omap_tree },
            phys: HashMap::new(),
            phys_dirty: Vec::new(),
            eph: HashMap::new(),
            eph_order: vec![OID_SPACEMAN, OID_REAPER],
            virt: HashMap::new(),
            virt_dirty: Vec::new(),
            fs_oid: vec![0; l.max_file_systems as usize],
            vols: BTreeMap::new(),
            rw_mounted: false,
            sb_copy,
            fxc: None,
            rove: 0,
            reaper: Reaper { next_reap_id: 1, completed_id: 0, head: 0, tail: 0, flags: 1, rlcount: 0, ty: 0, size: 0, fs_oid: 0, oid: 0, xid: 0, nrle_flags: 0 },
            reap_lists: BTreeMap::new(),
            alloc_delta: BTreeMap::new(),
            precounted: Default::default(),
            tx_ops: 0,
            solid_state: true,
            alloc_log: None,
        })
    }

    fn count(&mut self, _site: Site) -> u64 {
        self.counter += 1;
        self.counter
    }

    /// Whether the device reports `DK_FEATURE_BARRIER` (the in-memory space
    /// manager's start, I:0x10003ffec; the kernel's 0xfffffff00674d5f4):
    /// the free queues' age limit 2 and the main queue's count limit at
    /// most 1 GiB of blocks; else 8 and a 32nd of the blocks.
    pub fn set_barrier(&mut self, barrier: bool) {
        self.main_count_limit = self.l.blocks >> 5;
        if barrier {
            self.age_limit = 2;
            self.main_count_limit = self.main_count_limit.min((1u64 << 30) / self.l.bs);
        } else {
            self.age_limit = 8;
        }
    }

    /// Whether the device answers DKIOCISSOLIDSTATE with true (a regular
    /// file's ENOTTY counts as true, the default).
    pub fn set_solid_state(&mut self, solid: bool) {
        self.solid_state = solid;
    }

    /// The read-write mount: block 0 rewritten (its last state, not
    /// cleanly unmounted), the allocation zones chosen
    /// (`spaceman_allocation_init`), the metazone cursors and the pool's
    /// cursor reset (`spaceman_metazone_init`, I:0x100007e8c), and the
    /// newest mounting version raised to this APFS's. `newfs_apfs` does
    /// this at each run; the kernel once.
    pub fn mount_rw(&mut self) -> Result<(), String> {
        if self.rw_mounted {
            return Ok(());
        }
        let bs = self.l.bs as usize;
        let mut sb = vec![0u8; bs];
        self.sink.read_at(0, &mut sb)?;
        sb.put64(0x4f0, 0);
        let c = self.count(Site::Ephemeral);
        sb.put64(0x3d8, c);
        if self.newest_mounted == 0 && self.mode == Mode::Kernel {
            // The kernel raises the version after this write
            // (0xfffffff006671898 follows 0xfffffff00667177c).
        } else {
            sb.put64(0x568, self.newest_mounted.max(APFS_VERSION));
        }
        set_checksum(&mut sb);
        self.sink.write_at(0, &sb)?;
        if self.zones.iter().all(|z| !z.enabled) {
            for (z, (start, end)) in first_mount_datazones(&self.l, &self.chunks)?.into_iter().enumerate() {
                if end != 0 {
                    self.zones[z] = Zone { start, end, enabled: true, prev: [(0, 0); 7], index: 0 };
                }
            }
        }
        self.newest_mounted = self.newest_mounted.max(APFS_VERSION);
        self.classes = [Class::default(); 3];
        if let Some((start, mid, end)) = self.l.metazone() {
            self.classes[0] = Class { start, end: mid, cursor: start, state: 0, enabled: true };
            self.classes[1] = Class { start: mid, end, cursor: mid, state: 0, enabled: true };
        }
        self.ip_cursor = 0;
        // The roving pointer starts at zero (a zeroed space manager) and
        // leaves the metazone (I:0x100007e8c); the free-extent cache is
        // filled from the bitmaps (`spaceman_scan_free_blocks`,
        // I:0x100043910, K:0xfffffff0067532c8).
        self.rove = 0;
        if let Some((start, _, end)) = self.l.metazone() {
            if (start..end).contains(&self.rove) {
                self.rove = if end == self.l.blocks { 0 } else { end };
            }
        }
        self.fxc = Some(self.scan_free()?);
        self.wrote_checkpoint = false;
        self.rw_mounted = true;
        Ok(())
    }

    /// A new object identifier.
    pub fn new_oid(&mut self) -> u64 {
        let o = self.next_oid;
        self.next_oid += 1;
        o
    }

    /// `tx_enter` opening a transaction: the free queues' drain at its
    /// start (I:0x100041860).
    pub fn begin(&mut self) -> Result<(), String> {
        if self.in_tx {
            return Ok(());
        }
        self.in_tx = true;
        self.tx_ops = 0;
        if self.fq_too_big(FQ_IP, false)? {
            while self.fq_too_big(FQ_IP, true)? {
                if self.free_completed(FQ_IP)? == 0 {
                    break;
                }
            }
        }
        while self.fq[FQ_IP].count != 0 && self.xid - self.fq[FQ_IP].oldest_xid > self.age_limit {
            if self.free_completed(FQ_IP)? == 0 {
                break;
            }
        }
        if self.main_count_limit < self.fq[FQ_MAIN].count {
            while self.fq[FQ_MAIN].count > self.main_count_limit / 2 {
                if self.free_completed(FQ_MAIN)? == 0 {
                    break;
                }
            }
        }
        if self.sm_free < self.fq[FQ_MAIN].count {
            while self.fq[FQ_MAIN].count > self.sm_free / 2 {
                if self.free_completed(FQ_MAIN)? == 0 {
                    break;
                }
            }
        }
        if self.fq_too_big(FQ_MAIN, false)? {
            while self.fq_too_big(FQ_MAIN, true)? {
                if self.free_completed(FQ_MAIN)? == 0 {
                    break;
                }
            }
        }
        while self.fq[FQ_MAIN].count != 0 && self.xid - self.fq[FQ_MAIN].oldest_xid > self.age_limit {
            if self.free_completed(FQ_MAIN)? == 0 {
                break;
            }
        }
        Ok(())
    }

    /// `tx_enter` (I:0x10004bc64) by a caller that leaves its transaction
    /// with `tx_leave`: the open transaction joined, or a new one opened,
    /// its operation count raised.
    pub fn enter(&mut self) -> Result<(), String> {
        self.begin()?;
        self.tx_ops += 1;
        Ok(())
    }

    /// `tx_leave` (I:0x10004bc74) with `flags`: the transaction closes and
    /// its checkpoint is written when the caller asks (flag 4), when it
    /// holds more than 100,000 operations, when the object cache holds too
    /// many changed objects (I:0x100036ccc), or when the space manager
    /// needs a flush (I:0x100041c4c: the main free queue holding more than
    /// the free blocks, or more than its count limit, halved while the free
    /// blocks are under a 32nd of the device; a free queue past its node
    /// threshold); else it stays open for the next caller to join.
    pub fn leave(&mut self, flags: u32) -> Result<(), String> {
        if self.close_due(flags)? {
            self.commit()?;
        }
        Ok(())
    }

    /// Whether `tx_leave` with `flags` closes the open transaction (see
    /// [`Nx::leave`]); a caller still holding it commits when it leaves
    /// last.
    pub fn close_due(&mut self, flags: u32) -> Result<bool, String> {
        if !self.in_tx {
            return Ok(false);
        }
        let mut close = flags & 4 != 0 || self.tx_ops > 100_000;
        // The cache's changed objects (cache+0x374 virtual, +0x378
        // physical: raised by obj_dirty and by a physical object's
        // copy-on-write, lowered by the flush and by deleting one): the
        // virtual and physical objects changed here, each chunk-info block
        // and chunk bitmap copied in this transaction and the pool's bitmap
        // block; ephemeral objects never count (I:0x100036ccc). 1,024 on a
        // solid-state device (the device's dev+0x74, the kernel's dev+0x504;
        // any failure of the query, a regular file's ENOTTY included,
        // counts as one), 256 else.
        let dirty = (self.virt_dirty.len() + self.phys_dirty.len()) as u64 + self.cib_dirty.iter().filter(|d| **d).count() as u64 + self.chunks.iter().filter(|c| c.dirty).count() as u64 + u64::from(self.ipbm_xid == self.xid);
        if dirty >= if self.solid_state { 1024 } else { 256 } {
            close = true;
        }
        let main = self.fq[FQ_MAIN].count;
        let shift = if self.sm_free < self.l.blocks / 32 { 1 } else { 0 };
        if main > self.sm_free || main > self.main_count_limit >> shift || self.fq_too_big(FQ_IP, false)? || self.fq_too_big(FQ_MAIN, false)? {
            close = true;
        }
        Ok(close)
    }

    /// The blocks the space manager can still give
    /// (`spaceman_get_free_blocks`, I:0x100040a80 → I:0x100040bac, with no
    /// volume): the free blocks, or with the main free queue's and less
    /// the volume reserves not yet held, whichever is less (its
    /// reservation counters, sm+0x340 and +0x348, are zero: nothing this
    /// model runs reserves space).
    fn free_blocks_available(&self) -> u64 {
        let with_queue = self.sm_free.wrapping_add(self.fq[FQ_MAIN].count).wrapping_add(self.reserve.1.wrapping_sub(self.reserve.0));
        self.sm_free.min(with_queue)
    }

    // ---- The internal pool.

    /// The pool's bitmap's first change in this transaction: it moves to
    /// its ring's next block, the one it leaves joining the ring's free
    /// list (I:0x10004051c, I:0x10004996c).
    fn ipbm_touch(&mut self) -> Result<(), String> {
        if self.ipbm_xid == self.xid {
            return Ok(());
        }
        let new = self.ipbm_head;
        if new == IP_BM_INDEX_INVALID {
            return Err("the internal pool bitmap ring has no free block".into());
        }
        if self.ipbm_tail == new {
            self.ipbm_tail = IP_BM_INDEX_INVALID;
        }
        self.ipbm_head = self.ipbm_next[new as usize];
        self.ipbm_next[new as usize] = IP_BM_INDEX_INVALID;
        let old = self.ipbm_index;
        if self.ipbm_tail != IP_BM_INDEX_INVALID {
            self.ipbm_next[self.ipbm_tail as usize] = old;
        }
        self.ipbm_next[old as usize] = IP_BM_INDEX_INVALID;
        self.ipbm_tail = old;
        if self.ipbm_head == IP_BM_INDEX_INVALID {
            self.ipbm_head = old;
        }
        self.ipbm_index = new;
        self.ipbm_xid = self.xid;
        Ok(())
    }

    /// A pool block by the roving cursor (I:0x1000405fc).
    fn ip_alloc(&mut self) -> Result<u64, String> {
        let n = self.l.ip_blocks;
        let start = self.ip_cursor;
        let i = (start..n).chain(0..start).find(|&i| !self.ip_used[i as usize]).ok_or("not implemented: draining the internal pool's free queue for an allocation")?;
        self.ipbm_touch()?;
        self.ip_used[i as usize] = true;
        self.ip_cursor = if i + 1 >= n { 0 } else { i + 1 };
        Ok(self.l.ip_base + i)
    }

    // ---- Chunks.

    /// The first change to chunk `c` in this transaction: its chunk-info
    /// block and bitmap move to new pool blocks (`spaceman_modify_bits`,
    /// I:0x1000471c4).
    fn touch_chunk(&mut self, c: usize) -> Result<(), String> {
        if self.chunks[c].xid == self.xid && self.chunks[c].bitmap_addr != 0 {
            return Ok(());
        }
        let cib = c / self.l.chunks_per_cib as usize;
        if self.cib_xid[cib] != self.xid {
            let new = self.ip_alloc()?;
            let old = self.cib_addr[cib];
            self.fq_insert(FQ_IP, old, 1)?;
            self.cib_addr[cib] = new;
            self.cib_xid[cib] = self.xid;
        }
        self.cib_dirty[cib] = true;
        let bs = self.l.bs;
        let old = self.chunks[c].bitmap_addr;
        let new = self.ip_alloc()?;
        if old != 0 {
            if self.chunks[c].bitmap.is_none() {
                let mut b = vec![0u8; bs as usize];
                self.sink.read_at(old * bs, &mut b)?;
                self.chunks[c].bitmap = Some(b);
            }
            self.fq_insert(FQ_IP, old, 1)?;
        } else {
            self.chunks[c].bitmap = Some(vec![0u8; bs as usize]);
        }
        let ch = &mut self.chunks[c];
        ch.bitmap_addr = new;
        ch.xid = self.xid;
        ch.dirty = true;
        Ok(())
    }

    fn bitmap(&mut self, c: usize) -> Result<Option<&Vec<u8>>, String> {
        let bs = self.l.bs;
        let ch = &mut self.chunks[c];
        if ch.bitmap_addr == 0 {
            return Ok(None);
        }
        if ch.bitmap.is_none() {
            let mut buf = vec![0u8; bs as usize];
            self.sink.read_at(ch.bitmap_addr * bs, &mut buf)?;
            ch.bitmap = Some(buf);
        }
        Ok(ch.bitmap.as_ref())
    }

    /// The first free block of chunk `c` at or after block `from`.
    fn first_free_in(&mut self, c: usize, from: u64) -> Result<Option<u64>, String> {
        let bpc = self.l.blocks_per_chunk;
        let base = c as u64 * bpc;
        let end = (base + bpc).min(self.l.blocks);
        if self.chunks[c].free == 0 {
            return Ok(None);
        }
        let Some(bm) = self.bitmap(c)? else { return Ok((from < end).then_some(from)) };
        let mut b = from;
        while b < end {
            let i = (b - base) as usize;
            if i % 8 == 0 && bm[i / 8] == 0xff {
                b += 8;
                continue;
            }
            if bm[i / 8] & (1 << (i % 8)) == 0 {
                return Ok(Some(b));
            }
            b += 1;
        }
        Ok(None)
    }

    /// Marks `n` blocks from `b` used or free (`spaceman_modify_bits`).
    fn modify_bits(&mut self, b: u64, n: u64, used: bool) -> Result<(), String> {
        let bpc = self.l.blocks_per_chunk;
        let mut at = b;
        while at < b + n {
            let c = (at / bpc) as usize;
            let run = (b + n).min((c as u64 + 1) * bpc) - at;
            self.touch_chunk(c)?;
            let ch = &mut self.chunks[c];
            let bm = ch.bitmap.as_mut().unwrap();
            for k in at..at + run {
                let i = (k % bpc) as usize;
                if used {
                    bm[i / 8] |= 1 << (i % 8);
                } else {
                    bm[i / 8] &= !(1 << (i % 8));
                }
            }
            if used {
                ch.free -= run;
                self.sm_free -= run;
            } else {
                ch.free += run;
                self.sm_free += run;
            }
            at += run;
        }
        Ok(())
    }

    /// One block of metadata for metazone class `idx` (I:0x100044290 with
    /// flag 0x40): first fit around the device from the class's cursor
    /// (I:0x100008294), the class's cursor moved after it (I:0x1000081c0).
    pub fn alloc_meta_class(&mut self, idx: usize) -> Result<u64, String> {
        let cur = match idx {
            0 => self.classes[0].cursor,
            1 => self.classes[1].cursor,
            _ if self.classes[2].enabled => self.classes[2].cursor,
            _ => self.classes[1].cursor,
        };
        let start = if cur >= self.l.blocks { 0 } else { cur };
        let bpc = self.l.blocks_per_chunk;
        let sc = (start / bpc) as usize;
        let n = self.chunks.len();
        let mut found = None;
        for k in 0..n {
            let c = (sc + k) % n;
            let from = if k == 0 { start } else { c as u64 * bpc };
            if let Some(b) = self.first_free_in(c, from)? {
                found = Some(b);
                break;
            }
        }
        if found.is_none() {
            // Back at the start chunk: its blocks before the start.
            if let Some(b) = self.first_free_in(sc, sc as u64 * bpc)? {
                if b < start {
                    found = Some(b);
                }
            }
        }
        let Some(b) = found else {
            return Err("not implemented: draining the main free queue for a metadata allocation".into());
        };
        self.modify_bits(b, 1, true)?;
        self.fxc_remove(b, 1);
        let end = if b + 1 >= self.l.blocks { 0 } else { b + 1 };
        let c = &mut self.classes[idx.min(2)];
        if c.start <= end && end < c.end {
            c.cursor = end;
            c.state = 0;
        } else if c.cursor == c.start {
            c.cursor = end;
            c.state = 1;
        } else if c.state < 0 {
            c.cursor = c.start;
            c.state = 0;
        } else if c.state == 0 {
            c.cursor = c.start;
        } else {
            c.cursor = end;
            c.state += 1;
        }
        Ok(b)
    }

    /// One block of metadata from the upper metazone class.
    pub fn alloc_meta(&mut self) -> Result<u64, String> {
        self.alloc_meta_class(1)
    }

    fn fxc_remove(&mut self, b: u64, n: u64) {
        if let Some(f) = self.fxc.as_mut() {
            f.remove(b, n);
        }
    }

    /// The free-extent cache filled from the bitmaps: every maximal free
    /// run, a wholly free chunk as one, runs merged across chunk
    /// boundaries (I:0x1000421fc).
    fn scan_free(&mut self) -> Result<Fxc, String> {
        let bpc = self.l.blocks_per_chunk;
        let mut f = Fxc::new(self.l.blocks);
        let mut run: Option<u64> = None;
        for c in 0..self.chunks.len() {
            let base = c as u64 * bpc;
            let cnt = (self.l.blocks - base).min(bpc);
            if self.chunks[c].free == cnt {
                run.get_or_insert(base);
                continue;
            }
            if self.chunks[c].free == 0 {
                if let Some(s) = run.take() {
                    f.insert(s, base - s);
                }
                continue;
            }
            let bm = self.bitmap(c)?.ok_or("a partly used chunk with no bitmap")?.clone();
            for i in 0..cnt {
                let used = bm[(i / 8) as usize] & (1 << (i % 8)) != 0;
                match (used, run) {
                    (false, None) => run = Some(base + i),
                    (true, Some(s)) => {
                        f.insert(s, base + i - s);
                        run = None;
                    }
                    _ => {}
                }
            }
        }
        if let Some(s) = run {
            f.insert(s, self.l.blocks - s);
        }
        Ok(f)
    }

    /// What the free-extent cache's search clips: the metazone (to the
    /// upper class's end) and the allocation zones' current chunks.
    fn clip(&self) -> fxc::Clip {
        let metazone = self.classes[0].enabled.then(|| (self.classes[0].start, self.classes[1].end));
        let mut zones = [None; 4];
        for (z, zone) in self.zones.iter().enumerate() {
            if zone.enabled {
                zones[z] = Some((zone.start, zone.end));
            }
        }
        fxc::Clip { metazone, zones }
    }

    /// `spaceman_alloc` (I:0x100044290, K:0xfffffff0067535b0) of `count`
    /// data blocks with no hint and a count taken back (the kernel's
    /// `fs_make_hole_range_writable`, K:0xfffffff00670afbc). One to four
    /// blocks come from that size's allocation zone when its chunk has a
    /// free run that long (I:0x100044a1c..0x100044b14): the first such run
    /// from the chunk's start, the zone moved to a new chunk once its
    /// longest free run is shorter than the count; no search and no
    /// roving-pointer move. Anything else is the free-extent cache's best
    /// fit, its search given hint 0 (the hint spaceman_alloc passes on
    /// every data allocation without flag 2, whether it started from the
    /// roving pointer or a zone: measured), the roving pointer then moved
    /// to the allocation's end and off the metazone and the zones' chunks
    /// (I:0x100046580..0x100046c00). Where they go and how many: fewer
    /// than asked when nothing larger is free.
    pub fn alloc_data(&mut self, count: u64) -> Result<(u64, u64), String> {
        let (start, got) = self.alloc_data_placed(count)?;
        if let Some(log) = self.alloc_log.as_mut() {
            log.push((count, start, got, self.rove));
        }
        Ok((start, got))
    }

    fn alloc_data_placed(&mut self, count: u64) -> Result<(u64, u64), String> {
        if count == 0 {
            return Err("a data allocation of no blocks".into());
        }
        // The space and reserve checks (I:0x1000447cc..0x1000449d8): the
        // global count and the device's free blocks less what is reserved;
        // this model does not keep the reservations in flight (dirty
        // virtual objects, the kernel's write reservations), so it refuses
        // wherever the checks could bind.
        let held = self.reserve.0.saturating_sub(self.reserve.1);
        if count + held + self.fq[FQ_MAIN].count + self.fq[FQ_IP].count >= self.sm_free {
            return Err("not implemented: a data allocation the space manager's free-space and reserve checks may limit".into());
        }
        let bpc = self.l.blocks_per_chunk;
        let fxc_full = self.fxc.as_ref().is_some_and(|f| f.full());
        if (1..=4).contains(&count) && self.zones[count as usize - 1].enabled {
            let z = count as usize - 1;
            let c = (self.zones[z].start / bpc) as usize;
            if count <= self.longest(c)? {
                // The chunk scan from the zone chunk's start (I:0x100045060..
                // 0x100046140): the first run of `count` free blocks; the
                // shorter runs before it go back to the cache, where an
                // exact cache already holds them (a full one would recycle
                // its smallest extent, I:0x10000b814).
                let runs = self.free_runs(c)?;
                let (rs, _) = *runs.iter().find(|r| r.1 >= count).ok_or("an allocation zone's chunk without the run its longest names")?;
                if fxc_full && runs.iter().any(|r| r.0 < rs) {
                    return Err("not implemented: a zone allocation re-inserting runs into a full free-extent cache (its recycling of the smallest extent, I:0x10000b814)".into());
                }
                self.modify_bits(rs, count, true)?;
                self.fxc_remove(rs, count);
                // The refresh (I:0x1000469a8): the zone's chunk no longer has
                // a run of its size.
                if self.longest(c)? <= z as u64 {
                    self.zone_new_chunk(z)?;
                }
                return Ok((rs, count));
            }
        }
        let clip = self.clip();
        let f = self.fxc.as_ref().ok_or("a data allocation with no free-extent cache (the container not mounted read-write)")?;
        if f.total() != self.sm_free {
            return Err("not implemented: a data allocation with a free-extent cache that does not hold every free block (its rescan heuristic, I:0x10000db70)".into());
        }
        let found = f.search(0, count, fxc::flags::PARTIAL | fxc::flags::AVOID, &clip)?;
        let (start, got) = found.map_err(|_| "not implemented: a data allocation the free-extent cache cannot place (the chunk scan and the free queues' drain)".to_string())?;
        if got == 0 {
            return Err("not implemented: a data allocation the free-extent cache gives nothing for (the chunk scan)".into());
        }
        self.modify_bits(start, got, true)?;
        self.fxc_remove(start, got);
        let end = if start + got >= self.l.blocks { 0 } else { start + got };
        self.rove = end;
        // Off the metazone and the zones' chunks (flagged, I:0x100009498,
        // with count 5): the bitmap-hint search for one block
        // (I:0x100046da8) takes the start of the first chunk after the
        // end's, circularly, whose word has neither flag; the pointer stays
        // when there is none.
        let in_meta = clip.metazone.is_some_and(|(s, e)| (s..e).contains(&end));
        if in_meta || self.word_flags(end / bpc) & WORD_ZONE != 0 {
            let c0 = end / bpc;
            let cc = self.l.chunks;
            if self.word_flags(c0) & (WORD_METAZONE | WORD_ZONE) == 0 {
                return Ok((start, got));
            }
            let mut c = (c0 + 1) % cc;
            while c != c0 {
                if self.word_flags(c) & (WORD_METAZONE | WORD_ZONE) == 0 {
                    self.rove = c * bpc;
                    break;
                }
                c = (c + 1) % cc;
            }
        }
        Ok((start, got))
    }

    /// The flags of chunk `c`'s word: a chunk of the metazone (from its
    /// start's chunk to its end's, `spaceman_metazone_init` I:0x100007e8c),
    /// an enabled allocation zone's current chunk.
    fn word_flags(&self, c: u64) -> u32 {
        let bpc = self.l.blocks_per_chunk;
        let mut w = 0;
        if let Some((s, _, e)) = self.l.metazone() {
            if self.classes[0].enabled && c >= s / bpc && c <= (e - 1) / bpc {
                w |= WORD_METAZONE;
            }
        }
        if self.zones.iter().any(|z| z.enabled && z.start / bpc == c) {
            w |= WORD_ZONE;
        }
        w
    }

    /// The blocks of chunk `c`.
    fn chunk_len(&self, c: usize) -> u64 {
        let bpc = self.l.blocks_per_chunk;
        (self.l.blocks - c as u64 * bpc).min(bpc)
    }

    /// Chunk `c`'s free runs, in order: (first block, length).
    fn free_runs(&mut self, c: usize) -> Result<Vec<(u64, u64)>, String> {
        let base = c as u64 * self.l.blocks_per_chunk;
        let n = self.chunk_len(c);
        if self.chunks[c].free == 0 {
            return Ok(Vec::new());
        }
        let Some(bm) = self.bitmap(c)? else { return Ok(vec![(base, n)]) };
        let mut out = Vec::new();
        let mut run: Option<u64> = None;
        for i in 0..n {
            let used = bm[(i / 8) as usize] & (1 << (i % 8)) != 0;
            match (used, run) {
                (false, None) => run = Some(i),
                (true, Some(s)) => {
                    out.push((base + s, i - s));
                    run = None;
                }
                _ => {}
            }
        }
        if let Some(s) = run {
            out.push((base + s, n - s));
        }
        Ok(out)
    }

    /// The longest free run of chunk `c`: its word's low 24 bits, kept by
    /// `spaceman_modify_bits` for every chunk it changes (I:0x1000497ac)
    /// and by the mount's scan (a chunk with no bitmap: its free count).
    fn longest(&mut self, c: usize) -> Result<u64, String> {
        Ok(self.free_runs(c)?.iter().map(|r| r.1).max().unwrap_or(0).min(0xff_ffff))
    }

    /// `spaceman_get_new_chunk_for_allocation_zone` (I:0x100009014,
    /// K:0xfffffff0066bb264) for zone `z` (blocks `z + 1`): the oldest chunk
    /// of its ring that is unflagged and has a run longer than `z`, else
    /// the chunk with the most free blocks such a run and no flag, found by
    /// a scan of the chunk-info blocks from the current one (after the
    /// zone's chunk; that block skipped when the chunk is its last or the
    /// device's last) that stops at the end of the block where a wholly
    /// free chunk is found. Finding none, the zone keeps its chunk (0x1c,
    /// only logged).
    fn zone_new_chunk(&mut self, z: usize) -> Result<(), String> {
        let bpc = self.l.blocks_per_chunk;
        let (bc, cc, cpc, nc) = (self.l.blocks, self.l.chunks, self.l.chunks_per_cib, self.l.cibs);
        let zone = self.zones[z];
        let mut i = zone.index as usize;
        for _ in 0..7 {
            let (ps, pe) = zone.prev[i];
            if pe != 0 && pe <= bc {
                let c = ps / bpc;
                if c >= cc {
                    // pe <= bc keeps the chunk on the device; the library
                    // stops looking at the ring here.
                    break;
                }
                if self.word_flags(c) & (WORD_METAZONE | WORD_ZONE) == 0 && self.longest(c as usize)? > z as u64 {
                    return self.zone_install(z, c);
                }
            }
            i = (i + 1) % 7;
        }
        let cur = zone.start / bpc;
        let skip_cur = cur + 1 == cpc || cur == cc - 1;
        let mut best: Option<u64> = None;
        let mut best_free = 0;
        for i in u64::from(skip_cur)..nc {
            let cib = (cur / cpc + i) % nc;
            let j0 = if i == 0 { cur % cpc + 1 } else { 0 };
            let in_cib = (cc - cpc * cib).min(cpc);
            for j in j0..in_cib {
                let c = cpc * cib + j;
                let f = self.chunks[c as usize].free & 0xf_ffff;
                if f > best_free && self.word_flags(c) & (WORD_METAZONE | WORD_ZONE) == 0 && self.longest(c as usize)? > z as u64 {
                    best = Some(c);
                    best_free = f;
                    if f == bpc {
                        break;
                    }
                }
            }
            if best_free == bpc {
                break;
            }
        }
        match best {
            Some(c) => self.zone_install(z, c),
            None => Ok(()),
        }
    }

    /// `spaceman_update_allocation_zone` (I:0x100008b9c): zone `z` moved to
    /// chunk `c`, the chunk it leaves pushed onto its ring (or, when `c`
    /// is in the ring, that entry taken out and the one it leaves put
    /// newest).
    fn zone_install(&mut self, z: usize, c: u64) -> Result<(), String> {
        let bpc = self.l.blocks_per_chunk;
        if c >= self.l.chunks {
            return Err(format!("an allocation zone moved to chunk {c} past the device"));
        }
        let zone = &mut self.zones[z];
        if zone.enabled {
            let idx = zone.index as usize;
            let mut pushed = false;
            for k in 0..7 {
                let p = (idx + k) % 7;
                if zone.prev[p].1 != 0 && zone.prev[p].0 / bpc == c {
                    if p != idx {
                        let mut u = p;
                        loop {
                            let nx = (u + 1) % 7;
                            zone.prev[u] = zone.prev[nx];
                            u = nx;
                            if nx == idx {
                                break;
                            }
                        }
                        zone.prev[if idx == 0 { 6 } else { idx - 1 }] = (zone.start, zone.end);
                        pushed = true;
                    }
                    break;
                }
            }
            if !pushed {
                zone.prev[idx] = (zone.start, zone.end);
                zone.index = ((idx + 1) % 7) as u16;
            }
        }
        zone.start = c * bpc;
        zone.end = if c == self.l.chunks - 1 { self.l.blocks } else { zone.start + bpc };
        Ok(())
    }

    /// A new reap list (an ephemeral object; its entries all on its free
    /// list).
    fn reap_list_new(&mut self) -> u64 {
        let oid = self.new_oid();
        let bs = self.l.bs as usize;
        let mut b = vec![0u8; bs];
        let max = ((bs - 0x40) / 0x28) as u32;
        b.put32(0x2c, max);
        b.put32(0x34, NRL_NONE);
        b.put32(0x38, NRL_NONE);
        b.put32(0x3c, 0);
        for i in 0..max {
            b.put32(0x40 + 0x28 * i as usize, if i + 1 < max { i + 1 } else { NRL_NONE });
        }
        self.reap_lists.insert(oid, b);
        self.eph_order.push(oid);
        oid
    }

    /// `nx_reaper_add` (I:0x100016bf4): object `oid` of `ty` (`size` its
    /// node size), of volume `fs_oid`, queued for the reaper in its tail
    /// list (a new list when fewer than two entries are free): an entry
    /// with the transaction and one with the reap identifier. The reap
    /// identifier.
    pub fn reaper_add(&mut self, ty: u32, size: u32, fs_oid: u64, oid: u64, flags: u32) -> Result<u64, String> {
        let xid = self.xid;
        let list = if self.reaper.head == 0 && self.reaper.tail == 0 {
            let l = self.reap_list_new();
            self.reaper.head = l;
            self.reaper.tail = l;
            self.reaper.rlcount = 1;
            l
        } else {
            let l = self.reaper.tail;
            if self.reaper.rlcount == 0 && self.reaper.head == self.reaper.tail {
                self.reaper.rlcount = 1;
            }
            l
        };
        let mut list = list;
        {
            let b = self.reap_lists.get(&list).ok_or("the reaper's tail list not in the cache")?;
            let (count, max) = (u32::from_le_bytes(b[0x30..0x34].try_into().unwrap()), u32::from_le_bytes(b[0x2c..0x30].try_into().unwrap()));
            if count > max.wrapping_sub(2) {
                let n = self.reap_list_new();
                self.reap_lists.get_mut(&list).unwrap().put64(0x20, n);
                self.reaper.tail = n;
                if self.reaper.rlcount != 0 {
                    self.reaper.rlcount += 1;
                }
                list = n;
            }
        }
        let id = self.reaper.next_reap_id;
        self.reaper.next_reap_id += 1;
        let b = self.reap_lists.get_mut(&list).unwrap();
        let rd = |b: &Vec<u8>, o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let ent = |i: u32| 0x40 + 0x28 * i as usize;
        let e = rd(b, 0x3c);
        if e == NRL_NONE {
            return Err("reap list object free list erroneously empty".into());
        }
        let e2 = rd(b, ent(e));
        b.put32(0x3c, e2);
        let last = rd(b, 0x38);
        if last != NRL_NONE {
            b.put32(ent(last), e);
        }
        if rd(b, 0x34) == NRL_NONE {
            b.put32(0x34, e);
        }
        b.put32(0x38, e);
        let count = rd(b, 0x30);
        b.put32(0x30, count + 1);
        b.put32(ent(e), NRL_NONE);
        let put_entry = |b: &mut Vec<u8>, i: u32, fl: u32, last: u64| {
            let o = ent(i);
            b.put32(o + 4, fl);
            b.put32(o + 8, ty);
            b.put32(o + 12, size);
            b.put64(o + 16, fs_oid);
            b.put64(o + 24, oid);
            b.put64(o + 32, last);
        };
        put_entry(b, e, if flags & 2 != 0 { 0x15 } else { 5 }, xid);
        if e2 == NRL_NONE {
            return Err("reap list object free list erroneously empty".into());
        }
        let e3 = rd(b, ent(e2));
        b.put32(ent(e), e2);
        b.put32(0x38, e2);
        b.put32(0x3c, e3);
        b.put32(0x30, count + 2);
        b.put32(ent(e2), NRL_NONE);
        let mut fl = if flags & 2 != 0 { 0x13 } else { 3 };
        if flags & 1 != 0 {
            fl |= 0xc;
        }
        put_entry(b, e2, fl, id);
        Ok(id)
    }

    /// The reaper's run at a container mount (`nx_mount` I:0x1000340ec →
    /// I:0x1000175b4; the kernel's `apfs_reaper` thread runs the same
    /// loop, K 0xfffffff0066bee04): when an entry is in progress or the
    /// head list holds one, `nx_reaper` (I:0x1000176a4) takes the entries
    /// one at a time, each step in the open transaction, joined or opened
    /// by `tx_enter`, left with flags from the free space (`tx_leave(xid,
    /// (free < 1000) | (free < 2000) << 2)`, I:0x100017998). With the lists
    /// empty the transaction is left with no flags, open for the next
    /// caller.
    pub fn reaper_run(&mut self) -> Result<(), String> {
        if self.reaper.oid == 0 {
            if self.reaper.head == 0 {
                return Ok(());
            }
            let b = self.reap_lists.get(&self.reaper.head).ok_or("the reaper's head list not in the cache")?;
            if u32a(b, 0x30) == 0 && u64a(b, 0x20) == 0 {
                return Ok(());
            }
        }
        loop {
            self.enter()?;
            if self.reaper.oid == 0 {
                self.reaper_next_record()?;
                if self.reaper.oid == 0 {
                    return self.leave(0);
                }
            }
            let r = self.reaper;
            if r.nrle_flags & NRLE_CALL != 0 {
                match r.ty & otype::MASK {
                    otype::BTREE | otype::BTREE_NODE => self.btree_node_reap(r.ty, r.size, r.fs_oid, r.oid)?,
                    // The object descriptor table (I:0x100037fd4): the types
                    // with reap functions not transcribed here.
                    0x1 | 0x5 | 0x6 | 0x7 | 0x8 | 0xb | 0xd | 0x11 | 0x12 | 0x19 | 0x1b | 0x1d | 0x1e => return Err(format!("not implemented: reaping an object of type {:#x} (its descriptor's reap function, I:0x100037fd4)", r.ty)),
                    // "object type not reapable?": logged, the entry dropped.
                    _ => {}
                }
            }
            // The entry done (no reap function returns EINPROGRESS here).
            if r.nrle_flags & NRLE_REAP_ID_RECORD != 0 {
                self.reaper.completed_id = r.xid;
            }
            self.reaper.flags &= !NR_CONTINUE;
            self.reaper.oid = 0;
            let free = self.free_blocks_available();
            self.leave(u32::from(free < 1000) | u32::from(free < 2000) << 2)?;
        }
    }

    /// `nx_reaper_next_record` (I:0x10001855c): the head list's first entry
    /// becomes the reaper's, the entry back on the list's free list; an
    /// exhausted list gives way to the next one, and is deleted.
    fn reaper_next_record(&mut self) -> Result<(), String> {
        if self.reaper.head == 0 {
            return Ok(());
        }
        let ent = |i: u32| 0x40 + 0x28 * i as usize;
        while self.reaper.oid == 0 {
            let head = self.reaper.head;
            let b = self.reap_lists.get_mut(&head).ok_or("the reaper's head list not in the cache")?;
            let first = u32a(b, 0x34);
            if first == NRL_NONE {
                let next = u64a(b, 0x20);
                if next == 0 {
                    if self.reaper.rlcount == 0 && self.reaper.head == self.reaper.tail {
                        self.reaper.rlcount = 1;
                    }
                    break;
                }
                if !self.reap_lists.contains_key(&next) {
                    return Err("the next reap list not in the cache".into());
                }
                self.reaper.head = next;
                if self.reaper.rlcount != 0 {
                    self.reaper.rlcount -= 1;
                }
                self.reap_lists.remove(&head);
                self.eph_order.retain(|&o| o != head);
                continue;
            }
            let e = ent(first);
            let next = u32a(b, e);
            self.reaper.nrle_flags = u32a(b, e + 4);
            self.reaper.ty = u32a(b, e + 8);
            self.reaper.size = u32a(b, e + 12);
            self.reaper.fs_oid = u64a(b, e + 16);
            self.reaper.oid = u64a(b, e + 24);
            self.reaper.xid = u64a(b, e + 32);
            if u32a(b, 0x34) == u32a(b, 0x38) {
                b.put32(0x38, next);
            }
            b.put32(e + 4, 0);
            let f = u32a(b, 0x3c);
            b.put32(e, f);
            b.put32(0x3c, first);
            let c = u32a(b, 0x30);
            b.put32(0x30, c - 1);
            b.put32(0x34, next);
        }
        Ok(())
    }

    /// `nx_reaper_add_sub_object` (I:0x1000170c4, no flags): object `oid`
    /// queued at the front of the head list (a new head list when that one
    /// is full), to be reaped next.
    fn reaper_add_sub_object(&mut self, ty: u32, size: u32, fs_oid: u64, oid: u64) -> Result<(), String> {
        let xid = self.xid;
        if self.reaper.head == 0 && self.reaper.tail == 0 {
            let l = self.reap_list_new();
            self.reaper.head = l;
            self.reaper.tail = l;
            self.reaper.rlcount = 1;
        } else {
            if !self.reap_lists.contains_key(&self.reaper.head) {
                return Err("the reaper's head list not in the cache".into());
            }
            if self.reaper.rlcount == 0 && self.reaper.head == self.reaper.tail {
                self.reaper.rlcount = 1;
            }
        }
        let mut list = self.reaper.head;
        let b = &self.reap_lists[&list];
        if u32a(b, 0x2c).wrapping_sub(1) < u32a(b, 0x30) {
            let n = self.reap_list_new();
            let head = self.reaper.head;
            self.reap_lists.get_mut(&n).unwrap().put64(0x20, head);
            self.reaper.head = n;
            if self.reaper.rlcount != 0 {
                self.reaper.rlcount += 1;
            }
            list = n;
        }
        let b = self.reap_lists.get_mut(&list).unwrap();
        let i = u32a(b, 0x3c);
        if i == NRL_NONE {
            return Err("reap list object free list erroneously empty".into());
        }
        let e = 0x40 + 0x28 * i as usize;
        let f = u32a(b, e);
        b.put32(0x3c, f);
        let f = u32a(b, 0x34);
        b.put32(e, f);
        b.put32(0x34, i);
        if u32a(b, 0x38) == NRL_NONE {
            b.put32(0x38, i);
        }
        let c = u32a(b, 0x30);
        b.put32(0x30, c + 1);
        b.put32(e + 4, NRLE_VALID | NRLE_CALL);
        b.put32(e + 8, ty);
        b.put32(e + 12, size);
        b.put64(e + 16, fs_oid);
        b.put64(e + 24, oid);
        b.put64(e + 32, xid);
        Ok(())
    }

    /// The slot of the volume whose superblock is `fs_oid`.
    fn vol_index(&self, fs_oid: u64) -> Result<usize, String> {
        self.fs_oid.iter().position(|&o| o == fs_oid && o != 0).ok_or_else(|| format!("no volume {fs_oid:#x}"))
    }

    /// `btree_node_reap` (I:0x1000253a0), a B-tree node's reap function:
    /// its volume's superblock changed; an index node's children, last to
    /// first, deleted when they are leaves (a level-1 node's) and queued
    /// for the reaper when not; then the node deleted. A hashed node is
    /// refused (ENOTSUP), the reaper logging it and dropping the entry.
    fn btree_node_reap(&mut self, ty: u32, size: u32, fs_oid: u64, oid: u64) -> Result<(), String> {
        let vol = if fs_oid != 0 { Some(self.vol_index(fs_oid)?) } else { None };
        let physical = ty & otype::PHYSICAL != 0;
        let b = if physical {
            self.phys_obj(oid)?.b.clone()
        } else {
            let owner = vol.map_or(Owner::Container, Owner::Volume);
            self.virt.get(&(owner, oid)).ok_or_else(|| format!("not implemented: reading virtual object {oid:#x} through its object map"))?.b.clone()
        };
        let n = Node { b };
        if n.flags() & node_flags::HASHED != 0 {
            return Ok(());
        }
        if let Some(v) = vol {
            self.vol_sb(v)?;
        }
        if !n.is_leaf() {
            if n.flags() & node_flags::FIXED_KV_SIZE != 0 {
                return Err("not implemented: reaping a fixed-size B-tree's index node".into());
            }
            let shape = jtree_shape(self.l.bs, physical);
            let child_ty = (u32a(&n.b, 24) & !otype::MASK) | otype::BTREE_NODE;
            let child_fs = if vol.is_some() { fs_oid } else { 0 };
            for i in (0..n.nkeys()).rev() {
                let child = n.child(&shape, i);
                if n.level() < 2 {
                    self.obj_delete(child_ty, size, vol, child)?;
                } else {
                    self.reaper_add_sub_object(child_ty, size, child_fs, child)?;
                }
            }
        }
        self.obj_delete(ty, size, vol, oid)
    }

    /// `obj_delete` (I:0x100038968, by identifier I:0x100038d1c) of object
    /// `oid` of `ty` and `size` bytes, of volume `vol`: a physical one's
    /// blocks freed, a virtual one's mapping deleted from its object map.
    fn obj_delete(&mut self, ty: u32, size: u32, vol: Option<usize>, oid: u64) -> Result<(), String> {
        let n = u64::from(size).div_ceil(self.l.bs);
        if ty & otype::PHYSICAL != 0 {
            self.phys.remove(&oid);
            self.phys_dirty.retain(|&p| p != oid);
            return self.fs_free(vol, oid, n);
        }
        // A virtual object's obj_modify only reserves space (I:0x10003ae80):
        // a changed one still names its last mapping, which goes; one made
        // in this transaction has none and only leaves the cache.
        let owner = vol.map_or(Owner::Container, Owner::Volume);
        self.virt_dirty.retain(|&o| o != (owner, oid));
        self.precounted.remove(&(owner, oid));
        let vo = self.virt.remove(&(owner, oid)).ok_or_else(|| format!("no virtual object {oid:#x}"))?;
        match vo.mapped {
            Some((mxid, paddr)) => self.omap_delete(owner, oid, mxid, paddr, n),
            None => Ok(()),
        }
    }

    /// `omap_delete` (I:0x10003eedc) with flag 1 (an object's deletion) of
    /// `oid`'s mapping of transaction `xid_old` at `paddr`: in a volume's
    /// map (no snapshot holds it) a record of an older transaction of the
    /// same object leaves a deleted marker at this transaction, the
    /// mapping goes (unless the marker took its key) and its blocks are
    /// freed; in the container's map it goes and its blocks are freed.
    fn omap_delete(&mut self, owner: Owner, oid: u64, xid_old: u64, paddr: u64, n: u64) -> Result<(), String> {
        let xid = self.xid;
        let vol = match owner {
            Owner::Volume(i) => Some(i),
            Owner::Container => None,
        };
        let mut om = self.omap_of(owner)?;
        if vol.is_some() && u32a(&self.phys_obj(om.phys)?.b, 0x24) != 0 {
            return Err("not implemented: deleting a mapping from an object map with snapshots".into());
        }
        om.phys = self.phys_modify(om.phys)?;
        let key = |o: u64, x: u64| {
            let mut k = o.to_le_bytes().to_vec();
            k.extend_from_slice(&x.to_le_bytes());
            k
        };
        let mut st = PhysStore { nx: self, subtype: otype::OMAP_TREE_SUBTYPE, class: 2, vol };
        let marker = vol.is_some() && xid_old != 0 && om.tree.get_le(&mut st, &key(oid, xid_old - 1))?.is_some_and(|(k, _)| u64a(&k, 0) == oid);
        if marker {
            let mut v = omap_val::DELETED.to_le_bytes().to_vec();
            v.extend_from_slice(&(n as u32 * self.l.bs as u32).to_le_bytes());
            v.extend_from_slice(&paddr.to_le_bytes());
            let mut st = PhysStore { nx: self, subtype: otype::OMAP_TREE_SUBTYPE, class: 2, vol };
            om.tree.insert(&mut st, &key(oid, xid), Some(&v))?;
        }
        if !(xid_old == xid && marker) {
            let mut st = PhysStore { nx: self, subtype: otype::OMAP_TREE_SUBTYPE, class: 2, vol };
            om.tree.remove(&mut st, &key(oid, xid_old))?.ok_or_else(|| format!("no mapping of {oid:#x} at {xid_old}"))?;
        }
        let root = om.tree.root;
        self.phys_obj(om.phys)?.b.put64(0x30, root);
        self.phys_dirty_mark(om.phys);
        self.set_omap(owner, om)?;
        self.fs_free(vol, paddr, n)
    }

    /// `spaceman_free` (I:0x100047fd8) of `n` blocks at `paddr` for volume
    /// `vol`: to the main free queue, the volume's allocation count less
    /// them (I:0x1000483c8) and its last-change transaction this one
    /// (I:0x10001e498).
    fn fs_free(&mut self, vol: Option<usize>, paddr: u64, n: u64) -> Result<(), String> {
        self.free(paddr, n)?;
        let Some(v) = vol else { return Ok(()) };
        let xid = self.xid;
        let sb = self.vol_sb(v)?;
        if u64a(sb, 0x48) != 0 {
            return Err("not implemented: a free by a volume with a reserve (the space manager's reserve count, I:0x1000483c8)".into());
        }
        let role = u16::from_le_bytes([sb[0x3c4], sb[0x3c5]]);
        if [0u16, 2, 0x40, 0x240].contains(&role) {
            return Err(format!("not implemented: a free by a volume of role {role:#x} (+0x428, I:0x10001e498)"));
        }
        sb.put64(0x420, xid);
        *self.alloc_delta.entry(v).or_default() -= n as i64;
        Ok(())
    }

    /// `n` blocks allocated for volume `vol` (spaceman_modify_bits with an
    /// owner, I:0x100047ae8..0x100047b28): its `fs_alloc_count` raised, and
    /// the part of them within the volume's reserve counted in the space
    /// manager's `sm_fs_reserve_alloc_count`.
    pub fn vol_alloc_add(&mut self, vol: usize, n: u64) -> Result<(), String> {
        let sb = self.vol_sb(vol)?;
        let old = u64a(sb, 0x58);
        let reserve = u64a(sb, 0x48);
        sb.put64(0x58, old + n);
        self.reserve.1 += n.min(reserve.saturating_sub(old));
        Ok(())
    }

    /// A volume's file data freed (`apfs_free_data_blocks` K 0x66f6fe8):
    /// `spaceman_free` of `n` blocks at `paddr` for volume `vol`, then its
    /// `total_blocks_freed` raised by them.
    pub fn free_data(&mut self, vol: usize, paddr: u64, n: u64) -> Result<(), String> {
        self.fs_free(Some(vol), paddr, n)?;
        let sb = self.vol_sb(vol)?;
        let freed = u64a(sb, 0xe8);
        sb.put64(0xe8, freed + n);
        Ok(())
    }

    /// The container handed from the kernel to a user-space tool (or
    /// back): it is mounted again as that one's library mounts it, its
    /// counter taken from the newest checkpoint's copy.
    pub fn remount(&mut self, mode: Mode) -> Result<(), String> {
        if self.in_tx {
            return Err("remounting a container with a transaction open".into());
        }
        self.mode = mode;
        self.counter = u64a(&self.sb_copy, 0x3d8);
        self.rw_mounted = false;
        self.mount_rw()
    }

    /// The volume superblock's identifier of slot `index`.
    pub fn vol_oid(&self, index: usize) -> Option<u64> {
        self.fs_oid.get(index).copied().filter(|&o| o != 0)
    }

    /// Volume `index`'s file-system tree replaced by `t` (a new tree).
    pub fn replace_fs_tree(&mut self, index: usize, t: Tree) -> Result<(), String> {
        self.vols.get_mut(&index).ok_or_else(|| format!("no volume in slot {index}"))?.fs_tree = t;
        Ok(())
    }

    /// A new physical tree for volume `index` (its extent-reference
    /// tree's kind), and a new virtual one (its file-system tree's).
    pub fn new_extentref_tree(&mut self, index: usize) -> Result<Tree, String> {
        let bs = self.l.bs;
        let (_, mut st) = self.extentref_tree(index)?;
        Tree::create(&mut st, jtree_shape(bs, true), btree::cmp_jobj_hashed)
    }

    pub fn new_fs_tree(&mut self, index: usize, hashed: bool) -> Result<Tree, String> {
        let bs = self.l.bs;
        let (_, mut st) = self.fs_tree(index)?;
        Tree::create(&mut st, jtree_shape(bs, false), if hashed { btree::cmp_jobj_hashed } else { btree::cmp_jobj_plain })
    }

    /// The block size.
    pub fn block_size(&self) -> u64 {
        self.l.bs
    }

    /// The roving data pointer.
    pub fn rove(&self) -> u64 {
        self.rove
    }

    /// The allocation zones for 1 to 4 blocks: enabled, the current
    /// chunk's boundaries, the ring of chunks left and its index.
    pub fn zones(&self) -> Vec<(bool, (u64, u64), [(u64, u64); 7], u16)> {
        self.zones.iter().map(|z| (z.enabled, (z.start, z.end), z.prev, z.index)).collect()
    }

    /// The free-extent cache's extents.
    pub fn free_extents(&self) -> Vec<fxc::Ext> {
        self.fxc.as_ref().map(|f| f.extents()).unwrap_or_default()
    }

    // ---- The free queues.

    fn fq_tree(&mut self, q: usize) -> Result<Tree, String> {
        if let Some(t) = self.fq[q].tree {
            return Ok(t);
        }
        let shape = fq_shape(self.l.bs);
        let t = Tree::create(&mut EphStore { nx: self }, shape, btree::cmp_fq)?;
        self.fq[q].tree = Some(t);
        Ok(t)
    }

    /// `spaceman_free` (I:0x100047fd8): `n` blocks from `paddr` to the main
    /// free queue in this transaction.
    pub fn free(&mut self, paddr: u64, n: u64) -> Result<(), String> {
        self.fq_insert(FQ_MAIN, paddr, n)
    }

    /// `spaceman_fq_tree_insert` (I:0x1000484d8): merged with the
    /// transaction's entries before and after it.
    fn fq_insert(&mut self, q: usize, paddr: u64, n: u64) -> Result<(), String> {
        let xid = self.xid;
        let mut t = self.fq_tree(q)?;
        let key = |x: u64, p: u64| {
            let mut k = x.to_le_bytes().to_vec();
            k.extend_from_slice(&p.to_le_bytes());
            k
        };
        let recs = t.records(&mut EphStore { nx: self })?;
        let entry = |r: &(Vec<u8>, Option<Vec<u8>>)| (u64a(&r.0, 0), u64a(&r.0, 8), r.1.as_ref().map_or(1, |v| u64a(v, 0)));
        let pred = recs.iter().map(entry).filter(|&(x, p, _)| (x, p as i64) <= (xid, paddr as i64)).last();
        let (mut start, mut len) = (paddr, n);
        if let Some((px, pp, pl)) = pred {
            if px == xid {
                if paddr < pp + pl {
                    return Err(format!("not implemented: a free of blocks {paddr}+{n} overlapping the queued {pp}+{pl}"));
                }
                if pp + pl == paddr {
                    start = pp;
                    len = pl + n;
                }
            }
        }
        let succ = recs.iter().map(entry).find(|&(x, p, _)| (x, p as i64) > (xid, start as i64));
        let mut remove_succ = None;
        if let Some((sx, sp, sl)) = succ {
            if sx == xid && sp <= start + len {
                if sp < start + len {
                    return Err(format!("not implemented: a free of blocks {paddr}+{n} overlapping the queued {sp}+{sl}"));
                }
                len += sl;
                remove_succ = Some(sp);
            }
        }
        let v = len.to_le_bytes();
        t.insert(&mut EphStore { nx: self }, &key(xid, start), (len != 1).then_some(&v[..]))?;
        if let Some(sp) = remove_succ {
            t.remove(&mut EphStore { nx: self }, &key(xid, sp))?;
        }
        self.fq[q].tree = Some(t);
        if self.fq[q].count == 0 {
            self.fq[q].oldest_xid = xid;
        }
        self.fq[q].count += n;
        if self.fq_too_big(q, false)? {
            return Err("not implemented: a free queue drained because its tree outgrew its node limit".into());
        }
        Ok(())
    }

    /// The free queue's "too big" test (I:0x100043f1c): to start a drain,
    /// or (`cont`) to go on with one.
    fn fq_too_big(&mut self, q: usize, cont: bool) -> Result<bool, String> {
        let Some(t) = self.fq[q].tree else { return Ok(false) };
        let limit = u64::from(self.fq[q].limit);
        let root = EphStore { nx: self }.get(t.root)?;
        let nodes = super::node::Info::read(&root.b).node_count;
        let bs = self.l.bs as usize;
        Ok(if limit >= 2 {
            if cont {
                nodes > limit >> 1
            } else {
                nodes > (3 * limit) >> 2
            }
        } else {
            nodes > 1 || btree::root_free(&root) < if cont { bs / 2 } else { bs / 4 }
        })
    }

    /// `spaceman_free_completed` (I:0x100040f68): the oldest transaction's
    /// entries released, if a durable checkpoint covers them (every
    /// earlier transaction's is: each ends with its checkpoint written);
    /// the blocks released.
    fn free_completed(&mut self, q: usize) -> Result<u64, String> {
        let Some(mut t) = self.fq[q].tree else { return Ok(0) };
        let durable = self.xid - 1;
        let recs = t.records(&mut EphStore { nx: self })?;
        let Some(first) = recs.first() else { return Ok(0) };
        let first_xid = u64a(&first.0, 0);
        let mut released = 0;
        for (k, v) in recs {
            let (x, p) = (u64a(&k, 0), u64a(&k, 8));
            let len = v.as_ref().map_or(1, |v| u64a(v, 0));
            if x > self.xid {
                return Err("a free queue entry of a later transaction".into());
            }
            if x > first_xid {
                self.fq[q].oldest_xid = x;
                break;
            }
            if x > durable {
                break;
            }
            let n = if q == FQ_IP { len } else { len.min(4 * self.l.blocks_per_chunk) };
            if q == FQ_IP {
                self.ipbm_touch()?;
                for i in 0..len {
                    self.ip_used[(p + i - self.l.ip_base) as usize] = false;
                }
            } else {
                self.modify_bits(p, n, false)?;
                if let Some(f) = self.fxc.as_mut() {
                    f.insert(p, n);
                }
            }
            self.fq[q].count -= n;
            released += n;
            t.remove(&mut EphStore { nx: self }, &k)?;
            if n < len {
                let mut nk = x.to_le_bytes().to_vec();
                nk.extend_from_slice(&(p + n).to_le_bytes());
                let v = (len - n).to_le_bytes();
                t.insert(&mut EphStore { nx: self }, &nk, (len - n != 1).then_some(&v[..]))?;
            }
        }
        self.fq[q].tree = Some(t);
        Ok(released)
    }

    // ---- Objects.

    fn phys_obj(&mut self, paddr: u64) -> Result<&mut Obj, String> {
        if !self.phys.contains_key(&paddr) {
            let mut b = vec![0u8; self.l.bs as usize];
            self.sink.read_at(paddr * self.l.bs, &mut b)?;
            let t = u32::from_le_bytes(b[24..28].try_into().unwrap());
            let st = u32::from_le_bytes(b[28..32].try_into().unwrap());
            let class = if t & 0xffff == otype::OMAP || st == otype::OMAP_TREE_SUBTYPE { 2 } else { 1 };
            self.phys.insert(paddr, Obj { b, storage: t & otype::STORAGETYPE_MASK, subtype: st, class });
        }
        Ok(self.phys.get_mut(&paddr).unwrap())
    }

    fn phys_dirty_mark(&mut self, paddr: u64) {
        if !self.phys_dirty.contains(&paddr) {
            self.phys_dirty.push(paddr);
        }
    }

    /// A new physical object of `class` (`obj_create`, I:0x100037844): its
    /// block.
    fn phys_create(&mut self, mut b: Vec<u8>, storage: u32, subtype: u32, class: usize) -> Result<u64, String> {
        let paddr = self.alloc_meta_class(class)?;
        b.put64(8, paddr);
        b.put64(16, self.xid);
        self.phys.insert(paddr, Obj { b, storage, subtype, class });
        self.phys_dirty_mark(paddr);
        Ok(paddr)
    }

    /// `obj_modify` of a physical object (I:0x10003b2ac): a new block at
    /// its first change in this transaction, the old one freed at once.
    fn phys_modify(&mut self, paddr: u64) -> Result<u64, String> {
        let xid = self.xid;
        let o = self.phys_obj(paddr)?;
        if u64a(&o.b, 16) == xid {
            return Ok(paddr);
        }
        let class = o.class;
        let new = self.alloc_meta_class(class)?;
        let mut o = self.phys.remove(&paddr).unwrap();
        o.b.put64(8, new);
        o.b.put64(16, xid);
        self.phys.insert(new, o);
        self.phys_dirty.retain(|&p| p != paddr);
        self.phys_dirty_mark(new);
        self.free(paddr, 1)?;
        Ok(new)
    }

    /// `omap_set` (I:0x10003ecb0) and the old mapping's `omap_delete`
    /// (I:0x10003eedc) for object `oid` of `owner`, now at `paddr`: without
    /// snapshots the old record goes and its block is freed.
    fn omap_set(&mut self, owner: Owner, oid: u64, paddr: u64, old: Option<(u64, u64)>) -> Result<(), String> {
        let mut om = self.omap_of(owner)?;
        om.phys = self.phys_modify(om.phys)?;
        let mut k = oid.to_le_bytes().to_vec();
        k.extend_from_slice(&self.xid.to_le_bytes());
        let mut v = 0u32.to_le_bytes().to_vec();
        v.extend_from_slice(&(self.l.bs as u32).to_le_bytes());
        v.extend_from_slice(&paddr.to_le_bytes());
        let vol = match owner {
            Owner::Volume(i) => Some(i),
            Owner::Container => None,
        };
        om.tree.insert(&mut PhysStore { nx: self, subtype: otype::OMAP_TREE_SUBTYPE, class: 2, vol }, &k, Some(&v))?;
        if let Some((oxid, opaddr)) = old {
            if oxid != self.xid {
                let mut ok = oid.to_le_bytes().to_vec();
                ok.extend_from_slice(&oxid.to_le_bytes());
                om.tree.remove(&mut PhysStore { nx: self, subtype: otype::OMAP_TREE_SUBTYPE, class: 2, vol }, &ok)?;
                self.free(opaddr, 1)?;
            }
        }
        let root = om.tree.root;
        self.phys_obj(om.phys)?.b.put64(0x30, root);
        self.phys_dirty_mark(om.phys);
        self.set_omap(owner, om)
    }

    fn omap_of(&self, owner: Owner) -> Result<Omap, String> {
        match owner {
            Owner::Container => Ok(self.omap),
            Owner::Volume(i) => self.vols.get(&i).map(|v| v.omap).ok_or_else(|| format!("no volume in slot {i}")),
        }
    }

    fn set_omap(&mut self, owner: Owner, om: Omap) -> Result<(), String> {
        match owner {
            Owner::Container => self.omap = om,
            Owner::Volume(i) => {
                let v = self.vols.get_mut(&i).ok_or_else(|| format!("no volume in slot {i}"))?;
                let moved = v.omap.phys != om.phys;
                v.omap = om;
                // The superblock names its object map by address.
                if moved {
                    self.vol_sb(i)?.put64(0x80, om.phys);
                }
            }
        }
        Ok(())
    }

    /// A new virtual object of `owner`: its identifier.
    fn virt_create(&mut self, owner: Owner, mut b: Vec<u8>) -> u64 {
        let oid = self.new_oid();
        b.put64(8, oid);
        self.virt.insert((owner, oid), VObj { b, mapped: None });
        self.virt_dirty.push((owner, oid));
        oid
    }

    /// `obj_modify` of a virtual object: dirty from now on in this
    /// transaction.
    fn virt_modify(&mut self, owner: Owner, oid: u64) {
        if !self.virt_dirty.contains(&(owner, oid)) {
            self.virt_dirty.push((owner, oid));
        }
    }

    /// The flush (`obj_cache_flush_prepare`, I:0x100035080): the virtual
    /// objects' blocks and mappings in three passes (encrypted volumes'
    /// objects, the others, volume superblocks), each written as it is
    /// placed.
    fn flush(&mut self) -> Result<(), String> {
        let dirty = std::mem::take(&mut self.virt_dirty);
        let is_sb = |o: &(Owner, u64)| o.0 == Owner::Container;
        let enc = |nx: &Nx, o: &(Owner, u64)| matches!(o.0, Owner::Volume(i) if nx.vols.get(&i).is_some_and(|v| v.encrypted));
        let mut order: Vec<(Owner, u64)> = dirty.iter().copied().filter(|o| !is_sb(o) && enc(self, o)).collect();
        order.extend(dirty.iter().copied().filter(|o| !is_sb(o) && !enc(self, o)));
        order.extend(dirty.iter().copied().filter(is_sb));
        for (owner, oid) in order {
            let class = if enc(self, &(owner, oid)) { 0 } else { 1 };
            if let Owner::Volume(i) = owner {
                if self.virt.get(&(owner, oid)).is_some_and(|v| v.mapped.is_none()) && !self.precounted.remove(&(owner, oid)) {
                    *self.alloc_delta.entry(i).or_default() += 1;
                }
            }
            if owner == Owner::Container {
                // A volume's superblock takes its allocation count's
                // changes (the volume's objects were placed before it).
                if let Some(i) = self.fs_oid.iter().position(|&o| o == oid) {
                    let d = self.alloc_delta.remove(&i).unwrap_or(0);
                    if d != 0 {
                        let vo = self.virt.get_mut(&(owner, oid)).unwrap();
                        let old = u64a(&vo.b, 0x58);
                        let reserve = u64a(&vo.b, 0x48);
                        let c = old as i64 + d;
                        vo.b.put64(0x58, c as u64);
                        if reserve != 0 {
                            if d < 0 {
                                return Err("not implemented: a volume with a reserve losing blocks (the space manager's reserve count, I:0x1000483c8)".into());
                            }
                            self.reserve.1 += (d as u64).min(reserve.saturating_sub(old));
                        }
                    }
                }
            }
            let paddr = self.alloc_meta_class(class)?;
            let old = self.virt.get(&(owner, oid)).ok_or("a dirty object not in the cache")?.mapped;
            self.omap_set(owner, oid, paddr, old)?;
            let xid = self.xid;
            let vo = self.virt.get_mut(&(owner, oid)).unwrap();
            vo.mapped = Some((xid, paddr));
            vo.b.put64(8, oid);
            vo.b.put64(16, xid);
            let mut b = vo.b.clone();
            let ty = u32::from_le_bytes(b[24..28].try_into().unwrap());
            if ty & 0xffff == otype::BTREE || ty & 0xffff == otype::BTREE_NODE {
                let root = Node { b: b.clone() }.is_root();
                b.put32(24, (ty & !0xffff) | if root { otype::BTREE } else { otype::BTREE_NODE });
            }
            self.count(Site::Cached);
            set_checksum(&mut b);
            self.sink.write_at(paddr * self.l.bs, &b)?;
        }
        if self.alloc_delta.values().any(|&d| d != 0) {
            return Err("not implemented: a volume's allocation count changed in a transaction that did not change its superblock".into());
        }
        Ok(())
    }

    /// The transaction's flush and checkpoint (`tx_flush`, I:0x10004bfb8).
    pub fn commit(&mut self) -> Result<(), String> {
        self.begin()?;
        let bs = self.l.bs;
        let bsz = bs as usize;
        let xid = self.xid;
        self.flush()?;
        // Physical objects.
        let dirty = std::mem::take(&mut self.phys_dirty);
        for paddr in dirty {
            let o = self.phys.get(&paddr).ok_or("a dirty physical object not in the cache")?;
            let mut b = o.b.clone();
            let t = u32::from_le_bytes(b[24..28].try_into().unwrap());
            if t & 0xffff == otype::BTREE || t & 0xffff == otype::BTREE_NODE {
                let root = Node { b: b.clone() }.is_root();
                put_header(&mut b, paddr, xid, o.storage | if root { otype::BTREE } else { otype::BTREE_NODE }, o.subtype);
            }
            self.count(Site::Cached);
            set_checksum(&mut b);
            self.sink.write_at(paddr * bs, &b)?;
            self.phys.get_mut(&paddr).unwrap().b = b;
        }
        // Chunk-info blocks and bitmaps.
        for cib in 0..self.l.cibs as usize {
            if !self.cib_dirty[cib] {
                continue;
            }
            let addr = self.cib_addr[cib];
            let mut b = vec![0u8; bsz];
            put_header(&mut b, addr, self.cib_xid[cib], otype::PHYSICAL | 0x7, 0);
            let first = cib * self.l.chunks_per_cib as usize;
            let n = (self.l.chunks as usize - first).min(self.l.chunks_per_cib as usize);
            b.put32(0x20, cib as u32);
            b.put32(0x24, n as u32);
            for j in 0..n {
                let c = first + j;
                let o = 0x28 + 32 * j;
                let ch = &self.chunks[c];
                b.put64(o, ch.xid);
                b.put64(o + 8, c as u64 * self.l.blocks_per_chunk);
                b.put32(o + 16, (self.l.blocks - c as u64 * self.l.blocks_per_chunk).min(self.l.blocks_per_chunk) as u32);
                b.put32(o + 20, ch.free as u32);
                b.put64(o + 24, ch.bitmap_addr);
            }
            self.count(Site::Cached);
            set_checksum(&mut b);
            self.sink.write_at(addr * bs, &b)?;
            self.cib_dirty[cib] = false;
        }
        for c in 0..self.chunks.len() {
            if self.chunks[c].dirty {
                let ch = &mut self.chunks[c];
                ch.dirty = false;
                self.sink.write_at(ch.bitmap_addr * bs, ch.bitmap.as_ref().unwrap())?;
            }
        }
        if self.ipbm_xid == xid {
            let mut ipbm = vec![0u8; bsz];
            for (i, _) in self.ip_used.iter().enumerate().filter(|(_, u)| **u) {
                ipbm[i / 8] |= 1 << (i % 8);
            }
            self.sink.write_at((self.l.ip_bm_base + u64::from(self.ipbm_index)) * bs, &ipbm)?;
        }

        // The checkpoint: ephemeral objects in list order (map order at
        // mount, then creation), map blocks, the superblock copy last.
        let desc_start = (self.desc_index + self.desc_len) % self.l.desc_blocks;
        let data_start = (self.data_index + self.data_len) % self.l.data_blocks;
        let mut eph: Vec<(u32, u32, u64, Vec<u8>)> = Vec::new();
        for oid in self.eph_order.clone() {
            match oid {
                OID_SPACEMAN => eph.push((otype::EPHEMERAL | 0x5, 0, OID_SPACEMAN, self.spaceman_bytes())),
                OID_REAPER => {
                    let r = self.reaper;
                    let mut reaper = vec![0u8; bsz];
                    put_header(&mut reaper, OID_REAPER, xid, otype::EPHEMERAL | 0x11, 0);
                    reaper.put64(0x20, r.next_reap_id);
                    reaper.put64(0x28, r.completed_id);
                    reaper.put64(0x30, r.head);
                    reaper.put64(0x38, r.tail);
                    reaper.put32(0x40, r.flags);
                    reaper.put32(0x44, r.rlcount);
                    reaper.put32(0x48, r.ty);
                    reaper.put32(0x4c, r.size);
                    reaper.put64(0x50, r.fs_oid);
                    reaper.put64(0x58, r.oid);
                    reaper.put64(0x60, r.xid);
                    reaper.put32(0x68, r.nrle_flags);
                    reaper.put32(0x6c, bs as u32 - 0x70);
                    eph.push((otype::EPHEMERAL | 0x11, 0, OID_REAPER, reaper));
                }
                oid if self.reap_lists.contains_key(&oid) => {
                    let mut b = self.reap_lists[&oid].clone();
                    let ty = otype::EPHEMERAL | OBJECT_TYPE_NX_REAP_LIST;
                    put_header(&mut b, oid, xid, ty, 0);
                    eph.push((ty, 0, oid, b));
                }
                oid => {
                    let o = self.eph.get(&oid).ok_or("an ephemeral object not in the cache")?;
                    let mut b = o.b.clone();
                    let root = Node { b: b.clone() }.is_root();
                    let ty = o.storage | if root { otype::BTREE } else { otype::BTREE_NODE };
                    put_header(&mut b, oid, xid, ty, o.subtype);
                    eph.push((ty, o.subtype, oid, b));
                }
            }
        }
        // A map block's entries: (bs - sizeof(checkpoint_map_phys_t)) /
        // sizeof(checkpoint_mapping_t).
        let per_map = ((bs - 0x28) / 0x28) as usize;
        let maps = eph.len().div_ceil(per_map).max(1);
        let data_blocks: u64 = eph.iter().map(|e| e.3.len() as u64 / bs).sum();
        if (maps as u64) + 1 > self.l.desc_blocks || data_blocks > self.l.data_blocks {
            return Err("not implemented: a checkpoint larger than its rings".into());
        }
        let mut at = data_start;
        let mut map_blocks: Vec<Vec<u8>> = (0..maps).map(|_| vec![0u8; bsz]).collect();
        for (i, (ty, sub, oid, mut b)) in eph.into_iter().enumerate() {
            let (m, j) = (i / per_map, i % per_map);
            let o = 0x28 + 40 * j;
            let map = &mut map_blocks[m];
            map.put32(o, ty);
            map.put32(o + 4, sub);
            map.put32(o + 8, b.len() as u32);
            map.put64(o + 0x18, oid);
            map.put64(o + 0x20, self.l.data_base + at);
            map.put32(0x24, j as u32 + 1);
            self.count(Site::Ephemeral);
            set_checksum(&mut b);
            for blk in 0..b.len() / bsz {
                let idx = (at + blk as u64) % self.l.data_blocks;
                self.sink.write_at((self.l.data_base + idx) * bs, &b[blk * bsz..(blk + 1) * bsz])?;
            }
            at = (at + b.len() as u64 / bs) % self.l.data_blocks;
        }
        self.desc_index = desc_start;
        self.desc_len = maps as u64 + 1;
        self.data_index = data_start;
        self.data_len = data_blocks;
        for (m, map) in map_blocks.iter_mut().enumerate() {
            let paddr = self.l.desc_base + (desc_start + m as u64) % self.l.desc_blocks;
            put_header(map, paddr, xid, otype::PHYSICAL | otype::CHECKPOINT_MAP, 0);
            map.put32(0x20, if m + 1 == maps { CHECKPOINT_MAP_LAST } else { 0 });
        }
        let mut sb = self.superblock()?;
        sb.put64(0x3d8, self.counter);
        self.count(Site::Raw);
        set_checksum(&mut sb);
        let sb_at = self.l.desc_base + (desc_start + maps as u64) % self.l.desc_blocks;
        self.sink.write_at(sb_at * bs, &sb)?;
        self.sb_copy = sb;
        for (m, map) in map_blocks.iter_mut().enumerate() {
            self.count(Site::Raw);
            set_checksum(map);
            let paddr = self.l.desc_base + (desc_start + m as u64) % self.l.desc_blocks;
            self.sink.write_at(paddr * bs, map)?;
        }
        self.wrote_checkpoint = true;
        self.in_tx = false;
        self.xid += 1;
        Ok(())
    }

    /// The superblock as the latest checkpoint has it.
    fn superblock(&self) -> Result<Vec<u8>, String> {
        let mut sb = self.sb_copy.clone();
        put_header(&mut sb, 1, self.xid, otype::EPHEMERAL | otype::NX_SUPERBLOCK, 0);
        sb.put64(0x58, self.next_oid);
        sb.put64(0x60, self.xid + 1);
        sb.put32(0x80, ((self.desc_index + self.desc_len) % self.l.desc_blocks) as u32);
        sb.put32(0x84, ((self.data_index + self.data_len) % self.l.data_blocks) as u32);
        sb.put32(0x88, self.desc_index as u32);
        sb.put32(0x8c, self.desc_len as u32);
        sb.put32(0x90, self.data_index as u32);
        sb.put32(0x94, self.data_len as u32);
        sb.put64(0xa0, self.omap.phys);
        for (i, &o) in self.fs_oid.iter().enumerate() {
            sb.put64(0xb8 + 8 * i, o);
        }
        sb.put64(0x4f0, 0);
        sb.put64(0x568, self.newest_mounted);
        Ok(sb)
    }

    /// The unmount (`tx_unmount`, I:0x10004af70): an open transaction
    /// committed, then block 0 from the last checkpoint, cleanly
    /// unmounted, if this mount wrote a checkpoint.
    pub fn unmount(&mut self) -> Result<(), String> {
        if !self.rw_mounted {
            return Ok(());
        }
        if self.in_tx {
            self.commit()?;
        }
        if self.wrote_checkpoint {
            let mut sb = self.sb_copy.clone();
            let c = self.count(Site::Ephemeral);
            sb.put64(0x3d8, c);
            if self.desc_len != 0 && self.data_len != 0 {
                sb.put64(0x4f0, NX_CLEANLY_UNMOUNTED);
            }
            set_checksum(&mut sb);
            self.sink.write_at(0, &sb)?;
        }
        if self.mode == Mode::Userspace {
            // The next run's mount takes the count from the copy.
            self.counter = u64a(&self.sb_copy, 0x3d8);
        }
        self.rw_mounted = false;
        Ok(())
    }

    fn spaceman_bytes(&self) -> Vec<u8> {
        let l = &self.l;
        let mut sm = vec![0u8; l.sm_bytes as usize];
        put_header(&mut sm, OID_SPACEMAN, self.xid, otype::EPHEMERAL | 0x5, 0);
        sm.put32(0x20, l.bs as u32);
        sm.put32(0x24, l.blocks_per_chunk as u32);
        sm.put32(0x28, l.chunks_per_cib as u32);
        sm.put32(0x2c, l.cibs_per_cab as u32);
        sm.put64(0x30, l.blocks);
        sm.put64(0x38, l.chunks);
        sm.put32(0x40, l.cibs as u32);
        sm.put32(0x44, l.cabs as u32);
        sm.put64(0x48, self.sm_free);
        sm.put64(0xb8, self.reserve.0);
        sm.put64(0xc0, self.reserve.1);
        sm.put32(0x50, l.addr_offset as u32);
        sm.put32(0x80, (l.addr_offset + 8 * l.cibs) as u32);
        sm.put32(0x90, 1);
        sm.put32(0x94, 16);
        sm.put64(0x98, l.ip_blocks);
        sm.put32(0xa0, l.ip_bm_size as u32);
        sm.put32(0xa4, l.ip_bm_count as u32);
        sm.put64(0xa8, l.ip_bm_base);
        sm.put64(0xb0, l.ip_base);
        for (q, base) in [(FQ_IP, 0xc8usize), (FQ_MAIN, 0xf0)] {
            let f = &self.fq[q];
            sm.put64(base, f.count);
            sm.put64(base + 8, f.tree.map_or(0, |t| t.root));
            sm.put64(base + 16, f.oldest_xid);
            sm.put16(base + 24, f.limit);
        }
        sm.put16(0x140, self.ipbm_head);
        sm.put16(0x142, self.ipbm_tail);
        sm.put32(0x144, l.xid_offset as u32);
        sm.put32(0x148, l.bitmap_offset as u32);
        sm.put32(0x14c, l.free_next_offset as u32);
        sm.put32(0x150, 1);
        sm.put32(0x154, 0x9d8);
        // sm_datazone[SD_MAIN][size - 1]: the current chunk's boundaries,
        // the ring of previous chunks and its index, the zone id.
        for (z, zone) in self.zones.iter().enumerate() {
            if !zone.enabled {
                continue;
            }
            let o = 0x158 + 136 * z;
            sm.put64(o, zone.start);
            sm.put64(o + 8, zone.end);
            for (i, &(ps, pe)) in zone.prev.iter().enumerate() {
                sm.put64(o + 0x10 + 0x10 * i, ps);
                sm.put64(o + 0x18 + 0x10 * i, pe);
            }
            sm.put16(o + 0x80, z as u16 + 1);
            sm.put16(o + 0x82, zone.index);
        }
        sm.put64(l.xid_offset as usize, self.ipbm_xid);
        sm.put16(l.bitmap_offset as usize, self.ipbm_index);
        for (i, &n) in self.ipbm_next.iter().enumerate() {
            sm.put16(l.free_next_offset as usize + 2 * i, n);
        }
        for (i, &a) in self.cib_addr.iter().enumerate() {
            sm.put64(l.addr_offset as usize + 8 * i, a);
        }
        sm
    }

    /// `apfs_newfs`: a volume added (`newfs_apfs -A`), in its own
    /// transaction.
    pub fn create_volume(&mut self, v: &NewVolume) -> Result<u64, String> {
        self.begin()?;
        let bs = self.l.bs;
        let xid = self.xid;
        // apfs_fs_index: System 0, Data 1, the rest the first free from 2.
        let index = match v.role {
            0x1 => 0,
            0x40 => 1,
            _ => (2..self.fs_oid.len()).find(|&i| self.fs_oid[i] == 0).ok_or("no space for a new file system")?,
        };
        if self.fs_oid[index] != 0 {
            return Err(format!("existing file system (slot {index})"));
        }
        if v.encrypted {
            return Err("not implemented: an encrypted volume (its keys are the device's Secure Enclave's)".into());
        }
        let vol_oid = self.new_oid();
        // The volume's object map and its tree, then its extent-reference
        // and snapshot trees.
        let mut o = vec![0u8; bs as usize];
        put_header(&mut o, 0, xid, otype::PHYSICAL | otype::OMAP, 0);
        o.put32(0x28, otype::PHYSICAL | otype::BTREE);
        o.put32(0x2c, otype::PHYSICAL | otype::BTREE);
        let omap = self.phys_create(o, otype::PHYSICAL, 0, 2)?;
        let omap_tree = Tree::create(&mut PhysStore { nx: self, subtype: otype::OMAP_TREE_SUBTYPE, class: 2, vol: None }, omap_shape(bs), btree::cmp_omap)?;
        self.phys_obj(omap)?.b.put64(0x30, omap_tree.root);
        let extentref = Tree::create(&mut PhysStore { nx: self, subtype: BLOCKREFTREE, class: 1, vol: None }, jtree_shape(bs, true), btree::cmp_jobj_hashed)?;
        let snapmeta = Tree::create(&mut PhysStore { nx: self, subtype: SNAPMETATREE, class: 1, vol: None }, jtree_shape(bs, true), btree::cmp_jobj_hashed)?;
        self.vols.insert(index, Vol { oid: vol_oid, omap: Omap { phys: omap, tree: omap_tree }, encrypted: false, fs_tree: Tree { root: 0, shape: jtree_shape(bs, false), cmp: btree::cmp_jobj_hashed }, extentref, snapmeta });

        // The root and private directories.
        let mut fs = VirtStore { nx: self, owner: Owner::Volume(index), subtype: FSTREE };
        let mut fs_tree = Tree::create(&mut fs, jtree_shape(bs, false), btree::cmp_jobj_hashed)?;
        for (k, val) in initial_records(v) {
            fs_tree.insert(&mut fs, &k, Some(&val))?;
        }
        let root_oid = fs_tree.root;
        self.precounted.insert((Owner::Volume(index), root_oid));
        self.vols.get_mut(&index).unwrap().fs_tree = fs_tree;

        let mut sb = vec![0u8; bs as usize];
        put_header(&mut sb, vol_oid, xid, otype::FS, 0);
        sb.put32(0x20, crate::darwin::apfsread::APFS_MAGIC);
        sb.put32(0x24, index as u32);
        sb.put64(0x28, 0x2);
        let unwritten = v.e_apfs && ![0x1u16, 0x4, 0x8, 0x10, 0x20, 0x80, 0xc0, 0x100, 0x140, 0x280, 0x2c0].contains(&v.role);
        sb.put64(0x38, 0x8 | if unwritten { 0x80 } else { 0 });
        // `fssize=` (-s): the reserve and the quota, in blocks rounded up;
        // the space manager's reserve grows by it and counts the blocks the
        // volume holds against it (`spaceman_fs_bounds_set`, 0x100049c60;
        // measured: a volume's 5 blocks, for reserves of more than 5).
        let alloc = 5u64;
        if let Some(bytes) = v.size_bytes {
            let blocks = bytes.div_ceil(bs);
            if blocks < alloc {
                return Err("not implemented: a volume reserve smaller than the blocks the new volume holds (spaceman_fs_bounds_set's count of them)".into());
            }
            sb.put64(0x48, blocks);
            sb.put64(0x50, blocks);
            self.reserve.0 += blocks;
            self.reserve.1 += alloc;
        }
        sb.put64(0x58, alloc);
        if self.mode == Mode::Kernel {
            // wrapped_meta_crypto_state_t: version 5.0, no flags, class F
            // (6), the OS version, key revision 1.
            sb.put16(0x60, 5);
            sb.put32(0x68, 6);
            sb.put32(0x6c, v.key_os_version);
            sb.put16(0x70, 1);
        }
        sb.put32(0x74, otype::BTREE);
        sb.put32(0x78, otype::PHYSICAL | otype::BTREE);
        sb.put32(0x7c, otype::PHYSICAL | otype::BTREE);
        sb.put64(0x80, omap);
        sb.put64(0x88, root_oid);
        sb.put64(0x90, extentref.root);
        sb.put64(0x98, snapmeta.root);
        sb.put64(0xb0, 0x10);
        let mut uuid = *b"apfsuuid\0\0volum\0";
        uuid[8..10].copy_from_slice(&v.role.to_be_bytes());
        uuid[15] = index as u8;
        sb[0xf0..0x100].copy_from_slice(&uuid);
        sb.put64(0x100, v.times.modified);
        sb.put64(0x108, APFS_FS_UNENCRYPTED);
        sb[0x110..0x110 + FORMATTED_BY.len()].copy_from_slice(FORMATTED_BY.as_bytes());
        sb.put64(0x130, v.times.formatted);
        sb.put64(0x138, xid);
        sb[0x2c0..0x2c0 + v.name.len()].copy_from_slice(v.name.as_bytes());
        sb.put32(0x3c0, 3);
        sb.put16(0x3c4, v.role);
        sb.put32(0x410, otype::PHYSICAL | otype::BTREE);
        sb.put32(0x414, otype::PHYSICAL | otype::BTREE);
        sb.put64(0x420, xid);
        if [0u16, 2, 0x40, 0x240].contains(&v.role) {
            sb.put32(0x428, 0x10);
        }
        sb.put32(0x42c, 2);
        sb.put32(0x450, 2);
        // The superblock's identifier was the volume's first.
        self.virt.insert((Owner::Container, vol_oid), VObj { b: sb, mapped: None });
        self.virt_dirty.push((Owner::Container, vol_oid));
        self.fs_oid[index] = vol_oid;
        Ok(vol_oid)
    }
}

impl<'a> Nx<'a> {
    /// Volume `index`'s superblock, changed in this transaction
    /// (`obj_modify`).
    pub fn vol_sb(&mut self, index: usize) -> Result<&mut Vec<u8>, String> {
        let oid = *self.fs_oid.get(index).filter(|&&o| o != 0).ok_or_else(|| format!("no volume in slot {index}"))?;
        self.virt_modify(Owner::Container, oid);
        Ok(&mut self.virt.get_mut(&(Owner::Container, oid)).ok_or_else(|| format!("volume {index}'s superblock not in the cache"))?.b)
    }

    /// Volume `index`'s file-system tree and the store of its nodes.
    pub fn fs_tree(&mut self, index: usize) -> Result<(Tree, VirtStore<'_, 'a>), String> {
        let t = self.vols.get(&index).ok_or_else(|| format!("no volume in slot {index}"))?.fs_tree;
        Ok((t, VirtStore { nx: self, owner: Owner::Volume(index), subtype: FSTREE }))
    }

    /// Volume `index`'s file-system tree after a change.
    pub fn set_fs_tree(&mut self, index: usize, t: Tree) {
        if let Some(v) = self.vols.get_mut(&index) {
            v.fs_tree = t;
        }
    }

    /// Volume `index`'s extent-reference tree and its nodes.
    pub fn extentref_tree(&mut self, index: usize) -> Result<(Tree, PhysStore<'_, 'a>), String> {
        let t = self.vols.get(&index).ok_or_else(|| format!("no volume in slot {index}"))?.extentref;
        Ok((t, PhysStore { nx: self, subtype: BLOCKREFTREE, class: 1, vol: Some(index) }))
    }

    /// Volume `index`'s extent-reference tree after a change: the
    /// superblock names its root by address.
    pub fn set_extentref_tree(&mut self, index: usize, t: Tree) -> Result<(), String> {
        let v = self.vols.get_mut(&index).ok_or_else(|| format!("no volume in slot {index}"))?;
        let moved = v.extentref.root != t.root;
        v.extentref = t;
        if moved {
            self.vol_sb(index)?.put64(0x90, t.root);
        }
        Ok(())
    }

    /// File data written to blocks from `paddr` (data blocks go to the
    /// device as written, not through the object cache).
    pub fn write_data(&self, paddr: u64, buf: &[u8]) -> Result<(), String> {
        if paddr == 0 || paddr + (buf.len() as u64).div_ceil(self.l.bs) > self.l.blocks {
            return Err(format!("file data at block {paddr} outside the container"));
        }
        self.sink.write_at(paddr * self.l.bs, buf)
    }
}

/// A physical tree's nodes.
pub struct PhysStore<'n, 'a> {
    nx: &'n mut Nx<'a>,
    subtype: u32,
    class: usize,
    /// The volume whose allocation count its nodes are in.
    vol: Option<usize>,
}

impl Store for PhysStore<'_, '_> {
    fn get(&mut self, id: u64) -> Result<Node, String> {
        Ok(Node { b: self.nx.phys_obj(id)?.b.clone() })
    }
    fn put(&mut self, id: u64, n: Node) -> Result<(), String> {
        self.nx.phys_obj(id)?.b = n.b;
        self.nx.phys_dirty_mark(id);
        Ok(())
    }
    fn modify(&mut self, id: u64) -> Result<u64, String> {
        self.nx.phys_modify(id)
    }
    fn create(&mut self, n: Node) -> Result<u64, String> {
        let mut b = n.b;
        b.put32(24, otype::PHYSICAL | otype::BTREE);
        b.put32(28, self.subtype);
        if let Some(v) = self.vol {
            *self.nx.alloc_delta.entry(v).or_default() += 1;
        }
        self.nx.phys_create(b, otype::PHYSICAL, self.subtype, self.class)
    }
    fn delete(&mut self, id: u64) -> Result<(), String> {
        if let Some(v) = self.vol {
            *self.nx.alloc_delta.entry(v).or_default() -= 1;
        }
        self.nx.phys.remove(&id);
        self.nx.phys_dirty.retain(|&p| p != id);
        self.nx.free(id, 1)
    }
}

/// The free queues' nodes (ephemeral).
pub struct EphStore<'n, 'a> {
    nx: &'n mut Nx<'a>,
}

impl Store for EphStore<'_, '_> {
    fn get(&mut self, id: u64) -> Result<Node, String> {
        self.nx.eph.get(&id).map(|o| Node { b: o.b.clone() }).ok_or_else(|| format!("no ephemeral object {id:#x}"))
    }
    fn put(&mut self, id: u64, n: Node) -> Result<(), String> {
        self.nx.eph.get_mut(&id).ok_or_else(|| format!("no ephemeral object {id:#x}"))?.b = n.b;
        Ok(())
    }
    fn modify(&mut self, id: u64) -> Result<u64, String> {
        Ok(id)
    }
    fn create(&mut self, n: Node) -> Result<u64, String> {
        let oid = self.nx.new_oid();
        self.nx.eph.insert(oid, Obj { b: n.b, storage: otype::EPHEMERAL, subtype: SPACEMAN_FREE_QUEUE, class: 1 });
        self.nx.eph_order.push(oid);
        Ok(oid)
    }
    fn delete(&mut self, id: u64) -> Result<(), String> {
        self.nx.eph.remove(&id);
        self.nx.eph_order.retain(|&o| o != id);
        Ok(())
    }
}

/// A volume's virtual tree's nodes.
pub struct VirtStore<'n, 'a> {
    nx: &'n mut Nx<'a>,
    owner: Owner,
    subtype: u32,
}

impl Store for VirtStore<'_, '_> {
    fn get(&mut self, id: u64) -> Result<Node, String> {
        if let Some(o) = self.nx.virt.get(&(self.owner, id)) {
            return Ok(Node { b: o.b.clone() });
        }
        Err(format!("not implemented: reading virtual object {id:#x} through its object map"))
    }
    fn put(&mut self, id: u64, n: Node) -> Result<(), String> {
        self.nx.virt.get_mut(&(self.owner, id)).ok_or_else(|| format!("no virtual object {id:#x}"))?.b = n.b;
        self.nx.virt_modify(self.owner, id);
        Ok(())
    }
    fn modify(&mut self, id: u64) -> Result<u64, String> {
        self.nx.virt_modify(self.owner, id);
        Ok(id)
    }
    fn create(&mut self, n: Node) -> Result<u64, String> {
        let mut b = n.b;
        b.put32(24, otype::BTREE);
        b.put32(28, self.subtype);
        Ok(self.nx.virt_create(self.owner, b))
    }
    fn delete(&mut self, id: u64) -> Result<(), String> {
        let vol = match self.owner {
            Owner::Volume(i) => Some(i),
            Owner::Container => None,
        };
        let size = self.nx.l.bs as u32;
        self.nx.obj_delete(otype::BTREE_NODE, size, vol, id)
    }
}

/// When `apfs_newfs` read its clock: the format's start (`formatted_by`'s
/// timestamp), the root and private directories' creation, and the end
/// (`apfs_last_mod_time`), in nanoseconds since 1970.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeTimes {
    pub formatted: u64,
    pub root: u64,
    pub private: u64,
    pub modified: u64,
}

/// A volume to add: `newfs_apfs -A [-D] -o role=<c> -v <name> [-P]`.
#[derive(Clone, Debug)]
pub struct NewVolume {
    pub name: String,
    pub role: u16,
    pub encrypted: bool,
    /// The device tree's `/filesystems` `e-apfs`.
    pub e_apfs: bool,
    pub times: VolumeTimes,
    /// The owner and group of the root directory (`getuid`, `getgid`).
    pub uid: u32,
    pub gid: u32,
    /// `cp_os_version()`, the kernel's meta crypto state's.
    pub key_os_version: u32,
    /// `-s`'s bytes (`fssize=`): the volume's reserve and quota.
    pub size_bytes: Option<u64>,
}

/// The fs-tree records `apfs_newfs` inserts, in its order: the root's
/// directory record, the root inode, the private directory's record and
/// inode (keys and values as the Reference's `j_drec_hashed_key_t`,
/// `j_drec_val_t`, `j_inode_key_t`, `j_inode_val_t`).
fn initial_records(v: &NewVolume) -> Vec<(Vec<u8>, Vec<u8>)> {
    const ROOT_DIR_PARENT: u64 = 1;
    const DT_DIR: u16 = 4;
    let drec = |name: &str, id: u64, added: u64| {
        let mut k = (ROOT_DIR_PARENT | (9u64 << 60)).to_le_bytes().to_vec();
        let len = name.len() as u32 + 1;
        let h = crate::darwin::apfsread::fs::name_hash(name);
        k.extend_from_slice(&((h << 10) | len).to_le_bytes());
        k.extend_from_slice(name.as_bytes());
        k.push(0);
        let mut val = id.to_le_bytes().to_vec();
        val.extend_from_slice(&added.to_le_bytes());
        val.extend_from_slice(&DT_DIR.to_le_bytes());
        (k, val)
    };
    let inode = |id: u64, mode: u16, t: u64, name: &str| {
        let k = (id | (3u64 << 60)).to_le_bytes().to_vec();
        let mut val = Vec::new();
        for f in [ROOT_DIR_PARENT, id, t, t, t, t, 0x8000u64] {
            val.extend_from_slice(&f.to_le_bytes());
        }
        for f in [0u32, 0, 1, 0, v.uid, v.gid] {
            val.extend_from_slice(&f.to_le_bytes());
        }
        val.extend_from_slice(&mode.to_le_bytes());
        val.extend_from_slice(&0u16.to_le_bytes());
        val.extend_from_slice(&0u64.to_le_bytes());
        // One extended field: INO_EXT_TYPE_NAME (4), XF_DO_NOT_COPY (2).
        let data_len = name.len() + 1;
        let padded = data_len.div_ceil(8) * 8;
        val.extend_from_slice(&1u16.to_le_bytes());
        val.extend_from_slice(&(padded as u16).to_le_bytes());
        val.extend_from_slice(&[4, 2]);
        val.extend_from_slice(&(data_len as u16).to_le_bytes());
        val.extend_from_slice(name.as_bytes());
        val.resize(val.len() + padded - name.len(), 0);
        (k, val)
    };
    vec![drec("root", 2, v.times.root), inode(2, 0o40755, v.times.root, "root"), drec("private-dir", 3, v.times.private), inode(3, 0o40644, v.times.private, "private-dir")]
}

/// `spaceman_datazone_init` at the first read-write mount of a container
/// straight after `-C`: each fully free chunk outside the metadata zone,
/// in the order the free-block scan visits them (by chunk-info block, each
/// block's chunks sorted by bitmap address with the BSD `qsort`), goes to
/// the first allocation zone (sizes 1 to 4 blocks) still pending whose
/// size is under the chunk's longest free run. Zones need a versioned
/// space manager, a metadata zone and 8 chunks.
fn first_mount_datazones(l: &Layout, chunks: &[Chunk]) -> Result<[(u64, u64); 4], String> {
    let mut out = [(0u64, 0u64); 4];
    let Some((mz_start, _, mz_end)) = l.metazone() else { return Ok(out) };
    if l.chunks < 8 {
        return Ok(out);
    }
    let bpc = l.blocks_per_chunk;
    let in_meta = |c: u64| c >= mz_start / bpc && c <= (mz_end - 1) / bpc;
    let mut pending = [true; 4];
    for cib in 0..l.cibs {
        let first = cib * l.chunks_per_cib;
        let last = (first + l.chunks_per_cib).min(l.chunks);
        let mut ents: Vec<(u64, u64)> = (first..last).map(|c| (c, chunks[c as usize].bitmap_addr)).collect();
        bsd_qsort(&mut ents, &|x: &(u64, u64), y: &(u64, u64)| x.1.cmp(&y.1));
        for (c, _) in ents {
            let ch = &chunks[c as usize];
            let cnt = (l.blocks - c * bpc).min(bpc);
            if ch.free == bpc && ch.free == cnt && !in_meta(c) {
                // A wholly free chunk's longest run is the chunk.
                if let Some(z) = (0..4).find(|&z| pending[z] && (z as u64) < cnt) {
                    out[z] = (c * bpc, if c == l.chunks - 1 { l.blocks } else { c * bpc + bpc });
                    pending[z] = false;
                }
            } else if pending.iter().any(|p| *p) && ch.free != cnt && ch.free >= 4 && !in_meta(c) {
                return Err("not implemented: the allocation zones' fallback to partly used chunks".into());
            }
        }
    }
    if pending.iter().any(|p| *p) {
        return Err("not implemented: allocation zones left pending after the scan (the partly-used candidates' fallback)".into());
    }
    Ok(out)
}

/// The BSD `qsort` (Apple Libc's, with its swap-count shortcut to an
/// insertion sort): not stable, so equal keys come out permuted as it
/// permutes them.
fn bsd_qsort<T: Copy>(a: &mut [T], cmp: &dyn Fn(&T, &T) -> std::cmp::Ordering) {
    use std::cmp::Ordering::*;
    fn ins<T: Copy>(a: &mut [T], lo: usize, n: usize, cmp: &dyn Fn(&T, &T) -> std::cmp::Ordering) {
        for m in lo + 1..lo + n {
            let mut l = m;
            while l > lo && cmp(&a[l - 1], &a[l]) == Greater {
                a.swap(l, l - 1);
                l -= 1;
            }
        }
    }
    fn med3<T: Copy>(a: &[T], x: usize, y: usize, z: usize, cmp: &dyn Fn(&T, &T) -> std::cmp::Ordering) -> usize {
        if cmp(&a[x], &a[y]) == Less {
            if cmp(&a[y], &a[z]) == Less {
                y
            } else if cmp(&a[x], &a[z]) == Less {
                z
            } else {
                x
            }
        } else if cmp(&a[y], &a[z]) == Greater {
            y
        } else if cmp(&a[x], &a[z]) == Less {
            x
        } else {
            z
        }
    }
    fn rec<T: Copy>(a: &mut [T], mut lo: usize, mut n: usize, cmp: &dyn Fn(&T, &T) -> std::cmp::Ordering) {
        loop {
            let mut swapped = false;
            if n < 7 {
                ins(a, lo, n, cmp);
                return;
            }
            let mut pm = lo + n / 2;
            if n > 7 {
                let (mut pl, mut pn) = (lo, lo + n - 1);
                if n > 40 {
                    let d = n / 8;
                    pl = med3(a, pl, pl + d, pl + 2 * d, cmp);
                    pm = med3(a, pm - d, pm, pm + d, cmp);
                    pn = med3(a, pn - 2 * d, pn - d, pn, cmp);
                }
                pm = med3(a, pl, pm, pn, cmp);
            }
            a.swap(lo, pm);
            let (mut pa, mut pb) = (lo + 1, lo + 1);
            let (mut pc, mut pd) = (lo + n - 1, lo + n - 1);
            loop {
                while pb <= pc {
                    let r = cmp(&a[pb], &a[lo]);
                    if r == Greater {
                        break;
                    }
                    if r == Equal {
                        swapped = true;
                        a.swap(pa, pb);
                        pa += 1;
                    }
                    pb += 1;
                }
                while pb <= pc {
                    let r = cmp(&a[pc], &a[lo]);
                    if r == Less {
                        break;
                    }
                    if r == Equal {
                        swapped = true;
                        a.swap(pc, pd);
                        pd -= 1;
                    }
                    pc -= 1;
                }
                if pb > pc {
                    break;
                }
                a.swap(pb, pc);
                swapped = true;
                pb += 1;
                pc -= 1;
            }
            if !swapped {
                ins(a, lo, n, cmp);
                return;
            }
            let pn = lo + n;
            let r = (pa - lo).min(pb - pa);
            for k in 0..r {
                a.swap(lo + k, pb - r + k);
            }
            let r = (pd - pc).min(pn - pd - 1);
            for k in 0..r {
                a.swap(pb + k, pn - r + k);
            }
            let r = pb - pa;
            if r > 1 {
                rec(a, lo, r, cmp);
            }
            let r = pd - pc;
            if r > 1 {
                lo = pn - r;
                n = r;
                continue;
            }
            return;
        }
    }
    let n = a.len();
    rec(a, 0, n, cmp);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qsort_permutes_as_libc() {
        // A chunk-info block of 126 chunks, chunk 0 the only one with a
        // bitmap: the scan visits 125, 1..124, 0 (measured).
        let mut e: Vec<(u64, u64)> = (0..126).map(|i| (i, if i == 0 { 27973 } else { 0 })).collect();
        bsd_qsort(&mut e, &|x: &(u64, u64), y: &(u64, u64)| x.1.cmp(&y.1));
        let order: Vec<u64> = e.iter().map(|x| x.0).collect();
        let mut want = vec![125];
        want.extend(1..125);
        want.push(0);
        assert_eq!(order, want);
    }

    /// Replays newfs_apfs's own -C and -A runs (the image at `path`),
    /// each volume's name, role and size given, byte for byte over the
    /// container's metadata, given its uuid and clock readings (found
    /// through the image's own object maps).
    fn replay(path: &str, vols: &[(&str, u16, Option<u64>)]) {
        use crate::darwin::apfsread::{tests_support, Container, Medium};
        use std::os::unix::fs::FileExt;
        use std::sync::Arc;
        let want = std::fs::File::open(path).unwrap();
        let rd = |blk: u64| {
            let mut b = vec![0u8; 4096];
            want.read_exact_at(&mut b, blk * 4096).unwrap();
            b
        };
        let b0 = rd(0);
        let uuid: [u8; 16] = b0[0x48..0x58].try_into().unwrap();
        let blocks = 15_625_000u64;
        let c = Arc::new(Container::open(Arc::new(tests_support::HostFile(std::fs::File::open(path).unwrap(), blocks * 4096))).unwrap());
        let com = c.omap().unwrap();
        let tmp = std::env::temp_dir().join(format!("gex-apfswrite-replay-{}-{}", std::process::id(), vols.len()));
        let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&tmp).unwrap();
        f.set_len(blocks * 4096).unwrap();
        let sink = crate::darwin::apfswrite::HostFile(f, blocks * 4096);
        let fm = super::super::container::format(&sink, 4096, blocks, uuid).unwrap();
        let mut nx = Nx::formatted(&sink, &fm, uuid, Mode::Userspace).unwrap();
        let q = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        for (name, role, size) in vols.iter() {
            nx.mount_rw().unwrap();
            let index = match role {
                1 => 0,
                0x40 => 1,
                _ => (2..nx.fs_oid.len()).find(|&i| nx.fs_oid[i] == 0).unwrap(),
            };
            let sbb = c.read_raw(com.lookup(&c, c.nx.fs_oid[index], c.xid()).unwrap().unwrap().paddr).unwrap();
            let vom = crate::darwin::apfsread::Omap::open(&c, q(&sbb, 0x80)).unwrap();
            let rootb = c.read_raw(vom.lookup(&c, q(&sbb, 0x88), c.xid()).unwrap().unwrap().paddr).unwrap();
            let toc_v = |slot: usize| 4096 - 40 - u16::from_le_bytes(rootb[56 + 8 * slot + 4..56 + 8 * slot + 6].try_into().unwrap()) as usize;
            let times = VolumeTimes { formatted: q(&sbb, 0x130), root: q(&rootb, toc_v(1) + 8), private: q(&rootb, toc_v(0) + 8), modified: q(&sbb, 0x100) };
            nx.create_volume(&NewVolume { name: name.to_string(), role: *role, encrypted: false, e_apfs: true, times, uid: 0, gid: 0, key_os_version: 0, size_bytes: *size }).unwrap();
            nx.commit().unwrap();
            nx.unmount().unwrap();
        }
        let mut bad = Vec::new();
        let l = fm.layout;
        let mid = l.metazone().unwrap().1;
        let mut blks: Vec<u64> = (0..=l.desc_base + l.desc_blocks).chain(l.data_base..l.data_base + 120).chain(l.ip_bm_base..l.ip_bm_base + 16).chain(l.ip_base..l.ip_base + 40).chain(mid - 2..mid + 200).collect();
        blks.sort();
        blks.dedup();
        for blk in blks {
            let mut a = vec![0u8; 4096];
            sink.read_at(blk * 4096, &mut a).unwrap();
            let b = rd(blk);
            if a != b {
                let at: Vec<usize> = (0..4096).filter(|&i| a[i] != b[i]).collect();
                bad.push(format!("block {blk}: {:x?}", &at[..at.len().min(10)]));
            }
        }
        let _ = std::fs::remove_file(&tmp);
        assert!(bad.is_empty(), "{}", bad.join("; "));
    }

    /// newfs_apfs's own -C and seven -A runs in the restore's order and
    /// with its sizes (GEX_TEST_NEWFS_RESTORE7: its image).
    #[test]
    fn volumes_match_newfs() {
        let Ok(path) = std::env::var("GEX_TEST_NEWFS_RESTORE7") else { return };
        replay(&path, &[("System", 0x1u16, None), ("xART", 0x100, Some(10_485_760)), ("Hardware", 0x140, Some(6_291_456)), ("Preboot", 0x10, None), ("Update", 0xc0, None), ("Data", 0x40, None), ("User", 0x2, None)]);
    }

    /// Fourteen runs (GEX_TEST_NEWFS_RUNS14: the restore's seven with
    /// their sizes, then seven of no role): the free queues drain from the
    /// eleventh transaction on and the blocks they release are reused.
    #[test]
    fn draining_matches_newfs() {
        let Ok(path) = std::env::var("GEX_TEST_NEWFS_RUNS14") else { return };
        let mut vols = vec![("System", 0x1u16, None), ("xART", 0x100, Some(10_485_760)), ("Hardware", 0x140, Some(6_291_456)), ("Preboot", 0x10, None), ("Update", 0xc0, None), ("Data", 0x40, None), ("User", 0x2, None)];
        vols.extend(["V8", "V9", "V10", "V11", "V12", "V13", "V14"].iter().map(|n| (*n, 0u16, None)));
        replay(&path, &vols);
    }
}
