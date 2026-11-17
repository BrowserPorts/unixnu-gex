//! APFS's transactions on a mounted container, as APFS 2236.140.6 runs
//! them (the erase ramdisk's `newfs_apfs`, which carries the same code as
//! the kernelcache's kext, measured run for run against this): allocation
//! from the metadata zone, the space manager's copy-on-write of its
//! chunk-info blocks and bitmaps into the internal pool, the free queues
//! that hold what a transaction frees, the container object map's
//! rewrite, and the checkpoint each transaction ends with.
//!
//! What a transaction does, in order:
//!
//! - the first change to a chunk in a transaction moves its chunk-info
//!   block (once a transaction) and then its bitmap to the internal
//!   pool's first unused blocks, the old blocks going to the pool's free
//!   queue (a block freed right after another in the same transaction
//!   extends its entry);
//! - metadata is allocated from the metadata zone's upper half, the first
//!   free block from where the last allocation ended;
//! - at the flush, a changed container object map is written to two new
//!   blocks and its old two go to the main free queue; the changed
//!   chunk-info blocks and bitmaps are written; the pool's bitmap goes to
//!   the next block of its ring (the one it leaves joins the ring's free
//!   list's tail); then the checkpoint: the space manager, reaper and free
//!   queues (by object identifier) in the data area, the checkpoint map and
//!   a copy of the superblock in the descriptor area;
//! - a free queue's tree is made, its identifier the container's next,
//!   when the first block is freed to it.
//!
//! `nx_counters[0]` (`NX_CNTR_OBJ_CKSUM_SET`) counts the checksums set at
//! three sites: objects written through the object cache (A, 0x100035450),
//! ephemeral objects and the superblock written to block 0 (B,
//! 0x10003be14, the value stored including its own count), and raw
//! buffers, the superblock copy and checkpoint map among them (C,
//! 0x10003be40, the copy stored before its own count). A mount takes the
//! count from the newest checkpoint's copy.
//!
//! What is not implemented is refused: a free queue or object map that
//! outgrows one node, the checkpoint rings wrapping, the free queues'
//! draining, chunk-info address blocks, Fusion.

use super::container::{empty_fixed_root, Formatted, Layout, NX_CLEANLY_UNMOUNTED};
use super::{put_header, set_checksum, Put, Sink};
use crate::darwin::apfsread::otype;
use std::collections::BTreeMap;

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
const BTOFF_INVALID: u16 = 0xffff;

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

/// A free queue (`spaceman_free_queue_t`) and its records.
#[derive(Default)]
struct FreeQueue {
    oid: u64,
    limit: u16,
    /// (xid, first block) -> blocks.
    entries: BTreeMap<(u64, u64), u64>,
}

/// A chunk's state (`chunk_info_t`) and its bitmap once read.
struct Chunk {
    xid: u64,
    free: u64,
    bitmap_addr: u64,
    bitmap: Option<Vec<u8>>,
    dirty: bool,
}

/// A mounted container.
pub struct Nx<'a> {
    sink: &'a dyn Sink,
    pub l: Layout,
    pub uuid: [u8; 16],
    pub mode: Mode,
    /// The transaction in progress (one past the last checkpoint's when
    /// none is).
    pub xid: u64,
    pub next_oid: u64,
    counter: u64,
    newest_mounted: u64,
    desc_index: u64,
    desc_len: u64,
    data_index: u64,
    data_len: u64,
    chunks: Vec<Chunk>,
    cib_addr: Vec<u64>,
    cib_xid: Vec<u64>,
    cib_dirty: Vec<bool>,
    ip_used: Vec<bool>,
    ipbm_index: u16,
    ipbm_next: Vec<u16>,
    ipbm_head: u16,
    ipbm_tail: u16,
    fq: [FreeQueue; 2],
    sm_free: u64,
    datazone: [(u64, u64); 4],
    meta_cursor: u64,
    omap: BTreeMap<(u64, u64), (u32, u32, u64)>,
    omap_addr: u64,
    omap_dirty: bool,
    pub fs_oid: Vec<u64>,
    rw_mounted: bool,
}

const FQ_IP: usize = 0;
const FQ_MAIN: usize = 1;

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
                let q = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
                chunks.push(Chunk { xid: q(o), free: u64::from(u32::from_le_bytes(b[o + 20..o + 24].try_into().unwrap())), bitmap_addr: q(o + 24), bitmap: None, dirty: false });
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
        let mut ipbm_next: Vec<u16> = (0..l.ip_bm_count).map(|i| if i == 0 || i + 1 == l.ip_bm_count { IP_BM_INDEX_INVALID } else { (i + 1) as u16 }).collect();
        ipbm_next[0] = IP_BM_INDEX_INVALID;
        let sm_free = chunks.iter().map(|c| c.free).sum();
        Ok(Nx {
            sink,
            l,
            uuid,
            mode,
            xid: 2,
            next_oid: 0x402,
            counter: super::container::format_copy_count(&l)?,
            newest_mounted: 0,
            desc_index: 0,
            desc_len: 2,
            data_index: 0,
            data_len: l.sm_bytes / bs + 1,
            chunks,
            cib_xid: vec![1; l.cibs as usize],
            cib_dirty: vec![false; l.cibs as usize],
            cib_addr,
            ip_used,
            ipbm_index: 0,
            ipbm_next,
            ipbm_head: 1,
            ipbm_tail: (l.ip_bm_count - 1) as u16,
            fq: [FreeQueue { limit: l.fq_ip_limit as u16, ..Default::default() }, FreeQueue { limit: l.fq_main_limit as u16, ..Default::default() }],
            sm_free,
            datazone: [(0, 0); 4],
            meta_cursor: l.first_metadata_block(),
            omap: BTreeMap::new(),
            omap_addr: f.omap,
            omap_dirty: false,
            fs_oid: vec![0; l.max_file_systems as usize],
            rw_mounted: false,
        })
    }

    fn count(&mut self, _site: Site) -> u64 {
        self.counter += 1;
        self.counter
    }

    /// The read-write mount: block 0 rewritten (its last state, not
    /// cleanly unmounted), the allocation zones chosen
    /// (`spaceman_allocation_init`), and the newest mounting version
    /// raised to this APFS's. `newfs_apfs` does this at each run; the
    /// kernel once.
    pub fn mount_rw(&mut self) -> Result<(), String> {
        if self.rw_mounted {
            return Ok(());
        }
        // Block 0 as the last checkpoint left it, the clean flag cleared.
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
        if self.datazone == [(0, 0); 4] {
            self.datazone = first_mount_datazones(&self.l, &self.chunks)?;
        }
        self.newest_mounted = self.newest_mounted.max(APFS_VERSION);
        self.rw_mounted = true;
        Ok(())
    }

    /// A new object identifier.
    pub fn new_oid(&mut self) -> u64 {
        let o = self.next_oid;
        self.next_oid += 1;
        o
    }

    fn ip_alloc(&mut self) -> Result<u64, String> {
        let i = self.ip_used.iter().position(|u| !u).ok_or("the internal pool is full")?;
        self.ip_used[i] = true;
        Ok(self.l.ip_base + i as u64)
    }

    /// Frees `n` blocks from `paddr` to a free queue in this transaction.
    fn fq_free(&mut self, q: usize, paddr: u64, n: u64) {
        if self.fq[q].oid == 0 {
            self.fq[q].oid = self.new_oid();
        }
        let xid = self.xid;
        let prev = self.fq[q].entries.range((xid, 0)..=(xid, paddr)).next_back().map(|(k, v)| (*k, *v));
        match prev {
            Some((k, len)) if k.1 + len == paddr => {
                self.fq[q].entries.insert(k, len + n);
            }
            _ => {
                self.fq[q].entries.insert((xid, paddr), n);
            }
        }
    }

    /// The first change to chunk `c` in this transaction: its chunk-info
    /// block and bitmap move to new pool blocks.
    fn touch_chunk(&mut self, c: usize) -> Result<(), String> {
        if self.chunks[c].xid == self.xid {
            return Ok(());
        }
        let cib = c / self.l.chunks_per_cib as usize;
        if self.cib_xid[cib] != self.xid {
            let new = self.ip_alloc()?;
            let old = self.cib_addr[cib];
            self.fq_free(FQ_IP, old, 1);
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
            self.fq_free(FQ_IP, old, 1);
        } else {
            self.chunks[c].bitmap = Some(vec![0u8; bs as usize]);
        }
        let ch = &mut self.chunks[c];
        ch.bitmap_addr = new;
        ch.xid = self.xid;
        ch.dirty = true;
        Ok(())
    }

    fn block_used(&mut self, b: u64) -> Result<bool, String> {
        let bpc = self.l.blocks_per_chunk;
        let c = (b / bpc) as usize;
        let ch = &mut self.chunks[c];
        if ch.bitmap_addr == 0 {
            return Ok(false);
        }
        if ch.bitmap.is_none() {
            let mut buf = vec![0u8; self.l.bs as usize];
            self.sink.read_at(ch.bitmap_addr * self.l.bs, &mut buf)?;
            ch.bitmap = Some(buf);
        }
        let i = (b % bpc) as usize;
        Ok(ch.bitmap.as_ref().unwrap()[i / 8] & (1 << (i % 8)) != 0)
    }

    /// One block of metadata from the metadata zone's upper half.
    pub fn alloc_meta(&mut self) -> Result<u64, String> {
        let end = self.l.metazone().map_or(self.l.blocks, |z| z.2);
        let mut b = self.meta_cursor;
        while b < end && self.block_used(b)? {
            b += 1;
        }
        if b >= end {
            return Err("not implemented: allocating metadata past the metadata zone".into());
        }
        let c = (b / self.l.blocks_per_chunk) as usize;
        self.touch_chunk(c)?;
        let i = (b % self.l.blocks_per_chunk) as usize;
        let ch = &mut self.chunks[c];
        ch.bitmap.as_mut().unwrap()[i / 8] |= 1 << (i % 8);
        ch.free -= 1;
        self.sm_free -= 1;
        self.meta_cursor = b + 1;
        Ok(b)
    }

    /// Writes an object through the object cache (its checksum counted at
    /// site A).
    pub fn write_cached(&mut self, paddr: u64, mut b: Vec<u8>) -> Result<(), String> {
        self.count(Site::Cached);
        set_checksum(&mut b);
        self.sink.write_at(paddr * self.l.bs, &b)
    }

    /// Maps virtual `oid` at this transaction to `paddr` in the container's
    /// object map.
    pub fn omap_set(&mut self, oid: u64, paddr: u64) {
        self.omap.insert((oid, self.xid), (0, self.l.bs as u32, paddr));
        self.omap_dirty = true;
    }

    /// The transaction's flush and checkpoint.
    pub fn commit(&mut self) -> Result<(), String> {
        let bs = self.l.bs;
        let bsz = bs as usize;
        let xid = self.xid;
        if self.omap_dirty {
            let old = self.omap_addr;
            let phys = self.alloc_meta()?;
            let tree = self.alloc_meta()?;
            self.fq_free(FQ_MAIN, old, 2);
            let mut t = empty_fixed_root(bs, tree, xid, otype::PHYSICAL | otype::BTREE, otype::OMAP_TREE_SUBTYPE, 0x12, 16, 16);
            let kv: Vec<(Vec<u8>, Option<Vec<u8>>)> = self
                .omap
                .iter()
                .map(|((o, x), (f, s, p))| {
                    let mut k = o.to_le_bytes().to_vec();
                    k.extend_from_slice(&x.to_le_bytes());
                    let mut v = f.to_le_bytes().to_vec();
                    v.extend_from_slice(&s.to_le_bytes());
                    v.extend_from_slice(&p.to_le_bytes());
                    (k, Some(v))
                })
                .collect();
            fill_fixed_leaf(&mut t, &kv, 16, 16)?;
            self.write_cached(tree, t)?;
            let mut o = vec![0u8; bsz];
            put_header(&mut o, phys, xid, otype::PHYSICAL | otype::OMAP, 0);
            o.put32(0x20, 1);
            o.put32(0x28, otype::PHYSICAL | otype::BTREE);
            o.put32(0x2c, otype::PHYSICAL | otype::BTREE);
            o.put64(0x30, tree);
            self.write_cached(phys, o)?;
            self.omap_addr = phys;
            self.omap_dirty = false;
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
            self.write_cached(addr, b)?;
            self.cib_dirty[cib] = false;
        }
        for c in 0..self.chunks.len() {
            if self.chunks[c].dirty {
                let ch = &mut self.chunks[c];
                ch.dirty = false;
                self.sink.write_at(ch.bitmap_addr * bs, ch.bitmap.as_ref().unwrap())?;
            }
        }
        // The pool's bitmap to the ring's next block.
        let new = self.ipbm_head;
        if new == IP_BM_INDEX_INVALID {
            return Err("the internal pool bitmap ring has no free block".into());
        }
        self.ipbm_head = self.ipbm_next[new as usize];
        self.ipbm_next[new as usize] = IP_BM_INDEX_INVALID;
        let old = self.ipbm_index;
        self.ipbm_next[self.ipbm_tail as usize] = old;
        self.ipbm_tail = old;
        self.ipbm_next[old as usize] = IP_BM_INDEX_INVALID;
        self.ipbm_index = new;
        let mut ipbm = vec![0u8; bsz];
        for (i, _) in self.ip_used.iter().enumerate().filter(|(_, u)| **u) {
            ipbm[i / 8] |= 1 << (i % 8);
        }
        self.sink.write_at((self.l.ip_bm_base + u64::from(new)) * bs, &ipbm)?;

        // The checkpoint.
        let desc_index = self.desc_index + self.desc_len;
        let data_index = self.data_index + self.data_len;
        let mut eph: Vec<(u32, u32, u64, Vec<u8>)> = Vec::new();
        let sm = self.spaceman_bytes();
        eph.push((otype::EPHEMERAL | 0x5, 0, OID_SPACEMAN, sm));
        let mut reaper = vec![0u8; bsz];
        put_header(&mut reaper, OID_REAPER, xid, otype::EPHEMERAL | 0x11, 0);
        reaper.put64(0x20, 1);
        reaper.put32(0x40, 1);
        reaper.put32(0x6c, bs as u32 - 0x70);
        eph.push((otype::EPHEMERAL | 0x11, 0, OID_REAPER, reaper));
        for q in 0..2 {
            if self.fq[q].oid != 0 {
                let b = self.fq_node(q)?;
                eph.push((otype::EPHEMERAL | otype::BTREE, SPACEMAN_FREE_QUEUE, self.fq[q].oid, b));
            }
        }
        eph.sort_by_key(|e| e.2);
        let data_blocks: u64 = eph.iter().map(|e| e.3.len() as u64 / bs).sum();
        if desc_index + 2 > self.l.desc_blocks || data_index + data_blocks > self.l.data_blocks {
            return Err("not implemented: a checkpoint ring wrapping".into());
        }
        let mut map = vec![0u8; bsz];
        let map_paddr = self.l.desc_base + desc_index;
        put_header(&mut map, map_paddr, xid, otype::PHYSICAL | otype::CHECKPOINT_MAP, 0);
        map.put32(0x20, 1);
        map.put32(0x24, eph.len() as u32);
        let mut at = self.l.data_base + data_index;
        for (i, (ty, sub, oid, mut b)) in eph.into_iter().enumerate() {
            let o = 0x28 + 40 * i;
            map.put32(o, ty);
            map.put32(o + 4, sub);
            map.put32(o + 8, b.len() as u32);
            map.put64(o + 0x18, oid);
            map.put64(o + 0x20, at);
            self.count(Site::Ephemeral);
            set_checksum(&mut b);
            self.sink.write_at(at * bs, &b)?;
            at += b.len() as u64 / bs;
        }
        self.desc_index = desc_index;
        self.data_index = data_index;
        self.data_len = data_blocks;
        let mut sb = self.superblock()?;
        sb.put64(0x3d8, self.counter);
        self.count(Site::Raw);
        set_checksum(&mut sb);
        self.sink.write_at((map_paddr + 1) * bs, &sb)?;
        self.count(Site::Raw);
        set_checksum(&mut map);
        self.sink.write_at(map_paddr * bs, &map)?;
        self.xid += 1;
        Ok(())
    }

    /// The superblock as the latest checkpoint has it.
    fn superblock(&self) -> Result<Vec<u8>, String> {
        let bs = self.l.bs as usize;
        let mut sb = vec![0u8; bs];
        self.sink.read_at((self.l.desc_base + 1) * self.l.bs, &mut sb)?;
        put_header(&mut sb, 1, self.xid, otype::EPHEMERAL | otype::NX_SUPERBLOCK, 0);
        sb.put64(0x58, self.next_oid);
        sb.put64(0x60, self.xid + 1);
        sb.put32(0x80, (self.desc_index + self.desc_len) as u32);
        sb.put32(0x84, (self.data_index + self.data_len) as u32);
        sb.put32(0x88, self.desc_index as u32);
        sb.put32(0x8c, self.desc_len as u32);
        sb.put32(0x90, self.data_index as u32);
        sb.put32(0x94, self.data_len as u32);
        sb.put64(0xa0, self.omap_addr);
        for (i, &o) in self.fs_oid.iter().enumerate() {
            sb.put64(0xb8 + 8 * i, o);
        }
        sb.put64(0x4f0, 0);
        sb.put64(0x568, self.newest_mounted);
        Ok(sb)
    }

    /// The unmount: block 0 from the last checkpoint, cleanly unmounted.
    pub fn unmount(&mut self) -> Result<(), String> {
        let mut sb = vec![0u8; self.l.bs as usize];
        self.sink.read_at((self.l.desc_base + self.desc_index + 1) * self.l.bs, &mut sb)?;
        let c = self.count(Site::Ephemeral);
        sb.put64(0x3d8, c);
        sb.put64(0x4f0, NX_CLEANLY_UNMOUNTED);
        set_checksum(&mut sb);
        self.sink.write_at(0, &sb)?;
        if self.mode == Mode::Userspace {
            // The next run's mount takes the count from the copy.
            self.counter = u64::from_le_bytes(sb[0x3d8..0x3e0].try_into().unwrap());
            let mut copy = vec![0u8; 8];
            self.sink.read_at((self.l.desc_base + self.desc_index + 1) * self.l.bs + 0x3d8, &mut copy)?;
            self.counter = u64::from_le_bytes(copy.try_into().unwrap());
            self.rw_mounted = false;
        }
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
            sm.put64(base, f.entries.values().sum());
            sm.put64(base + 8, f.oid);
            sm.put64(base + 16, f.entries.keys().next().map_or(0, |k| k.0));
            sm.put16(base + 24, f.limit);
        }
        sm.put16(0x140, self.ipbm_head);
        sm.put16(0x142, self.ipbm_tail);
        sm.put32(0x144, l.xid_offset as u32);
        sm.put32(0x148, l.bitmap_offset as u32);
        sm.put32(0x14c, l.free_next_offset as u32);
        sm.put32(0x150, 1);
        sm.put32(0x154, 0x9d8);
        // sm_datazone[SD_MAIN][size - 1]: current boundaries and zone id.
        for (z, &(start, end)) in self.datazone.iter().enumerate() {
            if end == 0 {
                continue;
            }
            let o = 0x158 + 136 * z;
            sm.put64(o, start);
            sm.put64(o + 8, end);
            sm.put16(o + 128, z as u16 + 1);
        }
        sm.put64(l.xid_offset as usize, self.xid);
        sm.put16(l.bitmap_offset as usize, self.ipbm_index);
        for (i, &n) in self.ipbm_next.iter().enumerate() {
            sm.put16(l.free_next_offset as usize + 2 * i, n);
        }
        for (i, &a) in self.cib_addr.iter().enumerate() {
            sm.put64(l.addr_offset as usize + 8 * i, a);
        }
        sm
    }

    fn fq_node(&self, q: usize) -> Result<Vec<u8>, String> {
        let f = &self.fq[q];
        let mut b = empty_fixed_root(self.l.bs, f.oid, self.xid, otype::EPHEMERAL | otype::BTREE, SPACEMAN_FREE_QUEUE, 0xe, 16, 8);
        let kv: Vec<(Vec<u8>, Option<Vec<u8>>)> = f
            .entries
            .iter()
            .map(|((x, p), n)| {
                let mut k = x.to_le_bytes().to_vec();
                k.extend_from_slice(&p.to_le_bytes());
                (k, (*n != 1).then(|| n.to_le_bytes().to_vec()))
            })
            .collect();
        fill_fixed_leaf(&mut b, &kv, 16, 8)?;
        Ok(b)
    }

    /// `apfs_newfs`: a volume added (`newfs_apfs -A`), in its own
    /// transaction.
    pub fn create_volume(&mut self, v: &NewVolume) -> Result<u64, String> {
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
        let vol_oid = self.new_oid();
        let omap = self.alloc_meta()?;
        let omap_tree = self.alloc_meta()?;
        let extentref = self.alloc_meta()?;
        let snapmeta = self.alloc_meta()?;
        let root = self.alloc_meta()?;
        let root_oid = self.new_oid();
        let sbaddr = self.alloc_meta()?;

        // The root and private directories.
        let mut fsroot = vec![0u8; bs as usize];
        put_header(&mut fsroot, root_oid, xid, otype::BTREE, FSTREE);
        let recs = initial_records(v);
        fill_var_leaf(&mut fsroot, &recs, 0x42)?;
        self.write_cached(root, fsroot)?;

        let mut sb = vec![0u8; bs as usize];
        put_header(&mut sb, vol_oid, xid, otype::FS, 0);
        sb.put32(0x20, crate::darwin::apfsread::APFS_MAGIC);
        sb.put32(0x24, index as u32);
        sb.put64(0x28, 0x2);
        let unwritten = v.e_apfs && ![0x1u16, 0x4, 0x8, 0x10, 0x20, 0x80, 0xc0, 0x100, 0x140, 0x280, 0x2c0].contains(&v.role);
        sb.put64(0x38, 0x8 | if unwritten { 0x80 } else { 0 });
        sb.put64(0x58, 5);
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
        sb.put64(0x90, extentref);
        sb.put64(0x98, snapmeta);
        sb.put64(0xb0, 0x10);
        let mut uuid = *b"apfsuuid\0\0volum\0";
        uuid[8..10].copy_from_slice(&v.role.to_be_bytes());
        uuid[15] = index as u8;
        sb[0xf0..0x100].copy_from_slice(&uuid);
        sb.put64(0x100, v.times.modified);
        sb.put64(0x108, if v.encrypted { 0 } else { 1 });
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
        if v.encrypted {
            return Err("not implemented: an encrypted volume (its keys are the device's Secure Enclave's)".into());
        }
        self.write_cached(sbaddr, sb)?;

        // The volume's object map: its root tree's node.
        let mut t = empty_fixed_root(bs, omap_tree, xid, otype::PHYSICAL | otype::BTREE, otype::OMAP_TREE_SUBTYPE, 0x12, 16, 16);
        let mut k = root_oid.to_le_bytes().to_vec();
        k.extend_from_slice(&xid.to_le_bytes());
        let mut val = 0u32.to_le_bytes().to_vec();
        val.extend_from_slice(&(bs as u32).to_le_bytes());
        val.extend_from_slice(&root.to_le_bytes());
        fill_fixed_leaf(&mut t, &[(k, Some(val))], 16, 16)?;
        self.write_cached(omap_tree, t)?;
        let mut o = vec![0u8; bs as usize];
        put_header(&mut o, omap, xid, otype::PHYSICAL | otype::OMAP, 0);
        o.put32(0x28, otype::PHYSICAL | otype::BTREE);
        o.put32(0x2c, otype::PHYSICAL | otype::BTREE);
        o.put64(0x30, omap_tree);
        self.write_cached(omap, o)?;
        for (addr, sub) in [(extentref, BLOCKREFTREE), (snapmeta, SNAPMETATREE)] {
            let mut n = vec![0u8; bs as usize];
            put_header(&mut n, addr, xid, otype::PHYSICAL | otype::BTREE, sub);
            fill_var_leaf(&mut n, &[], 0x52)?;
            self.write_cached(addr, n)?;
        }
        self.fs_oid[index] = vol_oid;
        self.omap_set(vol_oid, sbaddr);
        Ok(vol_oid)
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

/// A root-and-leaf node of variable-size records, inserted in the order
/// given: keys from the table of contents' end forwards, values from the
/// value area's end backwards; the table of contents (8 entries' room, or
/// more by 8 at a time) in key order.
fn fill_var_leaf(b: &mut [u8], recs: &[(Vec<u8>, Vec<u8>)], bt_flags: u32) -> Result<(), String> {
    let bsz = b.len();
    let avail = bsz - 56 - 40;
    let toc_entries = recs.len().div_ceil(8).max(1) * 8;
    let toc = toc_entries * 8;
    let mut order: Vec<usize> = (0..recs.len()).collect();
    order.sort_by(|&x, &y| fs_key_cmp(&recs[x].0, &recs[y].0));
    let (mut koff, mut voff) = (0usize, 0usize);
    let mut locs = vec![(0u16, 0u16, 0u16, 0u16); recs.len()];
    let kstart = 56 + toc;
    let vend = bsz - 40;
    for (i, (k, v)) in recs.iter().enumerate() {
        if koff + k.len() + voff + v.len() + toc > avail {
            return Err("not implemented: a B-tree node splitting".into());
        }
        b[kstart + koff..kstart + koff + k.len()].copy_from_slice(k);
        voff += v.len();
        b[vend - voff..vend - voff + v.len()].copy_from_slice(v);
        locs[i] = (koff as u16, k.len() as u16, voff as u16, v.len() as u16);
        koff += k.len();
    }
    for (slot, &i) in order.iter().enumerate() {
        let (ko, kl, vo, vl) = locs[i];
        let o = 56 + 8 * slot;
        b.put16(o, ko);
        b.put16(o + 2, kl);
        b.put16(o + 4, vo);
        b.put16(o + 6, vl);
    }
    b.put16(0x20, 3);
    b.put32(0x24, recs.len() as u32);
    b.put16(0x28, 0);
    b.put16(0x2a, toc as u16);
    b.put16(0x2c, koff as u16);
    b.put16(0x2e, (avail - toc - koff - voff) as u16);
    b.put16(0x30, BTOFF_INVALID);
    b.put16(0x32, 0);
    b.put16(0x34, BTOFF_INVALID);
    b.put16(0x36, 0);
    let i = bsz - 40;
    b.put32(i, bt_flags);
    b.put32(i + 4, bsz as u32);
    b.put32(i + 16, recs.iter().map(|r| r.0.len()).max().unwrap_or(0) as u32);
    b.put32(i + 20, recs.iter().map(|r| r.1.len()).max().unwrap_or(0) as u32);
    b.put64(i + 24, recs.len() as u64);
    b.put64(i + 32, 1);
    Ok(())
}

/// The file-system tree's key order: object identifier, then record
/// type, then (for directory records) the hash and name.
fn fs_key_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    let ha = u64::from_le_bytes(a[..8].try_into().unwrap());
    let hb = u64::from_le_bytes(b[..8].try_into().unwrap());
    let (ia, ta) = (ha & 0x0fff_ffff_ffff_ffff, ha >> 60);
    let (ib, tb) = (hb & 0x0fff_ffff_ffff_ffff, hb >> 60);
    ia.cmp(&ib).then(ta.cmp(&tb)).then_with(|| {
        if a.len() >= 12 && b.len() >= 12 {
            let xa = u32::from_le_bytes(a[8..12].try_into().unwrap()) >> 10;
            let xb = u32::from_le_bytes(b[8..12].try_into().unwrap()) >> 10;
            xa.cmp(&xb).then_with(|| a[12..].cmp(&b[12..]))
        } else {
            a[8..].cmp(&b[8..])
        }
    })
}

/// Records into an empty fixed-size root-and-leaf node, in the order
/// given (sorted): keys forwards, values backwards from the value area's
/// end, a record without a value (a ghost) taking none.
fn fill_fixed_leaf(b: &mut [u8], recs: &[(Vec<u8>, Option<Vec<u8>>)], k: usize, v: usize) -> Result<(), String> {
    let bsz = b.len();
    let toc = u16::from_le_bytes(b[0x2a..0x2c].try_into().unwrap()) as usize;
    if recs.len() * 4 > toc {
        return Err("not implemented: a fixed-size B-tree outgrowing its root node".into());
    }
    let kstart = 56 + toc;
    let vend = bsz - 40;
    let mut voff = 0usize;
    let mut longest_val = 0;
    for (i, (key, val)) in recs.iter().enumerate() {
        b[kstart + k * i..kstart + k * (i + 1)].copy_from_slice(key);
        b.put16(56 + 4 * i, (k * i) as u16);
        match val {
            Some(val) => {
                voff += v;
                b[vend - voff..vend - voff + v].copy_from_slice(val);
                b.put16(56 + 4 * i + 2, voff as u16);
                longest_val = v;
            }
            None => b.put16(56 + 4 * i + 2, BTOFF_INVALID),
        }
    }
    let avail = bsz - 56 - 40;
    b.put32(0x24, recs.len() as u32);
    b.put16(0x2c, (k * recs.len()) as u16);
    b.put16(0x2e, (avail - toc - k * recs.len() - voff) as u16);
    let i = bsz - 40;
    b.put32(i + 16, if recs.is_empty() { 0 } else { k as u32 });
    b.put32(i + 20, longest_val as u32);
    b.put64(i + 24, recs.len() as u64);
    Ok(())
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

    /// newfs_apfs's own -C and seven -A runs in the restore's order
    /// (GEX_TEST_NEWFS_RESTORE7: its image), byte for byte, given its uuid
    /// and clock readings.
    #[test]
    fn volumes_match_newfs() {
        let Ok(path) = std::env::var("GEX_TEST_NEWFS_RESTORE7") else { return };
        use crate::darwin::apfsread::Medium;
        use std::os::unix::fs::FileExt;
        let want = std::fs::File::open(&path).unwrap();
        let rd = |blk: u64| {
            let mut b = vec![0u8; 4096];
            want.read_exact_at(&mut b, blk * 4096).unwrap();
            b
        };
        let b0 = rd(0);
        let uuid: [u8; 16] = b0[0x48..0x58].try_into().unwrap();
        let blocks = 15_625_000u64;
        let tmp = std::env::temp_dir().join(format!("gex-apfswrite-r7-{}", std::process::id()));
        let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&tmp).unwrap();
        f.set_len(blocks * 4096).unwrap();
        let sink = crate::darwin::apfswrite::HostFile(f, blocks * 4096);
        let fm = super::super::container::format(&sink, 4096, blocks, uuid).unwrap();
        let mut nx = Nx::formatted(&sink, &fm, uuid, Mode::Userspace).unwrap();
        let q = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        // The six-object volumes are 8 blocks apart from the zone's middle.
        let mid = fm.layout.metazone().unwrap().1;
        let vols = [("System", 0x1u16), ("xART", 0x100), ("Hardware", 0x140), ("Preboot", 0x10), ("Update", 0xc0), ("Data", 0x40), ("User", 0x2)];
        for (k, (name, role)) in vols.iter().enumerate() {
            let sbb = rd(mid + 7 + 8 * k as u64);
            let rootb = rd(mid + 6 + 8 * k as u64);
            // The clock readings: the format's start, the directories'
            // creation (their records' date_added), the end.
            let tv = |o: usize| q(&rootb, o);
            let toc_v = |slot: usize| 4096 - 40 - u16::from_le_bytes(rootb[56 + 8 * slot + 4..56 + 8 * slot + 6].try_into().unwrap()) as usize;
            let times = VolumeTimes { formatted: q(&sbb, 0x130), root: tv(toc_v(1) + 8), private: tv(toc_v(0) + 8), modified: q(&sbb, 0x100) };
            nx.mount_rw().unwrap();
            nx.create_volume(&NewVolume { name: name.to_string(), role: *role, encrypted: false, e_apfs: true, times, uid: 0, gid: 0, key_os_version: 0 }).unwrap();
            nx.commit().unwrap();
            nx.unmount().unwrap();
        }
        let mut bad = Vec::new();
        let l = fm.layout;
        let mut blks: Vec<u64> = (0..=l.desc_base + 16).chain(l.data_base..l.data_base + 30).chain(l.ip_bm_base..l.ip_bm_base + 16).chain(l.ip_base..l.ip_base + 24).chain(mid - 2..mid + 60).collect();
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
}
