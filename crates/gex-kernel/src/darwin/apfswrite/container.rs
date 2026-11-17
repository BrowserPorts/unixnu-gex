//! A container as `newfs_apfs -C` makes it (the erase ramdisk's, APFS
//! 2236.140.6): its sizing (0x100010208), the space manager, reaper and
//! object map it starts with, and the one checkpoint it writes.
//!
//! The sizing, with `bs` the block size and `N` the container's blocks
//! (no Fusion tier, no requested volume count):
//!
//! - a chunk is `bs * 8` blocks (one bitmap block's bits); a chunk-info
//!   block holds `(bs - 0x28) / 32` chunk infos, an address block
//!   `(bs - 0x28) / 8` addresses; one address block is never made (its
//!   addresses fit the space manager);
//! - the internal pool is 3 blocks per chunk, chunk-info block and address
//!   block; its bitmap takes `ceil(((pool + 63) / 8 & ~7) / bs)` blocks,
//!   kept in a ring 16 times that size (`sm_ip_bm_tx_multiplier`);
//! - the free queues' node limits follow the counts they track (see
//!   [`Layout::new`]); `nx_max_file_systems` is one per 512 MiB, at most
//!   100;
//! - the checkpoint areas hold what a transaction can write of ephemeral
//!   objects: two blocks (superblock and map), the main free queue's and
//!   the pool's free queue's limits, the space manager, and 8 blocks for
//!   each volume's minimum (`min(main limit, 8)`); the data area four
//!   times that, the descriptor area four maps' worth and 4;
//! - the descriptor area starts at block 1, the data area after it, the
//!   pool's bitmap ring after that, then the pool. Blocks before the pool's
//!   end are allocated.
//!
//! Metadata is allocated from the metadata zone at the container's end
//! (0x100013fac sizes it, 0x1000140b0 splits it): none below 6 GiB (at
//! 4 KiB blocks), 512 MiB below 16 GiB, else a share of the size (1/32 of
//! the first 64 GiB, 0.8/32 of the next 64, 1/128 of the next 128, 0.8/128
//! beyond), at most a quarter of the container. Its upper half is where
//! `newfs_apfs` and APFS's volume creation allocate, in order from its
//! start; without a zone, the first free block after the reserved ones.

use super::{cdiv, put_header, set_checksum, Put, Sink};
use crate::darwin::apfsread::otype;

/// `NX_MAX_FILE_SYSTEMS`, `NX_MAX_FILE_SYSTEM_EPH_STRUCTS`.
const NX_MAX_FILE_SYSTEMS: u64 = 100;
const NX_MAX_FILE_SYSTEM_EPH_STRUCTS: u64 = 4;
/// `nx_superblock_t`'s `NX_MAGIC`; the space manager's and reaper's fixed
/// object identifiers come from `nx_next_oid`, which starts at
/// `OID_RESERVED_COUNT` (1024) (0x1000106c8).
const OID_RESERVED_COUNT: u64 = 0x400;
/// `SPACEMAN_IP_BM_TX_MULTIPLIER`, `SPACEMAN_IP_BM_BLOCK_COUNT_MAX`,
/// `SPACEMAN_IP_BM_INDEX_INVALID`.
const IP_BM_TX_MULTIPLIER: u64 = 16;
const IP_BM_BLOCK_COUNT_MAX: u64 = 0xfffe;
const IP_BM_INDEX_INVALID: u16 = 0xffff;
/// `sizeof(spaceman_phys_t)` (`sm_struct_size`), where its arrays start.
const SPACEMAN_STRUCT_SIZE: u64 = 0x9d8;
/// `SM_FLAG_VERSIONED`; `sm_version`.
const SM_FLAG_VERSIONED: u32 = 1;
const SM_VERSION: u32 = 1;
/// `NR_BHM_FLAG`; the reaper's header and fields before its state buffer.
const NR_BHM_FLAG: u32 = 1;
const REAPER_HEADER: u32 = 0x70;
/// `OMAP_MANUALLY_MANAGED`.
const OMAP_MANUALLY_MANAGED: u32 = 1;
/// `CHECKPOINT_MAP_LAST`.
const CHECKPOINT_MAP_LAST: u32 = 1;
/// `NX_INCOMPAT_VERSION2`.
const NX_INCOMPAT_VERSION2: u64 = 2;
/// The flag block 0 gets when the container is unmounted cleanly
/// (0x10004bb5c sets it, a mount clears it).
pub const NX_CLEANLY_UNMOUNTED: u64 = 2;
/// B-tree flags (`btn_flags`, `bt_flags`).
const BTNODE_ROOT: u16 = 1;
const BTNODE_LEAF: u16 = 2;
const BTNODE_FIXED_KV_SIZE: u16 = 4;
const BTREE_SEQUENTIAL_INSERT: u32 = 2;
const BTREE_PHYSICAL: u32 = 0x10;
/// `sizeof(btree_node_phys_t)`, `sizeof(btree_info_t)`.
const BTNODE_HEADER: usize = 56;
const BTREE_INFO: usize = 40;
/// `BTOFF_INVALID`: an empty free list's offset.
const BTOFF_INVALID: u16 = 0xffff;

/// What `newfs_apfs -C` sizes for a container of `blocks` blocks of `bs`
/// bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub bs: u64,
    pub blocks: u64,
    pub blocks_per_chunk: u64,
    pub chunks_per_cib: u64,
    pub cibs_per_cab: u64,
    pub chunks: u64,
    pub cibs: u64,
    pub cabs: u64,
    pub ip_blocks: u64,
    pub ip_bm_size: u64,
    pub ip_bm_count: u64,
    /// The space manager's bytes (a whole number of blocks).
    pub sm_bytes: u64,
    pub fq_ip_limit: u64,
    pub fq_main_limit: u64,
    pub min_block_count: u64,
    pub max_file_systems: u64,
    pub desc_blocks: u64,
    pub data_blocks: u64,
    pub desc_base: u64,
    pub data_base: u64,
    pub ip_bm_base: u64,
    pub ip_base: u64,
    /// The space manager's arrays: the bitmap blocks' transaction
    /// identifiers, their ring indexes, the ring's free list, and the
    /// chunk-info (or address) block addresses.
    pub xid_offset: u64,
    pub bitmap_offset: u64,
    pub free_next_offset: u64,
    pub addr_offset: u64,
}

impl Layout {
    /// The sizing routine (0x100010208); block sizes outside 4 KiB to
    /// 64 KiB are refused, as it refuses them (EINVAL).
    pub fn new(bs: u64, blocks: u64) -> Result<Layout, String> {
        if !(4096..=65536).contains(&bs) || blocks == 0 {
            return Err(format!("a container of {blocks} blocks of {bs} bytes"));
        }
        let blocks_per_chunk = bs * 8;
        let chunks_per_cib = (bs - 0x28) >> 5;
        let cibs_per_cab = (bs - 0x28) >> 3;
        let chunks = cdiv(blocks, blocks_per_chunk);
        let cibs = cdiv(chunks, chunks_per_cib);
        let cabs = match cdiv(cibs, cibs_per_cab) {
            1 => 0,
            n => n,
        };
        let ip_blocks = 3 * (chunks + cibs + cabs);
        let bm_bytes = ((ip_blocks + 63) >> 3) & !7;
        let ip_bm_size = cdiv(bm_bytes, bs);
        let ip_bm_count = if ip_bm_size < 0x1000 { ip_bm_size * IP_BM_TX_MULTIPLIER } else { IP_BM_BLOCK_COUNT_MAX };
        let idx_bytes = (ip_bm_size * 2 + 6) & !7;
        let next_bytes = (ip_bm_count * 2 + 6) & !7;
        let addrs = if cabs == 0 { cibs } else { cabs };
        let sm_raw = idx_bytes + (ip_bm_size + addrs) * 8 + next_bytes + SPACEMAN_STRUCT_SIZE;
        if sm_raw > 0x10_0000 {
            return Err(format!("a space manager of {sm_raw} bytes"));
        }
        let sm_bytes = cdiv(sm_raw, bs) * bs;
        // How many 16/8 free-queue records a node holds: its space less a
        // table of contents of 4-byte entries for a 28-byte record each,
        // rounded up to 32 bytes, over 48 bytes a record.
        let w = bs - 0x60;
        let toc = ((((w >> 2) & 0x3fff) * 0x4925) >> 15) & 0x3ffc;
        let toc = (toc + 0x1c) & 0x7fe0;
        let per = ((w - toc) * 0xaaaa_aaab) >> 37;
        let cap = 0x20_0000 / bs;
        let scaled = |n: u64, by: u64| {
            if by < 0x4_0000 {
                (n + 0x3f) >> 6
            } else if by < 0x10_0000 {
                (n + 0x1f) >> 5
            } else {
                (n + 0xf) >> 4
            }
        };
        let limit = |v: u64| match cdiv(v, per).min(cap) {
            2 => 3,
            n => n,
        };
        let fq_main_limit = limit(scaled(blocks, blocks));
        let fq_ip_limit = limit(scaled(ip_blocks, blocks));
        let sm_blocks = sm_bytes / bs;
        let sm_extra = sm_blocks.saturating_sub(1);
        let min_block_count = fq_main_limit.min(8);
        let max_file_systems = cdiv(blocks * bs, 1 << 29).min(NX_MAX_FILE_SYSTEMS);
        let need = 2 + fq_main_limit + sm_blocks + fq_ip_limit + sm_extra + 8 * min_block_count * max_file_systems;
        let maps_per_block = ((bs - 0x28) & 0xffff) / 40;
        let desc_blocks = cdiv(need, maps_per_block) * 4 + 4;
        let data_blocks = need * 4;
        let desc_base = 1;
        let data_base = desc_base + desc_blocks;
        let ip_bm_base = data_base + data_blocks;
        let ip_base = ip_bm_base + ip_bm_count;
        let xid_offset = SPACEMAN_STRUCT_SIZE;
        let bitmap_offset = xid_offset + 8 * ip_bm_size;
        let free_next_offset = bitmap_offset + idx_bytes;
        let addr_offset = free_next_offset + next_bytes;
        Ok(Layout {
            bs,
            blocks,
            blocks_per_chunk,
            chunks_per_cib,
            cibs_per_cab,
            chunks,
            cibs,
            cabs,
            ip_blocks,
            ip_bm_size,
            ip_bm_count,
            sm_bytes,
            fq_ip_limit,
            fq_main_limit,
            min_block_count,
            max_file_systems,
            desc_blocks,
            data_blocks,
            desc_base,
            data_base,
            ip_bm_base,
            ip_base,
            xid_offset,
            bitmap_offset,
            free_next_offset,
            addr_offset,
        })
    }

    /// The blocks before the pool's end: allocated from the start.
    pub fn reserved_end(&self) -> u64 {
        self.ip_base + self.ip_blocks
    }

    /// `nx_ephemeral_info[0]`: the minimum block count, the most
    /// ephemeral structures a volume has, and the version (1).
    pub fn ephemeral_info(&self) -> u64 {
        (self.min_block_count << 32) | (NX_MAX_FILE_SYSTEM_EPH_STRUCTS << 16) | 1
    }

    /// The metadata zone's first block, the start of its upper half, and
    /// its end; none for a container under 6 GiB (at 4 KiB blocks).
    pub fn metazone(&self) -> Option<(u64, u64, u64)> {
        let by = self.bs * self.blocks;
        let k = self.bs >> 12;
        if (3 * k) << 31 > by {
            return None;
        }
        const GI64: u64 = 0x10_0000_0000;
        let z = if by >> 34 == 0 {
            0x2000_0000
        } else {
            // 0.8 is APFS's multiply by 0xcccccccccccccccd's high half.
            let four_fifths = |x: u64| ((u128::from(x) * 0xcccc_cccc_cccc_cccd) >> 64) as u64;
            let mut z = by.min(GI64) >> 5;
            if by > GI64 {
                z += four_fifths((by - GI64).min(GI64)) >> 5;
                if by > 2 * GI64 {
                    z += (by - 2 * GI64).min(2 * GI64) >> 7;
                    if by > 4 * GI64 {
                        z += four_fifths(by - 4 * GI64) >> 7;
                    }
                }
            }
            z
        };
        let z = (z * k).min(by / 4);
        let zb = z / self.bs;
        let start = self.blocks - zb;
        let mid = start + ((zb * self.bs) >> 1) / self.bs;
        Some((start, mid, start + (zb * self.bs) / self.bs))
    }

    /// Where metadata allocation starts: the metadata zone's upper half,
    /// or the first block after the reserved ones.
    pub fn first_metadata_block(&self) -> u64 {
        self.metazone().map_or(self.reserved_end(), |(_, mid, _)| mid)
    }
}

/// What a freshly formatted container is: its layout and the blocks the
/// format put its object map in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Formatted {
    pub layout: Layout,
    pub omap: u64,
    pub omap_tree: u64,
}

/// The internal pool's allocation state while formatting: the blocks
/// taken, in order.
struct Pool {
    used: Vec<bool>,
}

impl Pool {
    fn take(&mut self, l: &Layout) -> Result<u64, String> {
        let i = self.used.iter().position(|u| !u).ok_or("the internal pool is full")?;
        self.used[i] = true;
        Ok(l.ip_base + i as u64)
    }
}

/// A chunk's allocation state: its bitmap (once it has one) and free
/// count.
struct Chunk {
    bitmap: Option<(u64, Vec<u8>)>,
    free: u64,
}

/// `newfs_apfs -C` on `sink` (the container partition, `blocks` blocks
/// of `bs` bytes), with `uuid` its `nx_uuid` (newfs makes one with
/// `uuid_generate`, 0x100033618). The medium is assumed zeroed (the
/// restore's DKIOCFORMAT of the whole disk zeroes it before partitioning,
/// so `wipefs`'s zeroing of the container's first and last 2 MiB and of
/// 64 KiB about its middle writes nothing new).
pub fn format(sink: &dyn Sink, bs: u64, blocks: u64, uuid: [u8; 16]) -> Result<Formatted, String> {
    let l = Layout::new(bs, blocks)?;
    if sink.size() < blocks * bs {
        return Err(format!("a {}-byte medium for a container of {} bytes", sink.size(), blocks * bs));
    }
    if l.cabs != 0 {
        return Err("not implemented: formatting a container with chunk-info address blocks (more than one address block's worth of chunk-info blocks)".into());
    }
    let xid = 1u64;
    let bsz = bs as usize;
    let copy_count = format_copy_count(&l)?;
    let mut pool = Pool { used: vec![false; l.ip_blocks as usize] };
    let mut chunks: Vec<Chunk> = (0..l.chunks).map(|c| Chunk { bitmap: None, free: chunk_blocks(&l, c) }).collect();

    // The chunk-info blocks take the pool's first blocks.
    let cib_addrs: Vec<u64> = (0..l.cibs).map(|_| pool.take(&l)).collect::<Result<_, _>>()?;

    // Allocated: the reserved blocks, then the object map's two blocks.
    let mut allocate = |first: u64, n: u64, pool: &mut Pool| -> Result<(), String> {
        for b in first..first + n {
            let c = &mut chunks[(b / l.blocks_per_chunk) as usize];
            if c.bitmap.is_none() {
                c.bitmap = Some((pool.take(&l)?, vec![0u8; bsz]));
            }
            let (_, bits) = c.bitmap.as_mut().unwrap();
            let i = (b % l.blocks_per_chunk) as usize;
            if bits[i / 8] & (1 << (i % 8)) != 0 {
                return Err(format!("block {b} allocated twice"));
            }
            bits[i / 8] |= 1 << (i % 8);
            c.free -= 1;
        }
        Ok(())
    };
    allocate(0, l.reserved_end(), &mut pool)?;
    let omap = l.first_metadata_block();
    let omap_tree = omap + 1;
    allocate(omap, 2, &mut pool)?;
    let allocated: u64 = (0..l.chunks).map(|c| chunk_blocks(&l, c) - chunks[c as usize].free).sum();

    // The chunk-info blocks.
    for (i, &addr) in cib_addrs.iter().enumerate() {
        let mut b = vec![0u8; bsz];
        put_header(&mut b, addr, xid, otype::PHYSICAL | 0x7, 0);
        let first = i as u64 * l.chunks_per_cib;
        let n = (l.chunks - first).min(l.chunks_per_cib);
        b.put32(0x20, i as u32);
        b.put32(0x24, n as u32);
        for j in 0..n {
            let c = first + j;
            let o = 0x28 + 32 * j as usize;
            b.put64(o, xid);
            b.put64(o + 8, c * l.blocks_per_chunk);
            b.put32(o + 16, chunk_blocks(&l, c) as u32);
            b.put32(o + 20, chunks[c as usize].free as u32);
            b.put64(o + 24, chunks[c as usize].bitmap.as_ref().map_or(0, |(a, _)| *a));
        }
        set_checksum(&mut b);
        sink.write_at(addr * bs, &b)?;
    }
    // The chunks' bitmaps (no object header).
    for c in &chunks {
        if let Some((addr, bits)) = &c.bitmap {
            sink.write_at(addr * bs, bits)?;
        }
    }
    // The pool's bitmap: ring block 0 has the pool blocks taken.
    let mut ipbm = vec![0u8; bsz];
    for (i, _) in pool.used.iter().enumerate().filter(|(_, u)| **u) {
        ipbm[i / 8] |= 1 << (i % 8);
    }
    sink.write_at(l.ip_bm_base * bs, &ipbm)?;

    // The container's object map and its empty tree.
    let mut b = vec![0u8; bsz];
    put_header(&mut b, omap, xid, otype::PHYSICAL | otype::OMAP, 0);
    b.put32(0x20, OMAP_MANUALLY_MANAGED);
    b.put32(0x28, otype::PHYSICAL | otype::BTREE);
    b.put32(0x2c, otype::PHYSICAL | otype::BTREE);
    b.put64(0x30, omap_tree);
    set_checksum(&mut b);
    sink.write_at(omap * bs, &b)?;
    let b = empty_fixed_root(bs, omap_tree, xid, otype::PHYSICAL | otype::BTREE, otype::OMAP_TREE_SUBTYPE, BTREE_SEQUENTIAL_INSERT | BTREE_PHYSICAL, 16, 16);
    sink.write_at(omap_tree * bs, &b)?;

    // The checkpoint: the space manager and reaper in the data area, the
    // map and a superblock copy in the descriptor area.
    let sm_oid = OID_RESERVED_COUNT;
    let reaper_oid = OID_RESERVED_COUNT + 1;
    let sm_paddr = l.data_base;
    let sm_blocks = l.sm_bytes / bs;
    let reaper_paddr = l.data_base + sm_blocks;
    let mut sm = vec![0u8; l.sm_bytes as usize];
    put_header(&mut sm, sm_oid, xid, otype::EPHEMERAL | 0x5, 0);
    sm.put32(0x20, bs as u32);
    sm.put32(0x24, l.blocks_per_chunk as u32);
    sm.put32(0x28, l.chunks_per_cib as u32);
    sm.put32(0x2c, l.cibs_per_cab as u32);
    // sm_dev[SD_MAIN]
    sm.put64(0x30, blocks);
    sm.put64(0x38, l.chunks);
    sm.put32(0x40, l.cibs as u32);
    sm.put32(0x44, l.cabs as u32);
    sm.put64(0x48, blocks - allocated);
    sm.put32(0x50, l.addr_offset as u32);
    // sm_dev[SD_TIER2]: empty, its addresses after the main device's.
    sm.put32(0x80, (l.addr_offset + 8 * l.cibs) as u32);
    sm.put32(0x90, SM_FLAG_VERSIONED);
    sm.put32(0x94, IP_BM_TX_MULTIPLIER as u32);
    sm.put64(0x98, l.ip_blocks);
    sm.put32(0xa0, l.ip_bm_size as u32);
    sm.put32(0xa4, l.ip_bm_count as u32);
    sm.put64(0xa8, l.ip_bm_base);
    sm.put64(0xb0, l.ip_base);
    // sm_fq[SFQ_IP], sm_fq[SFQ_MAIN]: no trees yet, their node limits.
    sm.put16(0xe0, l.fq_ip_limit as u16);
    sm.put16(0x108, l.fq_main_limit as u16);
    // The bitmap ring: block 0 in use for each bitmap block, the rest
    // free in order.
    sm.put16(0x140, if l.ip_bm_count > l.ip_bm_size { l.ip_bm_size as u16 } else { IP_BM_INDEX_INVALID });
    sm.put16(0x142, if l.ip_bm_count > l.ip_bm_size { (l.ip_bm_count - 1) as u16 } else { IP_BM_INDEX_INVALID });
    sm.put32(0x144, l.xid_offset as u32);
    sm.put32(0x148, l.bitmap_offset as u32);
    sm.put32(0x14c, l.free_next_offset as u32);
    sm.put32(0x150, SM_VERSION);
    sm.put32(0x154, SPACEMAN_STRUCT_SIZE as u32);
    for i in 0..l.ip_bm_size {
        sm.put64((l.xid_offset + 8 * i) as usize, xid);
        sm.put16((l.bitmap_offset + 2 * i) as usize, i as u16);
    }
    for i in 0..l.ip_bm_count {
        let next = if i < l.ip_bm_size || i + 1 == l.ip_bm_count { IP_BM_INDEX_INVALID } else { (i + 1) as u16 };
        sm.put16((l.free_next_offset + 2 * i) as usize, next);
    }
    for (i, &a) in cib_addrs.iter().enumerate() {
        sm.put64(l.addr_offset as usize + 8 * i, a);
    }
    set_checksum(&mut sm);

    let mut reaper = vec![0u8; bsz];
    put_header(&mut reaper, reaper_oid, xid, otype::EPHEMERAL | 0x11, 0);
    reaper.put64(0x20, 1);
    reaper.put32(0x40, NR_BHM_FLAG);
    reaper.put32(0x6c, bs as u32 - REAPER_HEADER);
    set_checksum(&mut reaper);

    let mut map = vec![0u8; bsz];
    put_header(&mut map, l.desc_base, xid, otype::PHYSICAL | otype::CHECKPOINT_MAP, 0);
    map.put32(0x20, CHECKPOINT_MAP_LAST);
    map.put32(0x24, 2);
    for (i, (ty, size, oid, paddr)) in [(otype::EPHEMERAL | 0x5, l.sm_bytes, sm_oid, sm_paddr), (otype::EPHEMERAL | 0x11, bs, reaper_oid, reaper_paddr)].into_iter().enumerate() {
        let o = 0x28 + 40 * i;
        map.put32(o, ty);
        map.put32(o + 8, size as u32);
        map.put64(o + 0x18, oid);
        map.put64(o + 0x20, paddr);
    }
    set_checksum(&mut map);

    let mut sb = vec![0u8; bsz];
    put_header(&mut sb, 1, xid, otype::EPHEMERAL | otype::NX_SUPERBLOCK, 0);
    sb.put32(0x20, crate::darwin::apfsread::NX_MAGIC);
    sb.put32(0x24, bs as u32);
    sb.put64(0x28, blocks);
    sb.put64(0x40, NX_INCOMPAT_VERSION2);
    sb[0x48..0x58].copy_from_slice(&uuid);
    sb.put64(0x58, OID_RESERVED_COUNT + 2);
    sb.put64(0x60, xid + 1);
    sb.put32(0x68, l.desc_blocks as u32);
    sb.put32(0x6c, l.data_blocks as u32);
    sb.put64(0x70, l.desc_base);
    sb.put64(0x78, l.data_base);
    // Next free descriptor and data blocks, the checkpoint's first and
    // length in each area.
    sb.put32(0x80, 2);
    sb.put32(0x84, (sm_blocks + 1) as u32);
    sb.put32(0x88, 0);
    sb.put32(0x8c, 2);
    sb.put32(0x90, 0);
    sb.put32(0x94, (sm_blocks + 1) as u32);
    sb.put64(0x98, sm_oid);
    sb.put64(0xa0, omap);
    sb.put64(0xa8, reaper_oid);
    sb.put32(0xb4, l.max_file_systems as u32);
    sb.put64(0x520, l.ephemeral_info());
    // nx_counters[NX_CNTR_OBJ_CKSUM_SET]: the checksums set before the
    // copy (see [`format_copy_count`]).
    sb.put64(0x3d8, copy_count);
    set_checksum(&mut sb);

    sink.write_at(sm_paddr * bs, &sm)?;
    sink.write_at(reaper_paddr * bs, &reaper)?;
    sink.write_at(l.desc_base * bs, &map)?;
    sink.write_at((l.desc_base + 1) * bs, &sb)?;

    // Block 0, the unmount's: cleanly unmounted. The copy's and the map's
    // checksums, block 0's at the format and its own at the unmount came
    // since the copy's count.
    sb.put64(0x3d8, copy_count + 4);
    sb.put64(0x4f0, NX_CLEANLY_UNMOUNTED);
    set_checksum(&mut sb);
    sink.write_at(0, &sb)?;
    Ok(Formatted { layout: l, omap, omap_tree })
}

/// `nx_counters[0]` in the checkpoint's superblock copy `-C` writes: the
/// raw writes of every chunk-info block and of chunk-info block 0 twice
/// more, the cached writes of the object map's chunk's chunk-info block,
/// the object map's tree and the object map, and the space manager's and
/// reaper's (measured with a counting build of the binary: 11 for four
/// chunk-info blocks). Measured where the reserved blocks are all in chunk
/// 0 and the object map's chunk is another chunk-info block's; otherwise
/// not known.
pub fn format_copy_count(l: &Layout) -> Result<u64, String> {
    let omap_cib = l.first_metadata_block() / l.blocks_per_chunk / l.chunks_per_cib;
    if l.reserved_end() > l.blocks_per_chunk || omap_cib == 0 {
        return Err("not implemented: nx_counters[0] of a container whose reserved blocks pass chunk 0 or whose object map's chunk-info block is the first".into());
    }
    Ok(l.cibs + 2 + 3 + 2)
}

/// Chunk `c`'s blocks (the last chunk has what is left).
fn chunk_blocks(l: &Layout, c: u64) -> u64 {
    (l.blocks - c * l.blocks_per_chunk).min(l.blocks_per_chunk)
}

/// An empty root-and-leaf node of a tree of fixed-size keys and values:
/// its table of contents as long as a node's worth of entries, rounded up
/// to 32 bytes (`(node - header - info) / (k + v + 4) * 4`).
pub(crate) fn empty_fixed_root(bs: u64, oid: u64, xid: u64, ty: u32, subtype: u32, bt_flags: u32, k: u32, v: u32) -> Vec<u8> {
    let bsz = bs as usize;
    let mut b = vec![0u8; bsz];
    put_header(&mut b, oid, xid, ty, subtype);
    let avail = bsz - BTNODE_HEADER - BTREE_INFO;
    let toc = (avail / (k + v + 4) as usize * 4).div_ceil(32) * 32;
    b.put16(0x20, BTNODE_ROOT | BTNODE_LEAF | BTNODE_FIXED_KV_SIZE);
    b.put16(0x22, 0);
    b.put32(0x24, 0);
    b.put16(0x28, 0);
    b.put16(0x2a, toc as u16);
    b.put16(0x2c, 0);
    b.put16(0x2e, (avail - toc) as u16);
    b.put16(0x30, BTOFF_INVALID);
    b.put16(0x32, 0);
    b.put16(0x34, BTOFF_INVALID);
    b.put16(0x36, 0);
    let i = bsz - BTREE_INFO;
    b.put32(i, bt_flags);
    b.put32(i + 4, bs as u32);
    b.put32(i + 8, k);
    b.put32(i + 12, v);
    b.put64(i + 32, 1);
    set_checksum(&mut b);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::darwin::apfsread::Medium;

    #[test]
    fn sizes_match_newfs() {
        // 64,000,000,000 bytes of 4 KiB blocks, as measured of newfs_apfs.
        let l = Layout::new(4096, 15_625_000).unwrap();
        assert_eq!((l.chunks, l.cibs, l.cabs, l.ip_blocks, l.ip_bm_size, l.ip_bm_count), (477, 4, 0, 1443, 1, 16));
        assert_eq!((l.desc_blocks, l.data_blocks, l.data_base, l.ip_bm_base, l.ip_base), (280, 27672, 281, 27953, 27969));
        assert_eq!((l.fq_ip_limit, l.fq_main_limit, l.max_file_systems), (3, 512, 100));
        assert_eq!(l.ephemeral_info(), 0x0000_0008_0004_0001);
        assert_eq!(l.reserved_end(), 29412);
        assert_eq!(l.metazone(), Some((15_136_719, 15_380_859, 15_625_000)));
        assert_eq!((l.xid_offset, l.bitmap_offset, l.free_next_offset, l.addr_offset), (0x9d8, 0x9e0, 0x9e8, 0xa08));
        // The restore ramdisk's container (45,056 blocks): no zone.
        let r = Layout::new(4096, 45_056).unwrap();
        assert_eq!((r.desc_blocks, r.data_blocks, r.fq_ip_limit, r.fq_main_limit), (8, 312, 1, 10));
        assert_eq!(r.metazone(), None);
    }

    /// The device's newfs_apfs's own -C output (GEX_TEST_NEWFS_C: an image
    /// of 15,625,000 blocks it formatted), byte for byte, given its uuid.
    #[test]
    fn format_matches_newfs() {
        let Ok(path) = std::env::var("GEX_TEST_NEWFS_C") else { return };
        use std::os::unix::fs::FileExt;
        let want = std::fs::File::open(&path).unwrap();
        let mut b0 = vec![0u8; 4096];
        want.read_exact_at(&mut b0, 0).unwrap();
        let uuid: [u8; 16] = b0[0x48..0x58].try_into().unwrap();
        let dir = std::env::temp_dir().join(format!("gex-apfswrite-{}", std::process::id()));
        let f = std::fs::OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&dir).unwrap();
        let blocks = 15_625_000u64;
        f.set_len(blocks * 4096).unwrap();
        let sink = crate::darwin::apfswrite::HostFile(f, blocks * 4096);
        let fm = format(&sink, 4096, blocks, uuid).unwrap();
        let l = fm.layout;
        let mut bad = Vec::new();
        let mut check = |blk: u64| {
            let (mut a, mut b) = (vec![0u8; 4096], vec![0u8; 4096]);
            sink.read_at(blk * 4096, &mut a).unwrap();
            want.read_exact_at(&mut b, blk * 4096).unwrap();
            if a != b {
                let at: Vec<usize> = (0..4096).filter(|&i| a[i] != b[i]).collect();
                bad.push(format!("block {blk}: bytes {:x?} differ", &at[..at.len().min(12)]));
            }
        };
        for blk in [0, 1, 2, l.data_base, l.data_base + 1, l.ip_bm_base, fm.omap, fm.omap_tree] {
            check(blk);
        }
        for i in 0..8 {
            check(l.ip_base + i);
        }
        assert!(bad.is_empty(), "{}", bad.join("; "));
        let _ = std::fs::remove_file(&dir);
    }
}
