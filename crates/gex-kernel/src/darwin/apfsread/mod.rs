//! A read-only reader of an APFS container and its volumes, as Apple's
//! "Apple File System Reference" (developer.apple.com, revision
//! 2020-06-22) defines them, for the cryptex disk images APFS grafts
//! (`apfs_graft`, [`super::graft`]): a cryptex's `os.dmg` is a raw APFS
//! container, its block 0 the container superblock (no partition map, no
//! UDIF wrapper: APFS reads the image's blocks through the file's own
//! extents, its graft blockmap, 0xfffffff0067227fc).
//!
//! What is read, and from where in the Reference:
//!
//! - the container superblock and its latest valid checkpoint ("Mounting
//!   an Apple File System Partition", `nx_superblock_t`,
//!   `checkpoint_map_phys_t`), every object's Fletcher-64 checksum
//!   (`obj_phys_t`);
//! - object maps (`omap_phys_t`, `omap_key_t`, `omap_val_t`) and the
//!   B-trees they and the file systems are kept in (`btree_node_phys_t`,
//!   `btree_info_t`, `kvloc_t`, `kvoff_t`, `btn_index_node_val_t`), with a
//!   sealed volume's hashed nodes checked against their parents' hashes;
//! - the volume superblock (`apfs_superblock_t`), its integrity metadata
//!   (`integrity_meta_phys_t`) and file extent tree (`fext_tree_key_t`,
//!   `fext_tree_val_t`) ("Sealed Volumes");
//! - file-system records ([`fs`]): inodes, directory entries, extended
//!   attributes, extents, data streams, extended fields, siblings, and a
//!   sealed volume's file-info records, whose data hashes are checked as
//!   the data is read; and decmpfs files ([`decmpfs`]), LZBITMAP's
//!   included ([`lzbitmap`]).
//!
//! Nothing is read ahead: the medium is read a block at a time as the
//! structures are walked, a bounded number of B-tree nodes kept.
//!
//! What the Reference leaves out and the image settles, checked against
//! it (every one is hash-checked, so a wrong reading fails rather than
//! passes): the Fletcher-64 variant (the 32-bit words past the checksum
//! summed modulo 2^32 - 1, the checksum's two words made from the sums,
//! [`fletcher64`]); a sealed
//! file-system tree's child object identifiers, which are relative to its
//! root node's; the length of a hashed index value (the identifier and the
//! hash at its algorithm's size, not `BTREE_NODE_HASH_SIZE_MAX`); a
//! file-info record's address, the byte offset in the data stream it
//! hashes; and `xf_used_data`, the extended fields' values' bytes alone
//! ([`fs::xfields`]).

pub mod btree;
pub mod decmpfs;
pub mod fs;
pub mod lzbitmap;

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

/// Where a container's bytes are read from.
pub trait Medium: Send + Sync {
    /// The medium's size in bytes.
    fn size(&self) -> u64;
    /// All of `buf` from byte `off`, or why not.
    fn read_at(&self, off: u64, buf: &mut [u8]) -> std::result::Result<(), String>;
}

/// Why a read failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The medium could not be read.
    Io(String),
    /// A structure is not what the Reference defines.
    Malformed(String),
    /// A sealed volume's content does not match its hashes.
    Integrity(String),
    /// What this reader does not implement.
    Unsupported(String),
    /// A compressed file's data decmpfs's fetch refuses, with the error it
    /// returns.
    Decmpfs { errno: i32, why: String },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(s) => write!(f, "reading the medium: {s}"),
            Error::Malformed(s) => write!(f, "malformed: {s}"),
            Error::Integrity(s) => write!(f, "integrity: {s}"),
            Error::Unsupported(s) => write!(f, "not implemented: {s}"),
            Error::Decmpfs { errno, why } => write!(f, "decmpfs: {why} (errno {errno})"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

fn malformed<T>(what: impl Into<String>) -> Result<T> {
    Err(Error::Malformed(what.into()))
}

/// Little-endian fields of a byte slice, bounds-checked.
pub(crate) trait Le {
    fn u16_at(&self, o: usize) -> Result<u16>;
    fn u32_at(&self, o: usize) -> Result<u32>;
    fn u64_at(&self, o: usize) -> Result<u64>;
    fn slice_at(&self, o: usize, n: usize) -> Result<&[u8]>;
}

impl Le for [u8] {
    fn u16_at(&self, o: usize) -> Result<u16> {
        Ok(u16::from_le_bytes(self.slice_at(o, 2)?.try_into().unwrap()))
    }
    fn u32_at(&self, o: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(self.slice_at(o, 4)?.try_into().unwrap()))
    }
    fn u64_at(&self, o: usize) -> Result<u64> {
        Ok(u64::from_le_bytes(self.slice_at(o, 8)?.try_into().unwrap()))
    }
    fn slice_at(&self, o: usize, n: usize) -> Result<&[u8]> {
        o.checked_add(n).and_then(|e| self.get(o..e)).ok_or_else(|| Error::Malformed(format!("a field at {o}+{n} past the end of a {}-byte structure", self.len())))
    }
}

/// `obj_phys_t`'s Fletcher-64 checksum of an object (its bytes past the
/// checksum field).
pub fn fletcher64(obj: &[u8]) -> u64 {
    const M: u64 = 0xffff_ffff;
    let (mut s1, mut s2) = (0u64, 0u64);
    for w in obj[8..].chunks_exact(4) {
        s1 = (s1 + u64::from(u32::from_le_bytes(w.try_into().unwrap()))) % M;
        s2 = (s2 + s1) % M;
    }
    let c1 = M - (s1 + s2) % M;
    let c2 = M - (s1 + c1) % M;
    (c2 << 32) | c1
}

/// Whether an object's stored checksum is its checksum.
pub fn checksum_ok(obj: &[u8]) -> bool {
    obj.len() >= 32 && u64::from_le_bytes(obj[..8].try_into().unwrap()) == fletcher64(obj)
}

/// Object types and their flags (`o_type`).
pub mod otype {
    pub const MASK: u32 = 0x0000_ffff;
    pub const NX_SUPERBLOCK: u32 = 0x01;
    pub const BTREE: u32 = 0x02;
    pub const BTREE_NODE: u32 = 0x03;
    pub const OMAP: u32 = 0x0b;
    pub const CHECKPOINT_MAP: u32 = 0x0c;
    pub const FS: u32 = 0x0d;
    pub const FSTREE: u32 = 0x0e;
    pub const OMAP_TREE_SUBTYPE: u32 = 0x0b;
    pub const INTEGRITY_META: u32 = 0x1e;
    pub const FEXT_TREE: u32 = 0x1f;
    pub const PHYSICAL: u32 = 0x4000_0000;
    pub const EPHEMERAL: u32 = 0x8000_0000;
    pub const STORAGETYPE_MASK: u32 = 0xc000_0000;
    pub const ENCRYPTED: u32 = 0x1000_0000;
}

/// An object's header (`obj_phys_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjHeader {
    pub oid: u64,
    pub xid: u64,
    pub otype: u32,
    pub subtype: u32,
}

impl ObjHeader {
    pub fn parse(b: &[u8]) -> Result<ObjHeader> {
        Ok(ObjHeader { oid: b.u64_at(8)?, xid: b.u64_at(16)?, otype: b.u32_at(24)?, subtype: b.u32_at(28)? })
    }
    pub fn kind(&self) -> u32 {
        self.otype & otype::MASK
    }
}

/// `NX_MAGIC`, `APFS_MAGIC`.
pub const NX_MAGIC: u32 = u32::from_le_bytes(*b"NXSB");
pub const APFS_MAGIC: u32 = u32::from_le_bytes(*b"APSB");

/// `NX_MINIMUM_BLOCK_SIZE`, `NX_MAXIMUM_BLOCK_SIZE`, `NX_MAX_FILE_SYSTEMS`.
pub const NX_MINIMUM_BLOCK_SIZE: u32 = 4096;
pub const NX_MAXIMUM_BLOCK_SIZE: u32 = 65536;
pub const NX_MAX_FILE_SYSTEMS: usize = 100;

/// `nx_incompatible_features`: `NX_INCOMPAT_VERSION1`,
/// `NX_INCOMPAT_VERSION2`, `NX_INCOMPAT_FUSION`.
pub mod nx_incompat {
    pub const VERSION1: u64 = 0x1;
    pub const VERSION2: u64 = 0x2;
    pub const FUSION: u64 = 0x100;
}

/// The container superblock's fields this reader uses.
#[derive(Clone, Debug)]
pub struct NxSuperblock {
    pub header: ObjHeader,
    pub block_size: u32,
    pub block_count: u64,
    pub features: u64,
    pub ro_compat: u64,
    pub incompat: u64,
    pub uuid: [u8; 16],
    pub xp_desc_blocks: u32,
    pub xp_data_blocks: u32,
    pub xp_desc_base: u64,
    pub xp_data_base: u64,
    pub xp_desc_index: u32,
    pub xp_desc_len: u32,
    pub omap_oid: u64,
    pub max_file_systems: u32,
    pub fs_oid: Vec<u64>,
}

impl NxSuperblock {
    /// A container superblock, its magic and checksum checked.
    pub fn parse(b: &[u8]) -> Result<NxSuperblock> {
        let header = ObjHeader::parse(b)?;
        if header.kind() != otype::NX_SUPERBLOCK {
            return malformed(format!("a container superblock of object type {:#x}", header.otype));
        }
        if b.u32_at(32)? != NX_MAGIC {
            return malformed("a container superblock without NX_MAGIC");
        }
        if !checksum_ok(b) {
            return malformed("a container superblock whose checksum is wrong");
        }
        let max_file_systems = b.u32_at(0xb4)?;
        let n = (max_file_systems as usize).min(NX_MAX_FILE_SYSTEMS);
        let fs_oid = (0..n).map(|i| b.u64_at(0xb8 + 8 * i)).collect::<Result<Vec<_>>>()?;
        Ok(NxSuperblock {
            header,
            block_size: b.u32_at(0x24)?,
            block_count: b.u64_at(0x28)?,
            features: b.u64_at(0x30)?,
            ro_compat: b.u64_at(0x38)?,
            incompat: b.u64_at(0x40)?,
            uuid: b.slice_at(0x48, 16)?.try_into().unwrap(),
            xp_desc_blocks: b.u32_at(0x68)?,
            xp_data_blocks: b.u32_at(0x6c)?,
            xp_desc_base: b.u64_at(0x70)?,
            xp_data_base: b.u64_at(0x78)?,
            xp_desc_index: b.u32_at(0x88)?,
            xp_desc_len: b.u32_at(0x8c)?,
            omap_oid: b.u64_at(0xa0)?,
            max_file_systems,
            fs_oid,
        })
    }
}

/// Recently read B-tree nodes and objects, by physical address: a bounded
/// number, the oldest dropped first.
struct BlockCache {
    cap: usize,
    inner: Mutex<(HashMap<u64, Arc<[u8]>>, VecDeque<u64>)>,
}

impl BlockCache {
    fn new(cap: usize) -> BlockCache {
        BlockCache { cap, inner: Mutex::new((HashMap::new(), VecDeque::new())) }
    }
    fn get(&self, at: u64) -> Option<Arc<[u8]>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).0.get(&at).cloned()
    }
    fn put(&self, at: u64, b: Arc<[u8]>) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.0.insert(at, b).is_none() {
            g.1.push_back(at);
            while g.1.len() > self.cap {
                if let Some(old) = g.1.pop_front() {
                    g.0.remove(&old);
                }
            }
        }
    }
}

/// How many blocks of metadata a container keeps read (2 MiB of 4 KiB
/// blocks).
const CACHED_BLOCKS: usize = 512;

/// An open container: the medium, and its latest valid checkpoint's
/// superblock.
pub struct Container {
    medium: Arc<dyn Medium>,
    pub nx: NxSuperblock,
    cache: BlockCache,
}

impl std::fmt::Debug for Container {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Container").field("nx", &self.nx).finish_non_exhaustive()
    }
}

impl Container {
    /// The block size.
    pub fn block_size(&self) -> u32 {
        self.nx.block_size
    }

    /// The transaction the container is read at: its latest checkpoint's.
    pub fn xid(&self) -> u64 {
        self.nx.header.xid
    }

    /// Mount the container on `medium` ("Mounting an Apple File System
    /// Partition", steps 1 to 6): block 0's superblock, then the
    /// checkpoint descriptor area's superblock with the largest transaction
    /// identifier whose magic and checksum are valid and whose
    /// checkpoint-mapping blocks are too. A read-only reader reads no
    /// ephemeral object (step 5's allowance).
    pub fn open(medium: Arc<dyn Medium>) -> Result<Container> {
        let mut head = vec![0u8; NX_MINIMUM_BLOCK_SIZE as usize];
        medium.read_at(0, &mut head).map_err(Error::Io)?;
        let bs = head.u32_at(0x24)?;
        if !(NX_MINIMUM_BLOCK_SIZE..=NX_MAXIMUM_BLOCK_SIZE).contains(&bs) || !bs.is_power_of_two() {
            return malformed(format!("a container block size of {bs}"));
        }
        let mut b0 = vec![0u8; bs as usize];
        medium.read_at(0, &mut b0).map_err(Error::Io)?;
        let mut c = Container { medium, nx: NxSuperblock::parse(&b0)?, cache: BlockCache::new(CACHED_BLOCKS) };
        if c.nx.block_count.checked_mul(u64::from(bs)).is_none_or(|n| n > c.medium.size()) {
            return malformed(format!("a container of {} blocks of {bs} bytes on a medium of {} bytes", c.nx.block_count, c.medium.size()));
        }
        c.check_features(&c.nx.clone())?;
        let best = c.latest_checkpoint()?;
        c.check_features(&best)?;
        c.nx = best;
        Ok(c)
    }

    fn check_features(&self, nx: &NxSuperblock) -> Result<()> {
        if nx.block_size != self.nx.block_size {
            return malformed("checkpoints of different block sizes");
        }
        if nx.incompat & nx_incompat::VERSION2 == 0 {
            return Err(Error::Unsupported(format!("a container without NX_INCOMPAT_VERSION2 (incompatible features {:#x})", nx.incompat)));
        }
        let known = nx_incompat::VERSION2 | nx_incompat::FUSION;
        if nx.incompat & !known != 0 {
            return Err(Error::Unsupported(format!("a container's incompatible features {:#x}", nx.incompat)));
        }
        if nx.incompat & nx_incompat::FUSION != 0 {
            return Err(Error::Unsupported("a Fusion container".into()));
        }
        Ok(())
    }

    /// Step 4: the latest valid checkpoint.
    fn latest_checkpoint(&self) -> Result<NxSuperblock> {
        const FLAG: u32 = 0x8000_0000;
        if self.nx.xp_desc_blocks & FLAG != 0 {
            return Err(Error::Unsupported("a checkpoint descriptor area kept in a tree (nx_xp_desc_blocks' high bit; APFS's grafts refuse one too: \"xp desc is fragmented\")".into()));
        }
        let n = self.nx.xp_desc_blocks;
        if n == 0 {
            return malformed("an empty checkpoint descriptor area");
        }
        let mut found: Vec<NxSuperblock> = Vec::new();
        for i in 0..n {
            let b = self.read_raw(self.nx.xp_desc_base + u64::from(i))?;
            let Ok(h) = ObjHeader::parse(&b) else { continue };
            if h.kind() != otype::NX_SUPERBLOCK {
                continue;
            }
            if let Ok(sb) = NxSuperblock::parse(&b) {
                found.push(sb);
            }
        }
        found.sort_by_key(|sb| std::cmp::Reverse(sb.header.xid));
        for sb in found {
            if self.checkpoint_maps_ok(&sb)? {
                return Ok(sb);
            }
        }
        malformed("no valid checkpoint in the checkpoint descriptor area")
    }

    /// Whether a checkpoint's mapping blocks, the `xp_desc_len - 1` blocks
    /// before its superblock in the ring, are valid mapping blocks of its
    /// transaction, the last of them flagged last.
    fn checkpoint_maps_ok(&self, sb: &NxSuperblock) -> Result<bool> {
        const CHECKPOINT_MAP_LAST: u32 = 0x1;
        let n = u64::from(self.nx.xp_desc_blocks);
        if sb.xp_desc_len == 0 || u64::from(sb.xp_desc_len) > n || u64::from(sb.xp_desc_index) >= n {
            return Ok(false);
        }
        let maps = u64::from(sb.xp_desc_len) - 1;
        for j in 0..maps {
            let at = (u64::from(sb.xp_desc_index) + j) % n;
            let b = self.read_raw(self.nx.xp_desc_base + at)?;
            let Ok(h) = ObjHeader::parse(&b) else { return Ok(false) };
            if h.kind() != otype::CHECKPOINT_MAP || h.xid != sb.header.xid || !checksum_ok(&b) {
                return Ok(false);
            }
            let last = b.u32_at(0x20)? & CHECKPOINT_MAP_LAST != 0;
            if last != (j + 1 == maps) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The bytes of the block at physical address `paddr`, read from the
    /// medium.
    pub fn read_raw(&self, paddr: u64) -> Result<Vec<u8>> {
        let bs = u64::from(self.nx.block_size);
        if paddr >= self.nx.block_count.max(1) && self.nx.block_count != 0 {
            return malformed(format!("block {paddr:#x} past the container's {} blocks", self.nx.block_count));
        }
        let off = paddr.checked_mul(bs).ok_or_else(|| Error::Malformed(format!("block {paddr:#x}")))?;
        let mut b = vec![0u8; bs as usize];
        self.medium.read_at(off, &mut b).map_err(Error::Io)?;
        Ok(b)
    }

    /// Bytes of the medium, for data extents: `len` from block `paddr`.
    pub fn read_extent(&self, paddr: u64, within: u64, buf: &mut [u8]) -> Result<()> {
        let bs = u64::from(self.nx.block_size);
        let off = paddr.checked_mul(bs).and_then(|o| o.checked_add(within)).ok_or_else(|| Error::Malformed(format!("an extent at block {paddr:#x}")))?;
        let end = off.checked_add(buf.len() as u64).ok_or_else(|| Error::Malformed("an extent's end".into()))?;
        if end > self.nx.block_count.saturating_mul(bs) {
            return malformed(format!("an extent at block {paddr:#x} past the container's end"));
        }
        self.medium.read_at(off, buf).map_err(Error::Io)
    }

    /// A metadata block, from the cache or the medium.
    pub(crate) fn block(&self, paddr: u64) -> Result<Arc<[u8]>> {
        if let Some(b) = self.cache.get(paddr) {
            return Ok(b);
        }
        let b: Arc<[u8]> = self.read_raw(paddr)?.into();
        self.cache.put(paddr, Arc::clone(&b));
        Ok(b)
    }

    /// A physical object of kind `kind` at `paddr`, its header and checksum
    /// checked (its identifier is its address).
    pub(crate) fn physical(&self, paddr: u64, kind: u32) -> Result<Arc<[u8]>> {
        let b = self.block(paddr)?;
        let h = ObjHeader::parse(&b)?;
        if h.kind() != kind || h.otype & otype::STORAGETYPE_MASK != otype::PHYSICAL || h.oid != paddr || !checksum_ok(&b) {
            return malformed(format!("block {paddr:#x} is not a valid physical object of type {kind:#x} (header {h:?})"));
        }
        Ok(b)
    }

    /// The container's object map.
    pub fn omap(&self) -> Result<Omap> {
        Omap::open(self, self.nx.omap_oid)
    }

    /// The volume at `index` of `nx_fs_oid` (steps 7 and 8), if there is
    /// one.
    pub fn volume(self: &Arc<Self>, index: usize) -> Result<Option<Volume>> {
        let Some(&oid) = self.nx.fs_oid.get(index) else { return Ok(None) };
        if oid == 0 {
            return Ok(None);
        }
        let omap = self.omap()?;
        let v = omap.lookup(self, oid, self.xid())?.ok_or_else(|| Error::Malformed(format!("the volume {oid:#x} is not in the container's object map")))?;
        Volume::open(Arc::clone(self), v.paddr, oid).map(Some)
    }
}

/// `omap_val_t`'s flags.
pub mod omap_val {
    pub const DELETED: u32 = 0x1;
    pub const SAVED: u32 = 0x2;
    pub const ENCRYPTED: u32 = 0x4;
    pub const NOHEADER: u32 = 0x8;
    pub const CRYPTO_GENERATION: u32 = 0x10;
}

/// An object map's answer for a virtual object (`omap_val_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OmapVal {
    pub flags: u32,
    pub size: u32,
    pub paddr: u64,
}

/// An object map (`omap_phys_t`): its tree of mappings.
#[derive(Clone, Debug)]
pub struct Omap {
    pub tree: btree::Tree,
}

impl Omap {
    /// The object map at physical address `paddr`.
    pub fn open(c: &Container, paddr: u64) -> Result<Omap> {
        let b = c.physical(paddr, otype::OMAP)?;
        let tree_type = b.u32_at(0x28)?;
        let tree_oid = b.u64_at(0x30)?;
        if tree_type & otype::STORAGETYPE_MASK != otype::PHYSICAL {
            return Err(Error::Unsupported(format!("an object map whose tree is not physical (type {tree_type:#x})")));
        }
        Ok(Omap { tree: btree::Tree::open(c, tree_oid, btree::Children::Physical, None, otype::OMAP_TREE_SUBTYPE)? })
    }

    /// The mapping of virtual object `oid` at transaction `xid`: the one
    /// of the largest transaction not after it; none when it has none, or
    /// when that one says the object was deleted.
    pub fn lookup(&self, c: &Container, oid: u64, xid: u64) -> Result<Option<OmapVal>> {
        let target = (oid, xid);
        let key = |k: &[u8]| -> Result<(u64, u64)> { Ok((k.u64_at(0)?, k.u64_at(8)?)) };
        let found = self.tree.find_le(c, &mut |k| Ok(key(k)?.cmp(&target)))?;
        let Some((k, v)) = found else { return Ok(None) };
        if key(&k)?.0 != oid {
            return Ok(None);
        }
        let v = v.ok_or_else(|| Error::Malformed("an object map record without a value".into()))?;
        let val = OmapVal { flags: v.u32_at(0)?, size: v.u32_at(4)?, paddr: v.u64_at(8)? };
        if val.flags & omap_val::DELETED != 0 {
            return Ok(None);
        }
        if val.flags & omap_val::ENCRYPTED != 0 {
            return Err(Error::Unsupported(format!("the encrypted object {oid:#x}")));
        }
        Ok(Some(val))
    }
}

/// `apfs_incompatible_features`.
pub mod incompat {
    pub const CASE_INSENSITIVE: u64 = 0x1;
    pub const DATALESS_SNAPS: u64 = 0x2;
    pub const ENC_ROLLED: u64 = 0x4;
    pub const NORMALIZATION_INSENSITIVE: u64 = 0x8;
    pub const INCOMPLETE_RESTORE: u64 = 0x10;
    pub const SEALED_VOLUME: u64 = 0x20;
}

/// `apfs_fs_flags`: `APFS_FS_UNENCRYPTED`.
pub const APFS_FS_UNENCRYPTED: u64 = 0x1;

/// `apfs_hash_type_t`, and each algorithm's size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashType {
    Sha256,
    Sha512_256,
    Sha384,
    Sha512,
}

impl HashType {
    pub fn of(v: u32) -> Result<HashType> {
        match v {
            1 => Ok(HashType::Sha256),
            2 => Ok(HashType::Sha512_256),
            3 => Ok(HashType::Sha384),
            4 => Ok(HashType::Sha512),
            _ => malformed(format!("the hash type {v}")),
        }
    }
    pub fn code(self) -> u32 {
        match self {
            HashType::Sha256 => 1,
            HashType::Sha512_256 => 2,
            HashType::Sha384 => 3,
            HashType::Sha512 => 4,
        }
    }
    /// `APFS_HASH_CCSHA*_SIZE`.
    pub fn size(self) -> usize {
        match self {
            HashType::Sha256 | HashType::Sha512_256 => 32,
            HashType::Sha384 => 48,
            HashType::Sha512 => 64,
        }
    }
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        match self {
            HashType::Sha256 => sha2::Sha256::digest(data).to_vec(),
            HashType::Sha512_256 => sha2::Sha512_256::digest(data).to_vec(),
            HashType::Sha384 => sha2::Sha384::digest(data).to_vec(),
            HashType::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

/// A sealed volume's integrity metadata (`integrity_meta_phys_t`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegrityMeta {
    pub version: u32,
    pub flags: u32,
    pub hash_type: HashType,
    pub broken_xid: u64,
    /// The root hash, at `im_root_hash_offset`, its algorithm's size.
    pub root_hash: Vec<u8>,
}

/// `INTEGRITY_META_VERSION_HIGHEST`, `APFS_SEAL_BROKEN`.
pub const INTEGRITY_META_VERSION_HIGHEST: u32 = 2;
pub const APFS_SEAL_BROKEN: u32 = 0x1;

impl IntegrityMeta {
    pub fn parse(b: &[u8]) -> Result<IntegrityMeta> {
        let version = b.u32_at(0x20)?;
        if version == 0 || version > INTEGRITY_META_VERSION_HIGHEST {
            return malformed(format!("integrity metadata of version {version}"));
        }
        let hash_type = HashType::of(b.u32_at(0x28)?)?;
        let off = b.u32_at(0x2c)? as usize;
        Ok(IntegrityMeta { version, flags: b.u32_at(0x24)?, hash_type, broken_xid: b.u64_at(0x30)?, root_hash: b.slice_at(off, hash_type.size())?.to_vec() })
    }
    pub fn seal_broken(&self) -> bool {
        self.flags & APFS_SEAL_BROKEN != 0
    }
}

/// The volume superblock's fields this reader uses (`apfs_superblock_t`).
#[derive(Clone, Debug)]
pub struct VolumeSuperblock {
    pub header: ObjHeader,
    pub fs_index: u32,
    pub features: u64,
    pub ro_compat: u64,
    pub incompat: u64,
    pub root_tree_type: u32,
    pub omap_oid: u64,
    pub root_tree_oid: u64,
    pub next_obj_id: u64,
    pub num_files: u64,
    pub num_directories: u64,
    pub num_symlinks: u64,
    pub num_other_fsobjects: u64,
    pub uuid: [u8; 16],
    pub fs_flags: u64,
    pub volname: String,
    pub role: u16,
    pub er_state_oid: u64,
    pub integrity_meta_oid: u64,
    pub fext_tree_oid: u64,
    pub fext_tree_type: u32,
}

impl VolumeSuperblock {
    pub fn parse(b: &[u8]) -> Result<VolumeSuperblock> {
        let header = ObjHeader::parse(b)?;
        if header.kind() != otype::FS {
            return malformed(format!("a volume superblock of object type {:#x}", header.otype));
        }
        if b.u32_at(0x20)? != APFS_MAGIC {
            return malformed("a volume superblock without APFS_MAGIC");
        }
        if !checksum_ok(b) {
            return malformed("a volume superblock whose checksum is wrong");
        }
        let name = b.slice_at(0x2c0, 256)?;
        let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(name.len())];
        Ok(VolumeSuperblock {
            header,
            fs_index: b.u32_at(0x24)?,
            features: b.u64_at(0x28)?,
            ro_compat: b.u64_at(0x30)?,
            incompat: b.u64_at(0x38)?,
            root_tree_type: b.u32_at(0x74)?,
            omap_oid: b.u64_at(0x80)?,
            root_tree_oid: b.u64_at(0x88)?,
            next_obj_id: b.u64_at(0xb0)?,
            num_files: b.u64_at(0xb8)?,
            num_directories: b.u64_at(0xc0)?,
            num_symlinks: b.u64_at(0xc8)?,
            num_other_fsobjects: b.u64_at(0xd0)?,
            uuid: b.slice_at(0xf0, 16)?.try_into().unwrap(),
            fs_flags: b.u64_at(0x108)?,
            volname: String::from_utf8_lossy(name).into_owned(),
            role: b.u16_at(0x3c4)?,
            er_state_oid: b.u64_at(0x3d0)?,
            integrity_meta_oid: b.u64_at(0x400)?,
            fext_tree_oid: b.u64_at(0x408)?,
            fext_tree_type: b.u32_at(0x410)?,
        })
    }

    pub fn sealed(&self) -> bool {
        self.incompat & incompat::SEALED_VOLUME != 0
    }
}

/// An open volume: its superblock, object map and trees.
#[derive(Clone)]
pub struct Volume {
    pub container: Arc<Container>,
    pub sb: VolumeSuperblock,
    pub omap: Omap,
    /// Its file-system tree.
    pub fs_tree: btree::Tree,
    /// A sealed volume's file extent tree.
    pub fext_tree: Option<btree::Tree>,
    /// A sealed volume's hash algorithm, which its file-system tree's nodes
    /// and its file-info records are hashed with.
    pub hash_type: Option<HashType>,
    pub(crate) verified: Arc<Mutex<std::collections::HashSet<(u64, u64)>>>,
}

impl std::fmt::Debug for Volume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Volume").field("sb", &self.sb).finish_non_exhaustive()
    }
}

/// The volume incompatible features this reader reads.
const READABLE_INCOMPAT: u64 = incompat::DATALESS_SNAPS | incompat::ENC_ROLLED | incompat::NORMALIZATION_INSENSITIVE | incompat::INCOMPLETE_RESTORE | incompat::SEALED_VOLUME;

impl Volume {
    /// The volume whose superblock is at `paddr` (virtual object `oid`):
    /// its superblock checked, its object map, and its file-system tree
    /// (step 9), with a sealed volume's file extent tree; a sealed
    /// volume's root node is checked against its integrity metadata's
    /// root hash.
    pub fn open(container: Arc<Container>, paddr: u64, oid: u64) -> Result<Volume> {
        let b = container.block(paddr)?;
        let sb = VolumeSuperblock::parse(&b)?;
        if sb.header.oid != oid {
            return malformed(format!("the volume superblock at {paddr:#x} is object {:#x}, not {oid:#x}", sb.header.oid));
        }
        if sb.incompat & incompat::CASE_INSENSITIVE != 0 {
            return Err(Error::Unsupported("a case-insensitive volume (its names' Unicode case folding)".into()));
        }
        if sb.incompat & !READABLE_INCOMPAT != 0 {
            return Err(Error::Unsupported(format!("a volume's incompatible features {:#x}", sb.incompat)));
        }
        if sb.fs_flags & APFS_FS_UNENCRYPTED == 0 {
            return Err(Error::Unsupported(format!("the encrypted volume {:?} (apfs_fs_flags {:#x})", sb.volname, sb.fs_flags)));
        }
        let omap = Omap::open(&container, sb.omap_oid)?;
        let sealed = sb.sealed();
        let (hash_type, root_hash) = if sealed {
            if sb.integrity_meta_oid == 0 || sb.fext_tree_oid == 0 {
                return malformed("a sealed volume without integrity metadata or a file extent tree");
            }
            let im = Self::integrity_of(&container, &omap, &sb)?;
            (Some(im.hash_type), Some(im.root_hash))
        } else {
            (None, None)
        };
        let children = match sb.root_tree_type & otype::STORAGETYPE_MASK {
            otype::PHYSICAL => btree::Children::Physical,
            0 => btree::Children::Virtual { omap: Arc::new(omap.clone()), xid: container.xid() },
            t => return Err(Error::Unsupported(format!("a file-system tree of storage type {t:#x}"))),
        };
        let hashed = hash_type.zip(root_hash).map(|(t, h)| btree::Hashed { hash_type: t, root_hash: h });
        let fs_tree = btree::Tree::open(&container, sb.root_tree_oid, children, hashed, otype::FSTREE)?;
        if sealed && !fs_tree.is_hashed() {
            return malformed("a sealed volume whose file-system tree is not hashed");
        }
        let fext_tree = if sealed {
            if sb.fext_tree_type & otype::STORAGETYPE_MASK != otype::PHYSICAL {
                return Err(Error::Unsupported(format!("a file extent tree of type {:#x}", sb.fext_tree_type)));
            }
            Some(btree::Tree::open(&container, sb.fext_tree_oid, btree::Children::Physical, None, otype::FEXT_TREE)?)
        } else {
            None
        };
        Ok(Volume { container, sb, omap, fs_tree, fext_tree, hash_type, verified: Arc::new(Mutex::new(Default::default())) })
    }

    fn integrity_of(c: &Container, omap: &Omap, sb: &VolumeSuperblock) -> Result<IntegrityMeta> {
        let v = omap.lookup(c, sb.integrity_meta_oid, c.xid())?.ok_or_else(|| Error::Malformed("the integrity metadata is not in the volume's object map".into()))?;
        let b = c.block(v.paddr)?;
        let h = ObjHeader::parse(&b)?;
        if h.kind() != otype::INTEGRITY_META || h.oid != sb.integrity_meta_oid || !checksum_ok(&b) {
            return malformed(format!("the integrity metadata at {:#x} (header {h:?})", v.paddr));
        }
        IntegrityMeta::parse(&b)
    }

    /// The sealed volume's integrity metadata (none for a volume that is
    /// not sealed).
    pub fn integrity(&self) -> Result<Option<IntegrityMeta>> {
        if !self.sb.sealed() {
            return Ok(None);
        }
        Self::integrity_of(&self.container, &self.omap, &self.sb).map(Some)
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    /// A host file, read where it is.
    pub(crate) struct HostFile(pub std::fs::File, pub u64);

    impl super::Medium for HostFile {
        fn size(&self) -> u64 {
            self.1
        }
        fn read_at(&self, off: u64, buf: &mut [u8]) -> std::result::Result<(), String> {
            use std::os::unix::fs::FileExt;
            self.0.read_exact_at(buf, off).map_err(|e| e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An IPSW's cryptex image (GEX_DARWIN_RESTORE), if one is configured.
    pub(crate) fn restore_image(name: &str) -> Arc<Container> {
        let dir = std::env::var("GEX_DARWIN_RESTORE").expect("GEX_DARWIN_RESTORE");
        let f = std::fs::File::open(format!("{dir}/{name}")).unwrap();
        let n = f.metadata().unwrap().len();
        Arc::new(Container::open(Arc::new(super::tests_support::HostFile(f, n))).unwrap())
    }

    #[test]
    fn fletcher64_checks_an_object() {
        let mut b = vec![0u8; 4096];
        for (i, x) in b.iter_mut().enumerate().skip(8) {
            *x = (i * 7 + 3) as u8;
        }
        let c = fletcher64(&b);
        b[..8].copy_from_slice(&c.to_le_bytes());
        assert!(checksum_ok(&b));
        b[100] ^= 1;
        assert!(!checksum_ok(&b));
        // All zeros past the checksum: both sums zero, both words all ones.
        let z = vec![0u8; 64];
        assert_eq!(fletcher64(&z), 0xffff_ffff_ffff_ffff);
    }

    #[test]
    fn hash_types_and_sizes() {
        assert_eq!(HashType::of(1).unwrap().size(), 32);
        assert_eq!(HashType::of(2).unwrap().size(), 32);
        assert_eq!(HashType::of(3).unwrap().size(), 48);
        assert_eq!(HashType::of(4).unwrap().size(), 64);
        assert!(HashType::of(0).is_err());
        assert!(HashType::of(5).is_err());
        assert_eq!(HashType::Sha256.digest(b"abc")[..4], [0xba, 0x78, 0x16, 0xbf]);
    }

    /// The SystemOS cryptex of 21H461: a raw container of 4 KiB blocks,
    /// one sealed volume.
    #[test]
    #[ignore = "needs GEX_DARWIN_RESTORE's 044-76034-038.dmg (21H461)"]
    fn the_os_cryptex_container_opens() {
        let c = restore_image("044-76034-038.dmg");
        assert_eq!(c.block_size(), 4096);
        assert_eq!(c.nx.block_count, 806_400);
        assert_eq!(c.xid(), 14);
        let v = c.volume(0).unwrap().unwrap();
        assert!(c.volume(1).unwrap().is_none());
        assert_eq!(v.sb.volname, "DawnUpdate21H461.J120J121J207J208SystemCryptex");
        assert!(v.sb.sealed());
        assert_eq!(v.sb.role, 0);
        assert_eq!((v.sb.num_files, v.sb.num_directories, v.sb.num_symlinks), (1267, 692, 2));
        let im = v.integrity().unwrap().unwrap();
        assert_eq!((im.version, im.hash_type, im.seal_broken()), (2, HashType::Sha256, false));
    }
}
