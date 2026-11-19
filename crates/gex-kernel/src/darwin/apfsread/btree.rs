//! APFS's B-trees ("B-Trees" in the Reference): nodes
//! (`btree_node_phys_t`), their tables of contents (`kvloc_t`, `kvoff_t`),
//! the tree's information at the end of its root node (`btree_info_t`),
//! and a hashed tree's index values (`btn_index_node_val_t`), each child
//! checked against the hash its parent keeps of it.

use super::{malformed, otype, Container, Error, HashType, Le, ObjHeader, Omap, Result};
use std::cmp::Ordering;
use std::sync::Arc;

/// `btn_flags`.
pub mod node_flags {
    pub const ROOT: u16 = 0x0001;
    pub const LEAF: u16 = 0x0002;
    pub const FIXED_KV_SIZE: u16 = 0x0004;
    pub const HASHED: u16 = 0x0008;
    pub const NOHEADER: u16 = 0x0010;
    pub const CHECK_KOFF_INVAL: u16 = 0x8000;
}

/// `bt_flags`.
pub mod tree_flags {
    pub const UINT64_KEYS: u32 = 0x0000_0001;
    pub const SEQUENTIAL_INSERT: u32 = 0x0000_0002;
    pub const ALLOW_GHOSTS: u32 = 0x0000_0004;
    pub const EPHEMERAL: u32 = 0x0000_0008;
    pub const PHYSICAL: u32 = 0x0000_0010;
    pub const NONPERSISTENT: u32 = 0x0000_0020;
    pub const KV_NONALIGNED: u32 = 0x0000_0040;
    pub const HASHED: u32 = 0x0000_0080;
    pub const NOHEADER: u32 = 0x0000_0100;
}

/// `sizeof(btree_node_phys_t)`, where `btn_data` starts; `sizeof(btree_info_t)`.
const NODE_HEADER: usize = 56;
const INFO_SIZE: usize = 40;

/// `BTOFF_INVALID`: a ghost's value offset.
const BTOFF_INVALID: u16 = 0xffff;

/// How a tree's nodes name their children.
#[derive(Clone)]
pub enum Children {
    /// By physical address (`BTREE_PHYSICAL`).
    Physical,
    /// By virtual object identifier, mapped by `omap` at `xid`.
    Virtual { omap: Arc<Omap>, xid: u64 },
    /// By virtual object identifier, each node as a mounted container's
    /// object cache holds it now ([`LiveNodes`]): the tree as its owner's
    /// last change left it, committed or not.
    Live(Arc<dyn LiveNodes>),
}

impl std::fmt::Debug for Children {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Children::Physical => f.write_str("Physical"),
            Children::Virtual { xid, .. } => write!(f, "Virtual {{ xid: {xid} }}"),
            Children::Live(_) => f.write_str("Live"),
        }
    }
}

/// A virtual tree's nodes as the container that writes them holds them:
/// the root node's identifier now, and a node's bytes, from its object
/// cache or, when not there, from the block its object map's newest
/// mapping names. An object in memory carries no valid checksum (the
/// flush sets it), so its header is not checked here.
pub trait LiveNodes: Send + Sync {
    fn root(&self) -> Result<u64>;
    fn node(&self, oid: u64) -> Result<Arc<[u8]>>;
}

/// A hashed tree's algorithm and its root node's expected hash.
#[derive(Clone, Debug)]
pub struct Hashed {
    pub hash_type: HashType,
    pub root_hash: Vec<u8>,
}

/// `btree_info_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub flags: u32,
    pub node_size: u32,
    pub key_size: u32,
    pub val_size: u32,
    pub longest_key: u32,
    pub longest_val: u32,
    pub key_count: u64,
    pub node_count: u64,
}

/// A tree: its root node's identifier, how its children are named, and
/// what its root says of it.
#[derive(Clone, Debug)]
pub struct Tree {
    pub root_oid: u64,
    children: Children,
    hash_type: Option<HashType>,
    pub info: Info,
    subtype: u32,
}

/// A node read and its table of contents located.
pub struct Node {
    pub bytes: Arc<[u8]>,
    pub flags: u16,
    pub level: u16,
    pub nkeys: u32,
    toc: usize,
    key_start: usize,
    val_end: usize,
}

/// A record: its key and its value (none for a ghost).
pub type Record = (Vec<u8>, Option<Vec<u8>>);

impl Node {
    fn parse(bytes: Arc<[u8]>) -> Result<Node> {
        let b: &[u8] = &bytes;
        let flags = b.u16_at(0x20)?;
        let level = b.u16_at(0x22)?;
        let nkeys = b.u32_at(0x24)?;
        let (ts_off, ts_len) = (b.u16_at(0x28)? as usize, b.u16_at(0x2a)? as usize);
        let toc = NODE_HEADER + ts_off;
        let key_start = toc + ts_len;
        let val_end = b.len() - if flags & node_flags::ROOT != 0 { INFO_SIZE } else { 0 };
        if key_start > val_end || flags & node_flags::CHECK_KOFF_INVAL != 0 {
            return malformed(format!("a B-tree node with flags {flags:#x} and table of contents {ts_off}+{ts_len}"));
        }
        if (flags & node_flags::LEAF != 0) != (level == 0) {
            return malformed(format!("a B-tree node of level {level} with flags {flags:#x}"));
        }
        let entry = if flags & node_flags::FIXED_KV_SIZE != 0 { 4 } else { 8 };
        if (nkeys as usize).checked_mul(entry).is_none_or(|n| n > ts_len) {
            return malformed(format!("a B-tree node of {nkeys} keys whose table of contents has {ts_len} bytes"));
        }
        Ok(Node { bytes, flags, level, nkeys, toc, key_start, val_end })
    }

    pub fn is_leaf(&self) -> bool {
        self.flags & node_flags::LEAF != 0
    }

    /// Entry `i`'s key and value (none for a ghost). A fixed-size entry's
    /// key has the tree's key size, and its value the tree's value size in
    /// a leaf, an index value's size in an index node.
    fn entry(&self, i: u32, info: &Info, index_val: usize) -> Result<(&[u8], Option<&[u8]>)> {
        let b: &[u8] = &self.bytes;
        let (ko, kl, vo, vl) = if self.flags & node_flags::FIXED_KV_SIZE != 0 {
            let at = self.toc + 4 * i as usize;
            let vl = if self.is_leaf() { info.val_size as usize } else { index_val };
            (b.u16_at(at)? as usize, info.key_size as usize, b.u16_at(at + 2)?, vl)
        } else {
            let at = self.toc + 8 * i as usize;
            (b.u16_at(at)? as usize, b.u16_at(at + 2)? as usize, b.u16_at(at + 4)?, b.u16_at(at + 6)? as usize)
        };
        let key = b[..self.val_end].slice_at(self.key_start + ko, kl)?;
        let val = if vo == BTOFF_INVALID {
            if info.flags & tree_flags::ALLOW_GHOSTS == 0 {
                return malformed("a ghost in a B-tree that allows none");
            }
            None
        } else {
            let start = self.val_end.checked_sub(vo as usize).filter(|s| *s >= self.key_start).ok_or_else(|| Error::Malformed(format!("a B-tree value offset {vo}")))?;
            Some(b[..self.val_end].slice_at(start, vl)?)
        };
        Ok((key, val))
    }
}

impl Info {
    fn parse(root: &[u8]) -> Result<Info> {
        let o = root.len() - INFO_SIZE;
        Ok(Info {
            flags: root.u32_at(o)?,
            node_size: root.u32_at(o + 4)?,
            key_size: root.u32_at(o + 8)?,
            val_size: root.u32_at(o + 12)?,
            longest_key: root.u32_at(o + 16)?,
            longest_val: root.u32_at(o + 20)?,
            key_count: root.u64_at(o + 24)?,
            node_count: root.u64_at(o + 32)?,
        })
    }
}

impl Tree {
    /// The tree whose root node is object `root_oid`: its root read and
    /// checked (a hashed tree's against `hashed`'s root hash), its
    /// information parsed. `subtype` is the object subtype its nodes with
    /// headers carry.
    pub fn open(c: &Container, root_oid: u64, children: Children, hashed: Option<Hashed>, subtype: u32) -> Result<Tree> {
        let root_oid = match &children {
            Children::Live(nodes) => nodes.root()?,
            _ => root_oid,
        };
        let mut t = Tree { root_oid, children, hash_type: hashed.as_ref().map(|h| h.hash_type), info: Info { flags: 0, node_size: c.block_size(), key_size: 0, val_size: 0, longest_key: 0, longest_val: 0, key_count: 0, node_count: 0 }, subtype };
        if matches!(t.children, Children::Live(_)) && hashed.is_some() {
            return Err(Error::Unsupported("a hashed tree read through a container's object cache".into()));
        }
        let root = t.read_node(c, root_oid, hashed.as_ref().map(|h| &h.root_hash[..]), true)?;
        if root.flags & node_flags::ROOT == 0 {
            return malformed(format!("the B-tree root {root_oid:#x} without BTNODE_ROOT"));
        }
        t.info = Info::parse(&root.bytes)?;
        if t.info.node_size != c.block_size() {
            return Err(Error::Unsupported(format!("B-tree nodes of {} bytes in a container of {}-byte blocks", t.info.node_size, c.block_size())));
        }
        let physical = t.info.flags & tree_flags::PHYSICAL != 0;
        if physical != matches!(t.children, Children::Physical) {
            return malformed(format!("a B-tree whose flags {:#x} do not name its children as its owner does", t.info.flags));
        }
        if t.info.flags & tree_flags::EPHEMERAL != 0 {
            return Err(Error::Unsupported("an ephemeral B-tree".into()));
        }
        let tree_hashed = t.info.flags & tree_flags::HASHED != 0;
        if tree_hashed && t.hash_type.is_none() {
            return malformed("a hashed B-tree outside a sealed volume");
        }
        if !tree_hashed {
            t.hash_type = None;
        }
        if tree_hashed && physical {
            return Err(Error::Unsupported("a hashed B-tree of physical nodes".into()));
        }
        Ok(t)
    }

    /// Whether its index nodes keep their children's hashes.
    pub fn is_hashed(&self) -> bool {
        self.hash_type.is_some()
    }

    /// An index value's size: the child's identifier, and in a hashed tree
    /// its hash, at the tree's algorithm's size.
    fn index_val_size(&self) -> usize {
        8 + self.hash_type.map_or(0, HashType::size)
    }

    /// The node named `oid`, its hash checked against `hash` when its
    /// parent keeps one, its header (or the lack of one) checked.
    fn read_node(&self, c: &Container, oid: u64, hash: Option<&[u8]>, root: bool) -> Result<Node> {
        let (paddr, noheader_val) = match &self.children {
            Children::Physical => (oid, false),
            Children::Virtual { omap, xid } => {
                let v = omap.lookup(c, oid, *xid)?.ok_or_else(|| Error::Malformed(format!("the B-tree node {oid:#x} is not in its object map")))?;
                (v.paddr, v.flags & super::omap_val::NOHEADER != 0)
            }
            Children::Live(nodes) => {
                let node = Node::parse(nodes.node(oid)?)?;
                if node.flags & node_flags::NOHEADER != 0 {
                    return Err(Error::Unsupported(format!("the headerless B-tree node {oid:#x} read through a container's object cache")));
                }
                if root != (node.flags & node_flags::ROOT != 0) {
                    return malformed(format!("the B-tree node {oid:#x} with flags {:#x} where a {} is", node.flags, if root { "root" } else { "node below the root" }));
                }
                return Ok(node);
            }
        };
        let bytes = c.block(paddr)?;
        if let (Some(t), Some(want)) = (self.hash_type, hash) {
            if t.digest(&bytes) != want {
                return Err(Error::Integrity(format!("the B-tree node {oid:#x} (block {paddr:#x}) does not have the hash its parent keeps")));
            }
        }
        let node = Node::parse(bytes)?;
        if node.flags & node_flags::NOHEADER != 0 {
            if node.bytes[..32].iter().any(|&b| b != 0) {
                return malformed(format!("the B-tree node {oid:#x} with BTNODE_NOHEADER and a header"));
            }
            if matches!(self.children, Children::Virtual { .. }) && !noheader_val {
                return malformed(format!("the B-tree node {oid:#x} without a header, mapped as one with"));
            }
        } else {
            let h = ObjHeader::parse(&node.bytes)?;
            let kind = if node.flags & node_flags::ROOT != 0 { otype::BTREE } else { otype::BTREE_NODE };
            if h.kind() != kind || h.oid != oid || h.subtype != self.subtype || !super::checksum_ok(&node.bytes) {
                return malformed(format!("the B-tree node {oid:#x} (block {paddr:#x}, header {h:?})"));
            }
        }
        if !root && node.flags & node_flags::ROOT != 0 {
            return malformed(format!("the B-tree node {oid:#x} is a root below the root"));
        }
        Ok(node)
    }

    /// The child an index entry names, and the hash its parent keeps of
    /// it. A sealed volume's hashed tree names a child relative to its root
    /// node's identifier.
    fn child_of<'v>(&self, v: &'v [u8]) -> Result<(u64, Option<&'v [u8]>)> {
        let stored = v.u64_at(0)?;
        match self.hash_type {
            Some(t) => {
                let hash = v.slice_at(8, t.size())?;
                let oid = stored.checked_add(self.root_oid).ok_or_else(|| Error::Malformed(format!("the B-tree child {stored:#x}")))?;
                Ok((oid, Some(hash)))
            }
            None => Ok((stored, None)),
        }
    }

    /// The root node: for a tree read through a container's object cache,
    /// the one its owner names now.
    fn root(&self, c: &Container) -> Result<Node> {
        match &self.children {
            Children::Live(nodes) => self.read_node(c, nodes.root()?, None, true),
            _ => self.read_node(c, self.root_oid, None, true),
        }
    }

    fn child(&self, c: &Container, parent: &Node, v: Option<&[u8]>) -> Result<Node> {
        let v = v.ok_or_else(|| Error::Malformed("an index entry without a value".into()))?;
        let (oid, hash) = self.child_of(v)?;
        let n = self.read_node(c, oid, hash, false)?;
        if n.level + 1 != parent.level {
            return malformed(format!("the B-tree node {oid:#x} of level {} below one of level {}", n.level, parent.level));
        }
        Ok(n)
    }

    /// The record with the greatest key not greater than the target, as
    /// `cmp` compares a key with it; none when every key is greater.
    pub fn find_le(&self, c: &Container, cmp: &mut dyn FnMut(&[u8]) -> Result<Ordering>) -> Result<Option<Record>> {
        let ivs = self.index_val_size();
        let mut node = self.root(c)?;
        loop {
            let mut best = None;
            for i in 0..node.nkeys {
                let (k, _) = node.entry(i, &self.info, ivs)?;
                if cmp(k)? == Ordering::Greater {
                    break;
                }
                best = Some(i);
            }
            let Some(i) = best else { return Ok(None) };
            let (k, v) = node.entry(i, &self.info, ivs)?;
            if node.is_leaf() {
                return Ok(Some((k.to_vec(), v.map(<[u8]>::to_vec))));
            }
            let v = v.map(<[u8]>::to_vec);
            node = self.child(c, &node, v.as_deref())?;
        }
    }

    /// Each record from the first whose key is not less than the target
    /// (`cmp` comparing a key with it), in order, until `visit` says to
    /// stop.
    pub fn scan(&self, c: &Container, cmp: &mut dyn FnMut(&[u8]) -> Result<Ordering>, visit: &mut dyn FnMut(&[u8], Option<&[u8]>) -> Result<bool>) -> Result<()> {
        let root = self.root(c)?;
        self.scan_node(c, &root, cmp, visit).map(|_| ())
    }

    fn scan_node(&self, c: &Container, node: &Node, cmp: &mut dyn FnMut(&[u8]) -> Result<Ordering>, visit: &mut dyn FnMut(&[u8], Option<&[u8]>) -> Result<bool>) -> Result<bool> {
        let ivs = self.index_val_size();
        if node.is_leaf() {
            for i in 0..node.nkeys {
                let (k, v) = node.entry(i, &self.info, ivs)?;
                if cmp(k)? == Ordering::Less {
                    continue;
                }
                if !visit(k, v)? {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        // The last child whose first key is less than the target holds
        // the first record not less than it, or the child after it does.
        let mut start = 0;
        for i in 0..node.nkeys {
            let (k, _) = node.entry(i, &self.info, ivs)?;
            if cmp(k)? != Ordering::Less {
                break;
            }
            start = i;
        }
        for i in start..node.nkeys {
            let (_, v) = node.entry(i, &self.info, ivs)?;
            let v = v.map(<[u8]>::to_vec);
            let child = self.child(c, node, v.as_deref())?;
            if !self.scan_node(c, &child, cmp, visit)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Every record, in order (a whole walk: tests and checks).
    pub fn walk(&self, c: &Container, visit: &mut dyn FnMut(&[u8], Option<&[u8]>) -> Result<bool>) -> Result<()> {
        self.scan(c, &mut |_| Ok(Ordering::Greater), visit)
    }
}
