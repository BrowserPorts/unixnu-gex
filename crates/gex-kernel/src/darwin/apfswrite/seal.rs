//! The System volume's sealed file-system tree, as the erase restore
//! makes it of the IPSW's operating system image (044-76040-038.dmg, not
//! itself sealed): `apfs_invert` takes the image's records as they are (but
//! its file extents, which then name the image file's blocks);
//! `restored_external` moves the staged data-volume trees out
//! (0x10002f15c..0x10002f358: `MobileAsset/PreinstalledAssets`,
//! `PreinstalledAssetsV2` and `staged_system_apps` under `/private/var`);
//! `apfs_sealvolume -R <remap> -I <root hash> -u <digest.db>` remaps the
//! records (`apfs_remap_records_fsroot`, 0x10000c108: every time the
//! mtree's root time, the data streams' counters 1, no protection class,
//! write generation 1, inode flags 0x10008 cleared, single-link siblings
//! dropped) and rebuilds the tree (`update_tree`, 0x100007ee4): extents out
//! to the file extent tree, extended attributes' streams' counters 1 and
//! allocation trimmed to whole blocks, a data-hash record per 16 KiB of
//! each stream (a compressed file's expanded data, under its resource
//! fork's stream) from `digest.db`; then inserts them in key order into a
//! hashed tree with no node headers, by APFS's sequential insertion
//! (0x10001e538, 0x1000201bc, 0x10001ffdc, 0x10001e004), its nodes named by
//! identifiers relative to the root, each index value the child's
//! identifier and the SHA-256 of the child's 4096 bytes. The root node's
//! SHA-256 is the root hash the restore's signed `root_hash` holds.
//!
//! The paths `apfs_sealvolume` has that this image does not reach (a
//! decmpfs attribute in a stream, a sparse inode, a compressed inode
//! pending its size, a directory's FS_UUID, a dstream to trim or remove, an
//! attribute it drops, a single-link sibling) are refused as not
//! implemented: nothing here checks them against the binary's output.

use crate::darwin::apfsread::Volume;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};

/// The block size the seal is for (the 4 KiB slot of the root hash).
pub const BS: u64 = 4096;
const NODE: usize = 4096;
const HDR: usize = 56;
const INFO: usize = 40;
/// An index value: the child's identifier and SHA-256.
const IDX_VLEN: usize = 40;
/// `sizeof(j_inode_val_t)` before its extended fields.
const INODE_LEN: usize = 92;
const OBJ_MASK: u64 = 0x0fff_ffff_ffff_ffff;
const S_IFMT: u16 = 0o170000;
const S_IFDIR: u16 = 0o040000;

/// Record types (`j_obj_types`).
mod ty {
    pub const INODE: u64 = 3;
    pub const XATTR: u64 = 4;
    pub const SIBLING_LINK: u64 = 5;
    pub const DSTREAM_ID: u64 = 6;
    pub const FILE_EXTENT: u64 = 8;
    pub const DIR_REC: u64 = 9;
    pub const SIBLING_MAP: u64 = 12;
    pub const FILE_INFO: u64 = 13;
}

/// The trees `restored_external` removes from System before sealing.
pub const DELETED_PATHS: [&str; 3] = ["/private/var/MobileAsset/PreinstalledAssets", "/private/var/MobileAsset/PreinstalledAssetsV2", "/private/var/staged_system_apps"];

type Rec = (Vec<u8>, Vec<u8>);

fn nim(what: impl Into<String>) -> String {
    format!("not implemented: {}", what.into())
}

fn jkey(k: &[u8]) -> (u64, u64) {
    let x = u64::from_le_bytes(k[..8].try_into().unwrap());
    (x & OBJ_MASK, x >> 60)
}

fn u16a(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn u32a(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64a(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// An `xf_blob_t`'s fields: (type, flags, data).
fn xfields(b: &[u8], off: usize) -> Vec<(u8, u8, Vec<u8>)> {
    if b.len() < off + 4 {
        return Vec::new();
    }
    let n = u16a(b, off) as usize;
    let mut p = off + 4 + 4 * n;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let e = off + 4 + 4 * i;
        let s = u16a(b, e + 2) as usize;
        out.push((b[e], b[e + 1], b[p..p + s].to_vec()));
        p += (s + 7) & !7;
    }
    out
}

fn xf_blob(fields: &[(u8, u8, Vec<u8>)]) -> Vec<u8> {
    let used: usize = fields.iter().map(|f| (f.2.len() + 7) & !7).sum();
    let mut out = (fields.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(&(used as u16).to_le_bytes());
    for (t, f, d) in fields {
        out.extend_from_slice(&[*t, *f]);
        out.extend_from_slice(&(d.len() as u16).to_le_bytes());
    }
    for (_, _, d) in fields {
        out.extend_from_slice(d);
        out.resize(out.len() + (((d.len() + 7) & !7) - d.len()), 0);
    }
    out
}

/// The image volume's file-system records, in key order.
pub fn records(v: &Volume) -> Result<Vec<Rec>, String> {
    let mut out = Vec::new();
    v.fs_tree
        .walk(&v.container, &mut |k, val| {
            out.push((k.to_vec(), val.map(<[u8]>::to_vec).unwrap_or_default()));
            Ok(true)
        })
        .map_err(|e| e.to_string())?;
    Ok(out)
}

/// `restored_external`'s removal of [`DELETED_PATHS`] (each with what is
/// under it, its directory record and its parent's child count), and of
/// the deleted inodes' data streams' records.
pub fn restore_deletions(recs: Vec<Rec>) -> Result<(Vec<Rec>, usize), String> {
    let mut children: HashMap<u64, HashMap<Vec<u8>, u64>> = HashMap::new();
    let mut links: HashMap<u64, Vec<(u64, Vec<u8>)>> = HashMap::new();
    for (k, val) in &recs {
        let (oid, t) = jkey(k);
        if t == ty::DIR_REC {
            let ln = (u32a(k, 8) & 0x3ff) as usize;
            let name = k[12..12 + ln - 1].to_vec();
            let fid = u64a(val, 0);
            children.entry(oid).or_default().insert(name, fid);
            links.entry(fid).or_default().push((oid, k.clone()));
        }
    }
    let lookup = |path: &str| -> Option<u64> {
        let mut cur = 2u64;
        for p in path.trim_matches('/').split('/') {
            cur = *children.get(&cur)?.get(p.as_bytes())?;
        }
        Some(cur)
    };
    let mut dels: HashSet<u64> = HashSet::new();
    let mut drop_keys: HashSet<Vec<u8>> = HashSet::new();
    let mut parent_dec: HashMap<u64, u32> = HashMap::new();
    for p in DELETED_PATHS {
        let Some(i) = lookup(p) else { continue };
        let par = &p[..p.rfind('/').unwrap()];
        let pi = lookup(par).ok_or_else(|| format!("{p}'s parent"))?;
        for (lp, lk) in links.get(&i).into_iter().flatten() {
            if *lp == pi {
                drop_keys.insert(lk.clone());
            }
        }
        *parent_dec.entry(pi).or_default() += 1;
        let mut stack = vec![i];
        while let Some(x) = stack.pop() {
            if dels.insert(x) {
                if let Some(ch) = children.get(&x) {
                    stack.extend(ch.values().copied());
                }
            }
        }
    }
    for &i in &dels {
        let ls = links.get(&i).map_or(&[][..], Vec::as_slice);
        if ls.len() > 1 && ls.iter().any(|(lp, _)| !dels.contains(lp)) {
            return Err(nim(format!("a hard link from outside a removed tree into it ({i:#x})")));
        }
    }
    // Streams the deleted inodes' attributes keep (a file's own data
    // stream is the inode's identifier).
    let mut streams = HashSet::new();
    for (k, val) in &recs {
        let (oid, t) = jkey(k);
        if dels.contains(&oid) && t == ty::XATTR && u16a(val, 0) & 1 != 0 {
            streams.insert(u64a(val, 4));
        }
    }
    let n = dels.len();
    let mut out = Vec::with_capacity(recs.len());
    for (k, mut val) in recs {
        let (oid, t) = jkey(&k);
        if dels.contains(&oid) || streams.contains(&oid) || drop_keys.contains(&k) {
            continue;
        }
        if t == ty::INODE {
            if let Some(&d) = parent_dec.get(&oid) {
                let c = u32a(&val, 56) - d;
                val[56..60].copy_from_slice(&c.to_le_bytes());
            }
        }
        out.push((k, val));
    }
    Ok((out, n))
}

/// `apfs_sealvolume -R`'s remap of the records: every time `t`, as the
/// mtree's remap dictionary gives them all.
pub fn remap(recs: Vec<Rec>, t: u64) -> Result<Vec<Rec>, String> {
    let mut nlink: HashMap<u64, u32> = HashMap::new();
    for (k, val) in &recs {
        let (oid, ty_) = jkey(k);
        if ty_ == ty::INODE {
            let mode = u16a(val, 80);
            nlink.insert(oid, if mode & S_IFMT != S_IFDIR { u32a(val, 56) } else { 1 });
        }
    }
    let mut out = Vec::with_capacity(recs.len());
    for (k, val) in recs {
        let (oid, ty_) = jkey(&k);
        match ty_ {
            ty::INODE => {
                let mut v = val.clone();
                for o in [16, 24, 32, 40] {
                    v[o..o + 8].copy_from_slice(&t.to_le_bytes());
                }
                let iflags = u64a(&val, 48);
                if iflags & 0x200 != 0 {
                    return Err(nim("remapping a sparse inode"));
                }
                if u32a(&val, 68) & 0x20 != 0 && iflags & 0x40000 == 0 {
                    return Err(nim("remapping a compressed inode pending its uncompressed size"));
                }
                v[48..56].copy_from_slice(&(iflags & !0x10008).to_le_bytes());
                v[60..64].copy_from_slice(&0u32.to_le_bytes());
                v[64..68].copy_from_slice(&1u32.to_le_bytes());
                let mut xf = xfields(&val, INODE_LEN);
                for f in &mut xf {
                    // INO_EXT_TYPE_DSTREAM: bytes written and read 1.
                    if f.0 == 8 {
                        f.2.truncate(24);
                        f.2.extend_from_slice(&1u64.to_le_bytes());
                        f.2.extend_from_slice(&1u64.to_le_bytes());
                    }
                }
                xf.sort_by_key(|f| f.0);
                let mut nv = v[..INODE_LEN].to_vec();
                if !xf.is_empty() {
                    nv.extend_from_slice(&xf_blob(&xf));
                }
                if nv.len() != val.len() {
                    return Err(nim("an inode whose remap changes its length"));
                }
                out.push((k, nv));
            }
            ty::XATTR => {
                let flags = u16a(&val, 0);
                let nl = u16a(&k, 8) as usize;
                if flags & 3 == 1 && &k[10..10 + nl - 1] == b"com.apple.decmpfs" {
                    return Err(nim("the remap's decmpfs fixup (a decmpfs attribute kept in a stream)"));
                }
                out.push((k, val));
            }
            ty::SIBLING_LINK | ty::SIBLING_MAP => {
                let who = if ty_ == ty::SIBLING_LINK { oid } else { u64a(&val, 0) };
                if nlink.get(&who) == Some(&1) {
                    return Err(nim("the remap's drop of a single-link sibling record"));
                }
                out.push((k, val));
            }
            ty::FILE_EXTENT | ty::DSTREAM_ID => out.push((k, val)),
            ty::DIR_REC => {
                let fid = u64a(&val, 0);
                let dflags = u16a(&val, 16);
                let sib: Vec<Vec<u8>> = xfields(&val, 18).into_iter().filter(|f| f.0 == 1).map(|f| f.2).collect();
                let mut nv = fid.to_le_bytes().to_vec();
                nv.extend_from_slice(&t.to_le_bytes());
                nv.extend_from_slice(&(dflags & 0xf).to_le_bytes());
                if nlink.get(&fid).copied().unwrap_or(1) > 1 {
                    let s = sib.first().ok_or_else(|| format!("a directory record of multi-link {fid:#x} with no sibling id"))?;
                    nv.extend_from_slice(&xf_blob(&[(1, 2, s.clone())]));
                } else if !sib.is_empty() {
                    return Err(nim("the remap's drop of a single-link directory record's sibling id"));
                }
                out.push((k, nv));
            }
            ty::FILE_INFO => {}
            other => return Err(format!("a record of type {other}, which aborts the remap")),
        }
    }
    Ok(out)
}

/// `digest.db`'s data hashes by stream: (byte offset, value: hashed
/// length in blocks, hash size, hash, pad).
pub type Digests = HashMap<u64, Vec<(u64, Vec<u8>)>>;

/// The restore's `digest.db`, a Berkeley DB 1.85 B-tree (little-endian,
/// magic 0x053162): its leaf pages in order, from the leftmost; keys
/// stream id and offset (offsets not a whole block are the 8 KiB and
/// 16 KiB slots' tails, which the 4 KiB seal does not use).
pub fn read_digests(db: &[u8]) -> Result<Digests, String> {
    const P_BINTERNAL: u32 = 1;
    const P_BLEAF: u32 = 2;
    if db.len() < 64 || u32a(db, 0) != 0x053162 {
        return Err("digest.db is not a Berkeley DB B-tree".into());
    }
    let psize = u32a(db, 8) as usize;
    let page = |pg: u32| -> Result<&[u8], String> { db.get(pg as usize * psize..(pg as usize + 1) * psize).ok_or_else(|| format!("digest.db page {pg}")) };
    let mut pg = 1u32;
    loop {
        let b = page(pg)?;
        if u32a(b, 12) & P_BINTERNAL == 0 {
            break;
        }
        let off = u16a(b, 20) as usize;
        pg = u32a(b, off + 4);
    }
    let mut d: Digests = HashMap::new();
    while pg != 0 && pg != u32::MAX {
        let b = page(pg)?;
        let (nxt, flags, lower) = (u32a(b, 8), u32a(b, 12), u16a(b, 16) as usize);
        if flags & P_BLEAF == 0 {
            return Err(format!("digest.db page {pg}: not a leaf"));
        }
        for i in 0..(lower - 20) / 2 {
            let off = u16a(b, 20 + 2 * i) as usize;
            let (ks, ds, fl) = (u32a(b, off) as usize, u32a(b, off + 4) as usize, b[off + 8]);
            if fl != 0 {
                return Err(nim("a digest.db item on overflow pages"));
            }
            let k = &b[off + 9..off + 9 + ks];
            let v = &b[off + 9 + ks..off + 9 + ks + ds];
            let (sid, o) = (u64a(k, 0), u64a(k, 8));
            if o & 0xfff != 0 {
                continue;
            }
            d.entry(sid).or_default().push((o, v.to_vec()));
        }
        pg = nxt;
    }
    for l in d.values_mut() {
        l.sort_by_key(|e| e.0);
    }
    Ok(d)
}

/// `update_tree`: the sealed tree's records in key order. `extents` gets
/// the file extents, which go to the file extent tree.
pub fn update_tree(recs: Vec<Rec>, digest: &Digests, extents: &mut Vec<Rec>) -> Result<Vec<Rec>, String> {
    let mut comp: HashMap<u64, bool> = HashMap::new();
    let mut decmpfs_hdr: HashMap<u64, Vec<u8>> = HashMap::new();
    for (k, val) in &recs {
        let (oid, t) = jkey(k);
        if t == ty::INODE {
            comp.insert(oid, u32a(val, 68) & 0x20 != 0);
        } else if t == ty::XATTR {
            let nl = u16a(k, 8) as usize;
            if &k[10..10 + nl - 1] == b"com.apple.decmpfs" && u16a(val, 0) & 2 != 0 {
                decmpfs_hdr.insert(oid, val[4..20].to_vec());
            }
        }
    }
    let mut plain: HashMap<u64, u64> = HashMap::new();
    let mut sizes: HashMap<u64, u64> = HashMap::new();
    let mut out = Vec::with_capacity(recs.len() + recs.len() / 2);
    let mut pending: Option<u64> = None;
    let emit = |sid: u64, sizes: &HashMap<u64, u64>, plain: &HashMap<u64, u64>, out: &mut Vec<Rec>| -> Result<(), String> {
        let size = plain.get(&sid).or_else(|| sizes.get(&sid)).copied().ok_or_else(|| format!("stream {sid:#x}'s size"))?;
        let ents = digest.get(&sid).ok_or_else(|| format!("digest.db has no hashes of stream {sid:#x}"))?;
        let want: Vec<(u64, u16)> = (0..size).step_by(16384).map(|o| (o, ((16384.min(size - o) + BS - 1) / BS) as u16)).collect();
        let got: Vec<(u64, u16)> = ents.iter().map(|(o, d)| (*o, u16a(d, 0))).collect();
        if want != got {
            return Err(format!("digest.db does not cover stream {sid:#x}"));
        }
        for (o, d) in ents {
            if d[2] != 32 {
                return Err(format!("stream {sid:#x}: a hash of {} bytes", d[2]));
            }
            let mut k = (sid | (ty::FILE_INFO << 60)).to_le_bytes().to_vec();
            // APFS_FILE_INFO_DATA_HASH in the top byte of info_and_lba.
            k.extend_from_slice(&(o | (1 << 56)).to_le_bytes());
            out.push((k, d[..35].to_vec()));
        }
        Ok(())
    };
    for (k, val) in recs {
        let (oid, t) = jkey(&k);
        if let Some(p) = pending {
            if oid != p || t > ty::FILE_EXTENT {
                emit(p, &sizes, &plain, &mut out)?;
                pending = None;
            }
        }
        match t {
            ty::INODE => {
                for (xt, _, d) in xfields(&val, INODE_LEN) {
                    if xt == 8 {
                        let (size, alloced) = (u64a(&d, 0), u64a(&d, 8));
                        if size == 0 || alloced != size.div_ceil(BS) * BS {
                            return Err(nim("update_tree's trim or removal of a file's data stream"));
                        }
                        if comp[&oid] {
                            return Err(nim("update_tree on a compressed inode with a data stream"));
                        }
                        sizes.insert(u64a(&val, 8), size);
                    }
                    if xt == 11 && u16a(&val, 80) & S_IFMT == S_IFDIR {
                        return Err(nim("update_tree's removal of a directory's FS_UUID"));
                    }
                }
                out.push((k, val));
            }
            ty::XATTR => {
                let flags = u16a(&val, 0);
                let nl = u16a(&k, 8) as usize;
                let name = &k[10..10 + nl - 1];
                let kept: [&[u8]; 5] = [b"com.apple.decmpfs", b"com.apple.rootless", b"com.apple.fs.symlink", b"com.apple.fs.firmlink", b"com.apple.ResourceFork"];
                if !kept.contains(&name) && flags & 1 == 0 {
                    return Err(nim("update_tree's drop of an embedded extended attribute it does not keep"));
                }
                let mut val = val;
                if flags & 1 != 0 {
                    val[0..2].copy_from_slice(&(flags & !0x10).to_le_bytes());
                    let (sid, size, alloced) = (u64a(&val, 4), u64a(&val, 12), u64a(&val, 20));
                    let r = size.div_ceil(BS) * BS;
                    if r < alloced {
                        if name != b"com.apple.ResourceFork" {
                            return Err(nim("update_tree's trim of an overallocated attribute stream other than a resource fork (0x1000091c0)"));
                        }
                        val[20..28].copy_from_slice(&r.to_le_bytes());
                    }
                    val[0x24..0x2c].copy_from_slice(&1u64.to_le_bytes());
                    val[0x2c..0x34].copy_from_slice(&1u64.to_le_bytes());
                    if name == b"com.apple.ResourceFork" && comp.get(&oid) == Some(&true) {
                        let hdr = decmpfs_hdr.get(&oid).ok_or_else(|| format!("{oid:#x}'s decmpfs header"))?;
                        if u32a(hdr, 4) != 4 {
                            return Err(nim("a resource-fork compressed file of a decmpfs type other than 4"));
                        }
                        plain.insert(sid, u64a(hdr, 8));
                    } else if name == b"com.apple.decmpfs" {
                        return Err(nim("a decmpfs attribute in a stream reaching update_tree"));
                    }
                    sizes.insert(sid, size);
                }
                out.push((k, val));
            }
            ty::FILE_EXTENT => {
                pending = Some(oid);
                extents.push((k, val));
            }
            ty::FILE_INFO => {}
            _ => out.push((k, val)),
        }
    }
    if let Some(p) = pending {
        emit(p, &sizes, &plain, &mut out)?;
    }
    Ok(out)
}

/// A node of the tree being built.
struct BNode {
    level: u16,
    ents: Vec<(Vec<u8>, Val)>,
    toc_cap: usize,
    kv: usize,
    root: bool,
    /// The entry an index split took off the end: its key and value
    /// length, left in the node's free lists.
    stale: Option<(Vec<u8>, usize)>,
}

enum Val {
    Leaf(Vec<u8>),
    Child(usize),
}

/// The table of contents a node of `n` entries keeps: 8 entries at a time
/// (0x10001e004).
fn toc_need(n: usize) -> usize {
    let r = (n + 7) & !7;
    if r == 0 {
        8
    } else {
        r
    }
}

impl BNode {
    fn avail(&self) -> usize {
        NODE - HDR - if self.root { INFO } else { 0 }
    }
    fn flist(&self) -> usize {
        self.stale.as_ref().map_or(0, |(k, vl)| k.len() + vl)
    }
    fn free(&self) -> isize {
        self.avail() as isize - (self.toc_cap * 8) as isize - self.kv as isize - self.flist() as isize
    }
    /// 0x10001ffdc: whether entries of these key and value lengths fit.
    fn has_room(&self, lens: &[(usize, usize)]) -> bool {
        let n = self.ents.len();
        let (cur, new) = (toc_need(n), toc_need(n + lens.len()));
        let need = lens.iter().map(|(k, v)| k + v).sum::<usize>() + new.saturating_sub(cur) * 8;
        let avail = self.free() + self.flist() as isize + (self.toc_cap.saturating_sub(cur) * 8) as isize;
        need as isize <= avail
    }
    fn add(&mut self, k: Vec<u8>, v: Val, vl: usize) {
        let n = self.ents.len();
        if toc_need(n + 1) > self.toc_cap {
            self.toc_cap = toc_need(n + 1);
        }
        self.kv += k.len() + vl;
        self.ents.push((k, v));
    }
    fn longest_key(&self) -> usize {
        self.ents.iter().map(|e| e.0.len()).max().unwrap_or(0)
    }
}

/// The sealed tree being built by sequential insertion: its nodes by
/// identifier relative to the root (the root 0).
pub struct Builder {
    nodes: Vec<BNode>,
    longest_key: usize,
    longest_val: usize,
    count: u64,
}

impl Default for Builder {
    fn default() -> Self {
        Builder { nodes: vec![BNode { level: 0, ents: Vec::new(), toc_cap: 8, kv: 0, root: true, stale: None }], longest_key: 0, longest_val: 0, count: 0 }
    }
}

impl Builder {
    fn alloc(&mut self, level: u16) -> usize {
        self.nodes.push(BNode { level, ents: Vec::new(), toc_cap: 8, kv: 0, root: false, stale: None });
        self.nodes.len() - 1
    }

    /// The sequential split of index node `p`: its last entry moves to a
    /// new node on its right (the space it took left in its free lists).
    fn split_index(&mut self, gp: Option<usize>, p: usize) -> Result<usize, String> {
        let right = self.alloc(self.nodes[p].level);
        let (k, c) = self.nodes[p].ents.pop().ok_or("splitting an empty index node")?;
        self.nodes[p].kv -= k.len() + IDX_VLEN;
        if self.nodes[p].stale.is_some() {
            return Err(nim("an index node split twice"));
        }
        if !self.nodes[p].root {
            self.nodes[p].stale = Some((k.clone(), IDX_VLEN));
        }
        self.nodes[right].add(k, c, IDX_VLEN);
        self.finish_split(gp, p, right)?;
        Ok(right)
    }

    fn finish_split(&mut self, gp: Option<usize>, p: usize, right: usize) -> Result<(), String> {
        let rk = self.nodes[right].ents[0].0.clone();
        if self.nodes[p].root {
            let level = self.nodes[p].level;
            let left = self.alloc(level);
            let ents = std::mem::take(&mut self.nodes[p].ents);
            for (k, v) in ents {
                let vl = match &v {
                    Val::Leaf(b) if level == 0 => b.len(),
                    _ => IDX_VLEN,
                };
                self.nodes[left].add(k, v, vl);
            }
            let lk = self.nodes[left].ents[0].0.clone();
            let pn = &mut self.nodes[p];
            pn.kv = 0;
            pn.toc_cap = 8;
            pn.level += 1;
            pn.add(lk, Val::Child(left), IDX_VLEN);
            pn.add(rk, Val::Child(right), IDX_VLEN);
            return Ok(());
        }
        let gp = gp.ok_or("a split of a node with no parent")?;
        self.nodes[gp].add(rk, Val::Child(right), IDX_VLEN);
        Ok(())
    }

    fn last_child(&self, n: usize) -> usize {
        match self.nodes[n].ents.last() {
            Some((_, Val::Child(c))) => *c,
            _ => unreachable!("an index node's last entry"),
        }
    }

    /// Inserts a record after every one inserted so far.
    pub fn insert(&mut self, k: Vec<u8>, v: Vec<u8>) -> Result<(), String> {
        let (kl, vl) = (k.len(), v.len());
        let newlongest = self.longest_key.max(kl);
        let mut p: Option<usize> = None;
        let mut c = 0usize;
        // Down the rightmost path, splitting a parent with no room for two
        // index entries above a full child.
        while self.nodes[c].level > 0 {
            let gp = p;
            p = Some(c);
            let pi = c;
            c = self.last_child(pi);
            let lc = self.nodes[c].longest_key();
            let lens = if self.nodes[pi].level >= 2 {
                let m = kl.max(lc);
                [(m, IDX_VLEN), (m, IDX_VLEN)]
            } else {
                [(lc, IDX_VLEN), (kl, IDX_VLEN)]
            };
            if self.nodes[pi].has_room(&lens) {
                continue;
            }
            let croom = if self.nodes[c].level == 0 {
                self.nodes[c].has_room(&[(kl, vl)])
            } else {
                let m2 = self.longest_key.max(kl);
                self.nodes[c].has_room(&[(m2, IDX_VLEN), (m2, IDX_VLEN)])
            };
            if croom {
                continue;
            }
            // The child moved with the parent's last entry: it hangs from
            // the new right node now.
            let right = self.split_index(gp, pi)?;
            p = Some(right);
        }
        self.longest_key = newlongest;
        self.longest_val = self.longest_val.max(vl);
        self.count += 1;
        if self.nodes[c].has_room(&[(kl, vl)]) {
            self.nodes[c].add(k, Val::Leaf(v), vl);
            return Ok(());
        }
        let right = self.alloc(0);
        self.nodes[right].add(k.clone(), Val::Leaf(v), vl);
        if self.nodes[c].root {
            let left = self.alloc(0);
            let ents = std::mem::take(&mut self.nodes[c].ents);
            for (kk, vv) in ents {
                let l = if let Val::Leaf(b) = &vv { b.len() } else { IDX_VLEN };
                self.nodes[left].add(kk, vv, l);
            }
            let lk = self.nodes[left].ents[0].0.clone();
            let cn = &mut self.nodes[c];
            cn.kv = 0;
            cn.toc_cap = 8;
            cn.level = 1;
            cn.add(lk, Val::Child(left), IDX_VLEN);
            cn.add(k, Val::Child(right), IDX_VLEN);
        } else {
            let p = p.ok_or("a leaf with no parent")?;
            if !self.nodes[p].has_room(&[(kl, IDX_VLEN)]) {
                return Err("the leaf's parent has no room".into());
            }
            self.nodes[p].add(k, Val::Child(right), IDX_VLEN);
        }
        Ok(())
    }

    /// The node count.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Node `n`'s 4096 bytes, its values given (a leaf's records', or its
    /// children's identifiers and hashes).
    fn node_bytes(&self, n: usize, vals: &[Vec<u8>], bt_flags: u32) -> Result<Vec<u8>, String> {
        let nd = &self.nodes[n];
        let mut toc = vec![0u8; nd.toc_cap * 8];
        let mut keys = Vec::new();
        let mut vparts: Vec<Vec<u8>> = Vec::new();
        let (mut ko, mut vo) = (0usize, 0usize);
        for (i, ((k, _), v)) in nd.ents.iter().zip(vals).enumerate() {
            vo += v.len();
            for (j, x) in [ko, k.len(), vo, v.len()].into_iter().enumerate() {
                toc[i * 8 + 2 * j..i * 8 + 2 * j + 2].copy_from_slice(&(x as u16).to_le_bytes());
            }
            keys.extend_from_slice(k);
            ko += k.len();
            vparts.push(v.clone());
        }
        let (mut kf, mut vf) = ((0xffffu16, 0u16), (0xffffu16, 0u16));
        if let Some((sk, svl)) = &nd.stale {
            let i = nd.ents.len();
            for (j, x) in [ko, sk.len(), vo + svl, *svl].into_iter().enumerate() {
                toc[i * 8 + 2 * j..i * 8 + 2 * j + 2].copy_from_slice(&(x as u16).to_le_bytes());
            }
            kf = (ko as u16, sk.len() as u16);
            vf = ((vo + svl) as u16, *svl as u16);
            keys.extend_from_slice(&0xffffu16.to_le_bytes());
            keys.extend_from_slice(&(sk.len() as u16).to_le_bytes());
            keys.extend_from_slice(&sk[4..]);
            let mut sv = 0xffffu16.to_le_bytes().to_vec();
            sv.extend_from_slice(&(*svl as u16).to_le_bytes());
            sv.resize(*svl, 0);
            vparts.push(sv);
        }
        let vals_b: Vec<u8> = vparts.iter().rev().flatten().copied().collect();
        let flags: u16 = (if nd.level == 0 { 0x2 } else { 0 }) | (if nd.root { 0x1 } else { 0 }) | 0x8 | 0x10;
        let used = toc.len() + keys.len() + vals_b.len();
        if used > nd.avail() {
            return Err("a sealed node overflowing".into());
        }
        let free = nd.avail() - used;
        let mut raw = vec![0u8; NODE];
        for (o, x) in [(32usize, u32::from(flags)), (34, u32::from(nd.level))] {
            raw[o..o + 2].copy_from_slice(&(x as u16).to_le_bytes());
        }
        raw[36..40].copy_from_slice(&(nd.ents.len() as u32).to_le_bytes());
        for (o, x) in [(40usize, 0u16), (42, toc.len() as u16), (44, keys.len() as u16), (46, free as u16), (48, kf.0), (50, kf.1), (52, vf.0), (54, vf.1)] {
            raw[o..o + 2].copy_from_slice(&x.to_le_bytes());
        }
        raw[56..56 + toc.len()].copy_from_slice(&toc);
        raw[56 + toc.len()..56 + toc.len() + keys.len()].copy_from_slice(&keys);
        let vend = NODE - if nd.root { INFO } else { 0 };
        raw[vend - vals_b.len()..vend].copy_from_slice(&vals_b);
        if nd.root {
            let i = NODE - INFO;
            for (j, x) in [bt_flags, NODE as u32, 0, 0, self.longest_key as u32, self.longest_val as u32].into_iter().enumerate() {
                raw[i + 4 * j..i + 4 * j + 4].copy_from_slice(&x.to_le_bytes());
            }
            raw[i + 24..i + 32].copy_from_slice(&self.count.to_le_bytes());
            raw[i + 32..i + 40].copy_from_slice(&(self.nodes.len() as u64).to_le_bytes());
        }
        Ok(raw)
    }

    /// The tree's nodes' bytes by identifier, and the root hash: each
    /// index value its child's identifier and SHA-256.
    pub fn seal(&self, bt_flags: u32, keep: &mut Option<BTreeMap<u64, Vec<u8>>>) -> Result<[u8; 32], String> {
        self.seal_node(0, bt_flags, keep)
    }

    fn seal_node(&self, n: usize, bt_flags: u32, keep: &mut Option<BTreeMap<u64, Vec<u8>>>) -> Result<[u8; 32], String> {
        let mut vals = Vec::with_capacity(self.nodes[n].ents.len());
        for (_, v) in &self.nodes[n].ents {
            vals.push(match v {
                Val::Leaf(b) => b.clone(),
                Val::Child(c) => {
                    let h = self.seal_node(*c, bt_flags, keep)?;
                    let mut x = (*c as u64).to_le_bytes().to_vec();
                    x.extend_from_slice(&h);
                    x
                }
            });
        }
        let raw = self.node_bytes(n, &vals, bt_flags)?;
        let h: [u8; 32] = Sha256::digest(&raw).into();
        if let Some(m) = keep {
            m.insert(n as u64, raw);
        }
        Ok(h)
    }
}

/// The sealed tree's `bt_flags`: sequential insertion, nonaligned keys and
/// values, hashed, headerless.
pub const SEALED_BT_FLAGS: u32 = 0x1c2;

/// The System volume's sealed records from the image's volume `v`, the
/// mtree's root time `t` and `digest.db`'s hashes: the tree's records and
/// the file extents for the file extent tree.
pub fn sealed_records(v: &Volume, t: u64, digest: &Digests) -> Result<(Vec<Rec>, Vec<Rec>), String> {
    let recs = records(v)?;
    let (recs, _) = restore_deletions(recs)?;
    let recs = remap(recs, t)?;
    let mut extents = Vec::new();
    let out = update_tree(recs, digest, &mut extents)?;
    Ok((out, extents))
}

/// The sealed tree of `recs` (in key order) and its root hash.
pub fn build(recs: Vec<Rec>) -> Result<(Builder, [u8; 32]), String> {
    let mut b = Builder::default();
    for (k, v) in recs {
        b.insert(k, v)?;
    }
    let h = b.seal(SEALED_BT_FLAGS, &mut None)?;
    Ok((b, h))
}

/// `asv_process_rsrc_xattr` (0x100015c7c) as update_tree meets each
/// `com.apple.ResourceFork` attribute kept in a data stream: the streams
/// whose file extents update_tree cuts at their size rounded up to whole
/// blocks (FUN_10000adf8): a compressed file's resource fork of a non-zero
/// size always (its compressed data-stream record, whose +0x38 is that
/// size), another file's only when it holds more than that
/// (`asv_track_overallocated_dstream` 0x100015e1c). By stream, that size.
pub fn extent_limits(recs: &[Rec]) -> Result<HashMap<u64, u64>, String> {
    let mut comp: HashMap<u64, bool> = HashMap::new();
    let mut out = HashMap::new();
    for (k, val) in recs {
        let (oid, t) = jkey(k);
        if t == ty::INODE {
            comp.insert(oid, u32a(val, 68) & 0x20 != 0);
            continue;
        }
        if t != ty::XATTR || u16a(val, 0) & 1 == 0 {
            continue;
        }
        let nl = u16a(k, 8) as usize;
        if &k[10..10 + nl - 1] != b"com.apple.ResourceFork" {
            continue;
        }
        let (sid, size, alloced) = (u64a(val, 4), u64a(val, 12), u64a(val, 20));
        let r = size.div_ceil(BS) * BS;
        if comp.get(&oid) == Some(&true) {
            if u16a(val, 2) != 0x30 {
                return Err(format!("Unexpected size of extended attribute record for inode {oid}: expected 48, got {}", u16a(val, 2)));
            }
            if size != 0 {
                out.insert(sid, r);
            }
        } else if r < alloced {
            out.insert(sid, r);
        }
    }
    Ok(out)
}

/// update_tree's file extents (`extents`, the file-system tree's file
/// extent records in key order): each of a stream with a limit
/// ([`extent_limits`]) cut there (FUN_10000adf8: the part past it, the
/// whole extent at most, recorded in the overallocated-ranges tree by
/// first block, the extent shortened by it), then one not cut to nothing
/// inserted into the file extent tree (`fext_tree_insert_with_tree`
/// 0x10002f104: key {stream, logical address}, value {length, the
/// extent's flags but bit 0 in its top byte; physical block}). The file
/// extent tree's records in insertion order and the ranges to free:
/// first block to blocks.
pub fn fext_records(extents: &[Rec], limits: &HashMap<u64, u64>, bs: u64) -> Result<(Vec<Rec>, BTreeMap<u64, u64>), String> {
    let mut out = Vec::with_capacity(extents.len());
    let mut ranges = BTreeMap::new();
    for (k, v) in extents {
        let (oid, t) = jkey(k);
        if t != ty::FILE_EXTENT {
            return Err(format!("a record of type {t} among the file extents"));
        }
        let logical = u64a(k, 8);
        let lf = u64a(v, 0);
        let (mut len, flags, phys) = (lf & 0x00ff_ffff_ffff_ffff, (lf >> 56) as u8, u64a(v, 8));
        if let Some(&lim) = limits.get(&oid) {
            let end = logical + len;
            if lim <= end && end != lim {
                let excess = (end - lim).min(len);
                // bt_insert into the u64 tree: a second range at the same
                // block is EEXIST, which aborts the seal.
                if ranges.insert(phys + (len - excess) / bs, excess / bs).is_some() {
                    return Err(format!("Cannot insert range to deallocate at offset {logical} in data stream {oid}: EEXIST"));
                }
                len -= excess;
            }
        }
        if len == 0 {
            continue;
        }
        if phys == 0 {
            return Err(format!("Unexpected sparse extent at the offset {logical} in the data stream {oid}"));
        }
        let mut fk = oid.to_le_bytes().to_vec();
        fk.extend_from_slice(&logical.to_le_bytes());
        let mut fv = (len | u64::from(flags & 0xfe) << 56).to_le_bytes().to_vec();
        fv.extend_from_slice(&phys.to_le_bytes());
        out.push((fk, fv));
    }
    Ok((out, ranges))
}

/// The time `apfs_sealvolume -R` gives every record (seal.md 1, 2): the
/// remap dictionary `mtree -p /mnt1 -m` writes holds, for each of the five
/// time keys, the reference value of the first entry whose time on disk
/// differs from it (the spec's own value, or the spec root's birth time
/// where the spec has none); `populate_time_from_dict` takes the first of
/// CHANGE, BIRTH, MODIFICATION, ACCESS, DATEADDED there. With every time
/// in `mtree_txt` equal to the root's birth time, that is the root's birth
/// time as soon as one entry differs; the root's own inode (`root`, its
/// `j_inode_val_t`) is checked first. A spec with other times, or a root
/// that matches it, would need mtree's whole walk: refused. The dictionary's
/// identifier keys are not made: apfs_invert keeps the image's inode
/// numbers, sibling and stream identifiers, which are the spec's.
pub fn remap_time(mtree_txt: &[u8], root: &[u8]) -> Result<u64, String> {
    let text = std::str::from_utf8(mtree_txt).map_err(|_| "mtree.txt is not UTF-8")?;
    let parse = |v: &str| -> Result<u64, String> {
        let (s, n) = v.split_once('.').ok_or_else(|| format!("a time {v:?} without nanoseconds"))?;
        let (s, n): (u64, u64) = (s.parse().map_err(|_| format!("time {v:?}"))?, n.parse().map_err(|_| format!("time {v:?}"))?);
        Ok(s * 1_000_000_000 + n)
    };
    let mut times = Vec::new();
    let mut root_birth = None;
    let (mut in_root, mut cont, mut seen_root) = (false, false, false);
    for line in text.lines() {
        let l = line.trim();
        if !cont && (l.starts_with('#') || l.is_empty()) {
            continue;
        }
        let words: Vec<&str> = l.split_whitespace().filter(|w| *w != "\\").collect();
        if !cont {
            // A new entry: the spec's root is the first "." at the start
            // of a line.
            in_root = !seen_root && !line.starts_with(char::is_whitespace) && words.first() == Some(&".");
            seen_root |= in_root;
        }
        for w in &words {
            if let Some((kw, v)) = w.split_once('=') {
                if ["time", "btime", "ctime", "atime", "ptime"].contains(&kw) {
                    let t = parse(v)?;
                    times.push(t);
                    if in_root && kw == "btime" {
                        root_birth = Some(t);
                    }
                }
            }
        }
        cont = l.ends_with('\\');
    }
    let rb = root_birth.ok_or("mtree.txt's root has no btime")?;
    if times.iter().any(|&t| t != rb) {
        return Err(nim("a spec whose times differ from its root's birth time (mtree's walk order decides the remap dictionary's values)"));
    }
    // The root's create, modification, change and access times.
    if [16usize, 24, 32, 40].iter().all(|&o| u64a(root, o) == rb) {
        return Err(nim("a System root whose times match the spec (mtree's walk of the other entries)"));
    }
    Ok(rb)
}

/// `Img4DecodeInit` of an Image4 file (`IMG4 ::= SEQUENCE { "IMG4", IM4P,
/// [0] IM4M OPTIONAL, [1] IM4R OPTIONAL }`): its IM4P's type and data.
pub fn img4_payload(img4: &[u8]) -> Result<(&[u8], &[u8]), String> {
    use crate::darwin::image4::{der, tag};
    let it = der::parse_sequence(img4, &[der::spec(tag::IA5_STRING, 0), der::spec(tag::SEQUENCE, der::SAVE_DER), der::spec(tag::context(0), der::OPTIONAL), der::spec(tag::context(1), der::OPTIONAL)]).map_err(|e| format!("failed to decode img4: {e}"))?;
    if it[0] != Some(b"IMG4".as_slice()) {
        return Err("failed to decode img4: not an IMG4".into());
    }
    crate::darwin::aar::im4p_payload(it[1].ok_or("failed to decode img4: no IM4P")?)
}

/// What `asv_extract_hash_blob` (0x100015204, without `-P`:
/// `Img4DecodeInit`) and `authapfs_select_root_hash` (0x100016e98) take
/// from the root-hash Image4 file: its payload, of type "isys" or "xsys"
/// and 208 bytes, the hash length at +0xc and the 4, 8 and 16 KiB root
/// hashes at +0x10, +0x50 and +0x90.
pub fn root_hashes(img4: &[u8]) -> Result<[Vec<u8>; 3], String> {
    let (ty_, p) = img4_payload(img4)?;
    if p.len() != 0xd0 {
        return Err(format!("unexpected payload data size: {} != 208", p.len()));
    }
    if ty_.len() != 4 {
        return Err(format!("unexpected payload type length : {}", ty_.len()));
    }
    if ty_ != b"isys" && ty_ != b"xsys" {
        return Err(format!("unexpected payload type: {}", String::from_utf8_lossy(ty_)));
    }
    let n = u32a(p, 0xc) as usize;
    if n > 0x40 {
        return Err(format!("a root hash of {n} bytes"));
    }
    Ok([p[0x10..0x10 + n].to_vec(), p[0x50..0x50 + n].to_vec(), p[0x90..0x90 + n].to_vec()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::darwin::apfsread::Container;
    use std::sync::Arc;

    /// The mtree's root time (`mtree.txt`'s spec root, the remap's every
    /// time).
    const T_SPEC: u64 = 1_777_576_853_000_000_000;

    /// The IPSW's system image (GEX_TEST_UDIF) and the restore's digest.db
    /// (GEX_TEST_DIGESTDB) seal to the signed 4 KiB root hash.
    #[test]
    fn system_image_seals_to_the_signed_root_hash() {
        let (Ok(img), Ok(db)) = (std::env::var("GEX_TEST_UDIF"), std::env::var("GEX_TEST_DIGESTDB")) else { return };
        let f = std::fs::File::open(&img).unwrap();
        let size = f.metadata().unwrap().len();
        let u = Arc::new(crate::darwin::udif::Udif::open(Arc::new(crate::darwin::apfsread::tests_support::HostFile(f, size))).unwrap());
        let p = u.partition("Apple_APFS").unwrap();
        let c = Arc::new(Container::open(Arc::new(crate::darwin::udif::PartitionMedium { image: u, index: p })).unwrap());
        let v = c.volume(0).unwrap().unwrap();
        let digest = read_digests(&std::fs::read(&db).unwrap()).unwrap();
        // The same digests as the IPSW's mtree carries them
        // (GEX_TEST_MTREE), read in process.
        if let Ok(mtree) = std::env::var("GEX_TEST_MTREE") {
            let archive = crate::darwin::aar::mtree_payload(&std::fs::read(&mtree).unwrap()).unwrap();
            let db = crate::darwin::aar::file(&archive, "digest.db").unwrap();
            assert!(read_digests(db).unwrap() == digest);
        }
        let (recs, extents) = sealed_records(&v, T_SPEC, &digest).unwrap();
        assert!(!extents.is_empty());
        let (_, h) = build(recs.clone()).unwrap();
        let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "61f50c6269a33b16100d87e8a69de5797ccf07c1ab54ad68b02d5f236f366745");
        // The mtree's remap time from its spec and the image's root.
        if let Ok(mtree) = std::env::var("GEX_TEST_MTREE") {
            let archive = crate::darwin::aar::mtree_payload(&std::fs::read(&mtree).unwrap()).unwrap();
            let txt = crate::darwin::aar::file(&archive, "mtree.txt").unwrap();
            let root = records(&v).unwrap().into_iter().find(|(k, _)| jkey(k) == (2, ty::INODE)).unwrap().1;
            assert_eq!(remap_time(txt, &root).unwrap(), T_SPEC);
        }
        // The one overallocated stream: a compressed file's resource fork
        // of 1,083,643 bytes in 266 blocks, its last block cut off.
        let srecs = remap(restore_deletions(records(&v).unwrap()).unwrap().0, T_SPEC).unwrap();
        let limits = extent_limits(&srecs).unwrap();
        let (frecs, ranges) = fext_records(&extents, &limits, BS).unwrap();
        assert_eq!(frecs.len(), extents.len());
        assert_eq!(ranges.len(), 1);
        let (&p, &n) = ranges.iter().next().unwrap();
        assert_eq!((p, n), (0x1594e5 + 265, 1));
    }
}
