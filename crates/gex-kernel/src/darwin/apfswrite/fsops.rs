//! What the kernel's APFS (2236.140.6) writes for the file-system calls
//! the restore makes on a volume it mounted read-write (K: kernelcache
//! addresses): the mount's clone-epoch write, `mkdir`, `chmod`, `chown`
//! and the unmount's `apfs_modified_by` entry.
//!
//! Each call is a file-system transaction (`fs_tx_enter`, K 0x66fbf98:
//! the volume superblock changed with it; `fs_tx_leave`, K 0x66fc5f4:
//! `apfs_last_mod_time` read from the clock and the superblock's +0x420
//! set to the transaction, K 0x66f70c8) inside the container's open
//! transaction, which closes only when the container commits (on internal
//! storage nothing commits on a timer, K 0x675a6a0): at a sync or an
//! unmount here. Every timestamp is a fresh `nanotime` reading
//! (K 0x6737394), taken from `now`.

use super::btree::Tree;
use super::tx::Nx;
use super::Put;

const J_INODE: u64 = 3;
const J_DIR_REC: u64 = 9;
const OBJ_MASK: u64 = 0x0fff_ffff_ffff_ffff;
const S_IFMT: u16 = 0o170000;
const S_IFDIR: u16 = 0o040000;
const S_IFREG: u16 = 0o100000;
/// The volume's default protection class when no boot argument or
/// device-tree default names one (K 0x6737260).
const DEFAULT_CP_CLASS: u32 = 3;
/// `INODE_NO_RSRC_FORK`; the parent's flags a child inherits (K
/// 0x66f251c), and those inherited when set (K 0x66a39b8).
const INODE_NO_RSRC_FORK: u64 = 0x8000;
const INHERIT_KEPT: u64 = 0x2040_0002;
const INHERIT_EXTRA: u64 = 0x2_3000;
/// Volume superblock fields.
const SB_UNMOUNT_TIME: usize = 0x40;
const SB_NEXT_OBJ_ID: usize = 0xb0;
const SB_NUM_FILES: usize = 0xb8;
const SB_NUM_DIRECTORIES: usize = 0xc0;
const SB_LAST_MOD_TIME: usize = 0x100;
const SB_MODIFIED_BY: usize = 0x140;
const SB_CLONEINFO_EPOCH: usize = 0x3d8;
const SB_CLONEINFO_XID: usize = 0x3e0;
const SB_LAST_XID: usize = 0x420;
const SB_INCOMPAT: usize = 0x38;
const SB_ROLE: usize = 0x3c4;
/// `APFS_MODIFIED_NAMELEN`, `APFS_MAX_HIST`.
const MODIFIED_NAMELEN: usize = 32;
const MAX_HIST: usize = 8;
/// What the kernel calls itself in `apfs_modified_by` ("%s (%s)").
pub const KEXT_ID: &str = "apfs_kext (2236.140.6)";

fn u64a(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

fn inode_key(ino: u64) -> Vec<u8> {
    (ino | J_INODE << 60).to_le_bytes().to_vec()
}

/// A directory record's key: the parent, the name's length and hash
/// (`utf8_normalizeOptCaseFoldAndHash`, its low 22 bits), the name.
fn drec_key(parent: u64, name: &str) -> Vec<u8> {
    let mut k = (parent | J_DIR_REC << 60).to_le_bytes().to_vec();
    let h = crate::darwin::apfsread::fs::name_hash(name) & 0x3f_ffff;
    k.extend_from_slice(&((h << 10) | (name.len() as u32 + 1)).to_le_bytes());
    k.extend_from_slice(name.as_bytes());
    k.push(0);
    k
}

/// `fs_tx_enter`: the container's transaction joined, the volume
/// superblock changed with it.
fn fs_tx_enter(nx: &mut Nx<'_>, vol: usize) -> Result<(), String> {
    nx.enter()?;
    nx.vol_sb(vol)?;
    Ok(())
}

/// `fs_tx_leave`: `apfs_last_mod_time` and the last change's transaction.
fn fs_tx_leave(nx: &mut Nx<'_>, vol: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    let t = now();
    let xid = nx.xid;
    let sb = nx.vol_sb(vol)?;
    sb.put64(SB_LAST_MOD_TIME, t);
    sb.put64(SB_LAST_XID, xid);
    Ok(())
}

fn check_volume(nx: &mut Nx<'_>, vol: usize) -> Result<(), String> {
    let sb = nx.vol_sb(vol)?;
    let incompat = u64a(sb, SB_INCOMPAT);
    if incompat & 0x1 != 0 {
        return Err("not implemented: names of a case-insensitive volume (case folding in the name hash)".into());
    }
    if incompat & 0x8 == 0 {
        return Err("not implemented: directory records of a volume without NORMALIZATION_INSENSITIVE (unhashed keys)".into());
    }
    let role = u16::from_le_bytes([sb[SB_ROLE], sb[SB_ROLE + 1]]);
    if [0u16, 2, 0x40, 0x240].contains(&role) {
        return Err(format!("not implemented: the document-identifier and +0x428 upkeep of a volume of role {role:#x}"));
    }
    Ok(())
}

/// The read-write mount's one write (`set_cloneinfo_id_epoch`, K
/// 0x6716184): a volume never given a clone epoch, or changed since its
/// last unmount's entry, gets its next object identifier as the epoch.
pub fn mount_rw(nx: &mut Nx<'_>, vol: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    check_volume(nx, vol)?;
    let sb = nx.vol_sb(vol)?.clone();
    let epoch = u64a(&sb, SB_CLONEINFO_EPOCH);
    let last = u64a(&sb, SB_MODIFIED_BY + MODIFIED_NAMELEN + 8);
    if epoch != 0 && u64a(&sb, SB_CLONEINFO_XID) == last {
        return Ok(());
    }
    fs_tx_enter(nx, vol)?;
    let sb = nx.vol_sb(vol)?;
    let next = u64a(sb, SB_NEXT_OBJ_ID);
    sb.put64(SB_CLONEINFO_EPOCH, next);
    fs_tx_leave(nx, vol, now)
}

/// An inode's value, the record's fields at their `j_inode_val_t`
/// offsets.
struct Inode(Vec<u8>);

impl Inode {
    fn internal_flags(&self) -> u64 {
        u64a(&self.0, 0x30)
    }
}

/// `mkdir` (apfs_vnop_mkdir K 0x6695a18, fs_obj_create_do K 0x67006b8,
/// fs_obj_create_name_checked K 0x66f251c) of `name` in directory
/// `parent` with `mode` (the caller's umask already applied) by owner
/// `uid` and group `gid`: the new inode's number, or EEXIST.
pub fn mkdir(nx: &mut Nx<'_>, vol: usize, parent: u64, name: &str, mode: u16, uid: u32, gid: u32, now: &mut dyn FnMut() -> u64) -> Result<Result<u64, i32>, String> {
    create_obj(nx, vol, parent, name, S_IFDIR | (mode & 0o7777), uid, gid, now)
}

/// `open(O_CREAT)` of a regular file (apfs_vnop_create, through the same
/// fs_obj_create_do and fs_obj_create_name_checked): a link count of one,
/// no data stream until the file is given a size, the volume's default
/// protection class (`setup_prot_class` K 0x66a3670: the parent's class
/// when it is a valid file class other than 0, else the volume's
/// `aks_default_class`, `kern.default_cp_class` or 3, K 0x6737260; the
/// restore kernel has neither the boot argument nor the device-tree
/// default, so 3), and the file counted (`num_files`).
pub fn create(nx: &mut Nx<'_>, vol: usize, parent: u64, name: &str, mode: u16, uid: u32, gid: u32, now: &mut dyn FnMut() -> u64) -> Result<Result<u64, i32>, String> {
    create_obj(nx, vol, parent, name, S_IFREG | (mode & 0o7777), uid, gid, now)
}

fn create_obj(nx: &mut Nx<'_>, vol: usize, parent: u64, name: &str, mode: u16, uid: u32, gid: u32, now: &mut dyn FnMut() -> u64) -> Result<Result<u64, i32>, String> {
    check_volume(nx, vol)?;
    let dir = mode & S_IFMT == S_IFDIR;
    if !dir && mode & S_IFMT != S_IFREG {
        return Err(format!("not implemented: creating an object of mode {mode:o}"));
    }
    if name.is_empty() || name.len() > 255 || name.contains('/') {
        return Err(format!("not implemented: the name checks for {name:?}"));
    }
    let dk = drec_key(parent, name);
    {
        let (t, mut st) = nx.fs_tree(vol)?;
        if t.get(&mut st, &dk)?.is_some() {
            return Ok(Err(17));
        }
    }
    let pv = {
        let (t, mut st) = nx.fs_tree(vol)?;
        t.get(&mut st, &inode_key(parent))?.ok_or_else(|| format!("no inode {parent:#x}"))?
    };
    let pi = Inode(pv);
    if pi.0.len() < 92 || u16::from_le_bytes([pi.0[0x50], pi.0[0x51]]) & S_IFMT != S_IFDIR {
        return Err(format!("{parent:#x} is not a directory"));
    }
    fs_tx_enter(nx, vol)?;
    let ino = {
        let sb = nx.vol_sb(vol)?;
        let ino = u64a(sb, SB_NEXT_OBJ_ID);
        sb.put64(SB_NEXT_OBJ_ID, ino + 1);
        ino
    };
    if ino & !OBJ_MASK != 0 {
        return Err("inode numbers past the object identifier space".into());
    }
    // The directory record: its type from the mode (DT_DIR 4, DT_REG 8).
    let t1 = now();
    let mut dv = ino.to_le_bytes().to_vec();
    dv.extend_from_slice(&t1.to_le_bytes());
    dv.extend_from_slice(&(mode >> 12).to_le_bytes());
    // The inode: the parent's flags kept and inherited, the protection
    // class; one extended field, the name.
    let extra = pi.internal_flags() & INHERIT_EXTRA;
    if extra != 0 {
        return Err(format!("not implemented: an object inheriting internal flags {extra:#x}"));
    }
    if pi.internal_flags() & 0x2 != 0 {
        return Err("not implemented: directory statistics (INODE_MAINTAIN_DIR_STATS)".into());
    }
    if !dir && pi.internal_flags() & 0x200_0000 != 0 {
        return Err("not implemented: a file made in a directory whose internal flags have 0x2000000 (the type-15 extended field, K 0x66f2b9c)".into());
    }
    let flags = (pi.internal_flags() & INHERIT_KEPT) | INODE_NO_RSRC_FORK;
    let parent_prot = u32::from_le_bytes(pi.0[0x3c..0x40].try_into().unwrap());
    let prot = if dir {
        parent_prot
    } else if parent_prot != 0 {
        return Err(format!("not implemented: a file in a directory of protection class {parent_prot} (setup_prot_class's class checks, K 0x67684a0)"));
    } else {
        DEFAULT_CP_CLASS
    };
    let nlink = if dir { 0u32 } else { 1 };
    let mut iv = Vec::new();
    for f in [parent, ino, t1, t1, t1, t1, flags] {
        iv.extend_from_slice(&f.to_le_bytes());
    }
    for f in [nlink, prot, 1, 0, uid, gid] {
        iv.extend_from_slice(&f.to_le_bytes());
    }
    iv.extend_from_slice(&mode.to_le_bytes());
    iv.extend_from_slice(&0u16.to_le_bytes());
    iv.extend_from_slice(&0u64.to_le_bytes());
    let data_len = name.len() + 1;
    let padded = data_len.div_ceil(8) * 8;
    iv.extend_from_slice(&1u16.to_le_bytes());
    iv.extend_from_slice(&(padded as u16).to_le_bytes());
    iv.extend_from_slice(&[4, 2]);
    iv.extend_from_slice(&(data_len as u16).to_le_bytes());
    iv.extend_from_slice(name.as_bytes());
    iv.resize(iv.len() + padded - name.len(), 0);
    {
        let (mut t, mut st) = nx.fs_tree(vol)?;
        t.insert(&mut st, &dk, Some(&dv))?;
        t.insert(&mut st, &inode_key(ino), Some(&iv))?;
        // The parent: its times, children and write generation.
        let t2 = now();
        let mut p = pi.0.clone();
        p.put64(0x18, t2);
        p.put64(0x20, t2);
        let nchildren = i32::from_le_bytes(p[0x38..0x3c].try_into().unwrap()) + 1;
        p.put32(0x38, nchildren as u32);
        let wgc = u32::from_le_bytes(p[0x40..0x44].try_into().unwrap()) + 1;
        p.put32(0x40, wgc);
        t.insert(&mut st, &inode_key(parent), Some(&p))?;
        nx.set_fs_tree(vol, t);
    }
    let sb = nx.vol_sb(vol)?;
    let at = if dir { SB_NUM_DIRECTORIES } else { SB_NUM_FILES };
    let n = u64a(sb, at);
    sb.put64(at, n + 1);
    fs_tx_leave(nx, vol, now)?;
    Ok(Ok(ino))
}

/// An inode value's extended fields: type, flags and data.
fn xfields(v: &[u8]) -> Result<Vec<(u8, u8, Vec<u8>)>, String> {
    if v.len() <= 0x5c {
        return Ok(Vec::new());
    }
    let n = u16::from_le_bytes([v[0x5c], v[0x5d]]) as usize;
    let mut at = 0x60 + 4 * n;
    let mut out = Vec::new();
    for i in 0..n {
        let d = 0x60 + 4 * i;
        let size = u16::from_le_bytes([v[d + 2], v[d + 3]]) as usize;
        let data = v.get(at..at + size).ok_or("an inode's extended field past its value")?.to_vec();
        out.push((v[d], v[d + 1], data));
        at += size.div_ceil(8) * 8;
    }
    Ok(out)
}

/// An inode value with these extended fields (`xf_blob_t`: the count,
/// the data's length, the descriptors, each field's data padded to 8).
fn with_xfields(v: &[u8], x: &[(u8, u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = v[..0x5c].to_vec();
    if x.is_empty() {
        return out;
    }
    let used: usize = x.iter().map(|f| f.2.len().div_ceil(8) * 8).sum();
    out.extend_from_slice(&(x.len() as u16).to_le_bytes());
    out.extend_from_slice(&(used as u16).to_le_bytes());
    for (t, f, d) in x {
        out.extend_from_slice(&[*t, *f]);
        out.extend_from_slice(&(d.len() as u16).to_le_bytes());
    }
    for (_, _, d) in x {
        out.extend_from_slice(d);
        out.resize(out.len() + d.len().div_ceil(8) * 8 - d.len(), 0);
    }
    out
}

const J_EXTENT: u64 = 2;
const J_DSTREAM_ID: u64 = 6;
const J_FILE_EXTENT: u64 = 8;
const INO_EXT_TYPE_DSTREAM: u8 = 8;
const XF_SYSTEM_FIELD: u8 = 0x20;
/// `APFS_KIND_NEW`.
const KIND_NEW: u64 = 1;
const SB_FS_ALLOC_COUNT: usize = 0x58;

fn fext_key(oid: u64, logical: u64) -> Vec<u8> {
    let mut k = (oid | J_FILE_EXTENT << 60).to_le_bytes().to_vec();
    k.extend_from_slice(&logical.to_le_bytes());
    k
}

fn fext_val(len: u64, phys: u64) -> Vec<u8> {
    let mut v = len.to_le_bytes().to_vec();
    v.extend_from_slice(&phys.to_le_bytes());
    v.extend_from_slice(&0u64.to_le_bytes());
    v
}

/// A file's data stream as the inode's extended field holds it.
struct Dstream {
    oid: u64,
    size: u64,
    alloced: u64,
}

fn dstream_of(v: &[u8]) -> Result<Option<Dstream>, String> {
    let oid = u64a(v, 0x08);
    Ok(xfields(v)?.into_iter().find(|f| f.0 == INO_EXT_TYPE_DSTREAM).map(|f| Dstream { oid, size: u64a(&f.2, 0), alloced: u64a(&f.2, 8) }))
}

/// What the kernel writes for a file's inode as its size and data change
/// that is not transcribed here (apfs_truncate_locked K 0x66a6bbc and the
/// write path's inode updates: the sparse-bytes field and INODE_IS_SPARSE,
/// the data stream's byte counters, the times and write generation): the
/// inode keeps the fields its creation and its data stream's creation gave
/// it, the stream's size and allocated size.
pub const FILE_INODE_STAND_IN: &str = "the inode fields the kernel updates as a file's size and data change (sparse bytes, data-stream byte counters, times, write generation) are not transcribed (stand-in: the fields its creation and its data stream's creation give it, and the stream's sizes); for asr's image file apfs_invert retires these records whole";

/// `ftruncate` growing a file with no data (apfs_vnop_setattr K 0x668e4a0
/// → apfs_truncate_locked K 0x66a6bbc → apfs_set_file_size K 0x6766f50):
/// its data stream made (K 0x66fb32c: the inode's private identifier, an
/// extended field of type 8, a `j_dstream_id` record with one reference),
/// then `alloc_space_for_write_with_hint_and_spino` (K 0x6707764) with no
/// length: no blocks, one sparse extent from the old allocated size to
/// the new size rounded up to the block size, and the stream's sizes.
pub fn truncate_grow(nx: &mut Nx<'_>, vol: usize, ino: u64, size: u64, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    check_volume(nx, vol)?;
    let bs = nx.l.bs;
    fs_tx_enter(nx, vol)?;
    let (mut t, mut st) = nx.fs_tree(vol)?;
    let mut v = t.get(&mut st, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    if u16::from_le_bytes([v[0x50], v[0x51]]) & S_IFMT != S_IFREG {
        return Err(format!("{ino:#x} is not a regular file"));
    }
    let mut x = xfields(&v)?;
    let old = match dstream_of(&v)? {
        Some(d) => d,
        None => {
            let oid = u64a(&v, 0x08);
            x.push((INO_EXT_TYPE_DSTREAM, XF_SYSTEM_FIELD, vec![0u8; 0x28]));
            let mut dv = 1u32.to_le_bytes().to_vec();
            dv.truncate(4);
            t.insert(&mut st, &(oid | J_DSTREAM_ID << 60).to_le_bytes(), Some(&dv))?;
            Dstream { oid, size: 0, alloced: 0 }
        }
    };
    if size <= old.size || old.alloced != 0 {
        return Err("not implemented: a truncate other than growing a file with no data".into());
    }
    let alloced = size.div_ceil(bs) * bs;
    t.insert(&mut st, &fext_key(old.oid, 0), Some(&fext_val(alloced, 0)))?;
    let d = x.iter_mut().find(|f| f.0 == INO_EXT_TYPE_DSTREAM).unwrap();
    d.2.put64(0, size);
    d.2.put64(8, alloced);
    v = with_xfields(&v, &x);
    t.insert(&mut st, &inode_key(ino), Some(&v))?;
    nx.set_fs_tree(vol, t);
    fs_tx_leave(nx, vol, now)
}

/// A write into a file's sparse extent (apfs_vnop_write K 0x6691308 →
/// cluster_write → apfs_vnop_blockmap K 0x66882ec →
/// fs_make_hole_range_writable K 0x670afbc), `data` at byte `off` (both
/// block multiples): for each piece the space manager grants
/// ([`Nx::alloc_data`]), the volume's allocation count, the block
/// references (a record per physically contiguous run of the stream's
/// blocks, merged with its neighbours, `insert_phys_extent` K 0x66f6ca0),
/// and the file extents: a piece at the sparse extent's start replaces it
/// or, physically following the extent before it, extends that one; any
/// other piece splits it; what the piece leaves of it stays sparse. The
/// blocks granted, in order.
pub fn write_sparse(nx: &mut Nx<'_>, vol: usize, ino: u64, off: u64, data: &[u8], now: &mut dyn FnMut() -> u64) -> Result<Vec<(u64, u64)>, String> {
    check_volume(nx, vol)?;
    let bs = nx.l.bs;
    if off % bs != 0 || data.len() as u64 % bs != 0 || data.is_empty() {
        return Err("not implemented: a write not of whole blocks".into());
    }
    fs_tx_enter(nx, vol)?;
    let v = {
        let (t, mut st) = nx.fs_tree(vol)?;
        t.get(&mut st, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?
    };
    let ds = dstream_of(&v)?.ok_or("a write to a file with no data stream")?;
    if off + data.len() as u64 > ds.size {
        return Err("not implemented: a write past the end of a file".into());
    }
    let mut out = Vec::new();
    let mut pos = off;
    let end = off + data.len() as u64;
    while pos < end {
        // The sparse extent holding `pos`.
        let (mut t, mut st) = nx.fs_tree(vol)?;
        let recs = t.records(&mut st)?;
        let ext: Vec<(u64, u64, u64)> = recs
            .iter()
            .filter(|(k, _)| k.len() == 16 && u64a(k, 0) == (ds.oid | J_FILE_EXTENT << 60))
            .map(|(k, v)| {
                let v = v.as_ref().unwrap();
                (u64a(k, 8), u64a(v, 0) & 0x00ff_ffff_ffff_ffff, u64a(v, 8))
            })
            .collect();
        let &(hl, hlen, hphys) = ext.iter().find(|&&(l, n, _)| l <= pos && pos < l + n).ok_or("a write where the file has no extent")?;
        if hphys != 0 {
            return Err("not implemented: a write over a file's allocated blocks".into());
        }
        drop(st);
        let want = (end - pos).min(hl + hlen - pos);
        let blocks = want.div_ceil(bs);
        let (a, got) = nx.alloc_data(blocks)?;
        let n = got * bs;
        {
            let sb = nx.vol_sb(vol)?;
            let c = u64a(sb, SB_FS_ALLOC_COUNT);
            sb.put64(SB_FS_ALLOC_COUNT, c + got);
        }
        phys_extent_add(nx, vol, a, got, ds.oid)?;
        // The file extents.
        let (mut t, mut st) = nx.fs_tree(vol)?;
        let d = pos - hl;
        if d == 0 {
            let prev = ext.iter().find(|&&(l, len, p)| hl != 0 && l + len == hl && p != 0 && p + len / bs == a).copied();
            if let Some((pl, plen, pp)) = prev {
                t.insert(&mut st, &fext_key(ds.oid, pl), Some(&fext_val(plen + n, pp)))?;
                t.remove(&mut st, &fext_key(ds.oid, hl))?;
            } else {
                t.insert(&mut st, &fext_key(ds.oid, hl), Some(&fext_val(n, a)))?;
            }
        } else {
            t.insert(&mut st, &fext_key(ds.oid, hl), Some(&fext_val(d, 0)))?;
            t.insert(&mut st, &fext_key(ds.oid, pos), Some(&fext_val(n, a)))?;
        }
        if pos + n < hl + hlen {
            t.insert(&mut st, &fext_key(ds.oid, pos + n), Some(&fext_val(hl + hlen - (pos + n), 0)))?;
        }
        nx.set_fs_tree(vol, t);
        let at = (pos - off) as usize;
        nx.write_data(a, &data[at..at + n as usize])?;
        out.push((a, got));
        pos += n;
    }
    fs_tx_leave(nx, vol, now)?;
    Ok(out)
}

/// A new physical extent of a data stream in the volume's extent-reference
/// tree (`apfs_update_phys_range` K 0x66f61b4 → `insert_phys_extent` K
/// 0x66f6ca0): merged with the record ending where it starts and the one
/// starting where it ends when they have the same owner, kind and
/// reference count.
fn phys_extent_add(nx: &mut Nx<'_>, vol: usize, paddr: u64, len: u64, owner: u64) -> Result<(), String> {
    let key = |p: u64| (p | J_EXTENT << 60).to_le_bytes().to_vec();
    let val = |l: u64| {
        let mut v = (l | KIND_NEW << 60).to_le_bytes().to_vec();
        v.extend_from_slice(&owner.to_le_bytes());
        v.extend_from_slice(&1i32.to_le_bytes());
        v
    };
    let (mut t, mut st) = nx.extentref_tree(vol)?;
    let recs: Vec<(u64, u64, u64, i32, u64)> = t
        .records(&mut st)?
        .into_iter()
        .map(|(k, v)| {
            let v = v.unwrap_or_default();
            (u64a(&k, 0) & OBJ_MASK, u64a(&v, 0) & OBJ_MASK, u64a(&v, 8), i32::from_le_bytes(v[16..20].try_into().unwrap()), u64a(&v, 0) >> 60)
        })
        .collect();
    if recs.iter().any(|&(p, l, ..)| p < paddr + len && paddr < p + l) {
        return Err("not implemented: a physical extent overlapping one already referenced".into());
    }
    let same = |o: u64, r: i32, k: u64| o == owner && r == 1 && k == KIND_NEW;
    let pred = recs.iter().find(|&&(p, l, o, r, k)| p + l == paddr && same(o, r, k)).copied();
    let succ = recs.iter().find(|&&(p, _, o, r, k)| p == paddr + len && same(o, r, k)).copied();
    let (start, mut total) = match pred {
        Some((p, l, ..)) => (p, l + len),
        None => (paddr, len),
    };
    if let Some((sp, sl, ..)) = succ {
        total += sl;
        t.remove(&mut st, &key(sp))?;
    }
    t.insert(&mut st, &key(start), Some(&val(total)))?;
    nx.set_extentref_tree(vol, t)
}

/// `chmod` of `ino` to `mode` (apfs_vnop_setattr K 0x668e4a0): the same
/// mode takes the fast path (K 0x668f1a8), which changes only the
/// in-memory inode, whose next write sets its change time anew.
pub fn chmod(nx: &mut Nx<'_>, vol: usize, ino: u64, mode: u16) -> Result<(), String> {
    let (t, mut st) = nx.fs_tree(vol)?;
    let v = t.get(&mut st, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    let cur = u16::from_le_bytes([v[0x50], v[0x51]]);
    if (cur ^ mode) & 0o7777 != 0 {
        return Err(format!("not implemented: chmod of {ino:#x} from {:o} to {:o} (setattr's general path)", cur & 0o7777, mode & 0o7777));
    }
    Ok(())
}

/// `chown` of `ino` (apfs_vnop_setattr's general path, K
/// 0x668f2a4..0x668f8a0): owner and group set, the change time read even
/// when they do not change, the inode rewritten.
pub fn chown(nx: &mut Nx<'_>, vol: usize, ino: u64, uid: u32, gid: u32, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    fs_tx_enter(nx, vol)?;
    {
        let (mut t, mut st) = nx.fs_tree(vol)?;
        let mut v = t.get(&mut st, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
        v.put32(0x48, uid);
        v.put32(0x4c, gid);
        v.put64(0x20, now());
        t.insert(&mut st, &inode_key(ino), Some(&v))?;
        nx.set_fs_tree(vol, t);
    }
    fs_tx_leave(nx, vol, now)
}

/// The unmount of a read-write volume (apfs_vfsop_unmount K 0x66c8214):
/// XNU's sync commits the container's transaction (`tx_finish`); then, in
/// the next transaction, which stays open, the kernel's `apfs_modified_by`
/// entry (an existing one of the same name moves to the front, else the
/// entries shift and the oldest goes), the clone transaction, and the
/// unmount time.
pub fn unmount(nx: &mut Nx<'_>, vol: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    nx.commit()?;
    nx.begin()?;
    let xid = nx.xid;
    let ts = now();
    let sb = nx.vol_sb(vol)?;
    let mut id = [0u8; MODIFIED_NAMELEN];
    id[..KEXT_ID.len()].copy_from_slice(KEXT_ID.as_bytes());
    let entry = |i: usize| SB_MODIFIED_BY + 0x30 * i;
    let i = (0..MAX_HIST - 1).find(|&i| sb[entry(i)..entry(i) + MODIFIED_NAMELEN] == id).unwrap_or(MAX_HIST - 1);
    sb.copy_within(entry(0)..entry(i), entry(1));
    // strlcpy: the name and its NUL; the bytes after it are the old
    // entry's.
    sb[entry(0)..entry(0) + KEXT_ID.len()].copy_from_slice(KEXT_ID.as_bytes());
    sb[entry(0) + KEXT_ID.len()] = 0;
    sb.put64(entry(0) + MODIFIED_NAMELEN, ts);
    sb.put64(entry(0) + MODIFIED_NAMELEN + 8, xid);
    sb.put64(SB_CLONEINFO_XID, xid);
    sb.put64(SB_LAST_XID, xid);
    let t = now();
    let sb = nx.vol_sb(vol)?;
    sb.put64(SB_UNMOUNT_TIME, t);
    sb.put64(SB_LAST_XID, xid);
    Ok(())
}

/// Looks `name` up in directory `parent`: its inode number.
pub fn lookup(nx: &mut Nx<'_>, vol: usize, parent: u64, name: &str) -> Result<Option<u64>, String> {
    let (t, mut st): (Tree, _) = nx.fs_tree(vol)?;
    Ok(t.get(&mut st, &drec_key(parent, name))?.map(|v| u64a(&v, 0)))
}
