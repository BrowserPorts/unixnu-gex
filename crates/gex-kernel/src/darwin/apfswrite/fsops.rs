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
const S_IFDIR: u16 = 0o040000;
/// `INODE_NO_RSRC_FORK`; the parent's flags a child inherits (K
/// 0x66f251c), and those inherited when set (K 0x66a39b8).
const INODE_NO_RSRC_FORK: u64 = 0x8000;
const INHERIT_KEPT: u64 = 0x2040_0002;
const INHERIT_EXTRA: u64 = 0x2_3000;
/// Volume superblock fields.
const SB_UNMOUNT_TIME: usize = 0x40;
const SB_NEXT_OBJ_ID: usize = 0xb0;
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
    nx.begin()?;
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
    check_volume(nx, vol)?;
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
    if pi.0.len() < 92 || u16::from_le_bytes([pi.0[0x50], pi.0[0x51]]) & 0o170000 != S_IFDIR {
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
    // The directory record.
    let t1 = now();
    let mut dv = ino.to_le_bytes().to_vec();
    dv.extend_from_slice(&t1.to_le_bytes());
    dv.extend_from_slice(&4u16.to_le_bytes());
    // The inode: the parent's flags kept and inherited, its protection
    // class; one extended field, the name.
    let extra = pi.internal_flags() & INHERIT_EXTRA;
    if extra != 0 {
        return Err(format!("not implemented: a directory inheriting internal flags {extra:#x}"));
    }
    if pi.internal_flags() & 0x2 != 0 {
        return Err("not implemented: directory statistics (INODE_MAINTAIN_DIR_STATS)".into());
    }
    let flags = (pi.internal_flags() & INHERIT_KEPT) | INODE_NO_RSRC_FORK;
    let prot = u32::from_le_bytes(pi.0[0x3c..0x40].try_into().unwrap());
    let mut iv = Vec::new();
    for f in [parent, ino, t1, t1, t1, t1, flags] {
        iv.extend_from_slice(&f.to_le_bytes());
    }
    for f in [0u32, prot, 1, 0, uid, gid] {
        iv.extend_from_slice(&f.to_le_bytes());
    }
    iv.extend_from_slice(&(S_IFDIR | (mode & 0o7777)).to_le_bytes());
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
    let n = u64a(sb, SB_NUM_DIRECTORIES);
    sb.put64(SB_NUM_DIRECTORIES, n + 1);
    fs_tx_leave(nx, vol, now)?;
    Ok(Ok(ino))
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
