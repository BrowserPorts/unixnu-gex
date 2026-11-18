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
const S_IFLNK: u16 = 0o120000;
/// The volume's default protection class when no boot argument or
/// device-tree default names one (K 0x6737260).
const DEFAULT_CP_CLASS: u32 = 3;
/// `INODE_NO_RSRC_FORK`; the parent's flags a child inherits (K
/// 0x66f251c), and those inherited when set (K 0x66a39b8).
const INODE_NO_RSRC_FORK: u64 = 0x8000;
const INHERIT_KEPT: u64 = 0x2040_0002;
const INHERIT_EXTRA: u64 = 0x2_3000;
/// `INODE_PINNED_TO_MAIN`.
const INODE_PINNED_TO_MAIN: u64 = 0x1000;
/// Volume superblock fields.
const SB_UNMOUNT_TIME: usize = 0x40;
const SB_NEXT_OBJ_ID: usize = 0xb0;
const SB_NUM_FILES: usize = 0xb8;
const SB_NUM_DIRECTORIES: usize = 0xc0;
const SB_NUM_SYMLINKS: usize = 0xc8;
const SB_TOTAL_BLOCKS_ALLOCED: usize = 0xe0;
const SB_LAST_MOD_TIME: usize = 0x100;
const SB_VOLNAME: usize = 0x2c0;
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

/// `fs_tx_leave` (K 0x66f70c8): `apfs_last_mod_time` and the last
/// change's transaction; on a volume of a role that keeps document
/// identifiers (no role, User, Data, Enterprise), +0x428's 0x10 too; then
/// `tx_leave(nx, xid, 0)`, whose close rule ([`Nx::close_due`], checked at
/// every leave: drafts/s27/re-txdata.md 0.2) commits the transaction when
/// this was its last holder.
fn fs_tx_leave(nx: &mut Nx<'_>, vol: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    fs_tx_mark(nx, vol, now)?;
    if nx.close_due(0)? {
        nx.commit()?;
    }
    Ok(())
}

/// `fs_tx_leave`'s volume fields.
fn fs_tx_mark(nx: &mut Nx<'_>, vol: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    let t = now();
    let xid = nx.xid;
    let sb = nx.vol_sb(vol)?;
    sb.put64(SB_LAST_MOD_TIME, t);
    sb.put64(SB_LAST_XID, xid);
    if DOC_ID_ROLES.contains(&u16::from_le_bytes([sb[SB_ROLE], sb[SB_ROLE + 1]])) {
        let f = u32::from_le_bytes(sb[SB_DOC_ID_FLAGS..SB_DOC_ID_FLAGS + 4].try_into().unwrap());
        sb.put32(SB_DOC_ID_FLAGS, f | 0x10);
    }
    Ok(())
}

/// The roles whose volumes keep document identifiers (K 0x66f70c8, K
/// 0x6714ea4, K 0x671ae4c): no role, User, Data, Enterprise.
const DOC_ID_ROLES: [u16; 4] = [0, 2, 0x40, 0x240];
/// The superblock's document-identifier flags, its doc-id tree and
/// previous tree, and its encryption-rolling state.
const SB_DOC_ID_FLAGS: usize = 0x428;
const SB_DOC_ID_TREE: usize = 0x430;
const SB_DOC_ID_PREV_TREE: usize = 0x438;
const SB_ER_STATE: usize = 0x3d0;
const SB_FS_FLAGS: usize = 0x108;
const SB_FEATURES: usize = 0x28;
const SB_RO_COMPAT: usize = 0x30;

/// What the names of the volume's directory records need: hashed keys,
/// no case folding.
fn check_names(nx: &mut Nx<'_>, vol: usize) -> Result<(), String> {
    let (sb, _) = nx.vol_sb_read(vol)?;
    let incompat = u64a(sb, SB_INCOMPAT);
    if incompat & 0x1 != 0 {
        return Err("not implemented: names of a case-insensitive volume (case folding in the name hash)".into());
    }
    if incompat & 0x8 == 0 {
        return Err("not implemented: directory records of a volume without NORMALIZATION_INSENSITIVE (unhashed keys)".into());
    }
    Ok(())
}

fn check_volume(nx: &mut Nx<'_>, vol: usize) -> Result<(), String> {
    check_names(nx, vol)?;
    let (sb, _) = nx.vol_sb_read(vol)?;
    let role = u16::from_le_bytes([sb[SB_ROLE], sb[SB_ROLE + 1]]);
    if DOC_ID_ROLES.contains(&role) {
        return Err(format!("not implemented: the document-identifier upkeep of file operations on a volume of role {role:#x}"));
    }
    Ok(())
}

/// `clean_up_doc_id_trees_if_needed` (K 0x67150f8) at a read-write
/// mount: on a volume of a document-identifier role, the volume's last
/// change (+0x420) checked against the transaction its superblock was last
/// dirtied in or written by (`mark_doc_id_index_for_rebuild_if_needed`, K
/// 0x6714ea4); then the doc-id trees' rebuild, rotation and cleanup that
/// +0x428's bits 1 to 3 and the previous tree ask for. Only the states
/// where it writes nothing are implemented: the volume unchanged since its
/// superblock was written, no doc-id tree to check, nothing to rebuild.
fn doc_id_cleanup(nx: &mut Nx<'_>, vol: usize) -> Result<(), String> {
    let (sb, x) = nx.vol_sb_read(vol)?;
    let role = u16::from_le_bytes([sb[SB_ROLE], sb[SB_ROLE + 1]]);
    if !DOC_ID_ROLES.contains(&role) {
        return Ok(());
    }
    let flags = u32::from_le_bytes(sb[SB_DOC_ID_FLAGS..SB_DOC_ID_FLAGS + 4].try_into().unwrap());
    if u64a(sb, SB_LAST_XID) != x || (role == 0x240 && flags & 0x10 == 0) {
        return Err(format!("not implemented: marking the doc-id index for rebuild (K 0x6714ea4: the volume's last change {:#x}, its superblock's transaction {x:#x})", u64a(sb, SB_LAST_XID)));
    }
    if u64a(sb, SB_FS_FLAGS) & 1 == 0 && u64a(sb, SB_ER_STATE) == 0 && u64a(sb, SB_DOC_ID_TREE) != 0 {
        return Err("not implemented: the doc-id tree's check at mount (K 0x6714ea4's tree read)".into());
    }
    if flags & 0xe != 0 || (u64a(sb, SB_DOC_ID_PREV_TREE) != 0 && flags & 1 == 0) {
        return Err(format!("not implemented: the doc-id trees' rebuild or cleanup at mount (K 0x67150f8: flags {flags:#x})"));
    }
    Ok(())
}

/// A read-write mount (`apfs_vfsop_mount` K 0x66c5fac, of a volume's
/// device node): inside mount(2), the doc-id check ([`doc_id_cleanup`])
/// and the one write of `set_cloneinfo_id_epoch` (K 0x6716184: a volume
/// never given a clone epoch, or changed since its last unmount's entry,
/// gets its next object identifier as the epoch); then the threads the
/// mount's tail starts (K 0x66c8030..0x66c8074, drafts/s21/re-data.md
/// 1.3), which write only on a volume they run on: the pfkur thread's
/// temporary inode ([`pfkur_resume`]) and the fixup thread's transaction
/// ([`volume_fixup`]), in that order (RUN_STAND_IN: the two threads are not
/// ordered). The purgatory cleaner finds no deleted snapshot, the
/// encryption-rolling resume returns on a ramdisk boot, and the keybag
/// notification handler only waits: none writes.
pub fn mount_rw(nx: &mut Nx<'_>, vol: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    check_names(nx, vol)?;
    doc_id_cleanup(nx, vol)?;
    let (sb, _) = nx.vol_sb_read(vol)?;
    let epoch = u64a(sb, SB_CLONEINFO_EPOCH);
    let last = u64a(sb, SB_MODIFIED_BY + MODIFIED_NAMELEN + 8);
    if epoch == 0 || u64a(sb, SB_CLONEINFO_XID) != last {
        fs_tx_enter(nx, vol)?;
        let sb = nx.vol_sb(vol)?;
        let next = u64a(sb, SB_NEXT_OBJ_ID);
        sb.put64(SB_CLONEINFO_EPOCH, next);
        fs_tx_leave(nx, vol, now)?;
    }
    pfkur_resume(nx, vol, now)?;
    volume_fixup(nx, vol, now)
}

/// The volume's crypto kind (K 0x671a778, from `fs_flags & 0x109`): 3 for
/// a volume with a VEK (0x100), 2 for one with software crypto (8), 1 for
/// an encrypted one with its own key (0), else 0.
fn vol_crypto(sb: &[u8]) -> u32 {
    match u64a(sb, SB_FS_FLAGS) & 0x109 {
        0x100 => 3,
        8 => 2,
        0 => 1,
        _ => 0,
    }
}

/// The private directory's inode number (`PRIV_DIR_INO_NUM`).
const PRIV_DIR_INO: u64 = 3;

/// `pfkur_resume` (K 0x66b7b78) at a read-write mount: on a volume with
/// per-file keys (incompat 0x40, ro_compat without 0x2) of crypto kind 3,
/// with no pfk transcription under way (K 0x66a99b8: none at a fresh
/// Data's first mount) and no `-apfs_pfkur_disable` boot argument (the
/// restore's has none), the rolling thread starts (K 0x66a9bcc); its
/// first act (`pfkur_alloc_tls` K 0x66a9d04) makes its temporary inode
/// ([`alloc_tmp_ino`]), and with the pfkur tree empty it then parks (state
/// 3, K 0x66a9fb8) until the unmount stops it. The inode is kept in
/// `nx.pfkur_tmp`.
fn pfkur_resume(nx: &mut Nx<'_>, vol: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    let (sb, _) = nx.vol_sb_read(vol)?;
    if u64a(sb, SB_INCOMPAT) & 0x40 == 0 || u64a(sb, SB_RO_COMPAT) & 0x2 != 0 || vol_crypto(sb) != 3 {
        return Ok(());
    }
    if nx.pfkur_tmp.contains_key(&vol) {
        return Err("not implemented: a pfkur thread already running at the mount (apfs + 0x1ee8 set)".into());
    }
    let pfkur_root = u64a(sb, 0x418);
    if pfkur_root == 0 || nx.phys_node_counts(pfkur_root)? != (0, 0) {
        return Err("not implemented: the pfkur thread's iteration of a non-empty pfkur tree (K 0x66a9fb8)".into());
    }
    let ino = alloc_tmp_ino(nx, vol, now)?;
    nx.pfkur_tmp.insert(vol, ino);
    Ok(())
}

/// `alloc_tmp_ino_helper(apfs, &ino, 0, 0, NULL)` (K 0x6700e5c), in its
/// own file-system transaction: the next object identifier taken (no file
/// counted), the inode made in the private directory as
/// `fs_obj_create_name_checked` (K 0x66f251c, called at K 0x6700f44) makes
/// it with the helper's arguments (mode 0100600, owner and group 0, no BSD
/// flags, no extra internal flags, protection class 0), its name
/// `tmp-ino-xattr-dstream-0x0-0x<ino>`; then a data-stream field
/// (`XF_SYSTEM_FIELD`, its sizes and counters 0 and its default crypto
/// identifier all ones: the helper's third argument stands only with a
/// non-zero fourth) and the stream's `j_dstream_id` record with one
/// reference. Its inode number.
pub fn alloc_tmp_ino(nx: &mut Nx<'_>, vol: usize, now: &mut dyn FnMut() -> u64) -> Result<u64, String> {
    check_names(nx, vol)?;
    fs_tx_enter(nx, vol)?;
    let ino = {
        let sb = nx.vol_sb(vol)?;
        let ino = u64a(sb, SB_NEXT_OBJ_ID);
        sb.put64(SB_NEXT_OBJ_ID, ino + 1);
        ino
    };
    let name = format!("tmp-ino-xattr-dstream-0x0-{ino:#x}");
    let pv = get_rec(nx, vol, &inode_key(PRIV_DIR_INO))?.ok_or("the volume has no private directory")?;
    if get_rec(nx, vol, &drec_key(PRIV_DIR_INO, &name))?.is_some() {
        return Err(format!("the pfkur temporary inode's name {name} exists (EEXIST)"));
    }
    let v = obj_create_name(nx, vol, PRIV_DIR_INO, &Inode(pv), &name, S_IFREG | 0o600, 0, 0, ino, 0, 0, now)?;
    let mut ds = vec![0u8; 0x28];
    ds.put64(0x10, u64::MAX);
    let mut x = xfields(&v)?;
    x.push((INO_EXT_TYPE_DSTREAM, XF_SYSTEM_FIELD, ds));
    put_rec(nx, vol, &inode_key(ino), &with_xfields(&v, &x))?;
    put_rec(nx, vol, &(u64a(&v, 0x08) | J_DSTREAM_ID << 60).to_le_bytes(), &1u32.to_le_bytes())?;
    fs_tx_leave(nx, vol, now)?;
    Ok(ino)
}

/// `free_tmp_ino_helper(apfs, tmp, 0)` (K 0x6701940), run by the pfkur
/// thread when the unmount stops it: in a file-system transaction, the
/// temporary inode's directory entry found by its name field and removed
/// with the private directory's update ([`remove_dir_entry`], K
/// 0x66fd1ac), its data stream's `j_dstream_id` record, then the inode.
pub fn free_tmp_ino(nx: &mut Nx<'_>, vol: usize, ino: u64, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    fs_tx_enter(nx, vol)?;
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no temporary inode {ino:#x}"))?;
    let name = xfields(&v)?.into_iter().find(|f| f.0 == 4).ok_or("the temporary inode has no name field")?.2;
    let name = std::str::from_utf8(name.strip_suffix(&[0]).ok_or("a name field without its NUL")?).map_err(|_| "a name that is not UTF-8")?.to_string();
    let parent = u64a(&v, 0);
    let dk = drec_key(parent, &name);
    if get_rec(nx, vol, &dk)?.is_none() {
        return Err(format!("not implemented: a temporary inode whose entry {name} is gone (K 0x6701940's assertion path)"));
    }
    remove_dir_entry(nx, vol, parent, &dk, now)?;
    let private = u64a(&v, 0x08);
    if private != 0 {
        remove_rec(nx, vol, &(private | J_DSTREAM_ID << 60).to_le_bytes())?;
    }
    remove_rec(nx, vol, &inode_key(ino))?;
    fs_tx_leave(nx, vol, now)
}

/// `apfs_volume_fixup` (K 0x6713d14) at a read-write mount, and the
/// thread it starts (K 0x6713e00). The thread runs on a volume with the
/// hard-link map feature (0x2) and no doc-id fixup pending when it has the
/// expanded records (incompat 0x200) and is Data, or is another role with
/// fs_flags 0x400, and (on Data, e-apfs) no pfk transcription; its work:
/// the doc-id fixup loop (only with +0x428's bit 0), the post-offline-purge
/// cleanup (expanded records: an iteration of the purgeable tombstones,
/// which only offline purging makes and nothing here has made, then one
/// file-system transaction clearing fs_flags 0x400), and the
/// overprovisioning file's flag (none at the first mount).
fn volume_fixup(nx: &mut Nx<'_>, vol: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    let (sb, _) = nx.vol_sb_read(vol)?;
    let role = u16::from_le_bytes([sb[SB_ROLE], sb[SB_ROLE + 1]]);
    let (features, incompat, fs_flags) = (u64a(sb, SB_FEATURES), u64a(sb, SB_INCOMPAT), u64a(sb, SB_FS_FLAGS));
    let doc_flags = u32::from_le_bytes(sb[SB_DOC_ID_FLAGS..SB_DOC_ID_FLAGS + 4].try_into().unwrap());
    if features & 2 != 0 && doc_flags & 1 == 0 {
        if incompat & 0x200 == 0 {
            if role != 0x40 {
                return Ok(());
            }
        } else if role != 0x40 && fs_flags & 0x400 == 0 {
            return Ok(());
        }
        // K 0x66a99b8 on Data of an e-apfs device: no pfk transcription
        // state at the mount (apfs + 0x125, + 0x2298: set only by the
        // crypto migration), so only a crypto kind 1 volume answers 1.
        if role == 0x40 && vol_crypto(sb) == 1 {
            return Ok(());
        }
    }
    if features & 2 == 0 {
        return Err("not implemented: the fixup thread's hard-link map conversion (K 0x671478c)".into());
    }
    if doc_flags & 1 != 0 {
        return Err("not implemented: the fixup thread's doc-id fixup loop (K 0x6713e00)".into());
    }
    if incompat & 0x200 != 0 {
        if incompat & 0x100 != 0 {
            return Err("not implemented: the post-offline-purge cleanup on a volume's secondary tree".into());
        }
        fs_tx_enter(nx, vol)?;
        let sb = nx.vol_sb(vol)?;
        let f = u64a(sb, SB_FS_FLAGS);
        sb.put64(SB_FS_FLAGS, f & !0x400);
        fs_tx_leave(nx, vol, now)?;
    }
    if lookup(nx, vol, ROOT_DIR_INO, ".overprovisioning_file")?.is_some() {
        return Err("not implemented: the fixup thread's overprovisioning file flag (K 0x6713e00, inode flag 0x800)".into());
    }
    Ok(())
}

/// The root directory's inode number.
const ROOT_DIR_INO: u64 = 2;

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
    let dir = mode & S_IFMT == S_IFDIR;
    let link = mode & S_IFMT == S_IFLNK;
    // A directory on Data, or a directory or file on User: the only
    // document-identifier upkeep of mkdir and create is the tombstone
    // inheritance (K 0x66a3a38), which needs a tombstone the restore's
    // threads do not hold (drafts/s23/re-uml-data.md 1.3), and on User
    // their inode and directory records go to the file-system tree, not
    // the secondary one (K 0x66ed1bc; drafts/s23/re-user-copy.md 2.1).
    let doc_ok = !link && {
        let (sb, _) = nx.vol_sb_read(vol)?;
        match u16::from_le_bytes([sb[SB_ROLE], sb[SB_ROLE + 1]]) {
            0x40 => u64a(sb, SB_INCOMPAT) & 0x100 == 0,
            0x2 => vol_crypto(sb) == 1,
            _ => false,
        }
    };
    if doc_ok {
        check_names(nx, vol)?;
    } else {
        check_volume(nx, vol)?;
    }
    if !dir && !link && mode & S_IFMT != S_IFREG {
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
    // The extra flags (K 0x66a39b8, called by mkdir at K 0x6695bb8 and by
    // create for a regular file at K 0x668c510; a symbolic link gets none):
    // the parent's 0x23000, and PINNED_TO_MAIN (0x1000) on a Preboot or VM
    // volume when neither pinning flag came from the parent.
    let extra = if link {
        0
    } else {
        let mut e = pi.internal_flags() & INHERIT_EXTRA;
        let role = {
            let (sb, _) = nx.vol_sb_read(vol)?;
            u16::from_le_bytes([sb[SB_ROLE], sb[SB_ROLE + 1]])
        };
        if e & 0x3000 == 0 && (role == 0x10 || role == 0x8) {
            e |= INODE_PINNED_TO_MAIN;
        }
        e
    };
    if extra & !INODE_PINNED_TO_MAIN != 0 {
        return Err(format!("not implemented: an object inheriting internal flags {extra:#x}"));
    }
    let parent_prot = u32::from_le_bytes(pi.0[0x3c..0x40].try_into().unwrap());
    // A symbolic link is made with class 0 (apfs_vnop_symlink calls no
    // setup_prot_class).
    let (encrypted, crypto) = {
        let (sb, _) = nx.vol_sb_read(vol)?;
        (u64a(sb, SB_FS_FLAGS) & 1 == 0, vol_crypto(sb))
    };
    // setup_prot_class with no explicit class (K 0x66a3670's else branch):
    // a directory takes its parent's class; on a VEK volume (fs_flags
    // 0x100) PROT_CLASS_EXPLICIT (internal 0x8) is set for classes 0, 1, 2
    // and 7, and for 4 when class-F keys are supported (K 0x67372d0 in
    // crypto mode 3: yes) (K 0x66a3820..0x66a3858).
    let mut extra = extra;
    if dir && crypto == 3 && parent_prot <= 7 && (1u32 << parent_prot) & 0x97 != 0 {
        extra |= 0x8;
    }
    // On a volume with its own key (crypto mode 1) a file takes the
    // default class C like an unencrypted one's and a directory its
    // parent's, with no PROT_CLASS_EXPLICIT (drafts/s23/re-user-copy.md
    // 2.2, 2.3).
    // A file on a VEK volume takes its parent's class when that is a
    // valid file class (cp_is_valid_class(1, c): 1 to 7) other than 0, with
    // PROT_CLASS_EXPLICIT by the directory rule above (K 0x66a36c0..
    // 0x66a3858; drafts/s26/re-aks-data.md 3.6); under a class-0 parent it
    // would take the volume's default (fs + 0x350), not transcribed.
    let vek_file_class = encrypted && !dir && !link && crypto == 3 && (1..=7).contains(&parent_prot);
    if vek_file_class && (1u32 << parent_prot) & 0x97 != 0 {
        extra |= 0x8;
    }
    if encrypted && !dir && !link && crypto != 1 && !vek_file_class {
        return Err("not implemented: a file made with no explicit class on a VEK volume under a class-0 directory (setup_prot_class's volume default, fs + 0x350)".into());
    }
    if encrypted && dir && crypto != 3 && crypto != 1 {
        return Err("not implemented: a directory on an encrypted volume of crypto kind 0 or 2".into());
    }
    let prot = if dir {
        parent_prot
    } else if link {
        0
    } else if vek_file_class {
        parent_prot
    } else if parent_prot != 0 {
        return Err(format!("not implemented: a file in a directory of protection class {parent_prot} (setup_prot_class's class checks, K 0x67684a0)"));
    } else {
        DEFAULT_CP_CLASS
    };
    obj_create_name(nx, vol, parent, &pi, name, mode, uid, gid, ino, prot, extra, now)?;
    let sb = nx.vol_sb(vol)?;
    let at = if dir {
        SB_NUM_DIRECTORIES
    } else if link {
        SB_NUM_SYMLINKS
    } else {
        SB_NUM_FILES
    };
    let n = u64a(sb, at);
    sb.put64(at, n + 1);
    if !link {
        fs_tx_leave(nx, vol, now)?;
    }
    Ok(Ok(ino))
}

/// `fs_obj_create_name_checked` (K 0x66f251c) in an open file-system
/// transaction, the name already found absent: object `ino` named `name`
/// in directory `parent` (whose inode value `pi` is), with `mode`, owner
/// `uid`, group `gid`, no BSD flags, protection class `prot` (its
/// eleventh argument) and the extra internal flags `extra` (its tenth).
/// The directory record (its type from the mode) and the inode share one
/// clock reading (the record's date added and the inode's four times);
/// the inode keeps the parent's 0x20400002 internal flags and gets
/// `INODE_NO_RSRC_FORK`, a link count of one unless a directory, a write
/// generation of one and one extended field, its name; then the parent's
/// modification and change times (one more reading, K 0x66f3750), child
/// count and write generation. The new inode's value.
#[allow(clippy::too_many_arguments)]
fn obj_create_name(nx: &mut Nx<'_>, vol: usize, parent: u64, pi: &Inode, name: &str, mode: u16, uid: u32, gid: u32, ino: u64, prot: u32, extra: u64, now: &mut dyn FnMut() -> u64) -> Result<Vec<u8>, String> {
    let dir = mode & S_IFMT == S_IFDIR;
    if pi.internal_flags() & 0x2 != 0 {
        return Err("not implemented: directory statistics (INODE_MAINTAIN_DIR_STATS)".into());
    }
    if mode & S_IFMT == S_IFREG && pi.internal_flags() & 0x200_0000 != 0 {
        return Err("not implemented: a file made in a directory whose internal flags have 0x2000000 (the type-15 extended field, K 0x66f2b9c)".into());
    }
    // The expanded records' subdirectory count (incompat 0x200): a new
    // directory's j_inode_val +0x54 is 0 (K 0x66f2ae8) and its parent's
    // grows by one (K 0x66f37a8: the in-memory +0x90, serialized at +0x54
    // by K 0x66f0374); without them, ro_compat 0x2 would add the count as
    // extended field 0x11.
    let subdir_count = if dir {
        let (sb, _) = nx.vol_sb_read(vol)?;
        let expanded = u64a(sb, SB_INCOMPAT) & 0x200 != 0;
        if !expanded && u64a(sb, SB_RO_COMPAT) & 0x2 != 0 {
            return Err("not implemented: a directory made on a volume with ro_compat 0x2 (the subdirectory-count extended field 0x11, K 0x66f251c, K 0x66f37a8)".into());
        }
        expanded
    } else {
        false
    };
    let dk = drec_key(parent, name);
    nx.jobj_times.remove(&(vol, parent));
    let t1 = now();
    let mut dv = ino.to_le_bytes().to_vec();
    dv.extend_from_slice(&t1.to_le_bytes());
    dv.extend_from_slice(&(mode >> 12).to_le_bytes());
    let flags = (pi.internal_flags() & INHERIT_KEPT) | extra | INODE_NO_RSRC_FORK;
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
    let (mut t, mut st) = nx.fs_tree(vol)?;
    t.insert(&mut st, &dk, Some(&dv))?;
    t.insert(&mut st, &inode_key(ino), Some(&iv))?;
    // The parent: its times (any its in-memory object held are replaced),
    // children and write generation.
    let t2 = now();
    let mut p = pi.0.clone();
    p.put64(0x18, t2);
    p.put64(0x20, t2);
    let nchildren = i32::from_le_bytes(p[0x38..0x3c].try_into().unwrap()) + 1;
    p.put32(0x38, nchildren as u32);
    let wgc = u32::from_le_bytes(p[0x40..0x44].try_into().unwrap()) + 1;
    p.put32(0x40, wgc);
    if subdir_count {
        let n = u32::from_le_bytes(p[0x54..0x58].try_into().unwrap());
        p.put32(0x54, n.wrapping_add(1));
    }
    t.insert(&mut st, &inode_key(parent), Some(&p))?;
    nx.set_fs_tree(vol, t);
    Ok(iv)
}

/// `symlink(target, name)` in directory `parent` (apfs_vnop_symlink K
/// 0x668c974) by owner `uid` and group `gid` with `mode` (XNU's
/// `ACCESSPERMS & ~umask`): in one file-system transaction the object
/// made as `fs_obj_create_name_checked` makes it (DT_LNK, no protection
/// class, no extra flags), `num_symlinks` counted, then the target in the
/// `com.apple.fs.symlink` extended attribute (K 0x66f4048): embedded with
/// its NUL and flagged file-system owned while the record fits a node
/// (`tlen + 1 < 0xedd`). The link's inode number, or EEXIST.
pub fn symlink(nx: &mut Nx<'_>, vol: usize, parent: u64, name: &str, target: &str, mode: u16, uid: u32, gid: u32, now: &mut dyn FnMut() -> u64) -> Result<Result<u64, i32>, String> {
    const SYMLINK_EA: &str = "com.apple.fs.symlink";
    const XATTR_DATA_EMBEDDED: u16 = 0x2;
    const XATTR_FILE_SYSTEM_OWNED: u16 = 0x4;
    if target.is_empty() || target.len() + 1 >= 0xedd {
        return Err(format!("not implemented: a symbolic link target of {} bytes (the stream form, or the empty target)", target.len()));
    }
    let ino = match create_obj(nx, vol, parent, name, S_IFLNK | (mode & 0o7777), uid, gid, now)? {
        Ok(ino) => ino,
        Err(e) => return Ok(Err(e)),
    };
    let mut k = (ino | J_XATTR << 60).to_le_bytes().to_vec();
    k.extend_from_slice(&(SYMLINK_EA.len() as u16 + 1).to_le_bytes());
    k.extend_from_slice(SYMLINK_EA.as_bytes());
    k.push(0);
    let mut v = (XATTR_DATA_EMBEDDED | XATTR_FILE_SYSTEM_OWNED).to_le_bytes().to_vec();
    v.extend_from_slice(&(target.len() as u16 + 1).to_le_bytes());
    v.extend_from_slice(target.as_bytes());
    v.push(0);
    if k.len() + v.len() > 0xedd {
        return Err("not implemented: a symbolic link whose attribute record does not fit a node (bt size check K 0x6725a2c, the stream form)".into());
    }
    put_rec(nx, vol, &k, &v)?;
    fs_tx_leave(nx, vol, now)?;
    Ok(Ok(ino))
}

/// `setattrlist` of a volume's name (apfs_vfsop_setattr K 0x66ca364): in
/// the container's transaction, not a file-system one, the superblock's
/// `apfs_volname` given the name (K 0x6700520: whole UTF-8 characters
/// while they end before byte 256, then a NUL; the bytes after it kept,
/// with no shortcut for the same name) and +0x420 the transaction; no
/// `last_mod_time`. `tx_leave` with flags 0x15 then closes and commits
/// the transaction and waits for it.
pub fn set_volume_name(nx: &mut Nx<'_>, vol: usize, name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("can't set volume name: empty".into());
    }
    nx.enter()?;
    let xid = nx.xid;
    let mut n = 0;
    for c in name.chars() {
        if n + c.len_utf8() >= 256 {
            break;
        }
        n += c.len_utf8();
    }
    let sb = nx.vol_sb(vol)?;
    sb[SB_VOLNAME..SB_VOLNAME + n].copy_from_slice(&name.as_bytes()[..n]);
    sb[SB_VOLNAME + n] = 0;
    let role = u16::from_le_bytes([sb[SB_ROLE], sb[SB_ROLE + 1]]);
    if [0u16, 2, 0x40, 0x240].contains(&role) {
        return Err(format!("not implemented: the +0x428 flag a name change sets on a volume of role {role:#x}"));
    }
    sb.put64(SB_LAST_XID, xid);
    nx.leave(0x15)
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
/// that is not transcribed for asr's pwrites (prepare_write_and_lock's
/// per-write updates: the data stream's byte counters, the times, the write
/// generation, PREV_FSIZE): the inode keeps the fields its creation, its
/// data stream's creation, its truncate and its block maps' sparse bytes
/// give it.
pub const FILE_INODE_STAND_IN: &str = "the inode fields the kernel updates at each of asr's pwrites into its image file (data-stream byte counters, times, write generation, PREV_FSIZE) are not transcribed (stand-in: the fields its creation, its data stream's creation, its truncate and its block maps' sparse bytes give it, and the stream's sizes); apfs_invert retires these records whole";

/// `ftruncate` growing a file with no data (apfs_vnop_setattr K 0x668e4a0
/// → apfs_truncate_locked K 0x66a6bbc → apfs_set_file_size K 0x6766f50):
/// its data stream made (K 0x66fb32c: the inode's private identifier, an
/// extended field of type 8, a `j_dstream_id` record with one reference),
/// then `alloc_space_for_write_with_hint_and_spino` (K 0x6707764) with no
/// length: no blocks, one sparse extent from the old allocated size to
/// the new size rounded up to the block size, and the stream's sizes.
pub fn truncate_grow(nx: &mut Nx<'_>, vol: usize, ino: u64, size: u64, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    check_volume(nx, vol)?;
    truncate_grow_unchecked(nx, vol, ino, size, now)
}

/// [`truncate_grow`] on a volume whose role the caller has checked. On a
/// volume with unwritten extents (incompat 0x80) growing into the
/// preallocation records no unwritten range (K 0x66a7984): the records
/// are the same.
fn truncate_grow_unchecked(nx: &mut Nx<'_>, vol: usize, ino: u64, size: u64, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
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
    if size > old.size && size.div_ceil(bs) * bs <= old.alloced && old.size == 0 {
        // Grown into its preallocation (apfs_truncate_locked K 0x66a6bbc
        // l.553-984): the write generation (K 0x66a7348), the unwritten
        // range recorded in memory, no extent or sparse change, the size,
        // the modification and change times from one clock reading
        // (K 0x66f3750).
        if u64a(&v, INO_INTERNAL_FLAGS) & (INODE_PURGEABLE | 0x10 | 0x2) != 0 {
            return Err(format!("not implemented: growing a file with internal flags {:#x}", u64a(&v, INO_INTERNAL_FLAGS)));
        }
        let wgc = u32::from_le_bytes(v[INO_WRITE_GEN..INO_WRITE_GEN + 4].try_into().unwrap());
        v.put32(INO_WRITE_GEN, wgc.wrapping_add(1));
        let d = x.iter_mut().find(|f| f.0 == INO_EXT_TYPE_DSTREAM).unwrap();
        d.2.put64(0, size);
        let clock = now();
        v = with_xfields(&v, &x);
        v.put64(INO_MOD_TIME, clock);
        v.put64(INO_CHANGE_TIME, clock);
        t.insert(&mut st, &inode_key(ino), Some(&v))?;
        nx.set_fs_tree(vol, t);
        return fs_tx_leave(nx, vol, now);
    }
    if size <= old.size || old.alloced != 0 {
        return Err("not implemented: a truncate other than growing a file with no data or into its preallocation".into());
    }
    // alloc_space with no length (K 0x6707764): the hole extent, the
    // allocated size, then the sparse bytes it adds (K 0x6708614 →
    // update_sparse_bytes K 0x66ff7c0: INODE_IS_SPARSE and the
    // SPARSE_BYTES field, appended).
    let alloced = size.div_ceil(bs) * bs;
    t.insert(&mut st, &fext_key(old.oid, 0), Some(&fext_val(alloced, 0)))?;
    let d = x.iter_mut().find(|f| f.0 == INO_EXT_TYPE_DSTREAM).unwrap();
    d.2.put64(0, size);
    d.2.put64(8, alloced);
    sparse_bytes(&mut v, &mut x, alloced as i64)?;
    v = with_xfields(&v, &x);
    t.insert(&mut st, &inode_key(ino), Some(&v))?;
    nx.set_fs_tree(vol, t);
    fs_tx_leave(nx, vol, now)
}

/// `INO_EXT_TYPE_SPARSE_BYTES` and `INODE_IS_SPARSE`.
const INO_EXT_TYPE_SPARSE_BYTES: u8 = 0xd;
const INODE_IS_SPARSE: u64 = 0x200;

/// `update_sparse_bytes` (K 0x66ff7c0) by `delta` on an inode value `v`
/// whose extended fields are `x`: the SPARSE_BYTES field (flags 0x28)
/// rewritten in place or appended with INODE_IS_SPARSE while the count
/// stays above 0, else removed with the flag cleared. A decrease with no
/// field is the kernel's error (2).
fn sparse_bytes(v: &mut [u8], x: &mut Vec<(u8, u8, Vec<u8>)>, delta: i64) -> Result<(), String> {
    if delta == 0 {
        return Ok(());
    }
    let at = x.iter().position(|f| f.0 == INO_EXT_TYPE_SPARSE_BYTES);
    let old = match at {
        Some(i) => u64a(&x[i].2, 0) as i64,
        None if delta < 0 => return Err("a sparse-bytes decrease on an inode with no SPARSE_BYTES field (update_sparse_bytes returns 2)".into()),
        None => 0,
    };
    let new = old + delta;
    let f = u64a(v, INO_INTERNAL_FLAGS);
    if new < 1 {
        if let Some(i) = at {
            x.remove(i);
        }
        v[INO_INTERNAL_FLAGS..INO_INTERNAL_FLAGS + 8].copy_from_slice(&(f & !INODE_IS_SPARSE).to_le_bytes());
    } else {
        v[INO_INTERNAL_FLAGS..INO_INTERNAL_FLAGS + 8].copy_from_slice(&(f | INODE_IS_SPARSE).to_le_bytes());
        let d = (new as u64).to_le_bytes().to_vec();
        match at {
            Some(i) => x[i].2 = d,
            None => x.push((INO_EXT_TYPE_SPARSE_BYTES, 0x28, d)),
        }
    }
    Ok(())
}

/// A write into a file's sparse extent, as XNU's cluster layer pushes it:
/// one `VNOP_BLOCKMAP` of `data` at byte `off` (both block multiples)
/// (apfs_vnop_blockmap K 0x66882ec → fs_map_file_offset_ext K 0x6708b54 →
/// fs_make_hole_range_writable K 0x670afbc). Each piece the space manager
/// grants ([`Nx::alloc_data`], one request per transaction: a shorter
/// grant ends the block map and cluster_io maps the rest again) is its own
/// file-system transaction: the volume's allocation counts, the block
/// references (a record per physically contiguous run of the stream's
/// blocks, merged with its neighbours, `insert_phys_extent` K 0x66f6ca0),
/// the file extents (a piece at the sparse extent's start replaces it or,
/// physically following the extent before it, extends that one; any other
/// piece splits it; what the piece leaves of it stays sparse), the sparse
/// bytes lowered (K 0x670920c) and the inode rewritten from its in-memory
/// object (K 0x6709228), with `times` (the write's modification and change
/// times and the stream's bytes written) when the write's end has already
/// set them there. The data reaches the blocks with each piece. The
/// pieces granted, in order.
pub fn write_sparse(nx: &mut Nx<'_>, vol: usize, ino: u64, off: u64, data: &[u8], now: &mut dyn FnMut() -> u64) -> Result<Vec<(u64, u64)>, String> {
    check_volume(nx, vol)?;
    blockmap_fill(nx, vol, ino, off, data, None, now)
}

fn blockmap_fill(nx: &mut Nx<'_>, vol: usize, ino: u64, off: u64, data: &[u8], times: Option<(u64, u64)>, now: &mut dyn FnMut() -> u64) -> Result<Vec<(u64, u64)>, String> {
    let bs = nx.l.bs;
    if off % bs != 0 || data.len() as u64 % bs != 0 || data.is_empty() {
        return Err("not implemented: a write not of whole blocks".into());
    }
    let mut out = Vec::new();
    let mut pos = off;
    let end = off + data.len() as u64;
    while pos < end {
        fs_tx_enter(nx, vol)?;
        let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
        let ds = dstream_of(&v)?.ok_or("a write to a file with no data stream")?;
        if end > ds.alloced {
            return Err("not implemented: a block map past the file's allocated size".into());
        }
        // The sparse extent holding `pos`.
        let (t, mut st) = nx.fs_tree(vol)?;
        let recs = t.records(&mut st)?;
        let ext: Vec<(u64, u64, u64)> = recs
            .iter()
            .filter(|(k, _)| k.len() == 16 && u64a(k, 0) == (ds.oid | J_FILE_EXTENT << 60))
            .map(|(k, v)| {
                let v = v.as_ref().unwrap();
                (u64a(k, 8), u64a(v, 0) & 0x00ff_ffff_ffff_ffff, u64a(v, 8))
            })
            .collect();
        drop(st);
        let &(hl, hlen, hphys) = ext.iter().find(|&&(l, n, _)| l <= pos && pos < l + n).ok_or("a write where the file has no extent")?;
        if hphys != 0 {
            return Err("not implemented: a write over a file's allocated blocks".into());
        }
        let want = (end - pos).min(hl + hlen - pos);
        let blocks = want.div_ceil(bs);
        let (a, got) = nx.alloc_data(blocks)?;
        let n = got * bs;
        blocks_alloced(nx, vol, got)?;
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
        let mut v = v;
        let mut x = xfields(&v)?;
        sparse_bytes(&mut v, &mut x, -(n as i64))?;
        if let Some((t_w, written)) = times {
            let d = x.iter_mut().find(|f| f.0 == INO_EXT_TYPE_DSTREAM).unwrap();
            d.2.put64(0x18, written);
            v.put64(INO_MOD_TIME, t_w);
            v.put64(INO_CHANGE_TIME, t_w);
        }
        let v = with_xfields(&v, &x);
        put_rec(nx, vol, &inode_key(ino), &v)?;
        let at = (pos - off) as usize;
        nx.write_data(a, &data[at..at + n as usize])?;
        fs_tx_leave(nx, vol, now)?;
        out.push((a, got));
        pos += n;
    }
    Ok(out)
}

/// `got` blocks the space manager gave volume `vol` for file data: its
/// `fs_alloc_count` (spaceman_modify_bits with the volume as owner) and
/// `total_blocks_alloced` (alloc_space, K 0x6707e54) raised, +0x420 the
/// transaction (K 0x66f70c8 at K 0x6707e6c).
fn blocks_alloced(nx: &mut Nx<'_>, vol: usize, got: u64) -> Result<(), String> {
    nx.vol_alloc_add(vol, got)?;
    let xid = nx.xid;
    let sb = nx.vol_sb(vol)?;
    let c = u64a(sb, SB_TOTAL_BLOCKS_ALLOCED);
    sb.put64(SB_TOTAL_BLOCKS_ALLOCED, c + got);
    sb.put64(SB_LAST_XID, xid);
    Ok(())
}

/// `fcntl(F_PREALLOCATE)` with `F_ALLOCATEALL` from the physical end of
/// file (`F_PEOFPOSMODE`, offset 0) of `len` bytes on an empty regular file
/// with no data stream (apfs_vnop_allocate K 0x669a348 →
/// preallocate_inline K 0x669cef0, for a request under the 32 MiB that
/// sends larger ones to preallocate_with_temp_file): in one file-system
/// transaction the data stream made (its extended field with the
/// volume's default crypto identifier, 0 for an unencrypted volume, and
/// its `j_dstream_id` record), then alloc_space (K 0x6707764, flags 0x84,
/// no speculative blocks): one data allocation for all the blocks, taken
/// back in pieces when the space manager gives fewer, each piece counted
/// for the volume, its file extent (extending the one before it when
/// physically contiguous) and its block references; the stream's
/// allocated size, the inode's modification and change times from one
/// clock reading, the inode rewritten. The size stays 0 and the write
/// generation is not changed. The bytes allocated.
pub fn preallocate(nx: &mut Nx<'_>, vol: usize, ino: u64, len: u64, now: &mut dyn FnMut() -> u64) -> Result<u64, String> {
    check_volume(nx, vol)?;
    let bs = nx.l.bs;
    if len == 0 {
        return Ok(0);
    }
    if len >= 32 << 20 {
        return Err("not implemented: a preallocation of 32 MiB or more (the inline limit's flags at fs+0x3ac, preallocate_with_temp_file)".into());
    }
    {
        let sb = nx.vol_sb(vol)?;
        if u64a(sb, SB_INCOMPAT) & 0x80 != 0 {
            return Err("not implemented: preallocating on a volume with incompat 0x80 (unwritten extents)".into());
        }
        if u64a(sb, 0x108) & 1 == 0 {
            return Err("not implemented: preallocating on an encrypted volume (the stream's crypto identifier and the extents' crypto)".into());
        }
    }
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    if u16::from_le_bytes([v[INO_MODE], v[INO_MODE + 1]]) & S_IFMT != S_IFREG {
        return Err(format!("{ino:#x} is not a regular file"));
    }
    if u64a(&v, INO_INTERNAL_FLAGS) & (0x800 | INODE_PURGEABLE | 0x10 | 0x2) != 0 {
        return Err(format!("not implemented: preallocating a file with internal flags {:#x}", u64a(&v, INO_INTERNAL_FLAGS)));
    }
    if dstream_of(&v)?.is_some() {
        return Err("not implemented: preallocating a file that has a data stream".into());
    }
    let blocks = len.div_ceil(bs);
    fs_tx_enter(nx, vol)?;
    // The data stream (K 0x66fb32c): the inode's private identifier.
    let oid = u64a(&v, 0x08);
    let mut x = xfields(&v)?;
    x.push((INO_EXT_TYPE_DSTREAM, XF_SYSTEM_FIELD, vec![0u8; 0x28]));
    put_rec(nx, vol, &(oid | J_DSTREAM_ID << 60).to_le_bytes(), &1u32.to_le_bytes())?;
    // The quota check (re-alloc.md section 3) with what the volume holds.
    {
        let sb = nx.vol_sb(vol)?;
        let quota = u64a(sb, 0x50);
        if quota != 0 && quota < blocks + u64a(sb, 0x58) {
            return Err("not implemented: a preallocation the volume's quota cuts".into());
        }
    }
    let mut done = 0u64;
    let mut last: Option<(u64, u64, u64)> = None;
    while done < blocks {
        let (a, got) = nx.alloc_data(blocks - done)?;
        blocks_alloced(nx, vol, got)?;
        match last {
            Some((l, n, p)) if p + n / bs == a => {
                put_rec(nx, vol, &fext_key(oid, l), &fext_val(n + got * bs, p))?;
                last = Some((l, n + got * bs, p));
            }
            _ => {
                put_rec(nx, vol, &fext_key(oid, done * bs), &fext_val(got * bs, a))?;
                last = Some((done * bs, got * bs, a));
            }
        }
        phys_extent_add(nx, vol, a, got, oid)?;
        done += got;
    }
    let d = x.iter_mut().find(|f| f.0 == INO_EXT_TYPE_DSTREAM).unwrap();
    d.2.put64(8, blocks * bs);
    let t = now();
    let mut v = with_xfields(&v, &x);
    v.put64(INO_MOD_TIME, t);
    v.put64(INO_CHANGE_TIME, t);
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave(nx, vol, now)?;
    Ok(blocks * bs)
}

/// `restored_external`'s reserve_overprov_space (RE 0x10002e5bc,
/// drafts/s21/re-overprov.md) on the Data volume `vol` of a disk of
/// `disk_bytes` (the whole disk's DKIOCGETBLOCKSIZE times
/// DKIOCGETBLOCKCOUNT), whose container device answers DK_FEATURE_UNMAP as
/// `unmap`: `/.overprovisioning_file` made with `open_dprotected_np(O_RDWR
/// | O_CREAT | O_EXCL, class 6, 0600)` (stored as class C on a VEK volume),
/// `F_PREALLOCATE` {CONTIG | ALL | PERSIST, F_PEOFPOSMODE} of 1 GiB, or a
/// hundredth of the disk when it is no more than 0x1900000063 bytes,
/// `ftruncate` to it, `F_FULLFSYNC`, `F_TRIM_ACTIVE_FILE` over it, then
/// the closes (nothing written). Its inode number.
pub fn reserve_overprov_space(nx: &mut Nx<'_>, vol: usize, disk_bytes: u64, unmap: bool, now: &mut dyn FnMut() -> u64) -> Result<u64, String> {
    const NAME: &str = ".overprovisioning_file";
    let size = if disk_bytes as i64 > 0x19_0000_0063 { 0x4000_0000 } else { (disk_bytes as i64 / 100) as u64 };
    if lookup(nx, vol, ROOT_DIR_INO, NAME)?.is_some() {
        return Err("not implemented: the overprovisioning file's open finding it (O_EXCL: EEXIST)".into());
    }
    let ino = create_protected(nx, vol, ROOT_DIR_INO, NAME, 0o600, 0, 6, now)?;
    match preallocate_contig_persist(nx, vol, ino, size, now)? {
        Ok(got) if got == size => {}
        Ok(_) => return Err("a contiguous preallocation given fewer bytes".into()),
        Err(_) => return Err("not implemented: the overprovisioning file's preallocation retries after ENOSPC (flags 0xa, then 0x8: preallocate_with_temp_file)".into()),
    }
    check_names(nx, vol)?;
    truncate_grow_unchecked(nx, vol, ino, size, now)?;
    nx.tx_finish()?;
    if unmap {
        trim_active_file(nx, vol, ino, now)?;
    }
    Ok(ino)
}

/// `open_dprotected_np(O_CREAT, class, 0, mode)` of a regular file
/// `name` in directory `parent` of an encrypted volume with a VEK, by
/// root under umask 0 (apfs_vnop_create K 0x668c3f8): setup_prot_class
/// with an explicit class (K 0x66a3670, drafts/s21/re-overprov.md 1.1),
/// which on a VEK volume stores class 6 as class C without
/// PROT_CLASS_EXPLICIT and needs no per-file key (K 0x66f44b0 takes the
/// VEK); the Secure Enclave's lock-state answer for the class
/// (K 0x669caec, device-only) must allow it, as the restore's success
/// says it does; then the create as [`create`] makes it, the group the
/// parent's. Class 4 stays class D with PROT_CLASS_EXPLICIT (internal
/// 0x8; drafts/s23/re-uml-data.md 2.1): its per-file key comes with its
/// data stream. Only classes 4 and 6 on a volume with a VEK are
/// implemented. The new inode's number.
pub fn create_protected(nx: &mut Nx<'_>, vol: usize, parent: u64, name: &str, mode: u16, uid: u32, class: u32, now: &mut dyn FnMut() -> u64) -> Result<u64, String> {
    check_names(nx, vol)?;
    let (sb, _) = nx.vol_sb_read(vol)?;
    let role = u16::from_le_bytes([sb[SB_ROLE], sb[SB_ROLE + 1]]);
    if vol_crypto(sb) != 3 || u64a(sb, SB_INCOMPAT) & 0x100 != 0 {
        return Err("not implemented: an explicit protection class on a volume without a VEK (setup_prot_class's other branches, the per-file key path)".into());
    }
    // On Data, the only document-identifier upkeep of a create is the
    // tombstone transfer (K 0x66a3a38) for a thread holding a tombstone of
    // the name: none for the restore.
    if role != 0x40 {
        return Err(format!("not implemented: a protected create on a volume of role {role:#x}"));
    }
    let (stored, extra) = match class {
        6 => (DEFAULT_CP_CLASS, 0),
        4 => (4, 0x8),
        _ => return Err(format!("not implemented: a create with explicit class {class} on a VEK volume")),
    };
    if get_rec(nx, vol, &drec_key(parent, name))?.is_some() {
        return Err(format!("{name} exists (EEXIST)"));
    }
    let pv = get_rec(nx, vol, &inode_key(parent))?.ok_or_else(|| format!("no inode {parent:#x}"))?;
    let pi = Inode(pv);
    if u16::from_le_bytes([pi.0[0x50], pi.0[0x51]]) & S_IFMT != S_IFDIR {
        return Err(format!("{parent:#x} is not a directory"));
    }
    if pi.internal_flags() & INHERIT_EXTRA != 0 {
        return Err(format!("not implemented: a file inheriting internal flags {:#x}", pi.internal_flags() & INHERIT_EXTRA));
    }
    if parent == PRIV_DIR_INO {
        return Err("a create in the private directory (EACCES)".into());
    }
    let gid = u32::from_le_bytes(pi.0[0x4c..0x50].try_into().unwrap());
    fs_tx_enter(nx, vol)?;
    let ino = {
        let sb = nx.vol_sb(vol)?;
        let ino = u64a(sb, SB_NEXT_OBJ_ID);
        sb.put64(SB_NEXT_OBJ_ID, ino + 1);
        ino
    };
    obj_create_name(nx, vol, parent, &pi, name, S_IFREG | (mode & 0o7777), uid, gid, ino, stored, extra, now)?;
    let sb = nx.vol_sb(vol)?;
    let n = u64a(sb, SB_NUM_FILES);
    sb.put64(SB_NUM_FILES, n + 1);
    fs_tx_leave(nx, vol, now)?;
    Ok(ino)
}

/// `fcntl(F_PREALLOCATE)` {CONTIG | ALL | PERSIST, F_PEOFPOSMODE, 0, `len`}
/// on an empty regular file of a VEK volume with unwritten extents
/// (incompat 0x80) by a process entitled to `allocate_contig`
/// (apfs_vnop_allocate K 0x669a348 with VNOP flags 0x1f →
/// preallocate_inline K 0x669cef0 with 0xe5; drafts/s21/re-overprov.md
/// 2.2-2.4): in one file-system transaction the data stream made (its
/// default crypto identifier 4, the VEK's, K 0x66f44b0), then alloc_space
/// (K 0x6707764): the free-space floor, one contiguous non-partial data
/// allocation, the volume's counts, one unwritten file extent whose crypto
/// field is its physical block (FEXT_CRYPTO_ID_IS_TWEAK | unwritten, K
/// 0x6700a08), its block references; the stream's allocated size, the
/// inode's PERSIST flag 0x8000000, its modification and change times from
/// one clock reading. The bytes allocated, or ENOSPC.
fn preallocate_contig_persist(nx: &mut Nx<'_>, vol: usize, ino: u64, len: u64, now: &mut dyn FnMut() -> u64) -> Result<Result<u64, i32>, String> {
    const INODE_PREALLOCATED_PERSIST: u64 = 0x800_0000;
    const FEXT_CRYPTO_ID_IS_TWEAK: u64 = 1;
    const FEXT_UNWRITTEN: u64 = 2;
    const CRYPTO_VEK: u64 = 4;
    let bs = nx.l.bs;
    {
        let (sb, _) = nx.vol_sb_read(vol)?;
        if u64a(sb, SB_INCOMPAT) & 0x80 == 0 || vol_crypto(sb) != 3 {
            return Err("not implemented: a contiguous preallocation on a volume without unwritten extents or a VEK".into());
        }
        let quota = u64a(sb, 0x50);
        if quota != 0 || u64a(sb, 0x48) != 0 {
            return Err("not implemented: a contiguous preallocation on a volume with a quota or reserve".into());
        }
    }
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    if u16::from_le_bytes([v[INO_MODE], v[INO_MODE + 1]]) & S_IFMT != S_IFREG || dstream_of(&v)?.is_some() {
        return Err("not implemented: preallocating other than an empty regular file with no data stream".into());
    }
    if u64a(&v, INO_INTERNAL_FLAGS) & (INODE_PURGEABLE | 0x8 | 0x10 | 0x2) != 0 || u32::from_le_bytes(v[0x3c..0x40].try_into().unwrap()) != DEFAULT_CP_CLASS {
        return Err("not implemented: preallocating a file of another class, explicit class or internal flags".into());
    }
    if u32::from_le_bytes(v[0x44..0x48].try_into().unwrap()) & 0x4000_0020 == 0x4000_0020 {
        return Err("not implemented: a data stream of its own identifier (bsd_flags 0x40000020, K 0x66fb37c)".into());
    }
    if len == 0 || len % bs != 0 {
        return Err("not implemented: a contiguous preallocation not a whole number of blocks".into());
    }
    let blocks = len / bs;
    // preflight (K 0x669d2c4): the reservation counter and the space check
    // with blocks / 50 + 3 metadata blocks; the allocation's own checks
    // follow in alloc_data_contig.
    fs_tx_enter(nx, vol)?;
    let oid = u64a(&v, 0x08);
    let mut x = xfields(&v)?;
    let mut ds = vec![0u8; 0x28];
    ds.put64(0x10, CRYPTO_VEK);
    x.push((INO_EXT_TYPE_DSTREAM, XF_SYSTEM_FIELD, ds));
    put_rec(nx, vol, &(oid | J_DSTREAM_ID << 60).to_le_bytes(), &1u32.to_le_bytes())?;
    // The free-space floor (K 0x6707d1c..0x6707d70, the statistics of K
    // 0x67515e4): ENOSPC unless what stays free is at least a hundredth of
    // the blocks or 20 MiB, the smaller. Whether the free count the
    // statistics give is less the other volumes' reserves is not
    // transcribed: only an answer both ways give is taken.
    let (free, held, total) = nx.space_counts();
    let floor = (total / 100).min(0x140_0000 / bs);
    let fits = |free: u64| free >= blocks && free - blocks >= floor;
    if fits(free) != fits(free.saturating_sub(held)) {
        return Err("not implemented: the free-space floor where the volumes' reserves decide it (K 0x67515e4's free count)".into());
    }
    if !fits(free) {
        return Ok(Err(28));
    }
    let p = match nx.alloc_data_contig(blocks)? {
        Ok(p) => p,
        Err(e) => return Ok(Err(e)),
    };
    blocks_alloced(nx, vol, blocks)?;
    let mut fv = (len | (FEXT_CRYPTO_ID_IS_TWEAK | FEXT_UNWRITTEN) << 56).to_le_bytes().to_vec();
    fv.extend_from_slice(&p.to_le_bytes());
    fv.extend_from_slice(&p.to_le_bytes());
    put_rec(nx, vol, &fext_key(oid, 0), &fv)?;
    phys_extent_add(nx, vol, p, blocks, oid)?;
    let d = x.iter_mut().find(|f| f.0 == INO_EXT_TYPE_DSTREAM).unwrap();
    d.2.put64(8, len);
    let t = now();
    let mut v = with_xfields(&v, &x);
    let f = u64a(&v, INO_INTERNAL_FLAGS);
    v.put64(INO_INTERNAL_FLAGS, f | INODE_PREALLOCATED_PERSIST);
    v.put64(INO_MOD_TIME, t);
    v.put64(INO_CHANGE_TIME, t);
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave(nx, vol, now)?;
    Ok(Ok(len))
}

/// The two blobs AppleKeyStore's file-system key services write into a
/// new per-file key's crypto-state record (`fn + 0x50`, each at most 0x80
/// bytes; their lengths go in `key_len`): device-only, KEYS_STAND_IN.
pub const PER_FILE_KEY_STAND_IN: &str = "the wrapped per-file keys of class-D files on Data (device-only: the two blobs AppleKeyStore's file-system key services return for a new file key, each at most 0x80 bytes) (stand-in: two blobs of 0x28 bytes, \"KEY-STAND-IN\" repeated; measure a class-D file's crypto-state record on the device)";

const J_CRYPTO_STATE: u64 = 7;
const INO_EXT_TYPE_PREV_FSIZE: u8 = 5;

/// What a small first write leaves pending in memory (the file's times,
/// the stream's bytes written) for its `fsync` to write.
pub struct PendingWrite {
    ino: u64,
    len: u64,
    paddr: u64,
    data: Vec<u8>,
    times: u64,
}

/// The first `write(2)` of `data` (under one block) at offset 0 into an
/// empty class-D file with PROT_CLASS_EXPLICIT on a VEK volume
/// (apfs_vnop_write K 0x6691308, prepare_write_and_lock K 0x66a4024;
/// drafts/s23/re-uml-data.md 3): in one file-system transaction the data
/// stream made (its identifier the inode's) with the per-file key's
/// crypto-state record (K 0x66f441c's per-file path: the crypto identifier
/// is the stream's; K 0x6734154 fills the record with AppleKeyStore's
/// blobs, PER_FILE_KEY_STAND_IN; K 0x66f4e3c inserts it), its
/// `j_dstream_id`, one block from the allocation zone (alloc_space flags
/// 8) whose file extent counts the record a second reference (K
/// 0x66f8ad8), the block references, then the stream's size and allocated
/// size, a PREV_FSIZE field of the old size 0, the write generation and
/// the inode. The modification and change times (one more reading) and the
/// bytes written stay in memory until the `fsync` ([`fsync_pending`]); the
/// data reaches the block then.
pub fn write_new_protected(nx: &mut Nx<'_>, vol: usize, ino: u64, data: &[u8], now: &mut dyn FnMut() -> u64) -> Result<PendingWrite, String> {
    let bs = nx.l.bs;
    if data.is_empty() || data.len() as u64 >= bs {
        return Err(format!("not implemented: a first write of {} bytes (only one under a block is traced)", data.len()));
    }
    let key_os_version = {
        let (sb, _) = nx.vol_sb_read(vol)?;
        if vol_crypto(sb) != 3 || u64a(sb, SB_INCOMPAT) & 0x100 != 0 {
            return Err("not implemented: a per-file key on a volume without a VEK".into());
        }
        u32::from_le_bytes(sb[0x6c..0x70].try_into().unwrap())
    };
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    if u16::from_le_bytes([v[INO_MODE], v[INO_MODE + 1]]) & S_IFMT != S_IFREG || dstream_of(&v)?.is_some() {
        return Err("not implemented: a first write into other than an empty regular file".into());
    }
    if u32::from_le_bytes(v[0x3c..0x40].try_into().unwrap()) != 4 || u64a(&v, INO_INTERNAL_FLAGS) & 0x8 == 0 || u64a(&v, INO_INTERNAL_FLAGS) & 0x410 != 0 {
        return Err("not implemented: a first write into a file other than an explicit class-D one".into());
    }
    if u32::from_le_bytes(v[0x44..0x48].try_into().unwrap()) & 0x4000_0020 == 0x4000_0020 {
        return Err("not implemented: a data stream of its own identifier (bsd_flags 0x40000020, K 0x66fb37c)".into());
    }
    fs_tx_enter(nx, vol)?;
    let oid = u64a(&v, 0x08);
    // The crypto-state record (K 0x6734490/K 0x6734154): one reference,
    // version 6.0, no flags, class 4 (kind 3, K 0x67072f4), the OS version,
    // revision 0, the blobs' lengths, the blobs.
    let blob = |n: usize| -> Vec<u8> { b"KEY-STAND-IN".iter().copied().cycle().take(n).collect() };
    let (b1, b2) = (blob(0x28), blob(0x28));
    let mut cs = 1u32.to_le_bytes().to_vec();
    cs.extend_from_slice(&6u16.to_le_bytes());
    cs.extend_from_slice(&0u16.to_le_bytes());
    cs.extend_from_slice(&0u32.to_le_bytes());
    cs.extend_from_slice(&4u32.to_le_bytes());
    cs.extend_from_slice(&key_os_version.to_le_bytes());
    cs.extend_from_slice(&0u16.to_le_bytes());
    cs.extend_from_slice(&(b1.len() as u16 | (b2.len() as u16) << 8).to_le_bytes());
    cs.extend_from_slice(&b1);
    cs.extend_from_slice(&b2);
    let ck = (oid | J_CRYPTO_STATE << 60).to_le_bytes();
    put_rec(nx, vol, &ck, &cs)?;
    put_rec(nx, vol, &(oid | J_DSTREAM_ID << 60).to_le_bytes(), &1u32.to_le_bytes())?;
    let (p, got) = nx.alloc_data(1)?;
    if got != 1 {
        return Err("a one-block data allocation given no block".into());
    }
    blocks_alloced(nx, vol, 1)?;
    cs.put32(0, 2);
    put_rec(nx, vol, &ck, &cs)?;
    let mut fv = bs.to_le_bytes().to_vec();
    fv.extend_from_slice(&p.to_le_bytes());
    fv.extend_from_slice(&oid.to_le_bytes());
    put_rec(nx, vol, &fext_key(oid, 0), &fv)?;
    phys_extent_add(nx, vol, p, 1, oid)?;
    let mut x = xfields(&v)?;
    let mut ds = vec![0u8; 0x28];
    ds.put64(0, data.len() as u64);
    ds.put64(8, bs);
    ds.put64(0x10, oid);
    x.push((INO_EXT_TYPE_DSTREAM, XF_SYSTEM_FIELD, ds));
    x.push((INO_EXT_TYPE_PREV_FSIZE, 0, vec![0u8; 8]));
    let mut v = with_xfields(&v, &x);
    let wgc = u32::from_le_bytes(v[INO_WRITE_GEN..INO_WRITE_GEN + 4].try_into().unwrap());
    v.put32(INO_WRITE_GEN, wgc.wrapping_add(1));
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave(nx, vol, now)?;
    let times = now();
    Ok(PendingWrite { ino, len: data.len() as u64, paddr: p, data: data.to_vec(), times })
}

/// `fsync(2)` after [`write_new_protected`] (apfs_vnop_fsync K 0x669176c →
/// apfs_fsync_internal K 0x66a12e4; drafts/s23/re-uml-data.md 4): the
/// data block written (the bytes, then zeros to the block's end: the
/// plaintext the per-file key encrypts, KEYS_STAND_IN), then the
/// PREV_FSIZE field removed in a file-system transaction (K 0x6766d4c)
/// whose inode write carries the pending modification and change times
/// and the bytes written. No commit.
pub fn fsync_pending(nx: &mut Nx<'_>, vol: usize, w: &PendingWrite, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    let bs = nx.l.bs as usize;
    let mut b = w.data.clone();
    b.resize(bs, 0);
    nx.write_data(w.paddr, &b)?;
    fs_tx_enter(nx, vol)?;
    let v = get_rec(nx, vol, &inode_key(w.ino))?.ok_or("the written file has no inode")?;
    let x: Vec<(u8, u8, Vec<u8>)> = xfields(&v)?
        .into_iter()
        .filter(|f| f.0 != INO_EXT_TYPE_PREV_FSIZE)
        .map(|(t, fl, mut d)| {
            if t == INO_EXT_TYPE_DSTREAM {
                d.put64(0x18, w.len);
            }
            (t, fl, d)
        })
        .collect();
    let mut v = with_xfields(&v, &x);
    v.put64(INO_MOD_TIME, w.times);
    v.put64(INO_CHANGE_TIME, w.times);
    put_rec(nx, vol, &inode_key(w.ino), &v)?;
    fs_tx_leave(nx, vol, now)
}

/// The times a rename leaves in memory: the file's change time and its
/// directory's modification and change times (one reading each).
pub struct RenameTimes {
    pub file: (u64, u64),
    pub dir: (u64, u64),
}

/// `rename(2)` of regular file `ino` (one link) from `from` to `to` in
/// directory `dir`, no file named `to` there (apfs_vnop_renamex K
/// 0x6692440 with no flags; drafts/s23/re-uml-data.md 5.1): in one
/// file-system transaction the old record removed and the new one
/// inserted (its date added and flags the old one's), the inode's
/// name field and the directory's write generation rewritten, no time
/// changed; after it the file's change time and the directory's times
/// are read into memory only (returned; the directory's are also kept in
/// `nx.jobj_times`, for its next rewrite or a sync pass to write).
pub fn rename_in_dir(nx: &mut Nx<'_>, vol: usize, dir: u64, from: &str, to: &str, ino: u64, now: &mut dyn FnMut() -> u64) -> Result<RenameTimes, String> {
    check_names(nx, vol)?;
    let (sb, _) = nx.vol_sb_read(vol)?;
    if u16::from_le_bytes([sb[SB_ROLE], sb[SB_ROLE + 1]]) != 0x40 || u64a(sb, SB_INCOMPAT) & 0x100 != 0 {
        return Err("not implemented: a rename on other than Data (its document-identifier and secondary-tree rules)".into());
    }
    if to.is_empty() || to.len() > 255 || to.contains('/') {
        return Err(format!("not implemented: the name checks for {to:?}"));
    }
    let fk = drec_key(dir, from);
    let fdv = get_rec(nx, vol, &fk)?.ok_or("the file to rename is not there (ENOENT)")?;
    if u64a(&fdv, 0) != ino {
        return Err("the entry names another inode".into());
    }
    let tk = drec_key(dir, to);
    if get_rec(nx, vol, &tk)?.is_some() {
        return Err("not implemented: a rename onto an existing name".into());
    }
    let f = get_rec(nx, vol, &inode_key(ino))?.ok_or("the file has no inode")?;
    if u16::from_le_bytes([f[INO_MODE], f[INO_MODE + 1]]) & S_IFMT != S_IFREG || u32::from_le_bytes(f[INO_NCHILDREN..INO_NCHILDREN + 4].try_into().unwrap()) != 1 || u32::from_le_bytes(f[0x44..0x48].try_into().unwrap()) & 0x40 != 0 {
        return Err("not implemented: renaming other than a regular file of one link and no UF_TRACKED".into());
    }
    if fdv.len() != 0x12 {
        return Err("not implemented: a directory record with extended fields (SIBLING_ID)".into());
    }
    let mut d = get_rec(nx, vol, &inode_key(dir))?.ok_or("the directory has no inode")?;
    if u64a(&d, INO_INTERNAL_FLAGS) & INODE_MAINTAIN_DIR_STATS != 0 {
        return Err("not implemented: a rename in a directory keeping statistics".into());
    }
    fs_tx_enter(nx, vol)?;
    let g = u32::from_le_bytes(d[INO_WRITE_GEN..INO_WRITE_GEN + 4].try_into().unwrap());
    d.put32(INO_WRITE_GEN, g.wrapping_add(1));
    remove_rec(nx, vol, &fk)?;
    put_rec(nx, vol, &tk, &fdv)?;
    let mut name = to.as_bytes().to_vec();
    name.push(0);
    let x: Vec<(u8, u8, Vec<u8>)> = xfields(&f)?.into_iter().map(|(t, fl, dd)| if t == 4 { (t, fl, name.clone()) } else { (t, fl, dd) }).collect();
    let mut f = with_xfields(&f, &x);
    f.put64(0, dir);
    put_rec(nx, vol, &inode_key(ino), &f)?;
    put_rec(nx, vol, &inode_key(dir), &d)?;
    fs_tx_leave(nx, vol, now)?;
    // After the transaction (K 0x6693700, K 0x6693720): the file's change
    // time, then K 0x66f3750 on the directory, each with the times-dirty
    // bit.
    let fc = now();
    let dt = now();
    nx.jobj_times.insert((vol, dir), (dt, dt));
    Ok(RenameTimes { file: (u64a(&f, INO_MOD_TIME), fc), dir: (dt, dt) })
}

/// `fcntl(F_BARRIERFSYNC)` (apfs_vnop_ioctl 0x55 → K 0x66d6230): the
/// file's pending times written in a file-system transaction (K
/// 0x66a1878: `times` its modification and change times), then
/// `tx_finish(nx, 1)`: the container transaction closed and committed.
pub fn barrier_fsync(nx: &mut Nx<'_>, vol: usize, ino: u64, times: (u64, u64), now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    fs_tx_enter(nx, vol)?;
    let mut v = get_rec(nx, vol, &inode_key(ino))?.ok_or("the file has no inode")?;
    v.put64(INO_MOD_TIME, times.0);
    v.put64(INO_CHANGE_TIME, times.1);
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave(nx, vol, now)?;
    nx.tx_finish()
}

/// `fcntl(F_TRIM_ACTIVE_FILE)` over a whole file (K 0x66e882c, the device
/// answering DK_FEATURE_UNMAP): in its own file-system transaction the
/// inode's INODE_ACTIVE_FILE_TRIMMED (0x800), rewritten with no time
/// change; then the device told to unmap the file's extents (DKIOCUNMAP:
/// what the device then reads back for them is its own; nothing here
/// writes them).
fn trim_active_file(nx: &mut Nx<'_>, vol: usize, ino: u64, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    fs_tx_enter(nx, vol)?;
    let mut v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    let f = u64a(&v, INO_INTERNAL_FLAGS);
    v.put64(INO_INTERNAL_FLAGS, f | 0x800);
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave(nx, vol, now)
}

/// The close of a file whose size was grown into its preallocation
/// (drafts/s27/re-zerofill.md): VNOP_CLOSE's `VNOP_FSYNC(MNT_NOWAIT)` (K
/// 0x6690bb4) → apfs_flush_allocated_unwritten_ranges (K 0x66a1a98):
/// `cluster_write(vp, NULL, size, size, 0, 0, 0xb80)` zero-fills the
/// file's unwritten range [0, size) in clusters of `c` bytes, each pushed
/// as block maps of at most `m` bytes, stopping at the extents' ends, all
/// in file order (the write-behind pushes the lowest cluster at the fifth
/// and sixth, the flush's push the rest). Each block map takes the
/// extent's no-copy-on-write path (K 0x6708ce4: no transaction, no
/// change) and trims the range from its front; fs_update_prev_fsize (K
/// 0x670ad18) then records the start of what is left as a PREV_FSIZE
/// field when the inode has none or a larger one: so the first block map,
/// when others follow, adds PREV_FSIZE = its end in its own file-system
/// transaction (K 0x670add0), and the fsync, after the flush, removes it
/// in another (K 0x66a17f0 → K 0x6766d4c); the inode's size, times and
/// write generation are not touched. The zeros reach the blocks with the
/// pushes.
pub fn close_after_grow(nx: &mut Nx<'_>, vol: usize, ino: u64, c: u64, m: u64, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    const PAGE: u64 = 16 << 10;
    let bs = nx.l.bs;
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    let ds = dstream_of(&v)?.ok_or("a close-time zero fill of a file with no data stream")?;
    if xfields(&v)?.iter().any(|f| f.0 == INO_EXT_TYPE_PREV_FSIZE) {
        return Err("not implemented: a close-time zero fill of an inode with a PREV_FSIZE field".into());
    }
    if ds.size % PAGE != 0 || c == 0 || m == 0 || c % PAGE != 0 || m % bs != 0 {
        return Err(format!("not implemented: a zero fill of {} bytes in clusters of {c} and block maps of {m} (page-partial UPLs and cluster_io's partial runs)", ds.size));
    }
    let (t, mut st) = nx.fs_tree(vol)?;
    let recs = t.records(&mut st)?;
    drop(st);
    let mut extents = Vec::new();
    for (k, val) in recs.iter().filter(|(k, _)| k.len() == 16 && u64a(k, 0) == (ds.oid | J_FILE_EXTENT << 60)) {
        let val = val.as_ref().ok_or("a file extent with no value")?;
        let (logical, len, phys) = (u64a(k, 8), u64a(val, 0) & 0x00ff_ffff_ffff_ffff, u64a(val, 8));
        if phys == 0 || u64a(val, 0) >> 56 != 0 {
            return Err("not implemented: a zero fill over a sparse or flagged extent".into());
        }
        extents.push((logical, len, phys));
    }
    // The block maps: per cluster of `c`, runs of at most `m` that end
    // where the extent holding them does.
    let mut maps = Vec::new();
    let mut start = 0;
    while start < ds.size {
        let stop = (start + c).min(ds.size);
        let mut off = start;
        while off < stop {
            let want = m.min(stop - off);
            let &(l, len, p) = extents.iter().find(|&&(l, len, _)| l <= off && off < l + len).ok_or_else(|| format!("not implemented: a zero fill at {off:#x} past the file's extents"))?;
            let run = want.min(l + len - off);
            maps.push((off, run, p + (off - l) / bs));
            off += run;
        }
        start = stop;
    }
    let zeros = vec![0u8; m as usize];
    for (i, &(off, run, paddr)) in maps.iter().enumerate() {
        if i == 0 && maps.len() > 1 {
            // fs_update_prev_fsize: the remaining range's start.
            fs_tx_enter(nx, vol)?;
            let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
            let mut x = xfields(&v)?;
            x.push((INO_EXT_TYPE_PREV_FSIZE, 0, (off + run).to_le_bytes().to_vec()));
            put_rec(nx, vol, &inode_key(ino), &with_xfields(&v, &x))?;
            fs_tx_leave_last(nx, vol, false, now)?;
        }
        nx.write_data(paddr, &zeros[..run as usize])?;
    }
    if maps.len() > 1 {
        // The fsync's removal after the flush.
        fs_tx_enter(nx, vol)?;
        let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
        let mut x = xfields(&v)?;
        x.retain(|f| f.0 != INO_EXT_TYPE_PREV_FSIZE);
        put_rec(nx, vol, &inode_key(ino), &with_xfields(&v, &x))?;
        fs_tx_leave_last(nx, vol, false, now)?;
    }
    Ok(())
}

/// How XNU's cluster layer pushes a new file's data written by one
/// `write(2)` of `n` bytes from offset 0: the block maps it asks for, in
/// order (byte offset and length, block multiples ending at the file's
/// allocated end), and how many of them the write's own write-behind pushes
/// before its end (the rest the close's fsync pushes).
pub struct Pushes {
    pub maps: Vec<(u64, u64)>,
    pub before_end: usize,
}

/// `open_dprotected_np(O_WRONLY | O_CREAT | O_TRUNC, class -1 (the
/// default: no class passed), 0, mode)` (or `open` with the same flags) of
/// a new file `name` in `parent` of an unencrypted volume, one `write` of
/// all of `data` at offset 0, and `close` (drafts/s21/re-gigalocker.md D,
/// drafts/s23/re-kernelcache.md 4): the file made as [`create`] makes it
/// (O_TRUNC does nothing to a file the open made). The write's
/// transaction (prepare_write_and_lock K 0x66a4024) makes the data stream
/// and takes one of two paths (K 0x66a4410..0x66a4478):
/// - direct, for a length not a block multiple and under 0x20000: the
///   blocks allocated at once (alloc_space flags 8: requests for what is
///   left until the space manager has granted it all), each piece counted,
///   its file extent (extending the one before it when physically
///   contiguous) and block references; the size, a PREV_FSIZE field of the
///   old size 0, the write generation; the close's push writes the blocks
///   with no transaction;
/// - deferred, otherwise: one sparse extent over the allocated size, the
///   SPARSE_BYTES field and INODE_IS_SPARSE (alloc_space flags 0x10), the
///   size, PREV_FSIZE, the write generation; the blocks are allocated by
///   the block maps `pushes` gives ([`blockmap_fill`]), those after the
///   write's end carrying its times and bytes written.
/// The write's end reads the clock for the modification and change times
/// and counts the bytes written, in memory; the close's fsync removes the
/// PREV_FSIZE field in its own transaction (K 0x6766d4c) whose inode write
/// carries them. The file's inode number.
pub fn write_new_file(nx: &mut Nx<'_>, vol: usize, parent: u64, name: &str, mode: u16, data: &[u8], pushes: &dyn Fn(u64) -> Result<Pushes, String>, now: &mut dyn FnMut() -> u64) -> Result<u64, String> {
    let bs = nx.l.bs;
    let n = data.len() as u64;
    if n == 0 {
        return Err("not implemented: an empty write".into());
    }
    {
        let sb = nx.vol_sb(vol)?;
        if u64a(sb, 0x108) & 1 == 0 || u64a(sb, SB_INCOMPAT) & 0x80 != 0 {
            return Err("not implemented: a file write on an encrypted volume or one with unwritten extents".into());
        }
        // The volume's low-space state (fs + 0x3ac, set below the
        // thresholds at fs + 0x3b0..0x3bc) can force the direct path; its
        // thresholds are not transcribed, so only a volume without a quota
        // is taken.
        if u64a(sb, 0x50) != 0 && (n % bs == 0 || n >= 0x20000) {
            return Err("not implemented: a deferred write on a volume with a quota (the low-space state at fs + 0x3ac)".into());
        }
    }
    let ino = create(nx, vol, parent, name, mode, 0, 0, now)?.map_err(|e| format!("creating {name}: errno {e}"))?;
    let blocks = n.div_ceil(bs);
    let direct = n % bs != 0 && n < 0x20000;
    // The write's transaction.
    fs_tx_enter(nx, vol)?;
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    let oid = u64a(&v, 0x08);
    let mut x = xfields(&v)?;
    x.push((INO_EXT_TYPE_DSTREAM, XF_SYSTEM_FIELD, vec![0u8; 0x28]));
    put_rec(nx, vol, &(oid | J_DSTREAM_ID << 60).to_le_bytes(), &1u32.to_le_bytes())?;
    let mut v = v;
    let mut extents: Vec<(u64, u64, u64)> = Vec::new();
    if direct {
        let mut done = 0u64;
        while done < blocks {
            let (a, got) = nx.alloc_data(blocks - done)?;
            blocks_alloced(nx, vol, got)?;
            match extents.last_mut() {
                Some((l, len, p)) if *p + *len / bs == a => {
                    *len += got * bs;
                    put_rec(nx, vol, &fext_key(oid, *l), &fext_val(*len, *p))?;
                }
                _ => {
                    put_rec(nx, vol, &fext_key(oid, done * bs), &fext_val(got * bs, a))?;
                    extents.push((done * bs, got * bs, a));
                }
            }
            phys_extent_add(nx, vol, a, got, oid)?;
            done += got;
        }
    } else {
        put_rec(nx, vol, &fext_key(oid, 0), &fext_val(blocks * bs, 0))?;
        sparse_bytes(&mut v, &mut x, (blocks * bs) as i64)?;
    }
    {
        let d = x.iter_mut().find(|f| f.0 == INO_EXT_TYPE_DSTREAM).unwrap();
        d.2.put64(0, n);
        d.2.put64(8, blocks * bs);
    }
    x.push((INO_EXT_TYPE_PREV_FSIZE, 0, 0u64.to_le_bytes().to_vec()));
    let mut v = with_xfields(&v, &x);
    let wgc = u32::from_le_bytes(v[INO_WRITE_GEN..INO_WRITE_GEN + 4].try_into().unwrap());
    v.put32(INO_WRITE_GEN, wgc.wrapping_add(1));
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave(nx, vol, now)?;
    // The data as the pages hold it: the bytes, zeros to the block's end.
    let mut padded = data.to_vec();
    padded.resize((blocks * bs) as usize, 0);
    let t_w = if direct {
        // The write's end (K 0x66a5c80): the times and the bytes written,
        // in memory; the close's push writes the blocks.
        let t_w = now();
        for &(l, len, p) in &extents {
            nx.write_data(p, &padded[l as usize..(l + len) as usize])?;
        }
        t_w
    } else {
        let plan = pushes(n)?;
        let mut t_w = None;
        for (k, &(off, len)) in plan.maps.iter().enumerate() {
            if k == plan.before_end {
                t_w = Some(now());
            }
            blockmap_fill(nx, vol, ino, off, &padded[off as usize..(off + len) as usize], t_w.map(|t| (t, n)), now)?;
        }
        match t_w {
            Some(t) => t,
            None => now(),
        }
    };
    // The close: the PREV_FSIZE field's removal.
    fs_tx_enter(nx, vol)?;
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    let mut x = xfields(&v)?;
    if x.iter().any(|f| f.0 == INO_EXT_TYPE_SPARSE_BYTES) {
        return Err("the block maps left the file sparse".into());
    }
    x.retain(|f| f.0 != INO_EXT_TYPE_PREV_FSIZE);
    {
        let d = x.iter_mut().find(|f| f.0 == INO_EXT_TYPE_DSTREAM).unwrap();
        d.2.put64(0x18, n);
    }
    let mut v = with_xfields(&v, &x);
    v.put64(INO_MOD_TIME, t_w);
    v.put64(INO_CHANGE_TIME, t_w);
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave(nx, vol, now)?;
    Ok(ino)
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

/// The unmount of a read-write volume, `forced` (MNT_FORCE) or not:
/// without it XNU's VFS_SYNC first writes the times the volume's inodes
/// hold in memory and commits the container's transaction (`tx_finish`);
/// with it, inodes holding unwritten times are refused (their reclaim is
/// not transcribed); apfs_vfsop_unmount (K 0x66c8214) stops the volume's
/// pfkur thread (K 0x66b0ffc at K 0x66c8988), which removes its temporary
/// inode ([`free_tmp_ino`]), and commits (`tx_finish(0x11)` at K
/// 0x66c8ef8); then, in the next transaction, which stays open, the
/// kernel's `apfs_modified_by` entry (an existing one of the same name
/// moves to the front, else the entries shift and the oldest goes), the
/// clone transaction, and the unmount time.
pub fn unmount(nx: &mut Nx<'_>, vol: usize, forced: bool, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    let pending: Vec<u64> = nx.jobj_times.keys().filter(|k| k.0 == vol).map(|k| k.1).collect();
    if forced && !pending.is_empty() {
        return Err(format!("not implemented: a forced unmount reclaiming vnodes whose in-memory times are unwritten (inodes {pending:#x?}; apfs_vnop_reclaim not transcribed)"));
    }
    if !forced {
        // apfs_vfsop_sync (K 0x66c9d80): the vnode pass first (K 0x66d1748
        // → apfs_fsync_internal, whose times write for an inode with only
        // its times dirty is one file-system transaction rewriting it, K
        // 0x66a1878), then tx_finish.
        if pending.len() > 1 {
            return Err("not implemented: the sync pass's vnode order (vnode_iterate over the mount's list) for more than one inode with unwritten times".into());
        }
        for ino in pending {
            let (m, c) = nx.jobj_times.remove(&(vol, ino)).unwrap();
            fs_tx_enter(nx, vol)?;
            let mut v = inode(nx, vol, ino)?;
            v.put64(INO_MOD_TIME, m);
            v.put64(INO_CHANGE_TIME, c);
            put_rec(nx, vol, &inode_key(ino), &v)?;
            fs_tx_leave(nx, vol, now)?;
        }
        nx.commit()?;
    }
    if let Some(ino) = nx.pfkur_tmp.remove(&vol) {
        free_tmp_ino(nx, vol, ino, now)?;
    }
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

/// The attributes a `setattr` sets (XNU's `vnode_attr` as chmodx_np,
/// fchown, lchown and fsetattrlist fill it): owner, group, mode bits,
/// modification and access times.
#[derive(Default, Clone, Copy)]
pub struct SetAttr {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mode: Option<u16>,
    pub mtime: Option<u64>,
    pub atime: Option<u64>,
}

/// The roles whose file operations here are transcribed: Update's and the
/// others' unencrypted ones, Data's, User's (crypto mode 1).
fn check_setattr_volume(nx: &mut Nx<'_>, vol: usize) -> Result<(), String> {
    check_names(nx, vol)?;
    let (sb, _) = nx.vol_sb_read(vol)?;
    let role = u16::from_le_bytes([sb[SB_ROLE], sb[SB_ROLE + 1]]);
    if (role == 0 || role == 0x240) || (role == 2 && vol_crypto(sb) != 1) {
        return Err(format!("not implemented: setattr on a volume of role {role:#x}"));
    }
    Ok(())
}

/// `setattr` of `a` on `ino` (apfs_vnop_setattr K 0x668e4a0's general
/// path, drafts/s23/re-user-copy.md 2.4): nothing to set writes nothing; a
/// mode alone and unchanged takes the fast path (the change time in memory
/// only: every one here is overwritten by the next write, so it is not
/// kept); else in one file-system transaction owner and group (counted
/// even when unchanged), the mode bits, the access time (not counted), the
/// modification time (and the creation time lowered to it when later),
/// the change time read when anything counted, the inode rewritten.
pub fn setattr(nx: &mut Nx<'_>, vol: usize, ino: u64, a: SetAttr, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    check_setattr_volume(nx, vol)?;
    if a.uid.is_none() && a.gid.is_none() && a.mode.is_none() && a.mtime.is_none() && a.atime.is_none() {
        return Ok(());
    }
    let mut v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    let cur = u16::from_le_bytes([v[INO_MODE], v[INO_MODE + 1]]);
    if a.uid.is_none() && a.gid.is_none() && a.mtime.is_none() && a.atime.is_none() {
        let m = a.mode.unwrap();
        if (m ^ cur) & 0o7777 == 0 {
            return Ok(());
        }
    }
    if let Some(m) = a.mode {
        if (m ^ cur) & 0o7777 != 0 && u64a(&v, 0) == ROOT_DIR_INO && name_of(&v)? == "Library" {
            return Err("not implemented: a mode change of User's /Library (EPERM unless 0755)".into());
        }
    }
    fs_tx_enter(nx, vol)?;
    let mut n = 0;
    if let Some(u) = a.uid {
        v.put32(0x48, u);
        n += 1;
    }
    if let Some(g) = a.gid {
        v.put32(0x4c, g);
        n += 1;
    }
    if let Some(m) = a.mode {
        v.put16(INO_MODE, (cur & 0xf000) | (m & 0o7777));
        n += 1;
    }
    if let Some(t) = a.atime {
        v.put64(0x28, t);
    }
    if let Some(t) = a.mtime {
        v.put64(INO_MOD_TIME, t);
        n += 1;
        if t < u64a(&v, 0x10) {
            v.put64(0x10, t);
        }
    }
    if n != 0 {
        v.put64(INO_CHANGE_TIME, now());
    }
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave(nx, vol, now)
}

/// An inode's name, from its name field.
fn name_of(v: &[u8]) -> Result<String, String> {
    let n = xfields(v)?.into_iter().find(|f| f.0 == 4).ok_or("an inode with no name field")?.2;
    Ok(String::from_utf8_lossy(n.strip_suffix(&[0]).unwrap_or(&n)).into_owned())
}

/// `ftruncate(fd, 0)` of an empty regular file with no data stream
/// (apfs_truncate_locked K 0x66a6bbc's equal-size branch; drafts/s23/
/// re-user-copy.md 2.5): in one file-system transaction the modification
/// and change times (one reading), the inode rewritten; no data stream.
pub fn truncate_same(nx: &mut Nx<'_>, vol: usize, ino: u64, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    check_setattr_volume(nx, vol)?;
    let mut v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    if u16::from_le_bytes([v[INO_MODE], v[INO_MODE + 1]]) & S_IFMT != S_IFREG || dstream_of(&v)?.is_some() {
        return Err("not implemented: a truncate to 0 of other than an empty file with no data stream".into());
    }
    fs_tx_enter(nx, vol)?;
    let t = now();
    v.put64(INO_MOD_TIME, t);
    v.put64(INO_CHANGE_TIME, t);
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave(nx, vol, now)
}

/// `fsetxattr(fd, "com.apple.decmpfs", data, XATTR_SHOWCOMPRESSION)` on a
/// file not yet compressed (apfs_setxattr_internal K 0x6765cc4; drafts/
/// s23/re-user-copy.md 2.6): the attribute embedded in its record
/// (XATTR_DATA_EMBEDDED) in one file-system transaction, the file's change
/// time read, the inode rewritten.
pub fn set_decmpfs_xattr(nx: &mut Nx<'_>, vol: usize, ino: u64, data: &[u8], now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    const NAME: &str = "com.apple.decmpfs";
    check_setattr_volume(nx, vol)?;
    let mut k = (ino | J_XATTR << 60).to_le_bytes().to_vec();
    k.extend_from_slice(&(NAME.len() as u16 + 1).to_le_bytes());
    k.extend_from_slice(NAME.as_bytes());
    k.push(0);
    let mut val = 2u16.to_le_bytes().to_vec();
    val.extend_from_slice(&(data.len() as u16).to_le_bytes());
    val.extend_from_slice(data);
    if data.len() + 4 >= 0xedd || k.len() + val.len() > 0xedd {
        return Err("not implemented: a decmpfs attribute too large to embed (the stream form, K 0x665e120)".into());
    }
    let mut v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    if u32::from_le_bytes(v[0x44..0x48].try_into().unwrap()) & 0x20 != 0 || get_rec(nx, vol, &k)?.is_some() {
        return Err("not implemented: setting the decmpfs attribute of a compressed file or over an existing one".into());
    }
    fs_tx_enter(nx, vol)?;
    put_rec(nx, vol, &k, &val)?;
    v.put64(INO_CHANGE_TIME, now());
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave(nx, vol, now)
}

/// FSIOC_CAS_BSDFLAGS from `expected` to `new` (handle_cas_bsdflags K
/// 0x66e0088; drafts/s23/re-user-copy.md 2.7): setting UF_COMPRESSED on a
/// file with a valid decmpfs attribute first truncates it to its (equal)
/// size; then, the flags being `expected`, in one file-system transaction
/// the flags set, the change time read, and for a regular file becoming
/// compressed the decmpfs header's uncompressed size in j_inode_val +0x54
/// with INODE_HAS_UNCOMPRESSED_SIZE (0x40000), the inode rewritten.
pub fn cas_bsdflags(nx: &mut Nx<'_>, vol: usize, ino: u64, expected: u32, new: u32, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    check_setattr_volume(nx, vol)?;
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    let compressing = new & 0x20 != 0 && expected & 0x20 == 0;
    let mut usize_ = 0;
    if compressing {
        let mut k = (ino | J_XATTR << 60).to_le_bytes().to_vec();
        k.extend_from_slice(&18u16.to_le_bytes());
        k.extend_from_slice(b"com.apple.decmpfs\0");
        let x = get_rec(nx, vol, &k)?.ok_or("not implemented: UF_COMPRESSED on a file without a decmpfs attribute")?;
        let d = &x[4..];
        if x[0..2] != 2u16.to_le_bytes() || d.len() < 16 || &d[0..4] != b"fpmc" || u32::from_le_bytes(d[4..8].try_into().unwrap()) != 9 {
            return Err("not implemented: UF_COMPRESSED with a decmpfs attribute other than an embedded type 9".into());
        }
        usize_ = u64a(d, 8);
        truncate_same(nx, vol, ino, now)?;
    }
    let mut v = if compressing { get_rec(nx, vol, &inode_key(ino))?.ok_or("no inode")? } else { v };
    let flags = u32::from_le_bytes(v[0x44..0x48].try_into().unwrap());
    if flags & 0x3fff_ffff != expected {
        return Err("not implemented: a flags compare-and-swap that does not match".into());
    }
    if (flags ^ new) & !0x20 & 0x3fff_ffff != 0 {
        return Err("not implemented: changing BSD flags other than UF_COMPRESSED".into());
    }
    fs_tx_enter(nx, vol)?;
    v.put32(0x44, (flags & 0xc000_0000) | (new & 0x3fff_ffff));
    v.put64(INO_CHANGE_TIME, now());
    if compressing && u16::from_le_bytes([v[INO_MODE], v[INO_MODE + 1]]) & S_IFMT == S_IFREG && usize_ != 0 {
        v.put64(0x54, usize_);
        let f = u64a(&v, INO_INTERNAL_FLAGS);
        v.put64(INO_INTERNAL_FLAGS, f | 0x4_0000);
    }
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave(nx, vol, now)
}

/// `setattrlist(ATTR_CMN_DATA_PROTECT_FLAGS)` of directory `ino` to class
/// `class` (apfs_vnop_setattr K 0x668e4a0), on a volume of crypto mode 1
/// (drafts/s23/re-user-copy.md 3) or 3 (a VEK volume: K 0x668eb64 →
/// K 0x66a8804; drafts/s26/re-aks-data.md 1): nothing when the class is
/// already it; else one file-system transaction setting the class and
/// PROT_CLASS_EXPLICIT (0x8) with the change time read, the inode written
/// from its in-memory object (so with any times it held, `nx.jobj_times`),
/// then the general path's transaction with nothing counted (the inode
/// rewritten as it is).
pub fn set_dir_class(nx: &mut Nx<'_>, vol: usize, ino: u64, class: u32, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    check_setattr_volume(nx, vol)?;
    let crypto = {
        let (sb, _) = nx.vol_sb_read(vol)?;
        vol_crypto(sb)
    };
    if crypto != 1 && crypto != 3 {
        return Err(format!("not implemented: a class change on a volume of crypto mode {crypto}"));
    }
    let mut v = inode(nx, vol, ino)?;
    if u16::from_le_bytes([v[INO_MODE], v[INO_MODE + 1]]) & S_IFMT != S_IFDIR {
        return Err("not implemented: a class change of other than a directory".into());
    }
    if class == 6 {
        return Err("class F on a directory (EPERM)".into());
    }
    let old = u32::from_le_bytes(v[0x3c..0x40].try_into().unwrap());
    if crypto == 3 {
        // The mode-3 branch for a directory: the class must be a valid one
        // (classes 0 to 7 but 5, mask 0xdf), and K 0x6701c0c gives the
        // directory's current key kind from its class by the table at
        // K 0x55af1ac (a directory never uses the VEK, K 0x66f7f88); the
        // same kind writes nothing in K 0x66a8804, but the general path's
        // transaction still follows.
        const KIND: [u32; 8] = [5, 0, 1, 2, 3, 0, 4, 7];
        let valid = |c: u32| c < 8 && (0xdfu32 >> c) & 1 != 0;
        if !valid(class) {
            return Err(format!("class {class} on a directory (EINVAL)"));
        }
        if !valid(old & 0x1f) {
            return Err(format!("a directory of class {old:#x} has no key kind (K 0x66a8804 returns 0x5c)"));
        }
        if KIND[(old & 0x1f) as usize] == KIND[class as usize] {
            return Err("not implemented: a class change to the directory's own key kind (the general path's transaction alone)".into());
        }
    } else if old == class {
        return Ok(());
    }
    if crypto == 1 && old == 2 {
        return Err("not implemented: a class change from class B (K 0x66fac40)".into());
    }
    if let Some((m, c)) = nx.jobj_times.remove(&(vol, ino)) {
        v.put64(INO_MOD_TIME, m);
        v.put64(INO_CHANGE_TIME, c);
    }
    fs_tx_enter(nx, vol)?;
    v.put32(0x3c, class);
    let f = u64a(&v, INO_INTERNAL_FLAGS);
    v.put64(INO_INTERNAL_FLAGS, f | 0x8);
    v.put64(INO_CHANGE_TIME, now());
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave(nx, vol, now)?;
    fs_tx_enter(nx, vol)?;
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave(nx, vol, now)
}

/// The value of `ino`'s inode.
pub fn inode(nx: &mut Nx<'_>, vol: usize, ino: u64) -> Result<Vec<u8>, String> {
    get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))
}

/// The embedded value of `ino`'s extended attribute `name`, if it has
/// one; one kept in a stream is refused.
pub fn xattr_embedded(nx: &mut Nx<'_>, vol: usize, ino: u64, name: &str) -> Result<Option<Vec<u8>>, String> {
    let mut k = (ino | J_XATTR << 60).to_le_bytes().to_vec();
    k.extend_from_slice(&(name.len() as u16 + 1).to_le_bytes());
    k.extend_from_slice(name.as_bytes());
    k.push(0);
    match get_rec(nx, vol, &k)? {
        None => Ok(None),
        Some(v) if v[0..2] == 2u16.to_le_bytes() || v[0..2] == 6u16.to_le_bytes() => Ok(Some(v[4..].to_vec())),
        Some(_) => Err(format!("not implemented: the stream attribute {name}")),
    }
}

/// The names of `ino`'s extended attributes.
pub fn xattr_names(nx: &mut Nx<'_>, vol: usize, ino: u64) -> Result<Vec<String>, String> {
    let (t, mut st) = nx.fs_tree(vol)?;
    // The attributes follow the inode's record.
    let mut key = inode_key(ino);
    let mut out = Vec::new();
    while let Some((k, _)) = t.get_gt(&mut st, &key)? {
        if u64a(&k, 0) != (ino | J_XATTR << 60) {
            break;
        }
        out.push(String::from_utf8_lossy(&k[10..k.len() - 1]).into_owned());
        key = k;
    }
    Ok(out)
}

/// The directory `ino` is in (its inode's `parent_id`).
pub fn parent_of(nx: &mut Nx<'_>, vol: usize, ino: u64) -> Result<u64, String> {
    let (t, mut st) = nx.fs_tree(vol)?;
    let v = t.get(&mut st, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    Ok(u64a(&v, 0))
}

/// Looks `name` up in directory `parent`: its inode number.
pub fn lookup(nx: &mut Nx<'_>, vol: usize, parent: u64, name: &str) -> Result<Option<u64>, String> {
    let (t, mut st): (Tree, _) = nx.fs_tree(vol)?;
    Ok(t.get(&mut st, &drec_key(parent, name))?.map(|v| u64a(&v, 0)))
}

/// What the removals take from the run that only the device has: the
/// clock at each read (the parent's and the child's times, every
/// `fs_tx_leave`), the access-time marks reads leave (K 0x670e2f4, applied
/// at the next rewrite of a marked inode; the /mnt1 mount's atime flags
/// were not found), and the Data copy's writes that share their
/// transactions (BOM writes each file to /mnt2 before its unlink).
pub const REMOVE_STAND_IN: &str = "the clock readings of restored_external's removals from System, the access times its reads would mark, and the Data copy's writes in the same transactions (stand-in: the clock of the machine building the image; no access time written; the removals' transactions holding nothing else)";

const J_XATTR: u64 = 4;
const XATTR_DATA_STREAM: u16 = 0x1;
const SB_TOTAL_FILES_KEY: usize = SB_NUM_FILES;
/// `j_inode_val_t` fields.
const INO_MOD_TIME: usize = 0x18;
const INO_CHANGE_TIME: usize = 0x20;
const INO_INTERNAL_FLAGS: usize = 0x30;
const INO_NCHILDREN: usize = 0x38;
const INO_WRITE_GEN: usize = 0x40;
const INO_MODE: usize = 0x50;
/// `INODE_IS_APFS_PRIVATE`, `INODE_MAINTAIN_DIR_STATS`, the purgeable
/// flag (K 0x66fd850 C0) and the file-info flag (C5).
const INODE_IS_APFS_PRIVATE: u64 = 0x1;
const INODE_MAINTAIN_DIR_STATS: u64 = 0x2;
const INODE_PURGEABLE: u64 = 0x80000;
const INODE_HAS_FILE_INFO: u64 = 0x1000_0000;

fn get_rec(nx: &mut Nx<'_>, vol: usize, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let (t, mut st) = nx.fs_tree(vol)?;
    t.get(&mut st, key)
}

fn put_rec(nx: &mut Nx<'_>, vol: usize, key: &[u8], val: &[u8]) -> Result<(), String> {
    if key.len() == 8 && u64a(key, 0) >> 60 == J_INODE {
        let ino = u64a(key, 0) & OBJ_MASK;
        if nx.jobj_times.contains_key(&(vol, ino)) {
            return Err(format!("not implemented: a rewrite of inode {ino:#x} that does not carry the times its in-memory object holds"));
        }
    }
    let (mut t, mut st) = nx.fs_tree(vol)?;
    t.insert(&mut st, key, Some(val))?;
    nx.set_fs_tree(vol, t);
    Ok(())
}

fn remove_rec(nx: &mut Nx<'_>, vol: usize, key: &[u8]) -> Result<(), String> {
    let (mut t, mut st) = nx.fs_tree(vol)?;
    t.remove(&mut st, key)?.ok_or("a record to remove is not in the tree")?;
    nx.set_fs_tree(vol, t);
    Ok(())
}

/// A directory's records in key order (what `apfs_vnop_readdir` K
/// 0x6695ebc and `getattrlistbulk` return): each child's key, inode
/// number and `DT_` type.
pub fn read_dir(nx: &mut Nx<'_>, vol: usize, dir: u64) -> Result<Vec<(Vec<u8>, u64, u16)>, String> {
    let (t, mut st) = nx.fs_tree(vol)?;
    let mut out = Vec::new();
    // Below every record of the directory: a hash and name length of 0.
    let mut key = (dir | J_DIR_REC << 60).to_le_bytes().to_vec();
    key.extend_from_slice(&0u32.to_le_bytes());
    while let Some((k, v)) = t.get_gt(&mut st, &key)? {
        if u64a(&k, 0) != (dir | J_DIR_REC << 60) {
            break;
        }
        let v = v.ok_or("a directory record with no value")?;
        out.push((k.clone(), u64a(&v, 0), u16::from_le_bytes([v[16], v[17]]) & 0xf));
        key = k;
    }
    Ok(out)
}

/// `fs_tx_leave` inside an operation that still holds the transaction:
/// the volume's last change, and whether `tx_leave` marked it closing.
fn fs_tx_leave_nested(nx: &mut Nx<'_>, vol: usize, now: &mut dyn FnMut() -> u64) -> Result<bool, String> {
    fs_tx_mark(nx, vol, now)?;
    nx.close_due(0)
}

/// The operation's last `fs_tx_leave`: the transaction commits when it
/// was marked closing while held or `tx_leave` closes it now.
fn fs_tx_leave_last(nx: &mut Nx<'_>, vol: usize, closing: bool, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    fs_tx_mark(nx, vol, now)?;
    if nx.close_due(0)? || closing {
        nx.commit()?;
    }
    Ok(())
}

/// The removal of a directory entry (`remove_dir_entry` K 0x66fd1ac):
/// the record goes, then the parent's modification and change times (one
/// clock reading), child count and write generation.
fn remove_dir_entry(nx: &mut Nx<'_>, vol: usize, dir: u64, drec: &[u8], now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    remove_rec(nx, vol, drec)?;
    let tp = now();
    let mut d = get_rec(nx, vol, &inode_key(dir))?.ok_or("the parent has no inode")?;
    if u64a(&d, INO_INTERNAL_FLAGS) & INODE_MAINTAIN_DIR_STATS != 0 {
        return Err("not implemented: a removal from a directory keeping directory statistics".into());
    }
    d.put64(INO_MOD_TIME, tp);
    d.put64(INO_CHANGE_TIME, tp);
    let n = i32::from_le_bytes(d[INO_NCHILDREN..INO_NCHILDREN + 4].try_into().unwrap());
    d.put32(INO_NCHILDREN, (n - 1) as u32);
    let g = u32::from_le_bytes(d[INO_WRITE_GEN..INO_WRITE_GEN + 4].try_into().unwrap());
    d.put32(INO_WRITE_GEN, g.wrapping_add(1));
    put_rec(nx, vol, &inode_key(dir), &d)
}

/// The extent-removal loop for a stream truncated to nothing (K
/// 0x66fe9bc): the stream's file extents last to first in one batch of
/// at most 1,000, each record removed and its blocks' reference dropped
/// and freed (`_remove_extents_of_file_cb` K 0x66ff120,
/// `apfs_update_phys_range` K 0x66f61b4), in its own nested transaction
/// entry; `rewrite` is called before the batch's `fs_tx_leave` with the
/// logical address of the last extent handled. Whether the transaction
/// was marked closing.
fn remove_extents(nx: &mut Nx<'_>, vol: usize, oid: u64, rewrite: &mut dyn FnMut(&mut Nx<'_>, u64) -> Result<(), String>, now: &mut dyn FnMut() -> u64) -> Result<bool, String> {
    let bs = nx.block_size();
    let last_key = fext_key(oid, 0xffff_ffff_ffff_fffe);
    let last = {
        let (t, mut st) = nx.fs_tree(vol)?;
        t.get_le(&mut st, &last_key)?
    };
    match &last {
        Some((k, _)) if u64a(k, 0) == (oid | J_FILE_EXTENT << 60) => {}
        _ => return Ok(false),
    }
    fs_tx_enter(nx, vol)?;
    let mut count = 0;
    let mut alloced = None;
    loop {
        let rec = {
            let (t, mut st) = nx.fs_tree(vol)?;
            t.get_le(&mut st, &last_key)?
        };
        let Some((k, v)) = rec else { break };
        if u64a(&k, 0) != (oid | J_FILE_EXTENT << 60) {
            break;
        }
        if count == 1000 {
            return Err("not implemented: a stream of more than 1,000 extents (the removal's further batches)".into());
        }
        let v = v.ok_or("a file extent with no value")?;
        let (logical, len, phys) = (u64a(&k, 8), u64a(&v, 0) & 0x00ff_ffff_ffff_ffff, u64a(&v, 8));
        if phys == 0 {
            return Err("not implemented: removing a sparse extent (update_sparse_bytes, K 0x66ff7c0)".into());
        }
        if u64a(&v, 16) != 0 {
            return Err("not implemented: removing an extent with a crypto identifier".into());
        }
        remove_rec(nx, vol, &k)?;
        if len != 0 {
            let n = len / bs;
            let key = (phys | J_EXTENT << 60).to_le_bytes().to_vec();
            let (mut t, mut st) = nx.extentref_tree(vol)?;
            let pv = t.get(&mut st, &key)?.ok_or("not implemented: freeing an extent the extent-reference tree has no exact record of")?;
            if u64a(&pv, 0) & OBJ_MASK != n || i32::from_le_bytes(pv[16..20].try_into().unwrap()) != 1 {
                return Err("not implemented: freeing part of a referenced extent, or a shared one".into());
            }
            t.remove(&mut st, &key)?;
            nx.set_extentref_tree(vol, t)?;
            nx.free_data(vol, phys, n)?;
        }
        alloced = Some(logical);
        count += 1;
    }
    if let Some(a) = alloced {
        rewrite(nx, a)?;
    }
    fs_tx_leave_nested(nx, vol, now)
}

/// `unlink` of regular file `ino`, the only link to it and not open,
/// whose entry in directory `dir` is the record `drec`
/// (`apfs_vnop_remove` K 0x6691810, `fs_delete_inode_with_xid` K
/// 0x66fd850): in one transaction, the entry and the parent's update, the
/// file's change time read and its link count dropped, the files
/// counted down; its extended attributes in name order (an embedded one's
/// record; a stream's extents, then its record); its data stream's
/// reference dropped in place, its extents, the inode rewritten with the
/// stream's allocated size dropped, the stream's record; the inode.
pub fn unlink(nx: &mut Nx<'_>, vol: usize, dir: u64, drec: &[u8], ino: u64, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    check_volume(nx, vol)?;
    fs_tx_enter(nx, vol)?;
    let mut f = get_rec(nx, vol, &inode_key(ino))?.ok_or("the file has no inode")?;
    if u16::from_le_bytes([f[INO_MODE], f[INO_MODE + 1]]) & S_IFMT != S_IFREG {
        return Err("not implemented: unlink of a file that is not regular".into());
    }
    if i32::from_le_bytes(f[INO_NCHILDREN..INO_NCHILDREN + 4].try_into().unwrap()) != 1 {
        return Err("not implemented: unlink of a hard-linked file".into());
    }
    let iflags = u64a(&f, INO_INTERNAL_FLAGS);
    if iflags & (INODE_PURGEABLE | INODE_MAINTAIN_DIR_STATS | INODE_HAS_FILE_INFO) != 0 {
        return Err(format!("not implemented: unlink of a file with internal flags {iflags:#x}"));
    }
    if xfields(&f)?.iter().any(|x| x.0 == 1 || x.0 == 3 || x.0 == 10) {
        return Err("not implemented: unlink of a file with sibling, document or directory-statistics fields".into());
    }
    remove_dir_entry(nx, vol, dir, drec, now)?;
    let tc = now();
    f.put64(INO_CHANGE_TIME, tc);
    f.put32(INO_NCHILDREN, 0);
    if iflags & INODE_IS_APFS_PRIVATE == 0 {
        let sb = nx.vol_sb(vol)?;
        let n = u64a(sb, SB_TOTAL_FILES_KEY);
        sb.put64(SB_TOTAL_FILES_KEY, n - 1);
    }
    let mut closing = false;
    // The extended attributes, by name.
    let mut key = inode_key(ino);
    loop {
        let next = {
            let (t, mut st) = nx.fs_tree(vol)?;
            t.get_gt(&mut st, &key)?
        };
        let Some((k, v)) = next else { break };
        if u64a(&k, 0) != (ino | J_XATTR << 60) {
            break;
        }
        let v = v.ok_or("an extended attribute with no value")?;
        if u16::from_le_bytes([v[0], v[1]]) & XATTR_DATA_STREAM != 0 {
            let xoid = u64a(&v, 4);
            closing |= remove_extents(nx, vol, xoid, &mut |_, _| Ok(()), now)?;
        }
        remove_rec(nx, vol, &k)?;
        key = k;
    }
    // The data stream.
    if let Some(ds) = dstream_of(&f)?.filter(|d| d.oid != 0) {
        let idk = (ds.oid | J_DSTREAM_ID << 60).to_le_bytes().to_vec();
        let mut idv = get_rec(nx, vol, &idk)?.ok_or("a data stream with no reference record")?;
        if u32::from_le_bytes(idv[0..4].try_into().unwrap()) != 1 {
            return Err("not implemented: unlink of a file sharing its data stream (a clone)".into());
        }
        idv.put32(0, 0);
        put_rec(nx, vol, &idk, &idv)?;
        let mut rewrite = |nx: &mut Nx<'_>, alloced: u64| -> Result<(), String> {
            let x: Vec<(u8, u8, Vec<u8>)> = xfields(&f)?
                .into_iter()
                .map(|(t, fl, mut d)| {
                    if t == INO_EXT_TYPE_DSTREAM {
                        d.put64(8, alloced);
                    }
                    (t, fl, d)
                })
                .collect();
            let v = with_xfields(&f, &x);
            if v.len() != f.len() {
                return Err("an inode rewrite changing its length".into());
            }
            put_rec(nx, vol, &inode_key(ino), &v)
        };
        closing |= remove_extents(nx, vol, ds.oid, &mut rewrite, now)?;
        remove_rec(nx, vol, &idk)?;
    }
    remove_rec(nx, vol, &inode_key(ino))?;
    fs_tx_leave_last(nx, vol, closing, now)
}

/// `rmdir` of empty directory `ino` whose entry in `dir` is `drec`
/// (`apfs_vnop_rmdir_with_flags` K 0x66a2df4): in one transaction, the
/// entry and the parent's update, the inode, the directories counted
/// down.
pub fn rmdir(nx: &mut Nx<'_>, vol: usize, dir: u64, drec: &[u8], ino: u64, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    check_volume(nx, vol)?;
    fs_tx_enter(nx, vol)?;
    let g = get_rec(nx, vol, &inode_key(ino))?.ok_or("the directory has no inode")?;
    if u16::from_le_bytes([g[INO_MODE], g[INO_MODE + 1]]) & S_IFMT != S_IFDIR {
        return Err("rmdir of a file that is not a directory".into());
    }
    if i32::from_le_bytes(g[INO_NCHILDREN..INO_NCHILDREN + 4].try_into().unwrap()) != 0 {
        return Err("not implemented: rmdir of a directory that is not empty (K 0x6766a50)".into());
    }
    if u64a(&g, INO_INTERNAL_FLAGS) & (INODE_MAINTAIN_DIR_STATS | INODE_PURGEABLE) != 0 || u64a(&g, 0x08) != ino {
        return Err("not implemented: rmdir of a directory with statistics, purgeability or a data stream".into());
    }
    remove_dir_entry(nx, vol, dir, drec, now)?;
    let next = {
        let (t, mut st) = nx.fs_tree(vol)?;
        t.get_gt(&mut st, &inode_key(ino))?
    };
    if next.is_some_and(|(k, _)| u64a(&k, 0) & OBJ_MASK == ino) {
        return Err("not implemented: rmdir of a directory with extended attributes".into());
    }
    remove_rec(nx, vol, &inode_key(ino))?;
    let sb = nx.vol_sb(vol)?;
    let n = u64a(sb, SB_NUM_DIRECTORIES);
    sb.put64(SB_NUM_DIRECTORIES, n - 1);
    fs_tx_leave_last(nx, vol, false, now)
}

/// The trees restored_external's fixup_var moves from System to Data
/// (RE@0x10002f15c..0x10002f358), relative to /private/var, in its list's
/// order.
pub const MOVED_FROM_VAR: [&str; 3] = ["MobileAsset/PreinstalledAssets", "MobileAsset/PreinstalledAssetsV2", "staged_system_apps"];

/// fixup_var's removals from System (volume `vol`): BOM's copy of
/// /private/var (one thread, each directory read in key order and a
/// subdirectory descended into where it comes) unlinks each regular file
/// under a moved tree once it is copied (the handler RE@0x10003ca5c);
/// then `removefile(REMOVEFILE_RECURSIVE)` of each moved tree (fts,
/// physical, no comparator) removes its directories after their
/// contents. The copy's writes to Data are not made here.
pub fn remove_moved_trees(nx: &mut Nx<'_>, vol: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    const DT_DIR: u16 = 4;
    const DT_REG: u16 = 8;
    let mut var = 2;
    for n in ["private", "var"] {
        var = lookup(nx, vol, var, n)?.ok_or_else(|| format!("no {n} on the way to /private/var"))?;
    }
    fn under(rel: &str) -> bool {
        MOVED_FROM_VAR.iter().any(|m| rel == *m || rel.starts_with(&format!("{m}/")))
    }
    fn copy(nx: &mut Nx<'_>, vol: usize, dir: u64, rel: &str, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
        for (k, ino, ty) in read_dir(nx, vol, dir)? {
            let nl = (u32::from_le_bytes(k[8..12].try_into().unwrap()) & 0x3ff) as usize;
            let name = std::str::from_utf8(&k[12..12 + nl - 1]).map_err(|_| "a name that is not UTF-8")?;
            let path = if rel.is_empty() { name.to_string() } else { format!("{rel}/{name}") };
            match ty {
                DT_DIR => copy(nx, vol, ino, &path, now)?,
                DT_REG if under(&path) => unlink(nx, vol, dir, &k, ino, now)?,
                DT_REG => {}
                _ if under(&path) => return Err(format!("not implemented: moving a file of type {ty} from /private/var/{path}")),
                _ => {}
            }
        }
        Ok(())
    }
    copy(nx, vol, var, "", now)?;
    fn remove_tree(nx: &mut Nx<'_>, vol: usize, dir: u64, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
        for (k, ino, ty) in read_dir(nx, vol, dir)? {
            if ty != DT_DIR {
                return Err("not implemented: removefile meeting a file the copy left".into());
            }
            remove_tree(nx, vol, ino, now)?;
            rmdir(nx, vol, dir, &k, ino, now)?;
        }
        Ok(())
    }
    for m in MOVED_FROM_VAR {
        let (parent, name) = m.rsplit_once('/').map_or(("", m), |(p, n)| (p, n));
        let mut pdir = var;
        let mut found = true;
        for c in parent.split('/').filter(|c| !c.is_empty()) {
            match lookup(nx, vol, pdir, c)? {
                Some(i) => pdir = i,
                None => found = false,
            }
        }
        let Some(top) = found.then(|| lookup(nx, vol, pdir, name)).transpose()?.flatten() else { continue };
        remove_tree(nx, vol, top, now)?;
        let k = drec_key(pdir, name);
        rmdir(nx, vol, pdir, &k, top, now)?;
    }
    Ok(())
}
