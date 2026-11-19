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
use super::tx::{self, Nx};
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
/// `APFS_FS_UNENCRYPTED`.
const APFS_FS_UNENCRYPTED: u64 = 0x1;
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
    if nx.mounted.contains(&vol) {
        return Err(format!("mounting volume slot {vol}, which is mounted"));
    }
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
    volume_fixup(nx, vol, now)?;
    // mount_list_add; the first path through the mount point (the
    // restore's `.ramdisk-boot-done` open after its mounts) brings in the
    // root's vnode (VFS_ROOT).
    nx.mounted.push(vol);
    nx.vnode_get(vol, ROOT_DIR_INO, &|| format!("the root of volume slot {vol}"));
    Ok(())
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
/// overprovisioning file's flag 0x800 when it lacks it (no file at the
/// first mount).
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
    // The overprovisioning fixup (K 0x6714508..0x6714614): the root's
    // `.overprovisioning_file` (K 0x67018ec), when its in-memory object
    // lacks internal flag 0x800, given it in a file-system transaction
    // (4, 1, 0) that writes the object (update_jobj K 0x66f5030, with any
    // times it held unwritten): "overprovisioning fixup succeeded".
    if let Some(ino) = lookup(nx, vol, ROOT_DIR_INO, ".overprovisioning_file")? {
        if u64a(&inode(nx, vol, ino)?, INO_INTERNAL_FLAGS) & 0x800 == 0 {
            fs_tx_enter(nx, vol)?;
            let mut v = in_memory_inode(nx, vol, ino)?;
            let f = u64a(&v, INO_INTERNAL_FLAGS);
            v.put64(INO_INTERNAL_FLAGS, f | 0x800);
            put_rec(nx, vol, &inode_key(ino), &v)?;
            fs_tx_leave(nx, vol, now)?;
        }
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

/// [`create_obj_in`], with the vnode namei and the VNOP bring in: the new
/// inode's, or with EEXIST the existing one's.
fn create_obj(nx: &mut Nx<'_>, vol: usize, parent: u64, name: &str, mode: u16, uid: u32, gid: u32, now: &mut dyn FnMut() -> u64) -> Result<Result<u64, i32>, String> {
    let r = create_obj_in(nx, vol, parent, name, mode, uid, gid, now)?;
    match r {
        Ok(ino) => nx.vnode_get(vol, ino, &|| format!("the creation of {name} (inode {ino:#x}) on volume slot {vol}")),
        Err(_) => {
            lookup(nx, vol, parent, name)?;
        }
    }
    Ok(r)
}

fn create_obj_in(nx: &mut Nx<'_>, vol: usize, parent: u64, name: &str, mode: u16, uid: u32, gid: u32, now: &mut dyn FnMut() -> u64) -> Result<Result<u64, i32>, String> {
    let dir = mode & S_IFMT == S_IFDIR;
    let link = mode & S_IFMT == S_IFLNK;
    // A directory on Data, or a directory or file on User: the only
    // document-identifier upkeep of mkdir and create is the tombstone
    // inheritance (K 0x66a3a38), which needs a tombstone the restore's
    // threads do not hold (drafts/s23/re-uml-data.md 1.3), and on User
    // their inode and directory records go to the file-system tree, not
    // the secondary one (K 0x66ed1bc; drafts/s23/re-user-copy.md 2.1). A
    // symbolic link calls fs_obj_create_name_checked directly, without
    // fs_obj_create_do's tombstone step (drafts/s27/re-datawrite.md 6).
    let doc_ok = {
        let (sb, _) = nx.vol_sb_read(vol)?;
        match u16::from_le_bytes([sb[SB_ROLE], sb[SB_ROLE + 1]]) {
            0x40 => u64a(sb, SB_INCOMPAT) & 0x100 == 0,
            0x2 => !link && vol_crypto(sb) == 1,
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
    // 0x66a3858; drafts/s26/re-aks-data.md 3.6); under a parent of no valid
    // file class (0) it takes the volume's default (fs + 0x350: 3, as on an
    // unencrypted volume) with no PROT_CLASS_EXPLICIT (drafts/s27/
    // re-bomcopy.md 4.1).
    let vek_file_class = encrypted && !dir && !link && crypto == 3 && (1..=7).contains(&parent_prot);
    if vek_file_class && (1u32 << parent_prot) & 0x97 != 0 {
        extra |= 0x8;
    }
    let vek_default = encrypted && !dir && !link && crypto == 3 && !vek_file_class;
    if encrypted && !dir && !link && crypto != 1 && crypto != 3 {
        return Err("not implemented: a file on an encrypted volume of crypto kind 0 or 2".into());
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
    } else if vek_default {
        DEFAULT_CP_CLASS
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
    nx.take_times(vol, parent);
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

/// The size of the data stream an inode value `v` names (0 with none).
pub fn dstream_size(v: &[u8]) -> Result<u64, String> {
    Ok(dstream_of(v)?.map_or(0, |d| d.size))
}

/// How a stream's data is encrypted (drafts/s27/re-datawrite.md 0, 2): not
/// at all (an unencrypted volume); with the volume's key (identifier 4,
/// each data extent's crypto field its own first block, flagged
/// FEXT_CRYPTO_ID_IS_TWEAK); or with a per-file key (identifier the
/// stream's, a crypto-state record referenced by each data-extent record).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Crypt {
    None,
    Vek,
    Key(u64),
}

impl Crypt {
    /// The data stream's `default_crypto_id`.
    fn id(self) -> u64 {
        match self {
            Crypt::None => 0,
            Crypt::Vek => 4,
            Crypt::Key(f) => f,
        }
    }
}

/// The crypt of a new data stream `oid` of an object of protection class
/// `class` and internal flags `internal` on volume `vol` (K 0x66f441c's
/// crypto-mode-3 branch K 0x66f44b0..0x66f4544): classes 1 and 2, an
/// explicit class (PROT_CLASS_EXPLICIT) and class 4 (class-F keys are
/// supported in crypto mode 3, K 0x67372d0) take a per-file key named by
/// the stream; every other class the volume's key. Only class 4's key
/// record is transcribed (kind 3, K 0x67072f4).
fn stream_crypt(nx: &mut Nx<'_>, vol: usize, oid: u64, class: u32, internal: u64) -> Result<Crypt, String> {
    let (sb, _) = nx.vol_sb_read(vol)?;
    if u64a(sb, SB_FS_FLAGS) & 1 != 0 {
        return Ok(Crypt::None);
    }
    if vol_crypto(sb) != 3 || u64a(sb, SB_INCOMPAT) & 0x100 != 0 {
        return Err("not implemented: stream data on an encrypted volume of another crypto kind than a VEK volume's".into());
    }
    if class == 1 || class == 2 || internal & 0x8 != 0 || class == 4 {
        if class != 4 {
            return Err(format!("not implemented: a per-file key of protection class {class} (its crypto-state record's class field)"));
        }
        Ok(Crypt::Key(oid))
    } else {
        Ok(Crypt::Vek)
    }
}

/// The crypt of regular file `v`'s (its inode value) data stream.
fn file_crypt(nx: &mut Nx<'_>, vol: usize, v: &[u8]) -> Result<Crypt, String> {
    stream_crypt(nx, vol, u64a(v, 0x08), u32::from_le_bytes(v[0x3c..0x40].try_into().unwrap()), u64a(v, INO_INTERNAL_FLAGS))
}

/// A data extent's value (K 0x6700a08): with the volume's key on a volume
/// of fs_flags 0x108 the flag byte 1 (FEXT_CRYPTO_ID_IS_TWEAK) and the
/// extent's first block as its crypto field; with a per-file key that key's
/// identifier.
fn data_fext_val(len: u64, phys: u64, c: Crypt) -> Vec<u8> {
    let (flags, crypto) = match c {
        Crypt::None => (0, 0),
        Crypt::Vek => (1u64 << 56, phys),
        Crypt::Key(f) => (0, f),
    };
    let mut v = (len | flags).to_le_bytes().to_vec();
    v.extend_from_slice(&phys.to_le_bytes());
    v.extend_from_slice(&crypto.to_le_bytes());
    v
}

/// A new data-extent record's reference on its per-file key's crypto-state
/// record (K 0x66f8ad8); the volume's key takes none.
fn crypto_ref(nx: &mut Nx<'_>, vol: usize, c: Crypt) -> Result<(), String> {
    if let Crypt::Key(f) = c {
        let ck = (f | J_CRYPTO_STATE << 60).to_le_bytes();
        let mut cs = get_rec(nx, vol, &ck)?.ok_or("a per-file key with no crypto-state record")?;
        let n = u32::from_le_bytes(cs[0..4].try_into().unwrap());
        cs.put32(0, n + 1);
        put_rec(nx, vol, &ck, &cs)?;
    }
    Ok(())
}

/// A class-4 per-file key's crypto-state record (K 0x6734490/K 0x6734154):
/// one reference, version 6.0, no flags, class 4 (kind 3, K 0x67072f4), the
/// volume's OS version, revision 0, the AKS blobs' lengths and the blobs
/// ([`PER_FILE_KEY_STAND_IN`]).
fn class4_crypto_state(nx: &mut Nx<'_>, vol: usize) -> Result<Vec<u8>, String> {
    let key_os_version = {
        let (sb, _) = nx.vol_sb_read(vol)?;
        u32::from_le_bytes(sb[0x6c..0x70].try_into().unwrap())
    };
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
    Ok(cs)
}

/// The volume checks of a data write on volume `vol`: on Data (no
/// secondary tree) its names only, the write paths there having no
/// document-identifier step (traced for [`write_new_protected`],
/// drafts/s23/re-uml-data.md 3, and unchanged by the crypto kind,
/// drafts/s27/re-datawrite.md 0); elsewhere [`check_volume`]'s.
fn check_write_volume(nx: &mut Nx<'_>, vol: usize) -> Result<(), String> {
    let (sb, _) = nx.vol_sb_read(vol)?;
    if u16::from_le_bytes([sb[SB_ROLE], sb[SB_ROLE + 1]]) == 0x40 && u64a(sb, SB_INCOMPAT) & 0x100 == 0 {
        check_names(nx, vol)
    } else {
        check_volume(nx, vol)
    }
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
        let crypt = file_crypt(nx, vol, &v)?;
        // The sparse extent holding `pos`.
        let (t, mut st) = nx.fs_tree(vol)?;
        let recs = t.records(&mut st)?;
        let ext: Vec<(u64, u64, u64, Vec<u8>)> = recs
            .iter()
            .filter(|(k, _)| k.len() == 16 && u64a(k, 0) == (ds.oid | J_FILE_EXTENT << 60))
            .map(|(k, v)| {
                let v = v.as_ref().unwrap();
                (u64a(k, 8), u64a(v, 0) & 0x00ff_ffff_ffff_ffff, u64a(v, 8), v.clone())
            })
            .collect();
        drop(st);
        let (hl, hlen, hphys) = ext.iter().find(|e| e.0 <= pos && pos < e.0 + e.1).map(|e| (e.0, e.1, e.2)).ok_or("a write where the file has no extent")?;
        if hphys != 0 {
            return Err("not implemented: a write over a file's allocated blocks".into());
        }
        let want = (end - pos).min(hl + hlen - pos);
        let blocks = want.div_ceil(bs);
        let (a, got) = nx.alloc_data(blocks)?;
        let n = got * bs;
        blocks_alloced(nx, vol, got)?;
        phys_extent_add(nx, vol, a, got, ds.oid)?;
        // The file extents (K 0x670afbc): a data extent physically
        // continued is lengthened, its flags and crypto field kept, with no
        // key reference; a new one takes the stream's crypto (K 0x6700a08)
        // and a reference on a per-file key (K 0x670b3f4).
        let d = pos - hl;
        let prev = (d == 0).then(|| ext.iter().find(|e| hl != 0 && e.0 + e.1 == hl && e.2 != 0 && e.2 + e.1 / bs == a)).flatten();
        if let Some((pl, _, _, pv)) = prev {
            let mut nv = pv.clone();
            nv.put64(0, u64a(pv, 0) + n);
            let (mut t, mut st) = nx.fs_tree(vol)?;
            t.insert(&mut st, &fext_key(ds.oid, *pl), Some(&nv))?;
            t.remove(&mut st, &fext_key(ds.oid, hl))?;
            nx.set_fs_tree(vol, t);
        } else {
            if d != 0 {
                put_rec(nx, vol, &fext_key(ds.oid, hl), &fext_val(d, 0))?;
            }
            put_rec(nx, vol, &fext_key(ds.oid, pos), &data_fext_val(n, a, crypt))?;
            crypto_ref(nx, vol, crypt)?;
        }
        if pos + n < hl + hlen {
            put_rec(nx, vol, &fext_key(ds.oid, pos + n), &fext_val(hl + hlen - (pos + n), 0))?;
        }
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
    {
        let (sb, _) = nx.vol_sb_read(vol)?;
        if vol_crypto(sb) != 3 || u64a(sb, SB_INCOMPAT) & 0x100 != 0 {
            return Err("not implemented: a per-file key on a volume without a VEK".into());
        }
    }
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
    let mut cs = class4_crypto_state(nx, vol)?;
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

/// `rename(2)` of regular file or symbolic link `ino` (one link) from `from` to `to` in
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
    let role = u16::from_le_bytes([sb[SB_ROLE], sb[SB_ROLE + 1]]);
    if (role != 0x40 && DOC_ID_ROLES.contains(&role)) || u64a(sb, SB_INCOMPAT) & 0x100 != 0 {
        return Err("not implemented: a rename on a volume of another document-identifier role than Data's, or with a secondary tree".into());
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
    // A symbolic link's records change as a regular file's (drafts/s27/
    // re-datawrite.md 7.1).
    let fmt = u16::from_le_bytes([f[INO_MODE], f[INO_MODE + 1]]) & S_IFMT;
    if (fmt != S_IFREG && fmt != S_IFLNK) || u32::from_le_bytes(f[INO_NCHILDREN..INO_NCHILDREN + 4].try_into().unwrap()) != 1 || u32::from_le_bytes(f[0x44..0x48].try_into().unwrap()) & 0x40 != 0 {
        return Err("not implemented: renaming other than a regular file or symbolic link of one link and no UF_TRACKED".into());
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
    nx.hold_times(vol, dir, (dt, dt), false);
    Ok(RenameTimes { file: (u64a(&f, INO_MOD_TIME), fc), dir: (dt, dt) })
}

/// The in-memory times of a file written by apfs_fsync_internal (K
/// 0x66a1878, when the jobj's times-dirty bit is set with no data to push:
/// drafts/s27/re-txdata.md 4): one file-system transaction (type 4, count
/// 1), `times` its modification and change times, the inode rewritten.
pub fn write_times(nx: &mut Nx<'_>, vol: usize, ino: u64, times: (u64, u64), now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    fs_tx_enter(nx, vol)?;
    let mut v = get_rec(nx, vol, &inode_key(ino))?.ok_or("the file has no inode")?;
    v.put64(INO_MOD_TIME, times.0);
    v.put64(INO_CHANGE_TIME, times.1);
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave_last(nx, vol, false, now)
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

/// `open(O_WRONLY | O_CREAT | O_TRUNC)` of a new file `name` in `parent`,
/// one `write` of all of `data` at offset 0, and `close` (drafts/s21/
/// re-gigalocker.md D, drafts/s23/re-kernelcache.md 4): the file made as
/// [`create`] makes it by root, with its parent's group (O_TRUNC does
/// nothing to a file the open made), then [`write_first`]. The file's
/// inode number.
pub fn write_new_file(nx: &mut Nx<'_>, vol: usize, parent: u64, name: &str, mode: u16, data: &[u8], pushes: &dyn Fn(u64) -> Result<Pushes, String>, now: &mut dyn FnMut() -> u64) -> Result<u64, String> {
    if data.is_empty() {
        return Err("not implemented: an empty write".into());
    }
    let gid = u32::from_le_bytes(get_rec(nx, vol, &inode_key(parent))?.ok_or_else(|| format!("no inode {parent:#x}"))?[0x4c..0x50].try_into().unwrap());
    let ino = create(nx, vol, parent, name, mode, 0, gid, now)?.map_err(|e| format!("creating {name}: errno {e}"))?;
    write_first(nx, vol, ino, data, pushes, now)?;
    Ok(ino)
}

/// One `write` of all of `data` at offset 0 into the new, empty regular
/// file `ino`, and `close` (drafts/s21/re-gigalocker.md D, drafts/s23/
/// re-kernelcache.md 4, drafts/s27/re-datawrite.md 0.1). The write's
/// transaction (prepare_write_and_lock K 0x66a4024) makes the data stream
/// (on a VEK volume with its crypto identifier, [`Crypt`]: a per-file key's
/// crypto-state record first) and takes one of two paths
/// (K 0x66a4410..0x66a4478):
/// - direct, for a length not a block multiple and under 0x20000: the
///   blocks allocated at once (alloc_space flags 8: requests for what is
///   left until the space manager has granted it all), each piece counted,
///   its file extent (extending the one before it when physically
///   contiguous, its crypto field kept; a new one referencing a per-file
///   key's record) and block references; the size, a PREV_FSIZE field of
///   the old size 0, the write generation; the close's push writes the
///   blocks with no transaction;
/// - deferred, otherwise: one sparse extent over the allocated size, the
///   SPARSE_BYTES field and INODE_IS_SPARSE (alloc_space flags 0x10), the
///   size, PREV_FSIZE, the write generation; the blocks are allocated by
///   the block maps `pushes` gives ([`blockmap_fill`]), those after the
///   write's end carrying its times and bytes written.
/// The write's end reads the clock for the modification and change times
/// and counts the bytes written, in memory; the close's fsync removes the
/// PREV_FSIZE field in its own transaction (K 0x6766d4c) whose inode write
/// carries them. A file whose stream a truncate emptied (size and
/// allocated size 0, no extent) keeps it: the write takes the deferred
/// path into it, its bytes written counted on from the stream's.
pub fn write_first(nx: &mut Nx<'_>, vol: usize, ino: u64, data: &[u8], pushes: &dyn Fn(u64) -> Result<Pushes, String>, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    let bs = nx.l.bs;
    let n = data.len() as u64;
    if n == 0 {
        return Err("not implemented: an empty write".into());
    }
    check_write_volume(nx, vol)?;
    {
        // A volume with unwritten extents (incompat 0x80, Data's) takes the
        // same paths: neither path asks alloc_space for an unwritten extent,
        // and the deferred path's hole is made with flags 0
        // (K 0x6707ed0..0x6707f5c; drafts/s27/re-datawrite.md 1, 3).
        let sb = nx.vol_sb(vol)?;
        // The volume's low-space state (fs + 0x3ac, set below the
        // thresholds at fs + 0x3b0..0x3bc) can force the direct path; its
        // thresholds are not transcribed, so only a volume without a quota
        // is taken.
        if u64a(sb, 0x50) != 0 && (n % bs == 0 || n >= 0x20000) {
            return Err("not implemented: a deferred write on a volume with a quota (the low-space state at fs + 0x3ac)".into());
        }
    }
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    if u16::from_le_bytes([v[INO_MODE], v[INO_MODE + 1]]) & S_IFMT != S_IFREG {
        return Err("not implemented: a first write into other than an empty regular file".into());
    }
    // A stream the file already has, emptied by a truncate (drafts/
    // s27/re-populate.md 6.2): size and allocated size 0, no extent; the
    // write takes the deferred path (the direct one is chosen only where the
    // inode has no stream, or by the low-space state) and makes neither the
    // stream's reference record nor its field.
    let existing = dstream_of(&v)?;
    let mut written0 = 0u64;
    if let Some(d) = &existing {
        if d.size != 0 || d.alloced != 0 || extent_at(nx, vol, d.oid, 0)?.is_some() || xfields(&v)?.iter().any(|f| f.0 == INO_EXT_TYPE_PREV_FSIZE || f.0 == INO_EXT_TYPE_SPARSE_BYTES) {
            return Err("not implemented: a write at 0 into a stream with bytes, blocks or transient fields".into());
        }
        if u64a(nx.vol_sb(vol)?, 0x50) != 0 {
            return Err("not implemented: a write into an existing stream on a volume with a quota (the low-space state at fs + 0x3ac)".into());
        }
        written0 = u64a(&xfields(&v)?.into_iter().find(|f| f.0 == INO_EXT_TYPE_DSTREAM).unwrap().2, 0x18);
    }
    if u64a(&v, INO_INTERNAL_FLAGS) & 0x410 != 0 {
        return Err("not implemented: a first write into a file with internal flags 0x410 (K 0x66a4410)".into());
    }
    if u32::from_le_bytes(v[0x44..0x48].try_into().unwrap()) & 0x4000_0020 == 0x4000_0020 {
        return Err("not implemented: a data stream of its own identifier (bsd_flags 0x40000020, K 0x66fb37c)".into());
    }
    let crypt = file_crypt(nx, vol, &v)?;
    if existing.is_some() && crypt != Crypt::None {
        return Err("not implemented: a write into an existing stream on an encrypted volume (its crypto identifier)".into());
    }
    let blocks = n.div_ceil(bs);
    let direct = existing.is_none() && n % bs != 0 && n < 0x20000;
    // The write's transaction.
    fs_tx_enter(nx, vol)?;
    let oid = u64a(&v, 0x08);
    let mut x = xfields(&v)?;
    if existing.is_none() {
        if let Crypt::Key(f) = crypt {
            let cs = class4_crypto_state(nx, vol)?;
            put_rec(nx, vol, &(f | J_CRYPTO_STATE << 60).to_le_bytes(), &cs)?;
        }
        put_rec(nx, vol, &(oid | J_DSTREAM_ID << 60).to_le_bytes(), &1u32.to_le_bytes())?;
        let mut dsx = vec![0u8; 0x28];
        dsx.put64(0x10, crypt.id());
        x.push((INO_EXT_TYPE_DSTREAM, XF_SYSTEM_FIELD, dsx));
    }
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
                    put_rec(nx, vol, &fext_key(oid, *l), &data_fext_val(*len, *p, crypt))?;
                }
                _ => {
                    crypto_ref(nx, vol, crypt)?;
                    put_rec(nx, vol, &fext_key(oid, done * bs), &data_fext_val(got * bs, a, crypt))?;
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
            blockmap_fill(nx, vol, ino, off, &padded[off as usize..(off + len) as usize], t_w.map(|t| (t, written0 + n)), now)?;
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
        d.2.put64(0x18, written0 + n);
    }
    let mut v = with_xfields(&v, &x);
    v.put64(INO_MOD_TIME, t_w);
    v.put64(INO_CHANGE_TIME, t_w);
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave(nx, vol, now)?;
    Ok(())
}


/// `write(2)` of `data` at offset 0 into a new file whose blocks
/// [`preallocate`] already gave it (drafts/s27/re-splat.md 4.6): the write
/// ends within the allocated size, over a data extent, so no allocation
/// and no range (prepare_write_and_lock K 0x66a4024): one file-system
/// transaction with the size, a PREV_FSIZE field of the old size 0 and
/// the write generation, the inode rewritten; the write's end then reads
/// the clock for the modification and change times and counts the bytes,
/// in memory: they are returned, for the inode's next write. The data
/// reaches the blocks at the close's push ([`close_pushed`]).
pub fn write_into_preallocation(nx: &mut Nx<'_>, vol: usize, ino: u64, data: &[u8], now: &mut dyn FnMut() -> u64) -> Result<(u64, u64), String> {
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    if dstream_of(&v)?.is_some_and(|d| d.size != 0) {
        return Err("not implemented: a first write into a preallocation of a file with bytes".into());
    }
    extend_into_preallocation(nx, vol, ino, data.len() as u64, None, now)
}

/// `write(2)` of `n` bytes at the end of a regular file whose allocated
/// size already holds them (drafts/s27/re-populate.md 5.2; prepare_write_
/// and_lock K 0x66a4024): no allocation, and every block of the range in a
/// data extent, so no intention range or reservation (the range scan's
/// fs_map_file_offset_ext lookups only read); as the write extends the
/// file, one file-system transaction (K 0x66a5248, type 4): the size, a
/// PREV_FSIZE field of the old size when the inode has none (one it has of
/// at most the old size is kept, K 0x66a5a70..0x66a5aa0), the write
/// generation (K 0x66a5ae8), the inode rewritten from its in-memory object
/// (K 0x66a5b0c), which carries `held`, the times and byte count the
/// file's previous write's end left there (none for the stream's first
/// write: its record's own). The write's end then reads the clock for the
/// modification and change times and adds `n` to the bytes written, in
/// memory (K 0x66a5c80..0x66a5d7c): they are returned, for the inode's
/// next write. The bytes reach the blocks with the cluster layer's pushes
/// through the existing extents (no transaction; [`close_pushed`]).
pub fn extend_into_preallocation(nx: &mut Nx<'_>, vol: usize, ino: u64, n: u64, held: Option<(u64, u64)>, now: &mut dyn FnMut() -> u64) -> Result<(u64, u64), String> {
    check_volume(nx, vol)?;
    if u64a(nx.vol_sb(vol)?, SB_FS_FLAGS) & 1 == 0 {
        return Err("not implemented: a write into a preallocation on an encrypted volume".into());
    }
    let bs = nx.l.bs;
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    if u16::from_le_bytes([v[INO_MODE], v[INO_MODE + 1]]) & S_IFMT != S_IFREG {
        return Err(format!("{ino:#x} is not a regular file"));
    }
    let ds = dstream_of(&v)?.ok_or("not implemented: a write into a preallocation of a file with no data stream")?;
    let (off, end) = (ds.size, ds.size + n);
    if n == 0 || end > ds.alloced {
        return Err(format!("not implemented: a write of {n} bytes at {off} into an allocation of {} (the zero-length write, alloc_space)", ds.alloced));
    }
    let x0 = xfields(&v)?;
    if x0.iter().any(|f| f.0 == INO_EXT_TYPE_SPARSE_BYTES) {
        return Err("not implemented: a write into a preallocation of a sparse file".into());
    }
    if let Some(p) = x0.iter().find(|f| f.0 == INO_EXT_TYPE_PREV_FSIZE) {
        if u64a(&p.2, 0) > off {
            return Err("not implemented: a write past a PREV_FSIZE field larger than the old size".into());
        }
    }
    // The range scan: every block of [off, end) in a data extent.
    let mut pos = off / bs * bs;
    while pos < end {
        let (l, len, p) = extent_at(nx, vol, ds.oid, pos)?.ok_or("not implemented: a write into a preallocation over no extent")?;
        if p == 0 {
            return Err("not implemented: a write into a preallocation over a hole (the intention range and space reservation)".into());
        }
        pos = l + len;
    }
    let base = match held {
        Some((_, w)) => w,
        None => u64a(&x0.iter().find(|f| f.0 == INO_EXT_TYPE_DSTREAM).unwrap().2, 0x18),
    };
    fs_tx_enter(nx, vol)?;
    let mut v = in_memory_inode(nx, vol, ino)?;
    let mut x = xfields(&v)?;
    {
        let d = x.iter_mut().find(|f| f.0 == INO_EXT_TYPE_DSTREAM).unwrap();
        d.2.put64(0, end);
        if let Some((_, w)) = held {
            d.2.put64(0x18, w);
        }
    }
    if !x.iter().any(|f| f.0 == INO_EXT_TYPE_PREV_FSIZE) {
        x.push((INO_EXT_TYPE_PREV_FSIZE, 0, off.to_le_bytes().to_vec()));
    }
    if let Some((t, _)) = held {
        v.put64(INO_MOD_TIME, t);
        v.put64(INO_CHANGE_TIME, t);
    }
    let mut v = with_xfields(&v, &x);
    let wgc = u32::from_le_bytes(v[INO_WRITE_GEN..INO_WRITE_GEN + 4].try_into().unwrap());
    v.put32(INO_WRITE_GEN, wgc.wrapping_add(1));
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave_last(nx, vol, false, now)?;
    Ok((now(), base + n))
}

/// `ftruncate` of a file to its own size (apfs_truncate_locked's
/// equal-size branch, K 0x66a6e74): one file-system transaction (K
/// 0x66a6e9c), the modification and change times from one clock reading
/// (K 0x66a6eb8), the inode rewritten from its in-memory object (K
/// 0x66a6ed0), which carries `written`, the bytes the last write counted;
/// the write generation and PREV_FSIZE stay.
pub fn truncate_equal(nx: &mut Nx<'_>, vol: usize, ino: u64, written: u64, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    check_volume(nx, vol)?;
    fs_tx_enter(nx, vol)?;
    let v = in_memory_inode(nx, vol, ino)?;
    let mut x = xfields(&v)?;
    x.iter_mut().find(|f| f.0 == INO_EXT_TYPE_DSTREAM).ok_or("not implemented: an equal-size truncate of a file with no data stream")?.2.put64(0x18, written);
    let mut v = with_xfields(&v, &x);
    let t = now();
    v.put64(INO_MOD_TIME, t);
    v.put64(INO_CHANGE_TIME, t);
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave_last(nx, vol, false, now)
}

/// A truncate of regular file `ino` to `new` bytes, less than its size
/// (`open(O_TRUNC)`'s vnode_setsize or ftruncate: vnode_setattr's
/// va_data_size → apfs_vnop_setattr, which takes the inode's I/O lock
/// (`apfs_io_lock_exclusive` K 0x6767084 at K 0x668e628: jobj+0x190 the
/// thread), → apfs_truncate_locked K 0x66a6bbc's fast path, for an
/// unsealed volume and an inode neither cloned (internal 0x10) nor
/// dataless; drafts/s31 notes):
/// - `ino_shrink_size_tx` (K 0x669d444 → fs_tx_enter(1, 3)): a PREV_FSIZE
///   field of at least `new` removed (K 0x67641cc), the size, the
///   modification and change times from one clock reading (K 0x66f3750),
///   the write generation, the inode written from its in-memory object (K
///   0x66f3330 → bt_insert, K 0x66a770c); then ubc_setsize and the
///   in-memory ranges and dirty work past the new end (K 0x66ae7e8, K
///   0x675a3a4);
/// - `ino_remove_some_fexts`, inline under the I/O lock (asserted at K
///   0x66a7924): batches of one file-system transaction (fs_tx_enter(1,
///   15), K 0x66a7b80) each, which first writes the inode (K 0x66a7ba8),
///   then walks the stream's extents from the last (K 0x666a4b8, K
///   0x666a6f4), at most five: an extent ending at or before the new end
///   rounded to the block ends the walk; one wholly past it has its
///   record removed (K 0x674cf60) and its blocks' reference dropped (K
///   0x66b19c0 → K 0x66f7224) or, a hole, its bytes taken from the sparse
///   count; then the sparse bytes (K 0x66ff7c0), the allocated size (the
///   last removed extent's offset) and the inode written (K 0x66a7f60).
/// An extent straddling the new end (K 0x674cd34's split), a new size off
/// a page (the cluster layer's zero fill of its page), crypto identifiers
/// (an encrypted volume) and directory statistics are not implemented.
pub fn truncate_shrink(nx: &mut Nx<'_>, vol: usize, ino: u64, new: u64, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    const PAGE: u64 = 16 << 10;
    check_volume(nx, vol)?;
    let bs = nx.l.bs;
    {
        let sb = nx.vol_sb(vol)?;
        if u64a(sb, SB_INCOMPAT) & 0x20 != 0 {
            return Err("not implemented: a truncate on a sealed volume (apfs_truncate_locked's slow path)".into());
        }
        if u64a(sb, SB_FS_FLAGS) & 1 == 0 {
            return Err("not implemented: a shrinking truncate on an encrypted volume (the extents' crypto identifiers, rsb_unretain_id)".into());
        }
    }
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    if u16::from_le_bytes([v[INO_MODE], v[INO_MODE + 1]]) & S_IFMT != S_IFREG {
        return Err(format!("{ino:#x} is not a regular file"));
    }
    let iflags = u64a(&v, INO_INTERNAL_FLAGS);
    if iflags & (0x10 | INODE_MAINTAIN_DIR_STATS | INODE_HAS_FILE_INFO | INODE_PURGEABLE) != 0 {
        return Err(format!("not implemented: a shrinking truncate of a file with internal flags {iflags:#x}"));
    }
    if u32::from_le_bytes(v[0x44..0x48].try_into().unwrap()) & 0x4000_0000 != 0 {
        return Err("not implemented: a truncate of a dataless file".into());
    }
    let ds = dstream_of(&v)?.ok_or("a shrinking truncate of a file with no data stream")?;
    if new >= ds.size {
        return Err(format!("a shrinking truncate to {new} of a file of {} bytes", ds.size));
    }
    if new % PAGE != 0 {
        return Err("not implemented: a truncate to a size off a page (the cluster layer's zero fill, cluster_write 0x80)".into());
    }
    // ino_shrink_size_tx.
    fs_tx_enter(nx, vol)?;
    let v = in_memory_inode(nx, vol, ino)?;
    let mut x = xfields(&v)?;
    if let Some(i) = x.iter().position(|f| f.0 == INO_EXT_TYPE_PREV_FSIZE) {
        if new <= u64a(&x[i].2, 0) {
            x.remove(i);
        }
    }
    x.iter_mut().find(|f| f.0 == INO_EXT_TYPE_DSTREAM).unwrap().2.put64(0, new);
    let mut v = with_xfields(&v, &x);
    let t = now();
    v.put64(INO_MOD_TIME, t);
    v.put64(INO_CHANGE_TIME, t);
    let wgc = u32::from_le_bytes(v[INO_WRITE_GEN..INO_WRITE_GEN + 4].try_into().unwrap());
    v.put32(INO_WRITE_GEN, wgc.wrapping_add(1));
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave(nx, vol, now)?;
    // ino_remove_some_fexts.
    let end = new.div_ceil(bs) * bs;
    let last_key = fext_key(ds.oid, 0xffff_ffff_ffff_fffe);
    loop {
        let at = |nx: &mut Nx<'_>, key: &[u8]| -> Result<Option<(Vec<u8>, Vec<u8>)>, String> {
            let (t, mut st) = nx.fs_tree(vol)?;
            Ok(match t.get_le(&mut st, key)? {
                Some((k, Some(val))) if u64a(&k, 0) == (ds.oid | J_FILE_EXTENT << 60) => Some((k, val)),
                _ => None,
            })
        };
        let mut cur = at(nx, &last_key)?.ok_or("not implemented: a shrinking truncate of a stream with no extent (fexts cannot be iterated)")?;
        fs_tx_enter(nx, vol)?;
        let v = get_rec(nx, vol, &inode_key(ino))?.ok_or("the file has no inode")?;
        put_rec(nx, vol, &inode_key(ino), &v)?;
        let mut alloced = dstream_of(&v)?.unwrap().alloced;
        let mut sparse = 0i64;
        let mut done = false;
        for _ in 0..5 {
            let (k, val) = cur.clone();
            let (l, len, p) = (u64a(&k, 8), u64a(&val, 0) & 0x00ff_ffff_ffff_ffff, u64a(&val, 8));
            if l + len <= end {
                done = true;
                break;
            }
            if l < end {
                return Err("not implemented: a truncate inside an extent (K 0x674cd34's split)".into());
            }
            remove_rec(nx, vol, &k)?;
            if p == 0 {
                sparse -= len as i64;
            } else {
                deref_phys_range(nx, vol, p, len / bs)?;
            }
            alloced = l;
            match l.checked_sub(1).map(|b| fext_key(ds.oid, b)) {
                Some(prev) => match at(nx, &prev)? {
                    Some(e) => cur = e,
                    None => {
                        done = true;
                        break;
                    }
                },
                None => {
                    done = true;
                    break;
                }
            }
        }
        let v = get_rec(nx, vol, &inode_key(ino))?.ok_or("the file has no inode")?;
        let mut x = xfields(&v)?;
        let mut v = v;
        sparse_bytes(&mut v, &mut x, sparse)?;
        x.iter_mut().find(|f| f.0 == INO_EXT_TYPE_DSTREAM).unwrap().2.put64(8, alloced);
        put_rec(nx, vol, &inode_key(ino), &with_xfields(&v, &x))?;
        fs_tx_leave(nx, vol, now)?;
        if done {
            return Ok(());
        }
    }
}

/// The close of a file whose bytes `data` a write put within its data
/// extents (VNOP_CLOSE → VNOP_FSYNC(MNT_NOWAIT), drafts/s27/re-splat.md
/// 4.6): the push writes them, zeros to the block's end, through the
/// existing extents with no transaction; then PREV_FSIZE is removed in
/// its own transaction (K 0x6766d4c) with the inode as it stands.
pub fn close_pushed(nx: &mut Nx<'_>, vol: usize, ino: u64, data: &[u8], now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    let bs = nx.l.bs;
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    let ds = dstream_of(&v)?.ok_or("a close push of a file with no data stream")?;
    if ds.size != data.len() as u64 {
        return Err("a close push of other than the file's bytes".into());
    }
    let mut padded = data.to_vec();
    padded.resize(data.len().div_ceil(bs as usize) * bs as usize, 0);
    let mut off = 0u64;
    while off < padded.len() as u64 {
        let rec = {
            let (t, mut st) = nx.fs_tree(vol)?;
            t.get_le(&mut st, &fext_key(ds.oid, off))?
        };
        let (k, val) = match rec {
            Some((k, Some(val))) if u64a(&k, 0) == (ds.oid | J_FILE_EXTENT << 60) => (k, val),
            _ => return Err("a close push where the file has no extent".into()),
        };
        let (l, len, p) = (u64a(&k, 8), u64a(&val, 0) & 0x00ff_ffff_ffff_ffff, u64a(&val, 8));
        if p == 0 || u64a(&val, 0) >> 56 != 0 || off >= l + len {
            return Err("not implemented: a close push over a hole or a flagged extent".into());
        }
        let run = (l + len - off).min(padded.len() as u64 - off);
        nx.write_data(p + (off - l) / bs, &padded[off as usize..(off + run) as usize])?;
        off += run;
    }
    fs_tx_enter(nx, vol)?;
    let mut x = xfields(&v)?;
    let before = x.len();
    x.retain(|f| f.0 != INO_EXT_TYPE_PREV_FSIZE);
    if x.len() == before {
        return Err("a close with no PREV_FSIZE field to remove".into());
    }
    put_rec(nx, vol, &inode_key(ino), &with_xfields(&v, &x))?;
    fs_tx_leave_last(nx, vol, false, now)
}

/// The file extent of stream `oid` holding byte `pos`: its logical
/// offset, length and first block (0 for a hole).
pub fn extent_at(nx: &mut Nx<'_>, vol: usize, oid: u64, pos: u64) -> Result<Option<(u64, u64, u64)>, String> {
    let (t, mut st) = nx.fs_tree(vol)?;
    Ok(match t.get_le(&mut st, &fext_key(oid, pos))? {
        Some((k, Some(v))) if u64a(&k, 0) == (oid | J_FILE_EXTENT << 60) => {
            let (l, len, p) = (u64a(&k, 8), u64a(&v, 0) & 0x00ff_ffff_ffff_ffff, u64a(&v, 8));
            (pos < l + len).then_some((l, len, p))
        }
        _ => None,
    })
}

/// A file's bytes as a writer hands them to `write(2)`.
pub trait Bytes {
    fn len(&self) -> u64;
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), String>;
}

impl Bytes for Vec<u8> {
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), String> {
        let o = usize::try_from(off).map_err(|_| "an offset past the bytes")?;
        let src = self.get(o..o + buf.len()).ok_or("a read past the bytes")?;
        buf.copy_from_slice(src);
        Ok(())
    }
}

/// `grow_ahead` (K 0x6708864): the bytes past the write's end that the
/// hole grows by when the stream's allocated size `a` is past 64 KiB and
/// within the write's end `e`: a step of 16 blocks while `a` is at most 1
/// MiB, 256 to 64 MiB, 4,096 beyond, when the write's blocks past `a` fit
/// in one step (none else, or on a volume with read-only-compatible bit
/// 1).
fn grow_ahead(a: u64, e: u64, bs: u64, ro_compat: u64) -> u64 {
    if ro_compat & 2 != 0 || a <= 0xffff || a > e {
        return 0;
    }
    let g = if a > 0x10_0000 { if a > 0x400_0000 { 0x1000 } else { 0x100 } } else { 0x10 };
    let past = e.div_ceil(bs) * bs - a;
    if past <= g * bs {
        g * bs - past
    } else {
        0
    }
}

/// A new regular file `ino` of an unencrypted volume, opened for writing
/// and given its bytes `src` by a sequence of `write(2)` calls of the
/// lengths `writes` from offset 0, then closed (drafts/s27/re-splat.md 4),
/// with the cluster layer's cluster size `c` and block-map length `m`:
/// - the first write (a block multiple or 0x20000 bytes or more: the
///   deferred path, [`write_new_file`]'s) makes the data stream, its
///   sparse extent to the write's block end, SPARSE_BYTES, the size,
///   PREV_FSIZE 0 and the write generation (prepare_write_and_lock K
///   0x66a4024);
/// - every later write, the stream existing, is deferred too (K 0x66a4688:
///   only the volume's low-space state could make it direct): past the
///   allocated end, a file-system transaction whose alloc_space (flags
///   0x10, K 0x6707764) grows the hole to the write's block end, or, the
///   file 64 KiB or more and created a second or more before (K 0x66a4a70:
///   a clock reading, K 0x6737394), by [`grow_ahead`]'s step: the hole
///   extent ending there rewritten longer, or a new one after pushed data,
///   and the SPARSE_BYTES it adds; within it, a transaction with no extent
///   change (K 0x66a4b64); then the size, the write generation, the inode
///   rewritten with the times and bytes written of the last write's end;
/// - the cluster layer holds at most four clusters of `c` bytes: a write
///   reaching a fifth pushes the lowest ([`blockmap_fill`], block maps of at
///   most `m`) after its transaction; the write's end reads the clock for
///   the modification and change times and counts the bytes, in memory;
/// - the close's fsync pushes the held clusters in order (to the 16 KiB
///   page end, within the allocated size) and removes PREV_FSIZE in its
///   own transaction (K 0x6766d4c) carrying the last write's times. A
///   hole grow-ahead left past the pushed end stays, with its sparse bytes.
pub fn write_appends(nx: &mut Nx<'_>, vol: usize, ino: u64, writes: &[u64], src: &dyn Bytes, c: u64, m: u64, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    const PAGE: u64 = 16 << 10;
    let bs = nx.l.bs;
    check_write_volume(nx, vol)?;
    let total: u64 = writes.iter().sum();
    if total != src.len() || writes.iter().any(|&w| w == 0) || c == 0 || m == 0 || c % PAGE != 0 || m % bs != 0 {
        return Err("not implemented: writes that are not the file's bytes in order, an empty write, or cluster sizes not of whole pages".into());
    }
    {
        let sb = nx.vol_sb(vol)?;
        // Unwritten extents (incompat 0x80) change nothing here (drafts/s27/
        // re-datawrite.md 1, 3: holes made and extended with flags 0).
        if u64a(sb, 0x50) != 0 {
            return Err("not implemented: writes on a volume with a quota (the low-space state)".into());
        }
    }
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    if dstream_of(&v)?.is_some() || u16::from_le_bytes([v[INO_MODE], v[INO_MODE + 1]]) & S_IFMT != S_IFREG {
        return Err("not implemented: writes to a file that is not a new regular file".into());
    }
    if u64a(&v, INO_INTERNAL_FLAGS) & 0x410 != 0 || u32::from_le_bytes(v[0x44..0x48].try_into().unwrap()) & 0x4000_0020 == 0x4000_0020 {
        return Err("not implemented: writes to a file with internal flags 0x410 (K 0x66a4410) or bsd_flags 0x40000020 (K 0x66fb37c)".into());
    }
    // The stream's crypto (drafts/s27/re-datawrite.md 0.1): the first
    // write makes a per-file key's record; the appends add none.
    let crypt = file_crypt(nx, vol, &v)?;
    let first = writes[0];
    if first % bs != 0 && first < 0x20000 {
        return Err("not implemented: a first write on the direct path followed by more".into());
    }
    let created = u64a(&v, 0x10);
    let ro_compat = u64a(nx.vol_sb(vol)?, SB_RO_COMPAT);
    let oid = u64a(&v, 0x08);
    let mut s = 0u64;
    let mut a = 0u64;
    // The times and bytes written the in-memory inode holds after a write's
    // end.
    let mut finish: Option<(u64, u64)> = None;
    let mut held: std::collections::VecDeque<u64> = std::collections::VecDeque::new();
    let mut buf = vec![0u8; m as usize];
    for (k, &w) in writes.iter().enumerate() {
        let e = s + w;
        fs_tx_enter(nx, vol)?;
        let mut v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
        let mut x = xfields(&v)?;
        if k == 0 {
            if let Crypt::Key(f) = crypt {
                let cs = class4_crypto_state(nx, vol)?;
                put_rec(nx, vol, &(f | J_CRYPTO_STATE << 60).to_le_bytes(), &cs)?;
            }
            let mut dsx = vec![0u8; 0x28];
            dsx.put64(0x10, crypt.id());
            x.push((INO_EXT_TYPE_DSTREAM, XF_SYSTEM_FIELD, dsx));
            put_rec(nx, vol, &(oid | J_DSTREAM_ID << 60).to_le_bytes(), &1u32.to_le_bytes())?;
            a = e.div_ceil(bs) * bs;
            put_rec(nx, vol, &fext_key(oid, 0), &fext_val(a, 0))?;
            sparse_bytes(&mut v, &mut x, a as i64)?;
            x.push((INO_EXT_TYPE_PREV_FSIZE, 0, 0u64.to_le_bytes().to_vec()));
        } else if a < e {
            let mut target = e;
            if s >= 0x10000 && now().saturating_sub(created) >= 1_000_000_000 {
                target += grow_ahead(a, e, bs, ro_compat);
            }
            let new_a = target.div_ceil(bs) * bs;
            let last = {
                let (t, mut st) = nx.fs_tree(vol)?;
                t.get_le(&mut st, &fext_key(oid, a - 1))?
            };
            let (lk, lv) = match last {
                Some((k, Some(v))) if u64a(&k, 0) == (oid | J_FILE_EXTENT << 60) => (k, v),
                _ => return Err("a stream with no extent at its allocated end".into()),
            };
            let (l, len, p) = (u64a(&lk, 8), u64a(&lv, 0) & 0x00ff_ffff_ffff_ffff, u64a(&lv, 8));
            // A pushed data extent with the volume's key carries
            // FEXT_CRYPTO_ID_IS_TWEAK (flag byte 1).
            let flags = u64a(&lv, 0) >> 56;
            if l + len != a || !(flags == 0 || (flags == 1 && p != 0 && crypt == Crypt::Vek)) {
                return Err("not implemented: a stream whose last extent does not end at its allocated size, or one of other flags".into());
            }
            if p == 0 {
                put_rec(nx, vol, &lk, &fext_val(len + new_a - a, 0))?;
            } else {
                put_rec(nx, vol, &fext_key(oid, a), &fext_val(new_a - a, 0))?;
            }
            sparse_bytes(&mut v, &mut x, (new_a - a) as i64)?;
            a = new_a;
        }
        {
            let d = x.iter_mut().find(|f| f.0 == INO_EXT_TYPE_DSTREAM).ok_or("no data stream field")?;
            d.2.put64(0, e);
            d.2.put64(8, a);
            if let Some((_, written)) = finish {
                d.2.put64(0x18, written);
            }
        }
        let mut v = with_xfields(&v, &x);
        if let Some((t, _)) = finish {
            v.put64(INO_MOD_TIME, t);
            v.put64(INO_CHANGE_TIME, t);
        }
        let wgc = u32::from_le_bytes(v[INO_WRITE_GEN..INO_WRITE_GEN + 4].try_into().unwrap());
        v.put32(INO_WRITE_GEN, wgc.wrapping_add(1));
        put_rec(nx, vol, &inode_key(ino), &v)?;
        fs_tx_leave_last(nx, vol, false, now)?;
        // The cluster layer: a fifth cluster pushes the lowest.
        for j in s / c..=(e - 1) / c {
            if held.contains(&j) {
                continue;
            }
            if held.len() == 4 {
                let low = held.pop_front().unwrap();
                push_cluster(nx, vol, ino, low * c, (low + 1) * c, src, m, &mut buf, finish, now)?;
            }
            held.push_back(j);
        }
        finish = Some((now(), e));
        s = e;
    }
    // The close's fsync.
    let end = (s.div_ceil(PAGE) * PAGE).min(a);
    for j in held {
        push_cluster(nx, vol, ino, j * c, ((j + 1) * c).min(end), src, m, &mut buf, finish, now)?;
    }
    let (t, written) = finish.ok_or("a close with no write")?;
    fs_tx_enter(nx, vol)?;
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    let mut x = xfields(&v)?;
    x.retain(|f| f.0 != INO_EXT_TYPE_PREV_FSIZE);
    x.iter_mut().find(|f| f.0 == INO_EXT_TYPE_DSTREAM).ok_or("no data stream field")?.2.put64(0x18, written);
    let mut v = with_xfields(&v, &x);
    v.put64(INO_MOD_TIME, t);
    v.put64(INO_CHANGE_TIME, t);
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave_last(nx, vol, false, now)
}

/// One held cluster's push, [`from`, `to`) of the file: block maps of at
/// most `m` bytes, the file's bytes zero-padded past its size, each
/// rewriting the inode with the in-memory `finish` (the last write's end
/// times and bytes written) when there is one.
#[allow(clippy::too_many_arguments)]
fn push_cluster(nx: &mut Nx<'_>, vol: usize, ino: u64, from: u64, to: u64, src: &dyn Bytes, m: u64, buf: &mut [u8], finish: Option<(u64, u64)>, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    let mut off = from;
    while off < to {
        let len = m.min(to - off);
        let b = &mut buf[..len as usize];
        b.fill(0);
        let have = src.len().saturating_sub(off).min(len);
        src.read_at(off, &mut b[..have as usize])?;
        blockmap_fill(nx, vol, ino, off, b, finish, now)?;
        off += len;
    }
    Ok(())
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

/// `chmod` of `ino` to `mode` (apfs_vnop_setattr K 0x668e4a0 with only
/// va_mode active): the same mode bits (`& 0xfff`) take the fast path
/// (K 0x668f290 → K 0x668f348), which writes nothing: the in-memory
/// object's change time is read from the clock (K 0x668f35c) and marked
/// dirty (jobj + 0x98 |= 0x40000), held for the inode's next write
/// (`nx.jobj_times`); other bits take [`setattr`]'s general path.
pub fn chmod(nx: &mut Nx<'_>, vol: usize, ino: u64, mode: u16, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    chmod_through(nx, vol, ino, mode, false, now)
}

/// [`chmod`] by `fchmod` on a descriptor the caller keeps open until it
/// writes the inode again through it: the vnode stays referenced, off the
/// free list, so a full vnode table cannot recycle it meanwhile.
pub fn fchmod(nx: &mut Nx<'_>, vol: usize, ino: u64, mode: u16, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    chmod_through(nx, vol, ino, mode, true, now)
}

fn chmod_through(nx: &mut Nx<'_>, vol: usize, ino: u64, mode: u16, open: bool, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    let cur = u16::from_le_bytes([v[INO_MODE], v[INO_MODE + 1]]);
    if (cur ^ mode) & 0o7777 != 0 {
        return setattr(nx, vol, ino, SetAttr { mode: Some(mode), ..Default::default() }, now);
    }
    chmod_same(nx, vol, ino, &v, open, now);
    Ok(())
}

/// apfs_vnop_setattr's fast path for a mode alone and unchanged (K
/// 0x668f290 → K 0x668f348) on the inode whose record is `v`: the change
/// time read from the clock (K 0x668f35c) into the in-memory object, marked
/// dirty, nothing written (`nx.jobj_times` holds it for the next write).
fn chmod_same(nx: &mut Nx<'_>, vol: usize, ino: u64, v: &[u8], open: bool, now: &mut dyn FnMut() -> u64) {
    let t = now();
    let m = nx.jobj_times.get(&(vol, ino)).map_or(u64a(v, INO_MOD_TIME), |p| p.0);
    nx.hold_times(vol, ino, (m, t), open);
}

/// The inode `ino` as its in-memory object holds it, for a rewrite
/// (`update_jobj` K 0x66f5030 writes the whole object): its record with
/// the times the object holds unwritten (`nx.jobj_times`), which leave the
/// map.
fn in_memory_inode(nx: &mut Nx<'_>, vol: usize, ino: u64) -> Result<Vec<u8>, String> {
    let mut v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    if let Some((m, c)) = nx.take_times(vol, ino) {
        v.put64(INO_MOD_TIME, m);
        v.put64(INO_CHANGE_TIME, c);
    }
    Ok(v)
}

/// `chown` of `ino` (apfs_vnop_setattr's general path, K
/// 0x668f2a4..0x668f8a0): owner and group set, the change time read even
/// when they do not change, the inode rewritten from its in-memory object
/// (with any times it held unwritten).
pub fn chown(nx: &mut Nx<'_>, vol: usize, ino: u64, uid: u32, gid: u32, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    fs_tx_enter(nx, vol)?;
    let mut v = in_memory_inode(nx, vol, ino)?;
    v.put32(0x48, uid);
    v.put32(0x4c, gid);
    v.put64(INO_CHANGE_TIME, now());
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave(nx, vol, now)
}

/// The unmount of a read-write volume, `forced` (MNT_FORCE) or not:
/// without it XNU's dounmount runs ubc_umount (no dirty pages: every file
/// was closed after its writes) and VFS_SYNC(MNT_WAIT), whose vnode pass
/// ([`vnode_pass`]) writes the times the volume's inodes hold in memory,
/// and whose `tx_finish` commits the container's transaction; with it,
/// vflush's reclaims would write them (vclean's VNOP_FSYNC, or
/// apfs_vnop_reclaim's own transaction, not transcribed): refused, but for
/// inodes whose vnodes the full vnode table may already have recycled,
/// which are listed. apfs_vfsop_unmount (K 0x66c8214) stops the volume's
/// pfkur thread (K 0x66b0ffc at K 0x66c8988), which removes its temporary
/// inode ([`free_tmp_ino`]), and commits (`tx_finish(0x11)` at K
/// 0x66c8ef8, which, as the sync's, writes nothing when no transaction is
/// open: drafts/s16/re-kext-update.md 5); then, in the next transaction,
/// which stays open, the
/// kernel's `apfs_modified_by` entry (an existing one of the same name
/// moves to the front, else the entries shift and the oldest goes), the
/// clone transaction, and the unmount time. vflush reclaims the volume's
/// vnodes and the mount leaves the mount list.
pub fn unmount(nx: &mut Nx<'_>, vol: usize, forced: bool, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    if !nx.mounted.contains(&vol) {
        return Err(format!("unmounting volume slot {vol}, which is not mounted"));
    }
    if forced {
        drop_at_risk(nx, vol, "this forced unmount's vflush reclaims");
        let pending: Vec<u64> = nx.jobj_times.keys().filter(|k| k.0 == vol).map(|k| k.1).collect();
        if !pending.is_empty() {
            return Err(format!("not implemented: a forced unmount reclaiming vnodes whose in-memory times are unwritten (inodes {pending:#x?}; vclean's VNOP_FSYNC or apfs_vnop_reclaim's transaction not transcribed)"));
        }
    } else {
        vnode_pass(nx, vol, now)?;
        nx.tx_finish()?;
    }
    if let Some(ino) = nx.pfkur_tmp.remove(&vol) {
        free_tmp_ino(nx, vol, ino, now)?;
    }
    nx.tx_finish()?;
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
    nx.vnode_flush(vol);
    nx.mounted.retain(|&m| m != vol);
    Ok(())
}

/// The inodes of slot `vol` whose times are held unwritten while the
/// vnode table was full: their vnodes may have been recycled since
/// (new_vnode's reclaim of the free list's oldest vnode, or the
/// vn_laundry thread's, at times the device's scheduling decides), and the
/// recycling's vclean writes the times in a transaction of its own; else
/// `at` writes them. Which, and so in which transaction and with which
/// clock readings, the binaries do not settle: the times leave the model's
/// memory unwritten and are listed.
fn drop_at_risk(nx: &mut Nx<'_>, vol: usize, at: &str) {
    let risk: Vec<(u64, (u64, u64))> = nx.jobj_times.iter().filter(|(k, _)| k.0 == vol && nx.vnode_at_risk.contains(k)).map(|(k, t)| (k.1, *t)).collect();
    if risk.is_empty() {
        return;
    }
    for (ino, _) in &risk {
        nx.jobj_times.remove(&(vol, *ino));
        nx.vnode_at_risk.remove(&(vol, *ino));
    }
    let held: Vec<String> = risk.iter().map(|(i, t)| format!("{i:#x} ({}, {})", t.0, t.1)).collect();
    let fill = nx.vnode_fill_at.clone().unwrap_or_default();
    nx.vnode_missing.push(format!("the modification and change times {} inodes of volume slot {vol} held in memory while XNU's vnode table was full (desiredvnodes {}, the restore's vnodes reaching it at {fill}): each is written by its vnode's recycling (vclean's VNOP_FSYNC or apfs_vnop_reclaim, in a transaction of its own, at a point the run's scheduling of new_vnode and the vn_laundry thread decides, which depends on the restore ramdisk's own vnodes and the ones the model does not count) or by {at}; not written: {}", risk.len(), tx::DESIRED_VNODES, held.join(", ")));
}

/// apfs_vfsop_sync's vnode pass over slot `vol` (`vnode_iterate(mp, 0,
/// K 0x66d1748)`, K 0x66c9d80; drafts/s27/re-txdata.md 4): the mount's
/// vnode list from its head, the newest vnode first ([`Nx::vnode_list`]),
/// each vnode whose inode holds only its times unwritten (`(jobj+0x98 &
/// 0x40010) == 0x40000`) given apfs_fsync_internal's times write (K
/// 0x66a1878): one file-system transaction (type 4, count 1) rewriting the
/// inode with them, its own `fs_tx_leave`. The private directory's vnode
/// (fs+0x130) is skipped. Inodes at risk of recycling ([`drop_at_risk`])
/// are listed, not written.
fn vnode_pass(nx: &mut Nx<'_>, vol: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    drop_at_risk(nx, vol, "this vnode pass");
    let mut pending: Vec<u64> = nx.jobj_times.keys().filter(|k| k.0 == vol).map(|k| k.1).collect();
    if pending.is_empty() {
        return Ok(());
    }
    if pending.contains(&PRIV_DIR_INO) {
        return Err("not implemented: unwritten times on the private directory, whose vnode the sync pass skips".into());
    }
    let list = nx.vnode_list(vol);
    let at = |i: &u64| list.iter().position(|x| x == i);
    if pending.len() > 1 {
        if let Some(i) = pending.iter().find(|i| at(i).is_none()) {
            return Err(format!("not implemented: the vnode-list place of inode {i:#x}, whose vnode's creation the model does not see, among {} inodes with unwritten times", pending.len()));
        }
        pending.sort_by_key(|i| at(i).unwrap());
    }
    for ino in pending {
        let (m, c) = nx.take_times(vol, ino).unwrap();
        fs_tx_enter(nx, vol)?;
        let mut v = inode(nx, vol, ino)?;
        v.put64(INO_MOD_TIME, m);
        v.put64(INO_CHANGE_TIME, c);
        put_rec(nx, vol, &inode_key(ino), &v)?;
        fs_tx_leave(nx, vol, now)?;
    }
    Ok(())
}

/// `sync(2)` (X 0xfffffff0073843ec): `vfs_iterate(LK_NOWAIT, sync_callback,
/// NULL)` walks the mount list from its head, the oldest mount first, and
/// gives each read-write mount VFS_SYNC(MNT_NOWAIT): for this container's
/// volumes apfs_vfsop_sync (K 0x66c9d80), whose vnode pass ([`vnode_pass`])
/// writes held times, whose purgatory cleaner finds no deleted snapshot,
/// and whose `tx_finish` (flags 0x11 when the container's sync count, +1,
/// is a multiple of its mounted volumes, else 1: the same blocks) commits
/// the open transaction. The ramdisk's own mounts hold nothing of disk0.
pub fn sync(nx: &mut Nx<'_>, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    for vol in nx.mounted.clone() {
        vnode_pass(nx, vol, now)?;
        nx.tx_finish()?;
    }
    Ok(())
}

/// `VFS_SYNC`'s `waitfor` flags (`mount.h`): `MNT_WAIT`, `MNT_NOWAIT`,
/// `MNT_DWAIT`, `MNT_VOLUME`.
pub mod waitfor {
    pub const MNT_WAIT: u32 = 1;
    pub const MNT_NOWAIT: u32 = 2;
    pub const MNT_DWAIT: u32 = 4;
    pub const MNT_VOLUME: u32 = 8;
}

/// `VFS_SYNC(mp, waitfor)` of slot `vol`, which the container holds
/// mounted read-write: apfs_vfsop_sync (K 0x66c9d80; drafts/s27/
/// re-txdata.md 4.1). A volume mounted read-only (`apfs + 0x354`) or a
/// snapshot mount (`+ 0x380`) returns at once, and a mount being updated
/// (`MNT_UPDATE`) logs and returns: the caller's, which knows the mount.
/// Then:
///
/// - `vnode_iterate(mp, 0, K 0x66d1748)`: each vnode but a dead one's and
///   the private directory's given `apfs_fsync_internal(fs, vp, waitfor)`
///   (its data pushed, then the times its inode holds unwritten,
///   [`vnode_pass`]) and `cp_detach_ep` (K 0x66d13d4: only for an inode
///   with an encryption policy attached, jobj+0x98 bit 48);
/// - the purgatory cleaner (K 0x66cd0cc), whose thread
///   (`cleanup_snapshot_purgatory`, K 0x66cedfc) writes only for a deleted
///   snapshot;
/// - `tx_finish(nx, flags)` (K 0x66c9fe0): the open transaction closed and
///   committed, the caller waiting for its checkpoint; `flags` is 0x11 for
///   `MNT_VOLUME`, else 0x11 when the container's sync count (`nx +
///   0x1e8`, raised here) is a multiple of its mounted volumes and 1
///   otherwise, which differ only in the barrier after the superblock
///   (`tx_flush`'s 0x10 << 14, the same blocks written), and a 0x11 sync
///   clears `nx + 0x410` (`waitfor` chooses nothing else here);
/// - `ep_cache_purge_expired(apfs, 0)` (K 0x6736124): the volume's cache of
///   crypto states with encryption policies, whose expired entries'
///   inodes it updates.
///
/// The encryption-policy work (`cp_detach_ep`, the ep cache) is reached
/// only on a content-protected volume (crypto.c's `get_vol_crypto(apfs) ==
/// VOL_CPROTECTED` assertions): on a volume not `APFS_FS_UNENCRYPTED` it is
/// not implemented (AppleKeyStore's policy checks, K 0x67322b4). So are a
/// volume with snapshots (the cleaner's work on one deleted) and inodes
/// holding unwritten times, whose rewrite the kernel makes with
/// `update_jobj` (bt_update with the vnode's leaf hint, K 0x672c328) and
/// [`vnode_pass`] with this writer's insert.
pub fn vfs_sync(nx: &mut Nx<'_>, vol: usize, _waitfor: u32, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    if !nx.mounted.contains(&vol) {
        return Err(format!("VFS_SYNC of volume slot {vol}, which the container does not hold mounted read-write"));
    }
    let (sb, _) = nx.vol_sb_read(vol)?;
    let fs_flags = u64a(sb, SB_FS_FLAGS);
    if fs_flags & APFS_FS_UNENCRYPTED == 0 {
        return Err(format!("not implemented: apfs_vfsop_sync's encryption-policy work on an encrypted volume (apfs_fs_flags {fs_flags:#x}; cp_detach_ep, K 0x66d13d4, and ep_cache_purge_expired, K 0x6736124, with AppleKeyStore's policy checks)"));
    }
    let snaps = {
        let (t, _) = nx.snapmeta_tree(vol)?;
        t.root
    };
    if nx.phys_node_counts(snaps)? != (0, 0) {
        return Err(format!("not implemented: the purgatory cleaner (K 0x66cd0cc → K 0x66cedfc) of volume slot {vol}, which has snapshot records"));
    }
    let held: Vec<u64> = nx.jobj_times.keys().filter(|k| k.0 == vol).map(|k| k.1).collect();
    if !held.is_empty() {
        return Err(format!("not implemented: the vnode pass's rewrite of inodes {held:#x?} of volume slot {vol}, whose times are held unwritten (update_jobj's bt_update with the vnode's leaf hint, K 0x672c328)"));
    }
    vnode_pass(nx, vol, now)?;
    nx.tx_finish()
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
/// mode alone and unchanged takes the fast path ([`chmod_same`]: the change
/// time read into memory only); else in one file-system transaction owner and group (counted
/// even when unchanged), the mode bits, the access time (not counted), the
/// modification time, the creation time lowered to the modification time
/// when later and a time was given (K 0x668f6c4), the change time read
/// when anything counted, the inode rewritten from its in-memory object
/// (with any times it held unwritten).
pub fn setattr(nx: &mut Nx<'_>, vol: usize, ino: u64, a: SetAttr, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    check_setattr_volume(nx, vol)?;
    if a.uid.is_none() && a.gid.is_none() && a.mode.is_none() && a.mtime.is_none() && a.atime.is_none() {
        return Ok(());
    }
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    let cur = u16::from_le_bytes([v[INO_MODE], v[INO_MODE + 1]]);
    if a.uid.is_none() && a.gid.is_none() && a.mtime.is_none() && a.atime.is_none() {
        let m = a.mode.unwrap();
        if (m ^ cur) & 0o7777 == 0 {
            chmod_same(nx, vol, ino, &v, false, now);
            return Ok(());
        }
    }
    if let Some(m) = a.mode {
        if (m ^ cur) & 0o7777 != 0 && u64a(&v, 0) == ROOT_DIR_INO && name_of(&v)? == "Library" {
            return Err("not implemented: a mode change of User's /Library (EPERM unless 0755)".into());
        }
    }
    fs_tx_enter(nx, vol)?;
    let mut v = in_memory_inode(nx, vol, ino)?;
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
    }
    if (a.atime.is_some() || a.mtime.is_some()) && u64a(&v, INO_MOD_TIME) < u64a(&v, 0x10) {
        let m = u64a(&v, INO_MOD_TIME);
        v.put64(0x10, m);
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
/// and change times (one reading), the inode rewritten from its in-memory
/// object; no data stream.
pub fn truncate_same(nx: &mut Nx<'_>, vol: usize, ino: u64, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    check_setattr_volume(nx, vol)?;
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    if u16::from_le_bytes([v[INO_MODE], v[INO_MODE + 1]]) & S_IFMT != S_IFREG || dstream_of(&v)?.is_some() {
        return Err("not implemented: a truncate to 0 of other than an empty file with no data stream".into());
    }
    fs_tx_enter(nx, vol)?;
    let mut v = in_memory_inode(nx, vol, ino)?;
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
/// time read, the inode rewritten from its in-memory object.
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
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    if u32::from_le_bytes(v[0x44..0x48].try_into().unwrap()) & 0x20 != 0 || get_rec(nx, vol, &k)?.is_some() {
        return Err("not implemented: setting the decmpfs attribute of a compressed file or over an existing one".into());
    }
    fs_tx_enter(nx, vol)?;
    put_rec(nx, vol, &k, &val)?;
    let mut v = in_memory_inode(nx, vol, ino)?;
    v.put64(INO_CHANGE_TIME, now());
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave(nx, vol, now)
}

/// `XATTR_FILE_SYSTEM_OWNED`, `XATTR_DATA_EMBEDDED`.
const XATTR_FILE_SYSTEM_OWNED: u16 = 4;
const XATTR_DATA_EMBEDDED: u16 = 2;

/// The names `fs_add_xattr` makes file-system owned whatever its caller
/// asks (K 0x66f4250..0x66f4294).
const FS_OWNED_NAMES: [&str; 3] = ["com.apple.fs.symlink", "com.apple.fs.altlink", "com.apple.system.fs.speculative_telemetry"];

/// `fs_add_xattr(apfs, ino, name, value, len, flags, tx)` (K 0x66f4048) in
/// the open file-system transaction, of a value it embeds: the record
/// (`j_xattr_key_t` of the object, the name's length with its NUL and
/// the name; `j_xattr_val_t` of `flags`, file-system owned for the three
/// names it always owns, `XATTR_DATA_EMBEDDED`, the length and the value)
/// inserted in the file-system tree, nothing else of the object changed.
/// A value too large to embed (past 0xedc bytes, or a record past what a
/// node takes) goes in a data stream, an object of the secondary tree's
/// identifier range in another tree, and an attribute already there is
/// replaced: neither is implemented.
fn fs_add_xattr(nx: &mut Nx<'_>, vol: usize, ino: u64, name: &str, value: &[u8], flags: u16) -> Result<(), String> {
    if ino & 0x0fff_ffff_ffff_0000 == 0x0fff_ffff_ffff_0000 {
        return Err(format!("not implemented: fs_add_xattr on object {ino:#x}, of the secondary file-system tree (K 0x66ed638 kind 4)"));
    }
    let k = xattr_key(ino, name);
    let mut f = flags;
    if FS_OWNED_NAMES.contains(&name) {
        f |= XATTR_FILE_SYSTEM_OWNED;
    }
    let mut val = (f | XATTR_DATA_EMBEDDED).to_le_bytes().to_vec();
    val.extend_from_slice(&(value.len() as u16).to_le_bytes());
    val.extend_from_slice(value);
    if value.len() > 0xedc || k.len() + val.len() > 0xedd {
        return Err(format!("not implemented: fs_add_xattr of {name}, a value too large to embed (its data stream, K 0x66f40f8)"));
    }
    if get_rec(nx, vol, &k)?.is_some() {
        return Err(format!("not implemented: fs_add_xattr of {name} over the record inode {ino:#x} already has"));
    }
    put_rec(nx, vol, &k, &val)
}

/// `allocate_graft_jobj_range` (K 0x668747c) of a volume mounted
/// read-write (its `+0x354` clear), for the graft of image file `ino`
/// whose volume's next object identifier is `len`: a range past the
/// volume's identifier space, or one past the system identifiers
/// (0x0fffffff00000001 on), is ERANGE before anything changes; else, in a
/// file-system transaction (`fs_tx_enter(apfs, 1, 3, 0, 0)`), the volume's
/// `apfs_next_obj_id` taken as the range's first identifier and moved
/// past it, and `write_graft_file_xattrs` (K 0x6687934) adding to the
/// image file, file-system owned, the volume's UUID
/// (`com.apple.fs.graft-vol-uuid`), the range's first identifier and its
/// length, each [`fs_add_xattr`]; then `fs_tx_leave(apfs, 1, 1, 0, tx,
/// 0)`. The range's first identifier.
pub fn allocate_graft_jobj_range(nx: &mut Nx<'_>, vol: usize, ino: u64, len: u64, now: &mut dyn FnMut() -> u64) -> Result<Result<u64, i32>, String> {
    const ERANGE: i32 = 34;
    let next = u64a(nx.vol_sb_read(vol)?.0, SB_NEXT_OBJ_ID);
    match next.checked_add(len) {
        Some(end) if end < 0x0fff_ffff_0000_0001 => {}
        _ => return Ok(Err(ERANGE)),
    }
    check_volume(nx, vol)?;
    fs_tx_enter(nx, vol)?;
    let (base, uuid) = {
        let sb = nx.vol_sb(vol)?;
        let base = u64a(sb, SB_NEXT_OBJ_ID);
        sb.put64(SB_NEXT_OBJ_ID, base + len);
        (base, sb[0xf0..0x100].to_vec())
    };
    for (name, value) in [("com.apple.fs.graft-vol-uuid", uuid), ("com.apple.fs.graft-jobj-id-base", base.to_le_bytes().to_vec()), ("com.apple.fs.graft-jobj-id-len", len.to_le_bytes().to_vec())] {
        fs_add_xattr(nx, vol, ino, name, &value, XATTR_FILE_SYSTEM_OWNED)?;
    }
    fs_tx_leave(nx, vol, now)?;
    Ok(Ok(base))
}

/// The key of inode `ino`'s extended attribute `name`.
fn xattr_key(ino: u64, name: &str) -> Vec<u8> {
    let mut k = (ino | J_XATTR << 60).to_le_bytes().to_vec();
    k.extend_from_slice(&(name.len() as u16 + 1).to_le_bytes());
    k.extend_from_slice(name.as_bytes());
    k.push(0);
    k
}

/// The value of inode `ino`'s extended attribute `name` as its record
/// holds it (flags, length, then the data, or the stream's identifier and
/// `j_dstream`).
pub fn xattr_record(nx: &mut Nx<'_>, vol: usize, ino: u64, name: &str) -> Result<Option<Vec<u8>>, String> {
    get_rec(nx, vol, &xattr_key(ino, name))
}

/// The first `size` bytes of stream `oid` on unencrypted volume `vol`,
/// read through its extents.
pub fn read_stream(nx: &mut Nx<'_>, vol: usize, oid: u64, size: u64) -> Result<Vec<u8>, String> {
    let bs = nx.l.bs;
    {
        let (sb, _) = nx.vol_sb_read(vol)?;
        if u64a(sb, SB_FS_FLAGS) & 1 == 0 {
            return Err("not implemented: reading a stream of an encrypted volume".into());
        }
    }
    let mut out = vec![0u8; size as usize];
    let mut pos = 0u64;
    while pos < size {
        let (l, len, p) = extent_at(nx, vol, oid, pos)?.ok_or("a stream read past its extents")?;
        let run = (l + len - pos).min(size - pos);
        if p != 0 {
            let first = (pos - l) / bs;
            let skip = (pos - l) % bs;
            let mut b = vec![0u8; ((run + skip).div_ceil(bs) * bs) as usize];
            nx.read_data(p + first, &mut b)?;
            out[pos as usize..(pos + run) as usize].copy_from_slice(&b[skip as usize..(skip + run) as usize]);
        }
        pos += run;
    }
    Ok(out)
}

/// `setxattr(path, "com.apple.ResourceFork", data, len, pos,
/// XATTR_NOFOLLOW)` by root on regular file `ino`, not compressed, whose
/// fork is absent (`pos` 0) or `pos` bytes long (an append)
/// (apfs_vnop_setxattr K 0x6699610 → K 0x665fac0 → K 0x665d844;
/// drafts/s27/re-datawrite.md 0.2, 5):
/// - T1, a new stream (alloc_and_set_xattr K 0x665e120 with end 0): one
///   file-system transaction taking the stream's identifier X from
///   next_obj_id, its crypto by the file's class (the volume's key, or for
///   class 4 a per-file key X with its crypto-state record, K 0x66f441c),
///   the xattr record {DATA_STREAM, X, size 0, allocated 0, C, 0, 0}
///   (update_parent_xattr K 0x669d8d8 mode 2), and the file's
///   INODE_NO_RSRC_FORK cleared, the file rewritten;
/// - T2 (K 0x665e120 again, the stream existing), when the allocation
///   ends before the write's: alloc_space flags 0 from the allocated end
///   (grow-ahead when at most 16 blocks are wanted, the stream is 64 KiB or
///   more and a second has passed since its creation time 0, AS l.222-238),
///   pieces as the space manager grants them, each counted, extending the
///   data extent before it when physically contiguous (flags and crypto
///   kept, no key reference) or a new data extent keyed by X (a reference on
///   a per-file key), its block references owned by the file; the record's
///   allocated size (mode 0: no file write);
/// - the data pushed by the cluster layer through the allocated extents,
///   no transaction (the last block zero-filled past the end); then one
///   clock reading for the file's modification and change times (K
///   0x66f3750);
/// - T3: the record's size and bytes written (mode 1), the file's
///   INODE_HAS_RSRC_FORK set and the file written when it was not, its
///   write generation counted and the file written again (K 0x665e098).
/// No j_dstream_id record and no DSTREAM field for the stream.
pub fn setxattr_rsrc_fork(nx: &mut Nx<'_>, vol: usize, ino: u64, pos: u64, data: &[u8], now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    const NAME: &str = "com.apple.ResourceFork";
    const INODE_HAS_RSRC_FORK: u64 = 0x4000;
    let bs = nx.l.bs;
    check_write_volume(nx, vol)?;
    let k = xattr_key(ino, NAME);
    let f = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    if u16::from_le_bytes([f[INO_MODE], f[INO_MODE + 1]]) & S_IFMT != S_IFREG || data.is_empty() {
        return Err("not implemented: a resource fork set on other than a regular file, or an empty one".into());
    }
    if u32::from_le_bytes(f[0x44..0x48].try_into().unwrap()) & 0x20 != 0 {
        return Err("not implemented: a resource fork set on a compressed file (K 0x6684cc8)".into());
    }
    let (ro_compat, quota) = {
        let (sb, _) = nx.vol_sb_read(vol)?;
        (u64a(sb, SB_RO_COMPAT), u64a(sb, 0x50))
    };
    if quota != 0 {
        return Err("not implemented: alloc_space on a volume with a quota (the low-space state at fs + 0x3ac)".into());
    }
    let xval = |x: u64, size: u64, alloced: u64, c: u64, written: u64| -> Vec<u8> {
        let mut v = XATTR_DATA_STREAM.to_le_bytes().to_vec();
        v.extend_from_slice(&0x30u16.to_le_bytes());
        v.extend_from_slice(&x.to_le_bytes());
        for q in [size, alloced, c, written, 0] {
            v.extend_from_slice(&q.to_le_bytes());
        }
        v
    };
    let (x, crypt, mut size, mut alloced, mut written) = match get_rec(nx, vol, &k)? {
        None => {
            if pos != 0 {
                return Err("not implemented: a resource fork's first setxattr at a position past 0".into());
            }
            // T1.
            fs_tx_enter(nx, vol)?;
            let x = {
                let sb = nx.vol_sb(vol)?;
                let x = u64a(sb, SB_NEXT_OBJ_ID);
                sb.put64(SB_NEXT_OBJ_ID, x + 1);
                x
            };
            let crypt = stream_crypt(nx, vol, x, u32::from_le_bytes(f[0x3c..0x40].try_into().unwrap()), u64a(&f, INO_INTERNAL_FLAGS) & 0x8)?;
            if let Crypt::Key(id) = crypt {
                let cs = class4_crypto_state(nx, vol)?;
                put_rec(nx, vol, &(id | J_CRYPTO_STATE << 60).to_le_bytes(), &cs)?;
            }
            put_rec(nx, vol, &k, &xval(x, 0, 0, crypt.id(), 0))?;
            let mut fv = in_memory_inode(nx, vol, ino)?;
            let fl = u64a(&fv, INO_INTERNAL_FLAGS);
            if fl & INODE_NO_RSRC_FORK != 0 {
                fv.put64(INO_INTERNAL_FLAGS, fl & !INODE_NO_RSRC_FORK);
                put_rec(nx, vol, &inode_key(ino), &fv)?;
            }
            fs_tx_leave(nx, vol, now)?;
            (x, crypt, 0, 0, 0)
        }
        Some(r) => {
            if r.len() != 0x34 || u16::from_le_bytes([r[0], r[1]]) & XATTR_DATA_STREAM == 0 {
                return Err("not implemented: a resource fork set over an embedded one".into());
            }
            let c = u64a(&r, 28);
            let x = u64a(&r, 4);
            let crypt = match c {
                0 => Crypt::None,
                4 => Crypt::Vek,
                id if id == x => Crypt::Key(x),
                id => return Err(format!("a resource fork stream of crypto identifier {id:#x}")),
            };
            (x, crypt, u64a(&r, 12), u64a(&r, 20), u64a(&r, 36))
        }
    };
    if pos != size {
        return Err("not implemented: a resource fork setxattr other than at the stream's end (headOff, holes)".into());
    }
    let end = pos + data.len() as u64;
    let r_end = end.div_ceil(bs) * bs;
    // T2.
    if alloced < r_end {
        fs_tx_enter(nx, vol)?;
        let mut want = (r_end - alloced) / bs;
        if want - 1 < 16 && size >= 0x10000 && now() >= 1_000_000_000 {
            want += grow_ahead(alloced, end, bs, ro_compat) / bs;
        }
        let mut got_total = 0;
        while got_total < want {
            let (p, g) = nx.alloc_data(want - got_total)?;
            blocks_alloced(nx, vol, g)?;
            let logical = alloced + got_total * bs;
            let prev = if logical == 0 { None } else { extent_at(nx, vol, x, logical - 1)? };
            match prev {
                Some((l, len, pp)) if pp != 0 && l + len == logical && pp + len / bs == p => {
                    let mut v = get_rec(nx, vol, &fext_key(x, l))?.ok_or("an extent read back missing")?;
                    let lf = u64a(&v, 0) + g * bs;
                    v.put64(0, lf);
                    put_rec(nx, vol, &fext_key(x, l), &v)?;
                }
                _ => {
                    crypto_ref(nx, vol, crypt)?;
                    put_rec(nx, vol, &fext_key(x, logical), &data_fext_val(g * bs, p, crypt))?;
                }
            }
            phys_extent_add(nx, vol, p, g, ino)?;
            got_total += g;
        }
        alloced += want * bs;
        put_rec(nx, vol, &k, &xval(x, size, alloced, crypt.id(), written))?;
        fs_tx_leave(nx, vol, now)?;
    }
    // The push: the bytes, zeros to the last block's end, through the
    // extents.
    let mut b = data.to_vec();
    b.resize((r_end - pos) as usize, 0);
    let mut off = pos;
    while off < r_end {
        let (l, len, p) = extent_at(nx, vol, x, off)?.ok_or("a resource fork push past its extents")?;
        if p == 0 {
            return Err("a resource fork push into a hole".into());
        }
        let run = (l + len - off).min(r_end - off);
        nx.write_data(p + (off - l) / bs, &b[(off - pos) as usize..(off - pos + run) as usize])?;
        off += run;
    }
    size = end;
    written += data.len() as u64;
    let c = now();
    // T3.
    fs_tx_enter(nx, vol)?;
    put_rec(nx, vol, &k, &xval(x, size, alloced, crypt.id(), written))?;
    let mut fv = in_memory_inode(nx, vol, ino)?;
    fv.put64(INO_MOD_TIME, c);
    fv.put64(INO_CHANGE_TIME, c);
    let fl = u64a(&fv, INO_INTERNAL_FLAGS);
    if fl & INODE_HAS_RSRC_FORK == 0 {
        fv.put64(INO_INTERNAL_FLAGS, fl | INODE_HAS_RSRC_FORK);
        put_rec(nx, vol, &inode_key(ino), &fv)?;
    }
    let wgc = u32::from_le_bytes(fv[INO_WRITE_GEN..INO_WRITE_GEN + 4].try_into().unwrap());
    fv.put32(INO_WRITE_GEN, wgc.wrapping_add(1));
    put_rec(nx, vol, &inode_key(ino), &fv)?;
    fs_tx_leave(nx, vol, now)
}

/// FSIOC_CAS_BSDFLAGS from `expected` to `new` (handle_cas_bsdflags K
/// 0x66e0088; drafts/s23/re-user-copy.md 2.7): setting UF_COMPRESSED on a
/// file with a valid decmpfs attribute first truncates it to its (equal)
/// size; then, the flags being `expected`, in one file-system transaction
/// the flags set, the change time read, and for a regular file becoming
/// compressed the decmpfs header's uncompressed size in j_inode_val +0x54
/// with INODE_HAS_UNCOMPRESSED_SIZE (0x40000), the inode rewritten from
/// its in-memory object (any times it held unwritten with it).
pub fn cas_bsdflags(nx: &mut Nx<'_>, vol: usize, ino: u64, expected: u32, new: u32, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    check_setattr_volume(nx, vol)?;
    get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    let compressing = new & 0x20 != 0 && expected & 0x20 == 0;
    let mut usize_ = 0;
    if compressing {
        let mut k = (ino | J_XATTR << 60).to_le_bytes().to_vec();
        k.extend_from_slice(&18u16.to_le_bytes());
        k.extend_from_slice(b"com.apple.decmpfs\0");
        let x = get_rec(nx, vol, &k)?.ok_or("not implemented: UF_COMPRESSED on a file without a decmpfs attribute")?;
        let d = &x[4..];
        // Type 9 (the data in the header) and type 4 (in the resource fork)
        // take the same steps (drafts/s27/re-bomcopy.md 4.5).
        let ty = if d.len() >= 8 { u32::from_le_bytes(d[4..8].try_into().unwrap()) } else { 0 };
        if x[0..2] != 2u16.to_le_bytes() || d.len() < 16 || &d[0..4] != b"fpmc" || (ty != 9 && ty != 4) {
            return Err("not implemented: UF_COMPRESSED with a decmpfs attribute other than an embedded type 9 or 4".into());
        }
        usize_ = u64a(d, 8);
        truncate_same(nx, vol, ino, now)?;
    }
    let flags = u32::from_le_bytes(get_rec(nx, vol, &inode_key(ino))?.ok_or("no inode")?[0x44..0x48].try_into().unwrap());
    if flags & 0x3fff_ffff != expected {
        return Err("not implemented: a flags compare-and-swap that does not match".into());
    }
    if (flags ^ new) & !0x20 & 0x3fff_ffff != 0 {
        return Err("not implemented: changing BSD flags other than UF_COMPRESSED".into());
    }
    fs_tx_enter(nx, vol)?;
    let mut v = in_memory_inode(nx, vol, ino)?;
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
    if let Some((m, c)) = nx.take_times(vol, ino) {
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

/// BSD file flags (`bsd/sys/stat.h`).
pub mod bsd_flags {
    pub const UF_SETTABLE: u32 = 0x0000_ffff;
    pub const UF_IMMUTABLE: u32 = 0x0000_0002;
    pub const UF_APPEND: u32 = 0x0000_0004;
    pub const UF_COMPRESSED: u32 = 0x0000_0020;
    pub const UF_TRACKED: u32 = 0x0000_0040;
    pub const SF_SUPPORTED: u32 = 0x009f_0000;
    pub const SF_SYNTHETIC: u32 = 0xc000_0000;
    pub const SF_IMMUTABLE: u32 = 0x0002_0000;
    pub const SF_APPEND: u32 = 0x0004_0000;
    pub const SF_FIRMLINK: u32 = 0x0080_0000;
}

/// `INO_EXT_TYPE_DOCUMENT_ID`.
const INO_EXT_TYPE_DOCUMENT_ID: u8 = 3;

/// `chflags(path, flags)` by root of `ino`, the object the path names
/// (xnu-10063 vfs_syscalls.c chflags → chflags1 → chflags0;
/// drafts/s27/re-mountpoints.md 3), with `securelevel` the kernel's (`None`:
/// not known, refused where the answer needs it):
/// - mac_vnode_check_setflags: the MAC policies taken to allow it, as for
///   the restore's other calls (re-mountpoints.md UNSETTLED 4);
/// - vnode_authattr (vfs_subr.c:10822): SF_SYNTHETIC cleared from the new
///   and the old flags; for root no flag change is illegal (UF_SETTABLE |
///   SF_SETTABLE is every bit left); a change asks KAUTH_VNODE_WRITE_SECURITY
///   | KAUTH_VNODE_NOIMMUTABLE, which vnode_authorize grants root on a
///   read-write mount but for vnode_immutable's ignore case (vfs_subr.c:8789):
///   above securelevel 0 an old SF_IMMUTABLE or SF_APPEND is EPERM;
///   unchanged flags authorize nothing and go on;
/// - vnode_setattr (kpi_vfs.c:2940): the flags masked to SF_SUPPORTED |
///   UF_SETTABLE, then apfs_vnop_setattr (K 0x668e4a0) with va_flags alone:
///   decmpfs_update_attributes and the UF_COMPRESSED probe act only on a
///   UF_COMPRESSED change (not implemented: compression and decompression);
///   the general path (K 0x668f2a4) refuses SF_FIRMLINK newly set with
///   EPERM before any transaction (K 0x668f2b8), has purgeable bookkeeping
///   for an INODE_IS_PURGEABLE object (not implemented); then one
///   file-system transaction (`fs_tx_enter(4, 1)` K 0x668f414) in which
///   apfs_set_bsd_flags (K 0x66a96b4) keeps a stored SF_FIRMLINK, does the
///   document-identifier work a UF_TRACKED change asks (assigning an
///   identifier to an object without one, or removing one: not implemented)
///   and stores the old synthetic bits with the new low thirty
///   (K 0x66a9808); the change time read (K 0x668f858), the inode rewritten
///   from its in-memory object (update_jobj K 0x668f894), `fs_tx_leave`
///   (K 0x668f8bc). The flags are written even when unchanged, and
///   va_flags is marked supported (K 0x668f530), so no ENOTSUP.
///
/// `Ok(Err(errno))` is the call's own error.
pub fn chflags(nx: &mut Nx<'_>, vol: usize, ino: u64, flags: u32, securelevel: Option<i32>, now: &mut dyn FnMut() -> u64) -> Result<Result<(), i32>, String> {
    use bsd_flags::*;
    const EPERM: i32 = 1;
    check_setattr_volume(nx, vol)?;
    let v = get_rec(nx, vol, &inode_key(ino))?.ok_or_else(|| format!("no inode {ino:#x}"))?;
    let old = u32::from_le_bytes(v[0x44..0x48].try_into().unwrap());
    // vnode_authattr and vnode_authorize.
    let new = flags & !SF_SYNTHETIC;
    if new ^ (old & !SF_SYNTHETIC) != 0 && old & (SF_IMMUTABLE | SF_APPEND) != 0 {
        match securelevel {
            None => return Err(format!("not implemented: a chflags of {ino:#x}, whose flags {old:#x} hold SF_IMMUTABLE or SF_APPEND, at an unknown securelevel (vnode_immutable's ignore case)")),
            Some(s) if s > 0 => return Ok(Err(EPERM)),
            Some(_) => {}
        }
    }
    // vnode_setattr.
    let new = new & (SF_SUPPORTED | UF_SETTABLE);
    // apfs_vnop_setattr.
    if (new ^ old) & UF_COMPRESSED != 0 {
        return Err(format!("not implemented: a chflags of {ino:#x} changing UF_COMPRESSED (decmpfs_update_attributes, apfs_vnop_setattr's compression probe K 0x668e584, apfs_set_bsd_flags' decompression K 0x66a9850)"));
    }
    if new & SF_FIRMLINK != 0 && old & SF_FIRMLINK == 0 {
        return Ok(Err(EPERM));
    }
    if u64a(&v, INO_INTERNAL_FLAGS) & INODE_PURGEABLE != 0 {
        return Err(format!("not implemented: a setattr of the purgeable object {ino:#x} (K 0x668f2dc's purgeable bookkeeping)"));
    }
    let doc_id = xfields(&v)?.into_iter().find(|f| f.0 == INO_EXT_TYPE_DOCUMENT_ID).map_or(0, |f| f.2.get(..4).map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap())));
    if new & UF_TRACKED != 0 && old & UF_TRACKED == 0 && doc_id == 0 {
        return Err(format!("not implemented: UF_TRACKED set on {ino:#x}, which has no document identifier (the assignment K 0x6718530)"));
    }
    if new & UF_TRACKED == 0 && old & UF_TRACKED != 0 && doc_id != 0 {
        return Err(format!("not implemented: UF_TRACKED cleared on {ino:#x}, which has document identifier {doc_id} (the removal K 0x66fb9b0)"));
    }
    fs_tx_enter(nx, vol)?;
    let mut v = in_memory_inode(nx, vol, ino)?;
    let new = if new & SF_FIRMLINK == 0 && old & SF_FIRMLINK != 0 { new | SF_FIRMLINK } else { new };
    v.put32(0x44, (old & 0xc000_0000) | (new & 0x3fff_ffff));
    v.put64(INO_CHANGE_TIME, now());
    put_rec(nx, vol, &inode_key(ino), &v)?;
    fs_tx_leave(nx, vol, now)?;
    Ok(Ok(()))
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
    let found = {
        let (t, mut st): (Tree, _) = nx.fs_tree(vol)?;
        t.get(&mut st, &drec_key(parent, name))?.map(|v| u64a(&v, 0))
    };
    // VNOP_LOOKUP's hit: the inode's vnode (made unless it has one).
    if let Some(ino) = found {
        nx.vnode_get(vol, ino, &|| format!("the lookup of {name} (inode {ino:#x}) on volume slot {vol}"));
    }
    Ok(found)
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
            deref_phys_range(nx, vol, phys, len / bs)?;
        }
        alloced = Some(logical);
        count += 1;
    }
    if let Some(a) = alloced {
        rewrite(nx, a)?;
    }
    fs_tx_leave_nested(nx, vol, now)
}

/// The reference of `n` blocks at `phys` dropped (`apfs_update_phys_range`
/// K 0x66f61b4 with delta -1, through K 0x66f7224 or the unlink's
/// callback): an exact extent-reference record of one reference removed
/// and its blocks freed (`spaceman_free`, the volume's counts); part of a
/// record or a shared one is not implemented.
fn deref_phys_range(nx: &mut Nx<'_>, vol: usize, phys: u64, n: u64) -> Result<(), String> {
    let key = (phys | J_EXTENT << 60).to_le_bytes().to_vec();
    let (mut t, mut st) = nx.extentref_tree(vol)?;
    let pv = t.get(&mut st, &key)?.ok_or("not implemented: freeing an extent the extent-reference tree has no exact record of")?;
    if u64a(&pv, 0) & OBJ_MASK != n || i32::from_le_bytes(pv[16..20].try_into().unwrap()) != 1 {
        return Err("not implemented: freeing part of a referenced extent, or a shared one".into());
    }
    t.remove(&mut st, &key)?;
    nx.set_extentref_tree(vol, t)?;
    nx.free_data(vol, phys, n)
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
    fs_tx_leave_last(nx, vol, closing, now)?;
    // The unlinked file's last release: VNOP_INACTIVE recycles its vnode.
    nx.vnode_gone(vol, ino);
    Ok(())
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
    fs_tx_leave_last(nx, vol, false, now)?;
    nx.vnode_gone(vol, ino);
    Ok(())
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
    removefile_moved(nx, vol, var, now)
}

/// fixup_var's second removal phase on System (volume `vol`, its
/// /private/var directory `var`): `removefile(REMOVEFILE_RECURSIVE)` of
/// each moved tree in the list's order (fts, physical, no comparator), its
/// directories removed after their contents; a tree not there is skipped.
pub fn removefile_moved(nx: &mut Nx<'_>, vol: usize, var: u64, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    const DT_DIR: u16 = 4;
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
