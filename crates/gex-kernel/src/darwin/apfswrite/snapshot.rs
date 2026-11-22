//! The kernel's snapshot of a volume (`fs_snapshot_create`, XNU
//! `snapshot_create` → `vn_create` in the snapshot directory →
//! `apfs_snap_vnop_create` K 0x6666d94 → `clone_fs` K 0x66691c0; the APFS
//! kext 2236.140.6), as create_system_snapshot makes the System volume's
//! update snapshot: one transaction, committed and waited for:
//!
//! - a physical copy of the volume superblock (the snapshot's), its object
//!   map, snapshot tree, extent-reference tree and revert fields cleared;
//! - the snapshot's metadata and name records in the snapshot tree;
//! - a new, empty extent-reference tree for the live volume (the old one
//!   is the snapshot's);
//! - a sealed volume's file extent tree copied node for node, pre-order
//!   (the old one is the snapshot's);
//! - the volume's object map copied, given its snapshot tree and the
//!   transaction as its most recent snapshot;
//! - the volume's `snap_meta_ext` object;
//! - the superblock's snapshot count, trees, next object identifier and
//!   last modification time.
//!
//! Its clock readings (the snapshot's creation time, then the volume's
//! last modification time) are the caller's; the `snap_meta_ext`'s random
//! UUID is [`SNAP_UUID_STAND_IN`]'s.

use super::btree::Store;
use super::node::{Info, Node, Shape};
use super::tx::Nx;
use super::Put;
use crate::darwin::apfsread::otype;

/// The `snap_meta_ext`'s UUID, `uuid_generate` (K 0x6768f14 →
/// `uuid_generate_random`) of the device's run.
pub const SNAP_UUID_STAND_IN: &str = "the System volume's update snapshot's snap_meta_ext UUID (uuid_generate_random in clone_fs, K 0x6768f14) (stand-in 00000000-0000-4000-8000-000000000006; measure the System volume superblock's snap_meta_ext object on the device)";
const SNAP_UUID: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 6];

const OBJ_MASK: u64 = 0x0fff_ffff_ffff_ffff;
/// `j_obj_types`: `APFS_TYPE_SNAP_METADATA`, `APFS_TYPE_SNAP_NAME`.
const J_SNAP_METADATA: u64 = 1;
const J_SNAP_NAME: u64 = 11;
/// `OBJECT_TYPE_SNAP_META_EXT`.
const OBJECT_TYPE_SNAP_META_EXT: u32 = 0x1d;
const BLOCKREFTREE: u32 = 0x0f;
const EINVAL: i32 = 22;
const EEXIST: i32 = 17;
const EPERM: i32 = 1;
const ENOTSUP: i32 = 45;
const ENAMETOOLONG: i32 = 63;

fn u64a(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn u32a(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// `fs_snapshot_create(fd of the volume's root, name, 0)` on volume `vol`
/// by a process with `com.apple.private.vfs.snapshot` and
/// `com.apple.private.apfs.create-sealed-snapshot` (restored_external),
/// the volume mounted read-only or not: `apfs_snap_vnop_create`'s checks
/// in order, then [`clone_fs`]. The snapshot's transaction, or the errno.
pub fn fs_snapshot_create(nx: &mut Nx<'_>, vol: usize, name: &str, now: &mut dyn FnMut() -> u64) -> Result<Result<u64, i32>, String> {
    // XNU snapshot_create: no "/" and not "." or "..".
    if name.contains('/') || name == "." || name == ".." || name.is_empty() {
        return Ok(Err(EINVAL));
    }
    let (sb, _) = nx.vol_sb_read(vol)?;
    let sealed = u64a(sb, 0x38) & 0x20 != 0;
    // A sealed volume: the caller's create-sealed-snapshot entitlement
    // (K 0x6668f94) lets it on; a read-only mount of a sealed volume is
    // allowed.
    if !sealed {
        return Err("not implemented: a snapshot of a volume that is not sealed (the read-only mount's refusal, K 0x66812b4)".into());
    }
    if u64a(sb, 0xa0) != 0 {
        return Ok(Err(ENOTSUP));
    }
    // K 0x665254c: the names APFS keeps for itself.
    if name.starts_with("com.apple.apfs.snapxid.") || name.starts_with("com.apple.apfs.purgatory.") {
        return Ok(Err(EPERM));
    }
    let role = u16::from_le_bytes([sb[0x3c4], sb[0x3c5]]);
    if [0x8u16, 0x10, 0x100].contains(&role) {
        return Ok(Err(ENOTSUP));
    }
    // An existing snapshot of that name (K 0x6651eb8) is EEXIST.
    {
        let (t, mut st) = nx.snapmeta_tree(vol)?;
        if t.get(&mut st, &name_key(name))?.is_some() {
            return Ok(Err(EEXIST));
        }
    }
    // K 0x66b1d44: no dirty data on a volume mounted read-only.
    clone_fs(nx, vol, name, now)
}

/// A `j_snap_name_key_t`: `~0` with the name kind, the name's length
/// with its NUL, the name and NUL.
fn name_key(name: &str) -> Vec<u8> {
    let mut k = (OBJ_MASK | J_SNAP_NAME << 60).to_le_bytes().to_vec();
    k.extend_from_slice(&((name.len() + 1) as u16).to_le_bytes());
    k.extend_from_slice(name.as_bytes());
    k.push(0);
    k
}

/// `clone_fs` (K 0x66691c0) of volume `vol` as snapshot `name`.
fn clone_fs(nx: &mut Nx<'_>, vol: usize, name: &str, now: &mut dyn FnMut() -> u64) -> Result<Result<u64, i32>, String> {
    let bs = nx.block_size();
    let name_len = name.len() + 1;
    if name_len > 0x100 {
        return Ok(Err(ENAMETOOLONG));
    }
    // tx_finish(nx, 1): whatever is open committed and waited for; then
    // fs_tx_enter(apfs, 1, 0x67, reserve) (K 0x66fbf98: the superblock's
    // obj_modify only reserves).
    nx.tx_finish()?;
    nx.enter()?;
    let n = nx.xid;
    let vsb = nx.vol_sb_read(vol)?.0.to_vec();

    // (a) The snapshot's superblock (K 0x6741dbc): a physical object of
    // the volume's descriptor (OBJECT_TYPE_FS), a block of the metadata
    // class now, no owning volume; the live superblock's bytes past the
    // header.
    let mut c = vec![0u8; bs as usize];
    c[0x20..].copy_from_slice(&vsb[0x20..bs as usize]);
    let inc = u64a(&c, 0x38);
    c.put64(0x38, inc & !0x10);
    for o in [0x80usize, 0x98, 0x90, 0xa8, 0xa0] {
        c.put64(o, 0);
    }
    c.put64(0x420, n);
    let sblock = nx.phys_new(c, otype::PHYSICAL | otype::FS, 0, 1)?;

    // (b) The snapshot's record: its creation time, the next object
    // identifier taken as its inode number.
    let t1 = now();
    let inum = {
        let sb = nx.vol_sb(vol)?;
        let i = u64a(sb, 0xb0);
        sb.put64(0xb0, i + 1);
        i
    };
    let (er_oid, er_type) = (u64a(&vsb, 0x90), u32a(&vsb, 0x78));

    // (c) fs_insert_snapshot_metadata (K 0x66515e8): the metadata record,
    // then the name record (K 0x66efc60 cases 1 and 0xb).
    {
        let mut mv = er_oid.to_le_bytes().to_vec();
        for x in [sblock, t1, t1, inum] {
            mv.extend_from_slice(&x.to_le_bytes());
        }
        mv.extend_from_slice(&er_type.to_le_bytes());
        mv.extend_from_slice(&0u32.to_le_bytes());
        mv.extend_from_slice(&(name_len as u16).to_le_bytes());
        mv.extend_from_slice(name.as_bytes());
        mv.push(0);
        let (mut t, mut st) = nx.snapmeta_tree(vol)?;
        t.insert(&mut st, &(n & OBJ_MASK | J_SNAP_METADATA << 60).to_le_bytes(), Some(&mv))?;
        t.insert(&mut st, &name_key(name), Some(&n.to_le_bytes()))?;
        nx.set_snapmeta_tree(vol, t)?;
    }

    // (d) create_empty_extentref_tree (K 0x6652ab8): the live volume's new
    // extent-reference tree, physical, flags 0x42.
    if er_type & 0xffff != otype::BTREE {
        return Ok(Err(EINVAL));
    }
    let er_shape = Shape { bt_flags: 0x52, node_size: bs as usize, key_size: 0, val_size: 0, hash_size: 0 };
    let e0 = super::btree::Tree::create(&mut nx.phys_store(BLOCKREFTREE, 1, Some(vol)), er_shape, super::btree::cmp_jobj_hashed)?;

    // (e) A sealed volume's file extent tree copied (K 0x668597c → K
    // 0x6730194 → btree_node_copy K 0x672b100, deep).
    let ftype = u32a(&vsb, 0x410);
    if ftype & 0xffff != otype::BTREE {
        return Ok(Err(EINVAL));
    }
    if u64a(&vsb, 0x38) & 0x40 != 0 {
        return Err("not implemented: copying the pfkur tree into a snapshot".into());
    }
    let froot = u64a(&vsb, 0x408);
    let fshape = Shape { bt_flags: 0x12, node_size: bs as usize, key_size: 16, val_size: 16, hash_size: 0 };
    let e8 = node_copy(nx, vol, &fshape, froot)?;

    // (f) The volume's object map (K 0x6748cc4): its snapshot, in a
    // tx_enter joining the transaction and a tx_leave(4) marking it
    // closing.
    {
        let om = u64a(&vsb, 0x80);
        let ob = nx.phys_read(om)?;
        if u32a(&ob, 0x20) & 1 != 0 {
            return Err("the volume's object map is manually managed".into());
        }
    }
    nx.enter()?;
    if let Err(e) = nx.omap_snapshot_create(vol)? {
        return Err(format!("not implemented: unwinding a snapshot whose object map's snapshot failed (errno {e}, K 0x668579c)"));
    }

    // (g) The snap_meta_ext (K 0x6651468): a virtual object of the volume,
    // made when the superblock names none.
    if u64a(&vsb, 0x3e8) != 0 {
        return Err("not implemented: updating an existing snap_meta_ext object".into());
    }
    let mut x = vec![0u8; bs as usize];
    x.put32(24, OBJECT_TYPE_SNAP_META_EXT);
    x.put32(0x20, 1);
    x.put64(0x28, n);
    x[0x30..0x40].copy_from_slice(&SNAP_UUID);
    let ext = nx.virt_new(super::tx::Owner::Volume(vol), x);

    // (h) The superblock, then fs_tx_leave_ext(…, 5) (K 0x66fc5f4): its
    // last modification time, a forced close waited for.
    let t2 = now();
    {
        let sb = nx.vol_sb(vol)?;
        sb.put64(0x3e8, ext);
        let ns = u64a(sb, 0xd8);
        sb.put64(0xd8, ns + 1);
        sb.put64(0x418, 0);
        sb.put64(0x408, e8);
        sb.put64(0x90, e0.root);
        sb.put64(0x100, t2);
        sb.put64(0x420, n);
    }
    nx.set_extentref_tree(vol, e0)?;
    nx.leave(5)?;
    Ok(Ok(n))
}

/// `btree_node_copy` (K 0x672b100) of node `id` of a physical tree of
/// `shape` into a new node (`node_create` K 0x672b558: a block now, the
/// node's level and flags but the free-list bits, counted in the volume's
/// blocks): a leaf's bytes past the header copied; an index node made
/// first, then each child copied in turn and its entry appended under the
/// old key. The copy's address.
fn node_copy(nx: &mut Nx<'_>, vol: usize, shape: &Shape, id: u64) -> Result<u64, String> {
    let sub = otype::FEXT_TREE;
    let n = nx.phys_store(sub, 1, Some(vol)).get(id)?;
    let mut nb = Node::format(shape, n.flags() & 0x1b, n.level());
    if n.is_leaf() {
        nb.b[0x20..].copy_from_slice(&n.b[0x20..]);
        return nx.phys_store(sub, 1, Some(vol)).create(nb);
    }
    if n.is_root() {
        Info::read(&n.b).write(&mut nb.b);
    }
    let new = nx.phys_store(sub, 1, Some(vol)).create(nb)?;
    for i in 0..n.nkeys() {
        let c = node_copy(nx, vol, shape, n.child(shape, i))?;
        let mut st = nx.phys_store(sub, 1, Some(vol));
        let mut p = st.get(new)?;
        p.insert_at(shape, i, Some(n.key(shape, i)), Some(&c.to_le_bytes()), false).map_err(|e| format!("btree_node_insert_internal failed: {e}"))?;
        st.put(new, p)?;
    }
    Ok(new)
}
