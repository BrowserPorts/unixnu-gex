//! `apfs_sealvolume -R /mnt5/mtree_remap.xml -I /mnt5/root_hash -u
//! /mnt5/manifest_and_db/digest.db -d -v <System>`, the erase restore's
//! seal of the System volume (the ramdisk's binary, APFS 2236.140.6;
//! addresses S: are its own), on the container the kernel handed over:
//!
//! - the library's `nx_mount` (its reaper finding nothing: the kernel's ran
//!   to its end), the volume's `apfs_mount` (no write: its clone epoch is
//!   current, its private directory empty, it is not sealed);
//! - one transaction, opened by main's `tx_enter` (S:0x100006c84) and held
//!   to the end: the temporary tree of the remapped records (virtual, flags
//!   0x42, [`super::seal::remap`]), the integrity object, the file extent
//!   tree (physical, its root a block at once), "tree4" (an empty virtual
//!   u64 tree written at once, `obj_write`), the sealed tree (virtual,
//!   headerless, its nodes in creation order, [`super::seal::Builder`]),
//!   the file extents into the file extent tree, the overallocated
//!   ranges dereferenced (`dereference_phys_range`), the root hash into
//!   the integrity object, tree4 and the temporary tree to the reaper, the
//!   superblock's fields, `apfs_modified_by`, the unmount and modification
//!   time, the predefined UUID's byte 14 raised, the old tree to the
//!   reaper; main's `tx_leave` commits it when `tx_leave`'s rules close it;
//! - `nx_reaper_wait` for the three trees, `tx_finish(0x11)`, the unmount
//!   (block 0, cleanly unmounted).
//!
//! The seal fails, as the binary does, when the computed root hash is not
//! the signed one. Its two clock readings (the `apfs_modified_by` entry's
//! time, then the unmount and last-modification time) are the caller's.

use super::btree::{self, Tree};
use super::node::Shape;
use super::seal::{self, Builder, SEALED_BT_FLAGS};
use super::tx::{cmp_u64, Mode, Nx, Owner};
use super::Put;
use crate::darwin::apfsread::otype;

/// What apfs_sealvolume calls itself in `apfs_modified_by` ("%s (%s)").
pub const SEAL_ID: &str = "apfs_sealvolume (2236.140.6)";

const OBJ_MASK: u64 = 0x0fff_ffff_ffff_ffff;
const FSTREE: u32 = 0x0e;
/// `j_obj_types`' `APFS_TYPE_EXTENT`.
const J_EXTENT: u64 = 2;
/// The private directory's inode number (`PRIV_DIR_INO_NUM`), the
/// purgatory `fs_get_purgatory_inode` finds.
const PRIV_DIR_INO: u64 = 3;
const ROOT_INO: u64 = 2;

fn u64a(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn u32a(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// The seal's inputs, as restored_external hands them over.
pub struct SealInputs<'i> {
    /// `/mnt5/root_hash`: the host's SystemImageRootHash Image4 file.
    pub root_hash: &'i [u8],
    /// The canonical metadata archive's `digest.db` (`-u`).
    pub digest_db: &'i [u8],
    /// Its `mtree.txt`, which `mtree -m` makes the remap dictionary of.
    pub mtree_txt: &'i [u8],
}

/// What the seal made.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SealStats {
    pub records: usize,
    pub temp_nodes: u64,
    pub sealed_records: usize,
    pub sealed_nodes: usize,
    pub fext_records: usize,
    pub ranges: usize,
    pub root_hash: [u8; 32],
    /// The transaction the seal committed in.
    pub xid: u64,
}

/// apfs_sealvolume on volume `vol` of the container `nx` holds (unmounted
/// by the kernel; mounted here as the tool's library mounts it, on a
/// device reporting `DK_FEATURE_BARRIER` or not), with `now` its two clock
/// readings.
pub fn seal_volume(nx: &mut Nx<'_>, vol: usize, inputs: &SealInputs<'_>, barrier: bool, now: &mut dyn FnMut() -> u64) -> Result<SealStats, String> {
    let bs = nx.block_size();
    let owner = Owner::Volume(vol);
    // -I (asv_extract_hash_blob, S:0x10000692c) and -u (dbopen, S:0x100006568).
    let [h4, _, _] = seal::root_hashes(inputs.root_hash)?;
    let digests = seal::read_digests(inputs.digest_db)?;

    // nx_mount (S:0x1000541a8), its reaper run when it holds work.
    nx.set_barrier(barrier);
    nx.remount(Mode::Userspace)?;
    nx.reaper_run()?;
    let fs_oid = nx.vol_oid(vol).ok_or("no System volume")?;
    // apfs_mount (S:0x100045cf0 → S:0x100045274) and main's checks
    // (S:0x100006868..0x100006b30).
    {
        let (sb, _) = nx.vol_sb_read(vol)?;
        if u64a(sb, 0x108) & 1 == 0 {
            return Err("Sealing of encrypted volumes is not supported".into());
        }
        if u64a(sb, 0x3d8) == 0 || u64a(sb, 0x3e0) != u64a(sb, 0x140 + 0x28) {
            return Err("not implemented: the volume's clone epoch written at apfs_sealvolume's mount (set_cloneinfo_id_epoch)".into());
        }
        if u32a(sb, 0x74) != otype::BTREE {
            return Err(format!("the volume's file-system tree is of type {:#x}, not a virtual B-tree", u32a(sb, 0x74)));
        }
        if u64a(sb, 0x408) != 0 || u64a(sb, 0x38) & 0x20 != 0 {
            return Err("not implemented: sealing a volume that is already sealed (its old file extent tree and integrity object)".into());
        }
    }
    // asv_empty_purgatory (S:0x1000150bc): a transaction only for a
    // purgatory with children.
    let pv = super::fsops::inode(nx, vol, PRIV_DIR_INO)?;
    if i32::from_le_bytes(pv[0x38..0x3c].try_into().unwrap()) > 0 {
        return Err("not implemented: clearing the purgatory directory's children at apfs_sealvolume's mount".into());
    }

    // The source: the old tree's records, remapped (-R).
    let root = super::fsops::inode(nx, vol, ROOT_INO)?;
    let t = seal::remap_time(inputs.mtree_txt, &root)?;
    let (old_fs, src) = {
        let (tr, mut st) = nx.fs_tree(vol)?;
        (tr, tr.records(&mut st)?)
    };
    let src: Vec<(Vec<u8>, Vec<u8>)> = src.into_iter().map(|(k, v)| (k, v.unwrap_or_default())).collect();
    let remapped = seal::remap(src, t)?;
    let records = remapped.len();
    // update_tree's last key's object (S:0x10000960c's ctx+0x50), which
    // main's next_obj_id rule reads.
    let last_oid = remapped.last().map_or(0, |(k, _)| u64a(k, 0) & OBJ_MASK);
    let limits = seal::extent_limits(&remapped)?;

    // The transaction (main's tx_enter, held to S:0x1000072c8).
    nx.enter()?;
    let xid = nx.xid;
    // The temporary tree (S:0x100007014): virtual, SEQUENTIAL_INSERT |
    // KV_NONALIGNED, the volume's key order; apfs_remap_records_fsroot's
    // bt_insert of each record in iteration order.
    let temp = {
        let shape = Shape { bt_flags: 0x42, node_size: bs as usize, key_size: 0, val_size: 0, hash_size: 0 };
        let mut st = nx.virt_store(owner, FSTREE);
        let mut tr = Tree::create(&mut st, shape, old_fs.cmp)?;
        for (k, v) in &remapped {
            tr.insert(&mut st, k, Some(v))?;
        }
        tr
    };
    let temp_nodes = {
        let mut st = nx.virt_store(owner, FSTREE);
        temp.node_ids(&mut st)?.len() as u64
    };
    // authapfs_integrity_meta_create (S:0x100016a74): virtual, the
    // volume's, version 2, SHA-256 (hash type 1), the hash at 128.
    let integ = {
        let mut b = vec![0u8; bs as usize];
        b.put32(24, otype::INTEGRITY_META);
        b.put32(0x20, 2);
        b.put32(0x28, 1);
        b.put32(0x2c, 128);
        nx.virt_new(owner, b)
    };
    // The file extent tree (S:0x1000074e8): physical, flags 2 (bt_flags
    // 0x12), 16-byte keys and values; its root a block now.
    let fshape = Shape { bt_flags: 0x12, node_size: bs as usize, key_size: 16, val_size: 16, hash_size: 0 };
    let mut fext = Tree::create(&mut nx.phys_store(otype::FEXT_TREE, 1, Some(vol)), fshape, btree::cmp_fext)?;
    // The overallocated ranges' tree (S:0x100007580) is ephemeral and not
    // persistent: memory only, its identifier from a counter of its own.
    // tree4 (S:0x100007638, S:0x100007674): an empty virtual u64 tree,
    // flags 0, written now.
    let tree4 = {
        let shape = Shape { bt_flags: 0, node_size: bs as usize, key_size: 8, val_size: 8, hash_size: 0 };
        let mut st = nx.virt_store(owner, 0);
        Tree::create(&mut st, shape, cmp_u64)?
    };
    nx.virt_write_now(owner, tree4.root)?;

    // update_tree (S:0x100007ee4): the sealed tree's records and the file
    // extents; its root made by btree_create_extended (S:0x1000076c4), its
    // nodes in creation order, each taking the next identifier.
    let mut extents = Vec::new();
    let sealed = seal::update_tree(remapped, &digests, &mut extents)?;
    let sealed_records = sealed.len();
    let mut b = Builder::default();
    for (k, v) in sealed.iter().cloned() {
        b.insert(k, v)?;
    }
    let mut keep = Some(std::collections::BTreeMap::new());
    let h = b.seal(SEALED_BT_FLAGS, &mut keep)?;
    let nodes = keep.ok_or("the sealed tree's nodes")?;
    let mut hashed_root = 0;
    for (i, bytes) in nodes.into_iter() {
        let oid = nx.virt_new_noheader(owner, bytes);
        if i == 0 {
            hashed_root = oid;
        } else if oid != hashed_root + i {
            return Err("Failed to create contiguous fsroot tree".into());
        }
    }
    let (frecs, ranges) = seal::fext_records(&extents, &limits, bs)?;
    {
        let mut st = nx.phys_store(otype::FEXT_TREE, 1, Some(vol));
        for (k, v) in &frecs {
            fext.insert(&mut st, k, Some(v))?;
        }
    }
    // The 4 KiB hash against -I (main, S:0x100007c44: strncasecmp of the
    // hexadecimal; -a is not given, so a mismatch is EINVAL).
    if h4.len() != 32 || h4[..] != h[..] {
        let hex = |x: &[u8]| x.iter().map(|b| format!("{b:02x}")).collect::<String>();
        return Err(format!("Invalid root hash: {} (expected: {})", hex(&h), hex(&h4)));
    }
    // No 8 or 16 KiB slot's tree: ctx+0x44 bit 4 (FUN_10000a1c0 at
    // S:0x10000960c) is set only with -M (main reassigns its operand,
    // local_4d0, before S:0x100006664), which -I excludes.
    // The overallocated ranges, in block order (S:0x100009930).
    for (&p, &n) in &ranges {
        dereference_phys_range(nx, vol, p, n)?;
    }
    // authapfs_volume_seal (S:0x100016f20): the root hash into the
    // integrity object.
    nx.virt_mut(owner, integ)?[0x80..0xa0].copy_from_slice(&h);

    // main (S:0x100006e00..): tree4 and the temporary tree to the reaper
    // (btree_delete of a virtual tree that is not hashed).
    nx.reaper_add(otype::BTREE, bs as u32, fs_oid, tree4.root, 0)?;
    nx.reaper_add(otype::BTREE, bs as u32, fs_oid, temp.root, 0)?;
    // The superblock's fields (S:0x100006eb8..0x100007280).
    {
        let sb = nx.vol_sb(vol)?;
        if u64a(sb, 0x400) != 0 {
            return Err("not implemented: freeing the volume's old integrity object".into());
        }
        sb.put64(0x400, integ);
        sb.put64(0x88, hashed_root);
        sb.put32(0x410, otype::PHYSICAL | otype::BTREE);
        sb.put64(0x408, fext.root);
        let inc = u64a(sb, 0x38);
        sb.put64(0x38, if inc & 9 == 0 { inc | 0x28 } else { inc | 0x20 });
        if u64a(sb, 0xb0) <= last_oid {
            sb.put64(0xb0, last_oid + 1);
        }
        let f = u64a(sb, 0x108);
        sb.put64(0x108, f & !0x80);
    }
    // apfs_update_last_modified_by: its tx_enter joins main's.
    nx.enter()?;
    super::invert::modified_by_as(nx, vol, SEAL_ID, now)?;
    let ts = now();
    {
        let sb = nx.vol_sb(vol)?;
        sb.put64(0x40, ts);
        sb.put64(0x100, ts);
        // apfs_is_predefined_volume_uuid (S:0x100046264).
        if &sb[0xf0..0xf8] != b"apfsuuid" {
            return Err("not implemented: the sealed volume's new random UUID (uuid_generate)".into());
        }
        sb[0xfe] = sb[0xfe].wrapping_add(1);
    }
    let last = nx.reaper_add(otype::BTREE, bs as u32, fs_oid, old_fs.root, 0)?;
    nx.vol_sb(vol)?.put64(0x420, xid);
    nx.set_fs_tree(vol, Tree { root: hashed_root, shape: Shape { bt_flags: SEALED_BT_FLAGS, node_size: bs as usize, key_size: 0, val_size: 0, hash_size: 32 }, cmp: old_fs.cmp });
    // main's tx_leave (S:0x1000072c8).
    nx.leave(0)?;
    // nx_reaper_wait (S:0x10004d4bc): the reaper until the old tree's reap
    // identifier is done.
    let (_, next) = nx.reap_ids();
    if last >= next {
        return Err("nx_reaper_wait: a reap identifier past the reaper's".into());
    }
    while nx.reap_ids().0 < last {
        let before = nx.reap_ids().0;
        nx.reaper_run()?;
        if nx.reap_ids().0 == before {
            return Err("The reaper for the System volume's container failed".into());
        }
    }
    // tx_finish(nx, 0x11) (S:0x100007340), apfs_unmount (no write),
    // nx_unmount.
    nx.tx_finish()?;
    nx.unmount()?;
    Ok(SealStats { records, temp_nodes, sealed_records, sealed_nodes: b.len(), fext_records: frecs.len(), ranges: ranges.len(), root_hash: h, xid })
}

/// `dereference_phys_range(fs, xid, paddr, n)` (S:0x100039aa8 →
/// `apfs_update_phys_range` S:0x100038d64 with delta -1): the
/// extent-reference record holding the range found (the range lock's
/// lookup, S:0x100038a10); a record exactly the range drops to no
/// reference and goes; a range at the end of a longer record of one
/// reference leaves the record's front (its kind, owner and count kept;
/// S:0x100039790 merges it with no neighbour, which ends elsewhere) and
/// frees the range: `apfs_free_data_blocks` (S:0x10004628c: the main free
/// queue, the volume's allocation count less, its blocks freed more).
/// Other overlaps, a shared extent and a volume with snapshots are
/// refused, as not implemented.
fn dereference_phys_range(nx: &mut Nx<'_>, vol: usize, paddr: u64, n: u64) -> Result<(), String> {
    if n == 0 {
        return Err(format!("invalid zero len, paddr {paddr}"));
    }
    if u64a(nx.vol_sb_read(vol)?.0, 0xd8) != 0 {
        return Err("not implemented: dereferencing a range on a volume with snapshots".into());
    }
    let key = |p: u64| (p & OBJ_MASK | J_EXTENT << 60).to_le_bytes().to_vec();
    let (mut t, mut st) = nx.extentref_tree(vol)?;
    let (k, v) = match t.get_le(&mut st, &key(paddr))? {
        Some((k, Some(v))) if u64a(&k, 0) >> 60 == J_EXTENT => (k, v),
        _ => return Err(format!("Attempted to dereference range {paddr}+{n} but it isn't entirely there")),
    };
    let (p0, lk) = (u64a(&k, 0) & OBJ_MASK, u64a(&v, 0));
    let (l0, kind, owner) = (lk & OBJ_MASK, lk >> 60, u64a(&v, 8));
    let refcnt = i32::from_le_bytes(v[16..20].try_into().unwrap());
    if p0 + l0 < paddr + n {
        return Err(format!("Attempted to dereference range {paddr}+{n} but it isn't entirely there"));
    }
    if refcnt - 1 != 0 {
        return Err("not implemented: dereferencing a shared extent".into());
    }
    if owner >= 0xffff_ffff_ffff_fffe {
        return Err("not implemented: freeing an extent with no owning object".into());
    }
    if p0 == paddr && l0 == n {
        t.remove(&mut st, &k)?;
    } else if p0 < paddr && paddr + n == p0 + l0 {
        let mut nv = ((paddr - p0) | kind << 60).to_le_bytes().to_vec();
        nv.extend_from_slice(&v[8..20]);
        t.insert(&mut st, &k, Some(&nv))?;
    } else {
        return Err("not implemented: dereferencing a range that is not an extent's whole or its end".into());
    }
    nx.set_extentref_tree(vol, t)?;
    nx.free_data(vol, paddr, n)
}
