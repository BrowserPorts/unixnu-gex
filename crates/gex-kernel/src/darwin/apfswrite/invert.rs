//! `apfs_invert -d <container> -s 1 -n apfs_invert_asr_img -f`, the erase
//! restore's turn of asr's image file into the System volume's own
//! contents (the erase ramdisk's `apfs_invert`, APFS 2236.140.6; addresses
//! are its own, drafts' re-invert.md the transcription):
//!
//! - the outer container mounted by its library (`nx_mount` 0x100032d98),
//!   the volume (`apfs_mount` 0x10001f5fc, no snapshots allowed), the image
//!   file found in its root directory, its data stream's identifier and
//!   size;
//! - the inner container read through the file (`inv_dev_read`
//!   0x10004e3d8: each inner block at the file offset of its number,
//!   translated by the file's extents, `translate_inner_pbn` 0x10004e1a8;
//!   a sparse extent reads as zeros; writes to it are dropped);
//! - one transaction: a new extent-reference tree with the inner one's
//!   records at their outer addresses, split where the file's extents end
//!   (0x100006364, 0x100007168); a new file-system tree with the inner
//!   one's records decoded and encoded again, file extents translated the
//!   same way, their flags cleared (0x10000647c, 0x100007314); every outer
//!   block of the file no new record holds freed, one call per gap within
//!   each old record (0x1000069b8); the superblock's fields (0x100006d00),
//!   its `apfs_modified_by` entry (0x1000133d8); the old trees handed to
//!   the container's reaper (0x100006e58, `nx_reaper_add` 0x100016bf4);
//!   the transaction committed (`tx_finish(nx, 0x11)`);
//! - the unmount: block 0 from the last checkpoint, cleanly unmounted
//!   (0x100007080).
//!
//! Its two clock readings (the `apfs_modified_by` entry's time, then the
//! unmount and last-modification time) are the caller's.

use super::tx::{Mode, Nx};
use super::{Put, Sink};
use crate::darwin::apfsread::{btree as rbtree, otype, Container, Medium};
use std::sync::Arc;

const OBJ_MASK: u64 = 0x0fff_ffff_ffff_ffff;
/// What `apfs_invert` calls itself in `apfs_modified_by` ("%s (%s)").
pub const INVERT_ID: &str = "apfs_invert (2236.140.6)";

fn u64a(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Counts `apfs_invert` logs ("Copied A original extents and created B new
/// extents", "Copied C fs_root records plus D new file extents", "Freed E
/// data blocks and kept F data blocks").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub extents: u64,
    pub new_extents: u64,
    pub records: u64,
    pub new_file_extents: u64,
    pub freed: u64,
    pub kept: u64,
}

/// The image file's blocks as `inv_dev_read` reads them.
struct Inner {
    disk: Arc<dyn Sink>,
    /// The outer container's byte offset on `disk`.
    base: u64,
    bs: u64,
    size: u64,
    /// The file's extents: logical byte offset, length, first block.
    extents: Vec<(u64, u64, u64)>,
}

impl Inner {
    /// `translate_inner_pbn` (0x10004e1a8): the outer block of inner block
    /// `pbn` (0 for a sparse extent) and the blocks contiguous with it.
    fn translate(&self, pbn: u64) -> Result<(u64, u64), String> {
        let laddr = pbn * self.bs;
        if laddr >= self.size {
            return Err(format!("Trying to translate an inner pbn beyond the size of the image (laddr={laddr})"));
        }
        let &(l, n, p) = self.extents.iter().find(|&&(l, n, _)| l <= laddr && laddr < l + n).ok_or_else(|| format!("Couldn't find a file extent for inner_pbn {pbn}"))?;
        let off = laddr - l;
        Ok((if p == 0 { 0 } else { p + off / self.bs }, (n - off) / self.bs))
    }
}

impl Medium for Inner {
    fn size(&self) -> u64 {
        self.size
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<(), String> {
        if off % self.bs != 0 || buf.len() as u64 % self.bs != 0 {
            return Err("an inner read not of whole blocks".into());
        }
        let mut done = 0usize;
        while done < buf.len() {
            let pbn = (off + done as u64) / self.bs;
            let (o, contig) = self.translate(pbn)?;
            let n = ((buf.len() - done) as u64).min(contig * self.bs) as usize;
            if n == 0 {
                return Err("an inner read past the image file's extent".into());
            }
            if o == 0 {
                buf[done..done + n].fill(0);
            } else {
                self.disk.read_at(self.base + o * self.bs, &mut buf[done..done + n])?;
            }
            done += n;
        }
        Ok(())
    }
}

/// An inode's or a directory record's extended fields re-encoded
/// (0x10004d180, 0x10004d4e8): the bytes past the used data dropped, a
/// blob of no fields dropped, the first name field's last byte zeroed.
fn reencode_xfields(v: &[u8], fixed: usize) -> Result<Vec<u8>, String> {
    if v.len() <= fixed {
        return Ok(v.to_vec());
    }
    let n = u16::from_le_bytes([v[fixed], v[fixed + 1]]) as usize;
    if n == 0 {
        return Ok(v[..fixed].to_vec());
    }
    let used = u16::from_le_bytes([v[fixed + 2], v[fixed + 3]]) as usize;
    let end = fixed + 4 + 4 * n + used;
    let mut out = v.get(..end).ok_or("an extended-field blob past its value")?.to_vec();
    let mut at = fixed + 4 + 4 * n;
    for i in 0..n {
        let d = fixed + 4 + 4 * i;
        let size = u16::from_le_bytes([out[d + 2], out[d + 3]]) as usize;
        if out[d] == 4 && size != 0 {
            out[at + size - 1] = 0;
            break;
        }
        at += size.div_ceil(8) * 8;
    }
    Ok(out)
}

/// A name `strlcpy`'d with its length: refused where that would change it
/// (a NUL before its end).
fn name_ok(name: &[u8]) -> Result<(), String> {
    match name.iter().position(|&c| c == 0) {
        Some(p) if p + 1 == name.len() => Ok(()),
        _ => Err("not implemented: a name with a NUL before its end (strlcpy's copy of the stack's fill)".into()),
    }
}

/// `apfs_invert` on volume `vol` of the container `nx` holds (unmounted by
/// the kernel; mounted here as the tool's library mounts it, on a device
/// reporting `DK_FEATURE_BARRIER` or not: the free queues' age limit), its
/// container at byte `base` of `disk`, with `now` its two clock readings.
pub fn invert(nx: &mut Nx<'_>, vol: usize, name: &str, disk: Arc<dyn Sink>, base: u64, barrier: bool, now: &mut dyn FnMut() -> u64) -> Result<Stats, String> {
    let bs = nx.block_size();
    nx.set_barrier(barrier);
    nx.remount(Mode::Userspace)?;
    let fs_oid = nx.vol_oid(vol).ok_or("no outer volume")?;
    // apfs_mount: the clone epoch's own transaction when it would run.
    {
        let sb = nx.vol_sb(vol)?.clone();
        let epoch = u64a(&sb, 0x3d8);
        if epoch == 0 || u64a(&sb, 0x3e0) != u64a(&sb, 0x140 + 0x28) {
            return Err("not implemented: the outer volume's clone epoch written at apfs_invert's mount".into());
        }
        if u64a(&sb, 0xd8) != 0 {
            return Err("Outer volume has snapshots".into());
        }
    }
    let osb = nx.vol_sb(vol)?.clone();
    let old_incompat = u64a(&osb, 0x38);
    if old_incompat & 0x20 != 0 {
        return Err("not implemented: inverting into a sealed volume".into());
    }
    // The image file: the root directory's record, its inode, its data
    // stream.
    let ino = super::fsops::lookup(nx, vol, 2, name)?.ok_or_else(|| format!("no /{name} in the outer volume"))?;
    let (old_fs, mut st) = nx.fs_tree(vol)?;
    let iv = old_fs.get(&mut st, &(ino | 3 << 60).to_le_bytes())?.ok_or("the image file has no inode")?;
    let ds_oid = u64a(&iv, 0x08);
    let ds_size = image_size(&iv)?.ok_or("File might be 0-length")?;
    let recs = old_fs.records(&mut st)?;
    drop(st);
    let mut extents: Vec<(u64, u64, u64)> = recs
        .iter()
        .filter(|(k, _)| k.len() == 16 && u64a(k, 0) == (ds_oid | 8 << 60))
        .map(|(k, v)| {
            let v = v.as_ref().unwrap();
            (u64a(k, 8), u64a(v, 0) & 0x00ff_ffff_ffff_ffff, u64a(v, 8))
        })
        .collect();
    extents.sort_unstable();
    let inner = Arc::new(Inner { disk, base, bs, size: ds_size, extents });
    // The inner container and its first volume.
    let ic = Arc::new(Container::open(Arc::clone(&inner) as Arc<dyn Medium>).map_err(|e| format!("Couldn't nx_mount the image: {e}"))?);
    if u64::from(ic.block_size()) != bs {
        return Err("the image's block size is not the device's".into());
    }
    let idx = ic.nx.fs_oid.iter().position(|&o| o != 0).ok_or("the image has no volume")?;
    let iv_vol = ic.volume(idx).map_err(|e| e.to_string())?.ok_or("the image has no volume")?;
    if iv_vol.sb.fs_flags & 1 == 0 {
        return Err("Inner volume is encrypted".into());
    }
    let isb_paddr = ic.omap().map_err(|e| e.to_string())?.lookup(&ic, iv_vol.sb.header.oid, ic.xid()).map_err(|e| e.to_string())?.ok_or("the inner superblock not mapped")?.paddr;
    let isb = ic.read_raw(isb_paddr).map_err(|e| e.to_string())?;
    if u64a(&isb, 0xd8) != 0 {
        return Err("Inner volume has snapshots".into());
    }
    let inner_incompat = u64a(&isb, 0x38);
    if inner_incompat & 0x20 != 0 {
        return Err("not implemented: a sealed inner volume (btree_seal_copy, the integrity metadata)".into());
    }

    // The transaction.
    nx.begin()?;
    nx.vol_sb(vol)?;
    let mut stats = Stats::default();
    // The extent references.
    if u32::from_le_bytes(osb[0x78..0x7c].try_into().unwrap()) & 0xffff != 2 {
        return Err("the outer extent-reference tree's type".into());
    }
    let mut er = nx.new_extentref_tree(vol)?;
    let ier = rbtree::Tree::open(&ic, u64a(&isb, 0x90), rbtree::Children::Physical, None, 0x0f).map_err(|e| e.to_string())?;
    let mut inner_er = Vec::new();
    ier.walk(&ic, &mut |k, v| {
        inner_er.push((k.to_vec(), v.map(|v| v.to_vec())));
        Ok(true)
    })
    .map_err(|e| e.to_string())?;
    for (k, v) in &inner_er {
        if u64a(k, 0) >> 60 != 2 {
            return Err("found a non-extent record in the inner extent-reference tree".into());
        }
        let v = v.as_ref().ok_or("an extent record with no value")?;
        let paddr = u64a(k, 0) & OBJ_MASK;
        let len = u64a(v, 0) & OBJ_MASK;
        let kind = u64a(v, 0) >> 60;
        let mut done = 0;
        while done < len {
            let (o, contig) = inner.translate(paddr + done)?;
            if o == 0 {
                return Err("translate_inner_pbn hit a hole".into());
            }
            let piece = (len - done).min(contig);
            let key = (o & OBJ_MASK | 2 << 60).to_le_bytes();
            let mut val = (piece & OBJ_MASK | kind << 60).to_le_bytes().to_vec();
            val.extend_from_slice(&v[8..20]);
            let (_, mut st) = nx.extentref_tree(vol)?;
            er.insert(&mut st, &key, Some(&val))?;
            if done != 0 {
                stats.new_extents += 1;
            }
            done += piece;
        }
        stats.extents += 1;
        stats.kept += len;
    }
    // The file-system tree.
    let r = u32::from_le_bytes(osb[0x74..0x78].try_into().unwrap());
    if r & 0xffff != 2 || r & 0xffff_0000 != 0 {
        return Err("not implemented: an outer file-system tree that is not virtual".into());
    }
    let hashed = inner_incompat & 0x9 != 0;
    let mut fs = nx.new_fs_tree(vol, hashed)?;
    {
        let sb = nx.vol_sb(vol)?;
        sb.put64(0x38, (old_incompat & !0x9) | (inner_incompat & 0x9));
    }
    let mut inner_fs = Vec::new();
    iv_vol
        .fs_tree
        .walk(&ic, &mut |k, v| {
            inner_fs.push((k.to_vec(), v.map(|v| v.to_vec())));
            Ok(true)
        })
        .map_err(|e| e.to_string())?;
    for (k, v) in inner_fs {
        let v = v.unwrap_or_default();
        let ty = u64a(&k, 0) >> 60;
        let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        match ty {
            3 => {
                if let Some(d) = dstream_xfield(&v)? {
                    let c = u64a(&d, 16);
                    if c != 0 && c != u64::MAX {
                        return Err("an inner inode's data stream has a crypto identifier".into());
                    }
                }
                out.push((k.clone(), reencode_xfields(&v, 0x5c)?));
            }
            4 => {
                let nl = u16::from_le_bytes([k[8], k[9]]) as usize;
                name_ok(&k[10..10 + nl])?;
                let flags = u16::from_le_bytes([v[0], v[1]]);
                // XATTR_DATA_STREAM: j_xattr_dstream_t's stream's
                // default crypto identifier.
                if flags & 1 != 0 && v.len() >= 4 + 8 + 0x28 && u64a(&v, 4 + 8 + 16) != 0 && u64a(&v, 4 + 8 + 16) != u64::MAX {
                    return Err("an inner extended attribute's data stream has a crypto identifier".into());
                }
                out.push((k.clone(), v.clone()));
            }
            5 => {
                let nl = u16::from_le_bytes([v[8], v[9]]) as usize;
                name_ok(&v[10..10 + nl])?;
                out.push((k.clone(), v.clone()));
            }
            7 => return Err("Found a crypto_state record inside image".into()),
            8 => {
                let lf = u64a(&v, 0);
                let (len, flags) = (lf & 0x00ff_ffff_ffff_ffff, lf >> 56);
                let phys = u64a(&v, 8);
                if u64a(&v, 16) != 0 {
                    return Err("an inner file extent with a crypto identifier".into());
                }
                if phys == 0 {
                    out.push((k.clone(), v.clone()));
                } else {
                    let _ = flags;
                    let oid = u64a(&k, 0) & OBJ_MASK;
                    let logical = u64a(&k, 8);
                    let mut blocks = len / bs;
                    let (mut ipbn, mut laddr) = (phys, logical);
                    while blocks != 0 {
                        let (o, contig) = inner.translate(ipbn)?;
                        if o == 0 {
                            return Err("translate_inner_pbn hit a hole".into());
                        }
                        let n = blocks.min(contig);
                        let mut nk = (oid | 8 << 60).to_le_bytes().to_vec();
                        nk.extend_from_slice(&laddr.to_le_bytes());
                        let mut nv = (n * bs).to_le_bytes().to_vec();
                        nv.extend_from_slice(&o.to_le_bytes());
                        nv.extend_from_slice(&0u64.to_le_bytes());
                        out.push((nk, nv));
                        if laddr != logical {
                            stats.new_file_extents += 1;
                        }
                        laddr += n * bs;
                        ipbn += n;
                        blocks -= n;
                    }
                }
            }
            9 => {
                let (nl, name_at) = if hashed { ((u32::from_le_bytes(k[8..12].try_into().unwrap()) & 0x3ff) as usize, 12) } else { (u16::from_le_bytes([k[8], k[9]]) as usize, 10) };
                name_ok(&k[name_at..name_at + nl])?;
                out.push((k.clone(), reencode_xfields(&v, 0x12)?));
            }
            _ => out.push((k.clone(), v.clone())),
        }
        stats.records += 1;
        for (nk, nv) in out {
            let (_, mut st) = nx.fs_tree(vol)?;
            fs.insert(&mut st, &nk, Some(&nv))?;
        }
    }
    // free_unused_outer_blocks: every gap within each old record.
    let (old_er, mut st) = nx.extentref_tree(vol)?;
    let old_recs = old_er.records(&mut st)?;
    let new_recs: Vec<(u64, u64)> = er.records(&mut st)?.iter().map(|(k, v)| (u64a(k, 0) & OBJ_MASK, u64a(v.as_ref().unwrap(), 0) & OBJ_MASK)).collect();
    drop(st);
    let mut frees = Vec::new();
    for (k, v) in &old_recs {
        let (os, ol) = (u64a(k, 0) & OBJ_MASK, u64a(v.as_ref().unwrap(), 0) & OBJ_MASK);
        let oe = os + ol;
        let first = new_recs.iter().position(|&(s, l)| s + l > os && s < oe);
        let Some(first) = first else {
            frees.push((os, ol));
            continue;
        };
        let mut cur = os;
        for &(ns, nl) in &new_recs[first..] {
            if oe <= ns {
                break;
            }
            if cur < ns {
                frees.push((cur, ns - cur));
            }
            cur = ns + nl;
        }
        if cur < oe {
            frees.push((cur, oe - cur));
        }
    }
    for (p, l) in frees {
        nx.free(p, l)?;
        stats.freed += l;
        let xid = nx.xid;
        let sb = nx.vol_sb(vol)?;
        let (alloc, freed) = (u64a(sb, 0x58), u64a(sb, 0xe8));
        sb.put64(0x58, alloc - l);
        sb.put64(0xe8, freed + l);
        sb.put64(0x420, xid);
    }
    // The superblock.
    nx.set_extentref_tree(vol, er)?;
    nx.replace_fs_tree(vol, fs)?;
    {
        let sb = nx.vol_sb(vol)?;
        sb.put64(0x88, fs.root);
        sb.put32(0x74, r);
        sb.put64(0x90, er.root);
        sb.put64(0xe0, stats.kept);
        sb.put64(0xe8, 0);
        for o in [0xc0, 0xc8, 0xd0, 0xb0, 0xb8] {
            sb.put64(o, u64a(&isb, o));
        }
        sb[0x3c0..0x3c4].copy_from_slice(&isb[0x3c0..0x3c4]);
        sb[0x3c6..0x3c8].copy_from_slice(&isb[0x3c6..0x3c8]);
        sb.put64(0x108, (u64a(&isb, 0x108) & !0x9) | 0x1);
        let features = u64a(sb, 0x28);
        sb.put64(0x28, (features & !0x1a) | (u64a(&isb, 0x28) & 0x1a));
        sb.put64(0xa0, 0);
    }
    modified_by(nx, vol, now)?;
    let t = now();
    let xid = nx.xid;
    {
        let sb = nx.vol_sb(vol)?;
        sb[0x110..0x140].copy_from_slice(&isb[0x110..0x140]);
        sb.put64(0x40, t);
        sb.put64(0x100, t);
        sb.put64(0x420, xid);
        let role = u16::from_le_bytes([sb[0x3c4], sb[0x3c5]]);
        if [0u16, 2, 0x40, 0x240].contains(&role) {
            return Err(format!("not implemented: inverting into a volume of role {role:#x} (+0x428)"));
        }
    }
    // The old trees to the reaper: the file-system tree's root (its
    // object type, a virtual B-tree), then the extent-reference tree's.
    nx.reaper_add(otype::BTREE, bs as u32, fs_oid, old_fs.root, 0)?;
    nx.reaper_add(otype::PHYSICAL | otype::BTREE, bs as u32, fs_oid, old_er.root, 0)?;
    nx.commit()?;
    nx.unmount()?;
    Ok(stats)
}

/// The image file's size: its data stream's (type 8 field, 0x28 bytes).
fn image_size(iv: &[u8]) -> Result<Option<u64>, String> {
    Ok(dstream_xfield(iv)?.map(|d| u64a(&d, 0)))
}

fn dstream_xfield(v: &[u8]) -> Result<Option<Vec<u8>>, String> {
    if v.len() <= 0x5c {
        return Ok(None);
    }
    let n = u16::from_le_bytes([v[0x5c], v[0x5d]]) as usize;
    let mut at = 0x60 + 4 * n;
    for i in 0..n {
        let d = 0x60 + 4 * i;
        let size = u16::from_le_bytes([v[d + 2], v[d + 3]]) as usize;
        if v[d] == 8 {
            if size != 0x28 {
                return Err("the image file's data stream field is not 0x28 bytes".into());
            }
            return Ok(Some(v.get(at..at + size).ok_or("a data stream field past its value")?.to_vec()));
        }
        at += size.div_ceil(8) * 8;
    }
    Ok(None)
}

/// `apfs_modified_by` (0x1000133d8 → 0x10003455c): "apfs_invert
/// (2236.140.6)" at the front (an entry of that name moves there, else
/// the oldest goes), its time and transaction; the clone transaction.
fn modified_by(nx: &mut Nx<'_>, vol: usize, now: &mut dyn FnMut() -> u64) -> Result<(), String> {
    let xid = nx.xid;
    let ts = now();
    let sb = nx.vol_sb(vol)?;
    let mut id = [0u8; 32];
    id[..INVERT_ID.len()].copy_from_slice(INVERT_ID.as_bytes());
    let entry = |i: usize| 0x140 + 0x30 * i;
    // strncmp of 32 bytes: equal through the name's NUL.
    let i = (0..7).find(|&i| sb[entry(i)..entry(i) + INVERT_ID.len() + 1] == id[..INVERT_ID.len() + 1]).unwrap_or(7);
    sb.copy_within(entry(0)..entry(i), entry(1));
    sb[entry(0)..entry(0) + INVERT_ID.len()].copy_from_slice(INVERT_ID.as_bytes());
    sb[entry(0) + INVERT_ID.len()] = 0;
    sb.put64(entry(0) + 32, ts);
    sb.put64(entry(0) + 40, xid);
    sb.put64(0x3e0, xid);
    sb.put64(0x420, xid);
    Ok(())
}
