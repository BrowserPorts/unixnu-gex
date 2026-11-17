//! The cluster layer's policies over a vnode's pages, for the I/O they
//! issue and the logical writes they count (xnu-10063.141.1
//! `vfs_cluster.c`): `cluster_read_copy` with its prefetch and read-ahead
//! (`cluster_read_prefetch`, `cluster_read_ahead`, `advisory_read_ext`),
//! `cluster_write_copy` and its write-behind (`cluster_update_state_
//! internal`, `cluster_try_push`, `cluster_push_now`, the sparse cluster
//! map, `vfs_drt_*`), and `cluster_push_err`.
//!
//! Each I/O they make is `cluster_io`'s: the request rounded up to the
//! page, and of it what `VNOP_BLOCKMAP` maps reaches the device through
//! `spec_strategy` (a hole, and what lies past the file's allocation, is
//! zero-filled with no I/O), charged to the issuing thread's task
//! ([`Io`]).
//!
//! What the mount's I/O attributes are (`vfs_init_io_attributes` from the
//! volume's IOMedia) is not measured: [`MOUNT`] stands in for them.

use super::pagecache::{Io, Object, Page, PAGE};

/// `CONFIG_MAX_CLUSTERS` of the arm64 kernel (`xsmall`): 21H461's
/// `cluster_try_push` (0xfffffff007363470) returns `4 - cl_number`.
pub const MAX_CLUSTERS: usize = 4;

/// `MAX_UPL_TRANSFER_BYTES` and `MAX_UPL_SIZE_BYTES`
/// (`memory_object_types.h`): `cluster_max_io_size`'s floor and the
/// segment count's cap (0xfffffff0073634c4..dc compare with 0x100000 and
/// 0x1000 pages).
const MAX_UPL_TRANSFER: u64 = 1024 * 1024;
const MAX_UPL_SIZE: u64 = 64 * 1024 * 1024;

/// `MAX_IO_REQUEST_SIZE`.
const MAX_IO_REQUEST: u64 = 512 * 1024 * 1024;

/// Not `XNU_TARGET_OS_OSX`: `speculative_prefetch_max`,
/// `speculative_prefetch_max_iosize`, `prefetch_max`, and the prefetch
/// and write-behind scales (`PREFETCH`, `PREFETCH_SSD`, `WRITE_BEHIND`,
/// `WRITE_BEHIND_SSD`, all 1).
const SPECULATIVE_PREFETCH_MAX: u64 = 2048 * 1024;
const SPECULATIVE_PREFETCH_MAX_IOSIZE: u64 = 512 * 1024;
const PREFETCH_MAX: u64 = 1024 * 1024 * 1024;
const PREFETCH: u64 = 1;
const WRITE_BEHIND: u64 = 1;

/// `push_flag`s.
const PUSH_DELAY: u32 = 0x01;
const PUSH_ALL: u32 = 0x02;
const PUSH_SYNC: u32 = 0x04;

/// APFS's device block (`mnt_devblocksize`): a file's allocation ends at
/// its size rounded up to it.
pub const DEVBLOCK: u64 = 4096;

/// A mount's I/O attributes (`mnt_maxreadcnt`, `mnt_maxwritecnt`,
/// `mnt_segreadcnt`, `mnt_segwritecnt`, `mnt_ioscale`,
/// `mnt_minsaturationbytecount`, and `MNTK_SSD`).
#[derive(Clone, Copy, Debug)]
pub struct Mount {
    pub maxreadcnt: u64,
    pub maxwritecnt: u64,
    pub segreadcnt: u64,
    pub segwritecnt: u64,
    pub ioscale: u64,
    pub minsaturation: u64,
    pub ssd: bool,
}

/// The data volumes' mount: solid state (the namespaces' medium type);
/// the byte and segment counts at or under what `cluster_max_io_size`
/// raises them to (1 MiB), a command queue of at most 32
/// (`MNT_IOSCALE` 1) and no saturation byte count, which stand in.
pub const MOUNT: Mount = Mount {
    maxreadcnt: MAX_UPL_TRANSFER,
    maxwritecnt: MAX_UPL_TRANSFER,
    segreadcnt: MAX_UPL_TRANSFER / PAGE,
    segwritecnt: MAX_UPL_TRANSFER / PAGE,
    ioscale: 1,
    minsaturation: 0,
    ssd: true,
};

/// The stand-in for [`MOUNT`], as gexc reports it.
pub const MOUNT_STAND_IN: &str = "the APFS volumes' I/O attributes (vfs_init_io_attributes from the volume's IOMedia: DKIOCGETMAXBYTECOUNTREAD/WRITE, DKIOCGETMAXSEGMENTCOUNTREAD/WRITE, DKIOCGETCOMMANDPOOLSIZE, DKIOCGETMINSEGMENTALIGNMENTBYTECOUNT's saturation count), which size the cluster layer's read-ahead, prefetch and write-behind (stand-in: at most 1 MiB per I/O, a queue of at most 32, no saturation count; measure the volume IOMedia's IOMaximumByteCountRead/Write, IOMaximumSegmentCountRead/Write, IOCommandPoolSize and IOMinimumSaturationByteCount in a sysdiagnose's ioreg)";

fn trunc(v: u64) -> u64 {
    v & !(PAGE - 1)
}

fn round(v: u64) -> u64 {
    v.saturating_add(PAGE - 1) & !(PAGE - 1)
}

/// `cluster_max_io_size(mp, type)`.
pub fn max_io_size(read: bool) -> u64 {
    let (seg, max) = if read { (MOUNT.segreadcnt, MOUNT.maxreadcnt) } else { (MOUNT.segwritecnt, MOUNT.maxwritecnt) };
    let seg = seg.min(MAX_UPL_SIZE / PAGE);
    let m = (seg * PAGE).min(max);
    if m < MAX_UPL_TRANSFER {
        MAX_UPL_TRANSFER
    } else {
        m & !(PAGE - 1)
    }
}

/// `cluster_max_prefetch(vp, max_io_size, limit)`.
fn max_prefetch(max_io: u64, limit: u64) -> u64 {
    (max_io * MOUNT.ioscale * PREFETCH).min(limit)
}

/// What an operation knows of the file: its size as the operation sees
/// it (`ubc_getsize`, or the size the filesystem passes), and the bytes of
/// a range its allocation backs (`VNOP_BLOCKMAP`'s extents, holes left
/// out).
pub struct Cx<'a> {
    pub size: u64,
    pub backed: &'a dyn Fn(u64, u64) -> u64,
    pub io: Io,
}

impl Cx<'_> {
    /// A pager's read of `n` bytes at `f` (page-aligned, `cluster_pagein`).
    pub(super) fn read_pages(&mut self, f: u64, n: u64) {
        self.read(f, n);
    }

    /// `cluster_io(CL_READ)` of `n` bytes at `f` (page-aligned).
    fn read(&mut self, f: u64, n: u64) {
        let end = (f + round(n)).min(self.size.div_ceil(DEVBLOCK) * DEVBLOCK);
        if end > f {
            self.io.read += (self.backed)(f, end);
        }
    }

    /// `cluster_io` of a write of `n` bytes at `f` (page-aligned): the
    /// filesystem allocates what the write covers, up to the file's last
    /// block.
    fn write(&mut self, f: u64, n: u64) {
        let end = (f + round(n)).min(self.size.div_ceil(DEVBLOCK) * DEVBLOCK);
        if end > f {
            self.io.written += end - f;
        }
    }
}

/// A write-behind cluster (`struct cl_wextent`): pages `[b, e)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Ext {
    b: u64,
    e: u64,
    nocache: bool,
}

/// `struct cl_writebehind`.
#[derive(Debug, Default)]
pub struct WriteBehind {
    clusters: Vec<Ext>,
    seq_written: u64,
    last_write: u64,
    scmap: Option<Drt>,
}

/// `struct cl_readahead`, made at the first read that may read ahead.
#[derive(Clone, Copy, Debug)]
pub struct ReadAhead {
    lastr: i64,
    maxra: i64,
    ralen: i64,
}

impl Default for ReadAhead {
    fn default() -> ReadAhead {
        ReadAhead { lastr: -1, maxra: 0, ralen: 0 }
    }
}

/// What a write asks of the cluster layer (`cluster_write_ext`'s flags).
#[derive(Clone, Copy, Debug, Default)]
pub struct WriteFlags {
    /// `IO_SYNC`: the pages pushed at once.
    pub sync: bool,
    /// `IO_NOCACHE`.
    pub nocache: bool,
    /// `IO_HEADZEROFILL` from `head`, `IO_TAILZEROFILL` to `tail`.
    pub head: Option<u64>,
    pub tail: Option<u64>,
}

// -- the sparse cluster map (vfs_drt_*) ---------------------------------

/// `DRT_BITVECTOR_PAGES`: 256 KiB of 4 KiB pages' worth of bits, of the
/// map's pages.
const DRT_BITVECTOR_PAGES: u64 = (1024 * 256) / (4 * 1024);
const DRT_BLOCK: u64 = DRT_BITVECTOR_PAGES * PAGE;
/// Not `XNU_TARGET_OS_OSX`: the moduli and the memory each needs.
const DRT_SMALL: u32 = 1019;
const DRT_LARGE: u32 = 8179;
const DRT_XLARGE: u32 = 32749;
const DRT_LARGE_MEMORY: u64 = 4 * 1024 * 1024 * 1024;
const DRT_XLARGE_MEMORY: u64 = 32 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default)]
struct DrtEntry {
    /// `dhe_control`: the address (aligned) and the count, 0x1ff vacant.
    addr: u64,
    count: u32,
    bits: u64,
}

const VACANT: u32 = 0x1ff;

/// `struct vfs_drt_clustermap`.
#[derive(Clone, Debug)]
struct Drt {
    modulus: u32,
    buckets: u32,
    lastclean: u32,
    table: Vec<DrtEntry>,
}

impl Drt {
    fn new(modulus: u32) -> Drt {
        Drt { modulus, buckets: 0, lastclean: 0, table: vec![DrtEntry { addr: 0, count: VACANT, bits: 0 }; modulus as usize] }
    }

    fn hash(&self, addr: u64) -> u32 {
        (addr % u64::from(self.modulus)) as u32
    }

    fn vacant(&self, i: u32) -> bool {
        self.table[i as usize].count == VACANT
    }

    /// `vfs_drt_alloc_map`: a first map, or a larger one with the old
    /// one's entries; `false` where it cannot grow.
    fn alloc(old: Option<&Drt>) -> Option<Drt> {
        let max_mem = super::mig::machine::MEM_SIZE;
        let Some(o) = old else { return Some(Drt::new(DRT_SMALL)) };
        let active = (0..o.modulus).filter(|&i| !o.vacant(i) && o.table[i as usize].count != 0).count() as u32;
        let modulus = if o.modulus == DRT_SMALL {
            if active > DRT_SMALL - 5 && max_mem >= DRT_LARGE_MEMORY { DRT_LARGE } else { DRT_SMALL }
        } else if o.modulus == DRT_LARGE {
            if active > DRT_LARGE - 5 && max_mem >= DRT_XLARGE_MEMORY {
                DRT_XLARGE
            } else {
                return None;
            }
        } else {
            if active >= DRT_XLARGE {
                return None;
            }
            DRT_XLARGE
        };
        let mut n = Drt::new(modulus);
        for i in 0..o.modulus {
            let e = o.table[i as usize];
            if e.count == VACANT || e.count == 0 {
                continue;
            }
            let Some(j) = n.get_index(e.addr, true) else { panic!("vfs_drt: new cluster map mysteriously too small") };
            n.table[j as usize] = e;
        }
        Some(n)
    }

    /// `vfs_drt_search_index`.
    fn search(&self, offset: u64) -> Option<u32> {
        let offset = offset & !(DRT_BLOCK - 1);
        let mut index = self.hash(offset);
        for _ in 0..self.modulus {
            if self.vacant(index) {
                break;
            }
            if self.table[index as usize].addr == offset {
                return Some(index);
            }
            index = (index + 1) % self.modulus;
        }
        None
    }

    /// `vfs_drt_get_index` without the reallocation (`recursed`).
    fn get_index(&mut self, offset: u64, _recursed: bool) -> Option<u32> {
        if let Some(i) = self.search(offset) {
            return Some(i);
        }
        let offset = offset & !(DRT_BLOCK - 1);
        let mut index = self.hash(offset);
        for _ in 0..self.modulus {
            let c = self.table[index as usize].count;
            if c == VACANT || c == 0 {
                self.buckets += 1;
                if index < self.lastclean {
                    self.lastclean = index;
                }
                self.table[index as usize] = DrtEntry { addr: offset, count: 0, bits: 0 };
                return Some(index);
            }
            index = (index + 1) % self.modulus;
        }
        None
    }
}

/// `vfs_drt_get_index` with its reallocation, on the map in `slot`.
fn drt_get_index(slot: &mut Option<Drt>, offset: u64) -> Option<u32> {
    let m = slot.as_mut()?;
    if let Some(i) = m.get_index(offset, false) {
        return Some(i);
    }
    let grown = Drt::alloc(Some(m))?;
    *slot = Some(grown);
    slot.as_mut()?.get_index(offset, true)
}

/// `vfs_drt_do_mark_pages`: the pages set (or cleared), and whether every
/// one fit.
fn drt_mark(slot: &mut Option<Drt>, mut offset: u64, mut length: u64, dirty: bool) -> (u64, bool) {
    if slot.is_none() {
        if !dirty {
            return (0, true);
        }
        *slot = Drt::alloc(None);
    }
    let mut set = 0;
    while length > 0 {
        let Some(index) = drt_get_index(slot, offset) else { return (set, false) };
        let m = slot.as_mut().expect("a map");
        let e = &mut m.table[index as usize];
        let pgoff = (offset - (offset & !(DRT_BLOCK - 1))) / PAGE;
        let pgcount = (length / PAGE).min(DRT_BITVECTOR_PAGES - pgoff);
        for i in 0..pgcount {
            let bit = 1u64 << (pgoff + i);
            if dirty && e.bits & bit == 0 {
                e.bits |= bit;
                e.count += 1;
                set += 1;
            } else if !dirty && e.bits & bit != 0 {
                e.bits &= !bit;
                e.count -= 1;
                set += 1;
            }
        }
        offset += pgcount * PAGE;
        length -= pgcount * PAGE;
    }
    (set, true)
}

/// `vfs_drt_get_cluster`: the next run of marked pages, cleared; none
/// (and the map freed) when there is none.
fn drt_get_cluster(slot: &mut Option<Drt>) -> Option<(u64, u64)> {
    let m = slot.as_mut()?;
    let mut offset = 0u64;
    for _ in 0..m.modulus {
        let index = m.hash(offset);
        let e = m.table[index as usize];
        if e.count == VACANT || e.count == 0 {
            offset += DRT_BLOCK;
            continue;
        }
        let fs = (0..DRT_BITVECTOR_PAGES).find(|&i| e.bits & (1 << i) != 0).expect("vfs_drt: entry summary count > 0 but no bits set in map");
        let ls = (fs..DRT_BITVECTOR_PAGES).take_while(|&i| e.bits & (1 << i) != 0).count() as u64;
        let (o, l) = (e.addr + PAGE * fs, ls * PAGE);
        drt_mark(slot, o, l, false);
        if let Some(m) = slot.as_mut() {
            m.lastclean = index;
        }
        return Some((o, l));
    }
    *slot = None;
    None
}

// -- the object's pages, as the cluster layer moves them ----------------

impl Object {
    fn present(&self, off: u64) -> bool {
        self.pages.contains_key(&off)
    }

    fn dirty(&self, off: u64) -> bool {
        self.pages.get(&off).is_some_and(|p| p.dirty)
    }

    /// `VM_PAGE_CONSUME_CLUSTERED` of the page at `off`, if it is there.
    pub(super) fn consume(&mut self, off: u64) {
        if let Some(p) = self.pages.get_mut(&off) {
            if p.clustered {
                p.clustered = false;
                self.pages_used = self.pages_used.wrapping_add(1);
            }
        }
    }

    /// A UPL of its own (not `UPL_RET_ONLY_ABSENT`) over `[a, b)`: the
    /// clustered pages it takes are consumed.
    fn upl_take(&mut self, a: u64, b: u64) {
        let offs: Vec<u64> = self.pages.range(a..b).filter(|(_, p)| p.clustered).map(|(&o, _)| o).collect();
        for o in offs {
            self.consume(o);
        }
    }

    /// `ubc_range_op(UPL_ROP_PRESENT)`: the bytes from `a` of pages there
    /// in a row, before `b`.
    fn present_run(&self, a: u64, b: u64) -> u64 {
        let mut o = a;
        while o < b && self.present(o) {
            o += PAGE;
        }
        o - a
    }

    /// `memory_object_control_uiomove` from `off` for `n` bytes: through
    /// the pages there in a row, each consumed, each dirtied for a write
    /// (its bytes the task's logical writes). The bytes moved.
    fn ubc_copy(&mut self, off: u64, n: u64, write: bool) -> u64 {
        let mut moved = 0;
        let mut at = off;
        while moved < n {
            let pg = trunc(at);
            if !self.present(pg) {
                break;
            }
            let k = (pg + PAGE - at).min(n - moved);
            self.consume(pg);
            if write {
                self.pages.get_mut(&pg).expect("present").dirty = true;
            }
            moved += k;
            at += k;
        }
        moved
    }

    // -- reads ---------------------------------------------------------

    /// `cluster_read_prefetch(vp, f, size, filesize)`: the pages it
    /// covers.
    fn read_prefetch(&mut self, cx: &mut Cx<'_>, f: u64, size: u64, filesize: u64) -> u64 {
        if f >= filesize {
            return 0;
        }
        let size = size.min(filesize - f);
        self.advisory_read(cx, filesize, f, size);
        size.div_ceil(PAGE)
    }

    /// `advisory_read_ext(vp, filesize, f, resid)`: the absent pages read
    /// by a UPL of `UPL_RET_ONLY_ABSENT`, each clustered, a new
    /// speculative page.
    pub(super) fn advisory_read(&mut self, cx: &mut Cx<'_>, filesize: u64, mut f: u64, resid: u64) {
        let mut resid = resid as i64;
        let mut max_io = max_io_size(true);
        if MOUNT.ssd {
            max_io = max_io.min(SPECULATIVE_PREFETCH_MAX_IOSIZE);
        }
        while resid > 0 && f < filesize {
            let mut start_offset = f & (PAGE - 1);
            let mut upl_f = f - start_offset;
            let io_size = (resid as u64).min(filesize - f);
            let mut upl_size = round(start_offset + io_size).min(max_io);
            let skip = self.present_run(upl_f, upl_f + upl_size);
            if skip > 0 {
                let n = skip - start_offset;
                f += n;
                resid -= n as i64;
                if skip == upl_size {
                    continue;
                }
                start_offset = 0;
                upl_f += skip;
                upl_size -= skip;
            }
            let pages = upl_size / PAGE;
            let last = (0..pages).rev().find(|&i| !self.present(upl_f + i * PAGE)).map_or(0, |i| i + 1);
            let mut i = 0;
            while i < last {
                while i < last && self.present(upl_f + i * PAGE) {
                    i += 1;
                }
                let s = i;
                while i < last && !self.present(upl_f + i * PAGE) {
                    i += 1;
                }
                if i > s {
                    let at = upl_f + s * PAGE;
                    for p in s..i {
                        self.pages.insert(upl_f + p * PAGE, Page { clustered: true, ..Page::default() });
                        self.pages_created = self.pages_created.wrapping_add(1);
                    }
                    let n = ((i - s) * PAGE).min(filesize - at);
                    cx.read(at, n);
                }
            }
            let n = (upl_size - start_offset).min(resid as u64);
            f += n;
            resid -= n as i64;
        }
    }

    /// `cluster_read_ahead(vp, extent, filesize, rap)`.
    fn read_ahead(&mut self, cx: &mut Cx<'_>, b: i64, e: i64, filesize: u64) {
        let ra = self.ra;
        if b == ra.lastr && b == e {
            return;
        }
        if ra.lastr == -1 || (b != ra.lastr && b != ra.lastr + 1) {
            self.ra.ralen = 0;
            self.ra.maxra = 0;
            return;
        }
        let max_pf = max_prefetch(max_io_size(true), SPECULATIVE_PREFETCH_MAX);
        if max_pf <= PAGE {
            return;
        }
        if e < ra.maxra && ra.ralen >= 4 && (ra.maxra - e) > ra.ralen / 4 {
            return;
        }
        let r_addr = e.max(ra.maxra) + 1;
        let f = r_addr as u64 * PAGE;
        if self.present(f) {
            return;
        }
        if f < filesize {
            let cap = (max_pf / PAGE) as i64;
            self.ra.ralen = if ra.ralen != 0 { cap.min(ra.ralen << 1) } else { 1 };
            let read_size = (e + 1) - b;
            if read_size > self.ra.ralen {
                self.ra.ralen = read_size.min(cap);
            }
            let n = self.read_prefetch(cx, f, self.ra.ralen as u64 * PAGE, filesize);
            if n != 0 {
                self.ra.maxra = (r_addr + n as i64) - 1;
            }
        }
    }

    /// `cluster_read_copy(vp, uio, req, filesize, flags)` of `req` bytes
    /// at `off`, read-ahead off with `raoff`: what it reads, what it
    /// prefetches and reads ahead, and the pages left resident.
    pub(super) fn read_copy(&mut self, cx: &mut Cx<'_>, mut off: u64, mut req: u64, filesize: u64, raoff: bool) {
        let max_io = max_io_size(true);
        let max_rd_size = max_prefetch(max_io, PREFETCH_MAX);
        let last_request = (off + req).min(filesize);
        let rd_ahead = !(raoff || trunc(last_request) == trunc(off));
        let (b, e) = ((off / PAGE) as i64, (last_request.saturating_sub(1) / PAGE) as i64);
        let prefetch_enabled = true;
        let mut last_ioread: u64 = if rd_ahead && self.ra.ralen != 0 && (self.ra.lastr == b || self.ra.lastr + 1 == b) {
            let l = self.ra.maxra as u64 * PAGE + PAGE;
            if l < off {
                0
            } else {
                l.min(last_request)
            }
        } else {
            0
        };
        let rap = rd_ahead;
        while req > 0 && off < filesize {
            let mut max_size = filesize - off;
            let mut io_size = req.min(max_size);
            while io_size > 0 {
                if last_request != 0 && last_ioread != 0 && last_request > last_ioread {
                    let sp = last_request - last_ioread;
                    if last_ioread.wrapping_sub(off) as i64 <= max_rd_size as i64 && prefetch_enabled {
                        let n = self.read_prefetch(cx, last_ioread, sp.min(max_rd_size), filesize);
                        last_ioread = (last_ioread + n * PAGE).min(last_request);
                    }
                }
                let want = if last_ioread != 0 && io_size > max_io / 4 { max_io / 4 } else { io_size };
                let moved = self.ubc_copy(off, want, false);
                off += moved;
                io_size -= moved;
                req -= moved;
                if moved < want {
                    break;
                }
                if rd_ahead && (io_size == 0 || last_ioread == last_request) {
                    self.read_ahead(cx, b, e, filesize);
                }
            }
            if io_size == 0 {
                if rap {
                    if e < self.ra.lastr {
                        self.ra.maxra = 0;
                    }
                    self.ra.lastr = e;
                }
                break;
            }
            max_size = filesize - off;
            let start_offset = off & (PAGE - 1);
            let upl_f = off - start_offset;
            let io_size = io_size.min(max_rd_size);
            let mut upl_size = round(start_offset + io_size);
            if upl_size > max_io / 4 {
                upl_size = (max_io / 4) & !(PAGE - 1);
                if upl_size == 0 {
                    upl_size = PAGE;
                }
            }
            let pages = upl_size / PAGE;
            self.upl_take(upl_f, upl_f + upl_size);
            let start_pg = (0..pages).find(|&i| !self.present(upl_f + i * PAGE)).unwrap_or(pages);
            let last_pg = (start_pg..pages).find(|&i| self.present(upl_f + i * PAGE)).unwrap_or(pages);
            if start_pg < last_pg {
                let at = upl_f + start_pg * PAGE;
                let n = ((last_pg - start_pg) * PAGE).min(filesize - at);
                cx.read(at, n);
                for p in start_pg..last_pg {
                    self.pages.insert(upl_f + p * PAGE, Page::default());
                }
                if rap && e < self.ra.maxra {
                    self.ra.maxra = 0;
                }
            }
            let uio_last = (last_pg..pages).find(|&i| !self.present(upl_f + i * PAGE)).unwrap_or(pages);
            let val_size = (uio_last * PAGE - start_offset).min(max_size).min(req);
            if off + val_size > last_ioread {
                last_ioread = off + val_size;
            }
            if last_request > last_ioread && prefetch_enabled {
                if last_ioread - (off + val_size) <= upl_size {
                    let n = self.read_prefetch(cx, last_ioread, (last_request - last_ioread).min(max_rd_size), filesize);
                    last_ioread = (last_ioread + n * PAGE).min(last_request);
                }
            } else if off + val_size == last_request {
                if rd_ahead {
                    self.read_ahead(cx, b, e, filesize);
                }
                if rap {
                    if e < self.ra.lastr {
                        self.ra.maxra = 0;
                    }
                    self.ra.lastr = e;
                }
            }
            off += val_size;
            req -= val_size;
        }
    }

    // -- writes --------------------------------------------------------

    /// `cluster_write_copy(vp, uio, req, oldEOF, newEOF, headOff,
    /// tailOff, flags)` of `req` bytes at `off`, then `cluster_write_ext`'s
    /// loop over requests of at most `MAX_IO_REQUEST_SIZE`.
    pub(super) fn write(&mut self, cx: &mut Cx<'_>, off: u64, req: u64, old_eof: u64, new_eof: u64, fl: WriteFlags) {
        // prepare_write's mark of a written file.
        self.written = true;
        let mut at = off;
        let mut left = req;
        let mut old = old_eof;
        let mut head = fl.head;
        while left > 0 && at < new_eof {
            let n = left.min(MAX_IO_REQUEST);
            let last = n == left;
            let f = WriteFlags { head, tail: if last { fl.tail } else { None }, ..fl };
            self.write_copy(cx, at, n, true, old, new_eof, f);
            head = None;
            at += n;
            left -= n;
            if at > old {
                old = at;
            }
        }
    }

    /// `cluster_write(vp, NULL, oldEOF, newEOF, headOff, 0,
    /// IO_HEADZEROFILL)`: `[head, new_eof)` zero-filled in the cache, dirty.
    pub(super) fn zero_fill(&mut self, cx: &mut Cx<'_>, old_eof: u64, new_eof: u64, head: u64) {
        if head < new_eof {
            self.write_copy(cx, new_eof, 0, false, old_eof, new_eof, WriteFlags { head: Some(head), ..WriteFlags::default() });
        }
    }

    /// `cluster_write_copy` of `req` bytes at `off` (the uio's, with
    /// `uio`; without one, `off` is the new end a zero fill runs to).
    #[allow(clippy::too_many_arguments)]
    fn write_copy(&mut self, cx: &mut Cx<'_>, off: u64, req: u64, uio: bool, old_eof: u64, new_eof: u64, fl: WriteFlags) {
        let max_io = max_io_size(false);
        let (mut zero_cnt, mut zero_off) = (0u64, 0u64);
        let (mut zero_cnt1, mut zero_off1) = (0u64, 0u64);
        let mut headzero = fl.head.is_some();
        let mut tailzero = fl.tail.is_some();
        if let Some(h) = fl.head {
            if h < off {
                zero_cnt = off - h;
                zero_off = h;
            }
        } else if uio && off > old_eof {
            zero_off = trunc(off);
            if zero_off >= old_eof {
                zero_cnt = off - zero_off;
                headzero = true;
            }
        }
        if let Some(t) = fl.tail {
            if uio {
                zero_off1 = off + req;
                if zero_off1 < t {
                    zero_cnt1 = t - zero_off1;
                }
            }
        } else if uio && new_eof > old_eof {
            zero_off1 = off + req;
            if zero_off1 == new_eof && zero_off1 & (PAGE - 1) != 0 {
                zero_cnt1 = PAGE - (zero_off1 & (PAGE - 1));
                tailzero = true;
            }
        }
        let mut io_resid = req;
        let mut uio_off = off;
        let mut first_pass = uio;
        let (write_off, write_cnt) = (off, req);
        loop {
            let total0 = io_resid + zero_cnt + zero_cnt1;
            if total0 == 0 {
                break;
            }
            let (mut start_offset, mut upl_f) = if zero_cnt != 0 {
                (zero_off & (PAGE - 1), trunc(zero_off))
            } else if io_resid != 0 {
                (uio_off & (PAGE - 1), trunc(uio_off))
            } else {
                (zero_off1 & (PAGE - 1), trunc(zero_off1))
            };
            let mut total = total0.min(max_io);
            let cl_b = upl_f / PAGE;
            if !(fl.sync || headzero || tailzero) {
                if start_offset + total > max_io {
                    total = max_io - start_offset;
                }
                let moved = self.ubc_copy(uio_off, total, true);
                if moved != 0 {
                    cx.io.logical += moved as i64;
                }
                uio_off += moved;
                io_resid -= moved;
                total -= moved;
                start_offset = uio_off & (PAGE - 1);
                upl_f = uio_off - start_offset;
                if total == 0 {
                    if start_offset != 0 {
                        upl_f += PAGE;
                    }
                    let cl_e = upl_f / PAGE;
                    self.cluster_check(cx, cl_b, cl_e, new_eof, fl, &mut first_pass, write_off, write_cnt);
                    continue;
                }
            }
            let upl_size = round(start_offset + total).min(max_io);
            let pages = upl_size / PAGE;
            let io_size = (upl_size - start_offset).min(total);
            // The pages it gathers: the clustered ones there consumed, and
            // a partial first or last page within the old end not there
            // read first.
            self.upl_take(upl_f, upl_f + upl_size);
            let mut new_pages: Vec<u64> = (0..pages).map(|i| upl_f + i * PAGE).filter(|&p| !self.present(p)).collect();
            // (Read as the file is before the write: its old end.)
            let size = std::mem::replace(&mut cx.size, old_eof);
            if start_offset != 0 && upl_f < old_eof && !self.present(upl_f) {
                cx.read(upl_f, PAGE.min(old_eof - upl_f));
            }
            if (start_offset == 0 || upl_size > PAGE) && (start_offset + io_size) & (PAGE - 1) != 0 {
                let upl_offset = upl_size - PAGE;
                if upl_f + start_offset + io_size < old_eof && !self.present(upl_f + upl_offset) {
                    cx.read(upl_f + upl_offset, PAGE.min(old_eof - (upl_f + upl_offset)));
                }
            }
            cx.size = size;
            for &p in &new_pages {
                self.pages.insert(p, Page::default());
            }
            new_pages.clear();
            let mut xfer = io_size;
            let mut io_offset = start_offset;
            while zero_cnt != 0 && xfer != 0 {
                let z = zero_cnt.min(xfer);
                xfer -= z;
                zero_cnt -= z;
                zero_off += z;
                io_offset += z;
            }
            if xfer != 0 && io_resid != 0 {
                let mv = io_resid.min(xfer);
                // cluster_copy_upl_data: a page it writes that was not
                // dirty counts a page.
                let first = trunc(upl_f + io_offset);
                let mut p = first;
                let mut fresh = 0;
                while p < upl_f + io_offset + mv {
                    if !self.dirty(p) {
                        fresh += 1;
                    }
                    p += PAGE;
                }
                cx.io.logical += (fresh * PAGE) as i64;
                io_resid -= mv;
                xfer -= mv;
                uio_off += mv;
            }
            while xfer != 0 && zero_cnt1 != 0 {
                let z = zero_cnt1.min(xfer);
                xfer -= z;
                zero_cnt1 -= z;
                zero_off1 += z;
            }
            // Committed dirty, the whole UPL.
            for i in 0..pages {
                if let Some(pg) = self.pages.get_mut(&(upl_f + i * PAGE)) {
                    pg.dirty = true;
                }
            }
            let cl_e = (upl_f + upl_size) / PAGE;
            self.cluster_check(cx, cl_b, cl_e, new_eof, fl, &mut first_pass, write_off, write_cnt);
        }
    }

    /// `cluster_write_copy`'s `check_cluster:`: pushed now under
    /// `IO_SYNC`, else kept for write-behind.
    #[allow(clippy::too_many_arguments)]
    fn cluster_check(&mut self, cx: &mut Cx<'_>, b: u64, e: u64, new_eof: u64, fl: WriteFlags, first_pass: &mut bool, write_off: u64, write_cnt: u64) {
        if fl.sync {
            self.push_now(cx, Ext { b, e, nocache: fl.nocache }, new_eof);
        } else {
            self.update_state(cx, Ext { b, e, nocache: fl.nocache }, false, first_pass, write_off, write_cnt, new_eof);
        }
    }

    /// `cluster_update_state_internal(vp, cl, flags, defer_writes, ...)`.
    #[allow(clippy::too_many_arguments)]
    fn update_state(&mut self, cx: &mut Cx<'_>, mut cl: Ext, defer: bool, first_pass: &mut bool, write_off: u64, write_cnt: u64, new_eof: u64) {
        let max_pg = max_io_size(false) / PAGE;
        if self.wb.scmap.is_some() {
            if !cl.nocache {
                self.sparse_add(cx, cl, new_eof);
                return;
            }
            self.wb.clusters.clear();
            self.sparse_push(cx, new_eof, PUSH_ALL, false);
        } else {
            if *first_pass {
                if write_off == self.wb.last_write {
                    self.wb.seq_written += write_cnt;
                } else {
                    self.wb.seq_written = write_cnt;
                }
                self.wb.last_write = write_off + write_cnt;
                *first_pass = false;
            }
            if !self.wb.clusters.is_empty() {
                let mut merged = false;
                for c in self.wb.clusters.iter_mut() {
                    if cl.b >= c.b {
                        if cl.e <= c.b + max_pg {
                            if cl.e > c.e {
                                c.e = cl.e;
                            }
                            merged = true;
                            break;
                        }
                        if cl.b < c.b + max_pg {
                            c.e = c.b + max_pg;
                            cl.b = c.e;
                        }
                    } else {
                        if c.e - cl.b <= max_pg {
                            c.b = cl.b;
                            if cl.e > c.e {
                                c.e = cl.e;
                            }
                            merged = true;
                            break;
                        }
                        if cl.e > c.e.saturating_sub(max_pg) {
                            c.b = c.e - max_pg;
                            cl.e = c.b;
                        }
                    }
                }
                if merged {
                    return;
                }
                if !defer && self.wb.clusters.len() == MAX_CLUSTERS && self.wb.seq_written >= MAX_CLUSTERS as u64 * max_pg * PAGE {
                    let mut n = if MOUNT.minsaturation != 0 { (MOUNT.minsaturation / max_io_size(false)).min(MAX_CLUSTERS as u64) } else { 0 };
                    if n == 0 {
                        n = WRITE_BEHIND;
                    }
                    for _ in 0..n {
                        self.try_push(cx, new_eof, 0, false);
                    }
                }
                if self.wb.clusters.len() >= MAX_CLUSTERS {
                    let free = if !defer { self.try_push(cx, new_eof, if cl.nocache { 0 } else { PUSH_DELAY }, false) } else { 0 };
                    if free == 0 {
                        self.sparse_switch(cx, new_eof);
                        self.sparse_add(cx, cl, new_eof);
                        return;
                    }
                }
            }
        }
        self.wb.clusters.push(cl);
    }

    /// `cluster_try_push(wbp, vp, EOF, push_flag, io_flags)`: the free
    /// slots after.
    fn try_push(&mut self, cx: &mut Cx<'_>, eof: u64, push_flag: u32, sync: bool) -> usize {
        let max_pg = max_io_size(false) / PAGE;
        if self.wb.clusters.is_empty() {
            return MAX_CLUSTERS;
        }
        let mut l: Vec<Ext> = self.wb.clusters.iter().copied().filter(|c| c.b != c.e).collect();
        l.sort_by_key(|c| c.b);
        self.wb.clusters.clear();
        let cl_len = l.len();
        let mut pushed = 0;
        let mut dont_try = false;
        if push_flag & PUSH_DELAY != 0 && cl_len == MAX_CLUSTERS {
            for i in 0..MAX_CLUSTERS - 1 {
                if l[i].e - l[i].b != max_pg || l[i].e != l[i + 1].b {
                    dont_try = true;
                    break;
                }
            }
        }
        if !dont_try {
            for c in l.iter_mut() {
                self.push_now_sync(cx, *c, eof, sync || push_flag & PUSH_SYNC != 0);
                pushed += 1;
                *c = Ext::default();
                if push_flag & PUSH_ALL == 0 {
                    break;
                }
            }
        }
        if cl_len > pushed {
            let left: Vec<Ext> = l.into_iter().filter(|c| c.b != c.e).collect();
            if MAX_CLUSTERS - self.wb.clusters.len() < left.len() {
                self.sparse_switch(cx, eof);
                self.wb.clusters = left;
                self.sparse_switch(cx, eof);
            } else {
                self.wb.clusters.extend(left);
            }
        }
        MAX_CLUSTERS - self.wb.clusters.len()
    }

    fn push_now(&mut self, cx: &mut Cx<'_>, cl: Ext, eof: u64) {
        self.push_now_sync(cx, cl, eof, true);
    }

    /// `cluster_push_now(vp, cl, EOF, flags)`: the dirty pages of the
    /// cluster written, each run of them one I/O, clean after.
    fn push_now_sync(&mut self, cx: &mut Cx<'_>, cl: Ext, eof: u64, _sync: bool) {
        if cl.e == cl.b {
            return;
        }
        let upl_f = cl.b * PAGE;
        let mut upl_size = (cl.e - cl.b) * PAGE;
        if upl_f >= eof {
            return;
        }
        let mut size = if upl_f + upl_size >= eof {
            let s = eof - upl_f;
            upl_size = round(s);
            s
        } else {
            upl_size
        };
        let pages = upl_size / PAGE;
        // UPL_RET_ONLY_DIRTY: the dirty pages are the ones it returns.
        let Some(last) = (0..pages).rev().find(|&i| self.dirty(upl_f + i * PAGE)) else { return };
        let pages = last + 1;
        let mut last_pg = 0;
        while last_pg < pages {
            let Some(start_pg) = (last_pg..pages).find(|&i| self.dirty(upl_f + i * PAGE)) else { break };
            if start_pg > last_pg {
                size = size.saturating_sub((start_pg - last_pg) * PAGE);
            }
            last_pg = (start_pg..pages).find(|&i| !self.dirty(upl_f + i * PAGE)).unwrap_or(pages);
            let io_size = size.min((last_pg - start_pg) * PAGE);
            let at = upl_f + start_pg * PAGE;
            let was = cx.size;
            cx.size = eof;
            cx.write(at, io_size);
            cx.size = was;
            for i in start_pg..last_pg {
                if let Some(p) = self.pages.get_mut(&(upl_f + i * PAGE)) {
                    p.dirty = false;
                }
            }
            size = size.saturating_sub(io_size);
        }
    }

    /// `sparse_cluster_switch`: the clusters' dirty pages into the sparse
    /// map.
    fn sparse_switch(&mut self, cx: &mut Cx<'_>, eof: u64) {
        let clusters = std::mem::take(&mut self.wb.clusters);
        for c in &clusters {
            for b in c.b..c.e {
                if self.dirty(b * PAGE) {
                    self.sparse_add(cx, Ext { b, e: b + 1, nocache: false }, eof);
                }
            }
        }
    }

    /// `sparse_cluster_add`: the pages marked, the map pushed while full.
    fn sparse_add(&mut self, cx: &mut Cx<'_>, cl: Ext, eof: u64) {
        let mut offset = cl.b * PAGE;
        let mut length = (cl.e - cl.b) * PAGE;
        loop {
            let (set, fit) = drt_mark(&mut self.wb.scmap, offset, length, true);
            if fit {
                break;
            }
            let flag = if self.wb.scmap.as_ref().is_some_and(|m| m.modulus == DRT_XLARGE) { PUSH_ALL } else { 0 };
            self.sparse_push(cx, eof, flag, false);
            offset += set * PAGE;
            length -= set * PAGE;
        }
    }

    /// `sparse_cluster_push(wbp, scmap, vp, EOF, push_flag, io_flags)`.
    fn sparse_push(&mut self, cx: &mut Cx<'_>, eof: u64, push_flag: u32, sync: bool) {
        if push_flag & PUSH_ALL != 0 {
            if let Some(m) = self.wb.scmap.as_mut() {
                m.lastclean = 0;
            }
        }
        while let Some((o, l)) = drt_get_cluster(&mut self.wb.scmap) {
            let cl = Ext { b: o / PAGE, e: (o + l) / PAGE, nocache: false };
            self.push_now_sync(cx, cl, eof, sync);
            if push_flag & PUSH_ALL == 0 {
                break;
            }
        }
    }

    /// `vm_object_update` of `[start, end)` for `memory_object_lock_request`
    /// (`MEMORY_OBJECT_RETURN_DIRTY` with `push_dirty`, else
    /// `RETURN_NONE`; `MEMORY_OBJECT_DATA_FLUSH` with `invalidate`): each
    /// run of dirty pages returned is one `vnode_pageout`
    /// (`apfs_vnop_pageout`'s `cluster_pageout` of it, up to the file's
    /// end), clean after; flushed pages go, a dirty one not returned
    /// debited (`TASK_WRITE_INVALIDATED`).
    pub(super) fn lock_request(&mut self, cx: &mut Cx<'_>, start: u64, end: u64, m: super::pagecache::Msync) {
        let offs: Vec<u64> = self.pages.range(start..end).map(|(&o, _)| o).collect();
        let mut run: Option<(u64, u64)> = None;
        let mut runs = Vec::new();
        let mut discarded = 0u64;
        for o in offs {
            let dirty = self.dirty(o);
            if dirty && m.push_dirty {
                run = match run {
                    Some((a, b)) if b == o => Some((a, o + PAGE)),
                    Some(r) => {
                        runs.push(r);
                        Some((o, o + PAGE))
                    }
                    None => Some((o, o + PAGE)),
                };
                continue;
            }
            if m.invalidate {
                if dirty {
                    discarded += 1;
                }
                self.pages.remove(&o);
            }
        }
        runs.extend(run);
        cx.io.logical -= (discarded * PAGE) as i64;
        if !runs.is_empty() {
            // apfs_vnop_pageout's mark of a written file.
            self.written = true;
        }
        for (a, b) in runs {
            // cluster_pageout clips the run at the file's end.
            if a < cx.size {
                cx.write(a, (b - a).min(cx.size - a));
            }
            for o in (a..b).step_by(PAGE as usize) {
                if m.invalidate {
                    self.pages.remove(&o);
                } else if let Some(p) = self.pages.get_mut(&o) {
                    p.dirty = false;
                }
            }
        }
    }

    /// `cluster_push_err(vp, flags)`: every cluster (or the sparse map)
    /// pushed, `IO_SYNC` waiting for them.
    pub(super) fn push(&mut self, cx: &mut Cx<'_>, sync: bool) {
        let eof = cx.size;
        if !sync && self.wb.clusters.is_empty() && self.wb.scmap.is_none() {
            return;
        }
        if self.wb.scmap.is_some() {
            self.sparse_push(cx, eof, PUSH_ALL, sync);
        } else {
            self.try_push(cx, eof, PUSH_ALL, sync);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cx<'a>(size: u64, backed: &'a dyn Fn(u64, u64) -> u64) -> Cx<'a> {
        Cx { size, backed, io: Io::default() }
    }

    #[test]
    fn a_sequential_read_reads_ahead_more_each_time() {
        let all = |a: u64, b: u64| b - a;
        let mut o = Object::default();
        let size = 64 * PAGE;
        // First read of page 0: no read-ahead yet (cl_lastr -1), the page
        // read alone.
        let mut c = cx(size, &all);
        o.read_copy(&mut c, 0, PAGE, size, false);
        assert_eq!(c.io.read, PAGE);
        // Page 0 again whole, then page 1: sequential, a read-ahead of one
        // page after it.
        let mut c = cx(size, &all);
        o.read_copy(&mut c, PAGE, PAGE, size, false);
        assert_eq!(c.io.read, 2 * PAGE, "page 1 and one page ahead");
        assert!(o.pages.get(&(2 * PAGE)).is_some_and(|p| p.clustered));
    }

    #[test]
    fn a_read_past_the_allocation_reads_only_what_it_backs() {
        let all = |a: u64, b: u64| b - a;
        let mut o = Object::default();
        // 5000 bytes: one page, of which two 4 KiB blocks are the file's.
        let mut c = cx(5000, &all);
        o.read_copy(&mut c, 0, 5000, 5000, true);
        assert_eq!(c.io.read, 8192);
        // A hole reads nothing.
        let none = |_: u64, _: u64| 0;
        let mut o = Object::default();
        let mut c = cx(PAGE, &none);
        o.read_copy(&mut c, 0, PAGE, PAGE, true);
        assert_eq!(c.io.read, 0);
    }

    #[test]
    fn writes_count_their_new_dirty_pages_and_wait_for_write_behind() {
        let all = |a: u64, b: u64| b - a;
        let mut o = Object::default();
        let size = 8 * PAGE;
        // A whole-page write over nothing: one page dirtied, its 16 KiB
        // the logical writes; nothing written yet.
        let mut c = cx(size, &all);
        o.write(&mut c, 0, PAGE, size, size, WriteFlags::default());
        assert_eq!((c.io.logical, c.io.written, c.io.read), (PAGE as i64, 0, 0));
        // The same page again, through the cache: the bytes copied count.
        let mut c = cx(size, &all);
        o.write(&mut c, 100, 10, size, size, WriteFlags::default());
        assert_eq!(c.io.logical, 10);
        // A push writes the dirty page and leaves it clean.
        let mut c = cx(size, &all);
        o.push(&mut c, true);
        assert_eq!(c.io.written, PAGE);
        let mut c = cx(size, &all);
        o.push(&mut c, true);
        assert_eq!(c.io.written, 0);
        // A partial write of a page not there within the end reads it
        // first.
        let mut c = cx(size, &all);
        o.write(&mut c, 3 * PAGE + 10, 10, size, size, WriteFlags::default());
        assert_eq!((c.io.read, c.io.logical), (PAGE, PAGE as i64));
        // An IO_SYNC write is written at once.
        let mut c = cx(size, &all);
        o.write(&mut c, 5 * PAGE, PAGE, size, size, WriteFlags { sync: true, ..WriteFlags::default() });
        assert_eq!(c.io.written, PAGE);
    }

    #[test]
    fn four_clusters_then_a_far_write_goes_sparse_and_a_sequential_one_pushes() {
        let all = |a: u64, b: u64| b - a;
        let mb = 1024 * 1024u64;
        // Sequential 1 MiB writes: when four full clusters are held and
        // the writes so far are four clusters' worth, the oldest goes.
        let mut o = Object::default();
        let size = 64 * mb;
        let mut written = 0;
        for i in 0..6 {
            let mut c = cx(size, &all);
            o.write(&mut c, i * mb, mb, size, size, WriteFlags::default());
            written += c.io.written;
        }
        assert!(written >= mb, "write-behind pushed {written}");
        assert!(o.wb.scmap.is_none());
        // Random 16 KiB writes far apart: past four clusters, the sparse
        // map takes them, and a push empties it.
        let mut o = Object::default();
        for i in 0..6 {
            let mut c = cx(size, &all);
            o.write(&mut c, i * 4 * mb, PAGE, size, size, WriteFlags::default());
            assert_eq!(c.io.written, 0);
        }
        assert!(o.wb.scmap.is_some());
        let mut c = cx(size, &all);
        o.push(&mut c, true);
        assert_eq!(c.io.written, 6 * PAGE);
        assert!(o.wb.scmap.is_none());
    }
}
