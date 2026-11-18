//! The device's file pages as its VM keeps them, for the counts
//! `proc_pid_rusage` reads off them: which pages of each vnode's object
//! are resident, which came in clustered and are not yet mapped by any
//! pmap, and what the object's fault history tells `vm_object_cluster_size`
//! (xnu-10063.141.1 `vm_fault.c`, `vm_object.c`, `vm_pageout.c`,
//! `bsd_vm.c`).
//!
//! A task's page-ins (`task->pageins`, `ri_pageins`) are
//! `VM_PAGE_COUNT_AS_PAGEIN`'s, at a fault of the task's:
//!
//! - a page the object did not have, which `vm_fault_page` asks the vnode
//!   pager for (`DBG_PAGEIN_FAULT`, counted at its `done:`);
//! - a page the object has from a cluster (`vmp_clustered`) that no pmap
//!   has mapped (`vmp_pmapped` clear): `vm_fault_enter_prepare` counts it
//!   as the one page-in of its cluster that this fault consumes
//!   (`VM_PAGE_CONSUME_CLUSTERED`); a copy-on-write fault that copies such
//!   a page counts it the same way.
//!
//! The pager's request (`vnode_pager_data_request`, `MAX_UPL_TRANSFER_
//! BYTES` at most) is sized by [`cluster`], `vm_object_cluster_size`, and
//! reads a UPL of the pages absent there (`UPL_RET_ONLY_ABSENT`): each such
//! page is `vmp_clustered`, and its commit puts it on the speculative queue
//! as a new page (`vm_page_speculate(m, TRUE)`: `pages_created`); the
//! faulting page is one of them, consumed at once (`pages_used`). Pages a
//! `read` brings into the cache through a UPL without
//! `UPL_RET_ONLY_ABSENT` are not clustered: mapped later, they are cache
//! hits, no page-in.
//!
//! The device modelled is one that has just booted and runs no pageout
//! (as [`super::footprint`] has it): a page once resident stays, and the
//! free page count is never under `vm_page_free_target`, so
//! `vm_object_cluster_size` never shrinks a default cluster.
//!
//! What reaches here is what gex sees of the device's faults: a task's
//! first touch of a page of a file's mapping by a load or a store (its
//! access check, `darwin_access_fault`), and the pages its `read` and
//! `write` calls move through the cache. What it does not see is
//! reported where the counts are given ([`UNSEEN`]).
//!
//! The same pages give a task's disk I/O (`task_io_stats`: what
//! `spec_strategy` sees its threads issue) and its logical writes (the
//! `logical_writes` ledger). Per 21H461's AppleAPFS (notes in the
//! handoff's Step 24): a file's data reads and writes all reach
//! `spec_strategy` through `apfs_vnop_strategy`'s `buf_strategy` on the
//! device vnode, in the thread that issues them: the pager's cluster at a
//! fault (`cluster_pagein`), `read`'s misses, prefetch and read-ahead
//! (`apfs_vnop_read`'s `cluster_read` with the call's flags), `write`'s
//! reads of partial pages and its pushes (`apfs_vnop_write`'s
//! `cluster_write`: `IO_SYNC` for `O_SYNC` and `O_DSYNC`, else the
//! write-behind), `fsync`'s `cluster_push_err(IO_SYNC)` (`F_FULLFSYNC`
//! and `F_BARRIERFSYNC` too: their transaction is the flusher thread's,
//! kernel_task's), the last writer's close (`apfs_vnop_close`'s
//! `VNOP_FSYNC(MNT_NOWAIT)`), and msync's pageouts (`cluster_pageout`).
//! The pageout thread's and the syncer's writes are kernel_task's, as an
//! aio worker's I/O is. Logical writes are XNU's alone but for
//! AppleAPFS's `obj_dirty`: `cluster_write_copy`'s copies, a vnode page's
//! first store fault, and the dirty pages a truncation or an
//! invalidation discards (a debit).

use super::ubc::FileKey;
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

/// The map's page (`PAGE_SIZE`).
pub const PAGE: u64 = super::mach::PAGE_MASK + 1;

/// `preheat_min_bytes` and `preheat_max_bytes` (`vm_object.c:6553`, not
/// `XNU_TARGET_OS_OSX`).
const PREHEAT_MIN: u64 = 32 * 1024;
const PREHEAT_MAX: u64 = 512 * 1024;

/// `MAX_UPL_TRANSFER_BYTES` (`memory_object_types.h`), the size
/// `vnode_pager_data_request` asks `vm_object_cluster_size` for.
const MAX_UPL_TRANSFER: u64 = 1024 * 1024;

/// `MAX_SEQUENTIAL_RUN` (`vm_fault.c:386`).
const MAX_SEQUENTIAL_RUN: i64 = 1024 * 1024 * 1024;

/// What gex does not see of the device's faults on file pages, as gexc
/// reports it among the stand-ins.
pub const UNSEEN: &str = "the page-ins, reads and logical writes of faults gex does not see (ri_pageins counts a task's first load or store on each page of a file's mapping): instruction fetches from a file's pages (translated code reads the guest's memory directly), first faults on the shared cache's pages (its nested pmap), the kernel's copyin and copyout from a file's mapped pages, exec's and dyld's mappings faulted by the kernel; a store to a shared mapping's page after the page was cleaned (the arm pmap write-protects a cleaned page and arm_fast_fault sets its modify bit: such a page stays clean here, unwritten by a later msync); the files of a cryptex graft, which have no host file (none of their page-ins, reads or writes counted); a write to a file a private mapping has a copy object for (memory_object_control_uiomove declines and cluster_write goes through a UPL: the cache's copy taken as without one); the device's memory pressure, which would age and steal speculative pages, and throttled I/O and a read-ahead context another reader holds, which turn read-ahead off (stand-in: none of these; measure ri_pageins of a fresh process on the device that runs a known binary and maps a known file)";

/// What APFS does on a task's behalf that needs its objects' state, which
/// gex keeps only for disk0 at the restore, not for the booted volumes
/// (host directories), as gexc reports it.
pub const APFS_STAND_IN: &str = "APFS's own I/O and logical writes in a task's threads (they need its objects' state, not kept for the booted volumes, which are host directories): a lookup's metadata reads on an object-cache miss (obj_read through nx_buf_bread, synchronous through spec_strategy in the caller), the pending coalesced metadata writes an F_FULLFSYNC or F_BARRIERFSYNC flushes in the caller when its transaction has nothing dirty (tx_finish's device sync), obj_dirty's TASK_WRITE_METADATA logical write of each metadata object a transaction first dirties (its size rounded up to the container block: inodes, directory records, extents, the atime after a read), fsync's ubc_msync and zero fill of allocated-but-unwritten ranges, the compressed resource fork a compressed file's reads read (decmpfs; the host's copies are not compressed), and the sealed System volume's reads widened to whole hashed regions (stand-in: none of these; measure on the device ri_logical_writes and ri_diskio_* across creating, writing and fsyncing a file against the data written, and across a first read of a compressed system file)";

/// The stand-ins of the cache's counts, for gexc's report at start.
pub fn stand_ins() -> Vec<String> {
    let mut v = vec![UNSEEN.to_string(), APFS_STAND_IN.to_string(), PREPARE_WRITE_STAND_IN.to_string(), super::cluster::MOUNT_STAND_IN.to_string(), SYNC_STAND_IN.to_string()];
    if PROBE.get().is_none() {
        v.push(HOLES_STAND_IN.to_string());
    }
    v
}

/// `vm_behavior_t` of the faulting entry ([`super::vm::behavior`]).
pub use super::vm::behavior;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Page {
    /// `vmp_clustered`: read in by a cluster and not yet consumed.
    pub(super) clustered: bool,
    /// `vmp_pmapped`: some pmap has entered it.
    pub(super) pmapped: bool,
    /// `vmp_dirty` (or the pmap's modify bit): its data differs from
    /// the file's on the device.
    pub(super) dirty: bool,
    /// `vmp_wpmapped`: a write fault has entered it (its first counted a
    /// logical write).
    pub(super) wpmapped: bool,
}

/// A vnode's VM object, as far as the counts go.
#[derive(Debug, Default)]
pub(super) struct Object {
    /// Its resident pages, by object offset.
    pub(super) pages: BTreeMap<u64, Page>,
    /// `sequential` (bytes, negative for a reverse run) and `last_alloc`.
    sequential: i64,
    last_alloc: u64,
    /// `pages_created` (clustered pages committed) and `pages_used`
    /// (those consumed).
    pub(super) pages_created: u32,
    pub(super) pages_used: u32,
    /// The vnode's UBC write-behind and read-ahead state
    /// (`ubc_info`'s `cl_wbehind`, `cl_rahead`).
    pub(super) wb: super::cluster::WriteBehind,
    pub(super) ra: super::cluster::ReadAhead,
    /// `vnode_writecount`: the opens of it for writing.
    writers: u32,
    /// APFS's inode flag 0x10000000 (set by `prepare_write`, a pageout,
    /// a truncation; cleared only at reclaim): its last writer's close
    /// pushes it (`apfs_vnop_close`).
    pub(super) written: bool,
    /// The mount its vnode is on (`v_mount`), as the first open file that
    /// reached it here said ([`on_mount`]).
    on: Option<&'static super::kern::Mount>,
    /// The file's size as the last call that knew it gave it
    /// (`ubc_getsize`): every write, read and truncation gives it, so a
    /// vnode with a page or a cluster to push has one.
    size: Option<u64>,
}

/// What one operation on the cache charges its task: the bytes
/// `spec_strategy` sees read and written for it (`task_io_stats`), and
/// the `logical_writes` ledger's credit (a debit negative).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Io {
    pub read: u64,
    pub written: u64,
    pub logical: i64,
}

static CACHE: Mutex<Option<HashMap<FileKey, Object>>> = Mutex::new(None);

static ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The files are a Darwin system's: their pages are kept here (set at
/// its boot).
pub fn set_on() {
    ON.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Whether [`set_on`] was called.
pub fn on() -> bool {
    ON.load(std::sync::atomic::Ordering::Relaxed)
}

fn with<R>(key: FileKey, f: impl FnOnce(&mut Object) -> R) -> R {
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    f(c.get_or_insert_with(HashMap::new).entry(key).or_default())
}

fn trunc(v: u64) -> u64 {
    v & !(PAGE - 1)
}

fn round(v: u64) -> u64 {
    v.saturating_add(PAGE - 1) & !(PAGE - 1)
}

/// `vm_object_cluster_size(object, &start, &length, fault_info,
/// &io_streaming)` for a fault at `orig` (page-aligned) of an object of
/// `size` bytes, from `vnode_pager_data_request` (`length` in
/// `MAX_UPL_TRANSFER_BYTES`), under an entry of behavior `behavior` that
/// maps `[lo, hi)` of it (`fault_info`'s `lo_offset`, `hi_offset`; its
/// `cluster_size` 0, as `vm_map_lookup_and_lock_object` leaves it): the
/// cluster's start and length.
fn cluster(o: &mut Object, orig: u64, size: u64, behavior: u8, lo: u64, hi: u64) -> (u64, u64) {
    let mut start = orig;
    let mut length = PAGE;
    // No throttled I/O (`vnode_pager_get_throttle_io_limit`) and not an
    // SSD's macOS halving: the preheat bounds as they are.
    let (min_ph, max_ph) = (round(PREHEAT_MIN).max(PAGE), round(PREHEAT_MAX).clamp(PAGE, MAX_UPL_TRANSFER));
    let max_length = MAX_UPL_TRANSFER.min(max_ph);
    if max_length <= PAGE {
        return (start, length);
    }
    let object_size = round(size);
    if orig >= object_size {
        return (start, length);
    }
    if o.pages_used > o.pages_created {
        o.pages_used = 0;
        o.pages_created = 0;
    }
    let (mut sequential_run, mut seq_behavior) = (o.sequential, behavior::SEQUENTIAL);
    if sequential_run < 0 {
        seq_behavior = behavior::RSEQNTL;
        sequential_run = -sequential_run;
    }
    let sequential_run = sequential_run as u64;
    let (mut look_behind, mut look_ahead) = (true, true);
    let cluster_size = 0u64;
    let behavior = match behavior {
        behavior::RANDOM | behavior::SEQUENTIAL | behavior::RSEQNTL => behavior,
        _ => behavior::DEFAULT,
    };
    let mut pre_heat = match behavior {
        behavior::RANDOM => {
            if cluster_size <= PAGE {
                return (start, length);
            }
            cluster_size
        }
        behavior::SEQUENTIAL => {
            look_behind = false;
            if cluster_size == 0 { sequential_run + PAGE } else { cluster_size }
        }
        behavior::RSEQNTL => {
            look_ahead = false;
            if cluster_size == 0 { sequential_run + PAGE } else { cluster_size }
        }
        _ => {
            if sequential_run >= 3 * PAGE {
                if seq_behavior == behavior::SEQUENTIAL {
                    look_behind = false;
                } else {
                    look_ahead = false;
                }
                sequential_run + PAGE
            } else if u64::from(o.pages_created) < 20 * (min_ph / PAGE) {
                // Prime the pump.
                min_ph
            } else {
                let p = max_length * u64::from(o.pages_used) / u64::from(o.pages_created);
                if p < min_ph { min_ph } else { round(p) }
            }
        }
    };
    pre_heat = pre_heat.min(max_length);
    // (A default cluster over min_ph would shrink with the free pages
    // under vm_page_free_target: never, here.)
    let mut target = orig;
    let tail;
    if look_ahead {
        if look_behind {
            let head = trunc(pre_heat / 2);
            target = target.saturating_sub(head);
        }
        if target + pre_heat > object_size {
            pre_heat = round(object_size - target);
        }
        tail = pre_heat - (orig - target) - PAGE;
    } else {
        if pre_heat > target {
            pre_heat = target;
        }
        tail = 0;
    }
    if pre_heat <= PAGE {
        return (start, length);
    }
    if look_behind {
        let mut head = pre_heat - tail - PAGE;
        let mut off = orig.wrapping_sub(PAGE);
        while head > 0 {
            if orig < PAGE || off < lo || o.pages.contains_key(&off) {
                break;
            }
            start = off;
            length += PAGE;
            if off < PAGE {
                break;
            }
            off -= PAGE;
            head -= PAGE;
        }
    }
    if look_ahead {
        let mut t = tail;
        let mut off = orig + PAGE;
        while t > 0 {
            if off >= hi || o.pages.contains_key(&off) {
                break;
            }
            length += PAGE;
            off += PAGE;
            t -= PAGE;
        }
    }
    (start, length.min(max_length))
}

/// `vm_fault_is_sequential(object, offset, behavior)`.
fn is_sequential(o: &mut Object, offset: u64, behavior: u8) {
    let offset = trunc(offset);
    let (last, mut seq) = (o.last_alloc, o.sequential);
    if offset == last && behavior != behavior::RANDOM {
        return;
    }
    let page = PAGE as i64;
    match behavior {
        behavior::RANDOM => seq = 0,
        behavior::SEQUENTIAL => {
            if offset != 0 && last == offset - PAGE {
                if seq < MAX_SEQUENTIAL_RUN {
                    seq += page;
                }
            } else {
                seq = 0;
            }
        }
        behavior::RSEQNTL => {
            if last != 0 && last == offset + PAGE {
                if seq > -MAX_SEQUENTIAL_RUN {
                    seq -= page;
                }
            } else {
                seq = 0;
            }
        }
        _ => {
            if offset != 0 && last == offset - PAGE {
                seq = seq.max(0);
                if seq < MAX_SEQUENTIAL_RUN {
                    seq += page;
                }
            } else if last != 0 && last == offset + PAGE {
                seq = seq.min(0);
                if seq > -MAX_SEQUENTIAL_RUN {
                    seq -= page;
                }
            } else {
                seq = 0;
            }
        }
    }
    o.sequential = seq;
    o.last_alloc = offset;
}

/// What a fault did, for the faulting task's counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fault {
    /// Page-ins it counts against the task.
    pub pageins: u64,
    /// The cluster the pager read, `(start, length)` in the object, when it
    /// had to.
    pub read: Option<(u64, u64)>,
    /// The bytes the pager's read and a first write fault charge.
    pub io: Io,
    /// The page has not been entered for writing by a store's fault
    /// (`vmp_wpmapped` clear): a load's fault grants it read only, so the
    /// next store faults again (`vm_fault_enter_prepare`).
    pub read_only: bool,
}

/// A task's fault on the page at `offset` of file `key`'s object (`size`
/// bytes now), through an entry of behavior `behavior` mapping `[lo, hi)`
/// of it, a store's (`write`) or a load's, through a mapping that maps
/// the object's own pages for writing (`shared`: a store enters the
/// vnode's page; a private mapping's copies it into its own); `backed`
/// gives the bytes of a range the file's allocation backs. The page
/// resident after, and what it counts.
#[allow(clippy::too_many_arguments)]
pub fn fault(key: FileKey, size: u64, offset: u64, behavior: u8, lo: u64, hi: u64, write: bool, shared: bool, backed: &dyn Fn(u64, u64) -> u64) -> Fault {
    let off = trunc(offset);
    with(key, |o| {
        o.size = Some(size);
        let mut out = Fault::default();
        match o.pages.get(&off).copied() {
            Some(p) => {
                // A cache hit: the one page-in of its cluster a first
                // mapping consumes (`vm_fault_enter_prepare`).
                if !p.pmapped && p.clustered {
                    out.pageins = 1;
                    o.pages_used = o.pages_used.wrapping_add(1);
                }
                o.pages.insert(off, Page { clustered: false, pmapped: true, ..p });
                // vm_fault_page's done: of a cache hit, its access pattern.
                is_sequential(o, off, behavior);
            }
            None => {
                let (start, length) = cluster(o, off, size, behavior, lo, hi);
                for p in (start..start + length).step_by(PAGE as usize) {
                    // Every page of the UPL is absent there: clustered,
                    // committed as new speculative pages.
                    o.pages.insert(p, Page { clustered: true, ..Page::default() });
                    o.pages_created = o.pages_created.wrapping_add(1);
                }
                // The faulting page: DBG_PAGEIN_FAULT's one, consumed.
                out.pageins = 1;
                o.pages.insert(off, Page { clustered: false, pmapped: true, ..Page::default() });
                o.pages_used = o.pages_used.wrapping_add(1);
                is_sequential(o, off, behavior);
                out.read = Some((start, length));
                // The pager's cluster_pagein of the UPL, clipped at the
                // file's end (vnode_pagein), one cluster_io.
                if start < size {
                    let mut cx = super::cluster::Cx { size, backed, io: Io::default() };
                    cx.read_pages(start, length.min(size - start));
                    out.io = cx.io;
                }
            }
        }
        // vm_fault_enter_set_mapped: a store's fault entering the vnode's
        // page, the first since it came in, is a deferred logical write
        // of the page; the pmap's modify bit is set with it.
        if write && shared {
            let p = o.pages.get_mut(&off).expect("resident");
            if !p.wpmapped {
                p.wpmapped = true;
                out.io.logical += PAGE as i64;
            }
            p.dirty = true;
        }
        out.read_only = !write && !o.pages.get(&off).is_some_and(|p| p.wpmapped);
        out
    })
}

thread_local! {
    /// The task the running thread's I/O is charged to
    /// (`current_thread()`'s, `thread_update_io_stats`), set as the
    /// thread enters the kernel ([`set_task`]).
    static TASK: std::cell::RefCell<Option<std::sync::Arc<super::rusage::Shared>>> = const { std::cell::RefCell::new(None) };
}

/// The running thread's task is this one, until another is set.
pub fn set_task(t: &std::sync::Arc<super::rusage::Shared>) {
    TASK.with(|c| {
        let mut c = c.borrow_mut();
        if !c.as_ref().is_some_and(|x| std::sync::Arc::ptr_eq(x, t)) {
            *c = Some(std::sync::Arc::clone(t));
        }
    });
}

/// The running thread works for the kernel's own task (an aio worker's
/// request): until [`restore_task`], nothing is charged to its task.
pub fn take_task() -> Option<std::sync::Arc<super::rusage::Shared>> {
    TASK.with(|c| c.borrow_mut().take())
}

/// The task [`take_task`] took back.
pub fn restore_task(t: Option<std::sync::Arc<super::rusage::Shared>>) {
    TASK.with(|c| *c.borrow_mut() = t);
}

/// `VNOP_FSYNC` of `file` with `MNT_WAIT` (`apfs_vnop_fsync`'s
/// `cluster_push_err(vp, IO_SYNC)`), charged to the running thread's
/// task: `fsync`, `fdatasync`, `F_FULLFSYNC` and `F_BARRIERFSYNC` alike
/// (their transaction is the flusher thread's, the kernel's task's).
pub fn fsync(file: &crate::file::OpenFile) {
    if !on() || file.handle.is_stream() {
        return;
    }
    let Some(key) = file.handle.host_id() else { return };
    let size = file.handle.metadata().map_or(0, |m| m.size);
    on_mount(key, super::kern::mount_of_file(file));
    charge(push(key, size, true));
}

/// File `key`'s vnode is on mount `mnt` (its first word wins: a vnode's
/// mount is its own for good).
pub fn on_mount(key: FileKey, mnt: &'static super::kern::Mount) {
    with(key, |o| {
        o.on.get_or_insert(mnt);
    });
}

/// APFS's `VFS_SYNC` of the volume mounted at `mnt` (`apfs_vfsop_sync`,
/// 0xfffffff0066c9d80): `vnode_iterate` of its vnodes with
/// `apfs_sync_callback` (0xfffffff0066d1748), whose data flush
/// (0xfffffff0066a12e4) gives each regular file `cluster_push_err(vp,
/// flags)`, `IO_SYNC` when `waitfor` has `MNT_WAIT` or `MNT_DWAIT`
/// ([`SYNC_STAND_IN`]). What it writes, charged to the running thread's
/// task.
pub fn sync_mount(mnt: &super::kern::Mount, sync: bool) -> Io {
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(map) = c.as_mut() else { return Io::default() };
    let mut io = Io::default();
    for o in map.values_mut().filter(|o| o.on.is_some_and(|m| std::ptr::eq(m, mnt))) {
        let Some(size) = o.size else { continue };
        let none = |_: u64, _: u64| 0;
        let mut cx = super::cluster::Cx { size, backed: &none, io: Io::default() };
        o.push(&mut cx, sync);
        io.read += cx.io.read;
        io.written += cx.io.written;
        io.logical += cx.io.logical;
    }
    io
}

/// The stand-in for what APFS's sync passes over, as gexc reports it.
pub const SYNC_STAND_IN: &str = "apfs_vfsop_sync's data flush of each vnode (0xfffffff0066a12e4): the tests of its inode's flags before the push (+0x98 bits 0, 3, 4, 24 and 46..47, +0x7c bit 5) and what it does after it for an inode with dirty file extents (+0x11c), which read APFS's inode state, not kept here (stand-in: every regular file's write-behind pushed, nothing after; measure ri_diskio_byteswritten of a process that writes a file without fsync, then calls sync, on the device)";

/// `vflush(mp, NULLVP, SKIPSWAP | SKIPSYSTEM | SKIPROOT | FORCECLOSE)` at a
/// forced unmount of `mnt`: `vclean(vp, DOCLOSE)` of each of its vnodes,
/// in use or not, here every file whose object is kept: `VNOP_FSYNC` with
/// `MNT_WAIT` (`apfs_vnop_fsync`'s `cluster_push_err(IO_SYNC)`), then
/// `ubc_msync(vp, 0, ubc_getsize(vp), NULL, UBC_PUSHALL | UBC_INVALIDATE |
/// UBC_SYNC)`; the vnode is reclaimed, its object and its pages gone. (A
/// vnode in use is closed first, `VNOP_CLOSE` with no `FWRITE`, which
/// pushes nothing.) What it writes, charged to the running thread's task.
pub fn vflush(mnt: &super::kern::Mount) -> Io {
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(map) = c.as_mut() else { return Io::default() };
    let keys: Vec<FileKey> = map.iter().filter(|(_, o)| o.on.is_some_and(|m| std::ptr::eq(m, mnt))).map(|(k, _)| *k).collect();
    let mut io = Io::default();
    for k in keys {
        let Some(mut o) = map.remove(&k) else { continue };
        // A vnode no call has given a size has neither a page nor a
        // cluster to push.
        let Some(size) = o.size else { continue };
        let none = |_: u64, _: u64| 0;
        let mut cx = super::cluster::Cx { size, backed: &none, io: Io::default() };
        o.push(&mut cx, true);
        o.lock_request(&mut cx, 0, round(size), Msync { push_dirty: true, invalidate: true });
        io.read += cx.io.read;
        io.written += cx.io.written;
        io.logical += cx.io.logical;
    }
    io
}

/// Charge `io` to the running thread's task.
pub fn charge(io: Io) {
    if io == Io::default() {
        return;
    }
    TASK.with(|c| {
        if let Some(t) = c.borrow().as_ref() {
            t.io_add(io);
        }
    });
}

/// A `read` of `n` bytes at `off` of file `key` (`size` bytes) through
/// the cache (`cluster_read_ext`; `raoff` its `IO_RAOFF`): what it reads,
/// prefetches and reads ahead.
pub fn read(key: FileKey, off: u64, n: u64, size: u64, raoff: bool, backed: &dyn Fn(u64, u64) -> u64) -> Io {
    if n == 0 || off >= size {
        return Io::default();
    }
    with(key, |o| {
        o.size = Some(size);
        let mut cx = super::cluster::Cx { size, backed, io: Io::default() };
        o.read_copy(&mut cx, off, n, size, raoff);
        cx.io
    })
}

/// A `write` of `n` bytes at `off` of file `key` through the cache
/// (`cluster_write_ext`), the file `old_eof` bytes before and `new_eof`
/// after: what it reads first, writes at once and pushes behind it, and
/// its logical writes. `backed` is the allocation before the write.
pub fn write(key: FileKey, off: u64, n: u64, old_eof: u64, new_eof: u64, flags: super::cluster::WriteFlags, backed: &dyn Fn(u64, u64) -> u64) -> Io {
    if n == 0 {
        return Io::default();
    }
    with(key, |o| {
        o.size = Some(new_eof);
        let mut cx = super::cluster::Cx { size: new_eof, backed, io: Io::default() };
        o.write(&mut cx, off, n, old_eof, new_eof, flags);
        cx.io
    })
}

/// `apfs_vnop_write` (0xfffffff006691308) of `n` bytes at `off` of file
/// `key` (`old` bytes before; `sync`: `IO_SYNC`, `nocache`: `IO_NOCACHE`),
/// `backed` its allocation before the write: `prepare_write`'s zero-fill
/// flags, its `cluster_write` of the data, then of the gap a write past
/// the end leaves ([`PREPARE_WRITE_STAND_IN`]).
pub fn apfs_write(key: FileKey, off: u64, n: u64, old: u64, sync: bool, nocache: bool, backed: &dyn Fn(u64, u64) -> u64) -> Io {
    use super::cluster::{WriteFlags, DEVBLOCK};
    if n == 0 {
        return Io::default();
    }
    let end = off + n;
    let new = old.max(end);
    let alloc = old.div_ceil(DEVBLOCK) * DEVBLOCK;
    let blk = |x: u64| x & !(DEVBLOCK - 1);
    // IO_HEADZEROFILL: a start inside a block that is new (past the
    // allocation) or a hole; IO_TAILZEROFILL: an end inside an allocated
    // block, or a new end off a page boundary.
    let head = (off % DEVBLOCK != 0 && (off >= alloc || backed(blk(off), blk(off) + DEVBLOCK) == 0)).then(|| blk(off));
    let tail = ((end % DEVBLOCK != 0 && end < alloc) || (new > old && new % PAGE != 0)).then(|| end.div_ceil(DEVBLOCK) * DEVBLOCK);
    let flags = WriteFlags { sync, nocache, head, tail };
    with(key, |o| {
        o.size = Some(new);
        let mut cx = super::cluster::Cx { size: new, backed, io: Io::default() };
        o.write(&mut cx, off, n, old, new, flags);
        // The rest of the old last page, from the old end, when the write
        // starts past it.
        if off > old {
            let zero_end = round(old).min(blk(off));
            o.zero_fill(&mut cx, new, zero_end, old);
        }
        cx.io
    })
}

/// The stand-in for `prepare_write`'s arithmetic, as gexc reports it.
pub const PREPARE_WRITE_STAND_IN: &str = "apfs_vnop_write's prepare_write (0xfffffff0066a4024) offsets, read from a decompile only: IO_HEADZEROFILL's headOff and IO_TAILZEROFILL's tailOff, and the zero fill a write past the end makes of the gap (stand-in: headOff the start's 4 KiB block where the start is unaligned in a new block or a hole, tailOff the end rounded up to 4 KiB where it is unaligned inside the allocation or the new end is off a page, the gap from the old end to the end of its page or the write's block; measure ri_logical_writes and ri_diskio_byteswritten on the device across an fsync'd unaligned write past a file's end, against an aligned one)";

/// `cluster_push_err(vp, sync ? IO_SYNC : 0)` of file `key` (`size`
/// bytes): its write-behind clusters, or its sparse map, written.
pub fn push(key: FileKey, size: u64, sync: bool) -> Io {
    with(key, |o| {
        o.size = Some(size);
        let none = |_: u64, _: u64| 0;
        let mut cx = super::cluster::Cx { size, backed: &none, io: Io::default() };
        o.push(&mut cx, sync);
        cx.io
    })
}

/// What `ubc_msync` asks of `memory_object_lock_request` over a range.
#[derive(Clone, Copy, Debug, Default)]
pub struct Msync {
    /// `UBC_PUSHDIRTY` (`MEMORY_OBJECT_RETURN_DIRTY`): the dirty pages
    /// returned to the pager, written.
    pub push_dirty: bool,
    /// `UBC_INVALIDATE` (`MEMORY_OBJECT_DATA_FLUSH`): the pages discarded
    /// after.
    pub invalidate: bool,
}

/// `memory_object_lock_request` over `[start, end)` of file `key`
/// (`size` bytes) as `vm_object_update` makes it: each run of dirty pages
/// returned is one `vnode_pageout`, written up to the file's end, clean
/// after; with `invalidate` the pages go, a dirty one not returned a
/// debit of the logical writes (`TASK_WRITE_INVALIDATED`).
pub fn msync(key: FileKey, size: u64, start: u64, end: u64, m: Msync) -> Io {
    with(key, |o| {
        o.size = Some(size);
        let none = |_: u64, _: u64| 0;
        let mut cx = super::cluster::Cx { size, backed: &none, io: Io::default() };
        o.lock_request(&mut cx, trunc(start), round(end), m);
        cx.io
    })
}

/// A probe of the host's file open at a descriptor: the bytes of
/// `[a, b)` that hold data (`SEEK_DATA`, `SEEK_HOLE`), none where the host
/// cannot tell.
pub type DataProbe = fn(i32, u64, u64) -> Option<u64>;

static PROBE: std::sync::OnceLock<DataProbe> = std::sync::OnceLock::new();

/// The host's probe of its files' holes ([`DataProbe`]).
pub fn set_data_probe(p: DataProbe) {
    let _ = PROBE.set(p);
}

/// The bytes of `[a, b)` of the host file open at `fd` its allocation
/// backs (`VNOP_BLOCKMAP`'s extents: a hole maps to no block); all of
/// them where the host cannot tell ([`HOLES_STAND_IN`]).
pub fn backed(fd: Option<i32>, a: u64, b: u64) -> u64 {
    match (fd, PROBE.get()) {
        (Some(fd), Some(p)) => p(fd, a, b).unwrap_or(b - a),
        _ => b - a,
    }
}

/// The stand-in for a host that cannot tell a file's holes, as gexc
/// reports it.
pub const HOLES_STAND_IN: &str = "a file's holes where the host cannot tell them (SEEK_DATA/SEEK_HOLE): read as allocated, its bytes read from the device";

/// `vn_open` of file `key` for writing: `vnode_writecount` rises.
pub fn open_writer(key: FileKey) {
    with(key, |o| o.writers += 1);
}

/// `vn_close` of an open of file `key` (`size` bytes; `writer`: one for
/// writing): `apfs_vnop_close`'s push of a regular file written since it
/// came in, by its last writer (`VNOP_FSYNC(MNT_NOWAIT)`: an
/// asynchronous `cluster_push_err`), then `vnode_rele`'s drop of the
/// write count.
pub fn close(key: FileKey, size: u64, writer: bool) -> Io {
    with(key, |o| {
        o.size = Some(size);
        let mut io = Io::default();
        if writer {
            if o.written && o.writers == 1 {
                let none = |_: u64, _: u64| 0;
                let mut cx = super::cluster::Cx { size, backed: &none, io: Io::default() };
                o.push(&mut cx, false);
                io = cx.io;
            }
            o.writers = o.writers.saturating_sub(1);
        }
        io
    })
}

/// The file shrank to `size`: its pages past it go (`ubc_setsize`'s
/// `memory_object_lock_request` with `MEMORY_OBJECT_DATA_FLUSH` and
/// `RETURN_NONE`), each dirty one a debit of the logical writes.
pub fn truncate(key: FileKey, size: u64) -> Io {
    with(key, |o| {
        o.size = Some(size);
        let cut = round(size);
        let none = |_: u64, _: u64| 0;
        let mut cx = super::cluster::Cx { size, backed: &none, io: Io::default() };
        o.lock_request(&mut cx, cut, u64::MAX & !(PAGE - 1), Msync { push_dirty: false, invalidate: true });
        o.written = true;
        cx.io
    })
}

impl crate::syscalls::Kernel {
    /// This task's fault on the page at `at`, which its pmap enters now
    /// (its first touch there, by a load or a store): where a file's
    /// object is mapped there, the page-ins the device's `vm_fault`
    /// counts against the task.
    /// `vm_map_msync` of `[start, end)` (within one entry) on its vnode
    /// object: `memory_object_lock_request` with `push_dirty`
    /// (`RETURN_DIRTY`) and `invalidate` (`DATA_FLUSH`), its I/O charged to
    /// this task. A private mapping's entry has the vnode's object only
    /// until its first write shadows it, then an internal object with no
    /// pager, which msync passes over.
    pub(crate) fn darwin_msync_pages(&self, start: u64, end: u64, push_dirty: bool, invalidate: bool) {
        if !on() {
            return;
        }
        let Some(e) = self.dtask.vm.at_or_after(start).filter(|e| e.start <= start && e.attrs.obj != 0) else { return };
        let Some(v) = super::ubc::vnode(e.attrs.obj) else { return };
        let shared = e.attrs.kind == super::vm::kind::FILE_SHARED && !e.attrs.cow;
        if !shared {
            let mm = self.mem.lock();
            let shift = gex_abi::PERM_PAGE_SHIFT;
            let shadowed = (e.start >> shift..e.end.div_ceil(1 << shift)).any(|pg| !mm.is_copy_pending(pg) && !mm.is_unentered(pg) && !mm.is_absent(pg));
            if shadowed {
                return;
            }
        }
        let off = e.offset + (start - e.start);
        let io = msync(v.key, v.pager_size(), off, off + (end - start), Msync { push_dirty, invalidate });
        self.dtask.rusage.io_add(io);
    }

    /// Whether the page is to be entered read only ([`Fault::read_only`],
    /// through a mapping that may write the vnode's pages).
    pub(crate) fn darwin_file_page_fault(&self, at: u64, write: bool) -> bool {
        if !on() {
            return false;
        }
        let Some(e) = self.dtask.vm.at_or_after(at).filter(|e| e.start <= at && e.attrs.obj != 0) else { return false };
        let Some(v) = super::ubc::vnode(e.attrs.obj) else { return false };
        let offset = e.offset + (at - e.start);
        let shared = e.attrs.kind == super::vm::kind::FILE_SHARED && !e.attrs.cow;
        let fd = v.host_fd();
        let f = fault(v.key, v.pager_size(), offset, e.attrs.behavior, e.offset, e.offset + (e.end - e.start), write, shared, &|a, b| backed(fd, a, b));
        if f.pageins != 0 {
            self.dtask.rusage.pageins.fetch_add(f.pageins, std::sync::atomic::Ordering::AcqRel);
        }
        self.dtask.rusage.io_add(f.io);
        shared && f.read_only
    }
}

#[cfg(test)]
pub(crate) fn reset() {
    *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: fn(u64, u64) -> u64 = |a, b| b - a;

    fn key(n: u64) -> FileKey {
        (0xfeed, n, 1)
    }

    fn mount(on: &'static str) -> &'static super::super::kern::Mount {
        use super::super::kern::{Fs, From, Mount};
        Box::leak(Box::new(Mount::new(on, From::Volume(1), 0x1a00_0042, 0, Fs::Apfs, None, 0, Some(false))))
    }

    /// A mount's sync pushes the write-behind of its own files alone; its
    /// forced unmount's vflush pushes what is left, synchronously, and
    /// reclaims the vnodes: their objects go.
    #[test]
    fn a_mounts_sync_and_vflush_push_its_own_files() {
        let (on, other) = (mount("/private/var/sync-a"), mount("/private/var/sync-b"));
        let (k, j) = (key(901), key(902));
        on_mount(k, on);
        on_mount(j, other);
        let size = 8 * PAGE;
        assert_eq!(write(k, 0, PAGE, size, size, super::super::cluster::WriteFlags::default(), &ALL).written, 0);
        assert_eq!(write(j, 0, PAGE, size, size, super::super::cluster::WriteFlags::default(), &ALL).written, 0);
        assert_eq!(sync_mount(on, false).written, PAGE);
        assert_eq!(sync_mount(on, false).written, 0, "pushed, clean");
        assert_eq!(vflush(on).written, 0);
        assert_eq!(vflush(other).written, PAGE, "the other mount's file, pushed at its unmount");
        let c = CACHE.lock().unwrap();
        let map = c.as_ref().unwrap();
        assert!(!map.contains_key(&k) && !map.contains_key(&j), "reclaimed");
    }

    #[test]
    fn a_first_fault_reads_a_primed_cluster_around_it_and_counts_one() {
        // A 1 MiB file, a fault in its middle: pages_created is under 40,
        // so the cluster is preheat_min (32 KiB, two pages), centred: the
        // page before and the faulting one.
        let k = key(1);
        let f = fault(k, 1 << 20, 10 * PAGE, behavior::DEFAULT, 0, 1 << 20, false, false, &ALL);
        assert_eq!(f, Fault { pageins: 1, read: Some((9 * PAGE, 2 * PAGE)), io: Io { read: 2 * PAGE, ..Io::default() }, read_only: true });
        // The other page of the cluster: resident and clustered, unmapped:
        // its first fault is a page-in, its second nothing.
        assert_eq!(fault(k, 1 << 20, 9 * PAGE, behavior::DEFAULT, 0, 1 << 20, false, false, &ALL), Fault { pageins: 1, read: None, io: Io::default(), read_only: true });
        assert_eq!(fault(k, 1 << 20, 9 * PAGE, behavior::DEFAULT, 0, 1 << 20, false, false, &ALL), Fault { pageins: 0, read: None, io: Io::default(), read_only: true });
        assert_eq!(fault(k, 1 << 20, 10 * PAGE, behavior::DEFAULT, 0, 1 << 20, false, false, &ALL), Fault { pageins: 0, read: None, io: Io::default(), read_only: true });
    }

    #[test]
    fn a_sequential_run_reads_ahead_and_a_read_is_no_pagein() {
        let k = key(2);
        let size = 64 * PAGE;
        // Faults at 0, 1, 2, 3 ...: after three pages in a row the run
        // reads ahead only, run + a page.
        let mut reads = Vec::new();
        for i in 0..8 {
            let f = fault(k, size, i * PAGE, behavior::DEFAULT, 0, size, false, false, &ALL);
            assert_eq!(f.pageins, 1, "page {i}");
            reads.push(f.read);
        }
        // 0: the cluster can't look behind 0; preheat 2 pages centred at
        // 0 starts at 0: pages 0 and 1. 1: clustered, consumed. 2: absent,
        // sequential run 1 page (< 3): primed 2 pages centred: 1 is
        // resident so only 2 itself and 3.
        assert_eq!(reads[0], Some((0, 2 * PAGE)));
        assert_eq!(reads[1], None);
        assert_eq!(reads[2], Some((2 * PAGE, PAGE)));
        // A read's pages are resident but never clustered: a fault on one
        // is a cache hit.
        let k2 = key(3);
        assert_eq!(read(k2, 100, 3 * PAGE, size, true, &ALL).read, 4 * PAGE);
        assert_eq!(fault(k2, size, PAGE, behavior::DEFAULT, 0, size, false, false, &ALL), Fault { pageins: 0, read: None, io: Io::default(), read_only: true });
        assert_eq!(read(k2, 0, PAGE, size, true, &ALL), Io::default());
    }

    #[test]
    fn random_behavior_reads_one_page_and_the_entry_bounds_the_cluster() {
        let k = key(4);
        assert_eq!(fault(k, 1 << 20, 10 * PAGE, behavior::RANDOM, 0, 1 << 20, false, false, &ALL).read, Some((10 * PAGE, PAGE)));
        // An entry mapping from page 10 only: no look behind it.
        let k = key(5);
        assert_eq!(fault(k, 1 << 20, 10 * PAGE, behavior::DEFAULT, 10 * PAGE, 1 << 20, false, false, &ALL).read, Some((10 * PAGE, PAGE)));
        // Past the end of the file: the page alone.
        let k = key(6);
        assert_eq!(fault(k, PAGE, 0, behavior::DEFAULT, 0, 4 * PAGE, false, false, &ALL).read, Some((0, PAGE)));
        truncate(k, 0);
        assert_eq!(fault(k, PAGE, 0, behavior::DEFAULT, 0, 4 * PAGE, false, false, &ALL).pageins, 1);
    }

    #[test]
    fn a_first_store_fault_counts_a_page_and_a_truncation_takes_dirty_pages_back() {
        let k = key(7);
        let size = 4 * PAGE;
        // A store's fault entering the vnode's page: a page's logical
        // write, once; a private mapping's store copies it, none.
        assert_eq!(fault(k, size, 0, behavior::DEFAULT, 0, size, true, true, &ALL).io.logical, PAGE as i64);
        assert_eq!(fault(k, size, 0, behavior::DEFAULT, 0, size, true, true, &ALL).io.logical, 0);
        assert_eq!(fault(k, size, 3 * PAGE, behavior::DEFAULT, 0, size, true, false, &ALL).io.logical, 0);
        // The dirty page goes with the file's end: taken back.
        assert_eq!(truncate(k, 0).logical, -(PAGE as i64));
        // A hole reads nothing.
        let k = key(8);
        assert_eq!(fault(k, size, 0, behavior::RANDOM, 0, size, false, false, &|_, _| 0).io.read, 0);
    }
}
