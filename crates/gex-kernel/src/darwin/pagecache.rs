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
pub const UNSEEN: &str = "the page-ins of faults gex does not see (ri_pageins counts a task's first load or store on each page of a file's mapping): instruction fetches from a file's pages (translated code reads the guest's memory directly), first faults on the shared cache's pages (its nested pmap), the kernel's copyin and copyout from a file's mapped pages, exec's and dyld's mappings faulted by the kernel; the read-ahead of read(2) (cluster_read_ahead: its pages come in clustered, each a page-in when first mapped; its prefetch size is the mount's I/O size and speculative_prefetch_max); and the device's memory pressure, which would age and steal speculative pages (stand-in: none of these counted, no read-ahead, no page stolen; measure ri_pageins of a fresh process on the device that runs a known binary and maps a known file)";

/// `vm_behavior_t` of the faulting entry ([`super::vm::behavior`]).
pub use super::vm::behavior;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Page {
    /// `vmp_clustered`: read in by a cluster and not yet consumed.
    clustered: bool,
    /// `vmp_pmapped`: some pmap has entered it.
    pmapped: bool,
}

/// A vnode's VM object, as far as the counts go.
#[derive(Debug, Default)]
struct Object {
    /// Its resident pages, by object offset.
    pages: BTreeMap<u64, Page>,
    /// `sequential` (bytes, negative for a reverse run) and `last_alloc`.
    sequential: i64,
    last_alloc: u64,
    /// `pages_created` (clustered pages committed) and `pages_used`
    /// (those consumed).
    pages_created: u32,
    pages_used: u32,
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
}

/// A task's fault on the page at `offset` of file `key`'s object (`size`
/// bytes now), through an entry of behavior `behavior` mapping `[lo, hi)`
/// of it: the page resident after, and what it counts.
pub fn fault(key: FileKey, size: u64, offset: u64, behavior: u8, lo: u64, hi: u64) -> Fault {
    let off = trunc(offset);
    with(key, |o| {
        let mut out = Fault::default();
        match o.pages.get(&off).copied() {
            Some(p) => {
                // A cache hit: the one page-in of its cluster a first
                // mapping consumes (`vm_fault_enter_prepare`).
                if !p.pmapped && p.clustered {
                    out.pageins = 1;
                    o.pages_used = o.pages_used.wrapping_add(1);
                }
                o.pages.insert(off, Page { clustered: false, pmapped: true });
                // vm_fault_page's done: of a cache hit, its access pattern.
                is_sequential(o, off, behavior);
            }
            None => {
                let (start, length) = cluster(o, off, size, behavior, lo, hi);
                for p in (start..start + length).step_by(PAGE as usize) {
                    // Every page of the UPL is absent there: clustered,
                    // committed as new speculative pages.
                    o.pages.insert(p, Page { clustered: true, pmapped: false });
                    o.pages_created = o.pages_created.wrapping_add(1);
                }
                // The faulting page: DBG_PAGEIN_FAULT's one, consumed.
                out.pageins = 1;
                o.pages.insert(off, Page { clustered: false, pmapped: true });
                o.pages_used = o.pages_used.wrapping_add(1);
                is_sequential(o, off, behavior);
                out.read = Some((start, length));
            }
        }
        out
    })
}

/// A `read` or `write` that moved `[offset, offset + len)` of file `key`
/// through the cache by a UPL of its own (`cluster_read_copy`,
/// `cluster_write_copy`): its pages resident, not clustered; a page there
/// from a cluster stays one. The pages that were not resident.
pub fn through_cache(key: FileKey, offset: u64, len: u64) -> Vec<u64> {
    if len == 0 {
        return Vec::new();
    }
    with(key, |o| {
        let mut missed = Vec::new();
        for p in (trunc(offset)..round(offset + len)).step_by(PAGE as usize) {
            if !o.pages.contains_key(&p) {
                o.pages.insert(p, Page::default());
                missed.push(p);
            }
        }
        missed
    })
}

/// The file shrank to `size`: its pages past it go (`ubc_setsize`'s
/// `memory_object_lock_request` with `MEMORY_OBJECT_DATA_FLUSH`).
pub fn truncate(key: FileKey, size: u64) {
    with(key, |o| {
        let cut = round(size);
        o.pages.retain(|&p, _| p < cut);
    });
}

impl crate::syscalls::Kernel {
    /// This task's fault on the page at `at`, which its pmap enters now
    /// (its first touch there, by a load or a store): where a file's
    /// object is mapped there, the page-ins the device's `vm_fault`
    /// counts against the task.
    pub(crate) fn darwin_file_page_fault(&self, at: u64) {
        if !on() {
            return;
        }
        let Some(e) = self.dtask.vm.at_or_after(at).filter(|e| e.start <= at && e.attrs.obj != 0) else { return };
        let Some(v) = super::ubc::vnode(e.attrs.obj) else { return };
        let offset = e.offset + (at - e.start);
        let f = fault(v.key, v.pager_size(), offset, e.attrs.behavior, e.offset, e.offset + (e.end - e.start));
        if f.pageins != 0 {
            self.dtask.rusage.pageins.fetch_add(f.pageins, std::sync::atomic::Ordering::AcqRel);
        }
    }
}

#[cfg(test)]
pub(crate) fn reset() {
    *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u64) -> FileKey {
        (0xfeed, n, 1)
    }

    #[test]
    fn a_first_fault_reads_a_primed_cluster_around_it_and_counts_one() {
        // A 1 MiB file, a fault in its middle: pages_created is under 40,
        // so the cluster is preheat_min (32 KiB, two pages), centred: the
        // page before and the faulting one.
        let k = key(1);
        let f = fault(k, 1 << 20, 10 * PAGE, behavior::DEFAULT, 0, 1 << 20);
        assert_eq!(f, Fault { pageins: 1, read: Some((9 * PAGE, 2 * PAGE)) });
        // The other page of the cluster: resident and clustered, unmapped:
        // its first fault is a page-in, its second nothing.
        assert_eq!(fault(k, 1 << 20, 9 * PAGE, behavior::DEFAULT, 0, 1 << 20), Fault { pageins: 1, read: None });
        assert_eq!(fault(k, 1 << 20, 9 * PAGE, behavior::DEFAULT, 0, 1 << 20), Fault { pageins: 0, read: None });
        assert_eq!(fault(k, 1 << 20, 10 * PAGE, behavior::DEFAULT, 0, 1 << 20), Fault { pageins: 0, read: None });
    }

    #[test]
    fn a_sequential_run_reads_ahead_and_a_read_is_no_pagein() {
        let k = key(2);
        let size = 64 * PAGE;
        // Faults at 0, 1, 2, 3 ...: after three pages in a row the run
        // reads ahead only, run + a page.
        let mut reads = Vec::new();
        for i in 0..8 {
            let f = fault(k, size, i * PAGE, behavior::DEFAULT, 0, size);
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
        assert_eq!(through_cache(k2, 100, 3 * PAGE), vec![0, PAGE, 2 * PAGE, 3 * PAGE]);
        assert_eq!(fault(k2, size, PAGE, behavior::DEFAULT, 0, size), Fault { pageins: 0, read: None });
        assert!(through_cache(k2, 0, PAGE).is_empty());
    }

    #[test]
    fn random_behavior_reads_one_page_and_the_entry_bounds_the_cluster() {
        let k = key(4);
        assert_eq!(fault(k, 1 << 20, 10 * PAGE, behavior::RANDOM, 0, 1 << 20).read, Some((10 * PAGE, PAGE)));
        // An entry mapping from page 10 only: no look behind it.
        let k = key(5);
        assert_eq!(fault(k, 1 << 20, 10 * PAGE, behavior::DEFAULT, 10 * PAGE, 1 << 20).read, Some((10 * PAGE, PAGE)));
        // Past the end of the file: the page alone.
        let k = key(6);
        assert_eq!(fault(k, PAGE, 0, behavior::DEFAULT, 0, 4 * PAGE).read, Some((0, PAGE)));
        truncate(k, 0);
        assert_eq!(fault(k, PAGE, 0, behavior::DEFAULT, 0, 4 * PAGE).pageins, 1);
    }
}
