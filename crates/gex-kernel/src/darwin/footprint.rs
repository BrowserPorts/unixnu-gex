//! A task's `phys_footprint`: its ledger entry (`ledger.c`), the limit
//! `task_set_phys_footprint_limit_internal` sets on it, and what crossing
//! it does (`task_footprint_exceeded`, `memorystatus_on_ledger_footprint_
//! exceeded`, `memorystatus_warn_process`).
//!
//! The balance is what the task's pmap holds (`pmap.c`: its own pages,
//! internal and not reusable, and the page tables mapping its pages), kept
//! in a record of the task's pages ([`Pmap`]) rather than credited page by
//! page: a page the task touched is seen in the host's VM, which faults it
//! in. The device modelled runs no pageout (its pressure level stays
//! normal, `kfilt`), so a page once entered stays the task's until a
//! kernel operation removes it, and a page table stays until a
//! `pmap_remove` empties it: what the host compresses or reclaims of a
//! clean page (a page read and never written, a page `MADV_FREE` killed, a
//! file's page) changes nothing here. Between kernel operations the
//! balance can then only grow, so the ledger's peaks
//! (`LF_TRACKING_MAX`) are exact when the task's pages are looked at
//! before each operation that releases any ([`Kernel::darwin_footprint_
//! release`]) and whenever the ledger is read. What the host reclaims of
//! a page the task touched between two looks is not seen.
//!
//! A limit is crossed when a look says so, on the task's thread calls
//! every [`SAMPLE`], before a release and at a read, not at the page that
//! crossed it: the host takes the task's page faults.

use crate::page_state as ps;
use crate::syscalls::Kernel;
use crate::GuestMem;
use std::time::{Duration, Instant};

/// How often a task measures its footprint.
pub const SAMPLE: Duration = Duration::from_millis(100);

/// `LEDGER_LIMIT_INFINITY`.
pub const LIMIT_INFINITY: i64 = i64::MAX;
/// `max_task_footprint`: j120's `kern.max_task_pmem`, 3072 MB.
pub const MAX_TASK_FOOTPRINT: i64 = 3072 << 20;
/// `max_task_footprint_warning_level`: 100 MB below the limit on a
/// device with at least 1 GB, as a percentage.
pub const MAX_TASK_FOOTPRINT_WARNING_LEVEL: u32 = ((3072 - 100) * 100) / 3072;
/// `PHYS_FOOTPRINT_WARNING_LEVEL`.
pub const PHYS_FOOTPRINT_WARNING_LEVEL: u32 = 80;
/// `LEDGER_PERCENT_NONE`.
const PERCENT_NONE: u32 = u16::MAX as u32;

/// The map's page (16 KiB) and arm64's tables over it: a leaf table maps
/// 32 MB, a twig table 64 GB; the root, of 8 entries, is 64 bytes
/// (`__ARM64_PMAP_SUBPAGE_L1__`, `T0SZ_BOOT` 25).
pub(crate) const PAGE: u64 = super::mach::PAGE_MASK + 1;
const L3_SHIFT: u32 = 25;
const L2_SHIFT: u32 = 36;
const ROOT_SIZE: u64 = 64;

/// The `phys_footprint` entry of a task's ledger, and the task's memory
/// limit state.
#[derive(Clone, Copy, Debug)]
pub struct Ledger {
    pub balance: i64,
    pub lifetime_max: i64,
    /// `le_interval_max` (CONFIG_LEDGER_INTERVAL_MAX, which the device's
    /// kernel has: `ledger_get_interval_max` at 0xfffffff00721986c).
    pub interval_max: i64,
    pub limit: i64,
    /// `le_warn_percent`: the warning level in 16.16, or none.
    warn_percent: u32,
    /// `LF_CALLED_BACK`, `LF_WARNED`.
    called_back: bool,
    warned: bool,
    pub memlimit_active: bool,
    pub memlimit_fatal: bool,
    /// `memlimit_{active,inactive}_exc_resource`.
    exc_active: bool,
    exc_inactive: bool,
}

/// `task_create_internal`'s ledger: the system-wide limit at the default
/// warning level, neither active nor fatal.
impl Default for Ledger {
    fn default() -> Ledger {
        let mut l = Ledger { balance: 0, lifetime_max: 0, interval_max: 0, limit: LIMIT_INFINITY, warn_percent: PERCENT_NONE, called_back: false, warned: false, memlimit_active: false, memlimit_fatal: false, exc_active: false, exc_inactive: false };
        l.set_limit(MAX_TASK_FOOTPRINT, PHYS_FOOTPRINT_WARNING_LEVEL);
        l
    }
}

/// A ledger callback (`LEDGER_WARNING_*`, or the limit itself).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Crossing {
    Exceeded,
    RoseAbove,
    DippedBelow,
}

impl Ledger {
    /// `ledger_set_limit`.
    fn set_limit(&mut self, limit: i64, warn_level: u32) {
        self.limit = limit;
        self.called_back = false;
        self.warned = false;
        self.warn_percent = if warn_level != 0 { warn_level * (1 << 16) / 100 } else { PERCENT_NONE };
    }

    /// `task_set_phys_footprint_limit_internal(new_limit_mb, active,
    /// fatal)`: the old limit in MB.
    pub fn set_footprint_limit(&mut self, new_limit_mb: i32, active: bool, fatal: bool) -> i32 {
        let old = (self.limit >> 20) as i32;
        if new_limit_mb == -1 {
            self.set_limit(MAX_TASK_FOOTPRINT, MAX_TASK_FOOTPRINT_WARNING_LEVEL);
            self.memlimit_active = active;
            self.memlimit_fatal = fatal;
            return old;
        }
        if active == self.memlimit_active && fatal == self.memlimit_fatal && i64::from(new_limit_mb) << 20 == self.limit {
            return old;
        }
        self.memlimit_active = active;
        self.memlimit_fatal = fatal;
        self.set_limit(i64::from(new_limit_mb) << 20, PHYS_FOOTPRINT_WARNING_LEVEL);
        old
    }

    fn limit_exceeded(&self) -> bool {
        (self.limit <= 0 && self.balance < self.limit) || (self.limit > 0 && self.balance > self.limit)
    }

    fn warn_level_exceeded(&self) -> bool {
        self.warn_percent != PERCENT_NONE && i128::from(self.balance) > (i128::from(self.limit) * i128::from(self.warn_percent)) >> 16
    }

    /// A new balance (`LF_TRACKING_MAX`), and the callback
    /// `ledger_check_needblock` makes of it.
    pub fn balance_is(&mut self, balance: i64) -> Option<Crossing> {
        self.balance = balance;
        self.lifetime_max = self.lifetime_max.max(balance);
        self.interval_max = self.interval_max.max(balance);
        if !self.limit_exceeded() {
            if self.warn_level_exceeded() {
                if !self.warned {
                    self.warned = true;
                    return Some(Crossing::RoseAbove);
                }
            } else if self.warned {
                self.warned = false;
                return Some(Crossing::DippedBelow);
            }
            return None;
        }
        if self.called_back {
            return None;
        }
        self.called_back = true;
        Some(Crossing::Exceeded)
    }

    /// `ledger_get_interval_max(..., reset)`: the peak since the last
    /// reset, and with `reset` the next interval begun at the balance.
    pub fn get_interval_max(&mut self, reset: bool) -> i64 {
        let max = self.interval_max;
        if reset {
            self.interval_max = self.balance;
        }
        max
    }

    /// A reading of the balance by another task (`ledger_get_balance` and
    /// the peaks, from `proc_pid_rusage` of another process or at its
    /// exit): a balance the ledger had at that moment, so the peaks hold it;
    /// the limit's callbacks are the task's own.
    pub fn observe(&mut self, balance: i64) {
        self.balance = balance;
        self.lifetime_max = self.lifetime_max.max(balance);
        self.interval_max = self.interval_max.max(balance);
    }

    /// `task_has_triggered_exc_resource`, and its mark.
    fn exc_triggered(&mut self) -> bool {
        let t = if self.memlimit_active { &mut self.exc_active } else { &mut self.exc_inactive };
        std::mem::replace(t, true)
    }
}

/// The map's page shift.
const PAGE_SHIFT: u32 = PAGE.trailing_zeros();
/// Pages a chunk of the record holds (64 MiB of the map), two bits each.
const CHUNK_PAGES: u64 = 4096;
const CHUNK_WORDS: usize = (CHUNK_PAGES / 32) as usize;
/// Pages a leaf table maps.
const LEAF_PAGES: u64 = 1 << (L3_SHIFT - PAGE_SHIFT);
/// The low bit of each two-bit field of a word.
const LOW: u64 = 0x5555_5555_5555_5555;

/// What a task's pmap holds for one page of its map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Held {
    /// No entry.
    None,
    /// The task's own memory (internal, not reusable), resident or
    /// compressed: in `phys_footprint` (`internal`, `internal_compressed`).
    Own,
    /// Its own memory made reusable (`PMAP_OPTIONS_SET_REUSABLE`): entered,
    /// not counted.
    Reusable,
    /// A file's page: entered, not counted.
    File,
}

impl Held {
    fn bits(self) -> u64 {
        match self {
            Held::None => 0,
            Held::Own => 1,
            Held::Reusable => 2,
            Held::File => 3,
        }
    }

    fn of(bits: u64) -> Held {
        match bits & 3 {
            0 => Held::None,
            1 => Held::Own,
            2 => Held::Reusable,
            _ => Held::File,
        }
    }

    /// The page as a look finds it, the host's state of it being `st` and
    /// `self` what the pmap held at the last look. A page the host holds
    /// nothing of now (one it reclaimed, or one never touched) keeps what
    /// the pmap held: the device modelled reclaims none.
    pub fn looked(self, st: u8) -> Held {
        let own = st & ps::EXTERNAL == 0;
        if own && st & (ps::PRESENT | ps::PAGED_OUT) != 0 {
            if st & ps::REUSABLE != 0 {
                Held::Reusable
            } else {
                Held::Own
            }
        } else if !own && st & ps::PRESENT != 0 {
            Held::File
        } else {
            self
        }
    }
}

/// The record of what a task's pmap holds: each page's [`Held`], the leaf
/// tables (32 MB each) and twig tables (64 GB each) allocated.
#[derive(Debug, Default)]
pub struct Pmap {
    chunks: std::collections::BTreeMap<u64, Box<[u64; CHUNK_WORDS]>>,
    /// Pages held as [`Held::Own`].
    own: u64,
    /// Pages held as [`Held::Reusable`] and as [`Held::File`].
    reusable: u64,
    file: u64,
    leaves: std::collections::BTreeSet<u64>,
    twigs: std::collections::BTreeSet<u64>,
    /// The pmap's ledgers' lifetime peaks, in pages.
    pub peaks: Pages,
}

/// The pages a pmap's ledgers count (`pmap_enter`'s credits): `phys_mem`
/// (every page entered), `internal`, `external` and `reusable`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pages {
    pub resident: u64,
    pub internal: u64,
    pub external: u64,
    pub reusable: u64,
}

/// The pages of `[s, e)` (page aligned) by chunk: the chunk, and the first
/// and last-plus-one page index within it.
fn by_chunk(s: u64, e: u64) -> impl Iterator<Item = (u64, usize, usize)> {
    let (first, last) = (s >> PAGE_SHIFT, e >> PAGE_SHIFT);
    let mut at = first;
    std::iter::from_fn(move || {
        if at >= last {
            return None;
        }
        let c = at / CHUNK_PAGES;
        let stop = ((c + 1) * CHUNK_PAGES).min(last);
        let r = (c, (at - c * CHUNK_PAGES) as usize, (stop - c * CHUNK_PAGES) as usize);
        at = stop;
        Some(r)
    })
}

fn own_in(w: u64) -> u64 {
    u64::from((w & LOW & !(w >> 1)).count_ones())
}

fn reusable_in(w: u64) -> u64 {
    u64::from(((w >> 1) & LOW & !w).count_ones())
}

fn file_in(w: u64) -> u64 {
    u64::from((w & (w >> 1) & LOW).count_ones())
}

fn get(words: &[u64; CHUNK_WORDS], i: usize) -> Held {
    Held::of(words[i / 32] >> ((i % 32) * 2))
}

fn put(words: &mut [u64; CHUNK_WORDS], i: usize, h: Held) {
    let (w, sh) = (i / 32, (i % 32) * 2);
    words[w] = (words[w] & !(3 << sh)) | (h.bits() << sh);
}

impl Pmap {
    /// What the pmap holds for the page at `addr`.
    pub fn held(&self, addr: u64) -> Held {
        let p = addr >> PAGE_SHIFT;
        self.chunks.get(&(p / CHUNK_PAGES)).map_or(Held::None, |c| get(c, (p % CHUNK_PAGES) as usize))
    }

    /// What its ledgers count now.
    pub fn pages(&self) -> Pages {
        Pages { resident: self.own + self.reusable + self.file, internal: self.own, external: self.file, reusable: self.reusable }
    }

    /// The peaks raised to what the ledgers count now (`LF_TRACKING_MAX`).
    fn track(&mut self) {
        let n = self.pages();
        let p = &mut self.peaks;
        p.resident = p.resident.max(n.resident);
        p.internal = p.internal.max(n.internal);
        p.external = p.external.max(n.external);
        p.reusable = p.reusable.max(n.reusable);
    }

    /// Its `page_table` ledger: the root table and the leaf and twig
    /// tables.
    pub fn page_table(&self) -> u64 {
        ROOT_SIZE + (self.leaves.len() + self.twigs.len()) as u64 * PAGE
    }

    /// The `phys_footprint` it makes: its own pages, the root table, the
    /// leaf and twig tables.
    pub fn balance(&self) -> i64 {
        (self.own * PAGE + ROOT_SIZE + (self.leaves.len() + self.twigs.len()) as u64 * PAGE) as i64
    }

    /// A look at the pages of `ranges` (page aligned, sorted, disjoint),
    /// `states(addr, pages, out)` giving the host's state of each: each
    /// page's [`Held::looked`], a table for each page held. What lies
    /// outside the ranges is no longer the task's map's (gone with its
    /// mapping); `twigs` are twig tables the map has without a page of its
    /// own under them (the commpage's, the shared region's nest). False
    /// when the host cannot say.
    ///
    /// The pages of `unentered` (sorted, disjoint) are mapped and not
    /// entered yet: what the host holds of them is another mapping's (a
    /// page shared, or copied on write, with it), so they hold nothing here
    /// until their first access enters them.
    pub fn look(&mut self, ranges: &[(u64, u64)], twigs: &[u64], unentered: &[(u64, u64)], states: &mut dyn FnMut(u64, u64, &mut [u8]) -> bool) -> bool {
        let mut chunks: std::collections::BTreeMap<u64, Box<[u64; CHUNK_WORDS]>> = std::collections::BTreeMap::new();
        let mut out = vec![0u8; CHUNK_PAGES as usize];
        for &(s, e) in ranges {
            for (c, i0, i1) in by_chunk(s, e) {
                let at = (c * CHUNK_PAGES + i0 as u64) << PAGE_SHIFT;
                let n = i1 - i0;
                if !states(at, n as u64, &mut out[..n]) {
                    return false;
                }
                hide_unentered(unentered, at, &mut out[..n]);
                let old = self.chunks.get(&c);
                // Nothing held there and nothing on the host: nothing to keep.
                if old.is_none() && out[..n].iter().all(|&st| st == 0) {
                    continue;
                }
                let new = chunks.entry(c).or_insert_with(|| Box::new([0; CHUNK_WORDS]));
                for (k, &st) in out[..n].iter().enumerate() {
                    let i = i0 + k;
                    let was = old.map_or(Held::None, |o| get(o, i));
                    let h = was.looked(st);
                    if h != Held::None {
                        put(new, i, h);
                        let page = (c * CHUNK_PAGES + i as u64) << PAGE_SHIFT;
                        self.leaves.insert(page >> L3_SHIFT);
                        self.twigs.insert(page >> L2_SHIFT);
                    }
                }
            }
        }
        chunks.retain(|_, w| w.iter().any(|&x| x != 0));
        let count = |f: fn(u64) -> u64| chunks.values().map(|w| w.iter().map(|&x| f(x)).sum::<u64>()).sum::<u64>();
        (self.own, self.reusable, self.file) = (count(own_in), count(reusable_in), count(file_in));
        self.chunks = chunks;
        self.twigs.extend(twigs.iter().copied());
        self.track();
        true
    }

    /// The task's own pages it holds in `ranges` (sorted or not, disjoint).
    pub fn own_in(&self, ranges: &[(u64, u64)]) -> u64 {
        let mut n = 0;
        for &(s, e) in ranges {
            for (c, i0, i1) in by_chunk(s & !(PAGE - 1), (e + PAGE - 1) & !(PAGE - 1)) {
                if let Some(w) = self.chunks.get(&c) {
                    n += (i0..i1).filter(|&i| get(w, i) == Held::Own).count() as u64;
                }
            }
        }
        n
    }

    /// Whether the pmap holds a page of `[s, e)`; with `own_only`, one of
    /// the task's own.
    pub fn holds(&self, s: u64, e: u64, own_only: bool) -> bool {
        by_chunk(s, e).any(|(c, i0, i1)| self.chunks.get(&c).is_some_and(|w| (i0..i1).any(|i| matches!((get(w, i), own_only), (Held::Own, _) | (Held::Reusable | Held::File, false)))))
    }

    /// Change the pages of `[s, e)` by `f`.
    fn change(&mut self, s: u64, e: u64, f: impl Fn(Held) -> Held) {
        for (c, i0, i1) in by_chunk(s, e) {
            let Some(w) = self.chunks.get_mut(&c) else { continue };
            for i in i0..i1 {
                let (was, now) = (get(w, i), f(get(w, i)));
                if was != now {
                    for (n, h) in [(&mut self.own, Held::Own), (&mut self.reusable, Held::Reusable), (&mut self.file, Held::File)] {
                        *n = *n + u64::from(now == h) - u64::from(was == h);
                    }
                    put(w, i, now);
                }
            }
            if w.iter().all(|&x| x == 0) {
                self.chunks.remove(&c);
            }
        }
        self.track();
    }

    /// `pmap_remove` of `[s, e)` (`vm_map_delete`, an overwrite): its
    /// entries go, and each leaf table of the range left with none
    /// (`refcnt` 0, `pmap_tte_deallocate`). Twig tables stay while the
    /// pmap lives.
    pub fn remove(&mut self, s: u64, e: u64) {
        if s >= e {
            return;
        }
        self.change(s, e, |_| Held::None);
        let blocks: Vec<u64> = self.leaves.range(s >> L3_SHIFT..=(e - 1) >> L3_SHIFT).copied().collect();
        for b in blocks {
            let first = b * LEAF_PAGES;
            let (c, i0) = (first / CHUNK_PAGES, (first % CHUNK_PAGES) as usize);
            let used = self.chunks.get(&c).is_some_and(|w| w[i0 / 32..(i0 + LEAF_PAGES as usize) / 32].iter().any(|&x| x != 0));
            if !used {
                self.leaves.remove(&b);
            }
        }
    }

    /// `pmap_disconnect` of the pages of `[s, e)` (their object took them
    /// away: a file's past its new end): their entries go, the tables
    /// mapping them stay (`pmap_page_protect` only lowers their count).
    pub fn disconnect(&mut self, s: u64, e: u64) {
        if s < e {
            self.change(s, e, |_| Held::None);
        }
    }

    /// `vm_map_reusable_pages` of `[s, e)`: the task's own pages there are
    /// reusable (`deactivate_pages_in_object` with `DEACTIVATE_REUSABLE`),
    /// still entered.
    pub fn made_reusable(&mut self, s: u64, e: u64) {
        self.change(s, e, |h| if h == Held::Own { Held::Reusable } else { h });
    }

    /// `vm_map_reuse_pages` of `[s, e)`: its reusable pages are the task's
    /// own again (`vm_object_reuse_pages`, `PMAP_OPTIONS_CLEAR_REUSABLE`).
    pub fn reused(&mut self, s: u64, e: u64) {
        self.change(s, e, |h| if h == Held::Reusable { Held::Own } else { h });
    }
}

/// The states of the pages from `at` in `out` with those of `unentered`'s
/// pages cleared: the host's pages there are not this pmap's.
fn hide_unentered(unentered: &[(u64, u64)], at: u64, out: &mut [u8]) {
    let end = at + ((out.len() as u64) << PAGE_SHIFT);
    let i = unentered.partition_point(|&(_, e)| e <= at);
    for &(s, e) in unentered[i..].iter().take_while(|&&(s, _)| s < end) {
        let (a, b) = (((s.max(at) - at) >> PAGE_SHIFT) as usize, ((e.min(end) - at) >> PAGE_SHIFT) as usize);
        out[a..b].fill(0);
    }
}

/// What a kernel operation releases of the pages of its range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Release {
    /// Every entry (`pmap_remove`): an unmapping, a mapping over it.
    Remove,
    /// The task's own pages become reusable.
    Reusable,
}

/// A task's footprint meter, shared with the processes that read its
/// ledger: the record of its pmap, and the submap entries (the shared
/// region's, whose pages and tables are its own pmap's) its map
/// publishes.
#[derive(Debug, Default)]
pub struct Meter {
    pmap: std::sync::Mutex<Pmap>,
    pub submaps: std::sync::Arc<std::sync::Mutex<Vec<(u64, u64)>>>,
    /// The map's entries with `use_pmap` off (purgeable and tagged
    /// objects'): their pages are the objects' owners', not the pmap's.
    pub alt: std::sync::Arc<std::sync::Mutex<Vec<(u64, u64)>>>,
    /// The task as an owner of objects, whose pages it is billed for.
    owner: std::sync::Mutex<std::sync::Arc<super::purgeable::Owner>>,
}

/// The commpage alias in a task's memory: the host's mapping of the
/// commpage, not the task's.
fn commpage_alias() -> (u64, u64) {
    (gex_abi::DARWIN_COMMPAGE_ALIAS, gex_abi::DARWIN_COMMPAGE_ALIAS + (gex_abi::DARWIN_COMMPAGE_END - gex_abi::DARWIN_COMMPAGE_RO))
}

/// `ranges` (sorted, disjoint) less `holes` (sorted, disjoint).
fn less(ranges: &[(u64, u64)], holes: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for &(s, e) in ranges {
        let mut at = s;
        for &(hs, he) in holes.iter().filter(|&&(hs, he)| hs < e && he > s) {
            if hs > at {
                out.push((at, hs));
            }
            at = at.max(he);
        }
        if at < e {
            out.push((at, e));
        }
    }
    out
}

impl Meter {
    /// The record, held while a look or a release is made.
    pub fn lock(&self) -> std::sync::MutexGuard<'_, Pmap> {
        self.pmap.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A new task's pmap, as an exec makes it, and the new task an owner of
    /// nothing; the old task's objects disowned (`vm_owned_objects_disown`
    /// at its end).
    pub fn reset(&self) {
        *self.lock() = Pmap::default();
        let pid = self.owner().pid();
        let old = std::mem::replace(&mut *self.owner.lock().unwrap_or_else(|e| e.into_inner()), std::sync::Arc::new(super::purgeable::Owner::of(pid)));
        super::purgeable::disown(&old);
    }

    /// The task as an owner of objects.
    pub fn owner(&self) -> std::sync::Arc<super::purgeable::Owner> {
        std::sync::Arc::clone(&self.owner.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// The `phys_footprint` of what `pm` holds: the pmap's own pages less
    /// those under entries with `use_pmap` off, its tables, and the
    /// nonvolatile pages of the objects the task owns; none where the host
    /// cannot say what it holds of those.
    pub fn balance(&self, pm: &Pmap) -> Option<i64> {
        let alt = self.alt.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let owned = super::purgeable::owned(&self.owner())?;
        Some(pm.balance() - (pm.own_in(&alt) * PAGE) as i64 + owned.footprint as i64)
    }

    /// The ranges of map `mm` the pmap enters pages of: its mappings less
    /// the commpage alias and the submaps.
    pub fn ranges(&self, mm: &crate::mem::Mm) -> Vec<(u64, u64)> {
        let (alias, alias_end) = commpage_alias();
        let vmas: Vec<(u64, u64)> = mm.lock().vmas().iter().map(|v| (v.start, v.end)).filter(|&(s, e)| !(s >= alias && e <= alias_end)).collect();
        let mut holes = self.submaps.lock().unwrap_or_else(|e| e.into_inner()).clone();
        holes.sort_unstable();
        less(&vmas, &holes)
    }

    /// The twig tables the map has whatever its pages: the commpage's
    /// (`pmap_insert_commpage` expands to the twig level) and those over
    /// the submaps (`pmap_nest` expands the grand pmap to it).
    fn fixed_twigs(&self) -> Vec<u64> {
        let mut t = vec![gex_abi::DARWIN_COMMPAGE_RW >> L2_SHIFT];
        for &(s, e) in self.submaps.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            if s < e {
                t.extend(s >> L2_SHIFT..=(e - 1) >> L2_SHIFT);
            }
        }
        t
    }

    /// A look at the task's pages, its map `mm` and its memory `m`: the
    /// balance; none where the host cannot say.
    pub fn measure(&self, pm: &mut Pmap, mm: &crate::mem::Mm, m: &mut GuestMem<'_>) -> Option<i64> {
        let ranges = self.ranges(mm);
        let twigs = self.fixed_twigs();
        // What is not entered, and what is absent (no object's page, the
        // host's anonymous memory there), is no page of the pmap's.
        let (unentered, pending) = {
            let mut mm = mm.lock();
            let mut u = mm.unentered_ranges();
            u.extend(mm.absent_ranges());
            u.sort_unstable();
            (u, mm.copy_pending_runs())
        };
        // A private mapping's page it has not written is the file's,
        // whatever the host made of it.
        let ok = pm.look(&ranges, &twigs, &unentered, &mut |at, n, out| {
            if !m.page_states(at, n * PAGE, PAGE, out).unwrap_or(false) {
                return false;
            }
            let (first, end) = (at >> PAGE_SHIFT, (at >> PAGE_SHIFT) + n);
            let i = pending.partition_point(|&(_, e)| e <= first);
            for &(s, e) in pending[i..].iter().take_while(|&&(s, _)| s < end) {
                for p in s.max(first)..e.min(end) {
                    let st = &mut out[(p - first) as usize];
                    if *st & (ps::PRESENT | ps::PAGED_OUT) != 0 {
                        *st |= ps::EXTERNAL;
                    }
                }
            }
            true
        });
        if !ok {
            return None;
        }
        self.balance(pm)
    }

    /// Whether `how` releases anything of `[s, e)`: the record holds a page
    /// there it takes, or the host shows one the next look would. False
    /// only when nothing there can lower the balance.
    pub fn releases(&self, pm: &Pmap, mm: &crate::mem::Mm, m: &mut GuestMem<'_>, s: u64, e: u64, how: Release) -> bool {
        let own_only = how == Release::Reusable;
        if pm.holds(s, e, own_only) {
            return true;
        }
        let ranges: Vec<(u64, u64)> = self.ranges(mm).into_iter().filter(|&(rs, re)| rs < e && re > s).map(|(rs, re)| (rs.max(s), re.min(e))).collect();
        let unentered = mm.lock().unentered_ranges();
        let mut out = vec![0u8; CHUNK_PAGES as usize];
        for (rs, re) in ranges {
            for (c, i0, i1) in by_chunk(rs, re) {
                let at = (c * CHUNK_PAGES + i0 as u64) << PAGE_SHIFT;
                let n = i1 - i0;
                if !m.page_states(at, n as u64 * PAGE, PAGE, &mut out[..n]).unwrap_or(false) {
                    return true;
                }
                hide_unentered(&unentered, at, &mut out[..n]);
                if out[..n].iter().any(|&st| matches!((Held::None.looked(st), own_only), (Held::Own, _) | (Held::Reusable | Held::File, false))) {
                    return true;
                }
            }
        }
        false
    }
}

impl Kernel {
    /// The task's `phys_footprint` now: its pages looked at and its ledger
    /// told (the limit's callbacks made); none where the host cannot say,
    /// which is reported.
    pub(crate) fn darwin_footprint_now(&mut self, m: &mut GuestMem<'_>) -> Option<i64> {
        // A look made inside a release would wait on the release's own hold
        // of the record; the release looked first.
        if self.dtask.footprint_releasing {
            return self.procs.jetsam().ledgers.get(&self.pid).map(|l| l.balance);
        }
        let rusage = std::sync::Arc::clone(&self.dtask.rusage);
        let fp = {
            let mut pm = rusage.meter.lock();
            rusage.meter.measure(&mut pm, &self.mem, m)
        };
        let Some(fp) = fp else {
            self.darwin_unimplemented("phys_footprint on a host that cannot say which pages are a task's".into());
            return None;
        };
        if let Some((c, l)) = self.darwin_footprint_is(fp) {
            self.darwin_footprint_exceeded(m, c, l);
        }
        Some(fp)
    }

    /// The ledger told the balance is `fp`: the callback it makes, if any,
    /// with the ledger as it is then.
    fn darwin_footprint_is(&mut self, fp: i64) -> Option<(Crossing, Ledger)> {
        let pid = self.pid;
        let mut j = self.procs.jetsam();
        let l = j.ledgers.get_mut(&pid)?;
        l.balance_is(fp).map(|c| (c, *l))
    }

    /// `op` releases pages of `[s, e)` as `how` says: the task's pages are
    /// looked at first, so the ledger's peaks hold the balance it had, and
    /// the record follows the release (no other task's look comes between).
    /// The limit's callbacks are made after the operation, as the ledger's
    /// AST makes them on the way back to user space.
    pub(crate) fn darwin_footprint_release<R>(&mut self, m: &mut GuestMem<'_>, s: u64, e: u64, how: Release, op: impl FnOnce(&mut Kernel, &mut GuestMem<'_>) -> R) -> R {
        if self.dtask.footprint_releasing || s >= e {
            return op(self, m);
        }
        // pmap_remove takes the range's entries, and with them what was
        // waiting to be entered there.
        let cleared = |k: &mut Kernel| {
            if how == Release::Remove {
                k.mem.lock().clear_unentered(s, e);
            }
        };
        let rusage = std::sync::Arc::clone(&self.dtask.rusage);
        let mut pm = rusage.meter.lock();
        if !rusage.meter.releases(&pm, &self.mem, m, s, e, how) {
            drop(pm);
            let r = op(self, m);
            cleared(self);
            return r;
        }
        let before = rusage.meter.measure(&mut pm, &self.mem, m);
        let mut crossings = Vec::new();
        if let Some(fp) = before {
            crossings.extend(self.darwin_footprint_is(fp));
        }
        self.dtask.footprint_releasing = true;
        let r = op(self, m);
        self.dtask.footprint_releasing = false;
        cleared(self);
        match how {
            Release::Remove => pm.remove(s, e),
            Release::Reusable => pm.made_reusable(s, e),
        }
        // What the guest touched meanwhile is seen by the next look; the
        // balance only grew by it.
        let after = rusage.meter.balance(&pm);
        drop(pm);
        match (before, after) {
            (Some(_), Some(after)) => crossings.extend(self.darwin_footprint_is(after)),
            _ => self.darwin_unimplemented("phys_footprint on a host that cannot say which pages are a task's".into()),
        }
        for (c, l) in crossings {
            self.darwin_footprint_exceeded(m, c, l);
        }
        r
    }

    /// `vm_map_reuse_pages` of `[s, e)` done: the reusable pages there are
    /// the task's own again.
    pub(crate) fn darwin_footprint_reused(&mut self, m: &mut GuestMem<'_>, s: u64, e: u64) {
        let rusage = std::sync::Arc::clone(&self.dtask.rusage);
        let fp = {
            let mut pm = rusage.meter.lock();
            if !pm.holds(s, e, false) {
                return;
            }
            pm.reused(s, e);
            rusage.meter.balance(&pm)
        };
        let Some(fp) = fp else { return };
        if let Some((c, l)) = self.darwin_footprint_is(fp) {
            self.darwin_footprint_exceeded(m, c, l);
        }
    }

    /// A task's thread calls: its footprint measured when it is due, and
    /// its ledger told; when it is next due.
    pub(crate) fn darwin_footprint_tick(&mut self, m: &mut GuestMem<'_>) -> Option<Instant> {
        let now = Instant::now();
        if let Some(next) = self.dtask.footprint_due.filter(|&t| t > now) {
            return Some(next);
        }
        if !self.procs.jetsam().ledgers.contains_key(&self.pid) {
            return None;
        }
        self.darwin_footprint_now(m)?;
        let next = now + SAMPLE;
        self.dtask.footprint_due = Some(next);
        Some(next)
    }

    /// `task_footprint_exceeded`: a warning, or the limit itself.
    fn darwin_footprint_exceeded(&mut self, m: &mut GuestMem<'_>, c: Crossing, l: Ledger) {
        let warning = match c {
            // Task memory limits warn only on the way up.
            Crossing::DippedBelow => return,
            Crossing::RoseAbove => true,
            Crossing::Exceeded => false,
        };
        let (active, fatal) = (l.memlimit_active, l.memlimit_fatal);
        if !warning {
            let triggered = self.procs.jetsam().ledgers.get_mut(&self.pid).map(|l| l.exc_triggered()).unwrap_or(true);
            // PROC_CROSSED_HIGH_WATERMARK__SEND_EXC_RESOURCE_AND_SUSPEND,
            // for a task that is not traced (none here is) and not launchd:
            // a fatal limit's EXC_RESOURCE is the corpse its kill makes
            // (corpse_for_fatal_memkill: the map is marked a corpse source,
            // and proc_prepareexit makes the corpse, its codes the
            // EXC_RESOURCE's), a soft one's a corpse fork's
            // (exc_via_corpse_forking; no audio is active here), its code
            // the memory type, high watermark flavor and the limit in MB.
            if !triggered && self.pid != 1 {
                if fatal {
                    self.dtask.corpse_source = true;
                } else {
                    let mb = (l.limit >> 20) as i32;
                    let name = self.darwin_best_name();
                    super::corpse::kernel_log(format!("process {name} [{}] crossed memory high watermark ({mb} MB); EXC_RESOURCE ", self.pid));
                    const RESOURCE_TYPE_MEMORY: i64 = 3;
                    const FLAVOR_HIGH_WATERMARK: i64 = 1;
                    let code = (RESOURCE_TYPE_MEMORY << 61) | (FLAVOR_HIGH_WATERMARK << 58) | (i64::from(mb) & 0x1fff);
                    // XNU raises it on the thread whose credit crossed the
                    // limit: ledger_entry_check_new_balance sets AST_LEDGER
                    // on it (act_set_astledger_async), and its ledger_ast
                    // calls task_footprint_exceeded, whose fork makes that
                    // thread's copy the crashed one. This host's memory
                    // takes a thread's first store to a page with no fault,
                    // so the crossing is seen only by this sampling, and no
                    // thread is known to have made it: the copy of the
                    // first is the crashed thread.
                    self.darwin_unimplemented("the crashed thread of a soft memory limit's corpse fork (the thread whose page fault credited phys_footprint past the limit, ledger_ast's task_footprint_exceeded: no fault marks a first store here)".into());
                    let req = super::corpsefork::Request { etype: super::exception::EXC_RESOURCE, code, subcode: 0, reason: None, current: None, origin: super::corpsefork::Origin::ThreadCall };
                    // A host that cannot make it has said so.
                    let _ = self.darwin_corpse_fork_queue(req);
                }
            }
        }
        // memorystatus_on_ledger_footprint_exceeded.
        if warning {
            self.darwin_warn_process(m, active, fatal, false);
            return;
        }
        if fatal {
            // memorystatus_kill_process_sync(kMemorystatusKilledPerProcessLimit):
            // memorystatus_do_kill's jetsam_do_kill, for the reason
            // JETSAM_REASON_MEMORY_PERPROCESSLIMIT, a crash report asked for
            // (corpse_for_fatal_memkill, and the task is not traced).
            use super::procinfo::{P_JETSAM_PID, P_LTERM_JETSAM};
            use super::reason::{flag, OsReason, JETSAM_REASON_MEMORY_PERPROCESSLIMIT};
            let reason = OsReason::jetsam(JETSAM_REASON_MEMORY_PERPROCESSLIMIT, flag::GENERATE_CRASH_REPORT);
            // exit_with_reason's proc_prepareexit, its critical exit first.
            if self.procs.jetsam_kill(self.pid, P_LTERM_JETSAM | P_JETSAM_PID, std::sync::Arc::new(reason)) {
                self.darwin_critical_exit(super::signal::dsig::SIGKILL);
            }
        } else {
            self.procs.jetsam().hwm_candidates = true;
            self.darwin_warn_process(m, active, fatal, true);
        }
    }

    /// `memorystatus_warn_process`: this task's EVFILT_MEMORYSTATUS knotes
    /// told it is near (or, for a soft limit, past) its limit; whether it
    /// has any that listen.
    fn darwin_warn_process(&mut self, m: &mut GuestMem<'_>, _active: bool, _fatal: bool, exceeded: bool) -> bool {
        const PRESSURE_WARN: u32 = 0x02;
        const PRESSURE_CRITICAL: u32 = 0x04;
        const PROC_LIMIT_WARN: u32 = 0x10;
        const PROC_LIMIT_CRITICAL: u32 = 0x20;
        const PLATFORM_MACOS: u32 = 1;
        const PLATFORM_MACCATALYST: u32 = 6;
        const PLATFORM_DRIVERKIT: u32 = 10;
        let platform = self.dtask.platform.0;
        if matches!(platform, PLATFORM_MACOS | PLATFORM_MACCATALYST | PLATFORM_DRIVERKIT) {
            self.darwin_unimplemented("memory limit warnings to a macOS program (once per active and inactive limit)".into());
            return false;
        }
        let list = self.dtask.kevents.memorystatus_klist.clone();
        let (mut found, mut send) = (false, 0);
        for n in list {
            let k = self.knote(n);
            let f = if !exceeded {
                [PROC_LIMIT_WARN, PRESSURE_CRITICAL, PRESSURE_WARN].into_iter().find(|&f| k.sfflags & f != 0)
            } else {
                Some(PROC_LIMIT_CRITICAL).filter(|&f| k.sfflags & f != 0)
            };
            if let Some(f) = f {
                k.fflags = f;
                found = true;
                send += 1;
            }
        }
        if found && send > 0 {
            let list = self.dtask.kevents.memorystatus_klist.clone();
            self.knote_list(&list, 0);
            self.darwin_kevent_settle(m);
        }
        found
    }
}

impl Kernel {
    /// `task_info(TASK_VM_INFO)` and `TASK_VM_INFO_PURGEABLE` of this task
    /// (`task.c`), with the caller's count checked and fixed as XNU does
    /// (an iOS 12 SDK's larger count is taken as rev2's): the map's size,
    /// entries, page and bounds; the pmap's ledgers from one look at the
    /// task's pages (`phys_mem` as the resident size, `internal`,
    /// `external`, `reusable`, each with its lifetime peak); its
    /// `phys_footprint` ledger's balance (`get_task_phys_footprint`) and
    /// lifetime peak (`ledger_get_lifetime_max`), and what its memory limit
    /// leaves (`memorystatus_available_memory_internal`). The device
    /// modelled runs no pageout (its pressure level stays normal), so its
    /// compressor holds nothing of the task's and nothing is swapped: the
    /// compressed sizes, their peak and lifetime, the decompressions and
    /// the swap-ins are 0. The purgeable and tag ledgers are the objects
    /// the task owns ([`super::purgeable`]); TASK_VM_INFO_PURGEABLE
    /// (`purgeable`) adds `vm_map_query_volatile` of the map's volatile
    /// objects.
    pub(crate) fn darwin_task_vm_info(&mut self, m: &mut GuestMem<'_>, count: u32, purgeable: bool) -> super::kobject::Reply {
        use super::kobject::Reply;
        const KERN_INVALID_ARGUMENT: i32 = 4;
        // TASK_VM_INFO_REV*_COUNT: natural_t of the packed structure.
        const REV0: u32 = 36;
        const REV1: u32 = 38;
        const REV2: u32 = 42;
        const REV3: u32 = 84;
        const REV4: u32 = 86;
        const REV5: u32 = 87;
        const REV6: u32 = 89;
        const PLATFORM_IOS: u32 = 2;
        let mut original = count;
        let (platform, sdk) = self.dtask.platform;
        if original > REV2 && platform == PLATFORM_IOS && sdk != 0 && (sdk >> 16) <= 12 {
            original = REV2;
        }
        if original < REV0 {
            return Reply::err(KERN_INVALID_ARGUMENT);
        }
        let mut out = vec![0u8; REV6 as usize * 4];
        let put = |out: &mut Vec<u8>, at: usize, v: u64| out[at..at + 8].copy_from_slice(&v.to_le_bytes());
        let (size, entries) = self.dtask.vm.size_and_count();
        put(&mut out, 0, size);
        out[8..12].copy_from_slice(&entries.to_le_bytes());
        out[12..16].copy_from_slice(&((super::mach::PAGE_MASK + 1) as u32).to_le_bytes());
        // A corpse fork's ledgers are those copied to it: its pmap enters
        // nothing (phys_mem, external and reusable 0), and each copied
        // ledger's lifetime peak is the balance the copy credited.
        let copied = self.dtask.corpse.as_ref().and_then(|c| c.ledgers);
        // One look: the ledgers as the pmap holds them now.
        let footprint = match copied {
            Some(l) => Some(l.phys_footprint),
            None => self.darwin_footprint_now(m),
        };
        let (now, peaks) = match copied {
            Some(l) => {
                let p = Pages { internal: l.internal / PAGE, ..Default::default() };
                (p, p)
            }
            None => {
                let pm = self.dtask.rusage.meter.lock();
                (pm.pages(), pm.peaks)
            }
        };
        let Some(footprint) = footprint else {
            self.darwin_unimplemented("task_info TASK_VM_INFO on a host that cannot say which pages are a task's".into());
            return Reply::err(5);
        };
        for (at, pages) in [(16, now.resident), (24, peaks.resident), (48, now.internal), (56, peaks.internal), (64, now.external), (72, peaks.external), (80, now.reusable), (88, peaks.reusable)] {
            put(&mut out, at, pages * PAGE);
        }
        // vm_map_query_volatile: each entry of a volatile or emptied object,
        // its size, the object's resident pages past the entry's offset,
        // and the pmap's pages there.
        if purgeable {
            let (mut virt, mut res, mut pmap) = (0u64, 0u64, 0u64);
            let ents: Vec<(u64, u64, u64, u64)> = {
                let map = self.dtask.vm.lock();
                let mut v = Vec::new();
                let mut at = 0;
                while let Some(e) = map.at_or_after(at) {
                    v.push((e.start, e.end, e.attrs.obj, e.offset));
                    at = e.end;
                }
                v
            };
            let pm = self.dtask.rusage.meter.lock();
            for (s, e, obj, off) in ents {
                let volatile = super::vmobject::with(obj, |o| o.purg.as_ref().is_some_and(|p| p.state == super::purgeable::state::VOLATILE || p.state == super::purgeable::state::EMPTY)).unwrap_or(false);
                if !volatile {
                    continue;
                }
                virt += e - s;
                let resident = super::purgeable::resident(obj).unwrap_or(0) / PAGE;
                res += resident.saturating_sub(off / PAGE) * PAGE;
                let mut a = s;
                while a < e {
                    if pm.held(a) != Held::None {
                        pmap += PAGE;
                    }
                    a += PAGE;
                }
            }
            drop(pm);
            put(&mut out, 96, pmap);
            put(&mut out, 104, res);
            put(&mut out, 112, virt);
        }
        let mut n = REV0;
        if original >= REV1 {
            put(&mut out, 144, footprint as u64);
            n = REV1;
        }
        if original >= REV2 {
            put(&mut out, 152, self.dtask.map_min);
            put(&mut out, 160, self.darwin_map_max());
            n = REV2;
        }
        if original >= REV3 {
            // ledger_phys_footprint_peak, then the purgeable and tag
            // ledgers of what the task owns (their compressed parts 0).
            let peak = if copied.is_some() { footprint } else { self.procs.jetsam().ledgers.get(&self.pid).map_or(footprint, |l| l.lifetime_max) };
            put(&mut out, 168, peak as u64);
            let owned = match copied {
                Some(l) => Some(l.owned),
                None => super::purgeable::owned(&self.dtask.rusage.meter.owner()),
            };
            let Some(o) = owned else {
                self.darwin_unimplemented("task_info TASK_VM_INFO's owned ledgers on a host that cannot say what it holds of purgeable memory".into());
                return Reply::err(5);
            };
            for (at, v) in [(176, o.purgeable_nonvolatile), (192, o.purgeable_volatile), (208, o.network_nonvolatile), (224, o.network_volatile), (240, o.media_footprint), (256, o.media_nofootprint), (272, o.graphics_footprint), (288, o.graphics_nofootprint), (304, o.neural_footprint), (320, o.neural_nofootprint)] {
                put(&mut out, at, v);
            }
            n = REV3;
        }
        if original >= REV4 {
            // No process (a corpse fork's task): 0.
            let left = if copied.is_some() { 0 } else { self.procs.jetsam().available_memory(self.pid, footprint as u64) };
            put(&mut out, 336, left);
            n = REV4;
        }
        if original >= REV5 {
            n = REV5;
        }
        if original >= REV6 {
            n = REV6;
        }
        // task_info_out, CountInOut: the count, then that many words.
        let mut reply = n.to_le_bytes().to_vec();
        reply.extend_from_slice(&out[..n as usize * 4]);
        Reply::ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_limit_warns_at_80_percent_and_calls_back_once() {
        let mut l = Ledger::default();
        assert_eq!(l.limit, 3072 << 20);
        assert_eq!(MAX_TASK_FOOTPRINT_WARNING_LEVEL, 96);
        assert_eq!(l.balance_is(2000 << 20), None);
        assert_eq!(l.balance_is(2500 << 20), Some(Crossing::RoseAbove));
        assert_eq!(l.balance_is(2600 << 20), None);
        assert_eq!(l.balance_is(1000 << 20), Some(Crossing::DippedBelow));
        assert_eq!(l.balance_is(3100 << 20), Some(Crossing::Exceeded));
        assert_eq!(l.balance_is(3200 << 20), None);
        assert_eq!(l.balance_is(100 << 20), None);
        assert_eq!(l.balance_is(3200 << 20), None);
        assert_eq!(l.lifetime_max, 3200 << 20);
        // The interval's peak, until a reset begins the next at the balance.
        assert_eq!(l.get_interval_max(true), 3200 << 20);
        assert_eq!(l.get_interval_max(false), 3200 << 20);
        assert_eq!(l.balance_is(100 << 20), None);
        assert_eq!(l.get_interval_max(true), 3200 << 20);
        assert_eq!((l.get_interval_max(false), l.lifetime_max), (100 << 20, 3200 << 20));
    }

    #[test]
    fn a_new_limit_rearms_and_minus_one_is_the_system_wide_one() {
        let mut l = Ledger::default();
        assert_eq!(l.set_footprint_limit(100, true, true), 3072);
        assert!(l.memlimit_active && l.memlimit_fatal);
        assert_eq!(l.balance_is(101 << 20), Some(Crossing::Exceeded));
        assert_eq!(l.set_footprint_limit(100, true, true), 100);
        assert_eq!(l.balance_is(102 << 20), None);
        assert_eq!(l.set_footprint_limit(200, true, true), 100);
        assert_eq!(l.balance_is(102 << 20), None);
        assert_eq!(l.balance_is(170 << 20), Some(Crossing::RoseAbove));
        assert_eq!(l.set_footprint_limit(-1, false, false), 200);
        assert_eq!(l.limit, MAX_TASK_FOOTPRINT);
        // 96 %: 2949 MB is past it, 2900 MB is not.
        assert_eq!(l.balance_is(2900 << 20), None);
        assert_eq!(l.balance_is(2960 << 20), Some(Crossing::RoseAbove));
    }

    #[test]
    fn an_exc_resource_is_once_per_kind_of_limit() {
        let mut l = Ledger::default();
        l.memlimit_active = true;
        assert!(!l.exc_triggered());
        assert!(l.exc_triggered());
        l.memlimit_active = false;
        assert!(!l.exc_triggered());
    }

    /// A host whose pages have the states in `st`, by address; any other
    /// page none.
    fn host(st: &std::collections::BTreeMap<u64, u8>) -> impl FnMut(u64, u64, &mut [u8]) -> bool + '_ {
        move |at, n, out| {
            for (i, o) in out[..n as usize].iter_mut().enumerate() {
                *o = st.get(&(at + i as u64 * PAGE)).copied().unwrap_or(0);
            }
            true
        }
    }

    const BASE: u64 = 0x1_0000_0000;
    /// The root and the one twig table every map here has.
    const FIXED: i64 = (ROOT_SIZE + PAGE) as i64;

    #[test]
    fn a_look_counts_own_pages_and_the_tables_of_every_page_entered() {
        let mut st = std::collections::BTreeMap::new();
        // Two of its own pages (one compressed), a reusable one, a file's.
        st.insert(BASE, ps::PRESENT);
        st.insert(BASE + PAGE, ps::PAGED_OUT);
        st.insert(BASE + 2 * PAGE, ps::PRESENT | ps::REUSABLE);
        // A file's page in another leaf table's 32 MB.
        st.insert(BASE + (1 << L3_SHIFT), ps::PRESENT | ps::EXTERNAL);
        let mut pm = Pmap::default();
        assert!(pm.look(&[(BASE, BASE + (2 << L3_SHIFT))], &[0], &[], &mut host(&st)));
        assert_eq!(pm.balance(), 2 * PAGE as i64 + FIXED + 2 * PAGE as i64);
        assert_eq!((pm.held(BASE + 2 * PAGE), pm.held(BASE + (1 << L3_SHIFT))), (Held::Reusable, Held::File));
        // The host reclaims a clean page of the task's and evicts the
        // file's: the device modelled keeps both, and the tables.
        st.remove(&BASE);
        st.remove(&(BASE + (1 << L3_SHIFT)));
        assert!(pm.look(&[(BASE, BASE + (2 << L3_SHIFT))], &[0], &[], &mut host(&st)));
        assert_eq!(pm.balance(), 2 * PAGE as i64 + FIXED + 2 * PAGE as i64);
        // A page out of every range is the map's no more.
        assert!(pm.look(&[(BASE + PAGE, BASE + (2 << L3_SHIFT))], &[0], &[], &mut host(&st)));
        assert_eq!(pm.held(BASE), Held::None);
        assert_eq!(pm.balance(), PAGE as i64 + FIXED + 2 * PAGE as i64);
    }

    #[test]
    fn a_remove_frees_a_leaf_table_left_empty_and_keeps_the_twig() {
        let mut st = std::collections::BTreeMap::new();
        for i in 0..4 {
            st.insert(BASE + i * PAGE, ps::PRESENT);
        }
        st.insert(BASE + (1 << L3_SHIFT), ps::PRESENT);
        let mut pm = Pmap::default();
        assert!(pm.look(&[(BASE, BASE + (2 << L3_SHIFT))], &[], &[], &mut host(&st)));
        assert_eq!(pm.balance(), 5 * PAGE as i64 + FIXED + 2 * PAGE as i64);
        // Part of the first table's pages: it stays.
        pm.remove(BASE, BASE + 2 * PAGE);
        assert_eq!(pm.balance(), 3 * PAGE as i64 + FIXED + 2 * PAGE as i64);
        // The rest of them, and a range past them in the same table: it goes.
        pm.remove(BASE + 2 * PAGE, BASE + 8 * PAGE);
        assert_eq!(pm.balance(), PAGE as i64 + FIXED + PAGE as i64);
        assert!(!pm.holds(BASE, BASE + (1 << L3_SHIFT), false) && pm.holds(BASE, BASE + (2 << L3_SHIFT), true));
    }

    #[test]
    fn reusable_pages_leave_the_footprint_and_a_reuse_brings_them_back() {
        let mut st = std::collections::BTreeMap::new();
        for i in 0..3 {
            st.insert(BASE + i * PAGE, ps::PRESENT);
        }
        let mut pm = Pmap::default();
        assert!(pm.look(&[(BASE, BASE + 4 * PAGE)], &[], &[], &mut host(&st)));
        pm.made_reusable(BASE, BASE + 2 * PAGE);
        assert_eq!(pm.balance(), PAGE as i64 + FIXED + PAGE as i64);
        assert!(!pm.holds(BASE, BASE + 2 * PAGE, true) && pm.holds(BASE, BASE + 2 * PAGE, false));
        // The host reclaims one of them; the reuse finds both still entered.
        st.remove(&BASE);
        st.insert(BASE + PAGE, ps::PRESENT | ps::REUSABLE);
        assert!(pm.look(&[(BASE, BASE + 4 * PAGE)], &[], &[], &mut host(&st)));
        pm.reused(BASE, BASE + 4 * PAGE);
        assert_eq!(pm.balance(), 3 * PAGE as i64 + FIXED + PAGE as i64);
    }

    #[test]
    fn looks_before_each_release_give_the_exact_peaks() {
        // N pages touched between two kernel operations, then unmapped: the
        // look the unmap makes first holds the peak.
        const N: u64 = 100;
        let mut st = std::collections::BTreeMap::new();
        let mut pm = Pmap::default();
        let mut l = Ledger::default();
        let range = [(BASE, BASE + 2 * N * PAGE)];
        assert!(pm.look(&range, &[0], &[], &mut host(&st)));
        l.balance_is(pm.balance());
        let empty = pm.balance();
        for i in 0..N {
            st.insert(BASE + i * PAGE, ps::PRESENT);
        }
        // A look on the thread calls; then the host reclaims some clean ones
        // before the operation, which looks again first.
        assert!(pm.look(&range, &[0], &[], &mut host(&st)));
        l.balance_is(pm.balance());
        for i in 0..N / 4 {
            st.remove(&(BASE + i * PAGE));
        }
        assert!(pm.look(&range, &[0], &[], &mut host(&st)));
        l.balance_is(pm.balance());
        // The unmap: the host's pages go with the mapping.
        st.clear();
        pm.remove(BASE, BASE + N * PAGE);
        l.balance_is(pm.balance());
        assert_eq!(l.lifetime_max, empty + (N * PAGE) as i64 + PAGE as i64);
        assert_eq!(l.balance, empty);
        // A new interval begins at the balance; half as many pages touched.
        assert_eq!(l.get_interval_max(true), l.lifetime_max);
        for i in 0..N / 2 {
            st.insert(BASE + i * PAGE, ps::PRESENT);
        }
        assert!(pm.look(&range, &[0], &[], &mut host(&st)));
        l.observe(pm.balance());
        assert_eq!(l.get_interval_max(false), empty + (N / 2 * PAGE) as i64 + PAGE as i64);
        assert_eq!(l.lifetime_max, empty + (N * PAGE) as i64 + PAGE as i64);
    }

    #[test]
    fn pages_not_entered_hold_nothing_until_their_first_access() {
        // A fork's child: every page the parent had is the host's in the
        // child's memory too (a copy on write), none entered in its pmap.
        let mut st = std::collections::BTreeMap::new();
        for i in 0..8 {
            st.insert(BASE + i * PAGE, ps::PRESENT);
        }
        let range = [(BASE, BASE + 8 * PAGE)];
        let mut pm = Pmap::default();
        let mut unentered = vec![(BASE, BASE + 8 * PAGE)];
        assert!(pm.look(&range, &[0], &unentered, &mut host(&st)));
        assert_eq!(pm.balance(), FIXED, "only the twig the map always has");
        // Two pages touched (entered): those count, with their leaf table.
        unentered = vec![(BASE, BASE + 2 * PAGE), (BASE + 3 * PAGE, BASE + 7 * PAGE)];
        assert!(pm.look(&range, &[0], &unentered, &mut host(&st)));
        assert_eq!(pm.balance(), FIXED + 2 * PAGE as i64 + PAGE as i64);
        assert_eq!((pm.held(BASE + 2 * PAGE), pm.held(BASE + 7 * PAGE), pm.held(BASE)), (Held::Own, Held::Own, Held::None));
    }

    #[test]
    fn the_pmap_ledgers_count_each_kind_of_page_and_keep_their_peaks() {
        let mut st = std::collections::BTreeMap::new();
        st.insert(BASE, ps::PRESENT);
        st.insert(BASE + PAGE, ps::PRESENT);
        st.insert(BASE + 2 * PAGE, ps::PRESENT | ps::REUSABLE);
        st.insert(BASE + 3 * PAGE, ps::PRESENT | ps::EXTERNAL);
        let range = [(BASE, BASE + 8 * PAGE)];
        let mut pm = Pmap::default();
        assert!(pm.look(&range, &[], &[], &mut host(&st)));
        assert_eq!(pm.pages(), Pages { resident: 4, internal: 2, external: 1, reusable: 1 });
        pm.made_reusable(BASE, BASE + PAGE);
        assert_eq!(pm.pages(), Pages { resident: 4, internal: 1, external: 1, reusable: 2 });
        pm.remove(BASE, BASE + 4 * PAGE);
        assert_eq!(pm.pages(), Pages::default());
        assert_eq!(pm.peaks, Pages { resident: 4, internal: 2, external: 1, reusable: 2 });
    }

    #[test]
    fn the_counted_ranges_leave_out_the_holes() {
        assert_eq!(less(&[(0, 10), (20, 30)], &[(5, 22), (25, 26)]), vec![(0, 5), (22, 25), (26, 30)]);
        assert_eq!(less(&[(0, 10)], &[]), vec![(0, 10)]);
        assert_eq!(less(&[(0, 10)], &[(0, 10)]), vec![]);
    }
}
