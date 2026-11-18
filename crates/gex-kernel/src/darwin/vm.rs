//! A Darwin task's VM map entries, what the host's mappings do not carry:
//! where each `vm_map_entry` starts and ends, as `vm_map_enter` makes them
//! and clipping splits them, its object offset, maximum protection, user
//! tag (`VME_ALIAS`), inheritance, paging behavior, `zero_wired_pages` and
//! `no_cache`, and whether a fork left it copy-on-write (`needs_copy`) or
//! shared.
//!
//! (A shared mapping of a file opened read-only, whose maximum lacks write,
//! is refused write by the host's `mprotect` as XNU refuses it.)

use std::collections::BTreeMap;

/// `VM_PROT_ALL`.
pub const PROT_ALL: u8 = 7;

/// A task map's highest address (`vm_map_max`): `vm_compute_max_offset`'s
/// `ARM_PMAP_MAX_OFFSET_DEVICE`, which for a device with more than 3 GB of
/// memory (j120's 4 GB) is `ARM64_MAX_OFFSET_DEVICE_LARGE`, 0x138000000
/// past `ARM64_MIN_MAX_ADDRESS` (the shared region's end, 0x300000000,
/// and 512 MB). A jumbo map (`vm_map_set_jumbo`) reaches further.
pub const MAP_MAX: u64 = 0x1_8000_0000 + 0x1_8000_0000 + 0x2000_0000 + 0x1_3800_0000;

/// A jumbo map's highest address: `ARM_PMAP_MAX_OFFSET_JUMBO`, iOS's
/// `MACH_VM_MAX_ADDRESS`.
pub const JUMBO_MAX: u64 = 0xf_c000_0000;

/// Where the part of a task's map gex's memory holds ends: the 64-bit
/// memory's 16 GiB (`gex_abi::LIMIT64`, V8's memory64 cap) less the alias
/// of the commpage at its top (`gex_abi::DARWIN_COMMPAGE_ALIAS`), against
/// XNU's [`MAP_MAX`] (a jumbo map's [`JUMBO_MAX`]). What a program asks for
/// past it is reported (`Kernel::darwin_past_memory`).
pub const BACKED_END: u64 = gex_abi::DARWIN_COMMPAGE_ALIAS;
const _: () = assert!(BACKED_END < MAP_MAX && MAP_MAX < JUMBO_MAX);

/// `vm_inherit_t`.
pub mod inherit {
    pub const SHARE: u8 = 0;
    pub const COPY: u8 = 1;
    pub const NONE: u8 = 2;
    pub const DEFAULT: u8 = COPY;
}

/// `vm_behavior_t`: the ones an entry keeps.
pub mod behavior {
    pub const DEFAULT: u8 = 0;
    pub const RANDOM: u8 = 1;
    pub const SEQUENTIAL: u8 = 2;
    pub const RSEQNTL: u8 = 3;
}

/// What an entry maps: the object behind it, as far as its advice cares.
pub mod kind {
    /// Anonymous memory: an internal object (or none, until touched).
    pub const ANON: u8 = 0;
    /// A file, copy-on-write: the vnode object until a write, then a
    /// shadow of it.
    pub const FILE_PRIVATE: u8 = 1;
    /// A file, shared: the vnode object itself.
    pub const FILE_SHARED: u8 = 2;
    /// A POSIX shared memory object: internal, and named.
    pub const SHM: u8 = 3;
    /// The shared region: a submap.
    pub const SUBMAP: u8 = 4;
    /// A named memory entry's object, internal and shared through the
    /// entry (`true_share`).
    pub const OBJECT: u8 = 5;
}

/// `MACH_VM_MAX_ADDRESS` on iOS, `VM_MAX_ADDRESS` here.
pub const MACH_VM_MAX_ADDRESS: u64 = 0xf_c000_0000;

/// `vm_region_flavor_t`.
pub mod region {
    pub const BASIC_INFO_64: i32 = 9;
    pub const BASIC_INFO: i32 = 10;
    pub const EXTENDED_INFO_LEGACY: i32 = 7;
    pub const TOP_INFO: i32 = 12;
    pub const EXTENDED_INFO: i32 = 13;
    pub const BASIC_INFO_COUNT_64: u32 = 9;
    pub const BASIC_INFO_COUNT: u32 = 8;
}

/// `KERN_*` of the wiring calls.
mod kr {
    pub const SUCCESS: u64 = 0;
    pub const INVALID_ADDRESS: u64 = 1;
    pub const FAILURE: u64 = 5;
    pub const RESOURCE_SHORTAGE: u64 = 6;
}

/// `MAX_WIRE_COUNT`.
const MAX_WIRE_COUNT: u16 = 65535;
/// `vm_per_task_user_wire_limit` as `kmem_set_user_wire_limits` makes it
/// from `max_mem` on a jetsam kernel: 80% of it below 8 GiB
/// (`wire_limit_percents[bit_floor(max_mem) - 32]`, the index at least 0).
const PER_TASK_USER_WIRE_LIMIT: u64 = super::mig::machine::MEM_SIZE * 80 / 100;

/// `ANON_CHUNK_SIZE`: anonymous memory is entered in entries of at most this.
pub const ANON_CHUNK_SIZE: u64 = 128 << 20;

/// The `VM_MEMORY_*` tags a malloc region carries.
pub mod tag {
    pub const MALLOC: u8 = 1;
    pub const MALLOC_SMALL: u8 = 2;
    pub const MALLOC_LARGE: u8 = 3;
    pub const REALLOC: u8 = 6;
    pub const MALLOC_TINY: u8 = 7;
    pub const MALLOC_LARGE_REUSABLE: u8 = 8;
    pub const MALLOC_LARGE_REUSED: u8 = 9;
    pub const SHARED_PMAP: u8 = 32;
    pub const DYLD: u8 = 60;
}

/// One entry's attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attrs {
    pub kind: u8,
    pub max: u8,
    pub alias: u8,
    pub inherit: u8,
    pub behavior: u8,
    pub zero_wired: bool,
    pub no_cache: bool,
    /// Copy-on-write since a fork: its object is shared with the other
    /// task's entry until one of them writes (and gets a shadow object).
    pub cow: bool,
    /// `used_for_jit`: the map's JIT region, writable and executable at
    /// once.
    pub jit: bool,
    /// `is_shared`: another map has the entry too.
    pub shared: bool,
    /// `wired_count` and `user_wired_count`.
    pub wired: u16,
    pub user_wired: u16,
    /// `VME_OBJECT`: the object it maps ([`super::vmobject`]), 0 for the
    /// task's own anonymous memory, which no one else names.
    pub obj: u64,
    /// `!use_pmap`: its object (purgeable or ledger-tagged) has ledgers of
    /// its own, and a page the pmap enters here is alternate accounting,
    /// not the task's footprint.
    pub alt: bool,
}

impl Default for Attrs {
    fn default() -> Attrs {
        Attrs { kind: kind::ANON, max: PROT_ALL, alias: 0, inherit: inherit::DEFAULT, behavior: behavior::DEFAULT, zero_wired: false, no_cache: false, cow: false, jit: false, shared: false, wired: 0, user_wired: 0, obj: 0, alt: false }
    }
}

/// One entry past its start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    end: u64,
    attrs: Attrs,
    /// `VME_OFFSET`.
    offset: u64,
}

/// What `mach_vm_region` reports of an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryInfo {
    pub start: u64,
    pub end: u64,
    pub attrs: Attrs,
    pub offset: u64,
}

/// A task's map entries, by start: the task's own, and other tasks'
/// kernels' for one operation at a time (a remap from this map, a file's
/// change of size), through [`Entries::shared`].
///
/// An entry that names an object ([`Attrs::obj`]) holds a reference to it
/// ([`super::vmobject`]) for as long as it is in the map.
pub struct Entries {
    map: std::sync::Arc<crate::sync::Mutex<Map>>,
    /// `jit_entry_exists`: the map has had its JIT region (it stays set
    /// once the region is unmapped).
    pub jit_entry_exists: bool,
    /// `user_wire_limit`, none being the unlimited one a new map starts
    /// with.
    pub user_wire_limit: Option<u64>,
}

impl Default for Entries {
    fn default() -> Entries {
        Entries::of(Map::default(), None)
    }
}

impl std::fmt::Debug for Entries {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Entries")
    }
}

/// The entries themselves, as [`Entries`] shares them.
#[derive(Debug, Default)]
pub struct Map {
    ranges: BTreeMap<u64, Entry>,
    /// `user_wire_size`.
    user_wire_size: u64,
    /// Where the task's `wired_mem` ledger is read by others: the bytes
    /// the user's wirings hold, kept as `user_wire_size` changes.
    wired_gauge: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    /// Where the map's submap entries (the shared region's) are read by
    /// the task's footprint meter, its own and other processes'.
    submap_gauge: Option<std::sync::Arc<std::sync::Mutex<Vec<(u64, u64)>>>>,
    /// And its entries with `use_pmap` off.
    alt_gauge: Option<std::sync::Arc<std::sync::Mutex<Vec<(u64, u64)>>>>,
}

impl Drop for Map {
    /// The map's end (`vm_map_destroy`): each entry's reference given back.
    fn drop(&mut self) {
        for (_, e) in std::mem::take(&mut self.ranges) {
            super::vmobject::release(e.attrs.obj);
        }
    }
}

impl Entries {
    fn of(map: Map, user_wire_limit: Option<u64>) -> Entries {
        Entries { map: std::sync::Arc::new(crate::sync::Mutex::ranked(map, crate::sync::rank::ENTRIES)), jit_entry_exists: false, user_wire_limit }
    }

    /// A new image's map, with `vm_map_set_user_wire_limit`'s limit.
    pub fn with_user_wire_limit(limit: u64) -> Entries {
        Entries::of(Map::default(), Some(limit))
    }

    /// The entries, held for one operation.
    pub fn lock(&self) -> crate::sync::MutexGuard<'_, Map> {
        self.map.lock()
    }

    /// The entries as another task's kernel reaches them.
    pub fn shared(&self) -> std::sync::Arc<crate::sync::Mutex<Map>> {
        std::sync::Arc::clone(&self.map)
    }

    /// The task's `wired_mem` ledger, which this map's wirings now keep
    /// (a map's pmap is its task's: a wiring enters wired pages, which
    /// `pte_set_wired` credits to it, and an unwiring or the entry's
    /// removal debits them).
    pub fn set_wire_gauge(&mut self, gauge: std::sync::Arc<std::sync::atomic::AtomicU64>) {
        let mut m = self.lock();
        gauge.store(m.user_wire_size, std::sync::atomic::Ordering::Release);
        m.wired_gauge = Some(gauge);
    }

    /// The task's footprint meter's view of the submaps, which this map's
    /// entries now keep.
    pub fn set_submap_gauge(&mut self, gauge: std::sync::Arc<std::sync::Mutex<Vec<(u64, u64)>>>) {
        let mut m = self.lock();
        m.submap_gauge = Some(gauge);
        m.submaps_changed();
    }

    /// The task's footprint meter's view of the entries with `use_pmap`
    /// off, which this map's entries now keep.
    pub fn set_alt_gauge(&mut self, gauge: std::sync::Arc<std::sync::Mutex<Vec<(u64, u64)>>>) {
        let mut m = self.lock();
        m.alt_gauge = Some(gauge);
        m.alt_changed();
    }

    /// See [`Map::clip`].
    pub fn clip(&mut self, at: u64) {
        self.lock().clip(at)
    }

    /// See [`Map::clip_range`].
    pub fn clip_range(&mut self, start: u64, end: u64) {
        self.lock().clip_range(start, end)
    }

    /// See [`Map::clear`].
    pub fn clear(&mut self, start: u64, end: u64) {
        self.lock().clear(start, end)
    }

    /// See [`Map::enter`].
    pub fn enter(&mut self, start: u64, end: u64, attrs: Attrs, offset: u64) {
        self.lock().enter(start, end, attrs, offset)
    }

    /// See [`Map::enter_anon`].
    pub fn enter_anon(&mut self, start: u64, end: u64, attrs: Attrs, prev_same_prot: bool) {
        self.lock().enter_anon(start, end, attrs, prev_same_prot)
    }

    /// See [`Map::update`].
    pub fn update(&mut self, start: u64, end: u64, f: impl Fn(&mut Attrs)) {
        self.lock().update(start, end, f)
    }

    /// See [`Map::update_whole`].
    pub fn update_whole(&mut self, start: u64, end: u64, f: impl Fn(&mut Attrs)) {
        self.lock().update_whole(start, end, f)
    }

    /// See [`Map::wire`]; the map's limit is `user_wire_limit`.
    pub fn wire(&mut self, start: u64, end: u64) -> u64 {
        let limit = self.user_wire_limit;
        self.lock().wire(start, end, limit)
    }

    /// See [`Map::unwire`].
    pub fn unwire(&mut self, start: u64, end: u64) -> u64 {
        self.lock().unwire(start, end)
    }

    /// See [`Map::pieces`].
    pub fn pieces(&self, start: u64, end: u64) -> Vec<(u64, u64, Attrs)> {
        self.lock().pieces(start, end)
    }

    /// See [`Map::size_and_count`].
    pub fn size_and_count(&self) -> (u64, u32) {
        self.lock().size_and_count()
    }

    /// See [`Map::submaps`].
    pub fn submaps(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        self.lock().submaps(start, end)
    }

    /// See [`Map::at_or_after`].
    pub fn at_or_after(&self, addr: u64) -> Option<EntryInfo> {
        self.lock().at_or_after(addr)
    }

    /// See [`Map::fork`].
    pub fn fork(&mut self, mapped: &[(u64, u64)]) {
        self.lock().fork(mapped)
    }

    /// See [`Map::inherited_jit`].
    pub fn inherited_jit(&self) -> Vec<(u64, u64)> {
        self.lock().inherited_jit()
    }

    /// The child's entries from a map [`Entries::fork`] has marked: those
    /// inherited by copy or share; one not inherited is absent.
    pub fn inherited(&self) -> Entries {
        Entries::of(self.lock().inherited(), self.user_wire_limit)
    }

    /// See [`Map::inherited_corpse`].
    pub fn inherited_corpse(&self, shared: &[(u64, u64)]) -> Entries {
        Entries::of(self.lock().inherited_corpse(shared), self.user_wire_limit)
    }
}

impl Map {
    /// Entry `e` at `start`, holding a reference to its object; what was
    /// there before gives its own back.
    fn put(&mut self, start: u64, e: Entry) {
        super::vmobject::reference(e.attrs.obj);
        if let Some(old) = self.ranges.insert(start, e) {
            super::vmobject::release(old.attrs.obj);
        }
    }

    /// The entry at `start` taken out, its reference given back.
    fn take(&mut self, start: u64) -> Option<Entry> {
        let e = self.ranges.remove(&start)?;
        super::vmobject::release(e.attrs.obj);
        Some(e)
    }

    /// The entries with `use_pmap` off, told to their gauge.
    fn alt_changed(&self) {
        if let Some(g) = &self.alt_gauge {
            *g.lock().unwrap_or_else(|e| e.into_inner()) = self.ranges.iter().filter(|(_, e)| e.attrs.alt).map(|(&s, e)| (s, e.end)).collect();
        }
    }

    /// The submap entries, told to the gauge.
    fn submaps_changed(&self) {
        if let Some(g) = &self.submap_gauge {
            *g.lock().unwrap_or_else(|e| e.into_inner()) = self.submaps(0, u64::MAX);
        }
    }

    /// `user_wire_size`, told to the gauge.
    fn wire_size_changed(&self) {
        if let Some(g) = &self.wired_gauge {
            g.store(self.user_wire_size, std::sync::atomic::Ordering::Release);
        }
    }

    /// `vm_map_clip_start`: no entry crosses `at`; the upper half's offset
    /// moves with it, and it holds a reference of its own to the object.
    pub fn clip(&mut self, at: u64) {
        let Some((&s, &entry)) = self.ranges.range(..at).next_back() else { return };
        if entry.end > at {
            self.put(s, Entry { end: at, ..entry });
            self.put(at, Entry { offset: entry.offset + (at - s), ..entry });
        }
    }

    /// Clip at both ends of `[start, end)`.
    pub fn clip_range(&mut self, start: u64, end: u64) {
        self.clip(start);
        self.clip(end);
    }

    /// `[start, end)` no longer mapped.
    pub fn clear(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        self.clip_range(start, end);
        let inside: Vec<u64> = self.ranges.range(start..end).map(|(&s, _)| s).collect();
        let (mut submap, mut alt) = (false, false);
        for s in inside {
            if let Some(e) = self.take(s) {
                if e.attrs.user_wired > 0 {
                    self.user_wire_size -= e.end - s;
                }
                submap |= e.attrs.kind == kind::SUBMAP;
                alt |= e.attrs.alt;
            }
        }
        self.wire_size_changed();
        if submap {
            self.submaps_changed();
        }
        if alt {
            self.alt_changed();
        }
    }

    /// `[start, end)` becomes one new entry, as a new mapping over it does.
    pub fn enter(&mut self, start: u64, end: u64, attrs: Attrs, offset: u64) {
        self.clear(start, end);
        if start < end {
            self.put(start, Entry { end, attrs, offset });
            if attrs.kind == kind::SUBMAP {
                self.submaps_changed();
            }
            if attrs.alt {
                self.alt_changed();
            }
        }
    }

    /// `vm_map_enter` of anonymous memory, `prev_same_prot` saying whether
    /// the entry below has the new one's current protection: entries of at
    /// most [`ANON_CHUNK_SIZE`] (unless the maximum protection is none), the
    /// first extending the entry below when it can.
    pub fn enter_anon(&mut self, start: u64, end: u64, attrs: Attrs, prev_same_prot: bool) {
        self.clear(start, end);
        if start >= end {
            return;
        }
        let size = end - start;
        let chunked = size > ANON_CHUNK_SIZE && attrs.max != 0;
        let first_end = if chunked { start + ANON_CHUNK_SIZE } else { end };
        if !self.coalesce(start, first_end, attrs, prev_same_prot) {
            self.put(start, Entry { end: first_end, attrs, offset: 0 });
        }
        let mut at = first_end;
        while at < end {
            let e = if end - at > ANON_CHUNK_SIZE { at + ANON_CHUNK_SIZE } else { end };
            self.put(at, Entry { end: e, attrs, offset: 0 });
            at = e;
        }
    }

    /// `vm_map_enter`'s extension of the entry below over `[start, end)`.
    /// `NO_COALESCE_LIMIT` is zero on this platform, so only a
    /// `VM_MEMORY_REALLOC` request can extend one (up to
    /// [`ANON_CHUNK_SIZE`]). The object must be its entry's alone
    /// (`vm_object_coalesce`): none since a fork left it shared.
    fn coalesce(&mut self, start: u64, end: u64, attrs: Attrs, prev_same_prot: bool) -> bool {
        if attrs.alias != tag::REALLOC || attrs.jit || !prev_same_prot || attrs.obj != 0 {
            return false;
        }
        let Some((&s, prev)) = self.ranges.range_mut(..start).next_back() else { return false };
        let p = prev.attrs;
        let joins = prev.end == start
            && !p.shared
            && p.kind == kind::ANON
            && p.obj == 0
            && !p.cow
            && p.behavior == behavior::DEFAULT
            && p.max == attrs.max
            && p.inherit == attrs.inherit
            && p.no_cache == attrs.no_cache
            && !p.zero_wired
            && p.wired == 0
            && !p.jit
            && (prev.end - s) + (end - start) <= ANON_CHUNK_SIZE;
        if joins {
            prev.end = end;
        }
        joins
    }

    /// Change each entry of `[start, end)` by `f`, clipped to it. An entry
    /// `f` gives another object holds a reference to the new one instead.
    pub fn update(&mut self, start: u64, end: u64, f: impl Fn(&mut Attrs)) {
        self.clip_range(start, end);
        let (mut submap, mut alt) = (false, false);
        let mut objs = Vec::new();
        for (_, e) in self.ranges.range_mut(start..end) {
            let (was, obj, was_alt) = (e.attrs.kind == kind::SUBMAP, e.attrs.obj, e.attrs.alt);
            f(&mut e.attrs);
            submap |= was != (e.attrs.kind == kind::SUBMAP);
            alt |= was_alt != e.attrs.alt;
            if obj != e.attrs.obj {
                objs.push((obj, e.attrs.obj));
            }
        }
        for (old, new) in objs {
            super::vmobject::reference(new);
            super::vmobject::release(old);
        }
        if submap {
            self.submaps_changed();
        }
        if alt {
            self.alt_changed();
        }
    }

    /// Change every entry overlapping `[start, end)` whole, unclipped, as
    /// the reusable-pages calls retag an entry.
    pub fn update_whole(&mut self, start: u64, end: u64, f: impl Fn(&mut Attrs)) {
        let first = self.ranges.range(..=start).next_back().filter(|(_, e)| e.end > start).map_or(start, |(&s, _)| s);
        let mut submap = false;
        for (_, e) in self.ranges.range_mut(first..end) {
            let (was, obj) = (e.attrs.kind == kind::SUBMAP, e.attrs.obj);
            f(&mut e.attrs);
            assert_eq!(obj, e.attrs.obj, "update_whole changes no entry's object");
            submap |= was != (e.attrs.kind == kind::SUBMAP);
        }
        if submap {
            self.submaps_changed();
        }
    }

    /// `vm_map_wire_nested` for the user, access unstated (`mlock`): every
    /// entry in `[start, end)` gets a wiring (`add_wire_counts`), the ones
    /// before a hole or a limit none, `user_wire_limit` being the map's
    /// limit. The kernel's return code.
    pub fn wire(&mut self, start: u64, end: u64, user_wire_limit: Option<u64>) -> u64 {
        if start == end {
            return kr::SUCCESS;
        }
        self.clip_range(start, end);
        let mut s = start;
        let mut rc = kr::SUCCESS;
        while s < end {
            let Some(e) = self.ranges.get_mut(&s) else {
                rc = kr::INVALID_ADDRESS;
                break;
            };
            let size = e.end - s;
            let next = e.end;
            if e.attrs.user_wired == 0 {
                let limit = user_wire_limit.unwrap_or(u64::MAX).min(PER_TASK_USER_WIRE_LIMIT);
                if size + self.user_wire_size > limit {
                    rc = kr::RESOURCE_SHORTAGE;
                    break;
                }
                if e.attrs.wired == MAX_WIRE_COUNT {
                    rc = kr::FAILURE;
                    break;
                }
                e.attrs.wired += 1;
                self.user_wire_size += size;
            }
            if e.attrs.user_wired == MAX_WIRE_COUNT {
                rc = kr::FAILURE;
                break;
            }
            e.attrs.user_wired += 1;
            s = next;
        }
        if rc != kr::SUCCESS {
            self.unwire(start, s);
        }
        self.wire_size_changed();
        rc
    }

    /// `vm_map_unwire_nested` for the user: `[start, end)` loses a wiring
    /// where it has one. Only a start in no entry is an error.
    pub fn unwire(&mut self, start: u64, end: u64) -> u64 {
        if start == end {
            return kr::SUCCESS;
        }
        if !self.ranges.range(..=start).next_back().is_some_and(|(_, e)| e.end > start) {
            return kr::INVALID_ADDRESS;
        }
        self.clip_range(start, end);
        let mut released = 0;
        for (&s, e) in self.ranges.range_mut(start..end) {
            if e.attrs.wired == 0 || e.attrs.user_wired == 0 {
                continue;
            }
            if e.attrs.user_wired == 1 {
                e.attrs.wired -= 1;
                released += e.end - s;
            }
            e.attrs.user_wired -= 1;
        }
        self.user_wire_size -= released;
        self.wire_size_changed();
        kr::SUCCESS
    }

    /// The pieces of `[start, end)` and the attributes of each: the default
    /// ones for what no entry covers.
    pub fn pieces(&self, start: u64, end: u64) -> Vec<(u64, u64, Attrs)> {
        self.pieces_at(start, end).into_iter().map(|(s, e, a, _)| (s, e, a)).collect()
    }

    /// [`Map::pieces`] with each piece's offset in its object
    /// (`VME_OFFSET` moved to the piece's start; 0 where no entry is).
    pub fn pieces_at(&self, start: u64, end: u64) -> Vec<(u64, u64, Attrs, u64)> {
        let mut out = Vec::new();
        if start >= end {
            return out;
        }
        let mut at = start;
        let first = self.ranges.range(..=start).next_back().filter(|(_, e)| e.end > start).map_or(start, |(&s, _)| s);
        for (&s, e) in self.ranges.range(first..end) {
            let (ps, stop) = (s.max(start), e.end.min(end));
            if ps > at {
                out.push((at, ps, Attrs::default(), 0));
            }
            out.push((ps, stop, e.attrs, e.offset + (ps - s)));
            at = stop;
        }
        if at < end {
            out.push((at, end, Attrs::default(), 0));
        }
        out
    }

    /// The map's size (`map->size`, every entry's bytes) and its entries
    /// (`map->hdr.nentries`).
    pub fn size_and_count(&self) -> (u64, u32) {
        self.ranges.iter().fold((0, 0), |(size, n), (&s, e)| (size + (e.end - s), n + 1))
    }

    /// The submap entries (the shared region's) that meet `[start, end)`,
    /// clipped to it.
    pub fn submaps(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        if start >= end {
            return Vec::new();
        }
        let first = self.ranges.range(..=start).next_back().filter(|(_, e)| e.end > start).map_or(start, |(&s, _)| s);
        self.ranges.range(first..end).filter(|(_, e)| e.attrs.kind == kind::SUBMAP && e.end > start).map(|(&s, e)| (s.max(start), e.end.min(end))).collect()
    }

    /// The entries of `[start, end)` given object `obj` (a reference each),
    /// their offsets running from `offset` at `start`: an object made for
    /// them (`vm_map_copy_extract`'s for an entry that had none), which
    /// they then share.
    pub fn set_object(&mut self, start: u64, end: u64, obj: u64, offset: u64) {
        self.clip_range(start, end);
        let starts: Vec<u64> = self.ranges.range(start..end).map(|(&s, _)| s).collect();
        for s in starts {
            if let Some(e) = self.ranges.get(&s).copied() {
                let attrs = Attrs { obj, cow: false, shared: true, ..e.attrs };
                self.put(s, Entry { attrs, offset: offset + (s - start), ..e });
            }
        }
        self.alt_changed();
    }

    /// The entries in `[start, end)`, clipped to it, each with its offset in
    /// its object: what [`Map::restore`] puts back.
    pub fn snapshot(&self, start: u64, end: u64) -> Vec<(u64, u64, Attrs, u64)> {
        let first = self.ranges.range(..=start).next_back().filter(|(_, e)| e.end > start).map_or(start, |(&s, _)| s);
        self.ranges.range(first..end).filter(|(_, e)| e.end > start).map(|(&s, e)| (s.max(start), e.end.min(end), e.attrs, e.offset + (s.max(start) - s))).collect()
    }

    /// The entries of a [`Map::snapshot`] again (a mapping that failed
    /// after taking their place: `vm_map_enter`'s restore of what it
    /// zapped).
    pub fn restore(&mut self, snap: Vec<(u64, u64, Attrs, u64)>) {
        for (s, e, a, off) in snap {
            self.enter(s, e, a, off);
        }
    }

    /// The entries that name object `obj`: each one's range and its offset
    /// in the object at its start.
    pub fn of_object(&self, obj: u64) -> Vec<(u64, u64, Attrs, u64)> {
        if obj == 0 {
            return Vec::new();
        }
        self.ranges.iter().filter(|(_, e)| e.attrs.obj == obj).map(|(&s, e)| (s, e.end, e.attrs, e.offset)).collect()
    }

    /// `vm_map_lookup_entry` then `vme_next`: the entry at `addr`, or the
    /// first past it.
    pub fn at_or_after(&self, addr: u64) -> Option<EntryInfo> {
        let hit = self.ranges.range(..=addr).next_back().filter(|(_, e)| e.end > addr);
        let (&start, e) = hit.or_else(|| self.ranges.range(addr..).next())?;
        Some(EntryInfo { start, end: e.end, attrs: e.attrs, offset: e.offset })
    }

    /// `vm_map_fork`'s mark on the forking task's map, over its mapped
    /// ranges `mapped`: an entry inherited by copy is copy-on-write
    /// afterwards, in both maps, and one inherited by share is shared.
    pub fn fork(&mut self, mapped: &[(u64, u64)]) {
        for &(s, e) in mapped {
            self.update(s, e, |a| match a.inherit {
                inherit::COPY => a.cow = true,
                inherit::SHARE => a.shared = true,
                _ => {}
            });
        }
    }

    /// The JIT region's ranges a fork's child inherits (`vm_inherit` made
    /// it so): its copy is to lose execute access.
    pub fn inherited_jit(&self) -> Vec<(u64, u64)> {
        self.ranges.iter().filter(|(_, e)| e.attrs.jit && e.attrs.inherit != inherit::NONE).map(|(&s, e)| (s, e.end)).collect()
    }

    /// The child's entries from a map [`Map::fork`] has marked: those
    /// inherited by copy or share, each with its reference to its object;
    /// one not inherited is absent.
    pub fn inherited(&self) -> Map {
        let mut child = Map::default();
        for (&s, &entry) in &self.ranges {
            if entry.attrs.inherit != inherit::NONE {
                child.put(s, Entry { attrs: child_attrs(entry.attrs), ..entry });
            }
        }
        child
    }

    /// A corpse fork's entries (`vm_map_fork` with
    /// VM_MAP_FORK_SHARE_IF_INHERIT_NONE): those [`Map::inherited`] gives,
    /// and the entries not inherited that the fork shares instead (those
    /// starting in `shared`).
    pub fn inherited_corpse(&self, shared: &[(u64, u64)]) -> Map {
        let mut child = self.inherited();
        for (&s, &entry) in &self.ranges {
            if entry.attrs.inherit == inherit::NONE && shared.iter().any(|&(a, b)| a <= s && s < b) {
                child.put(s, Entry { attrs: child_attrs(entry.attrs), ..entry });
            }
        }
        child
    }
}

/// A fork's copy of an entry's attributes: a wiring is the map's own, and
/// (vm_map_entry_copy_code_signing: an iOS map allows no copy of a JIT
/// region, VM_MAP_POLICY_ALLOW_JIT_COPY) a JIT region's copy loses execute
/// access and is no JIT region.
fn child_attrs(mut a: Attrs) -> Attrs {
    a.wired = 0;
    a.user_wired = 0;
    if a.jit {
        a.jit = false;
        a.max &= !4;
    }
    a
}

/// `vm_map_entry_is_reusable` for an entry that is not wired and whose
/// protection is `prot`. `None` when the answer depends on whether either
/// task wrote to it since a fork (a shadow object).
pub fn reusable(a: &Attrs, prot: u8) -> Option<bool> {
    use tag::*;
    const VM_PROT_DEFAULT: u8 = 3;
    if a.kind == kind::SUBMAP {
        return Some(false);
    }
    if !matches!(a.alias, MALLOC | MALLOC_SMALL | MALLOC_LARGE | REALLOC | MALLOC_TINY | MALLOC_LARGE_REUSABLE | MALLOC_LARGE_REUSED) {
        return Some(true);
    }
    if prot != VM_PROT_DEFAULT || a.max != PROT_ALL || a.inherit != inherit::DEFAULT || a.no_cache || a.zero_wired {
        return Some(false);
    }
    // The object: none yet, or internal with no copy, no shadow and not
    // purgeable (a file's is external, or a shadow of it).
    match a.kind {
        kind::ANON if a.cow => None,
        kind::ANON | kind::SHM => Some(true),
        _ => Some(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: u64 = 0x4000;

    fn max(m: u8) -> Attrs {
        Attrs { max: m, ..Attrs::default() }
    }

    fn entry_starts(e: &Entries, end: u64) -> Vec<u64> {
        let mut out = Vec::new();
        let mut at = 0;
        while let Some(i) = e.at_or_after(at).filter(|i| i.start < end) {
            out.push(i.start);
            at = i.end;
        }
        out
    }

    #[test]
    fn a_clip_splits_and_nothing_rejoins() {
        let mut e = Entries::default();
        e.enter(0, 4 * K, Attrs::default(), 0);
        e.update(K, 2 * K, |a| a.max = 1);
        assert_eq!(entry_starts(&e, 4 * K), vec![0, K, 2 * K]);
        e.update(K, 2 * K, |a| a.max = 7);
        assert_eq!(entry_starts(&e, 4 * K), vec![0, K, 2 * K], "a clip is not undone");
    }

    #[test]
    fn the_offset_moves_with_the_upper_half() {
        let mut e = Entries::default();
        e.enter(4 * K, 8 * K, Attrs { kind: kind::FILE_PRIVATE, ..Attrs::default() }, 0x1000);
        e.clip(5 * K);
        assert_eq!(e.at_or_after(5 * K).unwrap().offset, 0x1000 + K);
        assert_eq!(e.at_or_after(4 * K).unwrap().offset, 0x1000);
    }

    #[test]
    fn only_realloc_memory_extends_the_entry_below() {
        let mut e = Entries::default();
        e.enter_anon(0, K, Attrs::default(), false);
        e.enter_anon(K, 2 * K, Attrs::default(), true);
        assert_eq!(entry_starts(&e, 2 * K), vec![0, K], "NO_COALESCE_LIMIT is zero");
        let r = Attrs { alias: tag::REALLOC, ..Attrs::default() };
        let mut e = Entries::default();
        e.enter_anon(0, K, r, false);
        e.enter_anon(K, 2 * K, r, true);
        assert_eq!(entry_starts(&e, 2 * K), vec![0]);
        e.enter_anon(2 * K, 3 * K, r, false);
        assert_eq!(entry_starts(&e, 3 * K), vec![0, 2 * K], "another protection");
    }

    #[test]
    fn large_anonymous_memory_is_entered_in_chunks() {
        let mut e = Entries::default();
        let size = 3 * ANON_CHUNK_SIZE - K;
        e.enter_anon(0, size, Attrs::default(), false);
        assert_eq!(entry_starts(&e, size), vec![0, ANON_CHUNK_SIZE, 2 * ANON_CHUNK_SIZE]);
        let mut e = Entries::default();
        e.enter_anon(0, size, max(0), false);
        assert_eq!(entry_starts(&e, size), vec![0], "no chunks for what can never be touched");
    }

    #[test]
    fn a_fork_copies_by_inheritance() {
        let mut e = Entries::default();
        e.enter(0, K, Attrs::default(), 0);
        e.enter(K, 2 * K, Attrs { inherit: inherit::SHARE, ..Attrs::default() }, 0);
        e.enter(2 * K, 3 * K, Attrs { inherit: inherit::NONE, ..Attrs::default() }, 0);
        e.fork(&[(0, 3 * K)]);
        let c = e.inherited();
        assert_eq!(entry_starts(&c, 3 * K), vec![0, K]);
        assert!(c.at_or_after(0).unwrap().attrs.cow);
        assert!(c.at_or_after(K).unwrap().attrs.shared);
        assert!(e.at_or_after(K).unwrap().attrs.shared, "the parent's is shared too");
    }

    #[test]
    fn the_wired_ledger_follows_the_users_wirings() {
        let g = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut e = Entries::default();
        e.set_wire_gauge(std::sync::Arc::clone(&g));
        e.enter(0, 4 * K, Attrs::default(), 0);
        let wired = || g.load(std::sync::atomic::Ordering::Acquire);
        assert_eq!(e.wire(K, 3 * K), kr::SUCCESS);
        assert_eq!(wired(), 2 * K);
        // A second wiring of a page holds nothing more.
        assert_eq!(e.wire(K, 2 * K), kr::SUCCESS);
        assert_eq!(wired(), 2 * K);
        assert_eq!(e.unwire(2 * K, 3 * K), kr::SUCCESS);
        assert_eq!(wired(), K);
        // Unmapping a wired entry releases it; a fork's child has none.
        e.clear(0, 2 * K);
        assert_eq!(wired(), 0);
        assert_eq!(e.wire(3 * K, 4 * K), kr::SUCCESS);
        let mut c = e.inherited();
        let cg = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(7));
        c.set_wire_gauge(std::sync::Arc::clone(&cg));
        assert_eq!((wired(), cg.load(std::sync::atomic::Ordering::Acquire)), (K, 0));
    }

    #[test]
    fn only_a_malloc_region_in_its_first_state_is_reusable() {
        let rw = 3;
        assert_eq!(reusable(&Attrs::default(), 1), Some(true));
        let malloc = Attrs { alias: tag::MALLOC_TINY, ..Attrs::default() };
        assert_eq!(reusable(&malloc, rw), Some(true));
        assert_eq!(reusable(&malloc, 1), Some(false));
        assert_eq!(reusable(&Attrs { max: 3, ..malloc }, rw), Some(false));
        assert_eq!(reusable(&Attrs { zero_wired: true, ..malloc }, rw), Some(false));
        assert_eq!(reusable(&Attrs { cow: true, ..malloc }, rw), None);
        assert_eq!(reusable(&Attrs { kind: kind::FILE_PRIVATE, ..malloc }, rw), Some(false));
        assert_eq!(reusable(&Attrs { kind: kind::SUBMAP, ..Attrs::default() }, rw), Some(false));
    }
}
