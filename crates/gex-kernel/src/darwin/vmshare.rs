//! Pages two mappings hold at once, and pages a map has not entered yet:
//! `vm_map_fork`'s inheritance (`vm_map.c`, xnu-10063.141.1).
//!
//! A task's memory is the host's, so a page one mapping shares with
//! another, or copies on write from it, is the host's mapping of the one's
//! pages at the other's addresses ([`crate::set_host_remap`]), whatever
//! process each is in: a write through a shared mapping is seen through
//! the other at once, and a copy is made only by the first write to it.
//!
//! What a mapping made that way holds is not the task's pmap's until the
//! task touches it: `vm_map_fork` copies no entry of the parent's pmap into
//! the child's, and `vm_map_remap` and `vm_map_copy_overwrite` remove the
//! destination's (`pmap_remove`) and enter nothing. Those pages are kept
//! not entered ([`crate::mem::MemoryMap::set_unentered`]): the task's first
//! access to one, or a call's copy to or from it, faults to the kernel,
//! which enters it, and only then does the footprint see it.

use super::ipc::kr;
use super::mach::{prot, vmf, PAGE_MASK};
use super::vm::{inherit, kind, Attrs};
use crate::syscalls::{nr, Kernel};
use crate::GuestMem;

const KERN_PROTECTION_FAILURE: u64 = 2;

/// Where a remap takes its pages from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The target's own map.
    Same,
    /// Another task's map (its task key).
    Other(u64),
}

/// `vm_map_remap`'s arguments, and what it gives back (`target`,
/// `cur`, `max`).
#[derive(Clone, Copy, Debug)]
pub struct Remap {
    pub target: u64,
    pub size: u64,
    pub mask: u64,
    pub flags: u64,
    pub src: Source,
    pub src_addr: u64,
    pub copy: bool,
    pub cur: u64,
    pub max: u64,
    pub inherit: u32,
    /// `vmkf_remap_prot_copy`: `vm_map_protect`'s VM_PROT_COPY.
    pub prot_copy: bool,
}

/// One entry `vm_map_remap_extract` makes: its place relative to the
/// range's start, its protection and its attributes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Extracted {
    pub off: u64,
    pub len: u64,
    pub prot: u64,
    pub attrs: Attrs,
    /// `VME_OFFSET` of the new entry: its source's place in their object.
    pub obj_off: u64,
    /// The source entry's kind.
    pub src_kind: u8,
}

/// What a remap from another task's map took of it: the new entries, the
/// host's hold of its pages, and its absent pages and pages the file still
/// holds over the range (by address, and by page).
pub(crate) struct Other {
    pub extracted: Vec<Extracted>,
    pub hold: std::sync::Arc<super::vmobject::Hold>,
    pub absent: Vec<(u64, u64)>,
    pub pending: Vec<(u64, u64)>,
}

/// How a fork's child gets one range of its parent's map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inherit {
    /// `VM_INHERIT_COPY`: a copy on write of the parent's pages.
    Copy,
    /// `VM_INHERIT_SHARE`: the parent's pages themselves.
    Share,
    /// `VM_INHERIT_NONE`: nothing; the range is a hole in the child.
    None,
}

/// One range of a fork: `[start, end)`, how the child gets it, and whether
/// its pages are the task's pmap's to enter (not a submap's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkRange {
    pub start: u64,
    pub end: u64,
    pub how: Inherit,
    pub own_pmap: bool,
}

/// `vm_map_remap_extract` of `[start, start + size)` of a map, its memory
/// map `mm` and entries `ents` (`same_map`: into the map itself): the new
/// entries, or the error and what is reported of it. The legacy call's
/// strictest protections go back in `a.cur` and `a.max`.
pub(crate) fn extract(mm: &mut crate::mem::MemoryMap, ents: &super::vm::Map, start: u64, size: u64, a: &mut Remap, same_map: bool) -> Result<Vec<Extracted>, (u64, Option<String>)> {
    let end = start + size;
    let mut max_prot_for_prot_copy = 0;
    if a.copy && a.prot_copy {
        max_prot_for_prot_copy = a.max & prot::ALL;
        a.cur = 0;
        a.max = 0;
    }
    let legacy = a.cur == 0 && a.max == 0;
    let (req_cur, req_max) = if legacy {
        a.cur = prot::ALL;
        a.max = prot::ALL;
        (0, 0)
    } else if a.copy {
        (0, prot::READ)
    } else {
        (a.cur, a.max)
    };
    let vmas: Vec<(u64, u64, u64)> = {
        let mut v: Vec<_> = mm.vmas().iter().filter(|v| v.end > start && v.start < end).map(|v| (v.start.max(start), v.end.min(end), u64::from(v.prot) & prot::ALL)).collect();
        v.sort();
        v
    };
    let pending = mm.copy_pending_runs();
    let mut out = Vec::new();
    let mut at = start;
    for (vs, ve, cur) in vmas {
        // A hole before it: vm_map_lookup_entry finds nothing.
        if vs > at {
            return Err((kr::INVALID_ADDRESS, None));
        }
        let pieces = ents.pieces_at(vs, ve);
        for (ps, pe, attrs, obj_off) in pieces {
            if attrs.kind == kind::SUBMAP {
                return Err((kr::FAILURE, Some(format!("mach_vm_remap of the shared region's submap at {ps:#x} (its entries are the region's)"))));
            }
            let max = u64::from(attrs.max);
            if cur & req_cur != req_cur || max & req_max != req_max {
                return Err((KERN_PROTECTION_FAILURE, None));
            }
            // An iOS map shares no JIT region with another map
            // (VM_MAP_POLICY_ALLOW_JIT_SHARING).
            if !a.copy && attrs.jit && !same_map {
                return Err((kr::INVALID_ARGUMENT, None));
            }
            // A private mapping's pages the file still holds, shared:
            // a write through either would copy them for both
            // (their shadow object), which pages kept per map cannot
            // say.
            if !a.copy && attrs.kind == kind::FILE_PRIVATE && super::ubc::vnode(attrs.obj).is_some() {
                if pending.iter().any(|&(s, e)| (s << gex_abi::PERM_PAGE_SHIFT) < pe && (e << gex_abi::PERM_PAGE_SHIFT) > ps) {
                    return Err((kr::FAILURE, Some(format!("a shared remap of a private file mapping's pages at {ps:#x} the file still holds (the copy a write makes is both mappings')"))));
                }
            }
            // vm_map_entry_copy: no wiring, not shared, and (an iOS map
            // allows no JIT copy) a JIT region's copy loses execute.
            let mut n = Attrs { wired: 0, user_wired: 0, shared: false, ..attrs };
            let mut p = cur;
            if attrs.jit {
                n.jit = false;
                p &= !prot::EXECUTE;
                n.max &= !(prot::EXECUTE as u8);
            }
            if a.copy && a.prot_copy {
                n.max |= prot::WRITE as u8;
                p &= max_prot_for_prot_copy;
            } else {
                n.inherit = a.inherit as u8;
                if !legacy {
                    p = a.cur;
                    n.max = a.max as u8;
                }
            }
            if a.copy {
                // A copy's object: an anonymous copy on write of the
                // source's, a shared one's private.
                n.kind = match attrs.kind {
                    kind::FILE_SHARED => kind::FILE_PRIVATE,
                    kind::SHM => kind::ANON,
                    k => k,
                };
                n.cow = n.kind == kind::ANON;
            } else {
                n.shared = true;
            }
            if legacy {
                a.cur &= cur;
                a.max &= max;
            }
            if a.flags & vmf::RESILIENT_CODESIGN != 0 {
                p = prot::READ;
                n.max = prot::READ as u8;
            }
            out.push(Extracted { off: ps - start, len: pe - ps, prot: p, attrs: n, obj_off, src_kind: attrs.kind });
        }
        at = at.max(ve);
    }
    if at < end || out.is_empty() {
        return Err((kr::INVALID_ADDRESS, None));
    }
    Ok(out)
}

impl Kernel {
    /// `vm_map_fork`'s walk of this (the parent's) map: each mapped range
    /// by its entries' inheritance. A submap (the shared region's) is
    /// inherited by share as the nested pmap it is (`vm_map_fork_share`);
    /// here its pages are each task's own mapping of the cache, which the
    /// child takes as the parent has them. The commpage's alias is the
    /// runtime's, not the map's, and is left out.
    pub fn darwin_fork_plan(&self) -> Vec<ForkRange> {
        let (alias, alias_end) = (gex_abi::DARWIN_COMMPAGE_ALIAS, gex_abi::DARWIN_COMMPAGE_ALIAS + (gex_abi::DARWIN_COMMPAGE_END - gex_abi::DARWIN_COMMPAGE_RO));
        let mapped: Vec<(u64, u64)> = self.mem.lock().vmas().iter().map(|v| (v.start, v.end)).filter(|&(s, e)| !(s >= alias && e <= alias_end)).collect();
        let mut out: Vec<ForkRange> = Vec::new();
        for (s, e) in mapped {
            for (ps, pe, a) in self.dtask.vm.pieces(s, e) {
                let submap = a.kind == kind::SUBMAP;
                let how = match a.inherit {
                    _ if submap => Inherit::Copy,
                    inherit::SHARE => Inherit::Share,
                    inherit::NONE => Inherit::None,
                    _ => Inherit::Copy,
                };
                match out.last_mut() {
                    Some(l) if l.end == ps && l.how == how && l.own_pmap == !submap => l.end = pe,
                    _ => out.push(ForkRange { start: ps, end: pe, how, own_pmap: !submap }),
                }
            }
        }
        out
    }

    /// The child's map once the host has given it its parent's pages by
    /// `plan` (`m` is the child's memory): a range not inherited is a hole
    /// (it has no entry in the child's map), and every page inherited is
    /// one the child's new pmap has not entered. Its protection table is
    /// written before it first runs.
    pub fn darwin_fork_child_vm(&mut self, m: &mut GuestMem<'_>, plan: &[ForkRange]) {
        // vm_map_fork's copy of a purgeable object is a new purgeable
        // object, the kernel's (VM_MAP_COPYIN_PRESERVE_PURGEABLE).
        for r in plan.iter().filter(|r| r.how == Inherit::Copy && r.own_pmap) {
            for (ps, _, a) in self.dtask.vm.pieces(r.start, r.end) {
                if super::vmobject::with(a.obj, |o| o.purg.as_ref().is_some_and(|p| p.state != super::purgeable::state::DENY)).unwrap_or(false) {
                    self.darwin_unimplemented(format!("a fork's copy of purgeable memory at {ps:#x} (a new purgeable object the kernel owns)"));
                }
            }
        }
        {
            let mut mm = self.mem.lock();
            for r in plan.iter().filter(|r| r.how == Inherit::None) {
                let _ = mm.unmap(r.start, r.end - r.start);
            }
            for r in plan.iter().filter(|r| r.how != Inherit::None && r.own_pmap) {
                mm.set_unentered(r.start, r.end);
            }
        }
        self.darwin_flush_perms(m);
    }

    /// `vm_map_remap`: the pages of `[a.src_addr, +a.size)` of the source
    /// map entered at `a.target` in this (the target) map, shared or (copy)
    /// copied on write, the target's place found anywhere or taken fixed
    /// (overwriting with VM_FLAGS_OVERWRITE). The legacy call
    /// (`mach_vm_remap`, `cur` and `max` none) keeps each entry's
    /// protections and gives back the strictest; `mach_vm_remap_new` gives
    /// every new entry `cur` and `max`, which each source entry must allow
    /// for a share (a copy needs only that it can be read).
    pub(crate) fn darwin_vm_remap(&mut self, m: &mut GuestMem<'_>, a: &mut Remap) -> u64 {
        let round = |x: u64| x.checked_add(PAGE_MASK).map(|v| v & !PAGE_MASK);
        // vm_map_range_overflows.
        if a.src_addr.checked_add(a.size).and_then(round).is_none() {
            return kr::INVALID_ARGUMENT;
        }
        if a.cur & a.max != a.cur {
            return kr::INVALID_ARGUMENT;
        }
        if a.inherit > u32::from(inherit::NONE) || a.size == 0 {
            return kr::INVALID_ARGUMENT;
        }
        let (start, size, offset_in_mapping) = if a.flags & vmf::RETURN_DATA_ADDR != 0 {
            let s = a.src_addr & !PAGE_MASK;
            let e = round(a.src_addr + a.size).unwrap_or(0);
            (s, e - s, a.src_addr - s)
        } else {
            // The legacy rounding: the start truncated, the size rounded
            // on its own.
            (a.src_addr & !PAGE_MASK, round(a.size).unwrap_or(0), 0)
        };
        if size == 0 {
            return kr::INVALID_ARGUMENT;
        }
        if a.flags & vmf::RESILIENT_MEDIA != 0 && !a.copy {
            return kr::INVALID_ARGUMENT;
        }
        // Another task's map: its pages held as the extract finds them.
        let other = match a.src {
            Source::Same => None,
            Source::Other(key) => {
                if !crate::host_can_remap() {
                    self.darwin_unimplemented("mach_vm_remap from another task's map on a host that cannot map its pages twice".into());
                    return kr::FAILURE;
                }
                match self.darwin_extract_other(key, start, size, a) {
                    Ok(o) => Some(o),
                    Err(k) => return k,
                }
            }
        };
        let extracted = match &other {
            Some(o) => o.extracted.clone(),
            None => match self.darwin_remap_extract(start, size, a) {
                Ok(x) => x,
                Err(k) => return k,
            },
        };
        let end = start + size;
        // What the host must do: share the pages, or copy them on write.
        if !a.copy && !crate::host_can_remap() {
            self.darwin_unimplemented("a shared remap on a host that cannot map its pages twice".into());
            return kr::FAILURE;
        }
        // vm_map_remap_range_allocate.
        let mut at = a.target & !PAGE_MASK;
        let fixed = a.flags & vmf::ANYWHERE == 0;
        let in_place = fixed && at == start && other.is_none();
        if fixed {
            if at & a.mask != 0 {
                return kr::NO_SPACE;
            }
            let Some(tend) = at.checked_add(size) else { return kr::INVALID_ADDRESS };
            if at < self.dtask.map_min || tend > self.darwin_map_max() {
                return kr::INVALID_ADDRESS;
            }
            if self.darwin_past_memory("a fixed remap", at, tend) {
                return kr::NO_SPACE;
            }
            if a.flags & vmf::OVERWRITE != 0 {
                let k = self.darwin_region_delete_check(at, tend);
                if k != kr::SUCCESS {
                    return k;
                }
                if other.is_none() && !in_place && at < end && start < tend {
                    self.darwin_unimplemented(format!("a remap over part of its own source ({start:#x}..{end:#x} to {at:#x})"));
                    return kr::FAILURE;
                }
            } else if self.darwin_in_shared_region(at, tend) || self.mem.lock().vmas().iter().any(|v| v.start < tend && at < v.end) {
                return kr::NO_SPACE;
            }
        } else {
            let mask = a.mask & !PAGE_MASK;
            at = if a.flags & vmf::RANDOM_ADDR != 0 {
                let hint = match self.darwin_random_address_for_size(size) {
                    Ok(h) => h,
                    Err(k) => return k,
                };
                let (_, limit) = self.darwin_effective_range();
                match self.darwin_find_space(hint, limit, size, mask) {
                    Some(s) => s,
                    None => {
                        self.darwin_no_space_below_memory(size);
                        return kr::NO_SPACE;
                    }
                }
            } else {
                match self.darwin_locate_space(at, size, mask) {
                    Ok(s) => s,
                    Err(k) => return k,
                }
            };
        }
        // The source's entries as the extract leaves them: shared, or
        // (copied) to be copied on their next write (another task's were
        // left so under its locks).
        for x in extracted.iter().filter(|_| other.is_none()) {
            let (s, e) = (start + x.off, start + x.off + x.len);
            if a.copy {
                self.dtask.vm.update(s, e, |at| {
                    if at.kind == kind::ANON {
                        at.cow = true;
                    }
                });
            } else {
                self.dtask.vm.update(s, e, |at| at.shared = true);
            }
        }
        let tend = at + size;
        let src_host = match &other {
            Some(o) => Some(o.hold.addr),
            None => m.host_addr(start, size),
        };
        // A copy the host cannot make on write: the bytes, read first.
        let bytes = if crate::host_can_remap() || other.is_some() { None } else { m.kernel().read(start, size as usize).ok().map(<[u8]>::to_vec) };
        let lprot = |p: u64| p & prot::ALL;
        let made = if in_place {
            // Over itself: the entries change and the pages are copied in
            // place; the pmap's entries go (vm_map_delete).
            self.darwin_footprint_release(m, at, tend, super::footprint::Release::Remove, |k, m| {
                // A copy of a file's shared mapping is no longer the file's.
                if a.copy {
                    k.mem.lock().log.shared_maps.cut(at, size);
                }
                let ok = match src_host {
                    Some(src) if crate::host_can_remap() => m.remap_from(at, src, size, a.copy).unwrap_or(false),
                    _ => true,
                };
                ok && extracted.iter().all(|x| k.canonical(m, nr::MPROTECT, [at + x.off, x.len, lprot(x.prot), 0, 0, 0]).is_ok())
            })
        } else {
            self.darwin_footprint_release(m, at, tend, super::footprint::Release::Remove, |k, m| {
                use crate::mem::flags as mf;
                k.dtask.vm.clear(at, tend);
                for x in &extracted {
                    let call = [at + x.off, x.len, lprot(x.prot), mf::PRIVATE | mf::ANONYMOUS | mf::FIXED, u64::MAX, 0];
                    if k.canonical(m, nr::MMAP, call).is_err() {
                        return false;
                    }
                }
                match (src_host, &bytes) {
                    (Some(src), None) => m.remap_from(at, src, size, a.copy).unwrap_or(false),
                    (_, Some(b)) => m.kernel().write(at, b).is_ok(),
                    _ => false,
                }
            })
        };
        if !made {
            self.darwin_unimplemented(format!("the host's mapping of {start:#x}..{end:#x} at {at:#x} (copy {})", a.copy));
            return kr::FAILURE;
        }
        // vm_map_store_entry_link of each new entry; none is entered in the
        // pmap until touched.
        for x in &extracted {
            let (s, e) = (at + x.off, at + x.off + x.len);
            self.dtask.vm.enter(s, e, x.attrs, x.obj_off);
        }
        {
            // A file's pages past its end are absent from the new entries
            // as from their source; a copy's pages of a file are the file's
            // until written (a private source's own copies are not).
            let mut mm = self.mem.lock();
            let (absent, pending) = match &other {
                Some(o) => (o.absent.clone(), std::sync::Arc::new(o.pending.clone())),
                None => (mm.absent_ranges(), mm.copy_pending_runs()),
            };
            mm.set_unentered(at, tend);
            for (s, e) in absent {
                let (lo, hi) = (s.max(start), e.min(end));
                if lo < hi {
                    mm.set_absent(at + (lo - start), at + (hi - start));
                }
            }
            for x in extracted.iter().filter(|x| a.copy && super::ubc::vnode(x.attrs.obj).is_some()) {
                let (s, e) = (start + x.off, start + x.off + x.len);
                if x.src_kind == kind::FILE_SHARED {
                    mm.set_copy_pending(at + x.off, at + x.off + x.len);
                    continue;
                }
                for &(ps, pe) in pending.iter() {
                    let (lo, hi) = ((ps << gex_abi::PERM_PAGE_SHIFT).max(s), (pe << gex_abi::PERM_PAGE_SHIFT).min(e));
                    if lo < hi {
                        mm.set_copy_pending(at + (lo - start), at + (hi - start));
                    }
                }
            }
        }
        self.darwin_flush_perms(m);
        if a.flags & vmf::RESILIENT_CODESIGN != 0 {
            a.cur = prot::READ;
            a.max = prot::READ;
        }
        a.target = at + if a.flags & vmf::RETURN_DATA_ADDR != 0 { offset_in_mapping } else { 0 };
        kr::SUCCESS
    }

    /// `vm_map_remap_extract` of `[start, start + size)` of another task's
    /// map (`key`'s, its convert_port_to_map's), under its memory map's and
    /// entries' locks as `vm_map_lock` holds that map: the new entries, its
    /// entries left shared or waiting to be copied, and its pages as they
    /// are now held by the host (shared, or copied on write), which the
    /// target's mapping is made from, as the copy's objects are.
    fn darwin_extract_other(&mut self, key: u64, start: u64, size: u64, a: &mut Remap) -> Result<Other, u64> {
        let pid = self.ipc().links.get(&key).map(|l| l.pid);
        let peer = pid.and_then(|pid| self.procs.vm(pid).ok());
        let ents = pid.and_then(|pid| self.procs.darwin(pid)).and_then(|(r, _)| r.downcast::<super::procinfo::Public>().ok()).and_then(|p| p.vm.clone());
        let (Some(peer), Some(ents)) = (peer, ents) else {
            // A task that is gone: its map has no entries left.
            return Err(kr::INVALID_ADDRESS);
        };
        let Some(hold_at) = crate::host_hold(size as usize) else {
            self.darwin_unimplemented("mach_vm_remap from another task's map on a host that holds no pages apart from a task's".into());
            return Err(kr::FAILURE);
        };
        let hold = std::sync::Arc::new(super::vmobject::Hold { addr: hold_at, len: size });
        let mut out: Option<Result<Other, (u64, Option<String>)>> = None;
        let copy = a.copy;
        peer.mem.with_guest(&mut |g| {
            let mut mm = peer.mm.lock();
            let mut map = ents.lock();
            let r = extract(&mut mm, &map, start, size, a, false).and_then(|x| {
                for p in &x {
                    let (s, e) = (start + p.off, start + p.off + p.len);
                    if copy {
                        map.update(s, e, |at| {
                            if at.kind == kind::ANON {
                                at.cow = true;
                            }
                        });
                    } else {
                        map.update(s, e, |at| at.shared = true);
                    }
                }
                let src = g.host_addr(start, size).ok_or((kr::FAILURE, None))?;
                if !crate::host_remap(hold.addr, src, size as usize, copy) {
                    return Err((kr::FAILURE, Some(format!("the host's mapping of another task's {start:#x}..{:#x}", start + size))));
                }
                let absent = mm.absent_ranges().into_iter().filter(|&(s, e)| s < start + size && e > start).collect();
                let pending = mm.copy_pending_runs().iter().copied().filter(|&(s, e)| (s << gex_abi::PERM_PAGE_SHIFT) < start + size && (e << gex_abi::PERM_PAGE_SHIFT) > start).collect();
                Ok(Other { extracted: x, hold: std::sync::Arc::clone(&hold), absent, pending })
            });
            out = Some(r);
        });
        match out.expect("with_guest calls its function") {
            Ok(o) => Ok(o),
            Err((k, loud)) => {
                if let Some(what) = loud {
                    self.darwin_unimplemented(what);
                }
                Err(k)
            }
        }
    }

    /// `vm_map_remap_extract` of `[start, start + size)` of this map into
    /// itself ([`extract`]), what it cannot do reported.
    pub(crate) fn darwin_remap_extract(&mut self, start: u64, size: u64, a: &mut Remap) -> Result<Vec<Extracted>, u64> {
        let r = {
            let mut mm = self.mem.lock();
            let ents = self.dtask.vm.lock();
            extract(&mut mm, &ents, start, size, a, true)
        };
        r.map_err(|(k, loud)| {
            if let Some(what) = loud {
                self.darwin_unimplemented(what);
            }
            k
        })
    }

    /// A child's ranges its host could not share with the parent (no
    /// [`crate::set_host_remap`]): given a copy instead, which the program
    /// cannot tell from shared memory until either writes. Reported.
    pub fn darwin_fork_unshared(&mut self, ranges: &[(u64, u64)]) {
        for &(s, e) in ranges {
            self.darwin_unimplemented(format!("memory inherited by share at {s:#x}..{e:#x} on a host that cannot share pages between processes: the child has a copy"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::darwin::vm::Attrs;

    #[test]
    fn a_fork_plan_follows_the_entries_inheritance() {
        let mut k = Kernel::new(0x1000, 0x10000, "/prog".into());
        k.darwin = true;
        k.darwin_use_pages();
        let base = gex_abi::DARWIN_GUEST_FLOOR + 0x1000_0000;
        const P: u64 = 0x4000;
        {
            let mut mm = k.mem.lock();
            mm.set_high_arena(gex_abi::DARWIN_GUEST_FLOOR, gex_abi::LIMIT64);
            let anon = crate::mem::flags::PRIVATE | crate::mem::flags::ANONYMOUS | crate::mem::flags::FIXED;
            mm.mmap(base, 6 * P, 3, anon, "").unwrap();
        }
        k.dtask.vm.enter_anon(base, base + 6 * P, Attrs::default(), false);
        k.dtask.vm.update(base + P, base + 2 * P, |a| a.inherit = inherit::SHARE);
        k.dtask.vm.update(base + 2 * P, base + 4 * P, |a| a.inherit = inherit::NONE);
        k.dtask.vm.update(base + 5 * P, base + 6 * P, |a| a.kind = kind::SUBMAP);
        let plan = k.darwin_fork_plan();
        let want = [
            ForkRange { start: base, end: base + P, how: Inherit::Copy, own_pmap: true },
            ForkRange { start: base + P, end: base + 2 * P, how: Inherit::Share, own_pmap: true },
            ForkRange { start: base + 2 * P, end: base + 4 * P, how: Inherit::None, own_pmap: true },
            ForkRange { start: base + 4 * P, end: base + 5 * P, how: Inherit::Copy, own_pmap: true },
            ForkRange { start: base + 5 * P, end: base + 6 * P, how: Inherit::Copy, own_pmap: false },
        ];
        assert_eq!(plan, want);
        let mut buf = vec![0u8; 0x10000];
        let mut m = GuestMem::new(&mut buf);
        let mut child = k.fork_kernel();
        child.darwin_fork_child_vm(&mut m, &plan);
        let mm = child.mem.lock();
        assert!(mm.vma_at(base + 2 * P).is_none() && mm.vma_at(base + 3 * P).is_none(), "not inherited: a hole");
        assert_eq!(mm.unentered_ranges(), vec![(base, base + 2 * P), (base + 4 * P, base + 5 * P)]);
    }
}
