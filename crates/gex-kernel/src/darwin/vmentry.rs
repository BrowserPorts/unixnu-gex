//! Named memory entries: `mach_make_memory_entry_64` and the routines of
//! `memory_entry.defs`, and the mapping of an entry by `mach_vm_map`
//! (`vm_user.c`, `vm_map_enter_mem_object`, xnu-10063.141.1).
//!
//! An entry names pages no task's mapping holds alone: a new object's, or
//! a range's of the task that made it, shared or copied. Its pages are the
//! host's, held apart from every task's memory ([`crate::set_host_hold`])
//! for as long as the entry is, and a mapping of the entry is the host's
//! mapping of them into the task ([`crate::set_host_remap`]), shared or
//! copied on write, whatever task it is in. The entry goes with its port's
//! last send right.

use super::ipc::kr;
use super::mach::{prot, PAGE_MASK};
use super::vm::{inherit, kind, Attrs};
use super::vmshare::{Remap, Source};
use crate::syscalls::{nr, Kernel};
use crate::GuestMem;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// `MAP_MEM_*`.
pub mod map_mem {
    pub const LEDGER_TAGGED: u32 = 0x00_2000;
    pub const PURGABLE_KERNEL_ONLY: u32 = 0x00_4000;
    pub const GRAB_SECLUDED: u32 = 0x00_8000;
    pub const ONLY: u32 = 0x01_0000;
    pub const NAMED_CREATE: u32 = 0x02_0000;
    pub const PURGABLE: u32 = 0x04_0000;
    pub const NAMED_REUSE: u32 = 0x08_0000;
    pub const USE_DATA_ADDR: u32 = 0x10_0000;
    pub const VM_COPY: u32 = 0x20_0000;
    pub const VM_SHARE: u32 = 0x40_0000;
    pub const DATA_ADDR_4K: u32 = 0x80_0000;
    pub const FLAGS_MASK: u32 = 0x00FF_FF00;
    pub const FLAGS_USER: u32 = PURGABLE_KERNEL_ONLY | GRAB_SECLUDED | ONLY | NAMED_CREATE | PURGABLE | NAMED_REUSE | USE_DATA_ADDR | VM_COPY | VM_SHARE | LEDGER_TAGGED | DATA_ADDR_4K;
    /// `MAP_MEM_NOOP` and `MAP_MEM_COPYBACK`: no cache mode, or the one
    /// memory has.
    pub const NOOP: u32 = 0;
    pub const COPYBACK: u32 = 1;
}

/// `VM_PROT_IS_MASK`.
pub const VM_PROT_IS_MASK: u32 = 0x40;
/// `ANON_MAX_SIZE` on LP64.
const ANON_MAX_SIZE: u64 = 0xFFFF_F000;

const KERN_PROTECTION_FAILURE: u64 = 2;
const KERN_INVALID_VALUE: u64 = 18;
const KERN_NOT_SUPPORTED: u64 = 46;

pub use super::vmobject::Hold;

/// A `vm_named_entry`.
#[derive(Clone, Debug)]
pub struct NamedEntry {
    /// Its object ([`super::vmobject`]), whose reference the entry holds
    /// while it is, and the object's pages (or its copy's), from `offset`.
    pub obj: u64,
    pub hold: Arc<Hold>,
    pub offset: u64,
    pub size: u64,
    /// `data_offset`: where the data starts in the first page.
    pub data_offset: u64,
    pub protection: u32,
    /// `is_copy`: a range's entries; else `is_object`, one object.
    pub is_copy: bool,
    /// `internal`: an anonymous object (one made, or a task's memory).
    pub internal: bool,
    /// A VM_COPY's entries, each waiting to be copied (`needs_copy`): a
    /// mapping of them copies on write whatever it asks.
    pub needs_copy: bool,
}

fn entries() -> &'static Mutex<HashMap<u64, NamedEntry>> {
    static E: OnceLock<Mutex<HashMap<u64, NamedEntry>>> = OnceLock::new();
    E.get_or_init(Default::default)
}

static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Entry `id`, as its port names it.
pub fn get(id: u64) -> Option<NamedEntry> {
    entries().lock().unwrap_or_else(|e| e.into_inner()).get(&id).cloned()
}

/// `mach_memory_entry_no_senders`: the entry goes, and its reference to
/// its object with it.
pub fn no_senders(id: u64) {
    let gone = entries().lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    if let Some(e) = gone {
        super::vmobject::release(e.obj);
    }
}

/// A new entry, which holds the reference to its object its maker gave
/// it.
fn insert(e: NamedEntry) -> u64 {
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    entries().lock().unwrap_or_else(|e| e.into_inner()).insert(id, e);
    id
}

/// What `mach_make_memory_entry_64` made: a new entry, or (a reuse) the
/// parent's again.
pub enum Made {
    New(u64),
    /// `MAP_MEM_NAMED_CREATE` of no size: success, and no entry.
    Nothing,
}

/// `ubc_setsize`'s flush of object `obj`'s pages past `size` from what
/// named entries hold of them: their holds' pages there are the host's
/// fresh memory, no longer the file's.
pub fn hold_pages_past(obj: u64, size: u64) {
    let held: Vec<NamedEntry> = entries().lock().unwrap_or_else(|e| e.into_inner()).values().filter(|e| e.obj == obj).cloned().collect();
    for e in held {
        let cut = (size + PAGE_MASK) & !PAGE_MASK;
        if e.offset + e.hold.len <= cut {
            continue;
        }
        let from = cut.saturating_sub(e.offset);
        let len = (e.hold.len - from) as usize;
        if let Some(fresh) = crate::host_hold(len) {
            crate::host_remap(e.hold.addr + from as usize, fresh, len, false);
            crate::host_unhold(fresh, len);
        }
    }
}

impl Kernel {
    /// `mach_make_memory_entry_64(target, &size, offset, permission,
    /// parent)`: a new entry, and the size it names past its data's
    /// offset.
    pub(crate) fn darwin_make_memory_entry(&mut self, m: &mut GuestMem<'_>, size: &mut u64, offset: u64, permission: u32, parent: Option<NamedEntry>) -> Result<Made, u64> {
        use map_mem::*;
        if (permission & FLAGS_MASK) & !FLAGS_USER != 0 {
            return Err(KERN_INVALID_VALUE);
        }
        if parent.as_ref().is_some_and(|p| p.is_copy) {
            return Err(kr::INVALID_ARGUMENT);
        }
        // vm_map_range_overflows.
        if offset.checked_add(*size).and_then(|e| e.checked_add(PAGE_MASK)).is_none() {
            return Err(kr::INVALID_ARGUMENT);
        }
        let mut protections = permission & prot::ALL as u32;
        let mask_protections = permission & VM_PROT_IS_MASK != 0;
        let access = permission >> 24;
        let use_data_addr = permission & USE_DATA_ADDR != 0;
        let use_4k = permission & DATA_ADDR_4K != 0;
        let map_start = offset & !PAGE_MASK;
        let round = |a: u64| a.checked_add(PAGE_MASK).map(|v| v & !PAGE_MASK);
        if permission & ONLY != 0 {
            self.darwin_unimplemented("mach_make_memory_entry_64 with MAP_MEM_ONLY (a parent object's cache mode)".into());
            return Err(kr::FAILURE);
        }
        if access != NOOP && access != COPYBACK {
            self.darwin_unimplemented(format!("a memory entry's cache mode {access} (an object's wimg bits)"));
            return Err(kr::FAILURE);
        }
        if permission & NAMED_CREATE != 0 {
            let Some(map_end) = offset.checked_add(*size).and_then(round) else { return Err(kr::INVALID_ARGUMENT) };
            let map_size = map_end - map_start;
            if map_size == 0 {
                return Ok(Made::Nothing);
            }
            if map_end == 0 || use_data_addr || use_4k {
                return Err(kr::INVALID_ARGUMENT);
            }
            if map_size > ANON_MAX_SIZE {
                return Err(kr::FAILURE);
            }
            if permission & PURGABLE != 0 && protections & prot::WRITE as u32 == 0 {
                return Err(kr::INVALID_ARGUMENT);
            }
            if permission & (PURGABLE | LEDGER_TAGGED) != 0 {
                self.darwin_unimplemented("a purgeable or ledger-tagged object made by mach_make_memory_entry_64 (its owner's purgeable and tag ledgers)".into());
                return Err(kr::FAILURE);
            }
            let Some(addr) = crate::host_hold(map_size as usize) else {
                self.darwin_unimplemented("a named memory entry's object on a host that holds no pages apart from a task's".into());
                return Err(kr::FAILURE);
            };
            let hold = Arc::new(Hold { addr, len: map_size });
            let obj = super::vmobject::allocate(map_size, super::vmobject::Pager::Anon, Some(Arc::clone(&hold)));
            let e = NamedEntry { obj, hold, offset: 0, size: map_size, data_offset: 0, protection: protections, is_copy: false, internal: true, needs_copy: false };
            *size = e.size;
            return Ok(Made::New(insert(e)));
        }
        let data_offset = |map_start: u64| {
            if use_data_addr || use_4k {
                let o = offset - map_start;
                if use_4k { o & !0xfff } else { o }
            } else {
                0
            }
        };
        if permission & VM_COPY != 0 || permission & VM_SHARE != 0 || parent.is_none() || permission & NAMED_REUSE != 0 {
            let Some(map_end) = offset.checked_add(*size).and_then(round) else { return Err(kr::INVALID_ARGUMENT) };
            let mut map_size = map_end - map_start;
            if map_size == 0 || map_end == 0 {
                return Err(kr::INVALID_ARGUMENT);
            }
            let offset_in_page = data_offset(map_start);
            let copy = permission & VM_COPY != 0;
            if !copy && permission & NAMED_REUSE != 0 && parent.is_some() {
                self.darwin_unimplemented("MAP_MEM_NAMED_REUSE (whether the range is still its parent entry's object)".into());
                return Err(kr::FAILURE);
            }
            // vm_map_copyin of the range (a copy needs it readable), or
            // vm_map_copy_extract of it shared, its protections checked
            // (or, as a mask, narrowed) as the extract finds them.
            let (cur, max) = if copy {
                (prot::READ, prot::READ)
            } else if mask_protections {
                (0, 0)
            } else {
                (u64::from(protections), u64::from(protections))
            };
            let mut r = Remap { target: 0, size: map_size, mask: 0, flags: 0, src: Source::Same, src_addr: map_start, copy, cur, max, inherit: u32::from(inherit::SHARE), prot_copy: false };
            let pieces = self.darwin_remap_extract(map_start, map_size, &mut r)?;
            // A file's pages named: the entry would hold the host file's
            // pages under an object of its own, which no change of the
            // file's size reaches.
            if pieces.iter().any(|x| super::ubc::vnode(x.attrs.obj).is_some()) {
                self.darwin_unimplemented("a named memory entry of a file's pages (the vnode's object named by the entry)".into());
                return Err(kr::FAILURE);
            }
            if copy {
                // vm_map_copyin's PROTECTION_FAILURE for what cannot be read.
                if pieces.iter().any(|x| x.prot & prot::READ == 0) {
                    return Err(KERN_PROTECTION_FAILURE);
                }
            } else if mask_protections {
                protections &= r.cur as u32;
                if protections == 0 {
                    return Err(KERN_PROTECTION_FAILURE);
                }
            }
            // The default: one object, the first entry's (vmkf_copy_single_object).
            if !copy && permission & VM_SHARE == 0 {
                map_size = pieces[0].len;
            }
            let Some(addr) = crate::host_hold(map_size as usize) else {
                self.darwin_unimplemented("a named memory entry of a task's range on a host that holds no pages apart from a task's".into());
                return Err(kr::FAILURE);
            };
            let hold = Arc::new(Hold { addr, len: map_size });
            let Some(src) = m.host_addr(map_start, map_size) else { return Err(kr::FAILURE) };
            if !crate::host_remap(addr, src, map_size as usize, copy) {
                self.darwin_unimplemented("a named memory entry of a task's range on a host that cannot map its pages twice".into());
                return Err(kr::FAILURE);
            }
            // The source's entries: shared now, or waiting to be copied.
            self.dtask.vm.update(map_start, map_start + map_size, |a| {
                if copy {
                    if a.kind == kind::ANON {
                        a.cow = true;
                    }
                } else {
                    a.shared = true;
                }
            });
            let internal = pieces.iter().take_while(|x| x.off < map_size).all(|x| matches!(x.attrs.kind, kind::ANON | kind::SHM | kind::OBJECT));
            let obj = super::vmobject::allocate(map_size, super::vmobject::Pager::Anon, Some(Arc::clone(&hold)));
            let e = NamedEntry { obj, hold, offset: 0, size: map_size, data_offset: offset_in_page, protection: protections, is_copy: copy || permission & VM_SHARE != 0, internal, needs_copy: copy };
            *size = e.size - e.data_offset;
            return Ok(Made::New(insert(e)));
        }
        // A part of the parent's object.
        let p = parent.expect("a parent entry");
        let (map_start, map_size, offset_in_page) = if use_data_addr || use_4k {
            let total = offset.checked_add(*size).and_then(|v| v.checked_add(p.data_offset)).ok_or(kr::INVALID_ARGUMENT)?;
            if total > p.size {
                return Err(kr::INVALID_ARGUMENT);
            }
            let start = offset.checked_add(p.data_offset).ok_or(kr::INVALID_ARGUMENT)? & !PAGE_MASK;
            let mut in_page = offset + p.data_offset - start;
            if use_4k {
                in_page &= !0xfff;
            }
            let end = round(total).ok_or(kr::INVALID_ARGUMENT)?;
            if end == 0 && *size != 0 {
                return Err(kr::INVALID_ARGUMENT);
            }
            (start, end - start, in_page)
        } else {
            let end = offset.checked_add(*size).and_then(round).ok_or(kr::INVALID_ARGUMENT)?;
            if end == 0 && *size != 0 {
                return Err(kr::INVALID_ARGUMENT);
            }
            let map_size = end - map_start;
            if offset.checked_add(map_size).is_none_or(|e| e > p.size) {
                return Err(kr::INVALID_ARGUMENT);
            }
            (map_start, map_size, 0)
        };
        if mask_protections {
            protections &= p.protection;
        }
        if protections & p.protection != protections {
            return Err(KERN_PROTECTION_FAILURE);
        }
        super::vmobject::reference(p.obj);
        let e = NamedEntry { obj: p.obj, hold: Arc::clone(&p.hold), offset: p.offset + map_start, size: map_size, data_offset: offset_in_page, protection: protections, is_copy: false, internal: p.internal, needs_copy: false };
        *size = e.size - e.data_offset;
        Ok(Made::New(insert(e)))
    }

    /// `vm_map_enter_mem_object` of named entry `e` at `*address` (its
    /// checks made): the entry's pages from `offset`, shared or (`copy`)
    /// copied on write, entered as the task touches them.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn darwin_map_named_entry(&mut self, m: &mut GuestMem<'_>, address: &mut u64, size: u64, mask: u64, flags: u64, e: &NamedEntry, offset: u64, copy: bool, cur: u64, max: u64, inherit: u8) -> u64 {
        use super::mach::vmf;
        let (mut cur, mut max) = (cur, max);
        if cur & u64::from(VM_PROT_IS_MASK) != 0 {
            cur &= u64::from(e.protection) | u64::from(VM_PROT_IS_MASK);
        }
        if max & u64::from(VM_PROT_IS_MASK) != 0 {
            max &= u64::from(e.protection) | u64::from(VM_PROT_IS_MASK);
        }
        let (cur, max) = (cur & prot::ALL, max & prot::ALL);
        if u64::from(e.protection) & max != max || u64::from(e.protection) & cur != cur {
            return kr::INVALID_RIGHT;
        }
        let return_data = flags & (vmf::RETURN_DATA_ADDR | vmf::RETURN_4K_DATA_ADDR) != 0;
        let data_offset = if return_data { e.data_offset } else { 0 };
        let Some(offset) = offset.checked_add(data_offset) else { return kr::INVALID_ARGUMENT };
        let obj_size = (size + PAGE_MASK) & !PAGE_MASK;
        if offset.checked_add(obj_size).is_none() || e.size < offset + size {
            return kr::INVALID_ARGUMENT;
        }
        // The callers' offset is from the entry's start in its object.
        let obj_offset = e.offset + offset;
        let in_page = obj_offset & PAGE_MASK;
        let obj_start = obj_offset & !PAGE_MASK;
        let map_size = ((in_page + size) + PAGE_MASK) & !PAGE_MASK;
        if obj_start + map_size > e.hold.len {
            return kr::INVALID_ARGUMENT;
        }
        // vm_map_enter: an anonymous mapping's place, then the entry's
        // pages over it.
        let mut at = *address;
        let k = self.darwin_vm_enter_anon_object(m, &mut at, map_size, mask, flags & !(vmf::RETURN_DATA_ADDR | vmf::RETURN_4K_DATA_ADDR), cur, max, inherit);
        if k != kr::SUCCESS {
            return k;
        }
        let copy = copy || e.needs_copy;
        if !m.remap_from(at, e.hold.addr + obj_start as usize, map_size, copy).unwrap_or(false) {
            let _ = self.canonical(m, nr::MUNMAP, [at, map_size, 0, 0, 0, 0]);
            self.dtask.vm.clear(at, at + map_size);
            self.darwin_unimplemented("a named memory entry's mapping on a host that cannot map its pages twice".into());
            return kr::FAILURE;
        }
        let attrs = if copy {
            Attrs { kind: kind::ANON, cow: true, max: max as u8, inherit, obj: e.obj, ..Attrs::default() }
        } else if e.internal {
            Attrs { kind: kind::OBJECT, max: max as u8, inherit, obj: e.obj, ..Attrs::default() }
        } else {
            Attrs { kind: kind::FILE_PRIVATE, max: max as u8, inherit, obj: e.obj, ..Attrs::default() }
        };
        self.dtask.vm.enter(at, at + map_size, Attrs { alias: (flags >> 24) as u8, ..attrs }, obj_start);
        self.mem.lock().set_unentered(at, at + map_size);
        self.darwin_flush_perms(m);
        *address = at + if return_data { in_page } else { 0 };
        kr::SUCCESS
    }

    /// `mach_memory_entry_purgable_control` of entry `e`: none of a copy;
    /// an object's whole or nothing; a non-purgeable object's
    /// (VM_PURGABLE_DENY) KERN_INVALID_ARGUMENT.
    pub(crate) fn darwin_entry_purgable_control(&mut self, e: &NamedEntry, control: u32, state: i32) -> u64 {
        const SET_STATE: u32 = 0;
        const GET_STATE: u32 = 1;
        const SET_STATE_FROM_KERNEL: u32 = 3;
        const ALL_MASKS: i32 = 3 | (1 << 4) | (1 << 5) | (1 << 6) | (7 << 8) | (3 << 12) | (1 << 16);
        if control == SET_STATE_FROM_KERNEL {
            return kr::INVALID_ARGUMENT;
        }
        if control != SET_STATE && control != GET_STATE {
            return kr::INVALID_ARGUMENT;
        }
        if control == SET_STATE && (state & !ALL_MASKS != 0 || (state & 3) > 3) {
            return kr::INVALID_ARGUMENT;
        }
        if e.is_copy {
            return kr::INVALID_ARGUMENT;
        }
        // No purgeable object is made here: every object is DENY.
        kr::INVALID_ARGUMENT
    }

    /// `mach_memory_entry_access_tracking`: a release kernel tracks no
    /// object's accesses (VM_OBJECT_ACCESS_TRACKING is a development
    /// kernel's), after the entry's checks.
    pub(crate) fn darwin_entry_access_tracking(&mut self, e: &NamedEntry) -> u64 {
        if e.is_copy {
            return kr::INVALID_ARGUMENT;
        }
        KERN_NOT_SUPPORTED
    }
}
