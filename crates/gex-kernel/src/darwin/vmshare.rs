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
//! the child's. Those pages are kept
//! not entered ([`crate::mem::MemoryMap::set_unentered`]): the task's first
//! access to one, or a call's copy to or from it, faults to the kernel,
//! which enters it, and only then does the footprint see it.

use super::vm::{inherit, kind};
use crate::syscalls::Kernel;
use crate::GuestMem;

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
