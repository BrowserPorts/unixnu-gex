//! Purgeable memory and owned objects' ledgers (`vm_purgeable.c`,
//! `vm_object_purgable_control`, `vm_object_ownership_change`,
//! `vm_purgeable_accounting`, `vm_object_ledger_tag_ledgers`,
//! xnu-10063.141.1).
//!
//! A purgeable object, and an object given a ledger tag, is owned by a
//! task, whose ledgers its resident pages are billed to rather than the
//! pmaps that map them (their entries have `use_pmap` off: a page entered
//! there is `internal` and `alternate_accounting`, not `phys_footprint`).
//! A nonvolatile object's pages are in its owner's `purgeable_nonvolatile`
//! (or its tag's) ledger and, unless it is marked so, its owner's
//! `phys_footprint`; a volatile or emptied one's in `purgeable_volatile`
//! (or its tag's "no footprint" ledger) only. The object's pages are the
//! host's, held apart from every task as host purgeable memory
//! ([`crate::set_host_purgeable`]), which every mapping of the object maps;
//! their count is what the host holds of them, looked at as the owner's
//! ledgers are read, and only grows between kernel operations (the model's
//! device runs no pageout, so nothing reclaims a page): an operation that
//! lowers the owner's footprint (a volatile state, an empty) looks first,
//! so its peaks hold.
//!
//! Volatile objects wait on their queue (FIFO, LIFO or obsolete) in their
//! group to be purged when memory is short (`vm_purgeable_object_purge_one`
//! from `vm_pageout_scan`), with a token that ripens as pages are reclaimed
//! (`vm_purgeable_q_advance_all`). The modelled device's memory is never
//! short (its pressure level stays normal), so no object is purged that way
//! and no token ripens: an object is emptied only by an explicit
//! VM_PURGABLE_EMPTY or VM_PURGABLE_PURGE_ALL. The host never purges an
//! object on its own: its object stays nonvolatile, emptied by the host only
//! when the guest's is.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::GuestMem;
use std::sync::{Arc, Mutex, OnceLock};

/// `vm_purgable_t` controls.
pub mod ctl {
    pub const SET_STATE: u32 = 0;
    pub const GET_STATE: u32 = 1;
    pub const PURGE_ALL: u32 = 2;
    pub const SET_STATE_FROM_KERNEL: u32 = 3;
}

/// An object's `purgable`, and the state word's masks.
pub mod state {
    pub const NONVOLATILE: u8 = 0;
    pub const VOLATILE: u8 = 1;
    pub const EMPTY: u8 = 2;
    pub const DENY: u8 = 3;
    pub const STATE_MASK: i32 = 3;
    pub const NO_AGING_MASK: i32 = 1 << 16;
    pub const DEBUG_EMPTY: i32 = 1 << 12;
    pub const DEBUG_FAULT: i32 = 2 << 12;
    pub const GROUP_SHIFT: i32 = 8;
    pub const GROUP_MASK: i32 = 7 << GROUP_SHIFT;
    pub const BEHAVIOR_LIFO: i32 = 1 << 6;
    pub const ORDERING_OBSOLETE: i32 = 1 << 5;
    pub const ORDER_MASK: i32 = 1 << 4;
    /// `VM_PURGABLE_ALL_MASKS`.
    pub const ALL_MASKS: i32 = STATE_MASK | ORDER_MASK | ORDERING_OBSOLETE | BEHAVIOR_LIFO | GROUP_MASK | (3 << 12) | NO_AGING_MASK;
}

/// `VM_LEDGER_TAG_*` and `VM_LEDGER_FLAG_*`.
pub mod tag {
    pub const NONE: i32 = 0;
    pub const DEFAULT: i32 = 1;
    pub const NETWORK: i32 = 2;
    pub const MEDIA: i32 = 3;
    pub const GRAPHICS: i32 = 4;
    pub const NEURAL: i32 = 5;
    pub const MAX: i32 = 5;
    pub const UNCHANGED: i32 = -1;
    pub const FLAG_NO_FOOTPRINT: i32 = 1 << 0;
    pub const FLAG_NO_FOOTPRINT_FOR_DEBUG: i32 = 1 << 1;
    pub const FLAGS: i32 = FLAG_NO_FOOTPRINT | FLAG_NO_FOOTPRINT_FOR_DEBUG;
}

/// The purgeable queues' types (`purgeable_q_type`).
const Q_OBSOLETE: u8 = 0;
const Q_FIFO: u8 = 1;
const Q_LIFO: u8 = 2;
/// `PURGEABLE_Q_TYPE_MAX`: on no queue.
const Q_NONE: u8 = 3;
/// `NUM_VOLATILE_GROUPS`.
const GROUPS: usize = 8;

/// A task as an owner of objects: its `task_objq`, and whether it has
/// given them up (`task_objects_disowning`, at its end).
#[derive(Debug, Default)]
pub struct Owner {
    objects: Mutex<Vec<u64>>,
    disowning: AtomicBool,
    /// Its process, for a look at its pages from another task.
    pid: std::sync::atomic::AtomicI32,
}

impl Owner {
    /// The owner of process `pid`'s objects.
    pub fn of(pid: i32) -> Owner {
        Owner { pid: std::sync::atomic::AtomicI32::new(pid), ..Owner::default() }
    }

    /// Its process.
    pub fn pid(&self) -> i32 {
        self.pid.load(Ordering::Acquire)
    }

    /// Its process is `pid` (a forked task's, as its fork chose it).
    pub fn set_pid(&self, pid: i32) {
        self.pid.store(pid, Ordering::Release);
    }

    /// The objects it owns now.
    pub fn objects(&self) -> Vec<u64> {
        self.objects.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// An object's purgeable and ownership state (`vm_object`'s fields).
#[derive(Clone, Debug)]
pub struct Purg {
    /// `purgable`: DENY for an object owned only for its ledger tag.
    pub state: u8,
    /// `purgeable_queue_type` and `purgeable_queue_group`, while volatile.
    pub queue: u8,
    pub group: u8,
    pub when_ripe: bool,
    pub volatile_empty: bool,
    pub volatile_fault: bool,
    pub only_by_kernel: bool,
    /// `vo_owner`: none for the disowned.
    pub owner: Option<Arc<Owner>>,
    /// `vo_ledger_tag` and `vo_no_footprint`.
    pub tag: i32,
    pub no_footprint: bool,
}

impl Purg {
    /// A new purgeable object's (NONVOLATILE, on no queue), unowned yet.
    pub fn nonvolatile() -> Purg {
        Purg { state: state::NONVOLATILE, queue: Q_NONE, group: 0, when_ripe: false, volatile_empty: false, volatile_fault: false, only_by_kernel: false, owner: None, tag: tag::NONE, no_footprint: false }
    }

    /// An object owned only for its tag (`purgable` DENY).
    pub fn tagged() -> Purg {
        Purg { state: state::DENY, ..Purg::nonvolatile() }
    }
}

/// The queues (`purgeable_queues`), the nonvolatile queue's count and the
/// tokens each queue holds (none ripens here).
#[derive(Debug)]
struct Queues {
    objq: [[VecDeque<u64>; GROUPS]; 3],
    tokens: [u64; 3],
    nonvolatile: u64,
}

fn queues() -> std::sync::MutexGuard<'static, Queues> {
    static Q: OnceLock<Mutex<Queues>> = OnceLock::new();
    Q.get_or_init(|| Mutex::new(Queues { objq: Default::default(), tokens: [0; 3], nonvolatile: 0 })).lock().unwrap_or_else(|e| e.into_inner())
}

/// `vm_purgeable_nonvolatile_enqueue`: object `id`'s purgeable state given
/// owner `owner` (or none, a disowning one counting as none), on the
/// nonvolatile queue.
pub fn nonvolatile_enqueue(p: &mut Purg, id: u64, owner: Option<Arc<Owner>>) {
    set_owner(p, id, owner);
    queues().nonvolatile += 1;
}

/// `vm_purgeable_nonvolatile_dequeue`: off the nonvolatile queue, and
/// disowned (an object's end).
pub fn nonvolatile_dequeue(p: &mut Purg, id: u64) {
    set_owner(p, id, None);
    let mut q = queues();
    q.nonvolatile = q.nonvolatile.saturating_sub(1);
}

/// `vm_object_reap`'s part for a purgeable or tagged object: off its
/// volatile queue (its token with it) or the nonvolatile one, and off its
/// owner's.
pub fn terminate(p: &mut Purg, id: u64) {
    if p.state != state::DENY {
        if p.queue != Q_NONE {
            queues().objq[p.queue as usize][p.group as usize].retain(|&o| o != id);
            if p.when_ripe {
                token_delete(p.queue);
            }
            p.queue = Q_NONE;
        } else {
            let mut q = queues();
            q.nonvolatile = q.nonvolatile.saturating_sub(1);
        }
    }
    set_owner(p, id, None);
}

/// The object's owner made `owner` (its `task_objq` left and joined).
pub fn set_owner(p: &mut Purg, id: u64, owner: Option<Arc<Owner>>) {
    if let Some(old) = p.owner.take() {
        old.objects.lock().unwrap_or_else(|e| e.into_inner()).retain(|&o| o != id);
    }
    let owner = owner.filter(|o| !o.disowning.load(Ordering::Acquire));
    if let Some(o) = &owner {
        o.objects.lock().unwrap_or_else(|e| e.into_inner()).push(id);
    }
    p.owner = owner;
}

/// `vm_owned_objects_disown`: every object `owner` owns is disowned, its
/// pages billed to no one from now on.
pub fn disown(owner: &Arc<Owner>) {
    owner.disowning.store(true, Ordering::Release);
    let ids = std::mem::take(&mut *owner.objects.lock().unwrap_or_else(|e| e.into_inner()));
    for id in ids {
        super::vmobject::with(id, |o| {
            if let Some(p) = &mut o.purg {
                p.owner = None;
            }
        });
    }
}

/// `vm_purgeable_object_add`: onto queue `queue` in `group` (the obsolete
/// queue has one), off the nonvolatile queue; FIFO and obsolete objects
/// last to die, LIFO first.
fn object_add(p: &mut Purg, id: u64, queue: u8, group: u8) {
    let group = if queue == Q_OBSOLETE { 0 } else { group };
    let mut q = queues();
    q.nonvolatile = q.nonvolatile.saturating_sub(1);
    let list = &mut q.objq[queue as usize][group as usize];
    if queue == Q_LIFO {
        list.push_front(id);
    } else {
        list.push_back(id);
    }
    p.queue = queue;
    p.group = group;
}

/// `vm_purgeable_object_remove`: off its volatile queue (back on the
/// nonvolatile one); the queue it was on, if any.
fn object_remove(p: &mut Purg, id: u64) -> Option<u8> {
    if p.queue == Q_NONE {
        return None;
    }
    let queue = p.queue;
    let mut q = queues();
    q.objq[queue as usize][p.group as usize].retain(|&o| o != id);
    q.nonvolatile += 1;
    p.queue = Q_NONE;
    p.group = 0;
    Some(queue)
}

/// `vm_purgeable_token_add`: a token for an object made volatile (the
/// array grows as it must; the kernel's memory for it is not short).
fn token_add(queue: u8) {
    queues().tokens[queue as usize] += 1;
}

/// `vm_purgeable_token_delete_first` and `_last`.
fn token_delete(queue: u8) {
    let mut q = queues();
    q.tokens[queue as usize] = q.tokens[queue as usize].saturating_sub(1);
}

/// What purging an object takes: the host emptying its pages
/// (`vm_object_purge`), done by the caller with the object's hold.
pub enum Purge {
    None,
    Pages,
}

/// `vm_object_purgable_control(object, control, state)` of object `id`
/// with purgeable state `p`: KERN_* and the old state back in `state`;
/// whether its pages are to be purged.
pub fn control(p: &mut Purg, id: u64, control: u32, st: &mut i32) -> (u64, Purge) {
    const KERN_INVALID_ARGUMENT: u64 = 4;
    const KERN_PROTECTION_FAILURE: u64 = 2;
    let old = p.state;
    if old == state::DENY {
        return (KERN_INVALID_ARGUMENT, Purge::None);
    }
    if control == ctl::GET_STATE {
        *st = i32::from(old);
        return (0, Purge::None);
    }
    if control == ctl::SET_STATE && p.only_by_kernel {
        return (KERN_PROTECTION_FAILURE, Purge::None);
    }
    if control != ctl::SET_STATE && control != ctl::SET_STATE_FROM_KERNEL {
        return (KERN_INVALID_ARGUMENT, Purge::None);
    }
    if *st & state::DEBUG_EMPTY != 0 {
        p.volatile_empty = true;
    }
    if *st & state::DEBUG_FAULT != 0 {
        p.volatile_fault = true;
    }
    let mut new = (*st & state::STATE_MASK) as u8;
    if new == state::VOLATILE && (old == state::EMPTY || p.volatile_empty) {
        new = state::EMPTY;
    }
    let mut purge = Purge::None;
    match new {
        state::DENY => return (KERN_INVALID_ARGUMENT, Purge::None),
        state::NONVOLATILE => {
            p.state = new;
            if old == state::VOLATILE {
                if let Some(q) = object_remove(p, id) {
                    if p.when_ripe {
                        token_delete(q);
                    }
                }
            }
        }
        state::VOLATILE => {
            let queue = if *st & state::ORDERING_OBSOLETE != 0 {
                Q_OBSOLETE
            } else if *st & state::BEHAVIOR_LIFO != 0 {
                Q_LIFO
            } else {
                Q_FIFO
            };
            let ripe = *st & state::NO_AGING_MASK == 0;
            if old == state::NONVOLATILE || old == state::EMPTY {
                p.when_ripe = ripe;
                if p.when_ripe {
                    token_add(queue);
                }
                p.state = new;
            } else if old == state::VOLATILE {
                let old_queue = object_remove(p, id).unwrap_or(Q_NONE);
                if old_queue != queue || ripe != p.when_ripe {
                    if p.when_ripe && old_queue != Q_NONE {
                        token_delete(old_queue);
                    }
                    p.when_ripe = ripe;
                    if p.when_ripe {
                        token_add(queue);
                    }
                }
            }
            object_add(p, id, queue, ((*st & state::GROUP_MASK) >> state::GROUP_SHIFT) as u8);
        }
        _ => {
            // EMPTY.
            if old == state::VOLATILE {
                if let Some(q) = object_remove(p, id) {
                    if p.when_ripe {
                        token_delete(q);
                    }
                }
            }
            p.state = state::EMPTY;
            purge = Purge::Pages;
        }
    }
    *st = i32::from(old);
    (0, purge)
}

/// `vm_purgeable_object_purge_all`'s objects: every volatile object, queue
/// by queue (obsolete, FIFO, LIFO) and group by group from the lowest, each
/// taken off its queue (its token with it) and emptied.
pub fn purge_all_objects() -> Vec<u64> {
    let mut out = Vec::new();
    for queue in [Q_OBSOLETE, Q_FIFO, Q_LIFO] {
        for group in 0..GROUPS {
            loop {
                let Some(id) = queues().objq[queue as usize][group].front().copied() else { break };
                let done = super::vmobject::with(id, |o| {
                    let Some(p) = &mut o.purg else { return };
                    // vm_purgeable_object_find_and_lock takes it off the
                    // queue (onto the nonvolatile one); vm_object_purge
                    // leaves it EMPTY.
                    let _ = object_remove(p, id);
                    if p.when_ripe {
                        token_delete(queue);
                    }
                    p.state = state::EMPTY;
                });
                if done.is_none() {
                    queues().objq[queue as usize][group].retain(|&o| o != id);
                    continue;
                }
                out.push(id);
            }
        }
    }
    out
}

/// One owner's ledgers of the objects it owns (bytes): the purgeable ones
/// and each tag's, as `vm_object_ledger_tag_ledgers` sorts them, and what
/// they add to its `phys_footprint`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Owned {
    pub purgeable_volatile: u64,
    pub purgeable_nonvolatile: u64,
    pub tagged_footprint: u64,
    pub tagged_nofootprint: u64,
    pub network_volatile: u64,
    pub network_nonvolatile: u64,
    pub media_footprint: u64,
    pub media_nofootprint: u64,
    pub graphics_footprint: u64,
    pub graphics_nofootprint: u64,
    pub neural_footprint: u64,
    pub neural_nofootprint: u64,
    pub footprint: u64,
}

impl Owned {
    /// Object `p`'s `bytes` of resident pages (wired ones excepted) billed
    /// as `vm_purgeable_accounting` and `vm_object_ledger_tag_ledgers` say.
    pub fn add(&mut self, p: &Purg, bytes: u64) {
        let volatile = p.state == state::VOLATILE || p.state == state::EMPTY;
        let mut do_footprint = !p.no_footprint;
        let slot = match p.tag {
            tag::NONE => {
                do_footprint = true;
                if volatile { &mut self.purgeable_volatile } else { &mut self.purgeable_nonvolatile }
            }
            tag::DEFAULT => {
                if volatile || !do_footprint { &mut self.tagged_nofootprint } else { &mut self.tagged_footprint }
            }
            tag::NETWORK => {
                do_footprint = false;
                if volatile { &mut self.network_volatile } else { &mut self.network_nonvolatile }
            }
            tag::MEDIA => {
                if volatile || !do_footprint { &mut self.media_nofootprint } else { &mut self.media_footprint }
            }
            tag::GRAPHICS => {
                if volatile || !do_footprint { &mut self.graphics_nofootprint } else { &mut self.graphics_footprint }
            }
            _ => {
                if volatile || !do_footprint { &mut self.neural_nofootprint } else { &mut self.neural_footprint }
            }
        };
        *slot += bytes;
        if !volatile && do_footprint {
            self.footprint += bytes;
        }
    }
}

/// `vm_purgeable_stats` of the volatile queues, `target` (an owner) or
/// every object's: each FIFO and LIFO group's and the obsolete queue's
/// object count and resident bytes (`resident(id)`).
pub fn stats(target: Option<&Arc<Owner>>, resident: &mut dyn FnMut(u64) -> u64) -> ([(u64, u64); GROUPS], [(u64, u64); GROUPS], (u64, u64)) {
    let lists: Vec<Vec<Vec<u64>>> = {
        let q = queues();
        q.objq.iter().map(|groups| groups.iter().map(|g| g.iter().copied().collect()).collect()).collect()
    };
    let mut stat = |ids: &[u64]| {
        let mut s = (0, 0);
        for &id in ids {
            let mine = super::vmobject::with(id, |o| o.purg.as_ref().map(|p| target.is_none_or(|t| p.owner.as_ref().is_some_and(|o| Arc::ptr_eq(o, t))))).flatten().unwrap_or(false);
            if mine {
                s.0 += 1;
                s.1 += resident(id);
            }
        }
        s
    };
    let mut fifo = [(0, 0); GROUPS];
    let mut lifo = [(0, 0); GROUPS];
    for g in 0..GROUPS {
        fifo[g] = stat(&lists[Q_FIFO as usize][g]);
        lifo[g] = stat(&lists[Q_LIFO as usize][g]);
    }
    let obsolete = stat(&lists[Q_OBSOLETE as usize][0]);
    (fifo, lifo, obsolete)
}

/// The system's purgeable page counts (`vm_page_purgeable_count` and the
/// objects on the queues), for `host_info(HOST_VM_PURGABLE)` and the
/// statistics: the volatile objects' resident pages (none wired here).
pub fn volatile_objects() -> Vec<u64> {
    let q = queues();
    q.objq.iter().flat_map(|groups| groups.iter().flat_map(|g| g.iter().copied())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj() -> u64 {
        super::super::vmobject::allocate(0x4000, super::super::vmobject::Pager::Anon, None)
    }

    #[test]
    fn states_move_as_the_object_control_moves_them() {
        let id = obj();
        let owner = Arc::new(Owner::default());
        let mut p = Purg::nonvolatile();
        nonvolatile_enqueue(&mut p, id, Some(Arc::clone(&owner)));
        assert_eq!(owner.objects(), vec![id]);
        let mut st = 0;
        assert_eq!(control(&mut p, id, ctl::GET_STATE, &mut st).0, 0);
        assert_eq!(st, i32::from(state::NONVOLATILE));
        // Volatile, LIFO, group 3: on that queue, the old state back.
        let mut st = i32::from(state::VOLATILE) | state::BEHAVIOR_LIFO | (3 << state::GROUP_SHIFT);
        assert_eq!(control(&mut p, id, ctl::SET_STATE, &mut st).0, 0);
        assert_eq!((st, p.state, p.queue, p.group, p.when_ripe), (0, state::VOLATILE, Q_LIFO, 3, true));
        // An empty one stays empty when made volatile again.
        let mut st = i32::from(state::EMPTY);
        assert!(matches!(control(&mut p, id, ctl::SET_STATE, &mut st), (0, Purge::Pages)));
        assert_eq!((p.state, p.queue), (state::EMPTY, Q_NONE));
        let mut st = i32::from(state::VOLATILE);
        control(&mut p, id, ctl::SET_STATE, &mut st);
        assert_eq!(p.state, state::EMPTY);
        let mut st = i32::from(state::NONVOLATILE);
        control(&mut p, id, ctl::SET_STATE, &mut st);
        assert_eq!((p.state, st), (state::NONVOLATILE, i32::from(state::EMPTY)));
        // DENY is refused; a kernel-only object refuses the user.
        let mut st = i32::from(state::DENY);
        assert_eq!(control(&mut p, id, ctl::SET_STATE, &mut st).0, 4);
        p.only_by_kernel = true;
        let mut st = 0;
        assert_eq!(control(&mut p, id, ctl::SET_STATE, &mut st).0, 2);
        assert_eq!(control(&mut p, id, ctl::SET_STATE_FROM_KERNEL, &mut st).0, 0);
        disown(&owner);
        assert!(owner.objects().is_empty());
    }

    #[test]
    fn the_ledgers_follow_the_state_and_the_tag() {
        let mut o = Owned::default();
        let mut p = Purg::nonvolatile();
        o.add(&p, 0x4000);
        p.state = state::VOLATILE;
        o.add(&p, 0x8000);
        assert_eq!((o.purgeable_nonvolatile, o.purgeable_volatile, o.footprint), (0x4000, 0x8000, 0x4000));
        let mut t = Purg { tag: tag::GRAPHICS, ..Purg::tagged() };
        let mut g = Owned::default();
        g.add(&t, 0x4000);
        t.no_footprint = true;
        g.add(&t, 0x4000);
        let n = Purg { tag: tag::NETWORK, ..Purg::tagged() };
        g.add(&n, 0x4000);
        assert_eq!((g.graphics_footprint, g.graphics_nofootprint, g.network_nonvolatile, g.footprint), (0x4000, 0x4000, 0x4000, 0x4000));
    }
}

/// The map's page.
const PAGE: u64 = super::mach::PAGE_MASK + 1;

/// The resident bytes of object `id`'s pages: what the host holds of them
/// (none wired: a purgeable object's wired pages are not billed). None
/// where the host cannot say.
pub fn resident(id: u64) -> Option<u64> {
    let hold = super::vmobject::with(id, |o| o.hold.clone()).flatten()?;
    let n = (hold.len / PAGE) as usize;
    let mut st = vec![0u8; n];
    if !crate::host_page_states(hold.addr, hold.len as usize, PAGE as usize, &mut st) {
        return None;
    }
    Some(st.iter().filter(|&&x| x & (crate::page_state::PRESENT | crate::page_state::PAGED_OUT) != 0).count() as u64 * PAGE)
}

/// The ledgers of the objects `owner` owns, from what the host holds of
/// their pages; none where the host cannot say.
pub fn owned(owner: &Owner) -> Option<Owned> {
    let mut o = Owned::default();
    for id in owner.objects() {
        let Some(p) = super::vmobject::with(id, |ob| ob.purg.clone()).flatten() else { continue };
        o.add(&p, resident(id)?);
    }
    Some(o)
}

/// `vm_object_purge`: the host's pages of object `id` emptied (its own
/// purgeable object made empty, then nonvolatile again so that the host
/// never empties it on its own). Whether the host did.
pub fn purge_pages(id: u64) -> bool {
    let Some(hold) = super::vmobject::with(id, |o| o.hold.clone()).flatten() else { return false };
    crate::host_purge(hold.addr, hold.len as usize)
}

impl crate::syscalls::Kernel {
    /// The task as an owner of objects.
    pub(crate) fn darwin_owner(&self) -> Arc<Owner> {
        self.dtask.rusage.meter.owner()
    }

    /// A new purgeable (or, `purg` DENY, only tagged) object of `size`
    /// bytes owned by this task, its pages the host's purgeable memory:
    /// the object and its maker's reference, or KERN_*.
    pub(crate) fn darwin_owned_object(&mut self, size: u64, purg: Purg) -> Result<u64, u64> {
        let Some(addr) = usize::try_from(size).ok().and_then(crate::host_hold_purgeable) else {
            self.darwin_unimplemented(format!("a purgeable or tagged object of {size:#x} bytes on a host that holds no purgeable memory apart from a task's, or not so much"));
            return Err(5);
        };
        let hold = Arc::new(super::vmobject::Hold { addr, len: size });
        let owner = self.darwin_owner();
        Ok(super::vmobject::allocate_owned(size, hold, purg, Some(owner)))
    }

    /// A look at the owner of object `id` before a change that lowers its
    /// footprint (a nonvolatile object made volatile or emptied), so the
    /// footprint's peaks hold what it had.
    fn darwin_owner_look(&mut self, m: &mut GuestMem<'_>, id: u64) {
        let Some(owner) = super::vmobject::with(id, |o| o.purg.as_ref().and_then(|p| p.owner.clone())).flatten() else { return };
        if Arc::ptr_eq(&owner, &self.darwin_owner()) {
            let _ = self.darwin_footprint_now(m);
            return;
        }
        let pid = owner.pid();
        if let Some((p, false)) = self.darwin_public(pid) {
            let _ = super::rusage::footprint_from_outside(&self.procs, pid, &p);
        }
    }

    /// `vm_object_purgable_control` of object `id` with its owner looked
    /// at first where its footprint may drop, and its pages emptied when
    /// the change says so: KERN_*, the old state in `st`.
    pub(crate) fn darwin_object_purgable_control(&mut self, m: &mut GuestMem<'_>, id: u64, control: u32, st: &mut i32) -> u64 {
        let was = super::vmobject::with(id, |o| o.purg.as_ref().map(|p| p.state)).flatten();
        let Some(was) = was else { return 4 };
        if control != ctl::GET_STATE && was == state::NONVOLATILE && (*st & state::STATE_MASK) as u8 != state::NONVOLATILE {
            self.darwin_owner_look(m, id);
        }
        let r = super::vmobject::with(id, |o| match &mut o.purg {
            Some(p) => self::control(p, id, control, st),
            None => (4, Purge::None),
        });
        let Some((kr, purge)) = r else { return 4 };
        if matches!(purge, Purge::Pages) && !purge_pages(id) {
            self.darwin_unimplemented("emptying a purgeable object on a host that cannot empty its own".into());
        }
        kr
    }

    /// `vm_purgeable_object_purge_all`: every volatile object, everyone's,
    /// emptied (no owner's footprint changes: volatile pages are in none).
    pub(crate) fn darwin_purge_all(&mut self) {
        for id in purge_all_objects() {
            if !purge_pages(id) {
                self.darwin_unimplemented("emptying a purgeable object on a host that cannot empty its own".into());
            }
        }
    }
}

impl crate::syscalls::Kernel {
    /// An entitlement's string value (`IOTaskGetEntitlement`), the task's.
    fn darwin_entitlement_string(c: Option<&super::codesign::CodeSign>, key: &str) -> Option<Vec<u8>> {
        match c?.ents.get(key.as_bytes())? {
            super::codesign::Ent::String(s) => Some(s.clone()),
            _ => None,
        }
    }

    /// `mach_memory_entry_ownership_from_user(entry, owner, ledger_tag,
    /// ledger_flags)` of named entry `id`: the owner a task's control port
    /// (else none, the owner left as it is), the right to give memory away,
    /// to keep it out of the footprint or to tag it "network" checked
    /// (`com.apple.private.memory.ownership_transfer`, or matching
    /// transfer-send and transfer-accept entitlements), then the entry's
    /// whole object (or, for a copy, each of its objects) given the owner
    /// and tag (`vm_object_ownership_change`).
    pub(crate) fn darwin_entry_ownership(&mut self, id: u64, owner: Option<super::ipc::right::Carried>, tag_in: i32, flags_in: i32) -> u64 {
        const KERN_INVALID_ARGUMENT: u64 = 4;
        const KERN_FAILURE: u64 = 5;
        const KERN_NO_ACCESS: u64 = 8;
        let me = self.ipc().task;
        // convert_port_to_task_mig: a task's control port, else none.
        let owner_key = match owner {
            Some(super::ipc::right::Carried::Port(p)) => {
                let ipc = self.ipc();
                let port = ipc.port(p);
                (port.active && port.kobject == Some(super::ipc::Kobject::Task)).then_some(if port.owner == 0 { me } else { port.owner })
            }
            _ => None,
        };
        let mut flags = flags_in;
        if (owner_key.is_some_and(|o| o != me)) || flags & (tag::FLAG_NO_FOOTPRINT | tag::FLAG_NO_FOOTPRINT_FOR_DEBUG) != 0 || tag_in == tag::NETWORK {
            let mut ok = self.darwin_task_entitled("com.apple.private.memory.ownership_transfer");
            if !ok {
                let ours = Self::darwin_entitlement_string(self.dtask.codesign.as_ref(), "com.apple.developer.memory.transfer-send");
                let theirs = owner_key.and_then(|o| {
                    let pid = if o == me { Some(self.pid) } else { self.ipc().links.get(&o).map(|l| l.pid) };
                    let p = self.darwin_public(pid?)?.0;
                    Self::darwin_entitlement_string(p.codesign.as_deref(), "com.apple.developer.memory.transfer-accept")
                });
                ok = matches!((ours, theirs), (Some(a), Some(b)) if a == b && a.len() < 1024);
            }
            if !ok {
                return KERN_NO_ACCESS;
            }
            if flags & tag::FLAG_NO_FOOTPRINT_FOR_DEBUG != 0 {
                flags = (flags & !tag::FLAG_NO_FOOTPRINT_FOR_DEBUG) | tag::FLAG_NO_FOOTPRINT;
            }
        }
        if flags & !tag::FLAGS != 0 {
            return KERN_INVALID_ARGUMENT;
        }
        if tag_in != tag::UNCHANGED && !(0..=tag::MAX).contains(&tag_in) {
            return KERN_INVALID_ARGUMENT;
        }
        let Some(e) = super::vmentry::get(id) else { return KERN_INVALID_ARGUMENT };
        // The new owner as an owner of objects: its meter's.
        let new_owner: Option<Arc<Owner>> = match owner_key {
            None => None,
            Some(o) if o == me => Some(self.darwin_owner()),
            Some(o) => {
                let pid = self.ipc().links.get(&o).map(|l| l.pid);
                match pid.and_then(|pid| self.darwin_public(pid)) {
                    Some((p, false)) => Some(p.rusage.meter.owner()),
                    // A task that has ended disowned everything.
                    _ => None,
                }
            }
        };
        let fully_owned = super::vmobject::with(e.obj, |o| o.purg.as_ref().is_some_and(|p| p.owner.is_some())).unwrap_or(false);
        if e.is_copy {
            if e.fully_owned {
                self.darwin_unimplemented("mach_memory_entry_ownership of a copy entry whose objects are all owned (each object's ownership)".into());
                return KERN_FAILURE;
            }
            return KERN_INVALID_ARGUMENT;
        }
        if !fully_owned {
            return KERN_INVALID_ARGUMENT;
        }
        let size = super::vmobject::with(e.obj, |o| o.size);
        if e.offset != 0 || size != Some(e.size) {
            return KERN_INVALID_ARGUMENT;
        }
        // vm_object_ownership_change, its old owner's footprint looked at
        // first.
        let internal = super::vmobject::with(e.obj, |o| o.internal()).unwrap_or(false);
        if !internal {
            return KERN_INVALID_ARGUMENT;
        }
        let state = super::vmobject::with(e.obj, |o| o.purg.as_ref().map(|p| (p.state, p.tag))).flatten();
        let Some((st, old_tag)) = state else { return KERN_INVALID_ARGUMENT };
        let new_tag = if tag_in == tag::UNCHANGED { old_tag } else { tag_in };
        if new_tag == tag::NONE && st == state::DENY {
            return KERN_INVALID_ARGUMENT;
        }
        let obj = e.obj;
        let _ = self.darwin_own_memory(|k, m| k.darwin_owner_look(m, obj));
        super::vmobject::with(obj, |o| {
            if let Some(p) = &mut o.purg {
                p.tag = new_tag;
                p.no_footprint = flags & tag::FLAG_NO_FOOTPRINT != 0;
                if let Some(no) = new_owner {
                    set_owner(p, obj, Some(no));
                }
            }
        });
        0
    }
}
