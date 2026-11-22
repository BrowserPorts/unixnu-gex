//! IPC importance (`osfmk/ipc/ipc_importance.c` and the importance parts
//! of `ipc_port.c`, `ipc_right.c`, `ipc_object.c`, `ipc_kmsg.c`,
//! `mach_port.c` and `task_policy.c`, xnu-10063.141.1).
//!
//! A donor's message to a port that takes donations raises the importance
//! of the port, of every port it is in transit to, and of the task that
//! receives the last of them if it takes boosts (a receiver): the task is
//! boosted while it holds any assertion. A boosted receiver donates in
//! turn through what it sends. A message keeps its link to its sender's
//! element until it is received, when the receiver either keeps the boost
//! in the voucher (an inherit element) or holds it as a legacy external
//! assertion until it drops it.
//!
//! Every user task has an element (`task_policy_create` makes it); here it
//! is made the first time it is needed. A task's marks (receiver, donor,
//! live donor, de-nap receiver) are its task policy's, and its boost is its
//! policy's `boosted`. Nothing here marks a task a de-nap receiver (only
//! macOS's apps are), so the App Nap drop delay never starts; importance
//! watch ports, the only way a port names a task to boost apart from its
//! receiver (`ip_imp_task`), are refused by spawn.

use super::ipc::msg::Kmsg;
use super::ipc::{Ipc, ObjId, Receiver, TaskKey};
use super::taskpolicy::Importance;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A task's policy, shared by its process.
pub type Policy = Arc<super::taskpolicy::PolicyCell>;

/// A task's policy as its element reaches it: the cell, where the process
/// holding the table is the task's own (natively every task's); else, in
/// the page, a task of another process, whose policy is in that process's
/// memory: a mirror of its importance marks, which that process sets each
/// time it gives the table back, and whose changes made here go to it
/// ([`super::ipc::Remote::Policy`]) as well.
#[derive(Clone, Debug)]
pub enum PolicyAt {
    Cell(Policy),
    Mirror(Importance),
}

impl PolicyAt {
    /// The task's importance marks.
    fn marks(&self) -> Importance {
        match self {
            PolicyAt::Cell(c) => c.lock().unwrap_or_else(|e| e.into_inner()).imp,
            PolicyAt::Mirror(m) => *m,
        }
    }
}

/// A change another task's call makes to a task's importance marks and
/// boost ([`PolicyAt`]), as the task's own process applies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyOp {
    /// `task_update_boost_locked`: boosted (with a transition) or not.
    Boost(bool),
    /// A live donor's mark propagated (`ipc_importance_task_update_live_donor`).
    DonorPropagated(bool),
    /// `ipc_importance_reset_locked`'s donor mark cleared.
    ResetDonor,
}

impl PolicyOp {
    /// The change, on the task's policy.
    pub fn apply(self, p: &mut super::taskpolicy::TaskPolicy) {
        self.apply_marks(&mut p.imp);
        if let PolicyOp::Boost(b) = self {
            p.set_boosted(b);
        }
    }

    /// The change, on its importance marks alone (a mirror's).
    fn apply_marks(self, imp: &mut Importance) {
        match self {
            PolicyOp::Boost(b) => {
                if b {
                    imp.transitions += 1;
                }
            }
            PolicyOp::DonorPropagated(d) => imp.donor_propagated = d,
            PolicyOp::ResetDonor => {
                imp.donor = false;
                imp.donor_propagated = false;
            }
        }
    }
}

/// A live donor's donor mark changed with its effective policy: its
/// importance is to be propagated ([`Ipc::importance_settle`]).
pub static LIVE_DONOR_CHANGED: AtomicBool = AtomicBool::new(false);

/// `III_DEPTH_RESET`, `III_DEPTH_MASK`, `III_DEPTH_MAX`.
const DEPTH_RESET: u32 = 0x8000_0000;
const DEPTH_MASK: u32 = 0xff;
const DEPTH_MAX: u32 = 32;

/// `kern_return_t`s.
pub mod kr {
    pub const SUCCESS: u32 = 0;
    pub const NO_SPACE: u32 = 3;
    pub const INVALID_ARGUMENT: u32 = 4;
    pub const FAILURE: u32 = 5;
    pub const INVALID_TASK: u32 = 16;
    pub const NOT_SUPPORTED: u32 = 46;
}

/// A task's element (`struct ipc_importance_task`).
#[derive(Debug)]
pub struct ImpTask {
    refs: u32,
    made: u32,
    externcnt: u32,
    externdrop: u32,
    /// `iit_kmsgs`: the messages whose importance links here, through this
    /// element or an inherit to it.
    kmsgs: Vec<u64>,
    /// `iit_task`: the task's key and process; none once disconnected.
    task: Option<(TaskKey, i32)>,
    /// The task's key, kept after the task is disconnected: whose policy
    /// this is.
    owner: TaskKey,
    /// The task's policy, with its marks, which outlive the task as the
    /// element's do.
    policy: PolicyAt,
    /// `iit_inherits`: the inherit elements made from this one (or from
    /// an inherit to it).
    inherits: Vec<u64>,
    assertcnt: u32,
    legacy_externcnt: u32,
    legacy_externdrop: u32,
    filelocks: u32,
    /// `iit_updatepolicy`: a transition is to be applied to the task.
    updatepolicy: bool,
    /// `iit_updateq` is the list of updates being made.
    queued: bool,
}

/// An inherit element (`struct ipc_importance_inherit`): a received
/// message's importance kept in its receiver's voucher.
#[derive(Debug)]
pub struct ImpInherit {
    refs: u32,
    made: u32,
    externcnt: u32,
    externdrop: u32,
    donating: bool,
    depth: u32,
    to_task: u64,
    from_elem: Option<u64>,
}

#[derive(Debug)]
pub enum Elem {
    Task(ImpTask),
    Inherit(ImpInherit),
}

/// A message's importance (`ikm_importance` and `MACH_MSGH_BITS_RAISEIMP`),
/// kept where every task reaches it wherever the message waits.
#[derive(Debug)]
struct KmsgImp {
    elem: Option<u64>,
    raised: bool,
    /// `msgh_remote_port`.
    dest: ObjId,
}

/// The system's importance elements and the messages linked to them.
#[derive(Debug, Default)]
pub struct ImpState {
    elems: HashMap<u64, Elem>,
    /// `task->task_imp_base`, by task.
    by_task: HashMap<TaskKey, u64>,
    /// The tasks that have ended, whose importance is gone.
    ended: std::collections::HashSet<TaskKey>,
    kmsgs: HashMap<u64, KmsgImp>,
    next_kmsg: u64,
    next_handle: u64,
    /// `task->watchports`: the ports each task's turnstile watch port
    /// elements are on.
    watchports: HashMap<TaskKey, Vec<ObjId>>,
}

impl ImpState {
    fn alloc(&mut self) -> u64 {
        // Apart from the bank's handles, aligned as an element's address.
        self.next_handle = self.next_handle.max(0x4000_0000) + 0x40;
        self.next_handle
    }
}

/// `III_EXTERN`, `IIT_EXTERN`, `IIT_LEGACY_EXTERN`.
fn extern_of(cnt: u32, drop: u32) -> u32 {
    cnt - drop
}

impl Ipc {
    fn imp(&mut self) -> &mut ImpState {
        &mut self.vouchers.imp
    }

    pub(crate) fn imp_is_task(&self, h: u64) -> bool {
        matches!(self.vouchers.imp.elems.get(&h).expect("an importance element"), Elem::Task(_))
    }

    fn itask(&mut self, h: u64) -> &mut ImpTask {
        match self.vouchers.imp.elems.get_mut(&h) {
            Some(Elem::Task(t)) => t,
            _ => panic!("an importance task element"),
        }
    }

    /// `op` on task element `h`'s policy: its cell's, or its mirror's and,
    /// told to its task's process, the cell's there.
    fn imp_policy_change(&mut self, h: u64, op: PolicyOp) {
        let it = self.itask(h);
        match &mut it.policy {
            PolicyAt::Cell(c) => {
                let c = Arc::clone(c);
                op.apply(&mut c.lock().unwrap_or_else(|e| e.into_inner()));
            }
            PolicyAt::Mirror(m) => {
                op.apply_marks(m);
                let owner = it.owner;
                // (a task that has ended hears nothing, as its policy
                // outlives it unread)
                self.remote(owner, super::ipc::Remote::Policy(op));
            }
        }
    }

    fn itask_ref(&self, h: u64) -> &ImpTask {
        match self.vouchers.imp.elems.get(&h) {
            Some(Elem::Task(t)) => t,
            _ => panic!("an importance task element"),
        }
    }

    fn iinherit(&mut self, h: u64) -> &mut ImpInherit {
        match self.vouchers.imp.elems.get_mut(&h) {
            Some(Elem::Inherit(i)) => i,
            _ => panic!("an importance inherit element"),
        }
    }

    fn irefs(&mut self, h: u64) -> &mut u32 {
        match self.vouchers.imp.elems.get_mut(&h).expect("an importance element") {
            Elem::Task(t) => &mut t.refs,
            Elem::Inherit(i) => &mut i.refs,
        }
    }

    pub(crate) fn imp_made(&mut self, h: u64) -> &mut u32 {
        match self.vouchers.imp.elems.get_mut(&h).expect("an importance element") {
            Elem::Task(t) => &mut t.made,
            Elem::Inherit(i) => &mut i.made,
        }
    }

    /// `ipc_importance_reference`.
    pub(crate) fn imp_reference(&mut self, h: u64) {
        let r = self.irefs(h);
        assert!(*r > 0);
        *r += 1;
    }

    /// `ipc_importance_task_release_internal`: a reference that cannot be
    /// the last.
    fn imp_release_internal(&mut self, h: u64) {
        let r = self.irefs(h);
        assert!(*r > 1, "iit unexpected zero refs");
        *r -= 1;
    }

    /// The task element an element's linkage lives on: itself, or an
    /// inherit's task.
    fn imp_link_task(&self, h: u64) -> u64 {
        match self.vouchers.imp.elems.get(&h).expect("an importance element") {
            Elem::Task(_) => h,
            Elem::Inherit(i) => i.to_task,
        }
    }

    // -- marks --------------------------------------------------------------------------

    fn imp_marks(&self, t: Option<u64>) -> Importance {
        match t {
            Some(h) => self.itask_ref(h).policy.marks(),
            None => Importance::default(),
        }
    }

    /// `ipc_importance_task_is_marked_receiver`.
    pub(crate) fn imp_is_marked_receiver(&self, t: Option<u64>) -> bool {
        self.imp_marks(t).receiver
    }

    /// `ipc_importance_task_is_marked_denap_receiver`.
    fn imp_is_marked_denap(&self, t: Option<u64>) -> bool {
        self.imp_marks(t).denap_receiver
    }

    /// `ipc_importance_task_is_any_receiver_type`.
    pub(crate) fn imp_is_any_receiver_type(&self, t: Option<u64>) -> bool {
        let m = self.imp_marks(t);
        m.receiver || m.denap_receiver
    }

    /// `ipc_importance_task_is_marked_donor`.
    fn imp_is_marked_donor(&self, t: Option<u64>) -> bool {
        self.imp_marks(t).donor
    }

    /// `ipc_importance_task_is_donor`: a marked donor, or a receiver
    /// holding assertions.
    pub(crate) fn imp_is_donor(&self, t: Option<u64>) -> bool {
        let Some(h) = t else { return false };
        let m = self.imp_marks(t);
        m.donor || (m.receiver && self.itask_ref(h).assertcnt > 0)
    }

    /// `ipc_importance_task_is_never_donor`.
    fn imp_is_never_donor(&self, t: Option<u64>) -> bool {
        if t.is_none() {
            return true;
        }
        let m = self.imp_marks(t);
        !m.donor && !m.live_donor && !m.receiver
    }

    // -- a task's element ---------------------------------------------------------------

    /// `task->task_imp_base`: the task's element, which every user task
    /// has (made here the first time it is wanted, with the task's
    /// reference); none for a task that has ended.
    pub(crate) fn imp_base(&mut self, key: TaskKey) -> Option<u64> {
        if let Some(&h) = self.vouchers.imp.by_task.get(&key) {
            return Some(h);
        }
        if self.vouchers.imp.ended.contains(&key) {
            return None;
        }
        let link = self.links.get(&key)?;
        let (pid, policy) = (link.pid, PolicyAt::Cell(link.policy.clone()?));
        let imp = self.imp();
        let h = imp.alloc();
        imp.elems.insert(h, Elem::Task(ImpTask { refs: 1, made: 0, externcnt: 0, externdrop: 0, kmsgs: Vec::new(), task: Some((key, pid)), owner: key, policy, inherits: Vec::new(), assertcnt: 0, legacy_externcnt: 0, legacy_externdrop: 0, filelocks: 0, updatepolicy: false, queued: false }));
        imp.by_task.insert(key, h);
        Some(h)
    }

    /// `ipc_importance_for_task(task, made)`: the task's element with a
    /// reference for the caller, or a made reference.
    pub(crate) fn imp_for_task(&mut self, key: TaskKey, made: bool) -> Option<u64> {
        let h = self.imp_base(key)?;
        let t = self.itask(h);
        if made {
            if t.made == 0 {
                t.refs += 1;
            }
            t.made += 1;
        } else {
            t.refs += 1;
        }
        Some(h)
    }

    /// `task_pid(iit_task)`: -1 for an element whose task is gone.
    pub(crate) fn imp_task_pid(&self, h: u64) -> i32 {
        self.itask_ref(h).task.map_or(-1, |(_, pid)| pid)
    }

    // -- references ---------------------------------------------------------------------

    /// `ipc_importance_release_locked`: the last reference of a task's
    /// element (its task gone) frees it; an inherit's unlinks it, gives
    /// back what it donated to its task, and lets go of its source and
    /// its task.
    pub(crate) fn imp_release(&mut self, h: u64) {
        let r = self.irefs(h);
        assert!(*r > 0);
        *r -= 1;
        if *r > 0 {
            return;
        }
        if self.imp_is_task(h) {
            debug_assert!(self.itask(h).task.is_none(), "the task still holds a reference on its importance");
            self.imp().elems.remove(&h);
            return;
        }
        let to = self.iinherit(h).to_task;
        debug_assert!(self.imp_is_any_receiver_type(Some(to)));
        let from = self.imp_inherit_unlink(h).expect("an inherit's source");
        let i = self.iinherit(h);
        debug_assert!(i.externcnt >= i.externdrop);
        if i.donating {
            let assertcnt = extern_of(i.externcnt, i.externdrop);
            let (cnt, drop) = (i.externcnt, i.externdrop);
            i.externcnt = 0;
            i.externdrop = 0;
            i.donating = false;
            let t = self.itask(to);
            debug_assert!(t.externcnt >= cnt && t.externdrop >= drop);
            t.externcnt -= cnt;
            t.externdrop -= drop;
            if self.imp_check_transition(to, false, assertcnt) {
                self.imp_propagate_assertion(to, false, true);
            }
        } else {
            i.externcnt = 0;
            i.externdrop = 0;
        }
        self.imp_release(from);
        self.imp_release(to);
        self.imp().elems.remove(&h);
    }

    /// `ipc_importance_inherit_link`.
    fn imp_inherit_link(&mut self, inherit: u64, from: u64) {
        let t = self.imp_link_task(from);
        self.itask(t).inherits.push(inherit);
        let i = self.iinherit(inherit);
        debug_assert!(i.from_elem.is_none());
        i.from_elem = Some(from);
    }

    /// `ipc_importance_inherit_unlink`.
    fn imp_inherit_unlink(&mut self, inherit: u64) -> Option<u64> {
        let from = self.iinherit(inherit).from_elem.take()?;
        let t = self.imp_link_task(from);
        self.itask(t).inherits.retain(|&x| x != inherit);
        Some(from)
    }

    /// `ipc_importance_inherit_find`.
    fn imp_inherit_find(&mut self, from: u64, to_task: u64, depth: u32) -> Option<u64> {
        let t = self.imp_link_task(from);
        let list = self.itask(t).inherits.clone();
        list.into_iter().find(|&i| {
            let x = self.iinherit(i);
            x.to_task == to_task && x.depth == depth
        })
    }

    // -- transitions and their propagation ----------------------------------------------

    /// `ipc_importance_task_check_transition`: the assertion count of a
    /// receiver changes by `delta`; whether its boost changed with it.
    fn imp_check_transition(&mut self, h: u64, hold: bool, delta: u32) -> bool {
        if !self.imp_is_any_receiver_type(Some(h)) {
            return false;
        }
        let t = self.itask(h);
        let before = t.assertcnt > 0;
        let ext = extern_of(t.externcnt, t.externdrop);
        if hold {
            t.assertcnt += delta;
        } else if t.assertcnt < delta + ext {
            t.assertcnt = ext;
        } else {
            t.assertcnt -= delta;
        }
        let after = t.assertcnt > 0;
        if after != before {
            debug_assert!(!t.updatepolicy);
            if t.queued {
                // Off the list of updates it was on, the change undone.
                t.queued = false;
                self.imp_release_internal(h);
            } else {
                self.itask(h).updatepolicy = true;
            }
            return true;
        }
        false
    }

    /// `ipc_importance_task_propagate_helper`: a change of the element's
    /// donation goes to the ports its messages are on and the tasks its
    /// inherits are to; tasks whose boost changed are queued.
    fn imp_propagate_helper(&mut self, h: u64, hold: bool, propagation: &mut VecDeque<u64>) {
        for id in self.itask(h).kmsgs.clone() {
            let Some(rec) = self.vouchers.imp.kmsgs.get_mut(&id) else { continue };
            let delta = if hold {
                if rec.raised {
                    continue;
                }
                rec.raised = true;
                1
            } else {
                if !rec.raised {
                    continue;
                }
                rec.raised = false;
                -1
            };
            let port = self.kmsg_dest_of(id);
            let (_, task) = self.port_importance_delta_internal(port, false, delta);
            let Some(t) = task else { continue };
            if self.imp_check_transition(t, hold, 1) {
                propagation.push_back(t);
            } else {
                self.imp_release_internal(t);
            }
        }
        for inh in self.itask(h).inherits.clone() {
            let i = self.iinherit(inh);
            let assertcnt = extern_of(i.externcnt, i.externdrop);
            let to = i.to_task;
            if assertcnt == 0 {
                debug_assert!(!i.donating);
                continue;
            }
            let (cnt, drop) = (i.externcnt, i.externdrop);
            if hold {
                if i.donating {
                    continue;
                }
                i.donating = true;
                let t = self.itask(to);
                t.externcnt += cnt;
                t.externdrop += drop;
            } else {
                if !i.donating {
                    continue;
                }
                i.donating = false;
                let t = self.itask(to);
                debug_assert!(t.externcnt >= cnt && t.externdrop >= drop);
                t.externcnt -= cnt;
                t.externdrop -= drop;
            }
            debug_assert!(self.imp_is_any_receiver_type(Some(to)));
            if self.imp_check_transition(to, hold, assertcnt) {
                self.imp_reference(to);
                propagation.push_back(to);
            }
        }
    }

    /// `ipc_importance_task_propagate_assertion_locked`: a transition of
    /// the element (or, without `update_task_imp`, of its donation alone)
    /// goes downstream through every receiver that is no donor itself; the
    /// tasks whose boost changed are then updated.
    fn imp_propagate_assertion(&mut self, h: u64, hold: bool, update_task_imp: bool) {
        let mut propagate = VecDeque::new();
        let mut updates: VecDeque<u64> = VecDeque::new();
        if update_task_imp {
            self.imp_reference(h);
            propagate.push_back(h);
        } else {
            self.imp_propagate_helper(h, hold, &mut propagate);
        }
        while let Some(t) = propagate.pop_front() {
            if !self.imp_is_marked_donor(Some(t)) && self.imp_is_marked_receiver(Some(t)) {
                self.imp_propagate_helper(t, hold, &mut propagate);
            }
            let it = self.itask(t);
            let need_update = std::mem::take(&mut it.updatepolicy);
            if need_update && it.task.is_some() {
                debug_assert!(!it.queued, "a task element already on an update queue");
                if !hold && t != h && self.imp_is_marked_denap(Some(t)) {
                    unreachable!("ipc_importance_task_delayed_drop: no task is a de-nap receiver on iOS");
                }
                self.itask(t).queued = true;
                self.imp_reference(t);
                if hold {
                    updates.push_back(t);
                } else {
                    updates.push_front(t);
                }
            }
            self.imp_release_internal(t);
        }
        if !updates.is_empty() {
            self.imp_process_updates(updates, hold);
        }
    }

    /// `ipc_importance_task_process_updates`: each task on the list has
    /// its boost applied to its policy (`task_update_boost_locked`).
    fn imp_process_updates(&mut self, updates: VecDeque<u64>, boost: bool) {
        for t in updates {
            let it = self.itask(t);
            if !it.queued {
                // Its transition was undone meanwhile (check_transition).
                continue;
            }
            it.queued = false;
            if it.task.is_none() {
                self.imp_release(t);
                continue;
            }
            self.imp_policy_change(t, PolicyOp::Boost(boost));
            self.imp_release(t);
        }
        self.importance_settle();
    }

    /// `ipc_importance_task_update_live_donor`, for each live donor whose
    /// policy changed its donor mark: what it donates through follows.
    pub(crate) fn importance_settle(&mut self) {
        LIVE_DONOR_CHANGED.store(false, Ordering::Relaxed);
        let tasks: Vec<u64> = self.vouchers.imp.by_task.values().copied().collect();
        for t in tasks {
            let imp = self.itask_ref(t).policy.marks();
            if !imp.live_donor || imp.donor == imp.donor_propagated {
                continue;
            }
            let hold = imp.donor;
            self.imp_policy_change(t, PolicyOp::DonorPropagated(hold));
            self.imp_propagate_assertion(t, hold, false);
        }
    }

    // -- assertions ---------------------------------------------------------------------

    /// `ipc_importance_task_hold_internal_assertion_locked`.
    pub(crate) fn imp_hold_internal_locked(&mut self, h: u64, count: u32) {
        if self.imp_check_transition(h, true, count) {
            self.imp_propagate_assertion(h, true, true);
        }
    }

    /// `ipc_importance_task_drop_internal_assertion_locked`.
    pub(crate) fn imp_drop_internal_locked(&mut self, h: u64, count: u32) {
        if self.imp_check_transition(h, false, count) {
            self.imp_propagate_assertion(h, false, true);
        }
    }

    /// `ipc_importance_task_hold_internal_assertion`: for a receiver.
    pub(crate) fn imp_hold_internal(&mut self, h: u64, count: u32) {
        if self.imp_is_any_receiver_type(Some(h)) {
            self.imp_hold_internal_locked(h, count);
        }
    }

    /// `ipc_importance_task_drop_internal_assertion`: for a receiver.
    pub(crate) fn imp_drop_internal(&mut self, h: u64, count: u32) {
        if self.imp_is_any_receiver_type(Some(h)) {
            self.imp_drop_internal_locked(h, count);
        }
    }

    /// `task_importance_hold_file_lock_assertion` (an element made if need
    /// be) or `task_importance_drop_file_lock_assertion` (only with one) on
    /// process `pid`'s task; a task that has ended has none.
    pub(crate) fn imp_file_lock(&mut self, pid: i32, hold: bool) {
        let Some(key) = self.links.iter().find(|(_, l)| l.pid == pid).map(|(&k, _)| k) else { return };
        if hold {
            if let Some(t) = self.imp_base(key) {
                self.imp_hold_file_lock(t, 1);
            }
        } else if let Some(t) = self.vouchers.imp.by_task.get(&key).copied() {
            self.imp_drop_file_lock(t, 1);
        }
    }

    /// `ipc_importance_task_hold_file_lock_assertion`.
    pub(crate) fn imp_hold_file_lock(&mut self, h: u64, count: u32) {
        if self.imp_is_any_receiver_type(Some(h)) {
            self.imp_hold_internal_locked(h, count);
            self.itask(h).filelocks += count;
        }
    }

    /// `ipc_importance_task_drop_file_lock_assertion`.
    pub(crate) fn imp_drop_file_lock(&mut self, h: u64, count: u32) -> u32 {
        if !self.imp_is_any_receiver_type(Some(h)) {
            return kr::SUCCESS;
        }
        let t = self.itask(h);
        if count > t.filelocks {
            return kr::INVALID_ARGUMENT;
        }
        t.filelocks -= count;
        self.imp_drop_internal_locked(h, count);
        kr::SUCCESS
    }

    /// `ipc_importance_task_hold_legacy_external_assertion`: only a task
    /// holding a legacy external boost may take another.
    pub(crate) fn imp_hold_legacy_external(&mut self, h: u64, count: u32) -> u32 {
        let t = self.itask(h);
        if extern_of(t.legacy_externcnt, t.legacy_externdrop) == 0 {
            return kr::FAILURE;
        }
        debug_assert!(t.assertcnt > 0 && extern_of(t.externcnt, t.externdrop) > 0);
        t.assertcnt += count;
        t.externcnt += count;
        t.legacy_externcnt += count;
        kr::SUCCESS
    }

    /// `ipc_importance_task_drop_legacy_external_assertion`.
    pub(crate) fn imp_drop_legacy_external(&mut self, h: u64, count: u32) -> u32 {
        if count > 1 {
            return kr::INVALID_ARGUMENT;
        }
        let t = self.itask(h);
        if count > extern_of(t.legacy_externcnt, t.legacy_externdrop) {
            return kr::FAILURE;
        }
        t.legacy_externdrop += count;
        t.externdrop += count;
        if extern_of(t.legacy_externcnt, t.legacy_externdrop) == 0 {
            if extern_of(t.externcnt, t.externdrop) != 0 {
                t.externcnt -= t.legacy_externcnt;
                t.externdrop -= t.legacy_externdrop;
            } else {
                t.externcnt = 0;
                t.externdrop = 0;
            }
            t.legacy_externcnt = 0;
            t.legacy_externdrop = 0;
        }
        if self.imp_check_transition(h, false, count) {
            self.imp_propagate_assertion(h, false, true);
        }
        kr::SUCCESS
    }

    /// `ipc_importance_task_externalize_legacy_assertion`: a received
    /// boost becomes the task's to drop.
    fn imp_externalize_legacy(&mut self, h: u64, count: u32) -> bool {
        if self.itask(h).task.is_none() || !self.imp_is_any_receiver_type(Some(h)) {
            return false;
        }
        let t = self.itask(h);
        t.legacy_externcnt += count;
        t.externcnt += count;
        true
    }

    /// `ipc_importance_reset_locked`: the task's donor mark (with
    /// `donor`) and legacy external assertions go, and what that changes
    /// downstream.
    fn imp_reset(&mut self, h: u64, donor: bool) {
        let before = self.imp_is_donor(Some(h));
        if donor {
            self.imp_policy_change(h, PolicyOp::ResetDonor);
        }
        let t = self.itask(h);
        t.externcnt -= t.legacy_externcnt;
        t.externdrop -= t.legacy_externdrop;
        let legacy = extern_of(t.legacy_externcnt, t.legacy_externdrop);
        if extern_of(t.externcnt, t.externdrop) < t.assertcnt {
            t.assertcnt -= legacy;
        } else {
            t.assertcnt = extern_of(t.externcnt, t.externdrop);
        }
        t.legacy_externcnt = 0;
        t.legacy_externdrop = 0;
        let after = self.imp_is_donor(Some(h));
        if after != before {
            self.imp_propagate_assertion(h, false, false);
        }
    }

    /// `task_importance_reset` (an exec's old task): its legacy external
    /// assertions go, its donor mark stays.
    pub(crate) fn imp_task_reset(&mut self, key: TaskKey) {
        if let Some(h) = self.vouchers.imp.by_task.get(&key).copied() {
            self.imp_reset(h, false);
        }
    }

    /// `ipc_importance_disconnect_task`: the task leaves its element, its
    /// donor mark and legacy assertions undone; vouchers may keep it.
    pub(crate) fn imp_disconnect_task(&mut self, key: TaskKey) {
        self.vouchers.imp.ended.insert(key);
        let Some(h) = self.vouchers.imp.by_task.remove(&key) else { return };
        self.itask(h).task = None;
        self.imp_reset(h, true);
        self.imp_release(h);
    }

    // -- ports --------------------------------------------------------------------------

    /// `ip_in_transit`.
    fn port_in_transit(&self, port: ObjId) -> bool {
        let p = self.port(port);
        p.active && p.receiver == Receiver::Transit && p.destination.is_some()
    }

    /// `ipc_port_impcount_delta`: the port's assertion count changes by
    /// `delta`, not below zero; the change made.
    pub(crate) fn port_impcount_delta(&mut self, port: ObjId, delta: i32) -> i32 {
        let p = self.port_mut(port);
        if !p.active {
            return 0;
        }
        if delta >= 0 {
            p.impcount += delta as u32;
            return delta;
        }
        let abs = delta.unsigned_abs();
        if p.impcount >= abs {
            p.impcount -= abs;
            return delta;
        }
        let d = -(p.impcount as i32);
        p.impcount = 0;
        d
    }

    /// The task a chain's base boosts: none for a temporary owner (it
    /// names no task here), else its receiver's if that takes boosts, with
    /// a reference.
    fn port_base_imp_task(&mut self, base: ObjId) -> Option<u64> {
        let p = self.port(base);
        if !p.active {
            return None;
        }
        if p.tempowner {
            // The task it names, if any.
            let t = p.imp_task?;
            self.imp_reference(t);
            return Some(t);
        }
        let Receiver::Space(_) = p.receiver else { return None };
        let owner = p.owner;
        let t = self.imp_base(owner)?;
        if !self.imp_is_any_receiver_type(Some(t)) {
            return None;
        }
        self.imp_reference(t);
        Some(t)
    }

    /// `ipc_port_importance_delta_internal`: the delta applied to the port
    /// and every port it is in transit to (with `sendpossible`, only once
    /// for an armed send-possible request), and the task at the end of
    /// the chain to apply it to, referenced.
    pub(crate) fn port_importance_delta_internal(&mut self, port: ObjId, sendpossible: bool, delta: i32) -> (i32, Option<u64>) {
        if delta == 0 {
            return (0, None);
        }
        let mut delta = delta;
        let mut base = port;
        while self.port_in_transit(base) {
            base = self.port(base).destination.expect("in transit");
        }
        if sendpossible {
            debug_assert_eq!(delta, 1);
            let p = self.port_mut(port);
            if p.sprequests && !p.spimportant {
                p.spimportant = true;
            } else {
                delta = 0;
            }
        }
        let mut cur = port;
        loop {
            delta = self.port_impcount_delta(cur, delta);
            if cur == base {
                break;
            }
            debug_assert!(!self.port(cur).tempowner);
            cur = self.port(cur).destination.expect("in transit");
        }
        (delta, self.port_base_imp_task(base))
    }

    /// `ipc_port_importance_delta`: and the assertions it brings to the
    /// task at the chain's end.
    pub(crate) fn port_importance_delta(&mut self, port: ObjId, sendpossible: bool, delta: i32) {
        let (delta, task) = self.port_importance_delta_internal(port, sendpossible, delta);
        let Some(t) = task else { return };
        if delta != 0 {
            debug_assert!(self.imp_is_any_receiver_type(Some(t)));
            if delta > 0 {
                self.imp_hold_internal(t, delta as u32);
            } else {
                self.imp_drop_internal(t, delta.unsigned_abs());
            }
        }
        self.imp_release(t);
    }

    /// `ipc_importance_check_circularity`'s accounting, once `port` is in
    /// transit to `dest`: its assertions go along the chain, and from the
    /// task that had them to the task at the chain's end.
    pub(crate) fn imp_port_enqueued(&mut self, port: ObjId, dest: ObjId) {
        // In a message, it watches for no task (its turnstile watch port
        // element goes), and the task it named is what had its boosts.
        self.watchport_clear(port);
        let release = self.port_mut(port).imp_task.take();
        let assertcnt = self.port(port).impcount;
        self.port_mut(port).tempowner = false;
        let mut cur = dest;
        loop {
            self.port_impcount_delta(cur, assertcnt as i32);
            if !self.port_in_transit(cur) {
                break;
            }
            cur = self.port(cur).destination.expect("in transit");
        }
        let task = if assertcnt > 0 { self.port_base_imp_task(cur) } else { None };
        let transfer = task != release;
        if let Some(t) = task {
            if transfer {
                self.imp_hold_internal_locked(t, assertcnt);
            }
        }
        if let Some(r) = release {
            if transfer {
                self.imp_drop_internal_locked(r, assertcnt);
            }
        }
        if let Some(t) = task {
            self.imp_release(t);
        }
        if let Some(r) = release {
            self.imp_release(r);
        }
    }

    /// `ipc_right_copyin` of a receive right: a port that was no temporary
    /// owner becomes one, and the assertions it brought its task are the
    /// count returned, for that task to drop.
    pub(crate) fn imp_receive_copied_in(&mut self, port: ObjId) -> u32 {
        let p = self.port_mut(port);
        if !p.tempowner {
            p.tempowner = true;
            return p.impcount;
        }
        0
    }

    /// `current_task()`.
    pub(crate) fn imp_current_task(&self) -> TaskKey {
        self.caller.unwrap_or(self.task)
    }

    /// `ipc_object_copyin`'s end: the current task loses the boosts of the
    /// receive right it gave up.
    pub(crate) fn imp_drop_current(&mut self, assertcnt: u32) {
        if assertcnt == 0 {
            return;
        }
        let me = self.imp_current_task();
        if let Some(t) = self.imp_base(me) {
            if self.imp_is_any_receiver_type(Some(t)) {
                self.imp_drop_internal(t, assertcnt);
            }
        }
    }

    /// `ipc_right_copyout` of a receive right that was in transit: the
    /// assertions it gave its old destination are taken back (its new
    /// task already has them).
    pub(crate) fn imp_receive_copied_out(&mut self, port: ObjId, old_dest: ObjId) {
        let assertcnt = self.port(port).impcount;
        self.port_impcount_delta(old_dest, -(assertcnt as i32));
    }

    /// `ipc_object_copyout_name` of a receive right: the port comes out of
    /// limbo into this space, whose task takes its assertions.
    pub(crate) fn imp_receive_slammed(&mut self, port: ObjId) {
        let me = self.task;
        let t = self.imp_base(me).filter(|&t| self.imp_is_any_receiver_type(Some(t)));
        let assertcnt = self.port(port).impcount;
        self.port_mut(port).tempowner = false;
        if let Some(t) = t {
            self.imp_hold_internal(t, assertcnt);
        }
    }

    /// `ipc_port_destroy`'s importance, before: the assertions a port that
    /// was no temporary owner had, which leave the current task (unless it
    /// is destroyed in the course of a destruction that has assertions of
    /// its own, `ith_assertions`); one sent home in a port-destroyed
    /// notification goes as a temporary owner. The count and whether this
    /// destruction is the outermost.
    pub(crate) fn imp_port_destroy_begin(&mut self, port: ObjId, pdrequest: bool) -> (u32, bool, Option<u64>) {
        self.watchport_clear(port);
        let top = self.ith_assertions == 0;
        let p = self.port_mut(port);
        let mut release = None;
        let assertcnt = if p.tempowner {
            // A temporary owner's named task had its boosts.
            release = p.imp_task.take();
            if release.is_some() { p.impcount } else { 0 }
        } else {
            if pdrequest {
                p.tempowner = true;
            }
            p.impcount
        };
        if top {
            self.ith_assertions = assertcnt;
        }
        (assertcnt, top, release)
    }

    /// `ipc_port_destroy`'s importance, after.
    pub(crate) fn imp_port_destroy_end(&mut self, assertcnt: u32, top: bool, release: Option<u64>) {
        if let Some(r) = release {
            if assertcnt > 0 {
                self.ith_assertions = 0;
                debug_assert!(self.imp_is_any_receiver_type(Some(r)));
                self.imp_drop_internal(r, assertcnt);
            }
            self.imp_release(r);
        } else if assertcnt > 0 && top {
            self.ith_assertions = 0;
            self.imp_drop_current(assertcnt);
        }
    }

    /// `mach_port_set_attributes(MACH_PORT_TEMPOWNER)`: the port's boosts
    /// leave the task that had them.
    pub(crate) fn imp_port_tempowner(&mut self, port: ObjId) {
        let p = self.port_mut(port);
        let mut release = None;
        let assertcnt = if p.tempowner {
            release = p.imp_task.take();
            if release.is_some() { p.impcount } else { 0 }
        } else {
            p.impcount
        };
        p.impdonation = true;
        p.tempowner = true;
        match release {
            Some(r) => {
                if assertcnt > 0 {
                    self.imp_drop_internal(r, assertcnt);
                }
                self.imp_release(r);
            }
            None => self.imp_drop_current(assertcnt),
        }
    }

    // -- watch ports --------------------------------------------------------------------

    /// A spawned task's watch ports (`proc_set_task_spawnpolicy`): for an
    /// adaptive daemon, each temporary owner sends its boosts to the task
    /// (`task_add_importance_watchport`), which holds those the ports had;
    /// for any task, each port in a space watches for it
    /// (`task_add_turnstile_watchports`), the task it watched for before
    /// losing it.
    pub(crate) fn imp_add_watchports(&mut self, key: TaskKey, ports: &[Option<ObjId>], adaptive: bool) {
        if adaptive {
            let mut boosts = 0;
            for &p in ports.iter().flatten() {
                let new = self.imp_for_task(key, false);
                let port = self.port_mut(p);
                let (mut boost, mut release, mut kept) = (0, None, false);
                if port.tempowner {
                    boost = port.impcount;
                    release = port.imp_task.take();
                    if self.imp_is_marked_receiver(new) {
                        self.port_mut(p).imp_task = new;
                        kept = true;
                    }
                }
                if let (Some(n), false) = (new, kept) {
                    self.imp_release(n);
                }
                if let Some(r) = release {
                    if boost > 0 {
                        self.imp_drop_internal(r, boost);
                    }
                    self.imp_release(r);
                }
                boosts += boost;
            }
            // task_importance_hold_internal_assertion.
            if boosts > 0 {
                if let Some(t) = self.imp_for_task(key, false) {
                    self.imp_hold_internal(t, boosts);
                    self.imp_release(t);
                }
            }
        }
        for &p in ports.iter().flatten() {
            let port = self.port(p);
            // ipc_port_add_watchport_elem_locked: a live port in a space,
            // not a special reply port.
            if !port.active || port.specialreply || !matches!(port.receiver, Receiver::Space(_)) {
                continue;
            }
            self.watchport_clear(p);
            self.port_mut(p).watchport = Some(key);
            self.vouchers.imp.watchports.entry(key).or_default().push(p);
        }
    }

    /// `ipc_port_clear_watchport_elem_internal`: the port watches for its
    /// task no more.
    fn watchport_clear(&mut self, port: ObjId) {
        if let Some(t) = self.port_mut(port).watchport.take() {
            if let Some(list) = self.vouchers.imp.watchports.get_mut(&t) {
                list.retain(|&x| x != port);
                if list.is_empty() {
                    self.vouchers.imp.watchports.remove(&t);
                }
            }
        }
    }

    /// `task_remove_turnstile_watchports`: a task that ends is watched for
    /// by no port.
    pub(crate) fn imp_remove_watchports(&mut self, key: TaskKey) {
        for p in self.vouchers.imp.watchports.remove(&key).unwrap_or_default() {
            if self.port(p).watchport == Some(key) {
                self.port_mut(p).watchport = None;
            }
        }
    }

    // -- messages -----------------------------------------------------------------------

    /// `ipc_kmsg_send`'s undo: a send that failed with one of these
    /// results lets go of the importance it took.
    pub(crate) fn importance_send_failed(&mut self, kmsg: &mut Kmsg, r: u32) {
        use super::ipc::msg::mr;
        if matches!(r, mr::SEND_TIMED_OUT | mr::SEND_NO_BUFFER | mr::SEND_INTERRUPTED | mr::SEND_INVALID_DEST) {
            self.importance_clean(kmsg);
        }
    }

    /// `task_is_importance_donor` of the current task.
    pub(crate) fn imp_current_is_donor(&mut self) -> bool {
        let me = self.imp_current_task();
        let t = self.imp_base(me);
        self.imp_is_donor(t)
    }

    fn kmsg_dest_of(&self, id: u64) -> ObjId {
        self.vouchers.imp.kmsgs.get(&id).expect("a linked message").dest
    }

    /// The message's importance record, made the first time.
    fn kmsg_imp_id(&mut self, kmsg: &mut Kmsg) -> u64 {
        if let Some(id) = kmsg.imp {
            return id;
        }
        let imp = self.imp();
        imp.next_kmsg += 1;
        let id = imp.next_kmsg;
        imp.kmsgs.insert(id, KmsgImp { elem: None, raised: false, dest: kmsg.dest });
        kmsg.imp = Some(id);
        id
    }

    /// `MACH_MSGH_BITS_RAISED_IMPORTANCE`.
    pub(crate) fn kmsg_raised(&self, kmsg: &Kmsg) -> bool {
        kmsg.imp.is_some_and(|id| self.vouchers.imp.kmsgs.get(&id).is_some_and(|r| r.raised))
    }

    fn kmsg_set_raised(&mut self, kmsg: &mut Kmsg, raised: bool) {
        let id = self.kmsg_imp_id(kmsg);
        self.imp().kmsgs.get_mut(&id).expect("a message's importance").raised = raised;
    }

    /// `ipc_importance_kmsg_link`: the message holds the element's
    /// reference, on its task's list.
    fn kmsg_link(&mut self, kmsg: &mut Kmsg, elem: u64) {
        let id = self.kmsg_imp_id(kmsg);
        let rec = self.imp().kmsgs.get_mut(&id).expect("a message's importance");
        debug_assert!(rec.elem.is_none());
        rec.elem = Some(elem);
        let t = self.imp_link_task(elem);
        self.itask(t).kmsgs.push(id);
    }

    /// `ipc_importance_kmsg_unlink`.
    fn kmsg_unlink(&mut self, kmsg: &Kmsg) -> Option<u64> {
        let id = kmsg.imp?;
        let elem = self.imp().kmsgs.get_mut(&id)?.elem.take()?;
        let t = self.imp_link_task(elem);
        self.itask(t).kmsgs.retain(|&x| x != id);
        Some(elem)
    }

    /// The message's importance record goes; its raised bit is the
    /// header's again.
    pub(crate) fn kmsg_imp_finish(&mut self, kmsg: &mut Kmsg) {
        let Some(id) = kmsg.imp.take() else { return };
        let rec = self.imp().kmsgs.remove(&id).expect("a message's importance");
        assert!(rec.elem.is_none());
        if rec.raised {
            kmsg.bits |= super::ipc::msg::bits::RAISEIMP;
        } else {
            kmsg.bits &= !super::ipc::msg::bits::RAISEIMP;
        }
    }

    /// `ipc_importance_clean`: a message that is not delivered lets go of
    /// its link and of the boost it carried to its port.
    pub(crate) fn importance_clean(&mut self, kmsg: &mut Kmsg) {
        if kmsg.imp.is_none() {
            return;
        }
        if let Some(e) = self.kmsg_unlink(kmsg) {
            self.imp_release(e);
        }
        if self.kmsg_raised(kmsg) {
            self.kmsg_set_raised(kmsg, false);
            let port = kmsg.dest;
            if self.port(port).active {
                self.port_importance_delta(port, false, -1);
            }
        }
        self.kmsg_imp_finish(kmsg);
    }

    /// `ipc_importance_send`: a message to a port that takes donations
    /// from a task that can donate links to the sender's importance (or
    /// to the importance a receiver's voucher holds for it), and, while
    /// the sender donates (or with MACH_SEND_IMPORTANCE), carries a boost
    /// to the port and to the task at the end of its chain.
    pub(crate) fn importance_send(&mut self, kmsg: &mut Kmsg, options: u64, sender: TaskKey, voucher_imp: Option<u64>) {
        use super::ipc::msg::opt;
        let port = kmsg.dest;
        if !self.port(port).impdonation || options & opt::SEND_NOIMPORTANCE != 0 {
            return;
        }
        if options & opt::SEND_IMPORTANCE == 0 {
            let task_imp = self.imp_base(sender);
            if self.imp_is_never_donor(task_imp) {
                return;
            }
            let task_imp = task_imp.expect("a donor has its element");
            // An importance receiver passing on a voucher sends the
            // importance it holds for itself there.
            let mut elem = task_imp;
            if let Some(v) = voucher_imp {
                if self.imp_is_marked_receiver(Some(task_imp)) {
                    let mine = if self.imp_is_task(v) { v == task_imp } else { self.iinherit(v).to_task == task_imp };
                    if mine {
                        elem = v;
                    }
                }
            }
            self.imp_reference(elem);
            self.kmsg_link(kmsg, elem);
            if !self.imp_is_donor(Some(task_imp)) {
                return;
            }
        }
        // Donating through this message, now.
        self.kmsg_set_raised(kmsg, true);
        let (delta, task) = self.port_importance_delta_internal(port, false, 1);
        if let Some(t) = task {
            if delta != 0 {
                debug_assert_eq!(delta, 1);
                if self.imp_check_transition(t, true, 1) {
                    self.imp_propagate_assertion(t, true, true);
                }
            }
            self.imp_release(t);
        }
    }

    /// `ipc_importance_inherit_from_kmsg`: a receiver's inherit of the
    /// message's importance (a new one or one it has), to go in its
    /// voucher; the message's boost moves from its port to the inherit.
    pub(crate) fn importance_inherit_from_kmsg(&mut self, kmsg: &mut Kmsg) -> Option<u64> {
        let from0 = kmsg.imp.and_then(|id| self.vouchers.imp.kmsgs.get(&id).and_then(|r| r.elem));
        if from0.is_none() && !self.kmsg_raised(kmsg) {
            return None;
        }
        let me = self.task;
        let mut from = from0;
        let mut inherit = None;
        let mut created = false;
        let mut task_imp = None;
        let mut cleared_self_donation = false;
        let mut depth = 1;
        let mine = self.imp_base(me);
        'out: {
            if !self.imp_is_any_receiver_type(mine) {
                break 'out;
            }
            task_imp = self.imp_for_task(me, false);
            let Some(ti) = task_imp else { break 'out };
            if let Some(f) = from.filter(|&f| !self.imp_is_task(f)) {
                let fi = self.iinherit(f);
                if fi.to_task == ti {
                    // Already for this task: clear a self-donation the
                    // inherit does not carry.
                    if !fi.donating && self.kmsg_raised(kmsg) {
                        self.kmsg_set_raised(kmsg, false);
                        cleared_self_donation = true;
                    }
                    inherit = Some(f);
                } else if fi.depth & DEPTH_MASK == DEPTH_MAX {
                    // Too deep: start over from the inherit's task.
                    let to = fi.to_task;
                    self.imp_reference(to);
                    from = Some(to);
                    depth = DEPTH_RESET | 1;
                    let unlinked = self.kmsg_unlink(kmsg);
                    debug_assert_eq!(unlinked, Some(f));
                    self.kmsg_link(kmsg, to);
                    self.imp_release(f);
                } else {
                    depth = fi.depth + 1;
                }
            }
            if from == Some(ti) {
                break 'out;
            }
            if from.is_none() {
                debug_assert!(self.kmsg_raised(kmsg));
                self.imp_reference(ti);
                from = Some(ti);
            }
            let f = from.expect("a source");
            if inherit.is_none() {
                inherit = self.imp_inherit_find(f, ti, depth);
            }
            let donating = self.kmsg_raised(kmsg);
            match inherit {
                Some(i) => {
                    let x = self.iinherit(i);
                    let first_made = x.made == 0;
                    x.made += 1;
                    if first_made {
                        x.refs += 1;
                    }
                    let x = self.iinherit(i);
                    if extern_of(x.externcnt, x.externdrop) == 0 {
                        debug_assert!(!x.donating);
                        x.donating = donating;
                        let (cnt, drop) = (x.externcnt, x.externdrop);
                        if donating {
                            let t = self.itask(ti);
                            t.externcnt += cnt;
                            t.externdrop += drop;
                        }
                    } else {
                        debug_assert_eq!(donating, x.donating);
                    }
                    self.iinherit(i).externcnt += 1;
                }
                None => {
                    let h = self.imp().alloc();
                    self.imp().elems.insert(h, Elem::Inherit(ImpInherit { refs: 1, made: 1, externcnt: 1, externdrop: 0, donating, depth, to_task: ti, from_elem: None }));
                    // The source's and the task's references go to the new
                    // inherit.
                    self.imp_inherit_link(h, f);
                    inherit = Some(h);
                    created = true;
                }
            }
        }
        let donating = self.kmsg_raised(kmsg);
        // The message's link, if it had one, is the source's reference
        // (relinked to the task when the chain was too deep).
        let unlinked = self.kmsg_unlink(kmsg);
        debug_assert!(unlinked.is_none() || unlinked == from);
        if let (Some(_), true, Some(ti)) = (inherit, donating, task_imp) {
            self.itask(ti).externcnt += 1;
            self.imp_hold_internal_locked(ti, 1);
        }
        if !created {
            // The message's (or the self-donation's) reference on the
            // source, and the caller's on the task, go.
            if let Some(f) = from {
                self.imp_release(f);
            }
            if let Some(ti) = task_imp {
                self.imp_release(ti);
            }
        }
        if donating || cleared_self_donation {
            let port = kmsg.dest;
            self.port_importance_delta(port, false, -1);
        }
        // The message has an importance attribute, donating or not.
        self.kmsg_set_raised(kmsg, inherit.is_some());
        self.kmsg_imp_finish(kmsg);
        inherit
    }

    /// `ipc_importance_receive` without a voucher: a linked importance
    /// goes; a boost the message carried is held by the receiver as a
    /// legacy external assertion (it says so with MACH_MSGH_BITS_RAISEIMP)
    /// and leaves the port.
    pub(crate) fn importance_receive_legacy(&mut self, kmsg: &mut Kmsg) {
        if let Some(e) = self.kmsg_unlink(kmsg) {
            self.imp_release(e);
        }
        if self.kmsg_raised(kmsg) {
            let me = self.task;
            if let Some(t) = self.imp_base(me) {
                self.imp_hold_internal(t, 1);
                self.imp_externalize_legacy(t, 1);
            }
            let port = kmsg.dest;
            self.port_importance_delta(port, false, -1);
        }
        self.kmsg_imp_finish(kmsg);
    }

    // -- the voucher attribute manager --------------------------------------------------

    /// `ipc_importance_get_value`'s REDEEM: a made reference.
    pub(crate) fn imp_redeem(&mut self, h: u64) {
        let m = self.imp_made(h);
        debug_assert!(*m > 0);
        *m += 1;
    }

    /// `ipc_importance_release_value`: the voucher system's made
    /// references, if they are all there are; an inherit gives back what
    /// it donated.
    pub(crate) fn imp_release_value(&mut self, h: u64, sync: u32) -> u32 {
        debug_assert!(sync > 0);
        let m = self.imp_made(h);
        if sync != *m {
            debug_assert!(sync < *m);
            return kr::FAILURE;
        }
        *m = 0;
        if !self.imp_is_task(h) {
            let i = self.iinherit(h);
            debug_assert!(i.externcnt >= i.externdrop);
            if i.donating {
                let to = i.to_task;
                let assertcnt = extern_of(i.externcnt, i.externdrop);
                let (cnt, drop) = (i.externcnt, i.externdrop);
                i.externcnt = 0;
                i.externdrop = 0;
                i.donating = false;
                debug_assert!(self.imp_is_any_receiver_type(Some(to)));
                let t = self.itask(to);
                debug_assert!(t.externcnt >= cnt && t.externdrop >= drop);
                t.externcnt -= cnt;
                t.externdrop -= drop;
                if self.imp_check_transition(to, false, assertcnt) {
                    self.imp_propagate_assertion(to, false, true);
                }
            } else {
                i.externcnt = 0;
                i.externdrop = 0;
            }
        }
        self.imp_release(h);
        kr::SUCCESS
    }

    /// `ipc_importance_extract_content`'s text: "Importance for pid N",
    /// each inherit adding its boosts and where they are from.
    pub(crate) fn imp_content(&mut self, h: u64) -> String {
        let mut s = String::from("Importance for ");
        let mut e = h;
        loop {
            let (task, inherit) = if self.imp_is_task(e) { (e, None) } else { (self.iinherit(e).to_task, Some(e)) };
            s.push_str(&format!("pid {}", self.imp_task_pid(task)));
            let Some(i) = inherit else { break };
            let x = self.iinherit(i);
            let (ext, cnt, how, from) = (extern_of(x.externcnt, x.externdrop), x.externcnt, if x.donating { "donated" } else { "linked" }, x.from_elem.expect("an inherit's source"));
            s.push_str(&format!(" ({ext} of {cnt} boosts) {how} from "));
            e = from;
        }
        s
    }

    /// `ipc_importance_command`'s MACH_VOUCHER_IMPORTANCE_ATTR_DROP_EXTERNAL
    /// on the first inherit: `refs` of its external boosts dropped (none:
    /// how many it has), for a de-nap receiver only.
    pub(crate) fn imp_drop_external(&mut self, vals: &[u64], refs: u32) -> Result<u32, u32> {
        let Some(i) = vals.iter().copied().find(|&v| v != 0 && !self.imp_is_task(v)) else { return Err(kr::INVALID_ARGUMENT) };
        let x = self.iinherit(i);
        if refs == 0 {
            return Ok(extern_of(x.externcnt, x.externdrop));
        }
        let to = x.to_task;
        debug_assert!(self.imp_is_any_receiver_type(Some(to)));
        if !self.imp_is_marked_denap(Some(to)) {
            return Err(kr::INVALID_TASK);
        }
        unreachable!("a de-nap receiver's inherit: no task is one on iOS");
    }
}

// -- the state as bytes ([`super::ipc::wire`]) ------------------------------------------

use super::ipc::wire::{sorted, Bad, Get, OwnTask, Put};

fn put_marks(p: &mut Put, m: &Importance) {
    for b in [m.donor, m.live_donor, m.receiver, m.denap_receiver] {
        p.bool(b);
    }
    p.u64(m.transitions);
    p.bool(m.donor_propagated);
}

fn get_marks(g: &mut Get<'_>) -> Result<Importance, Bad> {
    Ok(Importance { donor: g.bool()?, live_donor: g.bool()?, receiver: g.bool()?, denap_receiver: g.bool()?, transitions: g.u64()?, donor_propagated: g.bool()? })
}

fn put_u64s(p: &mut Put, v: &[u64]) {
    p.len(v.len());
    for &x in v {
        p.u64(x);
    }
}

fn get_u64s(g: &mut Get<'_>) -> Result<Vec<u64>, Bad> {
    let n = g.len()?;
    (0..n).map(|_| g.u64()).collect()
}

impl ImpState {
    /// The elements and messages as bytes: a task element's policy as its
    /// importance marks (a cell's as they are now), whose task the
    /// element's owner names.
    pub fn put(&self, p: &mut Put) {
        p.len(self.elems.len());
        for (&h, e) in sorted(&self.elems) {
            p.u64(h);
            match e {
                Elem::Task(t) => {
                    p.u8(0);
                    for w in [t.refs, t.made, t.externcnt, t.externdrop] {
                        p.u32(w);
                    }
                    put_u64s(p, &t.kmsgs);
                    p.opt(t.task, |p, (k, pid)| {
                        p.u64(k);
                        p.i32(pid);
                    });
                    p.u64(t.owner);
                    put_marks(p, &t.policy.marks());
                    put_u64s(p, &t.inherits);
                    for w in [t.assertcnt, t.legacy_externcnt, t.legacy_externdrop, t.filelocks] {
                        p.u32(w);
                    }
                    p.bool(t.updatepolicy);
                    p.bool(t.queued);
                }
                Elem::Inherit(i) => {
                    p.u8(1);
                    for w in [i.refs, i.made, i.externcnt, i.externdrop] {
                        p.u32(w);
                    }
                    p.bool(i.donating);
                    p.u32(i.depth);
                    p.u64(i.to_task);
                    p.opt(i.from_elem, Put::u64);
                }
            }
        }
        p.len(self.by_task.len());
        for (&k, &h) in sorted(&self.by_task) {
            p.u64(k);
            p.u64(h);
        }
        let mut ended: Vec<TaskKey> = self.ended.iter().copied().collect();
        ended.sort_unstable();
        put_u64s(p, &ended);
        p.len(self.kmsgs.len());
        for (&k, m) in sorted(&self.kmsgs) {
            p.u64(k);
            p.opt(m.elem, Put::u64);
            p.bool(m.raised);
            p.u64(m.dest);
        }
        p.u64(self.next_kmsg);
        p.u64(self.next_handle);
        p.len(self.watchports.len());
        for (&k, v) in sorted(&self.watchports) {
            p.u64(k);
            put_u64s(p, v);
        }
    }

    /// The state [`ImpState::put`] made: the elements of `own`'s task have
    /// its policy's cell, every other task's the marks as a mirror.
    pub fn get(g: &mut Get<'_>, own: &OwnTask) -> Result<ImpState, Bad> {
        let n = g.len()?;
        let mut elems = HashMap::new();
        for _ in 0..n {
            let h = g.u64()?;
            let e = match g.u8()? {
                0 => {
                    let (refs, made, externcnt, externdrop) = (g.u32()?, g.u32()?, g.u32()?, g.u32()?);
                    let kmsgs = get_u64s(g)?;
                    let task = g.opt(|g| Ok((g.u64()?, g.i32()?)))?;
                    let owner = g.u64()?;
                    let marks = get_marks(g)?;
                    let policy = match &own.policy {
                        Some(c) if owner == own.task => PolicyAt::Cell(Arc::clone(c)),
                        _ => PolicyAt::Mirror(marks),
                    };
                    let inherits = get_u64s(g)?;
                    Elem::Task(ImpTask { refs, made, externcnt, externdrop, kmsgs, task, owner, policy, inherits, assertcnt: g.u32()?, legacy_externcnt: g.u32()?, legacy_externdrop: g.u32()?, filelocks: g.u32()?, updatepolicy: g.bool()?, queued: g.bool()? })
                }
                1 => Elem::Inherit(ImpInherit { refs: g.u32()?, made: g.u32()?, externcnt: g.u32()?, externdrop: g.u32()?, donating: g.bool()?, depth: g.u32()?, to_task: g.u64()?, from_elem: g.opt(Get::u64)? }),
                _ => return Err(g.bad("an importance element's kind")),
            };
            elems.insert(h, e);
        }
        let n = g.len()?;
        let by_task = (0..n).map(|_| Ok((g.u64()?, g.u64()?))).collect::<Result<_, Bad>>()?;
        let ended = get_u64s(g)?.into_iter().collect();
        let n = g.len()?;
        let kmsgs = (0..n).map(|_| Ok((g.u64()?, KmsgImp { elem: g.opt(Get::u64)?, raised: g.bool()?, dest: g.u64()? }))).collect::<Result<_, Bad>>()?;
        let (next_kmsg, next_handle) = (g.u64()?, g.u64()?);
        let n = g.len()?;
        let watchports = (0..n).map(|_| Ok((g.u64()?, get_u64s(g)?))).collect::<Result<_, Bad>>()?;
        Ok(ImpState { elems, by_task, ended, kmsgs, next_kmsg, next_handle, watchports })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::darwin::taskpolicy::{PolicyCell, TaskPolicy};

    fn state(policy: &Policy) -> ImpState {
        let mut s = ImpState::default();
        let task = ImpTask { refs: 2, made: 1, externcnt: 3, externdrop: 1, kmsgs: vec![7], task: Some((5, 105)), owner: 5, policy: PolicyAt::Cell(Arc::clone(policy)), inherits: vec![0x40], assertcnt: 4, legacy_externcnt: 1, legacy_externdrop: 0, filelocks: 2, updatepolicy: false, queued: true };
        s.elems.insert(0x4000_0040, Elem::Task(task));
        s.elems.insert(0x4000_0080, Elem::Inherit(ImpInherit { refs: 1, made: 0, externcnt: 1, externdrop: 0, donating: true, depth: 2, to_task: 0x4000_0040, from_elem: None }));
        s.by_task.insert(5, 0x4000_0040);
        s.ended.insert(3);
        s.kmsgs.insert(7, KmsgImp { elem: Some(0x4000_0080), raised: true, dest: 12 });
        s.next_kmsg = 8;
        s.next_handle = 0x4000_0080;
        s.watchports.insert(5, vec![12, 13]);
        s
    }

    fn bytes(s: &ImpState) -> Vec<u8> {
        let mut p = Put::default();
        s.put(&mut p);
        p.0
    }

    #[test]
    fn a_task_element_is_its_own_processs_cell_and_a_mirror_elsewhere() {
        let mut tp = TaskPolicy::default();
        tp.imp.mark_receiver(true);
        tp.imp.mark_donor(true);
        let policy: Policy = Arc::new(PolicyCell::new(tp));
        let s = state(&policy);
        let b = bytes(&s);
        // Its own process: the cell itself.
        let own = OwnTask { task: 5, policy: Some(Arc::clone(&policy)), ledger: None };
        let mut g = Get::new(&b);
        let mine = ImpState::get(&mut g, &own).expect("it decodes");
        assert!(g.done());
        let Some(Elem::Task(t)) = mine.elems.get(&0x4000_0040) else { panic!("the task element") };
        assert!(matches!(&t.policy, PolicyAt::Cell(c) if Arc::ptr_eq(c, &policy)));
        assert_eq!(bytes(&mine), b);
        // Another: the marks, as they were.
        let other = OwnTask { task: 6, policy: Some(Arc::new(PolicyCell::default())), ledger: None };
        let theirs = ImpState::get(&mut Get::new(&b), &other).expect("it decodes");
        let Some(Elem::Task(t)) = theirs.elems.get(&0x4000_0040) else { panic!("the task element") };
        assert!(matches!(t.policy, PolicyAt::Mirror(m) if m == policy.lock().unwrap().imp));
        assert_eq!(bytes(&theirs), b);
        assert!(ImpState::get(&mut Get::new(&b[..b.len() - 1]), &other).is_err());
    }

    #[test]
    fn a_change_is_the_same_on_a_mirror_as_on_the_cell() {
        for op in [PolicyOp::Boost(true), PolicyOp::Boost(false), PolicyOp::DonorPropagated(false), PolicyOp::ResetDonor] {
            let mut tp = TaskPolicy::default();
            tp.imp.mark_donor(true);
            let mut mirror = tp.imp;
            op.apply(&mut tp);
            op.apply_marks(&mut mirror);
            assert_eq!(mirror, tp.imp, "{op:?}");
        }
        let mut tp = TaskPolicy::default();
        PolicyOp::Boost(true).apply(&mut tp);
        assert!(tp.requested.boosted);
    }
}
