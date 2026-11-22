//! Coalitions (`osfmk/kern/coalition.c`, `bsd/kern/sys_coalition.c`,
//! xnu-10063.141.1): the groups launchd puts its jobs' tasks in. Every task
//! is in one coalition of each type, a resource coalition and a jetsam
//! coalition, its parent's unless a spawn names others; a jetsam coalition
//! has a leader, XPC services, extensions and other members, and a thread
//! group its tasks run in. A coalition launchd asked to terminate is
//! terminated when its last task leaves, and launchd hears of it through
//! the host's coalition port; then it may be reaped.
//!
//! The table is the kernel's (`coalition_hash`), here this host process's
//! (the global kernel's in the page, [`share`]: each function here is one
//! call on it there), kept in the hash's order so lists come out as the
//! kernel gives them.
//! A task's membership is kept by its process. What a resource coalition
//! counts of its tasks' use (CPU, energy, I/O, wakeups) needs the tasks'
//! ledgers, which are not kept: that flavor and the I/O limit report so.

use super::bsd::sys;
use super::share::{self, Remote};
use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::GuestMem;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};

/// `COALITION_TYPE_*`.
pub mod ty {
    pub const RESOURCE: u32 = 0;
    pub const JETSAM: u32 = 1;
    pub const NUM: usize = 2;
}

/// `COALITION_ROLE_*`.
pub mod role {
    pub const SYSTEM: u32 = 1;
    pub const BACKGROUND: u32 = 2;
}

/// `COALITION_TASKROLE_*`.
pub mod taskrole {
    pub const NONE: i32 = -1;
    pub const UNDEF: i32 = 0;
    pub const LEADER: i32 = 1;
    pub const XPC: i32 = 2;
    pub const EXT: i32 = 3;
}

/// `THREAD_GROUP_SYSTEM`, `THREAD_GROUP_BACKGROUND`; dynamic groups are
/// numbered after the kernel's own (system, background, the retired
/// adaptive group, VM, I/O storage, the performance controller).
pub const THREAD_GROUP_SYSTEM: u64 = 0;
const THREAD_GROUP_BACKGROUND: u64 = 1;
const THREAD_GROUP_FIRST_DYNAMIC: u64 = 6;

/// `COALITION_CREATE_FLAGS_*`.
mod create {
    pub const MASK: u32 = 0xff3;
    pub const PRIVILEGED: u32 = 0x01;
    pub const EFFICIENT: u32 = 0x02;
}

/// `COALITION_OP_*`, `COALITION_INFO_*`, `COALITION_LEDGER_*`.
mod op {
    pub const CREATE: u32 = 1;
    pub const TERMINATE: u32 = 2;
    pub const REAP: u32 = 3;
    pub const INFO_RESOURCE_USAGE: u32 = 1;
    pub const INFO_SET_NAME: u32 = 2;
    pub const INFO_SET_EFFICIENCY: u32 = 3;
    pub const LEDGER_SET_LOGICAL_WRITES_LIMIT: u32 = 1;
}

/// `kern_return_t`s.
mod kr {
    pub const INVALID_ARGUMENT: u32 = 4;
    pub const ALREADY_IN_SET: u32 = 11;
    pub const TERMINATED: u32 = 37;
}

/// `COALITION_FLAGS_EFFICIENT`, `COALITION_EFFICIENCY_VALID_FLAGS`.
const FLAGS_EFFICIENT: u64 = 0x1;
/// `COALITION_MAX_LOGICAL_WRITES_LIMIT` (MB).
const MAX_LOGICAL_WRITES_LIMIT: i64 = i64::MAX >> 20;
/// `THREAD_GROUP_MAXNAME`.
const THREAD_GROUP_MAXNAME: usize = 32;
/// `HOST_COALITION_PORT`.
pub const HOST_COALITION_PORT: i32 = 22;
/// `coalition_notification`'s message id.
const COALITION_NOTIFICATION: i32 = 5300;
/// `COALITION_HASH_SIZE_MIN`.
const HASH_SIZE_MIN: usize = 16;

/// `struct coalition`, with its type's part.
#[derive(Debug)]
struct Coalition {
    id: u64,
    ty: u32,
    /// Its members, plus the spawns about to make tasks in it.
    active: u32,
    privileged: bool,
    termrequested: bool,
    terminated: bool,
    reaped: bool,
    notified: bool,
    // COALITION_TYPE_RESOURCE.
    task_count: u64,
    dead_task_count: u64,
    last_became_nonempty_time: u64,
    time_nonempty: u64,
    tasks: Vec<i32>,
    // COALITION_TYPE_JETSAM.
    leader: Option<i32>,
    services: Vec<i32>,
    extensions: Vec<i32>,
    other: Vec<i32>,
    thread_group: u64,
    tg_name: [u8; THREAD_GROUP_MAXNAME],
}

/// The kernel's coalitions and each process's task's.
#[derive(Debug)]
struct Table {
    coals: HashMap<u64, Coalition>,
    /// `coalition_hash`'s buckets, each chain from its head.
    buckets: Vec<Vec<u64>>,
    count: usize,
    next_id: u64,
    next_tg: u64,
    /// `task->coalition[]`, by process.
    members: HashMap<i32, [Option<u64>; ty::NUM]>,
    /// The processes whose tasks have ended.
    ended: std::collections::HashSet<i32>,
    init: [u64; ty::NUM],
    /// `corpse_coalition[]`: each type's corpse coalition.
    corpse: [u64; ty::NUM],
}

/// `smrh_key_hash_u64` with no seed.
fn hash(id: u64) -> u64 {
    let mut x = id;
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    u64::from(x as u32)
}

fn table() -> MutexGuard<'static, Table> {
    static T: OnceLock<Mutex<Table>> = OnceLock::new();
    T.get_or_init(|| {
        let mut t = Table { coals: HashMap::new(), buckets: vec![Vec::new(); HASH_SIZE_MIN], count: 0, next_id: 1, next_tg: THREAD_GROUP_FIRST_DYNAMIC, members: HashMap::new(), ended: Default::default(), init: [0; ty::NUM], corpse: [0; ty::NUM] };
        // coalitions_init: each type's default coalition, privileged, then
        // its corpse coalition.
        for k in 0..ty::NUM as u32 {
            t.init[k as usize] = t.create(k, role::SYSTEM, true, false);
            t.corpse[k as usize] = t.create(k, role::SYSTEM, false, false);
        }
        Mutex::new(t)
    })
    .lock()
    .unwrap_or_else(|e| e.into_inner())
}

/// A task's coalition id of each type and its role in each.
pub type Membership = ([u64; ty::NUM], [i32; ty::NUM]);

impl Table {
    fn bucket(&self, id: u64) -> usize {
        (hash(id) & (self.buckets.len() as u64 - 1)) as usize
    }

    /// `coalition_create_internal`.
    /// An efficient coalition's thread group is made efficient
    /// (`THREAD_GROUP_FLAGS_EFFICIENT`), which only the performance
    /// controller reads.
    fn create(&mut self, ty: u32, role: u32, privileged: bool, efficient: bool) -> u64 {
        let _ = efficient;
        let id = self.next_id;
        self.next_id += 1;
        // i_coal_jetsam_init: the system and background roles' groups are
        // the kernel's; any other gets one of its own.
        let thread_group = match role {
            role::SYSTEM => THREAD_GROUP_SYSTEM,
            role::BACKGROUND => THREAD_GROUP_BACKGROUND,
            _ if ty == ty::JETSAM => {
                self.next_tg += 1;
                self.next_tg - 1
            }
            _ => THREAD_GROUP_SYSTEM,
        };
        self.coals.insert(id, Coalition { id, ty, active: 0, privileged, termrequested: false, terminated: false, reaped: false, notified: false, task_count: 0, dead_task_count: 0, last_became_nonempty_time: 0, time_nonempty: 0, tasks: Vec::new(), leader: None, services: Vec::new(), extensions: Vec::new(), other: Vec::new(), thread_group, tg_name: [0; THREAD_GROUP_MAXNAME] });
        // smr_hash_serialized_insert: at the head of its chain; the table
        // doubles past four a bucket, each chain split in order.
        let b = self.bucket(id);
        self.buckets[b].insert(0, id);
        self.count += 1;
        let size = self.buckets.len();
        if size * 4 < self.count {
            let old = std::mem::take(&mut self.buckets);
            self.buckets = vec![Vec::new(); size * 2];
            for (i, chain) in old.into_iter().enumerate() {
                for c in chain {
                    let to = if hash(c) & size as u64 == 0 { i } else { i + size };
                    self.buckets[to].push(c);
                }
            }
        }
        id
    }

    /// The coalition `cid` while it is in the table (`coalition_find_by_id`).
    fn find(&mut self, cid: u64) -> Option<&mut Coalition> {
        if cid == 0 {
            return None;
        }
        self.coals.get_mut(&cid).filter(|c| !c.reaped)
    }

    /// `coalition_find_and_activate_by_id`: one not terminated, activated.
    fn find_and_activate(&mut self, cid: u64) -> Option<u64> {
        let c = self.find(cid)?;
        if c.terminated {
            return None;
        }
        c.active += 1;
        Some(cid)
    }

    /// `coalition_remove_active`: the coalition launchd asked to terminate
    /// is terminated when nothing is left in it; its id is to be told.
    fn remove_active(&mut self, cid: u64) -> Option<u64> {
        let c = self.coals.get_mut(&cid).expect("a coalition");
        debug_assert!(!c.reaped && c.active > 0);
        c.active -= 1;
        if c.termrequested && c.active == 0 {
            debug_assert!(!c.terminated && !c.notified);
            c.terminated = true;
            c.notified = true;
            return Some(c.id);
        }
        None
    }

    /// `coalition_adopt_task_internal`: a member at the end of its list (a
    /// jetsam coalition's others).
    fn adopt(&mut self, pid: i32, cid: u64) -> Result<(), u32> {
        let c = self.coals.get_mut(&cid).expect("a coalition");
        let k = c.ty as usize;
        if self.members.get(&pid).is_some_and(|m| m[k].is_some()) {
            return Err(kr::ALREADY_IN_SET);
        }
        let c = self.coals.get_mut(&cid).expect("a coalition");
        if c.reaped || c.terminated {
            return Err(kr::TERMINATED);
        }
        if c.ty == ty::RESOURCE {
            c.task_count += 1;
            if c.task_count - c.dead_task_count == 1 {
                c.last_became_nonempty_time = now();
            }
            c.tasks.push(pid);
        } else {
            c.other.push(pid);
        }
        c.active += 1;
        self.members.entry(pid).or_insert([None; ty::NUM])[k] = Some(cid);
        Ok(())
    }

    /// `coalitions_adopt_task`: a resource coalition at least; undone if
    /// one of them refuses.
    fn adopt_all(&mut self, pid: i32, coals: [Option<u64>; ty::NUM]) -> Result<(), u32> {
        if coals[ty::RESOURCE as usize].is_none() {
            return Err(kr::INVALID_ARGUMENT);
        }
        for (i, c) in coals.iter().enumerate() {
            if let Some(c) = c {
                if self.coals[c].ty as usize != i {
                    return Err(kr::INVALID_ARGUMENT);
                }
            }
        }
        for (i, c) in coals.iter().enumerate() {
            let Some(c) = *c else { continue };
            if let Err(e) = self.adopt(pid, c) {
                for j in (0..i).rev() {
                    let _ = self.remove(pid, j);
                }
                return Err(e);
            }
        }
        Ok(())
    }

    /// `i_coal_*_remove_task` and `coalition_remove_task_internal`: the
    /// task leaves (a resource coalition counts it dead and how long it
    /// was not empty); the id to be told if that terminated it.
    fn remove(&mut self, pid: i32, k: usize) -> Option<u64> {
        let cid = self.members.get_mut(&pid)?[k].take()?;
        let c = self.coals.get_mut(&cid).expect("a coalition");
        if c.ty == ty::RESOURCE {
            c.dead_task_count += 1;
            if c.task_count - c.dead_task_count == 0 {
                c.time_nonempty += now() - c.last_became_nonempty_time;
                c.last_became_nonempty_time = 0;
            }
            c.tasks.retain(|&p| p != pid);
        } else {
            if c.leader == Some(pid) {
                c.leader = None;
            }
            for q in [&mut c.services, &mut c.extensions, &mut c.other] {
                q.retain(|&p| p != pid);
            }
        }
        self.remove_active(cid)
    }

    /// `i_coal_jetsam_set_taskrole`.
    fn set_role(&mut self, pid: i32, cid: u64, role: i32) {
        let c = self.coals.get_mut(&cid).expect("a coalition");
        if c.ty != ty::JETSAM {
            return;
        }
        for q in [&mut c.services, &mut c.extensions, &mut c.other] {
            q.retain(|&p| p != pid);
        }
        match role {
            taskrole::LEADER => {
                // A leader there was goes back among the others.
                if let Some(old) = c.leader.replace(pid) {
                    if old != pid {
                        c.other.push(old);
                    }
                }
            }
            taskrole::XPC => c.services.push(pid),
            taskrole::EXT => c.extensions.push(pid),
            taskrole::NONE | taskrole::UNDEF => {
                if c.leader == Some(pid) {
                    c.leader = None;
                }
                c.other.push(pid);
            }
            _ => panic!("i_coal_jetsam_set_taskrole: invalid role({role}) for task"),
        }
    }

    /// `i_coal_jetsam_get_taskrole`: a resource coalition's members are of
    /// no role.
    fn role_of(&self, pid: i32, cid: u64) -> i32 {
        let c = &self.coals[&cid];
        if c.ty == ty::RESOURCE {
            return if c.tasks.contains(&pid) { taskrole::UNDEF } else { -1 };
        }
        if c.leader == Some(pid) {
            taskrole::LEADER
        } else if c.services.contains(&pid) {
            taskrole::XPC
        } else if c.extensions.contains(&pid) {
            taskrole::EXT
        } else if c.other.contains(&pid) {
            taskrole::UNDEF
        } else {
            taskrole::NONE
        }
    }

    /// `coalition_get_task_count`.
    fn task_count(&self, c: &Coalition) -> u32 {
        if c.ty == ty::RESOURCE {
            c.tasks.len() as u32
        } else {
            u32::from(c.leader.is_some()) + c.other.len() as u32 + c.extensions.len() as u32 + c.services.len() as u32
        }
    }
}

/// A forked process's task: its parent's coalitions (`task_create_internal`),
/// as a member of no particular role; a parent in none (the first task)
/// puts it in the default ones.
pub fn fork(parent: i32, child: i32) {
    match share::remote() {
        Some(r) => fork_through(r, parent, child),
        None => fork_here(parent, child),
    }
}

fn fork_here(parent: i32, child: i32) {
    let mut t = table();
    let coals = match t.members.get(&parent) {
        Some(m) if m[ty::RESOURCE as usize].is_some() => *m,
        _ => t.init.map(Some),
    };
    t.adopt_all(child, coals).expect("a fork's task adopts its parent's coalitions");
}

/// A corpse fork's task (`coalitions_adopt_corpse_task`): each type's
/// corpse coalition, in place of its parent's. It has no process, so its
/// membership is kept under `key`, a key no process has
/// ([`corpse_member_key`]).
pub fn adopt_corpse(key: i32) {
    match share::remote() {
        Some(r) => adopt_corpse_through(r, key),
        None => adopt_corpse_here(key),
    }
}

fn adopt_corpse_here(key: i32) {
    let mut t = table();
    let coals = t.corpse.map(Some);
    t.adopt_all(key, coals).expect("a corpse fork's task adopts the corpse coalitions");
}

/// The key a corpse fork's task's membership is kept under: from its task
/// key, below every pid.
pub fn corpse_member_key(task: u64) -> i32 {
    -1 - (task as i32 & i32::MAX)
}

/// An exec's new task takes over its old one's coalitions and roles, the
/// old task leaving them: a resource coalition counts a task started and
/// one ended.
pub fn exec(pid: i32) {
    match share::remote() {
        Some(r) => exec_through(r, pid),
        None => exec_here(pid),
    }
}

fn exec_here(pid: i32) {
    let mut t = table();
    let Some(m) = t.members.get(&pid).copied() else { return };
    if let Some(cid) = m[ty::RESOURCE as usize] {
        let c = t.coals.get_mut(&cid).expect("a coalition");
        c.task_count += 1;
        c.dead_task_count += 1;
    }
}

/// The process's coalitions and roles in them (`task_coalition_ids`,
/// `task_coalition_roles`); a process in none is in the default ones.
pub fn membership(pid: i32) -> Membership {
    match share::remote() {
        Some(r) => membership_through(r, pid),
        None => membership_here(pid),
    }
}

fn membership_here(pid: i32) -> Membership {
    let mut t = table();
    let m = match t.members.get(&pid) {
        Some(m) => *m,
        None if t.ended.contains(&pid) => [None; ty::NUM],
        None => {
            let init = t.init.map(Some);
            let _ = t.adopt_all(pid, init);
            init
        }
    };
    let mut ids = [0; ty::NUM];
    let mut roles = [taskrole::NONE; ty::NUM];
    for k in 0..ty::NUM {
        if let Some(c) = m[k] {
            ids[k] = c;
            roles[k] = t.role_of(pid, c);
        }
    }
    (ids, roles)
}

/// `task_coalition_get_thread_group`: the thread group of the process's
/// jetsam coalition.
pub fn thread_group(pid: i32) -> u64 {
    match share::remote() {
        Some(r) => thread_group_through(r, pid),
        None => thread_group_here(pid),
    }
}

fn thread_group_here(pid: i32) -> u64 {
    let (ids, _) = membership_here(pid);
    table().coals.get(&ids[ty::JETSAM as usize]).map_or(THREAD_GROUP_SYSTEM, |c| c.thread_group)
}

/// `task_is_in_privileged_coalition`.
pub fn privileged(pid: i32, k: u32) -> bool {
    match share::remote() {
        Some(r) => privileged_through(r, pid, k),
        None => privileged_here(pid, k),
    }
}

fn privileged_here(pid: i32, k: u32) -> bool {
    if k as usize >= ty::NUM {
        return false;
    }
    let (ids, _) = membership_here(pid);
    table().coals.get(&ids[k as usize]).is_some_and(|c| c.privileged)
}

/// The jetsam coalition's leader (`coalition_get_leader`), and whether
/// `pid` is it.
pub fn leader(pid: i32) -> (Option<i32>, bool) {
    match share::remote() {
        Some(r) => leader_through(r, pid),
        None => leader_here(pid),
    }
}

fn leader_here(pid: i32) -> (Option<i32>, bool) {
    let (ids, _) = membership_here(pid);
    let l = table().coals.get(&ids[ty::JETSAM as usize]).and_then(|c| c.leader);
    (l, l == Some(pid))
}

/// The process's task ends (`coalitions_remove_task`): the coalitions it
/// leaves, and those that terminated with it.
pub fn task_terminated(pid: i32) -> Vec<u64> {
    match share::remote() {
        Some(r) => task_terminated_through(r, pid),
        None => task_terminated_here(pid),
    }
}

fn task_terminated_here(pid: i32) -> Vec<u64> {
    let mut t = table();
    let mut told = Vec::new();
    for k in 0..ty::NUM {
        if let Some(id) = t.remove(pid, k) {
            told.push(id);
        }
    }
    t.members.remove(&pid);
    t.ended.insert(pid);
    told
}

/// A spawn's coalitions, activated against their end while the spawn makes
/// its task (`coalition_find_and_activate_by_id` for each id given).
pub struct Spawn {
    coals: [Option<u64>; ty::NUM],
    roles: [i32; ty::NUM],
}

impl Spawn {
    /// The coalitions a spawn's `_posix_spawn_coalition_info` names (ESRCH
    /// for one that is not there or not of its type; EINVAL without a
    /// resource coalition among some), given the spawner may (EPERM).
    pub fn activate(info: &[u8], may: impl Fn(u32) -> bool) -> Result<Spawn, Errno> {
        let mut s = Spawn { coals: [None; ty::NUM], roles: [taskrole::UNDEF; ty::NUM] };
        let mut n = 0;
        for k in 0..ty::NUM {
            let id = u64::from_le_bytes(info[24 * k..24 * k + 8].try_into().unwrap());
            if id == 0 {
                continue;
            }
            if !may(k as u32) {
                s.release_all();
                return Err(Errno::EPERM);
            }
            let Some(cty) = activate(id) else {
                s.release_all();
                return Err(Errno::ESRCH);
            };
            let typed = cty as usize == k;
            s.coals[k] = Some(id);
            if !typed {
                s.release_all();
                return Err(Errno::ESRCH);
            }
            s.roles[k] = i32::from_le_bytes(info[24 * k + 8..24 * k + 12].try_into().unwrap());
            n += 1;
        }
        if n < ty::NUM && s.coals[ty::RESOURCE as usize].is_none() {
            s.release_all();
            return Err(Errno::EINVAL);
        }
        Ok(s)
    }

    /// `spawn_coalitions_release_all`: the activations let go; the ids of
    /// coalitions that terminated with that.
    pub fn release_all(&mut self) -> Vec<u64> {
        let ids: Vec<u64> = self.coals.iter_mut().filter_map(Option::take).collect();
        release(&ids)
    }

    /// The new task, `child`, is put in these coalitions (fork1 with them)
    /// with its roles in each (`coalitions_set_roles`), or in its parent's
    /// if none were named.
    pub fn place(&self, parent: i32, child: i32) {
        if self.coals[ty::RESOURCE as usize].is_none() {
            fork(parent, child);
            return;
        }
        place(child, self.coals, self.roles);
    }
}

/// `coalition_find_and_activate_by_id`: the type of coalition `cid`,
/// activated, if it is there and not terminated.
fn activate(cid: u64) -> Option<u32> {
    match share::remote() {
        Some(r) => {
            let mut o = [0u8; 5];
            co_call(r, share::op::CO_ACTIVATE, &cid.to_le_bytes(), &mut o);
            (o[0] != 0).then(|| u32::from_le_bytes(o[1..5].try_into().unwrap()))
        }
        None => activate_here(cid),
    }
}

fn activate_here(cid: u64) -> Option<u32> {
    let mut t = table();
    let c = t.find_and_activate(cid)?;
    Some(t.coals[&c].ty)
}

/// `spawn_coalitions_release_all`'s releases of activated coalitions
/// `ids`, in their order: the ids of those that terminated with that.
fn release(ids: &[u64]) -> Vec<u64> {
    match share::remote() {
        Some(r) => {
            let req: Vec<u8> = ids.iter().flat_map(|i| i.to_le_bytes()).collect();
            let mut o = [0u8; 8 * ty::NUM];
            let n = co_call_upto(r, share::op::CO_RELEASE, &req, &mut o);
            ids_of(&o[..n])
        }
        None => release_here(ids),
    }
}

fn release_here(ids: &[u64]) -> Vec<u64> {
    let mut t = table();
    let mut told = Vec::new();
    for &id in ids {
        if let Some(n) = t.remove_active(id) {
            told.push(n);
        }
    }
    told
}

/// A spawn's task `child` put in coalitions `coals` with roles `roles`.
fn place(child: i32, coals: [Option<u64>; ty::NUM], roles: [i32; ty::NUM]) {
    match share::remote() {
        Some(r) => {
            let mut req = child.to_le_bytes().to_vec();
            for k in 0..ty::NUM {
                req.push(u8::from(coals[k].is_some()));
                req.extend_from_slice(&coals[k].unwrap_or(0).to_le_bytes());
                req.extend_from_slice(&roles[k].to_le_bytes());
            }
            co_call(r, share::op::CO_PLACE, &req, &mut []);
        }
        None => place_here(child, coals, roles),
    }
}

fn place_here(child: i32, coals: [Option<u64>; ty::NUM], roles: [i32; ty::NUM]) {
    let mut t = table();
    t.adopt_all(child, coals).expect("a spawn's task adopts the coalitions it was given");
    for k in 0..ty::NUM {
        if let Some(c) = coals[k] {
            t.set_role(child, c, roles[k]);
        }
    }
}

/// `coalition_create_internal` for `coalition(COALITION_OP_CREATE)`: the
/// new coalition's id.
fn create(k: u32, role: u32, privileged: bool, efficient: bool) -> u64 {
    match share::remote() {
        Some(r) => {
            let mut req = k.to_le_bytes().to_vec();
            req.extend_from_slice(&role.to_le_bytes());
            req.extend_from_slice(&[u8::from(privileged), u8::from(efficient)]);
            let mut o = [0u8; 8];
            co_call(r, share::op::CO_CREATE, &req, &mut o);
            u64::from_le_bytes(o)
        }
        None => table().create(k, role, privileged, efficient),
    }
}

/// `coalition_request_terminate_internal` (`reap` false) or
/// `coalition_reap_internal` of coalition `cid`: for a terminate, whether
/// it terminated now (launchd is then told).
fn terminate_or_reap(cid: u64, reap: bool) -> Result<bool, Errno> {
    match share::remote() {
        Some(r) => {
            let mut req = cid.to_le_bytes().to_vec();
            req.push(u8::from(reap));
            let mut o = [0u8; 5];
            co_call(r, share::op::CO_TERMINATE, &req, &mut o);
            match o[0] {
                0 => Ok(o[1] != 0),
                _ => Err(Errno(i32::from_le_bytes(o[1..5].try_into().unwrap()))),
            }
        }
        None => terminate_or_reap_here(cid, reap),
    }
}

fn terminate_or_reap_here(cid: u64, reap: bool) -> Result<bool, Errno> {
    let mut t = table();
    let init = t.init;
    let Some(c) = t.find(cid) else { return Err(Errno::ESRCH) };
    if !reap {
        // coalition_request_terminate_internal.
        if init.contains(&cid) {
            return Err(Errno::EPERM);
        }
        if c.terminated || c.termrequested {
            return Err(Errno::EALREADY);
        }
        c.termrequested = true;
        if c.active == 0 {
            c.terminated = true;
            c.notified = true;
            return Ok(true);
        }
        return Ok(false);
    }
    // coalition_reap_internal.
    if init.contains(&cid) {
        return Err(Errno::EPERM);
    }
    if !c.terminated || c.active > 0 {
        return Err(Errno::EBUSY);
    }
    c.reaped = true;
    let b = t.bucket(cid);
    t.buckets[b].retain(|&x| x != cid);
    t.count -= 1;
    // smr_hash_serialized_should_shrink(min 16, 2, 1): each
    // chain collapsed with its pair's after it.
    let size = t.buckets.len();
    if size > HASH_SIZE_MIN && size > t.count * 2 {
        let half = size / 2;
        let mut old = std::mem::take(&mut t.buckets);
        let upper = old.split_off(half);
        for (i, tail) in upper.into_iter().enumerate() {
            old[i].extend(tail);
        }
        t.buckets = old;
    }
    t.coals.remove(&cid);
    Ok(false)
}

/// The type of coalition `cid` (`coalition_find_by_id`), if it is there.
fn kind(cid: u64) -> Option<u32> {
    match share::remote() {
        Some(r) => {
            let mut o = [0u8; 5];
            co_call(r, share::op::CO_KIND, &cid.to_le_bytes(), &mut o);
            (o[0] != 0).then(|| u32::from_le_bytes(o[1..5].try_into().unwrap()))
        }
        None => kind_here(cid),
    }
}

fn kind_here(cid: u64) -> Option<u32> {
    table().find(cid).map(|c| c.ty)
}

/// `thread_group_set_name` of coalition `cid`'s thread group, if the
/// coalition is still there.
fn set_name(cid: u64, name: &[u8]) {
    match share::remote() {
        Some(r) => {
            let mut req = cid.to_le_bytes().to_vec();
            req.extend_from_slice(name);
            co_call(r, share::op::CO_SET_NAME, &req, &mut []);
        }
        None => set_name_here(cid, name),
    }
}

fn set_name_here(cid: u64, name: &[u8]) {
    let mut t = table();
    if let Some(c) = t.find(cid) {
        c.tg_name = [0; THREAD_GROUP_MAXNAME];
        c.tg_name[..name.len()].copy_from_slice(name);
    }
}

fn ids_of(b: &[u8]) -> Vec<u64> {
    b.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect()
}

fn pid_at(b: &[u8], at: usize) -> Option<i32> {
    Some(i32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn fork_through(r: Remote, parent: i32, child: i32) {
    let mut req = parent.to_le_bytes().to_vec();
    req.extend_from_slice(&child.to_le_bytes());
    co_call(r, share::op::CO_FORK, &req, &mut []);
}

fn adopt_corpse_through(r: Remote, key: i32) {
    co_call(r, share::op::CO_ADOPT_CORPSE, &key.to_le_bytes(), &mut []);
}

fn exec_through(r: Remote, pid: i32) {
    co_call(r, share::op::CO_EXEC, &pid.to_le_bytes(), &mut []);
}

fn membership_bytes(m: Membership) -> [u8; 24] {
    let mut b = [0u8; 24];
    for k in 0..ty::NUM {
        b[8 * k..8 * k + 8].copy_from_slice(&m.0[k].to_le_bytes());
        b[16 + 4 * k..20 + 4 * k].copy_from_slice(&m.1[k].to_le_bytes());
    }
    b
}

fn membership_through(r: Remote, pid: i32) -> Membership {
    let mut o = [0u8; 24];
    co_call(r, share::op::CO_MEMBERSHIP, &pid.to_le_bytes(), &mut o);
    let mut m: Membership = ([0; ty::NUM], [0; ty::NUM]);
    for k in 0..ty::NUM {
        m.0[k] = u64::from_le_bytes(o[8 * k..8 * k + 8].try_into().unwrap());
        m.1[k] = i32::from_le_bytes(o[16 + 4 * k..20 + 4 * k].try_into().unwrap());
    }
    m
}

fn thread_group_through(r: Remote, pid: i32) -> u64 {
    let mut o = [0u8; 8];
    co_call(r, share::op::CO_THREAD_GROUP, &pid.to_le_bytes(), &mut o);
    u64::from_le_bytes(o)
}

fn privileged_through(r: Remote, pid: i32, k: u32) -> bool {
    let mut req = pid.to_le_bytes().to_vec();
    req.extend_from_slice(&k.to_le_bytes());
    let mut o = [0u8; 1];
    co_call(r, share::op::CO_PRIVILEGED, &req, &mut o);
    o[0] != 0
}

fn leader_bytes(l: (Option<i32>, bool)) -> [u8; 6] {
    let mut b = [0u8; 6];
    b[0] = u8::from(l.0.is_some());
    b[1..5].copy_from_slice(&l.0.unwrap_or(0).to_le_bytes());
    b[5] = u8::from(l.1);
    b
}

fn leader_through(r: Remote, pid: i32) -> (Option<i32>, bool) {
    let mut o = [0u8; 6];
    co_call(r, share::op::CO_LEADER, &pid.to_le_bytes(), &mut o);
    ((o[0] != 0).then(|| i32::from_le_bytes(o[1..5].try_into().unwrap())), o[5] != 0)
}

fn task_terminated_through(r: Remote, pid: i32) -> Vec<u64> {
    let mut o = [0u8; 8 * ty::NUM];
    let n = co_call_upto(r, share::op::CO_TASK_TERMINATED, &pid.to_le_bytes(), &mut o);
    ids_of(&o[..n])
}

fn list_bytes(l: &[(u64, u32, u32)]) -> Vec<u8> {
    let mut b = Vec::with_capacity(16 * l.len());
    for &(id, t, n) in l {
        b.extend_from_slice(&id.to_le_bytes());
        b.extend_from_slice(&t.to_le_bytes());
        b.extend_from_slice(&n.to_le_bytes());
    }
    b
}

fn list_through(r: Remote, k: i32) -> Vec<(u64, u32, u32)> {
    let b = co_call_read(r, share::op::CO_LIST, &k.to_le_bytes());
    b.chunks_exact(16).map(|c| (u64::from_le_bytes(c[..8].try_into().unwrap()), u32::from_le_bytes(c[8..12].try_into().unwrap()), u32::from_le_bytes(c[12..16].try_into().unwrap()))).collect()
}

std::thread_local! {
    /// The counter's reading of the call the global kernel serves, which
    /// stands in for its own (it reads no clock): the time of the caller's
    /// call, as the table's times are natively read in the call.
    static CALLER_NOW: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// `mach_absolute_time` for the table's times: the calling process's
/// reading where the global kernel serves the call.
fn now() -> u64 {
    CALLER_NOW.with(|c| c.get()).unwrap_or_else(super::mach::absolute_time)
}

/// A call on the global kernel's table: the request after this process's
/// counter reading ([`now`]).
fn with_now(req: &[u8]) -> Vec<u8> {
    let mut b = super::mach::absolute_time().to_le_bytes().to_vec();
    b.extend_from_slice(req);
    b
}

fn co_call(r: Remote, op: u32, req: &[u8], out: &mut [u8]) {
    share::call(r, op, &with_now(req), out)
}

fn co_call_upto(r: Remote, op: u32, req: &[u8], out: &mut [u8]) -> usize {
    share::call_upto(r, op, &with_now(req), out)
}

fn co_call_read(r: Remote, op: u32, req: &[u8]) -> Vec<u8> {
    share::call_read(r, op, &with_now(req))
}

/// A coalition call the global kernel's channel carried ([`share::serve`]),
/// answered on this kernel's table at the caller's time: `None` for a call
/// that is not one of these.
pub(crate) fn serve(op: u32, req: &[u8], out: &mut [u8]) -> Option<i64> {
    if !(share::op::CO_FORK..=share::op::CO_SET_NAME).contains(&op) {
        return None;
    }
    let Some((now, req)) = req.split_first_chunk::<8>() else { return Some(-22) };
    CALLER_NOW.with(|c| c.set(Some(u64::from_le_bytes(*now))));
    let n = serve_at(op, req, out);
    CALLER_NOW.with(|c| c.set(None));
    n
}

fn serve_at(op: u32, req: &[u8], out: &mut [u8]) -> Option<i64> {
    use share::op as o;
    const EINVAL: i64 = 22;
    const E2BIG: i64 = 7;
    let answer = |out: &mut [u8], b: &[u8]| -> i64 {
        if b.len() > out.len() {
            return -E2BIG;
        }
        out[..b.len()].copy_from_slice(b);
        b.len() as i64
    };
    let u64_at = |at: usize| req.get(at..at + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()));
    Some(match op {
        o::CO_FORK => {
            let (Some(p), Some(c), 8) = (pid_at(req, 0), pid_at(req, 4), req.len()) else { return Some(-EINVAL) };
            fork_here(p, c);
            0
        }
        o::CO_ADOPT_CORPSE | o::CO_EXEC | o::CO_MEMBERSHIP | o::CO_THREAD_GROUP | o::CO_LEADER | o::CO_TASK_TERMINATED | o::CO_LIST => {
            let (Some(p), 4) = (pid_at(req, 0), req.len()) else { return Some(-EINVAL) };
            match op {
                o::CO_ADOPT_CORPSE => {
                    adopt_corpse_here(p);
                    0
                }
                o::CO_EXEC => {
                    exec_here(p);
                    0
                }
                o::CO_MEMBERSHIP => answer(out, &membership_bytes(membership_here(p))),
                o::CO_THREAD_GROUP => answer(out, &thread_group_here(p).to_le_bytes()),
                o::CO_LEADER => answer(out, &leader_bytes(leader_here(p))),
                o::CO_TASK_TERMINATED => {
                    let b: Vec<u8> = task_terminated_here(p).iter().flat_map(|i| i.to_le_bytes()).collect();
                    answer(out, &b)
                }
                // A read, answered whole however long: what fits in `out`,
                // and the whole length for the caller to ask again with room.
                _ => {
                    let b = list_bytes(&list_here(p));
                    let n = b.len().min(out.len());
                    out[..n].copy_from_slice(&b[..n]);
                    b.len() as i64
                }
            }
        }
        o::CO_PRIVILEGED => {
            let (Some(p), Some(k), 8) = (pid_at(req, 0), pid_at(req, 4), req.len()) else { return Some(-EINVAL) };
            answer(out, &[u8::from(privileged_here(p, k as u32))])
        }
        o::CO_ACTIVATE | o::CO_KIND => {
            let (Some(cid), 8) = (u64_at(0), req.len()) else { return Some(-EINVAL) };
            let t = if op == o::CO_ACTIVATE { activate_here(cid) } else { kind_here(cid) };
            let mut b = [0u8; 5];
            b[0] = u8::from(t.is_some());
            b[1..5].copy_from_slice(&t.unwrap_or(0).to_le_bytes());
            answer(out, &b)
        }
        o::CO_RELEASE => {
            if req.len() % 8 != 0 || req.len() > 8 * ty::NUM {
                return Some(-EINVAL);
            }
            let b: Vec<u8> = release_here(&ids_of(req)).iter().flat_map(|i| i.to_le_bytes()).collect();
            answer(out, &b)
        }
        o::CO_PLACE => {
            if req.len() != 4 + 13 * ty::NUM {
                return Some(-EINVAL);
            }
            let child = pid_at(req, 0).unwrap();
            let mut coals = [None; ty::NUM];
            let mut roles = [0; ty::NUM];
            for k in 0..ty::NUM {
                let at = 4 + 13 * k;
                coals[k] = (req[at] != 0).then(|| u64_at(at + 1).unwrap());
                roles[k] = pid_at(req, at + 9).unwrap();
            }
            place_here(child, coals, roles);
            0
        }
        o::CO_CREATE => {
            let (Some(k), Some(role), 10) = (pid_at(req, 0), pid_at(req, 4), req.len()) else { return Some(-EINVAL) };
            answer(out, &table().create(k as u32, role as u32, req[8] != 0, req[9] != 0).to_le_bytes())
        }
        o::CO_TERMINATE => {
            let (Some(cid), 9) = (u64_at(0), req.len()) else { return Some(-EINVAL) };
            let mut b = [0u8; 5];
            match terminate_or_reap_here(cid, req[8] != 0) {
                Ok(now) => b[1] = u8::from(now),
                Err(e) => {
                    b[0] = 1;
                    b[1..5].copy_from_slice(&e.0.to_le_bytes());
                }
            }
            answer(out, &b)
        }
        o::CO_SET_NAME => {
            let Some(cid) = u64_at(0) else { return Some(-EINVAL) };
            if req.len() - 8 >= THREAD_GROUP_MAXNAME {
                return Some(-EINVAL);
            }
            set_name_here(cid, &req[8..]);
            0
        }
        _ => return None,
    })
}

/// `struct procinfo_coalinfo`s of the coalitions of `type` (any, if
/// negative) in the table's order (`coalitions_get_list`).
pub fn list(k: i32) -> Vec<(u64, u32, u32)> {
    match share::remote() {
        Some(r) => list_through(r, k),
        None => list_here(k),
    }
}

fn list_here(k: i32) -> Vec<(u64, u32, u32)> {
    let t = table();
    let mut out = Vec::new();
    for chain in &t.buckets {
        for id in chain {
            let c = &t.coals[id];
            if !c.reaped && (k < 0 || k as u32 == c.ty) {
                out.push((c.id, c.ty, t.task_count(c)));
            }
        }
    }
    out
}

impl Kernel {
    /// `coalition_notify_user`: the host's coalition port, if launchd set
    /// one, hears that coalition `id` is empty (`coalition_notification`).
    fn darwin_coalition_notify(&mut self, id: u64) {
        use super::ipc::msg::{bits, Kmsg, Sender};
        use super::ipc::right::msgt;
        let ipc = self.ipc();
        let Some(&(_, port)) = ipc.host_special.iter().find(|(i, _)| *i == HOST_COALITION_PORT) else { return };
        if !ipc.port(port).active {
            return;
        }
        // The message's own send right, as host_get_coalition_port's copy
        // is moved into it.
        ipc.copy_send(port);
        let mut body = super::mig::NDR_RECORD.to_vec();
        body.extend_from_slice(&id.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        let k = Kmsg { bits: bits::set(msgt::PORT_SEND, 0, 0, 0), size: 24 + body.len() as u32, dest: port, reply: None, voucher: None, voucher_raw: 0, id: COALITION_NOTIFICATION, body, descs: Vec::new(), sender: Sender::KERNEL, aux: Vec::new(), keep_alive: false, ppriority: 0, qos_override: 0, imp: None };
        self.darwin_kernel_send(Box::new(k));
    }

    /// Tell launchd of each coalition that terminated.
    pub(crate) fn darwin_coalitions_notify(&mut self, ids: Vec<u64>) {
        for id in ids {
            self.darwin_coalition_notify(id);
        }
    }

    /// The process's task leaves its coalitions.
    pub(crate) fn darwin_coalitions_task_end(&mut self) {
        let told = task_terminated(self.pid);
        self.darwin_coalitions_notify(told);
    }

    fn darwin_coalition_cid(&self, m: &GuestMem<'_>, at: u64) -> Result<u64, Errno> {
        m.read_u64(at).map_err(|_| Errno::EFAULT)
    }

    /// `coalition(operation, cid, flags)`: for a member of a privileged
    /// coalition of the type the flags name.
    fn darwin_coalition(&mut self, m: &mut GuestMem<'_>, operation: u32, cidp: u64, flags: u32) -> Result<u64, Errno> {
        let k = (flags & 0xf0) >> 4;
        if !privileged(self.pid, k) {
            return Err(Errno::EPERM);
        }
        match operation {
            op::CREATE => {
                let r = (flags & 0xf00) >> 8;
                if flags & !create::MASK != 0 || k as usize >= ty::NUM {
                    return Err(Errno::EINVAL);
                }
                let id = create(k, r, flags & create::PRIVILEGED != 0, flags & create::EFFICIENT != 0);
                m.write_u64(cidp, id).map_err(|_| Errno::EFAULT)?;
                Ok(0)
            }
            op::TERMINATE | op::REAP => {
                if flags != 0 {
                    return Err(Errno::EINVAL);
                }
                let cid = self.darwin_coalition_cid(m, cidp)?;
                if terminate_or_reap(cid, operation == op::REAP)? {
                    self.darwin_coalition_notify(cid);
                }
                Ok(0)
            }
            _ => Err(Errno::ENOSYS),
        }
    }

    /// `coalition_info(flavor, cid, buffer, bufsize)`.
    fn darwin_coalition_info(&mut self, m: &mut GuestMem<'_>, flavor: u32, cidp: u64, buffer: u64, bufsizep: u64) -> Result<u64, Errno> {
        let cid = self.darwin_coalition_cid(m, cidp)?;
        let Some(cty) = kind(cid) else { return Err(Errno::ESRCH) };
        let bufsize = m.read_u64(bufsizep).map_err(|_| Errno::EFAULT)?;
        match flavor {
            op::INFO_RESOURCE_USAGE => {
                self.darwin_unimplemented("coalition_info's resource usage (its tasks' ledgers: CPU, energy, I/O and wakeups)".into());
                Err(Errno::EIO)
            }
            op::INFO_SET_NAME => {
                if cty != ty::JETSAM {
                    return Err(Errno::EINVAL);
                }
                let n = (bufsize as usize).min(THREAD_GROUP_MAXNAME - 1);
                let name = m.read(buffer, n).map_err(|_| Errno::EFAULT)?.to_vec();
                // thread_group_set_name: a name, not an empty one.
                if name.first().is_some_and(|&b| b != 0) {
                    set_name(cid, &name);
                }
                Ok(0)
            }
            op::INFO_SET_EFFICIENCY => {
                if cty != ty::JETSAM {
                    return Err(Errno::EINVAL);
                }
                let n = (bufsize as usize).min(8);
                let mut b = [0u8; 8];
                b[..n].copy_from_slice(m.read(buffer, n).map_err(|_| Errno::EFAULT)?);
                let flags = u64::from_le_bytes(b);
                if flags & FLAGS_EFFICIENT == 0 {
                    return Err(Errno::EINVAL);
                }
                // No longer taken here: efficiency is given at creation.
                Err(Errno::EOPNOTSUPP)
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// `coalition_ledger(operation, cid, buffer, bufsize)`: root's.
    fn darwin_coalition_ledger(&mut self, m: &mut GuestMem<'_>, operation: u32, cidp: u64, buffer: u64, bufsizep: u64) -> Result<u64, Errno> {
        if self.dtask.cred.uid != 0 {
            return Err(Errno::EPERM);
        }
        let cid = self.darwin_coalition_cid(m, cidp)?;
        let Some(cty) = kind(cid) else { return Err(Errno::ESRCH) };
        let bufsize = m.read_u64(bufsizep).map_err(|_| Errno::EFAULT)?;
        match operation {
            op::LEDGER_SET_LOGICAL_WRITES_LIMIT => {
                if cty != ty::RESOURCE {
                    return Err(Errno::EINVAL);
                }
                let n = (bufsize as usize).min(8);
                let mut b = [0u8; 8];
                b[..n].copy_from_slice(m.read(buffer, n).map_err(|_| Errno::EFAULT)?);
                let limit = i64::from_le_bytes(b);
                if limit > MAX_LOGICAL_WRITES_LIMIT || limit == 0 || limit < -1 {
                    return Err(Errno::EINVAL);
                }
                self.darwin_unimplemented("coalition_ledger's logical writes limit (the coalition's I/O ledger)".into());
                Err(Errno::EIO)
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// The call, if it is one of these.
    pub(crate) fn darwin_coalition_call(&mut self, m: &mut GuestMem<'_>, raw: u64, a: &[u64; 6]) -> Option<Result<u64, Errno>> {
        Some(match raw {
            sys::COALITION => self.darwin_coalition(m, a[0] as u32, a[1], a[2] as u32),
            sys::COALITION_INFO => self.darwin_coalition_info(m, a[0] as u32, a[1], a[2], a[3]),
            sys::COALITION_LEDGER => self.darwin_coalition_ledger(m, a[0] as u32, a[1], a[2], a[3]),
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each of the table's functions through the global kernel's channel
    /// answers as the serving kernel's table does, at the caller's time.
    #[test]
    fn the_table_through_the_channel_is_the_serving_kernels() {
        let r = Remote { call: share::serve };
        // Pids no other test uses.
        let (p, c) = (0x7100_0001, 0x7100_0002);
        fork_through(r, p, c);
        let (ids, roles) = membership_through(r, c);
        assert_eq!((ids, roles), membership_here(c));
        assert!(ids.iter().all(|&i| i != 0) && roles[ty::RESOURCE as usize] == taskrole::UNDEF);
        assert_eq!(thread_group_through(r, c), thread_group_here(c));
        assert!(privileged_through(r, c, ty::JETSAM));
        assert!(!privileged_through(r, c, 7));
        assert_eq!(leader_through(r, c), leader_here(c));
        exec_through(r, c);
        // A coalition made, found, terminated (nothing in it: at once) and
        // reaped, with the errors of each step taken again.
        let mut o = [0u8; 8];
        co_call(r, share::op::CO_CREATE, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &mut o);
        let id = u64::from_le_bytes(o);
        assert!(list_through(r, ty::RESOURCE as i32).iter().any(|&(i, t, n)| i == id && t == ty::RESOURCE && n == 0));
        let mut k = [0u8; 5];
        co_call(r, share::op::CO_KIND, &id.to_le_bytes(), &mut k);
        assert_eq!(k, [1, 0, 0, 0, 0]);
        let term = |reap: bool| {
            let mut req = id.to_le_bytes().to_vec();
            req.push(u8::from(reap));
            let mut o = [0u8; 5];
            co_call(r, share::op::CO_TERMINATE, &req, &mut o);
            o
        };
        let busy = Errno::EBUSY.0.to_le_bytes();
        assert_eq!(term(true), [1, busy[0], busy[1], busy[2], busy[3]]);
        assert_eq!(term(false), [0, 1, 0, 0, 0]);
        let already = Errno::EALREADY.0.to_le_bytes();
        assert_eq!(term(false), [1, already[0], already[1], already[2], already[3]]);
        assert_eq!(term(true), [0, 0, 0, 0, 0]);
        co_call(r, share::op::CO_KIND, &id.to_le_bytes(), &mut k);
        assert_eq!(k, [0; 5]);
        assert!(!list_through(r, -1).iter().any(|&(i, ..)| i == id));
        // The child's task ends: it leaves its coalitions (the default
        // ones, which do not terminate).
        assert_eq!(task_terminated_through(r, c), Vec::<u64>::new());
        assert_eq!(membership_through(r, c), ([0; ty::NUM], [taskrole::NONE; ty::NUM]));
        assert_eq!(serve(share::op::CO_FORK, &[0; 9], &mut []), Some(-22));
        assert_eq!(serve(share::op::CO_FORK, &[0; 4], &mut []), Some(-22));
        assert_eq!(serve(share::op::NEXT, &[0; 9], &mut []), None);
    }
}
