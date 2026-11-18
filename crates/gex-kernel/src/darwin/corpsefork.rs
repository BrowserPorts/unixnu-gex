//! Corpse forks (`osfmk/corpses/corpse.c`'s `task_generate_corpse_internal`,
//! `osfmk/kern/task.c`'s `task_duplicate_map_and_threads`, `vm_map_fork` in
//! corpse mode, xnu-10063.141.1): a copy of a live task, made for its crash
//! reporter while the task goes on. The copy is a task with no process
//! (`task_pid` -1), its map the live task's by `vm_map_fork` with
//! VM_MAP_FORK_SHARE_IF_INHERIT_NONE, VM_MAP_FORK_PRESERVE_PURGEABLE and
//! VM_MAP_FORK_CORPSE_FOOTPRINT, its threads copies of the live task's that
//! never run, its crash information the live process's.
//!
//! A corpse fork is asked for from inside a call (`os_fault_with_payload`),
//! a thread call (a soft memory limit) or a request served to the task's
//! port (`task_generate_corpse`), each with the task's kernel held. The
//! copy needs the task's threads held still and its memory copied, which
//! its host does outside the kernel: the request is queued here
//! ([`Kernel::darwin_corpse_fork_queue`]) and the host's thread-call thread
//! takes it ([`Kernel::darwin_corpse_fork_take`]), holds the task's threads,
//! has its kernel make the corpse's ([`Kernel::darwin_corpse_fork_build`]),
//! copies the memory, lets the threads go, enables the corpse ([`enable`])
//! and starts its thread calls, and gives the outcome back to whoever asked
//! ([`Kernel::darwin_corpse_fork_done`]).

use super::corpse::{self, flags, Corpse, Keep};
use super::vmshare::{ForkRange, Inherit};
use crate::syscalls::Kernel;
use crate::GuestMem;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// `KERN_*` codes the corpse fork returns.
const KERN_SUCCESS: u64 = 0;
const KERN_NO_SPACE: u64 = 3;
const KERN_INVALID_ARGUMENT: u64 = 4;
const KERN_FAILURE: u64 = 5;
const KERN_INVALID_TASK: u64 = 16;
const KERN_NOT_SUPPORTED: u64 = 46;

/// `EXC_GUARD_DECODE_GUARD_TYPE`'s GUARD_TYPE_USER.
const GUARD_TYPE_USER: i64 = 0x3;

/// `max_task_footprint_mb`: the device's system-wide task limit, of which
/// `memorystatus_allowed_vm_map_fork` allows a corpse fork of a task whose
/// footprint is at most a quarter.
const MAX_TASK_FOOTPRINT_MB: u64 = super::memorystatus::MAX_TASK_FOOTPRINT_MB as u64;

/// The tokens of `task_generate_corpse`'s deferred replies.
static NEXT_TOKEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// The next deferred reply's token.
pub fn next_token() -> u64 {
    NEXT_TOKEN.fetch_add(1, Ordering::Relaxed)
}

/// Whether the host makes corpse forks ([`set_host_forks_corpses`]).
static HOST_FORKS_CORPSES: AtomicBool = AtomicBool::new(false);

/// The host takes the corpse forks a task's kernel queues: it holds the
/// task's threads, copies its memory and runs the corpse's thread calls.
pub fn set_host_forks_corpses() {
    HOST_FORKS_CORPSES.store(true, Ordering::Release);
}

/// Who waits for a corpse fork's outcome.
#[derive(Debug)]
pub enum Origin {
    /// `task_generate_corpse`'s routine, its reply deferred under this
    /// token ([`super::kobject::Deferred::CorpseFork`]).
    Generate(u64),
    /// `task_enqueue_exception_with_corpse` from a call of thread `.0`,
    /// which waits for the return code.
    Call(i32),
    /// `task_enqueue_exception_with_corpse` from a thread call: no one.
    ThreadCall,
}

/// A corpse fork asked for: `task_generate_corpse_internal`'s exception
/// type (0 for `task_generate_corpse`), codes and reason, and the calling
/// thread when it is the task's own (`current_thread()`, whose copy is the
/// crashed thread).
#[derive(Debug)]
pub struct Request {
    pub etype: usize,
    pub code: i64,
    pub subcode: i64,
    pub reason: Option<Arc<super::reason::OsReason>>,
    pub current: Option<i32>,
    pub origin: Origin,
}

/// A corpse fork that failed before its corpse was made: who waits, and
/// the return code.
#[derive(Debug)]
pub struct Failed {
    pub origin: Origin,
    pub kr: u64,
}

/// A corpse being made: its kernel, the ranges of the live task's memory
/// the host gives it (`vm_map_fork`'s inheritance), and who waits.
pub struct Build {
    pub corpse: Kernel,
    pub plan: Vec<ForkRange>,
    pub origin: Origin,
}

/// One of the corpse's threads: its thread, its register context (the
/// live thread's, copied with the memory), its new thread id, and what it
/// copies of the live thread (`thread_dup2`'s TSD base, `bsd_copythreadname`).
struct Dup {
    tid: i32,
    ctx: u64,
    id: u64,
    tsd: u64,
    name: Option<Vec<u8>>,
}

impl Kernel {
    /// Queue a corpse fork of this task for the host's thread-call thread,
    /// waking it; KERN_FAILURE, said, on a host that makes none.
    pub(crate) fn darwin_corpse_fork_queue(&mut self, req: Request) -> Result<(), u64> {
        if !HOST_FORKS_CORPSES.load(Ordering::Acquire) {
            self.darwin_unimplemented("a corpse fork on a host that cannot copy a live task (corpsefork::set_host_forks_corpses)".into());
            return Err(KERN_FAILURE);
        }
        self.dtask.corpse_forks.push_back(req);
        self.dtask.timers.bell().ring();
        Ok(())
    }

    /// The next corpse fork queued, for the host.
    pub fn darwin_corpse_fork_take(&mut self) -> Option<Request> {
        self.dtask.corpse_forks.pop_front()
    }

    /// `task_generate_corpse_internal` up to the corpse's crash
    /// information, with this task's threads held still by the host
    /// (`task_suspend_internal`) and `m` its memory: the corpse's kernel,
    /// and the ranges of this task's memory the host is to give it. The
    /// host copies them ([`Kernel::darwin_corpse_fork_vm`] then enters
    /// them in the corpse's map) and enables the corpse ([`enable`]).
    pub fn darwin_corpse_fork_build(&mut self, m: &mut GuestMem<'_>, req: Request) -> Result<Build, Failed> {
        let Request { etype, code, subcode, reason, current, origin } = req;
        // corpses_enabled(): no -no_corpses boot argument here.
        // task_corpse_forking_disabled(): TF_NO_CORPSE_FORKING is set only
        // by task_set_corpse_forking_behavior, a DEVELOPMENT || DEBUG
        // routine this kernel does not have.
        let mut user_flags = flags::HAS_REF;
        if etype == super::exception::EXC_GUARD && (code >> 61) & 0x7 == GUARD_TYPE_USER {
            user_flags |= flags::USER_FAULT;
        }
        let who = self.darwin_best_name();
        if let Err(kr) = corpse::get_ref(user_flags, (&who, self.pid)) {
            return Err(Failed { origin, kr });
        }
        // proc_find(task_pid(task)): a process that has ended has no proc
        // to find.
        let public = match self.darwin_public(self.pid) {
            Some((p, false)) => p,
            _ => {
                corpse::release_ref(user_flags);
                return Err(Failed { origin, kr: KERN_INVALID_TASK });
            }
        };
        // task_create_internal: the corpse's task, its uniqueid the next
        // (task_set_uniqueid), its rights the parent's (ipc_task_init).
        let task_uniqueid = corpse::next_task_uniqueid();
        let (special, special_dead, registered, exc) = self.darwin_inherited_ports();
        let ports = super::kobject::Kports { special, special_dead, registered, exc, ..Default::default() };
        match self.darwin_duplicate_map_and_threads(m, current, etype != 0) {
            Ok((plan, shared, udata, dups, crashed, footprint)) => {
                let crashed_thread_id = dups[crashed].id;
                // task_collect_crash_info(new_task, TRUE): no reference of
                // its own; the fork's are given it after.
                let Some(info) = corpse::crashinfo_alloc_init(0, (&who, self.pid)) else {
                    self.darwin_corpse_ports_release(ports);
                    corpse::release_ref(user_flags);
                    return Err(Failed { origin, kr: KERN_FAILURE });
                };
                let mut c = Corpse {
                    info,
                    user_flags,
                    crashed_thread_id,
                    fork: true,
                    pending_report: true,
                    thread: dups[crashed].tid,
                    ctx: dups[crashed].ctx,
                    inspection: dups.iter().map(|d| d.tid).collect(),
                    task_uniqueid,
                    etype,
                    subcode: 0,
                    pending: None,
                    port: None,
                    vm: None,
                    keep: Keep::default(),
                    enqueued: None,
                    coalition_key: None,
                    footprint,
                };
                // gather_populate_corpse_crashinfo of the live process,
                // its usage as it stands (no exit time); the ledgers copied
                // to the corpse are this task's as they are now.
                let bills = self.darwin_bank_bills(self.pid, self.dtask.uniqueid, &Arc::clone(&self.dtask.rusage));
                let record = super::rusage::crash_record(&self.procs, self.pid, &public, bills, false);
                self.darwin_populate_corpse_crashinfo(&mut c, &public, code, subcode, &udata, reason, etype, record, current);
                let corpse = self.darwin_corpse_kernel(c, ports, &shared, &dups);
                Ok(Build { corpse, plan, origin })
            }
            Err(kr) => {
                self.darwin_corpse_ports_release(ports);
                corpse::release_ref(user_flags);
                Err(Failed { origin, kr })
            }
        }
    }

    /// The rights a corpse fork that failed had of its parent's, let go.
    fn darwin_corpse_ports_release(&mut self, k: super::kobject::Kports) {
        let ipc = self.ipc();
        for p in k.special.values().copied().chain(k.registered.into_iter().flatten()) {
            ipc.release_send(p);
        }
        super::exception::release_all(ipc, &k.exc);
        self.darwin_ipc_notify_drain();
    }

    /// `task_duplicate_map_and_threads` of this task (held still by the
    /// host): the corpse's map by `vm_map_fork` if memorystatus allows it
    /// (else none, unless the fork is not for an exception: KERN_NO_SPACE),
    /// the knotes' user data, and a copy of each active thread, the one of
    /// `current` (else the first) the corpse's crashed thread. The plan
    /// the host follows, the ranges shared in place of not inherited, the
    /// user data, the threads and the crashed one's index.
    #[allow(clippy::type_complexity)]
    fn darwin_duplicate_map_and_threads(&mut self, m: &mut GuestMem<'_>, current: Option<i32>, for_exception: bool) -> Result<(Vec<ForkRange>, Vec<(u64, u64)>, Vec<u64>, Vec<Dup>, usize, Option<corpse::Footprint>), u64> {
        // map->disable_vmentry_reuse: set only by debug.toggle_address_reuse,
        // whose write this kernel does not make (it says so).
        // The footprint as it is now (get_task_phys_footprint).
        if self.procs.jetsam().ledgers.contains_key(&self.pid) && self.darwin_footprint_now(m).is_none() {
            return Err(KERN_FAILURE);
        }
        let (plan, shared, udata, footprint) = if self.darwin_allowed_vm_map_fork() {
            let (plan, shared, footprint) = self.darwin_corpse_fork_map();
            // kevent_proc_copy_uptrs: the buffer holds the count first
            // found and 32 more, and the count does not change in between.
            let udata = self.dtask.kevents.proc_copy_uptrs();
            (plan, shared, udata, footprint)
        } else if !for_exception {
            return Err(KERN_NO_SPACE);
        } else {
            // The corpse keeps the empty map task_create_internal made it.
            (self.darwin_fork_plan().into_iter().map(|r| ForkRange { how: Inherit::None, ..r }).collect(), Vec::new(), Vec::new(), None)
        };
        // The task's active threads, in the order of its list.
        let mut tids = self.thread_signals.tids_in_order();
        tids.extend(self.dtask.threads.map.keys().copied());
        tids.sort_unstable();
        tids.dedup();
        if tids.is_empty() {
            return Err(KERN_FAILURE);
        }
        let mut dups = Vec::with_capacity(tids.len());
        let mut crashed = None;
        for tid in tids {
            let ts = self.thread_signals.get(tid);
            let ctx = ts.as_ref().map(|t| t.ctx()).filter(|&c| c != 0).or_else(|| (tid == self.tid).then_some(self.ctx_addr)).or_else(|| self.dtask.threads.map.get(&tid).map(|t| t.ctx_addr).filter(|&c| c != 0)).or_else(|| self.dtask.threads.map.get(&tid).and_then(|t| t.unstarted.as_ref()).map(|r| r.ctx_addr));
            let Some(ctx) = ctx else {
                self.darwin_unimplemented(format!("a corpse fork's copy of thread {tid}, whose register context is not known (thread_dup2)"));
                return Err(KERN_FAILURE);
            };
            // thread_create_with_continuation: the next thread id.
            let id = super::next_thread_id();
            if Some(tid) == current {
                crashed = Some(dups.len());
            }
            dups.push(Dup { tid, ctx, id, tsd: ts.as_ref().map_or(0, |t| t.tsd()), name: ts.as_ref().and_then(|t| t.name()) });
        }
        Ok((plan, shared, udata, dups, crashed.unwrap_or(0), footprint))
    }

    /// `memorystatus_allowed_vm_map_fork`: no jetsam purge of corpses
    /// blocking new ones (`block_corpses`: memorystatus_dump_caches's, which
    /// no memory pressure reaches here), and a footprint within a quarter
    /// of the system-wide task limit.
    fn darwin_allowed_vm_map_fork(&mut self) -> bool {
        let footprint = self.procs.jetsam().ledgers.get(&self.pid).map_or(0, |l| l.balance.max(0) as u64);
        let max_allowed = (MAX_TASK_FOOTPRINT_MB * 1024 * 1024) >> 2;
        if footprint > max_allowed {
            corpse::kernel_log(format!("memorystatus disallowed vm_map_fork {footprint}  {max_allowed}"));
            return false;
        }
        true
    }

    /// `vm_map_fork(..., VM_MAP_FORK_SHARE_IF_INHERIT_NONE |
    /// VM_MAP_FORK_PRESERVE_PURGEABLE | VM_MAP_FORK_CORPSE_FOOTPRINT)` of
    /// this task's map: each range by its entries' inheritance, an entry
    /// not inherited but readable (none here has a device pager:
    /// [`super::vmobject::Pager`]) shared instead; this map's entries
    /// marked as a fork marks them, and its footprint collected for the
    /// corpse. The plan, and the ranges shared in place of not inherited.
    fn darwin_corpse_fork_map(&mut self) -> (Vec<ForkRange>, Vec<(u64, u64)>, Option<corpse::Footprint>) {
        let (alias, alias_end) = (gex_abi::DARWIN_COMMPAGE_ALIAS, gex_abi::DARWIN_COMMPAGE_ALIAS + (gex_abi::DARWIN_COMMPAGE_END - gex_abi::DARWIN_COMMPAGE_RO));
        let vmas: Vec<(u64, u64, u32)> = self.mem.lock().vmas().iter().map(|v| (v.start, v.end, v.prot)).filter(|&(s, e, _)| !(s >= alias && e <= alias_end)).collect();
        let mut plan: Vec<ForkRange> = Vec::new();
        let mut shared: Vec<(u64, u64)> = Vec::new();
        let mut entries = Vec::new();
        for (s, e, prot) in vmas {
            for (ps, pe, a) in self.dtask.vm.pieces(s, e) {
                let submap = a.kind == super::vm::kind::SUBMAP;
                let how = match a.inherit {
                    _ if submap => Inherit::Copy,
                    super::vm::inherit::SHARE => Inherit::Share,
                    super::vm::inherit::NONE if prot & crate::mem::prot::READ != 0 => {
                        shared.push((ps, pe));
                        Inherit::Share
                    }
                    super::vm::inherit::NONE => Inherit::None,
                    _ => Inherit::Copy,
                };
                entries.push((ps, pe, a, how));
                match plan.last_mut() {
                    Some(l) if l.end == ps && l.how == how && l.own_pmap == !submap => l.end = pe,
                    _ => plan.push(ForkRange { start: ps, end: pe, how, own_pmap: !submap }),
                }
            }
        }
        // vm_map_fork_copy with VM_MAP_COPYIN_PRESERVE_PURGEABLE: a
        // purgeable object's copy is a purgeable object of its own.
        for &(ps, _, a, how) in &entries {
            if how == Inherit::Copy && a.kind != super::vm::kind::SUBMAP && super::vmobject::with(a.obj, |o| o.purg.as_ref().is_some_and(|p| p.state != super::purgeable::state::DENY)).unwrap_or(false) {
                self.darwin_unimplemented(format!("a corpse fork's copy of purgeable memory at {ps:#x} (VM_MAP_COPYIN_PRESERVE_PURGEABLE: a purgeable object of its own, in the source's state, owned by no one)"));
            }
        }
        // The footprint, before the entries change (vm_map_corpse_footprint_collect).
        let mut footprint = self.darwin_corpse_footprint_collect(&entries);
        // vm_map_corpse_footprint_collect_done.
        if let Some(f) = footprint.as_mut() {
            f.done();
        }
        // The parent's entries, as vm_map_fork leaves them: copies marked
        // needs_copy, shares is_shared.
        let mapped: Vec<(u64, u64)> = entries.iter().filter(|e| e.3 != Inherit::None).map(|e| (e.0, e.1)).collect();
        self.dtask.vm.fork(&mapped);
        for &(s, e) in &shared {
            self.dtask.vm.update(s, e, |a| a.shared = true);
        }
        (plan, shared, footprint)
    }

    /// `vm_map_corpse_footprint_collect` of each entry the fork inherits
    /// (`entries`, with how), in map order, into a new buffer sized as
    /// XNU sizes it: the buffer, or none if the map has nothing inherited.
    fn darwin_corpse_footprint_collect(&mut self, entries: &[(u64, u64, super::vm::Attrs, Inherit)]) -> Option<corpse::Footprint> {
        let nentries = entries.len() as u64;
        let size: u64 = entries.iter().map(|e| e.1 - e.0).sum();
        let mut fp: Option<corpse::Footprint> = None;
        let owner = self.dtask.rusage.meter.owner();
        let pm = Arc::clone(&self.dtask.rusage);
        let pm = pm.meter.lock();
        for &(s, e, a, how) in entries {
            if how == Inherit::None {
                continue;
            }
            let f = fp.get_or_insert_with(|| corpse::Footprint::new(nentries, size));
            if f.failed {
                break;
            }
            let mut loud = None;
            let ok = f.collect(s, e, |va| {
                let (d, why) = footprint_disposition(&pm, &owner, &a, va);
                if why.is_some() {
                    loud = why;
                }
                d
            });
            if let Some(w) = loud {
                self.darwin_unimplemented(w);
            }
            if !ok {
                f.failed = true;
            }
        }
        fp
    }

    /// The corpse's kernel: a task with no process, its corpse state `c`
    /// (its crash information in), its rights `ports`, its map the
    /// inherited entries (and those shared in place of not inherited,
    /// `shared`) over a copy of this map's mappings, and its threads
    /// `dups`, held for inspection.
    fn darwin_corpse_kernel(&mut self, c: Corpse, ports: super::kobject::Kports, shared: &[(u64, u64)], dups: &[Dup]) -> Kernel {
        let (_, abs) = super::start_times();
        let thread = c.thread;
        let ctx = c.ctx;
        let t = super::Task {
            rusage: super::rusage::Shared::new(abs),
            kports: ports,
            vm: self.dtask.vm.inherited_corpse(shared),
            map_max: self.dtask.map_max,
            map_min: self.dtask.map_min,
            strict: self.dtask.strict,
            codesign: self.dtask.codesign.clone(),
            csflags: Arc::new(std::sync::atomic::AtomicU32::new(self.dtask.csflags.load(Ordering::Acquire))),
            cputype: self.dtask.cputype,
            // task_create_internal: a task inheriting its parent's memory
            // has its dispatch queue offsets (libpthread's registration
            // gives them).
            pthread: self.dtask.pthread,
            dispatchqueue_serialno_offset: self.dtask.dispatchqueue_serialno_offset,
            dispatchqueue_label_offset: self.dtask.dispatchqueue_label_offset,
            corpse: Some(Box::new(c)),
            ..Default::default()
        }
        .with_wire_ledger();
        let mut k = self.fork_kernel_with(t);
        // No process: task_pid is -1, and it has no descriptors.
        k.pid = -1;
        k.ppid = 0;
        k.tid = thread;
        k.ctx_addr = ctx;
        k.fds = Arc::new(crate::file::FdTable::new());
        for d in dups {
            let ts = k.thread_signals.get_or_insert_with(d.tid, || Arc::new(crate::signal::ThreadSig::new_thread(0)));
            ts.set_darwin_id(d.id);
            ts.set_tsd(d.tsd);
            ts.set_ctx(d.ctx);
            ts.set_name(d.name.clone());
            k.dtask.threads.map.insert(d.tid, super::thread::DThread { ctx_addr: d.ctx, offcpu: true, ..Default::default() });
        }
        // An inherited JIT region's copy has no execute access.
        for (s, e) in self.dtask.vm.inherited_jit() {
            let parts: Vec<(u64, u64, u32)> = k.mem.lock().vmas().iter().filter(|v| v.start < e && v.end > s).map(|v| (v.start.max(s), v.end.min(e), v.prot)).collect();
            for (a, b, p) in parts {
                let _ = k.mem.lock().protect(a, b - a, p & !crate::mem::prot::EXEC);
            }
        }
        k
    }

    /// A corpse made but not enabled, let go (its host could not give it
    /// memory): `task_generate_corpse_internal`'s failure path, its
    /// threads ended, `task_clear_corpse`, `task_terminate_internal`, its
    /// reference to the corpses in flight released.
    pub fn darwin_corpse_fork_abandon(&mut self) {
        self.darwin_corpse_terminate();
    }

    /// The corpse's map once the host has given it this task's pages by
    /// `plan` (`m` the corpse's memory).
    pub fn darwin_corpse_fork_vm(&mut self, m: &mut GuestMem<'_>, plan: &[ForkRange]) {
        self.darwin_fork_child_enter(m, plan);
    }

    /// A corpse fork's outcome, given to whoever asked (`m` this task's
    /// memory): `task_generate_corpse`'s reply (the corpse's port, its
    /// no-senders notification armed), or the waiting call's return code.
    pub fn darwin_corpse_fork_done(&mut self, m: &mut GuestMem<'_>, origin: Origin, r: Result<Option<super::ipc::ObjId>, u64>) {
        use super::kobject::Reply;
        match origin {
            Origin::Generate(token) => {
                let reply = match r {
                    Ok(Some(port)) => Reply::port(super::ipc::right::Carried::Port(port)),
                    Ok(None) => Reply::err(KERN_FAILURE as i32),
                    Err(kr) => Reply::err(kr as i32),
                };
                self.darwin_answer_deferred(m, super::kobject::Deferred::CorpseFork(token), reply);
            }
            Origin::Call(tid) => {
                let kr = match r {
                    Ok(_) => KERN_SUCCESS,
                    Err(kr) => kr,
                };
                self.dtask.corpse_fork_results.insert(tid, kr);
                self.darwin_wake(m, tid, super::wait::WaitResult::Awakened);
            }
            Origin::ThreadCall => {}
        }
        self.darwin_ipc_settle(m);
    }

    /// `task_enqueue_exception_with_corpse(current_task(), etype, codes,
    /// reason, lightweight)` from a call of this thread: the corpse fork
    /// queued, the thread waiting for it (`Some`), or its return code.
    pub(crate) fn darwin_enqueue_exception_with_corpse(&mut self, m: &mut GuestMem<'_>, etype: usize, code: [i64; 2], reason: Option<Arc<super::reason::OsReason>>, lightweight: bool) -> Result<crate::syscalls::SyscallOutcome, u64> {
        if lightweight && self.darwin_lightweight_corpse_ports() {
            self.darwin_unimplemented("a lightweight corpse for an EXC_CORPSE_NOTIFY handler that prefers backtraces (MACH_EXCEPTION_BACKTRACE_PREFERRED: current_thread_collect_backtrace_info, a kcdata object, exception_deliver_backtrace)".into());
            return Err(KERN_FAILURE);
        }
        let tid = self.tid;
        let req = Request { etype, code: code[0], subcode: code[1], reason, current: Some(tid), origin: Origin::Call(tid) };
        self.darwin_corpse_fork_queue(req)?;
        Ok(self.darwin_block(m, super::wait::Wait { deadline: None, cont: super::thread::Finish::CorpseFork }))
    }

    /// `task_should_generate_lightweight_corpse` for this task's current
    /// thread (lw_corpses_enabled on an embedded kernel): a thread, task
    /// or host EXC_CORPSE_NOTIFY handler that prefers backtraces.
    fn darwin_lightweight_corpse_ports(&mut self) -> bool {
        use super::exception::EXC_CORPSE_NOTIFY;
        const MACH_EXCEPTION_BACKTRACE_PREFERRED: i32 = 0x2000_0000;
        let thread = self.dtask.kports.thread_exc.get(&self.tid).map(|a| a[EXC_CORPSE_NOTIFY]);
        let task = Some(self.dtask.kports.exc[EXC_CORPSE_NOTIFY]);
        let host = Some(self.ipc().host_exc[EXC_CORPSE_NOTIFY]);
        [thread, task, host].into_iter().flatten().any(|a| a.port.is_some() && a.behavior & MACH_EXCEPTION_BACKTRACE_PREFERRED != 0)
    }

    /// The corpse fork a thread's call waited for is done: its return code.
    pub(crate) fn darwin_corpse_fork_wait_done(&mut self, m: &mut GuestMem<'_>) -> Option<crate::syscalls::SyscallOutcome> {
        // The fork is made whatever interrupts the wait.
        let Some(kr) = self.dtask.corpse_fork_results.remove(&self.tid) else {
            return Some(self.darwin_block(m, super::wait::Wait { deadline: None, cont: super::thread::Finish::CorpseFork }));
        };
        self.darwin_corpse_fork_returned(m, kr)
    }
}

/// The corpse's enabling, with its kernel shared and its memory `vm`
/// (`ipc_task_enable` and the rest of `task_generate_corpse_internal`):
/// its task port made (its control port is its self port), its IPC space
/// ended, the corpse coalitions joined, the corpse on the corpse list.
/// For `task_generate_corpse` (`origin`), its threads' ports made anew and
/// a send right to its port with its no-senders notification armed
/// (`convert_corpse_to_port_and_nsrequest`), returned; for an exception,
/// its notification enqueued for its thread calls.
pub fn enable(corpse: &Arc<Mutex<Kernel>>, vm: Arc<crate::proc::PeerVm>, origin: &Origin) -> Option<super::ipc::ObjId> {
    let mut k = corpse.lock().unwrap_or_else(|e| e.into_inner());
    let me: Box<dyn std::any::Any + Send> = Box::new(Arc::clone(corpse));
    if let Some(c) = k.dtask.corpse.as_mut() {
        c.vm = Some(Arc::clone(&vm));
        c.keep.0 = Some(me);
    }
    k.darwin_task_enable();
    let ipc = k.ipc();
    let port = ipc.kobject_port(super::ipc::Kobject::Task);
    let key = ipc.task;
    k.dtask.kports.task = Some((port, port));
    if let Some(l) = k.ipc().link.clone() {
        l.ipc_active.store(true, Ordering::Release);
    }
    // ipc_space_terminate(new_task->itk_space).
    k.ipc().space_terminate();
    k.darwin_ipc_notify_drain();
    let ckey = super::coalition::corpse_member_key(key);
    super::coalition::adopt_corpse(ckey);
    let (info, task_uniqueid) = {
        let c = k.dtask.corpse.as_mut().expect("a corpse fork's corpse");
        c.coalition_key = Some(ckey);
        (c.info.bytes().to_vec(), c.task_uniqueid)
    };
    corpse::register(key, corpse::Registered { pid: -1, task_uniqueid, info, vm: Some(vm) });
    let out = match origin {
        Origin::Generate(_) => {
            // task_wait_till_threads_terminate_locked (they never ran),
            // then ipc_thread_reset of each.
            let threads = k.dtask.corpse.as_ref().map(|c| c.inspection.clone()).unwrap_or_default();
            for t in threads {
                k.darwin_corpse_thread_reset(t);
            }
            let ipc = k.ipc();
            ipc.make_send(port);
            ipc.port_mut(port).nsrequest_kobject = true;
            Some(port)
        }
        Origin::Call(_) | Origin::ThreadCall => {
            // thread_exception_enqueue.
            let etype = k.dtask.corpse.as_ref().map_or(0, |c| c.etype);
            if let Some(c) = k.dtask.corpse.as_mut() {
                c.enqueued = Some(etype);
            }
            k.dtask.timers.bell().ring();
            None
        }
    };
    k.darwin_ipc_leave();
    out
}

/// `vm_map_footprint_query_page_info` of the page at `va` of an entry with
/// attributes `a`, from what the task's pmap holds (`pm`) and the objects
/// the task owns (`owner`): the page's disposition, and what this kernel
/// cannot say of it.
fn footprint_disposition(pm: &super::footprint::Pmap, owner: &Arc<super::purgeable::Owner>, a: &super::vm::Attrs, va: u64) -> (i32, Option<String>) {
    use super::footprint::Held;
    const PRESENT: i32 = 0x1;
    const REF: i32 = 0x4;
    const DIRTY: i32 = 0x8;
    const EXTERNAL: i32 = 0x80;
    const REUSABLE: i32 = 0x800;
    // A submap's pages are its nested pmap's: no footprint. An entry with
    // no object has nothing mapped.
    if a.kind == super::vm::kind::SUBMAP || a.obj == 0 {
        return (0, None);
    }
    // pmap_query_page_info: a page entered through an entry with use_pmap
    // off is alternate accounting.
    let held = pm.held(va);
    let purg = super::vmobject::with(a.obj, |o| o.purg.as_ref().map(|p| (p.state, p.tag, p.no_footprint, p.owner.as_ref().is_some_and(|w| Arc::ptr_eq(w, owner))))).flatten();
    if let Some((state, tag, no_footprint, ours)) = purg {
        use super::purgeable::state as st;
        if no_footprint {
            return (0, None);
        }
        if ours && (state == st::NONVOLATILE || (state == st::DENY && tag != 0) || state == st::VOLATILE || state == st::EMPTY) {
            return (0, Some(format!("a corpse fork's footprint of a purgeable or ledger-tagged object the task owns, at {va:#x} (its resident, compressed and wired page counts)")));
        }
    }
    if a.alt && matches!(held, Held::Own | Held::Reusable) {
        return (0, None);
    }
    let d = match held {
        Held::None => 0,
        Held::Own => PRESENT | REF | DIRTY,
        Held::Reusable => PRESENT | REF | DIRTY | REUSABLE,
        Held::File => PRESENT | REF | EXTERNAL,
    };
    (d, None)
}

impl Kernel {
    /// The return code of `task_enqueue_exception_with_corpse` for its
    /// caller ([`Self::darwin_corpse_fork_wait_done`]).
    fn darwin_corpse_fork_returned(&mut self, m: &mut GuestMem<'_>, kr: u64) -> Option<crate::syscalls::SyscallOutcome> {
        super::thread::bsd_result(m, self.ctx_addr, guard_result(kr), false);
        Some(crate::syscalls::SyscallOutcome::Continue)
    }
}

/// `abort_with_payload_internal`'s errno for `task_violated_guard`'s
/// return code: none for KERN_SUCCESS, ENOTSUP, EINVAL, else EBUSY.
pub(crate) fn guard_result(kr: u64) -> Result<u64, crate::errno::Errno> {
    match kr {
        KERN_SUCCESS => Ok(0),
        KERN_NOT_SUPPORTED => Err(super::errno::errno_of(45)),
        KERN_INVALID_ARGUMENT => Err(crate::errno::Errno::EINVAL),
        _ => Err(super::errno::errno_of(16)),
    }
}
