//! A `posix_spawn`'s child, in bytes, for a host that runs it apart from
//! its spawner (the page, where each process is a Worker of its own): the
//! Darwin task the spawner's call made for it (`forkproc`'s copies and
//! what the spawn's attributes set) and the image the call activated,
//! which the child's start takes up (its image switch, activation and
//! task enable, as the native host's `start_darwin_spawn` does in the
//! spawner's call).
//!
//! What crosses is what `darwin_fork_task` and the spawn set on the task;
//! the rest of it is a new process's, as the child's own host makes it.
//! A part of that rest which is not as a new process's has it cannot
//! cross: [`put_task`] names each such, for the host to report.

use super::ipc::wire::{get_exc, put_exc, Bad, Get, Put};
use super::Task;
use std::sync::atomic::Ordering::Acquire;
use std::sync::Arc;

fn put_cred(p: &mut Put, c: &super::cred::Cred) {
    for v in [c.uid, c.ruid, c.svuid, c.rgid, c.svgid, c.gmuid, c.flags] {
        p.u32(v);
    }
    p.len(c.groups.len());
    for &g in &c.groups {
        p.u32(g);
    }
}

fn get_cred(g: &mut Get<'_>) -> Result<super::cred::Cred, Bad> {
    let (uid, ruid, svuid, rgid, svgid, gmuid, flags) = (g.u32()?, g.u32()?, g.u32()?, g.u32()?, g.u32()?, g.u32()?, g.u32()?);
    let n = g.len()?;
    // `cr_groups`: NGROUPS at most.
    if n == 0 || n > 16 {
        return Err(g.bad("a credential's groups"));
    }
    let groups = (0..n).map(|_| g.u32()).collect::<Result<_, _>>()?;
    Ok(super::cred::Cred { uid, ruid, svuid, groups, rgid, svgid, gmuid, flags })
}

fn put_sigacts(p: &mut Put, s: &super::signal::Sigacts) {
    for i in 0..super::signal::NSIG {
        p.u64(s.handler[i]);
        p.u64(s.tramp[i]);
        p.u32(s.catchmask[i]);
    }
    for v in [s.siginfo, s.sigintr, s.sigonstack, s.sigreset, s.signodefer, s.sigignore, s.sigreturn_validation] {
        p.u32(v);
    }
    p.bool(s.nocldstop);
    p.bool(s.nocldwait);
    p.opt(s.si.as_ref(), |p, si| {
        p.i32(si.pid);
        p.u32(si.uid);
        p.u32(si.status);
        p.u32(si.code);
        p.u8(si.xhighbits);
    });
}

fn get_sigacts(g: &mut Get<'_>) -> Result<super::signal::Sigacts, Bad> {
    let mut s = super::signal::Sigacts::default();
    for i in 0..super::signal::NSIG {
        s.handler[i] = g.u64()?;
        s.tramp[i] = g.u64()?;
        s.catchmask[i] = g.u32()?;
    }
    s.siginfo = g.u32()?;
    s.sigintr = g.u32()?;
    s.sigonstack = g.u32()?;
    s.sigreset = g.u32()?;
    s.signodefer = g.u32()?;
    s.sigignore = g.u32()?;
    s.sigreturn_validation = g.u32()?;
    s.nocldstop = g.bool()?;
    s.nocldwait = g.bool()?;
    s.si = g.opt(|g| Ok(super::signal::Si { pid: g.i32()?, uid: g.u32()?, status: g.u32()?, code: g.u32()?, xhighbits: g.u8()? }))?;
    Ok(s)
}

fn put_mask(p: &mut Put, m: &super::sandbox::FilterMask) {
    p.bytes(&super::sandbox::mask_bytes(m));
}

fn get_mask(g: &mut Get<'_>) -> Result<super::sandbox::FilterMask, Bad> {
    let b = g.bytes()?;
    let b: [u8; super::sandbox::MASK_BYTES] = b.try_into().map_err(|_| g.bad("a filter mask"))?;
    Ok(super::sandbox::mask_of(b))
}

/// A task's filter mask: the same mask as its sandbox's `i`th (the two
/// one mask, which Sandbox's evaluator sets bits of for both), or one of
/// its own.
fn put_task_mask(p: &mut Put, m: Option<&super::sandbox::FilterMask>, sb: Option<&super::sandboxes::Sandbox>) {
    p.opt(m, |p, m| match sb.and_then(|sb| sb.masks.iter().position(|s| s.as_ref().is_some_and(|s| Arc::ptr_eq(s, m)))) {
        Some(i) => p.u8(i as u8),
        None => {
            p.u8(u8::MAX);
            put_mask(p, m);
        }
    });
}

fn get_task_mask(g: &mut Get<'_>, sb: Option<&super::sandboxes::Sandbox>) -> Result<Option<super::sandbox::FilterMask>, Bad> {
    g.opt(|g| match g.u8()? {
        u8::MAX => get_mask(g),
        i => sb.and_then(|sb| sb.masks.get(i as usize)?.clone()).ok_or_else(|| g.bad("a sandbox's filter mask")),
    })
}

fn put_pending(p: &mut Put, s: &super::sandboxes::Pending) {
    p.opt(s.script.as_deref(), |p, s| p.bytes(s.as_bytes()));
    p.opt(s.spawnattrs.as_deref(), |p, s| p.bytes(s));
    p.bool(s.marked);
}

fn get_pending(g: &mut Get<'_>) -> Result<super::sandboxes::Pending, Bad> {
    let script = g.opt(|g| String::from_utf8(g.bytes()?).map_err(|_| g.bad("a script's path")))?;
    Ok(super::sandboxes::Pending { script, spawnattrs: g.opt(|g| g.bytes())?, marked: g.bool()? })
}

fn put_launch(p: &mut Put, s: &super::launchcon::Spawn) {
    p.u8(s.launch_type);
    p.opt(s.amfi.as_deref(), |p, a| p.bytes(a));
}

fn get_launch(g: &mut Get<'_>) -> Result<super::launchcon::Spawn, Bad> {
    Ok(super::launchcon::Spawn { launch_type: g.u8()?, amfi: g.opt(|g| g.bytes())? })
}

fn put_objs(p: &mut Put, v: &[Option<super::ipc::ObjId>]) {
    p.len(v.len());
    for o in v {
        p.opt(o.as_ref(), |p, &o| p.u64(o));
    }
}

fn get_objs(g: &mut Get<'_>) -> Result<Vec<Option<super::ipc::ObjId>>, Bad> {
    let n = g.len()?;
    (0..n).map(|_| g.opt(|g| g.u64())).collect()
}

/// The parts of `t`, a spawned child's task, that are not as a new
/// process's has them and do not cross. Every field of the task is placed
/// here by what becomes of it (the destructure has no rest pattern, so a
/// field added to the task must be placed too): it crosses
/// ([`put_task`]), wholly or in part with the rest a new process's; the
/// child's host makes it again; the child's image switch replaces it
/// (`darwin_exec_switch_body`); or it is a new process's, which is checked
/// against a new task's.
fn uncarried(t: &Task) -> Vec<&'static str> {
    let fresh = Task::default();
    let mut lost = Vec::new();
    let differs = |a: &dyn std::fmt::Debug, b: &dyn std::fmt::Debug| format!("{a:?}") != format!("{b:?}");
    let Task {
        // Crosses.
        pthread: _,
        live: _,
        vtimer_bits: _,
        rlim_cpu: _,
        vfs_iopolicy: _,
        strict: _,
        platform: _,
        pidversion: _,
        pending_watchports: _,
        codesign: _,
        csflags: _,
        pcaction: _,
        persona: _,
        textoff: _,
        uniqueid: _,
        puniqueid: _,
        uuid: _,
        p_name: _,
        user_faults: _,
        cputype: _,
        start: _,
        cred: _,
        sugid: _,
        sandbox: _,
        filter_msg: _,
        syscall_mask: _,
        mach_trap_mask: _,
        kobj_mask: _,
        exec_sandbox: _,
        exec_launch: _,
        original_ppid: _,
        responsible_pid: _,
        ladvlock: _,
        sigacts: _,
        rlimits: _,
        disallow_mwl: _,
        workq_allow_sigmask: _,
        dispatchqueue_serialno_offset: _,
        dispatchqueue_label_offset: _,
        map_max: _,
        crash_behavior: _,
        crash_behavior_deadline: _,
        crash_count: _,
        throttle_timeout: _,
        map_min: _,
        task_uniqueid: _,
        // Crosses in part, the rest a new process's.
        rusage,
        kports,
        vouchers,
        ipc_raw,
        // Made again by the child's host: its job and policy cells (the
        // system's process table's), what it has said, the record it has
        // sent.
        job: _,
        policy: _,
        said: _,
        clock_said: _,
        record_sent: _,
        // Replaced by the child's image switch: its map's entries.
        vm: _,
        // A new process's.
        pending_replies,
        realtimer,
        vtimers,
        cpuusage,
        wakeups,
        threads,
        waits,
        ulocks,
        psynch,
        timers,
        iomfb_call,
        spawns,
        connect_wait,
        connect_waited,
        tcp_socks,
        tcp_socks_gen,
        tcp_watch,
        kcaller,
        read_from,
        child_ports,
        semas,
        mk_timers,
        workq,
        workq_wake,
        in_callout,
        callout_pidle,
        callout_woken,
        workq_creator_pending,
        threadreqs,
        next_threadreq,
        kevents,
        vmrsrcowner,
        fork_ids,
        activated,
        lock_wakes,
        ttyops,
        custom_stack,
        spawn_failed,
        syscall_exit,
        crash_notify,
        corpse,
        corpse_forks,
        corpse_fork_results,
        bt_deliveries,
        bt_daemon,
        corpse_source,
        fault_code,
        ktriage_unmodelled,
        rpc_reply,
        rpc_replies,
        footprint_due,
        footprint_releasing,
        sema_wake,
        pending_send,
        pending_send_buf,
        guard_kill,
        fd_guard,
        aio,
        ca_client_wi,
        psem_waits,
        eventlink_waits,
        image_files,
        no_attach,
        p_debugger,
        force_quota,
        stop,
        job_event,
    } = t;
    macro_rules! new_process {
        ($($f:ident),* $(,)?) => {
            $(
                if differs($f, &fresh.$f) {
                    lost.push(stringify!($f));
                }
            )*
        };
    }
    new_process!(
        pending_replies, realtimer, vtimers, cpuusage, wakeups, threads, waits, ulocks, psynch, timers, iomfb_call, spawns, connect_wait, connect_waited, tcp_socks, tcp_socks_gen, tcp_watch, kcaller, read_from, child_ports, semas, mk_timers, workq, workq_wake, in_callout, callout_pidle, callout_woken, workq_creator_pending, threadreqs, next_threadreq, kevents, vmrsrcowner, fork_ids, activated, lock_wakes, ttyops, custom_stack, spawn_failed, syscall_exit, crash_notify, corpse, corpse_forks, corpse_fork_results, bt_deliveries, bt_daemon, corpse_source, fault_code, ktriage_unmodelled, rpc_reply, rpc_replies, footprint_due, footprint_releasing, sema_wake, pending_send, pending_send_buf, guard_kill, fd_guard, aio, ca_client_wi, psem_waits, eventlink_waits, image_files, no_attach, p_debugger, force_quota, stop, job_event,
    );
    // Its usage's start crosses; the rest of its usage is a new
    // process's, but for its objects' owner's pid, which its publishing
    // set (`darwin_publish`, as the child's start does again), and its
    // meter's submaps and entries with `use_pmap` off, its map's (the
    // shared region's it inherited, nested or unnested where its parent
    // wrote it, and the parent's purgeable and tagged objects' entries),
    // which the image switch's new map and its entry into its region make
    // again.
    let new_usage = super::rusage::Shared::new(rusage.start_abstime.load(Acquire));
    new_usage.meter.owner().set_pid(rusage.meter.owner().pid());
    *new_usage.meter.submaps.lock().unwrap_or_else(|e| e.into_inner()) = rusage.meter.submaps.lock().unwrap_or_else(|e| e.into_inner()).clone();
    *new_usage.meter.alt.lock().unwrap_or_else(|e| e.into_inner()) = rusage.meter.alt.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if differs(rusage, &new_usage) {
        lost.push("rusage");
    }
    // The rights ipc_task_init gave it cross; its task's own ports are
    // made when its task is enabled.
    let given = super::kobject::Kports { special: kports.special.clone(), special_dead: kports.special_dead.clone(), registered: kports.registered, exc: kports.exc, ..Default::default() };
    if differs(kports, &given) {
        lost.push("kports");
    }
    // The ids task_bank_init recorded cross; its bank context is made
    // when it is first asked for.
    let banked = match vouchers.bank_ids() {
        Some((uid, gid)) => super::voucher::Vouchers::forked(uid, gid),
        None => super::voucher::Vouchers::default(),
    };
    if differs(vouchers, &banked) {
        lost.push("vouchers");
    }
    lost.extend(ipc_raw.uncarried());
    lost
}

/// Put the spawned child's task `t`; the names of the parts of it that
/// are not as a new process's and do not cross ([`uncarried`]).
pub fn put_task(t: &Task, p: &mut Put) -> Vec<&'static str> {
    let mut lost = Vec::new();
    // The new process's: its ids and start (`forkproc`'s), its usage's
    // start.
    p.u64(t.uniqueid);
    p.i32(t.pidversion);
    p.u64(t.start.0);
    p.u64(t.start.1);
    p.u64(t.rusage.start_abstime.load(Acquire));
    p.u64(t.task_uniqueid);
    p.u64(t.puniqueid);
    p.i32(t.original_ppid);
    p.i32(t.responsible_pid);
    // `p_forkcopy`'s and the proc's.
    let l = &t.live;
    for v in [l.sigignore.load(Acquire), l.sigcatch.load(Acquire), l.acflag.load(Acquire), l.argc.load(Acquire), l.argslen.load(Acquire)] {
        p.u32(v);
    }
    p.u64(l.user_stack.load(Acquire));
    let (itv, rtime) = *l.realtimer.lock().unwrap_or_else(|e| e.into_inner());
    p.u64(itv.interval);
    p.u64(itv.value);
    p.u64(rtime);
    let r = &t.pthread;
    p.bool(r.registered);
    for v in [r.threadstart, r.wqthread, r.pthsize, r.tsd_offset, r.dispatch_queue_offset, r.return_to_kernel_offset, r.mach_thread_self_offset, r.wq_quantum_offset, r.stack_addr_hint] {
        p.u64(v);
    }
    p.u32(t.vtimer_bits);
    p.u64(t.rlim_cpu.0 as u64);
    p.i32(t.rlim_cpu.1);
    p.u32(t.vfs_iopolicy);
    p.u32(t.workq_allow_sigmask);
    p.u32(t.pcaction.load(Acquire));
    p.u32(t.csflags.load(Acquire));
    p.bool(t.strict);
    p.u32(t.platform.0);
    p.u32(t.platform.1);
    p.u64(t.dispatchqueue_serialno_offset);
    p.u64(t.dispatchqueue_label_offset);
    put_sigacts(p, &t.sigacts);
    for [cur, max] in t.rlimits.0 {
        p.u64(cur);
        p.u64(max);
    }
    p.u64(t.textoff as u64);
    p.u32(t.cputype.0);
    p.u32(t.cputype.1);
    p.bytes(&t.uuid);
    p.bytes(&t.p_name.0);
    p.u32(t.user_faults);
    p.u64(t.map_max);
    p.u64(t.map_min);
    p.u8(t.crash_behavior);
    p.u64(t.crash_behavior_deadline);
    p.u32(t.crash_count);
    p.u32(t.throttle_timeout);
    p.bool(t.ladvlock);
    p.bool(t.disallow_mwl);
    // Its credential, Sandbox label and masks, signature, persona.
    put_cred(p, &t.cred);
    p.bool(t.sugid);
    let sb = super::sandboxes::of(&t.sandbox);
    p.opt(sb.as_deref(), |p, s| s.put(p));
    p.bool(t.filter_msg);
    for m in [&t.syscall_mask, &t.mach_trap_mask, &t.kobj_mask] {
        put_task_mask(p, m.as_ref(), sb.as_deref());
    }
    p.opt(t.codesign.as_ref(), |p, c| c.put(p));
    p.opt(t.persona.as_ref(), |p, q| q.put(p));
    // The rights `ipc_task_init` gave it, of the system's IPC table.
    let k = &t.kports;
    let mut special: Vec<_> = k.special.iter().map(|(&w, &o)| (w, o)).collect();
    special.sort_unstable();
    p.len(special.len());
    for (w, o) in special {
        p.i32(w);
        p.u64(o);
    }
    let mut dead: Vec<_> = k.special_dead.iter().copied().collect();
    dead.sort_unstable();
    p.len(dead.len());
    for w in dead {
        p.i32(w);
    }
    put_objs(p, &k.registered);
    put_exc(p, &k.exc);
    p.opt(t.pending_watchports.as_ref(), |p, (ports, adaptive)| {
        put_objs(p, ports);
        p.bool(*adaptive);
    });
    p.bool(t.vouchers.bank_ids().is_some());
    if let Some((uid, gid)) = t.vouchers.bank_ids() {
        p.u32(uid);
        p.u32(gid);
    }
    // What the exec in progress keeps for its hooks.
    p.opt(t.exec_sandbox.as_ref(), put_pending);
    p.opt(t.exec_launch.as_ref(), put_launch);
    // Its task's key in the system's IPC table, if its spawn gave it one.
    p.u64(t.ipc_raw.task);
    lost.extend(uncarried(t));
    lost
}

/// The task [`put_task`] put.
pub fn get_task(g: &mut Get<'_>) -> Result<Task, Bad> {
    use std::sync::atomic::{AtomicU32, AtomicU64};
    let uniqueid = g.u64()?;
    let pidversion = g.i32()?;
    let start = (g.u64()?, g.u64()?);
    let abs = g.u64()?;
    let mut t = Task::forked_process(uniqueid, pidversion, start, abs);
    t.task_uniqueid = g.u64()?;
    t.puniqueid = g.u64()?;
    t.original_ppid = g.i32()?;
    t.responsible_pid = g.i32()?;
    let (sigignore, sigcatch, acflag, argc, argslen) = (g.u32()?, g.u32()?, g.u32()?, g.u32()?, g.u32()?);
    let user_stack = g.u64()?;
    let itv = super::itimer::Itimerval { interval: g.u64()?, value: g.u64()? };
    let rtime = g.u64()?;
    t.live = Arc::new(super::kinfo::Live {
        sigignore: AtomicU32::new(sigignore),
        sigcatch: AtomicU32::new(sigcatch),
        realtimer: std::sync::Mutex::new((itv, rtime)),
        acflag: AtomicU32::new(acflag),
        argc: AtomicU32::new(argc),
        argslen: AtomicU32::new(argslen),
        user_stack: AtomicU64::new(user_stack),
    });
    let registered = g.bool()?;
    let mut w = [0u64; 9];
    for v in w.iter_mut() {
        *v = g.u64()?;
    }
    let [threadstart, wqthread, pthsize, tsd_offset, dispatch_queue_offset, return_to_kernel_offset, mach_thread_self_offset, wq_quantum_offset, stack_addr_hint] = w;
    t.pthread = super::thread::Registration { registered, threadstart, wqthread, pthsize, tsd_offset, dispatch_queue_offset, return_to_kernel_offset, mach_thread_self_offset, wq_quantum_offset, stack_addr_hint };
    t.vtimer_bits = g.u32()?;
    t.rlim_cpu = (g.u64()? as i64, g.i32()?);
    t.vfs_iopolicy = g.u32()?;
    t.workq_allow_sigmask = g.u32()?;
    t.pcaction = Arc::new(AtomicU32::new(g.u32()?));
    t.csflags = Arc::new(AtomicU32::new(g.u32()?));
    t.strict = g.bool()?;
    t.platform = (g.u32()?, g.u32()?);
    t.dispatchqueue_serialno_offset = g.u64()?;
    t.dispatchqueue_label_offset = g.u64()?;
    t.sigacts = get_sigacts(g)?;
    for l in t.rlimits.0.iter_mut() {
        *l = [g.u64()?, g.u64()?];
    }
    t.textoff = g.u64()? as i64;
    t.cputype = (g.u32()?, g.u32()?);
    t.uuid = g.bytes()?.try_into().map_err(|_| g.bad("a UUID"))?;
    t.p_name = super::reason::PName(g.bytes()?.try_into().map_err(|_| g.bad("p_name"))?);
    t.user_faults = g.u32()?;
    t.map_max = g.u64()?;
    t.map_min = g.u64()?;
    t.crash_behavior = g.u8()?;
    t.crash_behavior_deadline = g.u64()?;
    t.crash_count = g.u32()?;
    t.throttle_timeout = g.u32()?;
    t.ladvlock = g.bool()?;
    t.disallow_mwl = g.bool()?;
    t.cred = get_cred(g)?;
    t.sugid = g.bool()?;
    let sb = g.opt(super::sandboxes::Sandbox::get)?.map(Arc::new);
    t.filter_msg = g.bool()?;
    t.syscall_mask = get_task_mask(g, sb.as_deref())?;
    t.mach_trap_mask = get_task_mask(g, sb.as_deref())?;
    t.kobj_mask = get_task_mask(g, sb.as_deref())?;
    t.sandbox = Arc::new(std::sync::Mutex::new(sb));
    t.codesign = g.opt(super::codesign::CodeSign::get)?;
    t.persona = g.opt(super::persona::Persona::get)?;
    let n = g.len()?;
    for _ in 0..n {
        let w = g.i32()?;
        t.kports.special.insert(w, g.u64()?);
    }
    let n = g.len()?;
    for _ in 0..n {
        t.kports.special_dead.insert(g.i32()?);
    }
    let reg = get_objs(g)?;
    t.kports.registered = reg.try_into().map_err(|_| g.bad("the registered ports"))?;
    t.kports.exc = get_exc(g)?;
    t.pending_watchports = g.opt(|g| Ok((get_objs(g)?, g.bool()?)))?;
    if g.bool()? {
        t.vouchers = super::voucher::Vouchers::forked(g.u32()?, g.u32()?);
    }
    t.exec_sandbox = g.opt(get_pending)?;
    t.exec_launch = g.opt(get_launch)?;
    t.ipc_raw.task = g.u64()?;
    Ok(t.with_wire_ledger())
}

/// Put a spawn's `After`.
fn put_after(p: &mut Put, a: &super::spawn::After) {
    p.u32(a.flags.into());
    p.u8(a.policy.0);
    p.u8(a.policy.1);
    p.u8(a.policy.2);
    p.u32(a.sigmask);
    p.u32(a.sigdefault);
    p.len(a.inherit.len());
    for &fd in &a.inherit {
        p.i32(fd);
    }
    p.u64(a.max_addr);
    p.u8(a.crash_behavior);
    p.u64(a.crash_behavior_deadline);
    p.u32(a.crash_count);
    p.u32(a.throttle_timeout);
    p.opt(a.pcontrol, |p, c| p.i32(c));
    p.u64(a.cpumonitor.0);
    p.u64(a.cpumonitor.1);
    p.bool(a.bad_psattr);
}

fn get_after(g: &mut Get<'_>) -> Result<super::spawn::After, Bad> {
    let flags = u16::try_from(g.u32()?).map_err(|_| g.bad("a spawn's flags"))?;
    let policy = (g.u8()?, g.u8()?, g.u8()?);
    let (sigmask, sigdefault) = (g.u32()?, g.u32()?);
    let n = g.len()?;
    let inherit = (0..n).map(|_| g.i32()).collect::<Result<_, _>>()?;
    Ok(super::spawn::After {
        flags,
        policy,
        sigmask,
        sigdefault,
        inherit,
        max_addr: g.u64()?,
        crash_behavior: g.u8()?,
        crash_behavior_deadline: g.u64()?,
        crash_count: g.u32()?,
        throttle_timeout: g.u32()?,
        pcontrol: g.opt(|g| g.i32())?,
        cpumonitor: (g.u64()?, g.u64()?),
        bad_psattr: g.bool()?,
    })
}

/// Put the image a spawn activated for its child.
pub fn put_image(img: &super::execve::Image, p: &mut Put) {
    p.bytes(img.path.as_bytes());
    p.u64(img.arch_offset);
    p.u64(img.arch_size);
    p.u32(img.cputype);
    p.u32(img.cpusubtype);
    img.strings.put(p);
    p.opt(img.spawn.as_ref(), put_after);
    let l = &img.load;
    p.opt(l.sig.as_deref(), |p, c| c.put(p));
    p.u32(l.csflags);
    p.bytes(&l.uuid);
    p.u32(l.cputype.0);
    p.u32(l.cputype.1);
    put_pending(p, &img.sandbox);
    p.opt(img.launch.as_ref(), put_launch);
    p.u32(img.setid.uid);
    p.u32(img.setid.gid);
    p.u32(img.setid.bits);
    p.u64(img.thread_id);
}

/// The image [`put_image`] put.
pub fn get_image(g: &mut Get<'_>) -> Result<super::execve::Image, Bad> {
    let path = String::from_utf8(g.bytes()?).map_err(|_| g.bad("an image's path"))?;
    let (arch_offset, arch_size, cputype, cpusubtype) = (g.u64()?, g.u64()?, g.u32()?, g.u32()?);
    let strings = super::exec::Strings::get(g)?;
    let spawn = g.opt(get_after)?;
    let sig = g.opt(super::codesign::CodeSign::get)?.map(Arc::new);
    let csflags = g.u32()?;
    let uuid = g.bytes()?.try_into().map_err(|_| g.bad("an image's UUID"))?;
    let load = super::codesign::LoadResult { sig, csflags, uuid, cputype: (g.u32()?, g.u32()?) };
    let sandbox = get_pending(g)?;
    let launch = g.opt(get_launch)?;
    let setid = super::execve::SetId { uid: g.u32()?, gid: g.u32()?, bits: g.u32()? };
    let thread_id = g.u64()?;
    Ok(super::execve::Image { path, arch_offset, arch_size, cputype, cpusubtype, strings, spawn, load, sandbox, launch, setid, thread_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscalls::Kernel;
    use std::sync::atomic::Ordering::Release;

    fn bytes_of(t: &Task) -> Vec<u8> {
        let mut p = Put::default();
        assert!(put_task(t, &mut p).is_empty());
        p.0
    }

    /// Every part of a spawned child's task that crosses comes back as it
    /// went, and puts the same bytes again.
    #[test]
    fn a_spawned_task_crosses_whole() {
        let k = Kernel::new(0x1000, 0x10000, "/prog".into());
        let mut t = k.darwin_fork_task();
        t.task_uniqueid = 77;
        t.puniqueid = 5;
        t.original_ppid = 9;
        t.responsible_pid = 8;
        t.live.sigignore.store(0x11, Release);
        t.live.sigcatch.store(0x22, Release);
        t.live.acflag.store(1, Release);
        t.live.argc.store(3, Release);
        t.live.argslen.store(40, Release);
        t.live.user_stack.store(0x1_6fdf_0000, Release);
        t.pthread.registered = true;
        t.pthread.stack_addr_hint = 0x1_7000_0000;
        t.pthread.tsd_offset = 0xe0;
        t.vtimer_bits = 4;
        t.rlim_cpu = (30, 0);
        t.vfs_iopolicy = 0x42;
        t.workq_allow_sigmask = 1 << 13;
        t.pcaction.store(3, Release);
        t.csflags.store(0x2000_0301, Release);
        t.strict = true;
        t.platform = (2, 0x000f_0000);
        t.dispatchqueue_serialno_offset = 0x18;
        t.dispatchqueue_label_offset = 0x78;
        t.sigacts.handler[2] = 0x1000_4000;
        t.sigacts.catchmask[2] = 0x10;
        t.sigacts.nocldwait = true;
        t.sigacts.si = Some(super::super::signal::Si { pid: 4, uid: 501, status: 9, code: 2, xhighbits: 1 });
        t.rlimits.0[0] = [60, 120];
        t.textoff = 0x4000;
        t.cputype = (0x0100_000c, 2);
        t.uuid = [7; 16];
        t.p_name.0[..4].copy_from_slice(b"prog");
        t.user_faults = 2;
        t.map_max = 0x10_0000_0000;
        t.map_min = 0x4000;
        t.crash_behavior = 1;
        t.crash_behavior_deadline = 99;
        t.crash_count = 3;
        t.throttle_timeout = 4;
        t.ladvlock = true;
        t.cred = super::super::cred::Cred::of(501, 20);
        t.cred.groups.push(12);
        t.sugid = true;
        t.filter_msg = true;
        t.syscall_mask = Some(super::super::sandbox::mask_of([0xa5; super::super::sandbox::MASK_BYTES]));
        t.kports.special.insert(4, 0x30);
        t.kports.special_dead.insert(9);
        t.kports.registered = [Some(0x31), None, Some(0x32)];
        t.kports.exc[1].port = Some(super::super::ipc::right::Carried::Port(0x33));
        t.kports.exc[1].behavior = 3;
        t.pending_watchports = Some((vec![Some(0x34), None], true));
        t.vouchers = super::super::voucher::Vouchers::forked(501, 20);
        t.exec_sandbox = Some(super::super::sandboxes::Pending { script: Some("/bin/s".into()), spawnattrs: Some(vec![1, 2]), marked: true });
        t.exec_launch = Some(super::super::launchcon::Spawn { launch_type: 2, amfi: Some(vec![3]) });
        let b = bytes_of(&t);
        let mut g = Get::new(&b);
        let u = get_task(&mut g).unwrap();
        assert!(g.done());
        assert_eq!(bytes_of(&u), b);
        assert_eq!((u.uniqueid, u.pidversion, u.start, u.task_uniqueid, u.puniqueid, u.original_ppid, u.responsible_pid), (t.uniqueid, t.pidversion, t.start, 77, 5, 9, 8));
        assert_eq!(u.rusage.start_abstime.load(Acquire), t.rusage.start_abstime.load(Acquire));
        assert_eq!((u.live.sigcatch.load(Acquire), u.live.argslen.load(Acquire), u.live.user_stack.load(Acquire)), (0x22, 40, 0x1_6fdf_0000));
        assert!(u.pthread.registered && u.pthread.stack_addr_hint == 0x1_7000_0000 && u.pthread.tsd_offset == 0xe0);
        assert_eq!((u.vfs_iopolicy, u.workq_allow_sigmask, u.pcaction.load(Acquire), u.csflags.load(Acquire)), (0x42, 1 << 13, 3, 0x2000_0301));
        assert_eq!((u.sigacts.handler[2], u.sigacts.catchmask[2], u.sigacts.nocldwait, u.sigacts.si), (0x1000_4000, 0x10, true, t.sigacts.si));
        assert_eq!(u.rlimits, t.rlimits);
        assert_eq!((u.textoff, u.cputype, u.uuid, &u.p_name.0[..4]), (0x4000, (0x0100_000c, 2), [7; 16], &b"prog"[..]));
        assert_eq!(u.cred, t.cred);
        assert!(u.sugid && u.filter_msg && u.strict && u.ladvlock);
        assert_eq!(super::super::sandbox::mask_bytes(u.syscall_mask.as_ref().unwrap()), [0xa5; super::super::sandbox::MASK_BYTES]);
        assert!(u.mach_trap_mask.is_none());
        assert_eq!((u.kports.special.get(&4), u.kports.special_dead.contains(&9), u.kports.registered), (Some(&0x30), true, [Some(0x31), None, Some(0x32)]));
        assert_eq!((u.kports.exc[1].port, u.kports.exc[1].behavior), (t.kports.exc[1].port, 3));
        assert_eq!(u.pending_watchports, Some((vec![Some(0x34), None], true)));
        assert_eq!(u.vouchers.bank_ids(), Some((501, 20)));
        assert_eq!(u.exec_sandbox.as_ref().map(|s| (s.script.clone(), s.marked)), Some((Some("/bin/s".into()), true)));
        assert_eq!(u.exec_launch.as_ref().map(|s| s.launch_type), Some(2));
    }

    /// A spawning task that wrote the shared region (one twig of its
    /// submap entry unnested, `use_pmap` off there) hands its child a map
    /// whose submap and unnested parts its meter shows: those are the
    /// map's, which the child's image switch makes again, not usage that
    /// fails to cross.
    #[test]
    fn an_unnested_region_twig_does_not_keep_the_child_from_crossing() {
        use super::super::vm::{kind, Attrs};
        const TWIG: u64 = 32 << 20;
        let mut k = Kernel::new(0x1000, 0x10000, "/prog".into());
        let (base, size) = (0x1_8000_0000, 4 * TWIG);
        k.dtask.vm.enter(base, base + size, Attrs { kind: kind::SUBMAP, ..Attrs::default() }, 0);
        k.dtask.vm.update(base + TWIG, base + 2 * TWIG, |a| a.alt = true);
        k.dtask.vm.fork(&[(base, base + size)]);
        let t = k.darwin_fork_task();
        assert_eq!(*t.rusage.meter.alt.lock().unwrap(), vec![(base + TWIG, base + 2 * TWIG)]);
        assert_eq!(*t.rusage.meter.submaps.lock().unwrap(), vec![(base, base + TWIG), (base + 2 * TWIG, base + size)]);
        let mut p = Put::default();
        assert_eq!(put_task(&t, &mut p), Vec::<&str>::new());
    }

    /// A child with state a new process has not cannot cross whole: the
    /// part is named.
    #[test]
    fn what_cannot_cross_is_named() {
        let k = Kernel::new(0x1000, 0x10000, "/prog".into());
        let mut t = k.darwin_fork_task();
        t.kports.resume = Some(1);
        t.spawn_failed = true;
        t.tcp_watch = true;
        let mut p = Put::default();
        assert_eq!(put_task(&t, &mut p), vec!["tcp_watch", "spawn_failed", "kports"]);
    }

    /// A spawn's image crosses as it went.
    #[test]
    fn a_spawned_image_crosses_whole() {
        let mut strings = super::super::exec::Strings::new();
        strings.save_path(b"/usr/bin/true").unwrap();
        let after = super::super::spawn::After { flags: 0x80, policy: (1, 2, 3), sigmask: 4, sigdefault: 5, inherit: vec![0, 2], max_addr: 6, crash_behavior: 7, crash_behavior_deadline: 8, crash_count: 9, throttle_timeout: 10, pcontrol: Some(2), cpumonitor: (11, 12), bad_psattr: true };
        let img = super::super::execve::Image {
            path: "/usr/bin/true".into(),
            arch_offset: 0x4000,
            arch_size: 0x8000,
            cputype: 0x0100_000c,
            cpusubtype: 2,
            strings,
            spawn: Some(after),
            load: super::super::codesign::LoadResult { sig: None, csflags: 0x301, uuid: [3; 16], cputype: (0x0100_000c, 2) },
            sandbox: super::super::sandboxes::Pending { script: None, spawnattrs: None, marked: false },
            launch: Some(super::super::launchcon::Spawn { launch_type: 1, amfi: None }),
            setid: super::super::execve::SetId { uid: 0, gid: 0, bits: 0o4755 },
            thread_id: 0,
        };
        let mut p = Put::default();
        put_image(&img, &mut p);
        let b = p.0;
        let mut g = Get::new(&b);
        let back = get_image(&mut g).unwrap();
        assert!(g.done());
        let mut q = Put::default();
        put_image(&back, &mut q);
        assert_eq!(q.0, b);
        assert_eq!(back.strings.path(), b"/usr/bin/true");
        let a = back.spawn.unwrap();
        assert_eq!((a.flags, a.policy, a.inherit, a.pcontrol, a.cpumonitor, a.bad_psattr), (0x80, (1, 2, 3), vec![0, 2], Some(2), (11, 12), true));
        assert_eq!((back.load.csflags, back.load.uuid, back.setid.bits, back.launch.map(|l| l.launch_type)), (0x301, [3; 16], 0o4755, Some(1)));
    }
}
