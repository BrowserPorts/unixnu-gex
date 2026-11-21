//! A Darwin process in the page: the boot payload the page gives it, and
//! its program started as the native host starts `gexc run`'s first one
//! (hosts/native/src/lib.rs `run_process` and `place_image`). Its Worker
//! is a Darwin one from the start (lib.rs `gex_set_darwin`); the system it
//! boots is this Worker's, as the Darwin kernel's system state is the
//! shim's (one Darwin process per system, until that state is the global
//! kernel's).

use super::*;

/// The boot payload's files, by name (`gex_darwin_boot_file`), as gexc
/// reads them from GEX_DARWIN_BOOT; a file the page did not give is absent.
static BOOT: std::sync::Mutex<Vec<(String, Vec<u8>)>> = std::sync::Mutex::new(Vec::new());

/// GEX_DARWIN_STRICT's: a Darwin process stops at anything gex reports it
/// does not do (`gex_darwin_set_strict`).
static STRICT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// One of the boot payload's files (page/runtime System's `darwin.boot`),
/// before the Darwin program's exec: `name` and the bytes, in this
/// module's heap (`gex_alloc`).
#[no_mangle]
pub extern "C" fn gex_darwin_boot_file(name: u32, name_len: u32, data: u32, data_len: u32) {
    let name = String::from_utf8_lossy(shim_slice(name, name_len)).into_owned();
    let bytes = shim_slice(data, data_len).to_vec();
    let mut b = BOOT.lock().unwrap_or_else(|e| e.into_inner());
    b.retain(|(n, _)| *n != name);
    b.push((name, bytes));
}

/// Whether the Darwin process stops at anything reported as not done
/// (GEX_DARWIN_STRICT=1 natively).
#[no_mangle]
pub extern "C" fn gex_darwin_set_strict(on: u32) {
    STRICT.store(on != 0, std::sync::atomic::Ordering::Relaxed);
}

/// The payload's file `name`, if the page gave it.
fn boot_file(name: &str) -> Option<Vec<u8>> {
    BOOT.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|(n, _)| n == name).map(|(_, b)| b.clone())
}

/// Why a Darwin program did not start.
enum Fail {
    /// It could not be loaded, or its system could not boot: said, and the
    /// process ends as one whose program could not be run (127).
    Load(String),
    /// Its image could not start (`darwin_start`'s error, exec's
    /// `badtoolate`): its task ended and the process killed (SIGKILL), as
    /// the native host ends it.
    Killed(String),
}

/// The exec of a Darwin program the page started, in this Darwin Worker's
/// fresh memory (vfork.rs `gex_adopted_exec`): its entry, or 0 when it did
/// not start (the process has then ended).
pub(crate) fn exec(h: &mut Host, path: &str, argv: &[String], envp: &[String]) -> u64 {
    match start(h, path, argv, envp) {
        Ok(entry) => entry,
        Err(Fail::Load(why)) => {
            warn_line(&format!("gex: {path}: {why}\n"));
            exit_process(127);
            0
        }
        Err(Fail::Killed(why)) => {
            warn_line(&format!("gex: {path}: killed by signal 9 (exec: {why})\n"));
            h.kernel.darwin_task_terminate();
            h.kernel.close_all_fds();
            exit_process(-9);
            0
        }
    }
}

fn start(h: &mut Host, path: &str, argv: &[String], envp: &[String]) -> Result<u64, Fail> {
    use gex_kernel::darwin;
    use gex_kernel::mem::prot;
    let load = |s: String| Fail::Load(s);
    // Its memory is new (`EXEC_FRESH`): nothing to clear before the image.
    if !EXEC_FRESH.with(|c| c.replace(false)) {
        return Err(load("a Darwin program's exec on a memory another program ran in (an exec of a Darwin process goes through its kernel's execve)".into()));
    }
    // launchd boots as the kernel's first process, pid 1, which is the
    // page kernel's own here.
    if path == "/sbin/launchd" || h.kernel.pid == gex_kernel::proc::INIT_PID {
        return Err(load("launchd as the system's first process (pid 1, the page kernel's own here)".into()));
    }
    let Some(bytes) = h.kernel.read_file(path) else { return Err(load("cannot read it".into())) };
    let img = {
        let k = &h.kernel;
        darwin::image::load(&bytes, path, &|p: &str| k.read_file(p).ok_or_else(|| format!("cannot read {p}"))).map_err(load)?
    };
    // dyld and the shared cache it maps: the root's, from the boot's
    // graft of the OS cryptex on the disk's Preboot volume, which the page
    // does not give a Darwin system yet.
    if img.program.interp.is_some() {
        return Err(load(format!(
            "a dynamic Darwin program (it names {}), whose shared cache comes from the boot's graft of the OS cryptex (the disk0 image), which the page does not give its Darwin system yet",
            img.dylinker.as_deref().unwrap_or("dyld")
        )));
    }

    // The old image's translations and the generic part of an exec, as
    // `do_exec` makes them: a fresh map that grows on demand, the
    // process's names, its clocks.
    jit_in_held(&mut h.jit);
    jitout::EXEC_EPOCH.fetch_add(1, std::sync::atomic::Ordering::Release);
    ALT_DIR.store(0, std::sync::atomic::Ordering::Release);
    EXEC_GEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    note_exec(path, argv);
    {
        let mut mm = h.kernel.mem.lock();
        mm.renew(0);
        mm.grows_on_demand(arena_grow, arena_back);
        // Everything above its page zero is the process's to map
        // (`memmap::claim_fixed`), the memory grown over what it maps.
        mm.set_high_arena(gex_abi::DARWIN_GUEST_FLOOR, gex_abi::LIMIT64);
    }
    h.kernel.exe_path = path.to_string();
    h.kernel.argv = argv.to_vec();
    h.kernel.envp = envp.to_vec();
    wl::publish_process(&h.kernel);
    h.kernel.publish_proc(&h.proc_state.0);
    h.kernel.compat = false;
    gex_xlate::set_compat(false);
    if h.kernel.started == 0 {
        h.kernel.started = now_ns() as u128;
    }
    // (No `clock_constants`: a Darwin process's clock calls are its
    // kernel's, never the Linux ones served without the lock.)
    h.kernel.wasm32 = false;
    WASM32.store(false, std::sync::atomic::Ordering::Release);
    cgen::wasmprog::stage(None);
    h.kernel.live_threads.store(1, std::sync::atomic::Ordering::Release);
    let ctx_addr = h.threads[cur()].ctx_addr();
    h.kernel.next_ctx_slot.reset(ctx_slots_below(ctx_addr).max(1));

    // The system boots, with the page's payload (gexc's GEX_DARWIN_BOOT).
    h.kernel.darwin = true;
    let tc = boot_file("TrustCache");
    let sandbox = darwin::SandboxProfiles { platform: boot_file("sandbox_profile.bin"), builtin: boot_file("sandbox_builtin.bin"), protobox: boot_file("sandbox_protobox.bin") };
    let device_tree = boot_file("DeviceTree");
    // AppleImage4's Cryptex1 anchor, extracted from the kernelcache.
    if let Some(anchor) = boot_file("img4_anchor.der") {
        darwin::image4::set_anchor(anchor).map_err(|e| load(format!("the boot payload: {e}")))?;
    }
    // The system volume's owners, modes and flags.
    let mut volume_attrs = Vec::new();
    for vol in [darwin::volattrs::Vol::System] {
        if let Some(spec) = boot_file(vol.file()) {
            volume_attrs.push((vol, spec));
        }
    }
    // No Cryptex1 ticket, nonce hash or web device, and no NVRAM image:
    // the page gives none yet (each needs a medium of the page's).
    use darwin::preboot::{Sources, Ticket};
    let cryptex1 = Sources { ticket: Ticket::Unset, nonce_hash: None, web_device: None };
    darwin::boot(tc.as_deref(), sandbox, device_tree.as_deref(), volume_attrs, cryptex1, None).map_err(|e| load(format!("the boot payload: {e}")))?;
    // The SEP's inputs, none of which the page gives: what needs the SEP
    // stops and names what is missing.
    darwin::sep::set_inputs(darwin::sep::core::Inputs { sepos: None, seprom: None, device_dir: None }).map_err(load)?;
    // The process, of the user it runs as.
    let k = &mut h.kernel;
    let (uid, gid) = (k.creds.uid(), k.creds.gid());
    k.dtask.cred = darwin::cred::Cred::of(uid, gid);
    k.dtask.uniqueid = darwin::next_uniqueid();
    k.dtask.start = darwin::procinfo::microtime();
    k.signals.thread().set_darwin_id(darwin::next_thread_id());
    k.darwin_cred_tokens();
    k.darwin_use_pages();
    k.darwin_dyld_infos = img.dyld_infos;
    k.darwin_dyld_infos_size = img.dyld_infos_size;
    k.darwin_dyld_final = false;
    k.dtask.strict = STRICT.load(std::sync::atomic::Ordering::Relaxed);
    // Its thread calls, before anything can arm one.
    calls_init(k);
    k.dtask.platform = img.platform;
    // Exec'd as XNU execs its first process: the next pidversion, and the
    // task_uniqueid load_init_program's clones and exec leave it.
    k.dtask.pidversion = darwin::next_pidversion();
    let _ = darwin::next_task_uniqueid();
    let _ = darwin::next_task_uniqueid();
    k.dtask.task_uniqueid = darwin::next_task_uniqueid();
    k.darwin_signals_init();
    k.darwin_nofile_sync();
    // (No scheduler maintenance thread: the page runs none, and the
    // averages it would keep say so when asked, `Sched::check`.)
    // A system launchd has booted has its Preboot volume grafted: with
    // the disk0 image only, which the page does not give yet.
    k.darwin_boot_grafts();
    // Its first thread is in its task's list from the start.
    if k.sig_tid == 0 {
        let tid = k.tid;
        k.thread_sig(tid);
    }

    // The image: each segment where its headers say, the memory grown to
    // it (above the page zero, `arena_back`).
    let mut data = guest();
    for seg in img.program.segments() {
        let end = seg.vaddr + seg.mem_size;
        if !grow_memory_to(end) {
            return Err(load(format!("its segment {:#x}..{end:#x}: the memory will not grow to it", seg.vaddr)));
        }
        data.write(seg.vaddr, &seg.bytes).map_err(|_| load(format!("its segment {:#x}..{end:#x} is outside the memory", seg.vaddr)))?;
        let mut p = 0;
        if seg.readable {
            p |= prot::READ;
        }
        if seg.writable {
            p |= prot::WRITE;
        }
        if seg.executable {
            p |= prot::EXEC;
        }
        let k = &mut h.kernel;
        k.mem.lock().insert(seg.vaddr, end, p, "[image]");
        k.darwin_image_segment(seg.vaddr, seg.bytes.len() as u64, seg.mem_size, seg.file_offset, seg.max_prot);
    }
    h.kernel.dtask.map_min = img.program.exe.page_zero;
    // load_threadstack: an LC_UNIXTHREAD that names a stack has it as its
    // own, with nothing allocated; the default stack is made instead.
    if img.thread_stack != 0 {
        let sp = img.thread_stack;
        h.kernel.darwin_unimplemented(format!("an LC_UNIXTHREAD that names its stack ({sp:#x}, load_threadstack's custom stack): the default stack is made instead"));
    }
    // Its shared region, as it enters it at exec (`vm_map_exec`): with
    // pid 1 the page kernel's own, an empty one (the boot's holds the
    // cache launchd's dyld mapped, which a static program does not use).
    h.kernel.darwin_shared_region_enter(&mut data, false);
    // And its commpage, at the alias its constant addresses are folded to.
    {
        use darwin::commpage;
        let pages = commpage::pages(darwin::mig::machine::NCPUS as u8, 4 << 30);
        let (lo, hi) = (gex_abi::DARWIN_COMMPAGE_ALIAS, gex_abi::DARWIN_COMMPAGE_ALIAS + (gex_abi::DARWIN_COMMPAGE_END - gex_abi::DARWIN_COMMPAGE_RO));
        if !grow_memory_to(hi) {
            return Err(load(format!("its commpage at {lo:#x}: the memory will not grow to it")));
        }
        for (at, page) in commpage::placements().into_iter().zip(&pages) {
            data.write(at, page).map_err(|_| load(format!("its commpage at {at:#x} is outside the memory")))?;
        }
        h.kernel.mem.lock().insert(lo, hi, prot::READ, "[commpage]");
    }
    // Brought up to date every quantum by the process's thread-call
    // Worker, from before its first instruction.
    // Its main stack, the kernel's to lay out (`create_unix_stack`, the
    // `apple[]` strings, `exec_copyout_strings`).
    let header = img.program.exe.segments.iter().map(|s| s.vaddr).min().unwrap_or(0);
    let st = {
        let loaded = darwin::exec::Loaded {
            mach_header: header,
            dylinker: None,
            stacksize: img.stacksize,
            exe_path: path,
            file_start: 0,
            code_signature: img.code_signature.as_deref(),
            signature: None,
            nano: false,
        };
        h.kernel.darwin_start(None, &loaded, img.user_stack).map_err(|e| Fail::Killed(format!("starting {path}: errno {}", e.0)))?
    };
    if !grow_memory_to(st.alloc + st.size) {
        return Err(Fail::Killed(format!("its stack {:#x}..{:#x}: the memory will not grow to it", st.alloc, st.alloc + st.size)));
    }
    data.write(st.sp, &st.bytes).map_err(|_| Fail::Killed(format!("its stack at {:#x} is outside the memory", st.sp)))?;
    {
        let mut mm = h.kernel.mem.lock();
        mm.insert(st.alloc, st.alloc + st.guard, prot::NONE, "[stack]");
        mm.insert(st.alloc + st.guard, st.alloc + st.size, prot::READ | prot::WRITE, "[stack]");
    }
    // Its registers: clear, its stack pointer and its entry.
    let entry = img.program.exe.entry;
    let c = ctx_addr as usize;
    for i in 0..31u8 {
        write_u64(&mut data, c + ctx::x(i), 0);
    }
    write_u64(&mut data, c + ctx::SP, st.sp);
    write_u64(&mut data, c + ctx::PC, entry);
    write_u64(&mut data, c + ctx::MON_SIZE, 0);
    data.write((c + ctx::SAFEPOINT_COUNTER) as u64, &1024i32.to_le_bytes()).map_err(|_| load("its thread's context is outside the memory".into()))?;
    h.threads.reset(h.kernel.pid, ctx_addr, ThreadCell::new(Run::new(entry, Waiting::Runnable)));
    set_current(h, 0);
    darwin::workq::thread_started(h.kernel.tid);
    // Its thread-call Worker, which the page starts now.
    let _ = CALLS.compare_exchange(CALLS_CAN, CALLS_WANTED, std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Acquire);
    Ok(entry)
}

/// A Darwin process's task end, at its process's end (`proc_exit`): its
/// task terminated and its descriptors closed, as the native host ends
/// one, before the end is published; nothing for a Linux process.
pub(crate) fn task_end(k: &mut gex_kernel::syscalls::Kernel) {
    if k.darwin {
        k.darwin_task_terminate();
        k.close_all_fds();
        // Every thread still on a Worker of its own ends with it, as each
        // native host thread notes its end however its thread ended
        // (`run_guest_thread`'s guard).
        let left = std::mem::take(&mut *on_workers());
        for tid in left {
            gex_kernel::darwin::workq::thread_ended(tid);
        }
    }
}

/// The threads started on Workers of their own ([`adopted`]) that have not
/// ended: what [`task_end`] ends with the process.
fn on_workers() -> std::sync::MutexGuard<'static, Vec<i32>> {
    static ON: std::sync::Mutex<Vec<i32>> = std::sync::Mutex::new(Vec::new());
    ON.lock().unwrap_or_else(|e| e.into_inner())
}

/// Darwin thread `tid` has ended (`workq::thread_ended`), its Worker no
/// longer its.
pub(crate) fn thread_ended(tid: i32) {
    on_workers().retain(|&t| t != tid);
    gex_kernel::darwin::workq::thread_ended(tid);
}

/// The process's thread calls (`gex_kernel::darwin::timer`), run as the
/// native host runs them (hosts/native/src/lib.rs
/// `start_darwin_thread_calls`): on a Worker of their own, which sleeps
/// until the earliest armed deadline, a ring of the bell (an earlier one
/// armed), or a change to a pipe or socket with a knote on it, and fires
/// what is due with the kernel locked; and which brings the commpage up to
/// date every quantum (`commpage::tick`), as XNU does at a running
/// thread's quantum's end. The Worker parks on its wait slot (`waitq`),
/// which is on the process's queue (its end), a queue of its own that the
/// bell's rings notify ([`CALLS_Q`]), and the queues of the descriptors the
/// pipe watch looks at.
static CALLS_Q: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// The thread-call Worker's state: [`CALLS_NONE`] until the page says it
/// can start one, then wanted, taken by the page, and up.
static CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(CALLS_NONE);
const CALLS_NONE: u32 = 0;
const CALLS_CAN: u32 = 1;
const CALLS_WANTED: u32 = 2;
const CALLS_TAKEN: u32 = 3;
const CALLS_UP: u32 = 4;

/// What the pipe watch's registration was made for ([`watch_print`]): a
/// call that changes it tells the Worker ([`after_call`]).
static WATCHED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// A call changed what the pipe watch looks at since the Worker last
/// registered for it.
static REWATCH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Before a Darwin program's exec: the page starts its process's thread-call
/// Worker (`#adoptExec`). Only with the global kernel, whose wait slots and
/// queues the Worker sleeps on.
#[no_mangle]
pub extern "C" fn gex_darwin_runs_thread_calls() {
    if unsafe { k_present() } != 0 {
        let _ = CALLS.compare_exchange(CALLS_NONE, CALLS_CAN, std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Acquire);
    }
}

/// After a Darwin program's exec: 1 when the page is to start its
/// thread-call Worker now (once).
#[no_mangle]
pub extern "C" fn gex_darwin_calls_take() -> u32 {
    use std::sync::atomic::Ordering;
    u32::from(CALLS.compare_exchange(CALLS_WANTED, CALLS_TAKEN, Ordering::AcqRel, Ordering::Acquire).is_ok())
}

/// Whether the thread-call Worker is up: the program's first instruction
/// waits for it, as the native host starts its threads before it.
#[no_mangle]
pub extern "C" fn gex_darwin_calls_up() -> u32 {
    u32::from(CALLS.load(std::sync::atomic::Ordering::Acquire) == CALLS_UP)
}

/// The bell's rings, told to the thread-call Worker.
fn rung() {
    let q = CALLS_Q.load(std::sync::atomic::Ordering::Acquire);
    if q != 0 {
        unsafe { k_wq_notify(q) };
    }
}

/// At a Darwin program's exec, before anything is armed: the thread calls
/// are the page's to run when it can start their Worker, and reported as
/// never run otherwise (`darwin_thread_calls_unrun`), as is the commpage's
/// quantum update, which nothing else makes.
fn calls_init(k: &mut gex_kernel::syscalls::Kernel) {
    use std::sync::atomic::Ordering;
    if CALLS.load(Ordering::Acquire) != CALLS_CAN {
        k.darwin_unimplemented("the thread calls and the commpage's quantum update: the page runs no Worker for them here (no global kernel, or no Worker of a process's own), so a call armed never fires and the commpage's approximate time stays where the exec left it".into());
        return;
    }
    if CALLS_Q.load(Ordering::Acquire) == 0 {
        CALLS_Q.store(unsafe { k_wq_new() }, Ordering::Release);
    }
    gex_kernel::darwin::timer::set_ring_hook(rung);
    gex_kernel::darwin::timer::set_host_runs_thread_calls();
}

/// What the pipe watch looks at, in a word: its knotes and the process's
/// TCP sockets, by identity.
fn watch_print(k: &gex_kernel::syscalls::Kernel) -> u64 {
    let kev = &k.dtask.kevents;
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |v: u64| h = (h ^ v).wrapping_mul(0x0100_0000_01b3);
    mix(kev.pipe_klist.len() as u64);
    for n in &kev.pipe_klist {
        mix(*n);
    }
    mix(k.dtask.tcp_socks.len() as u64);
    for w in &k.dtask.tcp_socks {
        mix(w.as_ptr() as *const u8 as usize as u64);
    }
    h
}

/// After a Darwin call: a change to what the pipe watch looks at is told
/// to the thread-call Worker, which registers its slot for it afresh.
pub(crate) fn after_call(k: &gex_kernel::syscalls::Kernel) {
    use std::sync::atomic::Ordering;
    let q = CALLS_Q.load(Ordering::Acquire);
    if q == 0 || CALLS.load(Ordering::Acquire) < CALLS_WANTED {
        return;
    }
    if watch_print(k) != WATCHED.load(Ordering::Acquire) {
        REWATCH.store(true, Ordering::Release);
        unsafe { k_wq_notify(q) };
    }
}

/// How often a knote whose descriptor no event announces is looked at, as
/// the native host's pipe watch does.
const POLL: std::time::Duration = std::time::Duration::from_millis(10);

/// The thread-call Worker's run (`gex_darwin_thread_calls`, from the
/// Worker the page started for it): until the process ends or execs.
/// 0 when there is nothing to run.
#[no_mangle]
pub extern "C" fn gex_darwin_thread_calls() -> u32 {
    use gex_kernel::darwin::{commpage, mach, time::Instant};
    use std::sync::atomic::Ordering;
    let q = CALLS_Q.load(Ordering::Acquire);
    if q == 0 || CALLS.load(Ordering::Acquire) != CALLS_TAKEN || unsafe { k_present() } == 0 {
        return 0;
    }
    let gen = EXEC_GEN.load(Ordering::Acquire);
    let slot = waitq::slot();
    let proc_q = waitq::proc_queue();
    unsafe {
        k_wq_add(q, slot as u32);
        k_wq_add(proc_q, slot as u32);
    }
    let (bell, pipes) = with_exec_lock(|h| (h.kernel.darwin_timer_bell(), h.kernel.darwin_pipe_watch()));
    // The descriptors' queues the slot is on.
    let mut watched: Vec<u32> = Vec::new();
    let mut unqueued = false;
    let mut next_tick = Instant::now();
    let mut next_call: Option<Instant> = None;
    let mut next_poll: Option<Instant> = None;
    let mut seen: Option<u64> = None;
    let mut woken = false;
    loop {
        let seq = unsafe { k_ws_seq(slot) };
        if exited() || EXEC_GEN.load(Ordering::Acquire) != gen || bell.closed() {
            break;
        }
        // The commpage, every quantum (the native host's tick thread).
        let now = Instant::now();
        if now >= next_tick {
            commpage::tick(&mut guest(), mach::absolute_time());
            next_tick = Instant::now() + commpage::QUANTUM;
        }
        // The pipe watch: a pipe or socket with a knote changed (its queue
        // notified the slot), or one no event announces is due a look; or
        // what it looks at changed.
        let count = pipes.load(Ordering::Acquire);
        let polled = count >> 32 != 0 || unqueued;
        let poll_due = polled && next_poll.map_or(true, |t| Instant::now() >= t);
        let piped = count > 0 && (woken || poll_due);
        let rewatch = REWATCH.swap(false, Ordering::AcqRel);
        // The thread calls: the bell rang, or the earliest is due.
        let rang = seen != Some(bell.generation());
        let due = next_call.is_some_and(|t| Instant::now() >= t);
        if rang || due || piped || rewatch {
            seen = Some(bell.generation());
            woken = false;
            let out = with_exec_lock(|h| {
                if exited() {
                    return None;
                }
                let next = h.kernel.darwin_thread_calls(&mut guest());
                // The threads they woke (a kevent's, a Mach message's
                // receiver), in their Workers.
                self::woken(&mut h.kernel);
                WATCHED.store(watch_print(&h.kernel), Ordering::Release);
                Some((next, h.kernel.darwin_pipe_watch_queues()))
            });
            let Some((next, (queues, none))) = out else { break };
            next_call = next;
            unqueued = none;
            for &old in watched.iter().filter(|o| !queues.contains(o)) {
                unsafe { k_wq_del(old, slot as u32) };
            }
            for &new in queues.iter().filter(|n| !watched.contains(n)) {
                unsafe { k_wq_add(new, slot as u32) };
                // A change made before the slot was on its queue is looked
                // for at once.
                woken = true;
            }
            watched = queues;
            if poll_due || next_poll.is_none() {
                next_poll = Some(Instant::now() + POLL);
            }
            // The program's first instruction waits for this.
            let _ = CALLS.compare_exchange(CALLS_TAKEN, CALLS_UP, Ordering::AcqRel, Ordering::Acquire);
        }
        // Asleep until the next of these, or a notify.
        let now = Instant::now();
        let polled = pipes.load(Ordering::Acquire) >> 32 != 0 || unqueued;
        let until = [Some(next_tick), next_call, if polled { next_poll } else { None }].into_iter().flatten().min().expect("the next tick");
        let ns = if until > now { (until - now).as_nanos().min(i64::MAX as u128) as i64 } else { 0 };
        // On the word as it was sampled before the look above: a ring, a
        // change or a notify since then ends the sleep at once.
        let r = unsafe { k_ws_park(slot, seq, ns) };
        // 0: notified, 1: notified before it slept; 2: its time.
        woken |= r != 2;
    }
    let slot = slot as u32;
    for q2 in watched.into_iter().chain([q, proc_q]) {
        unsafe { k_wq_del(q2, slot) };
    }
    1
}

/// How a Darwin thread's way back to user space ended ([`to_user`]).
pub(crate) enum ToUser {
    /// It runs on where it was.
    Run,
    /// A handler frame was set up while it was held, or its registers were
    /// set while it was in the kernel: it goes on at this pc.
    Resume(u64),
    /// Its process ended while it was held, or a signal it took ends it
    /// (the status, `exit_process`'s; its task already ended).
    Exit(Option<i32>),
}

/// `thread_apc_ast` for this Worker's Darwin thread on its way back to user
/// space (after a call, at a safepoint, after its wait, at its start), as
/// the native host's `darwin_return_to_user` makes it: while its task is
/// held (stopped) or the thread suspended it waits, the signals posted
/// meanwhile acted on as they come, and an abort lets it take its signals
/// before it asks again (`Kernel::darwin_hold`). It waits on its wait slot,
/// on its process's queue (a signal, its end) and for 20 ms at most, as the
/// native host waits on its descriptors' changes.
pub(crate) fn to_user() -> ToUser {
    use gex_kernel::darwin::jobctl::Hold;
    use gex_kernel::signal::Delivery;
    let slot = waitq::slot();
    let mut queued = false;
    let mut resume = None;
    let out = loop {
        let seq = unsafe { k_ws_seq(slot) };
        let held = with_exec_lock(|h| {
            let i = cur();
            let ks = h.threads[i].kstate();
            h.kernel.enter_thread(&ks);
            let mut gm = guest();
            let held = h.kernel.darwin_hold(&mut gm, ks.tid);
            // Held or let go, the replies waiting for it to be off its
            // processor are sent (`darwin_set_offcpu`): their receivers'
            // wakes.
            woken(&mut h.kernel);
            match held {
                Hold::Deliver => {
                    let d = h.kernel.deliver_pending(&mut gm);
                    woken(&mut h.kernel);
                    if let Delivery::Terminate { .. } = d {
                        task_end(&mut h.kernel);
                    }
                    Err(d)
                }
                held => Ok(held),
            }
        });
        match held {
            Ok(Hold::Run) => break resume.map_or(ToUser::Run, ToUser::Resume),
            Ok(Hold::Resume(pc)) => break ToUser::Resume(resume.unwrap_or(pc)),
            Err(Delivery::None) => continue,
            Err(Delivery::Resume(t)) => {
                resume = Some(t);
                continue;
            }
            Err(Delivery::Terminate { signal, .. }) => break ToUser::Exit(Some(-(signal as i32))),
            Ok(Hold::Park) | Ok(Hold::Deliver) => {}
        }
        // The process ending in another thread lets it go, to end too.
        if exited() {
            break ToUser::Exit(None);
        }
        if !queued && unsafe { k_present() } != 0 {
            unsafe { k_wq_add(waitq::proc_queue(), slot as u32) };
            queued = true;
        }
        unsafe { k_ws_park(slot, seq, HOLD_LOOK.as_nanos() as i64) };
    };
    if queued {
        unsafe { k_wq_del(waitq::proc_queue(), slot as u32) };
    }
    out
}

/// How often a held thread asks again with nothing having told it, as the
/// native host's does.
const HOLD_LOOK: std::time::Duration = std::time::Duration::from_millis(20);

/// [`to_user`] for this Worker's thread, which is to go on at `pc`: where
/// it goes on, or `None` when it does not (its process has ended, here or
/// in another thread).
pub(crate) fn to_user_at(pc: u64) -> Option<u64> {
    match to_user() {
        ToUser::Run => Some(pc),
        ToUser::Resume(t) => Some(t),
        ToUser::Exit(Some(code)) => {
            exit_here(code, Some(pc));
            None
        }
        ToUser::Exit(None) => None,
    }
}

/// A fault a Darwin thread takes at `pc`, the kernel's to raise
/// (`raise` makes it: `raise_fault`, `darwin_access_fault`), with the
/// kernel lock: its handler's frame or the access made again, the target
/// returned; or its process's end of the signal, its task with it (`None`:
/// the process has ended).
pub(crate) fn fault(ctx_addr: u64, pc: u64, raise: impl FnOnce(&mut gex_kernel::syscalls::Kernel, &mut GuestMem<'_>) -> gex_kernel::signal::Delivery) -> Option<u64> {
    use gex_kernel::signal::Delivery;
    let d = with_exec_lock(|h| {
        let mut gm = guest();
        let d = raise(&mut h.kernel, &mut gm);
        if let Delivery::Terminate { .. } = d {
            task_end(&mut h.kernel);
        }
        d
    });
    match d {
        Delivery::Resume(target) => {
            if let Some(run) = MY_RUN.with(|r| r.borrow().clone()) {
                run.lock().unwrap_or_else(|e| e.into_inner()).pc = target;
            }
            Some(target)
        }
        Delivery::Terminate { signal, .. } => {
            exit_here(-(signal as i32), Some(pc));
            None
        }
        // Raised and delivered: the thread goes on where its context says.
        Delivery::None => Some(guest().read_u64(ctx_addr + ctx::PC as u64).unwrap_or(pc)),
    }
}

/// [`fault`], and the thread's way back to JS: at the target, or its end.
pub(crate) fn fault_and_leave(ctx_addr: u64, pc: u64, raise: impl FnOnce(&mut gex_kernel::syscalls::Kernel, &mut GuestMem<'_>) -> gex_kernel::signal::Delivery) -> ! {
    if let Some(target) = fault(ctx_addr, pc, raise) {
        set_resume(target);
        set_resume_ctx(ctx_addr);
    }
    trap()
}

/// A Darwin thread at a safepoint, as the native host's safepoint takes
/// one: the signals pending for it, taken as its kernel takes them on the
/// way back to user space (`deliver_pending`, `bsd_ast`), with the kernel
/// lock, as a Darwin frame (never the lock-free Linux delivery,
/// `sigs::deliver`); with none, its hold ([`to_user`]).
pub(crate) fn safepoint(ctx_addr: u64, pc: u64) {
    use gex_kernel::signal::Delivery;
    let d = with_exec_lock(|h| {
        let mut gm = guest();
        let d = h.kernel.deliver_pending(&mut gm);
        if let Delivery::Terminate { .. } = d {
            task_end(&mut h.kernel);
        }
        d
    });
    let d = match d {
        Delivery::None => match to_user() {
            ToUser::Run => return,
            ToUser::Resume(t) => Delivery::Resume(t),
            ToUser::Exit(Some(code)) => {
                exit_here(code, Some(pc));
                trap();
            }
            ToUser::Exit(None) => {
                set_resume_none();
                set_resume_ctx_none();
                trap();
            }
        },
        d => d,
    };
    match d {
        Delivery::None => {}
        Delivery::Resume(target) => {
            if let Some(run) = MY_RUN.with(|c| c.borrow().clone()) {
                let mut r = run.lock().unwrap_or_else(|e| e.into_inner());
                r.pc = target;
                r.waiting = Waiting::Runnable;
            }
            set_resume(target);
            set_resume_ctx(ctx_addr);
            trap();
        }
        Delivery::Terminate { signal, .. } => {
            exit_here(-(signal as i32), Some(pc));
            trap();
        }
    }
}

/// Whether a Darwin call's wait is one the page parks: a thread's sleep on
/// its own wait word (`Kernel::darwin_block`'s, a futex wait on its
/// context's `WAIT`), which every Darwin wait queue's waiter makes (kevent,
/// psynch, ulock, mach_msg, select and poll among them), its end the
/// kernel's ([`finished`]).
pub(crate) fn parks(op: &gex_kernel::BlockOp) -> bool {
    matches!(op, gex_kernel::BlockOp::FutexWait { .. })
}

/// A Darwin call that parked on what the page does not park
/// (`SyscallOutcome::Blocking` other than [`parks`]'): a Darwin pipe's or
/// socket's write (its whole size and what it already wrote, `fp_writev`'s
/// rules) or a Darwin `wait4` (stops and continues), which the page's Linux
/// waits do not finish as the kernel does. Reported, and the call ended
/// through the kernel with ENOSYS; the outcome is the call's.
pub(crate) fn unparked(k: &mut gex_kernel::syscalls::Kernel, m: &mut GuestMem<'_>, op: &gex_kernel::BlockOp) -> gex_kernel::SyscallOutcome {
    let what = format!("{op:?}");
    let what = what.split(['{', '(', ' ']).next().unwrap_or("?");
    k.darwin_unimplemented(format!("a Darwin call's wait ({what}): the page's waits do not end a Darwin wait as its kernel does (finish_blocking); the call fails with ENOSYS"));
    match k.finish_blocking(m, Err(gex_kernel::Errno::ENOSYS)) {
        // A wait that would sleep again is not parked either: its call
        // fails as it is.
        gex_kernel::SyscallOutcome::Blocking(_) => {
            let _ = gex_kernel::darwin::set_result(m, k.ctx_addr, gex_kernel::Errno::ENOSYS.as_return());
            gex_kernel::SyscallOutcome::Continue
        }
        out => out,
    }
}

/// A Darwin `posix_spawn`'s child (`Kernel::darwin_spawned`): a second
/// Darwin process of this Worker's system, whose state is this process's
/// shim's, until it is the global kernel's. Reported, the child let go
/// (its task ended, its descriptors closed, its pid reaped) and the call
/// failed with ENOSYS.
pub(crate) fn spawn_refused(k: &mut gex_kernel::syscalls::Kernel, m: &mut GuestMem<'_>) {
    if let Some(mut child) = k.darwin_spawned.take() {
        let pid = child.pid;
        child.darwin_task_terminate();
        child.close_all_fds();
        k.procs.reap(pid);
    }
    k.darwin_unimplemented("posix_spawn's child: a second Darwin process of the system, whose Darwin state is this process's Worker's in the page; the call fails with ENOSYS".into());
    let _ = gex_kernel::darwin::set_result(m, k.ctx_addr, gex_kernel::Errno::ENOSYS.as_return());
}

/// A Darwin wait's end, in the Worker of thread `i` whose wait it was
/// (`finish_wait`, `r` its run state, locked): as the native host ends one
/// (`perform_block`, then `Kernel::finish_blocking` with the kernel locked):
/// the wait's own result, `ETIMEDOUT` at its deadline, `EINTR` when a
/// signal is pending for the thread (`signal_pending_for`, as the native
/// host's `interrupted`), else a wake; the kernel then writes the call's
/// answer, delivers a signal, or sleeps the thread again.
pub(crate) fn finished(r: &mut Run, i: usize, ctx_addr: u64, tid: i32, timed_out: bool, by_signal: bool) -> Done {
    use gex_kernel::{Errno, SyscallOutcome};
    let pc = r.pc;
    let out = with_exec_lock(|h| {
        let ks = h.threads[i].kstate();
        h.kernel.enter_thread(&ks);
        let mut gm = guest();
        let res = if timed_out {
            Err(Errno::ETIMEDOUT)
        } else if by_signal && h.kernel.signal_pending_for(tid) {
            Err(Errno::EINTR)
        } else {
            Ok(0)
        };
        let mut out = h.kernel.finish_blocking(&mut gm, res);
        // A wait it goes on to that the page does not park, as at a call.
        if let SyscallOutcome::Blocking(op) = &out {
            if !parks(op) {
                let op = op.clone();
                out = unparked(&mut h.kernel, &mut gm, &op);
            }
        }
        woken(&mut h.kernel);
        start_spawns(&mut h.kernel);
        if matches!(out, SyscallOutcome::Exit(_) | SyscallOutcome::Killed { .. }) {
            task_end(&mut h.kernel);
        }
        if matches!(out, SyscallOutcome::ThreadExit) {
            thread_ended(tid);
        }
        out
    });
    if spawned() {
        // SAFETY: a host import without arguments; nothing here holds a lock.
        unsafe { cgen::thread_start() };
    }
    match out {
        // On after the call; a thread parked at its first entry (`pc` 0,
        // `adopted`) where its context now says.
        SyscallOutcome::Continue if pc == 0 => Done::At(ctx_addr, guest().read_u64(ctx_addr + ctx::PC as u64).unwrap_or(0)),
        SyscallOutcome::Continue => Done::At(ctx_addr, pc),
        SyscallOutcome::Resume(target) => Done::At(ctx_addr, target),
        SyscallOutcome::Blocking(op) => {
            let gex_kernel::BlockOp::FutexWait { table, uaddr, deadline, parked, val } = &op else { unreachable!("a Darwin wait the page parks is a futex wait") };
            let waiting = Waiting::Futex {
                val: *val,
                wake_gen: unsafe { k_futex_gen(*uaddr) },
                parked: parked.clone().unwrap_or_else(|| table.park(*uaddr)),
                deadline: deadline.map(|d| turn_now() + d.as_nanos() as u64),
            };
            r.waiting = r.park_as(waiting);
            r.blocked_on = Some(op);
            r.owed = Owed { darwin: true, ..Owed::default() };
            Done::Parked
        }
        SyscallOutcome::Exit(code) => Done::Ends(code),
        SyscallOutcome::Killed { signal, .. } => Done::Ends(-(signal as i32)),
        SyscallOutcome::ThreadExit => {
            r.waiting = Waiting::Exited;
            Done::Gone
        }
        other => panic!("gex: Darwin thread {tid}: its wait ended in {other:?}, which a wait's end does not have"),
    }
}

/// The futexes a Darwin kernel entry woke (a waiter's wait word,
/// `darwin_wake`), told to the global kernel, so a thread parked on one in
/// another Worker sees the wake, as every call's are (`syscall_entry`).
pub(crate) fn woken(k: &mut gex_kernel::syscalls::Kernel) {
    if unsafe { k_present() } != 0 {
        for addr in k.futexes.take_woken() {
            unsafe { k_futex_wake(addr) };
        }
    }
}

/// The Darwin calls that make a process the page does not start yet,
/// refused before the kernel takes them, so that nothing of the child is
/// made: `fork` and `vfork` (a forked Darwin process's memory and task,
/// `darwin_fork_plan`'s inheritance). Reported, and the call fails with
/// ENOSYS; false for any other call.
pub(crate) fn refused(k: &mut gex_kernel::syscalls::Kernel, m: &mut GuestMem<'_>) -> bool {
    use gex_kernel::darwin;
    let raw = m.read_u64(k.ctx_addr + darwin::NR_SLOT as u64).unwrap_or(!0);
    if darwin::mach_trap_number(raw).is_some() || raw as u32 as u64 == darwin::PLATFORM {
        return false;
    }
    let what = match darwin::bsd_syscode(m, k.ctx_addr, raw) {
        2 => "fork",
        66 => "vfork",
        _ => return false,
    };
    k.darwin_unimplemented(format!("{what}: the page starts no forked child of a Darwin process yet; the call fails with ENOSYS"));
    let _ = darwin::set_result(m, k.ctx_addr, gex_kernel::Errno::ENOSYS.as_return());
    true
}

thread_local! {
    /// The call this Worker just made queued threads for the host to start
    /// ([`start_spawns`]).
    static SPAWNED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The threads a Darwin call made for the host to start once it returns (a
/// workqueue's, a thread resumed after it was made suspended:
/// `Kernel::take_spawns`), each queued for a Worker of its own, as the
/// native host starts a host thread for each after every call.
pub(crate) fn start_spawns(k: &mut gex_kernel::syscalls::Kernel) {
    let reqs = k.take_spawns();
    if reqs.is_empty() {
        return;
    }
    for r in reqs {
        thread_later(r.tid, r.ctx_addr);
    }
    SPAWNED.with(|c| c.set(true));
}

/// Whether the call just made queued threads ([`start_spawns`]): the host
/// starts their Workers once the kernel lock is let go.
pub(crate) fn spawned() -> bool {
    SPAWNED.with(|c| c.replace(false))
}

/// A Darwin thread's first entry, in its own Worker before it runs a guest
/// instruction (`gex_adopt_thread`), as the native host's
/// `run_guest_thread` makes it: the thread noted as started on this Worker
/// (`workq::thread_started`), then the kernel's own first entry for a
/// thread that has one (a workqueue thread, made parked:
/// `Kernel::darwin_thread_entry`), which leaves the context set for where
/// the guest begins. Its waits (`darwin_thread_entry`'s `perform_block`
/// natively) park this Worker as a call's do, and end as [`finished`]
/// ends them. Thread `i`'s entry pc, or `None` when it does not run (it,
/// or its process, has ended).
pub(crate) fn adopted(i: usize) -> Option<u64> {
    use gex_kernel::SyscallOutcome;
    let out = with_exec_lock(|h| {
        let ks = h.threads[i].kstate();
        gex_kernel::darwin::workq::thread_started(ks.tid);
        on_workers().push(ks.tid);
        h.kernel.enter_thread(&ks);
        let mut gm = guest();
        let mut out = h.kernel.darwin_thread_entry(&mut gm);
        if let Some(SyscallOutcome::Blocking(op)) = &out {
            if !parks(op) {
                let op = op.clone();
                out = Some(unparked(&mut h.kernel, &mut gm, &op));
            }
        }
        woken(&mut h.kernel);
        start_spawns(&mut h.kernel);
        match out {
            None | Some(SyscallOutcome::Continue) => {}
            Some(SyscallOutcome::Resume(pc)) => {
                let _ = gm.write_u64(ks.ctx_addr + ctx::PC as u64, pc);
            }
            Some(SyscallOutcome::Blocking(op)) => {
                // Parked from the start: the context's pc is where it goes
                // once its wait ends (`finished`).
                let gex_kernel::BlockOp::FutexWait { table, uaddr, deadline, parked, val } = &op else { unreachable!("a Darwin wait the page parks is a futex wait") };
                let waiting = Waiting::Futex {
                    val: *val,
                    wake_gen: unsafe { k_futex_gen(*uaddr) },
                    parked: parked.clone().unwrap_or_else(|| table.park(*uaddr)),
                    deadline: deadline.map(|d| turn_now() + d.as_nanos() as u64),
                };
                let mut r = h.threads[i].run();
                r.pc = 0;
                r.waiting = r.park_as(waiting);
                r.blocked_on = Some(op);
                r.owed = Owed { darwin: true, ..Owed::default() };
                return Some(None);
            }
            Some(SyscallOutcome::ThreadExit) => {
                h.threads[i].run().waiting = Waiting::Exited;
                thread_ended(ks.tid);
                return None;
            }
            Some(SyscallOutcome::Exit(code)) => {
                task_end(&mut h.kernel);
                exit_process(code);
                return None;
            }
            Some(SyscallOutcome::Killed { signal, .. }) => {
                task_end(&mut h.kernel);
                killed(signal as i32, 0);
                return None;
            }
            Some(other) => panic!("gex: Darwin thread {}: its first kernel entry's outcome {other:?}, which a thread's start does not have", ks.tid),
        }
        let pc = gm.read_u64(ks.ctx_addr + ctx::PC as u64).unwrap_or(0);
        h.threads[i].run().pc = pc;
        Some(Some(pc))
    });
    if spawned() {
        // SAFETY: a host import without arguments; nothing here holds a lock.
        unsafe { cgen::thread_start() };
    }
    match out {
        // Made while its task is held, it waits first (thread_create's
        // thread_hold).
        Some(Some(pc)) => to_user_at(pc),
        // Its first wait, in this Worker until it ends (as `wasm32_wait`
        // waits a call's out in place), then its way to user space.
        Some(None) => loop {
            let _now = NowScope::open();
            if schedule() == 1 {
                let pc = resume();
                set_resume_none();
                set_resume_ctx_none();
                return pc.and_then(to_user_at);
            }
            if exited() || SCHED_OVER.with(|c| c.replace(false)) {
                return None;
            }
            gex_park(0);
        },
        None => {
            end_if_all_exited();
            None
        }
    }
}
