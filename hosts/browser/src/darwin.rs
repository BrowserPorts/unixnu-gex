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
    // Brought up to date at once, as the native host's tick thread does.
    tick();
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
    Ok(entry)
}

/// A Darwin process's task end, at its process's end (`proc_exit`): its
/// task terminated and its descriptors closed, as the native host ends
/// one, before the end is published; nothing for a Linux process.
pub(crate) fn task_end(k: &mut gex_kernel::syscalls::Kernel) {
    if k.darwin {
        k.darwin_task_terminate();
        k.close_all_fds();
    }
}

/// When the commpage was last brought up to date ([`tick`]), in absolute
/// time; 0 for never.
static TICKED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The commpage's per-quantum update (`commpage::tick`: its approximate
/// time, quiescent counter and flags), which the native host makes on a
/// thread of its own every quantum: here as a Darwin thread runs, at its
/// calls and its safepoints, once a quantum has passed since the last, as
/// XNU makes it at a running thread's quantum's end.
pub(crate) fn tick() {
    use std::sync::atomic::Ordering;
    use gex_kernel::darwin::{commpage, mach};
    let now = mach::absolute_time();
    let last = TICKED.load(Ordering::Relaxed);
    let quantum = commpage::QUANTUM.as_nanos() as u64 * u64::from(mach::TIMEBASE.1) / u64::from(mach::TIMEBASE.0);
    if last != 0 && now < last.saturating_add(quantum) {
        return;
    }
    if TICKED.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
        commpage::tick(&mut guest(), now);
    }
}
