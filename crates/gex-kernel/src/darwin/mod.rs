//! The Darwin personality: a Mach-O process's system calls.
//!
//! Darwin enters the kernel with `svc #0x80` and the number in x16, and its
//! numbering says which kernel answers: a positive number is a BSD system
//! call, a negative one a Mach trap, and `0x8000_0000` the machine-dependent
//! calls (the thread's TSD pointer). BSD calls with a Linux counterpart are
//! renumbered onto it ([`bsd::translate`]) and run through the same
//! dispatch as a Linux process's, as the i386 and x86-64 numberings are;
//! the result goes back Darwin's way, with the carry flag set and a Darwin
//! errno in x0 on failure ([`set_result`]).

use crate::errno::Errno;
use crate::GuestMem;
use gex_abi::ctx;

pub mod aar;
pub mod aio;
pub mod amfi;
pub mod apfs;
pub mod apfsread;
pub mod apfswrite;
pub mod applematch;
pub mod attrcall;
pub mod attrlist;
pub mod bsd;
pub mod codesign;
pub mod clist;
pub mod commpage;
pub mod ptmx;
pub mod ctty;
pub mod devfs;
pub mod apfsmount;
pub mod plist;
pub mod preboot;
pub mod dkopen;
pub mod disknode;
pub mod tty;
pub mod ttydev;
pub mod km;
pub mod cpumon;
pub mod cred;
pub mod corpse;
pub mod corpsefork;
pub mod lwcorpse;
pub mod taskident;
pub mod critexit;
pub mod errno;
pub mod exec;
pub mod eventlink;
pub mod fileport;
pub mod footprint;
pub mod xattr;
pub mod iokit;
pub mod iodt;
pub mod iomatch;
pub mod iopower;
pub mod image;
pub mod image4;
pub mod image4ap;
pub mod img4;
pub mod iosurface;
pub mod hostuuid;
pub mod osserialize;
pub mod accel;
pub mod iomfb;
pub mod platform;
pub mod pagecache;
pub mod cluster;
pub mod pe;
pub mod vattr;
pub mod vauth;
pub mod volattrs;
pub mod guarded;
pub mod exit;
pub mod exception;
pub mod execve;
pub mod fsfreeze;
pub mod fsops;
pub mod inet6;
pub mod ioctl;
pub mod filesec;
pub mod fixedcalls;
pub mod graft;
pub mod graftfs;
pub mod clonefile;
pub mod pathconf;
pub mod itimer;
pub mod jobctl;
pub mod ipc;
pub mod kern;
pub mod kevent;
pub mod kfilt;
pub mod mac;
pub mod macvfs;
pub mod kobject;
pub mod lockf;
pub mod lzfse;
pub mod inflate;
pub mod xz;
pub mod mach;
pub mod mach_msg;
pub mod memorystatus;
pub mod mig;
pub mod mman;
pub mod mk_timer;
pub mod mwl;
pub mod noncemag;
pub mod nvram;
pub mod persona;
pub mod pipe;
pub mod priority;
pub mod procinfo;
pub mod procpolicy;
pub mod psem;
pub mod psynch;
pub mod reason;
pub mod reboot;
pub mod report;
pub mod rlimit;
pub mod rusage;
pub mod sandbox;
pub mod sockev;
pub mod shregion;
pub mod storage;
pub mod storagestack;
pub mod sandboxes;
pub mod sched;
pub mod sep;
pub mod thinfo;
pub mod sockbuf;
pub mod unixsock;
pub mod sema;
pub mod select;
pub mod share;
pub mod held;
pub mod shm;
pub mod signal;
pub mod sockaddr;
pub mod sockopt;
pub mod sockerr;
pub mod spawn;
pub mod kinfo;
pub mod launchcon;
pub mod lwcr;
pub mod machine;
pub mod sysctl;
mod sysctl_nodes;
pub mod sysno;
pub mod taskpolicy;
pub mod threadpolicy;
pub mod threadstate;
pub mod thread;
pub mod time;
pub mod timer;
pub mod triage;
pub mod kcdata;
pub mod udif;
pub mod trustcache;
pub mod vconsole;
pub mod vm;
pub mod vmshare;
mod vmmig;
pub mod vmentry;
pub mod vmobject;
pub mod ubc;
pub mod purgeable;
pub mod coalition;
pub mod importance;
pub mod voucher;
pub mod webdevice;
pub mod wait;
pub mod workinterval;
pub mod workq;


/// The Sandbox kext's profiles, which the kernelcache carries: its platform
/// profile, its builtin collection and its protobox collection.
#[derive(Default)]
pub struct SandboxProfiles {
    pub platform: Option<Vec<u8>>,
    pub builtin: Option<Vec<u8>>,
    pub protobox: Option<Vec<u8>>,
}

/// The boot: the boot loader's payload as the kernel takes it, the trust
/// cache bundle (`/chosen/memory-map/TrustCache`), whose first module is
/// the static trust cache (`load_static_trust_cache`; one that does not
/// load is the kernel's panic), without which there are no trust caches;
/// the Sandbox kext's profiles; and the sealed volumes' owners, modes and
/// flags, by volume ([`volattrs::Vol`]); and where the restore's Cryptex1
/// comes from ([`preboot::Sources`]); on the web device
/// ([`webdevice`]), its identity in `/chosen`, as its boot puts it there;
/// and the device's NVRAM namespace ([`nvram::Source`]), which the boot
/// reads into `/chosen` and IODTNVRAM's controller writes. Once per
/// system.
pub fn boot(trust_cache: Option<&[u8]>, sandbox: SandboxProfiles, device_tree: Option<&[u8]>, volume_attrs: Vec<(volattrs::Vol, Vec<u8>)>, cryptex1: preboot::Sources, nvram: Option<nvram::Source>) -> Result<(), String> {
    let mut chosen = match (&cryptex1.ticket, &cryptex1.web_device) {
        (preboot::Ticket::WebDevice, Some(w)) => {
            webdevice::set(w.clone())?;
            // Its identity, what its boot adds for its AP ticket and nonce,
            // and the boot command iBoot's `fsboot` adds (0x1800b0b2c →
            // 0x1800ccc44, 0x1800f07b8), by which AppleImage4 chooses its
            // i/o strategy.
            w.next_boot_chosen()?
        }
        (preboot::Ticket::WebDevice, None) => return Err("the Cryptex1 ticket is the web device's (GEX_DARWIN_CRYPTEX1_TICKET=web-device), but no web device is configured (GEX_DARWIN_WEB_DEVICE)".into()),
        (_, Some(_)) => return Err("a web device is configured (GEX_DARWIN_WEB_DEVICE), but the Cryptex1 ticket is not its own (GEX_DARWIN_CRYPTEX1_TICKET=web-device)".into()),
        (_, None) => Vec::new(),
    };
    // The NVRAM namespace as the boot reads it into /chosen.
    if let Some(src) = &nvram {
        chosen.extend(src.chosen()?);
        if let Some(gaps) = src.unmeasured() {
            crate::darwin_say!("[gex] Darwin: {gaps}");
        }
        crate::darwin_say!("[gex] Darwin: {NVRAM_WRITERS_UNMODELLED}");
    }
    match device_tree {
        Some(t) => {
            // IODTNVRAM starts over /chosen as the boot left it, before the
            // registry's matching publishes its services.
            match nvram {
                Some(src) => {
                    let mut probe = iokit::parse(t)?;
                    iokit::fill_chosen(&mut probe, &chosen)?;
                    nvram::boot(&nvram::chosen_of(&probe), src.medium)?;
                    // AppleImage4's boot over the NVRAM (its nonce
                    // magazine read and rolled) and its service's start
                    // (the magazine written as its strategy allows).
                    noncemag::start(&probe)?;
                }
                None => nvram::absent(nvram::NO_IMAGE.into()),
            }
            iokit::set_tree(t, &chosen, nvram::system_service())?
        }
        None if !chosen.is_empty() => return Err("the web device's boot fills in /chosen, but the boot payload has no device tree".into()),
        None => {}
    }
    // Its files' pages are kept as its VM keeps them, for the counts read
    // off them.
    pagecache::set_on();
    // The device facts that stand in until measured, once at start.
    if let Some(gaps) = storage::unmeasured() {
        crate::darwin_say!("[gex] Darwin: {gaps}");
    }
    for (vol, spec) in volume_attrs {
        volattrs::set(vol, spec)?;
    }
    preboot::set_sources(cryptex1)?;
    let m = match trust_cache {
        Some(b) => Some(trustcache::load_bundle(b).map_err(|e| format!("failed to load static trust cache module: 0 ({e:?})"))?),
        None => None,
    };
    trustcache::set_static(m)?;
    // devfs's terminal nodes: ptmx, its replicas, tty.
    crate::vfs::devfs::set_darwin_ttys();
    mac::set_platform_profile(sandbox.platform)?;
    sandboxes::set_collections(sandbox.builtin, sandbox.protobox)
}

/// The device's NVRAM writers at boot that are not modelled: only
/// IODTNVRAM's own start (the boot-args it makes) is.
const NVRAM_WRITERS_UNMODELLED: &str = "the boot's NVRAM writes outside IODTNVRAM's start are not modelled: iBoot's before it hands the kernel the bank (encrypted), and the kexts' at boot (AppleMobileApNonce's boot nonce, AppleSEPManager's ART, the backlight's level, AppleLockdownMode, iBootAudioVolumeManager, AppleM68Buttons' sync, RTBuddy's)";

thread_local! {
    /// What code with no kernel to hand met that is not modelled, for the
    /// call's end to report.
    static NOTES: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Note a gap where the kernel cannot be reached: reported (and stopped
/// at under strict mode) when the call ends.
pub fn note_unimplemented(what: String) {
    NOTES.with(|n| n.borrow_mut().push(what));
}

/// A Darwin process's kernel state beyond the BSD side's: its threads and
/// what they wait on.
#[derive(Debug, Default)]
pub struct Task {
    /// Its job control state, its cell in the process table, once asked.
    pub job: Option<std::sync::Arc<std::sync::Mutex<crate::proc::Job>>>,
    pub pthread: thread::Registration,
    /// Kernel replies waiting for a thread to go off its CPU.
    pub pending_replies: Vec<kobject::PendingReply>,
    /// What other processes read of this one (`kern.proc`).
    pub live: std::sync::Arc<kinfo::Live>,
    /// Its `proc_pid_rusage` state: the fork's start, the reaped
    /// children's sums, the end's record, the wired ledger.
    pub rusage: std::sync::Arc<rusage::Shared>,
    /// The real interval timer, and the virtual and profiling ones.
    pub realtimer: itimer::RealTimer,
    pub vtimers: [itimer::Itimerval; 2],
    /// `task->vtimers` (TASK_VTIMER_*), and `p_rlim_cpu`: the processor
    /// time left under RLIMIT_CPU (seconds, microseconds).
    pub vtimer_bits: u32,
    pub rlim_cpu: (i64, i32),
    /// The task's CPU usage limits (`rusage_cpu_*`).
    pub cpuusage: cpumon::CpuUsage,
    /// `p_vfs_iopolicy`.
    pub vfs_iopolicy: u32,
    /// The task's wakeups monitor.
    pub wakeups: cpumon::WakeupsMonitor,
    pub threads: thread::Threads,
    pub waits: wait::Waits,
    pub ulocks: thread::Ulocks,
    pub psynch: psynch::Psynch,
    pub timers: timer::Timers,
    /// The framebuffer's thread call for the next vertical blank, while
    /// armed ([`iomfb::swap`]).
    pub iomfb_call: Option<(crate::darwin::time::Instant, u64)>,
    /// Threads made by a call (resumed, or the workqueue's) for the host to
    /// start after it ([`crate::syscalls::Kernel::take_spawns`]).
    pub spawns: Vec<crate::syscalls::SpawnRequest>,
    /// A blocking `connect` whose socket is connecting: `connectit`'s
    /// sleep, from the call to its wait, and from the wait to the
    /// `so_error` it reports.
    pub connect_wait: Option<std::sync::Arc<crate::net::Socket>>,
    pub connect_waited: Option<std::sync::Arc<crate::net::Socket>>,
    /// The process's TCP sockets, whose timers its thread calls run
    /// (`Kernel::darwin_tcp_timers`), as of the descriptor table's
    /// generation; whether they are counted in the pipe watch, so that a
    /// change another process makes to one wakes the thread calls.
    pub tcp_socks: Vec<std::sync::Weak<crate::net::Socket>>,
    pub tcp_socks_gen: Option<u64>,
    pub tcp_watch: bool,
    /// `GEX_DARWIN_STRICT=1`: stop the process at the first thing it asks
    /// for that this kernel does not do.
    pub strict: bool,
    /// The program's `LC_BUILD_VERSION` platform and SDK (`p_platform`,
    /// `p_sdk`).
    pub platform: (u32, u32),
    /// The task's IPC.
    /// Reached through [`crate::syscalls::Kernel::ipc`], which takes the
    /// system's IPC table for the call.
    pub ipc_raw: ipc::Ipc,
    /// The task whose request to one of this task's kernel objects is
    /// being served (0: this task's own).
    pub kcaller: ipc::TaskKey,
    /// While this task's own kernel serves its `mach_vm_read_overwrite` of
    /// another task's map (whose copy is made into this map, the caller's
    /// `current_map()`): that task's process.
    pub read_from: Option<(ipc::TaskKey, i32)>,
    /// The send rights the next child task inherits (`ipc_task_init`):
    /// its special ports by kind, its registered ports, and its exception
    /// actions.
    #[allow(clippy::type_complexity)]
    pub child_ports: std::sync::Mutex<Option<(std::collections::HashMap<i32, ipc::ObjId>, std::collections::HashSet<i32>, [Option<ipc::ObjId>; 3], exception::ExcActions)>>,
    /// The kernel objects' ports.
    pub kports: kobject::Kports,
    pub semas: sema::Semas,
    pub mk_timers: mk_timer::MkTimers,
    /// `p_idversion`, from the system's `nextpidversion` at exec.
    pub pidversion: i32,
    /// The workqueue, once opened (`p_wqptr`), and what it owes: threads
    /// to wake or start, a creator pass.
    pub workq: Option<Box<workq::Workq>>,
    pub workq_wake: Vec<i32>,
    /// A thread call is running (`THREAD_TAG_CALLOUT` with
    /// `callout_woken_from_icontext`): the threads it wakes are interrupt
    /// wakeups; with `callout_woken_from_platform_idle` (every processor
    /// idle at the timer interrupt that woke it), platform-idle wakeups
    /// too. And the workqueue threads it woke whose wake is yet to be
    /// done, each with that platform-idle state.
    pub in_callout: bool,
    pub callout_pidle: bool,
    pub callout_woken: std::collections::HashMap<i32, bool>,
    pub workq_creator_pending: Option<u32>,
    /// Every thread request: the workqueue's (`workq_kernreturn`'s) and
    /// the kqueues' (`kqwq_request`, `kqwl_request`).
    pub threadreqs: std::collections::HashMap<workq::ReqId, workq::Req>,
    pub next_threadreq: u64,
    /// The process's kqueues and knotes.
    pub kevents: kevent::Kevents,
    /// The process's vouchers and their attribute managers' state.
    pub vouchers: voucher::Vouchers,
    /// A spawned task's watch ports, with their send rights, and whether it
    /// is an adaptive daemon: bound when its spawn enables the task
    /// ([`crate::syscalls::Kernel::darwin_task_enable`]).
    pub pending_watchports: Option<(Vec<Option<ipc::ObjId>>, bool)>,
    /// The program's code signature, when it has one, with the entitlements
    /// its credential carries.
    pub codesign: Option<codesign::CodeSign>,
    /// `p_csflags`, which another process reads and changes (csops).
    pub csflags: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// `p_pcaction`: what is to be done to the process on resource
    /// starvation (its control state, the low bits) and what has been done
    /// (its action state, from bit 16), which other processes read.
    pub pcaction: std::sync::Arc<std::sync::atomic::AtomicU32>,
    /// `P_LVMRSRCOWNER`: the process may restore others that resource
    /// starvation throttled or suspended.
    pub vmrsrcowner: bool,
    /// `p_persona`.
    pub persona: Option<persona::Persona>,
    /// `p_textoff`: where the image's slice starts in its file.
    pub textoff: i64,
    /// `p_uniqueid` and `p_puniqueid` (its parent's at its fork), and
    /// `p_uuid`, its image's UUID.
    pub uniqueid: u64,
    pub puniqueid: u64,
    pub uuid: [u8; 16],
    /// `p_name`.
    pub p_name: reason::PName,
    /// `p_user_faults`: the faults `os_fault_with_payload` simulated.
    pub user_faults: u32,
    /// `p_cputype`, `p_cpusubtype`: its image's.
    pub cputype: (u32, u32),
    /// `p_start`: when its fork made it.
    pub start: (u64, u64),
    /// The ids and start time a fork chose for its child, for the child's
    /// task to take.
    pub fork_ids: std::sync::Mutex<Option<(u64, i32, (u64, u64), u64)>>,
    /// The process's credential (`p_ucred`'s POSIX part) and `P_SUGID`.
    pub cred: cred::Cred,
    pub sugid: bool,
    /// The credential's Sandbox label: its sandbox, which the task's link
    /// shows other processes.
    pub sandbox: sandboxes::Label,
    /// `TFRO_FILTER_MSG`: the task's Mach messages are filtered.
    pub filter_msg: bool,
    /// The process's Unix call filter mask (`proc_ro`'s
    /// `syscall_filter_mask`) and its task's Mach trap and kernel MIG
    /// routine masks (`task_filters`), as Sandbox set them: none lets every
    /// call through unasked.
    pub syscall_mask: Option<sandbox::FilterMask>,
    pub mach_trap_mask: Option<sandbox::FilterMask>,
    pub kobj_mask: Option<sandbox::FilterMask>,
    /// What the exec in progress keeps for Sandbox's hook.
    pub exec_sandbox: Option<sandboxes::Pending>,
    /// What the spawn in progress gave AMFI's launch constraints hook.
    pub exec_launch: Option<launchcon::Spawn>,
    /// `p_original_ppid`: the pid of the process that forked this one,
    /// kept across exec and reparenting.
    pub original_ppid: i32,
    /// `p_responsible_pid`, which a fork copies from the parent. Nothing on
    /// this kernel sets it otherwise (no kext imports
    /// `proc_set_responsible_pid`), so it is `kernproc`'s, 0.
    pub responsible_pid: i32,
    /// A spawned child's activation, done in its parent's call
    /// (`Kernel::darwin_activate`): its answer, for the child's start.
    pub activated: Option<Result<(), crate::errno::Errno>>,

    /// `P_LADVLOCK`: the process has taken a POSIX record lock.
    pub ladvlock: bool,
    /// Threads whose lock requests another thread or process woke.
    pub lock_wakes: std::sync::Arc<std::sync::Mutex<Vec<i32>>>,
    /// Each thread's terminal call asleep on its terminal.
    pub ttyops: std::collections::HashMap<i32, ttydev::Pending>,
    /// `p_sigacts` and `p_sigignore`.
    pub sigacts: signal::Sigacts,
    /// `p_limit`.
    pub rlimits: rlimit::Rlimits,
    /// `P_LCUSTOM_STACK`: the main stack's size came from `LC_MAIN`.
    pub custom_stack: bool,
    /// `p_disallow_map_with_linking`: dyld said it is done mapping with
    /// linking.
    pub disallow_mwl: bool,
    /// `p_workq_allow_sigmask`.
    pub workq_allow_sigmask: u32,
    /// `p_dispatchqueue_serialno_offset`, `p_dispatchqueue_label_offset`.
    pub dispatchqueue_serialno_offset: u64,
    pub dispatchqueue_label_offset: u64,
    /// The task's policy (app type, role, QoS clamp and what follows): its
    /// cell in the process table, once asked.
    pub policy: Option<std::sync::Arc<taskpolicy::PolicyCell>>,
    /// What its map's entries keep beyond the host's mappings.
    pub vm: vm::Entries,
    /// Its map's highest address when an entitlement or a spawn raised it
    /// (`vm_map_set_max_addr`); 0 for [`vm::MAP_MAX`].
    pub map_max: u64,
    /// `p_crash_behavior` (a byte: `posix_spawn` truncates the
    /// attribute's flags) and `p_crash_behavior_deadline`, from a spawn of
    /// a parent entitled to set them; an exec clears them.
    pub crash_behavior: u8,
    pub crash_behavior_deadline: u64,
    /// `p_crash_count` and `p_throttle_timeout`: what `posix_spawn` set
    /// (`posix_spawnattr_set_crash_count_np`), for a corpse's crash
    /// information.
    pub crash_count: u32,
    pub throttle_timeout: u32,
    /// `p_posix_spawn_failed`: the spawn that made it failed.
    pub spawn_failed: bool,
    /// Its map's lowest address (`vm_map_min`): the end of the image's
    /// page zero.
    pub map_min: u64,
    /// Signals are being taken on the way out of a call, which can wait.
    pub syscall_exit: bool,
    /// The EXC_CRASH code and subcode a death owes its handlers.
    pub crash_notify: Option<(i64, i64)>,
    /// The task is a corpse (`TFRO_CORPSE`), with what it keeps.
    pub corpse: Option<Box<corpse::Corpse>>,
    /// `task_uniqueid` ([`next_task_uniqueid`]): the task's own, not its
    /// process's `p_uniqueid` (which `get_task_uniqueid` gives).
    pub task_uniqueid: u64,
    /// Corpse forks of the task asked for, for the host to make
    /// ([`corpsefork`]).
    pub corpse_forks: std::collections::VecDeque<corpsefork::Request>,
    /// The return codes of the corpse forks threads' calls wait for.
    pub corpse_fork_results: std::collections::HashMap<i32, u64>,
    /// Lightweight corpses' deliveries (`thread_backtrace_enqueue`), for
    /// the task's thread calls ([`lwcorpse`]).
    pub bt_deliveries: std::collections::VecDeque<lwcorpse::Delivery>,
    /// The task is the kernel's backtrace daemon's ([`lwcorpse`]).
    pub bt_daemon: bool,
    /// `vm_map_set_corpse_source`: a fatal memory limit's kill is to make
    /// the task a corpse whatever its EXC_CRASH handlers do.
    pub corpse_source: bool,
    /// The `vm_fault` result of the fault being raised as a signal.
    pub fault_code: Option<i64>,
    /// Each thread's paths XNU records kernel triage events on that this
    /// kernel does not record ([`crate::syscalls::Kernel::darwin_ktriage_unmodelled`]).
    pub ktriage_unmodelled: std::collections::HashMap<i32, Vec<String>>,
    /// Each thread's kernel reply port, and a reply that came to it.
    pub rpc_reply: std::collections::HashMap<i32, ipc::ObjId>,
    pub rpc_replies: std::collections::HashMap<i32, Box<ipc::msg::Kmsg>>,
    /// When its footprint is next measured ([`footprint::SAMPLE`]).
    pub footprint_due: Option<crate::darwin::time::Instant>,
    /// A release of its pages is under way, the footprint's record held
    /// ([`footprint::Release`]).
    pub footprint_releasing: bool,
    /// Threads a semaphore operation woke, and how.
    pub sema_wake: Vec<(i32, wait::WaitResult)>,
    /// A blocked send's message and its send buffer, by thread.
    pub pending_send: std::collections::HashMap<i32, Box<ipc::msg::Kmsg>>,
    pub pending_send_buf: std::collections::HashMap<i32, (u64, u32)>,
    /// A fatal guard exception was raised: the task is killed when the call
    /// returns.
    pub guard_kill: bool,
    /// `thread_guard_violation`'s pending exception of a guarded descriptor,
    /// its code and subcode, for the call's way out (`fd_guard_ast`).
    pub fd_guard: Option<(u64, u64)>,
    /// Its asynchronous I/O requests.
    pub aio: aio::Aio,
    /// TF_CA_CLIENT_WI: a Core Animation client work interval was made
    /// (`task_set_ca_client_wi`).
    pub ca_client_wi: bool,
    /// Each thread waiting on a POSIX semaphore, and on which.
    pub psem_waits: std::collections::HashMap<i32, psem::Waiting>,
    /// Each thread waiting on an eventlink, and on which.
    pub eventlink_waits: std::collections::HashMap<i32, eventlink::Waiting>,
    /// The files named to the image in `executable_file` and `dyld_file`
    /// (their file system, number and path), which `fsgetpath` is asked for.
    pub image_files: Vec<(u64, u64, String)>,
    /// `P_LNOATTACH` and `P_FORCEQUOTA`.
    pub no_attach: bool,
    /// `p_debugger`.
    pub p_debugger: bool,
    pub force_quota: bool,
    /// What has been reported as not done, so each is said once.
    said: std::collections::HashSet<String>,
    /// Under strict mode, the unimplemented thing that stops the process
    /// when the call returns.
    stop: Option<String>,
}

impl Task {
    /// A new process's task: it takes the next pidversion, and its start
    /// time (`microtime_with_abstime`).
    pub fn new_process() -> Task {
        let (start, abs) = start_times();
        Task { pidversion: next_pidversion(), uniqueid: next_uniqueid(), start, rusage: rusage::Shared::new(abs), ..Default::default() }.with_wire_ledger()
    }

    /// The map's wirings kept in the task's `wired_mem` ledger, and its
    /// submaps told to its footprint meter.
    pub fn with_wire_ledger(mut self) -> Task {
        self.vm.set_wire_gauge(std::sync::Arc::clone(&self.rusage.wired));
        self.vm.set_submap_gauge(std::sync::Arc::clone(&self.rusage.meter.submaps));
        self.vm.set_alt_gauge(std::sync::Arc::clone(&self.rusage.meter.alt));
        self
    }
}

/// `microtime_with_abstime`: the calendar time (`p_start`) and the Mach
/// time (`ps_start`) of a process's start, read together.
pub fn start_times() -> ((u64, u64), u64) {
    (procinfo::microtime(), mach::absolute_time())
}

impl Task {
    /// A forked task's process ids and start, as its fork chose them.
    pub fn forked_process(uniqueid: u64, pidversion: i32, start: (u64, u64), abs: u64) -> Task {
        Task { uniqueid, pidversion, start, rusage: rusage::Shared::new(abs), ..Task::default() }
    }
}

impl crate::syscalls::Kernel {
    /// A Darwin process maps in arm64 iOS's 16 KiB pages: `mmap`,
    /// `munmap` and `mprotect` align to them.
    pub fn darwin_use_pages(&mut self) {
        let mut mm = self.mem.lock();
        mm.set_page(exec::PAGE_SIZE);
        mm.keep_perms();
    }

    /// Write what has changed of the map to its protection table
    /// (`gex_abi::PERM_TABLE64`), before the thread returns to its program:
    /// a mapping call's change is in force when the call returns, for every
    /// thread.
    pub(crate) fn darwin_flush_perms(&mut self, m: &mut GuestMem<'_>) {
        let writes = self.mem.lock().take_perm_writes();
        for (page, bytes) in writes {
            if m.kernel().write(gex_abi::PERM_TABLE64 + page, &bytes).is_err() {
                self.darwin_unimplemented(format!("the protection table past the guest memory's end (page {page:#x})"));
            }
        }
    }

    /// The pages of this process's protection table a kernel object
    /// watches for stores, and those its pmap has not entered
    /// ([`crate::SoftPages`]): a call's copies may write the one and reach
    /// the other, noted for the object and the pmap. None when there are
    /// neither.
    pub(crate) fn darwin_soft_pages(&mut self) -> Option<std::sync::Arc<crate::SoftPages>> {
        let mut mm = self.mem.lock();
        let pages = mm.withheld_write_pages().unwrap_or_default();
        let unentered = mm.unentered_runs();
        let copying = mm.copy_pending_runs();
        if pages.is_empty() && unentered.is_empty() && copying.is_empty() {
            return None;
        }
        Some(std::sync::Arc::new(crate::SoftPages { pages, written: Default::default(), unentered, touched: Default::default(), copying, copied: Default::default() }))
    }

    /// The watched pages a call's copies wrote, told to the objects that
    /// watch them; the pages not entered they reached, entered.
    pub(crate) fn darwin_soft_written(&mut self, m: &mut GuestMem<'_>, soft: &crate::SoftPages) {
        // The pages not entered that a copy reached: its fault entered them.
        let touched = std::mem::take(&mut *soft.touched.lock().unwrap_or_else(|e| e.into_inner()));
        let copied = std::mem::take(&mut *soft.copied.lock().unwrap_or_else(|e| e.into_inner()));
        if !touched.is_empty() || !copied.is_empty() {
            let mut mm = self.mem.lock();
            for p in touched {
                mm.enter_page(p);
            }
            // A write's fault on a file's page copied it.
            for p in copied {
                mm.copied(p);
            }
            drop(mm);
            self.darwin_flush_perms(m);
        }
        let mut pages = std::mem::take(&mut *soft.written.lock().unwrap_or_else(|e| e.into_inner()));
        if pages.is_empty() {
            return;
        }
        pages.sort_unstable();
        pages.dedup();
        for p in pages {
            iosurface::note_store(self, m, p);
        }
        self.darwin_flush_perms(m);
    }

    /// This task's IPC state, with the system's table taken for the rest
    /// of the kernel call ([`Self::darwin_ipc_leave`] gives it back).
    pub(crate) fn ipc(&mut self) -> &mut ipc::Ipc {
        if !self.dtask.ipc_raw.held {
            if share::remote().is_some() {
                // The table the global kernel holds gives this task's own
                // bank context its ledger; what other processes left for
                // this task meanwhile is taken with it.
                let l = std::sync::Arc::clone(&self.dtask.rusage.bank.lock().unwrap_or_else(|e| e.into_inner()));
                self.dtask.ipc_raw.own_ledger = Some(l);
                let (tid, pc) = (self.tid, self.syscall_pc);
                self.dtask.ipc_raw.check_out(&self.procs.darwin_ipc, || format!("kernel call by thread {tid} (its last system call's pc {pc:#x})"));
                self.darwin_mailbox_fetch();
            } else {
                self.dtask.ipc_raw.check_out(&self.procs.darwin_ipc, String::new);
            }
        }
        &mut self.dtask.ipc_raw
    }

    /// In the page, what other processes left in this task's global
    /// mailbox, taken with the table: its policy's and ledger's changes
    /// made now (the table gave its own elements the policy and ledger
    /// themselves, which those changes are owed to before any other call
    /// reads them), the rest left in its mailbox for its thread calls.
    fn darwin_mailbox_fetch(&mut self) {
        let key = self.dtask.ipc_raw.task;
        let Some(link) = self.dtask.ipc_raw.link.clone() else { return };
        if key == 0 {
            return;
        }
        let mut rest = Vec::new();
        for b in ipc::wire::mailbox_take(key) {
            match ipc::wire::remote_of(&b) {
                Ok(ipc::Remote::Policy(op)) => self.darwin_policy_with(|p| op.apply(p)),
                Ok(ipc::Remote::Ledger { to_me, to_others, unkept }) => {
                    use std::sync::atomic::Ordering::AcqRel;
                    let l = std::sync::Arc::clone(&self.dtask.rusage.bank.lock().unwrap_or_else(|e| e.into_inner()));
                    l.to_me.fetch_add(to_me, AcqRel);
                    l.to_others.fetch_add(to_others, AcqRel);
                    l.unkept.fetch_or(unkept, AcqRel);
                }
                Ok(r) => rest.push(r),
                Err(e) => panic!("gex: a remote in task {key}'s global mailbox is not one ({e:?})"),
            }
        }
        if !rest.is_empty() {
            link.mailbox.lock().unwrap_or_else(|e| e.into_inner()).extend(rest);
            link.ring();
        }
    }

    /// `ipc_task_enable`: other tasks reach this task from here on, by its
    /// pid and through its ports. Its link (its mailbox, the bell of its
    /// thread calls, which empty it, and what other tasks read of its
    /// process) goes in the system's table under its key, made with its
    /// space if it has none yet; a spawn's watch ports are bound to it
    /// (`proc_set_task_spawnpolicy`, the spawn's rights to them let go
    /// after). `fork` and `posix_spawn` enable the new task before they
    /// return to the parent (a spawn's once its image is activated), an
    /// exec its new task once the image is in (and the run's first process
    /// its own), each before it runs.
    pub fn darwin_task_enable(&mut self) {
        let held = self.dtask.ipc_raw.held;
        let link = ipc::TaskLink {
            mailbox: std::sync::Mutex::new(Vec::new()),
            bell: self.dtask.timers.bell(),
            pid: self.pid,
            ipc_active: Default::default(),
            name_port: std::sync::Mutex::new(None),
            codesign: self.dtask.codesign.clone(),
            policy: self.dtask.policy.clone().or_else(|| self.procs.task_policy(self.pid)),
            elsewhere: None,
        };
        self.ipc().task_enable(link);
        // The task's threads, whose time by effective QoS its policy's
        // changes settle, and what each asked for.
        if let Some(cell) = self.dtask.policy.clone().or_else(|| self.procs.task_policy(self.pid)) {
            cell.qos_time.set_threads(&self.thread_signals);
        }
        let mut tids: Vec<i32> = self.dtask.threads.map.keys().copied().collect();
        tids.push(self.tid);
        for tid in tids {
            self.darwin_qos_note(tid);
        }
        if let Some((ports, adaptive)) = self.dtask.pending_watchports.take() {
            let ipc = self.ipc();
            let key = ipc.task;
            ipc.imp_add_watchports(key, &ports, adaptive);
            for p in ports.into_iter().flatten() {
                ipc.release_send(p);
            }
        }
        if !held {
            self.darwin_ipc_leave();
        }
    }

    /// The kernel call is done with IPC: the system's table goes back for
    /// the other tasks.
    pub fn darwin_ipc_leave(&mut self) {
        // A live donor whose donor mark changed in this call has its
        // importance propagated (`task_policy_update_complete_unlocked`).
        if importance::LIVE_DONOR_CHANGED.load(std::sync::atomic::Ordering::Relaxed) {
            self.ipc().importance_settle();
        }
        // The file lock assertions the locks took and gave back.
        if lockf::IMP_PENDING.load(std::sync::atomic::Ordering::Relaxed) {
            for (hold, pid) in lockf::take_importance() {
                self.ipc().imp_file_lock(pid, hold);
            }
        }
        self.dtask.ipc_raw.check_in();
    }

    /// This process's task policy, as it is now.
    pub(crate) fn darwin_policy(&self) -> taskpolicy::TaskPolicy {
        let cell = self.dtask.policy.clone().or_else(|| self.procs.task_policy(self.pid));
        cell.map(|c| *c.lock().unwrap_or_else(|e| e.into_inner())).unwrap_or_default()
    }

    /// Change this process's task policy.
    pub(crate) fn darwin_policy_with<R>(&mut self, f: impl FnOnce(&mut taskpolicy::TaskPolicy) -> R) -> R {
        if self.dtask.policy.is_none() {
            self.dtask.policy = self.procs.task_policy(self.pid);
        }
        let Some(c) = self.dtask.policy.clone() else { return f(&mut taskpolicy::TaskPolicy::default()) };
        let (r, changed) = {
            let mut p = c.lock().unwrap_or_else(|e| e.into_inner());
            let before = p.imp;
            let r = f(&mut p);
            (r, p.imp != before)
        };
        // In the page the other processes read this task's importance marks
        // from the table: taken now, it has them as they are when the call
        // gives it back.
        if changed && share::remote().is_some() && self.dtask.ipc_raw.link.is_some() {
            self.ipc();
        }
        r
    }

    /// The gaps [`note_unimplemented`] noted in this call, reported.
    pub(crate) fn darwin_take_notes(&mut self) {
        for what in NOTES.with(|n| std::mem::take(&mut *n.borrow_mut())) {
            self.darwin_unimplemented(what);
        }
    }

    /// A use of the Darwin system's state that reaches what process `pid`
    /// of the page (or several, [`held::SEVERAL`]) holds of a subsystem that
    /// is each process's own copy there ([`held`]): reported as not
    /// implemented, for the caller to fail.
    pub(crate) fn darwin_elsewhere(&mut self, what: &str, pid: i32) {
        let who = if pid == held::SEVERAL { "other processes of the page".to_string() } else { format!("process {pid} of the page") };
        self.darwin_unimplemented(format!("{what}, which {who} holds: in the page each process has its own copy of it, not the system's"));
    }

    /// Whether a change to the system-wide state `kind`, which every process
    /// reads without asking (the mount list, a freeze), is one this process
    /// may make where the state is each process's own copy: not when
    /// another process of the page changed it, nor while another Darwin
    /// process of the page runs (its copy would not change). Reported as
    /// `what`, for the caller to fail.
    pub(crate) fn darwin_system_change_refused(&mut self, kind: held::Kind, what: &str) -> bool {
        let pid = self.pid;
        let Some(h) = held::elsewhere(kind, &[], pid).or_else(|| held::any_elsewhere(held::Kind::Process, pid)) else { return false };
        self.darwin_elsewhere(what, h);
        true
    }

    /// A Darwin process of the page has started (its exec): it is one of
    /// the page's from now on, and what other processes changed of the
    /// system-wide state it reads from its start is reported: the mount
    /// list, which every path it looks up reads, and a freeze, which every
    /// write it makes checks.
    pub fn darwin_page_start(&mut self) {
        let pid = self.pid;
        held::set_me(pid);
        held::claim(held::Kind::Process, &pid.to_le_bytes(), pid);
        if let Some(h) = held::elsewhere(held::Kind::Mounts, &[], pid) {
            self.darwin_elsewhere("the mount list, which another process changed (mount(2), MNT_UPDATE or a shutdown's unmounts)", h);
        }
        if let Some(h) = held::elsewhere(held::Kind::Freeze, &[], pid) {
            self.darwin_elsewhere("a filesystem freeze (F_FREEZE_FS), which every write checks", h);
        }
    }

    /// Something a Darwin program asked for that this kernel does not do.
    /// It is said once per kind; under strict mode the process stops with
    /// SIGSYS when the call returns ([`Self::darwin_strict_stop`]).
    pub fn darwin_unimplemented(&mut self, what: String) {
        if self.dtask.said.insert(what.clone()) || self.trace {
            crate::darwin_say!("[gex:{}] Darwin: not implemented: {what}", self.pid);
        }
        if self.dtask.strict && self.dtask.stop.is_none() {
            self.dtask.stop = Some(what);
        }
    }

    /// The strict-mode stop a call left, taken.
    pub(crate) fn darwin_strict_stop(&mut self) -> Option<String> {
        self.dtask.stop.take()
    }

    /// The task's audit token (`proc_calc_audit_token`): auid, euid, egid,
    /// ruid, rgid, pid, asid, pidversion. A process launchd has put in no
    /// session has the default one (`AU_DEFAUDITID`, `AU_DEFAUDITSID`).
    pub(crate) fn darwin_audit_token(&self) -> [u32; 8] {
        // A corpse fork's is its parent's.
        if let Some(t) = self.dtask.corpse.as_ref().and_then(|c| c.audit) {
            return t;
        }
        const AU_DEFAUDITID: u32 = u32::MAX;
        const AU_DEFAUDITSID: u32 = 0;
        let c = &self.dtask.cred;
        [AU_DEFAUDITID, c.uid, c.gid(), c.ruid, c.rgid, self.pid as u32, AU_DEFAUDITSID, self.dtask.pidversion as u32]
    }

    /// A fatal Mach port guard exception was raised: with no exception
    /// handler the task exits as `exit_with_mach_exception` makes it, killed
    /// by SIGKILL.
    /// The end here is not `exit_with_guard_exception`'s: it makes no
    /// OS_REASON_GUARD exit reason and runs no `proc_prepareexit`, so the
    /// critical exit a crash behavior or initproc calls for is reported.
    pub(crate) fn darwin_guard_kill(&mut self) -> Option<crate::syscalls::SyscallOutcome> {
        if !std::mem::take(&mut self.dtask.guard_kill) {
            return None;
        }
        if self.dtask.crash_behavior != 0 || (self.pid == crate::proc::INIT_PID && !self.procs.virtual_init()) {
            self.darwin_unimplemented("the critical exit of a process a Mach port guard kills (exit_with_guard_exception's OS_REASON_GUARD exit reason and proc_prepareexit)".into());
        }
        Some(crate::syscalls::SyscallOutcome::Killed { signal: crate::signal::sig::SIGKILL as u32, core: false })
    }
}

/// The system's `nextuniqueid`: a new process takes the next (the kernel's
/// own process is 0, so the first is 1). The global kernel's where it holds
/// the system's state ([`share`]).
pub fn next_uniqueid() -> u64 {
    share::next(share::Counter::Uniqueid).unwrap_or_else(local_next_uniqueid)
}

fn local_next_uniqueid() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
}

/// `task_set_uniqueid`: `next_taskuniqueid`, one counter for every task
/// (OSIncrementAtomic64, which gives the value before). task_init's
/// task_create_internal of the kernel task took 0, so the first task made
/// here takes 1. Every task_create_internal takes one (a fork's or spawn's
/// child, an exec's new task in cloneproc, a corpse fork), and so do
/// exec_handle_sugid (each image activated) and task_mark_corpse.
pub fn next_task_uniqueid() -> u64 {
    share::next(share::Counter::TaskUniqueid).unwrap_or_else(local_next_task_uniqueid)
}

fn local_next_task_uniqueid() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// The system's `thread_unique_id`: a new thread takes the next (the first
/// is 101).
pub fn next_thread_id() -> u64 {
    share::next(share::Counter::ThreadId).unwrap_or_else(local_next_thread_id)
}

fn local_next_thread_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(100);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
}

/// `nextpidversion`: one counter for the system, taken at each exec
/// (`OSIncrementAtomic` returns the value before).
pub fn next_pidversion() -> i32 {
    share::next(share::Counter::Pidversion).map_or_else(local_next_pidversion, |v| v as u32 as i32)
}

fn local_next_pidversion() -> i32 {
    static NEXT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Where iOS 17's dyld finds the shared cache: in the SystemOS cryptex,
/// through the system volume's link `/System/Cryptexes/OS` to the
/// cryptex's graft on the Preboot volume.
pub const CACHE_PATH: &str = "/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64";

/// Where a Darwin thread puts its system call number.
pub const NR_SLOT: usize = ctx::x(16);

/// The machine-dependent call class (`PLATFORM_SYSCALL_TRAP_NO`'s x16).
pub const PLATFORM: u64 = 0x8000_0000;

/// `machdep_call` numbers in x3 under [`PLATFORM`].
pub mod machdep {
    pub const ICACHE_INVALIDATE: u64 = 0;
    pub const DCACHE_FLUSH: u64 = 1;
    pub const THREAD_SET_TSD: u64 = 2;
}

/// `machine_thread_set_tsd_base`: a thread's TSD base (`cthread_self`), none
/// past its map's end, and its TPIDRRO_EL0.
pub(crate) fn set_tsd_base(m: &mut GuestMem<'_>, ctx_addr: u64, thread: &crate::signal::ThreadSig, tsd: u64, map_max: u64) -> Result<(), Errno> {
    let tsd = if tsd > map_max { 0 } else { tsd };
    thread.set_tsd(tsd);
    // The context is the kernel's.
    m.kernel().write_u64(ctx_addr + ctx::TPIDRRO as u64, tsd)
}

/// A call answered here without going through the Linux dispatch: the
/// machine-dependent class. `None` for everything else.
/// `thread` is the calling thread's record, and `map_max` its task map's
/// highest address.
pub fn direct(m: &mut GuestMem<'_>, ctx_addr: u64, raw: u64, thread: &crate::signal::ThreadSig, map_max: u64) -> Option<u64> {
    if raw as u32 as u64 != PLATFORM {
        return None;
    }
    let code = m.read_u64(ctx_addr + ctx::x(3) as u64).unwrap_or(!0);
    Some(match code {
        // gex keeps no instruction cache to invalidate, and its data
        // writes are already visible.
        machdep::ICACHE_INVALIDATE | machdep::DCACHE_FLUSH => 0,
        machdep::THREAD_SET_TSD => {
            let tsd = m.read_u64(ctx_addr + ctx::x(0) as u64).unwrap_or(0);
            match set_tsd_base(m, ctx_addr, thread, tsd, map_max) {
                Ok(()) => 0,
                Err(e) => neg(e),
            }
        }
        _ => neg(Errno::ENOSYS),
    })
}

fn neg(e: Errno) -> u64 {
    (-(e.0 as i64)) as u64
}

/// Whether x16's number is a Mach trap: negative as the 32-bit value
/// libsyscall loads (`mov w16, #-n`), the machine-dependent class aside.
/// What a BSD call number comes to (`unix_syscall`).
pub enum Bsd {
    /// Call `nr`; its arguments start at register `first` (x1 for an
    /// indirect call through call 0, x0 otherwise).
    Call { nr: u64, first: u8 },
    /// An `enosys` entry: ENOSYS.
    Enosys,
    /// `nosys` (a retired entry, or past the table): SIGSYS, then ENOSYS.
    Nosys,
}

/// Resolve x16 as XNU does: zero means the number is in x0 and the
/// arguments follow it; the number is truncated to 16 bits, and one past
/// the table is `SYS_invalid`, a `nosys` entry.
pub fn bsd_call(m: &GuestMem<'_>, ctx_addr: u64, raw: u64) -> Bsd {
    let (code, first) = bsd_code(m, ctx_addr, raw);
    if code == 0 || code >= sysno::NSYSENT {
        Bsd::Nosys
    } else if sysno::ENOSYS.contains(&code) {
        Bsd::Enosys
    } else if sysno::name(code).is_none() {
        Bsd::Nosys
    } else {
        Bsd::Call { nr: code, first }
    }
}

/// The call's number, as `arm_get_syscall_number` reads it, and the
/// register its arguments start at.
fn bsd_code(m: &GuestMem<'_>, ctx_addr: u64, raw: u64) -> (u64, u8) {
    if raw != 0 {
        (raw as u16 as u64, 0)
    } else {
        (m.read_u64(ctx_addr + ctx::x(0) as u64).unwrap_or(0) as u16 as u64, 1)
    }
}

/// `SYS_invalid`: the entry a number past the table is taken as.
const SYS_INVALID: u64 = 63;

/// `unix_syscall`'s `syscode`, which its MAC filter asks about: the call's
/// number, or `SYS_invalid` past the table.
pub fn bsd_syscode(m: &GuestMem<'_>, ctx_addr: u64, raw: u64) -> u64 {
    let (code, _) = bsd_code(m, ctx_addr, raw);
    if code < sysno::NSYSENT { code } else { SYS_INVALID }
}

pub fn mach_trap_number(raw: u64) -> Option<i32> {
    let t = raw as u32 as i32;
    (t < 0 && raw as u32 as u64 != PLATFORM).then_some(t)
}

/// Write a Mach trap's result: x0 only.
pub fn set_mach_result(m: &mut GuestMem<'_>, ctx_addr: u64, kr: u64) -> Result<(), Errno> {
    m.write_u64(ctx_addr + ctx::x(0) as u64, kr)
}

/// Write a result in the canonical encoding (a value, or `-errno` with a
/// Linux errno) back the way Darwin returns it: on success the value in x0
/// and carry clear, on failure the Darwin errno in x0 and carry set.
pub fn set_result(m: &mut GuestMem<'_>, ctx_addr: u64, ret: u64) -> Result<(), Errno> {
    let r = ret as i64;
    let (x0, carry) = if (-4095..0).contains(&r) { (errno::to_darwin(-r as i32) as u64, 1u8) } else { (ret, 0u8) };
    m.write_u64(ctx_addr + ctx::x(0) as u64, x0)?;
    m.write(ctx_addr + ctx::CF as u64, &[carry])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_mem() -> Vec<u8> {
        vec![0u8; ctx::TPIDRRO + 64]
    }

    #[test]
    fn success_clears_carry() {
        let mut b = ctx_mem();
        b[ctx::CF] = 1;
        let mut m = GuestMem::new(&mut b);
        set_result(&mut m, 0, 18).unwrap();
        assert_eq!(m.read_u64(ctx::x(0) as u64).unwrap(), 18);
        assert_eq!(b[ctx::CF], 0);
    }

    #[test]
    fn failure_sets_carry_and_the_darwin_errno() {
        let mut b = ctx_mem();
        let mut m = GuestMem::new(&mut b);
        // Linux EAGAIN (11) is Darwin's 35.
        set_result(&mut m, 0, (-11i64) as u64).unwrap();
        assert_eq!(m.read_u64(ctx::x(0) as u64).unwrap(), 35);
        assert_eq!(b[ctx::CF], 1);
    }

    #[test]
    fn thread_set_tsd_writes_tpidrro() {
        let mut b = ctx_mem();
        let mut m = GuestMem::new(&mut b);
        m.write_u64(ctx::x(0) as u64, 0x2_0000_8000).unwrap();
        m.write_u64(ctx::x(3) as u64, machdep::THREAD_SET_TSD).unwrap();
        let t = crate::signal::ThreadSig::new_thread(0);
        assert_eq!(direct(&mut m, 0, PLATFORM, &t, vm::MAP_MAX), Some(0));
        assert_eq!(m.read_u64(ctx::TPIDRRO as u64).unwrap(), 0x2_0000_8000);
        assert_eq!(t.tsd(), 0x2_0000_8000);
        assert_eq!(direct(&mut m, 0, 4, &t, vm::MAP_MAX), None);
        // Past the map's end, none.
        m.write_u64(ctx::x(0) as u64, vm::MAP_MAX + 1).unwrap();
        assert_eq!(direct(&mut m, 0, PLATFORM, &t, vm::MAP_MAX), Some(0));
        assert_eq!(m.read_u64(ctx::TPIDRRO as u64).unwrap(), 0);
        assert_eq!(t.tsd(), 0);
    }
}
