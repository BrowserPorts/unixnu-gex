//! Corpses (`osfmk/corpses/corpse.c`, `osfmk/kern/task.c`,
//! `bsd/kern/kern_exit.c`): a crashed task kept after its process's end
//! for its EXC_CORPSE_NOTIFY handler to look at, its threads held for
//! inspection and its crash information (a kcdata buffer,
//! `populate_corpse_crashinfo`) kept with it until the last send right to
//! its port goes.
//!
//! A crash no EXC_CRASH handler took makes the crashing task itself the
//! corpse (`task_mark_corpse`, from `proc_prepareexit`): its IPC space ends
//! there, its BSD exit goes on (the parent sees it end), and its last
//! thread, once `proc_exit` is done, gives it new task and thread ports and
//! sends the notification (`task_deliver_crash_notification`). Here the
//! task's kernel outlives its process for that: its thread calls deliver
//! the notification and serve the handler's requests to the corpse's ports
//! until the corpse's port has no senders (`task_port_no_senders`), when
//! the task is terminated.
//!
//! Corpses in flight are counted (`inflight_corpses`): at most
//! `TOTAL_CORPSES_ALLOWED`, and of them at most `TOTAL_USER_FAULTS_ALLOWED`
//! for simulated user faults.

use super::kcdata::Kcdata;
use std::sync::atomic::{AtomicU32, Ordering};

/// `CORPSEINFO_ALLOCATION_SIZE`: this kernel has no `CONFIG_EXCLAVES` (its
/// `task_map_corpse_info_64` maps 0x4000 bytes).
pub const CORPSEINFO_ALLOCATION_SIZE: usize = 0x4000;
/// `TOTAL_CORPSES_ALLOWED` (not a watch), `TOTAL_USER_FAULTS_ALLOWED`: the
/// 21H461 `task_crashinfo_get_ref` compares the counts with 5 and 1.
pub const TOTAL_CORPSES_ALLOWED: u16 = 5;
pub const TOTAL_USER_FAULTS_ALLOWED: u16 = 1;
/// `VM_MEMORY_CORPSEINFO`: the tag of a mapped copy of a corpse's crash
/// information.
pub const VM_MEMORY_CORPSEINFO: u32 = 80;

/// `corpse_flags_t` (`kcd_user_flags`).
pub mod flags {
    pub const HAS_REF: u16 = 0x1;
    pub const USER_FAULT: u16 = 0x2;
}

/// `TASK_CRASHINFO_*` and the other item types a corpse's crash
/// information holds (`kcdata.h`).
pub mod ty {
    pub const BSDINFOWITHUNIQID: u32 = 0x802;
    pub const PID: u32 = 0x805;
    pub const PPID: u32 = 0x806;
    pub const RUSAGE_INFO: u32 = 0x808;
    pub const PROC_NAME: u32 = 0x809;
    pub const PROC_STARTTIME: u32 = 0x80B;
    pub const USERSTACK: u32 = 0x80C;
    pub const ARGSLEN: u32 = 0x80D;
    pub const EXCEPTION_CODES: u32 = 0x80E;
    pub const PROC_PATH: u32 = 0x80F;
    pub const PROC_CSFLAGS: u32 = 0x810;
    pub const UID: u32 = 0x812;
    pub const GID: u32 = 0x813;
    pub const PROC_ARGC: u32 = 0x814;
    pub const PROC_FLAGS: u32 = 0x815;
    pub const CPUTYPE: u32 = 0x816;
    pub const WORKQUEUEINFO: u32 = 0x817;
    pub const RESPONSIBLE_PID: u32 = 0x818;
    pub const DIRTY_FLAGS: u32 = 0x819;
    pub const CRASHED_THREADID: u32 = 0x81A;
    pub const COALITION_ID: u32 = 0x81B;
    pub const UDATA_PTRS: u32 = 0x81C;
    pub const MEMORY_LIMIT: u32 = 0x81D;
    pub const LEDGER_INTERNAL: u32 = 0x81E;
    pub const LEDGER_INTERNAL_COMPRESSED: u32 = 0x81F;
    pub const LEDGER_IOKIT_MAPPED: u32 = 0x820;
    pub const LEDGER_ALTERNATE_ACCOUNTING: u32 = 0x821;
    pub const LEDGER_ALTERNATE_ACCOUNTING_COMPRESSED: u32 = 0x822;
    pub const LEDGER_PURGEABLE_NONVOLATILE: u32 = 0x823;
    pub const LEDGER_PURGEABLE_NONVOLATILE_COMPRESSED: u32 = 0x824;
    pub const LEDGER_PAGE_TABLE: u32 = 0x825;
    pub const LEDGER_PHYS_FOOTPRINT: u32 = 0x826;
    pub const LEDGER_PHYS_FOOTPRINT_LIFETIME_MAX: u32 = 0x827;
    pub const LEDGER_NETWORK_NONVOLATILE: u32 = 0x828;
    pub const LEDGER_NETWORK_NONVOLATILE_COMPRESSED: u32 = 0x829;
    pub const LEDGER_WIRED_MEM: u32 = 0x82A;
    pub const PROC_PERSONA_ID: u32 = 0x82B;
    pub const MEMORY_LIMIT_INCREASE: u32 = 0x82C;
    pub const LEDGER_TAGGED_FOOTPRINT: u32 = 0x82D;
    pub const LEDGER_TAGGED_FOOTPRINT_COMPRESSED: u32 = 0x82E;
    pub const LEDGER_MEDIA_FOOTPRINT: u32 = 0x82F;
    pub const LEDGER_MEDIA_FOOTPRINT_COMPRESSED: u32 = 0x830;
    pub const LEDGER_GRAPHICS_FOOTPRINT: u32 = 0x831;
    pub const LEDGER_GRAPHICS_FOOTPRINT_COMPRESSED: u32 = 0x832;
    pub const LEDGER_NEURAL_FOOTPRINT: u32 = 0x833;
    pub const LEDGER_NEURAL_FOOTPRINT_COMPRESSED: u32 = 0x834;
    pub const MEMORYSTATUS_EFFECTIVE_PRIORITY: u32 = 0x835;
    pub const KERNEL_TRIAGE_INFO_V1: u32 = 0x836;
    pub const TASK_IS_CORPSE_FORK: u32 = 0x837;
    pub const EXCEPTION_TYPE: u32 = 0x838;
    pub const CRASH_COUNT: u32 = 0x839;
    pub const THROTTLE_TIMEOUT: u32 = 0x83A;
    pub const CS_SIGNING_ID: u32 = 0x83B;
    pub const CS_TEAM_ID: u32 = 0x83C;
    pub const CS_VALIDATION_CATEGORY: u32 = 0x83D;
    pub const CS_TRUST_LEVEL: u32 = 0x83E;
    pub const PROC_CPUTYPE: u32 = 0x83F;
    /// `EXIT_REASON_SNAPSHOT`.
    pub const EXIT_REASON_SNAPSHOT: u32 = 0x1001;
}

/// What holds a corpse's kernel alive after its process's end: the
/// host's reference to it, let go when the corpse is terminated.
#[derive(Default)]
pub struct Keep(pub Option<Box<dyn std::any::Any + Send>>);

impl std::fmt::Debug for Keep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() { "Keep(held)" } else { "Keep(none)" })
    }
}

/// A corpse's own state (`TFRO_CORPSE` and what goes with it).
#[derive(Debug)]
pub struct Corpse {
    /// `corpse_info`, with its `kcd_user_flags`.
    pub info: Kcdata,
    pub user_flags: u16,
    /// `crashed_thread_id`.
    pub crashed_thread_id: u64,
    /// `TF_CORPSE_FORK`: a copy of a live task, not the crashed task.
    pub fork: bool,
    /// `TF_PENDING_CORPSE` (`task_corpse_pending_report`).
    pub pending_report: bool,
    /// The thread the notification goes out from (the last to end, or the
    /// fork's equivalent of the one that raised it), and its register
    /// context.
    pub thread: i32,
    pub ctx: u64,
    /// The threads kept for inspection (`thread->inspection`).
    pub inspection: Vec<i32>,
    /// `task_uniqueid`, which `task_set_uniqueid` gives the corpse (no
    /// other task has one: 0).
    pub task_uniqueid: u64,
    /// The notification's exception type and subcode.
    pub etype: usize,
    pub subcode: i64,
    /// The delivery waiting for its handler's reply.
    pub pending: Option<super::triage::Pending>,
    /// The send right `convert_corpse_to_port_and_nsrequest` made, let go
    /// when the delivery is done.
    pub port: Option<super::ipc::ObjId>,
    /// The corpse's address space, as other tasks' kernels reach it.
    pub vm: Option<std::sync::Arc<crate::proc::PeerVm>>,
    pub keep: Keep,
}

/// `union corpse_creation_gate`'s word (`inflight_corpses`): the user
/// faults in its low half, the corpses in its high half.
static INFLIGHT: AtomicU32 = AtomicU32::new(0);

/// `KERN_RESOURCE_SHORTAGE`.
const KERN_RESOURCE_SHORTAGE: u64 = 6;

/// `total_corpses_count`: the corpses in flight.
pub fn total_corpses_count() -> u16 {
    (INFLIGHT.load(Ordering::Relaxed) >> 16) as u16
}

/// The simulated user faults among them.
pub fn total_user_faults_count() -> u16 {
    INFLIGHT.load(Ordering::Relaxed) as u16
}

/// `task_crashinfo_get_ref`: one more corpse in flight (and user fault,
/// for `flags::USER_FAULT`), unless the limit is reached:
/// KERN_RESOURCE_SHORTAGE. `who` is the calling process's best name and pid
/// for the kernel log lines it writes ([`kernel_log`]).
pub fn get_ref(f: u16, who: (&str, i32)) -> Result<(), u64> {
    let (name, pid) = who;
    let mut old = INFLIGHT.load(Ordering::Relaxed);
    loop {
        let (mut faults, mut corpses) = (old as u16, (old >> 16) as u16);
        if f & flags::USER_FAULT != 0 {
            let had = faults;
            faults = faults.wrapping_add(1);
            if had >= TOTAL_USER_FAULTS_ALLOWED {
                kernel_log(format!("{name}[{pid}] Corpse failure, too many faults {faults}"));
                return Err(KERN_RESOURCE_SHORTAGE);
            }
        }
        let had = corpses;
        corpses = corpses.wrapping_add(1);
        if had >= TOTAL_CORPSES_ALLOWED {
            kernel_log(format!("{name}[{pid}] Corpse failure, too many {corpses}"));
            return Err(KERN_RESOURCE_SHORTAGE);
        }
        let new = u32::from(faults) | (u32::from(corpses) << 16);
        match INFLIGHT.compare_exchange(old, new, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => {
                kernel_log(format!("{name}[{pid}] Corpse allowed {corpses} of {TOTAL_CORPSES_ALLOWED}"));
                return Ok(());
            }
            Err(v) => old = v,
        }
    }
}

/// A line of the kernel's log (`printf`, `os_log`), as this kernel gives
/// it: on the host's standard error. (`os_log`'s own reader, `/dev/oslog`,
/// is not modelled, and says so when opened.)
pub fn kernel_log(line: String) {
    eprintln!("{line}");
}

/// `task_crashinfo_release_ref`.
pub fn release_ref(f: u16) {
    let mut old = INFLIGHT.load(Ordering::Relaxed);
    loop {
        let (mut faults, mut corpses) = (old as u16, (old >> 16) as u16);
        if f & flags::USER_FAULT != 0 {
            faults = faults.checked_sub(1).expect("corpse in flight count over-release");
        }
        corpses = corpses.checked_sub(1).expect("corpse in flight count over-release");
        let new = u32::from(faults) | (u32::from(corpses) << 16);
        match INFLIGHT.compare_exchange(old, new, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => {
                kernel_log(format!("Corpse released, count at {corpses}"));
                return;
            }
            Err(v) => old = v,
        }
    }
}

/// `task_crashinfo_alloc_init` of a zeroed `CORPSEINFO_ALLOCATION_SIZE`
/// allocation (`task_collect_crash_info`): the reference its flags ask
/// for taken first (none for a corpse fork, whose reference its creation
/// took), the buffer begun with `TASK_CRASHINFO_BEGIN`.
pub fn crashinfo_alloc_init(user_flags: u16, who: (&str, i32)) -> Option<Kcdata> {
    if user_flags & flags::HAS_REF != 0 && get_ref(user_flags, who).is_err() {
        return None;
    }
    let k = Kcdata::alloc_init(super::kcdata::BUFFER_BEGIN_CRASHINFO, CORPSEINFO_ALLOCATION_SIZE, 0);
    if k.is_none() && user_flags & flags::HAS_REF != 0 {
        release_ref(user_flags);
    }
    k
}

/// Whether the host keeps a corpse's task past its process's end
/// ([`set_host_keeps_corpses`]).
static HOST_KEEPS_CORPSES: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The host keeps a corpse's task (its kernel and memory) past its
/// process's end, and calls [`hold`] and [`exited`] there.
pub fn set_host_keeps_corpses() {
    HOST_KEEPS_CORPSES.store(true, Ordering::Release);
}

/// `next_taskuniqueid`: `task_set_uniqueid`'s counter (OSIncrementAtomic64,
/// which gives the value before the increment).
static NEXT_TASKUNIQUEID: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// `KERN_NO_SPACE`, `KERN_NOT_SUPPORTED`.
const KERN_NO_SPACE: u64 = 3;
const KERN_NOT_SUPPORTED: u64 = 46;

/// `MACH_RCV_PORT_DIED`, `KERN_FAILURE`, `KERN_TERMINATED`,
/// `KERN_SUCCESS`, `KERN_INVALID_ARGUMENT`.
const RCV_PORT_DIED: u64 = 0x1000_4009;
const KERN_FAILURE: u64 = 5;
const KERN_TERMINATED: u64 = 37;
const KERN_SUCCESS: u64 = 0;
const KERN_INVALID_ARGUMENT: i32 = 4;

/// What other tasks' kernels reach of a corpse (the `corpse_tasks` queue's
/// task): its process, its crash information as populated, its address
/// space.
#[derive(Debug)]
pub struct Registered {
    pub pid: i32,
    /// `task_uniqueid` (`find_corpse_task_by_uniqueid_grp`).
    pub task_uniqueid: u64,
    pub info: Vec<u8>,
    pub vm: Option<std::sync::Arc<crate::proc::PeerVm>>,
}

/// `corpse_tasks`, by the corpse's task key.
fn registry() -> std::sync::MutexGuard<'static, std::collections::HashMap<super::ipc::TaskKey, std::sync::Arc<Registered>>> {
    static R: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<super::ipc::TaskKey, std::sync::Arc<Registered>>>> = std::sync::OnceLock::new();
    R.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

/// Task `task` if it is a corpse (`task_is_a_corpse`), as its kernel
/// registered it.
pub fn find(task: super::ipc::TaskKey) -> Option<std::sync::Arc<Registered>> {
    registry().get(&task).cloned()
}

/// The address space of the corpse of process `pid`, for another task's
/// read of its map.
pub fn vm_of_pid(pid: i32) -> Option<std::sync::Arc<crate::proc::PeerVm>> {
    registry().values().find(|r| r.pid == pid).and_then(|r| r.vm.clone())
}

/// `CPU_TYPE_ARM64`: `cpu_type()` with `CPU_ARCH_ABI64`, for a 64-bit
/// process.
const CPU_TYPE_ARM64: u32 = 0x0100_000C;
/// `P_LP64`, `P_SUGID`.
const P_LP64: u32 = 0x4;
const P_SUGID: u32 = 0x100;
/// `MAXCOMLEN + 1`, `MAXPATHLEN`, `sizeof(rusage_info_current)`,
/// `sizeof(struct kernel_triage_info_v1)`.
const COMM_LEN: usize = 17;
const MAXPATHLEN: usize = 1024;
const RUSAGE_INFO_CURRENT_SIZE: usize = 464;
const TRIAGE_INFO_SIZE: usize = 640;
/// `MAX_CRASHINFO_SIGNING_ID_LEN`, `MAX_CRASHINFO_TEAM_ID_LEN`.
const SIGNING_ID_LEN: usize = 64;
const TEAM_ID_LEN: usize = 32;
/// `KCDATA_INVALID_CS_TRUST_LEVEL`: `get_trust_level_kdp` fails on this
/// kernel (no code signing monitor), as its `populate_corpse_crashinfo`
/// writes.
const INVALID_CS_TRUST_LEVEL: u32 = 0xffff_ffff;
/// `VM_MEMORY_IOKIT`.
const VM_MEMORY_IOKIT: u8 = 21;
/// `EXC_RESOURCE_ENCODE_TYPE`'s RESOURCE_TYPE_MEMORY and
/// `EXC_RESOURCE_ENCODE_FLAVOR`'s FLAVOR_HIGH_WATERMARK.
const RESOURCE_TYPE_MEMORY: i64 = 3;
const FLAVOR_HIGH_WATERMARK: i64 = 1;

impl crate::syscalls::Kernel {
    /// `thread_tid` of thread `tid`.
    pub(crate) fn darwin_thread_tid(&self, tid: i32) -> u64 {
        self.thread_signals.get(tid).map_or(0, |t| t.darwin_id())
    }

    /// `proc_best_name`: `p_name` when it has one, else `p_comm`.
    pub(crate) fn darwin_best_name(&self) -> String {
        let n = &self.dtask.p_name.0;
        let len = n.iter().position(|&b| b == 0).unwrap_or(n.len());
        if len > 0 {
            return String::from_utf8_lossy(&n[..len]).into_owned();
        }
        self.darwin_public(self.pid).map(|p| String::from_utf8_lossy(&p.0.comm).into_owned()).unwrap_or_default()
    }

    /// A path XNU records a kernel triage event on (`ktriage_record`) was
    /// taken by thread `tid`, the event not modelled here: what it was, for
    /// a crash report that would carry it.
    pub(crate) fn darwin_ktriage_unmodelled(&mut self, tid: i32, what: String) {
        self.dtask.ktriage_unmodelled.entry(tid).or_default().push(what);
    }

    /// The rest of `proc_prepareexit` once its EXC_CRASH went to its
    /// handlers (`kr` what `task_exception_notify` returned): a report no
    /// handler took (or a map marked a corpse source) makes the task a
    /// corpse, when the process itself is ending (not another's `exit1` of
    /// it); its crash information then gets the EXC_CRASH codes (an exit
    /// reason may rewrite them) and its usage as it ends.
    pub(crate) fn darwin_prepareexit_corpse(&mut self, kr: u64, code: i64, subcode: i64) {
        let source = std::mem::take(&mut self.dtask.corpse_source);
        let current = self.procs.forced_exit(self.pid).is_none();
        if !((kr != 0 || source) && current) {
            return;
        }
        if !HOST_KEEPS_CORPSES.load(Ordering::Acquire) {
            self.darwin_unimplemented("a corpse on a host that does not keep a task past its process's end (corpse::hold, corpse::exited)".into());
            return;
        }
        let r = self.darwin_task_mark_corpse();
        if r != KERN_SUCCESS {
            let pid = self.pid;
            kernel_log(match r {
                KERN_NO_SPACE => format!("Process[{pid}] has no vm space for corpse info."),
                KERN_NOT_SUPPORTED => format!("Process[{pid}] was destined to be corpse. But corpse is disabled by config."),
                KERN_TERMINATED => format!("Process[{pid}] has been terminated before it could be converted to a corpse."),
                _ => {
                    let comm = self.darwin_public(pid).map(|p| String::from_utf8_lossy(&p.0.comm).into_owned()).unwrap_or_default();
                    format!("Process[{pid}] crashed: {comm}. Too many corpses being created.")
                }
            });
            return;
        }
        let (code, subcode) = self.darwin_corpse_exception_codes(code, subcode);
        let udata = self.darwin_corpse_uptrs();
        let bills = self.darwin_bank_bills(self.pid, self.dtask.uniqueid, &std::sync::Arc::clone(&self.dtask.rusage));
        let Some((public, _)) = self.darwin_public(self.pid) else {
            self.darwin_unimplemented("a corpse's crash information for a process with no record of its own".into());
            return;
        };
        let record = super::rusage::crash_record(&self.procs, self.pid, &public, bills, true);
        self.darwin_populate_corpse_crashinfo(&public, code, subcode, &udata, None, super::exception::EXC_CRASH, record);
    }

    /// `proc_update_corpse_exception_codes`: a process killed for its
    /// memory limit has its code made an EXC_RESOURCE high watermark's
    /// (over the code as it was) and its subcode 0.
    fn darwin_corpse_exception_codes(&mut self, code: i64, subcode: i64) -> (i64, i64) {
        let Some(r) = self.procs.exit_reason(self.pid).and_then(|n| super::reason::of(&n)) else { return (code, subcode) };
        if r.namespace == super::reason::ns::JETSAM && r.code == super::reason::JETSAM_REASON_MEMORY_PERPROCESSLIMIT {
            let limit = self.procs.jetsam().ledgers.get(&self.pid).map_or(super::footprint::Ledger::default().limit, |l| l.limit);
            let c = code | ((RESOURCE_TYPE_MEMORY & 0x7) << 61) | ((FLAVOR_HIGH_WATERMARK & 0x7) << 58) | ((limit >> 20) & 0x1fff);
            return (c, 0);
        }
        (code, subcode)
    }

    /// `kevent_proc_copy_uptrs` for the crash information
    /// (proc_prepareexit's buffer holds the count it first finds and 32
    /// more, and this one's count does not change in between).
    fn darwin_corpse_uptrs(&mut self) -> Vec<u64> {
        self.dtask.kevents.proc_copy_uptrs()
    }

    /// `task_mark_corpse`: the crash information made (a corpse in flight
    /// counted, unless too many are), the task marked a corpse with its
    /// report pending, the crashing thread's id and a new `task_uniqueid`,
    /// its threads kept for inspection, its ports disabled
    /// (`ipc_task_disable`), its IPC space ended, and the task put on the
    /// corpse list once its information is in
    /// ([`Self::darwin_populate_corpse_crashinfo`]).
    fn darwin_task_mark_corpse(&mut self) -> u64 {
        let Some(info) = crashinfo_alloc_init(flags::HAS_REF, (&self.darwin_best_name(), self.pid)) else { return KERN_FAILURE };
        if self.dtask.ipc_raw.ended {
            release_ref(flags::HAS_REF);
            return KERN_TERMINATED;
        }
        let tid = self.tid;
        let mut inspection = self.thread_signals.tids_in_order();
        inspection.extend(self.dtask.threads.map.keys().copied());
        inspection.push(tid);
        inspection.sort_unstable();
        inspection.dedup();
        let vm = self.procs.vm(self.pid).ok();
        self.dtask.corpse = Some(Box::new(Corpse {
            info,
            user_flags: flags::HAS_REF,
            crashed_thread_id: self.darwin_thread_tid(tid),
            fork: false,
            pending_report: true,
            thread: tid,
            ctx: self.ctx_addr,
            inspection,
            // task_set_uniqueid.
            task_uniqueid: NEXT_TASKUNIQUEID.fetch_add(1, Ordering::Relaxed) as u64,
            etype: super::exception::EXC_CRASH,
            subcode: 0,
            pending: None,
            port: None,
            vm,
            keep: Keep::default(),
        }));
        let ipc = self.ipc();
        ipc.task_disable();
        ipc.space_terminate();
        self.darwin_ipc_notify_drain();
        KERN_SUCCESS
    }

    /// `populate_corpse_crashinfo` of this process (`public` its record)
    /// into its corpse's crash information, item by item in the order the
    /// 21H461 kernel writes them; an item that does not fit is left out.
    /// `reason` is the corpse fork's (the process's exit reason otherwise),
    /// `record` its usage (`rusage_info_current`, its footprint 0).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn darwin_populate_corpse_crashinfo(&mut self, public: &super::procinfo::Public, code: i64, subcode: i64, udata: &[u64], reason: Option<std::sync::Arc<super::reason::OsReason>>, etype: usize, record: super::rusage::Record) {
        use std::sync::atomic::Ordering::Acquire;
        let pid = self.pid;
        let ppid = self.procs.ppid(pid);
        let exit_reason = self.procs.exit_reason(pid).and_then(|n| super::reason::of(&n));
        let unkept = record.unkept_within(RUSAGE_INFO_CURRENT_SIZE);
        if !unkept.is_empty() {
            self.darwin_unimplemented(format!("a corpse's TASK_CRASHINFO_RUSAGE_INFO: {}, not kept (given as 0)", unkept.join(", ")));
        }
        let csflags = self.dtask.csflags.load(Acquire);
        let ledger = self.procs.jetsam().ledgers.get(&pid).map_or_else(super::footprint::Ledger::default, |l| *l);
        let page = super::mach::PAGE_MASK + 1;
        let alt = self.dtask.rusage.meter.alt.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let (pages, page_table, alt_pages) = {
            let pm = self.dtask.rusage.meter.lock();
            (pm.pages(), pm.page_table(), pm.own_in(&alt))
        };
        let owned = match super::purgeable::owned(&self.dtask.rusage.meter.owner()) {
            Some(o) => o,
            None => {
                self.darwin_unimplemented("a corpse's purgeable and tagged ledgers on a host that cannot say what the task's objects hold".into());
                Default::default()
            }
        };
        // vm_map_iokit_mapped_region: IOKit's accounted mappings, which no
        // mapping made here is (iokit_acct).
        let iokit = {
            let map = self.dtask.vm.lock();
            let mut at = 0;
            let mut any = false;
            while let Some(e) = map.at_or_after(at) {
                any |= e.attrs.alias == VM_MEMORY_IOKIT;
                at = e.end;
            }
            any
        };
        if iokit {
            self.darwin_unimplemented("a corpse's TASK_CRASHINFO_LEDGER_IOKIT_MAPPED for a task with IOKit mappings (vm_map_iokit_mapped_region's iokit_acct)".into());
        }
        let wq = self.darwin_fill_procworkqueue();
        let persona = self.dtask.persona.as_ref().map_or(super::persona::ID_NONE, |p| p.id);
        let coalitions = super::coalition::membership(pid).0;
        let (dirty, effective) = {
            let j = self.procs.jetsam();
            (j.dirty_get(pid).unwrap_or(0), j.get(pid).map_or(0, |m| m.effective))
        };
        let signed = csflags & super::amfi::cs::SIGNED != 0;
        let blob = self.dtask.codesign.as_ref();
        let identity = blob.and_then(|c| c.identity.clone()).filter(|_| signed);
        let team = blob.and_then(|c| c.team_id.clone()).filter(|_| signed);
        let category = blob.filter(|_| csflags & (super::amfi::cs::VALID | super::amfi::cs::DEBUGGED) != 0).map_or(0, |c| c.category);
        let reason = exit_reason.or(reason);
        let crashed_tid = self.tid;
        if let Some(events) = self.dtask.ktriage_unmodelled.get(&crashed_tid).filter(|e| !e.is_empty()) {
            let e = events.join("; ");
            self.darwin_unimplemented(format!("a corpse's TASK_CRASHINFO_KERNEL_TRIAGE_INFO_V1 for a thread that took paths XNU records triage events on: {e}"));
        }

        let Some(c) = self.dtask.corpse.as_mut() else { return };
        let crashed = c.crashed_thread_id;
        let fork = c.fork;
        c.etype = etype;
        let k = &mut c.info;
        let mut codes = code.to_le_bytes().to_vec();
        codes.extend_from_slice(&subcode.to_le_bytes());
        k.put(ty::EXCEPTION_CODES, &codes);
        k.put(ty::PID, &pid.to_le_bytes());
        k.put(ty::PPID, &ppid.to_le_bytes());
        if reason.as_ref().is_none_or(|r| r.flags & super::reason::flag::NO_CRASHED_TID == 0) {
            k.put(ty::CRASHED_THREADID, &crashed.to_le_bytes());
        }
        k.put(ty::BSDINFOWITHUNIQID, &super::procinfo::uniqidentifierinfo(public));
        k.put(ty::RUSAGE_INFO, &record.bytes()[..RUSAGE_INFO_CURRENT_SIZE]);
        k.put(ty::PROC_CSFLAGS, &csflags.to_le_bytes());
        let mut comm = [0u8; COMM_LEN];
        let n = public.comm.len().min(COMM_LEN - 1);
        comm[..n].copy_from_slice(&public.comm[..n]);
        k.put(ty::PROC_NAME, &comm);
        let mut start = (self.dtask.start.0 as i64).to_le_bytes().to_vec();
        start.extend_from_slice(&(self.dtask.start.1 as i64).to_le_bytes());
        k.put(ty::PROC_STARTTIME, &start);
        k.put(ty::USERSTACK, &self.darwin_user_stack.to_le_bytes());
        k.put(ty::ARGSLEN, &self.dtask.live.argslen.load(Acquire).to_le_bytes());
        k.put(ty::PROC_ARGC, &self.dtask.live.argc.load(Acquire).to_le_bytes());
        let mut path = vec![0u8; MAXPATHLEN];
        let n = public.path.len().min(MAXPATHLEN - 1);
        path[..n].copy_from_slice(&public.path[..n]);
        k.put(ty::PROC_PATH, &path);
        let pflags = P_LP64 | if self.dtask.sugid { P_SUGID } else { 0 };
        k.put(ty::PROC_FLAGS, &pflags.to_le_bytes());
        k.put(ty::UID, &self.dtask.cred.uid.to_le_bytes());
        k.put(ty::GID, &self.dtask.cred.gid().to_le_bytes());
        k.put(ty::CPUTYPE, &CPU_TYPE_ARM64.to_le_bytes());
        k.put(ty::PROC_CPUTYPE, &self.dtask.cputype.0.to_le_bytes());
        k.put(ty::MEMORY_LIMIT, &((ledger.limit >> 20) as u64).to_le_bytes());
        k.put(ty::LEDGER_PHYS_FOOTPRINT_LIFETIME_MAX, &(ledger.lifetime_max as u64).to_le_bytes());
        // The device's pages are not compressed (no pageout runs), so the
        // compressed ledgers hold nothing.
        for (t, v) in [
            (ty::LEDGER_INTERNAL, pages.internal * page),
            (ty::LEDGER_INTERNAL_COMPRESSED, 0),
            (ty::LEDGER_IOKIT_MAPPED, 0),
            (ty::LEDGER_ALTERNATE_ACCOUNTING, alt_pages * page),
            (ty::LEDGER_ALTERNATE_ACCOUNTING_COMPRESSED, 0),
            (ty::LEDGER_PURGEABLE_NONVOLATILE, owned.purgeable_nonvolatile),
            (ty::LEDGER_PURGEABLE_NONVOLATILE_COMPRESSED, 0),
            (ty::LEDGER_PAGE_TABLE, page_table),
            (ty::LEDGER_PHYS_FOOTPRINT, ledger.balance as u64),
            (ty::LEDGER_NETWORK_NONVOLATILE, owned.network_nonvolatile),
            (ty::LEDGER_NETWORK_NONVOLATILE_COMPRESSED, 0),
            (ty::LEDGER_WIRED_MEM, self.dtask.rusage.wired.load(Acquire)),
        ] {
            k.put(t, &v.to_le_bytes());
        }
        if let Some(w) = wq {
            let b: Vec<u8> = w.iter().flat_map(|x| x.to_le_bytes()).collect();
            k.put(ty::WORKQUEUEINFO, &b);
        }
        k.put(ty::RESPONSIBLE_PID, &self.dtask.responsible_pid.to_le_bytes());
        k.put(ty::PROC_PERSONA_ID, &persona.to_le_bytes());
        let ids: Vec<u8> = coalitions.iter().flat_map(|x| x.to_le_bytes()).collect();
        k.put_array(ty::COALITION_ID, 8, coalitions.len() as u32, &ids);
        k.put(ty::DIRTY_FLAGS, &(dirty as i32).to_le_bytes());
        // p_memlimit_increase: no call here raises a memory limit by it.
        k.put(ty::MEMORY_LIMIT_INCREASE, &0u32.to_le_bytes());
        for (t, v) in [
            (ty::LEDGER_TAGGED_FOOTPRINT, owned.tagged_footprint),
            (ty::LEDGER_TAGGED_FOOTPRINT_COMPRESSED, 0),
            (ty::LEDGER_MEDIA_FOOTPRINT, owned.media_footprint),
            (ty::LEDGER_MEDIA_FOOTPRINT_COMPRESSED, 0),
            (ty::LEDGER_GRAPHICS_FOOTPRINT, owned.graphics_footprint),
            (ty::LEDGER_GRAPHICS_FOOTPRINT_COMPRESSED, 0),
            (ty::LEDGER_NEURAL_FOOTPRINT, owned.neural_footprint),
            (ty::LEDGER_NEURAL_FOOTPRINT_COMPRESSED, 0),
        ] {
            k.put(t, &v.to_le_bytes());
        }
        k.put(ty::MEMORYSTATUS_EFFECTIVE_PRIORITY, &effective.to_le_bytes());
        // ktriage_extract of the thread (the current one, the crashed
        // one's): the buffer zeroed (bzero in ktriage_extract), then its
        // recorded events as strings. None of the paths this kernel takes
        // records one, but those reported where taken ([`Self::darwin_ktriage_unmodelled`]).
        k.put(ty::KERNEL_TRIAGE_INFO_V1, &[0u8; TRIAGE_INFO_SIZE]);
        k.put(ty::TASK_IS_CORPSE_FORK, &u32::from(fork).to_le_bytes());
        k.put(ty::EXCEPTION_TYPE, &(etype as i32).to_le_bytes());
        k.put(ty::CRASH_COUNT, &self.dtask.crash_count.to_le_bytes());
        k.put(ty::THROTTLE_TIMEOUT, &self.dtask.throttle_timeout.to_le_bytes());
        let mut id = [0u8; SIGNING_ID_LEN];
        if let Some(s) = &identity {
            let n = s.len().min(SIGNING_ID_LEN - 1);
            id[..n].copy_from_slice(&s[..n]);
        }
        k.put(ty::CS_SIGNING_ID, &id);
        let mut tm = [0u8; TEAM_ID_LEN];
        if let Some(s) = &team {
            let n = s.len().min(TEAM_ID_LEN - 1);
            tm[..n].copy_from_slice(&s[..n]);
        }
        k.put(ty::CS_TEAM_ID, &tm);
        k.put(ty::CS_VALIDATION_CATEGORY, &category.to_le_bytes());
        k.put(ty::CS_TRUST_LEVEL, &INVALID_CS_TRUST_LEVEL.to_le_bytes());
        if let Some(r) = &reason {
            let mut ers = r.namespace.to_le_bytes().to_vec();
            ers.extend_from_slice(&r.code.to_le_bytes());
            ers.extend_from_slice(&r.flags.to_le_bytes());
            k.put(ty::EXIT_REASON_SNAPSHOT, &ers);
            let data = r.data();
            if !data.is_empty() {
                k.put(super::kcdata::TYPE_NESTED_KCDATA, data);
            }
        }
        if !udata.is_empty() {
            let b: Vec<u8> = udata.iter().flat_map(|x| x.to_le_bytes()).collect();
            k.put_array(ty::UDATA_PTRS, 8, udata.len() as u32, &b);
        }
        let info = k.bytes().to_vec();
        let vm = c.vm.clone();
        let task_uniqueid = c.task_uniqueid;
        // task_add_to_corpse_task_list.
        let key = self.ipc().task;
        registry().insert(key, std::sync::Arc::new(Registered { pid, task_uniqueid, info, vm }));
    }

    /// `proc_encode_exit_exception_code`: the exit reason's namespace and
    /// code, 32 bits of each.
    fn darwin_exit_exception_code(&self) -> i64 {
        let Some(r) = self.procs.exit_reason(self.pid).and_then(|n| super::reason::of(&n)) else { return 0 };
        ((u64::from(r.namespace) << 32) | (r.code & 0xffff_ffff)) as i64
    }

    /// The corpse's last thread, once `proc_exit` is done
    /// (`thread_terminate_self`): its task's ports made anew and enabled
    /// (`ipc_task_reset`, `ipc_task_enable`), then
    /// `task_deliver_crash_notification`.
    fn darwin_corpse_last_thread(&mut self, m: &mut crate::GuestMem<'_>) {
        self.darwin_corpse_task_reset();
        if let Some(l) = self.ipc().link.clone() {
            l.ipc_active.store(true, std::sync::atomic::Ordering::Release);
        }
        let subcode = self.darwin_exit_exception_code();
        self.darwin_deliver_crash_notification(m, subcode);
    }

    /// `ipc_task_reset` of a corpse: a new control port, which is its self
    /// port too (no immovable or pinned port for a task that runs no more
    /// code), and no settable self port (the corpse's port's no-senders
    /// notification wants none); the old control and self ports and the
    /// read and inspect ports gone; the handlers not set by a privileged
    /// task released, but the corpse notification's while its report is
    /// pending.
    fn darwin_corpse_task_reset(&mut self) {
        use super::exception::{EXC_CORPSE_NOTIFY, EXC_TYPES_COUNT};
        let ipc = self.ipc();
        let new = ipc.kobject_port(super::ipc::Kobject::Task);
        let old = self.dtask.kports.task.replace((new, new));
        let mut dead: Vec<super::ipc::ObjId> = self.dtask.kports.flavored.iter_mut().filter_map(Option::take).collect();
        if let Some((k, p)) = old {
            dead.push(k);
            if p != k {
                dead.push(p);
            }
        }
        let ipc = self.ipc();
        for p in dead {
            ipc.port_mut(p).kobject = None;
            ipc.port_mut(p).pinned = false;
            ipc.port_destroy(p);
        }
        let pending = self.dtask.corpse.as_ref().is_some_and(|c| c.pending_report);
        let mut released = Vec::new();
        for i in 1..EXC_TYPES_COUNT {
            if i == EXC_CORPSE_NOTIFY && pending {
                continue;
            }
            let a = &mut self.dtask.kports.exc[i];
            if !a.privileged {
                released.push(a.port.take());
            }
        }
        let ipc = self.ipc();
        for c in released {
            super::exception::release(ipc, c);
        }
        self.darwin_ipc_notify_drain();
    }

    /// `ipc_thread_reset` of a corpse's thread: a new control port (its
    /// self port too), the old ports gone, the handlers not set by a
    /// privileged task released.
    fn darwin_corpse_thread_reset(&mut self, tid: i32) {
        use super::kobject::flavor;
        let ipc = self.ipc();
        let new = ipc.kobject_port(super::ipc::Kobject::Thread(tid));
        let old = self.dtask.kports.threads.insert(tid, (new, new));
        let mut dead: Vec<super::ipc::ObjId> = [flavor::READ, flavor::INSPECT].iter().filter_map(|&f| self.dtask.kports.thread_flavored.remove(&(tid, f))).collect();
        if let Some((k, p)) = old {
            dead.push(k);
            if p != k {
                dead.push(p);
            }
        }
        let ipc = self.ipc();
        for p in dead {
            ipc.port_mut(p).kobject = None;
            ipc.port_mut(p).pinned = false;
            ipc.port_destroy(p);
        }
        let mut released = Vec::new();
        if let Some(a) = self.dtask.kports.thread_exc.get_mut(&tid) {
            for x in a.iter_mut().skip(1) {
                if !x.privileged {
                    released.push(x.port.take());
                }
            }
        }
        let ipc = self.ipc();
        for c in released {
            super::exception::release(ipc, c);
        }
        self.darwin_ipc_notify_drain();
    }

    /// `task_deliver_crash_notification`: EXC_CORPSE_NOTIFY, its code the
    /// exception type the crash information holds and `subcode`, from the
    /// corpse's thread, at `THREAD_UNINT`, its threads' ports made anew and
    /// a send right to the corpse's port made with its no-senders
    /// notification armed; that right goes once the handler is done.
    fn darwin_deliver_crash_notification(&mut self, m: &mut crate::GuestMem<'_>, subcode: i64) {
        let Some(c) = self.dtask.corpse.as_mut() else { return };
        c.subcode = subcode;
        let code = [c.etype as i64, subcode];
        let threads = c.inspection.clone();
        for t in threads {
            self.darwin_corpse_thread_reset(t);
        }
        // convert_corpse_to_port_and_nsrequest.
        let port = self.darwin_task_port();
        let ipc = self.ipc();
        ipc.make_send(port);
        ipc.port_mut(port).nsrequest_kobject = true;
        if let Some(c) = self.dtask.corpse.as_mut() {
            c.port = Some(port);
        }
        let t = super::triage::Triage::new(super::exception::EXC_CORPSE_NOTIFY, &code, super::triage::Then::Return, true);
        self.darwin_corpse_triage(m, t);
    }

    /// `exception_triage_thread` for the corpse's thread, from level
    /// `t.level` on: a handler's request sent is waited for
    /// ([`Self::darwin_corpse_progress`]).
    fn darwin_corpse_triage(&mut self, m: &mut crate::GuestMem<'_>, mut t: super::triage::Triage) {
        use super::triage::Delivered;
        let Some((tid, ctx)) = self.dtask.corpse.as_ref().map(|c| (c.thread, c.ctx)) else { return };
        let saved = (self.tid, self.ctx_addr);
        (self.tid, self.ctx_addr) = (tid, ctx);
        let mut last = KERN_FAILURE;
        while t.level < 3 {
            let actions: Option<super::exception::ExcActions> = match t.level {
                0 => self.dtask.kports.thread_exc.get(&tid).copied(),
                1 => Some(self.dtask.kports.exc),
                _ => Some(self.ipc().host_exc),
            };
            t.level += 1;
            let Some(actions) = actions else { continue };
            if !self.darwin_exc_receiver_independent(t.exc, &actions) {
                continue;
            }
            match self.darwin_exception_deliver(m, &t, &actions[t.exc]) {
                Delivered::Done(r) => {
                    last = r;
                    if r == KERN_SUCCESS || r == RCV_PORT_DIED {
                        break;
                    }
                }
                Delivered::Sent(p) => {
                    (self.tid, self.ctx_addr) = saved;
                    if let Some(c) = self.dtask.corpse.as_mut() {
                        c.pending = Some(p);
                    }
                    self.darwin_ipc_settle(m);
                    // The reply may be in already.
                    self.darwin_corpse_progress(m);
                    return;
                }
            }
        }
        (self.tid, self.ctx_addr) = saved;
        self.darwin_corpse_delivered(last);
    }

    /// The handler's reply to the corpse's notification, if it is in: the
    /// notification is done, or goes on to the next level.
    pub(crate) fn darwin_corpse_progress(&mut self, m: &mut crate::GuestMem<'_>) {
        let Some((tid, ctx)) = self.dtask.corpse.as_ref().filter(|c| c.pending.is_some()).map(|c| (c.thread, c.ctx)) else { return };
        let Some(k) = self.dtask.rpc_replies.remove(&tid) else { return };
        let p = self.dtask.corpse.as_mut().and_then(|c| c.pending.take()).expect("a pending notification");
        let saved = (self.tid, self.ctx_addr);
        (self.tid, self.ctx_addr) = (tid, ctx);
        let r = self.darwin_exc_reply(m, &p, &k);
        (self.tid, self.ctx_addr) = saved;
        self.ipc().kmsg_destroy(k, true);
        self.darwin_ipc_settle(m);
        if r == KERN_SUCCESS || r == RCV_PORT_DIED {
            self.darwin_corpse_delivered(r);
        } else {
            self.darwin_corpse_triage(m, p.t);
        }
    }

    /// The notification is done (`kr`, its printf on failure going to the
    /// console): the corpse port's send right goes, which with no other
    /// sender ends the corpse.
    fn darwin_corpse_delivered(&mut self, kr: u64) {
        if kr != KERN_SUCCESS {
            eprintln!("Failed to send exception EXC_CORPSE_NOTIFY. error code: {} for pid {}", kr as i32, self.pid);
        }
        if let Some(port) = self.dtask.corpse.as_mut().and_then(|c| c.port.take()) {
            self.ipc().release_send(port);
            self.darwin_ipc_notify_drain();
        }
    }

    /// `task_port_no_senders` (a corpse's control port, the only task port
    /// that asks for it): told to the task's own kernel when another's
    /// call let go of the last send right; there the corpse ends.
    pub(crate) fn darwin_task_port_no_senders(&mut self, port: super::ipc::ObjId, mscount: u32) {
        let ipc = self.ipc();
        let owner = ipc.port(port).owner;
        if owner != ipc.task {
            if !ipc.remote(owner, super::ipc::Remote::KobjectNoSenders { port, mscount }) {
                self.darwin_unimplemented("a task port's no-senders notification for a task that has ended".into());
            }
            return;
        }
        let ours = self.dtask.corpse.is_some() && self.dtask.kports.task.is_some_and(|(k, _)| k == port);
        if !ours {
            self.darwin_unimplemented("a no-senders notification for a task port that is not a corpse's".into());
            return;
        }
        self.darwin_corpse_terminate();
    }

    /// A corpse's end: off the corpse list, `task_clear_corpse` (its
    /// threads no longer kept, their ports disabled), and
    /// `task_terminate_internal` with the rest of its task's end; the
    /// corpse in flight is no longer counted, and its kernel is let go.
    fn darwin_corpse_terminate(&mut self) {
        let key = self.ipc().task;
        registry().remove(&key);
        let Some(mut c) = self.dtask.corpse.take() else { return };
        c.pending_report = false;
        let keep = std::mem::take(&mut c.keep);
        let user_flags = c.user_flags;
        drop(c);
        self.darwin_task_terminate_internal();
        if user_flags & flags::HAS_REF != 0 {
            release_ref(user_flags);
        }
        drop(keep);
    }

    /// Thread calls for a corpse whose process has ended: the requests
    /// other tasks make of its ports, and its notification's progress.
    pub(crate) fn darwin_corpse_thread_calls(&mut self, m: &mut crate::GuestMem<'_>) -> bool {
        if !self.dtask.corpse.as_ref().is_some_and(|c| c.keep.0.is_some()) {
            return false;
        }
        self.darwin_ipc_remote(m);
        self.darwin_corpse_progress(m);
        true
    }

    /// `task_map_corpse_info_64(task, corpse_task)` (and
    /// `task_map_corpse_info`, `narrow`): a copy of the corpse's crash
    /// information mapped into this task, `CORPSEINFO_ALLOCATION_SIZE`
    /// bytes anywhere, tagged VM_MEMORY_CORPSEINFO; its address and size.
    /// The corpse is converted as a read port (corpses allowed, the
    /// platform binary check made); this task must not be one.
    pub(crate) fn darwin_task_map_corpse_info(&mut self, corpse: Option<super::ipc::right::Carried>, narrow: bool) -> super::kobject::Reply {
        use super::ipc::right::Carried;
        use super::ipc::Kobject;
        use super::kobject::Reply;
        let target = match corpse {
            Some(Carried::Port(p)) => {
                let ipc = self.ipc();
                let port = ipc.port(p);
                match port.kobject {
                    Some(Kobject::Task | Kobject::TaskRead) if port.active => Some(port.owner),
                    _ => None,
                }
            }
            _ => None,
        };
        let Some(owner) = target else { return Reply::err(KERN_INVALID_ARGUMENT) };
        // task_conversion_eval for the read flavor: a platform binary's
        // task only for a platform binary.
        let victim_platform = self.ipc().links.get(&owner).and_then(|l| l.codesign.as_ref()).is_some_and(|c| c.platform != 0);
        let me_platform = self.dtask.codesign.as_ref().is_some_and(|c| c.platform != 0);
        if owner != self.ipc().task && victim_platform && !me_platform {
            return Reply::err(KERN_INVALID_ARGUMENT);
        }
        if self.dtask.corpse.is_some() {
            return Reply::err(KERN_INVALID_ARGUMENT);
        }
        let Some(info) = find(owner) else { return Reply::err(KERN_INVALID_ARGUMENT) };
        const VM_FLAGS_ANYWHERE: u64 = 1;
        let r = self.darwin_own_memory(|k, m| {
            let mut addr = 0;
            let kr = k.darwin_vm_map_anon(m, &mut addr, CORPSEINFO_ALLOCATION_SIZE as u64, 0, VM_FLAGS_ANYWHERE | u64::from(VM_MEMORY_CORPSEINFO) << 24);
            if kr == KERN_SUCCESS {
                // copyout: a failure is not the call's.
                let _ = m.kernel().write(addr, &info.info);
            }
            (kr, addr)
        });
        match r {
            Ok((KERN_SUCCESS, addr)) => {
                let mut out = addr.to_le_bytes().to_vec();
                if narrow {
                    out.extend_from_slice(&(CORPSEINFO_ALLOCATION_SIZE as u32).to_le_bytes());
                } else {
                    out.extend_from_slice(&(CORPSEINFO_ALLOCATION_SIZE as u64).to_le_bytes());
                }
                Reply::ok(out)
            }
            Ok((kr, _)) => Reply::err(kr as i32),
            Err(r) => r,
        }
    }
}

/// The corpses whose process's end is not yet published, by pid: their
/// kernels, held by the corpse ([`hold`]).
fn held() -> std::sync::MutexGuard<'static, std::collections::HashMap<i32, std::sync::Weak<std::sync::Mutex<crate::syscalls::Kernel>>>> {
    static H: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<i32, std::sync::Weak<std::sync::Mutex<crate::syscalls::Kernel>>>>> = std::sync::OnceLock::new();
    H.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

/// A process's task has ended as its process did
/// ([`crate::syscalls::Kernel::darwin_task_terminate`]): a corpse's kernel
/// is kept, by the corpse, until the corpse ends, whatever its host does
/// with it.
pub fn hold(kernel: &std::sync::Arc<std::sync::Mutex<crate::syscalls::Kernel>>) {
    let mut k = kernel.lock().unwrap_or_else(|e| e.into_inner());
    if !k.dtask.corpse.as_ref().is_some_and(|c| c.pending_report && c.keep.0.is_none()) {
        return;
    }
    let pid = k.pid;
    let me: Box<dyn std::any::Any + Send> = Box::new(std::sync::Arc::clone(kernel));
    if let Some(c) = k.dtask.corpse.as_mut() {
        c.keep.0 = Some(me);
    }
    held().insert(pid, std::sync::Arc::downgrade(kernel));
}

/// Process `pid`'s end is published (`proc_exit` is done): if its task is
/// a corpse, its last thread's work follows ([`hold`] kept it).
pub fn exited(pid: i32) {
    let Some(kernel) = held().remove(&pid).and_then(|w| w.upgrade()) else { return };
    let mut k = kernel.lock().unwrap_or_else(|e| e.into_inner());
    let Some(vm) = k.dtask.corpse.as_ref().and_then(|c| c.vm.clone()) else {
        k.darwin_unimplemented("a corpse on a host with no view of its process's memory".into());
        k.darwin_corpse_terminate();
        return;
    };
    let k = &mut *k;
    vm.mem.with_guest(&mut |m| k.darwin_corpse_last_thread(m));
    k.darwin_ipc_leave();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gate_counts_corpses_and_user_faults() {
        // One test owns the gate: the counts are the system's.
        assert_eq!(total_corpses_count(), 0);
        for _ in 0..TOTAL_CORPSES_ALLOWED {
            get_ref(flags::HAS_REF, ("test", 1)).unwrap();
        }
        assert_eq!(get_ref(flags::HAS_REF, ("test", 1)), Err(6));
        release_ref(flags::HAS_REF);
        get_ref(flags::HAS_REF | flags::USER_FAULT, ("test", 1)).unwrap();
        assert_eq!(total_user_faults_count(), 1);
        release_ref(flags::HAS_REF);
        // a second user fault is refused while one is in flight
        assert_eq!(get_ref(flags::HAS_REF | flags::USER_FAULT, ("test", 1)), Err(6));
        release_ref(flags::HAS_REF | flags::USER_FAULT);
        assert_eq!(total_corpses_count(), 3);
        for _ in 0..3 {
            release_ref(flags::HAS_REF);
        }
        assert_eq!(INFLIGHT.load(Ordering::Relaxed), 0);
    }
}
