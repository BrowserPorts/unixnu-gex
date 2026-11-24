//! `proc_pid_rusage` (`proc_info` call 9, `PROC_INFO_CALL_PIDRUSAGE`): a
//! process's `rusage_info_v0` to `_v6`, as `proc_pid_rusage`
//! (`proc_info.c`), `proc_get_rusage` and `gather_rusage_info`
//! (`kern_resource.c`) make it from its task's ledgers and counters
//! (`fill_task_rusage`, `fill_task_io_rusage`, `fill_task_qos_rusage`,
//! `bank_*_balance_safe`, `bsd_kern.c`, `bank.c`) and its `p_stats`.
//!
//! What 21H461's kernel (arm64, not arm64e) compiles of it decides some
//! fields (`gather_rusage_info` 0xfffffff00763b9cc, `fill_task_rusage`
//! 0xfffffff00727c0b0, `task_power_info_locked` 0xfffffff00724ca9c):
//!
//! - `ri_system_time` is 0: recount's kernel time is the user time's
//!   (MACH_RELEASE has no `PRECISE_USER_KERNEL_TIME`), and the power info
//!   gives the sum as `total_user` and 0 as `total_system`.
//! - `ri_flags` is 0: `RU_PROC_RUNS_RESLIDE` needs `ptrauth_calls`; the
//!   jump table sends RUSAGE_INFO_V5 and V6 to V4's arm.
//! - The performance cluster's figures (`ri_user_ptime`, `ri_system_ptime`,
//!   `ri_pinstructions`, `ri_pcycles`, `ri_penergy_nj`) are 0: the kernel
//!   is not built for AMP, and `recount_topo_matches_cpu_kind` matches no
//!   track (0xfffffff007228c70).
//! - `ri_secure_time_in_system` and `ri_secure_ptime_in_system` are 0:
//!   no `RECOUNT_SECURE_METRICS`, so `task_power_info_locked` leaves them
//!   as `fill_task_rusage` zeroed them.
//! - `ri_energy_nj`, `ri_billed_energy` and `ri_serviced_energy` are 0:
//!   recount keeps energy only with `RECOUNT_ENERGY`, which is
//!   `CONFIG_PERVASIVE_ENERGY` only where the SoC has a digital power
//!   estimation counter (`HAS_CPU_DPE_COUNTER`, `recount.c:75`; H13 and
//!   H14 only, not T8011's H9). The kernel's `kern.pervasive_energy`
//!   (0xfffffff00714cae0, the same condition) is 0, and
//!   `machine_switch_perfcontrol_context` (0xfffffff00733d35c) never reads
//!   the CLPC callback's energy estimate. So `recount_add_energy` is
//!   empty, `recount_current_thread_energy_nj` returns 0, and the bank's
//!   energy entries, which only `bank_swap_thread_bank_ledger` credits
//!   from that function's deltas (`bank.c:1980`), stay 0.
//! - CONFIG_PERVASIVE_CPI and CONFIG_LEDGER_INTERVAL_MAX are in: the
//!   CPMU's instructions and cycles (PMC1 and PMC0, read by
//!   `recount_snapshot` 0xfffffff0072287f8 at every switch and quantum
//!   expiry, counting EL0 and EL1) and the footprint's interval peak are
//!   real figures there.
//!
//! What is kept here: the executable's UUID; recount's time of the task
//! (its threads', the ended ones' with them), in Mach time units; that
//! time by each thread's effective QoS (`cpu_time_eqos_stats`, credited as
//! a thread's QoS inputs or its task's policy change, as it ends and as it
//! is read); the wakeups from interrupt context (`interrupt_wakeups`: a
//! wait's deadline timer, and what a thread call wakes, its thread woken by
//! the delayed timer's interrupt), and of them the platform-idle ones
//! (`platform_idle_wakeups`: no thread on any of the three processors at
//! that interrupt, [`super::sched::Sched::processors_idle`]); each
//! thread's runnable time; the map's
//! user wirings (`wired_mem`); the pmap's `phys_mem` ledger (every page
//! it has entered) and the `phys_footprint` ledger's balance and its
//! lifetime and interval peaks, the process's pages looked at as the
//! call is made (from outside it through its published map and memory
//! for another process, at its end for `p_ru`), the peaks held across
//! every release of its pages ([`super::footprint`]); the fork's start
//! (`ps_start`), an ended process's end and `p_ru`; the reaped children's
//! sums (`ri_child`); and the bank's CPU time bills (the time the threads
//! that adopted an account's voucher ran, rolled up into the holder's and
//! merchant's ledgers as the account goes); the page-ins, the disk I/O
//! and the logical writes the device's page cache and cluster layer make
//! of the task's faults, reads, writes, syncs and truncations
//! ([`super::pagecache`], [`super::cluster`]). What needs counters that
//! are not kept is given as 0
//! and reported: the wakeups a thread call's signal or message to another
//! task made, the CPMU's instructions
//! (XNU's own among them) and cycles (at CLPC's frequencies), the footprint
//! where the host keeps no view of the process's memory (the browser's),
//! and a bill while a thread that has it runs (the device credits it at
//! quantum ends).

use crate::syscalls::Kernel;
use crate::GuestMem;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// `RUSAGE_INFO_V0` .. `RUSAGE_INFO_V6` (`RUSAGE_INFO_CURRENT`).
pub const RUSAGE_INFO_CURRENT: u32 = 6;

/// `sizeof(struct rusage_info_v0)` .. `_v6`: the kernel's table at
/// 0xfffffff007022230.
pub const SIZES: [usize; 7] = [96, 144, 160, 232, 296, 304, 464];

/// `struct rusage_info_v6` in 64-bit words: the UUID's two, then each
/// field's.
pub const WORDS: usize = 58;

/// The fields' word indices.
pub mod ri {
    pub const USER_TIME: usize = 2;
    pub const SYSTEM_TIME: usize = 3;
    pub const PKG_IDLE_WKUPS: usize = 4;
    pub const INTERRUPT_WKUPS: usize = 5;
    pub const PAGEINS: usize = 6;
    pub const WIRED_SIZE: usize = 7;
    pub const RESIDENT_SIZE: usize = 8;
    pub const PHYS_FOOTPRINT: usize = 9;
    pub const PROC_START_ABSTIME: usize = 10;
    pub const PROC_EXIT_ABSTIME: usize = 11;
    pub const CHILD_USER_TIME: usize = 12;
    pub const CHILD_SYSTEM_TIME: usize = 13;
    pub const CHILD_PKG_IDLE_WKUPS: usize = 14;
    pub const CHILD_INTERRUPT_WKUPS: usize = 15;
    pub const CHILD_PAGEINS: usize = 16;
    pub const CHILD_ELAPSED_ABSTIME: usize = 17;
    pub const DISKIO_BYTESREAD: usize = 18;
    pub const DISKIO_BYTESWRITTEN: usize = 19;
    /// `ri_cpu_time_qos_default` .. `_user_interactive`, by THREAD_QOS_*.
    pub const CPU_TIME_QOS: usize = 20;
    pub const BILLED_SYSTEM_TIME: usize = 27;
    pub const SERVICED_SYSTEM_TIME: usize = 28;
    pub const LOGICAL_WRITES: usize = 29;
    pub const LIFETIME_MAX_PHYS_FOOTPRINT: usize = 30;
    pub const INSTRUCTIONS: usize = 31;
    pub const CYCLES: usize = 32;
    pub const BILLED_ENERGY: usize = 33;
    pub const SERVICED_ENERGY: usize = 34;
    pub const INTERVAL_MAX_PHYS_FOOTPRINT: usize = 35;
    pub const RUNNABLE_TIME: usize = 36;
    pub const FLAGS: usize = 37;
    pub const USER_PTIME: usize = 38;
    pub const SYSTEM_PTIME: usize = 39;
    pub const PINSTRUCTIONS: usize = 40;
    pub const PCYCLES: usize = 41;
    pub const ENERGY_NJ: usize = 42;
    pub const PENERGY_NJ: usize = 43;
    pub const SECURE_TIME_IN_SYSTEM: usize = 44;
    pub const SECURE_PTIME_IN_SYSTEM: usize = 45;
}

/// Each field that can go unkept: its name, and what it needs.
const UNKEPT: [(usize, &str, &str); 17] = [
    (ri::USER_TIME, "ri_user_time", "per-thread clocks on the host"),
    (ri::PKG_IDLE_WKUPS, "ri_pkg_idle_wkups", "the platform_idle_wakeups ledger: what a signal a thread call posted woke, or a thread call's message to another task's port"),
    (ri::INTERRUPT_WKUPS, "ri_interrupt_wkups", "the interrupt_wakeups ledger: what a signal a thread call posted woke, or a thread call's message to another task's port"),
    (ri::RESIDENT_SIZE, "ri_resident_size", "a look at the process's pages, which the host keeps no view of"),
    (ri::PHYS_FOOTPRINT, "ri_phys_footprint", "a look at the process's pages, which the host keeps no view of"),
    (ri::CHILD_PKG_IDLE_WKUPS, "ri_child_pkg_idle_wkups", "the reaped children's platform-idle wakeups"),
    (ri::CHILD_INTERRUPT_WKUPS, "ri_child_interrupt_wkups", "the reaped children's interrupt wakeups"),
    (ri::CHILD_PAGEINS, "ri_child_pageins", "the reaped children's page-ins"),
    (ri::CHILD_USER_TIME, "ri_child_user_time", "the reaped children's times on a host without per-thread clocks"),
    (ri::CPU_TIME_QOS, "ri_cpu_time_qos_*", "per-thread clocks on the host"),
    (ri::BILLED_SYSTEM_TIME, "ri_billed_system_time", "a bill one of whose adopting threads runs at the read (the device credits it at quantum ends), or whose time could not be read"),
    (ri::SERVICED_SYSTEM_TIME, "ri_serviced_system_time", "a bill one of whose adopting threads runs at the read (the device credits it at quantum ends), or whose time could not be read"),
    (ri::LIFETIME_MAX_PHYS_FOOTPRINT, "ri_lifetime_max_phys_footprint", "a look at the process's pages, which the host keeps no view of"),
    (ri::INSTRUCTIONS, "ri_instructions", "PMC1 at every switch and quantum expiry (recount_snapshot): the instructions the translator counts in each thread's context (none where the function tier runs, or where the host keeps no view of the process's memory)"),
    (ri::CYCLES, "ri_cycles", "PMC0 over the threads' on-core time: per-thread clocks on the host"),
    (ri::INTERVAL_MAX_PHYS_FOOTPRINT, "ri_interval_max_phys_footprint", "a look at the process's pages, which the host keeps no view of"),
    (ri::RUNNABLE_TIME, "ri_runnable_time", "per-thread clocks on the host"),
];

/// The QoS fields, one bit each in an unkept mask.
const QOS_FIELDS: std::ops::Range<usize> = ri::CPU_TIME_QOS..ri::CPU_TIME_QOS + 7;

/// One process's `rusage_info_v6`, and which of its fields are not kept
/// (a bit per word index).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub w: [u64; WORDS],
    pub unkept: u64,
}

impl Record {
    /// The record as bytes, for another process of the page (its `p_ru` in
    /// its record, [`super::procinfo::Facts::exited`]).
    pub(crate) fn put(&self, p: &mut super::ipc::wire::Put) {
        for &v in &self.w {
            p.u64(v);
        }
        p.u64(self.unkept);
    }

    pub(crate) fn get(g: &mut super::ipc::wire::Get<'_>) -> Result<Record, super::ipc::wire::Bad> {
        let mut w = [0u64; WORDS];
        for v in w.iter_mut() {
            *v = g.u64()?;
        }
        Ok(Record { w, unkept: g.u64()? })
    }

    /// The structure's bytes.
    pub fn bytes(&self) -> Vec<u8> {
        self.w.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    /// The fields within a flavor's `size` bytes that are not kept, by
    /// name and need, each once.
    pub fn unkept_within(&self, size: usize) -> Vec<String> {
        let words = size / 8;
        let mut out = Vec::new();
        for (i, name, need) in UNKEPT {
            let any = if i == ri::CPU_TIME_QOS { QOS_FIELDS.clone().any(|q| q < words && self.unkept & (1 << q) != 0) } else { i < words && self.unkept & (1 << i) != 0 };
            if any {
                out.push(format!("{name} ({need})"));
            }
        }
        out
    }
}

/// `p_stats->ri_child` (`struct rusage_info_child`): the reaped
/// children's sums, and which are not kept.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Child {
    pub user_time: u64,
    pub system_time: u64,
    pub pkg_idle_wkups: u64,
    pub interrupt_wkups: u64,
    pub pageins: u64,
    pub elapsed_abstime: u64,
    pub unkept: u64,
}

impl Child {
    /// `update_rusage_info_child`: a reaped child's own figures and its
    /// children's added.
    pub fn add(&mut self, r: &Record) {
        let w = &r.w;
        self.user_time = self.user_time.wrapping_add(w[ri::USER_TIME].wrapping_add(w[ri::CHILD_USER_TIME]));
        self.system_time = self.system_time.wrapping_add(w[ri::SYSTEM_TIME].wrapping_add(w[ri::CHILD_SYSTEM_TIME]));
        self.pkg_idle_wkups = self.pkg_idle_wkups.wrapping_add(w[ri::PKG_IDLE_WKUPS].wrapping_add(w[ri::CHILD_PKG_IDLE_WKUPS]));
        self.interrupt_wkups = self.interrupt_wkups.wrapping_add(w[ri::INTERRUPT_WKUPS].wrapping_add(w[ri::CHILD_INTERRUPT_WKUPS]));
        self.pageins = self.pageins.wrapping_add(w[ri::PAGEINS].wrapping_add(w[ri::CHILD_PAGEINS]));
        self.elapsed_abstime = self.elapsed_abstime.wrapping_add(w[ri::PROC_EXIT_ABSTIME].wrapping_sub(w[ri::PROC_START_ABSTIME]).wrapping_add(w[ri::CHILD_ELAPSED_ABSTIME]));
        let gone = |own: usize, child: usize| r.unkept & ((1 << own) | (1 << child)) != 0;
        for (own, child) in [
            (ri::USER_TIME, ri::CHILD_USER_TIME),
            (ri::PKG_IDLE_WKUPS, ri::CHILD_PKG_IDLE_WKUPS),
            (ri::INTERRUPT_WKUPS, ri::CHILD_INTERRUPT_WKUPS),
            (ri::PAGEINS, ri::CHILD_PAGEINS),
        ] {
            if gone(own, child) {
                self.unkept |= 1 << child;
            }
        }
    }
}

/// The bank's entries of a task's ledger (`cpu_time_billed_to_me`,
/// `cpu_time_billed_to_others`), in Mach time units: the bills of its
/// accounts rolled up as each account goes (`bank_rollup_chit_to_tasks`).
/// A new task (an exec's) has a new ledger.
#[derive(Debug, Default)]
pub struct BankLedger {
    pub to_me: AtomicU64,
    pub to_others: AtomicU64,
    /// A rolled-up bill held time not kept (a thread's time unread).
    pub unkept: AtomicBool,
}

/// The bank's figures of a task (`bank_billed_balance_safe`,
/// `bank_serviced_balance_safe`): its billed and serviced CPU time, none
/// where a bill is not known. Their energy is 0 on this kernel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bills {
    pub billed: Option<u64>,
    pub serviced: Option<u64>,
}

impl Bills {
    /// A task ledger's own entries, for a task with no bank context.
    pub fn of_ledger(l: &BankLedger) -> Bills {
        let known = !l.unkept.load(Ordering::Acquire);
        Bills { billed: known.then(|| l.to_me.load(Ordering::Acquire)), serviced: known.then(|| l.to_others.load(Ordering::Acquire)) }
    }
}

/// What a process's `proc_pid_rusage` reads that its record does not
/// otherwise carry, shared by the process and its readers.
#[derive(Debug, Default)]
pub struct Shared {
    /// `p_stats->ps_start`: the Mach time of its fork (`microtime_with_
    /// abstime`, with `p_start`); an exec keeps it.
    pub start_abstime: AtomicU64,
    /// The `wired_mem` ledger: what the map's user wirings hold.
    pub wired: Arc<AtomicU64>,
    /// The task's ledger's bank entries (`bt_ledger` of its bank context).
    pub bank: Mutex<Arc<BankLedger>>,
    /// Its bank figures as `proc_exit` gathers them, its bank context still
    /// there (`task_bank_reset` is the task's deallocation's): made as the
    /// task ends.
    pub exit_bills: Mutex<Option<Bills>>,
    /// The `interrupt_wakeups` ledger: its threads made runnable from
    /// interrupt context (`thread_unblock`'s `aticontext`: a wait's
    /// deadline timer), or by a thread-call thread the delayed timer woke
    /// from there (`callout_woken_from_icontext`).
    pub interrupt_wkups: AtomicU64,
    /// The `platform_idle_wakeups` ledger: those of the interrupt wakeups
    /// made while every processor was idle (`ml_get_power_state`'s
    /// `pidle`, [`super::sched::Sched::processors_idle`]), or by a
    /// thread-call thread that such an interrupt woke
    /// (`callout_woken_from_platform_idle`).
    pub pkg_idle_wkups: AtomicU64,
    /// A thread call did what may have woken one of its threads in a way
    /// not counted here: a signal it posted, or a message it sent to a
    /// port another task receives.
    pub wkups_unkept: AtomicBool,
    /// The task's footprint meter: what its pmap holds, for its own looks
    /// and other processes'.
    pub meter: super::footprint::Meter,
    /// `task->pageins`: `VM_PAGE_COUNT_AS_PAGEIN` at its faults
    /// ([`super::pagecache::fault`]). An exec's task takes the old one's
    /// (`task_rollup_accounting_info`).
    pub pageins: AtomicU64,
    /// `task_io_stats`' `disk_reads.size` and `total_io.size`: the bytes
    /// `spec_strategy` saw its threads read, and read and write
    /// ([`super::pagecache::charge`]). An exec's task takes the old one's.
    pub disk_read: AtomicU64,
    pub disk_total: AtomicU64,
    /// The `logical_writes` ledger's balance (credits less debits); an
    /// exec's task takes the old one's (`ledger_rollup_entry`).
    pub logical_writes: std::sync::atomic::AtomicI64,
    child: Mutex<Child>,
    /// `p_ru->ri`: what `proc_exit` gathered.
    exit: Mutex<Option<Record>>,
}

impl Shared {
    /// A new process's, forked at Mach time `start`.
    pub fn new(start: u64) -> Arc<Shared> {
        Arc::new(Shared { start_abstime: AtomicU64::new(start), ..Shared::default() })
    }

    /// `thread_unblock`'s credits of a wakeup from interrupt context:
    /// `interrupt_wakeups`, and `platform_idle_wakeups` with `pidle`.
    pub fn interrupt_wakeup(&self, pidle: bool) {
        self.interrupt_wkups.fetch_add(1, Ordering::AcqRel);
        if pidle {
            self.pkg_idle_wkups.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// `thread_update_io_stats` and `task_update_logical_writes` of one
    /// operation of its threads'.
    pub fn io_add(&self, io: super::pagecache::Io) {
        if io.read != 0 {
            self.disk_read.fetch_add(io.read, Ordering::AcqRel);
        }
        if io.read + io.written != 0 {
            self.disk_total.fetch_add(io.read + io.written, Ordering::AcqRel);
        }
        if io.logical != 0 {
            self.logical_writes.fetch_add(io.logical, Ordering::AcqRel);
        }
    }

    pub fn child(&self) -> Child {
        *self.child.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The record `proc_exit` left, once it has.
    pub fn exited(&self) -> Option<Record> {
        *self.exit.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// What decides a thread's effective QoS besides its task's policy: its
/// requested QoS, the highest of its overrides, and the DARWIN_BG asked of
/// the thread itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QosInputs {
    pub qos: u8,
    pub overrides: u8,
    pub darwinbg: bool,
}

/// A thread's share of its task's [`QosTime`]: what its effective QoS
/// follows from, that QoS once it has been settled (`thep_qos`; before, it
/// is what the inputs give under the task's policy), and its time when its
/// time was last credited (`vtimer_qos_save`, in Mach time units).
#[derive(Clone, Copy, Debug, Default)]
pub struct QosThread {
    pub inputs: QosInputs,
    eqos: Option<u8>,
    save: u64,
}

fn eqos(i: QosInputs, task: &super::taskpolicy::Effective) -> u8 {
    super::taskpolicy::thread_effective_qos(i.qos, 0, i.overrides, i.darwinbg, task).0
}

/// A thread's time so far in Mach time units, as recount gives it
/// (`recount_thread_time_mach`); none without the host's clocks.
fn thread_mach(t: &crate::signal::ThreadSig) -> Option<u64> {
    t.cpu.times().map(|(user, sys)| mach_of_ns(user + sys))
}

/// `thread_update_qos_cpu_time_locked`: the thread's time since its last
/// credit, `now` its time, to the effective QoS it has had.
fn credit_at(stats: &mut [u64; 7], q: &mut QosThread, now: u64, task: &super::taskpolicy::Effective) {
    let was = q.eqos.unwrap_or_else(|| eqos(q.inputs, task));
    stats[usize::from(was)] = stats[usize::from(was)].wrapping_add(now.wrapping_sub(q.save));
    q.save = now;
}

/// `task->cpu_time_eqos_stats`: the task's threads' time by their
/// effective QoS, each thread's credited as its QoS is about to change, as
/// it ends, and as the stats are read (`thread_update_qos_cpu_time`).
#[derive(Debug, Default)]
pub struct QosTime {
    /// By `THREAD_QOS_*`, in Mach time units.
    stats: Mutex<[u64; 7]>,
    /// The task's threads, for a change of its policy to settle.
    threads: Mutex<std::sync::Weak<crate::signal::ThreadSigs>>,
    /// A thread's time could not be read: the host has no per-thread
    /// clocks.
    unread: AtomicBool,
}

impl QosTime {
    /// The task's threads are these.
    pub fn set_threads(&self, threads: &Arc<crate::signal::ThreadSigs>) {
        *self.threads.lock().unwrap_or_else(|e| e.into_inner()) = Arc::downgrade(threads);
    }

    /// Credit thread `t`'s time since its last credit to the QoS it has
    /// had, under the task's effective policy `task`.
    fn credit(&self, stats: &mut [u64; 7], t: &crate::signal::ThreadSig, q: &mut QosThread, task: &super::taskpolicy::Effective) {
        let Some(now) = thread_mach(t) else {
            self.unread.store(true, Ordering::Release);
            return;
        };
        credit_at(stats, q, now, task);
    }

    /// Thread `t`'s inputs changed to `inputs` (its task's policy being
    /// `task`): its time so far goes to the QoS it had.
    pub fn thread_changed(&self, t: &crate::signal::ThreadSig, inputs: QosInputs, task: &super::taskpolicy::Effective) {
        let mut stats = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        let mut q = t.qos.lock().unwrap_or_else(|e| e.into_inner());
        self.credit(&mut stats, t, &mut q, task);
        q.inputs = inputs;
        q.eqos = Some(eqos(inputs, task));
    }

    /// The task's effective policy changed from `before` to `after`: each
    /// thread's time so far goes to the QoS it had.
    pub fn task_changed(&self, before: &super::taskpolicy::Effective, after: &super::taskpolicy::Effective) {
        let Some(threads) = self.threads.lock().unwrap_or_else(|e| e.into_inner()).upgrade() else { return };
        let mut stats = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        for tid in threads.tids() {
            let Some(t) = threads.get(tid) else { continue };
            let mut q = t.qos.lock().unwrap_or_else(|e| e.into_inner());
            self.credit(&mut stats, &t, &mut q, before);
            q.eqos = Some(eqos(q.inputs, after));
        }
    }

    /// Thread `t` ends: its last time goes to its QoS.
    pub fn thread_ended(&self, t: &crate::signal::ThreadSig, task: &super::taskpolicy::Effective) {
        let mut stats = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        let mut q = t.qos.lock().unwrap_or_else(|e| e.into_inner());
        self.credit(&mut stats, t, &mut q, task);
    }

    /// `fill_task_qos_rusage`: each live thread's time credited, then the
    /// stats; none without the host's clocks.
    pub fn read(&self, task: &super::taskpolicy::Effective) -> Option<[u64; 7]> {
        let threads = self.threads.lock().unwrap_or_else(|e| e.into_inner()).upgrade();
        let mut stats = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(threads) = threads {
            for tid in threads.tids() {
                let Some(t) = threads.get(tid) else { continue };
                let mut q = t.qos.lock().unwrap_or_else(|e| e.into_inner());
                self.credit(&mut stats, &t, &mut q, task);
                q.eqos = Some(eqos(q.inputs, task));
            }
        }
        (!self.unread.load(Ordering::Acquire)).then_some(*stats)
    }
}

/// What [`gather`] makes a record from.
#[derive(Clone, Copy, Debug, Default)]
pub struct Input {
    pub uuid: [u8; 16],
    /// Recount's time of the task, in nanoseconds; none without the
    /// host's clocks.
    pub time_ns: Option<u64>,
    /// Its threads' runnable time, the ended ones' with them, in Mach time
    /// units; none without the host's clocks.
    pub runnable: Option<u64>,
    pub wired: u64,
    /// The phys_footprint ledger's balance and the phys_mem ledger's (the
    /// pmap's pages, in bytes), where they are known now.
    pub footprint: Option<u64>,
    pub resident: Option<u64>,
    /// Its lifetime peak and the peak of its interval
    /// (`ledger_get_lifetime_max`, `ledger_get_interval_max` without a
    /// reset), where they are known.
    pub footprint_peaks: Option<(u64, u64)>,
    pub start_abstime: u64,
    pub child: Child,
    /// The bank's figures; none where no bank state can be read.
    pub bills: Option<Bills>,
    /// `cpu_time_eqos_stats` (`fill_task_qos_rusage`), by `THREAD_QOS_*`, in
    /// Mach time units; none without the host's clocks.
    pub qos: Option<[u64; 7]>,
    /// The `interrupt_wakeups` and `platform_idle_wakeups` ledgers'
    /// balances, where they are kept.
    pub wakeups: Option<(u64, u64)>,
    /// `proc_exit`'s gathering at this Mach time: the map is gone, so
    /// nothing is wired or resident, and the footprint is set to 0.
    pub exit_abstime: Option<u64>,
    /// recount's instructions of the task ([`cpmu::instructions`]), where
    /// they are counted.
    pub instructions: Option<u64>,
    /// `counter_load(&task->pageins)`.
    pub pageins: u64,
    /// `fill_task_io_rusage`'s `disk_reads.size` and `total_io.size`.
    pub disk_read: u64,
    pub disk_total: u64,
    /// `get_task_logical_writes(task, false)`: the ledger's balance.
    pub logical_writes: i64,
}

/// recount's CPMU figures (`CONFIG_PERVASIVE_CPI`): `ri_instructions` and
/// `ri_cycles`.
///
/// What 21H461's kernel does: `recount_snapshot` (0xfffffff0072287f8,
/// `mt_cur_cpu_cycles_instrs_speculative` inlined) reads PMC0 and PMC1
/// raw, adds each one's rise since the processor's last read to the
/// processor's running sums (`cpu+0x228` cycles, `+0x230` instructions),
/// and stores them, unscaled, in the snapshot. `recount_switch_thread` (at
/// `thread_invoke` 0xfffffff007231cac, `thread_quantum_expire`
/// 0xfffffff00722640c and `processor_idle`) adds the snapshot's rise since
/// the processor's last snapshot to the thread going off core, its task's
/// track and the processor's (`recount_absorb_snap`; an idle thread's to
/// none), at the kernel level (no `PRECISE_USER_KERNEL_TIME`).
/// `mt_cpu_run` (0xfffffff007346530) sets PMCR1 to count both counters at
/// EL0 (A32 and A64) and at EL1, so the sums are the program's and the
/// kernel's while the thread is on core. `task_power_info_locked` sums the
/// task track's levels (`recount_usage_cycles`, `recount_usage_
/// instructions`), and an exec's task takes the old one's
/// (`task_rollup_accounting_info`, `recount_task_copy`).
///
/// Instructions: the translator counts what each thread retires at EL0 in
/// its context (`gex_abi::ctx::INSTRUCTIONS`, block by block, taking back
/// what a fault or a signal leaves unretired); an ended thread's, and those
/// of the threads an exec ends, go to its process's sum. XNU's own
/// instructions at EL1 on the thread's behalf (its exception entries and
/// returns, the system calls' bodies, faults, interrupts and switches) are
/// not run here: none are added ([`EL1_STAND_IN`]). The figure is the
/// count up to the read, where the device's lags by each running thread's
/// stretch since its last switch or quantum end, as the time does.
///
/// Cycles: PMC0 counts the core's clock, which runs at the DVFS state CLPC
/// sets (the device tree's `/arm-io/pmgr/clpc` has `dynamic-cpu-control`
/// 1). The IPSW's device tree (J120's, `/arm-io/pmgr`) gives the states'
/// frequencies as 16.16 fixed-point pairs whose first is the frequency in
/// MHz: `ecore-static-vvfc` 396, 768, 1152 and `pcore-static-vvfc` 804,
/// 1140, 1548, 1956, 2316, 2400 ([`cpmu::STATES_MHZ`]; the A10X's cores
/// pair a fast and an efficient one under one processor, which the kernel
/// sees as three, `cpu0`..`cpu2`). The tables iBoot fills in
/// (`voltage-states0`, `voltage-states1`) are blank there, and CLPC's
/// choice among the states over time is AppleT8011CLPC's, not modelled:
/// every on-core stretch is held in the top state, a stand-in
/// ([`DVFS_STAND_IN`]). On-core time is the threads' time, as
/// `ri_user_time` has it.
pub mod cpmu {
    use gex_abi::ctx;

    /// The DVFS states the cores run in, by frequency in MHz: the
    /// efficient cores' (`ecore-static-vvfc`), then the fast ones'
    /// (`pcore-static-vvfc`), each pair's first 16.16 word.
    pub const STATES_MHZ: [u64; 9] = [396, 768, 1152, 804, 1140, 1548, 1956, 2316, 2400];

    /// The state every on-core stretch is held in: the fast cores' top
    /// (a stand-in for CLPC's choice, [`super::DVFS_STAND_IN`]).
    pub fn state() -> usize {
        STATES_MHZ.len() - 1
    }

    /// The cycles of `ns` nanoseconds on core in the current state.
    pub fn cycles(ns: u64) -> u64 {
        (u128::from(ns) * u128::from(STATES_MHZ[state()]) / 1000) as u64
    }

    /// Rollups under way (a thread's count moving from its context to its
    /// task's ended threads': a thread's end, an exec's), and how many have
    /// ended: a reader that met one reads again, so that no instruction is
    /// missed or counted twice (XNU's recount moves a thread's counts into
    /// its task's in one step).
    static ROLLING: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    static ROLLED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// A rollup of threads' counts into their task's, `f`, as a reader of
    /// [`instructions`] sees it: whole, before or after.
    pub fn rollup<R>(f: impl FnOnce() -> R) -> R {
        use std::sync::atomic::Ordering::{AcqRel, Release};
        ROLLING.fetch_add(1, AcqRel);
        let r = f();
        ROLLED.fetch_add(1, Release);
        ROLLING.fetch_sub(1, Release);
        r
    }

    /// The task's instructions: its ended threads' (`dead`) and each of
    /// `threads`' context's count, read with `read`, with no rollup
    /// between ([`rollup`]); none where they are not counted or a context
    /// cannot be read.
    pub fn instructions(dead: &dyn Fn() -> u64, threads: Option<&crate::signal::ThreadSigs>, read: &mut dyn FnMut(u64) -> Option<u64>) -> Option<u64> {
        use std::sync::atomic::Ordering::Acquire;
        if !gex_abi::count_instructions() {
            return None;
        }
        loop {
            let gen = ROLLED.load(Acquire);
            if ROLLING.load(Acquire) != 0 {
                std::thread::yield_now();
                continue;
            }
            let mut n = dead();
            if let Some(threads) = threads {
                for tid in threads.tids() {
                    let Some(t) = threads.get(tid) else { continue };
                    let c = t.ctx();
                    if c == 0 {
                        continue;
                    }
                    n = n.wrapping_add(read(c + ctx::INSTRUCTIONS as u64)?);
                }
            }
            if ROLLING.load(Acquire) == 0 && ROLLED.load(Acquire) == gen {
                return Some(n);
            }
        }
    }
}

/// The stand-in for XNU's EL1 instructions in `ri_instructions`, as gexc
/// reports it.
pub const EL1_STAND_IN: &str = "XNU's own instructions at EL1 on a thread's behalf in ri_instructions (PMC1 counts EL1 too: exception entries and returns, system calls' and faults' bodies, interrupts, switches) (stand-in: none, only the program's EL0 instructions the translator counts; measure on the device the ri_instructions rise across a loop of a known instruction count that makes N system calls, or takes N faults, against the same loop without them)";

/// The stand-in for the cores' DVFS states in `ri_cycles`, as gexc reports
/// it.
pub const DVFS_STAND_IN: &str = "the DVFS state CLPC holds each on-core stretch in, which ri_cycles counts PMC0 at (the states are the device tree's pmgr static-vvfc, 396 to 2400 MHz; AppleT8011CLPC's choice over time and iBoot's voltage-states are not known here) (stand-in: the fast cores' top state, 2400 MHz, for all on-core time; measure ri_cycles over ri_user_time of a process on the device, CPU-bound and bursty, at each QoS)";

/// Nanoseconds as Mach time units.
pub fn mach_of_ns(ns: u64) -> u64 {
    let (numer, denom) = super::mach::TIMEBASE;
    (u128::from(ns) * u128::from(denom) / u128::from(numer)) as u64
}

/// `gather_rusage_info(p, ru, RUSAGE_INFO_CURRENT)`: every field, kept or
/// marked. A flavor's copy takes the first of it.
pub fn gather(i: &Input) -> Record {
    let mut w = [0u64; WORDS];
    let mut unkept = 0u64;
    let mut mark = |f: usize| unkept |= 1 << f;
    w[0] = u64::from_le_bytes(i.uuid[..8].try_into().unwrap());
    w[1] = u64::from_le_bytes(i.uuid[8..].try_into().unwrap());
    match i.time_ns {
        Some(ns) => w[ri::USER_TIME] = mach_of_ns(ns),
        None => mark(ri::USER_TIME),
    }
    match i.wakeups {
        Some((interrupt, pkg_idle)) => {
            w[ri::INTERRUPT_WKUPS] = interrupt;
            w[ri::PKG_IDLE_WKUPS] = pkg_idle;
        }
        None => {
            mark(ri::INTERRUPT_WKUPS);
            mark(ri::PKG_IDLE_WKUPS);
        }
    }
    w[ri::DISKIO_BYTESREAD] = i.disk_read;
    w[ri::DISKIO_BYTESWRITTEN] = i.disk_total.wrapping_sub(i.disk_read);
    w[ri::LOGICAL_WRITES] = i.logical_writes as u64;
    w[ri::PAGEINS] = i.pageins;
    match i.instructions {
        Some(n) => w[ri::INSTRUCTIONS] = n,
        None => mark(ri::INSTRUCTIONS),
    }
    match i.time_ns {
        Some(ns) => w[ri::CYCLES] = cpmu::cycles(ns),
        None => mark(ri::CYCLES),
    }
    match i.footprint_peaks {
        Some((lifetime, interval)) => {
            w[ri::LIFETIME_MAX_PHYS_FOOTPRINT] = lifetime;
            w[ri::INTERVAL_MAX_PHYS_FOOTPRINT] = interval;
        }
        None => {
            mark(ri::LIFETIME_MAX_PHYS_FOOTPRINT);
            mark(ri::INTERVAL_MAX_PHYS_FOOTPRINT);
        }
    }
    match i.qos {
        Some(q) => w[QOS_FIELDS].copy_from_slice(&q),
        None => {
            for f in QOS_FIELDS {
                mark(f);
            }
        }
    }
    match i.exit_abstime {
        Some(t) => w[ri::PROC_EXIT_ABSTIME] = t,
        None => {
            w[ri::WIRED_SIZE] = i.wired;
            match i.resident {
                Some(r) => w[ri::RESIDENT_SIZE] = r,
                None => mark(ri::RESIDENT_SIZE),
            }
            match i.footprint {
                Some(f) => w[ri::PHYS_FOOTPRINT] = f,
                None => mark(ri::PHYS_FOOTPRINT),
            }
        }
    }
    w[ri::PROC_START_ABSTIME] = i.start_abstime;
    let c = i.child;
    w[ri::CHILD_USER_TIME] = c.user_time;
    w[ri::CHILD_SYSTEM_TIME] = c.system_time;
    w[ri::CHILD_PKG_IDLE_WKUPS] = c.pkg_idle_wkups;
    w[ri::CHILD_INTERRUPT_WKUPS] = c.interrupt_wkups;
    w[ri::CHILD_PAGEINS] = c.pageins;
    w[ri::CHILD_ELAPSED_ABSTIME] = c.elapsed_abstime;
    unkept |= c.unkept;
    let b = i.bills.unwrap_or_default();
    for (f, v) in [(ri::BILLED_SYSTEM_TIME, b.billed), (ri::SERVICED_SYSTEM_TIME, b.serviced)] {
        match v.filter(|_| i.bills.is_some()) {
            Some(t) => w[f] = t,
            None => unkept |= 1 << f,
        }
    }
    match i.runnable {
        Some(r) => w[ri::RUNNABLE_TIME] = r,
        None => unkept |= 1 << ri::RUNNABLE_TIME,
    }
    Record { w, unkept }
}

/// The input of process `pid` from its record and the table: its time and
/// runnable time, the ended threads' and the live ones'.
fn times(procs: &crate::proc::ProcTable, pid: i32, p: &super::procinfo::Public) -> (Option<u64>, Option<u64>) {
    if super::workq::host_clocks().is_none() {
        return (None, None);
    }
    let (du, ds) = procs.dead_cpu(pid);
    let dr = procs.dead_runnable(pid);
    let Some(threads) = p.threads.as_ref() else { return (Some(du + ds), Some(dr)) };
    let time = crate::cpu::live_times(threads).map(|v| v.iter().fold(du + ds, |a, &(u, s)| a + u + s));
    let runnable = crate::cpu::live_runnable(threads).map(|r| r + dr);
    (time, runnable)
}

fn input(procs: &crate::proc::ProcTable, pid: i32, p: &super::procinfo::Public) -> Input {
    let (time_ns, runnable) = times(procs, pid, p);
    let qos = procs.task_policy(pid).and_then(|cell| {
        let task = cell.lock().unwrap_or_else(|e| e.into_inner()).effective;
        cell.qos_time.read(&task)
    });
    let s = &p.rusage;
    Input {
        uuid: p.uuid,
        time_ns,
        runnable,
        wired: s.wired.load(Ordering::Acquire),
        footprint: None,
        resident: None,
        footprint_peaks: None,
        start_abstime: s.start_abstime.load(Ordering::Acquire),
        child: s.child(),
        bills: None,
        qos,
        wakeups: (!s.wkups_unkept.load(Ordering::Acquire)).then(|| (s.interrupt_wkups.load(Ordering::Acquire), s.pkg_idle_wkups.load(Ordering::Acquire))),
        exit_abstime: None,
        instructions: None,
        pageins: s.pageins.load(Ordering::Acquire),
        disk_read: s.disk_read.load(Ordering::Acquire),
        disk_total: s.disk_total.load(Ordering::Acquire),
        logical_writes: s.logical_writes.load(Ordering::Acquire),
    }
}

/// Process `pid`'s instructions ([`cpmu::instructions`]) read from
/// outside it, through the memory it published; none where the host keeps
/// no view of it.
pub fn instructions_from_outside(procs: &crate::proc::ProcTable, pid: i32, p: &super::procinfo::Public) -> Option<u64> {
    let peer = procs.vm(pid).ok()?;
    let mut n = None;
    peer.mem.with_guest(&mut |g| {
        let mut k = g.kernel();
        n = cpmu::instructions(&|| procs.dead_instructions(pid), p.threads.as_deref(), &mut |a| k.read_u64(a).ok());
    });
    n
}

/// What a look at a process's pages says: the `phys_footprint` balance,
/// its lifetime and interval peaks, and the `phys_mem` balance (bytes).
#[derive(Clone, Copy, Debug)]
pub struct Looked {
    pub footprint: u64,
    pub peaks: (u64, u64),
    pub resident: u64,
}

/// A look at process `pid`'s pages from outside it, through the map and
/// memory it published, its ledger told (the peaks raised, its callbacks
/// left to it); none where the host keeps no view of its memory.
pub fn footprint_from_outside(procs: &crate::proc::ProcTable, pid: i32, p: &super::procinfo::Public) -> Option<Looked> {
    let peer = procs.vm(pid).ok()?;
    let meter = &p.rusage.meter;
    let (fp, resident) = {
        let mut pm = meter.lock();
        let mut fp = None;
        peer.mem.with_guest(&mut |g| fp = meter.measure(&mut pm, &peer.mm, g));
        (fp?, pm.pages().resident * (super::mach::PAGE_MASK + 1))
    };
    let mut j = procs.jetsam();
    let l = j.ledgers.get_mut(&pid)?;
    l.observe(fp);
    Some(Looked { footprint: fp as u64, peaks: (l.lifetime_max as u64, l.interval_max as u64), resident })
}

/// `proc_exit`'s stash of process `pid`'s usage in `p_ru`, before it
/// becomes a zombie, for `proc_pid_rusage` to read: its pages looked at a
/// last time first, as its threads have stopped and before its map goes
/// (`vm_map_terminate` only releases), so the peaks are its whole life's.
pub fn proc_exit(procs: &crate::proc::ProcTable, pid: i32, p: &super::procinfo::Public) {
    let mut i = input(procs, pid, p);
    i.footprint_peaks = footprint_from_outside(procs, pid, p).map(|l| l.peaks);
    i.instructions = instructions_from_outside(procs, pid, p);
    i.bills = *p.rusage.exit_bills.lock().unwrap_or_else(|e| e.into_inner());
    i.exit_abstime = Some(super::mach::absolute_time());
    let r = gather(&i);
    *p.rusage.exit.lock().unwrap_or_else(|e| e.into_inner()) = Some(r);
}

/// `gather_rusage_info(p, ri, RUSAGE_INFO_CURRENT)` with `ri_phys_footprint`
/// 0, for a corpse's crash information: the task's usage as it stands (its
/// pages looked at from outside it), with `bills` its bank figures; and,
/// for `proc_prepareexit`'s record of an ending process (`exit`), its
/// `ri_proc_exit_abstime` now.
pub fn crash_record(procs: &crate::proc::ProcTable, pid: i32, p: &super::procinfo::Public, bills: Bills, exit: bool) -> Record {
    let mut i = input(procs, pid, p);
    let looked = footprint_from_outside(procs, pid, p);
    i.footprint_peaks = looked.as_ref().map(|l| l.peaks);
    i.resident = looked.as_ref().map(|l| l.resident);
    i.footprint = Some(0);
    i.instructions = instructions_from_outside(procs, pid, p);
    i.bills = Some(bills);
    let mut r = gather(&i);
    if exit {
        r.w[ri::PROC_EXIT_ABSTIME] = super::mach::absolute_time();
    }
    r
}

/// `reap_child_locked`'s `update_rusage_info_child` of a reaped child's
/// `p_ru` into its parent's `ri_child` (whatever the parent's
/// `P_NOCLDWAIT`); `times` is 2 for a parent with `P_NOCLDWAIT`, as
/// `proc_exit` added it once already before the kernel reaped it. A child
/// with no `p_ru` adds nothing ("lost p_ru").
pub fn reaped(child: &super::procinfo::Public, parent: &super::procinfo::Public, times: u32) {
    let Some(r) = child.rusage.exited() else { return };
    parent.rusage.add_reaped(&r, times);
}

impl Shared {
    /// `update_rusage_info_child` of a reaped child's `p_ru` `r` into this
    /// process's, `times` times ([`reaped`]).
    pub fn add_reaped(&self, r: &Record, times: u32) {
        let mut c = self.child.lock().unwrap_or_else(|e| e.into_inner());
        for _ in 0..times {
            c.add(r);
        }
    }
}

/// The record's copy size for a flavor; none for another.
pub fn size_of(flavor: u32) -> Option<usize> {
    SIZES.get(flavor as usize).copied()
}

impl Kernel {
    /// `proc_pid_rusage(pid, flavor, buffer)`: `proc_find`, else
    /// `proc_find_zombref`; the caller's right to look (`proc_security_
    /// policy` with the same-user check); then `proc_get_rusage`: an
    /// unknown flavor EINVAL, an ended process's `p_ru`, else the task's
    /// usage now, its end left 0. Not-kept fields in the copy are reported.
    pub(crate) fn darwin_proc_pid_rusage(&mut self, m: &mut GuestMem<'_>, pid: i32, flavor: u32, buf: u64) -> Result<u64, i32> {
        const ESRCH: i32 = 3;
        const EINVAL: i32 = 22;
        const EFAULT: i32 = 14;
        let target = if pid == 0 { Some((super::procinfo::Public::kernel(), false)) } else { self.darwin_public(pid) };
        let Some((target, _zombie)) = target else { return Err(ESRCH) };
        self.darwin_proc_info_policy(Some(&target), super::procinfo::call::PIDRUSAGE, true)?;
        let Some(size) = size_of(flavor) else { return Err(EINVAL) };
        if pid == 0 {
            self.darwin_unimplemented("proc_pid_rusage of kernel_task (the kernel task's ledgers and recount totals)".into());
            return Err(ESRCH);
        }
        let r = match target.rusage.exited() {
            Some(r) => r,
            None => {
                let mut i = input(&self.procs, pid, &target);
                i.instructions = if pid == self.pid {
                    let mut k = m.kernel();
                    cpmu::instructions(&|| self.procs.dead_instructions(pid), target.threads.as_deref(), &mut |a| k.read_u64(a).ok())
                } else {
                    instructions_from_outside(&self.procs, pid, &target)
                };
                if pid == self.pid {
                    if let Some(fp) = self.darwin_footprint_now(m) {
                        i.footprint = Some(fp as u64);
                        i.resident = Some(self.dtask.rusage.meter.lock().pages().resident * (super::mach::PAGE_MASK + 1));
                        i.footprint_peaks = self.procs.jetsam().ledgers.get(&pid).map(|l| (l.lifetime_max as u64, l.interval_max as u64));
                    }
                } else if let Some(l) = footprint_from_outside(&self.procs, pid, &target) {
                    i.footprint = Some(l.footprint);
                    i.resident = Some(l.resident);
                    i.footprint_peaks = Some(l.peaks);
                }
                i.bills = Some(self.darwin_bank_bills(pid, target.uniqueid, &target.rusage));
                gather(&i)
            }
        };
        let unkept = r.unkept_within(size);
        if !unkept.is_empty() {
            self.darwin_unimplemented(format!("proc_pid_rusage flavor {flavor}: {}, not kept (given as 0)", unkept.join(", ")));
        }
        m.write(buf, &r.bytes()[..size]).map_err(|_| EFAULT)?;
        Ok(0)
    }

    /// Thread `tid`'s requested QoS, overrides or own DARWIN_BG may have
    /// changed: its time so far goes to the effective QoS it had, and its
    /// task's [`QosTime`] learns what it has now.
    pub(crate) fn darwin_qos_note(&mut self, tid: i32) {
        let Some(t) = self.thread_signals.get(tid) else { return };
        let inputs = self.dtask.threads.map.get(&tid).map_or(QosInputs::default(), |d| QosInputs {
            qos: d.policy.qos,
            overrides: d.overrides.iter().map(|o| o.qos).max().unwrap_or(super::workq::qos::UNSPECIFIED),
            darwinbg: d.policy.int_darwinbg || d.policy.ext_darwinbg,
        });
        if t.qos.lock().unwrap_or_else(|e| e.into_inner()).inputs == inputs {
            return;
        }
        let Some(cell) = self.dtask.policy.clone().or_else(|| self.procs.task_policy(self.pid)) else { return };
        let task = cell.lock().unwrap_or_else(|e| e.into_inner()).effective;
        cell.qos_time.thread_changed(&t, inputs, &task);
    }

    /// An exec's: the old image's threads are gone, their instructions
    /// with them into the process's sum, which the new task keeps
    /// (`task_rollup_accounting_info`'s `recount_task_copy`, and
    /// `thread_copy_resource_info`'s for the thread that goes on). `m` is
    /// the old image's memory, its threads stopped.
    pub fn darwin_exec_instructions(&self, m: &mut GuestMem<'_>) {
        if !self.darwin || !gex_abi::count_instructions() {
            return;
        }
        let mut k = m.kernel();
        for tid in self.thread_signals.tids() {
            let Some(t) = self.thread_signals.get(tid) else { continue };
            let c = t.ctx();
            if c == 0 {
                continue;
            }
            cpmu::rollup(|| {
                t.set_ctx(0);
                if let Ok(n) = k.read_u64(c + gex_abi::ctx::INSTRUCTIONS as u64) {
                    self.procs.add_dead_instructions(self.pid, n);
                }
            });
        }
    }

    /// The process's thread whose context is at `ctx` starts counting
    /// there: a fork's child (its context the parent's copy, which a new
    /// task's thread does not keep: its count starts at 0), or an exec's
    /// new image (a new memory).
    pub fn darwin_thread_counts_at(&mut self, m: &mut GuestMem<'_>, ctx: u64, fresh: bool) {
        if !self.darwin || !gex_abi::count_instructions() {
            return;
        }
        if fresh {
            let _ = m.kernel().write_u64(ctx + gex_abi::ctx::INSTRUCTIONS as u64, 0);
        }
        self.signals.thread().set_ctx(ctx);
    }

    /// One of this task's threads was made runnable from interrupt
    /// context (`ledger_credit_thread(..., interrupt_wakeups, 1)`), and
    /// with `pidle` in the platform-idle state (`platform_idle_wakeups`
    /// too), `thread_unblock` (`sched_prim.c:943`).
    pub(crate) fn darwin_interrupt_wakeup(&self, pidle: bool) {
        self.dtask.rusage.interrupt_wakeup(pidle);
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sizes_are_the_kernels_and_the_layout_its_offsets() {
        assert_eq!(SIZES[6], WORDS * 8);
        // fill_task_rusage's and gather_rusage_info's stores.
        assert_eq!(ri::USER_TIME * 8, 0x10);
        assert_eq!(ri::PAGEINS * 8, 0x30);
        assert_eq!(ri::PHYS_FOOTPRINT * 8, 0x48);
        assert_eq!(ri::PROC_START_ABSTIME * 8, 0x50);
        assert_eq!(ri::PROC_EXIT_ABSTIME * 8, 0x58);
        assert_eq!(ri::CHILD_USER_TIME * 8, 0x60);
        assert_eq!(ri::DISKIO_BYTESREAD * 8, 0x90);
        assert_eq!(ri::BILLED_SYSTEM_TIME * 8, 0xd8);
        assert_eq!(ri::LOGICAL_WRITES * 8, 0xe8);
        assert_eq!(ri::INSTRUCTIONS * 8, 0xf8);
        assert_eq!(ri::BILLED_ENERGY * 8, 0x108);
        assert_eq!(ri::INTERVAL_MAX_PHYS_FOOTPRINT * 8, 0x118);
        assert_eq!(ri::RUNNABLE_TIME * 8, 0x120);
        assert_eq!(ri::USER_PTIME * 8, 0x130);
        assert_eq!(ri::ENERGY_NJ * 8, 0x150);
        assert_eq!(ri::SECURE_TIME_IN_SYSTEM * 8, 0x160);
        // Each flavor ends on a field the one before does not have.
        assert_eq!(SIZES[0], (ri::PROC_EXIT_ABSTIME + 1) * 8);
        assert_eq!(SIZES[1], (ri::CHILD_ELAPSED_ABSTIME + 1) * 8);
        assert_eq!(SIZES[2], (ri::DISKIO_BYTESWRITTEN + 1) * 8);
        assert_eq!(SIZES[3], (ri::SERVICED_SYSTEM_TIME + 1) * 8);
        assert_eq!(SIZES[4], (ri::RUNNABLE_TIME + 1) * 8);
        assert_eq!(SIZES[5], (ri::FLAGS + 1) * 8);
        assert_eq!(size_of(7), None);
    }

    fn live() -> Input {
        Input { uuid: [7; 16], time_ns: Some(1_000_000), runnable: Some(48_000), wired: 0x8000, footprint: Some(0x40000), resident: Some(0x6_0000), start_abstime: 1000, bills: Some(Bills { billed: Some(0), serviced: Some(0) }), ..Input::default() }
    }

    #[test]
    fn a_live_task_keeps_its_times_and_marks_what_is_not_kept() {
        let r = gather(&live());
        assert_eq!(&r.bytes()[..16], &[7; 16]);
        // 1 ms is 24000 ticks of the 24 MHz counter; no system time.
        assert_eq!(r.w[ri::USER_TIME], 24_000);
        assert_eq!(r.w[ri::SYSTEM_TIME], 0);
        assert_eq!((r.w[ri::WIRED_SIZE], r.w[ri::PHYS_FOOTPRINT], r.w[ri::PROC_START_ABSTIME], r.w[ri::PROC_EXIT_ABSTIME]), (0x8000, 0x40000, 1000, 0));
        assert_eq!((r.w[ri::RESIDENT_SIZE], r.unkept & (1 << ri::RESIDENT_SIZE)), (0x6_0000, 0));
        assert_eq!(r.w[ri::RUNNABLE_TIME], 48_000);
        for f in [ri::FLAGS, ri::USER_PTIME, ri::SYSTEM_PTIME, ri::PINSTRUCTIONS, ri::PCYCLES, ri::PENERGY_NJ, ri::SECURE_TIME_IN_SYSTEM, ri::SECURE_PTIME_IN_SYSTEM] {
            assert_eq!((r.w[f], r.unkept & (1 << f)), (0, 0));
        }
        let v0 = r.unkept_within(SIZES[0]);
        assert_eq!(v0.len(), 2, "{v0:?}");
        assert!(v0[0].starts_with("ri_pkg_idle_wkups") && v0[1].starts_with("ri_interrupt_wkups"));
        // Not looked at: the resident size too.
        let blind = gather(&Input { resident: None, ..live() });
        assert!(blind.unkept_within(SIZES[0])[2].starts_with("ri_resident_size"));
        // V1 adds nothing unkept while no child was reaped; nor V2: the
        // disk's I/O is the task's counters.
        assert_eq!(r.unkept_within(SIZES[1]).len(), 2);
        assert_eq!(r.unkept_within(SIZES[2]).len(), 2);
        // V3: the QoS times, once; the bank's bills are kept.
        assert_eq!(r.unkept_within(SIZES[3]).len(), 3);
        // V4: the peaks (not looked at) and the instructions (not counted
        // here); the logical writes are the ledger's, the cycles come with
        // the time.
        assert_eq!(r.unkept_within(SIZES[6]).len(), 3 + 3);
        // The disk I/O and logical writes: the task's sums, the written
        // bytes all but the read ones, the ledger's balance as it is.
        let io = gather(&Input { disk_read: 100, disk_total: 350, logical_writes: -16384, ..live() });
        assert_eq!((io.w[ri::DISKIO_BYTESREAD], io.w[ri::DISKIO_BYTESWRITTEN], io.w[ri::LOGICAL_WRITES] as i64), (100, 250, -16384));
        // The page-ins are the task's counter.
        assert_eq!(gather(&Input { pageins: 7, ..live() }).w[ri::PAGEINS], 7);
    }

    #[test]
    fn the_cpmu_fields_are_the_counted_instructions_and_the_time_at_the_top_state() {
        let mut i = live();
        i.instructions = Some(123_456);
        let r = gather(&i);
        assert_eq!(r.w[ri::INSTRUCTIONS], 123_456);
        // 1 ms at 2400 MHz.
        assert_eq!(r.w[ri::CYCLES], 2_400_000);
        let all = r.unkept_within(SIZES[6]).join(" ");
        assert!(!all.contains("ri_instructions") && !all.contains("ri_cycles"), "{all}");
        // No time, no cycles.
        let r = gather(&Input { time_ns: None, ..i });
        assert!(r.unkept_within(SIZES[6]).join(" ").contains("ri_cycles"));
        // The states are the device tree's, the fast cores' top last.
        assert_eq!(cpmu::STATES_MHZ[cpmu::state()], 2400);
        // A task whose instructions are not counted has none.
        assert_eq!(cpmu::instructions(&|| 5, None, &mut |_| Some(1)), gex_abi::count_instructions().then_some(5));
    }

    #[test]
    fn bills_keep_their_time_and_no_energy() {
        let mut i = live();
        i.bills = Some(Bills { billed: Some(240), serviced: None });
        i.footprint = None;
        let r = gather(&i);
        assert_eq!(r.w[ri::BILLED_SYSTEM_TIME], 240);
        let all = r.unkept_within(SIZES[6]).join(" ");
        for n in ["ri_serviced_system_time", "ri_phys_footprint"] {
            assert!(all.contains(n), "{n}");
        }
        assert!(!all.contains("ri_billed_system_time") && !all.contains("energy"));
        assert_eq!((r.w[ri::ENERGY_NJ], r.w[ri::BILLED_ENERGY], r.w[ri::SERVICED_ENERGY]), (0, 0, 0));
        // Kept peaks fill their fields.
        i.footprint_peaks = Some((0x90000, 0x50000));
        let r = gather(&i);
        assert_eq!((r.w[ri::LIFETIME_MAX_PHYS_FOOTPRINT], r.w[ri::INTERVAL_MAX_PHYS_FOOTPRINT]), (0x90000, 0x50000));
        assert!(!r.unkept_within(SIZES[6]).join(" ").contains("max_phys_footprint"));
    }

    #[test]
    fn an_exit_record_has_no_memory_and_its_end() {
        let mut i = live();
        i.exit_abstime = Some(5000);
        let r = gather(&i);
        assert_eq!((r.w[ri::WIRED_SIZE], r.w[ri::RESIDENT_SIZE], r.w[ri::PHYS_FOOTPRINT], r.w[ri::PROC_EXIT_ABSTIME]), (0, 0, 0, 5000));
        assert_eq!(r.unkept & ((1 << ri::RESIDENT_SIZE) | (1 << ri::PHYS_FOOTPRINT)), 0);
        assert_eq!(r.unkept_within(SIZES[0]).len(), 2);
    }

    #[test]
    fn qos_time_goes_to_the_effective_qos_a_thread_had() {
        use super::super::taskpolicy::Effective;
        use super::super::workq::qos;
        let mut stats = [0u64; 7];
        let task = Effective::default();
        let mut q = QosThread::default();
        // A new thread with no QoS asked for runs at the default's.
        credit_at(&mut stats, &mut q, 100, &task);
        assert_eq!(stats[usize::from(qos::UNSPECIFIED)], 100);
        // It asks for utility: what it ran before is the default's, what
        // it runs after utility's.
        credit_at(&mut stats, &mut q, 130, &task);
        q.inputs.qos = qos::UTILITY;
        q.eqos = Some(eqos(q.inputs, &task));
        credit_at(&mut stats, &mut q, 200, &task);
        assert_eq!((stats[usize::from(qos::UNSPECIFIED)], stats[usize::from(qos::UTILITY)]), (130, 70));
        // Its task goes to the background: DARWIN_BG puts utility at
        // background from then on.
        let bg = Effective { darwinbg: true, ..task };
        credit_at(&mut stats, &mut q, 260, &task);
        q.eqos = Some(eqos(q.inputs, &bg));
        credit_at(&mut stats, &mut q, 300, &bg);
        assert_eq!((stats[usize::from(qos::UTILITY)], stats[usize::from(qos::BACKGROUND)]), (130, 40));
        // An override above its QoS raises it; a clamp holds it under.
        assert_eq!(eqos(QosInputs { qos: qos::UTILITY, overrides: qos::USER_INITIATED, darwinbg: false }, &task), qos::USER_INITIATED);
        assert_eq!(eqos(QosInputs { qos: qos::USER_INITIATED, overrides: 0, darwinbg: false }, &Effective { qos_clamp: qos::UTILITY, ..task }), qos::UTILITY);
        assert_eq!(stats.iter().sum::<u64>(), 300);
    }

    #[test]
    fn kept_qos_times_fill_the_qos_fields() {
        let mut i = live();
        i.qos = Some([1, 2, 3, 4, 5, 6, 7]);
        let r = gather(&i);
        assert_eq!(&r.w[ri::CPU_TIME_QOS..ri::CPU_TIME_QOS + 7], &[1, 2, 3, 4, 5, 6, 7]);
        assert!(!r.unkept_within(SIZES[3]).join(" ").contains("ri_cpu_time_qos"));
        assert_eq!(r.unkept_within(SIZES[3]).len(), 2);
    }

    #[test]
    fn kept_wakeups_fill_their_fields() {
        let mut i = live();
        i.wakeups = Some((9, 4));
        let r = gather(&i);
        assert_eq!((r.w[ri::INTERRUPT_WKUPS], r.w[ri::PKG_IDLE_WKUPS]), (9, 4));
        let v0 = r.unkept_within(SIZES[0]).join(" ");
        assert!(v0.is_empty(), "{v0}");
        // A reaped child's are its parent's sums, kept as its own were.
        let mut c = Child::default();
        i.exit_abstime = Some(5000);
        c.add(&gather(&i));
        assert_eq!((c.interrupt_wkups, c.pkg_idle_wkups, c.unkept & (1 << ri::CHILD_PKG_IDLE_WKUPS)), (9, 4, 0));
    }

    #[test]
    fn a_reaped_child_adds_its_own_and_its_childrens() {
        let mut i = live();
        i.exit_abstime = Some(5000);
        i.child = Child { user_time: 10, system_time: 0, pkg_idle_wkups: 0, interrupt_wkups: 0, pageins: 0, elapsed_abstime: 100, unkept: 0 };
        let r = gather(&i);
        let mut c = Child::default();
        c.add(&r);
        c.add(&r);
        assert_eq!((c.user_time, c.system_time, c.elapsed_abstime), (2 * (24_000 + 10), 0, 2 * (4000 + 100)));
        // The child's wakeups are not kept, so neither are the sums; its
        // time and page-ins are.
        let mut p = live();
        p.child = c;
        let all = gather(&p).unkept_within(SIZES[1]).join(" ");
        assert!(!all.contains("ri_child_pageins") && all.contains("ri_child_interrupt_wkups") && !all.contains("ri_child_user_time"));
    }
}
