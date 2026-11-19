//! `reboot(2)` (`bsd/kern/kern_xxx.c`), `reboot_kernel`, `proc_shutdown`
//! and `panic_kernel` (`bsd/kern/kern_shutdown.c`), `vfs_unmountall`
//! (`bsd/vfs/vfs_subr.c`), `sync` and `dounmount`
//! (`bsd/vfs/vfs_syscalls.c`), and `host_reboot` (`osfmk/kern/machine.c`),
//! xnu-10063.141.1, as the 21H461 kernel has them.
//!
//! `reboot` (`0xfffffff007663f84`): `suser` (EPERM, else `ASU`); an
//! `RB_PANIC` message copied in (1024 bytes, `kPanicStringMaxLen`: one
//! with no NUL in them cut to 1023, one that faults replaced by "user
//! space RB_PANIC message copyin failed"); `mac_system_check_reboot`
//! (Sandbox's hook, slot 208 of its operations: `system-reboot`, operation
//! 179, argument kind 0x13 with the flags as a halfword at `+0xd8`;
//! AMFI's and AppleImage4's operations leave the slot NULL); `P_REBOOT`;
//! `reboot_kernel`.
//!
//! `reboot_kernel` (`0xfffffff00763c124`): `RB_PANIC|RB_QUICK` panics at
//! once; else the first shutdown (`system_inshutdown`; a later one is
//! EBUSY unless quick, which goes straight to the end), the platform's
//! shutdown notification, a quick one's `sync` (unless `RB_NOSYNC`), or a
//! full one's shutdown of every process and file system (unless
//! `RB_NOSYNC`), `if_down_all`; then `RB_PANIC` panics, the final stage
//! (`final_shutdown_stage`, else EBUSY), and `host_reboot`, inlined:
//! `RB_UPSDELAY`'s `PEHaltRestart(kPEUPSDelayHaltCPU)`, else
//! `halt_all_cpus(!(howto & RB_HALT))`.
//!
//! The RELEASE kernel has none of `kern_shutdown.c`'s `printf`s ("syncing
//! disks... ", "Killing all processes ", "continuing", the busy buffer
//! counts, "lingering dext"), nor `vfs_unmountall`'s, nor
//! `IOSystemShutdownNotification`'s: their strings are not in it and the
//! calls are not in its code. What reaches the disk is the shutdown log
//! (`PROC_SHUTDOWN_LOG`, written by `sd_log`) and the files' data the
//! syncs and unmounts push.
//!
//! What the full shutdown does that nothing can see once the machine has
//! ended is done as far as gex keeps its state, and the rest is reported
//! where some process could still see it ([`Kernel::darwin_shutdown_unseen`]):
//! the processes left running past `proc_shutdown` are initproc until its
//! second pass suspends it, and the rebooting process's other threads.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::kern::{self, Mount};
use super::machine::{self, caller, Cause, Event, Kind, Panic};
use super::mac::SbArgs;
use super::signal::dsig;
use crate::errno::Errno;
use crate::proc::ScanProc;
use crate::syscalls::Kernel;
use crate::GuestMem;

/// The `RB_*` flags (`bsd/sys/reboot.h`).
pub mod rb {
    pub const NOSYNC: u32 = 0x4;
    pub const HALT: u32 = 0x8;
    pub const UPSDELAY: u32 = 0x200;
    pub const QUICK: u32 = 0x400;
    pub const PANIC: u32 = 0x800;
    pub const PANIC_ZPRINT: u32 = 0x1000;
    pub const PANIC_FORCERESET: u32 = 0x2000;
}

/// `HOST_REBOOT_*` (`osfmk/mach/host_reboot.h`).
pub mod host {
    pub const HALT: u32 = 0x8;
    pub const UPSDELAY: u32 = 0x100;
}

/// `kPanicStringMaxLen`.
const PANIC_STRING_MAX: usize = 1024;

/// `system_inshutdown` and `final_shutdown_stage`.
static IN_SHUTDOWN: AtomicBool = AtomicBool::new(false);
static FINAL_STAGE: AtomicBool = AtomicBool::new(false);

/// `PROC_SHUTDOWN_LOG` (`bsd/sys/proc_internal.h`).
pub const PROC_SHUTDOWN_LOG: &str = "/var/log/kernel-shutdown.log";

/// `sd_logvp`: the shutdown log while `proc_shutdown` has it open.
static SD_LOG: Mutex<Option<Arc<crate::file::OpenFile>>> = Mutex::new(None);

/// `sd_log_offset`: where the next line goes. `sd_closelog` leaves it, so
/// a log opened again (and cut to nothing) is written on from there.
static SD_LOG_OFFSET: AtomicU64 = AtomicU64::new(0);

/// `sd_log`'s `logbuf`: what one line can hold, with its NUL.
const SD_LOGBUF: usize = 100;

/// `proc_shutdown`'s waits: up to 3 seconds for the processes sent SIGTERM,
/// 10 for those sent SIGKILL (the `timespec`s at `0xfffffff00700a6f0` and
/// `0xfffffff00700b9f0`).
pub const SIGTERM_WAIT_SECS: u64 = 3;
pub const SIGKILL_WAIT_SECS: u64 = 10;

/// Darwin's ETIMEDOUT, which `proc_shutdown` tests a wait's error against
/// (`cmp w22, #0x3c`). `msleep` answers a timeout with EWOULDBLOCK
/// (`_sleep`, `mov w20, #0x23` at `0xfffffff007644904`), so the logs of
/// the processes that did not act never happen.
const ETIMEDOUT: i32 = 60;

/// How `reboot_kernel` begins for `howto`, given whether it is the first
/// shutdown (`OSCompareAndSwap(0, 1, &system_inshutdown)` succeeded).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Begin {
    /// `panic_kernel`, before anything else.
    Panic,
    /// EBUSY: another shutdown has begun.
    Busy,
    /// Another has begun, and a quick one goes to `force_reboot`.
    ForceReboot,
    /// This is the shutdown.
    Shutdown,
}

/// `reboot_kernel`'s beginning.
pub fn begin(howto: u32, first: bool) -> Begin {
    if howto & (rb::PANIC | rb::QUICK) == rb::PANIC | rb::QUICK {
        Begin::Panic
    } else if first {
        Begin::Shutdown
    } else if howto & rb::QUICK != 0 {
        Begin::ForceReboot
    } else {
        Begin::Busy
    }
}

/// What the first shutdown does before `if_down_all`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Course {
    /// "Quick reboot...", and `sync` unless `RB_NOSYNC`.
    Quick { sync: bool },
    /// Every process and file system shut down.
    Full,
    /// `RB_NOSYNC` without `RB_QUICK`: nothing.
    NoSync,
}

/// `reboot_kernel`'s course for `howto`.
pub fn course(howto: u32) -> Course {
    if howto & rb::QUICK != 0 {
        Course::Quick { sync: howto & rb::NOSYNC == 0 }
    } else if howto & rb::NOSYNC == 0 {
        Course::Full
    } else {
        Course::NoSync
    }
}

/// `force_reboot:`'s end for `howto`, given whether the final stage had
/// begun (`OSCompareAndSwap(0, 1, &final_shutdown_stage)` failed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finish {
    Panic,
    Busy,
    /// `host_reboot(host_priv_self(), options)`.
    HostReboot(u32),
}

/// `force_reboot:`: `RB_PANIC` panics; a second final stage is EBUSY; else
/// `host_reboot` with `HOST_REBOOT_HALT` for `RB_HALT`, replaced by
/// `HOST_REBOOT_UPSDELAY` for `RB_UPSDELAY`.
pub fn finish(howto: u32, final_begun: bool) -> Finish {
    if howto & rb::PANIC != 0 {
        return Finish::Panic;
    }
    if final_begun {
        return Finish::Busy;
    }
    let mut options = 0;
    if howto & rb::HALT != 0 {
        options = host::HALT;
    }
    if howto & rb::UPSDELAY != 0 {
        options = host::UPSDELAY;
    }
    Finish::HostReboot(options)
}

/// What `host_reboot(host_priv, options)` ends the machine with (21H461
/// has no `HOST_REBOOT_DEBUGGER`, a development kernel's):
/// `HOST_REBOOT_UPSDELAY` is `PEHaltRestart(kPEUPSDelayHaltCPU)`, which
/// `PEHaltRestartInternal` (0xfffffff00780f74c) takes down the same path
/// as a halt and a restart (its jump table sends types 0, 1 and 3 to
/// 0xfffffff00780f790: the shutdown hang's thread call, then
/// `IOPMrootDomain::handlePlatformHaltRestart`, which treats it as
/// `kPEHaltCPU` but for clearing the RestartOnPowerLoss setting), then to
/// `gIOPlatform->haltRestart` (vtable slot 0x5b8). The platform expert is
/// AppleARMPE (its vtable 0xfffffff006cc03c8, made by the metaclass at
/// 0xfffffff007addf00), which keeps `IODTPlatformExpert::haltRestart`
/// (0xfffffff00780cfd0): `kPEUPSDelayHaltCPU` becomes `kPEHaltCPU` for
/// `PE_halt_restart`. So it halts, as `halt_all_cpus(FALSE)` does; else
/// `halt_all_cpus(!(options & HOST_REBOOT_HALT))`.
pub fn host_reboot_kind(options: u32) -> Kind {
    if options & host::UPSDELAY != 0 || options & host::HALT != 0 {
        Kind::Halt
    } else {
        Kind::Restart
    }
}

/// `panic_kernel(howto, message)`'s panic: `RB_PANIC_FORCERESET` asks for a
/// paniclog and an immediate reset (`DEBUGGER_OPTION_PANICLOGANDREBOOT`);
/// the message is `userspace panic: %s` of the copied message (none
/// prints nothing, `_doprnt`'s NULL string).
pub fn panic_kernel(howto: u32, message: Option<&[u8]>) -> Panic {
    let mut text = b"userspace panic: ".to_vec();
    text.extend_from_slice(message.unwrap_or(b""));
    let options = if howto & rb::PANIC_FORCERESET != 0 { machine::DEBUGGER_OPTION_PANICLOGANDREBOOT } else { 0 };
    Panic { cpu: machine::CPU, caller: caller::PANIC_KERNEL, options, message: text }
}

/// `sd_filterargs`.
#[derive(Clone, Copy, Debug)]
pub struct SdFilter {
    pub delayterm: bool,
    pub shutdownstate: u8,
    pub only_non_dext: bool,
}

/// `sd_filt1` for the shutdown made by process `me`: a process to send
/// SIGTERM is not a driver when only those are spared, not a system
/// process (`P_SYSTEM`: kernproc alone, not on the walk here), not
/// initproc (`p_ppid` 0), not the caller, not a zombie, in `shutdownstate`,
/// marked for delayed termination only in the delayed round, and catches
/// SIGTERM. `None` while its catch mask is not there to read.
pub fn sd_filt1(p: &ScanProc, me: i32, f: &SdFilter) -> Option<bool> {
    if f.only_non_dext && p.driver {
        return Some(false);
    }
    if p.ppid == 0 || p.pid == me || p.zombie || p.shutdownstate != f.shutdownstate || (!f.delayterm && p.delayterm) {
        return Some(false);
    }
    Some(p.sigcatch? & super::signal::sigmask(dsig::SIGTERM) != 0)
}

/// `sd_filt2`: as `sd_filt1`, but any process not yet in `shutdownstate`,
/// whatever it catches.
pub fn sd_filt2(p: &ScanProc, me: i32, f: &SdFilter) -> Option<bool> {
    if f.only_non_dext && p.driver {
        return Some(false);
    }
    Some(!(p.ppid == 0 || p.pid == me || p.zombie || p.shutdownstate == f.shutdownstate || (!f.delayterm && p.delayterm)))
}

impl Kernel {
    fn darwin_machine_event(&self, kind: Kind, cause: Cause) -> Event {
        let n = self.dtask.p_name.0;
        let name = String::from_utf8_lossy(&n[..n.iter().position(|&c| c == 0).unwrap_or(n.len())]).into_owned();
        Event { kind, cause, pid: self.pid, name }
    }

    /// `reboot(opt, msg)`.
    pub(crate) fn darwin_reboot(&mut self, m: &mut GuestMem<'_>, opt: i32, msg: u64) -> Result<u64, Errno> {
        self.darwin_suser()?;
        let howto = opt as u32;
        let message = if howto & rb::PANIC != 0 && msg != 0 {
            Some(match super::exec::copyinstr(m, msg, PANIC_STRING_MAX) {
                Ok(s) => s,
                Err(Errno::ENAMETOOLONG) => m.read(msg, PANIC_STRING_MAX - 1)?.to_vec(),
                Err(_) => b"user space RB_PANIC message copyin failed".to_vec(),
            })
        } else {
            None
        };
        let a = SbArgs { kind: super::sandbox::kind::REBOOT, number: howto & 0xffff, ..Default::default() };
        match self.darwin_sb_evaluate(super::mac::op::SYSTEM_REBOOT, &a) {
            0 => {}
            e => return Err(super::errno::errno_of(e as i32)),
        }
        self.procs.set_reboot(self.pid);
        self.darwin_reboot_kernel(howto, message.as_deref())
    }

    /// `reboot_kernel(howto, message)` as 21H461 compiles it: returns only
    /// with an error.
    ///
    /// Before the shutdown's notification it waits, under
    /// `vm_swap_data_lock`, for the swap file's creation and garbage
    /// collection threads to stop: neither runs here (no swap file is
    /// made: the device modelled runs no pageout). The
    /// `IOSystemShutdownNotification` stages reach no process here:
    /// `kIOSystemShutdownNotificationStageProcessExit` sets up the halt log
    /// (printed only under the `haltmslog` boot-arg, which this boot does
    /// not have), tells the kernel's own power clients
    /// (`IOPMRootDomainWillShutdown`), and pages off
    /// (`handlePlatformHaltRestart(kPEPagingOff)`), whose
    /// `updateConsoleUsers` publishes only a change of `IOConsoleLocked`:
    /// with no console user (no process can set the root's
    /// `IOConsoleUsers` here) it has been true since the boot's
    /// `kIOMessageSystemHasPoweredOn` call; `...StageRootUnmount` returns
    /// at once on a system that is not macOS; `...TerminateDEXTs`
    /// (`IOServicePH::systemHalt`) tells the DriverKit servers, none of
    /// which runs here, and waits for none. `halt_log_enter` keeps its
    /// times in that same unprinted log. `audit_shutdown` is not in
    /// 21H461 (no CONFIG_AUDIT), nor `unmountroot_pre_hook` (macOS's);
    /// `kdbg_dump_trace_to_file` runs only with kdebug tracing enabled,
    /// which it never is here; `cl_sparse_push_error` counts the sparse
    /// cluster pushes that failed with ENOSPC, and no push fails here.
    fn darwin_reboot_kernel(&mut self, howto: u32, message: Option<&[u8]>) -> Result<u64, Errno> {
        let first = howto & (rb::PANIC | rb::QUICK) != rb::PANIC | rb::QUICK && IN_SHUTDOWN.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok();
        match begin(howto, first) {
            Begin::Panic => machine::end(self.darwin_machine_event(Kind::Panic(panic_kernel(howto, message)), Cause::Reboot { howto })),
            Begin::Busy => return Err(Errno::EBUSY),
            Begin::ForceReboot => return self.darwin_force_reboot(howto, message),
            Begin::Shutdown => {}
        }
        match course(howto) {
            Course::Quick { sync } => {
                if sync {
                    self.darwin_sync();
                }
            }
            Course::Full => {
                self.darwin_proc_shutdown(true);
                self.darwin_sync();
                self.darwin_vfs_unmountall(true);
                self.darwin_proc_shutdown(false);
                self.darwin_vfs_unmountall(false);
                // The wait for the buffer cache's busy buffers
                // (count_busy_buffers: buf_busycount + bufs_iobufinuse, up
                // to 100 tries, each delay_for_interval(nbusy, 1 ms)): no
                // buffer is busy here, every I/O being done within the
                // call that makes it.
            }
            Course::NoSync => {}
        }
        // if_down_all: lo0 down; what goes with it, reported where a
        // process still runs.
        super::ioctl::if_down_all();
        self.darwin_shutdown_unseen("if_down_all's dlil_proto_unplumb_all of lo0 (its protocols and addresses gone) and its rt_ifmsg routing message");
        self.darwin_force_reboot(howto, message)
    }

    /// `force_reboot:` to the machine's end.
    fn darwin_force_reboot(&mut self, howto: u32, message: Option<&[u8]>) -> Result<u64, Errno> {
        let final_begun = howto & rb::PANIC == 0 && FINAL_STAGE.swap(true, Ordering::AcqRel);
        match finish(howto, final_begun) {
            Finish::Panic => machine::end(self.darwin_machine_event(Kind::Panic(panic_kernel(howto, message)), Cause::Reboot { howto })),
            Finish::Busy => Err(Errno::EBUSY),
            Finish::HostReboot(options) => {
                // What strict mode stops at, before the machine's end would
                // hide it.
                if self.dtask.strict && self.dtask.stop.is_some() {
                    return Err(Errno::EIO);
                }
                machine::end(self.darwin_machine_event(host_reboot_kind(options), Cause::Reboot { howto }))
            }
        }
    }

    /// `host_reboot(host_priv, options)` on the host's privileged port
    /// ([`host_reboot_kind`]): the machine's end.
    pub(crate) fn darwin_host_reboot(&mut self, options: u32) -> ! {
        machine::end(self.darwin_machine_event(host_reboot_kind(options), Cause::HostReboot { options }))
    }

    /// Report `what`, a part of the shutdown not modelled, when a thread
    /// that could see it still runs: the caller's other threads, or a
    /// process no signal ended and no hold stops (initproc before the
    /// second `proc_shutdown`).
    fn darwin_shutdown_unseen(&mut self, what: &str) {
        let others = self.procs.runnable_besides(self.pid);
        if !others.is_empty() {
            let who: Vec<String> = others.iter().map(|(pid, n)| format!("pid {pid} ({n} thread{})", if *n == 1 { "" } else { "s" })).collect();
            self.darwin_unimplemented(format!("the system's shutdown: {what}, while {} still run", who.join(", ")));
        }
    }

    /// `psignal(p, signum)` from this thread's process: posted with the
    /// reason `build_signal_reason(signum, NULL)` gives a signal that
    /// kills (the sender this process), and `si_pid` and `si_uid` this
    /// process's for one caught.
    fn darwin_shutdown_psignal(&mut self, pid: i32, signum: u32) {
        let note = self.darwin_signal_reason(signum);
        let _ = self.procs.kill_noted(self.pid, pid, kern::signal_to_linux(signum), Some(note));
    }

    /// `proc_shutdown(only_non_dext)`: initproc sent SIGTERM (unless it
    /// is the caller), then two rounds, the second for the processes
    /// marked for delayed termination: SIGTERM to those that catch it and
    /// a wait of up to [`SIGTERM_WAIT_SECS`] for them to end, SIGKILL to
    /// every one left and a wait of up to [`SIGKILL_WAIT_SECS`], then
    /// `exit1` of any still there; the log closed; and, past the drivers'
    /// pass, initproc's task suspended. A wait that times out takes
    /// `P_LIST_EXITCOUNT` off every process; its log of the processes that
    /// did not act tests the wait's error for ETIMEDOUT, which `msleep`
    /// never answers, so it never runs.
    fn darwin_proc_shutdown(&mut self, only_non_dext: bool) {
        let procs = Arc::clone(&self.procs);
        let me = self.pid;
        // proc_find(1): live and found, and not the caller.
        if me != crate::proc::INIT_PID && procs.darwin(crate::proc::INIT_PID).is_some_and(|(_, exited)| !exited) {
            self.darwin_shutdown_psignal(crate::proc::INIT_PID, dsig::SIGTERM);
        }
        let mut delayterm = false;
        loop {
            // SIGTERM to every process that catches it.
            let f = SdFilter { delayterm, shutdownstate: 0, only_non_dext };
            let mut active = 0u32;
            procs.rebootscan(|p| sd_filt1(p, me, &f), |pid| self.darwin_sd_callback_signal(pid, dsig::SIGTERM, 1, &mut active));
            if procs.shutdown_wait(active, SIGTERM_WAIT_SECS) == ETIMEDOUT {
                self.darwin_sd_log_unresponsive(1, "SIGTERM");
            }
            // SIGKILL to every one still there.
            let f = SdFilter { delayterm, shutdownstate: 2, only_non_dext };
            let mut active = 0u32;
            procs.rebootscan(|p| sd_filt2(p, me, &f), |pid| self.darwin_sd_callback_signal(pid, dsig::SIGKILL, 2, &mut active));
            if procs.shutdown_wait(active, SIGKILL_WAIT_SECS) == ETIMEDOUT {
                self.darwin_sd_log_unresponsive(2, "SIGKILL");
            }
            // exit1 of any that has still not ended.
            let f = SdFilter { delayterm, shutdownstate: 3, only_non_dext };
            procs.rebootscan(|p| sd_filt2(p, me, &f), |pid| self.darwin_sd_callback3(pid));
            if delayterm {
                break;
            }
            delayterm = true;
        }
        self.darwin_sd_closelog();
        if only_non_dext {
            return;
        }
        procs.task_suspend_internal(crate::proc::INIT_PID);
    }

    /// `sd_callback1` and `sd_callback2`: the process's `p_shutdownstate`
    /// is `state`; one not a zombie is counted to wait for and sent
    /// `signum` (a driver's "lingering dext" line is not in 21H461).
    fn darwin_sd_callback_signal(&mut self, pid: i32, signum: u32, state: u8, active: &mut u32) {
        if self.procs.shutdown_mark(pid, state, true) {
            self.darwin_shutdown_psignal(pid, signum);
            *active += 1;
        }
    }

    /// `sd_callback3`: the process's `p_shutdownstate` is 3; one not a
    /// zombie whose exit no thread has taken on is made to exit, with the
    /// shutdown log's line for it: `exit1(p, 1, NULL)`, its status 1 (as
    /// if signal 1 had ended it); one whose exit some thread is making is
    /// given a chance to end (`thread_block`).
    fn darwin_sd_callback3(&mut self, pid: i32) {
        if !self.procs.shutdown_mark(pid, 3, false) {
            return;
        }
        if !self.procs.claim_exit(pid, 1) {
            std::thread::yield_now();
            return;
        }
        let mut line = self.darwin_comm_of(pid);
        line.extend_from_slice(format!("[{pid}] had to be forced closed with exit1().\n").as_bytes());
        self.darwin_sd_log(&line);
        self.procs.exit_claimed(pid);
    }

    /// The lines of the processes a round's wait gave up on (`p_comm`,
    /// pid, the signal), in `allproc`'s order.
    fn darwin_sd_log_unresponsive(&mut self, state: u8, signal: &str) {
        for pid in self.procs.shutdown_in_state(state) {
            let mut line = self.darwin_comm_of(pid);
            line.extend_from_slice(format!("[{pid}]: didn't act on {signal}\n").as_bytes());
            self.darwin_sd_log(&line);
        }
    }

    /// Process `pid`'s `p_comm`.
    fn darwin_comm_of(&self, pid: i32) -> Vec<u8> {
        self.procs.darwin(pid).and_then(|(r, _)| r.downcast::<super::procinfo::Public>().ok()).map(|p| p.comm.clone()).unwrap_or_default()
    }

    /// `sd_log(ctx, fmt, ...)` of the formatted `line`: the log opened
    /// first if it is not, the line (formatted into a 100-byte buffer)
    /// written at the log's offset (`vn_rdwr`, `IO_UNIT | IO_NOAUTH`, this
    /// thread's credential), which moves by what was written when the
    /// write succeeds or fails with EIO.
    fn darwin_sd_log(&mut self, line: &[u8]) {
        if SD_LOG.lock().unwrap_or_else(|e| e.into_inner()).is_none() && self.darwin_sd_openlog().is_err() {
            return;
        }
        let Some(file) = SD_LOG.lock().unwrap_or_else(|e| e.into_inner()).clone() else { return };
        // vsnprintf's length is the whole line's, and vn_rdwr writes that
        // many bytes of the buffer: a line longer than the buffer would
        // write past it (no line here can be: p_comm is at most 16 bytes).
        if line.len() >= SD_LOGBUF {
            self.darwin_unimplemented(format!("sd_log of a line of {} bytes, longer than its 100-byte buffer", line.len()));
            return;
        }
        let at = SD_LOG_OFFSET.load(Ordering::Acquire);
        // IO_UNIT: a write that fails writes nothing (resid the length).
        if let Ok(n) = file.pwrite(at, line) {
            SD_LOG_OFFSET.store(at + n as u64, Ordering::Release);
        }
    }

    /// `sd_openlog(ctx)`: `vnode_open(PROC_SHUTDOWN_LOG, O_CREAT | FWRITE |
    /// O_NOFOLLOW, 0644, 0, &sd_logvp, ctx)` (its failure leaves no log;
    /// "Failed to open" is not in 21H461), cut to nothing
    /// (`vnode_setsize`), and its header with the calendar time's seconds.
    fn darwin_sd_openlog(&mut self) -> Result<(), Errno> {
        let file = match self.darwin_vnode_open_create(PROC_SHUTDOWN_LOG, 0o644) {
            Ok(f) => f,
            Err(e) => {
                *SD_LOG.lock().unwrap_or_else(|e| e.into_inner()) = None;
                return Err(e);
            }
        };
        *SD_LOG.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&file));
        let _ = file.handle.truncate(0);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        self.darwin_sd_log(format!("Process shutdown log.  Current time is {now} (in seconds).\n\n").as_bytes());
        Ok(())
    }

    /// `sd_closelog(ctx)`: an open log pushed (`VNOP_FSYNC`, `MNT_WAIT`)
    /// and closed (`vnode_close`, `FWRITE`).
    fn darwin_sd_closelog(&mut self) {
        let file = SD_LOG.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(file) = file {
            super::pagecache::fsync(&file);
            file.fg_drop();
        }
    }

    /// `sync(p, uap, retval)`: `vfs_iterate(LK_NOWAIT, sync_callback,
    /// NULL)`, whose `LK_NOWAIT` (1) is `VFS_ITERATE_TAIL_FIRST`, so from
    /// the mount list's last mount to its first, past those being
    /// unmounted; `print_vmpage_stat` (no sysctl or boot-arg sets it) is
    /// 0.
    pub(crate) fn darwin_sync(&mut self) {
        for mnt in kern::mounts().into_iter().rev() {
            if mnt.state().lflag & (kern::MNT_LDEAD | kern::MNT_LUNMOUNT) != 0 {
                continue;
            }
            self.darwin_sync_callback(mnt, kern::MNT_NOWAIT);
        }
    }

    /// `sync_callback(mp, arg)`: a mount not read-only has `MNT_ASYNC`
    /// cleared around its `VFS_SYNC(mp, waitfor, vfs_context_kernel())`.
    fn darwin_sync_callback(&mut self, mnt: &'static Mount, waitfor: u32) {
        let asyncflag = {
            let mut st = mnt.state();
            if st.flags & kern::MNT_RDONLY != 0 {
                return;
            }
            let a = st.flags & kern::MNT_ASYNC;
            st.flags &= !kern::MNT_ASYNC;
            a
        };
        self.darwin_vfs_sync(mnt, waitfor);
        if asyncflag != 0 {
            mnt.state().flags |= kern::MNT_ASYNC;
        }
    }

    /// `VFS_SYNC(mp, waitfor, ctx)`: devfs's `devfs_sync` does nothing;
    /// APFS's (apfs_vfsop_sync, K 0x66c9d80) returns at once for a volume
    /// mounted read-only (`+0x354`) and, after its log, for a mount being
    /// updated (`MNT_UPDATE`); else its vnode pass pushes each regular
    /// file's write-behind ([`super::pagecache::sync_mount`]), `IO_SYNC`
    /// for `MNT_WAIT` or `MNT_DWAIT`, charged to this thread's task. For a
    /// volume the kernel's container in the disk0 image holds read-write,
    /// the pass then writes the times its inodes hold and the container's
    /// open transaction is committed ([`super::disknode::vfs_sync`]).
    fn darwin_vfs_sync(&mut self, mnt: &'static Mount, waitfor: u32) {
        const MNT_UPDATE: u32 = 0x1_0000;
        if mnt.fs != kern::Fs::Apfs || mnt.state().apfs_ro == Some(true) {
            return;
        }
        if mnt.state().flags & MNT_UPDATE != 0 {
            return;
        }
        let sync = waitfor & (kern::MNT_WAIT | kern::MNT_DWAIT) != 0;
        super::pagecache::charge(super::pagecache::sync_mount(mnt, sync));
        if let Some(i) = kern::mount_volume(mnt).filter(|&i| super::disknode::holds_rw(i)) {
            if let Err(why) = super::disknode::vfs_sync(i, waitfor) {
                self.darwin_unimplemented(format!("VFS_SYNC of the volume on {}: {why}", mnt.on));
            }
        }
    }

    /// `vfs_unmountall(only_non_system)`: the mounts walked from the
    /// list's last (`VFS_ITERATE_TAIL_FIRST`, past those already being
    /// unmounted), each counted, and each but the root and the system
    /// mounts (`MNT_ROOTFS`, `MNTK_SYSTEM`) on the first pass given
    /// `dounmount(mp, MNT_FORCE, 1, ctx)`; while one was busy, a sleep of
    /// 1, 2, 4, 8, 16 and 32 seconds before each try again ("Unmounting
    /// timed out" is not in 21H461), else, when the walk missed mounts
    /// made meanwhile, one sleep of 2 seconds. (The watchdog's VFS shutdown
    /// times are the kernel's own.)
    fn darwin_vfs_unmountall(&mut self, only_non_system: bool) {
        let mut sec = 1u64;
        loop {
            let (mut busy, mut count) = (0u32, 0usize);
            for mnt in kern::mounts().into_iter().rev() {
                if mnt.state().lflag & (kern::MNT_LDEAD | kern::MNT_LUNMOUNT) != 0 {
                    continue;
                }
                count += 1;
                if only_non_system && (mnt.flags() & kern::MNT_ROOTFS != 0 || mnt.state().kern_flag & kern::MNTK_SYSTEM != 0) {
                    continue;
                }
                if self.darwin_dounmount_forced(mnt, false) == Err(Errno::EBUSY) {
                    busy += 1;
                }
            }
            let mounts = kern::mounts().len();
            if mounts == 0 {
                return;
            }
            if busy > 0 {
                std::thread::sleep(std::time::Duration::from_secs(sec));
                sec *= 2;
                if sec <= 32 {
                    continue;
                }
            } else if count < mounts {
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
            return;
        }
    }

    /// `dounmount(mp, MNT_FORCE | lnosub, 1, ctx)`: EBUSY for a mount
    /// already being mounted or unmounted; else `MNT_LFORCE`,
    /// `MNTK_UNMOUNT`, `MNT_LUNMOUNT`, `MNT_ASYNC` cleared; its submounts
    /// unmounted first (unless this is one); the mount generation moved;
    /// no `VFS_SYNC` for a forced unmount; `vflush` with `FORCECLOSE`
    /// ([`super::pagecache::vflush`]); `VFS_UNMOUNT` (APFS's, of a volume
    /// whose files are the host's, writes nothing here; devfs's
    /// `devfs_unmount` flushes its vnodes again and clears `MNT_LOCAL`);
    /// `mount_list_remove`, `MNT_LDEAD`; then `NOTE_WRITE` to the
    /// directory that holds its mount point. (`IOBSDMountChange` keeps a
    /// kernel core file, which a RELEASE kernel has none of; the
    /// `VQ_UNMOUNT` event has no EVFILT_FS knote to reach.) What the
    /// processes still running would see of it is reported
    /// ([`Kernel::darwin_shutdown_unseen`]).
    fn darwin_dounmount_forced(&mut self, mnt: &'static Mount, lnosub: bool) -> Result<(), Errno> {
        {
            let mut st = mnt.state();
            if st.lflag & (kern::MNT_LUNMOUNT | kern::MNT_LMOUNT) != 0 {
                return Err(Errno::EBUSY);
            }
            st.lflag |= kern::MNT_LFORCE | kern::MNT_LUNMOUNT;
            st.kern_flag |= kern::MNTK_UNMOUNT;
            st.flags &= !kern::MNT_ASYNC;
        }
        if !lnosub {
            self.darwin_dounmount_submounts(mnt);
        }
        kern::bump_mount_generation();
        self.darwin_shutdown_unseen(&format!(
            "the forced unmount of the volume on {} (vflush's FORCECLOSE of its vnodes in use, which then answer as dead ones, and the lookups past its mount point, of the directory it covered)",
            mnt.on
        ));
        super::pagecache::charge(super::pagecache::vflush(mnt));
        if mnt.fs == kern::Fs::Devfs {
            mnt.state().flags &= !kern::MNT_LOCAL;
        }
        // A writable mount of a volume the kernel's container in the disk0
        // image holds read-write: apfs_vfsop_unmount's own writes (the
        // container's commit, the volume's apfs_modified_by entry and
        // unmount time, super::apfswrite::fsops::unmount) are not made.
        if let Some(i) = kern::mount_volume(mnt).filter(|_| mnt.fs == kern::Fs::Apfs && mnt.state().apfs_ro == Some(false)) {
            if super::disknode::holds_rw(i) {
                self.darwin_unimplemented(format!("the forced unmount of the volume on {}: apfs_vfsop_unmount's writes to the kernel's container in the disk0 image (its commit, the volume's apfs_modified_by entry and unmount time)", mnt.on));
            }
        }
        kern::mount_list_remove(mnt);
        if mnt.flags() & kern::MNT_ROOTFS == 0 && crate::vnote::any() {
            let parent = crate::vfs::parent_of(mnt.on);
            if let Ok((Some(key), _)) = self.vfs.watch_target(&parent, true).and_then(|(fs, rel)| fs.watch_key(&rel)) {
                crate::vnote::post(key, crate::vnote::note::WRITE);
            }
        }
        Ok(())
    }

    /// `dounmount_submounts(mp, MNT_FORCE | MNT_LNOSUB, ctx)`: the mounts
    /// after it in the list whose covered vnode is on it or on one of
    /// those already found, unmounted from the last found, errors let be.
    fn darwin_dounmount_submounts(&mut self, mnt: &'static Mount) {
        let list = kern::mounts();
        let Some(at) = list.iter().position(|m| std::ptr::eq(*m, mnt)) else { return };
        let mut found: Vec<&'static Mount> = vec![mnt];
        for &smp in &list[at + 1..] {
            if smp.flags() & kern::MNT_ROOTFS != 0 {
                continue;
            }
            let under = kern::covered_mount(smp);
            if found.iter().any(|m| std::ptr::eq(*m, under)) {
                found.push(smp);
            }
        }
        for &smp in found[1..].iter().rev() {
            let _ = self.darwin_dounmount_forced(smp, true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quick_panic_panics_first_and_a_later_shutdown_is_busy_unless_quick() {
        assert_eq!(begin(rb::PANIC | rb::QUICK, false), Begin::Panic);
        assert_eq!(begin(rb::PANIC | rb::QUICK, true), Begin::Panic);
        assert_eq!(begin(0, true), Begin::Shutdown);
        assert_eq!(begin(rb::PANIC, false), Begin::Busy);
        assert_eq!(begin(rb::NOSYNC, false), Begin::Busy);
        assert_eq!(begin(rb::QUICK, false), Begin::ForceReboot);
        assert_eq!(begin(rb::QUICK | rb::HALT, false), Begin::ForceReboot);
    }

    #[test]
    fn the_course_is_quick_full_or_nothing() {
        assert_eq!(course(0), Course::Full);
        assert_eq!(course(rb::HALT), Course::Full);
        assert_eq!(course(rb::PANIC), Course::Full);
        assert_eq!(course(rb::NOSYNC), Course::NoSync);
        assert_eq!(course(rb::NOSYNC | rb::HALT), Course::NoSync);
        assert_eq!(course(rb::QUICK), Course::Quick { sync: true });
        assert_eq!(course(rb::QUICK | rb::NOSYNC), Course::Quick { sync: false });
    }

    #[test]
    fn the_end_panics_is_busy_or_reboots_the_host_with_ups_delay_last() {
        assert_eq!(finish(rb::PANIC, true), Finish::Panic);
        assert_eq!(finish(0, true), Finish::Busy);
        assert_eq!(finish(0, false), Finish::HostReboot(0));
        assert_eq!(finish(rb::HALT, false), Finish::HostReboot(host::HALT));
        assert_eq!(finish(rb::HALT | rb::UPSDELAY, false), Finish::HostReboot(host::UPSDELAY));
        assert_eq!(finish(rb::UPSDELAY, false), Finish::HostReboot(host::UPSDELAY));
    }

    #[test]
    fn host_reboot_halts_for_halt_and_for_the_ups_delay() {
        assert_eq!(host_reboot_kind(0), Kind::Restart);
        assert_eq!(host_reboot_kind(host::HALT), Kind::Halt);
        assert_eq!(host_reboot_kind(host::UPSDELAY), Kind::Halt);
        assert_eq!(host_reboot_kind(host::UPSDELAY | host::HALT), Kind::Halt);
        // HOST_REBOOT_DEBUGGER is a development kernel's: a restart.
        assert_eq!(host_reboot_kind(0x1000), Kind::Restart);
    }

    fn proc(pid: i32) -> ScanProc {
        ScanProc { pid, ppid: 2, shutdownstate: 0, delayterm: false, zombie: false, driver: false, sigcatch: Some(0) }
    }

    #[test]
    fn sigterm_goes_to_the_processes_that_catch_it_but_initproc_and_the_caller() {
        let term = super::super::signal::sigmask(dsig::SIGTERM);
        let f = SdFilter { delayterm: false, shutdownstate: 0, only_non_dext: true };
        let catcher = ScanProc { sigcatch: Some(term), ..proc(5) };
        assert_eq!(sd_filt1(&catcher, 2, &f), Some(true));
        assert_eq!(sd_filt1(&proc(5), 2, &f), Some(false), "a process that does not catch it");
        assert_eq!(sd_filt1(&ScanProc { ppid: 0, ..catcher }, 2, &f), Some(false), "initproc");
        assert_eq!(sd_filt1(&catcher, 5, &f), Some(false), "the caller");
        assert_eq!(sd_filt1(&ScanProc { zombie: true, ..catcher }, 2, &f), Some(false));
        assert_eq!(sd_filt1(&ScanProc { shutdownstate: 1, ..catcher }, 2, &f), Some(false));
        assert_eq!(sd_filt1(&ScanProc { delayterm: true, ..catcher }, 2, &f), Some(false), "delayed to the second round");
        assert_eq!(sd_filt1(&ScanProc { delayterm: true, ..catcher }, 2, &SdFilter { delayterm: true, ..f }), Some(true));
        assert_eq!(sd_filt1(&ScanProc { driver: true, ..catcher }, 2, &f), Some(false), "a driver, spared on the first pass");
        assert_eq!(sd_filt1(&ScanProc { driver: true, ..catcher }, 2, &SdFilter { only_non_dext: false, ..f }), Some(true));
        assert_eq!(sd_filt1(&ScanProc { sigcatch: None, ..catcher }, 2, &f), None, "its record not made yet");
    }

    #[test]
    fn sigkill_and_exit1_go_to_every_process_not_yet_in_their_state() {
        let f = SdFilter { delayterm: false, shutdownstate: 2, only_non_dext: true };
        assert_eq!(sd_filt2(&proc(5), 2, &f), Some(true));
        assert_eq!(sd_filt2(&ScanProc { shutdownstate: 1, ..proc(5) }, 2, &f), Some(true));
        assert_eq!(sd_filt2(&ScanProc { shutdownstate: 2, ..proc(5) }, 2, &f), Some(false));
        assert_eq!(sd_filt2(&ScanProc { sigcatch: None, ..proc(5) }, 2, &f), Some(true), "the catch mask is not read");
        assert_eq!(sd_filt2(&ScanProc { delayterm: true, ..proc(5) }, 2, &f), Some(false));
        assert_eq!(sd_filt2(&ScanProc { ppid: 0, ..proc(5) }, 2, &f), Some(false));
        let f3 = SdFilter { shutdownstate: 3, ..f };
        assert_eq!(sd_filt2(&ScanProc { shutdownstate: 2, ..proc(5) }, 2, &f3), Some(true));
    }

    #[test]
    fn panic_kernel_says_userspace_panic() {
        let p = panic_kernel(rb::PANIC | rb::QUICK, Some(b"boot task failure: fsck - exited due to SIGSYS"));
        assert_eq!(p.message, b"userspace panic: boot task failure: fsck - exited due to SIGSYS".to_vec());
        assert_eq!((p.options, p.caller), (0, caller::PANIC_KERNEL));
        assert_eq!(panic_kernel(rb::PANIC | rb::PANIC_FORCERESET, None).message, b"userspace panic: ".to_vec());
        assert_eq!(panic_kernel(rb::PANIC | rb::PANIC_FORCERESET, None).options, machine::DEBUGGER_OPTION_PANICLOGANDREBOOT);
    }
}
