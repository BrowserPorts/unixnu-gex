//! `thread_info` (`osfmk/kern/thread_act.c`) and `thread_info_internal`
//! (`osfmk/kern/thread.c`), as 21H461's kernel has them: a thread that has
//! ended is KERN_TERMINATED, then each flavor checks the caller's count
//! (MIG has already held it to `THREAD_INFO_MAX`, 32 words) and answers.
//!
//! The release kernel is built without `PRECISE_USER_KERNEL_TIME`
//! (`config_skip_precise_user_kernel_time` in `MASTER.arm64.iPhoneOS`'s
//! `MACH_RELEASE`): `recount_thread_times` counts a thread's time in the
//! kernel as its user time, and its system time is 0, as 21H461's
//! `retrieve_thread_basic_info` stores it.

use super::kobject::Reply;
use super::thread::{Finish, KStack};
use crate::syscalls::{BlockOp, Kernel};

/// `thread_flavor_t`s (`mach/thread_info.h`).
mod flavor {
    pub const BASIC_INFO: i32 = 3;
    pub const IDENTIFIER_INFO: i32 = 4;
    pub const EXTENDED_INFO: i32 = 5;
    pub const DEBUG_INFO_INTERNAL: i32 = 6;
    pub const SCHED_TIMESHARE_INFO: i32 = 10;
    pub const SCHED_RR_INFO: i32 = 11;
    pub const SCHED_FIFO_INFO: i32 = 12;
}

/// The flavors' counts: `THREAD_BASIC_INFO_COUNT`,
/// `THREAD_IDENTIFIER_INFO_COUNT`, `THREAD_EXTENDED_INFO_COUNT`,
/// `POLICY_TIMESHARE_INFO_COUNT`, `POLICY_RR_INFO_COUNT` and
/// `POLICY_FIFO_INFO_COUNT` (`mach/policy.h`).
mod count {
    pub const BASIC_INFO: u32 = 10;
    pub const IDENTIFIER_INFO: u32 = 6;
    pub const EXTENDED_INFO: u32 = 28;
    pub const TIMESHARE_INFO: u32 = 5;
    pub const RR_INFO: u32 = 5;
    pub const FIFO_INFO: u32 = 4;
}

const KERN_INVALID_ARGUMENT: i32 = 4;
const KERN_INVALID_POLICY: i32 = 28;
const KERN_TERMINATED: i32 = 37;
const KERN_NOT_SUPPORTED: i32 = 46;

/// `POLICY_TIMESHARE` (`mach/policy.h`).
const POLICY_TIMESHARE: u32 = 1;

/// `TH_STATE_*` (`mach/thread_info.h`).
mod th_state {
    pub const RUNNING: u32 = 1;
    pub const STOPPED: u32 = 2;
    pub const WAITING: u32 = 3;
    pub const UNINTERRUPTIBLE: u32 = 4;
}

/// `TH_FLAGS_SWAPPED`: no kernel stack.
const TH_FLAGS_SWAPPED: u32 = 0x1;

/// A thread's `sched_mode`, as far as it is known here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Timeshare,
    /// TH_MODE_FIXED or TH_MODE_REALTIME, unless the failsafe has demoted
    /// it to timesharing for running too long without blocking
    /// (`thread_quantum_expire`'s `max_unsafe_computation` checks), which
    /// is not metered here.
    FixedOrRealtime,
}

/// `thread_info` of thread `t` with the caller's `count` (already at most
/// `THREAD_INFO_MAX`).
pub(super) fn thread_info(k: &mut Kernel, t: i32, fl: i32, count: u32) -> Reply {
    // thread->active: its thread_terminate has not begun.
    if k.thread_signals.get(t).is_none() {
        return Reply::err(KERN_TERMINATED);
    }
    match fl {
        flavor::BASIC_INFO => {
            if count < count::BASIC_INFO {
                return Reply::err(KERN_INVALID_ARGUMENT);
            }
            match basic_info(k, t) {
                Ok(w) => {
                    k.darwin_clock_read();
                    Reply::ok(super::mig::words(&w))
                }
                Err(why) => loud(why),
            }
        }
        // thread_id, thread_handle (cthread_self) and dispatch_qaddr
        // (thread_dispatchqaddr: the handle plus the process's dispatch
        // queue offset, none without a handle). The count is left as the
        // caller gave it: the words past these are the zeroed reply's.
        flavor::IDENTIFIER_INFO => {
            if count < count::IDENTIFIER_INFO {
                return Reply::err(KERN_INVALID_ARGUMENT);
            }
            let Some(th) = k.thread_signals.get(t) else { return Reply::err(KERN_TERMINATED) };
            let handle = th.tsd();
            let qaddr = if handle == 0 { 0 } else { handle.wrapping_add(k.dtask.pthread.dispatch_queue_offset) };
            let mut w = vec![0u32; count as usize];
            for (i, v) in [th.darwin_id(), handle, qaddr].into_iter().enumerate() {
                w[2 * i] = v as u32;
                w[2 * i + 1] = (v >> 32) as u32;
            }
            Reply::ok(super::mig::words(&w))
        }
        flavor::EXTENDED_INFO => {
            if count < count::EXTENDED_INFO {
                return Reply::err(KERN_INVALID_ARGUMENT);
            }
            loud("thread_info THREAD_EXTENDED_INFO's pth_curpri (sched_pri: the clutch scheduler's timeshare decay and the kernel's promotions are not kept here)".into())
        }
        // DEVELOPMENT || DEBUG only.
        flavor::DEBUG_INFO_INTERNAL => Reply::err(KERN_NOT_SUPPORTED),
        flavor::SCHED_TIMESHARE_INFO => {
            if count < count::TIMESHARE_INFO {
                return Reply::err(KERN_INVALID_ARGUMENT);
            }
            match mode(k, t) {
                Mode::Timeshare => loud("thread_info THREAD_SCHED_TIMESHARE_INFO's cur_priority (sched_pri: the clutch scheduler's timeshare decay and the kernel's promotions are not kept here)".into()),
                Mode::FixedOrRealtime => loud(unmetered("THREAD_SCHED_TIMESHARE_INFO")),
            }
        }
        flavor::SCHED_RR_INFO => {
            if count < count::RR_INFO {
                return Reply::err(KERN_INVALID_ARGUMENT);
            }
            match mode(k, t) {
                Mode::Timeshare => Reply::err(KERN_INVALID_POLICY),
                Mode::FixedOrRealtime => loud(unmetered("THREAD_SCHED_RR_INFO")),
            }
        }
        flavor::SCHED_FIFO_INFO => {
            if count < count::FIFO_INFO {
                return Reply::err(KERN_INVALID_ARGUMENT);
            }
            Reply::err(KERN_INVALID_POLICY)
        }
        _ => Reply::err(KERN_INVALID_ARGUMENT),
    }
}

/// What is not kept here, reported, with KERN_NOT_SUPPORTED.
fn loud(why: String) -> Reply {
    let mut r = Reply::err(KERN_NOT_SUPPORTED);
    r.unimplemented = Some(why);
    r
}

fn unmetered(what: &str) -> String {
    format!("thread_info {what} of a fixed-priority or realtime thread (whether the failsafe has demoted it to timesharing: its computation between blocks is not metered here)")
}

impl Kernel {
    /// `thread_quantum_init`'s quantum for thread `t`, in Mach time units:
    /// a realtime thread's computation, else its clutch bucket's
    /// (`sched_clutch_thread_quantum_us`, an embedded kernel's: 10 ms for
    /// fixed priority and foreground, 8 ms user-initiated, 6 ms default,
    /// 4 ms utility, 2 ms background), the bucket from its base priority
    /// (`sched_clutch_update_thread_bucket`; a kernel promotion, which
    /// would use `sched_pri`, is not kept here).
    pub(crate) fn darwin_thread_quantum(&self, t: i32) -> u64 {
        use super::taskpolicy::pri::MAXPRI_THROTTLE;
        let m = mode(self, t);
        if m == Mode::FixedOrRealtime {
            if let Some(rt) = self.dtask.threads.map.get(&t).and_then(|th| th.realtime) {
                return u64::from(rt.computation);
            }
        }
        let p = i32::from(self.darwin_thread_base_pri(t));
        let us = if m == Mode::FixedOrRealtime && p >= 47 {
            10_000
        } else if p > 37 {
            10_000
        } else if p > 31 {
            8_000
        } else if p > 20 {
            6_000
        } else if p > MAXPRI_THROTTLE {
            4_000
        } else {
            2_000
        };
        super::mach::ns_to_abs(us * 1_000)
    }
}

/// Thread `t`'s `sched_mode`: a workqueue thread's from the policy
/// `thread_set_workq_pri` gave it (`convert_policy_to_sched_mode`; none
/// yet is the template's timesharing), a realtime thread's, a fixed one's
/// from THREAD_EXTENDED_POLICY, else timesharing; a fixed or realtime
/// thread whose maximum priority is at most MAXPRI_THROTTLE is demoted to
/// timesharing (`thread_task_priority`, `thread_create_internal`).
fn mode(k: &Kernel, t: i32) -> Mode {
    use super::taskpolicy::pri::MAXPRI_THROTTLE;
    let Some(th) = k.dtask.threads.map.get(&t) else { return Mode::Timeshare };
    let fixed = match &th.wq {
        Some(w) => !matches!(w.sched_policy, 0 | 1),
        None => th.realtime.is_some() || th.policy.timeshare == Some(false),
    };
    if !fixed || k.darwin_policy().max_priority <= MAXPRI_THROTTLE {
        Mode::Timeshare
    } else {
        Mode::FixedOrRealtime
    }
}

/// `retrieve_thread_basic_info`: `struct thread_basic_info`'s words.
fn basic_info(k: &Kernel, t: i32) -> Result<[u32; 10], String> {
    use super::sched::RunState;
    let Some((user, sys)) = k.thread_signals.get(t).and_then(|s| s.cpu.times()) else {
        return Err("thread_info THREAD_BASIC_INFO's times on a host without per-thread clocks".into());
    };
    let total = user + sys;
    let (secs, usecs) = crate::cpu::microtime(total);
    let cpu_usage = match k.procs.sched.cpu_usage(t, super::mach::ns_to_abs(total)) {
        Ok(Some(u)) => u,
        Ok(None) => return Err(format!("thread_info THREAD_BASIC_INFO of thread {t}, which the scheduler has no record of")),
        Err(why) => return Err(format!("thread_info THREAD_BASIC_INFO's cpu_usage: {why}")),
    };
    let policy = match mode(k, t) {
        Mode::Timeshare => POLICY_TIMESHARE,
        Mode::FixedOrRealtime => return Err(unmetered("THREAD_BASIC_INFO")),
    };
    let Some(state) = k.procs.sched.state(t) else {
        return Err(format!("thread_info THREAD_BASIC_INFO of thread {t}, which the scheduler has no record of"));
    };
    let th = k.dtask.threads.map.get(&t);
    let stopping = th.is_some_and(|d| d.stop_holds > 0);
    // TH_TERMINATE is not reached by a thread still active; then TH_RUN,
    // TH_UNINT, TH_SUSP (thread_stop's) and TH_WAIT, in that order.
    let run_state = match state {
        RunState::Run => th_state::RUNNING,
        RunState::Unint => th_state::UNINTERRUPTIBLE,
        RunState::Wait if stopping => th_state::STOPPED,
        RunState::Wait => th_state::WAITING,
    };
    // A thread on its CPU has its kernel stack; one made and never run has
    // none yet; a waiting one as its wait left it.
    let flags = if state == RunState::Run {
        0
    } else if th.is_some_and(|d| d.unstarted.is_some()) {
        TH_FLAGS_SWAPPED
    } else {
        match th.map_or(KStack::Kept, |d| d.kstack) {
            KStack::Kept => 0,
            KStack::Discarded => TH_FLAGS_SWAPPED,
            KStack::Unknown(what) => return Err(format!("thread_info THREAD_BASIC_INFO's TH_FLAGS_SWAPPED of a thread waiting in {what}")),
        }
    };
    let suspend_count = th.map_or(0, |d| d.suspend);
    Ok([secs as u32, usecs, 0, 0, cpu_usage as u32, policy, run_state, flags, suspend_count, 0])
}

impl Kernel {
    /// The calling thread blocks in `op`: whether XNU's wait for the call
    /// blocks at a continuation, which discards the thread's kernel stack
    /// (`thread_dispatch`), kept for `thread_info`'s TH_FLAGS_SWAPPED.
    pub(crate) fn darwin_note_wait(&mut self, op: &BlockOp) {
        let k = self.darwin_wait_kstack(op);
        self.darwin_me().kstack = k;
        if self.darwin_wait_sleeps(op) {
            self.dtask.rusage.ru.count(super::ru::l::NVCSW);
        }
    }

    /// Whether XNU's wait for what `op` waits for is an `_sleep` (`msleep`,
    /// `msleep0`, `msleep1`, `tsleep0`, `tsleep1`), whose entry counts a
    /// voluntary switch in `p_stats->p_ru.ru_nvcsw` (`kern_synch.c`): the
    /// BSD waits, not the Mach ones (a thread_block on a waitq: psynch,
    /// ulock, mach_msg, semaphores, kevent's scan, workq parks).
    fn darwin_wait_sleeps(&mut self, op: &BlockOp) -> bool {
        use super::sysno as sys;
        if let (BlockOp::FutexWait { .. }, Some(w)) = (op, &self.darwin_finish) {
            return match w.cont {
                // kern_lockf.c's msleep, kern_aio.c's aio_suspend msleep1,
                // kern_sig.c's __sigwait msleep, tty.c's ttysleep msleep0.
                Finish::Lockf(_) | Finish::AioSuspend(_) | Finish::Sigwait { .. } | Finish::Tty => true,
                // select's tsleep1 (sys_generic.c); poll's scan blocks on
                // the kqueue's waitq.
                Finish::Kevent(super::kevent::Cont::Poll { .. }) => matches!(self.darwin_uu_syscall_code(), sys::SELECT | sys::SELECT_NOCANCEL | sys::PSELECT | sys::PSELECT_NOCANCEL),
                _ => false,
            };
        }
        match op {
            // sys_pipe.c's piperd and pipewr msleep, uipc_socket2.c's
            // sbwait, accept's and connect's msleep (uipc_syscalls.c).
            BlockOp::ReadStream { .. } | BlockOp::WriteStream { .. } | BlockOp::WriteWait { .. } | BlockOp::AcceptWait { .. } | BlockOp::Connect { .. } => true,
            // lf_advlock's msleep.
            BlockOp::FileLock { .. } => true,
            // wait4's and waitid's msleep0, reached when no child it asks
            // for has anything to report (never under WNOHANG).
            BlockOp::WaitChild { nohang: false, .. } => super::exit::wait_would_sleep(op),
            // sigsuspend's tsleep0, entered whatever is pending.
            BlockOp::SigSuspend { .. } => true,
            _ => false,
        }
    }

    fn darwin_wait_kstack(&mut self, op: &BlockOp) -> KStack {
        use super::sysno as sys;
        use KStack::{Discarded, Kept, Unknown};
        let code = self.darwin_uu_syscall_code();
        if let (BlockOp::FutexWait { .. }, Some(w)) = (op, &self.darwin_finish) {
            return match w.cont {
                // sys_ulock.c: thread_block_parameter(ulock_wait_continue).
                Finish::Ulock { .. } => Discarded,
                Finish::Psynch(_) => Unknown("a psynch wait (ksyn_wait, of the pthread kext)"),
                // ipc_mqueue.c: a send waiting for room blocks with no
                // continuation; mach_msg's receive at
                // ipc_mqueue_receive_continue.
                Finish::MachMsg(super::mach_msg::Cont::Send { .. }) => Kept,
                Finish::MachMsg(super::mach_msg::Cont::Receive { .. }) => Discarded,
                // The semaphore traps pass thread_syscall_return, waited
                // for at semaphore_wait_continue (sync_sema.c).
                Finish::Sema(_) => Discarded,
                // clock.c: mach_wait_until_continue; syscall_subr.c:
                // thread_switch's thread_yield_with_continuation.
                Finish::Sleep(_) => Discarded,
                // pthread_workqueue.c: workq_unpark_continue.
                Finish::WorkqPark => Discarded,
                // kern_event.c: kqueue_scan_continue; a workloop's
                // waiter's filt_wlwait_continue (thread_handoff_parameter).
                // poll's scan (KEVENT_FLAG_POLL) blocks with none, select's
                // tsleep1 at selcontinue (sys_generic.c).
                Finish::Kevent(super::kevent::Cont::Scan { .. } | super::kevent::Cont::WlWait { .. }) => Discarded,
                Finish::Kevent(super::kevent::Cont::Poll { .. }) => match code {
                    sys::SELECT | sys::SELECT_NOCANCEL | sys::PSELECT | sys::PSELECT_NOCANCEL => Discarded,
                    sys::POLL | sys::POLL_NOCANCEL => Kept,
                    _ => Unknown("a kqueue scan of a call other than poll or select"),
                },
                // kern_lockf.c, kern_aio.c, kern_sig.c's __sigwait and
                // tty.c's ttysleep: msleep with no continuation; sem_wait's
                // semaphore_wait (posix_sem.c) and the eventlink's
                // thread_handoff_deallocate (ipc_eventlink.c) have none;
                // an exception's reply is received by
                // mach_msg_rpc_from_kernel with none (ipc_mig.c).
                Finish::Lockf(_) | Finish::AioSuspend(_) | Finish::Sigwait { .. } | Finish::Tty | Finish::Psem(_) | Finish::Eventlink(_) | Finish::Exception(_) => Kept,
                // task_generate_corpse_internal runs on the calling
                // thread's own stack, in its call.
                Finish::CorpseFork => Kept,
            };
        }
        match op {
            // sys_pipe.c's and uipc_socket2.c's sbwait msleep, accept's
            // and connect's (uipc_syscalls.c): no continuation.
            BlockOp::ReadStream { .. } | BlockOp::WriteStream { .. } | BlockOp::WriteWait { .. } | BlockOp::AcceptWait { .. } | BlockOp::Connect { .. } => Kept,
            // flock's lf_advlock: msleep.
            BlockOp::FileLock { .. } => Kept,
            // kern_exit.c: wait4's msleep0 at wait1continue, waitid's at
            // waitidcontinue; kern_sig.c: sigsuspend's tsleep0 at
            // sigcontinue.
            BlockOp::WaitChild { .. } => Discarded,
            BlockOp::SigSuspend { .. } => Discarded,
            // posix_spawn's own call, which XNU's activates the child's image
            // in (exec_activate_image): no sleep, the call's stack.
            BlockOp::SpawnStart { .. } => Kept,
            _ => Unknown("a wait of the host's whose call has not been matched to XNU's"),
        }
    }
}
