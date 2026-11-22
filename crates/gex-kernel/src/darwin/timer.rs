//! The kernel's thread calls (`osfmk/kern/thread_call.c`): work the kernel
//! itself does at a deadline (a Mach timer's expiry message, a kevent
//! timer firing), not on behalf of any thread's call.
//!
//! The host runs a thread for the process that sleeps until the earliest
//! deadline, or until one earlier is armed ([`Bell`]), and then fires what
//! is due with the kernel locked ([`Kernel::darwin_thread_calls`]).

use crate::syscalls::Kernel;
use crate::GuestMem;
use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};
use crate::darwin::time::Instant;

/// What a thread call does when it fires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// `mk_timer_expire` for the timer whose port this is.
    MkTimer(super::ipc::ObjId),
    /// One of the workqueue's thread calls.
    Workq(super::workq::Call),
    /// An `EVFILT_TIMER` knote's thread call (`filt_timerexpire`), armed
    /// in the timer state given.
    Knote(super::kevent::KnId, u32),
    /// The real interval timer's (`realitexpire`).
    RealTimer,
    /// The framebuffer's vertical blank ([`super::iomfb::swap`]).
    Iomfb,
}

/// How the thread-call thread learns that an earlier deadline was armed, or
/// that the process is gone.
#[derive(Debug, Default)]
pub struct Bell {
    state: Mutex<(u64, bool)>,
    cv: Condvar,
}

impl Bell {
    /// The count of rings so far.
    pub fn generation(&self) -> u64 {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).0
    }

    pub fn ring(&self) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).0 += 1;
        self.cv.notify_all();
        rung();
    }

    fn close(&self) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).1 = true;
        self.cv.notify_all();
        rung();
    }

    /// Whether the process is gone (the bell closed).
    pub fn closed(&self) -> bool {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).1
    }

    /// Sleep until `until`, or until a ring after `seen`; false once the
    /// process is gone.
    pub fn wait(&self, seen: u64, until: Option<Instant>) -> bool {
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if g.1 {
                return false;
            }
            if g.0 != seen {
                return true;
            }
            match until {
                None => g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner()),
                Some(t) => {
                    let now = Instant::now();
                    if now >= t {
                        return true;
                    }
                    g = self.cv.wait_timeout(g, t - now).unwrap_or_else(|e| e.into_inner()).0;
                }
            }
        }
    }
}

/// How a host whose thread-call runner sleeps on something other than the
/// bell's condition variable is told of a ring ([`set_ring_hook`]).
static RING_HOOK: std::sync::OnceLock<fn()> = std::sync::OnceLock::new();

/// Call `hook` after every ring of a bell, and its close: for a runner
/// that sleeps on a wait of the host's own (the page's Worker parks on its
/// wait slot) and must wake as [`Bell::wait`] would.
pub fn set_ring_hook(hook: fn()) {
    let _ = RING_HOOK.set(hook);
}

fn rung() {
    if let Some(hook) = RING_HOOK.get() {
        hook();
    }
}

/// The armed thread calls, by deadline (and a sequence number, so two at
/// the same instant both stay).
#[derive(Debug, Default)]
pub struct Timers {
    armed: BTreeMap<(Instant, u64), Action>,
    next: u64,
    bell: Arc<Bell>,
    /// A call armed while the host runs none ([`set_host_runs_thread_calls`]),
    /// to be reported ([`Kernel::darwin_thread_calls_unrun`]).
    unrun: Option<Action>,
}

/// Whether the host runs every Darwin process's thread calls: a thread (or
/// Worker) that fires them at their deadlines and looks at the pipes with
/// knotes on them ([`Kernel::darwin_thread_calls`]).
static HOST_RUNS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The host runs the thread calls: without it, a call armed would never
/// fire, and is reported instead.
pub fn set_host_runs_thread_calls() {
    HOST_RUNS.store(true, std::sync::atomic::Ordering::Release);
}

fn host_runs() -> bool {
    HOST_RUNS.load(std::sync::atomic::Ordering::Acquire)
}

impl Drop for Timers {
    fn drop(&mut self) {
        self.bell.close();
    }
}

impl Timers {
    /// Arm `action` for `at`; the key it can be cancelled by.
    pub fn arm(&mut self, at: Instant, action: Action) -> (Instant, u64) {
        self.next += 1;
        let key = (at, self.next);
        self.armed.insert(key, action);
        if !host_runs() && self.unrun.is_none() {
            self.unrun = Some(action);
        }
        if self.armed.keys().next() == Some(&key) {
            self.bell.ring();
        }
        key
    }

    /// Cancel the call armed as `key`; whether it was still armed
    /// (`thread_call_cancel`).
    pub fn cancel(&mut self, key: (Instant, u64)) -> bool {
        self.armed.remove(&key).is_some()
    }

    pub fn bell(&self) -> Arc<Bell> {
        Arc::clone(&self.bell)
    }
}

impl Kernel {
    /// What the host does not run of the thread calls, reported: a call
    /// armed, which would never fire, and knotes on pipes or sockets another
    /// process changes, which would never be looked at again.
    pub(crate) fn darwin_thread_calls_unrun(&mut self) {
        if host_runs() {
            return;
        }
        if let Some(a) = self.dtask.timers.unrun.take() {
            self.darwin_unimplemented(format!("a thread call armed ({a:?}): this host runs no thread calls for the process, so it never fires"));
        }
        if self.darwin_pipe_watch().load(std::sync::atomic::Ordering::Acquire) != 0 {
            self.darwin_unimplemented("a knote on a pipe or socket another process changes: this host runs no thread calls for the process, so it is not looked at again".into());
        }
    }

    /// The thread calls that are due, run; when the next one is.
    pub fn darwin_thread_calls(&mut self, m: &mut GuestMem<'_>) -> Option<Instant> {
        // The thread-call thread is runnable while it runs them.
        self.procs.sched.callout(true);
        let out = self.darwin_thread_calls_body(m);
        self.procs.sched.callout(false);
        self.darwin_ipc_leave();
        // What they mapped (a workqueue thread's stack) is in force for
        // every thread now.
        self.darwin_flush_perms(m);
        out
    }

    /// Fire every thread call that is due; the next deadline.
    fn darwin_thread_calls_body(&mut self, m: &mut GuestMem<'_>) -> Option<Instant> {
        // A corpse whose process has ended has only other tasks' requests
        // and its notification to see to.
        if self.darwin_corpse_thread_calls(m) {
            return None;
        }
        // The kernel's backtrace daemon: replies to its requests, and the
        // lightweight corpses' deliveries.
        if self.dtask.bt_daemon {
            self.darwin_ipc_remote(m);
            self.darwin_bt_deliveries(m);
            return None;
        }
        // Other tasks' IPC with this one's threads and ports.
        self.darwin_ipc_remote(m);
        // The TCP timers of the process's sockets, ahead of the look at
        // their knotes.
        let tcp = self.darwin_tcp_timers();
        // Signals posted, and pipes changed, from outside a call: their
        // knotes are told.
        if self.darwin_signal_knotes() | self.darwin_pipe_knotes() | self.darwin_vnode_knotes() | self.darwin_proc_knotes() {
            self.darwin_kevent_settle(m);
        }
        self.darwin_lock_wakes(m);
        // memorystatus' idle demotion call, which every task's thread calls
        // wake for.
        let jetsam = if self.darwin { self.darwin_jetsam_tick() } else { None };
        let footprint = if self.darwin { self.darwin_footprint_tick(m) } else { None };
        let jetsam = match (jetsam, footprint) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let own = loop {
            let now = Instant::now();
            let Some((&key, _)) = self.dtask.timers.armed.first_key_value() else { break None };
            if key.0 > now {
                break Some(key.0);
            }
            // A delayed thread call: the timer interrupt woke a thread of
            // its group (thread_call_wake), so what that thread wakes is an
            // interrupt wakeup. The framebuffer's vertical blank is an
            // interrupt event source's work-loop thread's, not a callout's.
            let action = self.dtask.timers.armed.remove(&key).expect("first key");
            self.dtask.in_callout = action != Action::Iomfb;
            // ml_get_power_state at that interrupt: whether every processor
            // was idle (cpu_idle_count == real_ncpus), this call's thread
            // not yet running.
            self.dtask.callout_pidle = self.dtask.in_callout && self.procs.sched.processors_idle(None, 1);
            self.darwin_pidle_elsewhere();
            self.darwin_ipc_callout(true);
            match action {
                Action::MkTimer(port) => self.mk_timer_expire(m, port, key),
                Action::Workq(c) => self.darwin_workq_call(m, c),
                Action::RealTimer => {
                    // psignal's wakeup of a thread, if any, is not followed.
                    self.dtask.rusage.wkups_unkept.store(true, std::sync::atomic::Ordering::Release);
                    self.darwin_realitexpire()
                }
                Action::Iomfb => self.darwin_iomfb_blank(m),
                Action::Knote(n, state) => {
                    self.filt_timerexpire(n, state);
                    self.darwin_kevent_settle(m);
                }
            }
            self.darwin_ipc_callout(false);
            self.dtask.in_callout = false;
            self.dtask.callout_pidle = false;
        };
        [own, jetsam, tcp].into_iter().flatten().min()
    }

    /// Whether every processor was idle, as this process's scheduler state
    /// says it: in the page, where another Darwin process runs threads this
    /// one's state does not have, the platform-idle wakeups are not kept
    /// (reported when read, as `proc_pid_rusage`'s unkept ledgers are).
    pub(crate) fn darwin_pidle_elsewhere(&mut self) {
        if self.procs.is_shared() && super::held::any_elsewhere(super::held::Kind::Process, self.pid).is_some() {
            self.dtask.rusage.wkups_unkept.store(true, std::sync::atomic::Ordering::Release);
        }
    }

    /// A thread call begins (`true`) or ends: the processes it told of
    /// something in the meantime have their interrupt wakeups marked as
    /// not followed.
    fn darwin_ipc_callout(&mut self, begin: bool) {
        let told = std::mem::replace(&mut *self.ipc().callout_remotes.lock().unwrap_or_else(|e| e.into_inner()), begin.then(Vec::new));
        for pid in told.unwrap_or_default() {
            if let Some((p, _)) = self.darwin_public(pid) {
                p.rusage.wkups_unkept.store(true, std::sync::atomic::Ordering::Release);
            }
        }
    }

    /// The bell the host's thread-call thread sleeps on.
    pub fn darwin_timer_bell(&self) -> Arc<Bell> {
        self.dtask.timers.bell()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static RUNG: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn note_ring() {
        RUNG.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// A ring, and a bell's close when its timers go, reach the host's
    /// hook as they reach a sleeper on the bell.
    #[test]
    fn ring_hook_hears_rings_and_close() {
        set_ring_hook(note_ring);
        let mut timers = Timers::default();
        let bell = timers.bell();
        let before = RUNG.load(std::sync::atomic::Ordering::SeqCst);
        let seen = bell.generation();
        timers.arm(Instant::now() + std::time::Duration::from_secs(60), Action::RealTimer);
        assert_ne!(bell.generation(), seen);
        assert!(RUNG.load(std::sync::atomic::Ordering::SeqCst) > before);
        let before = RUNG.load(std::sync::atomic::Ordering::SeqCst);
        assert!(!bell.closed());
        drop(timers);
        assert!(bell.closed());
        assert!(RUNG.load(std::sync::atomic::Ordering::SeqCst) > before);
        assert!(!bell.wait(bell.generation(), None));
    }
}
