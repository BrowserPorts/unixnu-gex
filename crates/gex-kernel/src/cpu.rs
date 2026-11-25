//! Processor time: what each Darwin thread has used, read from the host
//! thread that runs it (recount's). Its time in the kernel (a call or a
//! trap, from its entry to its return) and the rest are kept apart; the
//! host's wait in a blocked call is neither, as a blocked thread runs on no
//! processor. The release kernel is built without
//! `PRECISE_USER_KERNEL_TIME` (`config_skip_precise_user_kernel_time` in
//! `MASTER.arm64`'s `MACH_RELEASE`), so recount charges a thread's time in
//! the kernel to its user time, and every time it reports has a system time
//! of 0 (as 21H461's `retrieve_thread_basic_info` stores it).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

/// Guest thread `tid`'s host thread's processor time in nanoseconds, by the
/// host's per-thread clocks (`darwin::workq::set_thread_time`); none
/// without them, or once that thread has gone.
fn host_time(tid: i32) -> Option<u64> {
    crate::darwin::workq::host_thread_ns(tid)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    /// Not yet run on its host thread.
    #[default]
    Unstarted,
    User,
    Kernel,
    /// In a call that blocked: the host's wait is not the thread's time.
    Blocked,
    /// The host translating the thread's code: the runtime's work, which
    /// the device has no counterpart of.
    Host,
    Ended,
}

#[derive(Debug, Default)]
struct Inner {
    user: u64,
    sys: u64,
    /// The host thread's time when the state last changed.
    last: u64,
    state: State,
    tid: i32,
    /// How deep the host's work on the thread is ([`ThreadCpu::pause`]),
    /// and the state it interrupted.
    paused: u32,
    resumes: State,
    /// Its `runnable_timer` (Mach time units): `all_bits`, what
    /// `timer_grab` reads, and `tstamp`, where the timer last started or
    /// was updated. The timer starts at a wakeup (`thread_unblock`), is
    /// updated as the thread is dispatched (`thread_invoke`) and at each
    /// quantum's end (`thread_quantum_expire`), and stops as it blocks
    /// (`thread_dispatch`): what it holds never includes the stretch since
    /// the last of those.
    runnable: u64,
    tstamp: u64,
    /// When its current quantum began (its dispatch, or the last quantum's
    /// end), and the quantum (`thread_quantum_init`'s, Mach time units),
    /// 0 until the kernel sets one ([`ThreadCpu::set_quantum`]).
    quantum_start: u64,
    quantum: u64,
    /// When the host's own work on it began ([`ThreadCpu::pause`]): no
    /// time of the device's, so its timer and quantum skip it.
    host_since: u64,
}

impl Inner {
    /// The quantum ends that have passed by `now` while it ran
    /// (`thread_quantum_expire`: `timer_update` of the runnable timer at
    /// each, and a new quantum from there). The device runs nothing else
    /// on its processor meanwhile in this model, so each quantum runs out.
    fn expire(&mut self, now: u64) {
        if self.quantum == 0 || !matches!(self.state, State::User | State::Kernel) {
            return;
        }
        let n = now.saturating_sub(self.quantum_start) / self.quantum;
        if n > 0 {
            let end = self.quantum_start + n * self.quantum;
            self.runnable += end.saturating_sub(self.tstamp);
            self.tstamp = end;
            self.quantum_start = end;
        }
    }
}

/// One guest thread's processor time.
#[derive(Debug, Default)]
pub struct ThreadCpu(Arc<Mutex<Inner>>);

/// The threads running on host threads, by tid: what a host thread that
/// ends takes its last sample of ([`host_thread_ending`]).
fn running() -> std::sync::MutexGuard<'static, HashMap<i32, Weak<Mutex<Inner>>>> {
    static R: std::sync::OnceLock<Mutex<HashMap<i32, Weak<Mutex<Inner>>>>> = std::sync::OnceLock::new();
    R.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

/// Guest thread `tid`'s host thread is ending, however its thread ended (a
/// process killed has no exit call of each thread's): its last stretch,
/// read while the host's clock still knows it.
pub fn host_thread_ending(tid: i32) {
    let Some(inner) = running().remove(&tid).and_then(|w| w.upgrade()) else { return };
    ThreadCpu(inner).end();
}

/// Guest thread `tid`'s processor time so far, its user and system time
/// together, in nanoseconds: none unless it runs on a host thread here and
/// the host's per-thread clocks are kept.
pub fn thread_time_ns(tid: i32) -> Option<u64> {
    let inner = running().get(&tid).and_then(Weak::upgrade)?;
    let (user, sys) = ThreadCpu(inner).times()?;
    Some(user + sys)
}

impl ThreadCpu {
    /// The time since the last change charged to the state it was in, then
    /// the next state. Called on the thread's own host thread.
    fn sample(&self, next: State) {
        let mut i = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let Some(now) = host_time(i.tid) else { return };
        let abs = crate::darwin::mach::absolute_time();
        match i.state {
            State::Unstarted => {}
            State::User => i.user += now.saturating_sub(i.last),
            State::Kernel => i.sys += now.saturating_sub(i.last),
            State::Blocked | State::Host | State::Ended => {}
        }
        let running = |s: State| matches!(s, State::User | State::Kernel);
        i.expire(abs);
        match (i.state, next) {
            // A wakeup (or the first run) and its dispatch: the timer
            // starts, a quantum begins.
            (State::Unstarted | State::Blocked, n) if running(n) => {
                i.tstamp = abs;
                i.quantum_start = abs;
            }
            // A block, or its end: the timer stops at its dispatch off.
            (s, State::Blocked | State::Ended) if running(s) => {
                i.runnable += abs.saturating_sub(i.tstamp);
            }
            // The host's work begins: its time is skipped.
            (s, State::Host) if running(s) => i.host_since = abs,
            (State::Host, n) if running(n) => {
                let d = abs.saturating_sub(i.host_since);
                i.tstamp += d;
                i.quantum_start += d;
            }
            _ => {}
        }
        if i.state != State::Ended {
            i.last = now;
            i.state = next;
        }
    }

    /// Thread `tid` begins to run its program on this host thread.
    pub fn start(&self, tid: i32) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).tid = tid;
        running().insert(tid, Arc::downgrade(&self.0));
        self.sample(State::User);
    }

    /// A call or a trap begins.
    pub fn enter(&self) {
        self.sample(State::Kernel);
    }

    /// The call returns to the program, or it blocked.
    pub fn leave(&self, blocked: bool) {
        self.sample(if blocked { State::Blocked } else { State::User });
    }

    /// Another handle on the same thread's time (the host's, for
    /// [`Self::pause`]).
    pub fn handle(&self) -> ThreadCpu {
        ThreadCpu(Arc::clone(&self.0))
    }

    /// The host begins work of its own on the thread (translating its
    /// code): not the thread's time, until [`Self::resume`]. Nests.
    pub fn pause(&self) {
        let state = {
            let mut i = self.0.lock().unwrap_or_else(|e| e.into_inner());
            i.paused += 1;
            if i.paused > 1 {
                return;
            }
            i.state
        };
        if matches!(state, State::User | State::Kernel) {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).resumes = state;
            self.sample(State::Host);
        } else {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).resumes = state;
        }
    }

    /// The host's work on the thread is done: its time counts again, in
    /// the state it was in.
    pub fn resume(&self) {
        let back = {
            let mut i = self.0.lock().unwrap_or_else(|e| e.into_inner());
            if i.paused == 0 {
                return;
            }
            i.paused -= 1;
            if i.paused > 0 || i.state != State::Host {
                return;
            }
            i.resumes
        };
        self.sample(back);
    }

    /// The thread ends; its times are final.
    pub fn end(&self) {
        self.sample(State::Ended);
    }

    /// Its user and system time so far, in nanoseconds, as recount reports
    /// them: all of it user time, its time in the kernel too, and a system
    /// time of 0. None without the host's clocks.
    pub fn times(&self) -> Option<(u64, u64)> {
        let (user, kernel) = self.split()?;
        Some((user + kernel, 0))
    }

    /// Its runnable time so far (`timer_grab(&thread->runnable_timer)`),
    /// in Mach time units: what the timer holds, the quantum ends passed
    /// by now with it, never the stretch since the last of its updates.
    /// The host translating its code is no time of the device's, and its
    /// wait in a blocked call is not runnable time. None without the
    /// host's clocks.
    pub fn runnable(&self) -> Option<u64> {
        crate::darwin::workq::host_clocks()?;
        let mut i = self.0.lock().unwrap_or_else(|e| e.into_inner());
        i.expire(crate::darwin::mach::absolute_time());
        Some(i.runnable)
    }

    /// The quantum its next quantum end comes after (`thread_quantum_init`,
    /// Mach time units), the quantum ends so far taken at the old one.
    pub fn set_quantum(&self, q: u64) {
        let mut i = self.0.lock().unwrap_or_else(|e| e.into_inner());
        i.expire(crate::darwin::mach::absolute_time());
        i.quantum = q;
    }

    /// Its time out of the kernel and in it so far, in nanoseconds: a
    /// running thread's current stretch read from its host thread. None
    /// without the host's clocks.
    fn split(&self) -> Option<(u64, u64)> {
        crate::darwin::workq::host_clocks()?;
        let i = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let (mut user, mut sys) = (i.user, i.sys);
        if matches!(i.state, State::User | State::Kernel) {
            if let Some(now) = host_time(i.tid) {
                let d = now.saturating_sub(i.last);
                if i.state == State::User {
                    user += d;
                } else {
                    sys += d;
                }
            }
        }
        Some((user, sys))
    }
}

/// `absolutetime_to_microtime` of a time kept in nanoseconds: its Mach
/// time's whole seconds (`rtclock_sec_divisor`) and the microseconds past
/// them (`rtclock_usec_divisor`).
pub(crate) fn microtime(ns: u64) -> (u64, u32) {
    let (numer, denom) = crate::darwin::mach::TIMEBASE;
    let abs = (u128::from(ns) * u128::from(denom) / u128::from(numer)) as u64;
    let sec_divisor = 1_000_000_000 * u64::from(denom) / u64::from(numer);
    let secs = abs / sec_divisor;
    (secs, ((abs - secs * sec_divisor) / (sec_divisor / 1_000_000)) as u32)
}

/// `time_value_add` (and `timeradd`): seconds and microseconds, carried.
fn tv_add(a: (u64, u32), b: (u64, u32)) -> (u64, u32) {
    let (mut s, mut us) = (a.0 + b.0, a.1 + b.1);
    if us >= 1_000_000 {
        us -= 1_000_000;
        s += 1;
    }
    (s, us)
}

/// `calcru`: a process's user and system time as `timeval`s, from its
/// ended threads' times (`MACH_TASK_BASIC_INFO`'s, converted once) and each
/// live thread's (`TASK_THREAD_TIMES_INFO`'s, converted thread by thread and
/// added), all in nanoseconds.
pub(crate) fn calcru(dead: (u64, u64), live: &[(u64, u64)]) -> [(u64, u32); 2] {
    let (mut user, mut sys) = ((0, 0), (0, 0));
    for &(u, s) in live {
        user = tv_add(user, microtime(u));
        sys = tv_add(sys, microtime(s));
    }
    [tv_add(microtime(dead.0), user), tv_add(microtime(dead.1), sys)]
}

/// The runnable time of every thread of `threads` so far, in Mach time
/// units, summed; None without the host's clocks.
pub(crate) fn live_runnable(threads: &crate::signal::ThreadSigs) -> Option<u64> {
    let mut sum = 0;
    for tid in threads.tids() {
        if let Some(t) = threads.get(tid) {
            sum += t.cpu.runnable()?;
        }
    }
    Some(sum)
}

/// Every thread's of `threads` user and system time so far, in
/// nanoseconds; None without the host's clocks.
pub(crate) fn live_times(threads: &crate::signal::ThreadSigs) -> Option<Vec<(u64, u64)>> {
    let mut v = Vec::new();
    for tid in threads.tids() {
        if let Some(t) = threads.get(tid) {
            v.push(t.cpu.times()?);
        }
    }
    Some(v)
}

impl crate::syscalls::Kernel {
    /// This task's user and system time (`calcru`): its threads that have
    /// ended, and each of the others so far. None without the host's
    /// clocks.
    pub(crate) fn task_times(&self) -> Option<(u64, u64)> {
        let (mut user, mut sys) = self.procs.dead_cpu(self.pid);
        for tid in self.thread_signals.tids() {
            if let Some(t) = self.thread_signals.get(tid) {
                let (u, s) = t.cpu.times()?;
                user += u;
                sys += s;
            }
        }
        Some((user, sys))
    }

    /// `getrusage(who, rusage)`: this process's `p_ru` as `calcru` makes
    /// it (RUSAGE_SELF), or its reaped children's `p_cru`
    /// (RUSAGE_CHILDREN); EINVAL for anything else. The figures that
    /// stand in for what gex cannot see are said.
    pub(crate) fn darwin_getrusage(&mut self, m: &mut crate::GuestMem<'_>, who: i32, at: u64) -> Result<u64, crate::Errno> {
        const RUSAGE_SELF: i32 = 0;
        const RUSAGE_CHILDREN: i32 = -1;
        let r = match who {
            RUSAGE_SELF => {
                let r = self.darwin_calcru(m);
                if r.times_unknown {
                    self.darwin_unimplemented("getrusage's times on a host without per-thread clocks".into());
                    return Err(crate::Errno::ENOSYS);
                }
                r
            }
            RUSAGE_CHILDREN => {
                let r = self.dtask.rusage.ru.cru();
                if r.times_unknown {
                    self.darwin_unimplemented("getrusage(RUSAGE_CHILDREN)'s times on a host without per-thread clocks".into());
                    return Err(crate::Errno::ENOSYS);
                }
                r
            }
            _ => return Err(crate::Errno::EINVAL),
        };
        for t in r.stand_in_texts() {
            self.darwin_stand_in(t);
        }
        m.write(at, &r.bytes())?;
        Ok(0)
    }

    /// `calcru` of this process: its times (none without the host's
    /// clocks), its task's faults and page-ins, and its resident peak from
    /// a look at its pages now, where the host gives one.
    pub(crate) fn darwin_calcru(&mut self, m: &mut crate::GuestMem<'_>) -> crate::darwin::ru::Ru {
        let times = live_times(&self.thread_signals).map(|live| calcru(self.procs.dead_cpu(self.pid), &live));
        let rusage = std::sync::Arc::clone(&self.dtask.rusage);
        let maxrss = {
            let mut pm = rusage.meter.lock();
            rusage.meter.measure(&mut pm, &self.mem, m).map(|_| pm.peaks.resident * (crate::darwin::mach::PAGE_MASK + 1))
        };
        rusage.ru.calcru(times, rusage.pageins.load(std::sync::atomic::Ordering::Acquire), maxrss)
    }

    /// `thread_selfusage()`: the calling thread's user and system time, in
    /// Mach time units (`thread_get_runtime_self`).
    pub(crate) fn darwin_thread_selfusage(&mut self) -> Result<u64, crate::Errno> {
        let Some((u, s)) = self.signals.thread().cpu.times() else {
            self.darwin_unimplemented("thread_selfusage on a host without per-thread clocks".into());
            return Err(crate::Errno::ENOSYS);
        };
        let (numer, denom) = crate::darwin::mach::TIMEBASE;
        Ok((u128::from(u + s) * u128::from(denom) / u128::from(numer)) as u64)
    }
}
