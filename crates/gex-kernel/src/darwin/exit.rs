//! A Darwin parent's view of its children's ends (`bsd/kern/kern_exit.c`):
//! `wait4`'s and `waitid`'s choice of child, by pid or process group, and
//! the status in Darwin's encoding and siginfo.

use crate::errno::Errno;
use crate::syscalls::{BlockOp, Kernel, SyscallOutcome};
use crate::GuestMem;

/// The wait options (`bsd/sys/wait.h`).
const WNOHANG: i32 = 0x1;
const WEXITED: i32 = 0x4;
const WSTOPPED: i32 = 0x8;
const WCONTINUED: i32 = 0x10;
const WNOWAIT: i32 = 0x20;

/// `idtype_t`.
const P_PID: u64 = 1;
const P_PGID: u64 = 2;

/// `sizeof(user64_siginfo_t)`.
const SIGINFO_SIZE: usize = 104;
/// `CLD_EXITED`, `CLD_KILLED`, `CLD_DUMPED`, `CLD_STOPPED`, `CLD_CONTINUED`.
const CLD_EXITED: u32 = 1;
const CLD_KILLED: u32 = 2;
const CLD_DUMPED: u32 = 3;
pub const CLD_STOPPED: u32 = 5;
pub const CLD_CONTINUED: u32 = 6;

/// `wait4` options a Darwin wait reports stops and continues for.
const WUNTRACED: i32 = 0x2;

/// `WAIT_ANY`.
const WAIT_ANY: i32 = -1;

/// A status in the host's (Linux's) encoding as Darwin's: the same layout
/// (`W_EXITCODE`, `W_STOPCODE`, `WCOREFLAG`), with Darwin's signal
/// numbers; a continue is `W_STOPCODE(SIGCONT)`.
pub fn status_from_linux(w: u32) -> u32 {
    let to = |l: u32| super::signal::signal_from_linux(l).unwrap_or(l);
    if w == 0xffff {
        return 0x7f | (super::signal::dsig::SIGCONT << 8);
    }
    match w & 0x7f {
        0 => w & 0xff00,
        0x7f => 0x7f | (to((w >> 8) & 0xff) << 8),
        sig => to(sig) | (w & 0x80),
    }
}

/// `waitid`'s siginfo for child `pid` that ended with `word` (the host's
/// encoding): cleared, then SIGCHLD, the pid, CLD_EXITED and the exit
/// code, or CLD_KILLED (CLD_DUMPED with a core) and the signal. For no
/// child yet (`pid` 0) it is left as it was. The status carries the top
/// byte of the exit value where the child still has it.
pub fn waitid_report(m: &mut GuestMem<'_>, info: u64, pid: i32, word: u32, xhighbits: u8) -> Result<u64, Errno> {
    if pid <= 0 {
        return Ok(0);
    }
    let w = status_from_linux(word);
    let (code, status) = if w & 0x7f == 0 {
        (CLD_EXITED, ((w >> 8) & 0xff) | u32::from(xhighbits) << 24)
    } else if w & 0x80 != 0 {
        (CLD_DUMPED, (w & 0x7f) | u32::from(xhighbits) << 24)
    } else {
        (CLD_KILLED, (w & 0x7f) | u32::from(xhighbits) << 24)
    };
    waitid_job_report(m, info, pid, code, status)
}

/// `waitid`'s siginfo, zeroed but for SIGCHLD, `code`, `pid` and `status`
/// (a stop's or a continue's: the signal number in `p_xstat`).
pub fn waitid_job_report(m: &mut GuestMem<'_>, info: u64, pid: i32, code: u32, status: u32) -> Result<u64, Errno> {
    let mut b = [0u8; SIGINFO_SIZE];
    b[0..4].copy_from_slice(&super::signal::dsig::SIGCHLD.to_le_bytes());
    b[8..12].copy_from_slice(&code.to_le_bytes());
    b[12..16].copy_from_slice(&(pid as u32).to_le_bytes());
    b[20..24].copy_from_slice(&status.to_le_bytes());
    m.write(info, &b)?;
    Ok(0)
}

/// `wait4`'s copy of the child `pid` it collects (`kern_exit.c`): its
/// `p_ru->ru` (`munge_user64_rusage`) to `at`, ENOMEM where it has none
/// (`proc_exit` could not make one), EFAULT where `at` cannot be written.
/// The caller reaps the child only after this succeeds.
pub fn wait4_rusage(m: &mut GuestMem<'_>, at: u64, ru: Option<super::ru::Ru>) -> Result<(), Errno> {
    let r = ru.ok_or(Errno::ENOMEM)?;
    m.write(at, &r.bytes())
}

/// Whether a Darwin wait (`op`, a `WaitChild`) finds nothing to report as
/// it is made, so `wait4` or `waitid` reaches its `msleep0`: no child it
/// asks for has ended (an end it collects), or has a stop or continue it
/// reports. In the page the system's table is asked, taking nothing, and
/// with it the wakeups the waiter's children have given it so far (none
/// natively).
pub fn wait_would_sleep(op: &crate::syscalls::BlockOp) -> (bool, Option<u64>) {
    use std::sync::atomic::Ordering;
    let crate::syscalls::BlockOp::WaitChild { children, procs, ppid, want, group, waitid, jobs: Some(j), .. } = op else { return (false, None) };
    if procs.is_shared() {
        let (step, _, _, wakes) = super::share::dwait(*ppid, (*want, *group), *j, true, waitid.is_some(), true);
        return (matches!(step, crate::proc::WaitStep::Nothing), Some(wakes));
    }
    let sleeps = !children.iter().filter(|c| !c.reaped.load(Ordering::Acquire)).any(|c| {
        let ended = c.status.lock().unwrap_or_else(|e| e.into_inner()).is_some();
        if ended {
            return j.exits;
        }
        let job = c.job.lock().unwrap_or_else(|e| e.into_inner());
        (j.stops && job.stopped && !job.waited) || (j.continues && job.continued)
    });
    (sleeps, None)
}

/// Process `pid`'s `p_ru->ru` in this table's record of it.
pub fn exit_ru(procs: &crate::proc::ProcTable, pid: i32) -> Option<super::ru::Ru> {
    let (r, _) = procs.darwin(pid)?;
    r.downcast::<super::procinfo::Public>().ok()?.rusage.ru.exited()
}

impl Kernel {
    /// `waitid(idtype, id, infop, options)` and `waitid_nocancel`: a child's
    /// end (`WEXITED`), its stop not yet reported (`WSTOPPED`) or its
    /// continue (`WCONTINUED`), each left to be reported again under
    /// `WNOWAIT`.
    pub(crate) fn darwin_waitid(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        let fail = |k: &mut Kernel, m: &mut GuestMem<'_>, e: Errno| {
            let _ = super::set_result(m, k.ctx_addr, e.as_return());
            SyscallOutcome::Continue
        };
        let (idtype, id, info, options) = (a[0] as u32 as u64, a[1] as u32 as i32, a[2], a[3] as i32);
        if options == 0 || options & !(WNOHANG | WNOWAIT | WCONTINUED | WSTOPPED | WEXITED) != 0 {
            return fail(self, m, Errno::EINVAL);
        }
        if (idtype == P_PID || idtype == P_PGID) && id < 0 {
            return fail(self, m, Errno::EINVAL);
        }
        // No child has pid 0 (kern_exit.c compares each child's p_pid).
        if idtype == P_PID && id == 0 {
            return fail(self, m, Errno::ECHILD);
        }
        // In the page the children are the system's table's, which the
        // page's wait asks for one child, any, or a group's (share::dwait):
        // P_PGID's are those whose p_pgrpid is id.
        let want = self.darwin_page_wait_want(match idtype {
            P_PID => (id, false),
            P_PGID => (id, true),
            _ => (WAIT_ANY, false),
        });
        // Any other idtype matches every child, as in kern_exit.c.
        let children: Vec<_> = self
            .procs
            .children(self.pid)
            .into_iter()
            .filter(|c| match idtype {
                P_PID => c.pid == id,
                P_PGID => self.procs.pgid(self.pid, c.pid) == Ok(id),
                _ => true,
            })
            .collect();
        if children.is_empty() && want.is_none() {
            return fail(self, m, Errno::ECHILD);
        }
        SyscallOutcome::Blocking(BlockOp::WaitChild {
            children,
            procs: std::sync::Arc::clone(&self.procs),
            ppid: self.pid,
            want: want.map_or(0, |w| w.0),
            group: want.is_some_and(|w| w.1),
            wstatus: 0,
            nohang: options & WNOHANG != 0,
            waitid: Some(crate::syscalls::WaitidOut { info, nowait: options & WNOWAIT != 0, compat: false, darwin: true }),
            jobs: Some(crate::syscalls::JobWait { exits: options & WEXITED != 0, stops: options & WSTOPPED != 0, continues: options & WCONTINUED != 0 }),
            rusage: 0,
        })
    }

    /// In the page, which children a wait asks the system's table for (the
    /// process table here holds none of them): `(want, group)`, one child
    /// (`want` its pid), any (-1), or a process group's (`group`, `want` its
    /// id), as `share::dwait` asks. None natively, where the children are
    /// this table's.
    fn darwin_page_wait_want(&self, (want, group): (i32, bool)) -> Option<(i32, bool)> {
        self.procs.is_shared().then_some((want, group))
    }

    /// `wait4(pid, status, options, rusage)` and `wait4_nocancel`: the
    /// caller's children that `pid` names (one, any, or a process group's,
    /// zero for its own group), waited for unless `WNOHANG`.
    pub(crate) fn darwin_wait4(&mut self, m: &mut GuestMem<'_>, a: &[u64; 6]) -> SyscallOutcome {
        let fail = |k: &mut Kernel, m: &mut GuestMem<'_>, e: Errno| {
            let _ = super::set_result(m, k.ctx_addr, e.as_return());
            SyscallOutcome::Continue
        };
        let (mut pid, status, options, rusage) = (a[0] as i32, a[1], a[2] as i32, a[3]);
        if pid == 0 {
            match self.procs.pgid(self.pid, 0) {
                Ok(g) => pid = -g,
                Err(e) => return fail(self, m, e),
            }
        }
        if pid == i32::MIN {
            return fail(self, m, Errno::EINVAL);
        }
        // In the page: one child, any, or (below -1) the group -pid's.
        let want = self.darwin_page_wait_want(if pid < -1 { (-pid, true) } else { (pid, false) });
        let children: Vec<_> = self
            .procs
            .children(self.pid)
            .into_iter()
            .filter(|c| pid == WAIT_ANY || c.pid == pid || (pid < -1 && self.procs.pgid(self.pid, c.pid) == Ok(-pid)))
            .collect();
        if children.is_empty() && want.is_none() {
            return fail(self, m, Errno::ECHILD);
        }
        self.darwin_wait4 = Some((status, rusage));
        SyscallOutcome::Blocking(BlockOp::WaitChild {
            children,
            procs: std::sync::Arc::clone(&self.procs),
            ppid: self.pid,
            want: want.map_or(0, |w| w.0),
            group: want.is_some_and(|w| w.1),
            wstatus: status,
            nohang: options & WNOHANG != 0,
            waitid: None,
            jobs: Some(crate::syscalls::JobWait { exits: true, stops: options & WUNTRACED != 0, continues: options & WCONTINUED != 0 }),
            rusage,
        })
    }

    /// A `wait4` whose wait is over: for an ended child (which the host
    /// leaves there), the status copied out, then its `p_ru->ru` to
    /// `rusage`, and only then the child reaped (`reap_child_locked`),
    /// either copy failing ending the call with the child left to wait for;
    /// for a stop or a continue, its status in Darwin's encoding. Then,
    /// the last child reaped, a pending SIGCHLD the thread masks dropped.
    pub(crate) fn darwin_wait4_done(&mut self, m: &mut GuestMem<'_>, (status, rusage): (u64, u64), r: Result<u64, Errno>) -> Result<u64, Errno> {
        let Ok(pid) = r else { return r };
        if pid == 0 {
            return r;
        }
        match self.darwin_wait4_ended(pid as i32) {
            Some((word, ru)) => {
                if status != 0 {
                    m.write_u32(status, status_from_linux(word) & 0xffff)?;
                }
                if rusage != 0 {
                    wait4_rusage(m, rusage, ru)?;
                }
                self.darwin_wait4_reap(pid as i32);
                if rusage != 0 {
                    for t in ru.map(|r| r.stand_in_texts()).unwrap_or_default() {
                        self.darwin_stand_in(t);
                    }
                }
            }
            None => {
                if status != 0 {
                    if let Ok(w) = m.read_u32(status) {
                        let _ = m.write_u32(status, status_from_linux(w) & 0xffff);
                    }
                }
            }
        }
        if self.procs.children(self.pid).is_empty() {
            let l = super::kern::signal_to_linux(super::signal::dsig::SIGCHLD);
            if self.signals.blocked() & (1 << (l - 1)) != 0 {
                self.collect_signals();
                self.signals.discard_everywhere(l, &self.thread_signals);
            }
        }
        r
    }

    /// Child `pid`'s end that a wait4 found and has not collected: its wait
    /// status (the host's encoding) and its `p_ru->ru`; none for a child
    /// whose stop or continue it reported.
    fn darwin_wait4_ended(&mut self, pid: i32) -> Option<(u32, Option<super::ru::Ru>)> {
        if self.procs.is_shared() {
            let all = crate::syscalls::JobWait { exits: true, stops: false, continues: false };
            return match super::share::dwait(self.pid, (pid, false), all, true, false, true) {
                (crate::proc::WaitStep::Ended { word, .. }, _, ru, _) => Some((word, ru)),
                _ => None,
            };
        }
        let c = self.procs.children(self.pid).into_iter().find(|c| c.pid == pid)?;
        if c.reaped.load(std::sync::atomic::Ordering::Acquire) {
            return None;
        }
        let code = (*c.status.lock().unwrap_or_else(|e| e.into_inner()))?;
        Some((code as u32, exit_ru(&self.procs, pid)))
    }

    /// The child `pid` a wait4 copied out collected: reaped, and in the page
    /// its usage added to this process's children's.
    fn darwin_wait4_reap(&mut self, pid: i32) {
        if self.procs.is_shared() {
            let all = crate::syscalls::JobWait { exits: true, stops: false, continues: false };
            let (_, usage, ru, _) = super::share::dwait(self.pid, (pid, false), all, false, false, false);
            self.darwin_page_collected(usage, ru);
            return;
        }
        if let Some(c) = self.procs.children(self.pid).into_iter().find(|c| c.pid == pid) {
            c.status.lock().unwrap_or_else(|e| e.into_inner()).take();
            c.reaped.store(true, std::sync::atomic::Ordering::Release);
            self.procs.reap(pid);
        }
    }

    /// In the page, a child a wait collected: its `p_ru` to this process's
    /// children's usage, as `reap_child_locked` adds it (this parent has no
    /// P_NOCLDWAIT, or the child would have been reaped at its end):
    /// `p_ru->ri` to `ri_child`, `p_ru->ru` to `p_cru`.
    pub fn darwin_page_collected(&mut self, usage: Option<super::rusage::Record>, ru: Option<super::ru::Ru>) {
        if let Some(u) = usage {
            self.dtask.rusage.add_reaped(&u, 1);
        }
        if let Some(r) = ru {
            self.dtask.rusage.ru.add_reaped(&r);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_take_darwin_signal_numbers() {
        // exit(3); SIGUSR1 (Linux 10, Darwin 30) with a core; stopped by
        // SIGTSTP (Linux 20, Darwin 18); continued.
        assert_eq!(status_from_linux(3 << 8), 3 << 8);
        assert_eq!(status_from_linux(10 | 0x80), 30 | 0x80);
        assert_eq!(status_from_linux(0x7f | (20 << 8)), 0x7f | (18 << 8));
        assert_eq!(status_from_linux(0xffff), 0x7f | (19 << 8));
    }
}
