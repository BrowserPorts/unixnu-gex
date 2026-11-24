//! What a call changes of another process's state that is its own (its
//! task policy, its nice value, its job state).
//!
//! Natively the caller changes it in the one process table, under its
//! lock. In the page that state is its process's own table's, in that
//! process's memory: the change goes to the global kernel for the process
//! ([`super::share::op::CHANGE_POST`]), its process makes it as its thread
//! calls run ([`Kernel::darwin_changes_apply`]), with the same code a
//! change here runs ([`Kernel::darwin_change_here`]), and the caller waits
//! for it, with its result, as it waits for the lock natively.

use crate::errno::Errno;
use crate::syscalls::Kernel;

/// A change to a process's own state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// `donice`'s: the nice value, and `resetpriority`'s importance.
    Nice(i32),
    /// `do_background_proc`'s: the darwin background, external or not.
    DarwinBg { external: bool, on: bool },
    /// `set_gpudeny_proc`'s.
    GpuDenied(bool),
    /// `proc_set_darwin_role`'s: the task role (EOPNOTSUPP for a process
    /// that is not an application).
    Role(u8),
    /// `proc_set_game_mode`'s.
    GameMode(bool),
    /// `proc_terminate`'s `TASK_POLICY_TERMINATED`.
    Terminated,
    /// `pid_suspend`'s hold (EPERM when it holds one already) and
    /// `pid_resume`'s release (EPERM when it holds none).
    PidSuspend,
    PidResume,
}

impl Change {
    fn put(&self, p: &mut super::ipc::wire::Put) {
        match *self {
            Change::Nice(n) => {
                p.u8(0);
                p.i32(n);
            }
            Change::DarwinBg { external, on } => {
                p.u8(1);
                p.bool(external);
                p.bool(on);
            }
            Change::GpuDenied(d) => {
                p.u8(2);
                p.bool(d);
            }
            Change::Role(r) => {
                p.u8(3);
                p.u8(r);
            }
            Change::GameMode(on) => {
                p.u8(4);
                p.bool(on);
            }
            Change::Terminated => p.u8(5),
            Change::PidSuspend => p.u8(6),
            Change::PidResume => p.u8(7),
        }
    }

    fn get(g: &mut super::ipc::wire::Get<'_>) -> Result<Change, super::ipc::wire::Bad> {
        Ok(match g.u8()? {
            0 => Change::Nice(g.i32()?),
            1 => Change::DarwinBg { external: g.bool()?, on: g.bool()? },
            2 => Change::GpuDenied(g.bool()?),
            3 => Change::Role(g.u8()?),
            4 => Change::GameMode(g.bool()?),
            5 => Change::Terminated,
            6 => Change::PidSuspend,
            7 => Change::PidResume,
            _ => return Err(g.bad("a change")),
        })
    }

    pub(crate) fn bytes(&self) -> Vec<u8> {
        let mut p = super::ipc::wire::Put::default();
        self.put(&mut p);
        p.0
    }

    pub(crate) fn of_bytes(b: &[u8]) -> Result<Change, super::ipc::wire::Bad> {
        let g = &mut super::ipc::wire::Get::new(b);
        let c = Change::get(g)?;
        if !g.done() {
            return Err(g.bad("the end of a change"));
        }
        Ok(c)
    }
}

impl Kernel {
    /// Change process `pid`'s state as `c` says: here when this process's
    /// table holds `pid` (natively every process; in the page this process
    /// itself), else through `pid`'s own process in the page, waited for.
    /// A process that has gone has nothing changed (as no cell is found
    /// natively).
    pub(crate) fn darwin_change(&mut self, pid: i32, c: Change) -> Result<(), Errno> {
        if self.procs.holds(pid) || !self.procs.is_shared() {
            return self.darwin_change_here(pid, c);
        }
        // Nothing of the system's held while it waits: the process making
        // it may need the IPC table.
        // (a process gone: a job's ESRCH, as no cell is found)
        let gone = || match c {
            Change::PidSuspend | Change::PidResume => Err(Errno::ESRCH),
            _ => Ok(()),
        };
        let Some(ticket) = super::share::change_post(pid, &c.bytes()) else { return gone() };
        if let Some(link) = self.ipc().links.values().find(|l| l.pid == pid).cloned() {
            link.ring();
        }
        self.darwin_ipc_leave();
        match super::share::change_wait(pid, ticket) {
            Some(0) => Ok(()),
            Some(e) => Err(super::errno::errno_of(e)),
            None => gone(),
        }
    }

    /// Change `pid`'s state, which this process's table holds.
    pub(crate) fn darwin_change_here(&mut self, pid: i32, c: Change) -> Result<(), Errno> {
        match c {
            Change::Nice(n) => {
                self.procs.set_nice(pid, n);
                if let Some(p) = self.procs.task_policy(pid) {
                    // task_importance's refusal for a control application
                    // is not the caller's error.
                    let _ = p.lock().unwrap_or_else(|e| e.into_inner()).set_importance(-n);
                }
            }
            Change::DarwinBg { external, on } => {
                if let Some(p) = self.procs.task_policy(pid) {
                    p.lock().unwrap_or_else(|e| e.into_inner()).set_darwinbg(external, on);
                }
            }
            Change::GpuDenied(deny) => {
                if let Some(p) = self.procs.task_policy(pid) {
                    p.lock().unwrap_or_else(|e| e.into_inner()).gpu_denied = deny;
                }
            }
            Change::Role(role) => {
                let Some(p) = self.procs.task_policy(pid) else { return Ok(()) };
                let mut p = p.lock().unwrap_or_else(|e| e.into_inner());
                if !p.is_app() {
                    return Err(Errno::EOPNOTSUPP);
                }
                p.set_role(role);
            }
            Change::GameMode(on) => {
                if let Some(p) = self.procs.task_policy(pid) {
                    p.lock().unwrap_or_else(|e| e.into_inner()).game_mode = on;
                }
            }
            Change::Terminated => {
                if let Some(cell) = self.procs.task_policy(pid) {
                    let mut p = cell.lock().unwrap_or_else(|e| e.into_inner());
                    p.requested.terminated = true;
                    p.update(false);
                }
            }
            Change::PidSuspend => {
                let job = self.procs.job(pid).ok_or(Errno::ESRCH)?;
                let mut j = job.lock().unwrap_or_else(|e| e.into_inner());
                if j.pidsuspended {
                    return Err(Errno::EPERM);
                }
                j.pidsuspended = true;
                j.holds += 1;
            }
            Change::PidResume => {
                let job = self.procs.job(pid).ok_or(Errno::ESRCH)?;
                {
                    let mut j = job.lock().unwrap_or_else(|e| e.into_inner());
                    if !j.pidsuspended {
                        return Err(Errno::EPERM);
                    }
                    j.pidsuspended = false;
                    j.holds = j.holds.saturating_sub(1);
                }
                // Held threads wait on the host's readiness wake.
                self.fd_activity = true;
            }
        }
        Ok(())
    }

    /// In the page, the changes other processes left for this one, made,
    /// each one's result given back for its caller.
    pub(crate) fn darwin_changes_apply(&mut self) {
        if !self.procs.is_shared() {
            return;
        }
        let pid = self.pid;
        let pending = super::share::change_take(pid);
        if pending.is_empty() {
            return;
        }
        let mut results = Vec::with_capacity(pending.len());
        for (ticket, b) in pending {
            let c = match Change::of_bytes(&b) {
                Ok(c) => c,
                Err(e) => panic!("gex: a change for process {pid} in the global kernel is not one ({e:?})"),
            };
            results.push((ticket, self.darwin_change_here(pid, c).err().map_or(0, |e| e.0 as i32)));
        }
        // What the changes made of its record, before any caller goes on
        // to read it.
        if self.dtask.record_sent.is_some() {
            self.darwin_record_send();
        }
        for (ticket, r) in results {
            super::share::change_done(pid, ticket, r);
        }
        crate::wait::notify(super::ipc::wire::table_queue());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_change_is_the_same_change_after_its_bytes() {
        for c in [Change::Nice(-3), Change::DarwinBg { external: true, on: false }, Change::GpuDenied(true), Change::Role(4), Change::GameMode(true), Change::Terminated, Change::PidSuspend, Change::PidResume] {
            assert_eq!(Change::of_bytes(&c.bytes()), Ok(c));
        }
        assert!(Change::of_bytes(&[9]).is_err());
        assert!(Change::of_bytes(&[0, 1]).is_err());
    }
}
