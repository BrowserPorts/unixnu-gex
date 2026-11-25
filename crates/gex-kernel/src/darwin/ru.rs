//! A Darwin process's `struct rusage` (`bsd/sys/resource.h`): what
//! `getrusage` and `wait4` copy out (`kern_resource.c`, `kern_exit.c`).
//!
//! XNU keeps three of them per process: `p_stats->p_ru`, whose longs the
//! process's calls count as they go and `calcru` refreshes from its task;
//! `p_stats->p_cru`, the reaped children's sum (`reap_child_locked`'s
//! `ruadd`, none for a parent with `P_NOCLDWAIT`); and `p_ru->ru`, the
//! final record `proc_exit` makes (`calcru`, then `p_cru` added) for the
//! parent's `wait4`.
//!
//! Where XNU counts each long:
//!
//! - `ru_maxrss`: `calcru`, `MACH_TASK_BASIC_INFO`'s `resident_size_max`,
//!   the `phys_mem` ledger's lifetime peak in bytes.
//! - `ru_minflt` and `ru_majflt`: `calcru`, `TASK_EVENTS_INFO`'s `faults`
//!   (every `vm_fault_internal` of the task, `vm_fault.c`) less its
//!   `pageins`, and the `pageins`; each a 32-bit count, clamped.
//! - `ru_nvcsw`: `_sleep`'s entry (`kern_synch.c`), every `msleep`,
//!   `tsleep` and `msleep0`, whether or not it blocks.
//! - `ru_nivcsw`: `calcru`, `TASK_EVENTS_INFO`'s `csw` (each thread's
//!   `c_switch`, raised by `thread_invoke` as it puts the thread on core)
//!   less `ru_nvcsw`, never below 0.
//! - `ru_nsignals`: `postsig`, as a handler is about to be called.
//! - `ru_msgsnd`: `sosend`, past its `EOPNOTSUPP` and `EINVAL` checks;
//!   `ru_msgrcv`: `soreceive` at `dontblock`, with a record to take.
//! - `ru_inblock`: `bio_doread`, a buffer whose data is not valid read
//!   (`buf_bread`, `buf_meta_bread`, `buf_breadn` and its read-ahead);
//!   `ru_oublock`: `buf_bwrite`'s synchronous and undelayed writes, and
//!   `proc_increment_ru_oublock`'s callers.
//! - `ru_ixrss`, `ru_idrss`, `ru_isrss` and `ru_nswap`: never.
//!
//! What gex cannot see of these is given as what it counts and said once
//! per process as a stand-in ([`StandIn`]).

use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

/// The longs of `struct rusage`, by index.
pub mod l {
    pub const MAXRSS: usize = 0;
    pub const IXRSS: usize = 1;
    pub const IDRSS: usize = 2;
    pub const ISRSS: usize = 3;
    pub const MINFLT: usize = 4;
    pub const MAJFLT: usize = 5;
    pub const NSWAP: usize = 6;
    pub const INBLOCK: usize = 7;
    pub const OUBLOCK: usize = 8;
    pub const MSGSND: usize = 9;
    pub const MSGRCV: usize = 10;
    pub const NSIGNALS: usize = 11;
    pub const NVCSW: usize = 12;
    pub const NIVCSW: usize = 13;
}

/// `sizeof(struct user64_rusage)`: two `user64_timeval`s, fourteen longs.
pub const SIZE: usize = 144;

/// What a record's figures stand in for, a bit each.
pub mod stand_in {
    /// `ru_minflt`: faults gex does not take.
    pub const MINFLT: u32 = 1 << 0;
    /// `ru_nivcsw`: the threads' switches onto a core.
    pub const NIVCSW: u32 = 1 << 1;
    /// `ru_inblock`: buffer reads of APFS's.
    pub const INBLOCK: u32 = 1 << 2;
    /// `ru_oublock`: buffer writes.
    pub const OUBLOCK: u32 = 1 << 3;
    /// `ru_maxrss`: no look at the task's pages.
    pub const MAXRSS: u32 = 1 << 4;
    /// `ru_msgsnd`, `ru_msgrcv`: sockets whose sends and receives are not
    /// `sosend`'s and `soreceive`'s here.
    pub const MSGS: u32 = 1 << 5;
}

/// Each stand-in bit: the field and what it stands in for.
pub const STAND_INS: [(u32, &str); 7] = [
    (stand_in::MINFLT, "ru_minflt: the faults gex does not take (vm_fault counts each in task->faults): those the page-ins leave unseen (instruction fetches, the shared cache's first touches, copyin and copyout of a file's pages, the kernel's faults for exec and dyld) (stand-in: the faults gex takes, less the page-ins; measure ru_minflt on the device across a first run of a known binary that maps a known file)"),
    (stand_in::NIVCSW, "ru_nivcsw: the threads' switches onto a core (thread_invoke's c_switch, which calcru takes ru_nvcsw from), which the host's scheduler makes and does not tell a thread's (macOS's thread_info flavours give no switch count, proc_pidinfo's pti_csw is the whole host process's) (stand-in: 0; measure ru_nivcsw on the device of a CPU-bound process over a known run time)"),
    (stand_in::INBLOCK, "ru_inblock: APFS's own buffer reads on a miss (obj_read through nx_buf_bread and buf_meta_bread's bio_doread), which need its object cache's state, not kept for the volumes (stand-in: only a block disk node's buffer-cache misses are counted; measure ru_inblock on the device across a first stat of N files in a new directory)"),
    (stand_in::OUBLOCK, "ru_oublock: synchronous buffer writes (buf_bwrite) and the kexts' proc_increment_ru_oublock calls, APFS's among them, whose state is not kept (stand-in: 0; measure ru_oublock on the device across creating and fsyncing a file)"),
    (stand_in::MAXRSS, "ru_maxrss: the phys_mem ledger's lifetime peak, which needs a look at the task's pages the host does not give (stand-in: 0; measure ru_maxrss on the device of a process that touches a known number of pages)"),
    (stand_in::MSGS, "ru_msgsnd and ru_msgrcv of a socket other than a unix stream (its sends and receives are the host's socket code's, not sosend's and soreceive's) (stand-in: those not counted; measure on the device ru_msgsnd and ru_msgrcv across N sends and receives on a datagram socket)"),
];

/// The stand-ins gex always makes in a record: what it cannot see on any
/// host.
pub const ALWAYS: u32 = stand_in::MINFLT | stand_in::NIVCSW | stand_in::INBLOCK | stand_in::OUBLOCK;

/// `timeradd`.
fn timeradd(a: (u64, u32), b: (u64, u32)) -> (u64, u32) {
    let (mut s, mut us) = (a.0.wrapping_add(b.0), a.1 + b.1);
    if us >= 1_000_000 {
        s = s.wrapping_add(1);
        us -= 1_000_000;
    }
    (s, us)
}

/// One `struct rusage`, with what of it is not the device's: the times
/// unknown (no per-thread clocks on the host, here or in a reaped child),
/// and the stand-ins among its longs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ru {
    pub utime: (u64, u32),
    pub stime: (u64, u32),
    pub l: [i64; 14],
    pub times_unknown: bool,
    pub stand_ins: u32,
}

impl Ru {
    /// `ruadd(self, o)`: the times added, `ru_maxrss` the larger, every
    /// long from `ru_first` (`ru_ixrss`) to `ru_last` (`ru_nivcsw`) added.
    pub fn add(&mut self, o: &Ru) {
        self.utime = timeradd(self.utime, o.utime);
        self.stime = timeradd(self.stime, o.stime);
        if self.l[l::MAXRSS] < o.l[l::MAXRSS] {
            self.l[l::MAXRSS] = o.l[l::MAXRSS];
        }
        for i in l::IXRSS..=l::NIVCSW {
            self.l[i] = self.l[i].wrapping_add(o.l[i]);
        }
        self.times_unknown |= o.times_unknown;
        self.stand_ins |= o.stand_ins;
    }

    /// `munge_user64_rusage`: `struct user64_rusage`'s bytes.
    pub fn bytes(&self) -> [u8; SIZE] {
        let mut b = [0u8; SIZE];
        for (i, (secs, usecs)) in [self.utime, self.stime].into_iter().enumerate() {
            b[16 * i..16 * i + 8].copy_from_slice(&secs.to_le_bytes());
            b[16 * i + 8..16 * i + 12].copy_from_slice(&usecs.to_le_bytes());
        }
        for (i, v) in self.l.iter().enumerate() {
            b[32 + 8 * i..40 + 8 * i].copy_from_slice(&v.to_le_bytes());
        }
        b
    }

    /// The record as bytes, for another process of the page.
    pub(crate) fn put(&self, p: &mut super::ipc::wire::Put) {
        for (s, us) in [self.utime, self.stime] {
            p.u64(s);
            p.u32(us);
        }
        for &v in &self.l {
            p.u64(v as u64);
        }
        p.bool(self.times_unknown);
        p.u32(self.stand_ins);
    }

    pub(crate) fn get(g: &mut super::ipc::wire::Get<'_>) -> Result<Ru, super::ipc::wire::Bad> {
        let utime = (g.u64()?, g.u32()?);
        let stime = (g.u64()?, g.u32()?);
        let mut ll = [0i64; 14];
        for v in ll.iter_mut() {
            *v = g.u64()? as i64;
        }
        Ok(Ru { utime, stime, l: ll, times_unknown: g.bool()?, stand_ins: g.u32()? })
    }

    /// The fields this record stands in for, each by name and what it
    /// needs.
    pub fn stand_in_texts(&self) -> Vec<&'static str> {
        STAND_INS.iter().filter(|(b, _)| self.stand_ins & b != 0).map(|&(_, t)| t).collect()
    }
}

/// A count of the task's as `TASK_EVENTS_INFO` gives it: 32 bits, clamped.
fn events_count(n: u64) -> i32 {
    n.min(i32::MAX as u64) as i32
}

/// A process's `p_stats` usage: the counts its calls make in `p_ru`, its
/// task's faults, the reaped children's sum and its final record.
#[derive(Debug, Default)]
pub struct Stats {
    /// `p_stats->p_ru`'s longs that the process's own calls count
    /// (`ru_inblock`, `ru_oublock`, `ru_msgsnd`, `ru_msgrcv`,
    /// `ru_nsignals`, `ru_nvcsw`); `calcru` makes the rest.
    pub p_ru: [AtomicI64; 14],
    /// `task->faults`: every `vm_fault` of the task. An exec's task takes
    /// the old one's (`task_rollup_accounting_info`).
    pub faults: AtomicU64,
    /// The process did what its counts do not see ([`stand_in`] bits).
    pub unseen: AtomicU32,
    /// `p_stats->p_cru`.
    cru: Mutex<Ru>,
    /// `p_ru->ru`, once `proc_exit` has made it.
    exit: Mutex<Option<Ru>>,
}

impl Stats {
    /// One more of long `i` of `p_ru`.
    pub fn count(&self, i: usize) {
        self.p_ru[i].fetch_add(1, Ordering::AcqRel);
    }

    /// One more of the task's faults.
    pub fn fault(&self) {
        self.faults.fetch_add(1, Ordering::AcqRel);
    }

    /// What its counts do not see: the stand-in bits `bits`.
    pub fn unseen(&self, bits: u32) {
        self.unseen.fetch_or(bits, Ordering::AcqRel);
    }

    /// `p_stats->p_cru`.
    pub fn cru(&self) -> Ru {
        *self.cru.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `p_ru->ru`, once the process has ended.
    pub fn exited(&self) -> Option<Ru> {
        *self.exit.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `reap_child_locked`'s `ruadd(&parent->p_stats->p_cru, &child->p_ru->ru)`.
    pub fn add_reaped(&self, r: &Ru) {
        self.cru.lock().unwrap_or_else(|e| e.into_inner()).add(r);
    }

    /// `calcru` into `p_ru` and a copy of it (`getrusage(RUSAGE_SELF)`'s
    /// `rubuf`): the times (`times`, none without the host's clocks), the
    /// faults less the page-ins (`pageins`, the task's) and the page-ins,
    /// the switches less the voluntary ones, and the resident peak in
    /// bytes (`maxrss`, none where the task's pages cannot be looked at).
    pub fn calcru(&self, times: Option<[(u64, u32); 2]>, pageins: u64, maxrss: Option<u64>) -> Ru {
        let mut r = Ru::default();
        for (i, v) in self.p_ru.iter().enumerate() {
            r.l[i] = v.load(Ordering::Acquire);
        }
        match times {
            Some([u, s]) => {
                r.utime = u;
                r.stime = s;
            }
            None => r.times_unknown = true,
        }
        let (faults, pageins) = (events_count(self.faults.load(Ordering::Acquire)), events_count(pageins));
        r.l[l::MINFLT] = i64::from(faults.wrapping_sub(pageins));
        r.l[l::MAJFLT] = i64::from(pageins);
        // The switches onto a core are the host's (a stand-in): none
        // counted, so ru_nivcsw is clamped to 0 as calcru clamps it.
        r.l[l::NIVCSW] = 0;
        r.l[l::MAXRSS] = maxrss.unwrap_or(0) as i64;
        r.stand_ins = ALWAYS | self.unseen.load(Ordering::Acquire) | if maxrss.is_none() { stand_in::MAXRSS } else { 0 };
        r
    }

    /// `proc_exit`'s final record: `calcru` (as [`Self::calcru`]), then
    /// `ruadd` of `p_cru`.
    pub fn set_exit(&self, mut r: Ru) {
        r.add(&self.cru());
        *self.exit.lock().unwrap_or_else(|e| e.into_inner()) = Some(r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruadd_adds_the_times_with_carry_keeps_the_larger_maxrss_and_sums_the_rest() {
        let mut a = Ru { utime: (1, 600_000), stime: (0, 10), ..Ru::default() };
        a.l[l::MAXRSS] = 100;
        a.l[l::NVCSW] = 3;
        let mut b = Ru { utime: (2, 500_000), stime: (0, 999_995), stand_ins: stand_in::MAXRSS, ..Ru::default() };
        b.l[l::MAXRSS] = 50;
        b.l[l::NVCSW] = 4;
        b.l[l::IXRSS] = 1;
        a.add(&b);
        assert_eq!(a.utime, (4, 100_000));
        assert_eq!(a.stime, (1, 5));
        assert_eq!(a.l[l::MAXRSS], 100);
        assert_eq!(a.l[l::NVCSW], 7);
        assert_eq!(a.l[l::IXRSS], 1);
        assert_eq!(a.stand_ins, stand_in::MAXRSS);
    }

    #[test]
    fn the_user64_layout_is_two_timevals_then_fourteen_longs() {
        let mut r = Ru { utime: (7, 8), stime: (9, 10), ..Ru::default() };
        r.l[l::NIVCSW] = -1;
        let b = r.bytes();
        assert_eq!(u64::from_le_bytes(b[0..8].try_into().unwrap()), 7);
        assert_eq!(u32::from_le_bytes(b[8..12].try_into().unwrap()), 8);
        assert_eq!(u64::from_le_bytes(b[16..24].try_into().unwrap()), 9);
        assert_eq!(&b[140..144], &[0xff; 4]);
    }

    #[test]
    fn calcru_takes_the_page_ins_from_the_faults_and_the_exit_adds_the_children() {
        let s = Stats::default();
        for _ in 0..5 {
            s.fault();
        }
        s.count(l::NVCSW);
        let r = s.calcru(Some([(1, 0), (0, 0)]), 2, Some(16384));
        assert_eq!((r.l[l::MINFLT], r.l[l::MAJFLT], r.l[l::NVCSW], r.l[l::MAXRSS]), (3, 2, 1, 16384));
        assert_eq!(r.stand_ins, ALWAYS);
        let mut child = Ru { utime: (0, 1), ..Ru::default() };
        child.l[l::MAXRSS] = 1 << 20;
        child.l[l::MINFLT] = 4;
        s.add_reaped(&child);
        s.set_exit(r);
        let e = s.exited().unwrap();
        assert_eq!((e.utime, e.l[l::MAXRSS], e.l[l::MINFLT]), ((1, 1), 1 << 20, 7));
        let w = &mut super::super::ipc::wire::Put::default();
        e.put(w);
        assert_eq!(Ru::get(&mut super::super::ipc::wire::Get::new(&w.0)).unwrap(), e);
        assert!(s.calcru(None, 0, None).times_unknown);
    }
}
