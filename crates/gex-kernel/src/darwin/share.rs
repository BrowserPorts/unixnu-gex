//! The Darwin system's state where processes do not share one host process.
//!
//! Natively every task of a Darwin system runs in one host process, so the
//! system's state (its counters, its trust caches, ...) is this crate's
//! statics, and every task sees the same. In the page each process is a
//! Worker with a memory and an instance of this crate of its own, so the
//! same statics are one copy per process. The page's global kernel module
//! (hosts/kernel), which every Worker of every process shares, is where
//! that state lives instead: its instance of this crate holds the statics,
//! and a process reaches them through one encoded call ([`Remote::call`]),
//! which the global kernel answers by running the same code ([`serve`]).
//! That is the design of the Linux state the page shares
//! (`locks::share_locks`, `unix::Remote`).
//!
//! With no remote set (natively, and in the global kernel itself), every
//! function here is the local one.

use std::sync::OnceLock;

/// The global kernel's channel: one call `op` with the request `req`,
/// whose answer goes to `out`. Its result is the answer's length, or a
/// negated errno.
#[derive(Clone, Copy, Debug)]
pub struct Remote {
    pub call: fn(op: u32, req: &[u8], out: &mut [u8]) -> i64,
}

static REMOTE: OnceLock<Remote> = OnceLock::new();

/// The Darwin system's state is the global kernel's from now on: set by a
/// process of the page before its first kernel is made.
pub fn set_remote(r: Remote) {
    let _ = REMOTE.set(r);
}

pub(crate) fn remote() -> Option<Remote> {
    REMOTE.get().copied()
}

/// The calls [`Remote::call`] carries.
pub mod op {
    /// The next of one of the system's identifiers ([`super::Counter`]):
    /// the request its number, the answer 8 bytes.
    pub const NEXT: u32 = 1;
    /// One of the system's clock origins ([`super::Origin`]): the request
    /// its number and the caller's candidate (an instant and a calendar
    /// time, 12 bytes each: seconds, nanoseconds); the answer the origin.
    pub const ORIGIN: u32 = 2;
    /// The trust caches ([`super::super::trustcache`]): the boot's static
    /// one set (the request its module, none for no module; the answer 1
    /// when it is the one the system has), a query (the query's type and
    /// the cdhash; the entry found), whether the runtime has a UUID, a
    /// module loaded (its type and module; 0 loaded, 1 a duplicate, 2
    /// failed and why), and a boot cryptex type's loaded mark asked for
    /// and set.
    pub const TC_SET_STATIC: u32 = 16;
    pub const TC_QUERY: u32 = 17;
    pub const TC_HAS_UUID: u32 = 18;
    pub const TC_LOAD: u32 = 19;
    pub const TC_BOOT_LOADED: u32 = 20;
    pub const TC_MARK_LOADED: u32 = 21;
}

/// The system's identifiers each new process, task or thread takes the next
/// of ([`super::super::next_uniqueid`] and the others).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Counter {
    Uniqueid = 0,
    TaskUniqueid = 1,
    ThreadId = 2,
    Pidversion = 3,
}

impl Counter {
    fn of(n: u8) -> Option<Counter> {
        Some(match n {
            0 => Counter::Uniqueid,
            1 => Counter::TaskUniqueid,
            2 => Counter::ThreadId,
            3 => Counter::Pidversion,
            _ => return None,
        })
    }

    /// This kernel's own counter's next.
    fn local(self) -> u64 {
        match self {
            Counter::Uniqueid => super::local_next_uniqueid(),
            Counter::TaskUniqueid => super::local_next_task_uniqueid(),
            Counter::ThreadId => super::local_next_thread_id(),
            Counter::Pidversion => super::local_next_pidversion() as u32 as u64,
        }
    }
}

/// The system's clock origins, each taken by the first of its kernels to
/// ask: the counter's (`mach_absolute_time`'s zero, the boot, and the
/// calendar time then) and `microuptime`'s. Every process of the page reads
/// one clock (the page's), so an instant one takes is one in the others.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Origin {
    Counter = 0,
    Microuptime = 1,
}

type Moment = (super::time::Instant, std::time::SystemTime);

/// The system's origin `which`: the global kernel's, where it holds the
/// system's state (taken by the first process to ask, whose candidate
/// `here` was); else `here`, which the caller keeps as its own.
pub(crate) fn origin(which: Origin, here: Moment) -> Moment {
    match remote() {
        Some(r) => origin_through(r, which, here),
        None => here,
    }
}

fn put_duration(b: &mut Vec<u8>, d: std::time::Duration) {
    b.extend_from_slice(&d.as_secs().to_le_bytes());
    b.extend_from_slice(&d.subsec_nanos().to_le_bytes());
}

fn duration_at(b: &[u8]) -> std::time::Duration {
    std::time::Duration::new(u64::from_le_bytes(b[..8].try_into().unwrap()), u32::from_le_bytes(b[8..12].try_into().unwrap()))
}

fn moment_bytes(m: Moment) -> Vec<u8> {
    let mut b = Vec::with_capacity(24);
    put_duration(&mut b, m.0.reading());
    put_duration(&mut b, m.1.duration_since(std::time::UNIX_EPOCH).unwrap_or_default());
    b
}

/// A moment from 24 bytes, its calendar time past the epoch.
fn moment_of(b: &[u8]) -> Moment {
    (super::time::Instant::of_reading(duration_at(&b[..12])), std::time::UNIX_EPOCH + duration_at(&b[12..24]))
}

fn origin_through(r: Remote, which: Origin, here: Moment) -> Moment {
    let mut req = vec![which as u8];
    req.extend_from_slice(&moment_bytes(here));
    let mut o = [0u8; 24];
    call(r, op::ORIGIN, &req, &mut o);
    moment_of(&o)
}

/// The origins this kernel holds for the system's.
static ORIGINS: [OnceLock<Moment>; 2] = [OnceLock::new(), OnceLock::new()];

/// One call through `r`, whose answer must be `out`'s length: a channel
/// that fails is a broken system, which goes no further.
pub(crate) fn call(r: Remote, op: u32, req: &[u8], out: &mut [u8]) {
    let n = (r.call)(op, req, out);
    if n != out.len() as i64 {
        panic!("gex: the global kernel answered the Darwin system's call {op} with {n} (wanted {} bytes)", out.len());
    }
}

/// [`call`] with an answer of any length up to `out`'s: its length.
pub(crate) fn call_upto(r: Remote, op: u32, req: &[u8], out: &mut [u8]) -> usize {
    let n = (r.call)(op, req, out);
    if n < 0 || n > out.len() as i64 {
        panic!("gex: the global kernel answered the Darwin system's call {op} with {n} (wanted at most {} bytes)", out.len());
    }
    n as usize
}

/// The next of counter `c`: the global kernel's, where it holds the
/// system's state, else none (the caller takes its own).
pub(crate) fn next(c: Counter) -> Option<u64> {
    let r = remote()?;
    Some(next_through(r, c))
}

fn next_through(r: Remote, c: Counter) -> u64 {
    let mut o = [0u8; 8];
    call(r, op::NEXT, &[c as u8], &mut o);
    u64::from_le_bytes(o)
}

/// A call [`Remote::call`] carried, answered by this kernel, which holds the
/// system's state: the answer's length in `out`, or a negated errno
/// (`EINVAL` for a request that is not one, `ENOSYS` for an unknown call).
pub fn serve(op: u32, req: &[u8], out: &mut [u8]) -> i64 {
    const EINVAL: i64 = 22;
    const ENOSYS: i64 = 78;
    match op {
        op::NEXT => {
            let (Some(c), 8..) = (req.first().and_then(|&n| Counter::of(n)), out.len()) else { return -EINVAL };
            out[..8].copy_from_slice(&c.local().to_le_bytes());
            8
        }
        op::ORIGIN => {
            let (Some(&which @ (0 | 1)), 25, 24..) = (req.first(), req.len(), out.len()) else { return -EINVAL };
            let got = *ORIGINS[which as usize].get_or_init(|| moment_of(&req[1..]));
            out[..24].copy_from_slice(&moment_bytes(got));
            24
        }
        _ => match super::trustcache::serve(op, req, out) {
            Some(n) => n,
            None => -ENOSYS,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn through_serve(op: u32, req: &[u8], out: &mut [u8]) -> i64 {
        serve(op, req, out)
    }

    #[test]
    fn a_counter_through_the_channel_is_the_serving_kernels() {
        let r = Remote { call: through_serve };
        // The serving kernel's counters are this test binary's, which other
        // tests take from at the same time: each answer is one that kernel
        // gave, so later ones are larger.
        for c in [Counter::Uniqueid, Counter::TaskUniqueid, Counter::ThreadId] {
            let a = next_through(r, c);
            let b = next_through(r, c);
            assert!(b > a, "{c:?}: {a} then {b}");
        }
        let a = next_through(r, Counter::Pidversion) as u32 as i32;
        let b = next_through(r, Counter::Pidversion) as u32 as i32;
        assert!(b > a);
    }

    #[test]
    fn an_origin_is_the_first_askers() {
        let r = Remote { call: through_serve };
        let t = super::super::time::Instant::of_reading(std::time::Duration::new(5 << 32, 7));
        let a = (t, std::time::UNIX_EPOCH + std::time::Duration::new(1_700_000_000, 9));
        let b = (super::super::time::Instant::of_reading(std::time::Duration::new(6 << 32, 0)), std::time::UNIX_EPOCH);
        // (Origin::Microuptime here: the counter's is this binary's mach
        // origin, which other tests take.)
        let first = origin_through(r, Origin::Microuptime, a);
        assert_eq!(origin_through(r, Origin::Microuptime, b), first);
        let mut o = [0u8; 24];
        assert_eq!(serve(op::ORIGIN, &[2; 25], &mut o), -22);
        assert_eq!(serve(op::ORIGIN, &[0; 24], &mut o), -22);
    }

    #[test]
    fn a_call_that_is_not_one_is_refused() {
        let mut o = [0u8; 8];
        assert_eq!(serve(op::NEXT, &[9], &mut o), -22);
        assert_eq!(serve(op::NEXT, &[], &mut o), -22);
        assert_eq!(serve(op::NEXT, &[0], &mut o[..4]), -22);
        assert_eq!(serve(99, &[], &mut o), -78);
    }
}
