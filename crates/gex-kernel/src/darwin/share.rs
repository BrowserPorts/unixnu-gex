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

/// One call through `r`, whose answer must be `out`'s length: a channel
/// that fails is a broken system, which goes no further.
fn call(r: Remote, op: u32, req: &[u8], out: &mut [u8]) {
    let n = (r.call)(op, req, out);
    if n != out.len() as i64 {
        panic!("gex: the global kernel answered the Darwin system's call {op} with {n} (wanted {} bytes)", out.len());
    }
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
        _ => -ENOSYS,
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
    fn a_call_that_is_not_one_is_refused() {
        let mut o = [0u8; 8];
        assert_eq!(serve(op::NEXT, &[9], &mut o), -22);
        assert_eq!(serve(op::NEXT, &[], &mut o), -22);
        assert_eq!(serve(op::NEXT, &[0], &mut o[..4]), -22);
        assert_eq!(serve(99, &[], &mut o), -78);
    }
}
