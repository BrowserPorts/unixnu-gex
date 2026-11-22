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
    /// A system string's read or set (`kern.osreleasetype` 0,
    /// `kern.hostname` 1: [`super::super::sysctl`]): the request its
    /// number (0x80 added for a set) and a set's value; a read's answer the
    /// value, however long.
    pub const SYSTEM_STRING: u32 = 3;
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
    /// The coalitions ([`super::super::coalition`]), a call for each of
    /// its functions on the table: pids as 4 bytes, coalition ids as 8.
    pub const CO_FORK: u32 = 32;
    pub const CO_ADOPT_CORPSE: u32 = 33;
    pub const CO_EXEC: u32 = 34;
    pub const CO_MEMBERSHIP: u32 = 35;
    pub const CO_THREAD_GROUP: u32 = 36;
    pub const CO_PRIVILEGED: u32 = 37;
    pub const CO_LEADER: u32 = 38;
    pub const CO_TASK_TERMINATED: u32 = 39;
    pub const CO_ACTIVATE: u32 = 40;
    pub const CO_RELEASE: u32 = 41;
    pub const CO_PLACE: u32 = 42;
    pub const CO_LIST: u32 = 43;
    pub const CO_CREATE: u32 = 44;
    pub const CO_TERMINATE: u32 = 45;
    pub const CO_KIND: u32 = 46;
    pub const CO_SET_NAME: u32 = 47;
    /// The record of what each process of the page holds of the state
    /// that is still its own copy there ([`super::super::held`]): the
    /// request the kind, the caller's pid (4 bytes) and the key; the
    /// answer the holder's pid (4 bytes), or for a count the total (8).
    pub const HELD_CLAIM: u32 = 48;
    pub const HELD_HOLDER: u32 = 49;
    pub const HELD_LET_GO: u32 = 50;
    pub const HELD_ANY: u32 = 51;
    pub const HELD_TOUCH: u32 = 52;
    pub const HELD_COUNT: u32 = 53;
    /// One of the system's values ([`super::Value`]): the request its
    /// number, how (0 read, 1 set, 2 set unless set before) and a value
    /// (8 bytes); the answer the value after (8 bytes).
    pub const VALUE: u32 = 4;
    /// The boot payload's digest ([`super::boot_payload`]): the request
    /// the caller's (32 bytes), the answer the system's, the first asker's.
    pub const BOOT_PAYLOAD: u32 = 5;
    /// The devfs nodes' times ([`super::super::devfs`]): a mark or a read
    /// of one node's, with the caller's clock readings; a read's answer
    /// its times.
    pub const DEV_TIMES: u32 = 6;
    /// A task's global mailbox ([`super::super::ipc::wire::mailbox_put`]):
    /// the request the task's key (8 bytes), its process (4) and an encoded
    /// remote; a take's request the key, its answer every remote left, each
    /// with its length, however long.
    pub const MAILBOX_PUT: u32 = 7;
    pub const MAILBOX_TAKE: u32 = 8;
}

/// The boot payload every process of the page booted from: its files'
/// digest, the system's the first process's. Each process boots its own
/// copy of the boot's immutable data (the device tree, the sandbox
/// profiles, the system volume's attributes, the Image4 anchor, the trust
/// cache), which is the system's only while it is the same payload: a
/// process given another fails its boot. Nothing natively, where one boot
/// is the system's.
pub fn boot_payload(files: &[(String, Vec<u8>)]) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let Some(r) = remote() else { return Ok(()) };
    let mut sorted: Vec<&(String, Vec<u8>)> = files.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = Sha256::new();
    for (name, bytes) in sorted {
        h.update((name.len() as u64).to_le_bytes());
        h.update(name.as_bytes());
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    let mine: [u8; 32] = h.finalize().into();
    let mut o = [0u8; 32];
    call(r, op::BOOT_PAYLOAD, &mine, &mut o);
    if o != mine {
        return Err("a boot payload other than the one the page's first Darwin process booted from: each process holds its own copy of the boot's immutable data, which must be the system's".into());
    }
    Ok(())
}

/// The boot payload's digest this kernel holds for the system.
static BOOT_DIGEST: OnceLock<[u8; 32]> = OnceLock::new();

/// The system's identifiers each new process, task or thread takes the next
/// of ([`super::super::next_uniqueid`] and the others).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Counter {
    Uniqueid = 0,
    TaskUniqueid = 1,
    ThreadId = 2,
    Pidversion = 3,
    /// A user client's registry entry id's serial ([`super::super::iokit`]).
    IoClient = 4,
    /// A devfs node made after the mount: its inode number
    /// ([`super::super::devfs::later_ino`]).
    DevIno = 5,
    /// The kernel's SMR generation ([`super::super::commpage::tick`]).
    Quiesce = 6,
}

impl Counter {
    fn of(n: u8) -> Option<Counter> {
        Some(match n {
            0 => Counter::Uniqueid,
            1 => Counter::TaskUniqueid,
            2 => Counter::ThreadId,
            3 => Counter::Pidversion,
            4 => Counter::IoClient,
            5 => Counter::DevIno,
            6 => Counter::Quiesce,
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
            Counter::IoClient => super::iokit::local_next_client_serial(),
            Counter::DevIno => super::devfs::local_later_ino(),
            Counter::Quiesce => super::commpage::local_next_quiesce(),
        }
    }
}

/// The system's values every process reads, and the ones that change
/// them set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Value {
    /// `atm_diagnostic_config` ([`super::super::commpage`]).
    AtmDiagnosticConfig = 0,
    /// The commpage's ASB targets' first random index, drawn once.
    AsbIndex = 1,
    /// lo0's `if_flags` ([`super::super::ioctl`]).
    Lo0Flags = 2,
}

/// The values this kernel holds for the system's: each set or not.
static VALUES: std::sync::Mutex<[Option<u64>; 3]> = std::sync::Mutex::new([None; 3]);

/// Value `which`: the global kernel's, where it holds the system's state,
/// after `how` (0 read, 1 set to `v`, 2 set to `v` unless set before, 3 or
/// `v` into it, 4 and `v` into it; an or or an and of a value not set is
/// one of 0); none elsewhere (the caller's own is the system's).
pub(crate) fn value(which: Value, how: u8, v: u64) -> Option<u64> {
    let r = remote()?;
    let mut req = vec![which as u8, how];
    req.extend_from_slice(&v.to_le_bytes());
    let mut o = [0u8; 8];
    call(r, op::VALUE, &req, &mut o);
    Some(u64::from_le_bytes(o))
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

/// A read whose answer may be of any length: asked again with room for the
/// whole when the first answer says it is longer.
pub(crate) fn call_read(r: Remote, op: u32, req: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 4096];
    loop {
        let n = (r.call)(op, req, &mut out);
        if n < 0 {
            panic!("gex: the global kernel answered the Darwin system's call {op} with {n}");
        }
        if n as usize <= out.len() {
            out.truncate(n as usize);
            return out;
        }
        out = vec![0u8; n as usize];
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
        op::SYSTEM_STRING => super::sysctl::serve_string(req, out),
        op::BOOT_PAYLOAD => {
            let (32, 32..) = (req.len(), out.len()) else { return -EINVAL };
            let got = BOOT_DIGEST.get_or_init(|| req.try_into().unwrap());
            out[..32].copy_from_slice(got);
            32
        }
        op::VALUE => {
            let (Some(&which @ (0..=2)), Some(&how @ (0..=4)), 10, 8..) = (req.first(), req.get(1), req.len(), out.len()) else { return -EINVAL };
            let v = u64::from_le_bytes(req[2..10].try_into().unwrap());
            let mut t = VALUES.lock().unwrap_or_else(|e| e.into_inner());
            let slot = &mut t[which as usize];
            match how {
                1 => *slot = Some(v),
                2 => {
                    slot.get_or_insert(v);
                }
                3 => *slot = Some(slot.unwrap_or(0) | v),
                4 => *slot = Some(slot.unwrap_or(0) & v),
                _ => {}
            }
            out[..8].copy_from_slice(&slot.unwrap_or(0).to_le_bytes());
            8
        }
        _ => match super::trustcache::serve(op, req, out).or_else(|| super::coalition::serve(op, req, out)).or_else(|| super::held::serve(op, req, out)).or_else(|| super::devfs::serve(op, req, out)).or_else(|| super::ipc::wire::serve(op, req, out)) {
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

    /// An answer longer than the first buffer, as a read of a long system
    /// string gives it: the whole, the second time.
    fn long_answer(_op: u32, _req: &[u8], out: &mut [u8]) -> i64 {
        for (i, b) in out.iter_mut().enumerate().take(5000) {
            *b = i as u8;
        }
        5000
    }

    #[test]
    fn a_system_string_through_the_channel_is_the_serving_kernels() {
        let r = Remote { call: through_serve };
        // Each as the serving kernel has it, and set again to what it is
        // (other tests read them meanwhile).
        for which in [0u8, 1] {
            let v = call_read(r, op::SYSTEM_STRING, &[which]);
            let mut o = vec![0u8; v.len()];
            assert_eq!(super::super::sysctl::serve_string(&[which], &mut o), v.len() as i64);
            assert_eq!(o, v);
            let mut req = vec![which | 0x80];
            req.extend_from_slice(&v);
            call(r, op::SYSTEM_STRING, &req, &mut []);
        }
        let want: Vec<u8> = (0..5000).map(|i| i as u8).collect();
        assert_eq!(call_read(Remote { call: long_answer }, op::SYSTEM_STRING, &[0]), want);
        assert_eq!(serve(op::SYSTEM_STRING, &[2], &mut []), -22);
        assert_eq!(serve(op::SYSTEM_STRING, &[0, 1], &mut []), -22);
    }

    #[test]
    fn a_value_is_the_serving_kernels() {
        let r = Remote { call: through_serve };
        let req = |how: u8, v: u64| {
            let mut b = vec![Value::AsbIndex as u8, how];
            b.extend_from_slice(&v.to_le_bytes());
            b
        };
        let mut o = [0u8; 8];
        // (AsbIndex: this test's alone; the first candidate stays.)
        call(r, op::VALUE, &req(2, 7), &mut o);
        assert_eq!(u64::from_le_bytes(o), 7);
        call(r, op::VALUE, &req(2, 9), &mut o);
        assert_eq!(u64::from_le_bytes(o), 7);
        call(r, op::VALUE, &req(0, 0), &mut o);
        assert_eq!(u64::from_le_bytes(o), 7);
        assert_eq!(serve(op::VALUE, &[3, 0, 0, 0, 0, 0, 0, 0, 0, 0], &mut o), -22);
        assert_eq!(serve(op::VALUE, &[0, 5, 0, 0, 0, 0, 0, 0, 0, 0], &mut o), -22);
        assert_eq!(serve(op::VALUE, &[0, 0], &mut o), -22);
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
