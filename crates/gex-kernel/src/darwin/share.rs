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
    /// Park the calling thread until `ready` says it may go on: `ready`
    /// asked first, and again each time wait queue `queue` is notified.
    pub park: fn(queue: u32, ready: &mut dyn FnMut() -> bool),
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
    /// The system's IPC table ([`super::super::ipc::wire::take_table`]):
    /// a take's request the taker's pid, how many of the table's losses it
    /// has been told of (4 bytes) and the kernel call it takes it in; its
    /// answer the number of losses recorded (4 bytes), the ones the taker
    /// has not been told of (each a pid and its text), then the table's
    /// bytes (none before the first is given back); `-EAGAIN` while another
    /// holds it, or the answer's length (not taken) when it is longer than
    /// the room given. A give-back's request the giver's pid and the table.
    /// A loss's (`IPC_LOST`, [`super::super::ipc::wire::note_lost`]) the
    /// pid of the process that ended and what it lost.
    pub const IPC_TAKE: u32 = 9;
    pub const IPC_PUT: u32 = 10;
    pub const IPC_LOST: u32 = 11;
    /// One of the system's tables a process takes whole ([`super::Whole`],
    /// [`super::take_whole`]): a take's request the table's number, the
    /// taker's pid, how many of the losses it has been told of (4 bytes)
    /// and the kernel call it takes it in; its answer as the IPC table's
    /// (the losses, then the table's bytes), `-EAGAIN` while another holds
    /// it, or the answer's length (not taken) when it is longer than the
    /// room given. A give-back's request the table's number, the giver's
    /// pid and the table.
    pub const WHOLE_TAKE: u32 = 12;
    pub const WHOLE_PUT: u32 = 13;
    /// The scheduler's state ([`super::super::sched`]): the request one of
    /// its calls and the call's arguments, the answer its result.
    pub const SCHED: u32 = 14;
    /// A process's own record as the system's process table has it
    /// ([`crate::proc::Seed`]): the request its pid, the answer the record,
    /// `-ESRCH` for no such process.
    pub const PROC_SEED: u32 = 15;
    /// The records of the Darwin processes of the page
    /// ([`crate::darwin::procinfo::Public::put_record`]): a put's request
    /// the pid and the record; a get's the pid, its answer whether the
    /// process has exited (a byte) then the record, nothing for none; an
    /// exit's the pid.
    pub const RECORD_PUT: u32 = 54;
    pub const RECORD_GET: u32 = 55;
    pub const RECORD_EXITED: u32 = 56;
    /// A change to another process's own state ([`super::super::change`]):
    /// a post's request the pid and the change, its answer the ticket (8
    /// bytes), `-ESRCH` for a process that has no record or has exited; a
    /// take's the pid, its answer each change pending (its ticket and
    /// bytes); a done's the pid, the ticket and its errno; a state's the
    /// pid and the ticket, its answer 0 pending, 1 and the errno done, 2
    /// gone (the process ended first).
    pub const CHANGE_POST: u32 = 57;
    pub const CHANGE_TAKE: u32 = 58;
    pub const CHANGE_DONE: u32 = 59;
    pub const CHANGE_STATE: u32 = 60;
    /// A process's job state after a change, for its parent's wait
    /// ([`crate::proc::ProcTable::job_set`]): the request the pid, the
    /// change's event (a byte: 0 neither, 1 a stop, 2 a continue) and the
    /// state.
    pub const JOB_SET: u32 = 61;
    /// One look of a Darwin wait ([`crate::proc::ProcTable::darwin_wait_step`]):
    /// the request the parent's pid, the pid waited for, and a byte of
    /// flags (ends 1, stops 2, continues 4, WNOWAIT 8, waitid 16, a look
    /// only that takes nothing 32); the answer a byte for what it found (0
    /// no child, 1 nothing yet, 2 an end, 3 a stop, 4 a continue), then the
    /// pid, the status word or signal, and the end's p_xhighbits or the
    /// continue's p_contproc.
    pub const DWAIT: u32 = 62;
    /// A spawned child's start, where another host than its spawner's
    /// runs it (the page): its request the pid, its spawner's pid and the
    /// result (0 started, its image in place; else the errno its spawner's
    /// call fails with); the spawner's waiters are woken.
    pub const SPAWN_ACK: u32 = 63;
    /// Whether the start of spawned child `pid` is over, for its spawner's
    /// call: the request the pid and a byte (1 take the result, 0 only
    /// look); the answer a byte (0 not yet, 1 a result, 2 the child ended
    /// without one) and the result.
    pub const SPAWN_TAKE: u32 = 64;
    /// A process has exec'd (`P_EXEC`, [`crate::proc::ProcTable::set_execed`]):
    /// the request its pid.
    pub const EXECED: u32 = 65;
    /// Darwin's `setpgid` in the system's table
    /// ([`crate::proc::ProcTable::darwin_setpgid`]): the request the
    /// caller, the pid and the group; the answer its errno (0 for none).
    pub const DSETPGID: u32 = 66;
    /// A spawn's app type, QoS clamp and role on its child's task policy
    /// (`exec_handle_spawnattr_policy`), before the child starts: the
    /// request the pid and the three bytes; the answer 1 when the child's
    /// entry was there.
    pub const SPAWN_POLICY: u32 = 67;
    /// A call on the kernel's APFS container on disk0, which the global
    /// kernel holds for the system ([`super::super::disknode`]): the
    /// request its call, volume slot, the caller's `nanotime` and the
    /// call's arguments; the answer 0 and its result, or 1 and its error.
    pub const NX: u32 = 68;
}

/// Process `pid` has exec'd: the system's table's `P_EXEC`.
pub(crate) fn execed(pid: i32) {
    let Some(r) = remote() else { return };
    call(r, op::EXECED, &pid.to_le_bytes(), &mut []);
}

/// Darwin's `setpgid` by `caller` of `pid` to `pgid`, in the system's
/// table: its errno.
pub(crate) fn darwin_setpgid(caller: i32, pid: i32, pgid: i32) -> Result<(), crate::errno::Errno> {
    let r = remote().expect("a Darwin setpgid through the global kernel");
    let mut req = caller.to_le_bytes().to_vec();
    req.extend_from_slice(&pid.to_le_bytes());
    req.extend_from_slice(&pgid.to_le_bytes());
    let mut o = [0u8; 4];
    call(r, op::DSETPGID, &req, &mut o);
    match i32::from_le_bytes(o) {
        0 => Ok(()),
        e => Err(crate::errno::Errno(e)),
    }
}

/// A spawn's policy attributes on child `pid`'s task policy in the
/// system's table: whether its entry was there.
pub(crate) fn spawn_policy(pid: i32, apptype: u8, clamp: u8, role: u8) -> bool {
    let r = remote().expect("a spawn's policy through the global kernel");
    let mut req = pid.to_le_bytes().to_vec();
    req.extend_from_slice(&[apptype, clamp, role]);
    let mut o = [0u8; 1];
    call(r, op::SPAWN_POLICY, &req, &mut o);
    o[0] == 1
}

/// The spawned children's start results not yet taken by their spawners
/// (where this kernel is the global one).
static SPAWN_ACKS: std::sync::Mutex<std::collections::BTreeMap<i32, i32>> = std::sync::Mutex::new(std::collections::BTreeMap::new());

/// How a spawned child's start in another host ended, as its spawner's
/// call takes it ([`spawn_start`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpawnStart {
    /// Not over yet.
    Pending,
    /// Over: 0, its image in place, or the errno of a start that failed.
    Result(i32),
    /// The child ended before it said (a start that ended in its host),
    /// which ends the spawner's wait as the native host's `ImagePlaced` does.
    Ended,
}

/// Spawned child `pid`'s start is over in the host that runs it: `result`
/// for its spawner's call, its spawner `ppid` woken to take it.
pub fn spawn_started(pid: i32, ppid: i32, result: i32) {
    let r = remote().expect("a spawned child's start through the global kernel");
    let mut req = pid.to_le_bytes().to_vec();
    req.extend_from_slice(&ppid.to_le_bytes());
    req.extend_from_slice(&result.to_le_bytes());
    call(r, op::SPAWN_ACK, &req, &mut []);
}

/// Whether spawned child `pid`'s start is over (`take`: and the result
/// taken).
pub fn spawn_start(pid: i32, take: bool) -> SpawnStart {
    let r = remote().expect("a spawned child's start through the global kernel");
    let mut req = pid.to_le_bytes().to_vec();
    req.push(u8::from(take));
    let mut o = [0u8; 5];
    call(r, op::SPAWN_TAKE, &req, &mut o);
    match o[0] {
        0 => SpawnStart::Pending,
        1 => SpawnStart::Result(i32::from_le_bytes(o[1..5].try_into().unwrap())),
        2 => SpawnStart::Ended,
        k => panic!("gex: the global kernel answered a spawned child's start with {k}"),
    }
}

/// The system's process table, where this kernel is the global one: the
/// one whose jetsam table and scheduler state are the system's (set by
/// the global kernel before it serves a call).
static SYSTEM_PROCS: OnceLock<fn() -> &'static crate::proc::ProcTable> = OnceLock::new();

/// This kernel holds the system's process table, `procs`' (the global
/// kernel's).
pub fn set_system_procs(procs: fn() -> &'static crate::proc::ProcTable) {
    let _ = SYSTEM_PROCS.set(procs);
}

/// The system's process table, where this kernel holds it.
pub(crate) fn system_procs() -> Option<&'static crate::proc::ProcTable> {
    SYSTEM_PROCS.get().map(|f| f())
}

/// What processes of the page lost of the system's state as they ended
/// (each its pid and what it lost), held by the global kernel for every
/// process that takes a table of the system's from then on to report. A
/// process ends holding a table only when it ended inside a kernel call
/// that had taken it, which is gex itself failing there; the table goes
/// on as it was last given back, and what the call changed of it is lost.
static LOST: std::sync::Mutex<Vec<(i32, String)>> = std::sync::Mutex::new(Vec::new());

fn lost() -> std::sync::MutexGuard<'static, Vec<(i32, String)>> {
    LOST.lock().unwrap_or_else(|e| e.into_inner())
}

/// How many of the system's losses this process has reported.
static LOST_SEEN: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Record what process `pid` of the page lost of the system's state as
/// it ended (`what`), for every process that takes one of the system's
/// tables from here on to report: in the global kernel's record, from a
/// process of the page; in this kernel's own where it holds the record.
pub fn note_lost(pid: i32, what: &str) {
    match remote() {
        Some(r) => {
            let mut req = pid.to_le_bytes().to_vec();
            req.extend_from_slice(what.as_bytes());
            let n = (r.call)(op::IPC_LOST, &req, &mut []);
            if n != 0 {
                panic!("gex: the global kernel answered the record of a loss with {n}");
            }
        }
        None => lost().push((pid, what.to_string())),
    }
}

/// The start of a take's answer: how many losses are recorded, then the
/// ones after the first `seen` (each its pid and text).
pub(crate) fn lost_header(seen: usize) -> Vec<u8> {
    use super::ipc::wire::Put;
    let l = lost();
    let mut p = Put::default();
    p.u32(l.len() as u32);
    let new = l.get(seen..).unwrap_or(&[]);
    p.len(new.len());
    for (who, what) in new {
        p.i32(*who);
        p.bytes(what.as_bytes());
    }
    p.0
}

/// A take's request: `head` (the table's number, none for the IPC
/// table's), this process's pid, the losses it has been told of, and the
/// kernel call it takes it in.
pub(crate) fn take_request(head: &[u8], call: &str) -> Vec<u8> {
    let mut req = head.to_vec();
    req.extend_from_slice(&super::held::me().to_le_bytes());
    req.extend_from_slice(&LOST_SEEN.load(std::sync::atomic::Ordering::Relaxed).to_le_bytes());
    req.extend_from_slice(call.as_bytes());
    req
}

/// The losses at the start of a take's answer, read, and the ones this
/// process had not been told of reported (at the call's end): the rest of
/// the answer, the table.
pub(crate) fn report_lost(b: &[u8]) -> &[u8] {
    use super::ipc::wire::{Bad, Get};
    let g = &mut Get::new(b);
    let got = (|| {
        let total = g.u32()?;
        let n = g.len()?;
        let mut new = Vec::with_capacity(n);
        for _ in 0..n {
            let who = g.i32()?;
            new.push((who, String::from_utf8_lossy(&g.bytes()?).into_owned()));
        }
        Ok::<_, Bad>((total, new))
    })();
    let Ok((total, new)) = got else { panic!("gex: the global kernel's record of losses is not one ({got:?})") };
    LOST_SEEN.store(total, std::sync::atomic::Ordering::Relaxed);
    for (who, what) in new {
        super::note_unimplemented(format!("{what} (process {who} of the page)"));
    }
    g.rest()
}

/// Take a table of the system's from the global kernel, parked while
/// another process holds it (`ask` the take's call: its answer's length,
/// `-EAGAIN` while held): its answer.
pub(crate) fn take_parked(r: Remote, what: &str, ask: &mut dyn FnMut(&mut [u8]) -> i64) -> Vec<u8> {
    let q = super::ipc::wire::table_queue();
    let mut got: Option<Vec<u8>> = None;
    let mut out = vec![0u8; 64 << 10];
    let since = super::time::Instant::now();
    (r.park)(q, &mut || loop {
        let n = ask(&mut out);
        if n == -11 {
            // Held, as the native lock waits; a holder that never gives it
            // back is a broken system.
            if since.elapsed() > std::time::Duration::from_secs(120) {
                panic!("gex: {what} has been held for 120 s: a process of the page did not give it back");
            }
            return false;
        }
        if n < 0 {
            panic!("gex: the global kernel answered the take of {what} with {n}");
        }
        let n = n as usize;
        if n > out.len() {
            // Longer than the room: asked again with room for it.
            out = vec![0u8; n];
            continue;
        }
        got = Some(out[..n].to_vec());
        return true;
    });
    got.expect("taken")
}

/// The Darwin processes' records the global kernel holds for the page:
/// each one's bytes and whether it has exited, from its first publication
/// until it is reaped.
static RECORDS: std::sync::Mutex<std::collections::BTreeMap<i32, (Vec<u8>, bool)>> = std::sync::Mutex::new(std::collections::BTreeMap::new());

fn records() -> std::sync::MutexGuard<'static, std::collections::BTreeMap<i32, (Vec<u8>, bool)>> {
    RECORDS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Process `pid`'s record, as it gives it to the global kernel.
pub(crate) fn record_put(pid: i32, b: &[u8]) {
    let Some(r) = remote() else { return };
    let mut req = pid.to_le_bytes().to_vec();
    req.extend_from_slice(b);
    call(r, op::RECORD_PUT, &req, &mut []);
}

/// Process `pid` has exited (`proc_list_exited` holds of its record).
pub(crate) fn record_exited(pid: i32) {
    let Some(r) = remote() else { return };
    call(r, op::RECORD_EXITED, &pid.to_le_bytes(), &mut []);
}

/// Another process of the page's record, and whether it has exited: none
/// for no Darwin process of that pid that has published one (being made,
/// reaped, or not a Darwin process), and none where this kernel's table is
/// the system's.
pub(crate) fn record_get(pid: i32) -> Option<(Vec<u8>, bool)> {
    let r = remote()?;
    let b = call_read(r, op::RECORD_GET, &pid.to_le_bytes());
    let (&exited, rest) = b.split_first()?;
    Some((rest.to_vec(), exited != 0))
}

/// Whether process `pid`'s record here (the global kernel's) carries its
/// `p_ru` (it ended, and stashed it).
pub(crate) fn record_has_usage(pid: i32) -> bool {
    record_usage(pid).0.is_some()
}

/// Process `pid`'s `p_ru` (`p_ru->ri`, `p_ru->ru`), as its record here
/// carries it.
fn record_usage(pid: i32) -> (Option<super::rusage::Record>, Option<super::ru::Ru>) {
    let Some(b) = records().get(&pid).map(|e| e.0.clone()) else { return (None, None) };
    match super::procinfo::Public::of_record(pid, &b).ok().and_then(|p| p.table) {
        Some(f) => (f.exited, f.exited_ru),
        None => (None, None),
    }
}

/// The records' end with their processes: an exit marks it (and ends the
/// changes waiting for it: whether any were), a reap drops it (the global
/// kernel's).
pub fn record_process_exited(pid: i32) -> bool {
    if let Some(e) = records().get_mut(&pid) {
        e.1 = true;
    }
    let mut c = changes();
    let waiting = c.get(&pid).is_some_and(|x| !x.pending.is_empty());
    if let Some(x) = c.get_mut(&pid) {
        x.gone = true;
        x.pending.clear();
    }
    waiting
}

/// Process `pid`'s job state after a change, for the global kernel's entry
/// its parent's wait reads.
pub(crate) fn job_set(pid: i32, j: crate::proc::Job, ev: crate::proc::JobEvent) {
    let Some(r) = remote() else { return };
    let mut p = super::ipc::wire::Put::default();
    p.i32(pid);
    p.u8(match ev {
        crate::proc::JobEvent::Neither => 0,
        crate::proc::JobEvent::Stop => 1,
        crate::proc::JobEvent::Cont => 2,
    });
    j.put(&mut p);
    call(r, op::JOB_SET, &p.0, &mut []);
}

/// One look of a Darwin wait by `ppid` for `want`, in the global kernel's
/// table (`look`: only whether it would answer, taking nothing): what it
/// found, and an ended child's `p_ru` (`p_ru->ri`, `p_ru->ru`) where its
/// record carries one, whether or not the wait collected it.
pub fn dwait(ppid: i32, want: i32, jobs: crate::syscalls::JobWait, nowait: bool, waitid: bool, look: bool) -> (crate::proc::WaitStep, Option<super::rusage::Record>, Option<super::ru::Ru>) {
    use crate::proc::WaitStep;
    let r = remote().expect("a Darwin wait through the global kernel");
    let mut req = ppid.to_le_bytes().to_vec();
    req.extend_from_slice(&want.to_le_bytes());
    let f = u8::from(jobs.exits) | u8::from(jobs.stops) << 1 | u8::from(jobs.continues) << 2 | u8::from(nowait) << 3 | u8::from(waitid) << 4 | u8::from(look) << 5;
    req.push(f);
    let mut o = [0u8; 13 + 1 + 8 * (super::rusage::WORDS + 1) + 1 + 2 * 12 + 14 * 8 + 5];
    let n = call_upto(r, op::DWAIT, &req, &mut o);
    let g = &mut super::ipc::wire::Get::new(&o[..n]);
    let got = (|| {
        let (k, pid, a, b) = (g.u8()?, g.i32()?, g.u32()?, g.u32()?);
        let usage = g.opt(super::rusage::Record::get)?;
        let ru = g.opt(super::ru::Ru::get)?;
        Ok::<_, super::ipc::wire::Bad>((k, pid, a, b, usage, ru))
    })();
    let Ok((k, pid, a, b, usage, ru)) = got else { panic!("gex: the global kernel's Darwin wait answered {got:?}") };
    let step = match k {
        0 => WaitStep::NoChild,
        1 => WaitStep::Nothing,
        2 => WaitStep::Ended { pid, word: a, xhighbits: b as u8 },
        3 => WaitStep::Stopped { pid, xstat: a },
        4 => WaitStep::Continued { pid, xstat: a, contproc: b as i32 },
        k => panic!("gex: the global kernel's Darwin wait answered {k}"),
    };
    (step, usage, ru)
}

/// The changes other processes of the page left for each process: the
/// next ticket, those not yet made, the results of those made, and
/// whether the process has ended.
#[derive(Default)]
struct Changes {
    next: u64,
    pending: Vec<(u64, Vec<u8>)>,
    done: std::collections::BTreeMap<u64, i32>,
    gone: bool,
}

static CHANGES: std::sync::Mutex<std::collections::BTreeMap<i32, Changes>> = std::sync::Mutex::new(std::collections::BTreeMap::new());

fn changes() -> std::sync::MutexGuard<'static, std::collections::BTreeMap<i32, Changes>> {
    CHANGES.lock().unwrap_or_else(|e| e.into_inner())
}

/// Leave change `b` for process `pid`: its ticket, none for a process with
/// no live record.
pub(crate) fn change_post(pid: i32, b: &[u8]) -> Option<u64> {
    let r = remote()?;
    let mut req = pid.to_le_bytes().to_vec();
    req.extend_from_slice(b);
    let mut o = [0u8; 8];
    let n = (r.call)(op::CHANGE_POST, &req, &mut o);
    match n {
        8 => Some(u64::from_le_bytes(o)),
        -3 => None,
        _ => panic!("gex: the global kernel answered a change's post with {n}"),
    }
}

/// The changes left for process `pid` (this one), each with its ticket.
pub(crate) fn change_take(pid: i32) -> Vec<(u64, Vec<u8>)> {
    use super::ipc::wire::Get;
    let Some(r) = remote() else { return Vec::new() };
    let b = call_read(r, op::CHANGE_TAKE, &pid.to_le_bytes());
    let g = &mut Get::new(&b);
    let mut out = Vec::new();
    while !g.done() {
        match (g.u64(), g.bytes()) {
            (Ok(t), Ok(c)) => out.push((t, c)),
            _ => panic!("gex: the global kernel's changes for process {pid} are not a list"),
        }
    }
    out
}

/// Change `ticket` for process `pid` made, with errno `e` (0 for none).
pub(crate) fn change_done(pid: i32, ticket: u64, e: i32) {
    let Some(r) = remote() else { return };
    let mut req = pid.to_le_bytes().to_vec();
    req.extend_from_slice(&ticket.to_le_bytes());
    req.extend_from_slice(&e.to_le_bytes());
    call(r, op::CHANGE_DONE, &req, &mut []);
}

/// Wait for change `ticket` for process `pid` to be made: its errno, none
/// when the process ended first.
pub(crate) fn change_wait(pid: i32, ticket: u64) -> Option<i32> {
    let r = remote().expect("a change through the global kernel");
    let mut req = pid.to_le_bytes().to_vec();
    req.extend_from_slice(&ticket.to_le_bytes());
    let mut got = None;
    let since = super::time::Instant::now();
    (r.park)(super::ipc::wire::table_queue(), &mut || {
        let mut o = [0u8; 5];
        let n = (r.call)(op::CHANGE_STATE, &req, &mut o);
        match (n, o[0]) {
            (1.., 0) => {
                if since.elapsed() > std::time::Duration::from_secs(120) {
                    panic!("gex: process {pid} has not made a change asked of it in 120 s");
                }
                false
            }
            (5, 1) => {
                got = Some(Some(i32::from_le_bytes(o[1..5].try_into().unwrap())));
                true
            }
            (1.., 2) => {
                got = Some(None);
                true
            }
            _ => panic!("gex: the global kernel answered a change's state with {n}"),
        }
    });
    got.expect("waited")
}

pub fn record_process_reaped(pid: i32) {
    records().remove(&pid);
}

/// Process `pid`'s own record as the system's process table has it, for
/// the process itself at its start: none where this kernel's table is the
/// system's.
pub fn proc_seed(pid: i32) -> Option<crate::proc::Seed> {
    let r = remote()?;
    let mut out = [0u8; 512];
    let n = call_upto(r, op::PROC_SEED, &pid.to_le_bytes(), &mut out);
    let g = &mut super::ipc::wire::Get::new(&out[..n]);
    match crate::proc::Seed::get(g) {
        Ok(s) if g.done() => Some(s),
        got => panic!("gex: the global kernel's record of process {pid} is not one ({got:?})"),
    }
}

/// The system's tables, other than the IPC table, that a process of the
/// page takes whole from the global kernel for as long as natively their
/// lock is held, and gives back with what it changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Whole {
    /// The memorystatus state ([`super::memorystatus::Jetsam`]), the
    /// system process table's.
    Jetsam = 0,
    /// The persona registry ([`super::persona`]).
    Personas = 1,
}

impl Whole {
    fn of(n: u8) -> Option<Whole> {
        match n {
            0 => Some(Whole::Jetsam),
            1 => Some(Whole::Personas),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Whole::Jetsam => "the jetsam table",
            Whole::Personas => "the persona registry",
        }
    }
}

/// What a whole table's take found: held by another process, too long for
/// the room given (its length), or its bytes, taken.
pub(crate) enum Taking {
    Held,
    Long(usize),
    Got(Vec<u8>),
}

/// Take table `w` from the global kernel for this process's kernel call
/// (`call` naming it): its bytes, after the losses this process had not
/// been told of are reported. None where this kernel's own is the
/// system's.
pub(crate) fn take_whole(w: Whole, call: &str) -> Option<Vec<u8>> {
    let r = remote()?;
    let req = take_request(&[w as u8], call);
    let b = take_parked(r, w.name(), &mut |out| (r.call)(op::WHOLE_TAKE, &req, out));
    Some(report_lost(&b).to_vec())
}

/// Give table `w` back to the global kernel, and wake the processes
/// waiting for it.
pub(crate) fn give_whole(w: Whole, b: &[u8]) {
    let r = remote().expect("a table taken from the global kernel");
    let mut req = vec![w as u8];
    req.extend_from_slice(&super::held::me().to_le_bytes());
    req.extend_from_slice(b);
    let n = (r.call)(op::WHOLE_PUT, &req, &mut []);
    if n != 0 {
        panic!("gex: the global kernel answered the give-back of {} with {n}", w.name());
    }
    crate::wait::notify(super::ipc::wire::table_queue());
}

/// Process `pid` of the page has exited: a whole table it held (it ended
/// inside a kernel call) is let go as it was last given back, the loss
/// recorded. Whether it held one.
pub(crate) fn whole_exited(pid: i32) -> bool {
    let a = system_procs().is_some_and(|p| super::memorystatus::system_exited(p, pid));
    let b = super::persona::system_exited(pid);
    a || b
}

/// The loss of what process `pid`'s kernel call changed of `what`, which
/// it ended inside, holding it (`call` the call it took it in).
pub(crate) fn lost_in_call(pid: i32, what: &str, call: &str) -> String {
    format!("{what}'s changes made by process {pid}'s {call} (the process ended inside it, holding {what}): lost, the system's being the one it gave back before")
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

/// A park for tests, whose serving kernel is in the same instance: `ready`
/// asked until it says so.
#[cfg(test)]
pub(crate) fn park_by_asking(_queue: u32, ready: &mut dyn FnMut() -> bool) {
    while !ready() {
        std::thread::yield_now();
    }
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
    /// The wait queue a process waiting for the IPC table parks on
    /// ([`super::super::ipc::wire::take_table`]).
    IpcQueue = 3,
    /// The boot's shared region's slide, drawn once
    /// ([`super::super::shregion`]).
    BootRegionSlide = 4,
}

/// The values this kernel holds for the system's: each set or not.
static VALUES: std::sync::Mutex<[Option<u64>; 5]> = std::sync::Mutex::new([None; 5]);

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

/// Value `which` as this kernel holds it for the system (the global
/// kernel's own read): none before it is set.
pub fn local_value(which: Value) -> Option<u64> {
    VALUES.lock().unwrap_or_else(|e| e.into_inner())[which as usize]
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
        op::NX => super::disknode::serve(req, out),
        op::BOOT_PAYLOAD => {
            let (32, 32..) = (req.len(), out.len()) else { return -EINVAL };
            let got = BOOT_DIGEST.get_or_init(|| req.try_into().unwrap());
            out[..32].copy_from_slice(got);
            32
        }
        op::VALUE => {
            let (Some(&which @ (0..=4)), Some(&how @ (0..=4)), 10, 8..) = (req.first(), req.get(1), req.len(), out.len()) else { return -EINVAL };
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
        op::IPC_LOST => {
            let 4.. = req.len() else { return -EINVAL };
            let pid = i32::from_le_bytes(req[..4].try_into().unwrap());
            lost().push((pid, String::from_utf8_lossy(&req[4..]).into_owned()));
            0
        }
        op::WHOLE_TAKE => {
            let (Some(w), 9..) = (req.first().and_then(|&n| Whole::of(n)), req.len()) else { return -EINVAL };
            let pid = i32::from_le_bytes(req[1..5].try_into().unwrap());
            let seen = u32::from_le_bytes(req[5..9].try_into().unwrap()) as usize;
            let call = String::from_utf8_lossy(&req[9..]).into_owned();
            let head = lost_header(seen);
            let room = out.len().saturating_sub(head.len());
            let got = match w {
                Whole::Jetsam => match system_procs() {
                    Some(p) => super::memorystatus::system_take(p, pid, call, room),
                    None => return -ENOSYS,
                },
                Whole::Personas => super::persona::system_take(pid, call, room),
            };
            match got {
                Taking::Held => -11,
                Taking::Long(n) => (head.len() + n) as i64,
                Taking::Got(b) => {
                    out[..head.len()].copy_from_slice(&head);
                    out[head.len()..head.len() + b.len()].copy_from_slice(&b);
                    (head.len() + b.len()) as i64
                }
            }
        }
        op::WHOLE_PUT => {
            let (Some(w), 5..) = (req.first().and_then(|&n| Whole::of(n)), req.len()) else { return -EINVAL };
            let pid = i32::from_le_bytes(req[1..5].try_into().unwrap());
            let r = match w {
                Whole::Jetsam => match system_procs() {
                    Some(p) => super::memorystatus::system_put(p, pid, &req[5..]),
                    None => return -ENOSYS,
                },
                Whole::Personas => super::persona::system_put(pid, &req[5..]),
            };
            match r {
                Ok(()) => 0,
                Err(e) => -e,
            }
        }
        op::JOB_SET => {
            let (Some(p), 5..) = (system_procs(), req.len()) else { return -EINVAL };
            let pid = i32::from_le_bytes(req[..4].try_into().unwrap());
            let ev = match req[4] {
                0 => crate::proc::JobEvent::Neither,
                1 => crate::proc::JobEvent::Stop,
                2 => crate::proc::JobEvent::Cont,
                _ => return -EINVAL,
            };
            let g = &mut super::ipc::wire::Get::new(&req[5..]);
            let Ok(j) = crate::proc::Job::get(g) else { return -EINVAL };
            p.job_set(pid, j, ev);
            0
        }
        op::DWAIT => {
            use crate::proc::WaitStep;
            let (Some(p), 9) = (system_procs(), req.len()) else { return -EINVAL };
            let ppid = i32::from_le_bytes(req[..4].try_into().unwrap());
            let want = i32::from_le_bytes(req[4..8].try_into().unwrap());
            let f = req[8];
            let jobs = crate::syscalls::JobWait { exits: f & 1 != 0, stops: f & 2 != 0, continues: f & 4 != 0 };
            let (nowait, look) = (f & 8 != 0, f & 32 != 0);
            let step = p.darwin_wait_step(ppid, want, jobs, nowait, f & 16 != 0, look);
            // An ended child: its p_ru for its parent's wait4 to copy and,
            // once collected, its parent's children's usage
            // (reap_child_locked's ruadd and update_rusage_info_child, which
            // the parent makes in its own record); collected, it is no
            // longer one of the page's processes.
            let (mut usage, mut ru) = (None, None);
            if let WaitStep::Ended { pid, .. } = step {
                (usage, ru) = record_usage(pid);
                if !nowait && !look {
                    super::held::process_reaped(pid);
                }
            }
            let (k, pid, a, b) = match step {
                WaitStep::NoChild => (0u8, 0, 0, 0),
                WaitStep::Nothing => (1, 0, 0, 0),
                WaitStep::Ended { pid, word, xhighbits } => (2, pid, word, u32::from(xhighbits)),
                WaitStep::Stopped { pid, xstat } => (3, pid, xstat, 0),
                WaitStep::Continued { pid, contproc, xstat } => (4, pid, xstat, contproc as u32),
            };
            let mut p = super::ipc::wire::Put::default();
            p.u8(k);
            p.i32(pid);
            p.u32(a);
            p.u32(b);
            p.opt(usage.as_ref(), |p, r| r.put(p));
            p.opt(ru.as_ref(), |p, r| r.put(p));
            if p.0.len() > out.len() {
                return -EINVAL;
            }
            out[..p.0.len()].copy_from_slice(&p.0);
            p.0.len() as i64
        }
        op::EXECED => {
            let (Some(p), 4) = (system_procs(), req.len()) else { return -EINVAL };
            p.set_execed(i32::from_le_bytes(req[..4].try_into().unwrap()));
            0
        }
        op::DSETPGID => {
            let (Some(p), 12, 4..) = (system_procs(), req.len(), out.len()) else { return -EINVAL };
            let w = |i: usize| i32::from_le_bytes(req[i * 4..i * 4 + 4].try_into().unwrap());
            let e = match p.darwin_setpgid(w(0), w(1), w(2)) {
                Ok(()) => 0,
                Err(e) => e.0,
            };
            out[..4].copy_from_slice(&e.to_le_bytes());
            4
        }
        op::SPAWN_POLICY => {
            let (Some(p), 7, 1..) = (system_procs(), req.len(), out.len()) else { return -EINVAL };
            let pid = i32::from_le_bytes(req[..4].try_into().unwrap());
            out[0] = match p.task_policy(pid) {
                Some(cell) => {
                    cell.lock().unwrap_or_else(|e| e.into_inner()).spawnpolicy(req[4], req[5], req[6]);
                    1
                }
                None => 0,
            };
            1
        }
        op::SPAWN_ACK => {
            let (Some(p), 12) = (system_procs(), req.len()) else { return -EINVAL };
            let w = |i: usize| i32::from_le_bytes(req[i * 4..i * 4 + 4].try_into().unwrap());
            SPAWN_ACKS.lock().unwrap_or_else(|e| e.into_inner()).insert(w(0), w(2));
            p.wake(w(1));
            0
        }
        op::SPAWN_TAKE => {
            let (Some(p), 5, 5..) = (system_procs(), req.len(), out.len()) else { return -EINVAL };
            let pid = i32::from_le_bytes(req[..4].try_into().unwrap());
            let mut acks = SPAWN_ACKS.lock().unwrap_or_else(|e| e.into_inner());
            let got = if req[4] != 0 { acks.remove(&pid) } else { acks.get(&pid).copied() };
            drop(acks);
            let (k, v) = match got {
                Some(v) => (1u8, v),
                // Gone from the table, or ended there, with nothing said.
                None if p.handle(pid).is_none_or(|c| c.status.lock().map_or(true, |s| s.is_some())) => (2, 0),
                None => (0, 0),
            };
            out[0] = k;
            out[1..5].copy_from_slice(&v.to_le_bytes());
            5
        }
        op::CHANGE_POST => {
            let 4.. = req.len() else { return -EINVAL };
            let pid = i32::from_le_bytes(req[..4].try_into().unwrap());
            if !records().get(&pid).is_some_and(|(_, exited)| !exited) {
                return -3;
            }
            let mut c = changes();
            let x = c.entry(pid).or_default();
            x.next += 1;
            x.gone = false;
            let t = x.next;
            x.pending.push((t, req[4..].to_vec()));
            let 8.. = out.len() else { return -EINVAL };
            out[..8].copy_from_slice(&t.to_le_bytes());
            8
        }
        op::CHANGE_TAKE => {
            let 4 = req.len() else { return -EINVAL };
            let pid = i32::from_le_bytes(req.try_into().unwrap());
            let mut c = changes();
            let Some(x) = c.get_mut(&pid) else { return 0 };
            let mut p = super::ipc::wire::Put::default();
            for (t, b) in &x.pending {
                p.u64(*t);
                p.bytes(b);
            }
            if p.0.len() <= out.len() {
                out[..p.0.len()].copy_from_slice(&p.0);
                x.pending.clear();
            }
            p.0.len() as i64
        }
        op::CHANGE_DONE => {
            let 16 = req.len() else { return -EINVAL };
            let pid = i32::from_le_bytes(req[..4].try_into().unwrap());
            let t = u64::from_le_bytes(req[4..12].try_into().unwrap());
            let e = i32::from_le_bytes(req[12..16].try_into().unwrap());
            changes().entry(pid).or_default().done.insert(t, e);
            0
        }
        op::CHANGE_STATE => {
            let (12, 5..) = (req.len(), out.len()) else { return -EINVAL };
            let pid = i32::from_le_bytes(req[..4].try_into().unwrap());
            let t = u64::from_le_bytes(req[4..12].try_into().unwrap());
            let mut c = changes();
            let Some(x) = c.get_mut(&pid) else { return -EINVAL };
            if let Some(e) = x.done.remove(&t) {
                out[0] = 1;
                out[1..5].copy_from_slice(&e.to_le_bytes());
                return 5;
            }
            out[0] = if x.gone { 2 } else { 0 };
            1
        }
        op::RECORD_PUT => {
            let 4.. = req.len() else { return -EINVAL };
            let pid = i32::from_le_bytes(req[..4].try_into().unwrap());
            let mut t = records();
            let e = t.entry(pid).or_insert((Vec::new(), false));
            e.0 = req[4..].to_vec();
            0
        }
        op::RECORD_EXITED => {
            let 4 = req.len() else { return -EINVAL };
            record_process_exited(i32::from_le_bytes(req.try_into().unwrap()));
            0
        }
        op::RECORD_GET => {
            let 4 = req.len() else { return -EINVAL };
            let t = records();
            let Some((b, exited)) = t.get(&i32::from_le_bytes(req.try_into().unwrap())) else { return 0 };
            let n = 1 + b.len();
            if n <= out.len() {
                out[0] = u8::from(*exited);
                out[1..n].copy_from_slice(b);
            }
            n as i64
        }
        op::PROC_SEED => {
            let (Some(p), 4) = (system_procs(), req.len()) else { return -EINVAL };
            let Some(s) = p.seed_of(i32::from_le_bytes(req.try_into().unwrap())) else { return -3 };
            let mut b = super::ipc::wire::Put::default();
            s.put(&mut b);
            if b.0.len() > out.len() {
                return -EINVAL;
            }
            out[..b.0.len()].copy_from_slice(&b.0);
            b.0.len() as i64
        }
        op::SCHED => match system_procs() {
            Some(p) => super::sched::serve(&p.sched, req, out),
            None => -ENOSYS,
        },
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
        let r = Remote { call: through_serve, park: park_by_asking };
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
        let r = Remote { call: through_serve, park: park_by_asking };
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
        let r = Remote { call: through_serve, park: park_by_asking };
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
        assert_eq!(call_read(Remote { call: long_answer, park: park_by_asking }, op::SYSTEM_STRING, &[0]), want);
        assert_eq!(serve(op::SYSTEM_STRING, &[2], &mut []), -22);
        assert_eq!(serve(op::SYSTEM_STRING, &[0, 1], &mut []), -22);
    }

    #[test]
    fn a_value_is_the_serving_kernels() {
        let r = Remote { call: through_serve, park: park_by_asking };
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
        assert_eq!(serve(op::VALUE, &[5, 0, 0, 0, 0, 0, 0, 0, 0, 0], &mut o), -22);
        assert_eq!(serve(op::VALUE, &[0, 5, 0, 0, 0, 0, 0, 0, 0, 0], &mut o), -22);
        assert_eq!(serve(op::VALUE, &[0, 0], &mut o), -22);
        // The boot region's slide: the first process's draw is every
        // process's.
        let slide = |v: u64| {
            let mut b = vec![Value::BootRegionSlide as u8, 2];
            b.extend_from_slice(&v.to_le_bytes());
            let mut o = [0u8; 8];
            call(r, op::VALUE, &b, &mut o);
            u64::from_le_bytes(o)
        };
        assert_eq!(slide(0x1234000), 0x1234000);
        assert_eq!(slide(0x8000), 0x1234000);
    }

    #[test]
    fn a_change_waits_for_its_process_and_ends_with_it() {
        let pid: i32 = 8801;
        let post = |b: &[u8]| {
            let mut req = pid.to_le_bytes().to_vec();
            req.extend_from_slice(b);
            let mut o = [0u8; 8];
            (serve(op::CHANGE_POST, &req, &mut o), u64::from_le_bytes(o))
        };
        let state = |t: u64| {
            let mut req = pid.to_le_bytes().to_vec();
            req.extend_from_slice(&t.to_le_bytes());
            let mut o = [0u8; 5];
            let n = serve(op::CHANGE_STATE, &req, &mut o);
            (n, o)
        };
        // No record: no process to change.
        assert_eq!(post(&[1]).0, -3);
        let mut req = pid.to_le_bytes().to_vec();
        req.extend_from_slice(&[7, 7]);
        assert_eq!(serve(op::RECORD_PUT, &req, &mut []), 0);
        let (n, t) = post(&[5]);
        assert_eq!(n, 8);
        assert_eq!(state(t), (1, [0, 0, 0, 0, 0]));
        let mut out = [0u8; 64];
        let n = serve(op::CHANGE_TAKE, &pid.to_le_bytes(), &mut out) as usize;
        let g = &mut super::super::ipc::wire::Get::new(&out[..n]);
        assert_eq!((g.u64().unwrap(), g.bytes().unwrap()), (t, vec![5]));
        assert_eq!(serve(op::CHANGE_TAKE, &pid.to_le_bytes(), &mut out), 0);
        let mut done = pid.to_le_bytes().to_vec();
        done.extend_from_slice(&t.to_le_bytes());
        done.extend_from_slice(&1i32.to_le_bytes());
        assert_eq!(serve(op::CHANGE_DONE, &done, &mut []), 0);
        assert_eq!(state(t), (5, [1, 1, 0, 0, 0]));
        // One pending when the process ends: gone, and the exit says so.
        let (_, t2) = post(&[6]);
        assert!(record_process_exited(pid));
        assert_eq!(state(t2), (1, [2, 0, 0, 0, 0]));
        assert_eq!(post(&[6]).0, -3);
        record_process_reaped(pid);
    }

    #[test]
    fn every_call_has_a_number_of_its_own() {
        let mut all = vec![op::NEXT, op::ORIGIN, op::SYSTEM_STRING, op::TC_SET_STATIC, op::TC_QUERY, op::TC_HAS_UUID, op::TC_LOAD, op::TC_BOOT_LOADED, op::TC_MARK_LOADED, op::CO_FORK, op::CO_ADOPT_CORPSE, op::CO_EXEC, op::CO_MEMBERSHIP, op::CO_THREAD_GROUP, op::CO_PRIVILEGED, op::CO_LEADER, op::CO_TASK_TERMINATED, op::CO_ACTIVATE, op::CO_RELEASE, op::CO_PLACE, op::CO_LIST, op::CO_CREATE, op::CO_TERMINATE, op::CO_KIND, op::CO_SET_NAME, op::HELD_CLAIM, op::HELD_HOLDER, op::HELD_LET_GO, op::HELD_ANY, op::HELD_TOUCH, op::HELD_COUNT, op::VALUE, op::BOOT_PAYLOAD, op::DEV_TIMES, op::MAILBOX_PUT, op::MAILBOX_TAKE, op::IPC_TAKE, op::IPC_PUT, op::IPC_LOST, op::WHOLE_TAKE, op::WHOLE_PUT, op::SCHED, op::PROC_SEED, op::RECORD_PUT, op::RECORD_GET, op::RECORD_EXITED, op::CHANGE_POST, op::CHANGE_TAKE, op::CHANGE_DONE, op::CHANGE_STATE, op::JOB_SET, op::DWAIT, op::SPAWN_ACK, op::SPAWN_TAKE, op::EXECED, op::DSETPGID, op::SPAWN_POLICY, op::NX];
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), n, "two of the channel's calls share a number");
    }

    /// A page process's Darwin setpgid, P_EXEC and a spawn's policy
    /// attributes, served on the system's table: the group set there as
    /// setpgid sets it (and refused for a child that has exec'd), the
    /// child's entry marked exec'd, its task policy given the attributes;
    /// a child the table does not have is said to be missing.
    #[test]
    fn a_page_process_s_setpgid_exec_and_spawn_policy_are_the_system_table_s() {
        use crate::proc::{ProcTable, INIT_PID};
        static TABLE: OnceLock<ProcTable> = OnceLock::new();
        fn table() -> &'static ProcTable {
            TABLE.get_or_init(ProcTable::new)
        }
        set_system_procs(table);
        let t = system_procs().expect("the system's table");
        let sh = t.spawn(INIT_PID);
        t.setsid(sh).unwrap();
        let c = t.spawn(sh);
        let req = |a: i32, b: i32, g: i32| [a.to_le_bytes(), b.to_le_bytes(), g.to_le_bytes()].concat();
        let mut o = [0u8; 4];
        assert_eq!(serve(op::DSETPGID, &req(sh, c, c), &mut o), 4);
        assert_eq!(i32::from_le_bytes(o), 0);
        assert_eq!(t.pgid(INIT_PID, c), Ok(c));
        assert_eq!(serve(op::EXECED, &c.to_le_bytes(), &mut []), 0);
        assert!(t.execed(c));
        assert_eq!(serve(op::DSETPGID, &req(sh, c, sh), &mut o), 4);
        assert_eq!(crate::errno::Errno(i32::from_le_bytes(o)), crate::errno::Errno::EACCES);
        let mut f = [0u8; 1];
        let mut pol = c.to_le_bytes().to_vec();
        pol.extend_from_slice(&[super::super::taskpolicy::apptype::DAEMON_STANDARD, 0, 0]);
        assert_eq!(serve(op::SPAWN_POLICY, &pol, &mut f), 1);
        assert_eq!(f[0], 1);
        let mut missing = 9999i32.to_le_bytes().to_vec();
        missing.extend_from_slice(&[super::super::taskpolicy::apptype::DAEMON_STANDARD, 0, 0]);
        assert_eq!(serve(op::SPAWN_POLICY, &missing, &mut f), 1);
        assert_eq!(f[0], 0);
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
