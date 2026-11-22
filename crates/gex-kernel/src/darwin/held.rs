//! What each process of the page holds of the Darwin system's state that
//! is still its own copy there.
//!
//! Natively one host process holds every task, so a subsystem's statics
//! are the system's: a name one process makes, another finds. In the page
//! each process is a Worker with an instance of this crate of its own
//! ([`super::share`]), so a subsystem that has not moved to the global
//! kernel is one copy per process, and a use that natively reaches what
//! another process made would find this process's own copy instead, and
//! answer differently without saying so. The global kernel keeps a record
//! of which process holds what of each such subsystem (a name it made, a
//! change it made to a system-wide value), and a use that reaches another
//! process's is reported ([`super::super::syscalls::Kernel::darwin_elsewhere`])
//! and fails, where it would have answered differently.
//!
//! Natively (and in the global kernel itself) there is no record: every
//! process's state is the system's, and every function here answers that
//! no other process holds anything.

use std::collections::BTreeMap;
use std::sync::Mutex;

use super::share::{self, op, remote};

/// A subsystem whose state a process of the page holds a part of, and what
/// its key names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Kind {
    /// A Darwin process of the page, keyed by its pid: from its exec until
    /// it is reaped.
    Process = 0,
    /// A POSIX shared memory name ([`super::shm`]), until it is unlinked.
    ShmName = 1,
    /// A POSIX named semaphore's name ([`super::psem`]), until unlinked.
    PsemName = 2,
    /// The persona registry ([`super::persona`]), keyed by nothing: the
    /// process that changed it.
    Personas = 3,
    /// A host special port (`realhost.special[id]`), keyed by its id: the
    /// process that set it.
    HostSpecial = 4,
    /// The host's exception actions (`realhost.exc_actions`), keyed by
    /// nothing: the process that set them.
    HostExc = 5,
    /// A ptmx replica's minor ([`super::ptmx`]), while it is allocated.
    PtyUnit = 6,
    /// A BSD pty's terminal, keyed by its slot, once made (it is never
    /// freed).
    BsdPty = 7,
    /// The console's terminal, keyed by nothing: the process that opened
    /// it.
    Console = 8,
    /// The mount list ([`super::kern`]), keyed by nothing: the process
    /// that changed it.
    Mounts = 10,
    /// A filesystem freeze ([`super::fsfreeze`]), keyed by nothing.
    Freeze = 11,
    /// lo0's inet6 addresses ([`super::inet6`]), keyed by nothing: the
    /// process that changed them.
    Lo0Inet6 = 12,
    /// The system's shutdown ([`super::reboot`]), keyed by nothing.
    Shutdown = 14,
    /// The virtual console's options ([`super::vconsole`]), keyed by
    /// nothing: the process that changed them.
    Vconsole = 15,
    /// An IOKit service's state ([`super::iokit`]), keyed by its place in
    /// the device tree: the process that opened a user client of it.
    IoService = 16,
    /// A vnode's advisory locks ([`super::lockf`]), keyed by the vnode:
    /// the process that holds some.
    FileLocks = 17,
    /// Asynchronous I/O requests not yet returned ([`super::aio`]): a
    /// count.
    Aio = 18,
}

impl Kind {
    fn of(n: u8) -> Option<Kind> {
        Some(match n {
            0 => Kind::Process,
            1 => Kind::ShmName,
            2 => Kind::PsemName,
            3 => Kind::Personas,
            4 => Kind::HostSpecial,
            5 => Kind::HostExc,
            6 => Kind::PtyUnit,
            7 => Kind::BsdPty,
            8 => Kind::Console,
            10 => Kind::Mounts,
            11 => Kind::Freeze,
            12 => Kind::Lo0Inet6,
            14 => Kind::Shutdown,
            15 => Kind::Vconsole,
            16 => Kind::IoService,
            17 => Kind::FileLocks,
            18 => Kind::Aio,
            _ => return None,
        })
    }

    /// When what a process holds of it ends: its own existence when it is
    /// reaped (a zombie is still found); its ptmx replicas (closed with its
    /// descriptors) and its advisory locks (released) when it exits; a
    /// name, or a change to a system-wide value, never (a POSIX shared
    /// memory name stays until it is unlinked, a mount until it is
    /// unmounted, a freeze until it is thawed: none by its maker's end).
    fn ends(self) -> End {
        match self {
            Kind::Process => End::Reap,
            Kind::PtyUnit | Kind::FileLocks => End::Exit,
            _ => End::Never,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum End {
    Exit,
    Reap,
    Never,
}

/// The holder of something more than one process of the page changed
/// ([`touch`]): each has its own copy of it, none the system's.
pub const SEVERAL: i32 = -1;

/// The global kernel's record: each (kind, key) and the process holding it.
static HELD: Mutex<BTreeMap<(Kind, Vec<u8>), i32>> = Mutex::new(BTreeMap::new());

fn held() -> std::sync::MutexGuard<'static, BTreeMap<(Kind, Vec<u8>), i32>> {
    HELD.lock().unwrap_or_else(|e| e.into_inner())
}

/// This instance's process, in the page (where an instance is one
/// process: its pid stays across its execs, and it makes no other).
static ME: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// This instance is process `pid` of the page ([`super::super::syscalls::Kernel::darwin_page_start`]).
pub(crate) fn set_me(pid: i32) {
    ME.store(pid, std::sync::atomic::Ordering::Relaxed);
}

/// This instance's process, for what has no kernel to ask (0 before its
/// first Darwin exec, and natively).
pub(crate) fn me() -> i32 {
    ME.load(std::sync::atomic::Ordering::Relaxed)
}

/// [`elsewhere`] for this instance's process, noted (reported when the
/// call ends) as `what`: whether another process holds it.
pub(crate) fn noted_elsewhere(kind: Kind, key: &[u8], what: impl FnOnce() -> String) -> bool {
    let me = me();
    let Some(h) = (if me > 0 { elsewhere(kind, key, me) } else { None }) else { return false };
    note(what(), h);
    true
}

/// [`claim`] for this instance's process, noted as `what` when another
/// holds it: whether another does.
pub(crate) fn noted_claim(kind: Kind, key: &[u8], what: impl FnOnce() -> String) -> bool {
    let me = me();
    let Some(h) = (if me > 0 { claim(kind, key, me) } else { None }) else { return false };
    note(what(), h);
    true
}

/// [`touch`] for this instance's process: what another process changed of
/// it is now changed by several.
pub(crate) fn touch_mine(kind: Kind, key: &[u8]) {
    let me = me();
    if me > 0 {
        touch(kind, key, me);
    }
}

/// [`let_go`] for this instance's process.
pub(crate) fn let_go_mine(kind: Kind, key: &[u8]) {
    let me = me();
    if me > 0 {
        let_go(kind, key, me);
    }
}

fn note(what: String, h: i32) {
    let who = if h == SEVERAL { "other processes of the page".to_string() } else { format!("process {h} of the page") };
    super::note_unimplemented(format!("{what}, which {who} holds: in the page each process has its own copy of it, not the system's"));
}

fn request(kind: Kind, pid: i32, key: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(5 + key.len());
    b.push(kind as u8);
    b.extend_from_slice(&pid.to_le_bytes());
    b.extend_from_slice(key);
    b
}

fn ask(o: u32, kind: Kind, pid: i32, key: &[u8]) -> i32 {
    let Some(r) = remote() else { return 0 };
    let mut out = [0u8; 4];
    share::call(r, o, &request(kind, pid, key), &mut out);
    i32::from_le_bytes(out)
}

/// The process of the page other than `me` that holds `key` of `kind`, if
/// one does.
pub(crate) fn elsewhere(kind: Kind, key: &[u8], me: i32) -> Option<i32> {
    let h = ask(op::HELD_HOLDER, kind, me, key);
    (h != 0 && h != me).then_some(h)
}

/// `key` of `kind` is `me`'s from now on, unless another process of the
/// page holds it: that process, if one does (and then nothing changes).
pub(crate) fn claim(kind: Kind, key: &[u8], me: i32) -> Option<i32> {
    let h = ask(op::HELD_CLAIM, kind, me, key);
    (h != 0 && h != me).then_some(h)
}

/// `me` changed `key` of `kind`, whether or not another process of the
/// page holds it: that process, if one did (both have changed their own
/// copies from then on, [`SEVERAL`]).
pub(crate) fn touch(kind: Kind, key: &[u8], me: i32) -> Option<i32> {
    let h = ask(op::HELD_TOUCH, kind, me, key);
    (h != 0 && h != me).then_some(h)
}

/// How many `kind` things every process of the page has, after `me`
/// changed its own count by `delta` (0 to ask): counts that end with
/// their process.
pub(crate) fn count(kind: Kind, me: i32, delta: i32) -> Option<i64> {
    let r = remote()?;
    let mut req = request(kind, me, &[]);
    req.extend_from_slice(&delta.to_le_bytes());
    let mut out = [0u8; 8];
    share::call(r, op::HELD_COUNT, &req, &mut out);
    Some(i64::from_le_bytes(out))
}

/// `me` no longer holds `key` of `kind` (nothing changes if another does).
pub(crate) fn let_go(kind: Kind, key: &[u8], me: i32) {
    ask(op::HELD_LET_GO, kind, me, key);
}

/// A process of the page other than `me` that holds anything of `kind`,
/// if one does.
pub(crate) fn any_elsewhere(kind: Kind, me: i32) -> Option<i32> {
    let h = ask(op::HELD_ANY, kind, me, &[]);
    (h != 0).then_some(h)
}

/// Each process's count of a kind ([`count`]).
static COUNTS: Mutex<BTreeMap<(Kind, i32), i64>> = Mutex::new(BTreeMap::new());

fn counts() -> std::sync::MutexGuard<'static, BTreeMap<(Kind, i32), i64>> {
    COUNTS.lock().unwrap_or_else(|e| e.into_inner())
}

/// A call [`super::share::Remote::call`] carried for the record, answered
/// from it: none for a call that is not the record's.
pub(crate) fn serve(o: u32, req: &[u8], out: &mut [u8]) -> Option<i64> {
    const EINVAL: i64 = 22;
    if !matches!(o, op::HELD_CLAIM | op::HELD_HOLDER | op::HELD_LET_GO | op::HELD_ANY | op::HELD_TOUCH | op::HELD_COUNT) {
        return None;
    }
    let (Some(kind), 5.., 4..) = (req.first().and_then(|&n| Kind::of(n)), req.len(), out.len()) else { return Some(-EINVAL) };
    let pid = i32::from_le_bytes(req[1..5].try_into().unwrap());
    // (A read may name no process: one asking what another holds of
    // something it has none of.)
    if pid < 0 || (pid == 0 && !matches!(o, op::HELD_HOLDER | op::HELD_ANY)) {
        return Some(-EINVAL);
    }
    if o == op::HELD_COUNT {
        let (9, 8..) = (req.len(), out.len()) else { return Some(-EINVAL) };
        let delta = i64::from(i32::from_le_bytes(req[5..9].try_into().unwrap()));
        let mut c = counts();
        let mine = c.entry((kind, pid)).or_insert(0);
        *mine += delta;
        if *mine <= 0 {
            c.remove(&(kind, pid));
        }
        let total: i64 = c.iter().filter(|((k, _), _)| *k == kind).map(|(_, &n)| n).sum();
        out[..8].copy_from_slice(&total.to_le_bytes());
        return Some(8);
    }
    let key = req[5..].to_vec();
    let mut t = held();
    let answer = match o {
        op::HELD_CLAIM => *t.entry((kind, key)).or_insert(pid),
        op::HELD_TOUCH => {
            let h = t.entry((kind, key)).or_insert(pid);
            let was = *h;
            if was != pid {
                *h = SEVERAL;
            }
            was
        }
        op::HELD_HOLDER => t.get(&(kind, key)).copied().unwrap_or(0),
        op::HELD_LET_GO => {
            if t.get(&(kind, key.clone())) == Some(&pid) {
                t.remove(&(kind, key));
            }
            0
        }
        _ => t.iter().find(|((k, _), &h)| *k == kind && h != pid).map_or(0, |(_, &h)| h),
    };
    out[..4].copy_from_slice(&answer.to_le_bytes());
    Some(4)
}

/// Process `pid` of the page has exited: what it held that ends at its
/// exit goes, and so do its counts. Called by the global kernel, which
/// holds the record.
pub fn process_exited(pid: i32) {
    held().retain(|(k, _), h| *h != pid || k.ends() != End::Exit);
    counts().retain(|(_, p), _| *p != pid);
}

/// Process `pid` of the page has been reaped: it is no longer one.
pub fn process_reaped(pid: i32) {
    held().retain(|(k, _), h| *h != pid || k.ends() != End::Reap);
}

/// Whether `pid` is a Darwin process of the page: one whose exec made it one and that has not been reaped. Never natively
/// (each process's state there is the system's).
pub(crate) fn darwin_process(pid: i32) -> bool {
    pid > 0 && ask(op::HELD_HOLDER, Kind::Process, 0, &pid.to_le_bytes()) == pid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask_served(o: u32, kind: Kind, pid: i32, key: &[u8]) -> i32 {
        let mut out = [0u8; 4];
        assert_eq!(serve(o, &request(kind, pid, key), &mut out), Some(4));
        i32::from_le_bytes(out)
    }

    #[test]
    fn a_name_is_its_makers_until_let_go() {
        // (keys of this test's own, apart from the other tests')
        let key = b"held-test-name";
        assert_eq!(ask_served(op::HELD_HOLDER, Kind::ShmName, 7001, key), 0);
        assert_eq!(ask_served(op::HELD_CLAIM, Kind::ShmName, 7001, key), 7001);
        assert_eq!(ask_served(op::HELD_HOLDER, Kind::ShmName, 7002, key), 7001);
        // Another kind's key of the same bytes is another thing.
        assert_eq!(ask_served(op::HELD_HOLDER, Kind::PsemName, 7002, key), 0);
        // Only its holder lets it go.
        assert_eq!(ask_served(op::HELD_LET_GO, Kind::ShmName, 7002, key), 0);
        assert_eq!(ask_served(op::HELD_HOLDER, Kind::ShmName, 7002, key), 7001);
        // A claim of what another holds leaves it the other's; its own
        // holder's claim keeps it.
        assert_eq!(ask_served(op::HELD_CLAIM, Kind::ShmName, 7002, key), 7001);
        assert_eq!(ask_served(op::HELD_CLAIM, Kind::ShmName, 7001, key), 7001);
        // A name stays past its maker's end.
        process_exited(7001);
        process_reaped(7001);
        assert_eq!(ask_served(op::HELD_HOLDER, Kind::ShmName, 7002, key), 7001);
        assert_eq!(ask_served(op::HELD_LET_GO, Kind::ShmName, 7001, key), 0);
        assert_eq!(ask_served(op::HELD_HOLDER, Kind::ShmName, 7002, key), 0);
        assert_eq!(ask_served(op::HELD_CLAIM, Kind::ShmName, 7002, key), 7002);
        assert_eq!(ask_served(op::HELD_LET_GO, Kind::ShmName, 7002, key), 0);
    }

    #[test]
    fn a_process_is_held_until_it_ends() {
        let me = 7101i32.to_le_bytes();
        assert_eq!(ask_served(op::HELD_CLAIM, Kind::Process, 7101, &me), 7101);
        assert_eq!(ask_served(op::HELD_ANY, Kind::Process, 7102, &[]), 7101);
        assert_ne!(ask_served(op::HELD_ANY, Kind::Process, 7101, &[]), 7101);
        process_exited(7101);
        assert_eq!(ask_served(op::HELD_ANY, Kind::Process, 7102, &[]), 7101);
        process_reaped(7101);
        assert_ne!(ask_served(op::HELD_ANY, Kind::Process, 7102, &[]), 7101);
    }

    #[test]
    fn a_change_by_several_is_no_ones() {
        let key = b"held-test-touch";
        assert_eq!(ask_served(op::HELD_TOUCH, Kind::Vconsole, 7201, key), 7201);
        assert_eq!(ask_served(op::HELD_TOUCH, Kind::Vconsole, 7201, key), 7201);
        assert_eq!(ask_served(op::HELD_TOUCH, Kind::Vconsole, 7202, key), 7201);
        assert_eq!(ask_served(op::HELD_HOLDER, Kind::Vconsole, 7201, key), SEVERAL);
        assert_eq!(ask_served(op::HELD_HOLDER, Kind::Vconsole, 0, key), SEVERAL);
    }

    fn count_served(kind: Kind, pid: i32, delta: i32) -> i64 {
        let mut req = request(kind, pid, &[]);
        req.extend_from_slice(&delta.to_le_bytes());
        let mut out = [0u8; 8];
        assert_eq!(serve(op::HELD_COUNT, &req, &mut out), Some(8));
        i64::from_le_bytes(out)
    }

    #[test]
    fn a_count_is_every_processs_until_each_ends() {
        // (Kind::Process's counts are this test's alone.)
        assert_eq!(count_served(Kind::Process, 7301, 2), 2);
        assert_eq!(count_served(Kind::Process, 7302, 3), 5);
        assert_eq!(count_served(Kind::Process, 7301, -1), 4);
        process_exited(7302);
        assert_eq!(count_served(Kind::Process, 7301, 0), 1);
        assert_eq!(count_served(Kind::Process, 7301, -1), 0);
    }

    #[test]
    fn a_request_that_is_not_one_is_refused() {
        let mut out = [0u8; 4];
        assert_eq!(serve(op::HELD_CLAIM, &[99, 1, 0, 0, 0], &mut out), Some(-22));
        assert_eq!(serve(op::HELD_CLAIM, &[0, 1, 0, 0], &mut out), Some(-22));
        assert_eq!(serve(op::HELD_CLAIM, &[0, 0, 0, 0, 0], &mut out), Some(-22));
        assert_eq!(serve(op::HELD_COUNT, &[0, 1, 0, 0, 0], &mut [0u8; 8]), Some(-22));
        assert_eq!(serve(op::HELD_CLAIM, &[0, 1, 0, 0, 0], &mut out[..2]), Some(-22));
        assert_eq!(serve(op::NEXT, &[0], &mut out), None);
    }
}
