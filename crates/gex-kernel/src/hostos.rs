//! What the native runtime asks of the host's operating system that safe
//! code cannot: the process's ids, where an open descriptor is now, a
//! thread's processor time, whether a process lives, and a thread's name.
//! This crate (and the native host) have no unsafe code, so the calls are
//! hooks: the defaults read Linux's `/proc`, and gexc installs XNU's on
//! macOS before anything runs.

use crate::errno::Errno;
use std::path::PathBuf;
use std::sync::OnceLock;

/// The process's user and group ids, real and effective, and its
/// supplementary groups.
#[derive(Clone, Debug)]
pub struct Ids {
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
    pub groups: Vec<u32>,
}

pub struct Calls {
    /// The process's ids; `None` when the host cannot say.
    pub ids: fn() -> Option<Ids>,
    /// The host path an open descriptor names now, wherever it has been
    /// renamed to: `ENOENT` once it is deleted, `None` when the host cannot
    /// say.
    pub fd_path: fn(fd: i32) -> Option<Result<PathBuf, Errno>>,
    /// This host thread's id, as `thread_cpu_ns` takes it.
    pub thread_id: fn() -> u64,
    /// A host thread's time on a processor, in nanoseconds (`None`: this
    /// thread): user and system together, as Linux's `schedstat` counts it.
    pub thread_cpu_ns: fn(tid: Option<u64>) -> Option<u64>,
    /// Whether a host process `pid` exists.
    pub alive: fn(pid: u32) -> bool,
    /// Name this host thread (what a host's per-thread CPU view shows).
    pub name_thread: fn(name: &str),
}

static CALLS: OnceLock<Calls> = OnceLock::new();

/// Install the host's calls (gexc's, on a host that is not Linux). The
/// first call wins.
pub fn install(calls: Calls) {
    let _ = CALLS.set(calls);
}

pub fn calls() -> &'static Calls {
    CALLS.get().unwrap_or(&LINUX)
}

/// Linux's answers, from `/proc`.
const LINUX: Calls = Calls {
    ids: proc_ids,
    fd_path: proc_fd_path,
    thread_id: proc_thread_id,
    thread_cpu_ns: proc_thread_cpu_ns,
    alive: |pid| std::path::Path::new(&format!("/proc/{pid}")).exists(),
    name_thread: |name| {
        let _ = std::fs::write("/proc/thread-self/comm", name);
    },
};

/// `/proc/self/status`: "Uid:\treal\teffective\tsaved\tfs", Gid the same,
/// and "Groups:" the supplementary ones.
fn proc_ids() -> Option<Ids> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let field = |name: &str| -> Option<Vec<u32>> {
        status.lines().find_map(|l| l.strip_prefix(name)).map(|r| r.split_whitespace().filter_map(|v| v.parse().ok()).collect())
    };
    let (uid, gid) = (field("Uid:")?, field("Gid:")?);
    Some(Ids {
        uid: *uid.first()?,
        euid: *uid.get(1)?,
        gid: *gid.first()?,
        egid: *gid.get(1)?,
        groups: field("Groups:").unwrap_or_default(),
    })
}

/// `/proc/self/fd/<fd>`'s link, which says " (deleted)" after the path once
/// the file is gone.
fn proc_fd_path(fd: i32) -> Option<Result<PathBuf, Errno>> {
    let now = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()?;
    if now.to_str()?.ends_with(" (deleted)") {
        return Some(Err(Errno::ENOENT));
    }
    Some(Ok(now))
}

/// `/proc/thread-self` is `<pid>/task/<tid>`.
fn proc_thread_id() -> u64 {
    std::fs::read_link("/proc/thread-self").ok().and_then(|p| p.file_name()?.to_str()?.parse().ok()).unwrap_or(0)
}

/// A schedstat's first field: time on a processor, in nanoseconds.
fn proc_thread_cpu_ns(tid: Option<u64>) -> Option<u64> {
    let path = match tid {
        None => "/proc/thread-self/schedstat".to_string(),
        Some(tid) => format!("/proc/self/task/{tid}/schedstat"),
    };
    std::fs::read_to_string(path).ok()?.split_whitespace().next()?.parse().ok()
}
