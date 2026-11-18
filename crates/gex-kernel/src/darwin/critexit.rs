//! `proc_handle_critical_exit` (`bsd/kern/kern_exit.c`), the start of
//! `proc_prepareexit` for a process with a crash behavior or for initproc:
//! whether its end panics the system (`proc_should_trigger_panic`), and the
//! panic's message.
//!
//! As the 21H461 kernel has it (inlined in `proc_prepareexit` at
//! `0xfffffff0076218a4`): no `printf` of the exit before the panic (the
//! RELEASE kernel has neither "pid %d exited" string, nor "panic-on-crash
//! disabled via boot-arg"), `sync`, then `panic_with_options(0, NULL,
//! DEBUGGER_OPTION_INITPROC_PANIC, ...)` with the strings at
//! `0xfffffff007079cd6` on. The exit status it prints is `rv >> 8`, an
//! arithmetic shift (the kernel's own `WEXITSTATUS`, `asr w22, w22, #8`).

use super::machine::{self, caller, Cause, Event, Kind, Panic};
use super::reason::{self, flag, OsReason};
use crate::syscalls::Kernel;

/// `POSIX_SPAWN_PANIC_ON_*` (`bsd/sys/spawn.h`).
pub mod behavior {
    pub const ON_CRASH: u8 = 0x1;
    pub const ON_NON_ZERO_EXIT: u8 = 0x2;
    pub const ON_EXIT: u8 = 0x4;
    pub const ON_SPAWN_FAIL: u8 = 0x8;
}

/// What `proc_should_trigger_panic` reads of the ending process.
#[derive(Clone, Copy, Debug, Default)]
pub struct Facts {
    /// The process is `initproc`.
    pub initproc: bool,
    /// `p_crash_behavior`.
    pub behavior: u8,
    /// `p_crash_behavior_deadline` (`mach_continuous_time`), 0 for none.
    pub deadline: u64,
    /// `p_posix_spawn_failed`.
    pub spawn_failed: bool,
    /// `mach_continuous_time()` now.
    pub now: u64,
    /// The `panic_on_crash_disabled` boot-arg.
    pub disabled: bool,
    /// `p_exit_reason`'s flags, namespace and code.
    pub reason: Option<(u64, u32, u64)>,
}

/// `_proc_is_crashing_signal`: SIGILL, SIGTRAP, SIGABRT, SIGFPE, SIGBUS,
/// SIGSEGV, SIGSYS (the kernel's mask `0x1d70` of signals up to 12).
fn crashing(sig: u32) -> bool {
    sig <= 12 && (1u32 << sig) & 0x1d70 != 0
}

/// `proc_should_trigger_panic(p, rv)` in the compiled order: initproc
/// always; the boot-arg; PANIC_ON_EXIT and PANIC_ON_SPAWN_FAIL; a failed
/// spawn's end never otherwise; an expired deadline never; an exit with a
/// non-zero status under PANIC_ON_NON_ZERO_EXIT (`rv >= 0x100`, unsigned);
/// a stop (`0x7f`, unreachable) always; a death by signal under
/// PANIC_ON_CRASH by a fatal reason's namespace or crashing signal, else
/// by the crashing signal itself.
pub fn should_panic(f: &Facts, rv: u32) -> bool {
    if f.behavior == 0 && !f.initproc {
        return false;
    }
    if f.initproc {
        return true;
    }
    if f.disabled {
        return false;
    }
    if f.behavior & (behavior::ON_EXIT | behavior::ON_SPAWN_FAIL) != 0 {
        return true;
    }
    if f.spawn_failed {
        return false;
    }
    if f.deadline != 0 && f.now > f.deadline {
        return false;
    }
    let sig = rv & 0x7f;
    if sig == 0 {
        return rv >= 0x100 && f.behavior & behavior::ON_NON_ZERO_EXIT != 0;
    }
    if sig == 0x7f {
        return true;
    }
    if f.behavior & behavior::ON_CRASH == 0 {
        return false;
    }
    match f.reason {
        // _proc_is_fatal_reason: an abort is; no crash report is not.
        Some((flags, _, _)) if flags & (flag::ABORT | flag::NO_CRASH_REPORT) == flag::NO_CRASH_REPORT => false,
        Some((_, ns, code)) if ns == reason::ns::SIGNAL => crashing(code as u32),
        Some(_) => true,
        None => crashing(sig),
    }
}

/// What the panic's message names of the process.
pub struct Who<'a> {
    pub initproc: bool,
    /// `initproc_spawned`: launchd said it reached main.
    pub initproc_spawned: bool,
    /// `p_name`, to its NUL.
    pub name: &'a [u8],
    pub pid: i32,
    /// `CS_KILLED` in its code signing flags.
    pub cs_killed: bool,
}

/// `proc_handle_critical_exit`'s message for an end with status `rv`.
pub fn message(who: &Who<'_>, rv: u32, reason: Option<&OsReason>) -> Vec<u8> {
    let prefix: Vec<u8> = if who.initproc {
        if who.name.windows(7).any(|w| w == b"preinit") {
            b"LTE preinit process exited".to_vec()
        } else if who.initproc_spawned {
            b"initproc exited".to_vec()
        } else {
            b"initproc failed to start".to_vec()
        }
    } else {
        // snprintf into 128 bytes.
        let mut p = who.name.to_vec();
        p.extend_from_slice(format!("[{}] exited", who.pid).as_bytes());
        p.truncate(127);
        p
    };
    let cs: &[u8] = if who.cs_killed { b"CS_KILLED" } else { b"" };
    let mut out = Vec::new();
    match reason {
        None => {
            out.extend_from_slice(&prefix);
            out.extend_from_slice(format!(" -- no exit reason available -- (signal {}, exit status {} ", rv & 0x7f, (rv as i32) >> 8).as_bytes());
            out.extend_from_slice(cs);
            out.push(b')');
        }
        Some(r) => {
            out.extend_from_slice(cs);
            out.push(b' ');
            out.extend_from_slice(&prefix);
            out.extend_from_slice(format!(" -- exit reason namespace {} subcode {:#x} description: ", r.namespace as i32, r.code).as_bytes());
            // %.800s
            let d = r.user_desc().unwrap_or(b"none");
            out.extend_from_slice(&d[..d.len().min(800)]);
        }
    }
    out
}

impl Kernel {
    /// `proc_prepareexit`'s first act for an end with status `rv` (XNU's
    /// `W_EXITCODE` encoding): a process spawned with a crash behavior, or
    /// initproc (pid 1 when it is a program, launchd: not the kernel's own
    /// pid 1 a run of another program has), whose end calls for it panics
    /// the system.
    pub(crate) fn darwin_critical_exit(&mut self, rv: u32) {
        let initproc = self.pid == crate::proc::INIT_PID && !self.procs.virtual_init();
        if self.dtask.crash_behavior == 0 && !initproc {
            return;
        }
        let reason = self.procs.exit_reason(self.pid).and_then(|n| reason::of(&n));
        let facts = Facts {
            initproc,
            behavior: self.dtask.crash_behavior,
            deadline: self.dtask.crash_behavior_deadline,
            spawn_failed: self.dtask.spawn_failed,
            now: super::mach::absolute_time(),
            disabled: super::pe::parse_boot_argn("panic_on_crash_disabled").is_some_and(|v| v != 0),
            reason: reason.as_deref().map(|r| (r.flags, r.namespace, r.code)),
        };
        if !should_panic(&facts, rv) {
            return;
        }
        let p_name = self.dtask.p_name.0;
        let name = &p_name[..p_name.iter().position(|&c| c == 0).unwrap_or(p_name.len())];
        let who = Who {
            initproc,
            initproc_spawned: super::kern::initproc_spawned(),
            name,
            pid: self.pid,
            cs_killed: self.dtask.csflags.load(std::sync::atomic::Ordering::Acquire) & super::amfi::cs::KILLED != 0,
        };
        let message = message(&who, rv, reason.as_deref());
        // sync(p, NULL, NULL): what a process writes is through to its
        // file already (the `sync` call's VFS_SYNC has nothing to push).
        machine::end(Event {
            kind: Kind::Panic(Panic { cpu: machine::CPU, caller: caller::CRITICAL_EXIT, options: machine::DEBUGGER_OPTION_INITPROC_PANIC, message }),
            cause: Cause::CriticalExit,
            pid: self.pid,
            name: String::from_utf8_lossy(name).into_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(behavior: u8) -> Facts {
        Facts { behavior, ..Default::default() }
    }

    #[test]
    fn non_zero_exit_panics_only_with_its_flag_and_a_status() {
        let b = f(behavior::ON_NON_ZERO_EXIT);
        assert!(!should_panic(&b, 0));
        assert!(should_panic(&b, 8 << 8));
        assert!(should_panic(&b, 0xffff_ff00), "exit(-1)");
        assert!(!should_panic(&f(behavior::ON_CRASH), 8 << 8));
    }

    #[test]
    fn a_crash_panics_by_its_signal_or_its_reason() {
        let b = f(behavior::ON_CRASH);
        assert!(should_panic(&b, 11));
        assert!(!should_panic(&b, 9) && !should_panic(&b, 15));
        let with = |flags, ns, code| Facts { reason: Some((flags, ns, code)), ..b };
        assert!(!should_panic(&with(0, reason::ns::SIGNAL, 9), 9), "a signal reason's own signal");
        assert!(should_panic(&with(0, reason::ns::SIGNAL, 11), 9));
        assert!(should_panic(&with(0, 7, 1), 6), "another namespace is a crash");
        assert!(!should_panic(&with(flag::NO_CRASH_REPORT, 7, 1), 6));
        assert!(should_panic(&with(flag::NO_CRASH_REPORT | flag::ABORT, 7, 1), 6));
        assert!(should_panic(&with(0, reason::ns::SIGNAL, 0x1_0000_000b), 9), "the code's low word");
        assert!(!should_panic(&with(0, reason::ns::SIGNAL, 0xb_0000_0009), 9), "the code's low word");
    }

    #[test]
    fn exit_and_spawn_fail_panic_first_and_a_deadline_ends_the_rest() {
        assert!(should_panic(&f(behavior::ON_EXIT), 0));
        assert!(should_panic(&Facts { spawn_failed: true, ..f(behavior::ON_SPAWN_FAIL) }, 1));
        assert!(!should_panic(&Facts { spawn_failed: true, ..f(behavior::ON_CRASH) }, 1));
        let late = Facts { deadline: 10, now: 11, ..f(behavior::ON_NON_ZERO_EXIT) };
        assert!(!should_panic(&late, 1 << 8));
        assert!(should_panic(&Facts { now: 10, ..late }, 1 << 8));
        assert!(should_panic(&Facts { deadline: 10, now: 11, ..f(behavior::ON_EXIT) }, 0), "before the deadline's test");
        assert!(!should_panic(&Facts { disabled: true, ..f(behavior::ON_EXIT) }, 0));
        assert!(should_panic(&Facts { initproc: true, disabled: true, ..f(0) }, 0));
    }

    #[test]
    fn messages_are_the_kernels() {
        let who = Who { initproc: false, initproc_spawned: true, name: b"fsck", pid: 5, cs_killed: false };
        assert_eq!(message(&who, 8 << 8, None), b"fsck[5] exited -- no exit reason available -- (signal 0, exit status 8 )".to_vec());
        assert_eq!(message(&who, 0xffff_ff00, None), b"fsck[5] exited -- no exit reason available -- (signal 0, exit status -1 )".to_vec());
        let killed = Who { cs_killed: true, ..who };
        assert_eq!(message(&killed, 9, None), b"fsck[5] exited -- no exit reason available -- (signal 9, exit status 0 CS_KILLED)".to_vec());
        let r = OsReason::with_desc(7, 1, 0, b"boot task failure: fsck\0");
        let init = Who { initproc: true, name: b"launchd", pid: 1, ..who };
        assert_eq!(message(&init, 6, Some(&r)), b" initproc exited -- exit reason namespace 7 subcode 0x1 description: boot task failure: fsck".to_vec());
        let early = Who { initproc_spawned: false, ..init };
        assert_eq!(message(&early, 6, Some(&OsReason::new(2, 11))), b" initproc failed to start -- exit reason namespace 2 subcode 0xb description: none".to_vec());
    }

    #[test]
    fn a_long_description_is_cut_at_800() {
        let mut d = vec![b'x'; 900];
        d.push(0);
        let r = OsReason::with_desc(7, 1, 0, &d);
        let who = Who { initproc: false, initproc_spawned: true, name: b"a", pid: 2, cs_killed: false };
        let m = message(&who, 6, Some(&r));
        assert!(m.ends_with(&[b'x'; 800]) && !m.ends_with(&[b'x'; 801]));
    }
}
