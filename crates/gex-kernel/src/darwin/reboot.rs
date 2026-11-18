//! `reboot(2)` (`bsd/kern/kern_xxx.c`), `reboot_kernel` and `panic_kernel`
//! (`bsd/kern/kern_shutdown.c`), and `host_reboot` (`osfmk/kern/machine.c`),
//! as the 21H461 kernel has them.
//!
//! `reboot` (`0xfffffff007663f84`): `suser` (EPERM, else `ASU`); an
//! `RB_PANIC` message copied in (1024 bytes, `kPanicStringMaxLen`: one
//! with no NUL in them cut to 1023, one that faults replaced by "user
//! space RB_PANIC message copyin failed"); `mac_system_check_reboot`
//! (Sandbox's hook, slot 208 of its operations: `system-reboot`, operation
//! 179, argument kind 0x13 with the flags as a halfword at `+0xd8`;
//! AMFI's and AppleImage4's operations leave the slot NULL); `P_REBOOT`;
//! `reboot_kernel`.
//!
//! `reboot_kernel` (`0xfffffff00763c124`): `RB_PANIC|RB_QUICK` panics at
//! once; else the first shutdown (`system_inshutdown`; a later one is
//! EBUSY unless quick, which goes straight to the end), the platform's
//! shutdown notification (kernel drivers only), a quick one's `sync`
//! (unless `RB_NOSYNC`), or a full one's shutdown of every process and
//! file system (unless `RB_NOSYNC`), `if_down_all`; then `RB_PANIC`
//! panics, the final stage (`final_shutdown_stage`, else EBUSY), and
//! `host_reboot`: `RB_UPSDELAY`'s `PEHaltRestart(kPEUPSDelayHaltCPU)`, else
//! `halt_all_cpus(!(howto & RB_HALT))`.
//!
//! Here: the full shutdown (`proc_shutdown`'s signals and waits, the shutdown
//! log, `vfs_unmountall`, the buffer cache's drain) and the UPS-delayed halt
//! (what the arm platform expert's `haltRestart` does with type 3) are not
//! ported and are reported. `sync` has nothing to push (what a process
//! writes is through to its file), and nothing runs after the machine's
//! end to see the shutdown notification or the interfaces taken down.

use std::sync::atomic::{AtomicBool, Ordering};

use super::machine::{self, caller, Cause, Event, Kind, Panic};
use super::mac::SbArgs;
use crate::errno::Errno;
use crate::syscalls::Kernel;
use crate::GuestMem;

/// The `RB_*` flags (`bsd/sys/reboot.h`).
pub mod rb {
    pub const NOSYNC: u32 = 0x4;
    pub const HALT: u32 = 0x8;
    pub const UPSDELAY: u32 = 0x200;
    pub const QUICK: u32 = 0x400;
    pub const PANIC: u32 = 0x800;
    pub const PANIC_ZPRINT: u32 = 0x1000;
    pub const PANIC_FORCERESET: u32 = 0x2000;
}

/// `HOST_REBOOT_*` (`osfmk/mach/host_reboot.h`).
pub mod host {
    pub const HALT: u32 = 0x8;
    pub const UPSDELAY: u32 = 0x100;
}

/// `kPanicStringMaxLen`.
const PANIC_STRING_MAX: usize = 1024;

/// `system_inshutdown` and `final_shutdown_stage`.
static IN_SHUTDOWN: AtomicBool = AtomicBool::new(false);
static FINAL_STAGE: AtomicBool = AtomicBool::new(false);

/// Where `reboot_kernel` goes for `howto`, given whether a shutdown has
/// begun and reached its final stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// `panic_kernel`.
    Panic,
    /// EBUSY.
    Busy,
    /// A shutdown of every process and file system first (not ported).
    FullShutdown,
    /// `PEHaltRestart(kPEUPSDelayHaltCPU)` (not ported).
    UpsDelay,
    Halt,
    Restart,
}

/// `reboot_kernel`'s course for `howto`.
pub fn plan(howto: u32, in_shutdown: bool, final_stage: bool) -> Step {
    let quick = howto & rb::QUICK != 0;
    if howto & (rb::PANIC | rb::QUICK) == rb::PANIC | rb::QUICK {
        return Step::Panic;
    }
    if in_shutdown && !quick {
        return Step::Busy;
    }
    if !in_shutdown && !quick && howto & rb::NOSYNC == 0 {
        return Step::FullShutdown;
    }
    if howto & rb::PANIC != 0 {
        return Step::Panic;
    }
    if final_stage {
        return Step::Busy;
    }
    if howto & rb::UPSDELAY != 0 {
        return Step::UpsDelay;
    }
    if howto & rb::HALT != 0 {
        Step::Halt
    } else {
        Step::Restart
    }
}

/// `panic_kernel(howto, message)`'s panic: `RB_PANIC_FORCERESET` asks for a
/// paniclog and an immediate reset (`DEBUGGER_OPTION_PANICLOGANDREBOOT`);
/// the message is `userspace panic: %s` of the copied message (none
/// prints nothing, `_doprnt`'s NULL string).
pub fn panic_kernel(howto: u32, message: Option<&[u8]>) -> Panic {
    let mut text = b"userspace panic: ".to_vec();
    text.extend_from_slice(message.unwrap_or(b""));
    let options = if howto & rb::PANIC_FORCERESET != 0 { machine::DEBUGGER_OPTION_PANICLOGANDREBOOT } else { 0 };
    Panic { cpu: machine::CPU, caller: caller::PANIC_KERNEL, options, message: text }
}

impl Kernel {
    fn darwin_machine_event(&self, kind: Kind, cause: Cause) -> Event {
        let n = self.dtask.p_name.0;
        let name = String::from_utf8_lossy(&n[..n.iter().position(|&c| c == 0).unwrap_or(n.len())]).into_owned();
        Event { kind, cause, pid: self.pid, name }
    }

    /// `reboot(opt, msg)`.
    pub(crate) fn darwin_reboot(&mut self, m: &mut GuestMem<'_>, opt: i32, msg: u64) -> Result<u64, Errno> {
        self.darwin_suser()?;
        let howto = opt as u32;
        let message = if howto & rb::PANIC != 0 && msg != 0 {
            Some(match super::exec::copyinstr(m, msg, PANIC_STRING_MAX) {
                Ok(s) => s,
                Err(Errno::ENAMETOOLONG) => m.read(msg, PANIC_STRING_MAX - 1)?.to_vec(),
                Err(_) => b"user space RB_PANIC message copyin failed".to_vec(),
            })
        } else {
            None
        };
        let a = SbArgs { kind: super::sandbox::kind::REBOOT, number: howto & 0xffff, ..Default::default() };
        match self.darwin_sb_evaluate(super::mac::op::SYSTEM_REBOOT, &a) {
            0 => {}
            e => return Err(super::errno::errno_of(e as i32)),
        }
        self.procs.set_reboot(self.pid);
        self.darwin_reboot_kernel(howto, message.as_deref())
    }

    /// `reboot_kernel(howto, message)`: returns only with an error.
    fn darwin_reboot_kernel(&mut self, howto: u32, message: Option<&[u8]>) -> Result<u64, Errno> {
        let step = plan(howto, IN_SHUTDOWN.load(Ordering::Acquire), FINAL_STAGE.load(Ordering::Acquire));
        let cause = Cause::Reboot { howto };
        match step {
            Step::Panic => machine::end(self.darwin_machine_event(Kind::Panic(panic_kernel(howto, message)), cause)),
            Step::Busy => Err(Errno::EBUSY),
            Step::FullShutdown => {
                self.darwin_unimplemented(format!("reboot_kernel's full shutdown for howto {howto:#x} (proc_shutdown's signals and waits, the shutdown log, vfs_unmountall, the buffer cache's drain)"));
                Err(Errno::EINVAL)
            }
            Step::UpsDelay => {
                self.darwin_unimplemented(format!("reboot with RB_UPSDELAY (howto {howto:#x}): the arm platform expert's haltRestart(kPEUPSDelayHaltCPU)"));
                Err(Errno::EINVAL)
            }
            Step::Halt | Step::Restart => {
                IN_SHUTDOWN.store(true, Ordering::Release);
                if FINAL_STAGE.swap(true, Ordering::AcqRel) {
                    return Err(Errno::EBUSY);
                }
                let kind = if step == Step::Halt { Kind::Halt } else { Kind::Restart };
                machine::end(self.darwin_machine_event(kind, cause))
            }
        }
    }

    /// `host_reboot(host_priv, options)` on the host's privileged port:
    /// `HOST_REBOOT_DEBUGGER` is a development kernel's; `UPSDELAY`'s
    /// `PEHaltRestart(kPEUPSDelayHaltCPU)` is not ported (reported, the
    /// routine's KERN_SUCCESS after it); else `halt_all_cpus`, which ends
    /// the machine. Returns only with what is not ported.
    pub(crate) fn darwin_host_reboot(&mut self, options: u32) -> String {
        if options & host::UPSDELAY != 0 {
            return format!("host_reboot with HOST_REBOOT_UPSDELAY (options {options:#x}): the arm platform expert's haltRestart(kPEUPSDelayHaltCPU)");
        }
        let kind = if options & host::HALT != 0 { Kind::Halt } else { Kind::Restart };
        machine::end(self.darwin_machine_event(kind, Cause::HostReboot { options }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_panics_first_and_a_full_shutdown_is_not_ported() {
        assert_eq!(plan(rb::PANIC | rb::QUICK, true, true), Step::Panic);
        assert_eq!(plan(0, false, false), Step::FullShutdown);
        assert_eq!(plan(rb::PANIC, false, false), Step::FullShutdown);
        assert_eq!(plan(rb::PANIC | rb::NOSYNC, false, false), Step::Panic);
        assert_eq!(plan(rb::QUICK, false, false), Step::Restart);
        assert_eq!(plan(rb::QUICK | rb::HALT, false, false), Step::Halt);
        assert_eq!(plan(rb::NOSYNC | rb::HALT, false, false), Step::Halt);
        assert_eq!(plan(rb::QUICK | rb::UPSDELAY, false, false), Step::UpsDelay);
    }

    #[test]
    fn a_second_shutdown_is_busy_but_a_quick_one_goes_to_the_end() {
        assert_eq!(plan(rb::NOSYNC, true, false), Step::Busy);
        assert_eq!(plan(rb::QUICK, true, false), Step::Restart);
        assert_eq!(plan(rb::QUICK, true, true), Step::Busy);
        assert_eq!(plan(rb::QUICK | rb::PANIC, true, true), Step::Panic);
    }

    #[test]
    fn panic_kernel_says_userspace_panic() {
        let p = panic_kernel(rb::PANIC | rb::QUICK, Some(b"boot task failure: fsck - exited due to SIGSYS"));
        assert_eq!(p.message, b"userspace panic: boot task failure: fsck - exited due to SIGSYS".to_vec());
        assert_eq!((p.options, p.caller), (0, caller::PANIC_KERNEL));
        assert_eq!(panic_kernel(rb::PANIC | rb::PANIC_FORCERESET, None).message, b"userspace panic: ".to_vec());
        assert_eq!(panic_kernel(rb::PANIC | rb::PANIC_FORCERESET, None).options, machine::DEBUGGER_OPTION_PANICLOGANDREBOOT);
    }
}
