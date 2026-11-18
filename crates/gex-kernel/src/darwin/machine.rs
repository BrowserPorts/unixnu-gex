//! The machine's end: what the kernel does last when the system halts,
//! restarts or panics, and the event the host is given for it.
//!
//! On the device these are `halt_all_cpus` (`PEHaltRestart(kPEHaltCPU)` or
//! `kPERestartCPU`: the platform expert powers off or resets the SoC, and
//! iBoot runs again for a restart) and `panic_with_options`
//! (`panic_trap_to_debugger`: the other CPUs are stopped, the paniclog is
//! written to the panic region, the platform's panic actions run, and the
//! SoC is reset, iBoot booting again). The 21H461 RELEASE kernel prints
//! nothing of its own on a halt or a restart: `halt_all_cpus`'s "MACH
//! Reboot"/"CPU halted" and `reboot_kernel`'s "syncing disks"/"Quick
//! reboot" are not in its strings (`0xfffffff00733e408` is
//! `PEHaltRestart(reboot != 0)` and a spin). A panic's first paniclog line
//! is `panic(cpu %u caller 0x%lx): ` and the formatted message
//! (`debugger_collect_diagnostics`), on the console too.
//!
//! Here the kernel's part is exact up to the hardware: [`end`] takes the
//! first event (the machine stops there, as the debugger trap stops every
//! other CPU), gives it to the host's hook and parks the calling thread for
//! good. What the host does with it is the hardware's part:
//!
//! - the native host (gexc) prints the console's text and its own account
//!   of the event on standard error, then exits with the event's status
//!   (halt 200, restart 201, panic 202): the run is the machine's power;
//! - a browser host would take the event from the worker that ended the
//!   machine (its hook posts `{kind, howto, panic text}` to the page and
//!   the worker parks in `Atomics.wait`), terminate every guest worker,
//!   keep the panic text where the next boot's panic region would be
//!   (IndexedDB, beside the disk image), and, for a restart or a panic,
//!   boot the machine again from launchd with the same disk (iBoot's part:
//!   the disk, the boot-args and the restored files are unchanged); for a
//!   halt it shows the machine as off. Not built yet.
//!
//! The paniclog's body after the panic line (`do_print_all_backtraces`:
//! the Debugger message, device, boot-args, memory ID, OS and kernel
//! versions, kernelcache and boot session UUIDs, iBoot version, the
//! panicked task and thread with its backtrace, the CPUs' last
//! instructions and the panic stackshot), the panic region's header
//! (`embedded_panic_header`, its CRC), and the platform's panic actions
//! (the NVMe controller's `IOPlatformPanicAction`, which writes the log to
//! its panic log namespace, NS 7) are not modelled: [`Panic::UNMODELLED`]
//! says so with every panic. The kernel writes no NVRAM variable on a
//! panic or a restart (the arm `SavePanicInfo` writes the panic region);
//! the boot-args NVRAM keeps for the next boot are this boot's (none).

use std::sync::{Mutex, OnceLock};

/// `DEBUGGER_OPTION_PANICLOGANDREBOOT`.
pub const DEBUGGER_OPTION_PANICLOGANDREBOOT: u64 = 0x1;
/// `DEBUGGER_OPTION_INITPROC_PANIC`.
pub const DEBUGGER_OPTION_INITPROC_PANIC: u64 = 0x20;

/// The CPU the panicking thread is on: every thread's TPIDRRO_EL0 holds
/// its TSD base with the CPU number bits zero ([`super::set_tsd_base`]),
/// so every thread here is on CPU 0.
pub const CPU: u32 = 0;

/// The return addresses `panic_with_options` takes as its caller
/// (`__builtin_return_address(0)`), unslid, in the 21H461 kernelcache.
pub mod caller {
    /// `proc_handle_critical_exit`'s call, inlined in `proc_prepareexit`
    /// (`bl _panic_with_options` at `0xfffffff0076222a4`).
    pub const CRITICAL_EXIT: u64 = 0xfffffff0_076222a8;
    /// `panic_kernel`'s call (`0xfffffff0078b2f88`).
    pub const PANIC_KERNEL: u64 = 0xfffffff0_078b2f8c;
}

/// What ended the machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `halt_all_cpus(FALSE)`: `PEHaltRestart(kPEHaltCPU)`; and
    /// `PEHaltRestart(kPEUPSDelayHaltCPU)`, which the arm platform expert
    /// halts with the same `PE_halt_restart(kPEHaltCPU)`
    /// ([`super::reboot::host_reboot_kind`]).
    Halt,
    /// `halt_all_cpus(TRUE)`: `PEHaltRestart(kPERestartCPU)`.
    Restart,
    /// `panic_with_options`.
    Panic(Panic),
}

/// The call that ended it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// `reboot(2)` with these `RB_*` flags (`reboot_kernel`).
    Reboot { howto: u32 },
    /// `host_reboot` with these `HOST_REBOOT_*` options.
    HostReboot { options: u32 },
    /// `proc_prepareexit`'s `proc_handle_critical_exit` of an ending
    /// process.
    CriticalExit,
}

/// A panic: where, the options, and the message as `_doprnt` formats it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Panic {
    pub cpu: u32,
    /// The caller, unslid: the kernel slide is not modelled (the device's
    /// paniclog has it slid).
    pub caller: u64,
    pub options: u64,
    pub message: Vec<u8>,
}

impl Panic {
    /// What the paniclog has after the panic line that is not modelled.
    pub const UNMODELLED: &'static str = "the kernel slide (the caller is unslid), the paniclog's body (Debugger message, device and version lines, \
         the panicked task, thread and backtrace, the CPUs' state, the panic stackshot), the panic region's header and CRC, and the \
         NVMe controller's panic action writing the log to its panic log namespace";

    /// The paniclog's first line, as `debugger_collect_diagnostics` writes
    /// it: `panic(cpu %u caller 0x%lx): `, the message, a newline.
    pub fn line(&self) -> Vec<u8> {
        let mut l = format!("panic(cpu {} caller {:#x}): ", self.cpu, self.caller).into_bytes();
        l.extend_from_slice(&self.message);
        l.push(b'\n');
        l
    }
}

/// The machine's end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub kind: Kind,
    pub cause: Cause,
    /// The process whose call it was, and its `p_name`.
    pub pid: i32,
    pub name: String,
}

impl Event {
    /// What the console shows of it: the paniclog's first line for a
    /// panic; nothing for a halt or a restart (see the module's notes).
    pub fn console(&self) -> Vec<u8> {
        match &self.kind {
            Kind::Panic(p) => p.line(),
            Kind::Halt | Kind::Restart => Vec::new(),
        }
    }
}

/// The host's hook for the machine's end.
pub type Hook = fn(&Event);

static HOOK: OnceLock<Hook> = OnceLock::new();
static ENDED: Mutex<Option<Event>> = Mutex::new(None);

/// Give the host's hook (once; false when one is set already).
pub fn set_hook(h: Hook) -> bool {
    HOOK.set(h).is_ok()
}

/// The event that ended the machine, if one has.
pub fn ended() -> Option<Event> {
    ENDED.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// End the machine with `e`: the first end is the machine's (a later one,
/// on another thread, finds the CPUs stopped). The host's hook is given
/// it; without one its console text and a note go to standard error, as
/// the panic must not pass unseen. The calling thread never returns.
pub fn end(e: Event) -> ! {
    let first = {
        let mut g = ENDED.lock().unwrap_or_else(|e| e.into_inner());
        let first = g.is_none();
        if first {
            *g = Some(e.clone());
        }
        first
    };
    if first {
        match HOOK.get() {
            Some(h) => h(&e),
            None => {
                use std::io::Write;
                let mut err = std::io::stderr().lock();
                let _ = err.write_all(&e.console());
                let _ = writeln!(err, "[gex] the machine ended ({:?} by pid {}, {:?}) with no host to take it", e.kind, e.pid, e.cause);
            }
        }
    }
    loop {
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panics_line_is_its_header_and_message() {
        let p = Panic { cpu: 0, caller: caller::PANIC_KERNEL, options: 0, message: b"userspace panic: boot task failure: fsck - exited due to SIGSYS".to_vec() };
        assert_eq!(p.line(), b"panic(cpu 0 caller 0xfffffff0078b2f8c): userspace panic: boot task failure: fsck - exited due to SIGSYS\n".to_vec());
    }

    #[test]
    fn a_halt_or_restart_prints_nothing() {
        let e = Event { kind: Kind::Restart, cause: Cause::Reboot { howto: 0x400 }, pid: 1, name: "launchd".into() };
        assert!(e.console().is_empty());
    }
}
