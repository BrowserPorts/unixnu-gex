//! `gexc run` on a Darwin (Mach-O) program, on the Darwin personality.
//!
//! A static program (no `LC_LOAD_DYLINKER`) is mapped as it is and started
//! at its `LC_UNIXTHREAD` pc. A dynamic one starts in dyld, read from the
//! Darwin root (`--sysroot`), with the shared cache mapped where it was
//! linked: the OS cryptex's, at its graft on the Preboot volume (the root's
//! `/System/Cryptexes/OS` is a link to it), or `GEX_DARWIN_CACHE`'s. The system
//! boots with the payload in `GEX_DARWIN_BOOT` (its trust cache bundle,
//! the Sandbox's platform profile).
//!
//! The system's end is the run's: a halt, a restart or a panic
//! (`gex_kernel::darwin::machine`) prints what the console shows of it and
//! gex's account of it on standard error, and gexc exits with its status:
//! [`HALT_STATUS`], [`RESTART_STATUS`] or [`PANIC_STATUS`].

use crate::{choose_mem, report_exit, set_wasm_libs, RunArgs};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use gex_kernel::darwin::machine::{Event, Kind, Panic};

/// gexc's status when the system halts, restarts or panics
/// (`gex_kernel::darwin::machine`'s, which every host's run ends with).
pub use gex_kernel::darwin::machine::{HALT_STATUS, PANIC_STATUS, RESTART_STATUS};

/// The machine's end, as the native host takes it: the console's text (a
/// panic's paniclog line), gex's account of the event, and the run's end
/// with the event's status. Every guest thread ends with this process, as
/// the hardware stops every CPU.
fn machine_end(e: &Event) {
    use std::io::Write;
    let status = e.status();
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(&e.console());
    let _ = writeln!(err, "[gex] {}; gexc exits {status}", e.account());
    if let Kind::Panic(p) = &e.kind {
        let _ = writeln!(err, "[gex] panic options {:#x}; not modelled: {}", p.options, Panic::UNMODELLED);
    }
    let _ = err.flush();
    drop(err);
    std::process::exit(i32::from(status));
}


pub fn run(mut ra: RunArgs, bytes: &[u8]) -> Result<ExitCode> {
    let root = ra.opts.sysroot.clone();
    // The program's path as the guest sees it: inside the root when there
    // is one.
    let guest_path = match &root {
        Some(r) => Path::new(&ra.path).strip_prefix(r).map(|p| format!("/{}", p.display())).unwrap_or_else(|_| ra.path.clone()),
        None => ra.path.clone(),
    };
    // dyld, from the Darwin root.
    let read = |p: &str| -> std::result::Result<Vec<u8>, String> {
        let Some(root) = &root else {
            return Err(format!("{} is a dynamic Darwin program (it names {p}); give the Darwin root with --sysroot", ra.path));
        };
        let host = root.join(p.trim_start_matches('/'));
        std::fs::read(&host).map_err(|e| format!("reading {}: {e}", host.display()))
    };
    let img = gex_kernel::darwin::image::load(bytes, &ra.path, &read).map_err(anyhow::Error::msg)?;
    ra.opts.darwin_platform = img.platform;
    ra.opts.darwin_code_signature = img.code_signature;
    ra.opts.darwin_stacksize = img.stacksize;
    ra.opts.darwin_user_stack = img.user_stack;
    ra.opts.darwin_thread_stack = img.thread_stack;
    ra.opts.darwin_dylinker = img.dylinker;
    ra.opts.darwin_dyld_infos = img.dyld_infos;
    ra.opts.darwin_dyld_infos_size = img.dyld_infos_size;
    if img.program.interp.is_some() {
        let root = root.as_ref().expect("a root for dyld");
        // The cache's path as the guest names it: the OS cryptex's, which
        // the system's graft of the cryptex serves (the kernel reports a
        // graft it cannot make), or GEX_DARWIN_CACHE's file in the root.
        let cache = match std::env::var_os("GEX_DARWIN_CACHE") {
            Some(p) => {
                let p = PathBuf::from(p);
                if !p.exists() {
                    bail!("no shared cache at {} (GEX_DARWIN_CACHE)", p.display());
                }
                let rel = p.strip_prefix(root).with_context(|| format!("the shared cache {} is not in the root {}", p.display(), root.display()))?;
                format!("/{}", rel.display())
            }
            None => gex_kernel::darwin::CACHE_PATH.to_string(),
        };
        ra.opts.darwin_cache = Some(cache);
    }
    let program = img.program;
    let mut argv = vec![ra.argv0.clone().unwrap_or_else(|| guest_path.clone())];
    argv.append(&mut ra.guest_args);
    ra.opts.args = argv;
    ra.opts.exe.get_or_insert(guest_path);
    // launchd boots as the kernel's first process (load_init_program_at_path),
    // whose environment is none (envp NULL); another program gets a shell's.
    if ra.opts.env.is_empty() && ra.opts.exe.as_deref() != Some("/sbin/launchd") {
        ra.opts.env = vec!["PATH=/usr/bin:/bin".into(), "HOME=/var/mobile".into()];
    }
    ra.opts.darwin = true;
    // The boot payload: the trust caches and the Sandbox's platform
    // profile the system boots with.
    ra.opts.darwin_boot = std::env::var_os("GEX_DARWIN_BOOT").map(PathBuf::from);
    ra.opts.darwin_strict = std::env::var("GEX_DARWIN_STRICT").is_ok_and(|v| v == "1");
    // The test embedder's panel: the frames the framebuffer presents,
    // recorded into this directory.
    ra.opts.darwin_frames = std::env::var_os("GEX_DARWIN_FRAMES").map(PathBuf::from);
    // The device's disk0, as its restore made it (gexc darwin-disk0): its
    // Preboot volume holds the Cryptex1.
    ra.opts.darwin_disk0 = std::env::var_os("GEX_DARWIN_DISK0").map(PathBuf::from);
    // Whose Cryptex1 ticket the system boots with (a file, or web-device).
    ra.opts.darwin_cryptex1_ticket = std::env::var("GEX_DARWIN_CRYPTEX1_TICKET").ok();
    // The device's current cryptex1 boot nonce hash, which the ticket's
    // evaluation needs and only the device has.
    ra.opts.darwin_cryptex1_nonce_hash = std::env::var("GEX_DARWIN_CRYPTEX1_NONCE_HASH").ok();
    // The web device's directory (gexc darwin-web-device): the device the
    // system boots as, with GEX_DARWIN_CRYPTEX1_TICKET=web-device.
    ra.opts.darwin_web_device = std::env::var_os("GEX_DARWIN_WEB_DEVICE").filter(|v| !v.is_empty()).map(PathBuf::from);
    // A device's NVRAM namespace image, dumped from it: the NVRAM the
    // system boots with when it is not the web device.
    ra.opts.darwin_nvram = std::env::var_os("GEX_DARWIN_NVRAM").filter(|v| !v.is_empty()).map(PathBuf::from);
    // The Secure Enclave's inputs, which the owner supplies: the sepOS payload decrypted with the
    // SEP's GID key (GEX_DARWIN_SEPOS) and the A10X's SEP ROM (GEX_DARWIN_SEPROM). Without them
    // everything that needs the SEP stops and names what is missing.
    ra.opts.darwin_sepos = std::env::var_os("GEX_DARWIN_SEPOS").filter(|v| !v.is_empty()).map(PathBuf::from);
    ra.opts.darwin_seprom = std::env::var_os("GEX_DARWIN_SEPROM").filter(|v| !v.is_empty()).map(PathBuf::from);
    // Its commpage is folded to its alias at the top of the memory in
    // everything translated for it, which needs the addresses its code
    // builds in registers seen as the constants they are; and its tables
    // are kept inside its page zero (gex_abi::tables64).
    gex_abi::set_commpage_fold(true);
    gex_ir::pass::set_forward_reg_consts(true);
    // dyld rebases and binds its data after its code is translated: no
    // load may be folded to what memory held at translation.
    gex_ir::pass::set_fold_through_memory(false);
    // Each thread's retired instructions are counted in its context, for
    // the kernel's ri_instructions (recount's PMC1), by tier-1 code; the
    // function tiers do not count, so where they run the kernel reports
    // the field as not kept. GEX_NO_INSTRUCTION_COUNT=1 leaves it off too,
    // to price the count.
    let uncounted = std::env::var_os("GEX_NO_INSTRUCTION_COUNT").is_some_and(|v| v != "0");
    gex_abi::set_count_instructions(!(ra.xlate.cgen || ra.xlate.fjit || ra.xlate.no_blocks || uncounted));
    ra.opts.jit = ra.jit;
    // Darwin images live above 4 GiB: always a 64-bit memory.
    if ra.mem64 == Some(false) {
        bail!("--mem32: a Darwin program's images are above 4 GiB");
    }
    ra.mem64 = Some(true);
    choose_mem(&mut ra, true)?;
    set_wasm_libs()?;
    gex_kernel::darwin::machine::set_hook(machine_end);
    let (exit, _stats) = gex_native::run_program(&program, &ra.opts, &ra.xlate)?;
    Ok(report_exit(&exit, ra.opts.verbose))
}
