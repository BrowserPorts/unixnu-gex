//! The Secure Enclave: a second processor behind the mailbox AppleSEPManager
//! uses on the J120, running the real sepOS.
//!
//! The AP's side is ported from the kernelcache: the mailbox block
//! ([`akf`], AppleA7IOPV2's [`a7iop`]), the messages ([`frame`]), the
//! manager with its boot handshake and endpoints ([`manager`]), the shared
//! memory it hands the SEP ([`mem`], [`shm`]) and the user client
//! ([`userclient`]). The SEP's side is the real sepOS and SEP ROM: what the
//! owner supplies ([`image`], [`core`]) and the web device's own UID
//! ([`secrets`]). No reply of the SEP's is made here; what is missing
//! fails loudly and is named.

pub mod a7iop;
pub mod akf;
pub mod core;
pub mod frame;
pub mod hw;
pub mod image;
pub mod manager;
pub mod mem;
pub mod registry;
pub mod secrets;
pub mod shm;
pub mod userclient;

use super::iokit::{self, Node};
use hw::Hw;
use manager::{Config, Manager, MgrError};
use std::sync::{Arc, Mutex, OnceLock};

static INPUTS: OnceLock<core::Inputs> = OnceLock::new();

/// What the run was given of the SEP's inputs, once at boot.
pub fn set_inputs(i: core::Inputs) -> Result<(), String> {
    INPUTS.set(i).map_err(|_| "the SEP's inputs are set already".to_string())
}

/// The SEP's inputs: none when the run set none.
pub fn inputs() -> core::Inputs {
    INPUTS.get().cloned().unwrap_or_default()
}

/// The device tree's account of the `sep` node, which sets the manager up
/// (`AppleSEPManager::start` and the A7IOP's reads, 01 and 03 of the
/// specification): what it has and does not have.
pub fn manager_config(t: &[Node]) -> Config {
    let sep = "IODeviceTree:/arm-io/sep";
    let nub = "IODeviceTree:/arm-io/sep/iop-sep-nub";
    let has = |name: &str| iokit::dt_prop(t, sep, name).is_some() || iokit::dt_prop(t, nub, name).is_some();
    let mut c = Config::default();
    c.sep_page = if has("aarch64") { shm::SEP_PAGE_AARCH64 } else { shm::SEP_PAGE };
    c.sepfw_loaded = has("sepfw-loaded");
    c.sepfw_booted = has("sepfw-booted");
    c.has_art = has("has-art");
    c.ap_manifest = has("ap-manifest");
    c.has_xart = iokit::dt_has(t, "IODeviceTree:/arm-io/sep/iop-sep-nub/xART");
    if let Some(n) = iokit::dt_prop(t, nub, "rom-panic-bytes").and_then(|v| v.get(..4)) {
        c.rom_panic_words = u32::from_le_bytes(n.try_into().unwrap()) as usize / 8;
    }
    if let Some(n) = iokit::dt_prop(t, "IODeviceTree:/defaults", "sep-size").and_then(|v| v.get(..4)) {
        c.sepfw_len = u32::from_le_bytes(n.try_into().unwrap()) as usize;
    }
    c
}

/// The run's SEP: the mailbox, the manager and the threads that serve it.
pub struct Sep {
    pub mgr: Arc<Manager>,
    pub hw: Arc<Hw>,
    pub mem: mem::SepMem,
    /// The gigalocker file the user client's selector 44 named.
    pub gigalocker: Mutex<Option<String>>,
    _doorbell: std::thread::JoinHandle<()>,
    _core: std::thread::JoinHandle<()>,
}

static SYSTEM: OnceLock<Result<Sep, MgrError>> = OnceLock::new();

/// Whether the manager has set `sep-booted` (`_bootSEP` does, at each boot
/// attempt; `start` sets it false).
pub fn booted() -> bool {
    SYSTEM.get().and_then(|r| r.as_ref().ok()).is_some_and(|s| s.mgr.booted_property())
}

/// The SEP of this run, made the first time it is asked for: the manager
/// started over the device tree's account, the SEP ROM started
/// (`startCPU`), the harness waiting to release the core.
pub fn system(t: &[Node]) -> Result<&'static Sep, MgrError> {
    SYSTEM
        .get_or_init(|| {
            let hw = Hw::new();
            let mem = mem::SepMem::new();
            let cfg = manager_config(t);
            let mgr = Manager::new(cfg, Arc::clone(&hw), mem.clone())?;
            let doorbell = mgr.spawn_doorbell();
            let arch = core::Arch::of_device_tree(iokit::dt_prop(t, "IODeviceTree:/arm-io/sep", "aarch64").is_some());
            let (h, m) = (Arc::clone(&hw), Arc::clone(&mgr));
            let core = std::thread::Builder::new()
                .name("SEP core".into())
                .spawn(move || {
                    // The core is held until the AP releases it (CPU_CTRL's run bit), then
                    // the harness finds what it needs: when it cannot run, every wait of the
                    // AP's ends with what is missing.
                    loop {
                        if h.wait_until(std::time::Duration::from_secs(3600), |_, r| r.running) {
                            m.core_gone(core::release(&inputs(), arch).to_string());
                            return;
                        }
                        if h.is_closed() {
                            return;
                        }
                    }
                })
                .expect("the SEP core thread");
            mgr.power_on()?;
            Ok(Sep { mgr, hw, mem, gigalocker: Mutex::new(None), _doorbell: doorbell, _core: core })
        })
        .as_ref()
        .map_err(Clone::clone)
}
