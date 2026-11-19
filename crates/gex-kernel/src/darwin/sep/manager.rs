//! AppleSEPManager, the AP's side of the Secure Enclave: its state machine,
//! the doorbell that routes the SEP's messages, the control and discovery
//! endpoints, the SEP ROM's boot protocol (`AppleSEPBooter`) and the load of
//! the sepOS (`AppleSEPFirmware`), ported from the 21H461 kernelcache
//! (`drafts/sep/02-transport.md`, `03-boot-handshake.md`, `04-userclient-idp.md`;
//! `K` is a kernelcache vm address in AppleSEPManager).
//!
//! Everything below the mailbox is the SEP's: no reply the SEP ROM or the
//! sepOS would give is made here. A request nothing answers waits as the
//! kernel does and fails as the kernel does (a kernel panic is
//! [`MgrError::Panic`], a timeout an IOReturn); when the SEP core cannot
//! exist at all (no sepOS, no SEP ROM, no AArch32 core) the wait ends at
//! once with [`MgrError::CoreGone`], which says what is missing.
//!
//! What is not ported fails loudly ([`MgrError::Unimplemented`]): the
//! endpoint services other than control and discovery (logger, xART, ART,
//! keystore, hilo, debug, testing, pairing), sleep, nap and wake, the ART,
//! the TBM patch pieces (which the kernel itself cannot use without an
//! IOMapper), the iBIC key capture of development kernels, the trace and
//! core-dump buffers.

use super::a7iop::{A7iop, IopError};
use super::frame::{self, ep, rom, Message};
use super::hw::Hw;
use super::mem::SepMem;
use super::shm::{self, SharedMemory};
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

/// IOReturn codes the manager returns.
pub mod io {
    pub const BAD_ARGUMENT: i32 = 0xe00002c2_u32 as i32;
    pub const UNSUPPORTED: i32 = 0xe00002c7_u32 as i32;
    pub const BUSY: i32 = 0xe00002d5_u32 as i32;
    pub const TIMEOUT: i32 = 0xe00002d6_u32 as i32;
    pub const NOT_READY: i32 = 0xe00002d8_u32 as i32;
    pub const ERROR: i32 = 0xe00002bc_u32 as i32;
    pub const ABORTED: i32 = 0xe00002eb_u32 as i32;
    pub const DEVICE_ERROR: i32 = 0xe00002e9_u32 as i32;
}

/// `_sep_state` (this+0xcc): the values the code sets and compares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum State {
    ColdOff = 0,
    Asleep = 1,
    /// Powered, the ROM idle, waiting for a firmware or a boot message.
    RomIdle = 2,
    /// A message of the ROM's panic arrived (`EP_BOOTSTRAP` opcode 0xff).
    RomPanic = 4,
    Booting = 5,
    Waking = 6,
    OsActive = 7,
    Napping = 8,
    OsSleeping = 9,
    Failed = 10,
}

/// Why a call of the manager did not succeed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MgrError {
    /// An IOReturn.
    Io(i32),
    /// What the kernel does not return from: a `panic()` with this text.
    Panic(String),
    /// The SEP core cannot run: what is missing.
    CoreGone(String),
    /// Something the kernel does that this port does not.
    Unimplemented(String),
}

impl std::fmt::Display for MgrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MgrError::Io(c) => write!(f, "IOReturn {:#x}", *c as u32),
            MgrError::Panic(s) => write!(f, "kernel panic: {s}"),
            MgrError::CoreGone(s) => write!(f, "the SEP core cannot run: {s}"),
            MgrError::Unimplemented(s) => f.write_str(s),
        }
    }
}

impl From<IopError> for MgrError {
    fn from(e: IopError) -> MgrError {
        match e {
            IopError::Fault(f) => MgrError::Unimplemented(format!("{f}")),
            e => MgrError::Io(e.ioreturn()),
        }
    }
}

/// What the web device's boot gives the manager, and what its device tree
/// has of the `sep` node.
#[derive(Clone, Debug)]
pub struct Config {
    /// `boot-timeout-ms` (default 0xea60) and the multiplier
    /// (`this+0xac`: 1; 10 on a simulator target, 20 on an FPGA).
    pub boot_timeout_ms: u32,
    pub timeout_multiplier: u32,
    /// One millisecond of a timeout: 1 ms; tests shorten it.
    pub ms: Duration,
    /// `getSepPageSize`: 0x1000 without the `aarch64` property.
    pub sep_page: u64,
    pub shmcon_size: u64,
    pub trace_size: u64,
    /// The `/chosen/memory-map` entry `SEPFW`'s size: the region the
    /// sepOS is copied to. iBoot makes it; `/defaults sep-size` is the
    /// size the template names (0xc00000).
    pub sepfw_len: usize,
    /// `rom-panic-bytes` / 8: the SEP ROM's panic words.
    pub rom_panic_words: usize,
    /// `sepfw-loaded` and `sepfw-booted` as the device tree has them.
    pub sepfw_loaded: bool,
    pub sepfw_booted: bool,
    /// `has-art`, `ap-manifest` and an `xART` child: all absent or
    /// present on the J120's tree as the caller read them.
    pub has_art: bool,
    pub ap_manifest: bool,
    pub has_xart: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            boot_timeout_ms: 0xea60,
            timeout_multiplier: 1,
            ms: Duration::from_millis(1),
            sep_page: shm::SEP_PAGE,
            shmcon_size: shm::DEFAULT_SHMCON_SIZE,
            trace_size: shm::DEFAULT_TRACE_SIZE,
            sepfw_len: 0xc0_0000,
            rom_panic_words: 7,
            sepfw_loaded: false,
            sepfw_booted: false,
            has_art: false,
            ap_manifest: false,
            has_xart: true,
        }
    }
}

/// The sepOS as the SEP ROM is told of it (`AppleSEPFirmware`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Firmware {
    /// Its physical address, which the Boot message carries `>> 12`.
    pub address: u64,
    pub len: usize,
    /// `AppleSEPFirmwarePayloadType`: 0 SEPI, 1 RSEP.
    pub payload: u8,
    pub preload: bool,
}

/// The pieces of a firmware the user client's scalars give
/// (`PIECE_FIRMWARE`, `PIECE_PATCHES`, `PIECE_USTUFF`).
pub const MAX_PATCH_LEN: u64 = 0x40000;
pub const USTUFF_LEN: u64 = 0x77c;

/// One advertised endpoint (a Discovery record).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advertised {
    pub name: u32,
    pub id: u8,
    /// `ool_in_min/max_pages`, `ool_out_min/max_pages`, once advertised.
    pub ools: Option<[u8; 4]>,
}

/// The control endpoint's command slots: tag = slot + 1.
pub const CONTROL_TAGS: usize = 8;

struct Cmd {
    active: bool,
    reply: Option<Message>,
}

/// The ROM booter's state (`AppleSEPBooter`).
#[derive(Default)]
struct Booter {
    pending: bool,
    reply: Option<Message>,
    status: u16,
    /// The ROM's log characters not yet ended by a flush.
    line: Vec<u8>,
    panic_words: Vec<u64>,
}

struct G {
    state: State,
    firmware: Option<Firmware>,
    booter: Booter,
    cmds: Vec<Cmd>,
    /// `_no_ep_yet_messages`: messages for an endpoint nothing has
    /// registered (at most 32).
    pending: VecDeque<Message>,
    advertised: Vec<Advertised>,
    shm: Option<SharedMemory>,
    wake_flag: bool,
    sep_info: Option<u32>,
    core_gone: Option<String>,
    /// The kernel's own log lines (the reply texts the manager prints).
    log: Vec<String>,
    /// Gaps met while routing: reported by the user client.
    gaps: Vec<String>,
    booted_property: bool,
    /// Incremented at every SEP (re)boot (`asep[0x1a0]`).
    epoch: u32,
}

/// The manager.
pub struct Manager {
    pub cfg: Config,
    a7iop: Arc<A7iop>,
    mem: SepMem,
    sepfw: u64,
    g: Mutex<G>,
    cv: Condvar,
}

impl Manager {
    /// `AppleSEPManager::start`: the control and discovery endpoints exist,
    /// the doorbell action is set, the SEP is cold off. A `sepfw-loaded`
    /// property makes the firmware a preload (the sepOS iBoot put in the
    /// `SEPFW` region); that is the web device's boot to arrange, which it
    /// does not, so this is refused until it does.
    pub fn new(cfg: Config, hw: Arc<Hw>, mem: SepMem) -> Result<Arc<Manager>, MgrError> {
        if cfg.sepfw_loaded {
            return Err(MgrError::Unimplemented("AppleSEPManager::start with sepfw-loaded: AppleSEPFirmware::fromPreload needs the sepOS in the SEPFW region before the kernel runs, which the web device's boot does not do".into()));
        }
        if cfg.sepfw_booted {
            return Err(MgrError::Unimplemented("AppleSEPManager with sepfw-booted: a SEP the boot stage already booted (only the L4 info message is sent)".into()));
        }
        let sepfw = mem.alloc(cfg.sepfw_len, 0x1000);
        let g = G {
            state: State::ColdOff,
            firmware: None,
            booter: Booter::default(),
            cmds: (0..CONTROL_TAGS).map(|_| Cmd { active: false, reply: None }).collect(),
            pending: VecDeque::new(),
            advertised: Vec::new(),
            shm: None,
            wake_flag: false,
            sep_info: None,
            core_gone: None,
            log: Vec::new(),
            gaps: Vec::new(),
            booted_property: false,
            epoch: 0,
        };
        let m = Arc::new(Manager { cfg, a7iop: Arc::new(A7iop::new(hw)), mem, sepfw, g: Mutex::new(g), cv: Condvar::new() });
        let weak: Weak<Manager> = Arc::downgrade(&m);
        m.a7iop.set_doorbell_action(Arc::new(move || {
            if let Some(m) = weak.upgrade() {
                m.doorbell();
            }
        }));
        Ok(m)
    }

    fn g(&self) -> MutexGuard<'_, G> {
        self.g.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn a7iop(&self) -> &Arc<A7iop> {
        &self.a7iop
    }

    pub fn state(&self) -> State {
        self.g().state
    }

    pub fn log(&self) -> Vec<String> {
        self.g().log.clone()
    }

    /// Gaps met while the doorbell routed a message, taken.
    pub fn take_gaps(&self) -> Vec<String> {
        std::mem::take(&mut self.g().gaps)
    }

    pub fn sep_info(&self) -> Option<u32> {
        self.g().sep_info
    }

    /// `setProperty("sep-booted", true)` happened.
    pub fn booted_property(&self) -> bool {
        self.g().booted_property
    }

    pub fn advertised(&self) -> Vec<Advertised> {
        self.g().advertised.clone()
    }

    /// Whether the registry has the endpoint service `sep-endpoint,<name>`: an
    /// endpoint is published once both its advertisements arrived.
    pub fn endpoint_service(&self, name: u32) -> Option<Advertised> {
        self.g().advertised.iter().find(|a| a.name == name && a.ools.is_some()).cloned()
    }

    /// The SEP core cannot run: what is missing. Every wait ends.
    pub fn core_gone(&self, why: String) {
        self.g().core_gone = Some(why);
        self.cv.notify_all();
    }

    fn timeout(&self, ms: u64) -> Duration {
        self.cfg.ms * (ms * u64::from(self.cfg.timeout_multiplier)).min(u32::MAX as u64) as u32
    }

    /// Wait on the gate until `ready` or `limit`; `Err` when the core is gone.
    fn wait<'a, T>(&'a self, mut g: MutexGuard<'a, G>, limit: Option<Duration>, mut ready: impl FnMut(&mut G) -> Option<T>) -> Result<(Option<T>, MutexGuard<'a, G>), MgrError> {
        let deadline = limit.map(|d| Instant::now() + d);
        loop {
            if let Some(v) = ready(&mut g) {
                return Ok((Some(v), g));
            }
            if let Some(why) = g.core_gone.clone() {
                return Err(MgrError::CoreGone(why));
            }
            match deadline {
                Some(d) => {
                    let now = Instant::now();
                    if now >= d {
                        return Ok((None, g));
                    }
                    g = self.cv.wait_timeout(g, d - now).unwrap_or_else(|e| e.into_inner()).0;
                }
                None => g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner()),
            }
        }
    }

    // ---- power ----------------------------------------------------------------------------

    /// `_setPowerState(1)` from cold: the SEP ROM starts (`startCPU(NULL)`) and
    /// the state is 2. With no preloaded firmware nothing boots until a
    /// firmware load.
    pub fn power_on(&self) -> Result<(), MgrError> {
        if self.state() != State::ColdOff {
            return Ok(());
        }
        self.a7iop.start_cpu()?;
        let mut g = self.g();
        g.state = State::RomIdle;
        g.epoch += 1;
        self.cv.notify_all();
        Ok(())
    }

    // ---- sending --------------------------------------------------------------------------

    /// `_sendMessageGated`: the state decides what may be sent; the endpoint byte
    /// is the one given.
    pub fn send_message(&self, endpoint: u8, m: Message, wait: bool) -> Result<(), MgrError> {
        let state = self.g().state;
        let ok = match state {
            State::RomIdle | State::Booting | State::Waking => endpoint & !1 == 0xfe,
            State::OsActive | State::OsSleeping => {
                if endpoint == ep::BOOTSTRAP {
                    return Err(MgrError::Panic("*endpointHandle != EP_BOOTSTRAP".into()));
                }
                if endpoint >= ep::MAX && endpoint != ep::L4INFO {
                    return Err(MgrError::Panic("(*endpointHandle < _max_endpoints) || (*endpointHandle == EP_L4INFO)".into()));
                }
                true
            }
            State::Napping => return Err(MgrError::Unimplemented("sending to a napping SEP (the wake from nap)".into())),
            State::ColdOff | State::Asleep | State::RomPanic | State::Failed => false,
        };
        if !ok {
            let mut g = self.g();
            g.log.push(format!("AppleSEP:WARNING: attempt to send message to SEP in non-receptive state {}", state as u32));
            return Err(MgrError::Io(io::NOT_READY));
        }
        // The control endpoint's SLEEP and NAP messages change the state: not ported.
        if endpoint == ep::CONTROL && matches!(m.opcode(), frame::control::SLEEP | frame::control::NAP) {
            return Err(MgrError::Unimplemented(format!("a control message of opcode {:#x} (sleep and nap)", m.opcode())));
        }
        self.a7iop.post_mailbox(m.with_endpoint(endpoint), wait).map_err(MgrError::from)
    }

    // ---- the doorbell ---------------------------------------------------------------------

    /// `_doorbellAction`: drain the outbox, routing each message.
    pub fn doorbell(&self) {
        loop {
            match self.a7iop.get_mailbox() {
                Ok(m) => self.route(m),
                Err(IopError::NotReady) => break,
                Err(e) => {
                    self.g().gaps.push(format!("the SEP's mailbox: {}", MgrError::from(e)));
                    break;
                }
            }
        }
    }

    fn route(&self, m: Message) {
        let mut g = self.g();
        // The doorbell's wake fast path (K 0xfffffff0063cfae4): control opcodes 0x15 and 0x0f
        // set the wake byte and wake a waiter, and are consumed; with the byte already set an
        // 0x0f is dropped and an 0x15 goes on to the endpoint like any other message.
        if m.endpoint() == ep::CONTROL && matches!(m.opcode(), frame::control::OS_ACTIVE | frame::control::WAKE_ACK) {
            if !g.wake_flag {
                g.wake_flag = true;
                self.cv.notify_all();
                return;
            }
            if m.opcode() == frame::control::WAKE_ACK {
                return;
            }
        }
        if g.state == State::RomPanic {
            self.rom_message(&mut g, m);
            return;
        }
        match m.endpoint() {
            e if e < ep::MAX => {
                if e == ep::CONTROL {
                    self.control_message(&mut g, m);
                } else if g.pending.len() >= 31 {
                    g.gaps.push("AppleSEPManager's _no_ep_yet_messages FIFO is full: the kernel panics".into());
                } else {
                    g.log.push(format!("queueing message for unregistered endpoint {e}"));
                    g.gaps.push(format!("SEP endpoint {e} sent a message ({m:?}); no endpoint service is ported: logger, xART, ART, keystore, hilo, debug, testing and pairing are not"));
                    g.pending.push_back(m);
                }
            }
            ep::DISCOVERY => self.discovery_message(&mut g, m),
            ep::BOOTSTRAP => {
                if m.opcode() == rom::PANIC {
                    g.state = State::RomPanic;
                }
                self.rom_message(&mut g, m);
            }
            e => g.log.push(format!("received message for bad endpoint {e}")),
        }
        self.cv.notify_all();
    }

    // ---- discovery (endpoint 0xfd) --------------------------------------------------------

    fn discovery_message(&self, g: &mut G, m: Message) {
        let id = m.param();
        match m.opcode() {
            frame::discovery::ADVERTISE_ENDPOINT => {
                let name = m.data();
                let by_id = g.advertised.iter().position(|a| a.id == id);
                let by_name = g.advertised.iter().position(|a| a.name == name);
                match (by_id, by_name) {
                    (None, None) => {
                        if g.advertised.len() >= 0xfd {
                            g.gaps.push("_num_named_endpoints < sizeof(_endpoint_info) / sizeof(_endpoint_info[0]): the kernel panics".into());
                        } else {
                            g.advertised.push(Advertised { name, id, ools: None });
                        }
                    }
                    (Some(a), Some(b)) if a == b => g.log.push(format!("Duplicate advertisement of endpoint ID {id} name {name:#x}")),
                    _ => g.gaps.push(format!("a discovery advertisement (id {id}, name {name:#x}) that contradicts the endpoints known: old_info == _find_endpoint_info_by_name(name) fails, the kernel panics")),
                }
            }
            frame::discovery::ADVERTISE_OOLS => {
                let bytes = [(m.0 >> 32) as u8, (m.0 >> 40) as u8, (m.0 >> 48) as u8, (m.0 >> 56) as u8];
                match g.advertised.iter_mut().find(|a| a.id == id) {
                    None => g.gaps.push(format!("Can't find endpoint ID {id} for OOL size advertisement: the kernel panics")),
                    Some(a) => match a.ools {
                        None => a.ools = Some(bytes),
                        Some(old) if old == bytes => g.log.push(format!("Duplicate OOL advertisement for endpoint ID {id}")),
                        Some(_) => g.gaps.push(format!("an OOL advertisement for endpoint ID {id} that differs from the first: the kernel panics")),
                    },
                }
            }
            op => g.log.push(format!("Unknown opcode {op} in message {:#x}", m.0)),
        }
    }

    // ---- the control endpoint -------------------------------------------------------------

    fn control_message(&self, g: &mut G, m: Message) {
        if m.tag() != 0 {
            let slot = m.tag() as usize - 1;
            match g.cmds.get_mut(slot) {
                None => g.log.push(format!("EP0 received message for invalid tag {}", m.tag())),
                Some(c) if !c.active => g.log.push(format!("EP0 received message for inactive tag {}", m.tag())),
                Some(c) => {
                    c.active = false;
                    c.reply = Some(m);
                }
            }
            return;
        }
        match m.opcode() {
            0x01 => {}
            frame::control::OS_ACTIVE_ASYNC | frame::control::OS_ACTIVE => self.os_active(g),
            0x29 => {
                g.sep_info = Some(m.data());
                g.log.push(format!("SEP info: {:#x}", m.data()));
            }
            0x10 | 0x11 => g.gaps.push(format!("EP0 message {m:?}: the manager's reply to it (the camera-disable and the nap exchange) is not ported")),
            _ => g.log.push(format!("EP0 received unsolicited message {:#018x}", m.0)),
        }
    }

    /// `_notifyOSActiveGated`: in state 5 or 6 the SEP/OS is alive and the state is 7.
    fn os_active(&self, g: &mut G) {
        match g.state {
            State::Booting | State::Waking => {
                g.log.push("SEP/OS is alive".into());
                g.state = State::OsActive;
                // The firmware is released once the OS is active unless ap-manifest keeps it.
                if !self.cfg.ap_manifest {
                    g.firmware = None;
                }
            }
            State::Napping => g.state = State::OsActive,
            s => g.log.push(format!("AppleSEP:WARNING: received OS Active message in unexpected state {}", s as u32)),
        }
    }

    /// `AppleSEPControl::_cmsgSend`: one request, its tag taken from the
    /// eight slots (waiting for one), the reply waited for up to `timeout_ms`
    /// (0: no deadline) and its status mapped as the kernel maps it.
    pub fn cmsg_send(&self, m: Message, timeout_ms: u32, wait: bool) -> Result<Message, MgrError> {
        let tag = {
            let g = self.g();
            let (slot, mut g) = self.wait(g, None, |g| g.cmds.iter().position(|c| !c.active && c.reply.is_none()))?;
            let slot = slot.expect("no deadline");
            g.cmds[slot].active = true;
            slot + 1
        };
        let msg = m.with_endpoint(ep::CONTROL).with_tag(tag as u8);
        if let Err(e) = self.send_message(ep::CONTROL, msg, true) {
            let mut g = self.g();
            g.cmds[tag - 1].active = false;
            return Err(e);
        }
        if !wait {
            self.g().cmds[tag - 1].active = false;
            return Ok(msg);
        }
        let limit = (timeout_ms != 0).then(|| self.timeout(u64::from(timeout_ms)));
        let g = self.g();
        let (reply, mut g) = self.wait(g, limit, |g| g.cmds[tag - 1].reply.take())?;
        let Some(reply) = reply else {
            // The command is not returned to the pool on a timeout.
            g.log.push(format!("AppleSEP:WARNING: timeout waiting for reply to {:x}", msg.0));
            return Err(MgrError::Io(io::TIMEOUT));
        };
        g.cmds[tag - 1].active = false;
        match reply.param() {
            0 => Ok(reply),
            1 => Err(MgrError::Io(io::BAD_ARGUMENT)),
            2 => Err(MgrError::Io(io::ABORTED)),
            _ => Err(MgrError::Io(io::DEVICE_ERROR)),
        }
    }

    /// `cmsgSET_OOL_IN` / `cmsgSET_OOL_OUT`: a size message (capacity in
    /// bytes) and an address message (`slave address >> 12`), each waited
    /// for (K 0xfffffff0063c6218, K 0xfffffff0063c6304).
    pub fn cmsg_set_ool(&self, input: bool, endpoint: u8, address: u64, capacity: u32) -> Result<(), MgrError> {
        let (size_op, addr_op) = if input { (frame::control::SET_OOL_IN_SIZE, frame::control::SET_OOL_IN_ADDRESS) } else { (frame::control::SET_OOL_OUT_SIZE, frame::control::SET_OOL_OUT_ADDRESS) };
        self.cmsg_send(Message::new(0, 0, size_op, endpoint, capacity), 0, true)?;
        self.cmsg_send(Message::new(0, 0, addr_op, endpoint, (address >> 12) as u32), 0, true)?;
        Ok(())
    }

    /// The ping the user client's selector 0 sends (5000 ms).
    pub fn ping(&self) -> Result<(), MgrError> {
        self.cmsg_send(Message::new(0, 0, frame::control::PING, 0, 0), 5000, true).map(|_| ())
    }

    /// The security-mode query of selector 4: opcode 0x14, 500 ms; the reply's
    /// low byte (bit 0 production status, bit 1 security mode).
    pub fn security_mode(&self) -> Result<u8, MgrError> {
        self.cmsg_send(Message::new(0, 0, frame::control::STATUS, 0, 0), 500, true).map(|r| r.data() as u8)
    }

    // ---- the SEP ROM's protocol (AppleSEPBooter, endpoint 0xff) ---------------------------

    /// A ROM reply (`AppleSEPBooter::_msgReceived`, K 0xfffffff0063c6e64) or, after a ROM
    /// panic, a word of its panic buffer.
    fn rom_message(&self, g: &mut G, m: Message) {
        if g.state == State::RomPanic && m.opcode() != rom::PANIC {
            let words = self.cfg.rom_panic_words;
            g.booter.panic_words.push(m.0);
            if g.booter.panic_words.len() >= words {
                let text: String = g.booter.panic_words.iter().map(|w| w.to_le_bytes().iter().map(|b| format!("{b:02X}")).collect::<String>()).collect();
                g.gaps.push(format!("SEP ROM boot panic. 0x{text}: the kernel panics"));
            }
            return;
        }
        let data = m.data();
        match m.opcode() {
            rom::PING_RESPONSE => g.booter.pending = false,
            rom::STATUS_REPLY => {
                g.booter.status = data as u16;
                g.booter.reply = Some(m);
                g.booter.pending = false;
            }
            rom::STATUS_UNSOLICITED => g.booter.status = data as u16,
            rom::NONCE_GENERATED | rom::NONCE_WORD_REPLY | rom::IBIC_KEY | rom::IBIC_KEY_WORD_REPLY => {
                g.booter.reply = Some(m);
                g.booter.pending = false;
            }
            rom::TZ0_ACCEPTED => {
                g.booter.status = rom::status::TZ0_ACCEPTED;
                g.booter.pending = false;
            }
            rom::IMG4_ACCEPTED => {
                g.booter.status = rom::status::IMG4_ACCEPTED;
                g.booter.pending = false;
            }
            rom::SEPART_ACCEPTED => {
                g.booter.status = rom::status::SEPART_ACCEPTED;
                g.booter.pending = false;
            }
            rom::RESUMED => {
                g.booter.status = rom::status::RESUMED;
                g.booter.pending = false;
            }
            rom::TMM_ACCEPTED | rom::PATCHES_ACCEPTED => g.booter.pending = false,
            rom::REJECTED | rom::REJECTED_ALT => {
                if data == u32::from(rom::IBIC_KEY_REQUEST) {
                    g.log.push("Platform doesn't support SEPROM iBIC retrieval".into());
                    g.booter.reply = Some(m);
                    g.booter.pending = false;
                } else {
                    g.gaps.push(format!("SEP Boot failure, op {} data {data:#010x}: the kernel panics", m.opcode()));
                }
            }
            rom::LOG_WORD => g.log.push(format!("SEP: {}:{data:#010x}", m.param())),
            rom::LOG_CHARS => {
                let n = m.param() as usize;
                if n == 0 {
                    let line = String::from_utf8_lossy(&std::mem::take(&mut g.booter.line)).into_owned();
                    g.log.push(format!("SEP: {line}"));
                } else {
                    for i in 0..n.min(4) {
                        if g.booter.line.len() < 255 {
                            g.booter.line.push((data >> (8 * i)) as u8);
                        }
                    }
                }
            }
            rom::PANIC => {
                g.booter.status = rom::status::PANICKED;
            }
            op => g.log.push(format!("AppleSEP:WARNING: SEP: unexpected message, op {op} tag {} param {} data {data:#010x}", m.tag(), m.param())),
        }
    }

    /// A request to the ROM and the wait for its reply (`wait(ms)`: the reply clears
    /// the pending byte; a timeout sets the status 0xc9 and returns kIOReturnTimeout).
    fn rom_request(&self, op: u8, param: u8, data: u32, wait_ms: Option<u64>) -> Result<(), MgrError> {
        {
            let mut g = self.g();
            g.booter.pending = true;
            g.booter.reply = None;
        }
        self.send_message(ep::BOOTSTRAP, Message::new(ep::BOOTSTRAP, 1, op, param, data), true)?;
        match wait_ms {
            Some(ms) => self.rom_wait(ms),
            None => Ok(()),
        }
    }

    fn rom_wait(&self, ms: u64) -> Result<(), MgrError> {
        let g = self.g();
        let (done, mut g) = self.wait(g, Some(self.timeout(ms)), |g| (!g.booter.pending).then_some(()))?;
        if done.is_none() {
            g.booter.status = rom::status::TIMED_OUT;
            g.log.push("AppleSEP:WARNING: SEP ROM timeout - no response".into());
            return Err(MgrError::Io(io::TIMEOUT));
        }
        Ok(())
    }

    fn rom_status(&self) -> u16 {
        self.g().booter.status
    }

    /// `AppleSEPBooter::romCommand`: a request of the user's, whatever it is
    /// (selector 3): the reply message.
    pub fn rom_command(&self, m: Message, wait_ms: u64) -> Result<Message, MgrError> {
        self.rom_request(m.opcode(), m.param(), m.data(), Some(wait_ms))?;
        self.g().booter.reply.ok_or_else(|| MgrError::Io(io::ERROR))
    }

    /// `AppleSEPBooter::bootSEP` for a normal boot with a firmware
    /// (K 0xfffffff0063c7794): status must be 1, BootTz0, status must be 2, Boot,
    /// the shared memory's L4 info message, then the ROM's acceptance. The
    /// panics the kernel makes are [`MgrError::Panic`].
    pub fn boot_sep(&self, fw: &Firmware, shm: &SharedMemory, with_art: bool) -> Result<(), MgrError> {
        let t = u64::from(self.cfg.boot_timeout_ms);
        if self.cfg.has_art && !(fw.payload == rom::PAYLOAD_RSEP && !with_art) {
            return Err(MgrError::Unimplemented("bootSEP's LoadSEPART step (has-art: the ART from NVRAM to the ROM; AppleSEPARTService is not ported)".into()));
        }
        let fail = |what: &str, e: MgrError| match e {
            MgrError::Io(c) => MgrError::Panic(format!("SEP Boot Failure: {what} - {:#x}", c as u32)),
            e => e,
        };
        self.rom_request(rom::STATUS, 0, 0, Some(50_000)).map_err(|e| fail("status check 1 failed", e))?;
        if self.rom_status() != rom::status::BEFORE_TZ0 {
            return Err(MgrError::Panic(format!("SEP Boot Failure: unexpected status 1:{}", self.rom_status())));
        }
        self.rom_request(rom::BOOT_TZ0, fw.payload, 0, Some(t)).map_err(|e| fail("ROM failed to ack BootTz0", e))?;
        self.rom_request(rom::STATUS, 0, 0, Some(50_000)).map_err(|e| fail("status check 2 failed", e))?;
        if self.rom_status() != rom::status::AFTER_TZ0 {
            return Err(MgrError::Panic(format!("SEP Boot Failure: unexpected status 2:{}", self.rom_status())));
        }
        if fw.address & 0xfff != 0 {
            return Err(MgrError::Panic("(bpa % SEP_PAGE_SIZE_64) == 0".into()));
        }
        self.g().log.push("SEP booting".into());
        self.rom_request(rom::BOOT, fw.payload, (fw.address >> 12) as u32, None)?;
        // The shared buffer's hand-off on EP_L4INFO: bytes 2 and 3 its size in 4 KiB pages
        // (asserted to fit 16 bits), the datum its slave address >> 12.
        let size_pages = shm.len >> 12;
        if size_pages > 0xffff {
            return Err(MgrError::Panic("shm_size == message.sepboot_msg.size".into()));
        }
        let l4 = Message::new(ep::L4INFO, 1, size_pages as u8, (size_pages >> 8) as u8, (shm.address >> 12) as u32);
        self.send_message(ep::L4INFO, l4, true)?;
        self.rom_wait(t).map_err(|e| fail("ROM failed to ack Boot with", e))?;
        Ok(())
    }

    // ---- loading the sepOS ----------------------------------------------------------------

    /// `AppleSEPFirmware::fromMemory`: the user's buffer copied into the `SEPFW` region.
    /// `piece_lens` are the user client's three scalars.
    pub fn firmware_from_memory(&self, data: &[u8], piece_lens: [u64; 3], payload: u8) -> Result<Firmware, MgrError> {
        if piece_lens[0] > u64::from(u32::MAX) {
            return Err(MgrError::Panic("UINT32_MAX >= piece_lens[PIECE_FIRMWARE]".into()));
        }
        if piece_lens[1] != 0 {
            if piece_lens[1] > MAX_PATCH_LEN {
                return Err(MgrError::Panic("MAX_PATCH_LEN >= piece_lens[PIECE_PATCHES]".into()));
            }
            if piece_lens[2] != USTUFF_LEN {
                return Err(MgrError::Panic("USTUFF_LEN == piece_lens[PIECE_USTUFF]".into()));
            }
            // _mapMemoryToSEP without a mapper REQUIREs no patch buffer.
            return Err(MgrError::Panic("nullptr == _patch_buf (the SEP has no IOMapper, so patches cannot be mapped)".into()));
        }
        if piece_lens[0] != data.len() as u64 {
            return Err(MgrError::Panic("_sep_firmware_length == iomd->getLength()".into()));
        }
        if data.len() > self.cfg.sepfw_len {
            return Err(MgrError::Panic(format!("SEP firmware too large. Firmware size: {:#x}; allocated space: {:#x}", data.len(), self.cfg.sepfw_len)));
        }
        self.mem.write(self.sepfw, data).map_err(|e| MgrError::Unimplemented(format!("{e}")))?;
        Ok(Firmware { address: self.sepfw, len: data.len(), payload, preload: false })
    }

    /// `setFirmwareBytes` and `_bootSEP` (K 0xfffffff0063d0430, K 0xfffffff0063d057c): a firmware
    /// load, only in state 2 with no firmware; the call returns when the ROM has
    /// accepted the image, not when the sepOS is up.
    pub fn set_firmware_bytes(&self, data: &[u8], piece_lens: [u64; 3], restore: bool, with_art: bool) -> Result<(), MgrError> {
        {
            let g = self.g();
            let (_, g) = self.wait(g, None, |g| (g.state != State::ColdOff).then_some(()))?;
            if g.firmware.is_some() || g.state != State::RomIdle {
                drop(g);
                self.g().log.push("AppleSEP:WARNING: SEP firmware reload attempted".into());
                return Err(MgrError::Io(io::BUSY));
            }
        }
        let payload = u8::from(restore);
        let fw = self.firmware_from_memory(data, piece_lens, payload)?;
        let shm = SharedMemory::new(&self.mem, &shm::entries(true, self.cfg.shmcon_size, self.cfg.trace_size), self.cfg.sep_page).map_err(|e| MgrError::Panic(format!("failed to allocate SEP shared memory buffer: {e:?}")))?;
        shm.arm_panic_channel();
        shm.load_object(shm::chan::TEST_OBJECT, shm::TEST_OBJECT_DATA);
        shm.load_flags(false);
        {
            let mut g = self.g();
            g.firmware = Some(fw.clone());
            g.booted_property = true;
            g.shm = Some(shm.clone());
            g.state = State::Booting;
        }
        match self.boot_sep(&fw, &shm, with_art) {
            Ok(()) => Ok(()),
            Err(e) => {
                let mut g = self.g();
                g.state = State::Failed;
                g.log.push("AppleSEP:WARNING: SEP bootstrap failed".into());
                Err(e)
            }
        }
    }

    pub fn shm(&self) -> Option<SharedMemory> {
        self.g().shm.clone()
    }

    pub fn firmware(&self) -> Option<Firmware> {
        self.g().firmware.clone()
    }

    pub fn epoch(&self) -> u32 {
        self.g().epoch
    }

    /// Wait until the SEP/OS is active (`_waitOSActiveGated`), up to `ms`.
    pub fn wait_os_active(&self, ms: u64) -> Result<bool, MgrError> {
        let g = self.g();
        let (r, _gate) = self.wait(g, Some(self.timeout(ms)), |g| (g.state == State::OsActive).then_some(()))?;
        Ok(r.is_some())
    }

    /// The doorbell thread that runs [`Manager::doorbell`] on the outbox interrupt.
    pub fn spawn_doorbell(&self) -> std::thread::JoinHandle<()> {
        self.a7iop.spawn_doorbell()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A SEP's side of the mailbox, for the tests only: a thread that takes
    /// each message the AP posts and answers with what a script says. The
    /// script is the test's statement of what the real SEP ROM and sepOS say
    /// (03-boot-handshake.md section 11); the manager never makes these
    /// replies itself.
    struct Peer {
        seen: Arc<Mutex<Vec<Message>>>,
        stop: Arc<AtomicBool>,
        t: Option<std::thread::JoinHandle<()>>,
    }

    impl Peer {
        fn new(hw: &Arc<Hw>, script: impl Fn(Message) -> Vec<Message> + Send + 'static) -> Peer {
            let (seen, stop) = (Arc::new(Mutex::new(Vec::new())), Arc::new(AtomicBool::new(false)));
            let (h, s, st) = (Arc::clone(hw), Arc::clone(&seen), Arc::clone(&stop));
            let t = std::thread::spawn(move || {
                while !st.load(Ordering::Relaxed) {
                    if !h.wait_until(Duration::from_millis(20), |a, _| a.a2i_len() > 0) {
                        continue;
                    }
                    let Ok(m) = h.core_pop() else { continue };
                    let m = Message(m);
                    s.lock().unwrap().push(m);
                    for r in script(m) {
                        // The AP's doorbell drains the outbox as it fills.
                        while h.core_push(r.0).is_err() {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    }
                }
            });
            Peer { seen, stop, t: Some(t) }
        }

        fn seen(&self) -> Vec<Message> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Drop for Peer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(t) = self.t.take() {
                let _ = t.join();
            }
        }
    }

    fn cfg() -> Config {
        Config { ms: Duration::from_micros(40), ..Config::default() }
    }

    fn manager(script: impl Fn(Message) -> Vec<Message> + Send + 'static) -> (Arc<Manager>, Peer, Arc<Hw>, std::thread::JoinHandle<()>) {
        let hw = Hw::new();
        let m = Manager::new(cfg(), Arc::clone(&hw), SepMem::new()).unwrap();
        let peer = Peer::new(&hw, script);
        let door = m.spawn_doorbell();
        (m, peer, hw, door)
    }

    fn finish(m: &Manager, hw: &Hw, door: std::thread::JoinHandle<()>) {
        hw.close();
        let _ = m;
        door.join().unwrap();
    }

    fn rom(op: u8, param: u8, data: u32) -> Message {
        Message::new(ep::BOOTSTRAP, 0, op, param, data)
    }

    #[test]
    fn the_sep_is_cold_until_powered_and_refuses_sends_in_the_meantime() {
        let (m, _peer, hw, door) = manager(|_| vec![]);
        assert_eq!(m.state(), State::ColdOff);
        assert_eq!(m.send_message(ep::CONTROL, Message::new(0, 0, 0, 0, 0), false), Err(MgrError::Io(io::NOT_READY)));
        assert!(m.log().iter().any(|l| l.contains("non-receptive state 0")));
        m.power_on().unwrap();
        assert_eq!(m.state(), State::RomIdle);
        assert!(m.a7iop().running() && hw.run().running);
        finish(&m, &hw, door);
    }

    #[test]
    fn a_firmware_is_copied_and_checked_as_the_kernel_does() {
        let (m, _p, hw, door) = manager(|_| vec![]);
        let fw = m.firmware_from_memory(&[7; 0x2000], [0x2000, 0, 0], 0).unwrap();
        assert_eq!((fw.len, fw.payload, fw.preload), (0x2000, 0, false));
        assert_eq!(fw.address & 0xfff, 0);
        assert_eq!(m.mem.bytes(fw.address, 4).unwrap(), vec![7; 4]);
        // Length mismatch, too large, and patch pieces (no IOMapper to map them through).
        assert!(matches!(m.firmware_from_memory(&[0; 16], [32, 0, 0], 0), Err(MgrError::Panic(_))));
        let big = vec![0u8; 0xc0_0001];
        assert!(matches!(m.firmware_from_memory(&big, [0xc0_0001, 0, 0], 0), Err(MgrError::Panic(s)) if s.contains("SEP firmware too large")));
        assert!(matches!(m.firmware_from_memory(&[0; 16], [16, 4, USTUFF_LEN], 0), Err(MgrError::Panic(s)) if s.contains("_patch_buf")));
        assert!(matches!(m.firmware_from_memory(&[0; 16], [16, 4, 5], 0), Err(MgrError::Panic(s)) if s.contains("USTUFF_LEN")));
        assert!(matches!(m.firmware_from_memory(&[0; 16], [16, MAX_PATCH_LEN + 1, USTUFF_LEN], 0), Err(MgrError::Panic(s)) if s.contains("MAX_PATCH_LEN")));
        finish(&m, &hw, door);
    }

    #[test]
    fn the_boot_handshake_runs_in_the_order_the_booter_has_and_ends_in_the_l4_info_message() {
        // A ROM that says status 1 and then 2 (after BootTz0), and accepts Boot.
        let tz0 = Arc::new(AtomicBool::new(false));
        let t2 = Arc::clone(&tz0);
        let (m, peer, hw, door) = manager(move |msg| {
            if msg.endpoint() != ep::BOOTSTRAP {
                return vec![];
            }
            match msg.opcode() {
                rom::STATUS => vec![rom(rom::STATUS_REPLY, 0, if t2.load(Ordering::Relaxed) { 2 } else { 1 })],
                rom::BOOT_TZ0 => {
                    t2.store(true, Ordering::Relaxed);
                    vec![rom(rom::TZ0_ACCEPTED, 0, 0)]
                }
                rom::BOOT => vec![rom(rom::IMG4_ACCEPTED, 0, 0)],
                _ => vec![],
            }
        });
        m.power_on().unwrap();
        m.set_firmware_bytes(&[3; 0x1000], [0x1000, 0, 0], false, true).unwrap();
        assert_eq!(m.state(), State::Booting);
        assert!(m.booted_property());
        let seen = peer.seen();
        let ops: Vec<(u8, u8, u8, u8)> = seen.iter().map(|s| (s.endpoint(), s.tag(), s.opcode(), s.param())).collect();
        assert_eq!(
            ops,
            vec![
                (0xff, 1, rom::STATUS, 0),
                (0xff, 1, rom::BOOT_TZ0, 0),
                (0xff, 1, rom::STATUS, 0),
                (0xff, 1, rom::BOOT, 0),
                // The L4 info message: tag 1, bytes 2 and 3 the buffer's size in pages (0x5b), the datum its address >> 12.
                (0xfe, 1, 0x5b, 0),
            ]
        );
        let fw = m.firmware().unwrap();
        assert_eq!(seen[3].data() as u64, fw.address >> 12);
        let shm = m.shm().unwrap();
        assert_eq!(seen[4].data() as u64, shm.address >> 12);
        assert_eq!(shm.len >> 12, 0x5b);
        assert!(m.log().iter().any(|l| l == "SEP booting"));
        // The ROM does not wait for the sepOS: the state is Booting until the sepOS says it is alive.
        assert!(!m.wait_os_active(1).unwrap());
        finish(&m, &hw, door);
    }

    #[test]
    fn a_status_the_code_does_not_expect_panics_the_kernel() {
        let (m, _p, hw, door) = manager(|msg| match (msg.endpoint(), msg.opcode()) {
            (0xff, rom::STATUS) => vec![rom(rom::STATUS_REPLY, 0, 9)],
            _ => vec![],
        });
        m.power_on().unwrap();
        let e = m.set_firmware_bytes(&[3; 0x1000], [0x1000, 0, 0], false, true).unwrap_err();
        assert_eq!(e, MgrError::Panic("SEP Boot Failure: unexpected status 1:9".into()));
        assert_eq!(m.state(), State::Failed);
        finish(&m, &hw, door);
    }

    #[test]
    fn a_rom_that_does_not_answer_times_out_as_the_kernel_does() {
        let (m, _p, hw, door) = manager(|_| vec![]);
        m.power_on().unwrap();
        let e = m.set_firmware_bytes(&[3; 0x1000], [0x1000, 0, 0], false, true).unwrap_err();
        assert_eq!(e, MgrError::Panic(format!("SEP Boot Failure: status check 1 failed - {:#x}", io::TIMEOUT as u32)));
        finish(&m, &hw, door);
    }

    #[test]
    fn a_core_that_cannot_exist_ends_the_wait_at_once_and_says_why() {
        let (m, _p, hw, door) = manager(|_| vec![]);
        m.power_on().unwrap();
        let m2 = Arc::clone(&m);
        let t = std::thread::spawn(move || m2.set_firmware_bytes(&[3; 0x1000], [0x1000, 0, 0], false, true));
        std::thread::sleep(Duration::from_millis(50));
        m.core_gone("the SEP ROM (GEX_DARWIN_SEPROM) is not given".into());
        let e = t.join().unwrap().unwrap_err();
        assert_eq!(e, MgrError::CoreGone("the SEP ROM (GEX_DARWIN_SEPROM) is not given".into()));
        finish(&m, &hw, door);
    }

    #[test]
    fn a_second_firmware_load_is_busy() {
        let (m, _p, hw, door) = manager(rom_script_two_phase());
        m.power_on().unwrap();
        m.set_firmware_bytes(&[3; 0x1000], [0x1000, 0, 0], false, true).unwrap();
        assert_eq!(m.set_firmware_bytes(&[3; 0x1000], [0x1000, 0, 0], false, true), Err(MgrError::Io(io::BUSY)));
        assert!(m.log().iter().any(|l| l.contains("SEP firmware reload attempted")));
        finish(&m, &hw, door);
    }

    /// The SEP ROM as 03-boot-handshake.md section 11 has it for the kernel-load flow:
    /// status 1, BootTz0 accepted, status 2, Boot accepted.
    fn rom_script_two_phase() -> impl Fn(Message) -> Vec<Message> + Send + 'static {
        let tz0 = Arc::new(AtomicBool::new(false));
        move |msg| {
            if msg.endpoint() != ep::BOOTSTRAP {
                return vec![];
            }
            match msg.opcode() {
                rom::STATUS => vec![rom(rom::STATUS_REPLY, 0, if tz0.load(Ordering::Relaxed) { 2 } else { 1 })],
                rom::BOOT_TZ0 => {
                    tz0.store(true, Ordering::Relaxed);
                    vec![rom(rom::TZ0_ACCEPTED, 0, 0)]
                }
                rom::BOOT => vec![rom(rom::IMG4_ACCEPTED, 0, 0)],
                _ => vec![],
            }
        }
    }

    #[test]
    fn the_sepos_announces_itself_and_control_requests_get_their_replies() {
        let base = rom_script_two_phase();
        let (m, peer, hw, door) = manager(move |msg| {
            let mut out = base(msg);
            match (msg.endpoint(), msg.opcode()) {
                // After the L4 info message the sepOS comes up: it says so on the control endpoint.
                (0xfe, _) => out.push(Message::new(0, 0, frame::control::OS_ACTIVE_ASYNC, 0, 0)),
                // Control requests: the reply is the request with its status in byte 3.
                (0, frame::control::PING) => out.push(Message::new(0, msg.tag(), frame::control::PING, 0, 0)),
                (0, frame::control::STATUS) => out.push(Message::new(0, msg.tag(), frame::control::STATUS, 0, 3)),
                (0, 0x02) => out.push(Message::new(0, msg.tag(), 0x02, 1, 0)),
                _ => {}
            }
            out
        });
        m.power_on().unwrap();
        m.set_firmware_bytes(&[3; 0x1000], [0x1000, 0, 0], false, true).unwrap();
        assert!(m.wait_os_active(10_000).unwrap());
        assert_eq!(m.state(), State::OsActive);
        assert!(m.log().iter().any(|l| l == "SEP/OS is alive"));
        // The firmware is released once the OS is active (ap-manifest is absent).
        assert!(m.firmware().is_none());
        m.ping().unwrap();
        assert_eq!(m.security_mode().unwrap(), 3);
        // A reply status of 1 maps to kIOReturnBadArgument.
        assert_eq!(m.cmsg_send(Message::new(0, 0, 0x02, 4, 0), 100, true), Err(MgrError::Io(io::BAD_ARGUMENT)));
        let tags: Vec<u8> = peer.seen().iter().filter(|s| s.endpoint() == 0).map(|s| s.tag()).collect();
        assert!(tags.iter().all(|&t| (1..=8).contains(&t)), "{tags:?}");
        // Once the OS is active the ROM's endpoint is no longer sendable.
        assert!(matches!(m.send_message(ep::BOOTSTRAP, Message::new(0, 1, 2, 0, 0), false), Err(MgrError::Panic(_))));
        finish(&m, &hw, door);
    }

    #[test]
    fn a_control_request_nothing_answers_times_out_and_keeps_its_slot() {
        let (m, _p, hw, door) = manager(rom_script_two_phase());
        m.power_on().unwrap();
        m.set_firmware_bytes(&[3; 0x1000], [0x1000, 0, 0], false, true).unwrap();
        hw.core_push(Message::new(0, 0, frame::control::OS_ACTIVE_ASYNC, 0, 0).0).unwrap();
        assert!(m.wait_os_active(10_000).unwrap());
        assert_eq!(m.ping(), Err(MgrError::Io(io::TIMEOUT)));
        assert!(m.log().iter().any(|l| l.contains("timeout waiting for reply")));
        finish(&m, &hw, door);
    }

    #[test]
    fn the_wake_fast_path_consumes_the_first_0x15_and_dispatches_the_second() {
        let (m, _p, hw, door) = manager(rom_script_two_phase());
        m.power_on().unwrap();
        m.set_firmware_bytes(&[3; 0x1000], [0x1000, 0, 0], false, true).unwrap();
        // The first 0x15 sets the wake byte and wakes a waiter: the manager is not told the OS is up.
        hw.core_push(Message::new(0, 0, frame::control::OS_ACTIVE, 0, 0).0).unwrap();
        assert!(wait(|| m.g().wake_flag));
        assert_eq!(m.state(), State::Booting);
        // An 0x0f with the byte set is dropped; the second 0x15 reaches the control endpoint.
        hw.core_push(Message::new(0, 0, frame::control::WAKE_ACK, 0, 0).0).unwrap();
        hw.core_push(Message::new(0, 0, frame::control::OS_ACTIVE, 0, 0).0).unwrap();
        assert!(wait(|| m.state() == State::OsActive));
        assert!(m.log().iter().all(|l| !l.contains("unsolicited message")));
        finish(&m, &hw, door);
    }

    #[test]
    fn an_endpoint_is_published_after_both_advertisements() {
        let (m, _p, hw, door) = manager(|_| vec![]);
        m.power_on().unwrap();
        let name = frame::name::KEYSTORE;
        hw.core_push(Message::new(ep::DISCOVERY, 0, frame::discovery::ADVERTISE_ENDPOINT, 5, name).0).unwrap();
        assert!(wait(|| m.advertised().len() == 1));
        assert!(m.endpoint_service(name).is_none(), "the sizes have not come");
        hw.core_push(Message(Message::new(ep::DISCOVERY, 0, frame::discovery::ADVERTISE_OOLS, 5, 0).0 | 1 << 32 | 4 << 40 | 1 << 48 | 4 << 56).0).unwrap();
        assert!(wait(|| m.endpoint_service(name).is_some()));
        let a = m.endpoint_service(name).unwrap();
        assert_eq!((a.id, a.ools), (5, Some([1, 4, 1, 4])));
        // A repeat is logged; a contradiction is a panic the port reports.
        hw.core_push(Message::new(ep::DISCOVERY, 0, frame::discovery::ADVERTISE_ENDPOINT, 5, name).0).unwrap();
        assert!(wait(|| m.log().iter().any(|l| l.contains("Duplicate advertisement"))));
        hw.core_push(Message::new(ep::DISCOVERY, 0, frame::discovery::ADVERTISE_ENDPOINT, 5, frame::name::LOGGER).0).unwrap();
        assert!(wait(|| !m.take_gaps().is_empty()));
        finish(&m, &hw, door);
    }

    #[test]
    fn messages_for_endpoints_with_no_service_here_are_reported() {
        let (m, _p, hw, door) = manager(|_| vec![]);
        m.power_on().unwrap();
        hw.core_push(Message::new(5, 0, 7, 0, 0).0).unwrap();
        assert!(wait(|| m.take_gaps().iter().any(|g| g.contains("SEP endpoint 5"))));
        finish(&m, &hw, door);
    }

    #[test]
    fn a_rom_panic_collects_its_words_and_is_reported() {
        let (m, _p, hw, door) = manager(|_| vec![]);
        m.power_on().unwrap();
        hw.core_push(rom(rom::PANIC, 0, 0).0).unwrap();
        assert!(wait(|| m.state() == State::RomPanic));
        for i in 0..7u64 {
            hw.core_push(i).unwrap();
        }
        assert!(wait(|| m.take_gaps().iter().any(|g| g.contains("SEP ROM boot panic"))));
        finish(&m, &hw, door);
    }

    #[test]
    fn the_rom_log_is_assembled_from_its_characters() {
        let (m, _p, hw, door) = manager(|_| vec![]);
        m.power_on().unwrap();
        hw.core_push(rom(rom::LOG_CHARS, 4, u32::from_le_bytes(*b"boot")).0).unwrap();
        hw.core_push(rom(rom::LOG_CHARS, 0, 0).0).unwrap();
        hw.core_push(rom(rom::LOG_WORD, 3, 0x1234).0).unwrap();
        assert!(wait(|| m.log().iter().any(|l| l == "SEP: boot")));
        assert!(wait(|| m.log().iter().any(|l| l == "SEP: 3:0x00001234")));
        finish(&m, &hw, door);
    }

    #[test]
    fn preloaded_and_booted_flags_are_refused_until_the_boot_stage_does_them() {
        let cfg = Config { sepfw_loaded: true, ..cfg() };
        assert!(matches!(Manager::new(cfg, Hw::new(), SepMem::new()), Err(MgrError::Unimplemented(s)) if s.contains("fromPreload")));
        let cfg = Config { sepfw_booted: true, ..Config::default() };
        assert!(matches!(Manager::new(cfg, Hw::new(), SepMem::new()), Err(MgrError::Unimplemented(s)) if s.contains("sepfw-booted")));
    }

    fn wait(mut f: impl FnMut() -> bool) -> bool {
        for _ in 0..400 {
            if f() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }
}
