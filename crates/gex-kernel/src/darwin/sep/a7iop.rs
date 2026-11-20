//! AppleA7IOPV2, the driver `iop,s8000` matches for the SEP, as the
//! manager uses it: a doorbell action, start and stop of the core, and the
//! two mailbox calls (`drafts/sep/01-a7iop-mailbox.md`, sections 3 to 5;
//! K 0xfffffff005b126fc `startCPUWithOptions`, K 0xfffffff005b128cc
//! `stopCPU`, K 0xfffffff005b133b0 `postMailbox`, K 0xfffffff005b131a0
//! `getMailbox`, and the V2 register accessors from K 0xfffffff006c2ed94).
//!
//! The device-tree properties that change its behaviour are absent on the
//! J120's `sep` node (`ignore-mailboxes`, `cpu-ctrl-filtered`,
//! `force-timebase-sync`, `ignore-gating`, `auto-boot`, `post-retry-freq`),
//! so this has the defaults: the driver writes CPU_CTRL, makes no timebase
//! sync, posts retry at 10 Hz for 10 seconds. The SEP has no IOMapper
//! (nothing to activate) and its clock and power gates are the platform's
//! to open: [`A7iop::start_cpu`] says so by not waiting for them.

use super::akf::{self, ctrl, reg, Fault};
use super::frame::Message;
use super::hw::Hw;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// `AppleA7IOP::postMailbox`'s retry rate (`post-retry-freq`, default 10 Hz)
/// and its timeout in seconds (`a7iop_enable_timeout`, default 10): 100
/// retries of 100 ms.
pub const POST_RETRY_FREQ: u32 = 10;
pub const ENABLE_TIMEOUT_S: u32 = 10;

/// What a call of the driver returns when it is not success: the IOReturn
/// codes the driver names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IopError {
    /// `kIOReturnBusy`: `CPU already running`.
    Busy,
    /// `kIOReturnOffline`: a post while the core is not started.
    Offline,
    /// `kIOReturnNotReady`: an empty outbox.
    NotReady,
    /// `kIOReturnNoSpace`: a full inbox and no waiting.
    NoSpace,
    /// `kIOReturnTimeout`: the inbox stayed full.
    Timeout,
    /// The block faulted: an access the model has no answer for, or an
    /// overflow the hardware would flag.
    Fault(Fault),
    /// The driver REQUIREs a doorbell action before the core starts.
    NoDoorbellAction,
}

impl IopError {
    pub fn ioreturn(&self) -> i32 {
        (match self {
            IopError::Busy => 0xe00002d5_u32,
            IopError::Offline => 0xe00002d7,
            IopError::NotReady => 0xe00002d8,
            IopError::NoSpace => 0xe00002db,
            IopError::Timeout => 0xe00002d6,
            IopError::Fault(_) | IopError::NoDoorbellAction => 0xe00002bc,
        }) as i32
    }
}

impl From<Fault> for IopError {
    fn from(f: Fault) -> IopError {
        IopError::Fault(f)
    }
}

/// The manager's doorbell action (`_doorbellAction`): run when the outbox
/// has a message.
pub type Doorbell = Arc<dyn Fn() + Send + Sync>;

#[derive(Default)]
struct State {
    /// `_akfRunning`.
    running: bool,
    /// The doorbell action, set once (`setDoorbellAction` with index 0).
    action: Option<Doorbell>,
    /// The A2I slots the driver believes free (`credits`).
    credits: u32,
}

/// The driver. Its lock stands for `_akfLock` and the inbox and outbox
/// locks; interrupt index 1's and 2's sources (`IOFilterInterruptEventSource`s)
/// are enabled at the interrupt controller ([`Hw::set_source`]), which the
/// outbox interrupt's delivery reads without taking this lock (the filter,
/// `_outboxHandler` K 0xfffffff005b1309c, takes none: it calls the action).
pub struct A7iop {
    hw: Arc<Hw>,
    st: Mutex<State>,
}

impl A7iop {
    pub fn new(hw: Arc<Hw>) -> A7iop {
        A7iop { hw, st: Mutex::new(State::default()) }
    }

    pub fn hw(&self) -> &Arc<Hw> {
        &self.hw
    }

    fn st(&self) -> std::sync::MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn running(&self) -> bool {
        self.st().running
    }

    /// `setDoorbellAction(action, target, refcon, doorbellIndex = 0)`: set
    /// once; a second call fails.
    pub fn set_doorbell_action(&self, action: Doorbell) -> bool {
        let mut s = self.st();
        if s.action.is_some() {
            return false;
        }
        s.action = Some(action);
        true
    }

    /// `startCPU(NULL)` = `startCPUWithOptions(NULL, 0)`.
    pub fn start_cpu(&self) -> Result<(), IopError> {
        let mut s = self.st();
        if s.action.is_none() {
            return Err(IopError::NoDoorbellAction);
        }
        if s.running {
            return Err(IopError::Busy);
        }
        // _akfRunning, then the interrupt lines: MAILBOX_SET 0x1111, MAILBOX_CLR 1 and
        // 0x1000 (each also at its mirror), the outbox source enabled and the inbox source
        // disabled, OUTBOX_CTRL bit 0 set.
        s.running = true;
        s.credits = 0;
        let hw = &self.hw;
        hw.write32(reg::MAILBOX_SET, 0x1111)?;
        hw.write32(reg::MAILBOX_SET_MIRROR, 0x1111)?;
        hw.write32(reg::MAILBOX_CLR, 1)?;
        hw.write32(reg::MAILBOX_CLR_MIRROR, 1)?;
        hw.write32(reg::MAILBOX_CLR, 0x1000)?;
        hw.write32(reg::MAILBOX_CLR_MIRROR, 0x1000)?;
        hw.set_source(2, true);
        hw.set_source(1, false);
        let c = hw.read32(reg::OUTBOX_CTRL)?;
        hw.write32(reg::OUTBOX_CTRL, c & !ctrl::OUTBOX_ENABLE | ctrl::OUTBOX_ENABLE)?;
        // _setCPURun(1): CPU_CTRL's run bit.
        let c = hw.read32(reg::CPU_CTRL)?;
        hw.write32(reg::CPU_CTRL, c & !akf::CPU_RUN | akf::CPU_RUN)?;
        Ok(())
    }

    /// `stopCPU()`: the outbox disabled, both sources disabled, the run
    /// bit cleared.
    pub fn stop_cpu(&self) -> Result<(), IopError> {
        let mut s = self.st();
        let hw = &self.hw;
        let c = hw.read32(reg::OUTBOX_CTRL)?;
        hw.write32(reg::OUTBOX_CTRL, c & !ctrl::OUTBOX_ENABLE)?;
        hw.set_source(1, false);
        hw.set_source(2, false);
        let c = hw.read32(reg::CPU_CTRL)?;
        hw.write32(reg::CPU_CTRL, c & !akf::CPU_RUN)?;
        s.running = false;
        Ok(())
    }

    /// `postMailbox(0, &item, 0, wait)`: one message to the SEP. The driver
    /// counts A2I slots: it trusts 8 after it has seen the inbox empty, and
    /// waits (at the retry rate, up to the retry count) for an empty inbox
    /// when it has none.
    pub fn post_mailbox(&self, m: Message, wait: bool) -> Result<(), IopError> {
        let mut retries = ENABLE_TIMEOUT_S * POST_RETRY_FREQ;
        loop {
            {
                let mut s = self.st();
                if !s.running {
                    return Err(IopError::Offline);
                }
                if s.credits == 0 {
                    if self.hw.read32(reg::INBOX_CTRL)? & ctrl::EMPTY != 0 {
                        s.credits = akf::A2I_DEPTH as u32;
                    } else if !wait {
                        return Err(if retries > 0 { IopError::NoSpace } else { IopError::Timeout });
                    }
                }
                if s.credits > 0 {
                    s.credits -= 1;
                    self.hw.write64(reg::A2I, m.0)?;
                    return Ok(());
                }
                // The inbox source enabled (K 0xfffffff005b1333c) for the wait.
                self.hw.set_source(1, true);
            }
            let period = Duration::from_nanos(1_000_000_000 / u64::from(POST_RETRY_FREQ));
            if !self.hw.wait_until(period, |a, _| a.a2i_len() == 0) {
                retries -= 1;
                if retries == 0 {
                    return Err(IopError::Timeout);
                }
            }
        }
    }

    /// `getMailbox(0, &item, 0)`: the oldest message of the SEP's, or
    /// `NotReady` when the outbox is empty.
    pub fn get_mailbox(&self) -> Result<Message, IopError> {
        if self.hw.read32(reg::OUTBOX_CTRL)? & ctrl::EMPTY != 0 {
            return Err(IopError::NotReady);
        }
        Ok(Message(self.hw.read64(reg::I2A)?))
    }

    /// The doorbell thread: the outbox interrupt (index 2), a level that
    /// holds while the SEP has a message and its source is enabled; the
    /// action drains it. Ends when the machine closes.
    pub fn spawn_doorbell(self: &Arc<Self>) -> std::thread::JoinHandle<()> {
        let me = Arc::clone(self);
        std::thread::Builder::new()
            .name("AppleA7IOP outbox".into())
            .spawn(move || loop {
                let ready = me.hw.wait_interrupt(2, Duration::from_millis(50));
                if me.hw.is_closed() {
                    return;
                }
                if !ready {
                    continue;
                }
                let action = me.st().action.clone();
                if let Some(a) = action {
                    a();
                }
            })
            .expect("the doorbell thread")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn driver() -> (A7iop, Arc<Hw>) {
        let hw = Hw::new();
        let d = A7iop::new(Arc::clone(&hw));
        assert!(d.set_doorbell_action(Arc::new(|| {})));
        (d, hw)
    }

    #[test]
    fn start_needs_a_doorbell_action_and_runs_once() {
        let hw = Hw::new();
        let d = A7iop::new(Arc::clone(&hw));
        assert_eq!(d.start_cpu(), Err(IopError::NoDoorbellAction));
        assert!(d.set_doorbell_action(Arc::new(|| {})));
        assert!(!d.set_doorbell_action(Arc::new(|| {})), "set once");
        d.start_cpu().unwrap();
        assert_eq!(d.start_cpu(), Err(IopError::Busy));
        assert!(d.running());
    }

    #[test]
    fn start_programs_the_lines_the_outbox_and_the_run_bit() {
        let (d, hw) = driver();
        d.start_cpu().unwrap();
        assert!(hw.irq(1) && !hw.irq(2), "the inbox is empty, the outbox is too");
        assert!(hw.source_enabled(2) && !hw.source_enabled(1), "the outbox source enabled, the inbox source disabled");
        assert_eq!(hw.read32(reg::OUTBOX_CTRL).unwrap() & ctrl::OUTBOX_ENABLE, 1);
        assert_eq!(hw.run().running, true);
        hw.core_push(1).unwrap();
        assert!(hw.irq(2));
        d.stop_cpu().unwrap();
        assert!(!hw.irq(2) && !d.running() && !hw.run().running);
        assert!(!hw.source_enabled(1) && !hw.source_enabled(2));
    }

    #[test]
    fn a_post_before_the_core_starts_is_offline() {
        let (d, _) = driver();
        assert_eq!(d.post_mailbox(Message(1), false), Err(IopError::Offline));
        assert_eq!(IopError::Offline.ioreturn() as u32, 0xe00002d7);
    }

    #[test]
    fn eight_posts_fit_and_a_ninth_without_waiting_has_no_space() {
        let (d, hw) = driver();
        d.start_cpu().unwrap();
        for i in 0..8 {
            d.post_mailbox(Message(i), false).unwrap();
        }
        assert_eq!(d.post_mailbox(Message(9), false), Err(IopError::NoSpace));
        assert_eq!(IopError::NoSpace.ioreturn() as u32, 0xe00002db);
        // The core takes them in order; once it has emptied the inbox the AP trusts 8 again.
        for i in 0..8 {
            assert_eq!(hw.core_pop().unwrap(), i);
        }
        d.post_mailbox(Message(9), false).unwrap();
        assert_eq!(hw.core_pop().unwrap(), 9);
    }

    #[test]
    fn a_waiting_post_goes_when_the_core_empties_the_inbox() {
        let (d, hw) = driver();
        d.start_cpu().unwrap();
        for i in 0..8 {
            d.post_mailbox(Message(i), false).unwrap();
        }
        let h = Arc::clone(&hw);
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            while h.core_pop().is_ok() {}
        });
        d.post_mailbox(Message(100), true).unwrap();
        t.join().unwrap();
        assert_eq!(hw.core_pop().unwrap(), 100);
    }

    #[test]
    fn the_outbox_is_read_in_order_and_empty_is_not_ready() {
        let (d, hw) = driver();
        d.start_cpu().unwrap();
        assert_eq!(d.get_mailbox(), Err(IopError::NotReady));
        hw.core_push(0x0102_0304_0506_0708).unwrap();
        hw.core_push(2).unwrap();
        assert_eq!(d.get_mailbox().unwrap(), Message(0x0102_0304_0506_0708));
        assert_eq!(d.get_mailbox().unwrap(), Message(2));
        assert_eq!(d.get_mailbox(), Err(IopError::NotReady));
        assert_eq!(IopError::NotReady.ioreturn() as u32, 0xe00002d8);
    }

    #[test]
    fn the_doorbell_thread_runs_the_action_while_the_outbox_holds_a_message() {
        let hw = Hw::new();
        let d = Arc::new(A7iop::new(Arc::clone(&hw)));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (d2, s2) = (Arc::clone(&d), Arc::clone(&seen));
        d.set_doorbell_action(Arc::new(move || {
            while let Ok(m) = d2.get_mailbox() {
                s2.lock().unwrap().push(m.0);
            }
        }));
        let t = d.spawn_doorbell();
        d.start_cpu().unwrap();
        hw.core_push(7).unwrap();
        hw.core_push(8).unwrap();
        assert!(hw.wait_until(Duration::from_secs(5), |a, _| a.i2a_len() == 0));
        // The action pops before it records: give it the lock's turn.
        for _ in 0..200 {
            if seen.lock().unwrap().len() == 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(*seen.lock().unwrap(), vec![7, 8]);
        hw.close();
        t.join().unwrap();
    }
}
