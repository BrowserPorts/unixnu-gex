//! The SEP's mailbox block shared by the AP's driver and the SEP core: the
//! [`Akf`] registers behind one lock, the interrupt controller's enables
//! for the block's lines, and what each side waits for.

use super::akf::{Akf, Fault, Sink};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;
use crate::darwin::time::Instant;

/// Whether the SEP core is released (CPU_CTRL's run bit), and how many
/// times it has been: a core that is released again starts over.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Run {
    pub running: bool,
    pub releases: u32,
}

#[derive(Default)]
struct State {
    akf: Akf,
    run: Run,
    /// The interrupt controller's per-source enables for the block's
    /// interrupt indexes (bit `i`: index `i`). `IOInterruptEventSource`'s
    /// `enable()` and `disable()` reach the provider's `enableInterrupt` and
    /// `disableInterrupt`, the AIC's mask: delivery takes no lock of the
    /// driver's, so the mask lives here, beside the lines it gates.
    sources: u32,
    /// Set when the machine is going away: waiters return.
    closed: bool,
}

struct Notify<'a>(&'a mut Run);

impl Sink for Notify<'_> {
    fn run(&mut self, running: bool) {
        self.0.running = running;
        if running {
            self.0.releases += 1;
        }
    }
}

/// The block, shared.
#[derive(Default)]
pub struct Hw {
    state: Mutex<State>,
    changed: Condvar,
}

impl Hw {
    pub fn new() -> Arc<Hw> {
        Arc::new(Hw::default())
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn read32(&self, offset: u64) -> Result<u32, Fault> {
        self.lock().akf.read32(offset)
    }

    pub fn write32(&self, offset: u64, value: u32) -> Result<(), Fault> {
        let mut s = self.lock();
        let State { akf, run, .. } = &mut *s;
        akf.write32(offset, value, &mut Notify(run))?;
        drop(s);
        self.changed.notify_all();
        Ok(())
    }

    pub fn write64(&self, offset: u64, value: u64) -> Result<(), Fault> {
        self.lock().akf.write64(offset, value)?;
        self.changed.notify_all();
        Ok(())
    }

    pub fn read64(&self, offset: u64) -> Result<u64, Fault> {
        let v = self.lock().akf.read64(offset)?;
        self.changed.notify_all();
        Ok(v)
    }

    /// The SEP core's side: the oldest message the AP posted.
    pub fn core_pop(&self) -> Result<u64, Fault> {
        let v = self.lock().akf.core_pop()?;
        self.changed.notify_all();
        Ok(v)
    }

    /// The SEP core's side: a message for the AP.
    pub fn core_push(&self, m: u64) -> Result<(), Fault> {
        self.lock().akf.core_push(m)?;
        self.changed.notify_all();
        Ok(())
    }

    pub fn run(&self) -> Run {
        self.lock().run
    }

    pub fn irq(&self, index: u32) -> bool {
        self.lock().akf.irq(index)
    }

    /// Enable or disable interrupt index `index` at the interrupt
    /// controller. Enabling a line that is asserted delivers it: its
    /// waiter is woken.
    pub fn set_source(&self, index: u32, enabled: bool) {
        let mut s = self.lock();
        if enabled {
            s.sources |= 1 << index;
        } else {
            s.sources &= !(1 << index);
        }
        drop(s);
        self.changed.notify_all();
    }

    pub fn source_enabled(&self, index: u32) -> bool {
        self.lock().sources & 1 << index != 0
    }

    /// Release every waiter for good: the machine ends.
    pub fn close(&self) {
        self.lock().closed = true;
        self.changed.notify_all();
    }

    pub fn is_closed(&self) -> bool {
        self.lock().closed
    }

    /// Wait until `ready` holds of the registers, for at most `timeout`.
    /// False when it timed out or the machine closed.
    pub fn wait_until(&self, timeout: Duration, mut ready: impl FnMut(&Akf, &Run) -> bool) -> bool {
        self.wait_state(timeout, |s| ready(&s.akf, &s.run))
    }

    /// Wait until interrupt `index` is delivered (its line asserted and its
    /// source enabled), for at most `timeout`. False when it timed out or
    /// the machine closed.
    pub fn wait_interrupt(&self, index: u32, timeout: Duration) -> bool {
        self.wait_state(timeout, |s| s.akf.irq(index) && s.sources & 1 << index != 0)
    }

    fn wait_state(&self, timeout: Duration, mut ready: impl FnMut(&State) -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        let mut s = self.lock();
        loop {
            if ready(&s) {
                return true;
            }
            if s.closed {
                return false;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            s = self.changed.wait_timeout(s, deadline - now).unwrap_or_else(|e| e.into_inner()).0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::akf::{reg, CPU_RUN};
    use super::*;

    #[test]
    fn a_waiter_wakes_when_the_core_pushes() {
        let hw = Hw::new();
        let h = Arc::clone(&hw);
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            h.core_push(0x55).unwrap();
        });
        assert!(hw.wait_until(Duration::from_secs(5), |a, _| a.i2a_len() > 0));
        assert_eq!(hw.read64(reg::I2A).unwrap(), 0x55);
        t.join().unwrap();
    }

    #[test]
    fn a_wait_times_out_and_close_releases_it() {
        let hw = Hw::new();
        assert!(!hw.wait_until(Duration::from_millis(10), |a, _| a.i2a_len() > 0));
        let h = Arc::clone(&hw);
        let t = std::thread::spawn(move || h.wait_until(Duration::from_secs(30), |a, _| a.i2a_len() > 0));
        std::thread::sleep(Duration::from_millis(20));
        hw.close();
        assert!(!t.join().unwrap());
    }

    #[test]
    fn an_interrupt_is_delivered_only_while_its_source_is_enabled() {
        let hw = Hw::new();
        hw.write32(reg::MAILBOX_SET, 0x1111).unwrap();
        hw.write32(reg::OUTBOX_CTRL, 1).unwrap();
        hw.core_push(1).unwrap();
        assert!(hw.irq(2) && !hw.source_enabled(2));
        assert!(!hw.wait_interrupt(2, Duration::from_millis(10)), "the line is asserted, its source is masked");
        // Enabling the source of an asserted line delivers it to the waiter.
        let h = Arc::clone(&hw);
        let t = std::thread::spawn(move || h.wait_interrupt(2, Duration::from_secs(30)));
        std::thread::sleep(Duration::from_millis(20));
        hw.set_source(2, true);
        assert!(t.join().unwrap());
        hw.set_source(2, false);
        assert!(!hw.source_enabled(2));
    }

    #[test]
    fn the_run_bit_counts_releases() {
        let hw = Hw::new();
        hw.write32(reg::CPU_CTRL, CPU_RUN).unwrap();
        assert_eq!(hw.run(), Run { running: true, releases: 1 });
        hw.write32(reg::CPU_CTRL, 0).unwrap();
        hw.write32(reg::CPU_CTRL, CPU_RUN).unwrap();
        assert_eq!(hw.run(), Run { running: true, releases: 2 });
    }
}
