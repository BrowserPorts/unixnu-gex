//! The SEP's mailbox hardware: the AKF block behind `/arm-io/sep`'s first
//! `reg` entry, as AppleA7IOPV2 (the driver `iop,s8000` matches) programs it
//! (the registers: `drafts/sep/01-a7iop-mailbox.md`, each read from the
//! kernelcache's AppleA7IOP and AKFWrap-v2 kexts).
//!
//! Two FIFOs of 64-bit messages connect the AP and the SEP core: A2I (the
//! AP's 8-byte store to `0x4010` pushes) and I2A (its 8-byte load from
//! `0x4038` pops). This model has the AP's registers and the SEP core's
//! side of the FIFOs ([`Akf::core_pop`], [`Akf::core_push`]); the SEP core's
//! own view of the block (its register addresses) is the SEPROM's and the
//! sepOS's, which no AP binary has, so it is not modelled: the core harness
//! is what reaches the FIFOs.
//!
//! What the kernelcache does not say, and so what this does not claim:
//! - the real depth of either FIFO (the AP treats an empty A2I as 8 free
//!   slots, so [`A2I_DEPTH`] is that, and an AP that posts a ninth message
//!   unchecked faults);
//! - which half of a 64-bit access pushes or pops (the AP makes one 8-byte
//!   access, and so does this; a 32-bit access to a message register is
//!   reported);
//! - which of INBOX_CTRL's bits 18 and 19 is the underflow and which the
//!   overflow, and what bit 16 is (the AP only panics on either of the
//!   two, so a legal exchange never sets them; a fault here is reported
//!   and sets neither);
//! - MAILBOX_SET/CLR's read-back and polarity beyond their use: the driver
//!   sets `0x1111` and clears `0x1` and `0x1000`, leaving bits 4 and 8, the
//!   lines of interrupt indexes 1 and 2, the two it makes sources of.

use std::collections::VecDeque;

/// The window's physical address: arm-io's `ranges` base (0x200000000) and
/// the `sep` node's first `reg` entry (0x0da00000, size 0x10000).
pub const BASE: u64 = 0x2_0da0_0000;
pub const SIZE: u64 = 0x1_0000;

/// The depth the AP assumes of an empty A2I (`AppleA7IOP::postMailbox`
/// resets its credits to 8 when INBOX_CTRL reads empty).
pub const A2I_DEPTH: usize = 8;

/// The depth of I2A. The AP empties it at every interrupt; its real depth
/// is not in the AP's code.
pub const I2A_DEPTH: usize = 8;

/// The AIC interrupt numbers of the `sep` node's `interrupts`, by the index
/// the driver uses: 1 (0x6f) is "A2I empty", 2 (0x72) is "I2A not empty".
/// Indexes 0 (0x70) and 3 (0x71) have no source.
pub const IRQ_A2I_EMPTY: u32 = 0x6f;
pub const IRQ_I2A_NOT_EMPTY: u32 = 0x72;

pub mod reg {
    pub const MAILBOX_SET: u64 = 0x4000;
    pub const MAILBOX_CLR: u64 = 0x4004;
    pub const MAILBOX_SET_MIRROR: u64 = 0x0c00;
    pub const MAILBOX_CLR_MIRROR: u64 = 0x0c04;
    pub const INBOX_CTRL: u64 = 0x4008;
    pub const A2I: u64 = 0x4010;
    pub const OUTBOX_CTRL: u64 = 0x4020;
    pub const I2A: u64 = 0x4038;
    pub const IDLE_STATUS: u64 = 0x4040;
    /// Read by `_enablePower` only, which AppleSEPManager never calls.
    pub const READY: u64 = 0x0b88;
    pub const CPU_CTRL: u64 = 0x0044;
}

/// `MBOX_CTRL`'s bits as the driver tests them.
pub mod ctrl {
    pub const EMPTY: u32 = 1 << 17;
    /// Read by nothing in the kernelcache; [inferred] "full".
    pub const FULL: u32 = 1 << 16;
    /// "MBOX_CTRL_udfl" and "MBOX_CTRL_ovfl": which is which is not traced.
    pub const ERROR: u32 = 3 << 18;
    /// OUTBOX_CTRL bit 0, which `startCPU` sets and `stopCPU` clears.
    pub const OUTBOX_ENABLE: u32 = 1;
}

/// CPU_CTRL's run bit (`_setCPURun`).
pub const CPU_RUN: u32 = 1 << 4;

/// The lines MAILBOX_SET/CLR enable: bit `4 * i` for interrupt index `i`.
pub fn line_bit(index: u32) -> u32 {
    1 << (4 * index)
}

/// A register access the model does not do. The AP's code and the SEP
/// core's reach only what is modelled; anything else is reported by the
/// caller (`darwin_unimplemented`), never answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    /// A register or width this block's model has no answer for.
    Unmodelled { offset: u64, write: bool, width: u8, what: &'static str },
    /// A message pushed into a full FIFO (`from_ap`: A2I) or popped from an
    /// empty one: what the hardware flags in bits 18/19.
    Overflow { from_ap: bool },
    Underflow { from_ap: bool },
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fault::Unmodelled { offset, write, width, what } => {
                write!(f, "the SEP mailbox's {} of {} bits at {offset:#x} ({what})", if *write { "write" } else { "read" }, width * 8)
            }
            Fault::Overflow { from_ap: true } => f.write_str("a message posted to a full A2I mailbox FIFO"),
            Fault::Overflow { from_ap: false } => f.write_str("a message posted by the SEP core to a full I2A mailbox FIFO"),
            Fault::Underflow { from_ap: true } => f.write_str("a message read from an empty I2A mailbox FIFO"),
            Fault::Underflow { from_ap: false } => f.write_str("a message read by the SEP core from an empty A2I mailbox FIFO"),
        }
    }
}

/// What the block tells the rest of the system.
pub trait Sink {
    /// CPU_CTRL's run bit changed: the SEP core is released (true) or
    /// held (false).
    fn run(&mut self, running: bool);
}

/// The block's state.
#[derive(Debug, Default)]
pub struct Akf {
    a2i: VecDeque<u64>,
    i2a: VecDeque<u64>,
    /// The lines MAILBOX_SET/CLR have enabled.
    lines: u32,
    outbox_enable: bool,
    cpu_ctrl: u32,
}

impl Akf {
    pub fn new() -> Akf {
        Akf::default()
    }

    pub fn running(&self) -> bool {
        self.cpu_ctrl & CPU_RUN != 0
    }

    fn inbox_ctrl(&self) -> u32 {
        (if self.a2i.is_empty() { ctrl::EMPTY } else { 0 }) | (if self.a2i.len() >= A2I_DEPTH { ctrl::FULL } else { 0 })
    }

    fn outbox_ctrl(&self) -> u32 {
        (if self.i2a.is_empty() { ctrl::EMPTY } else { 0 }) | (if self.i2a.len() >= I2A_DEPTH { ctrl::FULL } else { 0 }) | u32::from(self.outbox_enable)
    }

    fn unmodelled(offset: u64, write: bool, width: u8, what: &'static str) -> Fault {
        Fault::Unmodelled { offset, write, width, what }
    }

    /// A 32-bit read by the AP.
    pub fn read32(&mut self, offset: u64) -> Result<u32, Fault> {
        match offset {
            reg::INBOX_CTRL => Ok(self.inbox_ctrl()),
            reg::OUTBOX_CTRL => Ok(self.outbox_ctrl()),
            reg::CPU_CTRL => Ok(self.cpu_ctrl),
            // The block's "ready" bit, which only `_enablePower` polls.
            reg::READY => Err(Self::unmodelled(offset, false, 4, "the ready bit: only AppleA7IOP::_enablePower reads it, which AppleSEPManager does not call")),
            reg::IDLE_STATUS => Err(Self::unmodelled(offset, false, 4, "IDLE_STATUS: read only by the driver's status dump")),
            reg::MAILBOX_SET | reg::MAILBOX_CLR => Err(Self::unmodelled(offset, false, 4, "MAILBOX_SET/CLR's read-back: read only by the driver's status dump")),
            _ => Err(Self::unmodelled(offset, false, 4, "no register of this model")),
        }
    }

    /// A 32-bit write by the AP. `sink` hears of the core's release.
    pub fn write32(&mut self, offset: u64, value: u32, sink: &mut dyn Sink) -> Result<(), Fault> {
        match offset {
            // Each write to the pair is repeated at its mirror by the
            // driver; the mirror's meaning is not traced, so it is taken
            // as the same line state, which a repeat leaves as it is.
            reg::MAILBOX_SET => self.lines |= value,
            reg::MAILBOX_CLR => self.lines &= !value,
            reg::MAILBOX_SET_MIRROR | reg::MAILBOX_CLR_MIRROR => {}
            reg::OUTBOX_CTRL => self.outbox_enable = value & ctrl::OUTBOX_ENABLE != 0,
            reg::CPU_CTRL => {
                let was = self.running();
                self.cpu_ctrl = value;
                if self.running() != was {
                    sink.run(self.running());
                }
            }
            _ => return Err(Self::unmodelled(offset, true, 4, "no register of this model (the driver writes the firmware map, the timebase and the doorbell only on paths the SEP's does not take)")),
        }
        Ok(())
    }

    /// The AP's 8-byte store: A2I pushes.
    pub fn write64(&mut self, offset: u64, value: u64) -> Result<(), Fault> {
        if offset != reg::A2I {
            return Err(Self::unmodelled(offset, true, 8, "only the A2I message register takes 8-byte stores"));
        }
        if self.a2i.len() >= A2I_DEPTH {
            return Err(Fault::Overflow { from_ap: true });
        }
        self.a2i.push_back(value);
        Ok(())
    }

    /// The AP's 8-byte load: I2A pops.
    pub fn read64(&mut self, offset: u64) -> Result<u64, Fault> {
        if offset != reg::I2A {
            return Err(Self::unmodelled(offset, false, 8, "only the I2A message register takes 8-byte loads"));
        }
        self.i2a.pop_front().ok_or(Fault::Underflow { from_ap: true })
    }

    /// The SEP core takes the oldest message of A2I.
    pub fn core_pop(&mut self) -> Result<u64, Fault> {
        self.a2i.pop_front().ok_or(Fault::Underflow { from_ap: false })
    }

    /// The SEP core puts a message in I2A.
    pub fn core_push(&mut self, m: u64) -> Result<(), Fault> {
        if self.i2a.len() >= I2A_DEPTH {
            return Err(Fault::Overflow { from_ap: false });
        }
        self.i2a.push_back(m);
        Ok(())
    }

    pub fn a2i_len(&self) -> usize {
        self.a2i.len()
    }

    pub fn i2a_len(&self) -> usize {
        self.i2a.len()
    }

    /// Whether interrupt `index` is asserted (a level: it stays while its
    /// condition holds, and nothing acknowledges it in the block): index 2
    /// while I2A has a message, index 1 while A2I is empty, each only when
    /// its line is enabled by MAILBOX_SET/CLR and, for index 2, OUTBOX_CTRL's
    /// enable is set. Indexes 0 and 3 have no source.
    pub fn irq(&self, index: u32) -> bool {
        match index {
            1 => self.lines & line_bit(1) != 0 && self.a2i.is_empty(),
            2 => self.lines & line_bit(2) != 0 && self.outbox_enable && !self.i2a.is_empty(),
            _ => false,
        }
    }

    pub fn lines(&self) -> u32 {
        self.lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Run(Vec<bool>);
    impl Sink for Run {
        fn run(&mut self, r: bool) {
            self.0.push(r);
        }
    }

    #[test]
    fn a_fresh_block_has_both_fifos_empty() {
        let mut a = Akf::new();
        assert_eq!(a.read32(reg::INBOX_CTRL).unwrap(), ctrl::EMPTY);
        assert_eq!(a.read32(reg::OUTBOX_CTRL).unwrap(), ctrl::EMPTY);
        assert!(!a.running());
    }

    #[test]
    fn the_ap_pushes_and_the_core_pops_in_order() {
        let mut a = Akf::new();
        a.write64(reg::A2I, 0x0102_0300_0001_0201).unwrap();
        a.write64(reg::A2I, 7).unwrap();
        assert_eq!(a.read32(reg::INBOX_CTRL).unwrap() & ctrl::EMPTY, 0);
        assert_eq!(a.core_pop().unwrap(), 0x0102_0300_0001_0201);
        assert_eq!(a.core_pop().unwrap(), 7);
        assert_eq!(a.read32(reg::INBOX_CTRL).unwrap(), ctrl::EMPTY);
    }

    #[test]
    fn the_core_pushes_and_the_ap_pops_in_order() {
        let mut a = Akf::new();
        a.core_push(1).unwrap();
        a.core_push(2).unwrap();
        assert_eq!(a.read32(reg::OUTBOX_CTRL).unwrap() & ctrl::EMPTY, 0);
        assert_eq!(a.read64(reg::I2A).unwrap(), 1);
        assert_eq!(a.read64(reg::I2A).unwrap(), 2);
        assert_eq!(a.read32(reg::OUTBOX_CTRL).unwrap() & ctrl::EMPTY, ctrl::EMPTY);
    }

    #[test]
    fn eight_messages_fit_after_an_empty_read_and_a_ninth_faults() {
        let mut a = Akf::new();
        for i in 0..A2I_DEPTH as u64 {
            a.write64(reg::A2I, i).unwrap();
        }
        assert_eq!(a.write64(reg::A2I, 99), Err(Fault::Overflow { from_ap: true }));
        // A fault sets no error bit: the AP's panic is for a block that
        // flagged one, which a legal exchange never has.
        assert_eq!(a.read32(reg::INBOX_CTRL).unwrap() & ctrl::ERROR, 0);
        assert_eq!(a.a2i_len(), A2I_DEPTH);
    }

    #[test]
    fn popping_an_empty_fifo_faults() {
        let mut a = Akf::new();
        assert_eq!(a.read64(reg::I2A), Err(Fault::Underflow { from_ap: true }));
        assert_eq!(a.core_pop(), Err(Fault::Underflow { from_ap: false }));
    }

    #[test]
    fn the_drivers_enable_sequence_leaves_the_two_used_lines() {
        let mut a = Akf::new();
        let mut run = Run::default();
        // startCPUWithOptions, steps 1-3 and 5 (K 0xfffffff005b127f0..0xfffffff005b12880).
        a.write32(reg::MAILBOX_SET, 0x1111, &mut run).unwrap();
        a.write32(reg::MAILBOX_CLR, 1, &mut run).unwrap();
        a.write32(reg::MAILBOX_CLR, 0x1000, &mut run).unwrap();
        a.write32(reg::OUTBOX_CTRL, ctrl::OUTBOX_ENABLE, &mut run).unwrap();
        assert_eq!(a.lines(), line_bit(1) | line_bit(2));
        // Index 1: A2I is empty. Index 2: I2A is.
        assert!(a.irq(1) && !a.irq(2) && !a.irq(0) && !a.irq(3));
        a.core_push(5).unwrap();
        assert!(a.irq(2));
        a.read64(reg::I2A).unwrap();
        assert!(!a.irq(2));
        a.write64(reg::A2I, 1).unwrap();
        assert!(!a.irq(1));
    }

    #[test]
    fn a_disabled_outbox_raises_nothing() {
        let mut a = Akf::new();
        let mut run = Run::default();
        a.write32(reg::MAILBOX_SET, 0x1111, &mut run).unwrap();
        a.core_push(1).unwrap();
        assert!(!a.irq(2));
        a.write32(reg::OUTBOX_CTRL, ctrl::OUTBOX_ENABLE, &mut run).unwrap();
        assert!(a.irq(2));
        a.write32(reg::OUTBOX_CTRL, 0, &mut run).unwrap();
        assert!(!a.irq(2));
    }

    #[test]
    fn the_run_bit_releases_and_halts_the_core() {
        let mut a = Akf::new();
        let mut run = Run::default();
        a.write32(reg::CPU_CTRL, CPU_RUN, &mut run).unwrap();
        a.write32(reg::CPU_CTRL, CPU_RUN, &mut run).unwrap();
        assert!(a.running());
        a.write32(reg::CPU_CTRL, 0, &mut run).unwrap();
        assert_eq!(run.0, vec![true, false]);
    }

    #[test]
    fn what_the_model_has_no_answer_for_is_reported() {
        let mut a = Akf::new();
        let mut run = Run::default();
        for off in [reg::READY, reg::IDLE_STATUS, reg::MAILBOX_SET, 0x1234] {
            assert!(matches!(a.read32(off), Err(Fault::Unmodelled { .. })), "{off:#x}");
        }
        // The firmware map, the doorbell and the timebase: not written for the SEP.
        for off in [0x8, 0x38, 0xc004, 0xc024, 0x80c, 0xc030] {
            assert!(matches!(a.write32(off, 1, &mut run), Err(Fault::Unmodelled { write: true, .. })), "{off:#x}");
        }
        // A 32-bit access to a message register is not one the AP makes.
        assert!(matches!(a.write32(reg::A2I, 1, &mut run), Err(Fault::Unmodelled { .. })));
        assert!(matches!(a.read32(reg::I2A), Err(Fault::Unmodelled { .. })));
        assert!(matches!(a.write64(reg::CPU_CTRL, 1), Err(Fault::Unmodelled { .. })));
    }
}
