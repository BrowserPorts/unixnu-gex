//! The processor modes, the banked registers and the PSRs (B1.3), and the
//! system instructions that use them (B9.3).

use crate::{abi, need, unimpl, unpred, Core, PhysMem, Regs, Stop};

// B1.3.1 Table B1-1.
pub const USR: u8 = 0b10000;
pub const FIQ: u8 = 0b10001;
pub const IRQ: u8 = 0b10010;
pub const SVC: u8 = 0b10011;
pub const ABT: u8 = 0b10111;
pub const UND: u8 = 0b11011;
pub const SYS: u8 = 0b11111;

// CPSR bits the model keeps (B1.3.3).
pub const E: u32 = 1 << 9;
pub const A: u32 = 1 << 8;
pub const I: u32 = 1 << 7;
pub const F: u32 = 1 << 6;

/// `BadMode()` (B1.3.1) without the Security and Virtualization
/// Extensions: Monitor and Hyp are not modes.
pub fn bad_mode(m: u8) -> bool {
    !matches!(m, USR | FIQ | IRQ | SVC | ABT | UND | SYS)
}

/// The bank of SP and LR (`RBankSelect`): usr/sys, fiq, irq, svc, abt, und.
fn bank(m: u8) -> usize {
    match m {
        FIQ => 1,
        IRQ => 2,
        SVC => 3,
        ABT => 4,
        UND => 5,
        _ => 0,
    }
}

/// Which copy of `R<n>` (8..=14) mode `m` uses (`LookUpRName`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Usr(usize),
    Fiq(usize),
    Sp(usize),
    Lr(usize),
}

fn slot(n: u8, m: u8) -> Slot {
    match n {
        8..=12 if m == FIQ => Slot::Fiq(n as usize - 8),
        8..=12 => Slot::Usr(n as usize - 8),
        13 => Slot::Sp(bank(m)),
        _ => Slot::Lr(bank(m)),
    }
}

/// The SPSR of mode `m` (`SPSR[]`): fiq, irq, svc, abt, und.
pub fn spsr_index(m: u8) -> Option<usize> {
    match m {
        FIQ => Some(0),
        IRQ => Some(1),
        SVC => Some(2),
        ABT => Some(3),
        UND => Some(4),
        _ => None,
    }
}

/// `ITAdvance()` (A2.5.2).
pub fn it_advance(it: u8) -> u8 {
    if it & 7 == 0 {
        0
    } else {
        (it & 0xe0) | ((it << 1) & 0x1f)
    }
}

/// A CPSR value split into the parts the model, the context and the PC
/// key hold.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NewPsr {
    pub nzcvq: u32,
    pub ge: u8,
    pub sys: u32,
    pub it: u8,
    pub j: bool,
    pub t: bool,
}

impl Core {
    pub(crate) fn privileged(&self) -> bool {
        self.mode() != USR
    }

    fn slot_get(&self, s: Slot) -> u32 {
        match s {
            Slot::Usr(i) => self.hi_usr[i],
            Slot::Fiq(i) => self.hi_fiq[i],
            Slot::Sp(i) => self.sp[i],
            Slot::Lr(i) => self.lr[i],
        }
    }

    fn slot_set(&mut self, s: Slot, v: u32) {
        match s {
            Slot::Usr(i) => self.hi_usr[i] = v,
            Slot::Fiq(i) => self.hi_fiq[i] = v,
            Slot::Sp(i) => self.sp[i] = v,
            Slot::Lr(i) => self.lr[i] = v,
        }
    }

    /// CPSR.M = `m`: the banked registers of the old mode leave the context
    /// and the new mode's come in (B1.3.2, Figure B1-2).
    pub(crate) fn set_mode(&mut self, regs: &mut dyn Regs, m: u8) {
        let old = self.mode();
        for n in 8..=14u8 {
            let (a, b) = (slot(n, old), slot(n, m));
            if a != b {
                self.slot_set(a, regs.r(n));
                regs.set_r(n, self.slot_get(b));
            }
        }
        self.psr = (self.psr & !0x1f) | m as u32;
    }

    /// `Rmode[n, mode]` (B1.3.2), non-assignment form.
    pub(crate) fn rmode(&self, regs: &dyn Regs, n: u8, m: u8) -> Result<u32, Stop> {
        if bad_mode(m) {
            return unpred(format!("Rmode[{n}, {m:#07b}]: BadMode (B1.3.2 RBankSelect)"));
        }
        if n < 8 || slot(n, m) == slot(n, self.mode()) {
            Ok(regs.r(n))
        } else {
            Ok(self.slot_get(slot(n, m)))
        }
    }

    /// `Rmode[n, mode] = v` (B1.3.2), assignment form.
    pub(crate) fn rmode_set(&mut self, regs: &mut dyn Regs, n: u8, m: u8, v: u32, thumb: bool) -> Result<(), Stop> {
        if bad_mode(m) {
            return unpred(format!("Rmode[{n}, {m:#07b}] =: BadMode (B1.3.2 RBankSelect)"));
        }
        if n == 13 && v & 3 != 0 && thumb {
            return unpred("Rmode[13] = a value not word aligned outside the ARM state (B1.3.2)");
        }
        if n < 8 || slot(n, m) == slot(n, self.mode()) {
            regs.set_r(n, v);
        } else {
            self.slot_set(slot(n, m), v);
        }
        Ok(())
    }

    /// The CPSR (B1.3.3, Format of the CPSR and SPSRs) with the given
    /// ITSTATE and T bit.
    pub(crate) fn cpsr_value(&self, regs: &dyn Regs, it: u8, t: bool) -> u32 {
        let it = it as u32;
        (regs.nzcv() & 0xf000_0000)
            | (regs.q() as u32) << 27
            | (it & 3) << 25
            | (regs.ge() as u32 & 0xf) << 16
            | (it >> 2) << 10
            | self.psr
            | (t as u32) << 5
    }

    /// The new CPSR `CPSRWriteByInstr(value, bytemask, is_excpt_return)`
    /// (B1.3.3) gives, checked before anything changes.
    pub(crate) fn cpsr_write_value(&self, regs: &dyn Regs, value: u32, mask: u32, ret: bool) -> Result<NewPsr, Stop> {
        let privileged = self.privileged();
        let nmfi = self.sr.sctlr & crate::cp::SCTLR_NMFI != 0;
        let key = regs.pc_key();
        let mut n = NewPsr {
            nzcvq: (regs.nzcv() & 0xf000_0000) | (regs.q() as u32) << 27,
            ge: regs.ge(),
            sys: self.psr,
            it: abi::key_it(key),
            j: false,
            t: abi::key_thumb(key),
        };
        if mask & 8 != 0 {
            n.nzcvq = value & 0xf800_0000;
            if ret {
                n.it = (n.it & 0xfc) | ((value >> 25) & 3) as u8;
                n.j = value & (1 << 24) != 0;
            }
        }
        if mask & 4 != 0 {
            n.ge = ((value >> 16) & 0xf) as u8;
        }
        if mask & 2 != 0 {
            if ret {
                n.it = (n.it & 3) | (((value >> 10) & 0x3f) << 2) as u8;
            }
            // The E bit is user-writable (the pseudocode; B1.3.3's text says
            // an MSR at PL0 does not change it, which only matters for a
            // write of 1, a stop either way).
            n.sys = (n.sys & !E) | (value & E);
            if privileged {
                n.sys = (n.sys & !A) | (value & A);
            }
        }
        if mask & 1 != 0 {
            if privileged {
                n.sys = (n.sys & !I) | (value & I);
            }
            if privileged && (!nmfi || value & F == 0) {
                n.sys = (n.sys & !F) | (value & F);
            }
            if ret {
                n.t = value & (1 << 5) != 0;
            }
            if privileged {
                let m = (value & 0x1f) as u8;
                if bad_mode(m) {
                    return unpred(format!("CPSRWriteByInstr of mode {m:#07b}: BadMode (B1.3.3, B9.1.2)"));
                }
                n.sys = (n.sys & !0x1f) | m as u32;
            }
        }
        if n.sys & E != 0 {
            return unimpl("CPSR.E = 1: big-endian data accesses");
        }
        if n.j {
            // B1.8.10 Exception return to an unimplemented instruction set state.
            let thumbee = self.config.features.thumbee;
            if !thumbee && need(self.config.imp.psr_j_raz_wi, "whether the PSR J bits are RAZ/WI (B1.8.10)")? {
                n.j = false;
            } else if n.t {
                return unimpl("execution in the ThumbEE state (CPSR.{J, T} = 11)");
            } else {
                return unimpl("execution in the Jazelle state (CPSR.{J, T} = 10): the Undefined Instruction exception it takes on a trivial Jazelle implementation (B1.8.10)");
            }
        }
        if ret {
            // A2.5.2: ITSTATE must be 0 outside the Thumb state, and a
            // reserved value (Table A2-2) is UNPREDICTABLE.
            if !n.t && n.it != 0 {
                return unpred(format!("exception return to the ARM state with ITSTATE {:#04x} (A2.5.2)", n.it));
            }
            if n.it & 0xf == 0 && n.it != 0 {
                return unpred(format!("exception return with the reserved ITSTATE {:#04x} (A2.5.2 Table A2-2)", n.it));
            }
        }
        Ok(n)
    }

    /// Commit a [`NewPsr`]: the flags to the context, the mode (and banks)
    /// and mask bits to the model. The execution state bits go to the PC key
    /// on an exception return only ([`Core::exception_return`]).
    pub(crate) fn cpsr_commit(&mut self, regs: &mut dyn Regs, n: &NewPsr) {
        regs.set_nzcv(n.nzcvq & 0xf000_0000);
        regs.set_q(n.nzcvq & (1 << 27) != 0);
        regs.set_ge(n.ge);
        self.set_mode(regs, (n.sys & 0x1f) as u8);
        self.psr = n.sys;
    }

    /// `CPSRWriteByInstr(SPSR or the loaded word, '1111', TRUE)` then
    /// `BranchWritePC(addr)` (B9.3.13, B9.3.20, B9.3.5, B9.3.3), the PC key
    /// taking the restored T and IT. An exception return sets the Event
    /// Register (B1.8.13).
    pub(crate) fn exception_return(&mut self, regs: &mut dyn Regs, value: u32, addr: u32) -> Result<u64, Stop> {
        let n = self.cpsr_write_value(regs, value, 0xf, true)?;
        self.cpsr_commit(regs, &n);
        // A2.3.2 BranchWritePC.
        let pc = if n.t { addr & !1 } else { addr & !3 };
        regs.set_pc_key(self.pc_key(pc, n.t, n.it));
        self.event = true;
        Err(Stop::Resume)
    }

    /// Commit the CPSR an MSR or CPS writes. A change between User mode and a
    /// privileged mode changes the privilege of instruction fetches: the
    /// next instruction's key (which the lifter put in the context) takes
    /// the new level's `KEY_USER`, and execution resumes there.
    fn commit_by_instr(&mut self, regs: &mut dyn Regs, n: &NewPsr) -> Result<(), Stop> {
        let was_user = self.mode() == USR;
        self.cpsr_commit(regs, n);
        let user = self.mode() == USR;
        if was_user == user {
            return Ok(());
        }
        let next = regs.pc_key() & !abi::KEY_USER;
        regs.set_pc_key(next | if user { abi::KEY_USER } else { 0 });
        Err(Stop::Resume)
    }

    fn spsr_or_unpred(&self, what: &str) -> Result<u32, Stop> {
        match crate::psr::spsr_index(self.mode()) {
            Some(i) => Ok(self.spsr[i]),
            None => unpred(format!("{what} in User or System mode: SPSR[] (B1.3.3)")),
        }
    }

    /// B9.3.8 MRS; at PL0 the APSR view (A2.4: bits 9:6 and 4:0 UNKNOWN; the
    /// mask bits are not returned, as ARM recommends, and M reads as User).
    pub(crate) fn mrs(&self, regs: &dyn Regs, read_spsr: bool) -> Result<u32, Stop> {
        if read_spsr {
            return self.spsr_or_unpred("MRS SPSR");
        }
        let v = self.cpsr_value(regs, 0, false) & 0xf8ff_03df;
        if !self.privileged() {
            return Ok((v & !0x3df) | USR as u32);
        }
        Ok(v)
    }

    /// B9.3.11 MSR (immediate), B9.3.12 MSR (register): `a` the field mask
    /// and 0x10 for the SPSR.
    pub(crate) fn msr(&mut self, regs: &mut dyn Regs, a: u32, v: u32) -> Result<(), Stop> {
        let mask = a & 0xf;
        if a & 0x10 != 0 {
            return self.spsr_write_by_instr(v, mask);
        }
        let n = self.cpsr_write_value(regs, v, mask, false)?;
        self.commit_by_instr(regs, &n)
    }

    /// `SPSRWriteByInstr()` (B1.3.3).
    pub(crate) fn spsr_write_by_instr(&mut self, v: u32, mask: u32) -> Result<(), Stop> {
        let i = match spsr_index(self.mode()) {
            Some(i) => i,
            None => return unpred("SPSRWriteByInstr in User or System mode (B1.3.3)"),
        };
        let mut s = self.spsr[i];
        if mask & 8 != 0 {
            let mut top = v & 0xff00_0000;
            if v & (1 << 24) != 0 && !self.config.features.thumbee && need(self.config.imp.psr_j_raz_wi, "whether the PSR J bits are RAZ/WI (B1.8.10)")? {
                top &= !(1 << 24);
            }
            s = (s & 0x00ff_ffff) | top;
        }
        if mask & 4 != 0 {
            // Bits 23:20 are reserved, RAZ/SBZP.
            s = (s & !0x00ff_0000) | (v & 0x000f_0000);
        }
        if mask & 2 != 0 {
            s = (s & !0xff00) | (v & 0xff00);
        }
        if mask & 1 != 0 {
            let m = (v & 0x1f) as u8;
            if bad_mode(m) {
                return unpred(format!("SPSRWriteByInstr of mode {m:#07b}: BadMode (B1.3.3)"));
            }
            s = (s & !0xff) | (v & 0xff);
        }
        self.spsr[i] = s;
        Ok(())
    }

    /// B9.3.1, B9.3.2 CPS: `a` is imod (1:0), A (2), I (3), F (4),
    /// changemode (5) and the mode (12:8). A NOP in User mode.
    pub(crate) fn cps(&mut self, regs: &mut dyn Regs, a: u32) -> Result<(), Stop> {
        if !self.privileged() {
            return Ok(());
        }
        let imod = a & 3;
        let bits = (a >> 2) & 7; // A I F
        let mut v = self.cpsr_value(regs, 0, false);
        let affect = ((bits & 1) * A) | ((bits >> 1 & 1) * I) | ((bits >> 2 & 1) * F);
        match imod {
            0b10 => v &= !affect,
            0b11 => v |= affect,
            _ => {}
        }
        if a & (1 << 5) != 0 {
            v = (v & !0x1f) | ((a >> 8) & 0x1f);
        }
        let n = self.cpsr_write_value(regs, v, 0xf, false)?;
        self.commit_by_instr(regs, &n)
    }

    /// A8.8.157 SETEND.
    pub(crate) fn setend(&mut self, big: bool) -> Result<(), Stop> {
        if big {
            return unimpl("SETEND BE: big-endian data accesses (CPSR.E = 1)");
        }
        self.psr &= !E;
        Ok(())
    }

    /// B9.3.6 LDM (User registers) and B9.3.17 STM (User registers):
    /// `Rmode[n, '10000']`.
    pub(crate) fn user_reg(&mut self, regs: &mut dyn Regs, n: u8, w: Option<u32>) -> Result<u32, Stop> {
        if matches!(self.mode(), USR | SYS) {
            return unpred("LDM/STM (User registers) in User or System mode (B9.3.6, B9.3.17)");
        }
        if !(8..=14).contains(&n) {
            return unimpl(format!("USER_READ/USER_WRITE of R{n}"));
        }
        match w {
            Some(v) => {
                let thumb = abi::key_thumb(regs.pc_key());
                self.rmode_set(regs, n, USR, v, thumb)?;
                Ok(0)
            }
            None => self.rmode(regs, n, USR),
        }
    }

    /// B9.3.20 SUBS PC, LR and related instructions (ARM), B9.3.19 (Thumb).
    pub(crate) fn alu_return(&mut self, regs: &mut dyn Regs, result: u32) -> Result<u64, Stop> {
        if matches!(self.mode(), USR | SYS) {
            return unpred("SUBS PC, LR and related instructions in User or System mode (B9.1.1)");
        }
        let spsr = self.spsr_or_unpred("SUBS PC, LR")?;
        self.exception_return(regs, spsr, result)
    }

    /// B9.3.5 LDM (exception return).
    pub(crate) fn ldm_return(&mut self, regs: &mut dyn Regs, new_pc: u32) -> Result<u64, Stop> {
        if matches!(self.mode(), USR | SYS) {
            return unpred("LDM (exception return) in User or System mode (B9.1.1)");
        }
        let spsr = self.spsr_or_unpred("LDM (exception return)")?;
        self.exception_return(regs, spsr, new_pc)
    }

    /// B9.3.3 ERET at PL1: `MOVS PC, LR` (and the Thumb `SUBS PC, LR, #0`).
    pub(crate) fn eret(&mut self, regs: &mut dyn Regs) -> Result<u64, Stop> {
        if matches!(self.mode(), USR | SYS) {
            return unpred("ERET in User or System mode (B9.3.3)");
        }
        let spsr = self.spsr_or_unpred("ERET")?;
        let lr = regs.r(14);
        self.exception_return(regs, spsr, lr)
    }

    /// B9.3.16 SRS: `a` is the mode (4:0), the addressing mode (9:8, IA IB
    /// DA DB) and writeback (10).
    pub(crate) fn srs(&mut self, regs: &mut dyn Regs, mem: &mut dyn PhysMem, pc: u64, a: u32) -> Result<u64, Stop> {
        if matches!(self.mode(), USR | SYS) {
            return unpred("SRS in User or System mode (B9.3.16)");
        }
        let mode = (a & 0x1f) as u8;
        let (increment, wordhigher) = amode(a);
        let wback = a & (1 << 10) != 0;
        let base = self.rmode(regs, 13, mode)?;
        let mut address = if increment { base } else { base.wrapping_sub(8) };
        if wordhigher {
            address = address.wrapping_add(4);
        }
        let lr = regs.r(14);
        let spsr = self.spsr_or_unpred("SRS")?;
        self.mem_a_write(regs, mem, pc, address, lr)?;
        self.mem_a_write(regs, mem, pc, address.wrapping_add(4), spsr)?;
        if wback {
            let nb = if increment { base.wrapping_add(8) } else { base.wrapping_sub(8) };
            self.rmode_set(regs, 13, mode, nb, abi::key_thumb(pc))?;
        }
        Ok(0)
    }

    /// B9.3.13 RFE: `a` is Rn (3:0), the addressing mode (9:8) and
    /// writeback (10).
    pub(crate) fn rfe(&mut self, regs: &mut dyn Regs, mem: &mut dyn PhysMem, pc: u64, a: u32) -> Result<u64, Stop> {
        if !self.privileged() {
            return unpred("RFE in User mode (B9.3.13)");
        }
        let n = (a & 0xf) as u8;
        let (increment, wordhigher) = amode(a);
        let wback = a & (1 << 10) != 0;
        let base = regs.r(n);
        let mut address = if increment { base } else { base.wrapping_sub(8) };
        if wordhigher {
            address = address.wrapping_add(4);
        }
        let new_pc = self.mem_a_read(regs, mem, pc, address)?;
        let spsr = self.mem_a_read(regs, mem, pc, address.wrapping_add(4))?;
        if wback {
            regs.set_r(n, if increment { base.wrapping_add(8) } else { base.wrapping_sub(8) });
        }
        self.exception_return(regs, spsr, new_pc)
    }
}

/// `Amode` bits 9:8 (IA IB DA DB): (increment, wordhigher = P == U).
fn amode(a: u32) -> (bool, bool) {
    match (a >> 8) & 3 {
        0 => (true, false),
        1 => (true, true),
        2 => (false, true),
        _ => (false, false),
    }
}
