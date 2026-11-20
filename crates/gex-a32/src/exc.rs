//! Exception entry (B1.8, B1.9), Reset (B1.9.1), and the checks the
//! architecture makes before an unimplemented instruction would execute.

use crate::cp::{SCTLR_EE, SCTLR_TE, SCTLR_V, SCTLR_VE};
use crate::psr::{self, it_advance, A, ABT, E, F, FIQ, I, IRQ, SVC, UND};
use crate::{abi, need, unimpl, unpred, Core, PhysMem, Regs, Stop};
use gex_isa_a32::{fp::FpInst, ItState, Op};

impl Core {
    /// `ExcVectorBase()` (B1.8.1), without the Security Extensions.
    pub(crate) fn exc_vector_base(&self) -> u32 {
        if self.sr.sctlr & SCTLR_V != 0 {
            0xffff_0000
        } else {
            0
        }
    }

    /// The common part of every exception entry to a PL1 mode (B1.9.2-B1.9.12
    /// pseudocode): CPSR.M, `SPSR[]`, `R[14]`, the mask bits, IT, J, T from
    /// SCTLR.TE, E from SCTLR.EE, and the branch to the vector. `extra` are
    /// the mask bits set besides I (A, F).
    pub(crate) fn enter(&mut self, regs: &mut dyn Regs, mode: u8, spsr: u32, lr: u32, vect: u32, extra: u32) -> Result<(), Stop> {
        if self.sr.sctlr & SCTLR_EE != 0 {
            return unimpl("exception entry with SCTLR.EE = 1: big-endian data accesses (CPSR.E = 1)");
        }
        let clear_cv = self.joscr_cv_cleared_on_entry()?;
        self.set_mode(regs, mode);
        let i = psr::spsr_index(mode).expect("an exception mode");
        self.spsr[i] = spsr;
        regs.set_r(14, lr);
        self.psr = (self.psr & !E) | I | extra;
        if clear_cv {
            self.sr.joscr &= !2;
        }
        let t = self.sr.sctlr & SCTLR_TE != 0;
        let pc = self.exc_vector_base().wrapping_add(vect);
        regs.set_pc_key(self.pc_key(pc, t, 0));
        Ok(())
    }

    /// ID_PFR0.State2 = 0b0010: the Jazelle extension clears JOSCR.CV on
    /// exception entry (B4.1.93); only a JOSCR that holds its value has one.
    fn joscr_cv_cleared_on_entry(&self) -> Result<bool, Stop> {
        if self.sr.joscr & 2 == 0 {
            return Ok(false);
        }
        let pfr0 = need(self.config.imp.id_pfr[0], "ID_PFR0 (whether exception entry clears JOSCR.CV)")?;
        Ok((pfr0 >> 8) & 0xf == 0b0010)
    }

    /// `TakeUndefInstrException()` (B1.9.2) for the instruction at key `pc`.
    pub(crate) fn take_undef(&mut self, regs: &mut dyn Regs, pc: u64) -> Result<u64, Stop> {
        let (addr, t, it) = (abi::key_addr(pc), abi::key_thumb(pc), abi::key_it(pc));
        let spsr = self.cpsr_value(regs, it, t);
        let lr = addr.wrapping_add(if t { 2 } else { 4 });
        self.enter(regs, UND, spsr, lr, 4, 0)?;
        Err(Stop::Resume)
    }

    /// `TakeSVCException()` (B1.9.4): SPSR.IT as `ITAdvance()` leaves it,
    /// LR the next instruction (SVC is 2 bytes in Thumb, 4 in ARM).
    pub(crate) fn take_svc(&mut self, regs: &mut dyn Regs, pc: u64) -> Result<u64, Stop> {
        let (addr, t, it) = (abi::key_addr(pc), abi::key_thumb(pc), abi::key_it(pc));
        let spsr = self.cpsr_value(regs, it_advance(it), t);
        let lr = addr.wrapping_add(if t { 2 } else { 4 });
        self.enter(regs, SVC, spsr, lr, 8, 0)?;
        Err(Stop::Resume)
    }

    /// `TakePrefetchAbortException()` (B1.9.7), the IFSR and IFAR already
    /// written: LR is the instruction's address + 4 in both states.
    pub(crate) fn take_pabt(&mut self, regs: &mut dyn Regs, pc: u64) -> Result<u64, Stop> {
        let (addr, t, it) = (abi::key_addr(pc), abi::key_thumb(pc), abi::key_it(pc));
        let spsr = self.cpsr_value(regs, it, t);
        self.enter(regs, ABT, spsr, addr.wrapping_add(4), 12, A)?;
        Err(Stop::Resume)
    }

    /// `TakeDataAbortException()` (B1.9.8), the DFSR and DFAR already
    /// written: LR is the instruction's address + 8 in both states.
    pub(crate) fn take_dabt(&mut self, regs: &mut dyn Regs, pc: u64) -> Result<u64, Stop> {
        let (addr, t, it) = (abi::key_addr(pc), abi::key_thumb(pc), abi::key_it(pc));
        let spsr = self.cpsr_value(regs, it, t);
        self.enter(regs, ABT, spsr, addr.wrapping_add(8), 16, A)?;
        Err(Stop::Resume)
    }

    /// `TakePhysicalIRQException()` (B1.9.10) at the instruction boundary
    /// before `next` (the key of the instruction that would execute next).
    /// No interrupt source exists yet; this is the entry an interrupt
    /// controller model will call.
    pub fn take_irq(&mut self, regs: &mut dyn Regs, next: u64) -> Result<(), Stop> {
        self.take_interrupt(regs, next, IRQ, 24, A)
    }

    /// `TakePhysicalFIQException()` (B1.9.12), as [`Core::take_irq`].
    pub fn take_fiq(&mut self, regs: &mut dyn Regs, next: u64) -> Result<(), Stop> {
        self.take_interrupt(regs, next, FIQ, 28, A | F)
    }

    fn take_interrupt(&mut self, regs: &mut dyn Regs, next: u64, mode: u8, vect: u32, extra: u32) -> Result<(), Stop> {
        if self.sr.sctlr & SCTLR_VE != 0 {
            return Err(Stop::ImpDef("SCTLR.VE = 1: the IMPLEMENTATION DEFINED IRQ/FIQ vector (B1.8.1 Vectored interrupt support)".into()));
        }
        let (addr, t, it) = (abi::key_addr(next), abi::key_thumb(next), abi::key_it(next));
        let spsr = self.cpsr_value(regs, it, t);
        self.enter(regs, mode, spsr, addr.wrapping_add(4), vect, extra)
    }

    /// `TakeReset()` (B1.9.1).
    pub(crate) fn take_reset(&mut self, regs: &mut dyn Regs) -> Result<(), Stop> {
        let imp = &self.config.imp;
        if need(imp.reset_ee, "the reset value of SCTLR.EE (CFGEND)")? {
            return unimpl("reset with SCTLR.EE = 1: big-endian data accesses (CPSR.E = 1)");
        }
        let reset_vector = need(imp.reset_vector, "whether the core has an IMPLEMENTATION DEFINED reset vector (B1.9.1)")?;
        let sctlr = self.sctlr_reset()?;
        // CPSR.M = '10011'; ResetControlRegisters().
        self.set_mode(regs, SVC);
        self.reset_control_registers(sctlr);
        // HaveAdvSIMDorVFP(): FPEXC.EN = '0'; HaveThumbEE(): TEECR.XED = '0';
        // HaveJazelle(): JMCR.JE = '0' (RAZ/WI on a trivial implementation).
        self.sr.fpexc &= !(1 << 30);
        self.sr.teecr = 0;
        // CPSR.{I, F, A} = 1, IT = 0, J = 0, T = SCTLR.TE, E = SCTLR.EE.
        self.psr = SVC as u32 | A | I | F;
        let t = self.sr.sctlr & SCTLR_TE != 0;
        let base = match reset_vector {
            Some(v) => v,
            None => self.exc_vector_base(),
        };
        regs.set_pc_key(self.pc_key(base & !1, t, 0));
        Ok(())
    }

    /// `EXCEPTION`: take exception `kind` (`gex_abi::a32::exc`) for the
    /// instruction at `pc`, `b` its syndrome.
    pub(crate) fn exception(&mut self, regs: &mut dyn Regs, mem: &mut dyn PhysMem, pc: u64, kind: i64, b: u64) -> Result<u64, Stop> {
        use abi::exc;
        match kind {
            exc::UNDEFINED => self.take_undef(regs, pc),
            exc::SVC => self.take_svc(regs, pc),
            // B9.3.14 SMC: `HaveSecurityExt()` is FALSE: UNDEFINED.
            exc::SMC => self.take_undef(regs, pc),
            // B9.3.4 HVC: `!HaveVirtExt()`: UNDEFINED.
            exc::HVC => self.take_undef(regs, pc),
            // C3.2, C4.1.1: a BKPT instruction debug event, Halting
            // debug-mode not selected (the model has no external debugger),
            // generates a debug exception: a Prefetch Abort, the IFSR
            // reporting a debug event (0b00010), the IFAR UNKNOWN (left as it
            // is, B3.13.4 Table B3-26). DBGDSCR.MOE is not modelled.
            exc::BKPT => {
                self.sr.ifsr = crate::vmsa::encode_fs(0b00010);
                self.take_pabt(regs, pc)
            }
            exc::FETCH => self.prefetch_abort_at(regs, mem, pc, b as u32),
            exc::PREFETCH_ABORT | exc::DATA_ABORT => {
                unimpl("a Prefetch or Data Abort raised by translated code without its fault: the model raises them itself")
            }
            exc::IRQ | exc::FIQ => unimpl("IRQ/FIQ raised by an instruction: they are asynchronous (take_irq/take_fiq)"),
            _ => unimpl(format!("exception kind {kind}")),
        }
    }

    /// `UNIMPLEMENTED`: what gex does not implement, after the checks the
    /// architecture makes first.
    pub(crate) fn unimplemented(&mut self, regs: &mut dyn Regs, pc: u64, what: i64, raw: u32) -> Result<u64, Stop> {
        match what {
            abi::unimpl::FP => self.fp_unimplemented(regs, pc, raw),
            abi::unimpl::THUMBEE => unimpl(format!("ThumbEE (ENTERX/LEAVEX) at {:#x}", abi::key_addr(pc))),
            abi::unimpl::DEBUG_DTR => unimpl(format!("the CP14 debug communications channel (LDC/STC DBGDTRTXint/DBGDTRRXint) at {:#x}", abi::key_addr(pc))),
            _ => unimpl(format!("unimplemented feature {what} (encoding {raw:#010x}) at {:#x}", abi::key_addr(pc))),
        }
    }

    /// A Floating-point or Advanced SIMD instruction: the checks of
    /// `CheckAdvSIMDOrVFPEnabled()` (B1.11.1) and of VMRS/VMSR of the
    /// system registers (B9.3.21, B9.3.22), which take the Undefined
    /// Instruction exception where they deny it; only an instruction they
    /// permit stops as unimplemented.
    fn fp_unimplemented(&mut self, regs: &mut dyn Regs, pc: u64, raw: u32) -> Result<u64, Stop> {
        let at = abi::key_addr(pc);
        let cpacr = self.sr.cpacr;
        let (cp10, cp11) = ((cpacr >> 20) & 3, (cpacr >> 22) & 3);
        if cp10 != cp11 {
            return unpred(format!("CPACR.cp10 != CPACR.cp11 at {at:#x} (B1.11.1)"));
        }
        match cp10 {
            0b00 => return self.take_undef(regs, pc),
            0b01 if !self.privileged() => return self.take_undef(regs, pc),
            0b10 => return unpred(format!("CPACR.cp10 = 0b10 (reserved) at {at:#x} (B4.1.40)")),
            _ => {}
        }
        // VMRS/VMSR of FPSID, MVFR0/1 and FPEXC: PL1 only, not affected by
        // FPEXC.EN (CheckVFPEnabled(FALSE)).
        let f = &self.config.features;
        let inst = if abi::key_thumb(pc) {
            gex_isa_a32::decode_thumb((raw >> 16) as u16, raw as u16, ItState(abi::key_it(pc)), f)
        } else {
            gex_isa_a32::decode_arm(raw, f)
        };
        let special = match inst.op {
            Op::Fp(FpInst::Vmrs { reg, .. }) | Op::Fp(FpInst::Vmsr { reg, .. }) if reg != 1 => Some(reg),
            _ => None,
        };
        if let Some(reg) = special {
            if !self.privileged() {
                return self.take_undef(regs, pc);
            }
            return unimpl(format!("VMRS/VMSR of Floating-point system register {reg} at {at:#x}"));
        }
        if self.sr.fpexc & (1 << 30) == 0 {
            // FPEXC.EN == '0': UNDEFINED (CPACR.ASEDIS would make an Advanced
            // SIMD instruction UNDEFINED first, the same exception).
            return self.take_undef(regs, pc);
        }
        unimpl(format!("Floating-point/Advanced SIMD instruction {raw:#010x} at {at:#x}"))
    }
}
