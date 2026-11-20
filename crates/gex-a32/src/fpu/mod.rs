//! The Advanced SIMD and Floating-point Extensions' system level (B1.11):
//! the enable checks of `CheckAdvSIMDOrVFPEnabled()` and `D[]`, the special
//! registers VMRS and VMSR reach (B9.3.21, B9.3.22, B4.1.57-B4.1.59,
//! B4.1.108, B4.1.109).
//!
//! The extension registers and the FPSCR are in the thread context
//! ([`Regs::d`], [`Regs::fpscr`]); FPEXC is the model's. Translated code
//! tests `gex_abi::a32::FPEN`, which [`Core::fpen`] computes, before every
//! Floating-point or Advanced SIMD instruction, and traps to
//! [`Core::fp_check_failed`] where a check it needs does not pass.

pub mod soft;
mod vfp;

use crate::{abi, need, unimpl, unpred, Core, Regs, Stop};
use gex_isa_a32::fp::FpInst;
use gex_isa_a32::{ItState, Op, VfpVersion};

/// FPEXC.EN, FPEXC.EX (B4.1.57).
pub(crate) const FPEXC_EN: u32 = 1 << 30;
pub(crate) const FPEXC_EX: u32 = 1 << 31;

/// CPACR.ASEDIS, CPACR.D32DIS (B4.1.40).
const CPACR_ASEDIS: u32 = 1 << 31;
const CPACR_D32DIS: u32 = 1 << 30;

/// The FPSCR fields (B4.1.58).
pub(crate) mod fpscr {
    pub const NZCV: u32 = 0xf << 28;
    pub const QC: u32 = 1 << 27;
    pub const AHP: u32 = 1 << 26;
    pub const DN: u32 = 1 << 25;
    pub const FZ: u32 = 1 << 24;
    pub const RMODE: u32 = 3 << 22;
    pub const STRIDE: u32 = 3 << 20;
    pub const LEN: u32 = 7 << 16;
    /// The trap enables IDE, IXE, UFE, OFE, DZE, IOE: RAZ/WI in VFPv3 and
    /// VFPv4.
    pub const ENABLES: u32 = 1 << 15 | 0x1f << 8;
    /// The cumulative exception bits IDC, IXC, UFC, OFC, DZC, IOC.
    pub const CUMULATIVE: u32 = 1 << 7 | 0x1f;
}

/// What the model requires of, and reads from, MVFR0 and MVFR1.
#[derive(Copy, Clone, Debug)]
pub(crate) struct FpImp {
    /// MVFR0.Short vectors: the hardware executes VFP short vectors
    /// (Appendix D11); otherwise a VFP vector operation is a bounce to
    /// support code, the Undefined Instruction exception.
    pub short_vectors: bool,
    /// MVFR0.Square root, MVFR0.Divide: VSQRT and VDIV are in hardware.
    pub sqrt: bool,
    pub divide: bool,
}

impl Core {
    /// The Floating-point implementation MVFR0 and MVFR1 describe. The
    /// model implements every rounding mode, untrapped exception handling
    /// only (VFPv3 and VFPv4, not the U variants), full denormal arithmetic
    /// and NaN propagation in hardware; a configuration that says otherwise
    /// is refused.
    pub(crate) fn fp_imp(&self) -> Result<FpImp, Stop> {
        let mvfr0 = need(self.config.imp.mvfr0, "MVFR0 (B4.1.108)")?;
        let mvfr1 = need(self.config.imp.mvfr1, "MVFR1 (B4.1.109)")?;
        let f = &self.config.features;
        let field = |v: u32, at: u32| (v >> at) & 0xf;
        if f.vfp.is_some() {
            if field(mvfr0, 28) != 1 {
                return unimpl("MVFR0.VFP rounding modes = 0: only Round to Nearest in hardware (the other modes bounce to support code)");
            }
            if field(mvfr0, 12) != 0 {
                return unimpl("MVFR0.VFP exception trapping: VFPv3U/VFPv4U trapped floating-point exceptions");
            }
            if field(mvfr0, 8) != 2 || field(mvfr0, 4) != 2 {
                return Err(Stop::ImpDef(format!("MVFR0 {mvfr0:#x}: VFPv3/VFPv4 single- and double-precision (0b0010) for a core with the Floating-point Extension")));
            }
            if field(mvfr1, 0) != 1 || field(mvfr1, 4) != 1 {
                return unimpl("MVFR1.FtZ mode or D_NaN mode = 0: hardware without denormal arithmetic or NaN propagation");
            }
        }
        let regs = if f.d32 { 2 } else { 1 };
        if field(mvfr0, 0) != regs {
            return Err(Stop::ImpDef(format!("MVFR0 {mvfr0:#x}: A_SIMD registers must be {regs} for this core's register bank")));
        }
        Ok(FpImp { short_vectors: field(mvfr0, 24) == 1, sqrt: field(mvfr0, 20) == 1, divide: field(mvfr0, 16) == 1 })
    }

    fn has_vfp_or_simd(&self) -> bool {
        self.config.features.vfp.is_some() || self.config.features.simd
    }

    /// The `gex_abi::a32::fpen` bits of the current CPACR and FPEXC: the
    /// cases where `CheckAdvSIMDOrVFPEnabled(TRUE, advsimd)` returns
    /// without an exception, and `VFPSmallRegisterBank()`. A state the
    /// checks make UNPREDICTABLE leaves its bits clear, so that the full
    /// check finds it.
    pub fn fpen(&self) -> u64 {
        use abi::fpen::*;
        if !self.has_vfp_or_simd() {
            return 0;
        }
        let cpacr = self.sr.cpacr;
        let (cp10, cp11) = ((cpacr >> 20) & 3, (cpacr >> 22) & 3);
        if cp10 != cp11 || self.sr.fpexc & FPEXC_EN == 0 {
            return 0;
        }
        let (pl1, pl0) = match cp10 {
            0b01 => (true, false),
            0b11 => (true, true),
            _ => (false, false),
        };
        let mut v = 0;
        if pl1 {
            v |= VFP_PL1;
        }
        if pl0 {
            v |= VFP_PL0;
        }
        if cpacr & CPACR_ASEDIS == 0 {
            v |= (v & (VFP_PL1 | VFP_PL0)) << 2;
        }
        if self.config.features.d32 && cpacr & CPACR_D32DIS == 0 {
            v |= D32;
        }
        v
    }

    /// `CheckAdvSIMDOrVFPEnabled(include_fpexc_check, advsimd)` (B1.11.1),
    /// without the Security and Virtualization Extensions: `Ok` where it
    /// returns, the Undefined Instruction exception taken where it is
    /// UNDEFINED.
    pub(crate) fn check_advsimd_or_vfp(&mut self, regs: &mut dyn Regs, pc: u64, include_fpexc_check: bool, advsimd: bool) -> Result<(), Stop> {
        let at = abi::key_addr(pc);
        let cpacr = self.sr.cpacr;
        let (cp10, cp11) = ((cpacr >> 20) & 3, (cpacr >> 22) & 3);
        if cp10 != cp11 {
            return unpred(format!("CPACR.cp10 != CPACR.cp11 at {at:#x} (B1.11.1)"));
        }
        match cp10 {
            0b00 => return self.take_undef(regs, pc).map(|_| ()),
            0b01 if !self.privileged() => return self.take_undef(regs, pc).map(|_| ()),
            0b10 => return unpred(format!("CPACR.cp10 = 0b10 (reserved) at {at:#x} (B1.11.1)")),
            _ => {}
        }
        if advsimd && cpacr & CPACR_ASEDIS != 0 {
            return self.take_undef(regs, pc).map(|_| ());
        }
        if include_fpexc_check && self.sr.fpexc & FPEXC_EN == 0 {
            return self.take_undef(regs, pc).map(|_| ());
        }
        Ok(())
    }

    /// `VFPSmallRegisterBank()` (A2.6.1): D16-D31 are not accessible.
    pub(crate) fn vfp_small_register_bank(&self, pc: u64) -> Result<bool, Stop> {
        if !self.config.features.d32 {
            return Ok(true);
        }
        let cpacr = self.sr.cpacr;
        match (cpacr & CPACR_D32DIS != 0, cpacr & CPACR_ASEDIS != 0) {
            (false, _) => Ok(false),
            (true, true) => Ok(true),
            (true, false) => unpred(format!("CPACR.D32DIS = 1 with CPACR.ASEDIS = 0 at {:#x} (A2.6.1 VFPSmallRegisterBank())", abi::key_addr(pc))),
        }
    }

    /// The trap translated code raises where `gex_abi::a32::FPEN` does not
    /// show the checks of the instruction at `pc` passing (`code` is
    /// `BRK_FP_CHECK` less its flags): the full checks, which take the
    /// Undefined Instruction exception (`Err(Stop::Resume)`) or stop.
    pub fn fp_check_failed(&mut self, regs: &mut dyn Regs, pc: u64, code: i32) -> Result<(), Stop> {
        let flags = abi::BRK_FP_CHECK - code;
        if !(0..=3).contains(&flags) {
            return unimpl(format!("Floating-point check trap code {code}"));
        }
        let r = self.fp_check_full(regs, pc, flags);
        regs.set_fpen(self.fpen());
        match r {
            Ok(()) => unimpl(format!(
                "the Floating-point/Advanced SIMD checks of the instruction at {:#x} pass, but translated code saw FPEN {:#x}",
                abi::key_addr(pc),
                self.fpen()
            )),
            Err(s) => Err(s),
        }
    }

    fn fp_check_full(&mut self, regs: &mut dyn Regs, pc: u64, flags: i32) -> Result<(), Stop> {
        self.check_advsimd_or_vfp(regs, pc, true, flags & abi::FP_CHECK_SIMD != 0)?;
        if flags & abi::FP_CHECK_D32 != 0 && self.vfp_small_register_bank(pc)? {
            // D[n] with n >= 16 and VFPSmallRegisterBank(): UNDEFINED.
            return self.take_undef(regs, pc).map(|_| ());
        }
        Ok(())
    }

    /// `IsNotAllocatedVFP(reg)` and the PL1-only special registers' checks
    /// (B9.3.21, B9.3.22): `Ok` where the access goes on.
    fn special_reg_checks(&mut self, regs: &mut dyn Regs, pc: u64, reg: u8) -> Result<(), Stop> {
        let at = abi::key_addr(pc);
        if (0b0010..=0b0101).contains(&reg) {
            return unpred(format!("VMRS/VMSR of the unallocated special register {reg:#06b} at {at:#x} (B9.3.21, B9.3.22)"));
        }
        if reg == 0b0001 {
            return self.check_advsimd_or_vfp(regs, pc, true, false);
        }
        // Non-FPSCR registers are accessible only at PL1 or above and not
        // affected by FPEXC.EN.
        if !self.privileged() {
            return self.take_undef(regs, pc).map(|_| ());
        }
        self.check_advsimd_or_vfp(regs, pc, false, false)
    }

    /// B9.3.21 VMRS of special register `reg`.
    pub(crate) fn vmrs(&mut self, regs: &mut dyn Regs, pc: u64, reg: u8) -> Result<u32, Stop> {
        self.special_reg_checks(regs, pc, reg)?;
        match reg {
            0b0000 => need(self.config.imp.fpsid, "FPSID (B4.1.59)"),
            0b0001 => Ok(regs.fpscr()),
            0b0110 => need(self.config.imp.mvfr1, "MVFR1 (B4.1.109)"),
            0b0111 => need(self.config.imp.mvfr0, "MVFR0 (B4.1.108)"),
            0b1000 => Ok(self.sr.fpexc),
            _ => unimpl(format!("VMRS of the SUBARCHITECTURE DEFINED register {reg:#06b} at {:#x}", abi::key_addr(pc))),
        }
    }

    /// B9.3.22 VMSR of special register `reg`.
    pub(crate) fn vmsr(&mut self, regs: &mut dyn Regs, pc: u64, reg: u8, v: u32) -> Result<(), Stop> {
        self.special_reg_checks(regs, pc, reg)?;
        let at = abi::key_addr(pc);
        match reg {
            // FPSID is read-only: a write only serializes.
            0b0000 => Ok(()),
            0b0001 => {
                let (writable, sbzp) = self.fpscr_bits();
                if v & sbzp != 0 {
                    return unpred(format!("VMSR FPSCR of {v:#010x} sets UNK/SBZP bits {:#x} at {at:#x} (B4.1.58)", v & sbzp));
                }
                regs.set_fpscr(v & writable);
                Ok(())
            }
            0b0110 | 0b0111 => unpred(format!("VMSR of MVFR{} at {at:#x} (B9.3.22)", if reg == 0b0110 { 1 } else { 0 })),
            0b1000 => {
                // EX: a write of 0 is valid; the model has no
                // subarchitecture state for 1. Bits 29:0 are SUBARCHITECTURE
                // DEFINED.
                if v & FPEXC_EX != 0 {
                    return unimpl(format!("VMSR FPEXC with EX = 1 at {at:#x}: SUBARCHITECTURE DEFINED exception state"));
                }
                if v & !(FPEXC_EX | FPEXC_EN) != 0 {
                    return unimpl(format!("VMSR FPEXC of {v:#010x} at {at:#x}: SUBARCHITECTURE DEFINED bits 29:0"));
                }
                self.sr.fpexc = v & FPEXC_EN;
                Ok(())
            }
            _ => unimpl(format!("VMSR of the SUBARCHITECTURE DEFINED register {reg:#06b} at {at:#x}")),
        }
    }

    /// The FPSCR's read/write bits and its UNK/SBZP bits for this core
    /// (B4.1.58); the trap enables are neither (RAZ/WI in VFPv3 and VFPv4).
    pub(crate) fn fpscr_bits(&self) -> (u32, u32) {
        use fpscr::*;
        let f = &self.config.features;
        let mut rw = 0;
        if f.vfp.is_some() {
            rw |= NZCV | DN | FZ | RMODE | STRIDE | LEN | CUMULATIVE;
            if f.fp16 || f.vfp == Some(VfpVersion::V4) {
                rw |= AHP;
            }
        }
        if f.simd {
            rw |= QC;
        }
        (rw, !(rw | ENABLES))
    }

    /// `FP`: a Floating-point or Advanced SIMD data-processing instruction.
    /// The instruction is decoded again from its encoding, as the lifter
    /// decoded it; its enable checks have passed and its condition holds.
    pub(crate) fn fp_exec(&mut self, regs: &mut dyn Regs, pc: u64, raw: u32) -> Result<u64, Stop> {
        let at = abi::key_addr(pc);
        let f = &self.config.features;
        let inst = if abi::key_thumb(pc) {
            gex_isa_a32::decode_thumb((raw >> 16) as u16, raw as u16, ItState(abi::key_it(pc)), f)
        } else {
            gex_isa_a32::decode_arm(raw, f)
        };
        if let Some(why) = inst.unpredictable {
            return unpred(format!("{why} at {at:#x}"));
        }
        let Op::Fp(i) = inst.op else {
            return unimpl(format!("A32Sys FP of {raw:#010x} at {at:#x}, which is not a Floating-point or Advanced SIMD instruction"));
        };
        let imp = self.fp_imp()?;
        match i {
            FpInst::Vfp3 { .. } | FpInst::Vfp2 { .. } | FpInst::Vcmp { .. } | FpInst::VmovImm { .. } => self.vfp_dp(regs, pc, &imp, &i)?,
            FpInst::VcvtInt { .. } | FpInst::VcvtFixed { .. } | FpInst::VcvtDs { .. } | FpInst::VcvtHalf { .. } => self.vfp_cvt(regs, &i)?,
            _ => return unimpl(format!("Floating-point/Advanced SIMD data processing {raw:#010x} ({i:?}) at {at:#x}")),
        }
        Ok(0)
    }
}
