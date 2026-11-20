//! Floating-point (VFP) data processing (A7.5): the A8 instruction
//! descriptions' operations under the FPSCR, and the VFP short vectors of
//! Appendix D11 (VFP Vector Operation Support).

use super::soft;
use super::FpImp;
use crate::{abi, unpred, Core, Regs, Stop};
use gex_isa_a32::fp::{FpInst, Vfp2Op, Vfp3Op, VReg};

/// An S or D register's number and its format width.
fn sd(r: VReg) -> (u8, u32) {
    match r {
        VReg::S(n) => (n, 32),
        VReg::D(n) => (n, 64),
        VReg::Q(_) => unreachable!("a Q register in a VFP instruction"),
    }
}

/// `S[n]` (`w` 32) or `D[n]` (`w` 64).
pub(crate) fn get(regs: &dyn Regs, n: u8, w: u32) -> u64 {
    if w == 64 {
        regs.d(n)
    } else {
        let d = regs.d(n / 2);
        if n % 2 == 0 {
            d & 0xffff_ffff
        } else {
            d >> 32
        }
    }
}

pub(crate) fn set(regs: &mut dyn Regs, n: u8, w: u32, v: u64) {
    if w == 64 {
        regs.set_d(n, v);
    } else {
        let d = regs.d(n / 2);
        let d = if n % 2 == 0 { (d & !0xffff_ffff) | (v & 0xffff_ffff) } else { (d & 0xffff_ffff) | (v << 32) };
        regs.set_d(n / 2, d);
    }
}

/// The registers of one operand of a VFP short-vector operation (D11.1,
/// D11.3): `first`, then on by the stride, wrapping round its bank (eight
/// single-precision registers, four double-precision ones).
fn element(first: u8, w: u32, i: u32, step: u32) -> u8 {
    let bank = if w == 32 { 8 } else { 4 };
    let base = first as u32 / bank * bank;
    (base + (first as u32 - base + i * step) % bank) as u8
}

/// Whether register `r` is in a scalar bank (D11.3: S0-S7; D0-D3 and
/// D16-D19).
fn scalar_bank(r: u8, w: u32) -> bool {
    if w == 32 {
        r < 8
    } else {
        r % 16 < 4
    }
}

impl Core {
    /// The vector length and step of FPSCR.{Len, Stride} for an instruction
    /// of width `w` that VFP vector mode affects (D11.1.1, Table D11-1):
    /// `(1, 1)` in scalar mode. A vector operation the hardware does not
    /// execute (MVFR0.Short vectors) is a bounce to support code: the
    /// Undefined Instruction exception.
    fn vfp_vector(&mut self, regs: &mut dyn Regs, pc: u64, imp: &FpImp, w: u32) -> Result<(u32, u32), Stop> {
        let fpscr = regs.fpscr();
        let len = ((fpscr >> 16) & 7) + 1;
        let stride = (fpscr >> 20) & 3;
        if len == 1 && stride == 0 {
            return Ok((1, 1));
        }
        if !imp.short_vectors {
            self.take_undef(regs, pc)?;
        }
        let at = abi::key_addr(pc);
        let step = match stride {
            0b00 => 1,
            0b11 if len <= 4 => 2,
            _ => return unpred(format!("FPSCR.{{Len, Stride}} = {{{:#05b}, {stride:#04b}}} at {at:#x} (Table D11-1)", len - 1)),
        };
        if w == 64 && (len > 4 || (step == 2 && len > 2)) {
            return unpred(format!(
                "a double-precision VFP vector instruction with FPSCR.{{Len, Stride}} = {{{:#05b}, {stride:#04b}}} at {at:#x} (Table D11-1)",
                len - 1
            ));
        }
        Ok((len, step))
    }

    /// A8.8.304 VCMP, VCMPE; VMOV (immediate), VMOV (register) and the
    /// arithmetic of A7.5.
    pub(crate) fn vfp_dp(&mut self, regs: &mut dyn Regs, pc: u64, imp: &FpImp, i: &FpInst) -> Result<(), Stop> {
        let mut fpscr = regs.fpscr();
        let mut exc = 0u32;
        let at = abi::key_addr(pc);
        match *i {
            FpInst::Vcmp { e, d, m, .. } => {
                let (dn, w) = sd(d);
                let op1 = get(regs, dn, w);
                let op2 = match m {
                    Some(m) => get(regs, sd(m).0, w),
                    None => soft::zero(false, w),
                };
                let nzcv = soft::compare(op1, op2, e, w, fpscr, &mut exc);
                fpscr = (fpscr & 0x0fff_ffff) | nzcv << 28;
            }
            FpInst::Vfp3 { op, d, n, m, .. } => {
                use Vfp3Op::*;
                let (dn, w) = sd(d);
                let (nn, mn) = (sd(n).0, sd(m).0);
                let fused = matches!(op, Vfma | Vfms | Vfnma | Vfnms);
                if fused && fpscr & (0x7 << 16 | 0x3 << 20) != 0 {
                    return unpred(format!("VFMA/VFMS/VFNMA/VFNMS with FPSCR.Len != 0 or FPSCR.Stride != 0 at {at:#x} (A8.8.318, A8.8.319)"));
                }
                if op == Vdiv && !imp.divide {
                    // MVFR0.Divide: not in hardware, support code's.
                    self.take_undef(regs, pc)?;
                }
                let (len, step) = if fused { (1, 1) } else { self.vfp_vector(regs, pc, imp, w)? };
                let (len, m_vec) = if len == 1 || scalar_bank(dn, w) { (1, false) } else { (len, !scalar_bank(mn, w)) };
                for k in 0..len {
                    let rd = element(dn, w, k, step);
                    let rn = element(nn, w, k, step);
                    let rm = if m_vec { element(mn, w, k, step) } else { mn };
                    let (vd, vn, vm) = (get(regs, rd, w), get(regs, rn, w), get(regs, rm, w));
                    let f = fpscr;
                    let x = &mut exc;
                    let r = match op {
                        Vmla | Vmls => {
                            let p = soft::mul(vn, vm, w, f, x);
                            let p = if op == Vmls { soft::neg(p, w) } else { p };
                            soft::add(vd, p, w, f, x)
                        }
                        Vnmla | Vnmls | Vnmul => {
                            let p = soft::mul(vn, vm, w, f, x);
                            match op {
                                Vnmla => soft::add(soft::neg(vd, w), soft::neg(p, w), w, f, x),
                                Vnmls => soft::add(soft::neg(vd, w), p, w, f, x),
                                _ => soft::neg(p, w),
                            }
                        }
                        Vmul => soft::mul(vn, vm, w, f, x),
                        Vadd => soft::add(vn, vm, w, f, x),
                        Vsub => soft::sub(vn, vm, w, f, x),
                        Vdiv => soft::div(vn, vm, w, f, x),
                        Vfma => soft::mul_add(vd, vn, vm, w, f, x),
                        Vfms => soft::mul_add(vd, soft::neg(vn, w), vm, w, f, x),
                        Vfnma => soft::mul_add(soft::neg(vd, w), soft::neg(vn, w), vm, w, f, x),
                        Vfnms => soft::mul_add(soft::neg(vd, w), vn, vm, w, f, x),
                    };
                    set(regs, rd, w, r);
                }
            }
            FpInst::Vfp2 { op, d, m, .. } => {
                let (dn, w) = sd(d);
                let mn = sd(m).0;
                if op == Vfp2Op::Vsqrt && !imp.sqrt {
                    self.take_undef(regs, pc)?;
                }
                let (len, step) = self.vfp_vector(regs, pc, imp, w)?;
                let (len, m_vec) = if len == 1 || scalar_bank(dn, w) { (1, false) } else { (len, !scalar_bank(mn, w)) };
                for k in 0..len {
                    let rd = element(dn, w, k, step);
                    let rm = if m_vec { element(mn, w, k, step) } else { mn };
                    let v = get(regs, rm, w);
                    let r = match op {
                        Vfp2Op::Vmov => v,
                        Vfp2Op::Vabs => soft::abs(v, w),
                        Vfp2Op::Vneg => soft::neg(v, w),
                        Vfp2Op::Vsqrt => soft::sqrt(v, w, fpscr, &mut exc),
                    };
                    set(regs, rd, w, r);
                }
            }
            FpInst::VmovImm { d, imm, .. } => {
                let (dn, w) = sd(d);
                let (len, step) = self.vfp_vector(regs, pc, imp, w)?;
                let len = if scalar_bank(dn, w) { 1 } else { len };
                for k in 0..len {
                    set(regs, element(dn, w, k, step), w, imm);
                }
            }
            _ => unreachable!("not a VFP data-processing instruction: {i:?}"),
        }
        regs.set_fpscr(fpscr | exc);
        Ok(())
    }

}
