//! The system-level instructions (B9.3 and the coprocessor instructions of
//! A8.8): each is one `A32Sys` operation of the host's model of the core,
//! which checks the mode and privilege the architecture requires at run
//! time.

use crate::{Flow, Lifter};
use gex_abi::a32 as abi;
use gex_ir::BinOp;
use gex_isa_a32::*;

fn amode_bits(m: Amode) -> u64 {
    match m {
        Amode::Ia => 0,
        Amode::Ib => 1,
        Amode::Da => 2,
        Amode::Db => 3,
    }
}

impl<'a> Lifter<'a> {
    pub(crate) fn system(&mut self, op: &Op) -> Flow {
        use abi::sys;
        match *op {
            // B9.3.8 MRS, A8.8.102 MRS (the APSR at PL0).
            Op::Mrs { rd, psr } => {
                let v = self.sys_k(sys::MRS, (psr == Psr::Spsr) as u64, 0);
                let v = self.wrap(v);
                self.w(rd, v);
                Flow::Next
            }
            // B9.3.11 MSR (immediate), B9.3.12 MSR (register).
            Op::Msr { psr, mask, src } => {
                let v = match src {
                    MsrSrc::Imm(i) => self.c32(i),
                    MsrSrc::Reg(r) => self.r(r),
                };
                let v = self.zext(v);
                let a = self.c64(mask as u64 | if psr == Psr::Spsr { 0x10 } else { 0 });
                // A change of mode may change the privilege the code after
                // it is fetched at: the host then goes on at the next
                // instruction under its key for the new level.
                self.pc_to_next();
                self.sys(sys::MSR, a, v);
                Flow::Next
            }
            // B9.3.9 MRS (Banked register), B9.3.10 MSR (Banked register).
            Op::MrsBanked { rd, sysm } => {
                let v = self.sys_k(sys::MRS_BANKED, sysm as u64, 0);
                let v = self.wrap(v);
                self.w(rd, v);
                Flow::Next
            }
            Op::MsrBanked { rn, sysm } => {
                let v = self.r(rn);
                let v = self.zext(v);
                let a = self.c64(sysm as u64);
                self.sys(sys::MSR_BANKED, a, v);
                Flow::Next
            }
            // B9.3.2 CPS.
            Op::Cps { imod, a, i, f, mode } => {
                let packed = (imod as u64 & 3)
                    | (a as u64) << 2
                    | (i as u64) << 3
                    | (f as u64) << 4
                    | (mode.is_some() as u64) << 5
                    | (mode.unwrap_or(0) as u64 & 31) << 8;
                self.pc_to_next();
                self.sys_k(sys::CPS, packed, 0);
                Flow::Next
            }
            // A8.8.157 SETEND.
            Op::Setend { big } => {
                self.sys_k(sys::SETEND, big as u64, 0);
                Flow::Next
            }
            // B9.3.16 SRS.
            Op::Srs { mode, amode, wback } => {
                let packed = (mode as u64 & 31) | amode_bits(amode) << 8 | (wback as u64) << 10;
                self.sys_k(sys::SRS, packed, 0);
                Flow::Next
            }
            // B9.3.13 RFE.
            Op::Rfe { rn, amode, wback } => {
                let packed = rn.0 as u64 | amode_bits(amode) << 8 | (wback as u64) << 10;
                self.pc_to_next();
                self.sys_k(sys::RFE, packed, 0);
                self.end_at_context_pc()
            }
            // B9.3.3 ERET.
            Op::Eret => {
                self.pc_to_next();
                self.sys_k(sys::ERET, 0, 0);
                self.end_at_context_pc()
            }
            // A8.8.99 MCR, A8.8.108 MRC: CP14 and CP15 are the system's
            // (B3.15); MCR2/MRC2 to them are UNDEFINED (B3.15.2), and so is
            // any coprocessor that is not implemented (B1.10.1). Coprocessors
            // 10 and 11 are the Floating-point and Advanced SIMD ones, which
            // the decoder gives as such.
            Op::Mcr { read, two, coproc, opc1, rt, crn, crm, opc2 } => {
                if two || !matches!(coproc, 14 | 15) {
                    return self.undefined();
                }
                let cp = abi::sys::cp(coproc, opc1, crn, crm, opc2) as u64;
                if read {
                    let v = self.sys_k(sys::MRC, cp, 0);
                    let v = self.wrap(v);
                    if rt.is_pc() {
                        // APSR_nzcv: the flags from bits 31:28.
                        for (k, f) in [(31, gex_ir::GuestReg::N), (30, gex_ir::GuestReg::Z), (29, gex_ir::GuestReg::C), (28, gex_ir::GuestReg::V)] {
                            let b = self.bit(v, k);
                            self.wflag(f, b);
                        }
                    } else {
                        self.w(rt, v);
                    }
                } else {
                    let v = self.r(rt);
                    let v = self.zext(v);
                    let a = self.c64(cp);
                    // A write may change how code is fetched (SCTLR, TTBR,
                    // the instruction cache maintenance): the host then
                    // goes on at the next instruction from a fresh
                    // translation.
                    self.pc_to_next();
                    self.sys(sys::MCR, a, v);
                }
                Flow::Next
            }
            // A8.8.100 MCRR, A8.8.109 MRRC: only the 64-bit CP14/CP15
            // registers, which the host knows.
            Op::Mcrr { read, two, coproc, opc1, rt, rt2, crm } => {
                if two || !matches!(coproc, 14 | 15) {
                    return self.undefined();
                }
                let cp = abi::sys::cp(coproc, opc1, 0, crm, 0) as u64;
                if read {
                    let v = self.sys_k(sys::MRRC, cp, 0);
                    let lo = self.wrap(v);
                    let hi = self.bini64(BinOp::ShrU, v, 32);
                    let hi = self.wrap(hi);
                    self.w(rt, lo);
                    self.w(rt2, hi);
                } else {
                    let lo = self.r(rt);
                    let hi = self.r(rt2);
                    let lo = self.zext(lo);
                    let hi = self.zext(hi);
                    let hi = self.bini64(BinOp::Shl, hi, 32);
                    let v = self.bin64(BinOp::Or, hi, lo);
                    let a = self.c64(cp);
                    self.pc_to_next();
                    self.sys(sys::MCRR, a, v);
                }
                Flow::Next
            }
            // A8.8.31 CDP: no implemented coprocessor has a data operation
            // (CDP to CP14/CP15 is UNDEFINED, B3.15.2).
            Op::Cdp { .. } => self.undefined(),
            // A8.8.56 LDC, A8.8.200 STC: to CP14 only the debug transfer
            // registers DBGDTRTXint/DBGDTRRXint (C6.4.4) are defined, and
            // gex has no model of the debug communications channel; any
            // other is UNDEFINED.
            Op::Ldc { two, long, coproc, crd, .. } => {
                if coproc == 14 && !two && !long && crd == 5 {
                    self.unimplemented(abi::unimpl::DEBUG_DTR)
                } else {
                    self.undefined()
                }
            }
            _ => unreachable!("system: {op:?}"),
        }
    }
}
