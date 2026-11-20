//! The Advanced SIMD and Floating-point Extensions (chapter A7, the A8
//! instruction descriptions).
//!
//! The extension register file is the context's `v0`-`v15`, `Q<n>` being
//! `v<n>` (`gex_abi::a32::FPSCR` gives the layout), and the FPSCR is
//! `ctx::x(FPSCR)`. Every instruction first makes its enable checks
//! (`CheckVFPEnabled(TRUE)`, `CheckAdvSIMDEnabled()`, `D[]` of D16-D31)
//! against `ctx::x(FPEN)`, trapping to the host's full checks where one it
//! needs is clear; the trap is taken only where the condition passes.
//!
//! Transfers between the ARM core and the extension registers, VMRS of the
//! FPSCR, and the loads and stores (every access through `A32Mem`) are
//! lifted here. The data-processing
//! instructions are executed by the host's software implementation of
//! their pseudocode (`A32Sys` `FP`, `gex_a32::Core`): the FPSCR's rounding
//! modes, flush-to-zero, default NaN and cumulative exception flags, and
//! the Advanced SIMD saturation flag, are not what a wasm host's operations
//! give, and the software is exact for all of them.

use crate::{Flow, Lifter};
use gex_abi::a32 as abi;
use gex_ir::{BinOp, CmpOp, Expr, GuestReg, MemSz, Order, Stmt, Ty, Value};
use gex_isa_a32::fp::{Dt, FpInst, LdStForm, Simd2Op, VReg};
use gex_isa_a32::Reg;

/// Whether `i` is an Advanced SIMD instruction (`CheckAdvSIMDEnabled()`, or
/// `CheckAdvSIMDOrVFPEnabled(TRUE, TRUE)`) rather than a Floating-point one
/// (`CheckVFPEnabled(TRUE)`).
fn is_advsimd(i: &FpInst) -> bool {
    use FpInst::*;
    match i {
        Simd3 { .. } | Simd3Scalar { .. } | Simd2 { .. } | SimdShift { .. } | SimdCvt { .. } | SimdImm { .. } | Vext { .. } | Vtbl { .. } | VdupScalar { .. } | VdupCore { .. } | SimdLdSt { .. } => true,
        // A8.8.342, A8.8.343: advsimd = (opc1:opc2 not the word form).
        VmovToScalar { dt, .. } | VmovFromScalar { dt, .. } => *dt != Dt::X32,
        _ => false,
    }
}

fn reg_d32(r: VReg) -> bool {
    match r {
        VReg::S(_) => false,
        VReg::D(n) => n >= 16,
        VReg::Q(n) => n >= 8,
    }
}

/// Whether `i` accesses any of D16-D31 (`D[n]` with `n >= 16`).
fn uses_d32(i: &FpInst) -> bool {
    use FpInst::*;
    match *i {
        Simd3 { d, n, m, .. } => reg_d32(d) || reg_d32(n) || reg_d32(m),
        Simd3Scalar { d, n, m, .. } => reg_d32(d) || reg_d32(n) || m >= 16,
        Simd2 { d, m, .. } | SimdShift { d, m, .. } | SimdCvt { d, m, .. } => reg_d32(d) || reg_d32(m),
        SimdImm { d, .. } => reg_d32(d),
        Vext { d, n, m, .. } => reg_d32(d) || reg_d32(n) || reg_d32(m),
        Vtbl { d, n, len, m, .. } => d >= 16 || n as u32 + len as u32 > 16 || m >= 16,
        VdupScalar { d, m, .. } => reg_d32(d) || m >= 16,
        VdupCore { d, .. } => reg_d32(d),
        VmovToScalar { d, .. } => d >= 16,
        VmovFromScalar { n, .. } => n >= 16,
        VmovCoreS { .. } | VmovCoreSS { .. } | Vmrs { .. } | Vmsr { .. } => false,
        VmovCoreD { m, .. } => m >= 16,
        Vfp3 { d, n, m, .. } => reg_d32(d) || reg_d32(n) || reg_d32(m),
        Vfp2 { d, m, .. } => reg_d32(d) || reg_d32(m),
        Vcmp { d, m, .. } => reg_d32(d) || m.is_some_and(reg_d32),
        VmovImm { d, .. } => reg_d32(d),
        VcvtInt { d, m, .. } => reg_d32(d) || reg_d32(m),
        VcvtFixed { d, .. } => reg_d32(d),
        VcvtDs { d, m } => reg_d32(d) || reg_d32(m),
        VcvtHalf { .. } => false,
        Vldm { d, regs, .. } => match d {
            VReg::D(n) => n as u32 + regs as u32 > 16,
            _ => false,
        },
        Vldr { d, .. } => reg_d32(d),
        SimdLdSt { count, d, inc, regs, .. } => {
            // The registers d, d+inc, ... (VLD1/VST1: d..d+regs-1; VLD2
            // multiple with regs 2: d, d+1, d2, d2+1).
            let span = match count {
                1 => regs as u32,
                _ => (count as u32 - 1) * inc as u32 + regs as u32,
            };
            d as u32 + span > 16
        }
    }
}

impl<'a> Lifter<'a> {
    // -- the enable checks (B1.11.1) ------------------------------------------

    /// `CheckVFPEnabled(TRUE)` or `CheckAdvSIMDEnabled()`, and the
    /// `VFPSmallRegisterBank()` check of an access to D16-D31, where the
    /// condition passes: a trap to the host's full checks where
    /// `ctx::x(FPEN)` does not show them passing at this privilege level.
    pub(crate) fn fp_check(&mut self, advsimd: bool, d32: bool) {
        use abi::fpen::*;
        let user = self.user() != 0;
        let mut need = match (advsimd, user) {
            (false, false) => VFP_PL1,
            (false, true) => VFP_PL0,
            (true, false) => SIMD_PL1,
            (true, true) => SIMD_PL0,
        };
        if d32 {
            need |= D32;
        }
        let fpen = self.b.read(GuestReg::X(abi::FPEN));
        let have = self.bini64(BinOp::And, fpen, need);
        let k = self.c64(need);
        let bad = self.b.cmp(CmpOp::Ne, Ty::I64, have, k);
        let bad = match self.pred {
            Some(p) => self.bin(BinOp::And, bad, p),
            None => bad,
        };
        let code = abi::BRK_FP_CHECK - if advsimd { abi::FP_CHECK_SIMD } else { 0 } - if d32 { abi::FP_CHECK_D32 } else { 0 };
        self.b.stmt(Stmt::Trap { cond: bad, pc: self.key, code });
    }

    // -- the extension registers (A2.6.1) --------------------------------------

    fn qreg(&mut self, q: u8) -> Value {
        self.b.read(GuestReg::V128(q))
    }

    /// Write `Q<q>` (a `V128`), kept as it was where the condition fails.
    fn set_qreg(&mut self, q: u8, v: Value) {
        let v = match self.pred {
            Some(p) => {
                let old = self.qreg(q);
                self.b.select(p, v, old, Ty::V128)
            }
            None => v,
        };
        self.b.write(GuestReg::V128(q), v);
    }

    /// Element `index` of `esize` bits of `D<d>`, as an `I32` (`esize` <= 32)
    /// or `I64`, zero- or sign-extended.
    pub(crate) fn d_elem(&mut self, d: u8, index: u32, esize: u32, signed: bool) -> Value {
        let q = self.qreg(d / 2);
        let per = 64 / esize;
        let lane = (d as u32 % 2) * per + index;
        let ty = if esize == 64 { Ty::I64 } else { Ty::I32 };
        self.b.def(Expr::VExtract { a: q, lane, lane_bytes: esize / 8, signed, ty })
    }

    /// `Elem[D[d], index, esize] = v` (`v` an `I32`, or an `I64` for 64).
    pub(crate) fn set_d_elem(&mut self, d: u8, index: u32, esize: u32, v: Value) {
        let q = self.qreg(d / 2);
        let per = 64 / esize;
        let lane = (d as u32 % 2) * per + index;
        let nq = self.b.def(Expr::VReplace { a: q, lane, lane_bytes: esize / 8, val: v });
        self.set_qreg(d / 2, nq);
    }

    pub(crate) fn dreg(&mut self, d: u8) -> Value {
        self.d_elem(d, 0, 64, false)
    }

    pub(crate) fn set_dreg(&mut self, d: u8, v: Value) {
        self.set_d_elem(d, 0, 64, v)
    }

    /// `S[s]`, an `I32`.
    pub(crate) fn sreg(&mut self, s: u8) -> Value {
        self.d_elem(s / 2, s as u32 % 2, 32, false)
    }

    pub(crate) fn set_sreg(&mut self, s: u8, v: Value) {
        self.set_d_elem(s / 2, s as u32 % 2, 32, v)
    }

    /// The FPSCR, an `I32`.
    fn fpscr(&mut self) -> Value {
        let x = self.b.read(GuestReg::X(abi::FPSCR));
        self.wrap(x)
    }

    // -- the instructions -------------------------------------------------------

    pub(crate) fn fp(&mut self, i: &FpInst) -> Flow {
        use FpInst::*;
        // VMRS/VMSR of a register other than the FPSCR: the host makes the
        // PL1 and `CheckVFPEnabled(FALSE)` checks itself (B9.3.21, B9.3.22).
        match *i {
            Vmrs { rt, reg } if reg != 1 => {
                let a = self.c64(reg as u64);
                let z = self.c64(0);
                self.pc_to_next();
                let v = self.sys(abi::sys::VMRS, a, z);
                let v = self.wrap(v);
                self.w(rt, v);
                return Flow::Next;
            }
            Vmsr { reg, rt } if reg != 1 => {
                let a = self.c64(reg as u64);
                let v = self.r(rt);
                let v = self.zext(v);
                self.pc_to_next();
                self.sys(abi::sys::VMSR, a, v);
                return Flow::Next;
            }
            _ => {}
        }
        let advsimd = is_advsimd(i);
        self.fp_check(advsimd, uses_d32(i));
        match *i {
            // A8.8.349 VMRS: the FPSCR to Rt, or its flags to the APSR.
            Vmrs { rt, .. } => {
                let f = self.fpscr();
                if rt.is_pc() {
                    for (k, fl) in [GuestReg::N, GuestReg::Z, GuestReg::C, GuestReg::V].into_iter().enumerate() {
                        let b = self.bit(f, 31 - k as u32);
                        self.wflag(fl, b);
                    }
                } else {
                    self.w(rt, f);
                }
                Flow::Next
            }
            // A8.8.350 VMSR: the host checks the value's UNK/SBZP bits and
            // writes the FPSCR's read/write ones.
            Vmsr { rt, .. } => {
                let a = self.c64(1);
                let v = self.r(rt);
                let v = self.zext(v);
                self.pc_to_next();
                self.sys(abi::sys::VMSR, a, v);
                Flow::Next
            }
            // A8.8.344 VMOV (between ARM core register and single-precision
            // register).
            VmovCoreS { to_core, rt, n } => {
                if to_core {
                    let v = self.sreg(n);
                    self.w(rt, v);
                } else {
                    let v = self.r(rt);
                    self.set_sreg(n, v);
                }
                Flow::Next
            }
            // A8.8.345: S<m>, S<m+1>.
            VmovCoreSS { to_core, rt, rt2, m } => {
                if to_core {
                    let a = self.sreg(m);
                    let b = self.sreg(m + 1);
                    self.w(rt, a);
                    self.w(rt2, b);
                } else {
                    let a = self.r(rt);
                    let b = self.r(rt2);
                    self.set_sreg(m, a);
                    self.set_sreg(m + 1, b);
                }
                Flow::Next
            }
            // A8.8.346: D<m><31:0> and <63:32>.
            VmovCoreD { to_core, rt, rt2, m } => {
                if to_core {
                    let a = self.d_elem(m, 0, 32, false);
                    let b = self.d_elem(m, 1, 32, false);
                    self.w(rt, a);
                    self.w(rt2, b);
                } else {
                    let a = self.r(rt);
                    let b = self.r(rt2);
                    self.set_d_elem(m, 0, 32, a);
                    self.set_d_elem(m, 1, 32, b);
                }
                Flow::Next
            }
            // A8.8.342 VMOV (ARM core register to scalar).
            VmovToScalar { dt, d, index, rt } => {
                let esize = dt.esize();
                let v = self.r(rt);
                self.set_d_elem(d, index as u32, esize, v);
                Flow::Next
            }
            // A8.8.343 VMOV (scalar to ARM core register).
            VmovFromScalar { dt, rt, n, index } => {
                let v = self.d_elem(n, index as u32, dt.esize(), dt.is_signed());
                self.w(rt, v);
                Flow::Next
            }
            // A8.8.315 VDUP (ARM core register).
            VdupCore { dt, d, rt } => {
                let esize = dt.esize();
                let v = self.r(rt);
                let v = if esize < 32 { self.bini(BinOp::And, v, (1 << esize) - 1) } else { v };
                let splat = self.b.def(Expr::VSplat { a: v, lane_bytes: esize / 8 });
                self.write_dq(d, splat);
                Flow::Next
            }
            // A8.8.341 VMOV (register), Advanced SIMD.
            Simd2 { op: Simd2Op::Vmov, d: VReg::Q(d), m: VReg::Q(m), .. } => {
                let v = self.qreg(m);
                self.set_qreg(d, v);
                Flow::Next
            }
            Simd2 { op: Simd2Op::Vmov, d: VReg::D(d), m: VReg::D(m), .. } => {
                let v = self.dreg(m);
                self.set_dreg(d, v);
                Flow::Next
            }
            Vldr { load, d, rn, add, imm } => self.vldr(load, d, rn, add, imm),
            Vldm { load, d, regs, rn, add, wback, fmx } => self.vldm(load, d, regs, rn, add, wback, fmx),
            SimdLdSt { load, form, count, esize, d, inc, regs, index, align, rn, wback, rm } => {
                self.simd_ldst(load, form, count, esize, d, inc, regs, index, align, rn, wback, rm)
            }
            _ => self.fp_data_processing(),
        }
    }

    /// `D[d] = v<63:0>` for a D register, `Q[q] = v` for a Q register, `v` a
    /// vector whose lanes are all the same.
    fn write_dq(&mut self, r: VReg, v: Value) {
        match r {
            VReg::Q(q) => self.set_qreg(q, v),
            VReg::D(d) => {
                let lo = self.b.def(Expr::VExtract { a: v, lane: 0, lane_bytes: 8, signed: false, ty: Ty::I64 });
                self.set_dreg(d, lo);
            }
            VReg::S(_) => unreachable!("an S register is never a vector destination"),
        }
    }

    /// A data-processing instruction, executed by the host where its
    /// condition passes.
    fn fp_data_processing(&mut self) -> Flow {
        let a = self.c64(self.raw as u64);
        let z = self.c64(0);
        self.sys(abi::sys::FP, a, z);
        Flow::Next
    }

    // -- extension register loads and stores (A7.6, A7.7) ----------------------

    /// A8.8.334 VLDR, A8.8.414 VSTR.
    fn vldr(&mut self, load: bool, d: VReg, rn: Reg, add: bool, imm: u32) -> Flow {
        let base = self.r_base(rn);
        let k = self.c32(imm);
        let addr = self.bin(if add { BinOp::Add } else { BinOp::Sub }, base, k);
        match d {
            // MemA[address, 4].
            VReg::S(s) => {
                let host = self.mem(addr, abi::mem::access(2, !load, false, 2));
                if load {
                    let v = self.b.def(Expr::Load { addr: host, offset: 0, sz: MemSz::B4, signed: false, ty: Ty::I32, order: Order::Relaxed });
                    self.set_sreg(s, v);
                } else {
                    let v = self.sreg(s);
                    self.b.stmt(Stmt::Store { addr: host, offset: 0, val: v, sz: MemSz::B4, order: Order::Relaxed });
                }
            }
            // Two word accesses, MemA[address, 4] and MemA[address+4, 4]:
            // one translation of the eight bytes, word aligned.
            VReg::D(dn) => {
                let host = self.mem(addr, abi::mem::access(3, !load, false, 2));
                self.dword(load, host, dn);
            }
            VReg::Q(_) => unreachable!("VLDR of a Q register"),
        }
        Flow::Next
    }

    /// Load or store `D<dn>` at `host` as two little-endian words.
    fn dword(&mut self, load: bool, host: Value, dn: u8) {
        for w in 0..2u32 {
            if load {
                let v = self.b.def(Expr::Load { addr: host, offset: 4 * w as i64, sz: MemSz::B4, signed: false, ty: Ty::I32, order: Order::Relaxed });
                self.set_d_elem(dn, w, 32, v);
            } else {
                let v = self.d_elem(dn, w, 32, false);
                self.b.stmt(Stmt::Store { addr: host, offset: 4 * w as i64, val: v, sz: MemSz::B4, order: Order::Relaxed });
            }
        }
    }

    /// A8.8.333 VLDM, A8.8.413 VSTM, A8.8.368 VPOP, A8.8.369 VPUSH. Every
    /// access is translated first, so an abort leaves the registers as they
    /// were.
    #[allow(clippy::too_many_arguments)]
    fn vldm(&mut self, load: bool, d: VReg, regs: u8, rn: Reg, add: bool, wback: bool, fmx: bool) -> Flow {
        let (first, size) = match d {
            VReg::S(s) => (s, 4u32),
            VReg::D(n) => (n, 8),
            VReg::Q(_) => unreachable!("VLDM of Q registers"),
        };
        let imm32 = size * regs as u32 + if fmx { 4 } else { 0 };
        let base = self.r(rn);
        let start = if add {
            base
        } else {
            let k = self.c32(imm32);
            self.bin(BinOp::Sub, base, k)
        };
        let access = abi::mem::access(if size == 4 { 2 } else { 3 }, !load, false, 2);
        let mut hosts = Vec::with_capacity(regs as usize);
        for r in 0..regs as u32 {
            let off = self.c32(size * r);
            let va = self.bin(BinOp::Add, start, off);
            hosts.push(self.mem(va, access));
        }
        for (r, host) in hosts.into_iter().enumerate() {
            let reg = first + r as u8;
            if size == 4 {
                if load {
                    let v = self.b.def(Expr::Load { addr: host, offset: 0, sz: MemSz::B4, signed: false, ty: Ty::I32, order: Order::Relaxed });
                    self.set_sreg(reg, v);
                } else {
                    let v = self.sreg(reg);
                    self.b.stmt(Stmt::Store { addr: host, offset: 0, val: v, sz: MemSz::B4, order: Order::Relaxed });
                }
            } else {
                self.dword(load, host, reg);
            }
        }
        if wback {
            let k = self.c32(imm32);
            let nb = self.bin(if add { BinOp::Add } else { BinOp::Sub }, base, k);
            self.w(rn, nb);
        }
        Flow::Next
    }

    /// A8.8.321-A8.8.332 VLD1-VLD4, A8.8.405-A8.8.412 VST1-VST4. The
    /// alignment check of the base address is the first access's; each
    /// element is a `MemU[]` access of its size (a 64-bit element's two words
    /// one translation, which SCTLR.A requires 8-byte aligned).
    #[allow(clippy::too_many_arguments)]
    fn simd_ldst(&mut self, load: bool, form: LdStForm, count: u8, esize: u8, d: u8, inc: u8, regs: u8, index: u8, align: u16, rn: Reg, wback: bool, rm: Option<Reg>) -> Flow {
        let esize = esize as u32;
        let ebytes = esize / 8;
        let elements = 64 / esize;
        // (register, element or None for all lanes) of each access, in
        // address order.
        let mut slots: Vec<(u8, Option<u32>)> = Vec::new();
        match form {
            LdStForm::Multiple => {
                for r in 0..regs {
                    for e in 0..elements {
                        for k in 0..count {
                            slots.push((d + k * inc + r, Some(e)));
                        }
                    }
                }
            }
            LdStForm::Lane => {
                for k in 0..count {
                    slots.push((d + k * inc, Some(index as u32)));
                }
            }
            LdStForm::AllLanes => {
                for k in 0..count {
                    slots.push((d + k * inc, None));
                }
            }
        }
        let total = ebytes * slots.len() as u32;
        let base = self.r(rn);
        let size_log2 = ebytes.trailing_zeros();
        let align_log2 = (align as u32).trailing_zeros();
        let mut hosts = Vec::with_capacity(slots.len());
        for k in 0..slots.len() as u32 {
            let off = self.c32(k * ebytes);
            let va = self.bin(BinOp::Add, base, off);
            let al = if k == 0 { align_log2 } else { 0 };
            hosts.push(self.mem(va, abi::mem::access(size_log2, !load, false, al)));
        }
        let sz = match ebytes {
            1 => MemSz::B1,
            2 => MemSz::B2,
            4 => MemSz::B4,
            _ => MemSz::B8,
        };
        let ty = if ebytes == 8 { Ty::I64 } else { Ty::I32 };
        for (&(reg, e), &host) in slots.iter().zip(hosts.iter()) {
            if load {
                let v = self.b.def(Expr::Load { addr: host, offset: 0, sz, signed: false, ty, order: Order::Relaxed });
                match e {
                    Some(e) => self.set_d_elem(reg, e, esize, v),
                    None => {
                        // Replicate(MemU[address, ebytes], elements), into
                        // `regs` registers for VLD1 (to all lanes).
                        let splat = self.b.def(Expr::VSplat { a: v, lane_bytes: ebytes });
                        let lo = self.b.def(Expr::VExtract { a: splat, lane: 0, lane_bytes: 8, signed: false, ty: Ty::I64 });
                        let n = if count == 1 { regs } else { 1 };
                        for r in 0..n {
                            self.set_dreg(reg + r, lo);
                        }
                    }
                }
            } else {
                let e = e.expect("no store to all lanes");
                let v = self.d_elem(reg, e, esize, false);
                self.b.stmt(Stmt::Store { addr: host, offset: 0, val: v, sz, order: Order::Relaxed });
            }
        }
        if wback {
            let inc = match rm {
                Some(m) => self.r(m),
                None => self.c32(total),
            };
            let nb = self.bin(BinOp::Add, base, inc);
            self.w(rn, nb);
        }
        Flow::Next
    }
}
