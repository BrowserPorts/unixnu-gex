//! Floating-point (VFP) and Advanced SIMD decoding (chapter A7).
//!
//! Every entry point takes the ARM form of an encoding. The Thumb decoder
//! converts: Advanced SIMD data processing `111U 1111 ...` becomes
//! `1111 001U ...` (A7.4), element and structure load/store `1111 1001 ...`
//! becomes `1111 0100 ...` (A7.7), and the coprocessor 10/11 encodings keep
//! their low 28 bits (A6.3.18).
//!
//! Register numbers are resolved as A7.3 gives them: a doubleword is `D:Vd`,
//! a single-precision register `Vd:D`, a quadword `D:Vd` halved after the
//! check that its low bit is clear. Immediates are expanded
//! (`AdvSIMDExpandImm`, `VFPExpandImm`), shift amounts and fraction bits
//! computed, and each `SEE` of the decode pseudocode followed.

use crate::{Features, InstrSet, Op, Reg, VfpVersion};

/// An extension register (A2.6.1, A7.3): `S0`-`S31`, `D0`-`D31`, `Q0`-`Q15`.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum VReg {
    S(u8),
    D(u8),
    Q(u8),
}

impl VReg {
    /// The doubleword registers it occupies, as `(first, count)`; `None` for
    /// a single-precision register, which never reaches D16-D31.
    pub fn dregs(self) -> Option<(u8, u8)> {
        match self {
            VReg::S(_) => None,
            VReg::D(n) => Some((n, 1)),
            VReg::Q(n) => Some((2 * n, 2)),
        }
    }
}

/// A data type (A2.6.3, A7.2.3): the `<dt>` of the assembler syntax, which
/// gives the element size and how the elements are interpreted.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Dt {
    None,
    /// An untyped size: `.8` .. `.64`.
    X8,
    X16,
    X32,
    X64,
    I8,
    I16,
    I32,
    I64,
    S8,
    S16,
    S32,
    S64,
    U8,
    U16,
    U32,
    U64,
    P8,
    F16,
    F32,
    F64,
}

impl Dt {
    pub fn name(self) -> &'static str {
        use Dt::*;
        match self {
            None => "",
            X8 => "8",
            X16 => "16",
            X32 => "32",
            X64 => "64",
            I8 => "i8",
            I16 => "i16",
            I32 => "i32",
            I64 => "i64",
            S8 => "s8",
            S16 => "s16",
            S32 => "s32",
            S64 => "s64",
            U8 => "u8",
            U16 => "u16",
            U32 => "u32",
            U64 => "u64",
            P8 => "p8",
            F16 => "f16",
            F32 => "f32",
            F64 => "f64",
        }
    }

    /// The element size in bits (0 for `None`).
    pub fn esize(self) -> u32 {
        use Dt::*;
        match self {
            None => 0,
            X8 | I8 | S8 | U8 | P8 => 8,
            X16 | I16 | S16 | U16 | F16 => 16,
            X32 | I32 | S32 | U32 | F32 => 32,
            X64 | I64 | S64 | U64 | F64 => 64,
        }
    }

    pub fn is_unsigned(self) -> bool {
        matches!(self, Dt::U8 | Dt::U16 | Dt::U32 | Dt::U64)
    }

    pub fn is_signed(self) -> bool {
        matches!(self, Dt::S8 | Dt::S16 | Dt::S32 | Dt::S64)
    }

    pub fn is_float(self) -> bool {
        matches!(self, Dt::F16 | Dt::F32 | Dt::F64)
    }

    fn of(kind: u8, esize: u32) -> Dt {
        use Dt::*;
        let i = match esize {
            8 => 0,
            16 => 1,
            32 => 2,
            _ => 3,
        };
        match kind {
            b'x' => [X8, X16, X32, X64][i],
            b'i' => [I8, I16, I32, I64][i],
            b's' => [S8, S16, S32, S64][i],
            _ => [U8, U16, U32, U64][i],
        }
    }
    /// `S<esize>` or `U<esize>`.
    fn su(unsigned: bool, esize: u32) -> Dt {
        Dt::of(if unsigned { b'u' } else { b's' }, esize)
    }
    fn i(esize: u32) -> Dt {
        Dt::of(b'i', esize)
    }
    fn x(esize: u32) -> Dt {
        Dt::of(b'x', esize)
    }
}

/// The Advanced SIMD operations on three registers (A7.4.1, A7.4.2) and on
/// two registers and a scalar (A7.4.3). The register kinds of the operands
/// give the shape: all the same (D or Q), long (Q, D, D), wide (Q, Q, D) or
/// narrow (D, Q, Q).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Simd3Op {
    /// A8.8.320 VHADD, VHSUB.
    Vhadd,
    Vhsub,
    /// A8.8.371 VQADD.
    Vqadd,
    /// A8.8.383 VQSUB.
    Vqsub,
    /// A8.8.388 VRHADD.
    Vrhadd,
    /// A8.8.288 VAND (register).
    Vand,
    /// A8.8.290 VBIC (register).
    Vbic,
    /// A8.8.361 VORR (register); `n == m` is VMOV (register), see
    /// [`Simd2Op::Vmov`].
    Vorr,
    /// A8.8.359 VORN (register).
    Vorn,
    /// A8.8.316 VEOR.
    Veor,
    /// A8.8.291 VBIF, VBIT, VBSL.
    Vbsl,
    Vbit,
    Vbif,
    /// A8.8.296 VCGT (register).
    Vcgt,
    /// A8.8.294 VCGE (register).
    Vcge,
    /// A8.8.292 VCEQ (register).
    Vceq,
    /// A8.8.422 VTST.
    Vtst,
    /// A8.8.282 VACGE, VACGT.
    Vacge,
    Vacgt,
    /// A8.8.397 VSHL (register): `d = m << n`, the shift in `n`.
    Vshl,
    /// A8.8.380 VQSHL (register).
    Vqshl,
    /// A8.8.389 VRSHL.
    Vrshl,
    /// A8.8.378 VQRSHL.
    Vqrshl,
    /// A8.8.335 / A8.8.336 VMAX, VMIN.
    Vmax,
    Vmin,
    /// A8.8.366 / A8.8.367 VPMAX, VPMIN.
    Vpmax,
    Vpmin,
    /// A8.8.279 / A8.8.280 VABD, A8.8.279 VABDL.
    Vabd,
    Vabdl,
    /// A8.8.278 VABA, VABAL.
    Vaba,
    Vabal,
    /// A8.8.283 / A8.8.284 VADD.
    Vadd,
    /// A8.8.415 / A8.8.416 VSUB.
    Vsub,
    /// A8.8.363 / A8.8.364 VPADD.
    Vpadd,
    /// A8.8.286 VADDL, VADDW.
    Vaddl,
    Vaddw,
    /// A8.8.418 VSUBL, VSUBW.
    Vsubl,
    Vsubw,
    /// A8.8.285 VADDHN, A8.8.384 VRADDHN.
    Vaddhn,
    Vraddhn,
    /// A8.8.417 VSUBHN, A8.8.395 VRSUBHN.
    Vsubhn,
    Vrsubhn,
    /// A8.8.337 / A8.8.338 / A8.8.339 VMLA, VMLAL, VMLS, VMLSL.
    Vmla,
    Vmls,
    Vmlal,
    Vmlsl,
    /// A8.8.351 / A8.8.352 / A8.8.353 VMUL, VMULL.
    Vmul,
    Vmull,
    /// A8.8.373 VQDMULH.
    Vqdmulh,
    /// A8.8.377 VQRDMULH.
    Vqrdmulh,
    /// A8.8.372 VQDMLAL, VQDMLSL.
    Vqdmlal,
    Vqdmlsl,
    /// A8.8.374 VQDMULL.
    Vqdmull,
    /// A8.8.318 VFMA, VFMS (Advanced SIMDv2).
    Vfma,
    Vfms,
    /// A8.8.386 VRECPS.
    Vrecps,
    /// A8.8.393 VRSQRTS.
    Vrsqrts,
}

/// The Advanced SIMD operations on two registers (A7.4.5, and VMOV
/// (register), VMOVL).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Simd2Op {
    /// A8.8.387 VREV16, VREV32, VREV64.
    Vrev16,
    Vrev32,
    Vrev64,
    /// A8.8.365 VPADDL.
    Vpaddl,
    /// A8.8.362 VPADAL.
    Vpadal,
    /// A8.8.300 VCLS.
    Vcls,
    /// A8.8.303 VCLZ.
    Vclz,
    /// A8.8.305 VCNT.
    Vcnt,
    /// A8.8.355 VMVN (register).
    Vmvn,
    /// A8.8.370 VQABS.
    Vqabs,
    /// A8.8.376 VQNEG.
    Vqneg,
    /// A8.8.297, A8.8.295, A8.8.293, A8.8.299, A8.8.302: the compares with
    /// zero.
    Vcgt0,
    Vcge0,
    Vceq0,
    Vcle0,
    Vclt0,
    /// A8.8.281 VABS.
    Vabs,
    /// A8.8.356 VNEG.
    Vneg,
    /// A8.8.419 VSWP.
    Vswp,
    /// A8.8.421 VTRN.
    Vtrn,
    /// A8.8.423 VUZP.
    Vuzp,
    /// A8.8.424 VZIP.
    Vzip,
    /// A8.8.348 VMOVN: `dt` is the source's (`I16` .. `I64`).
    Vmovn,
    /// A8.8.375 VQMOVN (`S`/`U` source, same-signed result) and VQMOVUN
    /// (signed source, unsigned result).
    Vqmovn,
    Vqmovun,
    /// A8.8.385 VRECPE (`U32` or `F32`).
    Vrecpe,
    /// A8.8.392 VRSQRTE.
    Vrsqrte,
    /// A8.8.341 VMOV (register): the VORR with both sources the same.
    Vmov,
    /// A8.8.347 VMOVL: `dt` is the source's.
    Vmovl,
}

/// The Advanced SIMD shifts by an immediate (A7.4.4).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum ShiftOp {
    /// A8.8.399 VSHR.
    Vshr,
    /// A8.8.403 VSRA.
    Vsra,
    /// A8.8.390 VRSHR.
    Vrshr,
    /// A8.8.394 VRSRA.
    Vrsra,
    /// A8.8.404 VSRI.
    Vsri,
    /// A8.8.396 VSHL (immediate).
    Vshl,
    /// A8.8.401 VSLI.
    Vsli,
    /// A8.8.381 VQSHL, VQSHLU (immediate).
    Vqshl,
    Vqshlu,
    /// A8.8.400 VSHRN.
    Vshrn,
    /// A8.8.391 VRSHRN.
    Vrshrn,
    /// A8.8.382 VQSHRN, VQSHRUN.
    Vqshrn,
    Vqshrun,
    /// A8.8.379 VQRSHRN, VQRSHRUN.
    Vqrshrn,
    Vqrshrun,
    /// A8.8.398 VSHLL: encoding A1 with `S`/`U` and `0 < shift < esize`,
    /// A2 with `I` and `shift == esize`.
    Vshll,
}

/// The Advanced SIMD one register and a modified immediate operations
/// (A7.4.6).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum ImmOp {
    /// A8.8.340 VMOV (immediate).
    Vmov,
    /// A8.8.360 VORR (immediate).
    Vorr,
    /// A8.8.354 VMVN (immediate): `d = NOT(imm)`.
    Vmvn,
    /// A8.8.289 VBIC (immediate).
    Vbic,
}

/// The Floating-point (VFP) operations on three registers (A7.5,
/// Table A7-16).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Vfp3Op {
    /// A8.8.338 VMLA, VMLS (floating-point).
    Vmla,
    Vmls,
    /// A8.8.357 VNMLA, VNMLS, VNMUL.
    Vnmla,
    Vnmls,
    Vnmul,
    /// A8.8.352 VMUL.
    Vmul,
    /// A8.8.284 VADD.
    Vadd,
    /// A8.8.416 VSUB.
    Vsub,
    /// A8.8.313 VDIV.
    Vdiv,
    /// A8.8.318 VFMA, VFMS (VFPv4).
    Vfma,
    Vfms,
    /// A8.8.319 VFNMA, VFNMS (VFPv4).
    Vfnma,
    Vfnms,
}

/// The Floating-point operations on two registers (A7.5, Table A7-17).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Vfp2Op {
    /// A8.8.341 VMOV (register).
    Vmov,
    /// A8.8.281 VABS.
    Vabs,
    /// A8.8.356 VNEG.
    Vneg,
    /// A8.8.402 VSQRT.
    Vsqrt,
}

/// The form of an Advanced SIMD element or structure load/store (A7.7).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum LdStForm {
    /// VLDn/VSTn (multiple n-element structures).
    Multiple,
    /// VLDn/VSTn (single n-element structure to/from one lane).
    Lane,
    /// VLDn (single n-element structure to all lanes).
    AllLanes,
}

/// A decoded Floating-point or Advanced SIMD instruction. Register fields
/// are the Arm ARM's `d`, `n`, `m`, `t` after the encoding-specific
/// operations, as [`VReg`]s where the register kind varies.
#[derive(Clone, PartialEq, Debug)]
pub enum FpInst {
    // -- Advanced SIMD data processing (A7.4) ------------------------------
    /// Three registers (A7.4.1, A7.4.2). `dt` is the `<dt>` of the syntax:
    /// the element type of the operands (of the wide operands for the
    /// narrowing forms); `None` for the bitwise operations.
    Simd3 { op: Simd3Op, dt: Dt, d: VReg, n: VReg, m: VReg },
    /// Two registers and a scalar (A7.4.3): the scalar is element `index`
    /// of `D<m>` (`m` 0-7 for 16-bit elements, 0-15 for 32-bit).
    Simd3Scalar { op: Simd3Op, dt: Dt, d: VReg, n: VReg, m: u8, index: u8 },
    /// Two registers (A7.4.5, VMOV (register), VMOVL).
    Simd2 { op: Simd2Op, dt: Dt, d: VReg, m: VReg },
    /// A shift by an immediate (A7.4.4): `shift` is the Arm ARM's
    /// `shift_amount`, `dt` the `<dt>` of the syntax (the source's for the
    /// narrowing and lengthening forms).
    SimdShift { op: ShiftOp, dt: Dt, d: VReg, m: VReg, shift: u8 },
    /// A8.8.306, A8.8.308, A8.8.311 VCVT (Advanced SIMD): to `to` from
    /// `from`; `fbits` is the fixed-point form's `frac_bits` (1-32), 0
    /// for the integer and half-precision forms.
    SimdCvt { to: Dt, from: Dt, d: VReg, m: VReg, fbits: u8 },
    /// One register and a modified immediate (A7.4.6): `imm` is
    /// `AdvSIMDExpandImm(op, cmode, imm8)`, `dt` the `<dt>` Table A7-15
    /// gives it.
    SimdImm { op: ImmOp, dt: Dt, d: VReg, imm: u64 },
    /// A8.8.317 VEXT: bytes from `imm` of `m:n`.
    Vext { d: VReg, n: VReg, m: VReg, imm: u8 },
    /// A8.8.420 VTBL (`tbx` false), VTBX: the table is `len` (1-4)
    /// registers from `D<n>`.
    Vtbl { tbx: bool, d: u8, n: u8, len: u8, m: u8 },
    /// A8.8.314 VDUP (scalar): `dt` `X8`/`X16`/`X32`.
    VdupScalar { dt: Dt, d: VReg, m: u8, index: u8 },

    // -- transfers between ARM core and extension registers (A7.8, A7.9) ---
    /// A8.8.315 VDUP (ARM core register).
    VdupCore { dt: Dt, d: VReg, rt: Reg },
    /// A8.8.342 VMOV (ARM core register to scalar): `dt` `X8`/`X16`/`X32`
    /// (`X32` the Floating-point word form).
    VmovToScalar { dt: Dt, d: u8, index: u8, rt: Reg },
    /// A8.8.343 VMOV (scalar to ARM core register): `dt` `S8`/`U8`/`S16`/
    /// `U16`, or `X32` for the word form.
    VmovFromScalar { dt: Dt, rt: Reg, n: u8, index: u8 },
    /// A8.8.344 VMOV (between ARM core register and single-precision
    /// register).
    VmovCoreS { to_core: bool, rt: Reg, n: u8 },
    /// A8.8.345 VMOV (between two ARM core registers and two
    /// single-precision registers): `S<m>` and `S<m+1>`.
    VmovCoreSS { to_core: bool, rt: Reg, rt2: Reg, m: u8 },
    /// A8.8.346 VMOV (between two ARM core registers and a doubleword
    /// extension register).
    VmovCoreD { to_core: bool, rt: Reg, rt2: Reg, m: u8 },
    /// A8.8.349 / B9.3.21 VMRS: `reg` the special register (0b0001 FPSCR,
    /// 0b0000 FPSID, 0b0110 MVFR1, 0b0111 MVFR0, 0b1000 FPEXC, the rest
    /// SUBARCHITECTURE DEFINED or UNPREDICTABLE). `rt` the PC is
    /// `APSR_nzcv`.
    Vmrs { rt: Reg, reg: u8 },
    /// A8.8.350 / B9.3.22 VMSR.
    Vmsr { reg: u8, rt: Reg },

    // -- Floating-point data processing (A7.5) -----------------------------
    /// Three registers: S, or D registers when `dp` (`sz` set).
    Vfp3 { op: Vfp3Op, dp: bool, d: VReg, n: VReg, m: VReg },
    /// Two registers.
    Vfp2 { op: Vfp2Op, dp: bool, d: VReg, m: VReg },
    /// A8.8.304 VCMP, VCMPE (`e`): with zero when `m` is `None`.
    Vcmp { e: bool, dp: bool, d: VReg, m: Option<VReg> },
    /// A8.8.340 VMOV (immediate), Floating-point: `imm` is
    /// `VFPExpandImm(imm8, 32 or 64)`.
    VmovImm { dp: bool, d: VReg, imm: u64 },
    /// A8.8.307 VCVT, VCVTR (between floating-point and integer): to an
    /// integer (`to` `S32`/`U32`, `d` an S register) rounding toward zero
    /// (`round_zero`, VCVT) or by the FPSCR (VCVTR); or from one (`from`
    /// `S32`/`U32`, `m` an S register; `round_zero` false).
    VcvtInt { to: Dt, from: Dt, d: VReg, m: VReg, round_zero: bool },
    /// A8.8.309 VCVT (between floating-point and fixed-point): in place in
    /// `d`. The fixed-point type is `S16`/`U16`/`S32`/`U32`; `fbits` is
    /// `frac_bits` (negative is UNPREDICTABLE and flagged).
    VcvtFixed { to: Dt, from: Dt, d: VReg, fbits: i8 },
    /// A8.8.310 VCVT (between double-precision and single-precision): the
    /// register kinds give the direction.
    VcvtDs { d: VReg, m: VReg },
    /// A8.8.312 VCVTB, VCVTT: half-precision in the bottom (`top` false) or
    /// top half of `S<d>` / `S<m>`; `to_half` is the single to half
    /// direction.
    VcvtHalf { to_half: bool, top: bool, d: u8, m: u8 },

    // -- extension register load/store (A7.6) ------------------------------
    /// A8.8.333 VLDM, A8.8.413 VSTM, A8.8.368 VPOP, A8.8.369 VPUSH: `regs`
    /// registers from `d`. `add` is increment-after, otherwise
    /// decrement-before. `fmx` is the FLDMX/FSTMX form (odd `imm8`): it
    /// transfers the same registers, but `imm32` and so the writeback
    /// adjustment is `8 * regs + 4`.
    Vldm { load: bool, d: VReg, regs: u8, rn: Reg, add: bool, wback: bool, fmx: bool },
    /// A8.8.334 VLDR, A8.8.414 VSTR: `imm` the unsigned offset, `add` its
    /// sign. A PC base reads `Align(PC, 4)`.
    Vldr { load: bool, d: VReg, rn: Reg, add: bool, imm: u32 },

    // -- Advanced SIMD element or structure load/store (A7.7) --------------
    /// A8.8.321-A8.8.332 VLD1-VLD4, A8.8.405-A8.8.412 VST1-VST4. `count` is
    /// the n of VLDn; the registers are `d`, `d+inc`, ... `regs` is the
    /// register count of VLD1/VST1 (multiple: 1-4; to all lanes: 1-2) and
    /// the per-structure count of VLD2/VST2 (multiple: 1-2), 1 otherwise.
    /// `esize` in bits, `index` the lane, `align` the alignment in bytes
    /// (1: none). `wback` is Rm != PC, `rm` the register post-increment
    /// (Rm neither SP nor PC).
    SimdLdSt {
        load: bool,
        form: LdStForm,
        count: u8,
        esize: u8,
        d: u8,
        inc: u8,
        regs: u8,
        index: u8,
        align: u16,
        rn: Reg,
        wback: bool,
        rm: Option<Reg>,
    },
}

type Dec = Result<(FpInst, Option<&'static str>), ()>;

#[inline]
fn bit(w: u32, n: u32) -> u32 {
    (w >> n) & 1
}
#[inline]
fn bits(w: u32, hi: u32, lo: u32) -> u32 {
    (w >> lo) & ((1u32 << (hi - lo + 1)) - 1)
}

/// `D:Vd`, `N:Vn`, `M:Vm`.
#[inline]
fn dd(w: u32) -> u8 {
    (bit(w, 22) << 4 | bits(w, 15, 12)) as u8
}
#[inline]
fn dn(w: u32) -> u8 {
    (bit(w, 7) << 4 | bits(w, 19, 16)) as u8
}
#[inline]
fn dm(w: u32) -> u8 {
    (bit(w, 5) << 4 | bits(w, 3, 0)) as u8
}
/// `Vd:D`, `Vn:N`, `Vm:M`.
#[inline]
fn sd(w: u32) -> u8 {
    (bits(w, 15, 12) << 1 | bit(w, 22)) as u8
}
#[inline]
fn sn(w: u32) -> u8 {
    (bits(w, 19, 16) << 1 | bit(w, 7)) as u8
}
#[inline]
fn sm(w: u32) -> u8 {
    (bits(w, 3, 0) << 1 | bit(w, 5)) as u8
}

/// The D or Q register for a `D:Vd`-style number (the Q number is halved;
/// callers check its low bit first).
#[inline]
fn dq(q: bool, n: u8) -> VReg {
    if q {
        VReg::Q(n >> 1)
    } else {
        VReg::D(n)
    }
}

/// An S or D register by `dp`, from the `D:Vd` and `Vd:D` numbers.
#[inline]
fn sdr(dp: bool, dnum: u8, snum: u8) -> VReg {
    if dp {
        VReg::D(dnum)
    } else {
        VReg::S(snum)
    }
}

macro_rules! ud {
    ($c:expr) => {
        if $c {
            return Err(());
        }
    };
}

fn ok(i: FpInst) -> Dec {
    Ok((i, None))
}

/// The Half-precision Extension: optional with VFPv3 and Advanced SIMDv1,
/// part of VFPv4 and Advanced SIMDv2 (A1.4.1, A2.6).
fn has_fp16(f: &Features) -> bool {
    f.fp16 || f.vfp == Some(VfpVersion::V4)
}

/// VFPv4 and Advanced SIMDv2, which a VFPv4 core's Advanced SIMD must be
/// (A1.4.1): the fused multiply-accumulates.
fn has_v4(f: &Features) -> bool {
    f.vfp == Some(VfpVersion::V4)
}

// ---------------------------------------------------------------------------
// Advanced SIMD data processing (A7.4)
// ---------------------------------------------------------------------------

/// Advanced SIMD data processing (A7.4) as an ARM-form word `1111001U...`.
pub fn decode_simd_dp(word: u32, f: &Features) -> (Op, Option<&'static str>) {
    if !f.simd || word >> 25 != 0b1111001 {
        return (Op::Undefined, None);
    }
    finish(simd_dp(word, f), f)
}

fn simd_dp(w: u32, f: &Features) -> Dec {
    // Table A7-8.
    if bit(w, 23) == 0 {
        return three_same(w, f);
    }
    if bit(w, 4) == 1 {
        if bit(w, 7) == 0 && bits(w, 21, 19) == 0 {
            return mod_imm(w);
        }
        return shift_imm(w);
    }
    if bits(w, 21, 20) != 0b11 {
        return if bit(w, 6) == 0 { three_diff(w) } else { two_scalar(w) };
    }
    if bit(w, 24) == 0 {
        return vext(w);
    }
    if bit(w, 11) == 0 {
        return two_misc(w, f);
    }
    if bits(w, 11, 10) == 0b10 {
        return vtbl(w);
    }
    if bits(w, 11, 7) == 0b11000 {
        return vdup_scalar(w);
    }
    Err(())
}

/// Three registers of the same length (A7.4.1, Table A7-9).
fn three_same(w: u32, f: &Features) -> Dec {
    use Simd3Op::*;
    let u = bit(w, 24) == 1;
    let q = bit(w, 6) == 1;
    let size = bits(w, 21, 20);
    let esize = 8 << size;
    let (d, n, m) = (dd(w), dn(w), dm(w));
    // Every instruction of the table: if Q == '1' && (Vd<0> == '1' ||
    // Vn<0> == '1' || Vm<0> == '1') then UNDEFINED.
    ud!(q && (d | n | m) & 1 == 1);
    let su = Dt::su(u, esize);
    let fop = bit(w, 21) == 1;
    let sz = bit(w, 20) == 1;
    let (op, dt) = match (bits(w, 11, 8), bit(w, 4)) {
        (0b0000, 0) => {
            ud!(size == 3);
            (Vhadd, su)
        }
        (0b0000, _) => (Vqadd, su),
        (0b0001, 0) => {
            ud!(size == 3);
            (Vrhadd, su)
        }
        (0b0001, _) => {
            let op = match (u, size) {
                (false, 0) => Vand,
                (false, 1) => Vbic,
                (false, 2) => {
                    if n == m {
                        // A8.8.361: if N == M && Vn == Vm then SEE VMOV
                        // (register).
                        return ok(FpInst::Simd2 { op: Simd2Op::Vmov, dt: Dt::None, d: dq(q, d), m: dq(q, m) });
                    }
                    Vorr
                }
                (false, _) => Vorn,
                (true, 0) => Veor,
                (true, 1) => Vbsl,
                (true, 2) => Vbit,
                (true, _) => Vbif,
            };
            (op, Dt::None)
        }
        (0b0010, 0) => {
            ud!(size == 3);
            (Vhsub, su)
        }
        (0b0010, _) => (Vqsub, su),
        (0b0011, b) => {
            ud!(size == 3);
            (if b == 0 { Vcgt } else { Vcge }, su)
        }
        (0b0100, b) => (if b == 0 { Vshl } else { Vqshl }, su),
        (0b0101, b) => (if b == 0 { Vrshl } else { Vqrshl }, su),
        (0b0110, b) => {
            ud!(size == 3);
            (if b == 0 { Vmax } else { Vmin }, su)
        }
        (0b0111, b) => {
            ud!(size == 3);
            (if b == 0 { Vabd } else { Vaba }, su)
        }
        (0b1000, 0) => (if u { Vsub } else { Vadd }, Dt::i(esize)),
        (0b1000, _) => {
            ud!(size == 3);
            if u {
                (Vceq, Dt::i(esize))
            } else {
                (Vtst, Dt::x(esize))
            }
        }
        (0b1001, 0) => {
            ud!(size == 3);
            (if u { Vmls } else { Vmla }, Dt::i(esize))
        }
        (0b1001, _) => {
            // A8.8.351: size == '11' || (op == '1' && size != '00').
            ud!(size == 3 || (u && size != 0));
            (Vmul, if u { Dt::P8 } else { Dt::i(esize) })
        }
        (0b1010, b) => {
            ud!(size == 3 || q);
            (if b == 0 { Vpmax } else { Vpmin }, su)
        }
        (0b1011, 0) => {
            ud!(size == 0 || size == 3);
            (if u { Vqrdmulh } else { Vqdmulh }, Dt::su(false, esize))
        }
        (0b1011, _) => {
            ud!(u || size == 3 || q);
            (Vpadd, Dt::i(esize))
        }
        (0b1100, 1) if !u => {
            // A8.8.318 VFMA, VFMS: Advanced SIMDv2.
            ud!(!has_v4(f) || sz);
            (if fop { Vfms } else { Vfma }, Dt::F32)
        }
        (0b1100, _) => return Err(()),
        (0b1101, 0) => {
            ud!(sz);
            match (u, fop) {
                (false, false) => (Vadd, Dt::F32),
                (false, true) => (Vsub, Dt::F32),
                (true, false) => {
                    ud!(q);
                    (Vpadd, Dt::F32)
                }
                (true, true) => (Vabd, Dt::F32),
            }
        }
        (0b1101, _) => {
            ud!(sz);
            match (u, fop) {
                (false, false) => (Vmla, Dt::F32),
                (false, true) => (Vmls, Dt::F32),
                (true, false) => (Vmul, Dt::F32),
                (true, true) => return Err(()),
            }
        }
        (0b1110, 0) => {
            ud!(sz);
            match (u, fop) {
                (false, false) => (Vceq, Dt::F32),
                (false, true) => return Err(()),
                (true, false) => (Vcge, Dt::F32),
                (true, true) => (Vcgt, Dt::F32),
            }
        }
        (0b1110, _) => {
            ud!(!u || sz);
            (if fop { Vacgt } else { Vacge }, Dt::F32)
        }
        (0b1111, 0) => {
            ud!(sz);
            if u {
                ud!(q);
                (if fop { Vpmin } else { Vpmax }, Dt::F32)
            } else {
                (if fop { Vmin } else { Vmax }, Dt::F32)
            }
        }
        (_, _) => {
            ud!(u || sz);
            (if fop { Vrsqrts } else { Vrecps }, Dt::F32)
        }
    };
    ok(FpInst::Simd3 { op, dt, d: dq(q, d), n: dq(q, n), m: dq(q, m) })
}

/// Three registers of different lengths (A7.4.2, Table A7-10); size != 0b11.
fn three_diff(w: u32) -> Dec {
    use Simd3Op::*;
    let u = bit(w, 24) == 1;
    let size = bits(w, 21, 20);
    let esize = 8 << size;
    let (d, n, m) = (dd(w), dn(w), dm(w));
    let su = Dt::su(u, esize);
    let long = |op, dt| -> Dec {
        // if Vd<0> == '1' then UNDEFINED.
        ud!(d & 1 == 1);
        ok(FpInst::Simd3 { op, dt, d: VReg::Q(d >> 1), n: VReg::D(n), m: VReg::D(m) })
    };
    let narrow = |op| -> Dec {
        // if Vn<0> == '1' || Vm<0> == '1' then UNDEFINED.
        ud!((n | m) & 1 == 1);
        ok(FpInst::Simd3 { op, dt: Dt::i(2 * esize), d: VReg::D(d), n: VReg::Q(n >> 1), m: VReg::Q(m >> 1) })
    };
    match bits(w, 11, 8) {
        a @ 0..=3 => {
            // A8.8.286 / A8.8.418: if Vd<0> == '1' || (op == '1' && Vn<0>
            // == '1') then UNDEFINED.
            let wide = a & 1 == 1;
            ud!(d & 1 == 1 || (wide && n & 1 == 1));
            let op = [Vaddl, Vaddw, Vsubl, Vsubw][a as usize];
            let nr = if wide { VReg::Q(n >> 1) } else { VReg::D(n) };
            ok(FpInst::Simd3 { op, dt: su, d: VReg::Q(d >> 1), n: nr, m: VReg::D(m) })
        }
        0b0100 => narrow(if u { Vraddhn } else { Vaddhn }),
        0b0101 => long(Vabal, su),
        0b0110 => narrow(if u { Vrsubhn } else { Vsubhn }),
        0b0111 => long(Vabdl, su),
        0b1000 | 0b1010 => long(if bit(w, 9) == 1 { Vmlsl } else { Vmlal }, su),
        0b1001 | 0b1011 => {
            // A8.8.372: if size == '00' || Vd<0> == '1' then UNDEFINED.
            ud!(u || size == 0);
            long(if bit(w, 9) == 1 { Vqdmlsl } else { Vqdmlal }, Dt::su(false, esize))
        }
        0b1100 => long(Vmull, su),
        0b1101 => {
            ud!(u || size == 0);
            long(Vqdmull, Dt::su(false, esize))
        }
        0b1110 => {
            // A8.8.351 A2: if op == '1' && (U != '0' || size != '00').
            ud!(u || size != 0);
            long(Vmull, Dt::P8)
        }
        _ => Err(()),
    }
}

/// Two registers and a scalar (A7.4.3, Table A7-11); size != 0b11.
fn two_scalar(w: u32) -> Dec {
    use Simd3Op::*;
    let u = bit(w, 24) == 1;
    let size = bits(w, 21, 20);
    let (d, n) = (dd(w), dn(w));
    // Every instruction of the table: size == '00' is UNDEFINED.
    ud!(size == 0);
    let esize = 8 << size;
    // size 01: m = UInt(Vm<2:0>), index = UInt(M:Vm<3>); size 10: m =
    // UInt(Vm), index = UInt(M).
    let (m, index) = if size == 1 {
        (bits(w, 2, 0) as u8, (bit(w, 5) << 1 | bit(w, 3)) as u8)
    } else {
        (bits(w, 3, 0) as u8, bit(w, 5) as u8)
    };
    let fbit = bit(w, 8) == 1;
    // The Q forms put Q in the U bit: if Q == '1' && (Vd<0> == '1' ||
    // Vn<0> == '1') then UNDEFINED.
    let same = |op, dt| -> Dec {
        ud!(u && (d | n) & 1 == 1);
        ok(FpInst::Simd3Scalar { op, dt, d: dq(u, d), n: dq(u, n), m, index })
    };
    let long = |op, dt| -> Dec {
        ud!(d & 1 == 1);
        ok(FpInst::Simd3Scalar { op, dt, d: VReg::Q(d >> 1), n: VReg::D(n), m, index })
    };
    let sub = bit(w, 10) == 1;
    match bits(w, 11, 8) {
        0b0000 | 0b0001 | 0b0100 | 0b0101 => {
            // if size == '00' || (F == '1' && size == '01') then UNDEFINED.
            ud!(fbit && size == 1);
            same(if sub { Vmls } else { Vmla }, if fbit { Dt::F32 } else { Dt::i(esize) })
        }
        0b0010 | 0b0110 => long(if sub { Vmlsl } else { Vmlal }, Dt::su(u, esize)),
        0b0011 | 0b0111 => {
            ud!(u);
            long(if sub { Vqdmlsl } else { Vqdmlal }, Dt::su(false, esize))
        }
        0b1000 | 0b1001 => {
            ud!(fbit && size == 1);
            same(Vmul, if fbit { Dt::F32 } else { Dt::i(esize) })
        }
        0b1010 => long(Vmull, Dt::su(u, esize)),
        0b1011 => {
            ud!(u);
            long(Vqdmull, Dt::su(false, esize))
        }
        0b1100 => same(Vqdmulh, Dt::su(false, esize)),
        0b1101 => same(Vqrdmulh, Dt::su(false, esize)),
        _ => Err(()),
    }
}

/// Two registers and a shift amount (A7.4.4, Table A7-12); L:imm3 != 0.
fn shift_imm(w: u32) -> Dec {
    use ShiftOp::*;
    let u = bit(w, 24) == 1;
    let l = bit(w, 7) == 1;
    let q = bit(w, 6) == 1;
    let imm6 = bits(w, 21, 16);
    let (d, m) = (dd(w), dm(w));
    // The element size of the L:imm6 forms: 0001xxx 8, 001xxxx 16,
    // 01xxxxx 32, 1xxxxxx 64.
    let esize: u32 = if l {
        64
    } else if imm6 & 0x20 != 0 {
        32
    } else if imm6 & 0x10 != 0 {
        16
    } else {
        8
    };
    // Right shifts: 16/32/64 - imm6 (64 - imm6 for 64-bit elements); left
    // shifts: imm6 - 8/16/32 (imm6 for 64-bit elements).
    let right = if esize == 64 { 64 - imm6 } else { 2 * esize - imm6 };
    let left = if esize == 64 { imm6 } else { imm6 - esize };
    let same = |op, dt, shift: u32| -> Dec {
        // if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED.
        ud!(q && (d | m) & 1 == 1);
        ok(FpInst::SimdShift { op, dt, d: dq(q, d), m: dq(q, m), shift: shift as u8 })
    };
    let narrow = |op, dt| -> Dec {
        ud!(l);
        // if Vm<0> == '1' then UNDEFINED.
        ud!(m & 1 == 1);
        ok(FpInst::SimdShift { op, dt, d: VReg::D(d), m: VReg::Q(m >> 1), shift: right as u8 })
    };
    match bits(w, 11, 8) {
        0b0000 => same(Vshr, Dt::su(u, esize), right),
        0b0001 => same(Vsra, Dt::su(u, esize), right),
        0b0010 => same(Vrshr, Dt::su(u, esize), right),
        0b0011 => same(Vrsra, Dt::su(u, esize), right),
        0b0100 => {
            ud!(!u);
            same(Vsri, Dt::x(esize), right)
        }
        0b0101 => {
            if u {
                same(Vsli, Dt::x(esize), left)
            } else {
                same(Vshl, Dt::i(esize), left)
            }
        }
        0b0110 => {
            // A8.8.381 with op == '0': U == '0' is UNDEFINED, U == '1' is
            // VQSHLU (signed source, unsigned result).
            ud!(!u);
            same(Vqshlu, Dt::su(false, esize), left)
        }
        0b0111 => same(Vqshl, Dt::su(u, esize), left),
        0b1000 => {
            let wide = 2 * esize;
            match (u, q) {
                (false, false) => narrow(Vshrn, Dt::i(wide)),
                (false, true) => narrow(Vrshrn, Dt::i(wide)),
                (true, false) => narrow(Vqshrun, Dt::su(false, wide)),
                (true, true) => narrow(Vqrshrun, Dt::su(false, wide)),
            }
        }
        0b1001 => narrow(if q { Vqrshrn } else { Vqshrn }, Dt::su(u, 2 * esize)),
        0b1010 => {
            ud!(l || q);
            // if Vd<0> == '1' then UNDEFINED.
            ud!(d & 1 == 1);
            if left == 0 {
                // A8.8.398: if shift_amount == 0 then SEE VMOVL.
                ok(FpInst::Simd2 { op: Simd2Op::Vmovl, dt: Dt::su(u, esize), d: VReg::Q(d >> 1), m: VReg::D(m) })
            } else {
                ok(FpInst::SimdShift { op: Vshll, dt: Dt::su(u, esize), d: VReg::Q(d >> 1), m: VReg::D(m), shift: left as u8 })
            }
        }
        0b1110 | 0b1111 => {
            // A8.8.308: if imm6 IN "0xxxxx" then UNDEFINED.
            ud!(l || imm6 & 0x20 == 0);
            ud!(q && (d | m) & 1 == 1);
            let to_fixed = bit(w, 8) == 1;
            let fx = Dt::su(u, 32);
            let (to, from) = if to_fixed { (fx, Dt::F32) } else { (Dt::F32, fx) };
            ok(FpInst::SimdCvt { to, from, d: dq(q, d), m: dq(q, m), fbits: (64 - imm6) as u8 })
        }
        _ => Err(()),
    }
}

/// `AdvSIMDExpandImm(op, cmode, imm8)` (A7.4.6): the constant, or UNDEFINED
/// (`None`), and whether the encoding is UNPREDICTABLE (`testimm8` with a
/// zero `imm8`).
pub fn adv_simd_expand_imm(op: bool, cmode: u32, imm8: u32) -> Option<(u64, bool)> {
    let i = imm8 as u64 & 0xff;
    let rep2 = |x: u64| x | x << 32;
    let rep4 = |x: u64| x | x << 16 | x << 32 | x << 48;
    let (imm, test) = match (cmode >> 1) & 7 {
        0 => (rep2(i), false),
        1 => (rep2(i << 8), true),
        2 => (rep2(i << 16), true),
        3 => (rep2(i << 24), true),
        4 => (rep4(i), false),
        5 => (rep4(i << 8), true),
        6 => {
            if cmode & 1 == 0 {
                (rep2(i << 8 | 0xff), true)
            } else {
                (rep2(i << 16 | 0xffff), true)
            }
        }
        _ => match (cmode & 1, op) {
            (0, false) => (i * 0x0101_0101_0101_0101, false),
            (0, true) => {
                let mut x = 0u64;
                for b in 0..8 {
                    if i >> b & 1 == 1 {
                        x |= 0xff << (8 * b);
                    }
                }
                (x, false)
            }
            (_, false) => {
                // imm8<7>:NOT(imm8<6>):Replicate(imm8<6>,5):imm8<5:0>:Zeros(19).
                let b6 = i >> 6 & 1;
                let imm32 = (i >> 7) << 31 | (b6 ^ 1) << 30 | (if b6 == 1 { 0x1f } else { 0 }) << 25 | (i & 0x3f) << 19;
                (rep2(imm32), false)
            }
            (_, true) => return None,
        },
    };
    Some((imm, test && i == 0))
}

/// One register and a modified immediate value (A7.4.6, Table A7-14).
fn mod_imm(w: u32) -> Dec {
    let op = bit(w, 5) == 1;
    let cmode = bits(w, 11, 8);
    let q = bit(w, 6) == 1;
    let d = dd(w);
    let imm8 = bit(w, 24) << 7 | bits(w, 18, 16) << 4 | bits(w, 3, 0);
    let iop = match (op, cmode) {
        (false, c) if c & 1 == 0 || c >= 0b1100 => ImmOp::Vmov,
        (false, _) => ImmOp::Vorr,
        (true, 0b1110) => ImmOp::Vmov,
        (true, 0b1111) => return Err(()),
        (true, c) if c & 1 == 0 || c == 0b1101 => ImmOp::Vmvn,
        (true, _) => ImmOp::Vbic,
    };
    // if Q == '1' && Vd<0> == '1' then UNDEFINED.
    ud!(q && d & 1 == 1);
    let (imm, unpred) = adv_simd_expand_imm(op, cmode, imm8).ok_or(())?;
    // Table A7-15's <dt>.
    let dt = match cmode {
        0..=7 => Dt::I32,
        8..=11 => Dt::I16,
        12 | 13 => Dt::I32,
        14 => {
            if op {
                Dt::I64
            } else {
                Dt::I8
            }
        }
        _ => Dt::F32,
    };
    let why = match (unpred, iop) {
        (false, _) => None,
        (true, ImmOp::Vmov) => Some("testimm8 && imm8 == '00000000' (A8.8.340 VMOV (immediate), A7.4.6)"),
        (true, ImmOp::Vorr) => Some("testimm8 && imm8 == '00000000' (A8.8.360 VORR (immediate), A7.4.6)"),
        (true, ImmOp::Vmvn) => Some("testimm8 && imm8 == '00000000' (A8.8.354 VMVN (immediate), A7.4.6)"),
        (true, ImmOp::Vbic) => Some("testimm8 && imm8 == '00000000' (A8.8.289 VBIC (immediate), A7.4.6)"),
    };
    Ok((FpInst::SimdImm { op: iop, dt, d: dq(q, d), imm }, why))
}

/// Two registers, miscellaneous (A7.4.5, Table A7-13).
fn two_misc(w: u32, f: &Features) -> Dec {
    use Simd2Op::*;
    let size = bits(w, 19, 18);
    let esize = 8 << size;
    let q = bit(w, 6) == 1;
    let (d, m) = (dd(w), dm(w));
    // if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED.
    let qchk = q && (d | m) & 1 == 1;
    let same = |op, dt| -> Dec {
        ud!(qchk);
        ok(FpInst::Simd2 { op, dt, d: dq(q, d), m: dq(q, m) })
    };
    match bits(w, 17, 16) {
        0b00 => match bits(w, 10, 7) {
            o @ 0..=2 => {
                // A8.8.387: if UInt(op)+UInt(size) >= 3 then UNDEFINED.
                ud!(o + size >= 3);
                same([Vrev64, Vrev32, Vrev16][o as usize], Dt::x(esize))
            }
            4 | 5 => {
                ud!(size == 3);
                same(Vpaddl, Dt::su(bit(w, 7) == 1, esize))
            }
            8 => {
                ud!(size == 3);
                same(Vcls, Dt::su(false, esize))
            }
            9 => {
                ud!(size == 3);
                same(Vclz, Dt::i(esize))
            }
            10 => {
                ud!(size != 0);
                same(Vcnt, Dt::X8)
            }
            11 => {
                ud!(size != 0);
                same(Vmvn, Dt::None)
            }
            12 | 13 => {
                ud!(size == 3);
                same(Vpadal, Dt::su(bit(w, 7) == 1, esize))
            }
            14 => {
                ud!(size == 3);
                same(Vqabs, Dt::su(false, esize))
            }
            15 => {
                ud!(size == 3);
                same(Vqneg, Dt::su(false, esize))
            }
            _ => Err(()),
        },
        0b01 => {
            let fl = bit(w, 10) == 1;
            let o = bits(w, 9, 7);
            ud!(o == 5);
            // if size == '11' || (F == '1' && size != '10') then UNDEFINED.
            ud!(size == 3 || (fl && size != 2));
            let op = [Vcgt0, Vcge0, Vceq0, Vcle0, Vclt0, Vabs, Vabs, Vneg][o as usize];
            let dt = if fl {
                Dt::F32
            } else if op == Vceq0 {
                Dt::i(esize)
            } else {
                Dt::su(false, esize)
            };
            same(op, dt)
        }
        0b10 => match bits(w, 10, 6) {
            0b00000 | 0b00001 => {
                ud!(size != 0);
                same(Vswp, Dt::None)
            }
            0b00010 | 0b00011 => {
                ud!(size == 3);
                same(Vtrn, Dt::x(esize))
            }
            0b00100 | 0b00101 => {
                ud!(size == 3 || (!q && size == 2));
                same(Vuzp, Dt::x(esize))
            }
            0b00110 | 0b00111 => {
                ud!(size == 3 || (!q && size == 2));
                same(Vzip, Dt::x(esize))
            }
            o @ 0b01000..=0b01011 => {
                // A8.8.348 / A8.8.375: if size == '11' || Vm<0> == '1' then
                // UNDEFINED. op 01: VQMOVUN; 10: VQMOVN.S; 11: VQMOVN.U.
                ud!(size == 3 || m & 1 == 1);
                let (op, dt) = match o & 3 {
                    0 => (Vmovn, Dt::i(2 * esize)),
                    1 => (Vqmovun, Dt::su(false, 2 * esize)),
                    2 => (Vqmovn, Dt::su(false, 2 * esize)),
                    _ => (Vqmovn, Dt::su(true, 2 * esize)),
                };
                ok(FpInst::Simd2 { op, dt, d: VReg::D(d), m: VReg::Q(m >> 1) })
            }
            0b01100 => {
                // A8.8.398 A2: if size == '11' || Vd<0> == '1' then
                // UNDEFINED.
                ud!(size == 3 || d & 1 == 1);
                ok(FpInst::SimdShift { op: ShiftOp::Vshll, dt: Dt::i(esize), d: VReg::Q(d >> 1), m: VReg::D(m), shift: esize as u8 })
            }
            0b11000 | 0b11100 => {
                // A8.8.311: Advanced SIMD with the Half-precision Extension.
                ud!(!has_fp16(f));
                let half_to_single = bit(w, 8) == 1;
                ud!(size != 1);
                if half_to_single {
                    ud!(d & 1 == 1);
                    ok(FpInst::SimdCvt { to: Dt::F32, from: Dt::F16, d: VReg::Q(d >> 1), m: VReg::D(m), fbits: 0 })
                } else {
                    ud!(m & 1 == 1);
                    ok(FpInst::SimdCvt { to: Dt::F16, from: Dt::F32, d: VReg::D(d), m: VReg::Q(m >> 1), fbits: 0 })
                }
            }
            _ => Err(()),
        },
        _ => {
            let b = bits(w, 10, 6);
            if b & 0b11000 == 0b10000 {
                // VRECPE (10x0x), VRSQRTE (10x1x): if size != '10' then
                // UNDEFINED.
                ud!(size != 2);
                let fl = bit(w, 8) == 1;
                let op = if bit(w, 7) == 1 { Vrsqrte } else { Vrecpe };
                same(op, if fl { Dt::F32 } else { Dt::U32 })
            } else if b & 0b11000 == 0b11000 {
                // A8.8.306: to_integer = (op<1> == '1'), unsigned = (op<0>
                // == '1').
                ud!(qchk);
                ud!(size != 2);
                let to_int = bit(w, 8) == 1;
                let ity = Dt::su(bit(w, 7) == 1, 32);
                let (to, from) = if to_int { (ity, Dt::F32) } else { (Dt::F32, ity) };
                ok(FpInst::SimdCvt { to, from, d: dq(q, d), m: dq(q, m), fbits: 0 })
            } else {
                Err(())
            }
        }
    }
}

/// A8.8.317 VEXT.
fn vext(w: u32) -> Dec {
    let q = bit(w, 6) == 1;
    let (d, n, m) = (dd(w), dn(w), dm(w));
    let imm4 = bits(w, 11, 8);
    ud!(q && (d | n | m) & 1 == 1);
    // if Q == '0' && imm4<3> == '1' then UNDEFINED.
    ud!(!q && imm4 & 8 != 0);
    ok(FpInst::Vext { d: dq(q, d), n: dq(q, n), m: dq(q, m), imm: imm4 as u8 })
}

/// A8.8.420 VTBL, VTBX.
fn vtbl(w: u32) -> Dec {
    let len = bits(w, 9, 8) as u8 + 1;
    let n = dn(w);
    let i = FpInst::Vtbl { tbx: bit(w, 6) == 1, d: dd(w), n, len, m: dm(w) };
    if n as u32 + len as u32 > 32 {
        return Ok((i, Some("n+length > 32 (A8.8.420 VTBL, VTBX)")));
    }
    ok(i)
}

/// A8.8.314 VDUP (scalar).
fn vdup_scalar(w: u32) -> Dec {
    let imm4 = bits(w, 19, 16);
    let q = bit(w, 6) == 1;
    let d = dd(w);
    // if imm4 IN "x000" then UNDEFINED.
    ud!(imm4 & 7 == 0);
    ud!(q && d & 1 == 1);
    let (dt, index) = if imm4 & 1 == 1 {
        (Dt::X8, imm4 >> 1)
    } else if imm4 & 2 == 2 {
        (Dt::X16, imm4 >> 2)
    } else {
        (Dt::X32, imm4 >> 3)
    };
    ok(FpInst::VdupScalar { dt, d: dq(q, d), m: dm(w), index: index as u8 })
}

// ---------------------------------------------------------------------------
// Advanced SIMD element or structure load/store (A7.7)
// ---------------------------------------------------------------------------

/// Advanced SIMD element or structure load/store (A7.7), ARM form
/// `11110100xxx0...`.
pub fn decode_simd_ldst(word: u32, f: &Features) -> (Op, Option<&'static str>) {
    if !f.simd || word >> 24 != 0b1111_0100 || bit(word, 20) != 0 {
        return (Op::Undefined, None);
    }
    finish(simd_ldst(word), f)
}

fn simd_ldst(w: u32) -> Dec {
    let load = bit(w, 21) == 1;
    let rn = Reg::of(bits(w, 19, 16));
    let rmf = bits(w, 3, 0);
    let d = dd(w);
    // wback = (m != 15); register_index = (m != 15 && m != 13).
    let wback = rmf != 15;
    let rm = if rmf != 15 && rmf != 13 { Some(Reg::of(rmf)) } else { None };
    let mk = |form, count: u32, esize: u32, inc: u32, regs: u32, index: u32, align: u32| FpInst::SimdLdSt {
        load,
        form,
        count: count as u8,
        esize: esize as u8,
        d,
        inc: inc as u8,
        regs: regs as u8,
        index: index as u8,
        align: align as u16,
        rn,
        wback,
        rm,
    };
    let n15 = rn.is_pc();
    let d32 = d as u32;
    if bit(w, 23) == 0 {
        // Multiple structures: type, size, align.
        let size = bits(w, 7, 6);
        let align = bits(w, 5, 4);
        let esize = 8 << size;
        // alignment = if align == '00' then 1 else 4 << UInt(align).
        let al = if align == 0 { 1 } else { 4 << align };
        let ty = bits(w, 11, 8);
        let (i, why) = match ty {
            0b0111 | 0b1010 | 0b0110 | 0b0010 => {
                // VLD1 / VST1 (multiple single elements).
                let regs = match ty {
                    0b0111 => {
                        ud!(align & 2 != 0);
                        1
                    }
                    0b1010 => {
                        ud!(align == 3);
                        2
                    }
                    0b0110 => {
                        ud!(align & 2 != 0);
                        3
                    }
                    _ => 4,
                };
                let why = if n15 || d32 + regs > 32 {
                    Some(if load {
                        "n == 15 || d+regs > 32 (A8.8.321 VLD1 (multiple single elements))"
                    } else {
                        "n == 15 || d+regs > 32 (A8.8.405 VST1 (multiple single elements))"
                    })
                } else {
                    None
                };
                (mk(LdStForm::Multiple, 1, esize, 1, regs, 0, al), why)
            }
            0b1000 | 0b1001 | 0b0011 => {
                ud!(size == 3);
                let (regs, inc) = match ty {
                    0b1000 => {
                        ud!(align == 3);
                        (1, 1)
                    }
                    0b1001 => {
                        ud!(align == 3);
                        (1, 2)
                    }
                    _ => (2, 2),
                };
                let why = if n15 || d32 + inc + regs > 32 {
                    Some(if load {
                        "n == 15 || d2+regs > 32 (A8.8.324 VLD2 (multiple 2-element structures))"
                    } else {
                        "n == 15 || d2+regs > 32 (A8.8.407 VST2 (multiple 2-element structures))"
                    })
                } else {
                    None
                };
                (mk(LdStForm::Multiple, 2, esize, inc, regs, 0, al), why)
            }
            0b0100 | 0b0101 => {
                // if size == '11' || align<1> == '1' then UNDEFINED.
                ud!(size == 3 || align & 2 != 0);
                let inc = if ty == 0b0100 { 1 } else { 2 };
                let why = if n15 || d32 + 2 * inc > 31 {
                    Some(if load {
                        "n == 15 || d3 > 31 (A8.8.327 VLD3 (multiple 3-element structures))"
                    } else {
                        "n == 15 || d3 > 31 (A8.8.409 VST3 (multiple 3-element structures))"
                    })
                } else {
                    None
                };
                let al = if align & 1 == 0 { 1 } else { 8 };
                (mk(LdStForm::Multiple, 3, esize, inc, 1, 0, al), why)
            }
            0b0000 | 0b0001 => {
                ud!(size == 3);
                let inc = if ty == 0 { 1 } else { 2 };
                let why = if n15 || d32 + 3 * inc > 31 {
                    Some(if load {
                        "n == 15 || d4 > 31 (A8.8.330 VLD4 (multiple 4-element structures))"
                    } else {
                        "n == 15 || d4 > 31 (A8.8.411 VST4 (multiple 4-element structures))"
                    })
                } else {
                    None
                };
                (mk(LdStForm::Multiple, 4, esize, inc, 1, 0, al), why)
            }
            _ => return Err(()),
        };
        return Ok((i, why));
    }
    let size = bits(w, 11, 10);
    let count = bits(w, 9, 8) + 1;
    if size == 3 {
        // To all lanes, loads only (Tables A7-20, A7-21): size, T, a.
        ud!(!load);
        let size = bits(w, 7, 6);
        let t = bit(w, 5);
        let a = bit(w, 4) == 1;
        let ebytes = 1u32 << size;
        let inc = t + 1;
        let (i, why) = match count {
            1 => {
                // if size == '11' || (size == '00' && a == '1') then
                // UNDEFINED.
                ud!(size == 3 || (size == 0 && a));
                let regs = t + 1;
                let why = if n15 || d32 + regs > 32 {
                    Some("n == 15 || d+regs > 32 (A8.8.323 VLD1 (single element to all lanes))")
                } else {
                    None
                };
                (mk(LdStForm::AllLanes, 1, 8 * ebytes, 1, regs, 0, if a { ebytes } else { 1 }), why)
            }
            2 => {
                ud!(size == 3);
                let why = if n15 || d32 + inc > 31 {
                    Some("n == 15 || d2 > 31 (A8.8.326 VLD2 (single 2-element structure to all lanes))")
                } else {
                    None
                };
                (mk(LdStForm::AllLanes, 2, 8 * ebytes, inc, 1, 0, if a { 2 * ebytes } else { 1 }), why)
            }
            3 => {
                ud!(size == 3 || a);
                let why = if n15 || d32 + 2 * inc > 31 {
                    Some("n == 15 || d3 > 31 (A8.8.329 VLD3 (single 3-element structure to all lanes))")
                } else {
                    None
                };
                (mk(LdStForm::AllLanes, 3, 8 * ebytes, inc, 1, 0, 1), why)
            }
            _ => {
                // if size == '11' && a == '0' then UNDEFINED; size 11 is
                // 32-bit elements with 16-byte alignment.
                ud!(size == 3 && !a);
                let (eb, al) = if size == 3 {
                    (4, 16)
                } else if size == 2 {
                    (4, if a { 8 } else { 1 })
                } else {
                    (ebytes, if a { 4 * ebytes } else { 1 })
                };
                let why = if n15 || d32 + 3 * inc > 31 {
                    Some("n == 15 || d4 > 31 (A8.8.332 VLD4 (single 4-element structure to all lanes))")
                } else {
                    None
                };
                (mk(LdStForm::AllLanes, 4, 8 * eb, inc, 1, 0, al), why)
            }
        };
        return Ok((i, why));
    }
    // One lane: size, index_align.
    let ia = bits(w, 7, 4);
    let esize = 8 << size;
    let (index, inc, al) = match (count, size) {
        (1, 0) => {
            ud!(ia & 1 != 0);
            (ia >> 1, 1, 1)
        }
        (1, 1) => {
            ud!(ia & 2 != 0);
            (ia >> 2, 1, if ia & 1 == 0 { 1 } else { 2 })
        }
        (1, _) => {
            ud!(ia & 4 != 0);
            ud!(ia & 3 != 0 && ia & 3 != 3);
            (ia >> 3, 1, if ia & 3 == 0 { 1 } else { 4 })
        }
        (2, 0) => (ia >> 1, 1, if ia & 1 == 0 { 1 } else { 2 }),
        (2, 1) => (ia >> 2, 1 + (ia >> 1 & 1), if ia & 1 == 0 { 1 } else { 4 }),
        (2, _) => {
            ud!(ia & 2 != 0);
            (ia >> 3, 1 + (ia >> 2 & 1), if ia & 1 == 0 { 1 } else { 8 })
        }
        (3, 0) => {
            ud!(ia & 1 != 0);
            (ia >> 1, 1, 1)
        }
        (3, 1) => {
            ud!(ia & 1 != 0);
            (ia >> 2, 1 + (ia >> 1 & 1), 1)
        }
        (3, _) => {
            ud!(ia & 3 != 0);
            (ia >> 3, 1 + (ia >> 2 & 1), 1)
        }
        (_, 0) => (ia >> 1, 1, if ia & 1 == 0 { 1 } else { 4 }),
        (_, 1) => (ia >> 2, 1 + (ia >> 1 & 1), if ia & 1 == 0 { 1 } else { 8 }),
        (_, _) => {
            ud!(ia & 3 == 3);
            (ia >> 3, 1 + (ia >> 2 & 1), if ia & 3 == 0 { 1 } else { 4 << (ia & 3) })
        }
    };
    let last = d32 + (count - 1) * inc;
    let why = match count {
        1 if n15 => Some(if load {
            "n == 15 (A8.8.322 VLD1 (single element to one lane))"
        } else {
            "n == 15 (A8.8.406 VST1 (single element from one lane))"
        }),
        2 if n15 || last > 31 => Some(if load {
            "n == 15 || d2 > 31 (A8.8.325 VLD2 (single 2-element structure to one lane))"
        } else {
            "n == 15 || d2 > 31 (A8.8.408 VST2 (single 2-element structure from one lane))"
        }),
        3 if n15 || last > 31 => Some(if load {
            "n == 15 || d3 > 31 (A8.8.328 VLD3 (single 3-element structure to one lane))"
        } else {
            "n == 15 || d3 > 31 (A8.8.410 VST3 (single 3-element structure from one lane))"
        }),
        4 if n15 || last > 31 => Some(if load {
            "n == 15 || d4 > 31 (A8.8.331 VLD4 (single 4-element structure to one lane))"
        } else {
            "n == 15 || d4 > 31 (A8.8.412 VST4 (single 4-element structure from one lane))"
        }),
        _ => None,
    };
    Ok((mk(LdStForm::Lane, count, esize, inc, 1, index, al), why))
}

// ---------------------------------------------------------------------------
// The coprocessor 10/11 space (A5.6, A6.3.18)
// ---------------------------------------------------------------------------

/// The coprocessor 10/11 space (A5.6, A6.3.18) as an ARM-form word (bits
/// 31:28 ignored), in the ARM instruction set.
pub fn decode_cp(word: u32, f: &Features) -> (Op, Option<&'static str>) {
    decode_cp_in(word, f, InstrSet::Arm)
}

/// [`decode_cp`] for either instruction set: the Thumb forms add the
/// `CurrentInstrSet() != InstrSet_ARM` UNPREDICTABLE conditions (SP as a
/// transfer register, PC as a VSTR or VLDM/VSTM base).
pub fn decode_cp_in(word: u32, f: &Features, set: InstrSet) -> (Op, Option<&'static str>) {
    if bits(word, 11, 9) != 0b101 {
        return (Op::Undefined, None);
    }
    let arm = set == InstrSet::Arm;
    let r = match bits(word, 27, 24) {
        0b1100 | 0b1101 => {
            if bits(word, 24, 23) == 0 && bit(word, 21) == 0 {
                // P = U = W = 0: 0010x is the 64-bit transfers, 0000x
                // UNDEFINED (A5.6, Table A7-19).
                if bit(word, 22) == 1 {
                    xfer64(word, f, arm)
                } else {
                    Err(())
                }
            } else {
                ext_ldst(word, f, arm)
            }
        }
        0b1110 => {
            if bit(word, 4) == 0 {
                vfp_dp(word, f)
            } else {
                xfer32(word, f, arm)
            }
        }
        _ => Err(()),
    };
    finish(r, f)
}

/// Extension register load/store (A7.6, Table A7-19).
fn ext_ldst(w: u32, f: &Features, arm: bool) -> Dec {
    let p = bit(w, 24) == 1;
    let u = bit(w, 23) == 1;
    let wb = bit(w, 21) == 1;
    let load = bit(w, 20) == 1;
    let dp = bit(w, 8) == 1;
    let rn = Reg::of(bits(w, 19, 16));
    let imm8 = bits(w, 7, 0);
    // T1/A1 (doublewords): VFP or Advanced SIMD; T2/A2: VFP only.
    ud!(f.vfp.is_none() && !(dp && f.simd));
    let d = sdr(dp, dd(w), sd(w));
    if p && !wb {
        // A8.8.334 VLDR, A8.8.414 VSTR.
        let i = FpInst::Vldr { load, d, rn, add: u, imm: imm8 << 2 };
        if !load && rn.is_pc() && !arm {
            return Ok((i, Some("n == 15 && CurrentInstrSet() != InstrSet_ARM (A8.8.414 VSTR)")));
        }
        return ok(i);
    }
    // if P == U && W == '1' then UNDEFINED.
    ud!(p == u);
    let first = match d {
        VReg::D(n) | VReg::S(n) => n as u32,
        VReg::Q(n) => 2 * n as u32,
    };
    // regs = UInt(imm8) DIV 2 for doublewords; an odd imm8 is FLDMX/FSTMX.
    let regs = if dp { imm8 / 2 } else { imm8 };
    let fmx = dp && imm8 & 1 == 1;
    let pushpop = rn.is_sp() && wb && (load == u);
    let i = FpInst::Vldm { load, d, regs: regs as u8, rn, add: u, wback: wb, fmx };
    let why: Option<&'static str> = if rn.is_pc() && (wb || !arm) {
        Some(if load {
            "n == 15 && (wback || CurrentInstrSet() != InstrSet_ARM) (A8.8.333 VLDM)"
        } else {
            "n == 15 && (wback || CurrentInstrSet() != InstrSet_ARM) (A8.8.413 VSTM)"
        })
    } else if dp && (regs == 0 || regs > 16 || first + regs > 32) {
        Some(match (load, pushpop) {
            (true, true) => "regs == 0 || regs > 16 || (d+regs) > 32 (A8.8.368 VPOP)",
            (true, false) => "regs == 0 || regs > 16 || (d+regs) > 32 (A8.8.333 VLDM)",
            (false, true) => "regs == 0 || regs > 16 || (d+regs) > 32 (A8.8.369 VPUSH)",
            (false, false) => "regs == 0 || regs > 16 || (d+regs) > 32 (A8.8.413 VSTM)",
        })
    } else if !dp && (regs == 0 || first + regs > 32) {
        Some(match (load, pushpop) {
            (true, true) => "regs == 0 || (d+regs) > 32 (A8.8.368 VPOP)",
            (true, false) => "regs == 0 || (d+regs) > 32 (A8.8.333 VLDM)",
            (false, true) => "regs == 0 || (d+regs) > 32 (A8.8.369 VPUSH)",
            (false, false) => "regs == 0 || (d+regs) > 32 (A8.8.413 VSTM)",
        })
    } else if dp && !f.d32 && first + regs > 16 {
        Some(match (load, pushpop) {
            (true, true) => "VFPSmallRegisterBank() && (d+regs) > 16 (A8.8.368 VPOP)",
            (true, false) => "VFPSmallRegisterBank() && (d+regs) > 16 (A8.8.333 VLDM)",
            (false, true) => "VFPSmallRegisterBank() && (d+regs) > 16 (A8.8.369 VPUSH)",
            (false, false) => "VFPSmallRegisterBank() && (d+regs) > 16 (A8.8.413 VSTM)",
        })
    } else if fmx && first + regs > 16 {
        Some("FLDMX/FSTMX accessing D16-D31 (A8.8.51 FLDMX, FSTMX)")
    } else {
        None
    };
    Ok((i, why))
}

/// 64-bit transfers between ARM core and extension registers (A7.9,
/// Table A7-23).
fn xfer64(w: u32, f: &Features, arm: bool) -> Dec {
    // op == 00x1.
    ud!(bits(w, 7, 6) != 0 || bit(w, 4) != 1);
    let to_core = bit(w, 20) == 1;
    let rt = Reg::of(bits(w, 15, 12));
    let rt2 = Reg::of(bits(w, 19, 16));
    if bit(w, 8) == 0 {
        // A8.8.345: VFPv2, VFPv3, VFPv4.
        ud!(f.vfp.is_none());
        let m = sm(w);
        let why = if rt.is_pc() || rt2.is_pc() || m == 31 {
            Some("t == 15 || t2 == 15 || m == 31 (A8.8.345 VMOV (two ARM core registers and two single-precision registers))")
        } else if !arm && (rt.is_sp() || rt2.is_sp()) {
            Some("CurrentInstrSet() != InstrSet_ARM && (t == 13 || t2 == 13) (A8.8.345 VMOV (two ARM core registers and two single-precision registers))")
        } else if to_core && rt == rt2 {
            Some("to_arm_registers && t == t2 (A8.8.345 VMOV (two ARM core registers and two single-precision registers))")
        } else {
            None
        };
        Ok((FpInst::VmovCoreSS { to_core, rt, rt2, m }, why))
    } else {
        // A8.8.346: VFPv2, VFPv3, VFPv4, Advanced SIMD.
        ud!(f.vfp.is_none() && !f.simd);
        let m = dm(w);
        let why = if rt.is_pc() || rt2.is_pc() {
            Some("t == 15 || t2 == 15 (A8.8.346 VMOV (two ARM core registers and a doubleword extension register))")
        } else if !arm && (rt.is_sp() || rt2.is_sp()) {
            Some("CurrentInstrSet() != InstrSet_ARM && (t == 13 || t2 == 13) (A8.8.346 VMOV (two ARM core registers and a doubleword extension register))")
        } else if to_core && rt == rt2 {
            Some("to_arm_registers && t == t2 (A8.8.346 VMOV (two ARM core registers and a doubleword extension register))")
        } else {
            None
        };
        Ok((FpInst::VmovCoreD { to_core, rt, rt2, m }, why))
    }
}

/// `VFPExpandImm(imm8, N)` (A7.5.1): the bits of the constant, in the low
/// 32 bits for N == 32.
pub fn vfp_expand_imm(imm8: u32, dp: bool) -> u64 {
    let i = imm8 as u64 & 0xff;
    let sign = i >> 7;
    let b6 = i >> 6 & 1;
    let ef = i >> 4 & 3;
    let frac = i & 15;
    if dp {
        // exp = NOT(imm8<6>):Replicate(imm8<6>, 8):imm8<5:4>; frac =
        // imm8<3:0>:Zeros(48).
        let exp = (b6 ^ 1) << 10 | (if b6 == 1 { 0xff } else { 0 }) << 2 | ef;
        sign << 63 | exp << 52 | frac << 48
    } else {
        let exp = (b6 ^ 1) << 7 | (if b6 == 1 { 0x1f } else { 0 }) << 2 | ef;
        sign << 31 | exp << 23 | frac << 19
    }
}

/// Floating-point data processing (A7.5, Table A7-16).
fn vfp_dp(w: u32, f: &Features) -> Dec {
    use Vfp3Op::*;
    ud!(f.vfp.is_none());
    let dp = bit(w, 8) == 1;
    let opc1 = bit(w, 23) << 2 | bits(w, 21, 20);
    let b6 = bit(w, 6) == 1;
    let d = sdr(dp, dd(w), sd(w));
    let n = sdr(dp, dn(w), sn(w));
    let m = sdr(dp, dm(w), sm(w));
    let three = |op| ok(FpInst::Vfp3 { op, dp, d, n, m });
    match opc1 {
        0 => three(if b6 { Vmls } else { Vmla }),
        // A8.8.357: type = if op == '1' then VFPNegMul_VNMLA else
        // VFPNegMul_VNMLS.
        1 => three(if b6 { Vnmla } else { Vnmls }),
        2 => three(if b6 { Vnmul } else { Vmul }),
        3 => three(if b6 { Vsub } else { Vadd }),
        4 => {
            ud!(b6);
            three(Vdiv)
        }
        5 => {
            // VFNMA (op 1), VFNMS: VFPv4.
            ud!(!has_v4(f));
            three(if b6 { Vfnma } else { Vfnms })
        }
        6 => {
            ud!(!has_v4(f));
            three(if b6 { Vfms } else { Vfma })
        }
        _ => vfp_other(w, f),
    }
}

/// Other Floating-point data-processing instructions (A7.5, Table A7-17).
fn vfp_other(w: u32, f: &Features) -> Dec {
    let dp = bit(w, 8) == 1;
    let d = sdr(dp, dd(w), sd(w));
    let m = sdr(dp, dm(w), sm(w));
    let b7 = bit(w, 7) == 1;
    if bit(w, 6) == 0 {
        // A8.8.340 VMOV (immediate) A2: sz (0) 0 (0) 0 imm4L.
        let imm8 = bits(w, 19, 16) << 4 | bits(w, 3, 0);
        let i = FpInst::VmovImm { dp, d, imm: vfp_expand_imm(imm8, dp) };
        if b7 || bit(w, 5) == 1 {
            return Ok((i, Some("(0) bits 7, 5 not zero (A8.8.340 VMOV (immediate))")));
        }
        return ok(i);
    }
    match bits(w, 19, 16) {
        0b0000 => ok(FpInst::Vfp2 { op: if b7 { Vfp2Op::Vabs } else { Vfp2Op::Vmov }, dp, d, m }),
        0b0001 => ok(FpInst::Vfp2 { op: if b7 { Vfp2Op::Vsqrt } else { Vfp2Op::Vneg }, dp, d, m }),
        0b0010 | 0b0011 => {
            // A8.8.312 VCVTB, VCVTT: VFPv3 Half-precision Extension, VFPv4.
            // half_to_single = (op == '0'); bit 8 is (0).
            ud!(!has_fp16(f));
            let i = FpInst::VcvtHalf { to_half: bit(w, 16) == 1, top: b7, d: sd(w), m: sm(w) };
            if dp {
                return Ok((i, Some("(0) bit 8 not zero (A8.8.312 VCVTB, VCVTT)")));
            }
            ok(i)
        }
        0b0100 => ok(FpInst::Vcmp { e: b7, dp, d, m: Some(m) }),
        0b0101 => {
            let i = FpInst::Vcmp { e: b7, dp, d, m: None };
            if bit(w, 5) == 1 || bits(w, 3, 0) != 0 {
                return Ok((i, Some("(0) bits 5, 3:0 not zero (A8.8.304 VCMP, VCMPE)")));
            }
            ok(i)
        }
        0b0111 => {
            ud!(!b7);
            // A8.8.310: double_to_single = (sz == '1').
            let (d, m) = if dp { (VReg::S(sd(w)), VReg::D(dm(w))) } else { (VReg::D(dd(w)), VReg::S(sm(w))) };
            ok(FpInst::VcvtDs { d, m })
        }
        0b1000 => {
            // A8.8.307 to floating-point: unsigned = (op == '0').
            let from = Dt::su(!b7, 32);
            ok(FpInst::VcvtInt { to: if dp { Dt::F64 } else { Dt::F32 }, from, d, m: VReg::S(sm(w)), round_zero: false })
        }
        0b1100 | 0b1101 => {
            // A8.8.307 to integer: unsigned = (opc2<0> == '0'); round_zero
            // = (op == '1').
            let to = Dt::su(bit(w, 16) == 0, 32);
            ok(FpInst::VcvtInt { to, from: if dp { Dt::F64 } else { Dt::F32 }, d: VReg::S(sd(w)), m, round_zero: b7 })
        }
        0b1010 | 0b1011 | 0b1110 | 0b1111 => {
            // A8.8.309: to_fixed = (op == '1'); size = if sx == '0' then 16
            // else 32; frac_bits = size - UInt(imm4:i).
            let to_fixed = bit(w, 18) == 1;
            let size = if b7 { 32 } else { 16 };
            let fx = Dt::su(bit(w, 16) == 1, size);
            let fl = if dp { Dt::F64 } else { Dt::F32 };
            let fbits = size as i32 - (bits(w, 3, 0) << 1 | bit(w, 5)) as i32;
            let (to, from) = if to_fixed { (fx, fl) } else { (fl, fx) };
            let i = FpInst::VcvtFixed { to, from, d, fbits: fbits as i8 };
            if fbits < 0 {
                return Ok((i, Some("frac_bits < 0 (A8.8.309 VCVT (between floating-point and fixed-point))")));
            }
            ok(i)
        }
        _ => Err(()),
    }
}

/// 8, 16, and 32-bit transfer between ARM core and extension registers
/// (A7.8, Table A7-22).
fn xfer32(w: u32, f: &Features, arm: bool) -> Dec {
    let l = bit(w, 20) == 1;
    let c = bit(w, 8) == 1;
    let a = bits(w, 23, 21);
    let rt = Reg::of(bits(w, 15, 12));
    let low0 = bits(w, 3, 0) != 0;
    // t == 15 || (CurrentInstrSet() != InstrSet_ARM && t == 13).
    let bad_t = rt.is_pc() || (!arm && rt.is_sp());
    match (l, c, a) {
        (_, false, 0) => {
            // A8.8.344: VFPv2, VFPv3, VFPv4.
            ud!(f.vfp.is_none());
            let i = FpInst::VmovCoreS { to_core: l, rt, n: sn(w) };
            let why = if bits(w, 6, 5) != 0 || low0 {
                Some("(0) bits 6:5, 3:0 not zero (A8.8.344 VMOV (between ARM core register and single-precision register))")
            } else if bad_t {
                Some("t == 15 || (CurrentInstrSet() != InstrSet_ARM && t == 13) (A8.8.344 VMOV (between ARM core register and single-precision register))")
            } else {
                None
            };
            Ok((i, why))
        }
        (false, false, 7) => {
            ud!(f.vfp.is_none() && !f.simd);
            let reg = bits(w, 19, 16) as u8;
            let i = FpInst::Vmsr { reg, rt };
            let why = if bits(w, 7, 5) != 0 || low0 {
                Some("(0) bits 7:5, 3:0 not zero (A8.8.350 VMSR)")
            } else if bad_t {
                Some("t == 15 || (t == 13 && CurrentInstrSet() != InstrSet_ARM) (A8.8.350 VMSR)")
            } else if reg & 0b1110 == 0b0010 || reg & 0b1100 == 0b0100 {
                Some("reg IN {001x, 01xx} (B9.3.22 VMSR)")
            } else {
                None
            };
            Ok((i, why))
        }
        (true, false, 7) => {
            ud!(f.vfp.is_none() && !f.simd);
            let reg = bits(w, 19, 16) as u8;
            let i = FpInst::Vmrs { rt, reg };
            let why = if bits(w, 7, 5) != 0 || low0 {
                Some("(0) bits 7:5, 3:0 not zero (A8.8.349 VMRS)")
            } else if rt.is_sp() && !arm {
                Some("t == 13 && CurrentInstrSet() != InstrSet_ARM (A8.8.349 VMRS)")
            } else if rt.is_pc() && reg != 1 {
                Some("t == 15 && reg != '0001' (B9.3.21 VMRS)")
            } else if reg & 0b1110 == 0b0010 || reg & 0b1110 == 0b0100 {
                Some("reg IN {001x, 010x} (B9.3.21 VMRS)")
            } else {
                None
            };
            Ok((i, why))
        }
        (false, true, 0..=3) => {
            // A8.8.342 VMOV (ARM core register to scalar): opc1:opc2 1xxx
            // byte, 0xx1 halfword, 0x00 word, 0x10 UNDEFINED.
            let opc = bits(w, 22, 21) << 2 | bits(w, 6, 5);
            let (dt, index) = if opc & 8 != 0 {
                ud!(!f.simd);
                (Dt::X8, opc & 7)
            } else if opc & 1 != 0 {
                ud!(!f.simd);
                (Dt::X16, opc >> 1 & 3)
            } else if opc & 2 == 0 {
                ud!(f.vfp.is_none() && !f.simd);
                (Dt::X32, opc >> 2 & 1)
            } else {
                return Err(());
            };
            let d = (bit(w, 7) << 4 | bits(w, 19, 16)) as u8;
            let i = FpInst::VmovToScalar { dt, d, index: index as u8, rt };
            let why = if low0 {
                Some("(0) bits 3:0 not zero (A8.8.342 VMOV (ARM core register to scalar))")
            } else if bad_t {
                Some("t == 15 || (CurrentInstrSet() != InstrSet_ARM && t == 13) (A8.8.342 VMOV (ARM core register to scalar))")
            } else {
                None
            };
            Ok((i, why))
        }
        (false, true, _) => {
            // A8.8.315 VDUP (ARM core register): B Q 0 Vd Rt 1011 D 0 E 1.
            ud!(bit(w, 6) != 0);
            ud!(!f.simd);
            let q = bit(w, 21) == 1;
            let d = (bit(w, 7) << 4 | bits(w, 19, 16)) as u8;
            ud!(q && d & 1 == 1);
            let dt = match bit(w, 22) << 1 | bit(w, 5) {
                0 => Dt::X32,
                1 => Dt::X16,
                2 => Dt::X8,
                _ => return Err(()),
            };
            let i = FpInst::VdupCore { dt, d: dq(q, d), rt };
            let why = if low0 {
                Some("(0) bits 3:0 not zero (A8.8.315 VDUP (ARM core register))")
            } else if bad_t {
                Some("t == 15 || (CurrentInstrSet() != InstrSet_ARM && t == 13) (A8.8.315 VDUP (ARM core register))")
            } else {
                None
            };
            Ok((i, why))
        }
        (true, true, _) => {
            // A8.8.343 VMOV (scalar to ARM core register): U:opc1:opc2
            // x1xxx byte, x0xx1 halfword, 00x00 word, 10x00 and x0x10
            // UNDEFINED.
            let u = bit(w, 23) == 1;
            let opc = bits(w, 22, 21) << 2 | bits(w, 6, 5);
            let (dt, index) = if opc & 8 != 0 {
                ud!(!f.simd);
                (Dt::su(u, 8), opc & 7)
            } else if opc & 1 != 0 {
                ud!(!f.simd);
                (Dt::su(u, 16), opc >> 1 & 3)
            } else if opc & 2 == 0 && !u {
                ud!(f.vfp.is_none() && !f.simd);
                (Dt::X32, opc >> 2 & 1)
            } else {
                return Err(());
            };
            let i = FpInst::VmovFromScalar { dt, rt, n: dn(w), index: index as u8 };
            let why = if low0 {
                Some("(0) bits 3:0 not zero (A8.8.343 VMOV (scalar to ARM core register))")
            } else if bad_t {
                Some("t == 15 || (CurrentInstrSet() != InstrSet_ARM && t == 13) (A8.8.343 VMOV (scalar to ARM core register))")
            } else {
                None
            };
            Ok((i, why))
        }
        _ => Err(()),
    }
}

// ---------------------------------------------------------------------------
// Register-file size (A2.6.1)
// ---------------------------------------------------------------------------

/// The highest doubleword register the instruction names, if any. `D[n]`
/// with `n >= 16` is UNDEFINED when `VFPSmallRegisterBank()`, which a core
/// without D32 always is (A2.6.1).
fn max_dreg(i: &FpInst) -> Option<u32> {
    fn top(r: VReg) -> Option<u32> {
        r.dregs().map(|(f, c)| f as u32 + c as u32 - 1)
    }
    let mx = |rs: &[Option<u32>]| rs.iter().flatten().copied().max();
    match *i {
        FpInst::Simd3 { d, n, m, .. } => mx(&[top(d), top(n), top(m)]),
        FpInst::Simd3Scalar { d, n, m, .. } => mx(&[top(d), top(n), Some(m as u32)]),
        FpInst::Simd2 { d, m, .. } | FpInst::SimdShift { d, m, .. } | FpInst::SimdCvt { d, m, .. } => mx(&[top(d), top(m)]),
        FpInst::SimdImm { d, .. } => top(d),
        FpInst::Vext { d, n, m, .. } => mx(&[top(d), top(n), top(m)]),
        FpInst::Vtbl { d, n, len, m, .. } => mx(&[Some(d as u32), Some(n as u32 + len as u32 - 1), Some(m as u32)]),
        FpInst::VdupScalar { d, m, .. } => mx(&[top(d), Some(m as u32)]),
        FpInst::VdupCore { d, .. } => top(d),
        FpInst::VmovToScalar { d, .. } => Some(d as u32),
        FpInst::VmovFromScalar { n, .. } => Some(n as u32),
        FpInst::VmovCoreD { m, .. } => Some(m as u32),
        FpInst::Vfp3 { d, n, m, .. } => mx(&[top(d), top(n), top(m)]),
        FpInst::Vfp2 { d, m, .. } => mx(&[top(d), top(m)]),
        FpInst::Vcmp { d, m, .. } => mx(&[top(d), m.and_then(top)]),
        FpInst::VmovImm { d, .. } | FpInst::VcvtFixed { d, .. } => top(d),
        FpInst::VcvtInt { d, m, .. } | FpInst::VcvtDs { d, m } => mx(&[top(d), top(m)]),
        // VLDM/VSTM's own decode rule covers D16-D31 (UNPREDICTABLE).
        FpInst::Vldm { .. } => None,
        FpInst::Vldr { d, .. } => top(d),
        FpInst::SimdLdSt { form, count, d, inc, regs, .. } => {
            let last = match (form, count) {
                (LdStForm::Multiple, 1) | (LdStForm::AllLanes, 1) => d as u32 + regs as u32 - 1,
                (LdStForm::Multiple, 2) => d as u32 + inc as u32 + regs as u32 - 1,
                _ => d as u32 + (count as u32 - 1) * inc as u32,
            };
            Some(last)
        }
        FpInst::VmovCoreS { .. } | FpInst::VmovCoreSS { .. } | FpInst::Vmrs { .. } | FpInst::Vmsr { .. } | FpInst::VcvtHalf { .. } => None,
    }
}

/// Wraps a decode: UNDEFINED, or the instruction with its UNPREDICTABLE
/// rule. An instruction naming D16-D31 on a core without them is
/// UNDEFINED (A2.6.1 `D[]`), unless its decode already made it
/// UNPREDICTABLE.
fn finish(r: Dec, f: &Features) -> (Op, Option<&'static str>) {
    match r {
        Err(()) => (Op::Undefined, None),
        Ok((i, why)) => {
            if why.is_none() && !f.d32 {
                if let Some(top) = max_dreg(&i) {
                    if top >= 16 {
                        return (Op::Undefined, None);
                    }
                }
            }
            (Op::Fp(i), why)
        }
    }
}

// ---------------------------------------------------------------------------
// LLVM's syntax
// ---------------------------------------------------------------------------

fn r(v: VReg) -> String {
    match v {
        VReg::S(n) => format!("s{}", n),
        VReg::D(n) => format!("d{}", n),
        VReg::Q(n) => format!("q{}", n),
    }
}

fn core(t: Reg) -> String {
    match t.0 {
        13 => "sp".to_string(),
        14 => "lr".to_string(),
        15 => "pc".to_string(),
        n => format!("r{}", n),
    }
}

fn with_dt(mn: &str, dt: Dt) -> String {
    if dt == Dt::None {
        mn.to_string()
    } else {
        format!("{}.{}", mn, dt.name())
    }
}

/// `printf("%e")` of a value.
fn fmt_e(v: f64) -> String {
    let s = format!("{:.6e}", v);
    let (mant, exp) = s.split_once('e').unwrap();
    let e: i32 = exp.parse().unwrap();
    format!("{}e{}{:02}", mant, if e < 0 { '-' } else { '+' }, e.abs())
}

fn simd3_name(op: Simd3Op) -> &'static str {
    use Simd3Op::*;
    match op {
        Vhadd => "vhadd",
        Vhsub => "vhsub",
        Vqadd => "vqadd",
        Vqsub => "vqsub",
        Vrhadd => "vrhadd",
        Vand => "vand",
        Vbic => "vbic",
        Vorr => "vorr",
        Vorn => "vorn",
        Veor => "veor",
        Vbsl => "vbsl",
        Vbit => "vbit",
        Vbif => "vbif",
        Vcgt => "vcgt",
        Vcge => "vcge",
        Vceq => "vceq",
        Vtst => "vtst",
        Vacge => "vacge",
        Vacgt => "vacgt",
        Vshl => "vshl",
        Vqshl => "vqshl",
        Vrshl => "vrshl",
        Vqrshl => "vqrshl",
        Vmax => "vmax",
        Vmin => "vmin",
        Vpmax => "vpmax",
        Vpmin => "vpmin",
        Vabd => "vabd",
        Vabdl => "vabdl",
        Vaba => "vaba",
        Vabal => "vabal",
        Vadd => "vadd",
        Vsub => "vsub",
        Vpadd => "vpadd",
        Vaddl => "vaddl",
        Vaddw => "vaddw",
        Vsubl => "vsubl",
        Vsubw => "vsubw",
        Vaddhn => "vaddhn",
        Vraddhn => "vraddhn",
        Vsubhn => "vsubhn",
        Vrsubhn => "vrsubhn",
        Vmla => "vmla",
        Vmls => "vmls",
        Vmlal => "vmlal",
        Vmlsl => "vmlsl",
        Vmul => "vmul",
        Vmull => "vmull",
        Vqdmulh => "vqdmulh",
        Vqrdmulh => "vqrdmulh",
        Vqdmlal => "vqdmlal",
        Vqdmlsl => "vqdmlsl",
        Vqdmull => "vqdmull",
        Vfma => "vfma",
        Vfms => "vfms",
        Vrecps => "vrecps",
        Vrsqrts => "vrsqrts",
    }
}

fn simd2_name(op: Simd2Op) -> &'static str {
    use Simd2Op::*;
    match op {
        Vrev16 => "vrev16",
        Vrev32 => "vrev32",
        Vrev64 => "vrev64",
        Vpaddl => "vpaddl",
        Vpadal => "vpadal",
        Vcls => "vcls",
        Vclz => "vclz",
        Vcnt => "vcnt",
        Vmvn => "vmvn",
        Vqabs => "vqabs",
        Vqneg => "vqneg",
        Vcgt0 => "vcgt",
        Vcge0 => "vcge",
        Vceq0 => "vceq",
        Vcle0 => "vcle",
        Vclt0 => "vclt",
        Vabs => "vabs",
        Vneg => "vneg",
        Vswp => "vswp",
        Vtrn => "vtrn",
        Vuzp => "vuzp",
        Vzip => "vzip",
        Vmovn => "vmovn",
        Vqmovn => "vqmovn",
        Vqmovun => "vqmovun",
        Vrecpe => "vrecpe",
        Vrsqrte => "vrsqrte",
        // LLVM prints VMOV (register) as the VORR it is encoded as.
        Vmov => "vorr",
        Vmovl => "vmovl",
    }
}

fn shift_name(op: ShiftOp) -> &'static str {
    use ShiftOp::*;
    match op {
        Vshr => "vshr",
        Vsra => "vsra",
        Vrshr => "vrshr",
        Vrsra => "vrsra",
        Vsri => "vsri",
        Vshl => "vshl",
        Vsli => "vsli",
        Vqshl => "vqshl",
        Vqshlu => "vqshlu",
        Vshrn => "vshrn",
        Vrshrn => "vrshrn",
        Vqshrn => "vqshrn",
        Vqshrun => "vqshrun",
        Vqrshrn => "vqrshrn",
        Vqrshrun => "vqrshrun",
        Vshll => "vshll",
    }
}

fn vfp3_name(op: Vfp3Op) -> &'static str {
    use Vfp3Op::*;
    match op {
        Vmla => "vmla",
        Vmls => "vmls",
        Vnmla => "vnmla",
        Vnmls => "vnmls",
        Vnmul => "vnmul",
        Vmul => "vmul",
        Vadd => "vadd",
        Vsub => "vsub",
        Vdiv => "vdiv",
        Vfma => "vfma",
        Vfms => "vfms",
        Vfnma => "vfnma",
        Vfnms => "vfnms",
    }
}

fn reglist(first: u32, count: u32, step: u32, suffix: &str) -> String {
    let v: Vec<String> = (0..count).map(|k| format!("d{}{}", first + k * step, suffix)).collect();
    format!("{{{}}}", v.join(", "))
}

/// The element value of an Advanced SIMD modified immediate, as LLVM shows
/// it.
fn simd_imm_text(dt: Dt, imm: u64) -> String {
    match dt {
        Dt::I8 => format!("#0x{:x}", imm & 0xff),
        Dt::I16 => format!("#0x{:x}", imm & 0xffff),
        Dt::I32 => format!("#0x{:x}", imm & 0xffff_ffff),
        Dt::I64 => format!("#0x{:x}", imm),
        _ => format!("#{}", fmt_e(f32::from_bits(imm as u32) as f64)),
    }
}

fn spec_reg(reg: u8) -> String {
    match reg {
        0 => "fpsid".to_string(),
        1 => "fpscr".to_string(),
        5 => "mvfr2".to_string(),
        6 => "mvfr1".to_string(),
        7 => "mvfr0".to_string(),
        8 => "fpexc".to_string(),
        9 => "fpinst".to_string(),
        10 => "fpinst2".to_string(),
        n => format!("<reg {}>", n),
    }
}

/// LLVM's spelling of the instruction (`llvm-mc --disassemble`, without
/// the condition), for the differential tests.
pub fn fmt(i: &FpInst) -> String {
    match *i {
        FpInst::Simd3 { op, dt, d, n, m } => {
            let mn = with_dt(simd3_name(op), dt);
            match op {
                // The shift operand (Vn) last: VSHL{<c>}.<dt> <Dd>, <Dm>, <Dn>.
                Simd3Op::Vshl | Simd3Op::Vqshl | Simd3Op::Vrshl | Simd3Op::Vqrshl => {
                    format!("{} {}, {}, {}", mn, r(d), r(m), r(n))
                }
                _ => format!("{} {}, {}, {}", mn, r(d), r(n), r(m)),
            }
        }
        FpInst::Simd3Scalar { op, dt, d, n, m, index } => {
            format!("{} {}, {}, d{}[{}]", with_dt(simd3_name(op), dt), r(d), r(n), m, index)
        }
        FpInst::Simd2 { op, dt, d, m } => {
            let mn = with_dt(simd2_name(op), dt);
            match op {
                Simd2Op::Vmov => format!("{} {}, {}, {}", mn, r(d), r(m), r(m)),
                Simd2Op::Vcgt0 | Simd2Op::Vcge0 | Simd2Op::Vceq0 | Simd2Op::Vcle0 | Simd2Op::Vclt0 => {
                    format!("{} {}, {}, #0", mn, r(d), r(m))
                }
                _ => format!("{} {}, {}", mn, r(d), r(m)),
            }
        }
        FpInst::SimdShift { op, dt, d, m, shift } => {
            format!("{} {}, {}, #{}", with_dt(shift_name(op), dt), r(d), r(m), shift)
        }
        FpInst::SimdCvt { to, from, d, m, fbits } => {
            if fbits != 0 {
                format!("vcvt.{}.{} {}, {}, #{}", to.name(), from.name(), r(d), r(m), fbits)
            } else {
                format!("vcvt.{}.{} {}, {}", to.name(), from.name(), r(d), r(m))
            }
        }
        FpInst::SimdImm { op, dt, d, imm } => {
            let mn = match op {
                ImmOp::Vmov => "vmov",
                ImmOp::Vorr => "vorr",
                ImmOp::Vmvn => "vmvn",
                ImmOp::Vbic => "vbic",
            };
            format!("{} {}, {}", with_dt(mn, dt), r(d), simd_imm_text(dt, imm))
        }
        FpInst::Vext { d, n, m, imm } => {
            // LLVM shows the widest element size the byte offset is a
            // multiple of (64-bit only for quadwords), the pseudo-instruction
            // forms of A8.8.317.
            let q = matches!(d, VReg::Q(_));
            let (sz, i) = if q && imm & 7 == 0 {
                (64, imm / 8)
            } else if imm & 3 == 0 {
                (32, imm / 4)
            } else if imm & 1 == 0 {
                (16, imm / 2)
            } else {
                (8, imm)
            };
            format!("vext.{} {}, {}, {}, #{}", sz, r(d), r(n), r(m), i)
        }
        FpInst::Vtbl { tbx, d, n, len, m } => {
            format!("{}.8 d{}, {}, d{}", if tbx { "vtbx" } else { "vtbl" }, d, reglist(n as u32, len as u32, 1, ""), m)
        }
        FpInst::VdupScalar { dt, d, m, index } => format!("vdup.{} {}, d{}[{}]", dt.name(), r(d), m, index),
        FpInst::VdupCore { dt, d, rt } => format!("vdup.{} {}, {}", dt.name(), r(d), core(rt)),
        FpInst::VmovToScalar { dt, d, index, rt } => format!("vmov.{} d{}[{}], {}", dt.name(), d, index, core(rt)),
        FpInst::VmovFromScalar { dt, rt, n, index } => format!("vmov.{} {}, d{}[{}]", dt.name(), core(rt), n, index),
        FpInst::VmovCoreS { to_core, rt, n } => {
            if to_core {
                format!("vmov {}, s{}", core(rt), n)
            } else {
                format!("vmov s{}, {}", n, core(rt))
            }
        }
        FpInst::VmovCoreSS { to_core, rt, rt2, m } => {
            if to_core {
                format!("vmov {}, {}, s{}, s{}", core(rt), core(rt2), m, m + 1)
            } else {
                format!("vmov s{}, s{}, {}, {}", m, m + 1, core(rt), core(rt2))
            }
        }
        FpInst::VmovCoreD { to_core, rt, rt2, m } => {
            if to_core {
                format!("vmov {}, {}, d{}", core(rt), core(rt2), m)
            } else {
                format!("vmov d{}, {}, {}", m, core(rt), core(rt2))
            }
        }
        FpInst::Vmrs { rt, reg } => {
            let t = if rt.is_pc() && reg == 1 { "APSR_nzcv".to_string() } else { core(rt) };
            format!("vmrs {}, {}", t, spec_reg(reg))
        }
        FpInst::Vmsr { reg, rt } => format!("vmsr {}, {}", spec_reg(reg), core(rt)),
        FpInst::Vfp3 { op, dp, d, n, m } => {
            format!("{}.{} {}, {}, {}", vfp3_name(op), if dp { "f64" } else { "f32" }, r(d), r(n), r(m))
        }
        FpInst::Vfp2 { op, dp, d, m } => {
            let mn = match op {
                Vfp2Op::Vmov => "vmov",
                Vfp2Op::Vabs => "vabs",
                Vfp2Op::Vneg => "vneg",
                Vfp2Op::Vsqrt => "vsqrt",
            };
            format!("{}.{} {}, {}", mn, if dp { "f64" } else { "f32" }, r(d), r(m))
        }
        FpInst::Vcmp { e, dp, d, m } => {
            let mn = if e { "vcmpe" } else { "vcmp" };
            let rhs = match m {
                Some(m) => r(m),
                None => "#0".to_string(),
            };
            format!("{}.{} {}, {}", mn, if dp { "f64" } else { "f32" }, r(d), rhs)
        }
        FpInst::VmovImm { dp, d, imm } => {
            let v = if dp { f64::from_bits(imm) } else { f32::from_bits(imm as u32) as f64 };
            format!("vmov.{} {}, #{}", if dp { "f64" } else { "f32" }, r(d), fmt_e(v))
        }
        FpInst::VcvtInt { to, from, d, m, round_zero } => {
            let mn = if to.is_float() || round_zero { "vcvt" } else { "vcvtr" };
            format!("{}.{}.{} {}, {}", mn, to.name(), from.name(), r(d), r(m))
        }
        FpInst::VcvtFixed { to, from, d, fbits } => {
            format!("vcvt.{}.{} {}, {}, #{}", to.name(), from.name(), r(d), r(d), fbits)
        }
        FpInst::VcvtDs { d, m } => match d {
            VReg::D(_) => format!("vcvt.f64.f32 {}, {}", r(d), r(m)),
            _ => format!("vcvt.f32.f64 {}, {}", r(d), r(m)),
        },
        FpInst::VcvtHalf { to_half, top, d, m } => {
            let mn = if top { "vcvtt" } else { "vcvtb" };
            let (a, b) = if to_half { ("f16", "f32") } else { ("f32", "f16") };
            format!("{}.{}.{} s{}, s{}", mn, a, b, d, m)
        }
        FpInst::Vldm { load, d, regs, rn, add, wback, fmx } => {
            let (first, pre) = match d {
                VReg::S(n) => (n as u32, "s"),
                VReg::D(n) => (n as u32, "d"),
                VReg::Q(n) => (2 * n as u32, "d"),
            };
            // An UNPREDICTABLE list running past register 31 is cut there,
            // as LLVM shows it.
            let list: Vec<String> = (first..(first + regs as u32).min(32)).map(|k| format!("{}{}", pre, k)).collect();
            let list = format!("{{{}}}", list.join(", "));
            if rn.is_sp() && wback && load == add && !fmx {
                return format!("{} {}", if load { "vpop" } else { "vpush" }, list);
            }
            let mode = if add { "ia" } else { "db" };
            let mn = if fmx {
                format!("{}{}x", if load { "fldm" } else { "fstm" }, mode)
            } else {
                format!("{}{}", if load { "vldm" } else { "vstm" }, mode)
            };
            format!("{} {}{}, {}", mn, core(rn), if wback { "!" } else { "" }, list)
        }
        FpInst::Vldr { load, d, rn, add, imm } => {
            let mn = if load { "vldr" } else { "vstr" };
            if add && imm == 0 {
                format!("{} {}, [{}]", mn, r(d), core(rn))
            } else {
                format!("{} {}, [{}, #{}{}]", mn, r(d), core(rn), if add { "" } else { "-" }, imm)
            }
        }
        FpInst::SimdLdSt { load, form, count, esize, d, inc, regs, index, align, rn, wback, rm } => {
            let mn = format!("{}{}.{}", if load { "vld" } else { "vst" }, count, esize);
            let d = d as u32;
            let list = match form {
                LdStForm::Multiple => match count {
                    1 => reglist(d, regs as u32, 1, ""),
                    2 if regs == 2 => reglist(d, 4, 1, ""),
                    _ => reglist(d, count as u32, inc as u32, ""),
                },
                LdStForm::Lane => reglist(d, count as u32, inc as u32, &format!("[{}]", index)),
                LdStForm::AllLanes => {
                    if count == 1 {
                        reglist(d, regs as u32, 1, "[]")
                    } else {
                        reglist(d, count as u32, inc as u32, "[]")
                    }
                }
            };
            let al = if align > 1 { format!(":{}", align as u32 * 8) } else { String::new() };
            let addr = format!("[{}{}]", core(rn), al);
            match (wback, rm) {
                (false, _) => format!("{} {}, {}", mn, list, addr),
                (true, None) => format!("{} {}, {}!", mn, list, addr),
                (true, Some(rm)) => format!("{} {}, {}, {}", mn, list, addr, core(rm)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Features;

    fn dec(w: u32) -> (Op, Option<&'static str>) {
        let f = Features::ALL;
        match w >> 24 {
            0xf2 | 0xf3 => decode_simd_dp(w, &f),
            0xf4 => decode_simd_ldst(w, &f),
            _ => decode_cp(w, &f),
        }
    }

    fn text(w: u32) -> String {
        match dec(w) {
            (Op::Fp(i), _) => fmt(&i),
            (Op::Undefined, _) => "UNDEFINED".to_string(),
            _ => unreachable!(),
        }
    }

    #[test]
    fn three_same() {
        assert_eq!(text(0xf2000d02), "vadd.f32 d0, d0, d2");
        assert_eq!(text(0xf3010d02), "vpadd.f32 d0, d1, d2");
        assert_eq!(text(0xf2100402), "vshl.s16 d0, d2, d0");
        assert_eq!(text(0xf2210112), "vorr d0, d1, d2");
        assert_eq!(text(0xf3100111), "vbsl d0, d0, d1");
        // VADD.F32 with Q set and an odd Vn.
        assert_eq!(text(0xf2010d42), "UNDEFINED");
        // VORR with Vn == Vm is VMOV (register).
        assert!(matches!(dec(0xf2210111).0, Op::Fp(FpInst::Simd2 { op: Simd2Op::Vmov, d: VReg::D(0), m: VReg::D(1), .. })));
    }

    #[test]
    fn modified_immediates() {
        assert_eq!(text(0xf2800010), "vmov.i32 d0, #0x0");
        assert_eq!(text(0xf3800f50), "vmov.f32 q0, #-2.000000e+00");
        assert_eq!(text(0xf3800e30), "vmov.i64 d0, #0xff00000000000000");
        // cmode 1100 with imm8 0: testimm8.
        assert!(dec(0xf2800c10).1.is_some());
        // op 1, cmode 1111.
        assert_eq!(text(0xf2800f30), "UNDEFINED");
        assert_eq!(adv_simd_expand_imm(false, 0b1111, 0x70).unwrap().0, 0x3f80_0000_3f80_0000);
    }

    #[test]
    fn others() {
        assert_eq!(text(0xf2c00000), "vaddl.s8 q8, d0, d0");
        assert_eq!(text(0xf2b10300), "vext.8 d0, d1, d0, #3");
        assert_eq!(text(0xf3b40c00), "vdup.32 d0, d0[0]");
        assert_eq!(text(0xf3f00840), "vtbx.8 d16, {d0}, d0");
        assert_eq!(text(0xf3b20200), "vmovn.i16 d0, q0");
        assert_eq!(text(0xf3b60600), "vcvt.f16.f32 d0, q0");
        assert_eq!(text(0xf2880a10), "vmovl.s8 q0, d0");
        assert_eq!(text(0xf3b20300), "vshll.i8 q0, d0, #8");
        assert_eq!(text(0xf3fb0640), "vcvt.f32.s32 q8, q0");
        assert_eq!(text(0xf3b60400), "UNDEFINED");
    }

    #[test]
    fn vfp() {
        assert_eq!(text(0xeef10a10), "vmrs r0, fpscr");
        assert_eq!(text(0xeef1fa10), "vmrs APSR_nzcv, fpscr");
        assert_eq!(vfp_expand_imm(0x70, false), 0x3f80_0000);
        assert_eq!(vfp_expand_imm(0x70, true), 0x3ff0_0000_0000_0000);
    }

    #[test]
    fn d16() {
        let mut f = Features::ALL;
        f.d32 = false;
        f.simd = false;
        // VADD.F64 d16, d0, d0.
        assert!(matches!(decode_cp(0xee700b00, &f).0, Op::Undefined));
        assert!(matches!(decode_cp(0xee300b00, &f).0, Op::Fp(_)));
        // No VFP at all.
        assert!(matches!(decode_cp(0xee300b00, &Features::BASE).0, Op::Undefined));
        // VLDR d16: D[16] is UNDEFINED; VLDM reaching d16 is the decode's
        // VFPSmallRegisterBank() UNPREDICTABLE.
        assert!(matches!(decode_cp(0xedd00b00, &f).0, Op::Undefined));
        let (op, why) = decode_cp(0xec90fb04, &f);
        assert!(matches!(op, Op::Fp(FpInst::Vldm { regs: 2, .. })));
        assert!(why.unwrap().starts_with("VFPSmallRegisterBank()"));
        // VMOV.32 d16[0], r0.
        assert!(matches!(decode_cp(0xee000b90, &f).0, Op::Undefined));
        assert!(matches!(decode_cp(0xee000b90, &Features::ALL).0, Op::Fp(_)));
    }

    /// One hand-built encoding per family, each confirmed with LLVM.
    #[test]
    fn families() {
        let cases: &[(u32, &str)] = &[
            // A7.4.1 three registers of the same length.
            (0xf2010802, "vadd.i8 d0, d1, d2"),
            (0xf2120b44, "vqdmulh.s16 q0, q1, q2"),
            (0xf2010c12, "vfma.f32 d0, d1, d2"),
            // A7.4.2 three registers of different lengths.
            (0xf2810002, "vaddl.s8 q0, d1, d2"),
            (0xf2820404, "vaddhn.i16 d0, q1, q2"),
            (0xf2810e02, "vmull.p8 q0, d1, d2"),
            // A7.4.3 two registers and a scalar: index M:Vm<3>.
            (0xf291004a, "vmla.i16 d0, d1, d2[1]"),
            // A7.4.4 shifts: 16 - imm6, narrow, fixed-point VCVT.
            (0xf28d0011, "vshr.s8 d0, d1, #3"),
            (0xf28d0812, "vshrn.i16 d0, q1, #3"),
            (0xf2b00f11, "vcvt.s32.f32 d0, d1, #16"),
            // A7.4.6 modified immediate.
            (0xf2810010, "vmov.i32 d0, #0x10"),
            // A7.4.5 two registers, miscellaneous.
            (0xf3b00001, "vrev64.8 d0, d1"),
            (0xf3b00501, "vcnt.8 d0, d1"),
            (0xf3b10201, "vclt.s8 d0, d1, #0"),
            (0xf3b60701, "vcvt.f32.f16 q0, d1"),
            (0xf3bb0401, "vrecpe.u32 d0, d1"),
            (0xf3bb0701, "vcvt.s32.f32 d0, d1"),
            (0xf3b20001, "vswp d0, d1"),
            (0xf3b60182, "vzip.16 d0, d2"),
            // VEXT, VTBL, VDUP (scalar).
            (0xf2b10302, "vext.8 d0, d1, d2, #3"),
            (0xf3b10802, "vtbl.8 d0, {d1}, d2"),
            (0xf3b40c01, "vdup.32 d0, d1[0]"),
            // A7.7 element and structure load/store.
            (0xf4200a2d, "vld1.8 {d0, d1}, [r0:128]!"),
            (0xf4a0076f, "vld4.16 {d0[1], d2[1], d4[1], d6[1]}, [r0]"),
            (0xf4a00d4f, "vld2.16 {d0[], d1[]}, [r0]"),
            (0xf4800b0f, "vst4.32 {d0[0], d1[0], d2[0], d3[0]}, [r0]"),
            (0xf4000702, "vst1.8 {d0}, [r0], r2"),
            // A7.5 Floating-point data processing.
            (0xee300a81, "vadd.f32 s0, s1, s2"),
            (0xee000b40, "vmls.f64 d0, d0, d0"),
            (0xee100b40, "vnmla.f64 d0, d0, d0"),
            (0xeea00b40, "vfms.f64 d0, d0, d0"),
            (0xee900b40, "vfnma.f64 d0, d0, d0"),
            (0xeeb10bc0, "vsqrt.f64 d0, d0"),
            (0xeeb80bc0, "vcvt.f64.s32 d0, s0"),
            (0xeebd0ac0, "vcvt.s32.f32 s0, s0"),
            (0xeebd0a40, "vcvtr.s32.f32 s0, s0"),
            (0xeeba0a46, "vcvt.f32.s16 s0, s0, #4"),
            (0xeeb70ac0, "vcvt.f64.f32 d0, s0"),
            (0xeeb20a60, "vcvtb.f32.f16 s0, s1"),
            (0xeeb50a40, "vcmp.f32 s0, #0"),
            (0xeeb00a00, "vmov.f32 s0, #2.000000e+00"),
            // A7.6 extension register load/store.
            (0xed100b01, "vldr d0, [r0, #-4]"),
            (0xed2d8b04, "vpush {d8, d9}"),
            (0xecbd8b04, "vpop {d8, d9}"),
            (0xec800b05, "fstmiax r0, {d0, d1}"),
            // A7.8 8, 16 and 32-bit transfers.
            (0xee100a10, "vmov r0, s0"),
            (0xee000b10, "vmov.32 d0[0], r0"),
            (0xee900b30, "vmov.u16 r0, d0[0]"),
            (0xeea00b10, "vdup.32 q0, r0"),
            (0xeef1fa10, "vmrs APSR_nzcv, fpscr"),
            // A7.9 64-bit transfers.
            (0xec510b15, "vmov r0, r1, d5"),
            (0xec410a30, "vmov s1, s2, r0, r1"),
        ];
        for &(w, t) in cases {
            assert_eq!(text(w), t, "{:08x}", w);
            assert!(dec(w).1.is_none(), "{:08x}", w);
        }
    }

    #[test]
    fn fields() {
        // VMOV.I64: each imm8 bit (0x13) becomes a byte.
        assert!(matches!(
            dec(0xf2810e33).0,
            Op::Fp(FpInst::SimdImm { op: ImmOp::Vmov, dt: Dt::I64, imm: 0xff_0000_ffff, .. })
        ));
        // VQSHLU.S8 (U 1, op 0): left shift imm6 - 8.
        assert!(matches!(dec(0xf38b0611).0, Op::Fp(FpInst::SimdShift { op: ShiftOp::Vqshlu, dt: Dt::S8, shift: 3, .. })));
        // VSHLL with shift 0 is VMOVL.
        assert!(matches!(dec(0xf2880a11).0, Op::Fp(FpInst::Simd2 { op: Simd2Op::Vmovl, dt: Dt::S8, .. })));
        // VLD4 (all lanes) size 11: 32-bit elements, 16-byte alignment.
        assert!(matches!(
            dec(0xf4a00fdf).0,
            Op::Fp(FpInst::SimdLdSt { form: LdStForm::AllLanes, count: 4, esize: 32, align: 16, wback: false, rm: None, .. })
        ));
        // VST1 with Rm = r2: register post-increment.
        assert!(matches!(dec(0xf4000702).0, Op::Fp(FpInst::SimdLdSt { wback: true, rm: Some(Reg(2)), .. })));
        // FSTMIAX: odd imm8.
        assert!(matches!(dec(0xec800b05).0, Op::Fp(FpInst::Vldm { regs: 2, fmx: true, .. })));
        // VCVT (fixed-point) with frac_bits < 0.
        let (op, why) = dec(0xeeba0a6f);
        assert!(matches!(op, Op::Fp(FpInst::VcvtFixed { fbits: -15, .. })));
        assert!(why.is_some());
    }

    #[test]
    fn undefined_and_unpredictable() {
        // VQDMULH size 00; VPADD.F32 with Q; VMUL.P16; VCVT (fixed) imm6
        // 0xxxxx; VUZP.32 on doublewords; VREV16.16; VST1 to all lanes.
        for w in [0xf2020b04u32, 0xf3000d40, 0xf3110910, 0xf29f0f11, 0xf3ba0100, 0xf3b40100, 0xf4800c0f] {
            assert_eq!(text(w), "UNDEFINED", "{:08x}", w);
        }
        // VLD1 with a PC base.
        assert!(dec(0xf42f070f).1.is_some());
        // VMOV r0, r0, d0: t == t2 for a transfer to the core.
        assert!(dec(0xec500b10).1.is_some());
        // VMRS PC (not APSR_nzcv) from FPEXC.
        assert!(dec(0xeef8fa10).1.is_some());
        // VDUP (ARM core register) with a (0) bit set.
        assert!(dec(0xeea00b11).1.is_some());
    }

    #[test]
    fn features() {
        let v3 = Features { vfp: Some(crate::VfpVersion::V3), fp16: false, ..Features::ALL };
        // VFMA (both forms) needs VFPv4 / Advanced SIMDv2; VCVTB and the
        // Advanced SIMD half-precision VCVT the Half-precision Extension.
        assert!(matches!(decode_simd_dp(0xf2010c12, &v3).0, Op::Undefined));
        assert!(matches!(decode_cp(0xeea00b00, &v3).0, Op::Undefined));
        assert!(matches!(decode_cp(0xeeb20a60, &v3).0, Op::Undefined));
        assert!(matches!(decode_simd_dp(0xf3b60701, &v3).0, Op::Undefined));
        let v3hp = Features { fp16: true, ..v3 };
        assert!(matches!(decode_cp(0xeeb20a60, &v3hp).0, Op::Fp(_)));
        assert!(matches!(decode_simd_dp(0xf3b60701, &v3hp).0, Op::Fp(_)));

        // VFP without Advanced SIMD: the byte/halfword scalar moves and VDUP
        // are UNDEFINED, the word forms are not.
        let vfp_only = Features { simd: false, ..Features::ALL };
        assert!(matches!(decode_simd_dp(0xf2010802, &vfp_only).0, Op::Undefined));
        assert!(matches!(decode_simd_ldst(0xf4200a2d, &vfp_only).0, Op::Undefined));
        assert!(matches!(decode_cp(0xee900b30, &vfp_only).0, Op::Undefined));
        assert!(matches!(decode_cp(0xeea00b10, &vfp_only).0, Op::Undefined));
        assert!(matches!(decode_cp(0xee000b10, &vfp_only).0, Op::Fp(_)));

        // Advanced SIMD without VFP: doubleword loads/stores and transfers
        // remain; single-precision ones and data processing do not.
        let simd_only = Features { vfp: None, ..Features::ALL };
        assert!(matches!(decode_cp(0xed100b01, &simd_only).0, Op::Fp(_)));
        assert!(matches!(decode_cp(0xed100a01, &simd_only).0, Op::Undefined));
        assert!(matches!(decode_cp(0xec510b15, &simd_only).0, Op::Fp(_)));
        assert!(matches!(decode_cp(0xec410a30, &simd_only).0, Op::Undefined));
        assert!(matches!(decode_cp(0xee100a10, &simd_only).0, Op::Undefined));
        assert!(matches!(decode_cp(0xeef1fa10, &simd_only).0, Op::Fp(_)));
        assert!(matches!(decode_cp(0xee300a81, &simd_only).0, Op::Undefined));
    }

    #[test]
    fn thumb_rules() {
        let f = Features::ALL;
        // VMOV s0, sp: fine in ARM, UNPREDICTABLE in Thumb.
        assert!(decode_cp_in(0xee00da10, &f, InstrSet::Arm).1.is_none());
        assert!(decode_cp_in(0xee00da10, &f, InstrSet::Thumb).1.is_some());
        // VSTR with a PC base.
        assert!(decode_cp_in(0xed0f0b01, &f, InstrSet::Arm).1.is_none());
        assert!(decode_cp_in(0xed0f0b01, &f, InstrSet::Thumb).1.is_some());
        // VLDM with a PC base, no writeback.
        assert!(decode_cp_in(0xec9f0b04, &f, InstrSet::Arm).1.is_none());
        assert!(decode_cp_in(0xec9f0b04, &f, InstrSet::Thumb).1.is_some());
    }
}
