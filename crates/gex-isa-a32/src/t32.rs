//! The Thumb (T32) instruction set's decoding (chapter A6): the 16-bit
//! encodings (A6.2) and the 32-bit ones (A6.3), each table followed in
//! order down to the A8/B9 encoding diagrams and their decode pseudocode.
//!
//! Conditions that depend on the run-time state (the mode, the Security
//! state, ThumbEE state, SCR/HCR/NSACR) are left to the lifter; each place
//! one applies says so.

use crate::*;

/// The decoder's state: the IT state the instruction executes in and the
/// first UNPREDICTABLE rule the encoding hits.
struct D<'a> {
    it: ItState,
    f: &'a Features,
    unp: Option<&'static str>,
    /// An instruction whose syntax has no `<c>` (CBZ, CPS, SETEND, HVC,
    /// ENTERX/LEAVEX, MOVS T2): unconditional, AL. Inside an IT block each
    /// is UNPREDICTABLE.
    uncond: bool,
}

impl D<'_> {
    /// Records `why` when `c` holds (the first rule hit is kept).
    fn unp(&mut self, c: bool, why: &'static str) {
        if c && self.unp.is_none() {
            self.unp = Some(why);
        }
    }
    /// Bits shown as `(0)` under `mask` (A6.1.1).
    fn zeros(&mut self, v: u32, mask: u32) {
        self.unp(v & mask != 0, "a (0) bit is 1 (A6.1.1)");
    }
    /// Bits shown as `(1)` under `mask` (A6.1.1).
    fn ones(&mut self, v: u32, mask: u32) {
        self.unp(v & mask != mask, "a (1) bit is 0 (A6.1.1)");
    }
    /// `if InITBlock() then UNPREDICTABLE`.
    fn not_in_it(&mut self, why: &'static str) {
        self.unp(self.it.in_it(), why);
    }
    /// `if c && InITBlock() && !LastInITBlock() then UNPREDICTABLE`: a
    /// branch or PC write that is not the last instruction of its block.
    fn last_in_it(&mut self, c: bool, why: &'static str) {
        self.unp(c && self.it.in_it() && !self.it.last_in_it(), why);
    }
}

#[inline]
fn r(x: u32) -> Reg {
    Reg::of(x)
}

/// `x IN {13,15}` (`BadReg`).
#[inline]
fn bad(x: u32) -> bool {
    x == 13 || x == 15
}

/// Sign-extends the low `n` bits of `v`.
#[inline]
fn sext(v: u32, n: u32) -> i32 {
    ((v << (32 - n)) as i32) >> (32 - n)
}

/// An offset of `imm` added (`add`) or subtracted.
#[inline]
fn signed(imm: u32, add: bool) -> i32 {
    if add {
        imm as i32
    } else {
        -(imm as i32)
    }
}

fn reg(rm: u32) -> Operand {
    Operand::RegImm { rm: r(rm), shift: Shift::Lsl, amount: 0 }
}

fn imm(value: u32) -> Operand {
    Operand::Imm { value, carry: None }
}

/// The operand fields the data-processing operations leave unused (`rn`
/// of MOV/MVN, `rd` of the tests) hold R0.
const UNUSED: Reg = Reg(0);

fn dp(op: DpOp, s: bool, rd: u32, rn: u32, src: Operand) -> Op {
    Op::Dp { op, s, rd: r(rd), rn: r(rn), src }
}

fn test(op: DpOp, rn: u32, src: Operand) -> Op {
    Op::Dp { op, s: true, rd: UNUSED, rn: r(rn), src }
}

fn mov(s: bool, rd: u32, src: Operand) -> Op {
    Op::Dp { op: DpOp::Mov, s, rd: r(rd), rn: UNUSED, src }
}

#[allow(clippy::too_many_arguments)]
fn ldst(load: bool, size: Size, signed: bool, user: bool, rt: u32, rn: u32, offset: Offset, index: bool, wback: bool) -> Op {
    Op::Ldst { load, size, signed, user, rt: r(rt), rn: r(rn), offset, index, wback }
}

fn roff(rm: u32, amount: u32) -> Offset {
    Offset::Reg { rm: r(rm), shift: Shift::Lsl, amount: amount as u8, add: true }
}

/// `ThumbExpandImm_C(imm12, -)` (A6.3.2): the constant, the carry it
/// produces (`None`: the carry flag unchanged), and whether the encoding is
/// UNPREDICTABLE (a replicated pattern of a zero byte).
pub fn thumb_expand_imm(imm12: u32) -> (u32, Option<bool>, bool) {
    let imm12 = imm12 & 0xfff;
    if imm12 >> 10 == 0 {
        let b = imm12 & 0xff;
        match (imm12 >> 8) & 3 {
            0 => (b, None, false),
            1 => (b << 16 | b, None, b == 0),
            2 => (b << 24 | b << 8, None, b == 0),
            _ => (b.wrapping_mul(0x0101_0101), None, b == 0),
        }
    } else {
        let v = (0x80 | (imm12 & 0x7f)).rotate_right(imm12 >> 7);
        (v, Some(v >> 31 == 1), false)
    }
}

/// `BadMode()` (B1.3.1): whether a mode number is not one the core has.
fn bad_mode(mode: u32, f: &Features) -> bool {
    match mode {
        0b10000 | 0b10001 | 0b10010 | 0b10011 | 0b10111 | 0b11011 | 0b11111 => false,
        0b10110 => !f.security,
        0b11010 => !f.virtualization,
        _ => true,
    }
}

/// Decode the Thumb instruction starting with `hw1` (`hw2` the next
/// halfword, ignored for a 16-bit instruction) in IT state `it`.
pub fn decode(hw1: u16, hw2: u16, it: ItState, f: &Features) -> Inst {
    let mut d = D { it, f, unp: None, uncond: false };
    let (len, raw, (op, own)) = if thumb_is_32(hw1) {
        let raw = (hw1 as u32) << 16 | hw2 as u32;
        (4, raw, d32(&mut d, hw1 as u32, hw2 as u32))
    } else {
        (2, hw1 as u32, d16(&mut d, hw1 as u32))
    };
    let own = if d.uncond { Some(Cond::AL) } else { own };
    let cond = match own {
        Some(c) => c,
        None => {
            // A8.3.1 CurrentCond(): ITSTATE<3:0> zero with ITSTATE<7:4>
            // nonzero is a reserved state.
            d.unp(!it.in_it() && it.0 != 0, "CurrentCond() with ITSTATE<3:0> zero and ITSTATE<7:4> nonzero (A8.3.1)");
            if it.in_it() {
                it.cond()
            } else {
                Cond::AL
            }
        }
    };
    Inst { op, cond, len, raw, set: InstrSet::Thumb, unpredictable: d.unp }
}

// ===========================================================================
// 16-bit encodings (A6.2)
// ===========================================================================

/// A decoded operation and, for B<c> T1/T3, BKPT and IT, the condition it
/// executes under in place of ITSTATE's.
type Dec = (Op, Option<Cond>);

fn d16(d: &mut D, h: u32) -> Dec {
    let op = match h >> 10 {
        0b000000..=0b001111 => shift_add_sub_mov_cmp(d, h),
        0b010000 => dp16(d, h),
        0b010001 => special16(d, h),
        // A8.8.65 LDR (literal) T1.
        0b010010 | 0b010011 => {
            ldst(true, Size::W, false, false, (h >> 8) & 7, 15, Offset::Imm(((h & 0xff) << 2) as i32), true, false)
        }
        0b010100..=0b100111 => ldst16(h),
        // A8.8.12 ADR T1.
        0b101000 | 0b101001 => Op::Adr { rd: r((h >> 8) & 7), imm: ((h & 0xff) << 2) as i32 },
        // A8.8.9 ADD (SP plus immediate) T1.
        0b101010 | 0b101011 => dp(DpOp::Add, false, (h >> 8) & 7, 13, imm((h & 0xff) << 2)),
        0b101100..=0b101111 => return misc16(d, h),
        // A8.8.200 STM (STMIA, STMEA) T1. In ThumbEE state this space holds
        // the ThumbEE instructions (A9.2); this is Thumb state.
        0b110000 | 0b110001 => {
            let regs = h & 0xff;
            d.unp(regs == 0, "A8.8.200: BitCount(registers) < 1");
            Op::Ldm { load: false, mode: Amode::Ia, rn: r((h >> 8) & 7), regs: regs as u16, wback: true, user: false }
        }
        // A8.8.58 LDM/LDMIA/LDMFD (Thumb) T1.
        0b110010 | 0b110011 => {
            let n = (h >> 8) & 7;
            let regs = h & 0xff;
            d.unp(regs == 0, "A8.8.58: BitCount(registers) < 1");
            Op::Ldm { load: true, mode: Amode::Ia, rn: r(n), regs: regs as u16, wback: regs >> n & 1 == 0, user: false }
        }
        0b110100..=0b110111 => return branch16(d, h),
        // A8.8.18 B T2.
        0b111000 | 0b111001 => {
            d.last_in_it(true, "A8.8.18: B (T2) inside an IT block but not last");
            Op::B { imm: sext((h & 0x7ff) << 1, 12) }
        }
        _ => Op::Undefined,
    };
    (op, None)
}

/// A6.2.1 Shift (immediate), add, subtract, move, and compare.
fn shift_add_sub_mov_cmp(d: &mut D, h: u32) -> Op {
    let s = !d.it.in_it();
    let rd = h & 7;
    let rm = (h >> 3) & 7;
    let imm5 = (h >> 6) & 31;
    let opc = (h >> 9) & 31;
    match opc >> 2 {
        0b000 if imm5 == 0 => {
            // A8.8.104 MOV (register, Thumb) T2: MOVS, flags always set.
            d.not_in_it("A8.8.104: MOVS (T2) inside an IT block");
            d.uncond = true;
            mov(true, rd, reg(rm))
        }
        // A8.8.95 LSL, A8.8.97 LSR, A8.8.16 ASR (immediate) T1.
        0b000..=0b010 => {
            let (shift, amount) = Shift::decode_imm(opc >> 2, imm5);
            mov(s, rd, Operand::RegImm { rm: r(rm), shift, amount })
        }
        0b011 => {
            let x = (h >> 6) & 7;
            match opc & 3 {
                // A8.8.6 ADD (register, Thumb) T1, A8.8.224 SUB (register) T1.
                0 => dp(DpOp::Add, s, rd, rm, reg(x)),
                1 => dp(DpOp::Sub, s, rd, rm, reg(x)),
                // A8.8.4 ADD, A8.8.222 SUB (immediate, Thumb) T1.
                2 => dp(DpOp::Add, s, rd, rm, imm(x)),
                _ => dp(DpOp::Sub, s, rd, rm, imm(x)),
            }
        }
        _ => {
            let rdn = (h >> 8) & 7;
            let i8 = imm(h & 0xff);
            match opc >> 2 {
                // A8.8.103 MOV (immediate) T1: the carry unchanged.
                0b100 => mov(s, rdn, i8),
                // A8.8.37 CMP (immediate) T1.
                0b101 => test(DpOp::Cmp, rdn, i8),
                // A8.8.4 ADD, A8.8.222 SUB (immediate, Thumb) T2.
                0b110 => dp(DpOp::Add, s, rdn, rdn, i8),
                _ => dp(DpOp::Sub, s, rdn, rdn, i8),
            }
        }
    }
}

/// A6.2.2 Data-processing.
fn dp16(d: &mut D, h: u32) -> Op {
    let s = !d.it.in_it();
    let rdn = h & 7;
    let rm = (h >> 3) & 7;
    let by = |shift| mov(s, rdn, Operand::RegReg { rm: r(rdn), shift, rs: r(rm) });
    match (h >> 6) & 15 {
        0 => dp(DpOp::And, s, rdn, rdn, reg(rm)),
        1 => dp(DpOp::Eor, s, rdn, rdn, reg(rm)),
        // A8.8.96 LSL, A8.8.98 LSR, A8.8.17 ASR, A8.8.151 ROR (register) T1.
        2 => by(Shift::Lsl),
        3 => by(Shift::Lsr),
        4 => by(Shift::Asr),
        5 => dp(DpOp::Adc, s, rdn, rdn, reg(rm)),
        6 => dp(DpOp::Sbc, s, rdn, rdn, reg(rm)),
        7 => by(Shift::Ror),
        8 => test(DpOp::Tst, rdn, reg(rm)),
        // A8.8.153 RSB (immediate) T1: RSBS <Rd>, <Rn>, #0.
        9 => dp(DpOp::Rsb, s, rdn, rm, imm(0)),
        10 => test(DpOp::Cmp, rdn, reg(rm)),
        11 => test(DpOp::Cmn, rdn, reg(rm)),
        12 => dp(DpOp::Orr, s, rdn, rdn, reg(rm)),
        // A8.8.115 MUL T1: MULS <Rdm>, <Rn>, <Rdm>.
        13 => Op::Mul { s, rd: r(rdn), rn: r(rm), rm: r(rdn) },
        14 => dp(DpOp::Bic, s, rdn, rdn, reg(rm)),
        _ => Op::Dp { op: DpOp::Mvn, s, rd: r(rdn), rn: UNUSED, src: reg(rm) },
    }
}

/// A6.2.3 Special data instructions and branch and exchange.
fn special16(d: &mut D, h: u32) -> Op {
    let rdn = ((h >> 4) & 8) | (h & 7);
    let rm = (h >> 3) & 15;
    match (h >> 6) & 15 {
        0..=3 => {
            if rm == 13 {
                // A8.8.10 ADD (SP plus register, Thumb) T1: ADD <Rdm>, SP, <Rdm>.
                d.last_in_it(rdn == 15, "A8.8.10: d == 15 inside an IT block but not last");
                dp(DpOp::Add, false, rdn, 13, reg(rdn))
            } else if rdn == 13 {
                // A8.8.10 T2: ADD SP, <Rm>.
                dp(DpOp::Add, false, 13, 13, reg(rm))
            } else {
                // A8.8.6 ADD (register, Thumb) T2.
                d.unp(rdn == 15 && rm == 15, "A8.8.6: n == 15 && m == 15");
                d.last_in_it(rdn == 15, "A8.8.6: d == 15 inside an IT block but not last");
                dp(DpOp::Add, false, rdn, rdn, reg(rm))
            }
        }
        // A8.8.38 CMP (register) T2.
        4..=7 => {
            d.unp(rdn < 8 && rm < 8, "A8.8.38: n < 8 && m < 8");
            d.unp(rdn == 15 || rm == 15, "A8.8.38: n == 15 || m == 15");
            test(DpOp::Cmp, rdn, reg(rm))
        }
        // A8.8.104 MOV (register, Thumb) T1.
        8..=11 => {
            d.last_in_it(rdn == 15, "A8.8.104: d == 15 inside an IT block but not last");
            mov(false, rdn, reg(rm))
        }
        // A8.8.27 BX.
        12 | 13 => {
            d.zeros(h, 7);
            d.last_in_it(true, "A8.8.27: BX inside an IT block but not last");
            Op::Bx { rm: r(rm) }
        }
        // A8.8.26 BLX (register).
        _ => {
            d.zeros(h, 7);
            d.unp(rm == 15, "A8.8.26: m == 15");
            d.last_in_it(true, "A8.8.26: BLX inside an IT block but not last");
            Op::BlxReg { rm: r(rm) }
        }
    }
}

/// A6.2.4 Load/store single data item.
fn ldst16(h: u32) -> Op {
    let rt = h & 7;
    let rn = (h >> 3) & 7;
    let imm5 = (h >> 6) & 31;
    let load = (h >> 11) & 1 == 1;
    let i = |v: u32| Offset::Imm(v as i32);
    match h >> 12 {
        0b0101 => {
            // STR, STRH, STRB, LDRSB, LDR, LDRH, LDRB, LDRSH (register) T1.
            let (load, size, signed) = match (h >> 9) & 7 {
                0 => (false, Size::W, false),
                1 => (false, Size::H, false),
                2 => (false, Size::B, false),
                3 => (true, Size::B, true),
                4 => (true, Size::W, false),
                5 => (true, Size::H, false),
                6 => (true, Size::B, false),
                _ => (true, Size::H, true),
            };
            ldst(load, size, signed, false, rt, rn, roff((h >> 6) & 7, 0), true, false)
        }
        // STR/LDR, STRB/LDRB, STRH/LDRH (immediate, Thumb) T1.
        0b0110 => ldst(load, Size::W, false, false, rt, rn, i(imm5 << 2), true, false),
        0b0111 => ldst(load, Size::B, false, false, rt, rn, i(imm5), true, false),
        0b1000 => ldst(load, Size::H, false, false, rt, rn, i(imm5 << 1), true, false),
        // STR/LDR (immediate, Thumb) T2: SP-relative.
        _ => ldst(load, Size::W, false, false, (h >> 8) & 7, 13, i((h & 0xff) << 2), true, false),
    }
}

/// A6.2.5 Miscellaneous 16-bit instructions.
fn misc16(d: &mut D, h: u32) -> Dec {
    let op = match (h >> 5) & 0x7f {
        // A8.8.9 ADD (SP plus immediate) T2, A8.8.226 SUB (SP minus immediate) T1.
        0b0000000..=0b0000011 => dp(DpOp::Add, false, 13, 13, imm((h & 0x7f) << 2)),
        0b0000100..=0b0000111 => dp(DpOp::Sub, false, 13, 13, imm((h & 0x7f) << 2)),
        // A8.8.29 CBNZ, CBZ.
        0b0001000..=0b0001111 | 0b0011000..=0b0011111 | 0b1001000..=0b1001111 | 0b1011000..=0b1011111 => {
            d.not_in_it("A8.8.29: CBZ/CBNZ inside an IT block");
            d.uncond = true;
            Op::Cbz { nonzero: (h >> 11) & 1 == 1, rn: r(h & 7), imm: ((h >> 9) & 1) << 6 | ((h >> 3) & 31) << 1 }
        }
        // A8.8.236 SXTH, A8.8.234 SXTB, A8.8.277 UXTH, A8.8.275 UXTB T1.
        0b0010000..=0b0010111 => {
            let kind = [ExtKind::Sxth, ExtKind::Sxtb, ExtKind::Uxth, ExtKind::Uxtb][((h >> 6) & 3) as usize];
            Op::Extend { kind, rd: r(h & 7), rn: None, rm: r((h >> 3) & 7), rotation: 0 }
        }
        // A8.8.134 PUSH T1.
        0b0100000..=0b0101111 => {
            let regs = ((h >> 8) & 1) << 14 | (h & 0xff);
            d.unp(regs == 0, "A8.8.134: BitCount(registers) < 1");
            Op::Ldm { load: false, mode: Amode::Db, rn: Reg::SP, regs: regs as u16, wback: true, user: false }
        }
        // A8.8.168 SETEND.
        0b0110010 => {
            d.ones(h, 0x10);
            d.zeros(h, 7);
            d.not_in_it("A8.8.168: SETEND inside an IT block");
            d.uncond = true;
            Op::Setend { big: (h >> 3) & 1 == 1 }
        }
        // B9.3.1 CPS (Thumb) T1. At PL0 it is a NOP (the lifter's).
        0b0110011 => {
            d.zeros(h, 8);
            d.unp(h & 7 == 0, "B9.3.1: A:I:F == '000'");
            d.not_in_it("B9.3.1: CPS inside an IT block");
            d.uncond = true;
            Op::Cps { imod: 0b10 | ((h >> 4) & 1) as u8, a: h & 4 != 0, i: h & 2 != 0, f: h & 1 != 0, mode: None }
        }
        // A8.8.146 REV, A8.8.147 REV16, A8.8.148 REVSH T1.
        0b1010000 | 0b1010001 | 0b1010010 | 0b1010011 | 0b1010110 | 0b1010111 => {
            let kind = match (h >> 6) & 3 {
                0 => RevKind::Rev,
                1 => RevKind::Rev16,
                _ => RevKind::Revsh,
            };
            Op::Rev { kind, rd: r(h & 7), rm: r((h >> 3) & 7) }
        }
        // A8.8.132 POP (Thumb) T1.
        0b1100000..=0b1101111 => {
            let regs = ((h >> 8) & 1) << 15 | (h & 0xff);
            d.unp(regs == 0, "A8.8.132: BitCount(registers) < 1");
            d.last_in_it(regs >> 15 == 1, "A8.8.132: PC in the list inside an IT block but not last");
            Op::Ldm { load: true, mode: Amode::Ia, rn: Reg::SP, regs: regs as u16, wback: true, user: false }
        }
        // A8.8.24 BKPT: unconditional, even inside an IT block.
        0b1110000..=0b1110111 => return (Op::Bkpt { imm: (h & 0xff) as u16 }, Some(Cond::AL)),
        // If-Then, and hints (Table A6-7).
        0b1111000..=0b1111111 => {
            let (a, b) = ((h >> 4) & 15, h & 15);
            if b != 0 {
                // A8.8.55 IT.
                d.unp(a == 15 || (a == 14 && b.count_ones() != 1), "A8.8.55: firstcond == '1111', or '1110' with BitCount(mask) != 1");
                d.not_in_it("A8.8.55: IT inside an IT block");
                return (Op::It { firstcond: a as u8, mask: b as u8 }, Some(Cond::AL));
            }
            Op::Hint(match a {
                0 => Hint::Nop,
                1 => Hint::Yield,
                2 => Hint::Wfe,
                3 => Hint::Wfi,
                4 => Hint::Sev,
                // Unallocated hints: they execute as NOPs.
                _ => Hint::Nop,
            })
        }
        _ => Op::Undefined,
    };
    (op, None)
}

/// A6.2.6 Conditional branch, and Supervisor Call.
fn branch16(d: &mut D, h: u32) -> Dec {
    let imm8 = h & 0xff;
    match (h >> 8) & 15 {
        // A8.8.248 UDF T1 (conditional in an IT block, deprecated there).
        0b1110 => (Op::Udf { imm: imm8 as u16 }, None),
        // A8.8.229 SVC.
        0b1111 => (Op::Svc { imm: imm8 }, None),
        // A8.8.18 B T1: its own condition.
        c => {
            d.not_in_it("A8.8.18: B<c> (T1) inside an IT block");
            (Op::B { imm: sext(imm8 << 1, 9) }, Some(Cond(c as u8)))
        }
    }
}

// ===========================================================================
// 32-bit encodings (A6.3)
// ===========================================================================

fn d32(d: &mut D, h1: u32, h2: u32) -> Dec {
    let op2 = (h1 >> 4) & 0x7f;
    let op = match (h1 >> 11) & 3 {
        0b01 => {
            if op2 & 0b1100100 == 0 {
                ldm32(d, h1, h2)
            } else if op2 & 0b1100100 == 0b0000100 {
                dual_excl_tb(d, h1, h2)
            } else if op2 & 0b1100000 == 0b0100000 {
                dp_shifted(d, h1, h2)
            } else {
                coproc(d, h1, h2)
            }
        }
        0b10 => {
            if h2 >> 15 == 1 {
                return branch_misc(d, h1, h2);
            } else if op2 & 0b0100000 == 0 {
                dp_modimm(d, h1, h2)
            } else {
                dp_plain(d, h1, h2)
            }
        }
        _ => {
            if op2 & 0b1110001 == 0 {
                store32(d, h1, h2)
            } else if op2 & 0b1100111 == 0b0000001 {
                load_byte(d, h1, h2)
            } else if op2 & 0b1100111 == 0b0000011 {
                load_half(d, h1, h2)
            } else if op2 & 0b1100111 == 0b0000101 {
                load_word(d, h1, h2)
            } else if op2 & 0b1100111 == 0b0000111 {
                Op::Undefined
            } else if op2 & 0b1110001 == 0b0010000 {
                // A7.7 Advanced SIMD element or structure load/store: Thumb
                // 1111 1001 xxx0 is ARM 1111 0100 xxx0.
                fp_result(d, fp::decode_simd_ldst(0xf400_0000 | ((h1 << 16 | h2) & 0x00ff_ffff), d.f))
            } else if op2 & 0b1110000 == 0b0100000 {
                dp_reg(d, h1, h2)
            } else if op2 & 0b1111000 == 0b0110000 {
                mul32(d, h1, h2)
            } else if op2 & 0b1111000 == 0b0111000 {
                mul_long(d, h1, h2)
            } else {
                coproc(d, h1, h2)
            }
        }
    };
    (op, None)
}

fn fp_result(d: &mut D, (op, unp): (Op, Option<&'static str>)) -> Op {
    if let Some(w) = unp {
        d.unp(true, w);
    }
    op
}

/// A6.3.5 Load/store multiple.
fn ldm32(d: &mut D, h1: u32, h2: u32) -> Op {
    let opc = (h1 >> 7) & 3;
    let wback = (h1 >> 5) & 1 == 1;
    let load = (h1 >> 4) & 1 == 1;
    let n = h1 & 15;
    match (opc, load) {
        // B9.3.15 SRS (Thumb). In Hyp mode UNDEFINED, in User or System
        // mode UNPREDICTABLE, and in Non-secure state for Monitor or
        // reserved-FIQ modes UNPREDICTABLE: the lifter's.
        (0 | 3, false) => {
            d.ones(h1, 0b1101);
            d.zeros(h1, 0b0010);
            d.ones(h2, 0xc000);
            d.zeros(h2, 0x3fe0);
            let mode = h2 & 31;
            // Rmode[13, mode] of a mode the core lacks is UNPREDICTABLE
            // (BadMode(), via RBankSelect()), and Hyp mode's SP is not
            // accessible to SRS.
            d.unp(mode == 0b11010, "B9.3.15: mode == '11010'");
            d.unp(bad_mode(mode, d.f), "B9.3.15: BadMode(mode)");
            Op::Srs { mode: mode as u8, amode: if opc == 0 { Amode::Db } else { Amode::Ia }, wback }
        }
        // B9.3.13 RFE. In Hyp mode UNDEFINED, at PL0 UNPREDICTABLE: the lifter's.
        (0 | 3, true) => {
            d.ones(h2, 0xc000);
            d.zeros(h2, 0x3fff);
            d.unp(n == 15, "B9.3.13: n == 15");
            d.last_in_it(true, "B9.3.13: RFE inside an IT block but not last");
            Op::Rfe { rn: r(n), amode: if opc == 0 { Amode::Db } else { Amode::Ia }, wback }
        }
        // A8.8.200 STM T2; A8.8.202 STMDB T1, PUSH T2 (A8.8.134) for SP!.
        (1 | 2, false) => {
            d.zeros(h2, 0xa000);
            let regs = h2 & 0x5fff;
            if opc == 2 && wback && n == 13 {
                d.unp(regs.count_ones() < 2, "A8.8.134: BitCount(registers) < 2");
            } else {
                d.unp(n == 15 || regs.count_ones() < 2, "A8.8.200/A8.8.202: n == 15 || BitCount(registers) < 2");
                d.unp(wback && regs >> n & 1 == 1, "A8.8.200/A8.8.202: wback && registers<n> == '1'");
            }
            let mode = if opc == 1 { Amode::Ia } else { Amode::Db };
            Op::Ldm { load: false, mode, rn: r(n), regs: regs as u16, wback, user: false }
        }
        // A8.8.58 LDM T2, POP T2 (A8.8.132) for SP!; A8.8.61 LDMDB T1.
        _ => {
            d.zeros(h2, 0x2000);
            let regs = h2 & 0xdfff;
            let pm = h2 >> 14 == 3;
            if opc == 1 && wback && n == 13 {
                d.unp(regs.count_ones() < 2 || pm, "A8.8.132: BitCount(registers) < 2 || (P == '1' && M == '1')");
            } else {
                d.unp(n == 15 || regs.count_ones() < 2 || pm, "A8.8.58/A8.8.61: n == 15 || BitCount(registers) < 2 || (P == '1' && M == '1')");
            }
            d.last_in_it(regs >> 15 == 1, "A8.8.58/A8.8.61/A8.8.132: PC in the list inside an IT block but not last");
            d.unp(wback && regs >> n & 1 == 1, "A8.8.58/A8.8.61: wback && registers<n> == '1'");
            let mode = if opc == 1 { Amode::Ia } else { Amode::Db };
            Op::Ldm { load: true, mode, rn: r(n), regs: regs as u16, wback, user: false }
        }
    }
}

/// A6.3.6 Load/store dual, load/store exclusive, table branch.
fn dual_excl_tb(d: &mut D, h1: u32, h2: u32) -> Op {
    let op1 = (h1 >> 7) & 3;
    let op2 = (h1 >> 4) & 3;
    let n = h1 & 15;
    let t = h2 >> 12;
    let t2 = (h2 >> 8) & 15;
    let rd = h2 & 15;
    let imm8 = h2 & 0xff;
    match (op1, op2) {
        // A8.8.213 STREX: Rd in bits 11:8.
        (0, 0) => {
            let rd = t2;
            d.unp(bad(rd) || bad(t) || n == 15, "A8.8.213: d IN {13,15} || t IN {13,15} || n == 15");
            d.unp(rd == n || rd == t, "A8.8.213: d == n || d == t");
            Op::Strex { size: Size::W, rd: r(rd), rt: r(t), rt2: Reg::PC, rn: r(n), imm: imm8 << 2 }
        }
        // A8.8.76 LDREX.
        (0, 1) => {
            d.ones(h2, 0x0f00);
            d.unp(bad(t) || n == 15, "A8.8.76: t IN {13,15} || n == 15");
            Op::Ldrex { size: Size::W, rt: r(t), rt2: Reg::PC, rn: r(n), imm: imm8 << 2 }
        }
        (1, 0) => match (h2 >> 4) & 15 {
            // A8.8.214 STREXB, A8.8.216 STREXH.
            0b0100 | 0b0101 => {
                d.ones(h2, 0x0f00);
                d.unp(bad(rd) || bad(t) || n == 15, "A8.8.214/A8.8.216: d IN {13,15} || t IN {13,15} || n == 15");
                d.unp(rd == n || rd == t, "A8.8.214/A8.8.216: d == n || d == t");
                let size = if (h2 >> 4) & 1 == 0 { Size::B } else { Size::H };
                Op::Strex { size, rd: r(rd), rt: r(t), rt2: Reg::PC, rn: r(n), imm: 0 }
            }
            // A8.8.215 STREXD.
            0b0111 => {
                d.unp(bad(rd) || bad(t) || bad(t2) || n == 15, "A8.8.215: d, t or t2 IN {13,15} || n == 15");
                d.unp(rd == n || rd == t || rd == t2, "A8.8.215: d == n || d == t || d == t2");
                Op::Strex { size: Size::D, rd: r(rd), rt: r(t), rt2: r(t2), rn: r(n), imm: 0 }
            }
            _ => Op::Undefined,
        },
        (1, 1) => match (h2 >> 4) & 15 {
            // A8.8.237 TBB, TBH.
            0b0000 | 0b0001 => {
                d.ones(h2, 0xf000);
                d.zeros(h2, 0x0f00);
                d.unp(n == 13 || bad(rd), "A8.8.237: n == 13 || m IN {13,15}");
                d.last_in_it(true, "A8.8.237: TBB/TBH inside an IT block but not last");
                Op::Tb { half: (h2 >> 4) & 1 == 1, rn: r(n), rm: r(rd) }
            }
            // A8.8.77 LDREXB, A8.8.79 LDREXH.
            0b0100 | 0b0101 => {
                d.ones(h2, 0x0f0f);
                d.unp(bad(t) || n == 15, "A8.8.77/A8.8.79: t IN {13,15} || n == 15");
                let size = if (h2 >> 4) & 1 == 0 { Size::B } else { Size::H };
                Op::Ldrex { size, rt: r(t), rt2: Reg::PC, rn: r(n), imm: 0 }
            }
            // A8.8.78 LDREXD.
            0b0111 => {
                d.ones(h2, 0x000f);
                d.unp(bad(t) || bad(t2) || t == t2 || n == 15, "A8.8.78: t or t2 IN {13,15} || t == t2 || n == 15");
                Op::Ldrex { size: Size::D, rt: r(t), rt2: r(t2), rn: r(n), imm: 0 }
            }
            _ => Op::Undefined,
        },
        _ => {
            // P:U is op1 and W:L is op2: op1 0x with op2 1x, or op1 1x.
            let (p, u, w, l) = ((h1 >> 8) & 1 == 1, (h1 >> 7) & 1 == 1, (h1 >> 5) & 1 == 1, (h1 >> 4) & 1 == 1);
            let offset = Offset::Imm(signed(imm8 << 2, u));
            if !l {
                // A8.8.211 STRD (immediate).
                d.unp(w && (n == t || n == t2), "A8.8.211: wback && (n == t || n == t2)");
                d.unp(n == 15 || bad(t) || bad(t2), "A8.8.211: n == 15 || t IN {13,15} || t2 IN {13,15}");
            } else if n == 15 {
                // A8.8.74 LDRD (literal).
                d.unp(bad(t) || bad(t2) || t == t2, "A8.8.74: t IN {13,15} || t2 IN {13,15} || t == t2");
                d.unp(w, "A8.8.74: W == '1'");
            } else {
                // A8.8.73 LDRD (immediate).
                d.unp(w && (n == t || n == t2), "A8.8.73: wback && (n == t || n == t2)");
                d.unp(bad(t) || bad(t2) || t == t2, "A8.8.73: t IN {13,15} || t2 IN {13,15} || t == t2");
            }
            Op::Ldrd { load: l, rt: r(t), rt2: r(t2), rn: r(n), offset, index: p, wback: w }
        }
    }
}

/// The 1PUW forms of A6.3.7-A6.3.10 (`op2` 1xx1xx and 1100xx): LDR/STR
/// T4, LDRB/LDRH/STRB/STRH T3, LDRSB/LDRSH T2.
fn puw(h2: u32) -> (Offset, bool, bool) {
    let (p, u, w) = ((h2 >> 10) & 1 == 1, (h2 >> 9) & 1 == 1, (h2 >> 8) & 1 == 1);
    (Offset::Imm(signed(h2 & 0xff, u)), p, w)
}

/// Whether `op2` (bits 11:6 of the second halfword) is 1xx1xx or 1100xx.
fn is_puw(op2: u32) -> bool {
    op2 & 0b100100 == 0b100100 || op2 & 0b111100 == 0b110000
}

/// A6.3.7 Load word.
fn load_word(d: &mut D, h1: u32, h2: u32) -> Op {
    let op1 = (h1 >> 7) & 3;
    let n = h1 & 15;
    let t = h2 >> 12;
    let op2 = (h2 >> 6) & 63;
    let pc_why = "A8.8.63-A8.8.66: t == 15 inside an IT block but not last";
    if n == 15 {
        if op1 & 2 != 0 {
            return Op::Undefined;
        }
        // A8.8.65 LDR (literal) T2.
        d.last_in_it(t == 15, pc_why);
        return ldst(true, Size::W, false, false, t, 15, Offset::Imm(signed(h2 & 0xfff, (h1 >> 7) & 1 == 1)), true, false);
    }
    match op1 {
        // A8.8.63 LDR (immediate, Thumb) T3.
        1 => {
            d.last_in_it(t == 15, pc_why);
            ldst(true, Size::W, false, false, t, n, Offset::Imm((h2 & 0xfff) as i32), true, false)
        }
        0 if op2 == 0 => {
            // A8.8.66 LDR (register, Thumb) T2.
            let m = h2 & 15;
            d.unp(bad(m), "A8.8.66: m IN {13,15}");
            d.last_in_it(t == 15, pc_why);
            ldst(true, Size::W, false, false, t, n, roff(m, (h2 >> 4) & 3), true, false)
        }
        0 if op2 & 0b111100 == 0b111000 => {
            // A8.8.93 LDRT.
            d.unp(bad(t), "A8.8.93: t IN {13,15}");
            ldst(true, Size::W, false, true, t, n, Offset::Imm((h2 & 0xff) as i32), true, false)
        }
        0 if is_puw(op2) => {
            // A8.8.63 LDR (immediate, Thumb) T4; POP T3 (A8.8.132) is the
            // post-indexed SP, #4 form, the same operation (an unaligned
            // access permitted).
            let (offset, p, w) = puw(h2);
            d.unp(w && n == t, "A8.8.63: wback && n == t");
            d.last_in_it(t == 15, pc_why);
            ldst(true, Size::W, false, false, t, n, offset, p, w)
        }
        _ => Op::Undefined,
    }
}

/// The byte and halfword loads of A6.3.8 and A6.3.9 with Rn != PC: the
/// shared rows. `rt == 15` rows that are hints are handled by the caller.
fn load_bh(d: &mut D, h1: u32, h2: u32, size: Size) -> Op {
    let op1 = (h1 >> 7) & 3;
    let signed = op1 & 2 != 0;
    let n = h1 & 15;
    let t = h2 >> 12;
    let op2 = (h2 >> 6) & 63;
    if op1 & 1 == 1 {
        // LDRB/LDRH (immediate, Thumb) T2, LDRSB/LDRSH (immediate) T1.
        d.unp(t == 13, "A8.8.68/A8.8.80/A8.8.85/A8.8.89: t == 13");
        return ldst(true, size, signed, false, t, n, Offset::Imm((h2 & 0xfff) as i32), true, false);
    }
    if op2 == 0 {
        // LDRB/LDRH/LDRSB/LDRSH (register) T2.
        let m = h2 & 15;
        d.unp(t == 13 || bad(m), "A8.8.71/A8.8.83/A8.8.87/A8.8.91: t == 13 || m IN {13,15}");
        ldst(true, size, signed, false, t, n, roff(m, (h2 >> 4) & 3), true, false)
    } else if op2 & 0b111100 == 0b111000 {
        // LDRBT, LDRHT, LDRSBT, LDRSHT.
        d.unp(bad(t), "A8.8.72/A8.8.84/A8.8.88/A8.8.92: t IN {13,15}");
        ldst(true, size, signed, true, t, n, Offset::Imm((h2 & 0xff) as i32), true, false)
    } else if is_puw(op2) {
        // LDRB/LDRH (immediate, Thumb) T3, LDRSB/LDRSH (immediate) T2.
        let (offset, p, w) = puw(h2);
        d.unp(t == 13 || (t == 15 && w) || (w && n == t), "A8.8.68/A8.8.80/A8.8.85/A8.8.89: t == 13 || (t == 15 && W == '1') || (wback && n == t)");
        ldst(true, size, signed, false, t, n, offset, p, w)
    } else {
        Op::Undefined
    }
}

/// A literal load: LDRB/LDRH/LDRSB/LDRSH (literal).
fn load_lit(d: &mut D, h1: u32, h2: u32, size: Size) -> Op {
    let t = h2 >> 12;
    d.unp(t == 13, "A8.8.70/A8.8.82/A8.8.86/A8.8.90: t == 13");
    let signed = (h1 >> 8) & 1 == 1;
    ldst(true, size, signed, false, t, 15, Offset::Imm(signed_off(h1, h2)), true, false)
}

/// The U-signed imm12 of a literal form.
fn signed_off(h1: u32, h2: u32) -> i32 {
    signed(h2 & 0xfff, (h1 >> 7) & 1 == 1)
}

/// A preload hint: PLD (`write` false), PLDW, PLI (`instr`).
fn pld(write: bool, instr: bool, rn: u32, offset: Offset) -> Op {
    Op::Pld { write, instr, rn: r(rn), offset }
}

/// A6.3.8 Load halfword, memory hints.
fn load_half(d: &mut D, h1: u32, h2: u32) -> Op {
    let op1 = (h1 >> 7) & 3;
    let n = h1 & 15;
    let t = h2 >> 12;
    let op2 = (h2 >> 6) & 63;
    if n == 15 {
        if t != 15 {
            return load_lit(d, h1, h2, Size::H);
        }
        if op1 & 2 == 0 {
            // A8.8.128 PLD (literal): its bit 5 is (0), 1 in this space.
            d.zeros(h1, 0x20);
            return pld(false, false, 15, Offset::Imm(signed_off(h1, h2)));
        }
        // Unallocated memory hint (treat as NOP).
        return Op::Hint(Hint::Nop);
    }
    if t != 15 {
        return load_bh(d, h1, h2, Size::H);
    }
    // Rt == 1111: PLDW (A8.8.127, A8.8.129) with the Multiprocessing
    // Extensions, unallocated memory hints (NOPs) without them; the NOP
    // rows; and the loads whose Rt == 15 is UNPREDICTABLE.
    let pldw = |d: &mut D, offset: Offset, m: Option<u32>| {
        if d.f.mp {
            if let Some(m) = m {
                d.unp(bad(m), "A8.8.129: m IN {13,15}");
            }
            pld(true, false, n, offset)
        } else {
            Op::Hint(Hint::Nop)
        }
    };
    match op1 {
        0 if op2 == 0 => pldw(d, roff(h2 & 15, (h2 >> 4) & 3), Some(h2 & 15)),
        0 if op2 & 0b111100 == 0b110000 => pldw(d, Offset::Imm(-((h2 & 0xff) as i32)), None),
        1 => pldw(d, Offset::Imm((h2 & 0xfff) as i32), None),
        2 if op2 == 0 || op2 & 0b111100 == 0b110000 => Op::Hint(Hint::Nop),
        3 => Op::Hint(Hint::Nop),
        _ => load_bh(d, h1, h2, Size::H),
    }
}

/// A6.3.9 Load byte, memory hints.
fn load_byte(d: &mut D, h1: u32, h2: u32) -> Op {
    let op1 = (h1 >> 7) & 3;
    let n = h1 & 15;
    let t = h2 >> 12;
    let op2 = (h2 >> 6) & 63;
    let instr = op1 & 2 != 0;
    if n == 15 {
        if t != 15 {
            return load_lit(d, h1, h2, Size::B);
        }
        // A8.8.128 PLD (literal); A8.8.130 PLI (immediate, literal) T3.
        return pld(false, instr, 15, Offset::Imm(signed_off(h1, h2)));
    }
    if t != 15 {
        return load_bh(d, h1, h2, Size::B);
    }
    match op1 {
        // A8.8.129 PLD (register), A8.8.131 PLI (register).
        0 | 2 if op2 == 0 => {
            let m = h2 & 15;
            d.unp(bad(m), "A8.8.129/A8.8.131: m IN {13,15}");
            pld(false, instr, n, roff(m, (h2 >> 4) & 3))
        }
        // A8.8.127 PLD (immediate) T2, A8.8.130 PLI T2.
        0 | 2 if op2 & 0b111100 == 0b110000 => pld(false, instr, n, Offset::Imm(-((h2 & 0xff) as i32))),
        // A8.8.127 PLD (immediate) T1, A8.8.130 PLI T1.
        1 | 3 => pld(false, instr, n, Offset::Imm((h2 & 0xfff) as i32)),
        _ => load_bh(d, h1, h2, Size::B),
    }
}

/// A6.3.10 Store single data item.
fn store32(d: &mut D, h1: u32, h2: u32) -> Op {
    let op1 = (h1 >> 5) & 7;
    let n = h1 & 15;
    let t = h2 >> 12;
    let op2 = (h2 >> 6) & 63;
    let size = match op1 & 3 {
        0 => Size::B,
        1 => Size::H,
        2 => Size::W,
        _ => return Op::Undefined,
    };
    // Every store with Rn == '1111' is UNDEFINED.
    if n == 15 {
        return Op::Undefined;
    }
    // STR allows Rt == SP, STRB and STRH do not.
    let bad_t = if size == Size::W { t == 15 } else { bad(t) };
    let why_t = "A8.8.204-A8.8.221: t == 15 (STR) or t IN {13,15} (STRB, STRH)";
    if op1 & 4 != 0 {
        // STRB/STRH (immediate, Thumb) T2, STR (immediate, Thumb) T3.
        d.unp(bad_t, why_t);
        return ldst(false, size, false, false, t, n, Offset::Imm((h2 & 0xfff) as i32), true, false);
    }
    if op2 == 0 {
        // STR/STRB/STRH (register) T2.
        let m = h2 & 15;
        d.unp(bad_t || bad(m), "A8.8.206/A8.8.209/A8.8.219: t restricted or m IN {13,15}");
        ldst(false, size, false, false, t, n, roff(m, (h2 >> 4) & 3), true, false)
    } else if op2 & 0b111100 == 0b111000 {
        // STRT, STRBT, STRHT.
        d.unp(bad(t), "A8.8.210/A8.8.220/A8.8.221: t IN {13,15}");
        ldst(false, size, false, true, t, n, Offset::Imm((h2 & 0xff) as i32), true, false)
    } else if is_puw(op2) {
        // STR (immediate, Thumb) T4; PUSH T3 (A8.8.134) is the
        // pre-indexed SP, #-4 form, the same operation. STRB/STRH T3.
        let (offset, p, w) = puw(h2);
        d.unp(bad_t || (w && n == t), "A8.8.204/A8.8.207/A8.8.217: t restricted || (wback && n == t)");
        ldst(false, size, false, false, t, n, offset, p, w)
    } else {
        Op::Undefined
    }
}

/// A6.3.11 Data-processing (shifted register).
fn dp_shifted(d: &mut D, h1: u32, h2: u32) -> Op {
    d.zeros(h2, 0x8000);
    let opc = (h1 >> 5) & 15;
    let s = (h1 >> 4) & 1 == 1;
    let n = h1 & 15;
    let rd = (h2 >> 8) & 15;
    let imm5 = ((h2 >> 12) & 7) << 2 | (h2 >> 6) & 3;
    let ty = (h2 >> 4) & 3;
    let m = h2 & 15;
    let (shift, amount) = Shift::decode_imm(ty, imm5);
    let src = Operand::RegImm { rm: r(m), shift, amount };
    // The logical and arithmetic operations with every register restricted.
    let all = |d: &mut D, op: DpOp, why: &'static str| {
        d.unp(bad(rd) || bad(n) || bad(m), why);
        dp(op, s, rd, n, src)
    };
    let test_rd = rd == 15 && s;
    match opc {
        0b0000 | 0b0100 if test_rd => {
            // A8.8.242 TST, A8.8.239 TEQ (register).
            d.unp(bad(n) || bad(m), "A8.8.239/A8.8.242: n IN {13,15} || m IN {13,15}");
            test(if opc == 0 { DpOp::Tst } else { DpOp::Teq }, n, src)
        }
        0b0000 | 0b0100 => {
            // A8.8.14 AND, A8.8.48 EOR (register) T2.
            d.unp(rd == 13 || (rd == 15 && !s) || bad(n) || bad(m), "A8.8.14/A8.8.48: d == 13 || (d == 15 && S == '0') || n or m IN {13,15}");
            dp(if opc == 0 { DpOp::And } else { DpOp::Eor }, s, rd, n, src)
        }
        0b0001 => all(d, DpOp::Bic, "A8.8.22: d, n or m IN {13,15}"),
        0b0010 | 0b0011 if n != 15 => {
            // A8.8.124 ORR, A8.8.122 ORN (register).
            d.unp(bad(rd) || n == 13 || bad(m), "A8.8.122/A8.8.124: d IN {13,15} || n == 13 || m IN {13,15}");
            dp(if opc == 2 { DpOp::Orr } else { DpOp::Orn }, s, rd, n, src)
        }
        0b0010 => {
            // Move register and immediate shifts (Table A6-23).
            if ty == 0 && imm5 == 0 {
                // A8.8.104 MOV (register, Thumb) T3.
                if s {
                    d.unp(bad(rd) || bad(m), "A8.8.104: setflags && (d or m IN {13,15})");
                } else {
                    d.unp(rd == 15 || m == 15 || (rd == 13 && m == 13), "A8.8.104: !setflags && (d == 15 || m == 15 || (d == 13 && m == 13))");
                }
            } else {
                // A8.8.95 LSL, A8.8.97 LSR, A8.8.16 ASR, A8.8.150 ROR
                // (immediate) T2, A8.8.152 RRX.
                d.unp(bad(rd) || bad(m), "A8.8.16/95/97/150/152: d IN {13,15} || m IN {13,15}");
            }
            mov(s, rd, src)
        }
        0b0011 => {
            // A8.8.117 MVN (register) T2.
            d.unp(bad(rd) || bad(m), "A8.8.117: d IN {13,15} || m IN {13,15}");
            Op::Dp { op: DpOp::Mvn, s, rd: r(rd), rn: UNUSED, src }
        }
        0b0110 => {
            // A8.8.126 PKH: S and T (bit 4) are UNDEFINED when set.
            if s || ty & 1 == 1 {
                return Op::Undefined;
            }
            let tb = ty >> 1 == 1;
            let (_, amount) = Shift::decode_imm(ty & 2, imm5);
            d.unp(bad(rd) || bad(n) || bad(m), "A8.8.126: d, n or m IN {13,15}");
            Op::Pkh { tb, rd: r(rd), rn: r(n), rm: r(m), amount }
        }
        0b1000 | 0b1101 => {
            let (op, t) = if opc == 0b1000 { (DpOp::Add, DpOp::Cmn) } else { (DpOp::Sub, DpOp::Cmp) };
            if test_rd {
                // A8.8.35 CMN, A8.8.38 CMP (register) T2/T3.
                d.unp(n == 15 || bad(m), "A8.8.35/A8.8.38: n == 15 || m IN {13,15}");
                test(t, n, src)
            } else if n == 13 {
                // A8.8.10 ADD (SP plus register) T3, A8.8.227 SUB (SP minus register) T1.
                d.unp(rd == 13 && (shift != Shift::Lsl || amount > 3), "A8.8.10/A8.8.227: d == 13 && (shift_t != SRType_LSL || shift_n > 3)");
                d.unp((rd == 15 && !s) || bad(m), "A8.8.10/A8.8.227: (d == 15 && S == '0') || m IN {13,15}");
                dp(op, s, rd, 13, src)
            } else {
                // A8.8.6 ADD (register, Thumb) T3, A8.8.224 SUB (register) T2.
                d.unp(rd == 13 || (rd == 15 && !s) || n == 15 || bad(m), "A8.8.6/A8.8.224: d == 13 || (d == 15 && S == '0') || n == 15 || m IN {13,15}");
                dp(op, s, rd, n, src)
            }
        }
        0b1010 => all(d, DpOp::Adc, "A8.8.2: d, n or m IN {13,15}"),
        0b1011 => all(d, DpOp::Sbc, "A8.8.163: d, n or m IN {13,15}"),
        0b1110 => all(d, DpOp::Rsb, "A8.8.154: d, n or m IN {13,15}"),
        _ => Op::Undefined,
    }
}

/// A6.3.1 Data-processing (modified immediate).
fn dp_modimm(d: &mut D, h1: u32, h2: u32) -> Op {
    let opc = (h1 >> 5) & 15;
    let s = (h1 >> 4) & 1 == 1;
    let n = h1 & 15;
    let rd = (h2 >> 8) & 15;
    let imm12 = ((h1 >> 10) & 1) << 11 | ((h2 >> 12) & 7) << 8 | (h2 & 0xff);
    if !matches!(opc, 0b0000..=0b0100 | 0b1000 | 0b1010 | 0b1011 | 0b1101 | 0b1110) {
        return Op::Undefined;
    }
    let (value, carry, zero) = thumb_expand_imm(imm12);
    d.unp(zero, "A6.3.2 ThumbExpandImm_C: imm12<7:0> == '00000000' with imm12<11:8> == '00xx', xx != '00'");
    let src = Operand::Imm { value, carry };
    let test_rd = rd == 15 && s;
    match opc {
        0b0000 | 0b0100 if test_rd => {
            // A8.8.241 TST, A8.8.238 TEQ (immediate).
            d.unp(bad(n), "A8.8.238/A8.8.241: n IN {13,15}");
            test(if opc == 0 { DpOp::Tst } else { DpOp::Teq }, n, src)
        }
        0b0000 | 0b0100 => {
            // A8.8.13 AND, A8.8.47 EOR (immediate).
            d.unp(rd == 13 || (rd == 15 && !s) || bad(n), "A8.8.13/A8.8.47: d == 13 || (d == 15 && S == '0') || n IN {13,15}");
            dp(if opc == 0 { DpOp::And } else { DpOp::Eor }, s, rd, n, src)
        }
        0b0001 | 0b1010 | 0b1011 | 0b1110 => {
            // A8.8.21 BIC, A8.8.1 ADC, A8.8.162 SBC, A8.8.153 RSB (immediate).
            d.unp(bad(rd) || bad(n), "A8.8.1/21/153/162: d IN {13,15} || n IN {13,15}");
            let op = match opc {
                0b0001 => DpOp::Bic,
                0b1010 => DpOp::Adc,
                0b1011 => DpOp::Sbc,
                _ => DpOp::Rsb,
            };
            dp(op, s, rd, n, src)
        }
        0b0010 | 0b0011 if n == 15 => {
            // A8.8.103 MOV (immediate) T2, A8.8.116 MVN (immediate).
            d.unp(bad(rd), "A8.8.103/A8.8.116: d IN {13,15}");
            let op = if opc == 2 { DpOp::Mov } else { DpOp::Mvn };
            Op::Dp { op, s, rd: r(rd), rn: UNUSED, src }
        }
        0b0010 | 0b0011 => {
            // A8.8.123 ORR, A8.8.121 ORN (immediate).
            d.unp(bad(rd) || n == 13, "A8.8.121/A8.8.123: d IN {13,15} || n == 13");
            dp(if opc == 2 { DpOp::Orr } else { DpOp::Orn }, s, rd, n, src)
        }
        _ => {
            let (op, t) = if opc == 0b1000 { (DpOp::Add, DpOp::Cmn) } else { (DpOp::Sub, DpOp::Cmp) };
            if test_rd {
                // A8.8.34 CMN, A8.8.37 CMP (immediate) T1/T2.
                d.unp(n == 15, "A8.8.34/A8.8.37: n == 15");
                test(t, n, src)
            } else if n == 13 {
                // A8.8.9 ADD (SP plus immediate) T3, A8.8.226 SUB (SP minus immediate) T2.
                d.unp(rd == 15 && !s, "A8.8.9/A8.8.226: d == 15 && S == '0'");
                dp(op, s, rd, 13, src)
            } else {
                // A8.8.4 ADD, A8.8.222 SUB (immediate, Thumb) T3.
                d.unp(rd == 13 || (rd == 15 && !s) || n == 15, "A8.8.4/A8.8.222: d == 13 || (d == 15 && S == '0') || n == 15");
                dp(op, s, rd, n, src)
            }
        }
    }
}

/// A6.3.3 Data-processing (plain binary immediate).
fn dp_plain(d: &mut D, h1: u32, h2: u32) -> Op {
    let opc = (h1 >> 4) & 31;
    let n = h1 & 15;
    let rd = (h2 >> 8) & 15;
    let imm12 = ((h1 >> 10) & 1) << 11 | ((h2 >> 12) & 7) << 8 | (h2 & 0xff);
    let imm5 = ((h2 >> 12) & 7) << 2 | (h2 >> 6) & 3;
    match opc {
        0b00000 | 0b01010 => {
            let add = opc == 0;
            if n == 15 {
                // A8.8.12 ADR T3 (add) and T2 (subtract).
                d.unp(bad(rd), "A8.8.12: d IN {13,15}");
                Op::Adr { rd: r(rd), imm: signed(imm12, add) }
            } else if n == 13 {
                // A8.8.9 ADD (SP plus immediate) T4, A8.8.226 SUB (SP minus immediate) T3.
                d.unp(rd == 15, "A8.8.9/A8.8.226: d == 15");
                dp(if add { DpOp::Add } else { DpOp::Sub }, false, rd, 13, imm(imm12))
            } else {
                // A8.8.4 ADDW, A8.8.222 SUBW (immediate, Thumb) T4.
                d.unp(bad(rd), "A8.8.4/A8.8.222: d IN {13,15}");
                dp(if add { DpOp::Add } else { DpOp::Sub }, false, rd, n, imm(imm12))
            }
        }
        0b00100 | 0b01100 => {
            // A8.8.103 MOV (immediate) T3 (MOVW), A8.8.107 MOVT.
            d.unp(bad(rd), "A8.8.103/A8.8.107: d IN {13,15}");
            let imm = (n << 12 | imm12) as u16;
            if opc == 0b00100 {
                Op::Movw { rd: r(rd), imm }
            } else {
                Op::Movt { rd: r(rd), imm }
            }
        }
        0b10000 | 0b10010 | 0b11000 | 0b11010 => {
            d.zeros(h1, 0x400);
            let unsigned = opc & 0b01000 != 0;
            let sh = (h1 >> 5) & 1;
            if sh == 1 && imm5 == 0 {
                // A8.8.195 SSAT16, A8.8.268 USAT16.
                d.zeros(h2, 0x30);
                d.unp(bad(rd) || bad(n), "A8.8.195/A8.8.268: d IN {13,15} || n IN {13,15}");
                let sat = (h2 & 15) as u8 + if unsigned { 0 } else { 1 };
                Op::Sat16 { unsigned, rd: r(rd), rn: r(n), sat }
            } else {
                // A8.8.194 SSAT, A8.8.267 USAT.
                d.zeros(h2, 0x20);
                d.unp(bad(rd) || bad(n), "A8.8.194/A8.8.267: d IN {13,15} || n IN {13,15}");
                let (shift, amount) = Shift::decode_imm(sh << 1, imm5);
                let sat = (h2 & 31) as u8 + if unsigned { 0 } else { 1 };
                Op::Sat { unsigned, rd: r(rd), rn: r(n), sat, shift, amount }
            }
        }
        0b10100 | 0b11100 => {
            // A8.8.165 SBFX, A8.8.247 UBFX.
            d.zeros(h1, 0x400);
            d.zeros(h2, 0x20);
            let widthm1 = h2 & 31;
            d.unp(bad(rd) || bad(n), "A8.8.165/A8.8.247: d IN {13,15} || n IN {13,15}");
            d.unp(imm5 + widthm1 > 31, "A8.8.165/A8.8.247: lsbit + widthminus1 > 31");
            Op::Bfx { signed: opc == 0b10100, rd: r(rd), rn: r(n), lsb: imm5 as u8, width: (widthm1 + 1) as u8 }
        }
        0b10110 => {
            // A8.8.20 BFI, A8.8.19 BFC (Rn == '1111').
            d.zeros(h1, 0x400);
            d.zeros(h2, 0x20);
            let msb = h2 & 31;
            let rn = if n == 15 {
                d.unp(bad(rd), "A8.8.19: d IN {13,15}");
                None
            } else {
                d.unp(bad(rd) || n == 13, "A8.8.20: d IN {13,15} || n == 13");
                Some(r(n))
            };
            d.unp(msb < imm5, "A8.8.19/A8.8.20: msbit < lsbit");
            Op::Bfi { rd: r(rd), rn, lsb: imm5 as u8, msb: msb as u8 }
        }
        _ => Op::Undefined,
    }
}

/// The imm32 of B T4, BL and BLX (immediate): `S:I1:I2:hi:lo`, `lo`
/// `lo_bits` wide, I1 = NOT(J1 EOR S), I2 = NOT(J2 EOR S).
fn branch_imm(h1: u32, h2: u32, lo: u32, lo_bits: u32) -> i32 {
    let s = (h1 >> 10) & 1;
    let i1 = !((h2 >> 13) ^ s) & 1;
    let i2 = !((h2 >> 11) ^ s) & 1;
    let v = s << 24 | i1 << 23 | i2 << 22 | (h1 & 0x3ff) << 12 | lo << (12 - lo_bits);
    sext(v, 25)
}

/// A6.3.4 Branches and miscellaneous control.
fn branch_misc(d: &mut D, h1: u32, h2: u32) -> Dec {
    let op = (h1 >> 4) & 0x7f;
    let op1 = (h2 >> 12) & 7;
    let op2 = (h2 >> 8) & 15;
    let imm8 = h2 & 0xff;
    let n = h1 & 15;
    let f = d.f;
    let res = match op1 {
        0b000 | 0b010 if op & 0b0111000 != 0b0111000 => {
            // A8.8.18 B T3: its own condition.
            d.not_in_it("A8.8.18: B<c> (T3) inside an IT block");
            let s = (h1 >> 10) & 1;
            let v = s << 20 | ((h2 >> 11) & 1) << 19 | ((h2 >> 13) & 1) << 18 | (h1 & 63) << 12 | (h2 & 0x7ff) << 1;
            return (Op::B { imm: sext(v, 21) }, Some(Cond(((h1 >> 6) & 15) as u8)));
        }
        0b000 | 0b010 => match op {
            0b0111000 | 0b0111001 if imm8 & 0x20 != 0 => {
                // B9.3.10 MSR (Banked register). The mode-dependent
                // UNPREDICTABLE cases (BankedRegisterAccessValid,
                // SPSRaccessValid) are the lifter's.
                d.zeros(h2, 0x2000 | 0xcf);
                let sysm = ((op & 1) << 5 | ((h2 >> 4) & 1) << 4 | op2) as u8;
                d.unp(bad(n), "B9.3.10: n IN {13,15}");
                d.unp(fmt::banked_name(sysm).is_none(), "B9.2.3: an UNPREDICTABLE SYSm encoding");
                if f.virtualization {
                    Op::MsrBanked { rn: r(n), sysm }
                } else {
                    Op::Undefined
                }
            }
            0b0111000 | 0b0111001 => {
                // A8.8.113 MSR (register) (R == 0, mask<1:0> == '00': the
                // APSR's nzcvq and g, CPSR_f and CPSR_s), B9.3.12 MSR
                // (register) otherwise.
                d.zeros(h2, 0x2000 | 0xdf);
                let spsr = op & 1 == 1;
                if !spsr && op2 & 3 == 0 {
                    d.unp(op2 == 0, "A8.8.113: mask == '00'");
                } else {
                    d.unp(op2 == 0, "B9.3.12: mask == '0000'");
                }
                d.unp(bad(n), "A8.8.113/B9.3.12: n IN {13,15}");
                Op::Msr { psr: if spsr { Psr::Spsr } else { Psr::Cpsr }, mask: op2 as u8, src: MsrSrc::Reg(r(n)) }
            }
            0b0111010 => cps_hint(d, h1, h2),
            0b0111011 => {
                // Miscellaneous control instructions (Table A6-15).
                d.ones(h1, 0xf);
                d.zeros(h2, 0x2000);
                d.ones(h2, 0x0f00);
                let option = (h2 & 15) as u8;
                match (h2 >> 4) & 15 {
                    0b0000 | 0b0001 => {
                        // A9.3.1 ENTERX, LEAVEX (ThumbEE): LEAVEX is a NOP in Thumb state.
                        d.ones(h2, 0xf);
                        d.not_in_it("A9.3.1: ENTERX/LEAVEX inside an IT block");
                        d.uncond = true;
                        if f.thumbee {
                            Op::Enterx { leave: (h2 >> 4) & 1 == 0 }
                        } else {
                            Op::Undefined
                        }
                    }
                    // A8.8.32 CLREX.
                    0b0010 => {
                        d.ones(h2, 0xf);
                        Op::Clrex
                    }
                    // A8.8.45 DSB, A8.8.44 DMB, A8.8.54 ISB.
                    0b0100 => Op::Barrier { kind: Barrier::Dsb, option },
                    0b0101 => Op::Barrier { kind: Barrier::Dmb, option },
                    0b0110 => Op::Barrier { kind: Barrier::Isb, option },
                    _ => Op::Undefined,
                }
            }
            0b0111100 => {
                // A8.8.28 BXJ.
                d.zeros(h2, 0x2000 | 0xff);
                d.ones(h2, 0x0f00);
                d.unp(bad(n), "A8.8.28: m IN {13,15}");
                d.last_in_it(true, "A8.8.28: BXJ inside an IT block but not last");
                Op::Bxj { rm: r(n) }
            }
            0b0111101 => {
                // B9.3.19 SUBS PC, LR (Thumb), and ERET (B9.3.3) for imm8 ==
                // 0 with the Virtualization Extensions (SUBS PC, LR, #0
                // without them; the same operation at PL1). UNDEFINED in
                // Hyp mode when not ERET, and UNPREDICTABLE in User or
                // System mode: the lifter's.
                d.ones(h1, 0xe);
                d.zeros(h1, 0x1);
                d.zeros(h2, 0x2000);
                d.ones(h2, 0x0f00);
                d.last_in_it(true, "B9.3.3/B9.3.19: exception return inside an IT block but not last");
                if imm8 == 0 && f.virtualization {
                    Op::Eret
                } else {
                    Op::Dp { op: DpOp::Sub, s: true, rd: Reg::PC, rn: Reg::LR, src: imm(imm8) }
                }
            }
            0b0111110 | 0b0111111 if imm8 & 0x20 != 0 => {
                // B9.3.9 MRS (Banked register): SYSm<3:0> in Rn's place.
                d.zeros(h2, 0x2000 | 0xcf);
                let sysm = ((op & 1) << 5 | ((h2 >> 4) & 1) << 4 | n) as u8;
                d.unp(bad(op2), "B9.3.9: d IN {13,15}");
                d.unp(fmt::banked_name(sysm).is_none(), "B9.2.3: an UNPREDICTABLE SYSm encoding");
                if f.virtualization {
                    Op::MrsBanked { rd: r(op2), sysm }
                } else {
                    Op::Undefined
                }
            }
            0b0111110 | 0b0111111 => {
                // A8.8.110 MRS, B9.3.8 MRS (R == '1': the SPSR).
                d.ones(h1, 0xf);
                d.zeros(h2, 0x2000 | 0xdf);
                d.unp(bad(op2), "A8.8.110/B9.3.8: d IN {13,15}");
                Op::Mrs { rd: r(op2), psr: if op & 1 == 1 { Psr::Spsr } else { Psr::Cpsr } }
            }
            0b1111110 if op1 == 0 => {
                // B9.3.4 HVC. UNDEFINED or UNPREDICTABLE by mode and
                // SCR.HCE: the lifter's.
                d.not_in_it("B9.3.4: HVC inside an IT block");
                d.uncond = true;
                if f.virtualization {
                    Op::Hvc { imm: (n << 12 | (h2 & 0xfff)) as u16 }
                } else {
                    Op::Undefined
                }
            }
            0b1111111 if op1 == 0 => {
                // B9.3.14 SMC. UNDEFINED at PL0 and by SCR.SCD/HCR.TSC: the lifter's.
                d.zeros(h2, 0xfff);
                d.last_in_it(true, "B9.3.14: SMC inside an IT block but not last");
                if f.security {
                    Op::Smc { imm: n as u8 }
                } else {
                    Op::Undefined
                }
            }
            // A8.8.248 UDF T2.
            0b1111111 => Op::Udf { imm: (n << 12 | (h2 & 0xfff)) as u16 },
            _ => Op::Undefined,
        },
        0b001 | 0b011 => {
            // A8.8.18 B T4.
            d.last_in_it(true, "A8.8.18: B (T4) inside an IT block but not last");
            Op::B { imm: branch_imm(h1, h2, h2 & 0x7ff, 11) }
        }
        0b100 | 0b110 => {
            // A8.8.25 BLX (immediate) T2: H == '1' is UNDEFINED.
            if h2 & 1 == 1 {
                Op::Undefined
            } else {
                d.last_in_it(true, "A8.8.25: BLX inside an IT block but not last");
                Op::Bl { imm: branch_imm(h1, h2, (h2 >> 1) & 0x3ff, 10), switch: true }
            }
        }
        _ => {
            // A8.8.25 BL T1.
            d.last_in_it(true, "A8.8.25: BL inside an IT block but not last");
            Op::Bl { imm: branch_imm(h1, h2, h2 & 0x7ff, 11), switch: false }
        }
    };
    (res, None)
}

/// Change Processor State, and hints (Table A6-14).
fn cps_hint(d: &mut D, h1: u32, h2: u32) -> Op {
    d.ones(h1, 0xf);
    d.zeros(h2, 0x2000 | 0x0800);
    let op1 = (h2 >> 8) & 7;
    let op2 = h2 & 0xff;
    if op1 == 0 {
        // NOP, YIELD, WFE, WFI, SEV, CSDB, DBG; the other op2 values are
        // unallocated hints that behave as op2 == 0 (NOP).
        return Op::Hint(match op2 {
            1 => Hint::Yield,
            2 => Hint::Wfe,
            3 => Hint::Wfi,
            4 => Hint::Sev,
            0b0001_0100 => {
                // A8.8.42 CSDB.
                d.not_in_it("A8.8.42: CSDB inside an IT block");
                Hint::Csdb
            }
            0xf0..=0xff => Hint::Dbg((op2 & 15) as u8),
            _ => Hint::Nop,
        });
    }
    // B9.3.1 CPS (Thumb) T2. At PL0 a NOP; a mode change to a BadMode()
    // mode, or one not permitted from the current mode and Security state,
    // is UNPREDICTABLE at PL1 (CPSRWriteByInstr): the lifter's.
    let imod = op1 >> 1;
    let m = op1 & 1 == 1;
    let aif = (h2 >> 5) & 7;
    let mode = h2 & 31;
    d.unp(mode != 0 && !m, "B9.3.1: mode != '00000' && M == '0'");
    d.unp((imod & 2 != 0 && aif == 0) || (imod & 2 == 0 && aif != 0), "B9.3.1: imod<1> and A:I:F disagree");
    d.unp(imod == 1, "B9.3.1: imod == '01'");
    d.not_in_it("B9.3.1: CPS inside an IT block");
    d.uncond = true;
    Op::Cps { imod: imod as u8, a: aif & 4 != 0, i: aif & 2 != 0, f: aif & 1 != 0, mode: if m { Some(mode as u8) } else { None } }
}

/// A6.3.12 Data-processing (register), A6.3.13-A6.3.15.
fn dp_reg(d: &mut D, h1: u32, h2: u32) -> Op {
    if h2 >> 12 != 0b1111 {
        return Op::Undefined;
    }
    let op1 = (h1 >> 4) & 15;
    let n = h1 & 15;
    let rd = (h2 >> 8) & 15;
    let op2 = (h2 >> 4) & 15;
    let m = h2 & 15;
    let three = |d: &mut D, why: &'static str| d.unp(bad(rd) || bad(n) || bad(m), why);
    if op2 == 0 && op1 < 8 {
        // A8.8.96 LSL, A8.8.98 LSR, A8.8.17 ASR, A8.8.151 ROR (register) T2.
        three(d, "A8.8.17/96/98/151: d, n or m IN {13,15}");
        return mov(op1 & 1 == 1, rd, Operand::RegReg { rm: r(n), shift: Shift::of_type(op1 >> 1), rs: r(m) });
    }
    if op2 & 8 != 0 && op1 < 6 {
        // SXTAH/SXTH, UXTAH/UXTH, SXTAB16/SXTB16, UXTAB16/UXTB16,
        // SXTAB/SXTB, UXTAB/UXTB (A8.8.231-A8.8.236, A8.8.272-A8.8.277).
        d.zeros(h2, 0x40);
        let kind = [ExtKind::Sxth, ExtKind::Uxth, ExtKind::Sxtb16, ExtKind::Uxtb16, ExtKind::Sxtb, ExtKind::Uxtb][op1 as usize];
        let rn = if n == 15 {
            d.unp(bad(rd) || bad(m), "A8.8.234-236/A8.8.275-277: d IN {13,15} || m IN {13,15}");
            None
        } else {
            d.unp(bad(rd) || n == 13 || bad(m), "A8.8.231-233/A8.8.272-274: d IN {13,15} || n == 13 || m IN {13,15}");
            Some(r(n))
        };
        return Op::Extend { kind, rd: r(rd), rn, rm: r(m), rotation: (((h2 >> 4) & 3) << 3) as u8 };
    }
    if op1 & 8 != 0 && op2 & 0b1000 == 0 {
        // A6.3.13/A6.3.14 Parallel addition and subtraction, signed and unsigned.
        let u = op2 & 4 != 0;
        let kind = match (u, op2 & 3) {
            (false, 0) => ParKind::S,
            (false, 1) => ParKind::Q,
            (false, 2) => ParKind::Sh,
            (true, 0) => ParKind::U,
            (true, 1) => ParKind::Uq,
            (true, 2) => ParKind::Uh,
            _ => return Op::Undefined,
        };
        let op = match op1 & 7 {
            0b001 => ParOp::Add16,
            0b010 => ParOp::Asx,
            0b110 => ParOp::Sax,
            0b101 => ParOp::Sub16,
            0b000 => ParOp::Add8,
            0b100 => ParOp::Sub8,
            _ => return Op::Undefined,
        };
        three(d, "A8.8.136-A8.8.271 (parallel add/subtract): d, n or m IN {13,15}");
        return Op::Parallel { kind, op, rd: r(rd), rn: r(n), rm: r(m) };
    }
    if op1 & 0b1100 == 0b1000 && op2 & 0b1100 == 0b1000 {
        // A6.3.15 Miscellaneous operations.
        let mop2 = op2 & 3;
        return match op1 & 3 {
            0 => {
                // A8.8.135 QADD, A8.8.139 QDADD, A8.8.142 QSUB, A8.8.140 QDSUB.
                three(d, "A8.8.135/139/140/142: d, n or m IN {13,15}");
                Op::Qadd { sub: mop2 & 2 != 0, double: mop2 & 1 != 0, rd: r(rd), rm: r(m), rn: r(n) }
            }
            1 => {
                // A8.8.146 REV, A8.8.147 REV16, A8.8.145 RBIT, A8.8.148 REVSH T2.
                d.unp(n != m, "A8.8.145-A8.8.148: !Consistent(Rm)");
                d.unp(bad(rd) || bad(m), "A8.8.145-A8.8.148: d IN {13,15} || m IN {13,15}");
                let kind = [RevKind::Rev, RevKind::Rev16, RevKind::Rbit, RevKind::Revsh][mop2 as usize];
                Op::Rev { kind, rd: r(rd), rm: r(m) }
            }
            2 if mop2 == 0 => {
                // A8.8.167 SEL.
                three(d, "A8.8.167: d, n or m IN {13,15}");
                Op::Sel { rd: r(rd), rn: r(n), rm: r(m) }
            }
            3 if mop2 == 0 => {
                // A8.8.33 CLZ.
                d.unp(n != m, "A8.8.33: !Consistent(Rm)");
                d.unp(bad(rd) || bad(m), "A8.8.33: d IN {13,15} || m IN {13,15}");
                Op::Clz { rd: r(rd), rm: r(m) }
            }
            _ => Op::Undefined,
        };
    }
    Op::Undefined
}

/// A6.3.16 Multiply, multiply accumulate, and absolute difference.
fn mul32(d: &mut D, h1: u32, h2: u32) -> Op {
    if (h2 >> 6) & 3 != 0 {
        return Op::Undefined;
    }
    let op1 = (h1 >> 4) & 7;
    let n = h1 & 15;
    let a = h2 >> 12;
    let rd = (h2 >> 8) & 15;
    let op2 = (h2 >> 4) & 3;
    let m = h2 & 15;
    let acc = a != 15;
    let (rd_, rn_, rm_) = (r(rd), r(n), r(m));
    let ra = if acc { Some(r(a)) } else { None };
    // `a == 13` is UNPREDICTABLE for the accumulating forms (`a == 15` is
    // the non-accumulating instruction).
    let chk = |d: &mut D, why: &'static str| d.unp(bad(rd) || bad(n) || bad(m) || (acc && a == 13), why);
    match (op1, op2) {
        (0b000, 0b00) => {
            // A8.8.101 MLA, A8.8.115 MUL T2.
            chk(d, "A8.8.101/A8.8.115: d, n or m IN {13,15} || a == 13");
            if acc {
                Op::Mla { s: false, sub: false, rd: rd_, rn: rn_, rm: rm_, ra: r(a) }
            } else {
                Op::Mul { s: false, rd: rd_, rn: rn_, rm: rm_ }
            }
        }
        (0b000, 0b01) => {
            // A8.8.102 MLS.
            d.unp(bad(rd) || bad(n) || bad(m) || bad(a), "A8.8.102: d, n, m or a IN {13,15}");
            Op::Mla { s: false, sub: true, rd: rd_, rn: rn_, rm: rm_, ra: r(a) }
        }
        (0b001, _) => {
            // A8.8.177 SMLA<x><y>, A8.8.189 SMUL<x><y>.
            chk(d, "A8.8.177/A8.8.189: d, n or m IN {13,15} || a == 13");
            Op::Smulxy { rd: rd_, rn: rn_, rm: rm_, ra, n_top: op2 & 2 != 0, m_top: op2 & 1 != 0 }
        }
        (0b010 | 0b100, 0 | 1) => {
            // A8.8.178 SMLAD, A8.8.188 SMUAD, A8.8.183 SMLSD, A8.8.192 SMUSD.
            chk(d, "A8.8.178/183/188/192: d, n or m IN {13,15} || a == 13");
            Op::Smlad { rd: rd_, rn: rn_, rm: rm_, ra, sub: op1 == 0b100, swap: op2 & 1 != 0 }
        }
        (0b011, 0 | 1) => {
            // A8.8.182 SMLAW<y>, A8.8.191 SMULW<y>.
            chk(d, "A8.8.182/A8.8.191: d, n or m IN {13,15} || a == 13");
            Op::Smulwy { rd: rd_, rn: rn_, rm: rm_, ra, m_top: op2 & 1 != 0 }
        }
        (0b101, 0 | 1) => {
            // A8.8.185 SMMLA, A8.8.187 SMMUL.
            chk(d, "A8.8.185/A8.8.187: d, n or m IN {13,15} || a == 13");
            Op::Smmul { rd: rd_, rn: rn_, rm: rm_, ra, sub: false, round: op2 & 1 != 0 }
        }
        (0b110, 0 | 1) => {
            // A8.8.186 SMMLS: Ra == '1111' is not a separate instruction.
            d.unp(bad(rd) || bad(n) || bad(m) || bad(a), "A8.8.186: d, n, m or a IN {13,15}");
            Op::Smmul { rd: rd_, rn: rn_, rm: rm_, ra: Some(r(a)), sub: true, round: op2 & 1 != 0 }
        }
        (0b111, 0b00) => {
            // A8.8.266 USADA8, A8.8.265 USAD8.
            chk(d, "A8.8.265/A8.8.266: d, n or m IN {13,15} || a == 13");
            Op::Usad8 { rd: rd_, rn: rn_, rm: rm_, ra }
        }
        _ => Op::Undefined,
    }
}

/// A6.3.17 Long multiply, long multiply accumulate, and divide.
fn mul_long(d: &mut D, h1: u32, h2: u32) -> Op {
    let op1 = (h1 >> 4) & 7;
    let op2 = (h2 >> 4) & 15;
    let n = h1 & 15;
    let lo = h2 >> 12;
    let hi = (h2 >> 8) & 15;
    let m = h2 & 15;
    let long = |d: &mut D, why: &'static str| {
        d.unp(bad(lo) || bad(hi) || bad(n) || bad(m), why);
        d.unp(hi == lo, "A8.8.179-A8.8.258 (long multiply): dHi == dLo");
    };
    let (rdlo, rdhi, rn, rm) = (r(lo), r(hi), r(n), r(m));
    let ml = |kind| Op::MulLong { kind, s: false, rdlo, rdhi, rn, rm };
    match (op1, op2) {
        (0b000, 0b0000) => {
            long(d, "A8.8.190: dLo, dHi, n or m IN {13,15}");
            ml(MulLong::Smull)
        }
        (0b010, 0b0000) => {
            long(d, "A8.8.258: dLo, dHi, n or m IN {13,15}");
            ml(MulLong::Umull)
        }
        (0b100, 0b0000) => {
            long(d, "A8.8.179: dLo, dHi, n or m IN {13,15}");
            ml(MulLong::Smlal)
        }
        (0b110, 0b0000) => {
            long(d, "A8.8.257: dLo, dHi, n or m IN {13,15}");
            ml(MulLong::Umlal)
        }
        (0b110, 0b0110) => {
            long(d, "A8.8.256: dLo, dHi, n or m IN {13,15}");
            ml(MulLong::Umaal)
        }
        (0b100, 0b1000..=0b1011) => {
            // A8.8.180 SMLAL<x><y>.
            long(d, "A8.8.180: dLo, dHi, n or m IN {13,15}");
            Op::Smlalxy { rdlo, rdhi, rn, rm, n_top: op2 & 2 != 0, m_top: op2 & 1 != 0 }
        }
        (0b100 | 0b101, 0b1100 | 0b1101) => {
            // A8.8.181 SMLALD, A8.8.184 SMLSLD.
            long(d, "A8.8.181/A8.8.184: dLo, dHi, n or m IN {13,15}");
            Op::Smlald { rdlo, rdhi, rn, rm, sub: op1 == 0b101, swap: op2 & 1 != 0 }
        }
        (0b001 | 0b011, 0b1111) => {
            // A8.8.166 SDIV, A8.8.249 UDIV: optional in ARMv7-A.
            d.ones(h2, 0xf000);
            d.unp(bad(hi) || bad(n) || bad(m), "A8.8.166/A8.8.249: d, n or m IN {13,15}");
            if d.f.thumb_div {
                Op::Div { signed: op1 == 0b001, rd: rdhi, rn, rm }
            } else {
                Op::Undefined
            }
        }
        _ => Op::Undefined,
    }
}

/// A6.3.18 Coprocessor, Advanced SIMD, and Floating-point instructions.
/// Which coprocessors exist and what an access to one does (UNDEFINED for
/// an absent or inaccessible one) is the lifter's.
fn coproc(d: &mut D, h1: u32, h2: u32) -> Op {
    let raw = h1 << 16 | h2;
    let two = (h1 >> 12) & 1 == 1;
    let op1 = (h1 >> 4) & 63;
    let n = h1 & 15;
    let cp = (h2 >> 8) & 15;
    if op1 & 0b111110 == 0 {
        return Op::Undefined;
    }
    if op1 & 0b110000 == 0b110000 {
        // A7.4 Advanced SIMD data-processing: Thumb 111U 1111 is ARM
        // 1111 001U. Executed conditionally inside an IT block (A7.4;
        // A8.3 deprecates it).
        return fp_result(d, fp::decode_simd_dp(0xf200_0000 | ((raw >> 28) & 1) << 24 | (raw & 0x00ff_ffff), d.f));
    }
    if cp & 0b1110 == 0b1010 {
        // Coprocessors 10 and 11: the Floating-point and Advanced SIMD
        // register transfers and data processing (A7.5, A7.6, A7.8, A7.9),
        // the ARM form's low 28 bits with cond AL. The bit-28 forms (LDC2,
        // STC2, MCRR2, MRRC2, CDP2, MCR2, MRC2) with coproc 101x are
        // UNDEFINED.
        if two {
            return Op::Undefined;
        }
        return fp_result(d, fp::decode_cp_in(raw, d.f, InstrSet::Thumb));
    }
    let coproc = cp as u8;
    let t = h2 >> 12;
    if op1 & 0b100000 == 0 {
        if op1 & 0b111110 == 0b000100 {
            // A8.8.100 MCRR/MCRR2, A8.8.109 MRRC/MRRC2.
            let read = op1 & 1 == 1;
            d.unp(t == 15 || n == 15, "A8.8.100/A8.8.109: t == 15 || t2 == 15");
            d.unp(read && t == n, "A8.8.109: t == t2");
            d.unp(t == 13 || n == 13, "A8.8.100/A8.8.109: t == 13 || t2 == 13 (Thumb)");
            return Op::Mcrr { read, two, coproc, opc1: ((h2 >> 4) & 15) as u8, rt: r(t), rt2: r(n), crm: (h2 & 15) as u8 };
        }
        // A8.8.56/A8.8.57 LDC/LDC2, A8.8.199 STC/STC2 (op1 not 000x0x).
        let (p, u, dbit, w, l) = (op1 & 16 != 0, op1 & 8 != 0, op1 & 4 != 0, op1 & 2 != 0, op1 & 1 != 0);
        let imm8 = h2 & 0xff;
        if l && n == 15 {
            d.unp(w || !p, "A8.8.57: W == '1' || (P == '0' && Thumb)");
        } else if !l {
            d.unp(n == 15, "A8.8.199: n == 15 (Thumb)");
        }
        let option = if !p && !w { Some(imm8 as u8) } else { None };
        let imm = if option.is_some() { 0 } else { signed(imm8 << 2, u) };
        return Op::Ldc { load: l, two, long: dbit, coproc, crd: (h2 >> 12) as u8, rn: r(n), imm, index: p, wback: w, option };
    }
    if (h2 >> 4) & 1 == 0 {
        // A8.8.30 CDP/CDP2.
        return Op::Cdp {
            two,
            coproc,
            opc1: ((h1 >> 4) & 15) as u8,
            crd: t as u8,
            crn: n as u8,
            crm: (h2 & 15) as u8,
            opc2: ((h2 >> 5) & 7) as u8,
        };
    }
    // A8.8.99 MCR/MCR2, A8.8.108 MRC/MRC2 (Rt == 15: the flags).
    let read = (h1 >> 4) & 1 == 1;
    if read {
        d.unp(t == 13, "A8.8.108: t == 13 (Thumb)");
    } else {
        d.unp(t == 15 || t == 13, "A8.8.99: t == 15 || t == 13 (Thumb)");
    }
    Op::Mcr {
        read,
        two,
        coproc,
        opc1: ((h1 >> 5) & 7) as u8,
        rt: r(t),
        crn: n as u8,
        crm: (h2 & 15) as u8,
        opc2: ((h2 >> 5) & 7) as u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUT: ItState = ItState(0);
    /// `it eq`: the instruction is the last of a one-instruction block.
    const LAST: ItState = ItState(0x08);
    /// `itt eq`: the first of a two-instruction block, not last.
    const FIRST: ItState = ItState(0x04);

    fn t16(h: u16, it: ItState) -> Inst {
        decode(h, 0, it, &Features::ALL)
    }
    fn t32(h1: u16, h2: u16) -> Inst {
        decode(h1, h2, OUT, &Features::ALL)
    }
    fn t32f(h1: u16, h2: u16, f: &Features) -> Inst {
        decode(h1, h2, OUT, f)
    }
    fn unp(i: &Inst) -> bool {
        i.unpredictable.is_some()
    }
    fn imm_of(i: &Inst) -> (u32, Option<bool>) {
        match i.op {
            Op::Dp { src: Operand::Imm { value, carry }, .. } => (value, carry),
            _ => panic!("{:?}", i.op),
        }
    }

    #[test]
    fn sixteen_bit_setflags_follow_it() {
        // ADDS r0, r1, #2 (A8.8.4 T1): flags outside, none inside an IT block.
        let i = t16(0x1c88, OUT);
        assert_eq!(i.op, Op::Dp { op: DpOp::Add, s: true, rd: Reg(0), rn: Reg(1), src: imm(2) });
        assert_eq!((i.len, i.raw, i.cond), (2, 0x1c88, Cond::AL));
        let i = t16(0x1c88, LAST);
        assert_eq!(i.op, Op::Dp { op: DpOp::Add, s: false, rd: Reg(0), rn: Reg(1), src: imm(2) });
        assert_eq!(i.cond, Cond::EQ);
        // LSLS r1, r2, r3 is LSL (register): MOV of r1 shifted by r3... here
        // 0x4099 is LSLS r1, r3: Rdn = r1, Rm = r3.
        let i = t16(0x4099, OUT);
        assert_eq!(i.op, Op::Dp { op: DpOp::Mov, s: true, rd: Reg(1), rn: UNUSED, src: Operand::RegReg { rm: Reg(1), shift: Shift::Lsl, rs: Reg(3) } });
        // MULS r0, r1, r0 (0x4348).
        assert_eq!(t16(0x4348, OUT).op, Op::Mul { s: true, rd: Reg(0), rn: Reg(1), rm: Reg(0) });
        // LSRS r0, r1, #32 (imm5 == 0).
        let i = t16(0x0808, OUT);
        assert_eq!(i.op, mov(true, 0, Operand::RegImm { rm: Reg(1), shift: Shift::Lsr, amount: 32 }));
    }

    #[test]
    fn movs_t2_and_unconditional_in_it() {
        // MOVS r0, r1 (A8.8.104 T2): not permitted in an IT block.
        let i = t16(0x0008, OUT);
        assert_eq!((i.op.clone(), unp(&i)), (mov(true, 0, reg(1)), false));
        let i = t16(0x0008, LAST);
        assert!(unp(&i));
        assert_eq!(i.cond, Cond::AL);
        // CBZ r0, #2: UNPREDICTABLE in an IT block.
        let i = t16(0xb108, OUT);
        assert_eq!(i.op, Op::Cbz { nonzero: false, rn: Reg(0), imm: 2 });
        assert!(unp(&t16(0xb108, LAST)));
        // CPSIE i (B9.3.1 T1), SETEND BE.
        assert_eq!(t16(0xb662, OUT).op, Op::Cps { imod: 2, a: false, i: true, f: false, mode: None });
        assert!(unp(&t16(0xb662, LAST)));
        assert_eq!(t16(0xb658, OUT).op, Op::Setend { big: true });
        assert!(unp(&t16(0xb640, OUT))); // SETEND with its bit 4 (1) clear
        // BKPT is unconditional even inside an IT block.
        let i = t16(0xbe01, LAST);
        assert_eq!((i.op.clone(), i.cond, unp(&i)), (Op::Bkpt { imm: 1 }, Cond::AL, false));
    }

    #[test]
    fn it_instruction() {
        let i = t16(0xbf08, OUT);
        assert_eq!((i.op.clone(), i.cond, unp(&i)), (Op::It { firstcond: 0, mask: 8 }, Cond::AL, false));
        // IT inside an IT block, IT AL with an E, IT with firstcond 1111.
        assert!(unp(&t16(0xbf08, LAST)));
        assert!(unp(&t16(0xbfe6, OUT)));
        assert!(!unp(&t16(0xbfe8, OUT)));
        assert!(unp(&t16(0xbff8, OUT)));
        // Hints and unallocated hints.
        assert_eq!(t16(0xbf20, OUT).op, Op::Hint(Hint::Wfe));
        assert_eq!(t16(0xbf50, OUT).op, Op::Hint(Hint::Nop));
    }

    #[test]
    fn branches_and_it() {
        // BEQ #-4 (T1): its own condition; UNPREDICTABLE inside IT.
        let i = t16(0xd0fe, OUT);
        assert_eq!((i.op.clone(), i.cond), (Op::B { imm: -4 }, Cond::EQ));
        assert!(unp(&t16(0xd0fe, LAST)));
        // B #-4 (T2): permitted last in a block only.
        assert_eq!(t16(0xe7fe, OUT).op, Op::B { imm: -4 });
        assert!(!unp(&t16(0xe7fe, LAST)));
        assert!(unp(&t16(0xe7fe, FIRST)));
        // UDF #1 and SVC #1 (A6.2.6).
        assert_eq!(t16(0xde01, OUT).op, Op::Udf { imm: 1 });
        assert_eq!(t16(0xdf01, OUT).op, Op::Svc { imm: 1 });
        // BL #-4, BLX #-4 (T2, H == 0), BLX with H == 1 UNDEFINED.
        assert_eq!(t32(0xf7ff, 0xfffe).op, Op::Bl { imm: -4, switch: false });
        assert_eq!(t32(0xf7ff, 0xeffe).op, Op::Bl { imm: -4, switch: true });
        assert!(t32(0xf7ff, 0xefff).is_undefined());
        assert!(unp(&decode(0xf7ff, 0xfffe, FIRST, &Features::ALL)));
        // B.W T3: BNE #-4 with its condition; T4: B.W #-4.
        let i = t32(0xf47f, 0xaffe);
        assert_eq!((i.op.clone(), i.cond), (Op::B { imm: -4 }, Cond::NE));
        assert_eq!(t32(0xf7ff, 0xbffe).op, Op::B { imm: -4 });
        // BX lr; BLX pc is UNPREDICTABLE; MOV pc, r0 not last in IT.
        assert_eq!(t16(0x4770, OUT).op, Op::Bx { rm: Reg::LR });
        assert!(unp(&t16(0x47f8, OUT)));
        assert!(unp(&t16(0x4687, FIRST)));
        assert!(!unp(&t16(0x4687, LAST)));
        // TBB [r1, r2].
        assert_eq!(t32(0xe8d1, 0xf002).op, Op::Tb { half: false, rn: Reg(1), rm: Reg(2) });
    }

    #[test]
    fn modified_immediates_and_carry() {
        // MOV.W r0, #0x40000000: rotated, carry = bit 31 = 0.
        assert_eq!(imm_of(&t32(0xf04f, 0x4080)), (0x4000_0000, Some(false)));
        // MOV.W r0, #0x80000000: carry 1.
        assert_eq!(imm_of(&t32(0xf04f, 0x4000)), (0x8000_0000, Some(true)));
        // Unrotated: no carry change.
        assert_eq!(imm_of(&t32(0xf04f, 0x0012)), (0x12, None));
        assert_eq!(imm_of(&t32(0xf04f, 0x3012)), (0x1212_1212, None));
        assert_eq!(imm_of(&t32(0xf04f, 0x2012)), (0x1200_1200, None));
        // A replicated zero byte is UNPREDICTABLE.
        assert!(unp(&t32(0xf04f, 0x1000)));
        // TST r0, #1 (Rd == 1111, S == 1); AND with Rd == PC, S == 0 is UNPREDICTABLE.
        assert!(matches!(t32(0xf010, 0x0f01).op, Op::Dp { op: DpOp::Tst, .. }));
        assert!(unp(&t32(0xf000, 0x0f01)));
        // ADD.W sp, sp, #4 (A8.8.9 T3); undefined op 0101.
        assert_eq!(t32(0xf10d, 0x0d04).op, dp(DpOp::Add, false, 13, 13, imm(4)));
        assert!(t32(0xf0a0, 0x0000).is_undefined());
    }

    #[test]
    fn plain_immediates() {
        // ADDW r0, r1, #0xfff; ADR.W r0, #-4 (SUBW form); MOVW/MOVT.
        assert_eq!(t32(0xf601, 0x70ff).op, dp(DpOp::Add, false, 0, 1, imm(0xfff)));
        assert_eq!(t32(0xf2af, 0x0004).op, Op::Adr { rd: Reg(0), imm: -4 });
        assert_eq!(t32(0xf241, 0x2034).op, Op::Movw { rd: Reg(0), imm: 0x1234 });
        assert_eq!(t32(0xf2c1, 0x2034).op, Op::Movt { rd: Reg(0), imm: 0x1234 });
        // SSAT r0, #8, r1, asr #3; SSAT16 r0, #8, r1; USAT r0, #31, r1.
        assert_eq!(t32(0xf321, 0x00c7).op, Op::Sat { unsigned: false, rd: Reg(0), rn: Reg(1), sat: 8, shift: Shift::Asr, amount: 3 });
        assert_eq!(t32(0xf321, 0x0007).op, Op::Sat16 { unsigned: false, rd: Reg(0), rn: Reg(1), sat: 8 });
        assert_eq!(t32(0xf381, 0x001f).op, Op::Sat { unsigned: true, rd: Reg(0), rn: Reg(1), sat: 31, shift: Shift::Lsl, amount: 0 });
        // BFI r0, r1, #4, #8 (msb 11); BFC with msb < lsb is UNPREDICTABLE.
        assert_eq!(t32(0xf361, 0x100b).op, Op::Bfi { rd: Reg(0), rn: Some(Reg(1)), lsb: 4, msb: 11 });
        assert!(unp(&t32(0xf36f, 0x1001)));
        // UBFX r0, r1, #28, #8: lsb + width - 1 > 31.
        assert!(unp(&t32(0xf3c1, 0x7007)));
        assert_eq!(t32(0xf3c1, 0x1007).op, Op::Bfx { signed: false, rd: Reg(0), rn: Reg(1), lsb: 4, width: 8 });
    }

    #[test]
    fn shifted_register_and_register() {
        // ADD.W r0, r1, r2, lsl #3; RRX r0, r1; PKHTB r0, r1, r2, asr #32.
        assert_eq!(t32(0xeb01, 0x00c2).op, dp(DpOp::Add, false, 0, 1, Operand::RegImm { rm: Reg(2), shift: Shift::Lsl, amount: 3 }));
        assert_eq!(t32(0xea4f, 0x0031).op, mov(false, 0, Operand::RegImm { rm: Reg(1), shift: Shift::Rrx, amount: 1 }));
        assert_eq!(t32(0xeac1, 0x0022).op, Op::Pkh { tb: true, rd: Reg(0), rn: Reg(1), rm: Reg(2), amount: 32 });
        // PKH with S or T set is UNDEFINED.
        assert!(t32(0xead1, 0x0002).is_undefined());
        assert!(t32(0xeac1, 0x0012).is_undefined());
        // ADD sp, sp, r0, lsl #4 is UNPREDICTABLE (shift > 3 into SP).
        assert!(unp(&t32(0xeb0d, 0x1d00)));
        assert!(!unp(&t32(0xeb0d, 0x0d80)));
        // The (0) at bit 15 of the second halfword.
        assert!(unp(&t32(0xeb01, 0x8002)));
        // LSL.W r0, r1, r2; SXTAB r0, r1, r2, ror #8; REV with !Consistent(Rm).
        assert_eq!(t32(0xfa01, 0xf002).op, mov(false, 0, Operand::RegReg { rm: Reg(1), shift: Shift::Lsl, rs: Reg(2) }));
        assert_eq!(t32(0xfa41, 0xf092).op, Op::Extend { kind: ExtKind::Sxtb, rd: Reg(0), rn: Some(Reg(1)), rm: Reg(2), rotation: 8 });
        assert_eq!(t32(0xfa92, 0xf082).op, Op::Rev { kind: RevKind::Rev, rd: Reg(0), rm: Reg(2) });
        assert!(unp(&t32(0xfa91, 0xf082)));
        // UQSUB8 r0, r1, r2; QADD r0, r2, r1 (Rd, Rm, Rn); the DP (register)
        // space needs bits 15:12 == 1111.
        assert_eq!(t32(0xfac1, 0xf052).op, Op::Parallel { kind: ParKind::Uq, op: ParOp::Sub8, rd: Reg(0), rn: Reg(1), rm: Reg(2) });
        assert_eq!(t32(0xfa81, 0xf082).op, Op::Qadd { sub: false, double: false, rd: Reg(0), rm: Reg(2), rn: Reg(1) });
        assert!(t32(0xfa81, 0xe082).is_undefined());
    }

    #[test]
    fn multiplies_and_divide() {
        // MLA r0, r1, r2, r3; MUL (Ra == 1111); SMULL; dHi == dLo.
        assert_eq!(t32(0xfb01, 0x3002).op, Op::Mla { s: false, sub: false, rd: Reg(0), rn: Reg(1), rm: Reg(2), ra: Reg(3) });
        assert_eq!(t32(0xfb01, 0xf002).op, Op::Mul { s: false, rd: Reg(0), rn: Reg(1), rm: Reg(2) });
        assert_eq!(t32(0xfb81, 0x0302).op, Op::MulLong { kind: MulLong::Smull, s: false, rdlo: Reg(0), rdhi: Reg(3), rn: Reg(1), rm: Reg(2) });
        assert!(unp(&t32(0xfb81, 0x0002)));
        // SDIV r0, r1, r2: UNDEFINED without the Thumb divide.
        assert_eq!(t32(0xfb91, 0xf0f2).op, Op::Div { signed: true, rd: Reg(0), rn: Reg(1), rm: Reg(2) });
        assert!(t32f(0xfb91, 0xf0f2, &Features::BASE).is_undefined());
        // Bits 7:6 of the multiply space are UNDEFINED when set.
        assert!(t32(0xfb01, 0xf042).is_undefined());
    }

    #[test]
    fn loads_stores_and_hints() {
        // LDR.W r0, [pc, #-4]; LDR r0, [r1, #-4]!; STR r0, [r1], #4.
        assert_eq!(t32(0xf85f, 0x0004).op, ldst(true, Size::W, false, false, 0, 15, Offset::Imm(-4), true, false));
        assert_eq!(t32(0xf851, 0x0d04).op, ldst(true, Size::W, false, false, 0, 1, Offset::Imm(-4), true, true));
        assert_eq!(t32(0xf841, 0x0b04).op, ldst(false, Size::W, false, false, 0, 1, Offset::Imm(4), false, true));
        // PUSH.W {r0} (STR r0, [sp, #-4]!), POP.W {r0} (LDR r0, [sp], #4).
        assert_eq!(t32(0xf84d, 0x0d04).op, ldst(false, Size::W, false, false, 0, 13, Offset::Imm(-4), true, true));
        assert_eq!(t32(0xf85d, 0x0b04).op, ldst(true, Size::W, false, false, 0, 13, Offset::Imm(4), false, true));
        // LDRT r0, [r1, #4]; stores with Rn == PC are UNDEFINED; P == W == 0 too.
        assert_eq!(t32(0xf851, 0x0e04).op, ldst(true, Size::W, false, true, 0, 1, Offset::Imm(4), true, false));
        assert!(t32(0xf8cf, 0x0000).is_undefined());
        assert!(t32(0xf841, 0x0804).is_undefined());
        // LDR pc not last in IT.
        assert!(unp(&decode(0xf8d1, 0xf000, FIRST, &Features::ALL)));
        // PLD [r0, #4]; PLDW [r0, #4] (NOP without MP); PLI [r0, #4].
        assert_eq!(t32(0xf890, 0xf004).op, pld(false, false, 0, Offset::Imm(4)));
        assert_eq!(t32(0xf8b0, 0xf004).op, pld(true, false, 0, Offset::Imm(4)));
        assert_eq!(t32f(0xf8b0, 0xf004, &Features::BASE).op, Op::Hint(Hint::Nop));
        assert_eq!(t32(0xf990, 0xf004).op, pld(false, true, 0, Offset::Imm(4)));
        // LDRSH T1 with Rt == PC: an unallocated memory hint, a NOP.
        assert_eq!(t32(0xf9b0, 0xf000).op, Op::Hint(Hint::Nop));
        // PLD (literal) in the halfword space: bit 5 is (0).
        assert!(unp(&t32(0xf8bf, 0xf004)));
        // LDRD r0, r1, [r2, #8]!; STRD with n == t and writeback.
        assert_eq!(t32(0xe9f2, 0x0102).op, Op::Ldrd { load: true, rt: Reg(0), rt2: Reg(1), rn: Reg(2), offset: Offset::Imm(8), index: true, wback: true });
        assert!(unp(&t32(0xe9e0, 0x0102)));
        // LDREX r0, [r1, #4]; STREXD r0, r2, r3, [r1].
        assert_eq!(t32(0xe851, 0x0f01).op, Op::Ldrex { size: Size::W, rt: Reg(0), rt2: Reg::PC, rn: Reg(1), imm: 4 });
        assert_eq!(t32(0xe8c1, 0x2370).op, Op::Strex { size: Size::D, rd: Reg(0), rt: Reg(2), rt2: Reg(3), rn: Reg(1), imm: 0 });
    }

    #[test]
    fn load_store_multiple() {
        // PUSH {r4, lr}; POP {r4, pc}; POP.W {r4, r5}; LDM with bit 13 (0) set.
        assert_eq!(t16(0xb510, OUT).op, Op::Ldm { load: false, mode: Amode::Db, rn: Reg::SP, regs: 0x4010, wback: true, user: false });
        assert_eq!(t16(0xbd10, OUT).op, Op::Ldm { load: true, mode: Amode::Ia, rn: Reg::SP, regs: 0x8010, wback: true, user: false });
        assert!(unp(&t16(0xbd10, FIRST)));
        assert_eq!(t32(0xe8bd, 0x0030).op, Op::Ldm { load: true, mode: Amode::Ia, rn: Reg::SP, regs: 0x30, wback: true, user: false });
        let i = t32(0xe890, 0x2003);
        assert!(unp(&i));
        assert!(matches!(i.op, Op::Ldm { regs: 0x0003, .. }));
        // LDM r0!, {r0, r1} (16-bit) has no writeback; LDM r0, {r1}: wback.
        assert!(matches!(t16(0xc803, OUT).op, Op::Ldm { wback: false, .. }));
        assert!(matches!(t16(0xc802, OUT).op, Op::Ldm { wback: true, .. }));
        // SRSDB sp!, #19; RFEIA r0; SRS to Hyp mode is UNPREDICTABLE.
        assert_eq!(t32(0xe82d, 0xc013).op, Op::Srs { mode: 19, amode: Amode::Db, wback: true });
        assert_eq!(t32(0xe990, 0xc000).op, Op::Rfe { rn: Reg(0), amode: Amode::Ia, wback: false });
        assert!(unp(&t32(0xe82d, 0xc01a)));
        assert!(unp(&t32f(0xe82d, 0xc016, &Features::BASE)));
    }

    #[test]
    fn system_and_extensions() {
        // ERET (Virtualization) or SUBS PC, LR, #0; SUBS PC, LR, #4.
        assert_eq!(t32(0xf3de, 0x8f00).op, Op::Eret);
        let subs = |v| Op::Dp { op: DpOp::Sub, s: true, rd: Reg::PC, rn: Reg::LR, src: imm(v) };
        assert_eq!(t32f(0xf3de, 0x8f00, &Features::BASE).op, subs(0));
        assert_eq!(t32(0xf3de, 0x8f04).op, subs(4));
        assert!(unp(&decode(0xf3de, 0x8f04, FIRST, &Features::ALL)));
        // SMC #0, HVC #0x1234: UNDEFINED without their extensions.
        assert_eq!(t32(0xf7f0, 0x8000).op, Op::Smc { imm: 0 });
        assert!(t32f(0xf7f0, 0x8000, &Features::BASE).is_undefined());
        assert_eq!(t32(0xf7e1, 0x8234).op, Op::Hvc { imm: 0x1234 });
        assert!(t32f(0xf7e1, 0x8234, &Features::BASE).is_undefined());
        // UDF.W #0.
        assert_eq!(t32(0xf7f0, 0xa000).op, Op::Udf { imm: 0 });
        // MRS r0, apsr; MSR APSR_nzcvq, r0; MSR SPSR_fsxc, r0.
        assert_eq!(t32(0xf3ef, 0x8000).op, Op::Mrs { rd: Reg(0), psr: Psr::Cpsr });
        assert_eq!(t32(0xf380, 0x8800).op, Op::Msr { psr: Psr::Cpsr, mask: 8, src: MsrSrc::Reg(Reg(0)) });
        assert_eq!(t32(0xf390, 0x8f00).op, Op::Msr { psr: Psr::Spsr, mask: 15, src: MsrSrc::Reg(Reg(0)) });
        assert!(unp(&t32(0xf380, 0x8000)));
        // MSR r8_usr, r0 and MRS r0, spsr_irq (Banked); an unallocated SYSm.
        assert_eq!(t32(0xf380, 0x8020).op, Op::MsrBanked { rn: Reg(0), sysm: 0 });
        assert_eq!(t32(0xf3f0, 0x8030).op, Op::MrsBanked { rd: Reg(0), sysm: 0x30 });
        assert!(unp(&t32(0xf380, 0x8720)));
        assert!(t32f(0xf380, 0x8020, &Features::BASE).is_undefined());
        // CPSID if, #19; CPS with imod 01 is UNPREDICTABLE.
        assert_eq!(t32(0xf3af, 0x8773).op, Op::Cps { imod: 3, a: false, i: true, f: true, mode: Some(19) });
        assert!(unp(&t32(0xf3af, 0x8200)));
        // Hints: CSDB (UNPREDICTABLE in IT), DBG #5, unallocated NOP.
        assert_eq!(t32(0xf3af, 0x8014).op, Op::Hint(Hint::Csdb));
        assert!(unp(&decode(0xf3af, 0x8014, LAST, &Features::ALL)));
        assert_eq!(t32(0xf3af, 0x80f5).op, Op::Hint(Hint::Dbg(5)));
        assert_eq!(t32(0xf3af, 0x8007).op, Op::Hint(Hint::Nop));
        // DMB ish, CLREX; ENTERX only with ThumbEE.
        assert_eq!(t32(0xf3bf, 0x8f5b).op, Op::Barrier { kind: Barrier::Dmb, option: 11 });
        assert_eq!(t32(0xf3bf, 0x8f2f).op, Op::Clrex);
        assert!(t32(0xf3bf, 0x8f1f).is_undefined());
        let ee = Features { thumbee: true, ..Features::ALL };
        assert_eq!(t32f(0xf3bf, 0x8f1f, &ee).op, Op::Enterx { leave: false });
        // BXJ r0.
        assert_eq!(t32(0xf3c0, 0x8f00).op, Op::Bxj { rm: Reg(0) });
    }

    #[test]
    fn coprocessor() {
        // MCR p15, #0, r0, c1, c0, #0; MRC2 p14 into APSR_nzcv; MCRR p15.
        assert_eq!(t32(0xee01, 0x0f10).op, Op::Mcr { read: false, two: false, coproc: 15, opc1: 0, rt: Reg(0), crn: 1, crm: 0, opc2: 0 });
        assert!(matches!(t32(0xfe11, 0xfe10).op, Op::Mcr { read: true, two: true, coproc: 14, .. }));
        assert_eq!(t32(0xec41, 0x0f02).op, Op::Mcrr { read: false, two: false, coproc: 15, opc1: 0, rt: Reg(0), rt2: Reg(1), crm: 2 });
        // LDC p1, c2, [r0], {4} (unindexed); LDC2 to coproc 10 is UNDEFINED.
        assert_eq!(t32(0xec90, 0x2104).op, Op::Ldc { load: true, two: false, long: false, coproc: 1, crd: 2, rn: Reg(0), imm: 0, index: false, wback: false, option: Some(4) });
        assert!(t32(0xfcd0, 0x0a01).is_undefined());
        // STC with Rn == PC is UNPREDICTABLE in Thumb; op1 00000x UNDEFINED.
        assert!(unp(&t32(0xed8f, 0x1000)));
        assert!(t32(0xec00, 0x1000).is_undefined());
    }

    #[test]
    fn simd_in_it_is_conditional() {
        // VADD.I8 d0, d0, d0 (ARM f2000800) inside `it eq`: conditional
        // (A7.4: the Thumb encodings execute conditionally under IT).
        let i = decode(0xef00, 0x0800, LAST, &Features::ALL);
        assert!(!i.is_undefined());
        assert_eq!(i.cond, Cond::EQ);
    }

    #[test]
    fn reserved_itstate() {
        // ITSTATE<3:0> zero with ITSTATE<7:4> nonzero (A8.3.1).
        assert!(unp(&t16(0x1c88, ItState(0x10))));
    }

    #[test]
    fn total() {
        // Every 16-bit encoding and every first halfword with a spread of
        // second halfwords, in several IT states, decodes without panicking.
        let its = [ItState(0), ItState(0x08), ItState(0x04), ItState(0xe8), ItState(0xf1), ItState(0x10)];
        for f in [Features::ALL, Features::BASE] {
            for h in 0..=0xffffu32 {
                for &it in &its {
                    if thumb_is_32(h as u16) {
                        for h2 in [0u16, 0xffff, 0x8000, 0x0f0f, 0xf0f0, 0x5a5a, 0xa5a5, 0x1234] {
                            let i = decode(h as u16, h2, it, &f);
                            assert_eq!(i.len, 4);
                            let _ = fmt::disasm(&i);
                        }
                    } else {
                        let i = decode(h as u16, 0, it, &f);
                        assert_eq!(i.len, 2);
                        let _ = fmt::disasm(&i);
                    }
                }
            }
        }
    }
}
