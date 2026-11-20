//! The ARM (A32) instruction set's decoding (chapter A5).
//!
//! Each function follows one table of A5 in the table's order, then the
//! decode pseudocode of the A8/B9 encoding it selects: the `SEE`
//! redirections, the UNDEFINED cases, and the UNPREDICTABLE cases, the first
//! of which that holds is reported in [`Inst::unpredictable`]. A bit shown as
//! `(0)` or `(1)` that does not have that value makes the encoding
//! UNPREDICTABLE (A5.1.2) and is checked after the pseudocode's conditions.
//!
//! UNPREDICTABLE cases that depend on the mode or state at run time (SUBS PC,
//! LR and LDM (exception return) in User or System mode, the unprivileged
//! loads and stores in Hyp mode, MRS/MSR (Banked register) accesses invalid
//! for the current mode, SRS of a mode the current state cannot reach, CPS
//! in User mode) are left to the lifter.

use crate::*;

type D = (Op, Option<&'static str>);

const UNDEF: D = (Op::Undefined, None);

#[inline]
fn bit(w: u32, n: u32) -> bool {
    (w >> n) & 1 == 1
}

/// Bits `hi:lo` of `w`.
#[inline]
fn fld(w: u32, hi: u32, lo: u32) -> u32 {
    (w >> lo) & ((1u32 << (hi - lo + 1)) - 1)
}

#[inline]
fn reg(w: u32, lo: u32) -> Reg {
    Reg::of(w >> lo)
}

/// A bit shown as `(0)` that is not 0.
#[inline]
fn sbz(w: u32, mask: u32) -> bool {
    w & mask != 0
}

/// A bit shown as `(1)` that is not 1.
#[inline]
fn sbo(w: u32, mask: u32) -> bool {
    w & mask != mask
}

/// The operation, with the first of `rules` that holds as the UNPREDICTABLE
/// reason.
fn rules(op: Op, rules: &[(bool, &'static str)]) -> D {
    (op, rules.iter().find(|r| r.0).map(|r| r.1))
}

/// `ARMExpandImm_C(imm12, APSR.C)` (A5.2.4): the carry out is APSR.C
/// unchanged (`None`) for a rotation of 0, the constant's bit 31 otherwise.
pub fn expand_imm(imm12: u32) -> Operand {
    let rot = (imm12 >> 8) & 15;
    let value = (imm12 & 0xff).rotate_right(2 * rot);
    Operand::Imm { value, carry: if rot == 0 { None } else { Some(value >> 31 == 1) } }
}

/// A signed offset from an unsigned magnitude and the U bit.
#[inline]
fn signed(imm: u32, add: bool) -> i32 {
    if add {
        imm as i32
    } else {
        -(imm as i32)
    }
}

/// `registers<n> == '1'`.
#[inline]
fn has(regs: u32, r: Reg) -> bool {
    regs >> r.n() & 1 == 1
}

pub fn decode(word: u32, f: &Features) -> Inst {
    let cond = word >> 28;
    let (op, unpredictable) = if cond == 0b1111 { unconditional(word, f) } else { conditional(word, f) };
    Inst {
        op,
        cond: Cond(if cond == 0b1111 { 14 } else { cond as u8 }),
        len: 4,
        raw: word,
        set: InstrSet::Arm,
        unpredictable,
    }
}

// A5.1 ARM instruction set encoding, Table A5-1 (cond not 1111).
fn conditional(w: u32, f: &Features) -> D {
    match fld(w, 27, 25) {
        0b000 | 0b001 => dp_misc(w, f),
        0b010 => ldst_word(w),
        0b011 if !bit(w, 4) => ldst_word(w),
        0b011 => media(w, f),
        0b100 | 0b101 => branch_block(w),
        _ => coproc(w, f, false),
    }
}

// -- A5.2 Data-processing and miscellaneous instructions --------------------

// Table A5-2: op (25), op1 (24:20), op2 (7:4).
fn dp_misc(w: u32, f: &Features) -> D {
    let op1 = fld(w, 24, 20);
    let op2 = fld(w, 7, 4);
    let misc_space = op1 & 0b11001 == 0b10000; // 10xx0
    if !bit(w, 25) {
        if op2 & 1 == 0 {
            return if !misc_space {
                dp_reg(w)
            } else if op2 & 8 == 0 {
                misc(w, f)
            } else {
                halfword_mul(w)
            };
        }
        if op2 & 8 == 0 {
            return if misc_space { misc(w, f) } else { dp_regshift(w) };
        }
        if op2 == 0b1001 {
            return if op1 & 0x10 == 0 { multiply(w) } else { sync(w) };
        }
        // 1011, 1101, 1111 (A5.2.8 sends the unprivileged forms to A5.2.9).
        return extra_ldst(w);
    }
    match op1 {
        // A8.8.103 MOV (immediate) A2 (MOVW).
        0b10000 => {
            let rd = reg(w, 12);
            let imm = (fld(w, 19, 16) << 12 | fld(w, 11, 0)) as u16;
            rules(Op::Movw { rd, imm }, &[(rd.is_pc(), "A8.8.103 MOVW: d == 15")])
        }
        // A8.8.107 MOVT.
        0b10100 => {
            let rd = reg(w, 12);
            let imm = (fld(w, 19, 16) << 12 | fld(w, 11, 0)) as u16;
            rules(Op::Movt { rd, imm }, &[(rd.is_pc(), "A8.8.107 MOVT: d == 15")])
        }
        0b10010 | 0b10110 => msr_imm_hints(w),
        _ => dp_imm(w),
    }
}

const DP_OPS: [DpOp; 16] = [
    DpOp::And,
    DpOp::Eor,
    DpOp::Sub,
    DpOp::Rsb,
    DpOp::Add,
    DpOp::Adc,
    DpOp::Sbc,
    DpOp::Rsc,
    DpOp::Tst,
    DpOp::Teq,
    DpOp::Cmp,
    DpOp::Cmn,
    DpOp::Orr,
    DpOp::Mov,
    DpOp::Bic,
    DpOp::Mvn,
];

/// The data-processing operation and the `(0)` fields shared by all three
/// forms: a test's Rd and a MOV's or MVN's Rn.
fn dp(w: u32, src: Operand, first: Option<&'static str>) -> D {
    let op = DP_OPS[fld(w, 24, 21) as usize];
    let s = bit(w, 20);
    let unp = first.or(if op.is_test() && sbz(w, 0xf000) {
        Some("A8.8 TST/TEQ/CMP/CMN: (0) bits 15:12 (Rd) not 0 (A5.1.2)")
    } else if !op.has_rn() && sbz(w, 0xf_0000) {
        Some("A8.8 MOV/MVN and the shifts: (0) bits 19:16 (Rn) not 0 (A5.1.2)")
    } else {
        None
    });
    (Op::Dp { op, s, rd: reg(w, 12), rn: reg(w, 16), src }, unp)
}

// A5.2.1 Data-processing (register), Table A5-3: AND..MVN (register),
// MOV (register, ARM), LSL/LSR/ASR/ROR (immediate), RRX. The PC is allowed
// in every register field; Rd = PC with S is SUBS PC, LR (B9.3.20).
fn dp_reg(w: u32) -> D {
    let (shift, amount) = Shift::decode_imm(fld(w, 6, 5), fld(w, 11, 7));
    dp(w, Operand::RegImm { rm: reg(w, 0), shift, amount }, None)
}

// A5.2.2 Data-processing (register-shifted register), Table A5-4: the
// register-shifted forms and LSL/LSR/ASR/ROR (register). The register
// shifted (Rm, bits 3:0) is LSL's <Rn>, the amount register (Rs, 11:8) its
// <Rm>.
fn dp_regshift(w: u32) -> D {
    let op = DP_OPS[fld(w, 24, 21) as usize];
    let (rd, rn, rm, rs) = (reg(w, 12), reg(w, 16), reg(w, 0), reg(w, 8));
    let pc = (!op.is_test() && rd.is_pc()) || (op.has_rn() && rn.is_pc()) || rm.is_pc() || rs.is_pc();
    let first = if pc { Some("A8.8 (register-shifted register): d, n, m or s == 15") } else { None };
    dp(w, Operand::RegReg { rm, shift: Shift::of_type(fld(w, 6, 5)), rs }, first)
}

// A5.2.3 Data-processing (immediate), Table A5-5. ADR (A8.8.12) is ADD/SUB
// with Rn = PC and S clear, decoded as that ADD/SUB.
fn dp_imm(w: u32) -> D {
    dp(w, expand_imm(fld(w, 11, 0)), None)
}

// A5.2.11 MSR (immediate), and hints, Table A5-13: op (22), op1 (19:16),
// op2 (7:0).
fn msr_imm_hints(w: u32) -> D {
    let r = bit(w, 22);
    let mask = fld(w, 19, 16) as u8;
    if !r && mask == 0 {
        // A8.8.120 NOP, A8.8.427 YIELD, A8.8.425 WFE, A8.8.426 WFI,
        // A8.8.169 SEV, A8.8.42 CSDB, A8.8.43 DBG. The unallocated hints
        // behave as NOP, and are NOP's encoding with another op2.
        let op2 = fld(w, 7, 0);
        let h = match op2 {
            0 => Hint::Nop,
            1 => Hint::Yield,
            2 => Hint::Wfe,
            3 => Hint::Wfi,
            4 => Hint::Sev,
            0x14 => Hint::Csdb,
            0xf0..=0xff => Hint::Dbg((op2 & 15) as u8),
            _ => Hint::Nop,
        };
        return rules(
            Op::Hint(h),
            &[
                (h == Hint::Csdb && w >> 28 != 0b1110, "A8.8.42 CSDB: cond != '1110'"),
                (sbo(w, 0xf000) || sbz(w, 0xf00), "A5.2.11 hints: (1) bits 15:12 / (0) bits 11:8 (A5.1.2)"),
            ],
        );
    }
    // A8.8.112 MSR (immediate) (application level: op1 0100, 1x00) and
    // B9.3.11 MSR (immediate) (system level: op1 xx01, xx1x, or R).
    let v = (fld(w, 7, 0)).rotate_right(2 * fld(w, 11, 8));
    rules(
        Op::Msr { psr: if r { Psr::Spsr } else { Psr::Cpsr }, mask, src: MsrSrc::Imm(v) },
        &[
            (mask == 0, "B9.3.11 MSR (immediate): mask == '0000'"),
            (sbo(w, 0xf000), "MSR (immediate): (1) bits 15:12 (A5.1.2)"),
        ],
    )
}

/// Table B9-1 and B9-2: the R:SYSm values that name a Banked register; the
/// others are UNPREDICTABLE whatever the mode.
fn banked_valid(sysm: u8) -> bool {
    let m = sysm & 31;
    if sysm & 32 == 0 {
        match m >> 3 {
            0 | 1 => m & 7 != 7,
            2 => true,
            _ => m & 4 != 0,
        }
    } else {
        matches!(m, 0b01110 | 0b10000 | 0b10010 | 0b10100 | 0b10110 | 0b11100 | 0b11110)
    }
}

// A5.2.12 Miscellaneous instructions, Table A5-14: op (22:21), op1
// (19:16), B (9), op2 (6:4). Other encodings are UNDEFINED.
fn misc(w: u32, f: &Features) -> D {
    let op = fld(w, 22, 21);
    let op2 = fld(w, 6, 4);
    let cond_al = w >> 28 == 0b1110;
    match op2 {
        0b000 if bit(w, 9) => {
            if !f.virtualization {
                return UNDEF;
            }
            let sysm = ((bit(w, 22) as u8) << 5) | ((bit(w, 8) as u8) << 4) | fld(w, 19, 16) as u8;
            if op & 1 == 0 {
                // B9.3.9 MRS (Banked register).
                let rd = reg(w, 12);
                rules(
                    Op::MrsBanked { rd, sysm },
                    &[
                        (rd.is_pc(), "B9.3.9 MRS (Banked register): d == 15"),
                        (!banked_valid(sysm), "B9.2.3 MRS (Banked register): R:SYSm is UNPREDICTABLE (Table B9-1/B9-2)"),
                        (sbz(w, 0xc0f), "B9.3.9 MRS (Banked register): (0) bits 11:10, 3:0 (A5.1.2)"),
                    ],
                )
            } else {
                // B9.3.10 MSR (Banked register).
                let rn = reg(w, 0);
                rules(
                    Op::MsrBanked { rn, sysm },
                    &[
                        (rn.is_pc(), "B9.3.10 MSR (Banked register): n == 15"),
                        (!banked_valid(sysm), "B9.2.3 MSR (Banked register): R:SYSm is UNPREDICTABLE (Table B9-1/B9-2)"),
                        (sbo(w, 0xf000) || sbz(w, 0xc00), "B9.3.10 MSR (Banked register): (1) bits 15:12 / (0) bits 11:10 (A5.1.2)"),
                    ],
                )
            }
        }
        0b000 => {
            let psr = if bit(w, 22) { Psr::Spsr } else { Psr::Cpsr };
            if op & 1 == 0 {
                // A8.8.110 / B9.3.8 MRS.
                let rd = reg(w, 12);
                rules(
                    Op::Mrs { rd, psr },
                    &[
                        (rd.is_pc(), "A8.8.110 MRS: d == 15"),
                        (sbo(w, 0xf_0000) || sbz(w, 0xd0f), "A8.8.110 MRS: (1) bits 19:16 / (0) bits 11:10, 8, 3:0 (A5.1.2)"),
                    ],
                )
            } else {
                // A8.8.113 MSR (register) (op1 xx00) / B9.3.12 MSR (register).
                let mask = fld(w, 19, 16) as u8;
                let rn = reg(w, 0);
                rules(
                    Op::Msr { psr, mask, src: MsrSrc::Reg(rn) },
                    &[
                        (mask == 0, "A8.8.113/B9.3.12 MSR (register): mask == '0000'"),
                        (rn.is_pc(), "A8.8.113 MSR (register): n == 15"),
                        (sbo(w, 0xf000) || sbz(w, 0xd00), "MSR (register): (1) bits 15:12 / (0) bits 11:10, 8 (A5.1.2)"),
                    ],
                )
            }
        }
        // A8.8.27 BX.
        0b001 if op == 0b01 => rules(Op::Bx { rm: reg(w, 0) }, &[(sbo(w, 0xfff00), "A8.8.27 BX: (1) bits 19:8 (A5.1.2)")]),
        // A8.8.33 CLZ.
        0b001 if op == 0b11 => {
            let (rd, rm) = (reg(w, 12), reg(w, 0));
            rules(
                Op::Clz { rd, rm },
                &[
                    (rd.is_pc() || rm.is_pc(), "A8.8.33 CLZ: d == 15 || m == 15"),
                    (sbo(w, 0xf_0f00), "A8.8.33 CLZ: (1) bits 19:16, 11:8 (A5.1.2)"),
                ],
            )
        }
        // A8.8.28 BXJ: BX, as ARMv7-A's Jazelle is the trivial one.
        0b010 if op == 0b01 => {
            let rm = reg(w, 0);
            rules(
                Op::Bxj { rm },
                &[(rm.is_pc(), "A8.8.28 BXJ: m == 15"), (sbo(w, 0xfff00), "A8.8.28 BXJ: (1) bits 19:8 (A5.1.2)")],
            )
        }
        // A8.8.26 BLX (register).
        0b011 if op == 0b01 => {
            let rm = reg(w, 0);
            rules(
                Op::BlxReg { rm },
                &[(rm.is_pc(), "A8.8.26 BLX (register): m == 15"), (sbo(w, 0xfff00), "A8.8.26 BLX (register): (1) bits 19:8 (A5.1.2)")],
            )
        }
        // A5.2.6 Saturating addition and subtraction, Table A5-8: A8.8.135
        // QADD, A8.8.142 QSUB, A8.8.139 QDADD, A8.8.140 QDSUB.
        0b101 => {
            let (rd, rn, rm) = (reg(w, 12), reg(w, 16), reg(w, 0));
            rules(
                Op::Qadd { sub: op & 1 == 1, double: op & 2 == 2, rd, rm, rn },
                &[
                    (rd.is_pc() || rn.is_pc() || rm.is_pc(), "A8.8.135 QADD/QSUB/QDADD/QDSUB: d, n or m == 15"),
                    (sbz(w, 0xf00), "A8.8.135 QADD/QSUB/QDADD/QDSUB: (0) bits 11:8 (A5.1.2)"),
                ],
            )
        }
        // B9.3.3 ERET (Virtualization Extensions). UNPREDICTABLE in User
        // or System mode and in Debug state: the lifter's.
        0b110 if op == 0b11 => {
            if !f.virtualization {
                return UNDEF;
            }
            rules(Op::Eret, &[(sbz(w, 0xfff00) || w & 15 != 0b1110, "B9.3.3 ERET: (0) bits 19:8 / (1)(1)(1)(0) bits 3:0 (A5.1.2)")])
        }
        // A8.8.24 BKPT.
        0b111 if op == 0b01 => {
            let imm = (fld(w, 19, 8) << 4 | fld(w, 3, 0)) as u16;
            rules(Op::Bkpt { imm }, &[(!cond_al, "A8.8.24 BKPT: cond != '1110'")])
        }
        // B9.3.4 HVC (Virtualization Extensions).
        0b111 if op == 0b10 => {
            if !f.virtualization {
                return UNDEF;
            }
            let imm = (fld(w, 19, 8) << 4 | fld(w, 3, 0)) as u16;
            rules(Op::Hvc { imm }, &[(!cond_al, "B9.3.4 HVC: cond != '1110'")])
        }
        // B9.3.14 SMC (Security Extensions).
        0b111 if op == 0b11 => {
            if !f.security {
                return UNDEF;
            }
            rules(Op::Smc { imm: fld(w, 3, 0) as u8 }, &[(sbz(w, 0xfff00), "B9.3.14 SMC: (0) bits 19:8 (A5.1.2)")])
        }
        _ => UNDEF,
    }
}

// A5.2.7 Halfword multiply and multiply accumulate, Table A5-9: op1
// (22:21), op (5).
fn halfword_mul(w: u32) -> D {
    let (r16, r12, rm, rn) = (reg(w, 16), reg(w, 12), reg(w, 8), reg(w, 0));
    let (m_top, n_top) = (bit(w, 6), bit(w, 5));
    let pc3 = r16.is_pc() || rn.is_pc() || rm.is_pc();
    match fld(w, 22, 21) {
        // A8.8.177 SMLA<x><y>.
        0b00 => rules(
            Op::Smulxy { rd: r16, rn, rm, ra: Some(r12), n_top, m_top },
            &[(pc3 || r12.is_pc(), "A8.8.177 SMLA<x><y>: d, n, m or a == 15")],
        ),
        // A8.8.182 SMLAW<y>.
        0b01 if !bit(w, 5) => rules(
            Op::Smulwy { rd: r16, rn, rm, ra: Some(r12), m_top },
            &[(pc3 || r12.is_pc(), "A8.8.182 SMLAW<y>: d, n, m or a == 15")],
        ),
        // A8.8.191 SMULW<y>.
        0b01 => rules(
            Op::Smulwy { rd: r16, rn, rm, ra: None, m_top },
            &[(pc3, "A8.8.191 SMULW<y>: d, n or m == 15"), (sbz(w, 0xf000), "A8.8.191 SMULW<y>: (0) bits 15:12 (A5.1.2)")],
        ),
        // A8.8.180 SMLAL<x><y>.
        0b10 => rules(
            Op::Smlalxy { rdlo: r12, rdhi: r16, rn, rm, n_top, m_top },
            &[
                (pc3 || r12.is_pc(), "A8.8.180 SMLAL<x><y>: dLo, dHi, n or m == 15"),
                (r12 == r16, "A8.8.180 SMLAL<x><y>: dHi == dLo"),
            ],
        ),
        // A8.8.189 SMUL<x><y>.
        _ => rules(
            Op::Smulxy { rd: r16, rn, rm, ra: None, n_top, m_top },
            &[(pc3, "A8.8.189 SMUL<x><y>: d, n or m == 15"), (sbz(w, 0xf000), "A8.8.189 SMUL<x><y>: (0) bits 15:12 (A5.1.2)")],
        ),
    }
}

// A5.2.5 Multiply and multiply accumulate, Table A5-7: op (23:20).
fn multiply(w: u32) -> D {
    let (r16, r12, rm, rn) = (reg(w, 16), reg(w, 12), reg(w, 8), reg(w, 0));
    let s = bit(w, 20);
    let pc3 = r16.is_pc() || rn.is_pc() || rm.is_pc();
    let long = |kind: MulLong, s: bool, name: &'static str, same: &'static str| {
        rules(
            Op::MulLong { kind, s, rdlo: r12, rdhi: r16, rn, rm },
            &[(pc3 || r12.is_pc(), name), (r12 == r16, same)],
        )
    };
    match fld(w, 23, 21) {
        // A8.8.115 MUL.
        0b000 => rules(
            Op::Mul { s, rd: r16, rn, rm },
            &[(pc3, "A8.8.115 MUL: d, n or m == 15"), (sbz(w, 0xf000), "A8.8.115 MUL: (0) bits 15:12 (A5.1.2)")],
        ),
        // A8.8.101 MLA.
        0b001 => rules(Op::Mla { s, sub: false, rd: r16, rn, rm, ra: r12 }, &[(pc3 || r12.is_pc(), "A8.8.101 MLA: d, n, m or a == 15")]),
        // A8.8.256 UMAAL; 0101 UNDEFINED.
        0b010 if !s => long(MulLong::Umaal, false, "A8.8.256 UMAAL: dLo, dHi, n or m == 15", "A8.8.256 UMAAL: dHi == dLo"),
        // A8.8.102 MLS; 0111 UNDEFINED.
        0b011 if !s => rules(Op::Mla { s: false, sub: true, rd: r16, rn, rm, ra: r12 }, &[(pc3 || r12.is_pc(), "A8.8.102 MLS: d, n, m or a == 15")]),
        0b010 | 0b011 => UNDEF,
        // A8.8.258 UMULL, A8.8.257 UMLAL, A8.8.190 SMULL, A8.8.179 SMLAL.
        0b100 => long(MulLong::Umull, s, "A8.8.258 UMULL: dLo, dHi, n or m == 15", "A8.8.258 UMULL: dHi == dLo"),
        0b101 => long(MulLong::Umlal, s, "A8.8.257 UMLAL: dLo, dHi, n or m == 15", "A8.8.257 UMLAL: dHi == dLo"),
        0b110 => long(MulLong::Smull, s, "A8.8.190 SMULL: dLo, dHi, n or m == 15", "A8.8.190 SMULL: dHi == dLo"),
        _ => long(MulLong::Smlal, s, "A8.8.179 SMLAL: dLo, dHi, n or m == 15", "A8.8.179 SMLAL: dHi == dLo"),
    }
}

// A5.2.10 Synchronization primitives, Table A5-12: op (23:20). Other
// encodings are UNDEFINED.
fn sync(w: u32) -> D {
    let (rn, r12, r0) = (reg(w, 16), reg(w, 12), reg(w, 0));
    let op = fld(w, 23, 20);
    if op & 0b1011 == 0 {
        // A8.8.230 SWP, SWPB. Optional in ARMv7VE and disabled by
        // SCTLR.SW with the Multiprocessing Extensions: the lifter's.
        let (rt, rt2) = (r12, r0);
        return rules(
            Op::Swp { byte: bit(w, 22), rt, rt2, rn },
            &[
                (rt.is_pc() || rt2.is_pc() || rn.is_pc() || rn == rt || rn == rt2, "A8.8.230 SWP/SWPB: t, t2 or n == 15, or n == t or t2"),
                (sbz(w, 0xf00), "A8.8.230 SWP/SWPB: (0) bits 11:8 (A5.1.2)"),
            ],
        );
    }
    if op & 0b1000 == 0 {
        return UNDEF;
    }
    let size = match op >> 1 & 3 {
        0 => Size::W,
        1 => Size::D,
        2 => Size::B,
        _ => Size::H,
    };
    let dual = size == Size::D;
    if op & 1 == 1 {
        // A8.8.76 LDREX, A8.8.78 LDREXD, A8.8.77 LDREXB, A8.8.79 LDREXH.
        // `rt2` is t+1 for LDREXD, unused (the PC) otherwise.
        let rt = r12;
        let rt2 = if dual { Reg::of(rt.n() + 1) } else { Reg::PC };
        let bad = if dual {
            (rt.n() & 1 == 1 || rt.n() == 14 || rn.is_pc(), "A8.8.78 LDREXD: Rt<0> == '1' || Rt == '1110' || n == 15")
        } else {
            (rt.is_pc() || rn.is_pc(), "A8.8.76 LDREX{B,H}: t == 15 || n == 15")
        };
        rules(Op::Ldrex { size, rt, rt2, rn, imm: 0 }, &[bad, (sbo(w, 0xf0f), "A8.8.76 LDREX: (1) bits 11:8, 3:0 (A5.1.2)")])
    } else {
        // A8.8.213 STREX, A8.8.215 STREXD, A8.8.214 STREXB, A8.8.216 STREXH.
        let (rd, rt) = (r12, r0);
        let rt2 = if dual { Reg::of(rt.n() + 1) } else { Reg::PC };
        let bad = if dual {
            (
                rd.is_pc() || rt.n() & 1 == 1 || rt.n() == 14 || rn.is_pc(),
                "A8.8.215 STREXD: d == 15 || Rt<0> == '1' || Rt == '1110' || n == 15",
            )
        } else {
            (rd.is_pc() || rt.is_pc() || rn.is_pc(), "A8.8.213 STREX{B,H}: d, t or n == 15")
        };
        let same = if dual {
            (rd == rn || rd == rt || rd == rt2, "A8.8.215 STREXD: d == n || d == t || d == t2")
        } else {
            (rd == rn || rd == rt, "A8.8.213 STREX{B,H}: d == n || d == t")
        };
        rules(Op::Strex { size, rd, rt, rt2, rn, imm: 0 }, &[bad, same, (sbo(w, 0xf00), "A8.8.213 STREX: (1) bits 11:8 (A5.1.2)")])
    }
}

// A5.2.8 Extra load/store instructions, Table A5-10, and A5.2.9 Extra
// load/store instructions, unprivileged, Table A5-11: op1 (24:20) is
// P U I W L, op2 (6:5).
fn extra_ldst(w: u32) -> D {
    let (p, u, i, wb, l) = (bit(w, 24), bit(w, 23), bit(w, 22), bit(w, 21), bit(w, 20));
    let op2 = fld(w, 6, 5);
    let (rn, rt, rm) = (reg(w, 16), reg(w, 12), reg(w, 0));
    let (n, t, m) = (rn.n(), rt.n(), rm.n());
    let imm8 = fld(w, 11, 8) << 4 | fld(w, 3, 0);
    let offset = if i { Offset::Imm(signed(imm8, u)) } else { Offset::Reg { rm, shift: Shift::Lsl, amount: 0, add: u } };
    let sbz_reg = (!i && sbz(w, 0xf00), "A8.8 extra load/store (register): (0) bits 11:8 (A5.1.2)");

    // A5.2.9: A8.8.220 STRHT, A8.8.84 LDRHT, A8.8.88 LDRSBT, A8.8.92
    // LDRSHT (UNPREDICTABLE in Hyp mode: the lifter's).
    if !p && wb && (op2 == 0b01 || l) {
        let (size, signed) = match op2 {
            0b01 => (Size::H, false),
            0b10 => (Size::B, true),
            _ => (Size::H, true),
        };
        return rules(
            Op::Ldst { load: l, size, signed, user: true, rt, rn, offset, index: false, wback: true },
            &[(t == 15 || n == 15 || n == t || (!i && m == 15), "A8.8.84 LDRHT/LDRSBT/LDRSHT/STRHT: t or n == 15, n == t, or m == 15"), sbz_reg],
        );
    }

    let wback = !p || wb;
    match (op2, l) {
        // LDRD (A8.8.73-A8.8.75) and STRD (A8.8.211, A8.8.212).
        (0b10, false) | (0b11, false) => {
            let load = op2 == 0b10;
            let rt2 = Reg::of(t + 1);
            let t2 = t + 1;
            let odd = (t & 1 == 1, "A8.8.73 LDRD/STRD: Rt<0> == '1'");
            if load && i && n == 15 {
                // A8.8.74 LDRD (literal): P is (1), W is (0).
                return rules(
                    Op::Ldrd { load, rt, rt2, rn, offset, index: p, wback },
                    &[odd, (t2 == 15, "A8.8.74 LDRD (literal): t2 == 15"), (!p || wb, "A8.8.74 LDRD (literal): (1) bit 24 / (0) bit 21 (A5.1.2)")],
                );
            }
            let pw = (!p && wb, "A8.8.73 LDRD/STRD: P == '0' && W == '1'");
            let op = Op::Ldrd { load, rt, rt2, rn, offset, index: p, wback };
            match (load, i) {
                (true, true) => rules(
                    op,
                    &[odd, pw, (wback && (n == t || n == t2), "A8.8.73 LDRD (immediate): wback && (n == t || n == t2)"), (t2 == 15, "A8.8.73 LDRD (immediate): t2 == 15")],
                ),
                (true, false) => rules(
                    op,
                    &[
                        odd,
                        pw,
                        (t2 == 15 || m == 15 || m == t || m == t2, "A8.8.75 LDRD (register): t2 == 15 || m == 15 || m == t || m == t2"),
                        (wback && (n == 15 || n == t || n == t2), "A8.8.75 LDRD (register): wback && (n == 15 || n == t || n == t2)"),
                        sbz_reg,
                    ],
                ),
                (false, true) => rules(
                    op,
                    &[odd, pw, (wback && (n == 15 || n == t || n == t2), "A8.8.211 STRD (immediate): wback && (n == 15 || n == t || n == t2)"), (t2 == 15, "A8.8.211 STRD (immediate): t2 == 15")],
                ),
                (false, false) => rules(
                    op,
                    &[
                        odd,
                        pw,
                        (t2 == 15 || m == 15, "A8.8.212 STRD (register): t2 == 15 || m == 15"),
                        (wback && (n == 15 || n == t || n == t2), "A8.8.212 STRD (register): wback && (n == 15 || n == t || n == t2)"),
                        sbz_reg,
                    ],
                ),
            }
        }
        // A8.8.218 STRH (immediate, ARM), A8.8.219 STRH (register).
        (_, false) => rules(
            Op::Ldst { load: false, size: Size::H, signed: false, user: false, rt, rn, offset, index: p, wback },
            &[
                (t == 15 || (!i && m == 15), "A8.8.218 STRH: t == 15 (|| m == 15)"),
                (wback && (n == 15 || n == t), "A8.8.218 STRH: wback && (n == 15 || n == t)"),
                sbz_reg,
            ],
        ),
        // A8.8.81-A8.8.83 LDRH, A8.8.85-A8.8.87 LDRSB, A8.8.89-A8.8.91 LDRSH.
        (_, true) => {
            let (size, signed) = match op2 {
                0b01 => (Size::H, false),
                0b10 => (Size::B, true),
                _ => (Size::H, true),
            };
            let op = Op::Ldst { load: true, size, signed, user: false, rt, rn, offset, index: p, wback };
            if i && n == 15 {
                // A8.8.82 LDRH (literal), A8.8.86 LDRSB (literal), A8.8.90
                // LDRSH (literal): P == W is UNPREDICTABLE (P0 W1 is the
                // unprivileged form).
                rules(op, &[(p == wb, "A8.8.82 LDRH/LDRSB/LDRSH (literal): P == W"), (t == 15, "A8.8.82 LDRH/LDRSB/LDRSH (literal): t == 15")])
            } else if i {
                rules(op, &[(t == 15 || (wback && n == t), "A8.8.81 LDRH/LDRSB/LDRSH (immediate): t == 15 || (wback && n == t)")])
            } else {
                rules(
                    op,
                    &[
                        (t == 15 || m == 15, "A8.8.83 LDRH/LDRSB/LDRSH (register): t == 15 || m == 15"),
                        (wback && (n == 15 || n == t), "A8.8.83 LDRH/LDRSB/LDRSH (register): wback && (n == 15 || n == t)"),
                        sbz_reg,
                    ],
                )
            }
        }
    }
}

// -- A5.3 Load/store word and unsigned byte -----------------------------------

// Table A5-15: A (25), op1 (24:20) is P U B W L, B (4) is 0 for A = 1.
fn ldst_word(w: u32) -> D {
    let (a, p, u, byte, wb, l) = (bit(w, 25), bit(w, 24), bit(w, 23), bit(w, 22), bit(w, 21), bit(w, 20));
    let (rn, rt, rm) = (reg(w, 16), reg(w, 12), reg(w, 0));
    let (n, t, m) = (rn.n(), rt.n(), rm.n());
    let offset = if a {
        let (shift, amount) = Shift::decode_imm(fld(w, 6, 5), fld(w, 11, 7));
        Offset::Reg { rm, shift, amount, add: u }
    } else {
        Offset::Imm(signed(fld(w, 11, 0), u))
    };
    let size = if byte { Size::B } else { Size::W };
    let mpc = a && m == 15;

    if !p && wb {
        // A8.8.221 STRT, A8.8.93 LDRT, A8.8.210 STRBT, A8.8.72 LDRBT
        // (UNPREDICTABLE in Hyp mode: the lifter's).
        let bad = if !l && !byte {
            (n == 15 || n == t || mpc, "A8.8.221 STRT: n == 15 || n == t (|| m == 15)")
        } else {
            (t == 15 || n == 15 || n == t || mpc, "A8.8.93 LDRT/LDRBT/STRBT: t == 15 || n == 15 || n == t (|| m == 15)")
        };
        return rules(Op::Ldst { load: l, size, signed: false, user: true, rt, rn, offset, index: false, wback: true }, &[bad]);
    }

    let wback = !p || wb;
    let op = Op::Ldst { load: l, size, signed: false, user: false, rt, rn, offset, index: p, wback };
    match (l, byte, a) {
        // A8.8.65 LDR (literal), A8.8.70 LDRB (literal).
        (true, _, false) if n == 15 => rules(
            op,
            &[(p == wb, "A8.8.65 LDR/LDRB (literal): P == W"), (byte && t == 15, "A8.8.70 LDRB (literal): t == 15")],
        ),
        // A8.8.64 LDR (immediate, ARM) (single-register POP is A8.8.133 A2).
        (true, false, false) => rules(op, &[(wback && n == t, "A8.8.64 LDR (immediate, ARM): wback && n == t")]),
        // A8.8.67 LDR (register, ARM).
        (true, false, true) => rules(
            op,
            &[(m == 15, "A8.8.67 LDR (register, ARM): m == 15"), (wback && (n == 15 || n == t), "A8.8.67 LDR (register, ARM): wback && (n == 15 || n == t)")],
        ),
        // A8.8.69 LDRB (immediate, ARM).
        (true, true, false) => rules(op, &[(t == 15 || (wback && n == t), "A8.8.69 LDRB (immediate, ARM): t == 15 || (wback && n == t)")]),
        // A8.8.71 LDRB (register).
        (true, true, true) => rules(
            op,
            &[(t == 15 || m == 15, "A8.8.71 LDRB (register): t == 15 || m == 15"), (wback && (n == 15 || n == t), "A8.8.71 LDRB (register): wback && (n == 15 || n == t)")],
        ),
        // A8.8.205 STR (immediate, ARM) (single-register PUSH is A8.8.134 A2).
        (false, false, false) => rules(op, &[(wback && (n == 15 || n == t), "A8.8.205 STR (immediate, ARM): wback && (n == 15 || n == t)")]),
        // A8.8.206 STR (register).
        (false, false, true) => rules(
            op,
            &[(m == 15, "A8.8.206 STR (register): m == 15"), (wback && (n == 15 || n == t), "A8.8.206 STR (register): wback && (n == 15 || n == t)")],
        ),
        // A8.8.208 STRB (immediate, ARM), A8.8.209 STRB (register).
        (false, true, _) => rules(
            op,
            &[(t == 15 || mpc, "A8.8.208 STRB: t == 15 (|| m == 15)"), (wback && (n == 15 || n == t), "A8.8.208 STRB: wback && (n == 15 || n == t)")],
        ),
    }
}

// -- A5.4 Media instructions ------------------------------------------------

// Table A5-16: op1 (24:20), op2 (7:5), Rd (15:12), Rn (3:0). Other
// encodings are UNDEFINED.
fn media(w: u32, f: &Features) -> D {
    let op1 = fld(w, 24, 20);
    let op2 = fld(w, 7, 5);
    match op1 >> 3 {
        0b00 => parallel(w),
        0b01 => pack(w),
        0b10 => signed_mul(w, f),
        _ => {
            let (r16, r12, r8, r0) = (reg(w, 16), reg(w, 12), reg(w, 8), reg(w, 0));
            match op1 {
                // A8.8.265 USAD8, A8.8.266 USADA8.
                0b11000 if op2 == 0 => rules(
                    Op::Usad8 { rd: r16, rn: r0, rm: r8, ra: if r12.is_pc() { None } else { Some(r12) } },
                    &[(r16.is_pc() || r0.is_pc() || r8.is_pc(), "A8.8.265 USAD8/USADA8: d, n or m == 15")],
                ),
                // A8.8.165 SBFX, A8.8.247 UBFX.
                0b11010 | 0b11011 | 0b11110 | 0b11111 if op2 & 3 == 0b10 => {
                    let lsb = fld(w, 11, 7) as u8;
                    let widthm1 = fld(w, 20, 16) as u8;
                    rules(
                        Op::Bfx { signed: op1 & 4 == 0, rd: r12, rn: r0, lsb, width: widthm1 + 1 },
                        &[
                            (r12.is_pc() || r0.is_pc(), "A8.8.165 SBFX/UBFX: d == 15 || n == 15"),
                            (lsb + widthm1 > 31, "A8.8.165 SBFX/UBFX: lsbit + widthminus1 > 31 (Operation)"),
                        ],
                    )
                }
                // A8.8.19 BFC (Rn = 1111), A8.8.20 BFI.
                0b11100 | 0b11101 if op2 & 3 == 0 => {
                    let (lsb, msb) = (fld(w, 11, 7) as u8, fld(w, 20, 16) as u8);
                    rules(
                        Op::Bfi { rd: r12, rn: if r0.is_pc() { None } else { Some(r0) }, lsb, msb },
                        &[(r12.is_pc(), "A8.8.19 BFC/BFI: d == 15"), (msb < lsb, "A8.8.19 BFC/BFI: msbit < lsbit (Operation)")],
                    )
                }
                // A8.8.248 UDF: the mnemonic is for cond 1110 only; the
                // other conditions are permanently UNDEFINED too.
                0b11111 if op2 == 0b111 => {
                    if w >> 28 == 0b1110 {
                        (Op::Udf { imm: (fld(w, 19, 8) << 4 | fld(w, 3, 0)) as u16 }, None)
                    } else {
                        UNDEF
                    }
                }
                _ => UNDEF,
            }
        }
    }
}

// A5.4.1 / A5.4.2 Parallel addition and subtraction, Tables A5-17 and
// A5-18: U (22), op1 (21:20), op2 (7:5). Other encodings are UNDEFINED.
fn parallel(w: u32) -> D {
    let u = bit(w, 22);
    let kind = match (u, fld(w, 21, 20)) {
        (_, 0b00) => return UNDEF,
        (false, 0b01) => ParKind::S,
        (false, 0b10) => ParKind::Q,
        (false, _) => ParKind::Sh,
        (true, 0b01) => ParKind::U,
        (true, 0b10) => ParKind::Uq,
        (true, _) => ParKind::Uh,
    };
    let op = match fld(w, 7, 5) {
        0b000 => ParOp::Add16,
        0b001 => ParOp::Asx,
        0b010 => ParOp::Sax,
        0b011 => ParOp::Sub16,
        0b100 => ParOp::Add8,
        0b111 => ParOp::Sub8,
        _ => return UNDEF,
    };
    let (rd, rn, rm) = (reg(w, 12), reg(w, 16), reg(w, 0));
    rules(
        Op::Parallel { kind, op, rd, rn, rm },
        &[
            (rd.is_pc() || rn.is_pc() || rm.is_pc(), "A8.8 parallel add/subtract: d, n or m == 15"),
            (sbo(w, 0xf00), "A8.8 parallel add/subtract: (1) bits 11:8 (A5.1.2)"),
        ],
    )
}

// A5.4.3 Packing, unpacking, saturation, and reversal, Table A5-19: op1
// (22:20), op2 (7:5), A (19:16). Other encodings are UNDEFINED.
fn pack(w: u32) -> D {
    let op1 = fld(w, 22, 20);
    let op2 = fld(w, 7, 5);
    let (r16, rd, r0) = (reg(w, 16), reg(w, 12), reg(w, 0));
    let dm = rd.is_pc() || r0.is_pc();
    let extend = |kind: ExtKind| {
        rules(
            Op::Extend { kind, rd, rn: if r16.is_pc() { None } else { Some(r16) }, rm: r0, rotation: (fld(w, 11, 10) * 8) as u8 },
            &[(dm, "A8.8.231 SXTA*/UXTA*/SXT*/UXT*: d == 15 || m == 15"), (sbz(w, 0x300), "A8.8.231 extend: (0) bits 9:8 (A5.1.2)")],
        )
    };
    let rev = |kind: RevKind| {
        rules(
            Op::Rev { kind, rd, rm: r0 },
            &[(dm, "A8.8.146 REV/REV16/REVSH/RBIT: d == 15 || m == 15"), (sbo(w, 0xf_0f00), "A8.8.146 REV/REV16/REVSH/RBIT: (1) bits 19:16, 11:8 (A5.1.2)")],
        )
    };
    let sat = |unsigned: bool| {
        let (shift, amount) = Shift::decode_imm(fld(w, 6, 6) << 1, fld(w, 11, 7));
        let sat_imm = fld(w, 20, 16) as u8;
        rules(
            Op::Sat { unsigned, rd, rn: r0, sat: if unsigned { sat_imm } else { sat_imm + 1 }, shift, amount },
            &[(dm, "A8.8.194 SSAT/USAT: d == 15 || n == 15")],
        )
    };
    let sat16 = |unsigned: bool| {
        let sat_imm = fld(w, 19, 16) as u8;
        rules(
            Op::Sat16 { unsigned, rd, rn: r0, sat: if unsigned { sat_imm } else { sat_imm + 1 } },
            &[(dm, "A8.8.195 SSAT16/USAT16: d == 15 || n == 15"), (sbo(w, 0xf00), "A8.8.195 SSAT16/USAT16: (1) bits 11:8 (A5.1.2)")],
        )
    };
    match (op1, op2) {
        // A8.8.126 PKH.
        (0b000, _) if op2 & 1 == 0 => {
            let tb = bit(w, 6);
            let (_, amount) = Shift::decode_imm((tb as u32) << 1, fld(w, 11, 7));
            rules(
                Op::Pkh { tb, rd, rn: r16, rm: r0, amount },
                &[(rd.is_pc() || r16.is_pc() || r0.is_pc(), "A8.8.126 PKH: d, n or m == 15")],
            )
        }
        (0b000, 0b011) => extend(ExtKind::Sxtb16),
        // A8.8.167 SEL.
        (0b000, 0b101) => rules(
            Op::Sel { rd, rn: r16, rm: r0 },
            &[(rd.is_pc() || r16.is_pc() || r0.is_pc(), "A8.8.167 SEL: d, n or m == 15"), (sbo(w, 0xf00), "A8.8.167 SEL: (1) bits 11:8 (A5.1.2)")],
        ),
        (0b010 | 0b011, _) if op2 & 1 == 0 => sat(false),
        (0b010, 0b001) => sat16(false),
        (0b010, 0b011) => extend(ExtKind::Sxtb),
        (0b011, 0b001) => rev(RevKind::Rev),
        (0b011, 0b011) => extend(ExtKind::Sxth),
        (0b011, 0b101) => rev(RevKind::Rev16),
        (0b100, 0b011) => extend(ExtKind::Uxtb16),
        (0b110 | 0b111, _) if op2 & 1 == 0 => sat(true),
        (0b110, 0b001) => sat16(true),
        (0b110, 0b011) => extend(ExtKind::Uxtb),
        (0b111, 0b001) => rev(RevKind::Rbit),
        (0b111, 0b011) => extend(ExtKind::Uxth),
        (0b111, 0b101) => rev(RevKind::Revsh),
        _ => UNDEF,
    }
}

// A5.4.4 Signed multiply, signed and unsigned divide, Table A5-20: op1
// (22:20), op2 (7:5), A (15:12). Other encodings are UNDEFINED.
fn signed_mul(w: u32, f: &Features) -> D {
    let op1 = fld(w, 22, 20);
    let op2 = fld(w, 7, 5);
    let (r16, r12, rm, rn) = (reg(w, 16), reg(w, 12), reg(w, 8), reg(w, 0));
    let pc3 = r16.is_pc() || rn.is_pc() || rm.is_pc();
    let ra = if r12.is_pc() { None } else { Some(r12) };
    let x = bit(w, 5);
    match (op1, op2 >> 1) {
        // A8.8.178 SMLAD / A8.8.188 SMUAD, A8.8.183 SMLSD / A8.8.192 SMUSD.
        (0b000, 0b00) | (0b000, 0b01) => {
            rules(Op::Smlad { rd: r16, rn, rm, ra, sub: op2 & 2 != 0, swap: x }, &[(pc3, "A8.8.178 SMLAD/SMUAD/SMLSD/SMUSD: d, n or m == 15")])
        }
        // A8.8.166 SDIV, A8.8.249 UDIV (optional in ARMv7-A).
        (0b001, _) | (0b011, _) if op2 == 0 => {
            if !f.arm_div {
                return UNDEF;
            }
            rules(
                Op::Div { signed: op1 == 0b001, rd: r16, rn, rm },
                &[(pc3, "A8.8.166 SDIV/UDIV: d, n or m == 15"), (sbo(w, 0xf000), "A8.8.166 SDIV/UDIV: (1) bits 15:12 (A5.1.2)")],
            )
        }
        // A8.8.181 SMLALD, A8.8.184 SMLSLD.
        (0b100, 0b00) | (0b100, 0b01) => rules(
            Op::Smlald { rdlo: r12, rdhi: r16, rn, rm, sub: op2 & 2 != 0, swap: x },
            &[(pc3 || r12.is_pc(), "A8.8.181 SMLALD/SMLSLD: dLo, dHi, n or m == 15"), (r12 == r16, "A8.8.181 SMLALD/SMLSLD: dHi == dLo")],
        ),
        // A8.8.185 SMMLA / A8.8.187 SMMUL.
        (0b101, 0b00) => rules(Op::Smmul { rd: r16, rn, rm, ra, sub: false, round: x }, &[(pc3, "A8.8.185 SMMLA/SMMUL: d, n or m == 15")]),
        // A8.8.186 SMMLS.
        (0b101, 0b11) => rules(
            Op::Smmul { rd: r16, rn, rm, ra: Some(r12), sub: true, round: x },
            &[(pc3 || r12.is_pc(), "A8.8.186 SMMLS: d, n, m or a == 15")],
        ),
        _ => UNDEF,
    }
}

// -- A5.5 Branch, branch with link, and block data transfer -------------------

// Table A5-21: op (25:20), R (15), Rn (19:16).
fn branch_block(w: u32) -> D {
    if bit(w, 25) {
        // A8.8.18 B, A8.8.25 BL: SignExtend(imm24:'00').
        let imm = ((w << 8) as i32) >> 6;
        return (if bit(w, 24) { Op::Bl { imm, switch: false } } else { Op::B { imm } }, None);
    }
    let (p, u, s, wb, l) = (bit(w, 24), bit(w, 23), bit(w, 22), bit(w, 21), bit(w, 20));
    let rn = reg(w, 16);
    let regs = fld(w, 15, 0);
    let mode = Amode::of_pu(p, u);
    let op = Op::Ldm { load: l, mode, rn, regs: regs as u16, wback: wb, user: s };
    let empty = rn.is_pc() || regs == 0;
    match (s, l) {
        // A8.8.200-A8.8.203 STM/STMDA/STMDB/STMIB (A8.8.134 PUSH).
        (false, false) => rules(op, &[(empty, "A8.8.200 STM: n == 15 || BitCount(registers) < 1")]),
        // A8.8.59-A8.8.62 LDM/LDMDA/LDMDB/LDMIB (A8.8.133 POP).
        (false, true) => rules(
            op,
            &[(empty, "A8.8.59 LDM: n == 15 || BitCount(registers) < 1"), (wb && has(regs, rn), "A8.8.59 LDM: wback && registers<n> == '1'")],
        ),
        // B9.3.17 STM (User registers) (UNPREDICTABLE in User or System
        // mode, UNDEFINED in Hyp mode: the lifter's).
        (true, false) => rules(
            op,
            &[(empty, "B9.3.17 STM (User registers): n == 15 || BitCount(registers) < 1"), (wb, "B9.3.17 STM (User registers): (0) bit 21 (A5.1.2)")],
        ),
        // B9.3.6 LDM (User registers).
        (true, true) if regs & 0x8000 == 0 => rules(
            op,
            &[(empty, "B9.3.6 LDM (User registers): n == 15 || BitCount(registers) < 1"), (wb, "B9.3.6 LDM (User registers): (0) bit 21 (A5.1.2)")],
        ),
        // B9.3.5 LDM (exception return).
        (true, true) => rules(
            op,
            &[(rn.is_pc(), "B9.3.5 LDM (exception return): n == 15"), (wb && has(regs, rn), "B9.3.5 LDM (exception return): wback && registers<n> == '1'")],
        ),
    }
}

// -- A5.6 Coprocessor instructions, and Supervisor Call -----------------------

// Table A5-22 (`two` false: cond not 1111) and the coprocessor rows of
// Table A5-23 (`two`: cond 1111, the `2` forms): op1 (25:20), coproc
// (11:8), op (4).
fn coproc(w: u32, f: &Features, two: bool) -> D {
    let op1 = fld(w, 25, 20);
    let cp = fld(w, 11, 8);
    if op1 & 0b111110 == 0 {
        return UNDEF;
    }
    if op1 & 0b110000 == 0b110000 {
        // A8.8.229 SVC; no unconditional form.
        return if two { UNDEF } else { (Op::Svc { imm: fld(w, 23, 0) }, None) };
    }
    if cp & 0b1110 == 0b1010 {
        // Floating-point and Advanced SIMD (A7.5, A7.8, A7.9). The `2`
        // forms with coproc 101x are UNDEFINED (A8.8.30 and the like).
        return if two { UNDEF } else { fp::decode_cp(w, f) };
    }
    let coproc = cp as u8;
    let (r16, r12) = (reg(w, 16), reg(w, 12));
    match op1 {
        // A8.8.100 MCRR, MCRR2.
        0b000100 => rules(
            Op::Mcrr { read: false, two, coproc, opc1: fld(w, 7, 4) as u8, rt: r12, rt2: r16, crm: fld(w, 3, 0) as u8 },
            &[(r12.is_pc() || r16.is_pc(), "A8.8.100 MCRR: t == 15 || t2 == 15")],
        ),
        // A8.8.109 MRRC, MRRC2.
        0b000101 => rules(
            Op::Mcrr { read: true, two, coproc, opc1: fld(w, 7, 4) as u8, rt: r12, rt2: r16, crm: fld(w, 3, 0) as u8 },
            &[(r12.is_pc() || r16.is_pc() || r12 == r16, "A8.8.109 MRRC: t == 15 || t2 == 15 || t == t2")],
        ),
        _ if op1 & 0b100000 == 0 => {
            // A8.8.199 STC, STC2; A8.8.56 LDC, LDC2 (immediate); A8.8.57
            // LDC, LDC2 (literal). P U D W = 0 0 x 0 was taken above.
            let (p, u, d, wb, l) = (bit(w, 24), bit(w, 23), bit(w, 22), bit(w, 21), bit(w, 20));
            let imm8 = fld(w, 7, 0);
            let (imm, option) = if !p && !wb { (0, Some(imm8 as u8)) } else { (signed(imm8 << 2, u), None) };
            let op = Op::Ldc { load: l, two, long: d, coproc, crd: fld(w, 15, 12) as u8, rn: r16, imm, index: p, wback: wb, option };
            if l {
                rules(op, &[(r16.is_pc() && wb, "A8.8.57 LDC (literal): W == '1'")])
            } else {
                rules(op, &[(r16.is_pc() && wb, "A8.8.199 STC: n == 15 && wback")])
            }
        }
        // A8.8.30 CDP, CDP2.
        _ if !bit(w, 4) => (
            Op::Cdp {
                two,
                coproc,
                opc1: fld(w, 23, 20) as u8,
                crd: fld(w, 15, 12) as u8,
                crn: fld(w, 19, 16) as u8,
                crm: fld(w, 3, 0) as u8,
                opc2: fld(w, 7, 5) as u8,
            },
            None,
        ),
        // A8.8.99 MCR, MCR2; A8.8.108 MRC, MRC2 (Rt = PC writes NZCV).
        _ => {
            let read = bit(w, 20);
            rules(
                Op::Mcr { read, two, coproc, opc1: fld(w, 23, 21) as u8, rt: r12, crn: fld(w, 19, 16) as u8, crm: fld(w, 3, 0) as u8, opc2: fld(w, 7, 5) as u8 },
                &[(!read && r12.is_pc(), "A8.8.99 MCR: t == 15")],
            )
        }
    }
}

// -- A5.7 Unconditional instructions ------------------------------------------

// Table A5-23: op1 (27:20), op (4). Other encodings are UNDEFINED.
fn unconditional(w: u32, f: &Features) -> D {
    let op1 = fld(w, 27, 20);
    if op1 & 0x80 == 0 {
        return hints_simd_misc(w, f);
    }
    match op1 >> 5 {
        0b100 => {
            let (p, u, wb) = (bit(w, 24), bit(w, 23), bit(w, 21));
            let amode = Amode::of_pu(p, u);
            match op1 & 0b101 {
                // B9.3.16 SRS (ARM). A mode the current state may not
                // store (Hyp; Monitor or FIQ from Non-secure) is
                // UNPREDICTABLE at run time: the lifter's.
                0b100 => rules(
                    Op::Srs { mode: fld(w, 4, 0) as u8, amode, wback: wb },
                    &[(w & 0x000f_ffe0 != 0x000d_0500, "B9.3.16 SRS: (1)/(0) bits 19:5 (A5.1.2)")],
                ),
                // B9.3.13 RFE.
                0b001 => {
                    let rn = reg(w, 16);
                    rules(
                        Op::Rfe { rn, amode, wback: wb },
                        &[(rn.is_pc(), "B9.3.13 RFE: n == 15"), (w & 0xffff != 0x0a00, "B9.3.13 RFE: (1)/(0) bits 15:0 (A5.1.2)")],
                    )
                }
                _ => UNDEF,
            }
        }
        // A8.8.25 BLX (immediate): SignExtend(imm24:H:'0').
        0b101 => (Op::Bl { imm: (((w << 8) as i32) >> 6) | ((bit(w, 24) as i32) << 1), switch: true }, None),
        _ => coproc(w, f, true),
    }
}

// A5.7.1 Memory hints, Advanced SIMD instructions, and miscellaneous
// instructions, Table A5-24: op1 (26:20), op2 (7:4), Rn (19:16). Other
// encodings are UNDEFINED. The rows the table makes UNPREDICTABLE have no
// instruction: they decode to `Op::Undefined` with the reason set.
fn hints_simd_misc(w: u32, f: &Features) -> D {
    let op1 = fld(w, 26, 20);
    let op2 = fld(w, 7, 4);
    let rn = reg(w, 16);
    let is = |mask: u32, val: u32| op1 & mask == val;
    let unp = |why: &'static str| (Op::Undefined, Some(why));
    let imm_off = Offset::Imm(signed(fld(w, 11, 0), bit(w, 23)));
    let reg_off = || {
        let (shift, amount) = Shift::decode_imm(fld(w, 6, 5), fld(w, 11, 7));
        Offset::Reg { rm: reg(w, 0), shift, amount, add: bit(w, 23) }
    };
    let sbo_rt = (sbo(w, 0xf000), "A8.8.127 PLD/PLDW/PLI: (1) bits 15:12 (A5.1.2)");

    if op1 == 0b0010000 {
        if op2 & 0b0010 == 0 && rn.n() & 1 == 0 {
            // B9.3.2 CPS (ARM) (a NOP in User mode: the lifter's).
            let imod = fld(w, 19, 18) as u8;
            let m = bit(w, 17);
            let (a, i, ff) = (bit(w, 8), bit(w, 7), bit(w, 6));
            let mode = fld(w, 4, 0) as u8;
            let aif = a || i || ff;
            return rules(
                Op::Cps { imod, a, i, f: ff, mode: if m { Some(mode) } else { None } },
                &[
                    (mode != 0 && !m, "B9.3.2 CPS: mode != '00000' && M == '0'"),
                    ((imod & 2 != 0 && !aif) || (imod & 2 == 0 && aif), "B9.3.2 CPS: imod<1> and A:I:F disagree"),
                    ((imod == 0 && !m) || imod == 1, "B9.3.2 CPS: (imod == '00' && M == '0') || imod == '01'"),
                    (sbz(w, 0xfe00), "B9.3.2 CPS: (0) bits 15:9 (A5.1.2)"),
                ],
            );
        }
        if op2 == 0 && rn.n() & 1 == 1 {
            // A8.8.168 SETEND.
            return rules(Op::Setend { big: bit(w, 9) }, &[(sbz(w, 0x000e_fd0f), "A8.8.168 SETEND: (0) bits 19:17, 15:10, 8, 3:0 (A5.1.2)")]);
        }
        return UNDEF;
    }
    if op1 == 0b0010010 && op2 == 0b0111 {
        return unp("A5.7.1: op1 0010010 op2 0111 is UNPREDICTABLE");
    }
    if is(0b1100000, 0b0100000) {
        // A7.4 Advanced SIMD data-processing instructions.
        return fp::decode_simd_dp(w, f);
    }
    if is(0b1110001, 0b1000000) {
        // A7.7 Advanced SIMD element or structure load/store instructions.
        return fp::decode_simd_ldst(w, f);
    }
    if is(0b1110111, 0b1000001) {
        // Unallocated memory hint (MP Extensions): treat as NOP.
        return if f.mp { (Op::Hint(Hint::Nop), None) } else { UNDEF };
    }
    if is(0b1110111, 0b1000101) {
        // A8.8.130 PLI (immediate, literal).
        return rules(Op::Pld { write: false, instr: true, rn, offset: imm_off }, &[sbo_rt]);
    }
    if is(0b1110011, 0b1000011) {
        return unp("A5.7.1: op1 100xx11 is UNPREDICTABLE");
    }
    if is(0b1110111, 0b1010001) {
        if rn.is_pc() {
            // A8.8.127 sends Rn = 1111 to A8.8.128 PLD (literal), whose R
            // (bit 22) is (1); Table A5-24 makes the row UNPREDICTABLE.
            return (
                Op::Pld { write: false, instr: false, rn, offset: imm_off },
                Some("A8.8.128 PLD (literal): (1) bit 22 (R) is 0 (Table A5-24: op1 101x001, Rn 1111, UNPREDICTABLE)"),
            );
        }
        // A8.8.127 PLDW (immediate) (MP Extensions).
        return if f.mp { rules(Op::Pld { write: true, instr: false, rn, offset: imm_off }, &[sbo_rt]) } else { UNDEF };
    }
    if is(0b1110111, 0b1010101) {
        // A8.8.127 PLD (immediate), A8.8.128 PLD (literal).
        return rules(Op::Pld { write: false, instr: false, rn, offset: imm_off }, &[sbo_rt]);
    }
    if op1 == 0b1010011 {
        return unp("A5.7.1: op1 1010011 is UNPREDICTABLE");
    }
    if op1 == 0b1010111 {
        let barrier = |kind: Barrier| {
            rules(Op::Barrier { kind, option: fld(w, 3, 0) as u8 }, &[(w & 0xfff00 != 0xff000, "A8.8.44 DMB/DSB/ISB: (1) bits 19:12 / (0) bits 11:8 (A5.1.2)")])
        };
        return match op2 {
            // A8.8.32 CLREX.
            0b0001 => rules(Op::Clrex, &[(w & 0xfff0f != 0xff00f, "A8.8.32 CLREX: (1) bits 19:12, 3:0 / (0) bits 11:8 (A5.1.2)")]),
            // A8.8.45 DSB, A8.8.44 DMB, A8.8.54 ISB.
            0b0100 => barrier(Barrier::Dsb),
            0b0101 => barrier(Barrier::Dmb),
            0b0110 => barrier(Barrier::Isb),
            _ => unp("A5.7.1: op1 1010111 with op2 0000, 001x, 0111 or 1xxx is UNPREDICTABLE"),
        };
    }
    if is(0b1111011, 0b1011011) {
        return unp("A5.7.1: op1 1011x11 is UNPREDICTABLE");
    }
    if is(0b1100000, 0b1100000) && op2 & 1 == 0 {
        let rm = reg(w, 0);
        if is(0b1110111, 0b1100001) {
            // Unallocated memory hint (MP Extensions): treat as NOP.
            return if f.mp { (Op::Hint(Hint::Nop), None) } else { UNDEF };
        }
        if is(0b1110111, 0b1100101) {
            // A8.8.131 PLI (register).
            return rules(Op::Pld { write: false, instr: true, rn, offset: reg_off() }, &[(rm.is_pc(), "A8.8.131 PLI (register): m == 15"), sbo_rt]);
        }
        if is(0b1110111, 0b1110001) {
            // A8.8.129 PLDW (register) (MP Extensions).
            if !f.mp {
                return UNDEF;
            }
            return rules(
                Op::Pld { write: true, instr: false, rn, offset: reg_off() },
                &[(rm.is_pc() || rn.is_pc(), "A8.8.129 PLDW (register): m == 15 || (n == 15 && is_pldw)"), sbo_rt],
            );
        }
        if is(0b1110111, 0b1110101) {
            // A8.8.129 PLD (register).
            return rules(Op::Pld { write: false, instr: false, rn, offset: reg_off() }, &[(rm.is_pc(), "A8.8.129 PLD (register): m == 15"), sbo_rt]);
        }
        if is(0b1100011, 0b1100011) {
            return unp("A5.7.1: op1 11xxx11 with op2 xxx0 is UNPREDICTABLE");
        }
    }
    // Including 1111111 1111, permanently UNDEFINED.
    UNDEF
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(w: u32) -> Inst {
        decode(w, &Features::ALL)
    }
    fn op(w: u32) -> Op {
        d(w).op
    }
    fn unp(w: u32) -> bool {
        d(w).unpredictable.is_some()
    }
    fn ok(w: u32) -> Op {
        let i = d(w);
        assert!(i.unpredictable.is_none(), "{w:08x}: {:?}", i.unpredictable);
        i.op
    }
    fn base(w: u32) -> Op {
        decode(w, &Features::BASE).op
    }
    fn r(n: u8) -> Reg {
        Reg(n)
    }
    fn text(w: u32) -> String {
        fmt::disasm(&d(w))
    }

    #[test]
    fn arm_expand_imm_c() {
        // rotation 0: APSR.C unchanged.
        assert_eq!(expand_imm(0x0ff), Operand::Imm { value: 255, carry: None });
        assert_eq!(expand_imm(0x000), Operand::Imm { value: 0, carry: None });
        // 2 ROR 2.
        assert_eq!(expand_imm(0x102), Operand::Imm { value: 0x8000_0000, carry: Some(true) });
        // 0xff ROR 4.
        assert_eq!(expand_imm(0x2ff), Operand::Imm { value: 0xf000_000f, carry: Some(true) });
        // 0x3f ROR 24: carry is bit 31, 0.
        assert_eq!(expand_imm(0xc3f), Operand::Imm { value: 0x3f00, carry: Some(false) });
        // The ANDS R1, R2, #12, #2 example of A5.2.4: 3, carry 0.
        assert_eq!(expand_imm(0x10c), Operand::Imm { value: 3, carry: Some(false) });
    }

    #[test]
    fn data_processing() {
        // ADD r0, r1, r2.
        assert_eq!(
            ok(0xe081_0002),
            Op::Dp { op: DpOp::Add, s: false, rd: r(0), rn: r(1), src: Operand::RegImm { rm: r(2), shift: Shift::Lsl, amount: 0 } }
        );
        // DecodeImmShift: LSR #0 is 32, ASR #0 is 32, ROR #0 is RRX.
        assert!(matches!(ok(0xe1a0_0021), Op::Dp { op: DpOp::Mov, src: Operand::RegImm { shift: Shift::Lsr, amount: 32, .. }, .. }));
        assert!(matches!(ok(0xe1a0_0041), Op::Dp { op: DpOp::Mov, src: Operand::RegImm { shift: Shift::Asr, amount: 32, .. }, .. }));
        assert!(matches!(ok(0xe1a0_0061), Op::Dp { op: DpOp::Mov, src: Operand::RegImm { shift: Shift::Rrx, amount: 1, .. }, .. }));
        assert_eq!(text(0xe1a0_0061), "rrx r0, r1");
        assert_eq!(text(0xe1a0_1081), "lsl r1, r1, #1");
        // ADR is ADD/SUB with Rn = PC.
        assert_eq!(ok(0xe28f_0004), Op::Dp { op: DpOp::Add, s: false, rd: r(0), rn: Reg::PC, src: Operand::Imm { value: 4, carry: None } });
        assert!(matches!(ok(0xe24f_0004), Op::Dp { op: DpOp::Sub, rn: Reg::PC, .. }));
        // ANDS with a rotated constant carries bit 31.
        assert_eq!(
            ok(0xe210_0102),
            Op::Dp { op: DpOp::And, s: true, rd: r(0), rn: r(0), src: Operand::Imm { value: 0x8000_0000, carry: Some(true) } }
        );
        // Register-shifted register: ADD r0, r1, r2, LSL r3; a PC is
        // UNPREDICTABLE.
        assert_eq!(
            ok(0xe081_0312),
            Op::Dp { op: DpOp::Add, s: false, rd: r(0), rn: r(1), src: Operand::RegReg { rm: r(2), shift: Shift::Lsl, rs: r(3) } }
        );
        assert!(unp(0xe081_031f));
        assert!(unp(0xe08f_0312));
        // LSL r0, r1, r2 is MOV r0, r1, LSL r2.
        assert_eq!(text(0xe1a0_0211), "lsl r0, r1, r2");
        // SUBS PC, LR, #4 (B9.3.20) and MOVS PC, LR: data processing with
        // Rd = PC and S; mode checks are the lifter's.
        assert_eq!(ok(0xe25e_f004), Op::Dp { op: DpOp::Sub, s: true, rd: Reg::PC, rn: Reg::LR, src: Operand::Imm { value: 4, carry: None } });
        assert!(matches!(ok(0xe1b0_f00e), Op::Dp { op: DpOp::Mov, s: true, rd: Reg::PC, .. }));
        // A test's Rd and a MOV's Rn are (0).
        assert!(matches!(op(0xe311_1001), Op::Dp { op: DpOp::Tst, .. }));
        assert!(unp(0xe311_1001));
        assert!(!unp(0xe311_0001));
        assert!(unp(0xe1a1_0002));
        // MOVW / MOVT.
        assert_eq!(ok(0xe30a_1bcd), Op::Movw { rd: r(1), imm: 0xabcd });
        assert_eq!(ok(0xe34a_1bcd), Op::Movt { rd: r(1), imm: 0xabcd });
        assert!(unp(0xe30a_fbcd));
        // The alternative constant syntax of A5.2.4.
        assert_eq!(text(0xe3a0_0f1f), "mov r0, #31, #30");
        assert_eq!(text(0xe3a0_0102), "mov r0, #-2147483648");
        assert_eq!(text(0xe3a0_f102), "mov pc, #2147483648");
    }

    #[test]
    fn hints_and_msr() {
        assert_eq!(ok(0xe320_f000), Op::Hint(Hint::Nop));
        assert_eq!(ok(0xe320_f001), Op::Hint(Hint::Yield));
        assert_eq!(ok(0xe320_f002), Op::Hint(Hint::Wfe));
        assert_eq!(ok(0xe320_f003), Op::Hint(Hint::Wfi));
        assert_eq!(ok(0xe320_f004), Op::Hint(Hint::Sev));
        assert_eq!(ok(0xe320_f014), Op::Hint(Hint::Csdb));
        assert_eq!(ok(0xe320_f0f5), Op::Hint(Hint::Dbg(5)));
        // Unallocated hints behave as NOP.
        assert_eq!(ok(0xe320_f005), Op::Hint(Hint::Nop));
        assert_eq!(ok(0xe320_f080), Op::Hint(Hint::Nop));
        // CSDB must be AL; (1)/(0) bits of the hints.
        assert!(unp(0x0320_f014));
        assert!(unp(0xe320_0000));
        assert!(unp(0xe320_f100));
        // MSR (immediate): APSR_nzcvq, #0x80000000.
        assert_eq!(ok(0xe328_f102), Op::Msr { psr: Psr::Cpsr, mask: 8, src: MsrSrc::Imm(0x8000_0000) });
        assert_eq!(ok(0xe363_f0ff), Op::Msr { psr: Psr::Spsr, mask: 3, src: MsrSrc::Imm(255) });
        // SPSR with mask 0000 is UNPREDICTABLE (B9.3.11).
        assert!(unp(0xe360_f023));
        assert!(unp(0xe328_0102));
    }

    #[test]
    fn miscellaneous() {
        assert_eq!(ok(0xe10f_0000), Op::Mrs { rd: r(0), psr: Psr::Cpsr });
        assert_eq!(ok(0xe14f_0000), Op::Mrs { rd: r(0), psr: Psr::Spsr });
        assert!(unp(0xe10f_f000));
        assert!(unp(0xe10e_0000));
        assert_eq!(ok(0xe129_f000), Op::Msr { psr: Psr::Cpsr, mask: 9, src: MsrSrc::Reg(r(0)) });
        assert!(unp(0xe120_f000)); // mask 0000
        assert!(unp(0xe129_f00f)); // n == 15
        // MRS (Banked register) r0, r8_usr; MSR SPSR_irq, r12.
        assert_eq!(ok(0xe100_0200), Op::MrsBanked { rd: r(0), sysm: 0 });
        assert_eq!(ok(0xe160_f30c), Op::MsrBanked { rn: r(12), sysm: 0b11_0000 });
        assert_eq!(text(0xe160_f30c), "msr SPSR_irq, r12");
        assert!(unp(0xe107_0200)); // SYSm 00111
        assert!(unp(0xe161_f30c)); // R = 1, SYSm 10001
        assert_eq!(base(0xe100_0200), Op::Undefined);
        assert_eq!(ok(0xe12f_ff1e), Op::Bx { rm: Reg::LR });
        assert!(unp(0xe12f_0f1e));
        assert_eq!(ok(0xe12f_ff33), Op::BlxReg { rm: r(3) });
        assert!(unp(0xe12f_ff3f));
        assert_eq!(ok(0xe12f_ff23), Op::Bxj { rm: r(3) });
        assert_eq!(ok(0xe16f_1f12), Op::Clz { rd: r(1), rm: r(2) });
        // QADD r1, r3, r2 (Rd, Rm, Rn); QDSUB.
        assert_eq!(ok(0xe102_1053), Op::Qadd { sub: false, double: false, rd: r(1), rm: r(3), rn: r(2) });
        assert_eq!(ok(0xe162_1053), Op::Qadd { sub: true, double: true, rd: r(1), rm: r(3), rn: r(2) });
        assert!(unp(0xe102_1153));
        assert_eq!(ok(0xe160_006e), Op::Eret);
        assert_eq!(base(0xe160_006e), Op::Undefined);
        assert_eq!(ok(0xe121_2374), Op::Bkpt { imm: 0x1234 });
        assert!(unp(0x0121_2374));
        assert_eq!(ok(0xe14f_ff7f), Op::Hvc { imm: 0xffff });
        assert_eq!(base(0xe14f_ff7f), Op::Undefined);
        assert_eq!(ok(0xe160_0073), Op::Smc { imm: 3 });
        assert_eq!(base(0xe160_0073), Op::Undefined);
        assert!(unp(0xe160_0173));
        // op2 100 and BX's op2 with op 00 are UNDEFINED.
        assert_eq!(op(0xe120_0040), Op::Undefined);
        assert_eq!(op(0xe10f_ff1e), Op::Undefined);
    }

    #[test]
    fn multiplies() {
        assert_eq!(ok(0xe001_0392), Op::Mul { s: false, rd: r(1), rn: r(2), rm: r(3) });
        assert_eq!(ok(0xe021_4392), Op::Mla { s: false, sub: false, rd: r(1), rn: r(2), rm: r(3), ra: r(4) });
        assert_eq!(ok(0xe061_4392), Op::Mla { s: false, sub: true, rd: r(1), rn: r(2), rm: r(3), ra: r(4) });
        assert_eq!(ok(0xe042_1392), Op::MulLong { kind: MulLong::Umaal, s: false, rdlo: r(1), rdhi: r(2), rn: r(2), rm: r(3) });
        assert_eq!(ok(0xe082_1392), Op::MulLong { kind: MulLong::Umull, s: false, rdlo: r(1), rdhi: r(2), rn: r(2), rm: r(3) });
        assert_eq!(ok(0xe0f2_1392), Op::MulLong { kind: MulLong::Smlal, s: true, rdlo: r(1), rdhi: r(2), rn: r(2), rm: r(3) });
        assert_eq!(op(0xe052_1392), Op::Undefined);
        assert_eq!(op(0xe072_1392), Op::Undefined);
        assert!(unp(0xe081_1392)); // dHi == dLo
        assert!(unp(0xe001_1392)); // MUL (0) bits 15:12
        // Halfword multiplies.
        assert_eq!(ok(0xe101_2384), Op::Smulxy { rd: r(1), rn: r(4), rm: r(3), ra: Some(r(2)), n_top: false, m_top: false });
        assert_eq!(ok(0xe161_03a4), Op::Smulxy { rd: r(1), rn: r(4), rm: r(3), ra: None, n_top: true, m_top: false });
        assert_eq!(text(0xe161_03a4), "smultb r1, r4, r3");
        assert_eq!(ok(0xe121_03e4), Op::Smulwy { rd: r(1), rn: r(4), rm: r(3), ra: None, m_top: true });
        assert_eq!(ok(0xe121_23c4), Op::Smulwy { rd: r(1), rn: r(4), rm: r(3), ra: Some(r(2)), m_top: true });
        assert_eq!(ok(0xe142_13c4), Op::Smlalxy { rdlo: r(1), rdhi: r(2), rn: r(4), rm: r(3), n_top: false, m_top: true });
        // Media signed multiplies and divides.
        assert_eq!(ok(0xe701_4312), Op::Smlad { rd: r(1), rn: r(2), rm: r(3), ra: Some(r(4)), sub: false, swap: false });
        assert_eq!(ok(0xe701_f312), Op::Smlad { rd: r(1), rn: r(2), rm: r(3), ra: None, sub: false, swap: false });
        assert_eq!(ok(0xe701_4372), Op::Smlad { rd: r(1), rn: r(2), rm: r(3), ra: Some(r(4)), sub: true, swap: true });
        assert_eq!(ok(0xe711_f312), Op::Div { signed: true, rd: r(1), rn: r(2), rm: r(3) });
        assert_eq!(ok(0xe731_f312), Op::Div { signed: false, rd: r(1), rn: r(2), rm: r(3) });
        assert_eq!(base(0xe711_f312), Op::Undefined);
        assert!(unp(0xe711_0312));
        assert_eq!(ok(0xe742_1312), Op::Smlald { rdlo: r(1), rdhi: r(2), rn: r(2), rm: r(3), sub: false, swap: false });
        assert_eq!(ok(0xe751_f312), Op::Smmul { rd: r(1), rn: r(2), rm: r(3), ra: None, sub: false, round: false });
        assert_eq!(ok(0xe751_4332), Op::Smmul { rd: r(1), rn: r(2), rm: r(3), ra: Some(r(4)), sub: false, round: true });
        assert_eq!(ok(0xe751_43d2), Op::Smmul { rd: r(1), rn: r(2), rm: r(3), ra: Some(r(4)), sub: true, round: false });
        assert!(unp(0xe751_f3d2)); // SMMLS a == 15
        assert_eq!(op(0xe721_4312), Op::Undefined);
    }

    #[test]
    fn synchronization() {
        assert_eq!(ok(0xe102_1093), Op::Swp { byte: false, rt: r(1), rt2: r(3), rn: r(2) });
        assert_eq!(ok(0xe142_1093), Op::Swp { byte: true, rt: r(1), rt2: r(3), rn: r(2) });
        assert!(unp(0xe101_1093)); // n == t
        assert_eq!(ok(0xe192_1f9f), Op::Ldrex { size: Size::W, rt: r(1), rt2: Reg::PC, rn: r(2), imm: 0 });
        assert_eq!(ok(0xe182_1f93), Op::Strex { size: Size::W, rd: r(1), rt: r(3), rt2: Reg::PC, rn: r(2), imm: 0 });
        assert_eq!(ok(0xe1b2_0f9f), Op::Ldrex { size: Size::D, rt: r(0), rt2: r(1), rn: r(2), imm: 0 });
        assert_eq!(ok(0xe1a4_1f92), Op::Strex { size: Size::D, rd: r(1), rt: r(2), rt2: r(3), rn: r(4), imm: 0 });
        assert_eq!(ok(0xe1d2_1f9f), Op::Ldrex { size: Size::B, rt: r(1), rt2: Reg::PC, rn: r(2), imm: 0 });
        assert_eq!(ok(0xe1e2_1f93), Op::Strex { size: Size::H, rd: r(1), rt: r(3), rt2: Reg::PC, rn: r(2), imm: 0 });
        assert!(unp(0xe1b2_1f9f)); // LDREXD Rt odd
        assert!(unp(0xe1b2_ef9f)); // LDREXD Rt == 14
        assert!(unp(0xe182_2f93)); // STREX d == n
        assert!(unp(0xe192_1e9f)); // (1) bits
        assert_eq!(op(0xe112_1f9f), Op::Undefined); // op 0001
    }

    #[test]
    fn extra_load_store() {
        let ldst = |load, size, signed, user, rt, rn, offset, index, wback| Op::Ldst {
            load,
            size,
            signed,
            user,
            rt: r(rt),
            rn: r(rn),
            offset,
            index,
            wback,
        };
        let lsl0 = |m: u8, add: bool| Offset::Reg { rm: r(m), shift: Shift::Lsl, amount: 0, add };
        assert_eq!(ok(0xe1d2_10b4), ldst(true, Size::H, false, false, 1, 2, Offset::Imm(4), true, false));
        assert_eq!(ok(0xe182_10b3), ldst(false, Size::H, false, false, 1, 2, lsl0(3, true), true, false));
        assert_eq!(ok(0xe052_10d4), ldst(true, Size::B, true, false, 1, 2, Offset::Imm(-4), false, true));
        assert_eq!(ok(0xe1d2_10f4), ldst(true, Size::H, true, false, 1, 2, Offset::Imm(4), true, false));
        assert_eq!(ok(0xe0f2_10b4), ldst(true, Size::H, false, true, 1, 2, Offset::Imm(4), false, true));
        assert_eq!(ok(0xe072_10d4), ldst(true, Size::B, true, true, 1, 2, Offset::Imm(-4), false, true));
        assert_eq!(text(0xe0f2_10b4), "ldrht r1, [r2], #4");
        // LDRD/STRD.
        assert_eq!(ok(0xe1c2_40d8), Op::Ldrd { load: true, rt: r(4), rt2: r(5), rn: r(2), offset: Offset::Imm(8), index: true, wback: false });
        assert_eq!(ok(0xe1e2_40f8), Op::Ldrd { load: false, rt: r(4), rt2: r(5), rn: r(2), offset: Offset::Imm(8), index: true, wback: true });
        assert_eq!(ok(0xe182_40f3), Op::Ldrd { load: false, rt: r(4), rt2: r(5), rn: r(2), offset: lsl0(3, true), index: true, wback: false });
        assert!(unp(0xe1c2_50d8)); // Rt odd
        assert!(unp(0xe062_40d8)); // P == 0 && W == 1 (not unprivileged for LDRD)
        assert!(unp(0xe1a4_40d2)); // LDRD (register) wback && n == t
        assert!(!unp(0xe1a2_40d2)); // m == n is UNPREDICTABLE only before ARMv6
        // LDRD (literal): P (1), W (0).
        assert_eq!(ok(0xe1cf_40d8), Op::Ldrd { load: true, rt: r(4), rt2: r(5), rn: Reg::PC, offset: Offset::Imm(8), index: true, wback: false });
        assert!(unp(0xe0cf_40d8));
        // LDRH (literal): P == W is UNPREDICTABLE.
        assert!(!unp(0xe1df_10b4));
        assert!(unp(0xe0df_10b4));
        // (0) bits 11:8 of the register forms.
        assert!(unp(0xe182_11b3));
    }

    #[test]
    fn load_store_word_byte() {
        let shifted = Offset::Reg { rm: r(3), shift: Shift::Lsl, amount: 2, add: true };
        assert_eq!(
            ok(0xe592_1004),
            Op::Ldst { load: true, size: Size::W, signed: false, user: false, rt: r(1), rn: r(2), offset: Offset::Imm(4), index: true, wback: false }
        );
        assert_eq!(
            ok(0xe782_1103),
            Op::Ldst { load: false, size: Size::W, signed: false, user: false, rt: r(1), rn: r(2), offset: shifted, index: true, wback: false }
        );
        assert_eq!(
            ok(0xe4d2_1001),
            Op::Ldst { load: true, size: Size::B, signed: false, user: false, rt: r(1), rn: r(2), offset: Offset::Imm(1), index: false, wback: true }
        );
        assert_eq!(
            ok(0xe4b2_1004),
            Op::Ldst { load: true, size: Size::W, signed: false, user: true, rt: r(1), rn: r(2), offset: Offset::Imm(4), index: false, wback: true }
        );
        assert_eq!(text(0xe4b2_1004), "ldrt r1, [r2], #4");
        // LDR (literal); P == W is UNPREDICTABLE.
        assert!(matches!(ok(0xe59f_1008), Op::Ldst { rn: Reg::PC, index: true, wback: false, .. }));
        assert!(unp(0xe49f_1008));
        // Single-register PUSH and POP.
        assert_eq!(text(0xe52d_1004), "str r1, [sp, #-4]!");
        assert_eq!(text(0xe49d_1004), "ldr r1, [sp], #4");
        assert!(unp(0xe52d_d004)); // PUSH {sp}: t == 13 / n == t
        assert!(unp(0xe5a2_2004)); // wback && n == t
        assert!(unp(0xe792_100f)); // m == 15
        assert!(unp(0xe5c2_f000)); // STRB t == 15
        assert!(!unp(0xe582_f000)); // STR of the PC is allowed
        assert!(unp(0xe4a2_2004)); // STRT n == t
    }

    #[test]
    fn media() {
        assert_eq!(ok(0xe612_1f13), Op::Parallel { kind: ParKind::S, op: ParOp::Add16, rd: r(1), rn: r(2), rm: r(3) });
        assert_eq!(ok(0xe662_1ff3), Op::Parallel { kind: ParKind::Uq, op: ParOp::Sub8, rd: r(1), rn: r(2), rm: r(3) });
        assert_eq!(op(0xe602_1f13), Op::Undefined);
        assert_eq!(op(0xe612_1fb3), Op::Undefined);
        assert!(unp(0xe612_1013));
        assert_eq!(ok(0xe682_1153), Op::Pkh { tb: true, rd: r(1), rn: r(2), rm: r(3), amount: 2 });
        assert_eq!(ok(0xe682_1053), Op::Pkh { tb: true, rd: r(1), rn: r(2), rm: r(3), amount: 32 });
        assert_eq!(ok(0xe6a4_1013), Op::Sat { unsigned: false, rd: r(1), rn: r(3), sat: 5, shift: Shift::Lsl, amount: 0 });
        assert_eq!(ok(0xe6e4_1053), Op::Sat { unsigned: true, rd: r(1), rn: r(3), sat: 4, shift: Shift::Asr, amount: 32 });
        assert_eq!(ok(0xe6a3_1f32), Op::Sat16 { unsigned: false, rd: r(1), rn: r(2), sat: 4 });
        assert_eq!(ok(0xe6e3_1f32), Op::Sat16 { unsigned: true, rd: r(1), rn: r(2), sat: 3 });
        assert_eq!(ok(0xe6a2_1473), Op::Extend { kind: ExtKind::Sxtb, rd: r(1), rn: Some(r(2)), rm: r(3), rotation: 8 });
        assert_eq!(ok(0xe6af_1073), Op::Extend { kind: ExtKind::Sxtb, rd: r(1), rn: None, rm: r(3), rotation: 0 });
        assert_eq!(ok(0xe6ff_1073), Op::Extend { kind: ExtKind::Uxth, rd: r(1), rn: None, rm: r(3), rotation: 0 });
        assert_eq!(ok(0xe68f_1073), Op::Extend { kind: ExtKind::Sxtb16, rd: r(1), rn: None, rm: r(3), rotation: 0 });
        assert!(unp(0xe6af_1173)); // (0) bit 8
        assert_eq!(ok(0xe6bf_1f32), Op::Rev { kind: RevKind::Rev, rd: r(1), rm: r(2) });
        assert_eq!(ok(0xe6bf_1fb2), Op::Rev { kind: RevKind::Rev16, rd: r(1), rm: r(2) });
        assert_eq!(ok(0xe6ff_1f32), Op::Rev { kind: RevKind::Rbit, rd: r(1), rm: r(2) });
        assert_eq!(ok(0xe6ff_1fb2), Op::Rev { kind: RevKind::Revsh, rd: r(1), rm: r(2) });
        assert_eq!(ok(0xe682_1fb3), Op::Sel { rd: r(1), rn: r(2), rm: r(3) });
        assert_eq!(op(0xe691_1f32), Op::Undefined);
        assert_eq!(ok(0xe781_f312), Op::Usad8 { rd: r(1), rn: r(2), rm: r(3), ra: None });
        assert_eq!(ok(0xe781_4312), Op::Usad8 { rd: r(1), rn: r(2), rm: r(3), ra: Some(r(4)) });
        assert_eq!(ok(0xe7a4_1253), Op::Bfx { signed: true, rd: r(1), rn: r(3), lsb: 4, width: 5 });
        assert_eq!(ok(0xe7e4_1253), Op::Bfx { signed: false, rd: r(1), rn: r(3), lsb: 4, width: 5 });
        assert!(unp(0xe7bf_1253)); // lsb 4 + widthm1 31 > 31
        assert_eq!(ok(0xe7c4_121f), Op::Bfi { rd: r(1), rn: None, lsb: 4, msb: 4 });
        assert_eq!(ok(0xe7c4_1213), Op::Bfi { rd: r(1), rn: Some(r(3)), lsb: 4, msb: 4 });
        assert!(unp(0xe7c3_1213)); // msb 3 < lsb 4
        assert_eq!(ok(0xe7f0_00f0), Op::Udf { imm: 0 });
        assert_eq!(ok(0xe7f1_23f4), Op::Udf { imm: 0x1234 });
        assert_eq!(op(0x07f0_00f0), Op::Undefined);
    }

    #[test]
    fn branches_and_block_transfers() {
        assert_eq!(ok(0xea00_0000), Op::B { imm: 0 });
        assert_eq!(ok(0xebff_fffe), Op::Bl { imm: -8, switch: false });
        assert_eq!(ok(0xea7f_ffff), Op::B { imm: 0x01ff_fffc });
        assert_eq!(ok(0xea80_0000), Op::B { imm: -0x0200_0000 });
        let blx = d(0xfb00_0000);
        assert_eq!(blx.op, Op::Bl { imm: 2, switch: true });
        assert_eq!(blx.cond, Cond::AL);
        assert_eq!(ok(0xfaff_ffff), Op::Bl { imm: -4, switch: true });
        // PUSH {r4, lr} / POP {r4, pc}.
        assert_eq!(ok(0xe92d_4010), Op::Ldm { load: false, mode: Amode::Db, rn: Reg::SP, regs: 0x4010, wback: true, user: false });
        assert_eq!(ok(0xe8bd_8010), Op::Ldm { load: true, mode: Amode::Ia, rn: Reg::SP, regs: 0x8010, wback: true, user: false });
        assert_eq!(text(0xe92d_4010), "stmdb sp!, {r4, lr}");
        assert_eq!(ok(0xe999_0006), Op::Ldm { load: true, mode: Amode::Ib, rn: r(9), regs: 6, wback: false, user: false });
        assert_eq!(ok(0xe810_0006), Op::Ldm { load: true, mode: Amode::Da, rn: r(0), regs: 6, wback: false, user: false });
        // User-register and exception-return forms.
        assert_eq!(ok(0xe8d0_0003), Op::Ldm { load: true, mode: Amode::Ia, rn: r(0), regs: 3, wback: false, user: true });
        assert_eq!(ok(0xe8c0_0003), Op::Ldm { load: false, mode: Amode::Ia, rn: r(0), regs: 3, wback: false, user: true });
        assert_eq!(ok(0xe8f2_8003), Op::Ldm { load: true, mode: Amode::Ia, rn: r(2), regs: 0x8003, wback: true, user: true });
        assert!(unp(0xe8f0_8003)); // exception return, wback && registers<n>
        assert!(unp(0xe8f0_0003)); // user registers, (0) W
        assert!(unp(0xe8e0_0003)); // STM user registers, (0) W
        assert!(unp(0xe8b0_0001)); // LDM wback && registers<n>
        assert!(!unp(0xe8a0_0001)); // STM with the base in the list
        assert!(unp(0xe880_0000)); // empty list
        assert!(unp(0xe89f_0001)); // n == 15
    }

    #[test]
    fn coprocessor() {
        let mcr = |read, two, coproc, opc1, rt, crn, crm, opc2| Op::Mcr { read, two, coproc, opc1, rt: r(rt), crn, crm, opc2 };
        assert_eq!(ok(0xee01_0f10), mcr(false, false, 15, 0, 0, 1, 0, 0));
        assert_eq!(ok(0xee11_0f10), mcr(true, false, 15, 0, 0, 1, 0, 0));
        assert_eq!(ok(0xee11_ff10), mcr(true, false, 15, 0, 15, 1, 0, 0));
        assert!(unp(0xee01_ff10));
        assert_eq!(ok(0xfe01_0f10), mcr(false, true, 15, 0, 0, 1, 0, 0));
        assert_eq!(ok(0xec41_0f00), Op::Mcrr { read: false, two: false, coproc: 15, opc1: 0, rt: r(0), rt2: r(1), crm: 0 });
        assert_eq!(ok(0xec51_0f00), Op::Mcrr { read: true, two: false, coproc: 15, opc1: 0, rt: r(0), rt2: r(1), crm: 0 });
        assert!(unp(0xec50_0f00)); // MRRC t == t2
        assert!(!unp(0xec40_0f00)); // MCRR t == t2 is allowed
        assert_eq!(ok(0xee00_0100), Op::Cdp { two: false, coproc: 1, opc1: 0, crd: 0, crn: 0, crm: 0, opc2: 0 });
        assert_eq!(ok(0xfe00_0100), Op::Cdp { two: true, coproc: 1, opc1: 0, crd: 0, crn: 0, crm: 0, opc2: 0 });
        let ldc = |load, imm, index, wback, option| Op::Ldc { load, two: false, long: false, coproc: 1, crd: 0, rn: r(0), imm, index, wback, option };
        assert_eq!(ok(0xed90_0100), ldc(true, 0, true, false, None));
        assert_eq!(ok(0xec90_0105), ldc(true, 0, false, false, Some(5)));
        assert_eq!(ok(0xed20_0101), ldc(false, -4, true, true, None));
        assert_eq!(text(0xec90_0105), "ldc p1, c0, [r0], {5}");
        assert!(unp(0xedbf_0101)); // LDC (literal) W == 1
        assert!(unp(0xed2f_0101)); // STC n == 15 && wback
        assert_eq!(op(0xec00_0100), Op::Undefined);
        assert_eq!(op(0xec10_0100), Op::Undefined);
        assert_eq!(ok(0xef00_0123), Op::Svc { imm: 0x123 });
        // The `2` forms with coproc 101x are UNDEFINED; SVC has no
        // unconditional form.
        assert_eq!(op(0xfd90_0a00), Op::Undefined);
        assert_eq!(op(0xfe00_0b10), Op::Undefined);
        assert_eq!(op(0xff00_0000), Op::Undefined);
    }

    #[test]
    fn unconditional() {
        assert_eq!(ok(0xf96d_0513), Op::Srs { mode: 19, amode: Amode::Db, wback: true });
        assert!(unp(0xf96d_0413));
        assert_eq!(ok(0xf8b0_0a00), Op::Rfe { rn: r(0), amode: Amode::Ia, wback: true });
        assert!(unp(0xf8bf_0a00));
        assert!(unp(0xf8b0_0b00));
        assert_eq!(ok(0xf108_0080), Op::Cps { imod: 2, a: false, i: true, f: false, mode: None });
        assert_eq!(ok(0xf102_0013), Op::Cps { imod: 0, a: false, i: false, f: false, mode: Some(19) });
        assert_eq!(ok(0xf10e_0053), Op::Cps { imod: 3, a: false, i: false, f: true, mode: Some(19) });
        assert!(unp(0xf100_0013)); // mode with M == 0
        assert!(unp(0xf108_0000)); // enable with no A:I:F
        assert!(unp(0xf104_0080)); // imod 01
        assert_eq!(ok(0xf101_0200), Op::Setend { big: true });
        assert_eq!(ok(0xf101_0000), Op::Setend { big: false });
        assert!(unp(0xf101_0001));
        assert_eq!(ok(0xf57f_f01f), Op::Clrex);
        assert_eq!(ok(0xf57f_f05f), Op::Barrier { kind: Barrier::Dmb, option: 15 });
        assert_eq!(ok(0xf57f_f04b), Op::Barrier { kind: Barrier::Dsb, option: 11 });
        assert_eq!(ok(0xf57f_f06f), Op::Barrier { kind: Barrier::Isb, option: 15 });
        assert!(unp(0xf57f_f15f));
        assert_eq!(text(0xf57f_f050), "dmb #0x0");
        assert_eq!(ok(0xf5d2_f004), Op::Pld { write: false, instr: false, rn: r(2), offset: Offset::Imm(4) });
        assert_eq!(ok(0xf552_f004), Op::Pld { write: false, instr: false, rn: r(2), offset: Offset::Imm(-4) });
        assert_eq!(ok(0xf592_f004), Op::Pld { write: true, instr: false, rn: r(2), offset: Offset::Imm(4) });
        assert_eq!(base(0xf592_f004), Op::Undefined);
        assert_eq!(ok(0xf4d2_f004), Op::Pld { write: false, instr: true, rn: r(2), offset: Offset::Imm(4) });
        assert_eq!(ok(0xf55f_f004), Op::Pld { write: false, instr: false, rn: Reg::PC, offset: Offset::Imm(-4) });
        let reg3 = Offset::Reg { rm: r(3), shift: Shift::Lsl, amount: 0, add: true };
        assert_eq!(ok(0xf7d2_f003), Op::Pld { write: false, instr: false, rn: r(2), offset: reg3 });
        assert_eq!(ok(0xf792_f003), Op::Pld { write: true, instr: false, rn: r(2), offset: reg3 });
        assert_eq!(ok(0xf6d2_f003), Op::Pld { write: false, instr: true, rn: r(2), offset: reg3 });
        assert!(unp(0xf7d2_f00f)); // m == 15
        assert!(unp(0xf79f_f003)); // PLDW n == 15
        assert!(!unp(0xf7df_f003)); // PLD n == 15 is allowed
        assert!(unp(0xf5d2_0004)); // (1) bits 15:12
        // PLDW's encoding with Rn = 1111 is PLD (literal) with R = 0.
        assert!(matches!(op(0xf51f_f004), Op::Pld { write: false, rn: Reg::PC, .. }));
        assert!(unp(0xf51f_f004));
        // Unallocated memory hints (MP Extensions) are NOPs.
        assert_eq!(ok(0xf412_0000), Op::Hint(Hint::Nop));
        assert_eq!(ok(0xf612_0000), Op::Hint(Hint::Nop));
        assert_eq!(base(0xf412_0000), Op::Undefined);
        assert_eq!(op(0xf612_0010), Op::Undefined);
        // The UNPREDICTABLE rows of Table A5-24 have no instruction.
        for w in [0xf432_0000u32, 0xf57f_f000, 0xf57f_f07f, 0xf530_0000, 0xf5b0_0000, 0xf670_0000, 0xf120_0070] {
            let i = d(w);
            assert!(i.is_undefined() && i.unpredictable.is_some(), "{w:08x}");
        }
        // Permanently UNDEFINED, and other unallocated encodings.
        for w in [0xf7f0_00f0u32, 0xf110_0000, 0xf500_0000, 0xf800_0000, 0xf850_0000] {
            let i = d(w);
            assert!(i.is_undefined() && i.unpredictable.is_none(), "{w:08x}");
        }
    }

    #[test]
    fn inst_fields_and_totality() {
        let i = d(0x1081_0002);
        assert_eq!(i.cond, Cond::NE);
        assert_eq!((i.len, i.raw, i.set), (4, 0x1081_0002, InstrSet::Arm));
        assert_eq!(d(0xf57f_f01f).cond, Cond::AL);
        // Never panics, under either feature set.
        let mut x: u64 = 0x1234_5678_9abc_def1;
        for _ in 0..300_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let w = x as u32;
            let _ = fmt::disasm(&decode(w, &Features::ALL));
            let _ = decode(w, &Features::BASE);
        }
    }
}
