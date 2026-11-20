//! `gex-isa-a32` — AArch32 instruction decoder: ARMv7-A's ARM (A32) and
//! Thumb (T32, 16- and 32-bit) instruction sets, as the ARM Architecture
//! Reference Manual, ARMv7-A and ARMv7-R edition (ARM DDI 0406C.d) encodes
//! them: chapter A5 (ARM), A6 (Thumb), A7 (Advanced SIMD and Floating-point)
//! and the encoding diagrams of A8 and B9.
//!
//! Both instruction sets decode to one [`Inst`], since the Arm ARM gives
//! each instruction one operation shared by all of its encodings. The
//! invariants the lifter depends on are the A64 decoder's:
//!
//! * **Total.** Every encoding decodes to some `Inst`. An encoding the Arm
//!   ARM declares UNDEFINED, or that belongs to an extension the core does
//!   not have ([`Features`]), is [`Op::Undefined`]: executing it takes the
//!   Undefined Instruction exception. Never panics.
//! * **UNPREDICTABLE is reported, never chosen.** An encoding the Arm ARM
//!   declares UNPREDICTABLE, including a bit shown as `(0)` or `(1)` that
//!   does not have that value (A5.1.2, A6.1.1), decodes to its instruction
//!   with [`Inst::unpredictable`] naming the rule. The lifter refuses it.
//! * **Encoding-specific operations done.** Register roles, `DecodeImmShift`,
//!   `ARMExpandImm_C` / `ThumbExpandImm_C`, sign extension of offsets, the
//!   add/subtract of an offset and the `SEE` redirections of the Arm ARM's
//!   decode pseudocode are resolved, so the lifter implements each operation
//!   once from its A8 pseudocode.

#![forbid(unsafe_code)]

pub mod a32;
pub mod fmt;
pub mod fp;
pub mod t32;

/// The instruction set an encoding is in (B1.4, the CPSR's J and T bits:
/// ARMv7-A's Jazelle is the trivial implementation, and ThumbEE is a
/// [`Features`] option).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum InstrSet {
    Arm,
    Thumb,
}

/// An ARM core register `R0`-`R15` (A2.3). `R13` is SP, `R14` LR, `R15` PC.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Reg(pub u8);

impl Reg {
    pub const SP: Reg = Reg(13);
    pub const LR: Reg = Reg(14);
    pub const PC: Reg = Reg(15);

    #[inline]
    pub fn of(field: u32) -> Reg {
        Reg((field & 15) as u8)
    }
    #[inline]
    pub fn n(self) -> u32 {
        self.0 as u32
    }
    #[inline]
    pub fn is_pc(self) -> bool {
        self.0 == 15
    }
    #[inline]
    pub fn is_sp(self) -> bool {
        self.0 == 13
    }
}

/// A condition (A8.3, Table A8-1). `0b1110` is AL. In an [`Inst`] the
/// condition is the one the instruction executes under: an ARM
/// instruction's `cond` field, a Thumb instruction's from ITSTATE or its own
/// field (`B<c>`), AL otherwise.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Cond(pub u8);

impl Cond {
    pub const EQ: Cond = Cond(0);
    pub const NE: Cond = Cond(1);
    pub const AL: Cond = Cond(14);

    #[inline]
    pub fn is_always(self) -> bool {
        self.0 >= 14
    }

    pub fn name(self) -> &'static str {
        const N: [&str; 16] = [
            "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "", "",
        ];
        N[(self.0 & 15) as usize]
    }

    /// `ConditionHolds` (A8.3.1) on the four flags.
    pub fn holds(self, n: bool, z: bool, c: bool, v: bool) -> bool {
        let r = match self.0 >> 1 {
            0 => z,
            1 => c,
            2 => n,
            3 => v,
            4 => c && !z,
            5 => n == v,
            6 => n == v && !z,
            _ => true,
        };
        if self.0 & 1 == 1 && self.0 != 15 {
            !r
        } else {
            r
        }
    }
}

/// `SRType` (A8.4.3).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Shift {
    Lsl,
    Lsr,
    Asr,
    Ror,
    /// Rotate right with extend, by one.
    Rrx,
}

impl Shift {
    /// The 2-bit `type` field as register-shifted-register operands use it
    /// (`DecodeRegShift`).
    pub fn of_type(t: u32) -> Shift {
        match t & 3 {
            0 => Shift::Lsl,
            1 => Shift::Lsr,
            2 => Shift::Asr,
            _ => Shift::Ror,
        }
    }

    /// `DecodeImmShift(type, imm5)` (A8.4.3): the shift and its amount, an
    /// LSR or ASR of 0 encoding 32, and an ROR of 0 encoding RRX.
    pub fn decode_imm(t: u32, imm5: u32) -> (Shift, u8) {
        let imm5 = (imm5 & 31) as u8;
        match t & 3 {
            0 => (Shift::Lsl, imm5),
            1 => (Shift::Lsr, if imm5 == 0 { 32 } else { imm5 }),
            2 => (Shift::Asr, if imm5 == 0 { 32 } else { imm5 }),
            _ => {
                if imm5 == 0 {
                    (Shift::Rrx, 1)
                } else {
                    (Shift::Ror, imm5)
                }
            }
        }
    }
}

/// The flexible second operand of a data-processing instruction.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Operand {
    /// A modified immediate, expanded: `(imm32, carry)` from `ARMExpandImm_C`
    /// (A5.2.4) or `ThumbExpandImm_C` (A6.3.2). `carry` is `None` where the
    /// expansion returns the carry flag unchanged (no rotation), `Some` where
    /// it returns `imm32<31>` of a rotated constant. Also the plain binary
    /// immediates, with `carry: None`.
    Imm { value: u32, carry: Option<bool> },
    /// A register shifted by a constant, already through `DecodeImmShift`:
    /// `Lsl` 0 is the register itself, `Rrx` has amount 1.
    RegImm { rm: Reg, shift: Shift, amount: u8 },
    /// A register shifted by the bottom byte of another (`Rrx` never).
    RegReg { rm: Reg, shift: Shift, rs: Reg },
}

/// Data-processing operations (A5.2.1-A5.2.3, A6.3.1, A6.3.11).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum DpOp {
    And,
    Eor,
    Sub,
    Rsb,
    Add,
    Adc,
    Sbc,
    Rsc,
    Tst,
    Teq,
    Cmp,
    Cmn,
    Orr,
    /// MOV, and the shifts LSL/LSR/ASR/ROR/RRX, which are MOV of a shifted
    /// operand (`rn` unused).
    Mov,
    Bic,
    /// `rn` unused.
    Mvn,
    /// Thumb only.
    Orn,
}

impl DpOp {
    /// TST, TEQ, CMP and CMN: flags only, no destination.
    pub fn is_test(self) -> bool {
        matches!(self, DpOp::Tst | DpOp::Teq | DpOp::Cmp | DpOp::Cmn)
    }
    /// The logical operations, whose carry is the shifter's carry out.
    pub fn is_logical(self) -> bool {
        matches!(
            self,
            DpOp::And | DpOp::Eor | DpOp::Tst | DpOp::Teq | DpOp::Orr | DpOp::Mov | DpOp::Bic | DpOp::Mvn | DpOp::Orn
        )
    }
    /// MOV and MVN take no first operand.
    pub fn has_rn(self) -> bool {
        !matches!(self, DpOp::Mov | DpOp::Mvn)
    }
}

/// Long multiplies (A5.2.5, A6.3.17).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum MulLong {
    Umull,
    Umlal,
    Smull,
    Smlal,
    /// No `S` form.
    Umaal,
}

/// The parallel add/subtract operations (A5.4.1, A5.4.2, A6.3.13, A6.3.14).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum ParOp {
    Add16,
    /// ASX: add high, subtract low (exchange).
    Asx,
    /// SAX: subtract high, add low (exchange).
    Sax,
    Sub16,
    Add8,
    Sub8,
}

/// The prefix of a parallel add/subtract: signed (GE-setting), signed
/// saturating, signed halving, and the unsigned three.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum ParKind {
    S,
    Q,
    Sh,
    U,
    Uq,
    Uh,
}

/// The extend instructions (A5.4.3, A6.3.12).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum ExtKind {
    Sxtb,
    Sxth,
    Sxtb16,
    Uxtb,
    Uxth,
    Uxtb16,
}

/// Byte and bit reversals (A5.4.3, A6.3.15).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum RevKind {
    Rev,
    Rev16,
    Revsh,
    Rbit,
}

/// A load/store's access (A5.3, A5.2.8, A6.3.7-A6.3.10).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Size {
    B,
    H,
    W,
    /// Doubleword: the exclusives only (`LDREXD`/`STREXD`).
    D,
}

/// A load/store's offset from its base register.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Offset {
    /// A constant, its sign already applied (`add` folded in).
    Imm(i32),
    /// `+/- Shift(Rm, shift, amount)`, `DecodeImmShift` applied.
    Reg { rm: Reg, shift: Shift, amount: u8, add: bool },
}

/// LDM/STM addressing (A8.8.58-A8.8.61; SRS/RFE too).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Amode {
    /// Increment after.
    Ia,
    /// Increment before.
    Ib,
    /// Decrement after.
    Da,
    /// Decrement before.
    Db,
}

impl Amode {
    /// From the P (before) and U (increment) bits.
    pub fn of_pu(p: bool, u: bool) -> Amode {
        match (p, u) {
            (false, true) => Amode::Ia,
            (true, true) => Amode::Ib,
            (false, false) => Amode::Da,
            (true, false) => Amode::Db,
        }
    }
}

/// The hints (A5.2.11, A6.3.4).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Hint {
    Nop,
    Yield,
    Wfe,
    Wfi,
    Sev,
    /// CSDB, Consumption of Speculative Data Barrier (A8.8.42).
    Csdb,
    /// `DBG #option`: a hint to the debug system; a NOP without one.
    Dbg(u8),
}

/// The barriers (A8.8.43, A8.8.44, A8.8.53).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Barrier {
    Dmb,
    Dsb,
    Isb,
}

/// Which PSR an MRS/MSR names: CPSR (the APSR at PL0) or the current mode's
/// SPSR.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Psr {
    Cpsr,
    Spsr,
}

/// The value an MSR writes.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum MsrSrc {
    Imm(u32),
    Reg(Reg),
}

/// A decoded instruction's operation. Register fields hold the Arm ARM's
/// `d`, `n`, `m`, `t`, ... after the encoding-specific operations.
#[derive(Clone, PartialEq, Debug)]
pub enum Op {
    // -- data processing (A8.8.1-A8.8.14 and the like) ---------------------
    /// The sixteen (seventeen with ORN) data-processing operations. With
    /// `rd` the PC and `s` set this is SUBS PC, LR and related instructions
    /// (B9.3.20), an exception return; with `s` clear and `rd` the PC, a
    /// write of the PC (`ALUWritePC`). `rd` is unused by the tests, `rn` by
    /// MOV and MVN. A PC operand reads the PC (`+8`, `+4`), unaligned.
    Dp { op: DpOp, s: bool, rd: Reg, rn: Reg, src: Operand },
    /// ADR: `Align(PC, 4) + imm` (A8.8.12), `imm` signed. Thumb's, and the
    /// Thumb ADDW/SUBW with Rn = PC.
    Adr { rd: Reg, imm: i32 },
    /// MOVW (MOV (immediate) A2/T3): `rd = imm16`.
    Movw { rd: Reg, imm: u16 },
    /// MOVT: `rd<31:16> = imm16`.
    Movt { rd: Reg, imm: u16 },

    // -- multiplies (A5.2.5, A5.2.7, A5.4.4, A6.3.16, A6.3.17) ------------
    /// MUL{S}: `rd = rn * rm`.
    Mul { s: bool, rd: Reg, rn: Reg, rm: Reg },
    /// MLA{S}: `rd = rn * rm + ra`; MLS (`sub`): `rd = ra - rn * rm`.
    Mla { s: bool, sub: bool, rd: Reg, rn: Reg, rm: Reg, ra: Reg },
    /// UMULL, UMLAL, SMULL, SMLAL, UMAAL.
    MulLong { kind: MulLong, s: bool, rdlo: Reg, rdhi: Reg, rn: Reg, rm: Reg },
    /// SMUL<x><y> (`ra` None) and SMLA<x><y>; `n_top`/`m_top` select the
    /// top halfword of `rn` / `rm`.
    Smulxy { rd: Reg, rn: Reg, rm: Reg, ra: Option<Reg>, n_top: bool, m_top: bool },
    /// SMULW<y> (`ra` None) and SMLAW<y>.
    Smulwy { rd: Reg, rn: Reg, rm: Reg, ra: Option<Reg>, m_top: bool },
    /// SMLAL<x><y>.
    Smlalxy { rdlo: Reg, rdhi: Reg, rn: Reg, rm: Reg, n_top: bool, m_top: bool },
    /// SMUAD/SMUSD (`ra` None) and SMLAD/SMLSD: dual 16-bit multiply,
    /// products added or (`sub`) subtracted; `swap` is the X (exchange) form.
    Smlad { rd: Reg, rn: Reg, rm: Reg, ra: Option<Reg>, sub: bool, swap: bool },
    /// SMLALD/SMLSLD.
    Smlald { rdlo: Reg, rdhi: Reg, rn: Reg, rm: Reg, sub: bool, swap: bool },
    /// SMMUL (`ra` None), SMMLA, SMMLS (`sub`); `round` is the R form.
    Smmul { rd: Reg, rn: Reg, rm: Reg, ra: Option<Reg>, sub: bool, round: bool },
    /// SDIV/UDIV (A8.8.165, A8.8.248).
    Div { signed: bool, rd: Reg, rn: Reg, rm: Reg },

    // -- saturation and the media instructions ----------------------------
    /// QADD, QSUB (`sub`), QDADD, QDSUB (`double`): `rd = sat(rm +/- [2*]rn)`.
    Qadd { sub: bool, double: bool, rd: Reg, rm: Reg, rn: Reg },
    /// SSAT/USAT: saturate `Shift(rn, shift, amount)` (only LSL or ASR) to
    /// `sat` bits: `sat` is `saturate_to` (1..=32 signed, 0..=31 unsigned).
    Sat { unsigned: bool, rd: Reg, rn: Reg, sat: u8, shift: Shift, amount: u8 },
    /// SSAT16/USAT16.
    Sat16 { unsigned: bool, rd: Reg, rn: Reg, sat: u8 },
    /// The parallel add/subtract instructions.
    Parallel { kind: ParKind, op: ParOp, rd: Reg, rn: Reg, rm: Reg },
    /// SEL.
    Sel { rd: Reg, rn: Reg, rm: Reg },
    /// USAD8 (`ra` None) and USADA8.
    Usad8 { rd: Reg, rn: Reg, rm: Reg, ra: Option<Reg> },
    /// PKHBT (`tb` false: `rm` shifted left) and PKHTB (`tb`: ASR).
    Pkh { tb: bool, rd: Reg, rn: Reg, rm: Reg, amount: u8 },
    /// SXTB..UXTB16 (`rn` None) and the accumulating SXTAB..UXTAB16:
    /// `rotation` is 0, 8, 16 or 24.
    Extend { kind: ExtKind, rd: Reg, rn: Option<Reg>, rm: Reg, rotation: u8 },
    /// REV, REV16, REVSH, RBIT.
    Rev { kind: RevKind, rd: Reg, rm: Reg },
    /// CLZ.
    Clz { rd: Reg, rm: Reg },
    /// BFC (`rn` None) and BFI: bits `lsb..=msb` of `rd` from `rn`'s low bits.
    /// `msb < lsb` is UNPREDICTABLE and flagged.
    Bfi { rd: Reg, rn: Option<Reg>, lsb: u8, msb: u8 },
    /// SBFX/UBFX: `width` bits of `rn` from `lsb`.
    Bfx { signed: bool, rd: Reg, rn: Reg, lsb: u8, width: u8 },

    // -- branches (A8.8.18-A8.8.29, A8.8.192, A8.8.193) -------------------
    /// B: to `PC + imm` (PC the instruction's address + 8 or + 4).
    B { imm: i32 },
    /// BL (`switch` false) and BLX (immediate) (`switch`): to `PC + imm`
    /// in the same set, or `Align(PC, 4) + imm` in the other.
    Bl { imm: i32, switch: bool },
    /// BX.
    Bx { rm: Reg },
    /// BLX (register).
    BlxReg { rm: Reg },
    /// BXJ: with the trivial Jazelle implementation of ARMv7-A, BX.
    Bxj { rm: Reg },
    /// CBZ/CBNZ (`nonzero`): to `PC + imm`.
    Cbz { nonzero: bool, rn: Reg, imm: u32 },
    /// TBB/TBH (`half`).
    Tb { half: bool, rn: Reg, rm: Reg },

    // -- loads and stores --------------------------------------------------
    /// LDR, LDRB, LDRH, LDRSB, LDRSH, STR, STRB, STRH, and their
    /// unprivileged forms (`user`). `index` is P (offset applied before the
    /// access), `wback` is W (or post-indexing). A PC base reads
    /// `Align(PC, 4)` (the literal forms).
    Ldst { load: bool, size: Size, signed: bool, user: bool, rt: Reg, rn: Reg, offset: Offset, index: bool, wback: bool },
    /// LDRD/STRD.
    Ldrd { load: bool, rt: Reg, rt2: Reg, rn: Reg, offset: Offset, index: bool, wback: bool },
    /// LDM/STM in their four modes. `user` is the `^` form: STM (user
    /// registers), LDM (user registers) without the PC, LDM (exception
    /// return) with it.
    Ldm { load: bool, mode: Amode, rn: Reg, regs: u16, wback: bool, user: bool },
    /// LDREX{B,H,D}: `rt2` for D only; `imm` is Thumb LDREX's offset.
    Ldrex { size: Size, rt: Reg, rt2: Reg, rn: Reg, imm: u32 },
    /// STREX{B,H,D}: `rd` gets the status.
    Strex { size: Size, rd: Reg, rt: Reg, rt2: Reg, rn: Reg, imm: u32 },
    /// CLREX.
    Clrex,
    /// SWP/SWPB (`byte`): `rt = [rn]; [rn] = rt2`.
    Swp { byte: bool, rt: Reg, rt2: Reg, rn: Reg },
    /// PLD (`write` false), PLDW (`write`), PLI (`instr`). Hints: no
    /// synchronous abort, no effect on the architectural state.
    Pld { write: bool, instr: bool, rn: Reg, offset: Offset },

    // -- status registers and modes (B9.3) --------------------------------
    /// MRS: `rd = CPSR/APSR` or SPSR.
    Mrs { rd: Reg, psr: Psr },
    /// MSR: `mask` is the field mask, bit 0 `c` (7:0), 1 `x` (15:8), 2 `s`
    /// (23:16), 3 `f` (31:24). At PL0 only the APSR's `f` (NZCVQ) and `s`
    /// (GE) bits are written (A8.8.104 vs B9.3.12): the lifter decides.
    Msr { psr: Psr, mask: u8, src: MsrSrc },
    /// MRS (Banked register) (B9.3.9): `sysm` is R:SYSm.
    MrsBanked { rd: Reg, sysm: u8 },
    /// MSR (Banked register) (B9.3.10).
    MsrBanked { rn: Reg, sysm: u8 },
    /// CPS (B9.3.2): `imod` 0b10 enables, 0b11 disables the selected of
    /// `a`/`i`/`f`; `mode` changes the mode.
    Cps { imod: u8, a: bool, i: bool, f: bool, mode: Option<u8> },
    /// SETEND.
    Setend { big: bool },
    /// SRS (B9.3.16): store LR and SPSR to `mode`'s stack.
    Srs { mode: u8, amode: Amode, wback: bool },
    /// RFE (B9.3.13).
    Rfe { rn: Reg, amode: Amode, wback: bool },

    // -- exceptions and hints ----------------------------------------------
    /// SVC.
    Svc { imm: u32 },
    /// SMC (B9.3.14).
    Smc { imm: u8 },
    /// HVC (B9.3.4).
    Hvc { imm: u16 },
    /// ERET (B9.3.3).
    Eret,
    /// BKPT: unconditional even inside an IT block.
    Bkpt { imm: u16 },
    /// UDF: permanently UNDEFINED (A8.8.247).
    Udf { imm: u16 },
    Hint(Hint),
    /// DMB/DSB/ISB with their option field.
    Barrier { kind: Barrier, option: u8 },
    /// IT (A8.8.55): `firstcond` and `mask` as encoded.
    It { firstcond: u8, mask: u8 },
    /// ENTERX/LEAVEX (ThumbEE, A9.3).
    Enterx { leave: bool },

    // -- coprocessor (A8.8.31 CDP .. A8.8.100 MRRC) ------------------------
    /// MCR/MCR2 (`read` false), MRC/MRC2 (`read`). `two` is the cond-1111
    /// (ARM) or bit-28 (Thumb) form. An MRC with `rt` the PC writes NZCV.
    Mcr { read: bool, two: bool, coproc: u8, opc1: u8, rt: Reg, crn: u8, crm: u8, opc2: u8 },
    /// MCRR/MCRR2, MRRC/MRRC2.
    Mcrr { read: bool, two: bool, coproc: u8, opc1: u8, rt: Reg, rt2: Reg, crm: u8 },
    /// CDP/CDP2.
    Cdp { two: bool, coproc: u8, opc1: u8, crd: u8, crn: u8, crm: u8, opc2: u8 },
    /// LDC/LDC2/STC/STC2. `long` is the D bit (`L` in the syntax).
    /// `option` is the unindexed form's 8-bit option (then `imm` is 0 and
    /// neither `index` nor `wback`); a PC base reads `Align(PC, 4)`.
    Ldc { load: bool, two: bool, long: bool, coproc: u8, crd: u8, rn: Reg, imm: i32, index: bool, wback: bool, option: Option<u8> },

    // -- Floating-point and Advanced SIMD (chapter A7) ---------------------
    /// A Floating-point (VFP) or Advanced SIMD instruction, decoded
    /// ([`fp::FpInst`]).
    Fp(fp::FpInst),

    /// An UNDEFINED encoding: executing it takes the Undefined Instruction
    /// exception. Also every instruction of an extension the core does not
    /// have.
    Undefined,
}

/// A decoded instruction.
#[derive(Clone, PartialEq, Debug)]
pub struct Inst {
    pub op: Op,
    /// The condition it executes under (AL for the unconditional ones).
    pub cond: Cond,
    /// 4, or 2 for a 16-bit Thumb instruction.
    pub len: u8,
    /// The encoding: an ARM word; a 32-bit Thumb instruction's first
    /// halfword in bits 31:16 and its second in 15:0; a 16-bit one's
    /// halfword in 15:0.
    pub raw: u32,
    pub set: InstrSet,
    /// Why the Arm ARM makes this encoding UNPREDICTABLE, when it does: the
    /// pseudocode condition or the `(0)`/`(1)` bit, and the section.
    pub unpredictable: Option<&'static str>,
}

impl Inst {
    pub fn is_undefined(&self) -> bool {
        matches!(self.op, Op::Undefined)
    }
}

/// Floating-point (VFP) extension version (A2.6, B1.11).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum VfpVersion {
    V3,
    V4,
}

/// What the core implements of ARMv7-A's optional parts: an instruction of
/// an absent extension is UNDEFINED (A5.1.2, A6.1.1). The ID registers
/// (ID_ISAR0-5, ID_PFR0/1, MVFR0/1) report the same choices.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Features {
    /// SDIV/UDIV in the Thumb instruction set (ID_ISAR0.Divide_instrs >= 1).
    pub thumb_div: bool,
    /// SDIV/UDIV in the ARM instruction set (Divide_instrs == 2).
    pub arm_div: bool,
    /// The Security Extensions: SMC, Monitor mode, the banked CP15.
    pub security: bool,
    /// The Virtualization Extensions: HVC, ERET, the Banked-register
    /// MRS/MSR, Hyp mode. Implies `security` and `lpae`.
    pub virtualization: bool,
    /// The Multiprocessing Extensions: PLDW.
    pub mp: bool,
    /// The Large Physical Address Extension.
    pub lpae: bool,
    /// ThumbEE (ENTERX/LEAVEX, the ThumbEE state).
    pub thumbee: bool,
    /// The Floating-point extension, if any.
    pub vfp: Option<VfpVersion>,
    /// Thirty-two doubleword registers (VFPv3-D32 / Advanced SIMD); sixteen
    /// otherwise: D16-D31 are then UNDEFINED.
    pub d32: bool,
    /// The Advanced SIMD extension. ARMv7 requires VFPv3-D32 with it.
    pub simd: bool,
    /// The half-precision extension (VCVT between half and single).
    pub fp16: bool,
}

impl Features {
    /// A core with every optional part of ARMv7-A: the Cortex-A15's choice
    /// (VFPv4-D32, Advanced SIMDv2, both dividers, the Security,
    /// Virtualization, Multiprocessing and Large Physical Address
    /// Extensions), without ThumbEE.
    pub const ALL: Features = Features {
        thumb_div: true,
        arm_div: true,
        security: true,
        virtualization: true,
        mp: true,
        lpae: true,
        thumbee: false,
        vfp: Some(VfpVersion::V4),
        d32: true,
        simd: true,
        fp16: true,
    };

    /// ARMv7-A with none of its options.
    pub const BASE: Features = Features {
        thumb_div: false,
        arm_div: false,
        security: false,
        virtualization: false,
        mp: false,
        lpae: false,
        thumbee: false,
        vfp: None,
        d32: false,
        simd: false,
        fp16: false,
    };
}

/// ITSTATE (A2.5.2): `IT<7:5>` the base condition, `IT<4:0>` the size and
/// the next instructions' condition bits. Zero outside an IT block.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct ItState(pub u8);

impl ItState {
    /// `InITBlock()`.
    #[inline]
    pub fn in_it(self) -> bool {
        self.0 & 0xf != 0
    }
    /// `LastInITBlock()`.
    #[inline]
    pub fn last_in_it(self) -> bool {
        self.0 & 0xf == 0b1000
    }
    /// The current instruction's condition (`CurrentCond()` in a block).
    #[inline]
    pub fn cond(self) -> Cond {
        Cond(self.0 >> 4)
    }
    /// `ITAdvance()`.
    #[inline]
    pub fn advance(self) -> ItState {
        if self.0 & 7 == 0 {
            ItState(0)
        } else {
            ItState((self.0 & 0xe0) | ((self.0 << 1) & 0x1f))
        }
    }
}

/// Decode one ARM instruction word.
pub fn decode_arm(word: u32, f: &Features) -> Inst {
    a32::decode(word, f)
}

/// Decode the Thumb instruction starting with halfword `hw1`, `hw2` the
/// next halfword (ignored for a 16-bit instruction), in IT state `it`.
pub fn decode_thumb(hw1: u16, hw2: u16, it: ItState, f: &Features) -> Inst {
    t32::decode(hw1, hw2, it, f)
}

/// Whether `hw1` begins a 32-bit Thumb instruction (A6.1).
#[inline]
pub fn thumb_is_32(hw1: u16) -> bool {
    matches!(hw1 >> 11, 0b11101 | 0b11110 | 0b11111)
}
