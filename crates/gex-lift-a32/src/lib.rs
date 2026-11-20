//! `gex-lift-a32` — AArch32 (ARMv7-A ARM and Thumb) instruction semantics
//! in GIR, from the operation pseudocode of the ARM Architecture Reference
//! Manual, ARMv7-A and ARMv7-R edition (ARM DDI 0406C.d), chapters A8 and B9.
//!
//! The core is a system-level one (the SEP's), so its state is split as
//! `gex_abi::a32` describes: the current mode's `R0`-`R14`, the flags, Q and
//! GE live in the thread context, where translated code computes on them;
//! everything else (the mode and its banked registers, the SPSRs, the rest
//! of the CPSR, the coprocessor registers, the memory system) is the host's
//! model of the core, reached through two host calls:
//!
//! * `A32Mem` translates every data access's virtual address to the host
//!   address it is made at, or takes the Data Abort its translation and
//!   checks raise (the host does not return);
//! * `A32Sys` does every system-level operation: MRS/MSR/CPS, the
//!   coprocessor registers, exception entry and return, WFI/WFE, and the
//!   loud stop of an UNPREDICTABLE encoding or of what gex does not
//!   implement.
//!
//! Both are clobbering calls: the emitter writes every register back before
//! them and reloads after, so the host always sees the exact architectural
//! state of the instruction it is called for.
//!
//! Conditional execution (A8.3) is lifted by predication: an instruction
//! whose condition is not AL computes its condition once, and every
//! register and flag it writes keeps its old value, every access goes to
//! the sink, and every system operation becomes a NOP, where the condition
//! fails. A branch's condition becomes the block's two-way terminator.

#![forbid(unsafe_code)]

pub mod block;
mod media;
mod mem;
mod sys;

pub use block::{lift_block, BlockLimits};

use gex_abi::a32 as abi;
use gex_ir::{BinOp, Builder, CmpOp, Expr, GuestReg, HostFunc, Stmt, Term, Ty, UnOp, Value};
use gex_isa_a32::*;

/// How an instruction left the block.
pub enum Flow {
    /// Execution continues with the next instruction.
    Next,
    /// The instruction ends the block.
    End(Term),
}

/// Lifts one instruction.
pub struct Lifter<'a> {
    pub(crate) b: &'a mut Builder,
    pub(crate) set: InstrSet,
    /// The instruction's address.
    pub(crate) addr: u32,
    /// Its key (`gex_abi::a32::key`), with the ITSTATE it executes in.
    pub(crate) key: u64,
    /// The key of the instruction after it, its ITSTATE advanced.
    pub(crate) next: u64,
    /// Whether the condition passed (an `I32` 0 or 1), `None` for AL.
    pub(crate) pred: Option<Value>,
    pub(crate) raw: u32,
    pub(crate) len: u8,
}

/// A PC write: where control goes after the instruction, if it goes
/// anywhere but on.
pub(crate) enum PcWrite {
    /// A constant key.
    Key(u64),
    /// A computed key (`I64`).
    Dyn(Value),
}

impl<'a> Lifter<'a> {
    pub fn new(b: &'a mut Builder, set: InstrSet, addr: u32, key: u64, next: u64, raw: u32, len: u8) -> Lifter<'a> {
        Lifter { b, set, addr, key, next, pred: None, raw, len }
    }

    pub(crate) fn thumb(&self) -> bool {
        self.set == InstrSet::Thumb
    }

    // -- values --------------------------------------------------------------

    pub(crate) fn c32(&mut self, v: u32) -> Value {
        self.b.const_i32(v)
    }

    pub(crate) fn c64(&mut self, v: u64) -> Value {
        self.b.const_i64(v)
    }

    pub(crate) fn bin(&mut self, op: BinOp, a: Value, b: Value) -> Value {
        self.b.bin(op, Ty::I32, a, b)
    }

    pub(crate) fn bin64(&mut self, op: BinOp, a: Value, b: Value) -> Value {
        self.b.bin(op, Ty::I64, a, b)
    }

    pub(crate) fn bini(&mut self, op: BinOp, a: Value, k: u32) -> Value {
        let k = self.c32(k);
        self.bin(op, a, k)
    }

    pub(crate) fn bini64(&mut self, op: BinOp, a: Value, k: u64) -> Value {
        let k = self.c64(k);
        self.bin64(op, a, k)
    }

    pub(crate) fn cmp(&mut self, op: CmpOp, a: Value, b: Value) -> Value {
        self.b.cmp(op, Ty::I32, a, b)
    }

    pub(crate) fn cmpi(&mut self, op: CmpOp, a: Value, k: u32) -> Value {
        let k = self.c32(k);
        self.cmp(op, a, k)
    }

    pub(crate) fn sel(&mut self, c: Value, a: Value, b: Value) -> Value {
        self.b.select(c, a, b, Ty::I32)
    }

    pub(crate) fn sel64(&mut self, c: Value, a: Value, b: Value) -> Value {
        self.b.select(c, a, b, Ty::I64)
    }

    pub(crate) fn zext(&mut self, v: Value) -> Value {
        self.b.extend(v, false)
    }

    pub(crate) fn sext(&mut self, v: Value) -> Value {
        self.b.extend(v, true)
    }

    pub(crate) fn wrap(&mut self, v: Value) -> Value {
        self.b.wrap(v)
    }

    /// Bit `n` of an `I32`, as 0 or 1.
    pub(crate) fn bit(&mut self, v: Value, n: u32) -> Value {
        let s = self.bini(BinOp::ShrU, v, n);
        self.bini(BinOp::And, s, 1)
    }

    /// `ExtendBits`: the low `bits` of an `I32`, sign- or zero-extended.
    pub(crate) fn ext_bits(&mut self, v: Value, bits: u32, signed: bool) -> Value {
        self.b.def(Expr::ExtendBits { a: v, ty: Ty::I32, bits, signed })
    }

    pub(crate) fn not(&mut self, v: Value) -> Value {
        self.b.un(UnOp::Not, Ty::I32, v)
    }

    // -- the PC and the registers (A2.3, A8.4) -------------------------------

    /// The value a read of the PC gives: the instruction's address plus 8
    /// (ARM) or 4 (Thumb).
    pub(crate) fn pc_value(&self) -> u32 {
        self.addr.wrapping_add(if self.thumb() { 4 } else { 8 })
    }

    /// `R[r]`, an `I32`.
    pub(crate) fn r(&mut self, r: Reg) -> Value {
        if r.is_pc() {
            let v = self.pc_value();
            return self.c32(v);
        }
        let x = self.b.read(GuestReg::X(r.0));
        self.wrap(x)
    }

    /// A base register as a load/store or ADR reads it: the PC is
    /// `Align(PC, 4)` (A6.1.2; in the ARM state the PC is aligned already).
    pub(crate) fn r_base(&mut self, r: Reg) -> Value {
        if r.is_pc() {
            let v = self.pc_value() & !3;
            return self.c32(v);
        }
        self.r(r)
    }

    /// `R[r] = v` for `r` not the PC, kept as it was where the condition
    /// fails.
    pub(crate) fn w(&mut self, r: Reg, v: Value) {
        debug_assert!(!r.is_pc());
        let v = match self.pred {
            Some(p) => {
                let old = self.r(r);
                self.sel(p, v, old)
            }
            None => v,
        };
        let x = self.zext(v);
        self.b.write(GuestReg::X(r.0), x);
    }

    /// Write a flag (0 or 1), predicated.
    pub(crate) fn wflag(&mut self, f: GuestReg, v: Value) {
        let v = match self.pred {
            Some(p) => {
                let old = self.b.read(f);
                self.sel(p, v, old)
            }
            None => v,
        };
        self.b.write(f, v);
    }

    /// N and Z of a 32-bit result.
    pub(crate) fn nz(&mut self, result: Value) {
        let n = self.bit(result, 31);
        let z = self.cmpi(CmpOp::Eq, result, 0);
        self.wflag(GuestReg::N, n);
        self.wflag(GuestReg::Z, z);
    }

    /// The Q flag (`ctx::x(Q)`), an `I32`.
    pub(crate) fn q(&mut self) -> Value {
        let x = self.b.read(GuestReg::X(abi::Q));
        self.wrap(x)
    }

    /// Set Q where `sat` (0 or 1) is 1; Q is sticky.
    pub(crate) fn set_q(&mut self, sat: Value) {
        let q = self.q();
        let v = self.bin(BinOp::Or, q, sat);
        let v = match self.pred {
            Some(p) => self.sel(p, v, q),
            None => v,
        };
        let x = self.zext(v);
        self.b.write(GuestReg::X(abi::Q), x);
    }

    pub(crate) fn ge(&mut self) -> Value {
        let x = self.b.read(GuestReg::X(abi::GE));
        self.wrap(x)
    }

    pub(crate) fn set_ge(&mut self, v: Value) {
        let v = match self.pred {
            Some(p) => {
                let old = self.ge();
                self.sel(p, v, old)
            }
            None => v,
        };
        let x = self.zext(v);
        self.b.write(GuestReg::X(abi::GE), x);
    }

    pub(crate) fn carry(&mut self) -> Value {
        self.b.read(GuestReg::C)
    }

    // -- conditions (A8.3.1) ------------------------------------------------

    /// `ConditionHolds(cond)` on the flags, an `I32` 0 or 1.
    pub(crate) fn cond_holds(&mut self, cond: Cond) -> Value {
        let n = self.b.read(GuestReg::N);
        let z = self.b.read(GuestReg::Z);
        let c = self.b.read(GuestReg::C);
        let v = self.b.read(GuestReg::V);
        let base = match cond.0 >> 1 {
            0 => z,
            1 => c,
            2 => n,
            3 => v,
            4 => {
                // C == 1 && Z == 0
                let nz = self.bini(BinOp::Xor, z, 1);
                self.bin(BinOp::And, c, nz)
            }
            5 => self.cmp(CmpOp::Eq, n, v),
            6 => {
                let eq = self.cmp(CmpOp::Eq, n, v);
                let nz = self.bini(BinOp::Xor, z, 1);
                self.bin(BinOp::And, eq, nz)
            }
            _ => return self.c32(1),
        };
        if cond.0 & 1 == 1 {
            self.bini(BinOp::Xor, base, 1)
        } else {
            base
        }
    }

    // -- the shifter (A8.4.3) -------------------------------------------------

    /// `Shift_C(value, type, amount, carry_in)` with a constant amount, as
    /// `DecodeImmShift` gives it: the result and, when asked for, the
    /// carry out.
    pub(crate) fn shift_imm(&mut self, x: Value, shift: Shift, amount: u8, want_carry: bool) -> (Value, Option<Value>) {
        let n = amount as u32;
        if n == 0 && shift != Shift::Rrx {
            // A zero shift (only LSL #0 decodes to one) is the value and C.
            let c = want_carry.then(|| self.carry());
            return (x, c);
        }
        match shift {
            Shift::Lsl => {
                // LSL_C: carry is x<32-n>.
                let r = self.bini(BinOp::Shl, x, n);
                let c = want_carry.then(|| self.bit(x, 32 - n));
                (r, c)
            }
            Shift::Lsr => {
                let r = if n == 32 { self.c32(0) } else { self.bini(BinOp::ShrU, x, n) };
                let c = want_carry.then(|| self.bit(x, n - 1));
                (r, c)
            }
            Shift::Asr => {
                let r = self.bini(BinOp::ShrS, x, n.min(31));
                let c = want_carry.then(|| self.bit(x, n.min(32) - 1));
                (r, c)
            }
            Shift::Ror => {
                let r = self.bini(BinOp::Rotr, x, n & 31);
                let c = want_carry.then(|| self.bit(r, 31));
                (r, c)
            }
            Shift::Rrx => {
                // RRX_C: (carry_in : x<31:1>), carry out x<0>.
                let c_in = self.carry();
                let top = self.bini(BinOp::Shl, c_in, 31);
                let lo = self.bini(BinOp::ShrU, x, 1);
                let r = self.bin(BinOp::Or, top, lo);
                let c = want_carry.then(|| self.bini(BinOp::And, x, 1));
                (r, c)
            }
        }
    }

    /// `Shift_C` by `Rs<7:0>` (register-shifted register operands): every
    /// amount 0..=255 as the pseudocode defines it (A8.4.3), computed on
    /// 64-bit values so that no wasm shift masks the amount.
    pub(crate) fn shift_reg(&mut self, x: Value, shift: Shift, rs: Value, want_carry: bool) -> (Value, Option<Value>) {
        let amt = self.bini(BinOp::And, rs, 0xff);
        let zero_amt = self.cmpi(CmpOp::Eq, amt, 0);
        // Amounts of 33 and more behave as 33 for LSL, LSR and ASR.
        let big = self.cmpi(CmpOp::GtU, amt, 40);
        let k40 = self.c32(40);
        let clamped = self.sel(big, k40, amt);
        let cl64 = self.zext(clamped);
        let (r, c) = match shift {
            Shift::Lsl => {
                let x64 = self.zext(x);
                let t = self.bin64(BinOp::Shl, x64, cl64);
                let r = self.wrap(t);
                let c = want_carry.then(|| {
                    let s = self.bini64(BinOp::ShrU, t, 32);
                    let s = self.wrap(s);
                    self.bini(BinOp::And, s, 1)
                });
                (r, c)
            }
            Shift::Lsr | Shift::Asr => {
                // (x << 1) >> amount: bit 0 is the last bit shifted out.
                let x64 = if shift == Shift::Lsr { self.zext(x) } else { self.sext(x) };
                let t = self.bini64(BinOp::Shl, x64, 1);
                let t = self.bin64(if shift == Shift::Lsr { BinOp::ShrU } else { BinOp::ShrS }, t, cl64);
                let r = self.bini64(BinOp::ShrS, t, 1);
                let r = self.wrap(r);
                let c = want_carry.then(|| {
                    let t32 = self.wrap(t);
                    self.bini(BinOp::And, t32, 1)
                });
                (r, c)
            }
            Shift::Ror | Shift::Rrx => {
                // ROR_C by amount mod 32; a multiple of 32 leaves x, carry x<31>.
                let n = self.bini(BinOp::And, amt, 31);
                let r = self.bin(BinOp::Rotr, x, n);
                let c = want_carry.then(|| self.bit(r, 31));
                (r, c)
            }
        };
        // An amount of 0: the value unchanged and the carry flag.
        let r = self.sel(zero_amt, x, r);
        let c = c.map(|c| {
            let cin = self.carry();
            self.sel(zero_amt, cin, c)
        });
        (r, c)
    }

    /// The second operand of a data-processing instruction: its value and,
    /// when asked for, the shifter's carry out.
    pub(crate) fn operand(&mut self, src: &Operand, want_carry: bool) -> (Value, Option<Value>) {
        match *src {
            Operand::Imm { value, carry } => {
                let v = self.c32(value);
                let c = want_carry.then(|| match carry {
                    Some(b) => self.c32(b as u32),
                    None => self.carry(),
                });
                (v, c)
            }
            Operand::RegImm { rm, shift, amount } => {
                let x = self.r(rm);
                self.shift_imm(x, shift, amount, want_carry)
            }
            Operand::RegReg { rm, shift, rs } => {
                let x = self.r(rm);
                let s = self.r(rs);
                self.shift_reg(x, shift, s, want_carry)
            }
        }
    }

    /// `AddWithCarry(x, y, carry_in)` (A2.2.1): the result, the carry and
    /// the overflow.
    pub(crate) fn add_with_carry(&mut self, x: Value, y: Value, cin: Value) -> (Value, Value, Value) {
        let x64 = self.zext(x);
        let y64 = self.zext(y);
        let c64 = self.zext(cin);
        let s = self.bin64(BinOp::Add, x64, y64);
        let s = self.bin64(BinOp::Add, s, c64);
        let r = self.wrap(s);
        let hi = self.bini64(BinOp::ShrU, s, 32);
        let carry = self.wrap(hi);
        // Overflow: the operands agree in sign and the result does not.
        let a = self.bin(BinOp::Xor, x, r);
        let b2 = self.bin(BinOp::Xor, y, r);
        let o = self.bin(BinOp::And, a, b2);
        let v = self.bit(o, 31);
        (r, carry, v)
    }

    // -- PC writes (A2.3.2) ---------------------------------------------------

    /// The PL0 bit of this block's keys, which every branch keeps.
    pub(crate) fn user(&self) -> u64 {
        self.key & abi::KEY_USER
    }

    /// The key of a branch to `addr` in the current instruction set.
    pub(crate) fn key_same(&self, addr: u32) -> u64 {
        self.user()
            | if self.thumb() {
                abi::key(addr & !1, true, 0)
            } else {
                abi::key(addr & !3, false, 0)
            }
    }

    /// The key of a computed address (`I32`) whose bit 0 is the Thumb bit.
    fn dyn_key(&mut self, a: Value) -> PcWrite {
        let k = self.zext(a);
        let u = self.user();
        PcWrite::Dyn(if u != 0 { self.bini64(BinOp::Or, k, u) } else { k })
    }

    /// `BranchWritePC` of a computed address: ARM `address<31:2>:'00'`,
    /// Thumb `address<31:1>:'0'`, the set unchanged.
    pub(crate) fn branch_write_pc(&mut self, a: Value) -> PcWrite {
        let a = if self.thumb() {
            let m = self.bini(BinOp::And, a, !1);
            self.bini(BinOp::Or, m, 1)
        } else {
            self.bini(BinOp::And, a, !3)
        };
        self.dyn_key(a)
    }

    /// `BXWritePC`: bit 0 selects Thumb, which is the key's own bit 0; in
    /// the ARM state bits 1:0 of `0b10` are UNPREDICTABLE, which a trap
    /// reports.
    pub(crate) fn bx_write_pc(&mut self, a: Value) -> PcWrite {
        let low = self.bini(BinOp::And, a, 3);
        let bad = self.cmpi(CmpOp::Eq, low, 2);
        let bad = match self.pred {
            Some(p) => self.bin(BinOp::And, bad, p),
            None => bad,
        };
        self.b.stmt(Stmt::Trap { cond: bad, pc: self.key, code: abi::BRK_UNPREDICTABLE_PC });
        self.dyn_key(a)
    }

    /// `ALUWritePC`: BXWritePC in the ARM state (ARMv7), else BranchWritePC.
    pub(crate) fn alu_write_pc(&mut self, a: Value) -> PcWrite {
        if self.thumb() {
            self.branch_write_pc(a)
        } else {
            self.bx_write_pc(a)
        }
    }

    /// `LoadWritePC`: BXWritePC (ARMv5 and later).
    pub(crate) fn load_write_pc(&mut self, a: Value) -> PcWrite {
        self.bx_write_pc(a)
    }

    /// The terminator a PC write gives, the condition applied.
    pub(crate) fn end_with(&mut self, w: PcWrite) -> Flow {
        let next = self.next;
        Flow::End(match (w, self.pred) {
            (PcWrite::Key(k), None) => Term::Goto { target: k },
            (PcWrite::Key(k), Some(p)) => Term::Branch { cond: p, taken: k, not_taken: next },
            (PcWrite::Dyn(v), None) => Term::Indirect { target: v, is_ret: false },
            (PcWrite::Dyn(v), Some(p)) => {
                let n = self.c64(next);
                let t = self.sel64(p, v, n);
                Term::Indirect { target: t, is_ret: false }
            }
        })
    }

    /// End the block at the PC the context holds (after a system
    /// operation that may have changed it).
    pub(crate) fn end_at_context_pc(&mut self) -> Flow {
        let t = self.b.read(GuestReg::Pc);
        Flow::End(Term::Indirect { target: t, is_ret: false })
    }

    // -- host calls -----------------------------------------------------------

    /// An `A32Sys` operation, a NOP where the condition fails. The PC is
    /// set to the next instruction first, so an operation that does not
    /// change it carries on there.
    pub(crate) fn sys(&mut self, op: i32, a: Value, b: Value) -> Value {
        let opv = self.c32(op as u32);
        let opv = match self.pred {
            Some(p) => {
                let nop = self.c32(abi::sys::NOP as u32);
                self.sel(p, opv, nop)
            }
            None => opv,
        };
        self.sys_raw(opv, a, b)
    }

    /// An `A32Sys` operation whatever the condition.
    pub(crate) fn sys_raw(&mut self, op: Value, a: Value, b: Value) -> Value {
        let pc = self.c64(self.key);
        self.b.def(Expr::HostCall { func: HostFunc::A32Sys, args: vec![pc, op, a, b], ty: Ty::I64 })
    }

    pub(crate) fn sys_k(&mut self, op: i32, a: u64, b: u64) -> Value {
        let a = self.c64(a);
        let b = self.c64(b);
        self.sys(op, a, b)
    }

    /// The PC the context holds is the next instruction's, for a system
    /// operation that may branch elsewhere.
    pub(crate) fn pc_to_next(&mut self) {
        let n = self.c64(self.next);
        self.b.write(GuestReg::Pc, n);
    }

    /// Take exception `kind` at this instruction where the condition
    /// passes, and end the block.
    pub(crate) fn exception(&mut self, kind: i64, info: u64) -> Flow {
        self.pc_to_next();
        let a = self.c64(kind as u64);
        let b = self.c64(info);
        self.sys(abi::sys::EXCEPTION, a, b);
        self.end_at_context_pc()
    }

    /// An UNDEFINED encoding: the Undefined Instruction exception where the
    /// condition passes; where it fails, the IMPLEMENTATION DEFINED choice
    /// of B1.9 (Conditional execution of undefined instructions), the
    /// host's.
    pub(crate) fn undefined(&mut self) -> Flow {
        self.pc_to_next();
        let op = self.c32(abi::sys::EXCEPTION as u32);
        let op = match self.pred {
            Some(p) => {
                let failed = self.c32(abi::sys::UNDEF_COND_FAILED as u32);
                self.sel(p, op, failed)
            }
            None => op,
        };
        let a = self.c64(abi::exc::UNDEFINED as u64);
        let b = self.c64(0);
        self.sys_raw(op, a, b);
        self.end_at_context_pc()
    }

    /// An UNPREDICTABLE encoding: a loud stop when reached, whatever the
    /// condition.
    pub(crate) fn unpredictable(&mut self) -> Flow {
        self.pc_to_next();
        let op = self.c32(abi::sys::UNPREDICTABLE as u32);
        let a = self.c64(self.raw as u64);
        let b = self.c64(self.len as u64);
        self.sys_raw(op, a, b);
        self.end_at_context_pc()
    }

    /// Something gex does not implement: a loud stop where the condition
    /// passes (the host may first take an exception the architecture
    /// defines, e.g. the Undefined Instruction exception of a disabled
    /// Floating-point unit).
    pub(crate) fn unimplemented(&mut self, what: i64) -> Flow {
        self.pc_to_next();
        let a = self.c64(what as u64);
        let b = self.c64(self.raw as u64);
        self.sys(abi::sys::UNIMPLEMENTED, a, b);
        self.end_at_context_pc()
    }

    /// The host address of a data access to `va` (`I32`), `access` as
    /// `gex_abi::a32::mem` encodes it; the sink where the condition fails.
    pub(crate) fn mem(&mut self, va: Value, access: i32) -> Value {
        let acc = self.c32(access as u32);
        let acc = match self.pred {
            Some(p) => {
                let skip = self.c32((access | abi::mem::SKIP) as u32);
                self.sel(p, acc, skip)
            }
            None => acc,
        };
        let pc = self.c64(self.key);
        let va = self.zext(va);
        self.b.def(Expr::HostCall { func: HostFunc::A32Mem, args: vec![pc, va, acc], ty: Ty::I64 })
    }

    // -- the instructions -----------------------------------------------------

    /// Lift `inst`.
    pub fn lift(&mut self, inst: &Inst) -> Flow {
        if inst.unpredictable.is_some() {
            return self.unpredictable();
        }
        if !inst.cond.is_always() && !matches!(inst.op, Op::B { .. }) {
            let c = self.cond_holds(inst.cond);
            self.pred = Some(c);
        }
        match &inst.op {
            Op::Dp { op, s, rd, rn, src } => self.dp(*op, *s, *rd, *rn, src),
            Op::Adr { rd, imm } => {
                let v = (self.pc_value() & !3).wrapping_add(*imm as u32);
                let v = self.c32(v);
                self.write_or_branch(*rd, v, false)
            }
            Op::Movw { rd, imm } => {
                let v = self.c32(*imm as u32);
                self.w(*rd, v);
                Flow::Next
            }
            Op::Movt { rd, imm } => {
                let old = self.r(*rd);
                let lo = self.bini(BinOp::And, old, 0xffff);
                let v = self.bini(BinOp::Or, lo, (*imm as u32) << 16);
                self.w(*rd, v);
                Flow::Next
            }
            Op::B { imm } => {
                let target = self.pc_value().wrapping_add(*imm as u32);
                let k = self.key_same(target);
                if inst.cond.is_always() {
                    Flow::End(Term::Goto { target: k })
                } else {
                    let c = self.cond_holds(inst.cond);
                    Flow::End(Term::Branch { cond: c, taken: k, not_taken: self.next })
                }
            }
            Op::Bl { imm, switch } => self.bl(*imm, *switch),
            Op::Bx { rm } | Op::Bxj { rm } => {
                let a = self.r(*rm);
                let w = self.bx_write_pc(a);
                self.end_with(w)
            }
            Op::BlxReg { rm } => {
                let a = self.r(*rm);
                let lr = self.return_address();
                let lrv = self.c32(lr);
                self.w(Reg::LR, lrv);
                let w = self.bx_write_pc(a);
                self.b.set_call_return(self.next);
                self.end_with(w)
            }
            Op::Cbz { nonzero, rn, imm } => {
                // A8.8.29: never in an IT block, so never predicated.
                let v = self.r(*rn);
                let z = self.cmpi(if *nonzero { CmpOp::Ne } else { CmpOp::Eq }, v, 0);
                let target = self.pc_value().wrapping_add(*imm);
                let k = self.key_same(target);
                Flow::End(Term::Branch { cond: z, taken: k, not_taken: self.next })
            }
            Op::Tb { half, rn, rm } => self.table_branch(*half, *rn, *rm),
            Op::Mul { .. }
            | Op::Mla { .. }
            | Op::MulLong { .. }
            | Op::Smulxy { .. }
            | Op::Smulwy { .. }
            | Op::Smlalxy { .. }
            | Op::Smlad { .. }
            | Op::Smlald { .. }
            | Op::Smmul { .. }
            | Op::Div { .. }
            | Op::Qadd { .. }
            | Op::Sat { .. }
            | Op::Sat16 { .. }
            | Op::Parallel { .. }
            | Op::Sel { .. }
            | Op::Usad8 { .. }
            | Op::Pkh { .. }
            | Op::Extend { .. }
            | Op::Rev { .. }
            | Op::Clz { .. }
            | Op::Bfi { .. }
            | Op::Bfx { .. } => {
                self.media(&inst.op);
                Flow::Next
            }
            Op::Ldst { .. } | Op::Ldrd { .. } | Op::Ldm { .. } | Op::Ldrex { .. } | Op::Strex { .. } | Op::Swp { .. } => {
                self.memory(&inst.op)
            }
            Op::Clrex => {
                // A8.8.32: the local monitor to Open Access.
                let z = self.c64(0);
                let z = match self.pred {
                    Some(p) => {
                        let old = self.b.read(GuestReg::MonSize);
                        self.sel64(p, z, old)
                    }
                    None => z,
                };
                self.b.write(GuestReg::MonSize, z);
                Flow::Next
            }
            // A8.8.127-A8.8.129: hints with no architectural effect; they
            // generate no synchronous abort.
            Op::Pld { .. } => Flow::Next,
            Op::Hint(h) => match h {
                // CSDB (A8.8.42) orders speculation only, which gex does not do.
                Hint::Nop | Hint::Yield | Hint::Csdb | Hint::Dbg(_) => Flow::Next,
                Hint::Wfi => self.wait(abi::sys::WFI),
                Hint::Wfe => self.wait(abi::sys::WFE),
                Hint::Sev => {
                    self.sys_k(abi::sys::SEV, 0, 0);
                    Flow::Next
                }
            },
            Op::Barrier { kind, .. } => match kind {
                // A8.8.43 DMB, A8.8.44 DSB: every access is ordered.
                Barrier::Dmb | Barrier::Dsb => {
                    self.b.stmt(Stmt::Fence);
                    Flow::Next
                }
                // A8.8.53 ISB: a context synchronization event.
                Barrier::Isb => {
                    self.b.stmt(Stmt::Fence);
                    self.pc_to_next();
                    self.sys_k(abi::sys::ISB, 0, 0);
                    self.end_at_context_pc()
                }
            },
            // The block lifter consumes IT itself (A8.8.55).
            Op::It { .. } => Flow::Next,
            Op::Enterx { .. } => self.unimplemented(abi::unimpl::THUMBEE),
            Op::Svc { imm } => self.exception(abi::exc::SVC, *imm as u64),
            Op::Bkpt { imm } => self.exception(abi::exc::BKPT, *imm as u64),
            Op::Smc { imm } => self.exception(abi::exc::SMC, *imm as u64),
            Op::Hvc { imm } => self.exception(abi::exc::HVC, *imm as u64),
            Op::Udf { .. } | Op::Undefined => self.undefined(),
            Op::Fp(_) => self.unimplemented(abi::unimpl::FP),
            Op::Mrs { .. }
            | Op::Msr { .. }
            | Op::MrsBanked { .. }
            | Op::MsrBanked { .. }
            | Op::Cps { .. }
            | Op::Setend { .. }
            | Op::Srs { .. }
            | Op::Rfe { .. }
            | Op::Eret
            | Op::Mcr { .. }
            | Op::Mcrr { .. }
            | Op::Cdp { .. }
            | Op::Ldc { .. } => self.system(&inst.op),
        }
    }

    /// The address a BL or BLX leaves in LR: the next instruction's, with
    /// bit 0 set in the Thumb state (A8.8.25).
    pub(crate) fn return_address(&self) -> u32 {
        let next = self.addr.wrapping_add(self.len as u32);
        if self.thumb() {
            next | 1
        } else {
            next
        }
    }

    /// A8.8.25 BL, BLX (immediate).
    fn bl(&mut self, imm: i32, switch: bool) -> Flow {
        let lr = self.return_address();
        let lrv = self.c32(lr);
        self.w(Reg::LR, lrv);
        let (addr, thumb) = if !switch {
            (self.pc_value().wrapping_add(imm as u32), self.thumb())
        } else {
            // targetInstrSet != CurrentInstrSet: Align(PC, 4) + imm32.
            ((self.pc_value() & !3).wrapping_add(imm as u32), !self.thumb())
        };
        let k = self.user() | abi::key(if thumb { addr & !1 } else { addr & !3 }, thumb, 0);
        self.b.set_call_return(self.next);
        self.end_with(PcWrite::Key(k))
    }

    /// A8.8.223 TBB, TBH: `BranchWritePC(PC + 2*halfwords)`.
    fn table_branch(&mut self, half: bool, rn: Reg, rm: Reg) -> Flow {
        let base = self.r(rn);
        let idx = self.r(rm);
        let off = if half { self.bini(BinOp::Shl, idx, 1) } else { idx };
        let va = self.bin(BinOp::Add, base, off);
        let size = if half { 1 } else { 0 };
        let host = self.mem(va, abi::mem::access(size, false, false, 0));
        let v = self.b.def(Expr::Load {
            addr: host,
            offset: 0,
            sz: if half { gex_ir::MemSz::B2 } else { gex_ir::MemSz::B1 },
            signed: false,
            ty: Ty::I32,
            order: gex_ir::Order::Relaxed,
        });
        let two = self.bini(BinOp::Shl, v, 1);
        let pc = self.c32(self.pc_value());
        let t = self.bin(BinOp::Add, pc, two);
        let w = self.branch_write_pc(t);
        self.end_with(w)
    }

    /// A WFI or WFE: the host waits, or stops loudly when nothing can wake
    /// the core; the block ends so that what woke it is seen.
    fn wait(&mut self, op: i32) -> Flow {
        self.pc_to_next();
        self.sys_k(op, 0, 0);
        self.end_at_context_pc()
    }

    /// `R[d] = v`, or a PC write by `ALUWritePC` (or `BranchWritePC` for
    /// ADR, whose `d == 15` is a branch of the current set).
    pub(crate) fn write_or_branch(&mut self, rd: Reg, v: Value, alu: bool) -> Flow {
        if rd.is_pc() {
            let w = if alu { self.alu_write_pc(v) } else { self.branch_write_pc(v) };
            self.end_with(w)
        } else {
            self.w(rd, v);
            Flow::Next
        }
    }

    // -- data processing (A8.8.1 ADC .. A8.8.296; A5.2.1-A5.2.3) --------------

    fn dp(&mut self, op: DpOp, s: bool, rd: Reg, rn: Reg, src: &Operand) -> Flow {
        // SUBS PC, LR and related instructions (B9.3.20): the result to the
        // PC, the SPSR to the CPSR; the host checks the mode.
        let exc_return = s && rd.is_pc() && !op.is_test();
        let set_flags = s && !exc_return;
        let logical = op.is_logical();
        let (shifted, sc) = self.operand(src, set_flags && logical);
        let a = if op.has_rn() { Some(self.r(rn)) } else { None };
        let (result, carry, overflow) = match op {
            DpOp::And | DpOp::Tst => (self.bin(BinOp::And, a.unwrap(), shifted), sc, None),
            DpOp::Eor | DpOp::Teq => (self.bin(BinOp::Xor, a.unwrap(), shifted), sc, None),
            DpOp::Orr => (self.bin(BinOp::Or, a.unwrap(), shifted), sc, None),
            DpOp::Orn => {
                let n = self.not(shifted);
                (self.bin(BinOp::Or, a.unwrap(), n), sc, None)
            }
            DpOp::Bic => {
                let n = self.not(shifted);
                (self.bin(BinOp::And, a.unwrap(), n), sc, None)
            }
            DpOp::Mov => (shifted, sc, None),
            DpOp::Mvn => (self.not(shifted), sc, None),
            DpOp::Add | DpOp::Cmn => {
                let z = self.c32(0);
                let (r, c, v) = self.add_with_carry(a.unwrap(), shifted, z);
                (r, Some(c), Some(v))
            }
            DpOp::Adc => {
                let cin = self.carry();
                let (r, c, v) = self.add_with_carry(a.unwrap(), shifted, cin);
                (r, Some(c), Some(v))
            }
            DpOp::Sub | DpOp::Cmp => {
                let n = self.not(shifted);
                let one = self.c32(1);
                let (r, c, v) = self.add_with_carry(a.unwrap(), n, one);
                (r, Some(c), Some(v))
            }
            DpOp::Sbc => {
                let n = self.not(shifted);
                let cin = self.carry();
                let (r, c, v) = self.add_with_carry(a.unwrap(), n, cin);
                (r, Some(c), Some(v))
            }
            DpOp::Rsb => {
                let n = self.not(a.unwrap());
                let one = self.c32(1);
                let (r, c, v) = self.add_with_carry(n, shifted, one);
                (r, Some(c), Some(v))
            }
            DpOp::Rsc => {
                let n = self.not(a.unwrap());
                let cin = self.carry();
                let (r, c, v) = self.add_with_carry(n, shifted, cin);
                (r, Some(c), Some(v))
            }
        };
        if set_flags {
            self.nz(result);
            if let Some(c) = carry {
                self.wflag(GuestReg::C, c);
            }
            if let Some(v) = overflow {
                self.wflag(GuestReg::V, v);
            }
        }
        if op.is_test() {
            return Flow::Next;
        }
        if exc_return {
            let r64 = self.zext(result);
            let a0 = self.c64(0);
            self.pc_to_next();
            self.sys(abi::sys::ALU_RETURN, a0, r64);
            return self.end_at_context_pc();
        }
        self.write_or_branch(rd, result, true)
    }
}
