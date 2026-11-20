//! Loads and stores (A8.8.62-A8.8.89 LDR..., A8.8.198-A8.8.215 STR...,
//! A8.8.58-A8.8.61 LDM, A8.8.199-A8.8.202 STM, the exclusives, SWP; B9.3.5
//! and B9.3.6 LDM (exception return, user registers), B9.3.17 STM (user
//! registers)).
//!
//! Every access goes through the host's translation (`A32Mem`) first; an
//! instruction of several accesses translates them all before it reads or
//! writes anything, so an abort leaves the registers as they were, which
//! is one of the outcomes the architecture allows for an aborted LDM or
//! LDRD (B3.12.7 and the instruction descriptions) and is exact for the
//! single accesses.

use crate::{Flow, Lifter, PcWrite};
use gex_abi::a32 as abi;
use gex_ir::{BinOp, CmpOp, Expr, GuestReg, MemSz, Order, Stmt, Ty, Value};
use gex_isa_a32::*;

fn log2(size: Size) -> u32 {
    match size {
        Size::B => 0,
        Size::H => 1,
        Size::W => 2,
        Size::D => 3,
    }
}

fn mem_sz(size: Size) -> MemSz {
    match size {
        Size::B => MemSz::B1,
        Size::H => MemSz::B2,
        Size::W => MemSz::B4,
        Size::D => MemSz::B8,
    }
}

impl<'a> Lifter<'a> {
    fn load(&mut self, host: Value, sz: MemSz, signed: bool, ty: Ty) -> Value {
        self.b.def(Expr::Load { addr: host, offset: 0, sz, signed, ty, order: Order::Relaxed })
    }

    fn store(&mut self, host: Value, val: Value, sz: MemSz) {
        self.b.stmt(Stmt::Store { addr: host, offset: 0, val, sz, order: Order::Relaxed });
    }

    /// `PCStoreValue()`: the PC as a read of it gives it (A2.3.1).
    fn store_value(&mut self, r: Reg) -> Value {
        self.r(r)
    }

    /// The offset address and the address of a load/store's access.
    fn addresses(&mut self, rn: Reg, offset: &Offset, index: bool) -> (Value, Value) {
        let base = self.r_base(rn);
        let off = match *offset {
            Offset::Imm(i) => {
                let k = self.c32(i as u32);
                self.bin(BinOp::Add, base, k)
            }
            Offset::Reg { rm, shift, amount, add } => {
                let m = self.r(rm);
                let (o, _) = self.shift_imm(m, shift, amount, false);
                self.bin(if add { BinOp::Add } else { BinOp::Sub }, base, o)
            }
        };
        let addr = if index { off } else { base };
        (off, addr)
    }

    /// A load into the PC must come from a word-aligned address (A8.8.63
    /// and the like: `if address<1:0> == '00' then LoadWritePC(data) else
    /// UNPREDICTABLE`).
    fn check_pc_load_aligned(&mut self, addr: Value) {
        let low = self.bini(BinOp::And, addr, 3);
        let bad = self.cmpi(CmpOp::Ne, low, 0);
        let bad = match self.pred {
            Some(p) => self.bin(BinOp::And, bad, p),
            None => bad,
        };
        self.b.stmt(Stmt::Trap { cond: bad, pc: self.key, code: abi::BRK_UNPREDICTABLE_PC });
    }

    pub(crate) fn memory(&mut self, op: &Op) -> Flow {
        match *op {
            Op::Ldst { load, size, signed, user, rt, rn, ref offset, index, wback } => {
                let (off_addr, addr) = self.addresses(rn, offset, index);
                let access = abi::mem::access(log2(size), !load, user, 0);
                if load {
                    let host = self.mem(addr, access);
                    let data = self.load(host, mem_sz(size), signed, Ty::I32);
                    if wback {
                        self.w(rn, off_addr);
                    }
                    if rt.is_pc() {
                        self.check_pc_load_aligned(addr);
                        let w = self.load_write_pc(data);
                        return self.end_with(w);
                    }
                    self.w(rt, data);
                } else {
                    let v = self.store_value(rt);
                    let host = self.mem(addr, access);
                    self.store(host, v, mem_sz(size));
                    if wback {
                        self.w(rn, off_addr);
                    }
                }
                Flow::Next
            }
            // A8.8.72 LDRD, A8.8.210 STRD: two word accesses, each word
            // aligned (MemA); one translation of the eight bytes.
            Op::Ldrd { load, rt, rt2, rn, ref offset, index, wback } => {
                let (off_addr, addr) = self.addresses(rn, offset, index);
                let access = abi::mem::access(3, !load, false, 2);
                if load {
                    let host = self.mem(addr, access);
                    let lo = self.load(host, MemSz::B4, false, Ty::I32);
                    let hi = self.b.def(Expr::Load { addr: host, offset: 4, sz: MemSz::B4, signed: false, ty: Ty::I32, order: Order::Relaxed });
                    if wback {
                        self.w(rn, off_addr);
                    }
                    self.w(rt, lo);
                    self.w(rt2, hi);
                } else {
                    let a = self.store_value(rt);
                    let b = self.store_value(rt2);
                    let host = self.mem(addr, access);
                    self.store(host, a, MemSz::B4);
                    self.b.stmt(Stmt::Store { addr: host, offset: 4, val: b, sz: MemSz::B4, order: Order::Relaxed });
                    if wback {
                        self.w(rn, off_addr);
                    }
                }
                Flow::Next
            }
            Op::Ldm { load, mode, rn, regs, wback, user } => self.ldm(load, mode, rn, regs, wback, user),
            // A8.8.75-A8.8.78 LDREX{,B,D,H}: the local monitor records the
            // access's host address, size and the value read.
            Op::Ldrex { size, rt, rt2, rn, imm } => {
                let base = self.r(rn);
                let k = self.c32(imm);
                let va = self.bin(BinOp::Add, base, k);
                let lg = log2(size);
                let host = self.mem(va, abi::mem::access(lg, false, false, lg) | abi::mem::EXCL);
                let wide = size == Size::D;
                let v = self.load(host, mem_sz(size), false, if wide { Ty::I64 } else { Ty::I32 });
                if wide {
                    let lo = self.wrap(v);
                    let hi = self.bini64(BinOp::ShrU, v, 32);
                    let hi = self.wrap(hi);
                    self.w(rt, lo);
                    self.w(rt2, hi);
                } else {
                    self.w(rt, v);
                }
                let v64 = if wide { v } else { self.zext(v) };
                let bytes = self.c64(1 << lg);
                self.monitor(host, bytes, v64);
                Flow::Next
            }
            // A8.8.212-A8.8.215 STREX{,B,D,H}: the store happens only where
            // the monitor holds this access; Rd is 0 then and 1 otherwise,
            // and the monitor is cleared either way.
            Op::Strex { size, rd, rt, rt2, rn, imm } => {
                let base = self.r(rn);
                let k = self.c32(imm);
                let va = self.bin(BinOp::Add, base, k);
                let lg = log2(size);
                let wide = size == Size::D;
                let value = if wide {
                    let lo = self.r(rt);
                    let hi = self.r(rt2);
                    let lo = self.zext(lo);
                    let hi = self.zext(hi);
                    let hi = self.bini64(BinOp::Shl, hi, 32);
                    self.bin64(BinOp::Or, hi, lo)
                } else {
                    self.r(rt)
                };
                let host = self.mem(va, abi::mem::access(lg, true, false, lg) | abi::mem::EXCL);
                let mon_addr = self.b.read(GuestReg::MonAddr);
                let mon_size = self.b.read(GuestReg::MonSize);
                let want = self.c64(1 << lg);
                let a_ok = self.b.cmp(CmpOp::Eq, Ty::I64, mon_addr, host);
                let s_ok = self.b.cmp(CmpOp::Eq, Ty::I64, mon_size, want);
                let armed = self.bin(BinOp::And, a_ok, s_ok);
                let sink = self.b.read(GuestReg::X(abi::SINK));
                let eff = self.sel64(armed, host, sink);
                let ty = if wide { Ty::I64 } else { Ty::I32 };
                let mv = self.b.read(GuestReg::MonValue);
                let expected = if wide { mv } else { self.wrap(mv) };
                let old = self.b.def(Expr::CmpXchg { addr: eff, expected, replacement: value, sz: mem_sz(size), ty });
                let same = self.b.cmp(CmpOp::Eq, ty, old, expected);
                let ok = self.bin(BinOp::And, armed, same);
                let status = self.bini(BinOp::Xor, ok, 1);
                self.w(rd, status);
                self.clear_monitor();
                Flow::Next
            }
            // A8.8.229 SWP, SWPB: an atomic exchange, the word one aligned.
            Op::Swp { byte, rt, rt2, rn } => {
                let va = self.r(rn);
                let (lg, sz) = if byte { (0, MemSz::B1) } else { (2, MemSz::B4) };
                let host = self.mem(va, abi::mem::access(lg, true, false, lg) | abi::mem::SWP);
                let v = self.r(rt2);
                let old = self.b.def(Expr::Rmw { op: gex_ir::RmwOp::Xchg, addr: host, val: v, sz, ty: Ty::I32 });
                self.w(rt, old);
                Flow::Next
            }
            _ => unreachable!("memory: {op:?}"),
        }
    }

    fn monitor(&mut self, host: Value, bytes: Value, value: Value) {
        let (h, s, v) = match self.pred {
            Some(p) => {
                let oh = self.b.read(GuestReg::MonAddr);
                let os = self.b.read(GuestReg::MonSize);
                let ov = self.b.read(GuestReg::MonValue);
                (self.sel64(p, host, oh), self.sel64(p, bytes, os), self.sel64(p, value, ov))
            }
            None => (host, bytes, value),
        };
        self.b.write(GuestReg::MonAddr, h);
        self.b.write(GuestReg::MonSize, s);
        self.b.write(GuestReg::MonValue, v);
    }

    fn clear_monitor(&mut self) {
        let z = self.c64(0);
        let z = match self.pred {
            Some(p) => {
                let old = self.b.read(GuestReg::MonSize);
                self.sel64(p, z, old)
            }
            None => z,
        };
        self.b.write(GuestReg::MonSize, z);
    }

    /// LDM/STM in the four modes, and their user-register and
    /// exception-return forms.
    fn ldm(&mut self, load: bool, mode: Amode, rn: Reg, regs: u16, wback: bool, user: bool) -> Flow {
        let count = regs.count_ones();
        let base = self.r(rn);
        let start = match mode {
            Amode::Ia => 0i32,
            Amode::Ib => 4,
            Amode::Da => 4 - 4 * count as i32,
            Amode::Db => -4 * count as i32,
        };
        let delta = match mode {
            Amode::Ia | Amode::Ib => 4 * count,
            Amode::Da | Amode::Db => (4 * count).wrapping_neg(),
        };
        let list: Vec<u8> = (0..16).filter(|i| regs & (1 << i) != 0).collect();
        // Every access translated first (MemA: word aligned).
        let access = abi::mem::access(2, !load, false, 2);
        let mut hosts = Vec::with_capacity(list.len());
        for k in 0..list.len() {
            let off = self.c32((start + 4 * k as i32) as u32);
            let va = self.bin(BinOp::Add, base, off);
            hosts.push(self.mem(va, access));
        }
        let new_base = {
            let d = self.c32(delta);
            self.bin(BinOp::Add, base, d)
        };
        if !load {
            // STM: a register's value as it was; with writeback, the base
            // as it was too where it is the lowest register listed, and
            // UNKNOWN otherwise (A8.8.199), which the value as it was is.
            for (k, &i) in list.iter().enumerate() {
                let v = if user && (8..=14).contains(&i) {
                    // B9.3.17 STM (user registers): the User mode's.
                    let a = self.c64(i as u64);
                    let z = self.c64(0);
                    let r = self.sys(abi::sys::USER_READ, a, z);
                    self.wrap(r)
                } else {
                    self.store_value(Reg(i))
                };
                self.store(hosts[k], v, MemSz::B4);
            }
            if wback {
                self.w(rn, new_base);
            }
            return Flow::Next;
        }
        let mut loaded = Vec::with_capacity(list.len());
        for h in &hosts {
            loaded.push(self.load(*h, MemSz::B4, false, Ty::I32));
        }
        let has_pc = regs & 0x8000 != 0;
        if user && !has_pc {
            // B9.3.6 LDM (user registers): R0-R7 are the same in every
            // mode; the rest are the User mode's, the host's to write.
            for (k, &i) in list.iter().enumerate() {
                if i >= 8 {
                    let a = self.c64(i as u64);
                    let v = self.zext(loaded[k]);
                    self.sys(abi::sys::USER_WRITE, a, v);
                } else {
                    self.w(Reg(i), loaded[k]);
                }
            }
            // No writeback in this form (the decoder refuses W = 1).
            return Flow::Next;
        }
        if wback && regs & (1 << rn.0) == 0 {
            self.w(rn, new_base);
        }
        for (k, &i) in list.iter().enumerate() {
            if i != 15 {
                self.w(Reg(i), loaded[k]);
            }
        }
        if !has_pc {
            return Flow::Next;
        }
        let pc = *loaded.last().unwrap();
        if user {
            // B9.3.5 LDM (exception return): the SPSR to the CPSR, then
            // the loaded word to the PC; the host checks the mode.
            let a = self.c64(0);
            let v = self.zext(pc);
            self.pc_to_next();
            self.sys(abi::sys::LDM_RETURN, a, v);
            return self.end_at_context_pc();
        }
        let w: PcWrite = self.load_write_pc(pc);
        self.end_with(w)
    }
}
