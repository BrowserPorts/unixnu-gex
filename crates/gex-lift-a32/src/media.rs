//! Multiplies, saturation, the parallel (SIMD-in-a-register) instructions,
//! packing, extension, reversal and bit fields (A8.8, from the pseudocode
//! of each instruction).

use crate::Lifter;
use gex_ir::{BinOp, CmpOp, GuestReg, Ty, UnOp, Value};
use gex_isa_a32::*;

impl<'a> Lifter<'a> {
    pub(crate) fn media(&mut self, op: &Op) {
        match *op {
            // A8.8.114 MUL: N and Z only, C and V unchanged (ARMv7).
            Op::Mul { s, rd, rn, rm } => {
                let n = self.r(rn);
                let m = self.r(rm);
                let r = self.bin(BinOp::Mul, n, m);
                self.w(rd, r);
                if s {
                    self.nz(r);
                }
            }
            // A8.8.100 MLA, A8.8.101 MLS.
            Op::Mla { s, sub, rd, rn, rm, ra } => {
                let n = self.r(rn);
                let m = self.r(rm);
                let a = self.r(ra);
                let p = self.bin(BinOp::Mul, n, m);
                let r = if sub { self.bin(BinOp::Sub, a, p) } else { self.bin(BinOp::Add, p, a) };
                self.w(rd, r);
                if s {
                    self.nz(r);
                }
            }
            // A8.8.255 UMULL, A8.8.254 UMLAL, A8.8.189 SMULL, A8.8.178
            // SMLAL, A8.8.253 UMAAL.
            Op::MulLong { kind, s, rdlo, rdhi, rn, rm } => {
                let signed = matches!(kind, MulLong::Smull | MulLong::Smlal);
                let n = self.r(rn);
                let m = self.r(rm);
                let n64 = self.b.extend(n, signed);
                let m64 = self.b.extend(m, signed);
                let mut p = self.bin64(BinOp::Mul, n64, m64);
                match kind {
                    MulLong::Umlal | MulLong::Smlal => {
                        let acc = self.pair(rdhi, rdlo);
                        p = self.bin64(BinOp::Add, p, acc);
                    }
                    MulLong::Umaal => {
                        let lo = self.r(rdlo);
                        let hi = self.r(rdhi);
                        let lo = self.zext(lo);
                        let hi = self.zext(hi);
                        p = self.bin64(BinOp::Add, p, lo);
                        p = self.bin64(BinOp::Add, p, hi);
                    }
                    _ => {}
                }
                self.write_pair(rdhi, rdlo, p);
                if s {
                    let hi = self.bini64(BinOp::ShrU, p, 63);
                    let n = self.wrap(hi);
                    let z0 = self.c64(0);
                    let z = self.b.cmp(CmpOp::Eq, Ty::I64, p, z0);
                    self.wflag(GuestReg::N, n);
                    self.wflag(GuestReg::Z, z);
                }
            }
            // A8.8.176 SMLABB..SMLATT, A8.8.188 SMULBB..SMULTT.
            Op::Smulxy { rd, rn, rm, ra, n_top, m_top } => {
                let a = self.half(rn, n_top);
                let b = self.half(rm, m_top);
                let p = self.bin(BinOp::Mul, a, b);
                let p64 = self.sext(p);
                match ra {
                    None => self.w(rd, p),
                    Some(ra) => {
                        let acc = self.r(ra);
                        let acc64 = self.sext(acc);
                        let sum = self.bin64(BinOp::Add, p64, acc64);
                        let r = self.wrap(sum);
                        self.w(rd, r);
                        let ov = self.not_i32(sum);
                        self.set_q(ov);
                    }
                }
            }
            // A8.8.181 SMLAWB/T, A8.8.191 SMULWB/T: bits 47:16 of the
            // 48-bit product (plus Ra << 16).
            Op::Smulwy { rd, rn, rm, ra, m_top } => {
                let n = self.r(rn);
                let n64 = self.sext(n);
                let b = self.half(rm, m_top);
                let b64 = self.sext(b);
                let mut p = self.bin64(BinOp::Mul, n64, b64);
                if let Some(ra) = ra {
                    let acc = self.r(ra);
                    let acc64 = self.sext(acc);
                    let sh = self.bini64(BinOp::Shl, acc64, 16);
                    p = self.bin64(BinOp::Add, p, sh);
                }
                let top = self.bini64(BinOp::ShrS, p, 16);
                let r = self.wrap(top);
                self.w(rd, r);
                if ra.is_some() {
                    let ov = self.not_i32(top);
                    self.set_q(ov);
                }
            }
            // A8.8.179 SMLALBB..SMLALTT.
            Op::Smlalxy { rdlo, rdhi, rn, rm, n_top, m_top } => {
                let a = self.half(rn, n_top);
                let b = self.half(rm, m_top);
                let p = self.bin(BinOp::Mul, a, b);
                let p64 = self.sext(p);
                let acc = self.pair(rdhi, rdlo);
                let r = self.bin64(BinOp::Add, p64, acc);
                self.write_pair(rdhi, rdlo, r);
            }
            // A8.8.177 SMLAD, A8.8.182 SMLSD, A8.8.187 SMUAD, A8.8.192 SMUSD.
            Op::Smlad { rd, rn, rm, ra, sub, swap } => {
                let (p1, p2) = self.dual(rn, rm, swap);
                let mut r = self.bin64(if sub { BinOp::Sub } else { BinOp::Add }, p1, p2);
                if let Some(ra) = ra {
                    let acc = self.r(ra);
                    let acc64 = self.sext(acc);
                    r = self.bin64(BinOp::Add, r, acc64);
                }
                let v = self.wrap(r);
                self.w(rd, v);
                let ov = self.not_i32(r);
                self.set_q(ov);
            }
            // A8.8.180 SMLALD, A8.8.183 SMLSLD.
            Op::Smlald { rdlo, rdhi, rn, rm, sub, swap } => {
                let (p1, p2) = self.dual(rn, rm, swap);
                let d = self.bin64(if sub { BinOp::Sub } else { BinOp::Add }, p1, p2);
                let acc = self.pair(rdhi, rdlo);
                let r = self.bin64(BinOp::Add, d, acc);
                self.write_pair(rdhi, rdlo, r);
            }
            // A8.8.184 SMMLA, A8.8.185 SMMLS, A8.8.186 SMMUL.
            Op::Smmul { rd, rn, rm, ra, sub, round } => {
                let n = self.r(rn);
                let m = self.r(rm);
                let n64 = self.sext(n);
                let m64 = self.sext(m);
                let p = self.bin64(BinOp::Mul, n64, m64);
                let mut r = match ra {
                    Some(ra) => {
                        let a = self.r(ra);
                        let a64 = self.zext(a);
                        let a64 = self.bini64(BinOp::Shl, a64, 32);
                        self.bin64(if sub { BinOp::Sub } else { BinOp::Add }, a64, p)
                    }
                    None => p,
                };
                if round {
                    r = self.bini64(BinOp::Add, r, 0x8000_0000);
                }
                let hi = self.bini64(BinOp::ShrU, r, 32);
                let v = self.wrap(hi);
                self.w(rd, v);
            }
            // A8.8.165 SDIV, A8.8.248 UDIV: a zero divisor gives 0 (the
            // ARMv7-A profile does not trap it, D16.7.15); 0x80000000 / -1
            // gives 0x80000000.
            Op::Div { signed, rd, rn, rm } => {
                let n = self.r(rn);
                let m = self.r(rm);
                let n64 = self.b.extend(n, signed);
                let m64 = self.b.extend(m, signed);
                let zero = self.cmpi(CmpOp::Eq, m, 0);
                let one = self.c64(1);
                let d = self.sel64(zero, one, m64);
                let q = self.bin64(if signed { BinOp::DivS } else { BinOp::DivU }, n64, d);
                let q = self.wrap(q);
                let z = self.c32(0);
                let r = self.sel(zero, z, q);
                self.w(rd, r);
            }
            // A8.8.134 QADD, A8.8.138 QDADD, A8.8.139 QDSUB, A8.8.141 QSUB.
            Op::Qadd { sub, double, rd, rm, rn } => {
                let m = self.r(rm);
                let n = self.r(rn);
                let m64 = self.sext(m);
                let n64 = self.sext(n);
                let (opnd, sat1) = if double {
                    let d = self.bin64(BinOp::Add, n64, n64);
                    let (v, s) = self.signed_sat(d, 32);
                    (self.sext(v), Some(s))
                } else {
                    (n64, None)
                };
                let r = self.bin64(if sub { BinOp::Sub } else { BinOp::Add }, m64, opnd);
                let (v, sat2) = self.signed_sat(r, 32);
                self.w(rd, v);
                let sat = match sat1 {
                    Some(s1) => self.bin(BinOp::Or, s1, sat2),
                    None => sat2,
                };
                self.set_q(sat);
            }
            // A8.8.160 SSAT, A8.8.250 USAT.
            Op::Sat { unsigned, rd, rn, sat, shift, amount } => {
                let n = self.r(rn);
                let (opnd, _) = self.shift_imm(n, shift, amount, false);
                let o64 = self.sext(opnd);
                let (v, s) = if unsigned { self.unsigned_sat(o64, sat as u32) } else { self.signed_sat(o64, sat as u32) };
                self.w(rd, v);
                self.set_q(s);
            }
            // A8.8.161 SSAT16, A8.8.251 USAT16.
            Op::Sat16 { unsigned, rd, rn, sat } => {
                let n = self.r(rn);
                let lo = self.ext_bits(n, 16, true);
                let hi = self.bini(BinOp::ShrS, n, 16);
                let lo64 = self.sext(lo);
                let hi64 = self.sext(hi);
                let f = |l: &mut Self, v| if unsigned { l.unsigned_sat(v, sat as u32) } else { l.signed_sat(v, sat as u32) };
                let (rl, s1) = f(self, lo64);
                let (rh, s2) = f(self, hi64);
                let rl = self.bini(BinOp::And, rl, 0xffff);
                let rh = self.bini(BinOp::Shl, rh, 16);
                let r = self.bin(BinOp::Or, rh, rl);
                self.w(rd, r);
                let s = self.bin(BinOp::Or, s1, s2);
                self.set_q(s);
            }
            Op::Parallel { kind, op, rd, rn, rm } => self.parallel(kind, op, rd, rn, rm),
            // A8.8.162 SEL: each byte from Rn where its GE bit is set.
            Op::Sel { rd, rn, rm } => {
                let n = self.r(rn);
                let m = self.r(rm);
                let ge = self.ge();
                let mut mask = self.c32(0);
                for i in 0..4 {
                    let g = self.bit(ge, i);
                    let neg = self.b.un(UnOp::Neg, Ty::I32, g);
                    let byte = self.bini(BinOp::And, neg, 0xff << (8 * i));
                    mask = self.bin(BinOp::Or, mask, byte);
                }
                let a = self.bin(BinOp::And, n, mask);
                let nm = self.not(mask);
                let b = self.bin(BinOp::And, m, nm);
                let r = self.bin(BinOp::Or, a, b);
                self.w(rd, r);
            }
            // A8.8.252 USAD8, A8.8.253 USADA8.
            Op::Usad8 { rd, rn, rm, ra } => {
                let n = self.r(rn);
                let m = self.r(rm);
                let mut sum = match ra {
                    Some(ra) => self.r(ra),
                    None => self.c32(0),
                };
                for i in 0..4 {
                    let a = self.bini(BinOp::ShrU, n, 8 * i);
                    let a = self.bini(BinOp::And, a, 0xff);
                    let b = self.bini(BinOp::ShrU, m, 8 * i);
                    let b = self.bini(BinOp::And, b, 0xff);
                    let d1 = self.bin(BinOp::Sub, a, b);
                    let d2 = self.bin(BinOp::Sub, b, a);
                    let lt = self.cmp(CmpOp::LtU, a, b);
                    let d = self.sel(lt, d2, d1);
                    sum = self.bin(BinOp::Add, sum, d);
                }
                self.w(rd, sum);
            }
            // A8.8.125 PKHBT, PKHTB.
            Op::Pkh { tb, rd, rn, rm, amount } => {
                let n = self.r(rn);
                let m = self.r(rm);
                let r = if tb {
                    let sh = self.bini(BinOp::ShrS, m, (amount as u32).min(31));
                    let lo = self.bini(BinOp::And, sh, 0xffff);
                    let hi = self.bini(BinOp::And, n, 0xffff_0000);
                    self.bin(BinOp::Or, hi, lo)
                } else {
                    let sh = self.bini(BinOp::Shl, m, amount as u32);
                    let hi = self.bini(BinOp::And, sh, 0xffff_0000);
                    let lo = self.bini(BinOp::And, n, 0xffff);
                    self.bin(BinOp::Or, hi, lo)
                };
                self.w(rd, r);
            }
            // A8.8.220-A8.8.225 SXTAB..SXTH, A8.8.271-A8.8.276 UXTAB..UXTH.
            Op::Extend { kind, rd, rn, rm, rotation } => {
                let m = self.r(rm);
                let rot = if rotation == 0 { m } else { self.bini(BinOp::Rotr, m, rotation as u32) };
                let r = match kind {
                    ExtKind::Sxtb | ExtKind::Uxtb | ExtKind::Sxth | ExtKind::Uxth => {
                        let bits = if matches!(kind, ExtKind::Sxtb | ExtKind::Uxtb) { 8 } else { 16 };
                        let signed = matches!(kind, ExtKind::Sxtb | ExtKind::Sxth);
                        let e = self.ext_bits(rot, bits, signed);
                        match rn {
                            Some(rn) => {
                                let n = self.r(rn);
                                self.bin(BinOp::Add, n, e)
                            }
                            None => e,
                        }
                    }
                    ExtKind::Sxtb16 | ExtKind::Uxtb16 => {
                        let signed = kind == ExtKind::Sxtb16;
                        let b0 = self.ext_bits(rot, 8, signed);
                        let b2s = self.bini(BinOp::ShrU, rot, 16);
                        let b2 = self.ext_bits(b2s, 8, signed);
                        let (lo, hi) = match rn {
                            Some(rn) => {
                                let n = self.r(rn);
                                let nhi = self.bini(BinOp::ShrU, n, 16);
                                (self.bin(BinOp::Add, n, b0), self.bin(BinOp::Add, nhi, b2))
                            }
                            None => (b0, b2),
                        };
                        let lo = self.bini(BinOp::And, lo, 0xffff);
                        let hi = self.bini(BinOp::Shl, hi, 16);
                        self.bin(BinOp::Or, hi, lo)
                    }
                };
                self.w(rd, r);
            }
            // A8.8.144 REV, A8.8.145 REV16, A8.8.146 REVSH, A8.8.143 RBIT.
            Op::Rev { kind, rd, rm } => {
                let m = self.r(rm);
                let r = match kind {
                    RevKind::Rev => self.b.un(UnOp::Bswap, Ty::I32, m),
                    RevKind::Rev16 => {
                        let a = self.bini(BinOp::ShrU, m, 8);
                        let a = self.bini(BinOp::And, a, 0x00ff_00ff);
                        let b2 = self.bini(BinOp::Shl, m, 8);
                        let b2 = self.bini(BinOp::And, b2, 0xff00_ff00);
                        self.bin(BinOp::Or, a, b2)
                    }
                    RevKind::Revsh => {
                        // result<31:8> = SignExtend(Rm<7:0>), result<7:0> = Rm<15:8>.
                        let lo = self.ext_bits(m, 8, true);
                        let lo = self.bini(BinOp::Shl, lo, 8);
                        let hi = self.bini(BinOp::ShrU, m, 8);
                        let hi = self.bini(BinOp::And, hi, 0xff);
                        self.bin(BinOp::Or, lo, hi)
                    }
                    RevKind::Rbit => {
                        let mut v = self.b.un(UnOp::Bswap, Ty::I32, m);
                        for (sh, mask) in [(4u32, 0x0f0f_0f0fu32), (2, 0x3333_3333), (1, 0x5555_5555)] {
                            let a = self.bini(BinOp::ShrU, v, sh);
                            let a = self.bini(BinOp::And, a, mask);
                            let b2 = self.bini(BinOp::And, v, mask);
                            let b2 = self.bini(BinOp::Shl, b2, sh);
                            v = self.bin(BinOp::Or, a, b2);
                        }
                        v
                    }
                };
                self.w(rd, r);
            }
            // A8.8.33 CLZ.
            Op::Clz { rd, rm } => {
                let m = self.r(rm);
                let r = self.b.un(UnOp::Clz, Ty::I32, m);
                self.w(rd, r);
            }
            // A8.8.20 BFC, A8.8.21 BFI (msb >= lsb: the rest is UNPREDICTABLE
            // and was refused).
            Op::Bfi { rd, rn, lsb, msb } => {
                let width = msb as u32 - lsb as u32 + 1;
                let field = if width == 32 { u32::MAX } else { ((1u32 << width) - 1) << lsb };
                let d = self.r(rd);
                let keep = self.bini(BinOp::And, d, !field);
                let r = match rn {
                    Some(rn) => {
                        let n = self.r(rn);
                        let s = self.bini(BinOp::Shl, n, lsb as u32);
                        let s = self.bini(BinOp::And, s, field);
                        self.bin(BinOp::Or, keep, s)
                    }
                    None => keep,
                };
                self.w(rd, r);
            }
            // A8.8.164 SBFX, A8.8.246 UBFX.
            Op::Bfx { signed, rd, rn, lsb, width } => {
                let n = self.r(rn);
                let top = 32 - (lsb as u32 + width as u32);
                let s = self.bini(BinOp::Shl, n, top);
                let r = self.bini(if signed { BinOp::ShrS } else { BinOp::ShrU }, s, 32 - width as u32);
                self.w(rd, r);
            }
            _ => unreachable!("media: {op:?}"),
        }
    }

    /// `R[hi]:R[lo]` as an `I64`.
    fn pair(&mut self, hi: Reg, lo: Reg) -> Value {
        let h = self.r(hi);
        let l = self.r(lo);
        let h = self.zext(h);
        let l = self.zext(l);
        let h = self.bini64(BinOp::Shl, h, 32);
        self.bin64(BinOp::Or, h, l)
    }

    /// `R[hi] = v<63:32>; R[lo] = v<31:0>`.
    fn write_pair(&mut self, hi: Reg, lo: Reg, v: Value) {
        let h = self.bini64(BinOp::ShrU, v, 32);
        let h = self.wrap(h);
        let l = self.wrap(v);
        self.w(hi, h);
        self.w(lo, l);
    }

    /// The signed halfword `R[r]<31:16>` (`top`) or `<15:0>`, an `I32`.
    fn half(&mut self, r: Reg, top: bool) -> Value {
        let v = self.r(r);
        if top {
            self.bini(BinOp::ShrS, v, 16)
        } else {
            self.ext_bits(v, 16, true)
        }
    }

    /// The two products of the dual 16-bit multiplies, `I64`s.
    fn dual(&mut self, rn: Reg, rm: Reg, swap: bool) -> (Value, Value) {
        let n = self.r(rn);
        let m = self.r(rm);
        let m = if swap { self.bini(BinOp::Rotr, m, 16) } else { m };
        let nl = self.ext_bits(n, 16, true);
        let nh = self.bini(BinOp::ShrS, n, 16);
        let ml = self.ext_bits(m, 16, true);
        let mh = self.bini(BinOp::ShrS, m, 16);
        let p1 = self.bin(BinOp::Mul, nl, ml);
        let p2 = self.bin(BinOp::Mul, nh, mh);
        (self.sext(p1), self.sext(p2))
    }

    /// 1 where the `I64` `v` is not the sign extension of its low word.
    fn not_i32(&mut self, v: Value) -> Value {
        let lo = self.wrap(v);
        let back = self.sext(lo);
        self.b.cmp(CmpOp::Ne, Ty::I64, v, back)
    }

    /// `SignedSatQ(v, n)` (A2.2.1) of an `I64`: the `I32` result and
    /// whether it saturated.
    pub(crate) fn signed_sat(&mut self, v: Value, n: u32) -> (Value, Value) {
        let max = (1i64 << (n - 1)) - 1;
        let min = -(1i64 << (n - 1));
        self.clamp(v, min, max)
    }

    /// `UnsignedSatQ(v, n)`.
    pub(crate) fn unsigned_sat(&mut self, v: Value, n: u32) -> (Value, Value) {
        let max = (1i64 << n) - 1;
        self.clamp(v, 0, max)
    }

    fn clamp(&mut self, v: Value, min: i64, max: i64) -> (Value, Value) {
        let kmax = self.c64(max as u64);
        let kmin = self.c64(min as u64);
        let over = self.b.cmp(CmpOp::GtS, Ty::I64, v, kmax);
        let under = self.b.cmp(CmpOp::LtS, Ty::I64, v, kmin);
        let r = self.sel64(over, kmax, v);
        let r = self.sel64(under, kmin, r);
        let sat = self.bin(BinOp::Or, over, under);
        (self.wrap(r), sat)
    }

    /// The parallel add and subtract instructions (A8.8.130 QADD16 ..
    /// A8.8.262 USUB8): two halfword or four byte lanes, each the sum or
    /// difference of lanes of Rn and Rm (ASX and SAX cross them), and per
    /// prefix: S and U set GE, Q and UQ saturate, SH and UH halve.
    fn parallel(&mut self, kind: ParKind, op: ParOp, rd: Reg, rn: Reg, rm: Reg) {
        let n = self.r(rn);
        let m = self.r(rm);
        let signed = matches!(kind, ParKind::S | ParKind::Q | ParKind::Sh);
        let (w, lanes): (u32, Vec<(u32, u32, bool)>) = match op {
            // (lane of Rn, lane of Rm, subtract)
            ParOp::Add16 => (16, vec![(0, 0, false), (1, 1, false)]),
            ParOp::Sub16 => (16, vec![(0, 0, true), (1, 1, true)]),
            ParOp::Asx => (16, vec![(0, 1, true), (1, 0, false)]),
            ParOp::Sax => (16, vec![(0, 1, false), (1, 0, true)]),
            ParOp::Add8 => (8, (0..4).map(|i| (i, i, false)).collect()),
            ParOp::Sub8 => (8, (0..4).map(|i| (i, i, true)).collect()),
        };
        let lane_mask = (1u32 << w) - 1;
        let mut result = self.c32(0);
        let mut ge = self.c32(0);
        for (i, &(ln, lm, sub)) in lanes.iter().enumerate() {
            let a = self.bini(BinOp::ShrU, n, ln * w);
            let a = self.ext_bits(a, w, signed);
            let b = self.bini(BinOp::ShrU, m, lm * w);
            let b = self.ext_bits(b, w, signed);
            let r = self.bin(if sub { BinOp::Sub } else { BinOp::Add }, a, b);
            let lane = match kind {
                ParKind::S | ParKind::U => {
                    // GE: a signed result >= 0; an unsigned sum >= 2^w, or
                    // an unsigned difference >= 0.
                    let g = match (kind, sub) {
                        (ParKind::S, _) | (ParKind::U, true) => self.cmpi(CmpOp::GeS, r, 0),
                        _ => self.cmpi(CmpOp::GeU, r, 1 << w),
                    };
                    let bits = if w == 16 { 3u32 } else { 1 };
                    let neg = self.b.un(UnOp::Neg, Ty::I32, g);
                    let gb = self.bini(BinOp::And, neg, bits << (i as u32 * if w == 16 { 2 } else { 1 }));
                    ge = self.bin(BinOp::Or, ge, gb);
                    r
                }
                ParKind::Q => {
                    let r64 = self.sext(r);
                    self.signed_sat(r64, w).0
                }
                ParKind::Uq => {
                    let r64 = self.sext(r);
                    self.unsigned_sat(r64, w).0
                }
                ParKind::Sh => self.bini(BinOp::ShrS, r, 1),
                ParKind::Uh => self.bini(BinOp::ShrU, r, 1),
            };
            let lane = self.bini(BinOp::And, lane, lane_mask);
            let lane = self.bini(BinOp::Shl, lane, i as u32 * w);
            result = self.bin(BinOp::Or, result, lane);
        }
        self.w(rd, result);
        if matches!(kind, ParKind::S | ParKind::U) {
            self.set_ge(ge);
        }
    }
}
