//! Advanced SIMD integer and polynomial data processing: the A8
//! descriptions of the three-register (A7.4.1, A7.4.2), scalar (A7.4.3),
//! shift (A7.4.4), two-register (A7.4.5) and immediate (A7.4.6) forms on
//! integer and polynomial elements.

use super::simd::*;
use crate::Regs;
use gex_isa_a32::fp::{Dt, FpInst, ImmOp, ShiftOp, Simd2Op, Simd3Op, VReg};

/// `Elem[]` of `size` bits of the register operand starting at doubleword
/// `first`, its elements numbered across its doublewords (`Q[]` or `D[]`).
fn get(f: &[u64; 32], first: usize, e: u32, size: u32) -> u64 {
    let per = 64 / size;
    elem(f[first + (e / per) as usize], e % per, size)
}

fn put(f: &mut [u64; 32], first: usize, e: u32, size: u32, v: u64) {
    let per = 64 / size;
    set_elem(&mut f[first + (e / per) as usize], e % per, size, v);
}

fn ones_if(b: bool, esize: u32) -> u64 {
    if b {
        mask(esize)
    } else {
        0
    }
}

/// `CountLeadingSignBits()` of an `esize`-bit value.
fn cls(x: u64, esize: u32) -> u64 {
    let y = ((x >> 1) ^ x) & mask(esize - 1);
    // CountLeadingZeroBits() of the (esize-1)-bit y.
    let lz = if y == 0 { esize - 1 } else { y.leading_zeros() - (64 - (esize - 1)) };
    lz as u64
}

fn clz(x: u64, esize: u32) -> u64 {
    if x == 0 {
        esize as u64
    } else {
        (x.leading_zeros() - (64 - esize)) as u64
    }
}

/// Execute an integer or polynomial Advanced SIMD instruction; `true` when
/// it saturated (FPSCR.QC).
pub(crate) fn exec(regs: &mut dyn Regs, i: &FpInst) -> bool {
    let src = File::read(regs).d;
    let mut out = src;
    let mut qc = false;
    match *i {
        FpInst::Simd3 { op, dt, d, n, m } => three(&src, &mut out, &mut qc, op, dt, d, n, m, None),
        FpInst::Simd3Scalar { op, dt, d, n, m, index } => {
            let esize = dt.esize();
            let s = elem(src[m as usize], index as u32, esize);
            three(&src, &mut out, &mut qc, op, dt, d, n, VReg::D(m), Some(s))
        }
        FpInst::Simd2 { op, dt, d, m } => two(&src, &mut out, &mut qc, op, dt, d, m),
        FpInst::SimdShift { op, dt, d, m, shift } => shift_imm(&src, &mut out, &mut qc, op, dt, d, m, shift as u32),
        FpInst::SimdImm { op, d, imm, .. } => {
            let (first, regs) = dregs(d);
            for r in first..first + regs {
                out[r] = match op {
                    ImmOp::Vmov => imm,
                    ImmOp::Vorr => src[r] | imm,
                    ImmOp::Vmvn => !imm,
                    ImmOp::Vbic => src[r] & !imm,
                };
            }
        }
        _ => unreachable!("not an integer Advanced SIMD instruction: {i:?}"),
    }
    for (k, (a, b)) in src.iter().zip(out.iter()).enumerate() {
        if a != b {
            regs.set_d(k as u8, *b);
        }
    }
    qc
}

/// The three-register forms, and the scalar forms with `scalar` the
/// element of `D[m]` they use.
#[allow(clippy::too_many_arguments)]
fn three(src: &[u64; 32], out: &mut [u64; 32], qc: &mut bool, op: Simd3Op, dt: Dt, d: VReg, n: VReg, m: VReg, scalar: Option<u64>) {
    use Simd3Op::*;
    let (df, dregs_n) = dregs(d);
    let (nf, _) = dregs(n);
    let (mf, _) = dregs(m);
    match op {
        // Bitwise (A8.8.288 VAND .. A8.8.361 VORR): whole doublewords.
        Vand | Vbic | Vorr | Vorn | Veor | Vbsl | Vbit | Vbif => {
            for r in 0..dregs_n {
                let (a, b, c) = (src[nf + r], src[mf + r], src[df + r]);
                out[df + r] = match op {
                    Vand => a & b,
                    Vbic => a & !b,
                    Vorr => a | b,
                    Vorn => a | !b,
                    Veor => a ^ b,
                    Vbsl => (a & c) | (b & !c),
                    Vbit => (a & b) | (c & !b),
                    _ => (c & b) | (a & !b),
                };
            }
            return;
        }
        _ => {}
    }
    let u = dt.is_unsigned();
    match op {
        // Long: Q[d] from D[n], D[m] (or the scalar).
        Vabdl | Vabal | Vaddl | Vsubl | Vmlal | Vmlsl | Vmull | Vqdmlal | Vqdmlsl | Vqdmull | Vaddw | Vsubw => {
            let esize = dt.esize();
            let w = 2 * esize;
            for e in 0..64 / esize {
                let a = if matches!(op, Vaddw | Vsubw) { int(get(src, nf, e, w), w, u) } else { int(get(src, nf, e, esize), esize, u) };
                let bb = scalar.unwrap_or_else(|| get(src, mf, e, esize));
                let b = int(bb, esize, u);
                let old = get(src, df, e, w);
                let r: u64 = match op {
                    Vabdl => (a - b).unsigned_abs() as u64,
                    Vabal => old.wrapping_add((a - b).unsigned_abs() as u64),
                    Vaddl | Vaddw => (a + b) as u64,
                    Vsubl | Vsubw => (a - b) as u64,
                    Vmlal => old.wrapping_add((a * b) as u64),
                    Vmlsl => old.wrapping_sub((a * b) as u64),
                    Vmull if dt == Dt::P8 => poly_mul(get(src, nf, e, esize), bb, esize),
                    Vmull => (a * b) as u64,
                    Vqdmull => {
                        let (p, s) = sat_q(2 * a * b, w, false);
                        *qc |= s;
                        p
                    }
                    _ => {
                        // VQDMLAL, VQDMLSL.
                        let (p, s1) = sat_q(2 * a * b, w, false);
                        let p = int(p, w, false);
                        let acc = int(old, w, false);
                        let (r, s2) = sat_q(if op == Vqdmlal { acc + p } else { acc - p }, w, false);
                        *qc |= s1 || s2;
                        r
                    }
                };
                put(out, df, e, w, r & mask(w));
            }
        }
        // Narrow: D[d] from Q[n], Q[m], the high halves of the sums.
        Vaddhn | Vraddhn | Vsubhn | Vrsubhn => {
            let w = dt.esize();
            let esize = w / 2;
            for e in 0..64 / esize {
                let (a, b) = (get(src, nf, e, w), get(src, mf, e, w));
                let rc = if matches!(op, Vraddhn | Vrsubhn) { 1u64 << (esize - 1) } else { 0 };
                let s = if matches!(op, Vaddhn | Vraddhn) { a.wrapping_add(b) } else { a.wrapping_sub(b) };
                let s = s.wrapping_add(rc) & mask(w);
                put(out, df, e, esize, s >> esize);
            }
        }
        // Pairwise, doublewords only.
        Vpadd | Vpmax | Vpmin => {
            let esize = dt.esize();
            let h = 32 / esize;
            let mut dest = 0u64;
            for e in 0..h {
                for (base, x) in [(0, src[nf]), (h, src[mf])] {
                    let (a, b) = (elem(x, 2 * e, esize), elem(x, 2 * e + 1, esize));
                    let r = match op {
                        Vpadd => a.wrapping_add(b),
                        _ => {
                            let (ia, ib) = (int(a, esize, u), int(b, esize, u));
                            (if op == Vpmax { ia.max(ib) } else { ia.min(ib) }) as u64
                        }
                    };
                    set_elem(&mut dest, base + e, esize, r);
                }
            }
            out[df] = dest;
        }
        _ => {
            let esize = dt.esize();
            for e in 0..(dregs_n as u32 * 64 / esize) {
                let a = get(src, nf, e, esize);
                let b = scalar.unwrap_or_else(|| get(src, mf, e, esize));
                let c = get(src, df, e, esize);
                let (ia, ib) = (int(a, esize, u), int(b, esize, u));
                // The shifts by register: the shift is the low byte of the
                // n operand's element, signed; the value is m's.
                let shift = int(a & 0xff, 8, false) as i32;
                let (sa, sb) = (int(a, esize, false), int(b, esize, false));
                let r: u64 = match op {
                    Vhadd => ((ia + ib) >> 1) as u64,
                    Vhsub => ((ia - ib) >> 1) as u64,
                    Vrhadd => ((ia + ib + 1) >> 1) as u64,
                    Vqadd | Vqsub => {
                        let (r, s) = sat_q(if op == Vqadd { ia + ib } else { ia - ib }, esize, u);
                        *qc |= s;
                        r
                    }
                    Vcgt => ones_if(ia > ib, esize),
                    Vcge => ones_if(ia >= ib, esize),
                    Vceq => ones_if(a == b, esize),
                    Vtst => ones_if(a & b != 0, esize),
                    Vshl => shl_bits(ib, shift),
                    Vrshl => {
                        if shift >= 0 {
                            shl_bits(ib, shift)
                        } else {
                            round_shr(ib, -shift) as u64
                        }
                    }
                    Vqshl | Vqrshl => {
                        let v = if shift >= 0 {
                            shl_sat(ib, shift)
                        } else if op == Vqrshl {
                            round_shr(ib, -shift)
                        } else {
                            ib >> (-shift).min(127)
                        };
                        let (r, s) = sat_q(v, esize, u);
                        *qc |= s;
                        r
                    }
                    Vmax => ia.max(ib) as u64,
                    Vmin => ia.min(ib) as u64,
                    Vabd => (ia - ib).unsigned_abs() as u64,
                    Vaba => c.wrapping_add((ia - ib).unsigned_abs() as u64),
                    Vadd => a.wrapping_add(b),
                    Vsub => a.wrapping_sub(b),
                    Vmla => c.wrapping_add(a.wrapping_mul(b)),
                    Vmls => c.wrapping_sub(a.wrapping_mul(b)),
                    Vmul if dt == Dt::P8 => poly_mul(a, b, esize),
                    Vmul => a.wrapping_mul(b),
                    Vqdmulh | Vqrdmulh => {
                        let rc = if op == Vqrdmulh { 1i128 << (esize - 1) } else { 0 };
                        let (r, s) = sat_q((2 * sa * sb + rc) >> esize, esize, false);
                        *qc |= s;
                        r
                    }
                    _ => unreachable!("not an integer three-register operation: {op:?}"),
                };
                put(out, df, e, esize, r & mask(esize));
            }
        }
    }
}

/// The two-register miscellaneous forms (A7.4.5).
fn two(src: &[u64; 32], out: &mut [u64; 32], qc: &mut bool, op: Simd2Op, dt: Dt, d: VReg, m: VReg) {
    use Simd2Op::*;
    let (df, dn) = dregs(d);
    let (mf, _) = dregs(m);
    let u = dt.is_unsigned();
    match op {
        Vmvn => {
            for r in 0..dn {
                out[df + r] = !src[mf + r];
            }
        }
        // A8.8.348 VMOVN, A8.8.375 VQMOVN, VQMOVUN: `dt` is the source's.
        Vmovn | Vqmovn | Vqmovun => {
            let w = dt.esize();
            let esize = w / 2;
            for e in 0..64 / esize {
                let x = get(src, mf, e, w);
                let r = match op {
                    Vmovn => x & mask(esize),
                    _ => {
                        let dest_unsigned = op == Vqmovun || u;
                        let (r, s) = sat_q(int(x, w, u), esize, dest_unsigned);
                        *qc |= s;
                        r
                    }
                };
                put(out, df, e, esize, r);
            }
        }
        // A8.8.347 VMOVL.
        Vmovl => {
            let esize = dt.esize();
            for e in 0..64 / esize {
                let v = int(get(src, mf, e, esize), esize, u) as u64;
                put(out, df, e, 2 * esize, v & mask(2 * esize));
            }
        }
        // A8.8.365 VPADDL, A8.8.362 VPADAL.
        Vpaddl | Vpadal => {
            let esize = dt.esize();
            for r in 0..dn {
                for e in 0..32 / esize {
                    let x = src[mf + r];
                    let s = int(elem(x, 2 * e, esize), esize, u) + int(elem(x, 2 * e + 1, esize), esize, u);
                    let mut v = s as u64;
                    if op == Vpadal {
                        v = v.wrapping_add(elem(src[df + r], e, 2 * esize));
                    }
                    set_elem(&mut out[df + r], e, 2 * esize, v);
                }
            }
        }
        _ => {
            let esize = dt.esize();
            for e in 0..(dn as u32 * 64 / esize) {
                let x = get(src, mf, e, esize);
                let sx = int(x, esize, false);
                let r = match op {
                    Vcls => cls(x, esize),
                    Vclz => clz(x, esize),
                    Vcnt => x.count_ones() as u64,
                    Vqabs | Vqneg => {
                        let (r, s) = sat_q(if op == Vqabs { sx.abs() } else { -sx }, esize, false);
                        *qc |= s;
                        r
                    }
                    Vcgt0 => ones_if(sx > 0, esize),
                    Vcge0 => ones_if(sx >= 0, esize),
                    Vceq0 => ones_if(x == 0, esize),
                    Vcle0 => ones_if(sx <= 0, esize),
                    Vclt0 => ones_if(sx < 0, esize),
                    Vabs => sx.unsigned_abs() as u64,
                    Vneg => (-sx) as u64,
                    _ => unreachable!("not an integer two-register operation: {op:?}"),
                };
                put(out, df, e, esize, r & mask(esize));
            }
        }
    }
}

/// The shifts by an immediate (A7.4.4); `dt` is the source's.
#[allow(clippy::too_many_arguments)]
fn shift_imm(src: &[u64; 32], out: &mut [u64; 32], qc: &mut bool, op: ShiftOp, dt: Dt, d: VReg, m: VReg, shift: u32) {
    use ShiftOp::*;
    let (df, dn) = dregs(d);
    let (mf, _) = dregs(m);
    let u = dt.is_unsigned();
    let sh = shift as i32;
    match op {
        // Narrowing: D[d] from Q[m].
        Vshrn | Vrshrn | Vqshrn | Vqshrun | Vqrshrn | Vqrshrun => {
            let w = dt.esize();
            let esize = w / 2;
            for e in 0..64 / esize {
                let x = get(src, mf, e, w);
                let r = match op {
                    // LSR(Elem[Qin[m>>1],e,2*esize] (+ round_const), shift):
                    // the sum is 2*esize bits.
                    Vshrn => shl_bits(x as i128, -sh) & mask(esize),
                    Vrshrn => {
                        let s = (x as u128 + (1u128 << (shift - 1))) as u64 & mask(w);
                        shl_bits(s as i128, -sh) & mask(esize)
                    }
                    _ => {
                        let v = int(x, w, u);
                        let v = if matches!(op, Vqrshrn | Vqrshrun) { round_shr(v, sh) } else { v >> sh };
                        let (r, s) = sat_q(v, esize, u || matches!(op, Vqshrun | Vqrshrun));
                        *qc |= s;
                        r
                    }
                };
                put(out, df, e, esize, r);
            }
        }
        // A8.8.398 VSHLL: Q[d] from D[m].
        Vshll => {
            let esize = dt.esize();
            for e in 0..64 / esize {
                let v = shl_bits(int(get(src, mf, e, esize), esize, u), sh);
                put(out, df, e, 2 * esize, v & mask(2 * esize));
            }
        }
        _ => {
            let esize = dt.esize();
            for e in 0..(dn as u32 * 64 / esize) {
                let x = get(src, mf, e, esize);
                let c = get(src, df, e, esize);
                let ix = int(x, esize, u);
                let r = match op {
                    Vshr => shl_bits(ix, -sh),
                    Vsra => c.wrapping_add(shl_bits(ix, -sh)),
                    Vrshr => round_shr(ix, sh) as u64,
                    Vrsra => c.wrapping_add(round_shr(ix, sh) as u64),
                    Vsri => {
                        // mask = LSR(Ones(esize), shift); LSR of the element.
                        let mk = if shift >= esize { 0 } else { mask(esize) >> shift };
                        let v = if shift >= esize { 0 } else { x >> shift };
                        (c & !mk) | v
                    }
                    Vshl => x << shift,
                    Vsli => {
                        let mk = mask(esize) << shift;
                        (c & !mk) | (x << shift)
                    }
                    Vqshl | Vqshlu => {
                        // VQSHLU: a signed source to an unsigned result.
                        let (r, s) = sat_q(shl_sat(ix, sh), esize, u || op == Vqshlu);
                        *qc |= s;
                        r
                    }
                    _ => unreachable!("not a same-length shift: {op:?}"),
                };
                put(out, df, e, esize, r & mask(esize));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::exec;
    use crate::tests::R;
    use gex_isa_a32::fp::{Dt, FpInst, ShiftOp, Simd2Op, Simd3Op, VReg};

    /// Run `i` with D0 = `n`, D1 = `m`, D2 = `d`: D2 and QC after it.
    fn run(i: FpInst, n: u64, m: u64, d: u64) -> (u64, bool) {
        let mut r = R::default();
        r.d[0] = n;
        r.d[1] = m;
        r.d[2] = d;
        let qc = exec(&mut r, &i);
        (r.d[2], qc)
    }

    fn s3(op: Simd3Op, dt: Dt) -> FpInst {
        FpInst::Simd3 { op, dt, d: VReg::D(2), n: VReg::D(0), m: VReg::D(1) }
    }

    fn sh(op: ShiftOp, dt: Dt, shift: u8) -> FpInst {
        FpInst::SimdShift { op, dt, d: VReg::D(2), m: VReg::D(1), shift }
    }

    #[test]
    fn doubling_multiplies_saturate_only_at_the_minimum() {
        // VQDMULH.S16: -32768 * -32768 saturates; 0x4000 * 0x4000 = 0x2000.
        assert_eq!(run(s3(Simd3Op::Vqdmulh, Dt::S16), 0x8000, 0x8000, 0), (0x7fff, true));
        assert_eq!(run(s3(Simd3Op::Vqdmulh, Dt::S16), 0x4000, 0x4000, 0), (0x2000, false));
        // VQRDMULH.S32 rounds: (2 * 2^30 * 1 + 2^31) >> 32 = 1.
        assert_eq!(run(s3(Simd3Op::Vqrdmulh, Dt::S32), 0x4000_0000, 1, 0), (1, false));
    }

    #[test]
    fn shifts_by_register() {
        // VRSHL.S8 by -1 of -127: (-127 + 1) >> 1 = -63.
        assert_eq!(run(s3(Simd3Op::Vrshl, Dt::S8), 0xff, 0x81, 0).0 & 0xff, 0xc1);
        // VRSHL.U64 by -64: (2^64 - 1 + 2^63) >> 64 = 1.
        assert_eq!(run(s3(Simd3Op::Vrshl, Dt::U64), 0xc0, u64::MAX, 0).0, 1);
        // A shift count of -128 rounds every value to 0.
        assert_eq!(run(s3(Simd3Op::Vrshl, Dt::U64), 0x80, u64::MAX, 0).0, 0);
        // VQSHL.U8 by 8 saturates; VQSHL.S64 of -1 by 64 saturates low.
        assert_eq!(run(s3(Simd3Op::Vqshl, Dt::U8), 0x08, 0x01, 0), (0xff, true));
        assert_eq!(run(s3(Simd3Op::Vqshl, Dt::S64), 0x40, u64::MAX, 0), (1 << 63, true));
        assert_eq!(run(s3(Simd3Op::Vqshl, Dt::S64), 0x40, 0, 0), (0, false));
        // VSHL.I64 by 64 is 0; by -64 of a signed value its sign.
        assert_eq!(run(s3(Simd3Op::Vshl, Dt::U64), 0x40, u64::MAX, 7).0, 0);
        assert_eq!(run(s3(Simd3Op::Vshl, Dt::S64), 0xc0, 1 << 63, 7).0, u64::MAX);
    }

    #[test]
    fn counts_and_polynomials() {
        let cls = |x| run(FpInst::Simd2 { op: Simd2Op::Vcls, dt: Dt::S8, d: VReg::D(2), m: VReg::D(1) }, 0, x, 0).0 & 0xff;
        assert_eq!([cls(0x00), cls(0xff), cls(0x40), cls(0xc0), cls(0x01)], [7, 7, 0, 1, 6]);
        let clz = |x| run(FpInst::Simd2 { op: Simd2Op::Vclz, dt: Dt::I16, d: VReg::D(2), m: VReg::D(1) }, 0, x, 0).0 & 0xffff;
        assert_eq!([clz(0), clz(1), clz(0x8000)], [16, 15, 0]);
        // VMULL.P8 0xff * 0xff = 0x5555.
        let i = FpInst::Simd3 { op: Simd3Op::Vmull, dt: Dt::P8, d: VReg::Q(1), n: VReg::D(0), m: VReg::D(1) };
        assert_eq!(run(i, 0xff, 0xff, 0).0 & 0xffff, 0x5555);
    }

    #[test]
    fn narrows_and_accumulates() {
        let n2 = |op, dt, shift: u8, m: u64| {
            let mut r = R::default();
            r.d[2] = m;
            r.d[3] = 0;
            let qc = exec(&mut r, &FpInst::SimdShift { op, dt, d: VReg::D(0), m: VReg::Q(1), shift });
            (r.d[0] & 0xff, qc)
        };
        // VRSHRN.I16 #8 of 0xffff: the sum wraps at 16 bits.
        assert_eq!(n2(ShiftOp::Vrshrn, Dt::I16, 8, 0xffff), (0, false));
        // VQRSHRN.U16 #8 of 0xffff: 0x100 saturates to 0xff.
        assert_eq!(n2(ShiftOp::Vqrshrn, Dt::U16, 8, 0xffff), (0xff, true));
        // VQSHRUN.S16 #1 of -2 saturates to 0.
        assert_eq!(n2(ShiftOp::Vqshrun, Dt::S16, 1, 0xfffe), (0, true));
        // VQMOVUN.S16 of 0x0100.
        let mut r = R::default();
        r.d[2] = 0x0100;
        assert!(exec(&mut r, &FpInst::Simd2 { op: Simd2Op::Vqmovun, dt: Dt::S16, d: VReg::D(0), m: VReg::Q(1) }));
        assert_eq!(r.d[0] & 0xff, 0xff);
        // VPADAL.S8: -1 + -1 added to 3 in each halfword.
        let i = FpInst::Simd2 { op: Simd2Op::Vpadal, dt: Dt::S8, d: VReg::D(2), m: VReg::D(1) };
        assert_eq!(run(i, 0, 0xffff, 0x0003).0 & 0xffff, 0x0001);
        // VSRI.64 #64 leaves the destination; VSLI.8 #7.
        assert_eq!(run(sh(ShiftOp::Vsri, Dt::X64, 64), 0, u64::MAX, 0x1234).0, 0x1234);
        assert_eq!(run(sh(ShiftOp::Vsli, Dt::X8, 7), 0, 0x01, 0x7f).0 & 0xff, 0xff);
        // VQSHLU.S8 #1: negative saturates to 0, 0x40 to 0x80, 0x7f to 0xfe.
        assert_eq!(run(sh(ShiftOp::Vqshlu, Dt::S8, 1), 0, 0xff, 0), (0, true));
        assert_eq!(run(sh(ShiftOp::Vqshlu, Dt::S8, 1), 0, 0x7f40, 0), (0xfe80, false));
    }
}
