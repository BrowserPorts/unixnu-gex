//! Advanced SIMD floating-point data processing, under the standard FPSCR
//! value (A2.7.8 `StandardFPSCRValue()`: Flush-to-zero, Default NaN,
//! Round to Nearest, untrapped exceptions, FPSCR.AHP kept), and the
//! reciprocal and reciprocal square root estimates and steps.

use super::simd::*;
use super::soft::{self, standard_fpscr};
use crate::Regs;
use gex_isa_a32::fp::{Dt, FpInst, Simd2Op, Simd3Op};

fn ones_if(b: bool) -> u64 {
    if b {
        0xffff_ffff
    } else {
        0
    }
}

fn get(f: &[u64; 32], first: usize, e: u32, size: u32) -> u64 {
    let per = 64 / size;
    elem(f[first + (e / per) as usize], e % per, size)
}

fn put(f: &mut [u64; 32], first: usize, e: u32, size: u32, v: u64) {
    let per = 64 / size;
    set_elem(&mut f[first + (e / per) as usize], e % per, size, v);
}

/// Execute a floating-point Advanced SIMD instruction (or VRECPE/VRSQRTE of
/// unsigned integers); the cumulative exception bits it raises.
pub(crate) fn exec(regs: &mut dyn Regs, i: &FpInst) -> u32 {
    let src = File::read(regs).d;
    let mut out = src;
    let std = standard_fpscr(regs.fpscr());
    let mut exc = 0u32;
    let x = &mut exc;
    match *i {
        FpInst::Simd3 { op, d, n, m, .. } => {
            let (df, dn) = dregs(d);
            let (nf, _) = dregs(n);
            let (mf, _) = dregs(m);
            if matches!(op, Simd3Op::Vpadd | Simd3Op::Vpmax | Simd3Op::Vpmin) {
                // A8.8.364 VPADD, A8.8.367 VPMAX, VPMIN: doublewords.
                let mut dest = 0u64;
                for (base, v) in [(0, src[nf]), (1, src[mf])] {
                    let (a, b) = (elem(v, 0, 32), elem(v, 1, 32));
                    let r = match op {
                        Simd3Op::Vpadd => soft::add(a, b, 32, std, x),
                        _ => soft::max_min(a, b, op == Simd3Op::Vpmax, 32, std, x),
                    };
                    set_elem(&mut dest, base, 32, r);
                }
                out[df] = dest;
            } else {
                for e in 0..(dn as u32 * 2) {
                    let (a, b, c) = (get(&src, nf, e, 32), get(&src, mf, e, 32), get(&src, df, e, 32));
                    let r = three(op, a, b, c, std, x);
                    put(&mut out, df, e, 32, r);
                }
            }
        }
        FpInst::Simd3Scalar { op, d, n, m, index, .. } => {
            let (df, dn) = dregs(d);
            let (nf, _) = dregs(n);
            let s = elem(src[m as usize], index as u32, 32);
            for e in 0..(dn as u32 * 2) {
                let (a, c) = (get(&src, nf, e, 32), get(&src, df, e, 32));
                let r = three(op, a, s, c, std, x);
                put(&mut out, df, e, 32, r);
            }
        }
        FpInst::Simd2 { op, dt, d, m } => {
            let (df, dn) = dregs(d);
            let (mf, _) = dregs(m);
            for e in 0..(dn as u32 * 2) {
                let v = get(&src, mf, e, 32);
                let z = soft::zero(false, 32);
                let r = match op {
                    Simd2Op::Vabs => soft::abs(v, 32),
                    Simd2Op::Vneg => soft::neg(v, 32),
                    Simd2Op::Vcgt0 => ones_if(soft::compare_gt(v, z, 32, std, x)),
                    Simd2Op::Vcge0 => ones_if(soft::compare_ge(v, z, 32, std, x)),
                    Simd2Op::Vceq0 => ones_if(soft::compare_eq(v, z, 32, std, x)),
                    Simd2Op::Vcle0 => ones_if(soft::compare_ge(z, v, 32, std, x)),
                    Simd2Op::Vclt0 => ones_if(soft::compare_gt(z, v, 32, std, x)),
                    Simd2Op::Vrecpe if dt == Dt::U32 => soft::unsigned_recip_estimate(v as u32) as u64,
                    Simd2Op::Vrecpe => soft::recip_estimate32(v as u32, std, x) as u64,
                    Simd2Op::Vrsqrte if dt == Dt::U32 => soft::unsigned_rsqrt_estimate(v as u32) as u64,
                    Simd2Op::Vrsqrte => soft::rsqrt_estimate32(v as u32, std, x) as u64,
                    _ => unreachable!("not a floating-point two-register operation: {op:?}"),
                };
                put(&mut out, df, e, 32, r);
            }
        }
        FpInst::SimdCvt { to, from, d, m, fbits } => match (to, from) {
            // A8.8.311: half-precision, D[d] from Q[m] or Q[d] from D[m].
            (Dt::F16, Dt::F32) => {
                let (df, mf) = (dregs(d).0, dregs(m).0);
                for e in 0..4 {
                    let h = soft::single_to_half(get(&src, mf, e, 32) as u32, std, x);
                    put(&mut out, df, e, 16, h as u64);
                }
            }
            (Dt::F32, Dt::F16) => {
                let (df, mf) = (dregs(d).0, dregs(m).0);
                for e in 0..4 {
                    let s = soft::half_to_single(get(&src, mf, e, 16) as u16, std, x);
                    put(&mut out, df, e, 32, s as u64);
                }
            }
            // A8.8.306, A8.8.308: to an integer or fixed-point (round towards
            // zero), or from one (round to nearest).
            _ => {
                let (df, dn) = dregs(d);
                let (mf, _) = dregs(m);
                for e in 0..(dn as u32 * 2) {
                    let v = get(&src, mf, e, 32);
                    let r = if to == Dt::F32 {
                        soft::from_fixed(v, 32, 32, fbits as u32, from.is_unsigned(), true, std, x)
                    } else {
                        soft::to_fixed(v, 32, 32, fbits as u32, to.is_unsigned(), true, std, x)
                    };
                    put(&mut out, df, e, 32, r);
                }
            }
        },
        _ => unreachable!("not a floating-point Advanced SIMD instruction: {i:?}"),
    }
    for (k, (a, b)) in src.iter().zip(out.iter()).enumerate() {
        if a != b {
            regs.set_d(k as u8, *b);
        }
    }
    exc
}

/// An element of a same-length floating-point operation: `a` from `n`, `b`
/// from `m` (or the scalar), `c` the destination's.
fn three(op: Simd3Op, a: u64, b: u64, c: u64, std: u32, x: &mut u32) -> u64 {
    use Simd3Op::*;
    match op {
        Vadd => soft::add(a, b, 32, std, x),
        Vsub => soft::sub(a, b, 32, std, x),
        Vmul => soft::mul(a, b, 32, std, x),
        // A8.8.280 VABD: FPAbs(FPSub()).
        Vabd => soft::abs(soft::sub(a, b, 32, std, x), 32),
        Vmla | Vmls => {
            let p = soft::mul(a, b, 32, std, x);
            let p = if op == Vmls { soft::neg(p, 32) } else { p };
            soft::add(c, p, 32, std, x)
        }
        Vfma => soft::mul_add(c, a, b, 32, std, x),
        Vfms => soft::mul_add(c, soft::neg(a, 32), b, 32, std, x),
        Vceq => ones_if(soft::compare_eq(a, b, 32, std, x)),
        Vcge => ones_if(soft::compare_ge(a, b, 32, std, x)),
        Vcgt => ones_if(soft::compare_gt(a, b, 32, std, x)),
        Vacge => ones_if(soft::compare_ge(soft::abs(a, 32), soft::abs(b, 32), 32, std, x)),
        Vacgt => ones_if(soft::compare_gt(soft::abs(a, 32), soft::abs(b, 32), 32, std, x)),
        Vmax => soft::max_min(a, b, true, 32, std, x),
        Vmin => soft::max_min(a, b, false, 32, std, x),
        Vrecps => soft::step32(a as u32, b as u32, false, std, x) as u64,
        Vrsqrts => soft::step32(a as u32, b as u32, true, std, x) as u64,
        _ => unreachable!("not a floating-point three-register operation: {op:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::exec;
    use crate::fpu::soft::{DZC, IDC, IOC, IXC};
    use crate::tests::R;
    use gex_isa_a32::fp::{Dt, FpInst, Simd2Op, Simd3Op, VReg};

    fn pair(a: f32, b: f32) -> u64 {
        (b.to_bits() as u64) << 32 | a.to_bits() as u64
    }

    #[test]
    fn standard_fpscr_value_whatever_the_fpscr() {
        let mut r = R::default();
        // Round towards Zero, no Flush-to-zero, no Default NaN in the FPSCR:
        // Advanced SIMD still rounds to nearest, flushes and gives the
        // default NaN.
        r.fpscr = 3 << 22;
        r.d[0] = pair(1.0, 1.0) & 0xffff_ffff | 0x0000_0001u64 << 32;
        r.d[1] = pair(f32::from_bits(0x3380_0001), 0.0) & 0xffff_ffff | 0x7f80_0001u64 << 32;
        let i = FpInst::Simd3 { op: Simd3Op::Vadd, dt: Dt::F32, d: VReg::D(2), n: VReg::D(0), m: VReg::D(1) };
        let exc = exec(&mut r, &i);
        // 1 + (2^-24 + 2^-47) rounds up to nearest; denormal + sNaN gives
        // the default NaN with IDC and IOC.
        assert_eq!(r.d[2] as u32, 0x3f80_0001);
        assert_eq!((r.d[2] >> 32) as u32, 0x7fc0_0000);
        assert_eq!(exc, IXC | IDC | IOC);
    }

    #[test]
    fn estimates_and_conversions() {
        let mut r = R::default();
        r.d[1] = pair(1.0, 0.0);
        let i = FpInst::Simd2 { op: Simd2Op::Vrecpe, dt: Dt::F32, d: VReg::D(2), m: VReg::D(1) };
        assert_eq!(exec(&mut r, &i), DZC);
        assert_eq!(r.d[2], 0x7f80_0000_3f7f_8000);
        // VCVT.S32.F32 #1 rounds towards zero: -1.75 * 2 = -3.5 -> -3.
        r.d[1] = pair(-1.75, 3e9);
        let i = FpInst::SimdCvt { to: Dt::S32, from: Dt::F32, d: VReg::D(2), m: VReg::D(1), fbits: 1 };
        assert_eq!(exec(&mut r, &i), IXC | IOC);
        assert_eq!(r.d[2], 0x7fff_ffff_ffff_fffd);
    }
}
