//! Advanced SIMD permutes: A8.8.317 VEXT, A8.8.420 VTBL/VTBX, A8.8.314
//! VDUP (scalar), A8.8.387 VREV16/VREV32/VREV64, A8.8.419 VSWP, A8.8.421
//! VTRN, A8.8.423 VUZP and A8.8.424 VZIP.

use super::simd::*;
use crate::{Regs, Stop};
use gex_isa_a32::fp::{FpInst, Simd2Op, VReg};

/// The value of a register operand as one integer (`D[n]` or `Q[n]`).
fn whole(f: &[u64; 32], r: VReg) -> u128 {
    let (first, n) = dregs(r);
    if n == 1 {
        f[first] as u128
    } else {
        (f[first + 1] as u128) << 64 | f[first] as u128
    }
}

fn set_whole(f: &mut [u64; 32], r: VReg, v: u128) {
    let (first, n) = dregs(r);
    f[first] = v as u64;
    if n == 2 {
        f[first + 1] = (v >> 64) as u64;
    }
}

fn bits_of(r: VReg) -> u32 {
    64 * dregs(r).1 as u32
}

fn el(v: u128, e: u32, esize: u32) -> u128 {
    (v >> (e * esize)) & ((1u128 << esize) - 1)
}

fn set_el(v: &mut u128, e: u32, esize: u32, x: u128) {
    let m = ((1u128 << esize) - 1) << (e * esize);
    *v = (*v & !m) | ((x << (e * esize)) & m);
}

/// Execute a permute. A destination the description makes UNKNOWN (the
/// same register for both operands of VSWP, VTRN, VUZP, VZIP) stops the
/// model rather than taking a value of its choosing.
pub(crate) fn exec(regs: &mut dyn Regs, pc_addr: u32, i: &FpInst) -> Result<(), Stop> {
    let src = File::read(regs).d;
    let mut out = src;
    match *i {
        FpInst::Vext { d, n, m, imm } => {
            let bits = bits_of(d);
            let pos = 8 * imm as u32;
            let (vn, vm) = (whole(&src, n), whole(&src, m));
            // (m:n)<position+bits-1:position>.
            let r = if pos == 0 { vn } else { (vn >> pos) | (vm << (bits - pos)) };
            let r = if bits == 64 { r & u64::MAX as u128 } else { r };
            set_whole(&mut out, d, r);
        }
        FpInst::Vtbl { tbx, d, n, len, m } => {
            let mut table = [0u8; 32];
            for k in 0..len as usize {
                table[8 * k..8 * k + 8].copy_from_slice(&src[n as usize + k].to_le_bytes());
            }
            let idx = src[m as usize].to_le_bytes();
            let mut dest = src[d as usize].to_le_bytes();
            for (b, &ix) in dest.iter_mut().zip(idx.iter()) {
                if (ix as usize) < 8 * len as usize {
                    *b = table[ix as usize];
                } else if !tbx {
                    *b = 0;
                }
            }
            out[d as usize] = u64::from_le_bytes(dest);
        }
        FpInst::VdupScalar { dt, d, m, index } => {
            let esize = dt.esize();
            let s = elem(src[m as usize], index as u32, esize);
            let (first, n) = dregs(d);
            for r in first..first + n {
                let mut x = 0;
                for e in 0..64 / esize {
                    set_elem(&mut x, e, esize, s);
                }
                out[r] = x;
            }
        }
        FpInst::Simd2 { op, dt, d, m } => {
            let esize = dt.esize();
            let unknown = |what: &str| -> Result<(), Stop> {
                Err(Stop::Unpredictable(format!("{what} with the same register for both operands at {pc_addr:#x}: its result is UNKNOWN")))
            };
            match op {
                Simd2Op::Vrev16 | Simd2Op::Vrev32 | Simd2Op::Vrev64 => {
                    let group = match op {
                        Simd2Op::Vrev16 => 16,
                        Simd2Op::Vrev32 => 32,
                        _ => 64,
                    };
                    let reverse_mask = group / esize - 1;
                    let (df, n) = dregs(d);
                    let (mf, _) = dregs(m);
                    for r in 0..n {
                        let mut dest = 0;
                        for e in 0..64 / esize {
                            set_elem(&mut dest, e ^ reverse_mask, esize, elem(src[mf + r], e, esize));
                        }
                        out[df + r] = dest;
                    }
                }
                Simd2Op::Vswp | Simd2Op::Vtrn => {
                    if d == m {
                        return unknown(if op == Simd2Op::Vswp { "VSWP (A8.8.419)" } else { "VTRN (A8.8.421)" });
                    }
                    let (df, n) = dregs(d);
                    let (mf, _) = dregs(m);
                    for r in 0..n {
                        if op == Simd2Op::Vswp {
                            out[df + r] = src[mf + r];
                            out[mf + r] = src[df + r];
                        } else {
                            for e in 0..32 / esize {
                                set_elem(&mut out[df + r], 2 * e + 1, esize, elem(src[mf + r], 2 * e, esize));
                                set_elem(&mut out[mf + r], 2 * e, esize, elem(src[df + r], 2 * e + 1, esize));
                            }
                        }
                    }
                }
                Simd2Op::Vuzp | Simd2Op::Vzip => {
                    if d == m {
                        return unknown(if op == Simd2Op::Vuzp { "VUZP (A8.8.423)" } else { "VZIP (A8.8.424)" });
                    }
                    let bits = bits_of(d);
                    let (vd, vm) = (whole(&src, d), whole(&src, m));
                    let (mut rd, mut rm) = (0u128, 0u128);
                    let elems = bits / esize;
                    if op == Simd2Op::Vuzp {
                        // zipped = m:d; d gets the even elements, m the odd.
                        let z = |k: u32| if k < elems { el(vd, k, esize) } else { el(vm, k - elems, esize) };
                        for e in 0..elems {
                            set_el(&mut rd, e, esize, z(2 * e));
                            set_el(&mut rm, e, esize, z(2 * e + 1));
                        }
                    } else {
                        // zipped<2e> = d<e>, zipped<2e+1> = m<e>; d gets the
                        // low half, m the high.
                        for e in 0..elems {
                            for (k, v) in [(2 * e, el(vd, e, esize)), (2 * e + 1, el(vm, e, esize))] {
                                if k < elems {
                                    set_el(&mut rd, k, esize, v);
                                } else {
                                    set_el(&mut rm, k - elems, esize, v);
                                }
                            }
                        }
                    }
                    set_whole(&mut out, d, rd);
                    set_whole(&mut out, m, rm);
                }
                _ => unreachable!("not a permute: {op:?}"),
            }
        }
        _ => unreachable!("not a permute: {i:?}"),
    }
    for (k, (a, b)) in src.iter().zip(out.iter()).enumerate() {
        if a != b {
            regs.set_d(k as u8, *b);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::exec;
    use crate::tests::R;
    use crate::Stop;
    use gex_isa_a32::fp::{Dt, FpInst, Simd2Op, VReg};

    #[test]
    fn table_lookups() {
        let mut r = R::default();
        r.d[0] = 0x0706_0504_0302_0100;
        r.d[1] = 0x0f0e_0d0c_0b0a_0908;
        // Indices 0, 9, 16 (out of a two-register table), 255.
        r.d[2] = 0x00ff_1009;
        r.d[3] = 0xaaaa_aaaa_aaaa_aaaa;
        exec(&mut r, 0, &FpInst::Vtbl { tbx: false, d: 3, n: 0, len: 2, m: 2 }).unwrap();
        // Bytes 0-3 index 9, 0x10, 0xff, 0; bytes 4-7 index 0: the out of
        // range indices give 0 (VTBL) or leave the byte (VTBX).
        assert_eq!(r.d[3], 0x0000_0000_0000_0009);
        r.d[3] = 0xaaaa_aaaa_aaaa_aaaa;
        exec(&mut r, 0, &FpInst::Vtbl { tbx: true, d: 3, n: 0, len: 2, m: 2 }).unwrap();
        assert_eq!(r.d[3], 0x0000_0000_00aa_aa09);
    }

    #[test]
    fn same_register_operands_are_unknown() {
        let mut r = R::default();
        for op in [Simd2Op::Vswp, Simd2Op::Vtrn, Simd2Op::Vuzp, Simd2Op::Vzip] {
            let i = FpInst::Simd2 { op, dt: Dt::X8, d: VReg::D(4), m: VReg::D(4) };
            assert!(matches!(exec(&mut r, 0x100, &i), Err(Stop::Unpredictable(_))), "{op:?}");
        }
    }

    #[test]
    fn zip_unzip_and_extract() {
        let mut r = R::default();
        r.d[0] = 0x0706_0504_0302_0100;
        r.d[1] = 0x1716_1514_1312_1110;
        exec(&mut r, 0, &FpInst::Simd2 { op: Simd2Op::Vzip, dt: Dt::X8, d: VReg::D(0), m: VReg::D(1) }).unwrap();
        assert_eq!((r.d[0], r.d[1]), (0x1303_1202_1101_1000, 0x1707_1606_1505_1404));
        exec(&mut r, 0, &FpInst::Simd2 { op: Simd2Op::Vuzp, dt: Dt::X8, d: VReg::D(0), m: VReg::D(1) }).unwrap();
        assert_eq!((r.d[0], r.d[1]), (0x0706_0504_0302_0100, 0x1716_1514_1312_1110));
        exec(&mut r, 0, &FpInst::Vext { d: VReg::D(2), n: VReg::D(0), m: VReg::D(1), imm: 3 }).unwrap();
        assert_eq!(r.d[2], 0x1211_1007_0605_0403);
    }
}
