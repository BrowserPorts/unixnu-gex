//! Advanced SIMD data processing (A7.4): the register file as the
//! pseudocode's `Elem[]`, `Din[]` and `Qin[]` see it, and saturation
//! (A2.2.1 Pseudocode details of saturation).
//!
//! An instruction reads its operands from a copy of the register file made
//! before it writes anything, which is the `_Dclone[]` of
//! `CheckAdvSIMDEnabled()` (B1.11.1). Where a description reads `D[]`
//! rather than `Din[]`, every read of a register the instruction also
//! writes comes before that write in the pseudocode's own order (the same
//! element of an element-wise operation, or a whole operand read before
//! the destination is assembled), so the copy gives the same values.

use crate::Regs;
use gex_isa_a32::fp::VReg;

/// The 32 doublewords, read once.
pub(crate) struct File {
    pub d: [u64; 32],
}

impl File {
    pub fn read(regs: &dyn Regs) -> File {
        let mut d = [0; 32];
        for (n, v) in d.iter_mut().enumerate() {
            *v = regs.d(n as u8);
        }
        File { d }
    }
}

pub(crate) fn mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1 << bits) - 1
    }
}

/// `Elem[x, e, esize]` of a doubleword.
pub(crate) fn elem(x: u64, e: u32, esize: u32) -> u64 {
    (x >> (e * esize)) & mask(esize)
}

pub(crate) fn set_elem(x: &mut u64, e: u32, esize: u32, v: u64) {
    let m = mask(esize) << (e * esize);
    *x = (*x & !m) | ((v << (e * esize)) & m);
}

/// `Int(x, unsigned)` of an `esize`-bit value.
pub(crate) fn int(x: u64, esize: u32, unsigned: bool) -> i128 {
    let x = x & mask(esize);
    if unsigned || esize == 0 || x >> (esize - 1) & 1 == 0 {
        x as i128
    } else {
        x as i128 - (1i128 << esize)
    }
}

/// `SatQ(i, N, unsigned)`: the saturated value's low `n` bits and whether
/// it saturated (`UnsignedSatQ()`, `SignedSatQ()`).
pub(crate) fn sat_q(i: i128, n: u32, unsigned: bool) -> (u64, bool) {
    let (lo, hi) = if unsigned { (0, (1i128 << n) - 1) } else { (-(1i128 << (n - 1)), (1i128 << (n - 1)) - 1) };
    if i > hi {
        (hi as u64 & mask(n), true)
    } else if i < lo {
        (lo as u64 & mask(n), true)
    } else {
        (i as u64 & mask(n), false)
    }
}

/// `x << s` of the pseudocode's integers (`s` negative for a shift right,
/// rounding down) for a saturating shift, `|x| <= 2^64`: a nonzero value
/// shifted left 64 places or more is beyond every destination, and is
/// given as such.
pub(crate) fn shl_sat(x: i128, s: i32) -> i128 {
    if s >= 64 {
        x.signum() * i128::MAX
    } else if s >= 0 {
        x << s
    } else {
        x >> (-s).min(127)
    }
}

/// The low 64 bits of `x << s` (`s` negative for a shift right, rounding
/// down), `|x| <= 2^64`.
pub(crate) fn shl_bits(x: i128, s: i32) -> u64 {
    if s >= 64 {
        0
    } else if s >= 0 {
        ((x as u128) << s) as u64
    } else {
        (x >> (-s).min(127)) as u64
    }
}

/// `(x + round_const) >> k` of the rounding shifts right, `round_const`
/// being `1 << (k-1)`, `k >= 1`, `|x| <= 2^64`. For `k > 65` it is 0 for
/// every such `x`.
pub(crate) fn round_shr(x: i128, k: i32) -> i128 {
    if k > 65 {
        return 0;
    }
    (x + (1i128 << (k - 1))) >> k
}

/// The first doubleword and the count of a D or Q register operand.
pub(crate) fn dregs(r: VReg) -> (usize, usize) {
    match r {
        VReg::D(n) => (n as usize, 1),
        VReg::Q(n) => (2 * n as usize, 2),
        VReg::S(_) => unreachable!("an S register in an Advanced SIMD instruction"),
    }
}

/// `PolynomialMult(op1, op2)` (A2.8.1): the carry-less product.
pub(crate) fn poly_mul(a: u64, b: u64, esize: u32) -> u64 {
    let mut r = 0u128;
    for i in 0..esize {
        if b >> i & 1 == 1 {
            r ^= (a as u128) << i;
        }
    }
    r as u64
}
