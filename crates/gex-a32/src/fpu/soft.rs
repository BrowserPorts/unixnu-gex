//! The floating-point pseudocode of A2.7.8 (Pseudocode details of
//! floating-point operations), computed exactly in software.
//!
//! A value is handled as the pseudocode's `real`: an exact binary number
//! (`mant * 2^exp`, with a sticky bit below its last place where a
//! division or square root leaves a remainder), so that `FPRound()` sees
//! precisely the value, the exponent and the rounding error the
//! pseudocode gives it. Each function takes the FPSCR value the
//! pseudocode's `fpscr_val` is (the FPSCR, or [`standard_fpscr`] for
//! Advanced SIMD) and accumulates the cumulative exception bits that
//! `FPProcessException()` sets in `exc` (the FPSCR's bit positions). The
//! trap enables are RAZ in VFPv3 and VFPv4, so every exception is
//! untrapped.

use core::cmp::Ordering;

/// FPSCR control bits (B4.1.58).
pub const AHP: u32 = 1 << 26;
pub const DN: u32 = 1 << 25;
pub const FZ: u32 = 1 << 24;
pub const RMODE: u32 = 3 << 22;

/// The cumulative exception bits, FPSCR<7, 4:0>.
pub const IOC: u32 = 1;
pub const DZC: u32 = 1 << 1;
pub const OFC: u32 = 1 << 2;
pub const UFC: u32 = 1 << 3;
pub const IXC: u32 = 1 << 4;
pub const IDC: u32 = 1 << 7;

/// `StandardFPSCRValue()`: `'00000' : FPSCR<26> : '11' : Zeros(24)` (A2.7.8,
/// Selection of ARM standard floating-point arithmetic).
pub fn standard_fpscr(fpscr: u32) -> u32 {
    (fpscr & AHP) | DN | FZ
}

/// `FPType`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FpType {
    Nonzero,
    Zero,
    Infinity,
    QNaN,
    SNaN,
}

impl FpType {
    fn is_nan(self) -> bool {
        matches!(self, FpType::QNaN | FpType::SNaN)
    }
}

/// `(E, F)`: exponent and fraction widths of an `n`-bit format.
fn fmt(n: u32) -> (u32, u32) {
    match n {
        16 => (5, 10),
        32 => (8, 23),
        64 => (11, 52),
        _ => panic!("no {n}-bit floating-point format"),
    }
}

fn mask(n: u32) -> u64 {
    if n == 64 {
        u64::MAX
    } else {
        (1 << n) - 1
    }
}

/// `FPUnpack()`'s result: the type, the sign, and for `Nonzero` the value's
/// magnitude `mant * 2^exp`.
#[derive(Copy, Clone, Debug)]
pub struct Unpacked {
    pub ty: FpType,
    pub sign: bool,
    pub mant: u64,
    pub exp: i32,
}

/// `FPUnpack(fpval, fpscr_val)`.
pub fn unpack(v: u64, n: u32, fpscr: u32, exc: &mut u32) -> Unpacked {
    let (e, f) = fmt(n);
    let sign = (v >> (n - 1)) & 1 == 1;
    let exp = ((v >> f) & ((1 << e) - 1)) as u32;
    let frac = v & ((1 << f) - 1);
    let bias = (1i32 << (e - 1)) - 1;
    let un = |ty, mant, exp| Unpacked { ty, sign, mant, exp };
    if exp == 0 {
        // Zero, or a denormal: flushed to zero in Flush-to-zero mode, which
        // has no effect on half precision.
        if frac == 0 {
            return un(FpType::Zero, 0, 0);
        }
        if n != 16 && fpscr & FZ != 0 {
            *exc |= IDC;
            return un(FpType::Zero, 0, 0);
        }
        return un(FpType::Nonzero, frac, 1 - bias - f as i32);
    }
    // Half precision's maximum exponent is a number in the alternative
    // format (FPSCR.AHP).
    if exp == (1 << e) - 1 && (n != 16 || fpscr & AHP == 0) {
        if frac == 0 {
            return un(FpType::Infinity, 0, 0);
        }
        let ty = if frac >> (f - 1) & 1 == 1 { FpType::QNaN } else { FpType::SNaN };
        return un(ty, 0, 0);
    }
    un(FpType::Nonzero, (1 << f) | frac, exp as i32 - bias - f as i32)
}

/// `FPZero(sign, N)`.
pub fn zero(sign: bool, n: u32) -> u64 {
    (sign as u64) << (n - 1)
}

/// `FPInfinity(sign, N)`.
pub fn infinity(sign: bool, n: u32) -> u64 {
    let (e, f) = fmt(n);
    zero(sign, n) | (((1u64 << e) - 1) << f)
}

/// `FPMaxNormal(sign, N)`.
pub fn max_normal(sign: bool, n: u32) -> u64 {
    let (e, f) = fmt(n);
    zero(sign, n) | (((1u64 << e) - 2) << f) | ((1u64 << f) - 1)
}

/// `FPDefaultNaN(N)` (VFPv3 and later: the sign is 0).
pub fn default_nan(n: u32) -> u64 {
    let (e, f) = fmt(n);
    (((1u64 << e) - 1) << f) | (1 << (f - 1))
}

/// `FPTwo(N)`, `FPThree(N)`.
pub fn two(n: u32) -> u64 {
    let (e, f) = fmt(n);
    (1u64 << (e - 1)) << f
}

pub fn three(n: u32) -> u64 {
    let (e, f) = fmt(n);
    ((1u64 << (e - 1)) << f) | (1 << (f - 1))
}

/// `FPNeg()`, `FPAbs()`: the sign bit only.
pub fn neg(v: u64, n: u32) -> u64 {
    v ^ (1 << (n - 1))
}

pub fn abs(v: u64, n: u32) -> u64 {
    v & !(1 << (n - 1))
}

/// An exact nonzero real: `(-1)^sign * (mant + d) * 2^exp`, where `d` is 0
/// when `sticky` is clear and some value strictly between 0 and 1 when it
/// is set. A sticky value always has more than 64 significant bits, so its
/// `d` lies below every place `FPRound()` rounds at.
#[derive(Copy, Clone, Debug)]
pub struct Real {
    pub sign: bool,
    pub mant: u128,
    pub exp: i32,
    pub sticky: bool,
}

impl Real {
    fn of(u: &Unpacked) -> Real {
        Real { sign: u.sign, mant: u.mant as u128, exp: u.exp, sticky: false }
    }

    /// The same value with its leading one at bit 125.
    fn normalized(self) -> Real {
        let msb = 127 - self.mant.leading_zeros() as i32;
        let s = 125 - msb;
        if s >= 0 {
            Real { mant: self.mant << s, exp: self.exp - s, ..self }
        } else {
            // Only an exact value is ever wider than 126 bits here.
            assert!(!self.sticky && self.mant.trailing_zeros() as i32 >= -s, "inexact real wider than 126 bits");
            Real { mant: self.mant >> -s, exp: self.exp - s, ..self }
        }
    }
}

/// `x + y` exactly, `None` when it is exactly zero. Neither is sticky.
fn add_exact(x: Real, y: Real) -> Option<Real> {
    debug_assert!(!x.sticky && !y.sticky);
    if x.mant == 0 {
        return (y.mant != 0).then_some(y);
    }
    if y.mant == 0 {
        return Some(x);
    }
    let (mut x, mut y) = (x.normalized(), y.normalized());
    if y.exp > x.exp || (y.exp == x.exp && y.mant > x.mant) {
        core::mem::swap(&mut x, &mut y);
    }
    let d = (x.exp - y.exp) as u32;
    let (ym, sticky) = if d >= 127 { (0, true) } else { (y.mant >> d, y.mant & ((1u128 << d) - 1) != 0) };
    if x.sign == y.sign {
        return Some(Real { sign: x.sign, mant: x.mant + ym, exp: x.exp, sticky });
    }
    if d == 0 && x.mant == y.mant {
        return None;
    }
    // x - (ym + d) = (x - ym - 1) + (1 - d) when y's tail is not zero.
    Some(Real { sign: x.sign, mant: x.mant - ym - sticky as u128, exp: x.exp, sticky })
}

fn mul_exact(a: &Unpacked, b: &Unpacked) -> Real {
    Real { sign: a.sign != b.sign, mant: a.mant as u128 * b.mant as u128, exp: a.exp + b.exp, sticky: false }
}

fn div_exact(a: &Unpacked, b: &Unpacked) -> Real {
    let sa = a.mant.leading_zeros() as i32;
    let sb = b.mant.leading_zeros() as i32;
    let an = (a.mant << sa) as u128;
    let bn = (b.mant << sb) as u128;
    let num = an << 64;
    let q = num / bn;
    let r = num % bn;
    Real { sign: a.sign != b.sign, mant: q, exp: (a.exp - sa) - (b.exp - sb) - 64, sticky: r != 0 }
}

fn isqrt(v: u128) -> u128 {
    // Bit by bit: the largest r with r*r <= v.
    let mut r: u128 = 0;
    let mut bit: u128 = 1 << 126;
    let mut x = v;
    while bit > x {
        bit >>= 2;
    }
    while bit != 0 {
        if x >= r + bit {
            x -= r + bit;
            r = (r >> 1) + bit;
        } else {
            r >>= 1;
        }
        bit >>= 2;
    }
    r
}

fn sqrt_exact(a: &Unpacked) -> Real {
    let msb = 63 - a.mant.leading_zeros() as i32;
    let s = 125 - msb;
    let mut m = (a.mant as u128) << s;
    let mut e = a.exp - s;
    if e & 1 != 0 {
        m <<= 1;
        e -= 1;
    }
    let r = isqrt(m);
    Real { sign: false, mant: r, exp: e / 2, sticky: r * r != m }
}

/// The rounding error of an integer part as `FPRound()` and `FPToFixed()`
/// see it: whether it is zero, and how it compares with one half.
#[derive(Copy, Clone, Debug)]
struct Err {
    nonzero: bool,
    vs_half: Ordering,
}

/// `floor(mant * 2^-shift)` and the error, for `shift >= 1` or an exact
/// value.
fn split(mant: u128, shift: i32, sticky: bool) -> (u128, Err) {
    if shift <= 0 {
        assert!(!sticky, "a sticky value rounded above its last place");
        assert!(-shift < 128 && mant.leading_zeros() as i32 >= -shift);
        return (mant << -shift, Err { nonzero: false, vs_half: Ordering::Less });
    }
    if shift > 128 {
        return (0, Err { nonzero: true, vs_half: Ordering::Less });
    }
    let (int, rem) = if shift == 128 { (0, mant) } else { (mant >> shift, mant & ((1u128 << shift) - 1)) };
    let half = 1u128 << (shift - 1);
    let vs_half = match rem.cmp(&half) {
        Ordering::Equal if sticky => Ordering::Greater,
        o => o,
    };
    (int, Err { nonzero: rem != 0 || sticky, vs_half })
}

/// `FPRound(value, N, fpscr_val)`.
pub fn round(v: Real, n: u32, fpscr: u32, exc: &mut u32) -> u64 {
    assert!(v.mant != 0, "FPRound of zero");
    let (e, f) = fmt(n);
    let (e, f) = (e as i32, f as i32);
    let sign = v.sign;
    let minimum_exp = 2 - (1 << (e - 1));
    let msb = 127 - v.mant.leading_zeros() as i32;
    let exponent = v.exp + msb;
    if fpscr & FZ != 0 && n != 16 && exponent < minimum_exp {
        // Flush-to-zero never generates a trapped exception.
        *exc |= UFC;
        return zero(sign, n);
    }
    let mut biased_exp = (exponent - minimum_exp + 1).max(0);
    let scale = if biased_exp == 0 { minimum_exp - f } else { exponent - f };
    let (mut int_mant, err) = split(v.mant, scale - v.exp, v.sticky);
    let mut error = err.nonzero;
    if biased_exp == 0 && error {
        *exc |= UFC;
    }
    let (round_up, overflow_to_inf) = match (fpscr >> 22) & 3 {
        0 => (err.vs_half == Ordering::Greater || (err.vs_half == Ordering::Equal && int_mant & 1 == 1), true),
        1 => (error && !sign, !sign),
        2 => (error && sign, sign),
        _ => (false, false),
    };
    if round_up {
        int_mant += 1;
        if int_mant == 1 << f {
            biased_exp = 1;
        }
        if int_mant == 1 << (f + 1) {
            biased_exp += 1;
            int_mant >>= 1;
        }
    }
    let encode = |be: i32, im: u128| zero(sign, n) | ((be as u64) << f) | (im as u64 & ((1u64 << f) - 1));
    let result;
    if n != 16 || fpscr & AHP == 0 {
        if biased_exp >= (1 << e) - 1 {
            result = if overflow_to_inf { infinity(sign, n) } else { max_normal(sign, n) };
            *exc |= OFC;
            error = true;
        } else {
            result = encode(biased_exp, int_mant);
        }
    } else if biased_exp >= 1 << e {
        result = zero(sign, 16) | 0x7fff;
        *exc |= IOC;
        error = false;
    } else {
        result = encode(biased_exp, int_mant);
    }
    if error {
        *exc |= IXC;
    }
    result
}

/// `FPProcessNaN(type, operand, fpscr_val)`.
pub fn process_nan(ty: FpType, op: u64, n: u32, fpscr: u32, exc: &mut u32) -> u64 {
    let (_, f) = fmt(n);
    let mut r = op;
    if ty == FpType::SNaN {
        r |= 1 << (f - 1);
        *exc |= IOC;
    }
    if fpscr & DN != 0 {
        r = default_nan(n);
    }
    r
}

/// `FPProcessNaNs()`.
fn process_nans(a: &Unpacked, b: &Unpacked, op1: u64, op2: u64, n: u32, fpscr: u32, exc: &mut u32) -> Option<u64> {
    for (t, op) in [(FpType::SNaN, 0), (FpType::SNaN, 1), (FpType::QNaN, 0), (FpType::QNaN, 1)] {
        let (u, v) = if op == 0 { (a, op1) } else { (b, op2) };
        if u.ty == t {
            return Some(process_nan(t, v, n, fpscr, exc));
        }
    }
    None
}

/// `FPProcessNaNs3()`.
fn process_nans3(a: &Unpacked, b: &Unpacked, c: &Unpacked, ops: [u64; 3], n: u32, fpscr: u32, exc: &mut u32) -> Option<u64> {
    let us = [a, b, c];
    for t in [FpType::SNaN, FpType::QNaN] {
        for k in 0..3 {
            if us[k].ty == t {
                return Some(process_nan(t, ops[k], n, fpscr, exc));
            }
        }
    }
    None
}

/// The sign of an exact zero sum: '1' only when rounding towards Minus
/// Infinity.
fn zero_sum_sign(fpscr: u32) -> bool {
    (fpscr >> 22) & 3 == 2
}

/// `FPAdd()` (`sub` false) and `FPSub()`.
fn add_sub(op1: u64, op2: u64, sub: bool, n: u32, fpscr: u32, exc: &mut u32) -> u64 {
    let a = unpack(op1, n, fpscr, exc);
    let b = unpack(op2, n, fpscr, exc);
    if let Some(r) = process_nans(&a, &b, op1, op2, n, fpscr, exc) {
        return r;
    }
    // Subtraction is the addition of the negated second operand, which is
    // what the pseudocode's cases of FPSub() spell out.
    let sb = b.sign != sub;
    let (inf1, inf2) = (a.ty == FpType::Infinity, b.ty == FpType::Infinity);
    let (zero1, zero2) = (a.ty == FpType::Zero, b.ty == FpType::Zero);
    if inf1 && inf2 && a.sign != sb {
        *exc |= IOC;
        return default_nan(n);
    }
    if (inf1 && !a.sign) || (inf2 && !sb) {
        return infinity(false, n);
    }
    if (inf1 && a.sign) || (inf2 && sb) {
        return infinity(true, n);
    }
    if zero1 && zero2 && a.sign == sb {
        return zero(a.sign, n);
    }
    let x = Real::of(&a);
    let y = Real { sign: sb, ..Real::of(&b) };
    match add_exact(x, y) {
        None => zero(zero_sum_sign(fpscr), n),
        Some(r) => round(r, n, fpscr, exc),
    }
}

pub fn add(op1: u64, op2: u64, n: u32, fpscr: u32, exc: &mut u32) -> u64 {
    add_sub(op1, op2, false, n, fpscr, exc)
}

pub fn sub(op1: u64, op2: u64, n: u32, fpscr: u32, exc: &mut u32) -> u64 {
    add_sub(op1, op2, true, n, fpscr, exc)
}

/// `FPMul()`.
pub fn mul(op1: u64, op2: u64, n: u32, fpscr: u32, exc: &mut u32) -> u64 {
    let a = unpack(op1, n, fpscr, exc);
    let b = unpack(op2, n, fpscr, exc);
    if let Some(r) = process_nans(&a, &b, op1, op2, n, fpscr, exc) {
        return r;
    }
    let (inf1, inf2) = (a.ty == FpType::Infinity, b.ty == FpType::Infinity);
    let (zero1, zero2) = (a.ty == FpType::Zero, b.ty == FpType::Zero);
    let sign = a.sign != b.sign;
    if (inf1 && zero2) || (zero1 && inf2) {
        *exc |= IOC;
        return default_nan(n);
    }
    if inf1 || inf2 {
        return infinity(sign, n);
    }
    if zero1 || zero2 {
        return zero(sign, n);
    }
    round(mul_exact(&a, &b), n, fpscr, exc)
}

/// `FPDiv()`.
pub fn div(op1: u64, op2: u64, n: u32, fpscr: u32, exc: &mut u32) -> u64 {
    let a = unpack(op1, n, fpscr, exc);
    let b = unpack(op2, n, fpscr, exc);
    if let Some(r) = process_nans(&a, &b, op1, op2, n, fpscr, exc) {
        return r;
    }
    let (inf1, inf2) = (a.ty == FpType::Infinity, b.ty == FpType::Infinity);
    let (zero1, zero2) = (a.ty == FpType::Zero, b.ty == FpType::Zero);
    let sign = a.sign != b.sign;
    if (inf1 && inf2) || (zero1 && zero2) {
        *exc |= IOC;
        return default_nan(n);
    }
    if inf1 || zero2 {
        if !inf1 {
            *exc |= DZC;
        }
        return infinity(sign, n);
    }
    if zero1 || inf2 {
        return zero(sign, n);
    }
    round(div_exact(&a, &b), n, fpscr, exc)
}

/// `FPMulAdd(addend, op1, op2)`: `addend + op1*op2` with one rounding.
pub fn mul_add(addend: u64, op1: u64, op2: u64, n: u32, fpscr: u32, exc: &mut u32) -> u64 {
    let ad = unpack(addend, n, fpscr, exc);
    let a = unpack(op1, n, fpscr, exc);
    let b = unpack(op2, n, fpscr, exc);
    let (inf1, inf2) = (a.ty == FpType::Infinity, b.ty == FpType::Infinity);
    let (zero1, zero2) = (a.ty == FpType::Zero, b.ty == FpType::Zero);
    let mut result = process_nans3(&ad, &a, &b, [addend, op1, op2], n, fpscr, exc);
    if ad.ty == FpType::QNaN && ((inf1 && zero2) || (zero1 && inf2)) {
        result = Some(default_nan(n));
        *exc |= IOC;
    }
    if let Some(r) = result {
        return r;
    }
    let (inf_a, zero_a) = (ad.ty == FpType::Infinity, ad.ty == FpType::Zero);
    let sign_p = a.sign != b.sign;
    let inf_p = inf1 || inf2;
    let zero_p = zero1 || zero2;
    if (inf1 && zero2) || (zero1 && inf2) || (inf_a && inf_p && ad.sign != sign_p) {
        *exc |= IOC;
        return default_nan(n);
    }
    if (inf_a && !ad.sign) || (inf_p && !sign_p) {
        return infinity(false, n);
    }
    if (inf_a && ad.sign) || (inf_p && sign_p) {
        return infinity(true, n);
    }
    if zero_a && zero_p && ad.sign == sign_p {
        return zero(ad.sign, n);
    }
    let p = if zero_p { Real { sign: sign_p, mant: 0, exp: 0, sticky: false } } else { mul_exact(&a, &b) };
    match add_exact(Real::of(&ad), p) {
        None => zero(zero_sum_sign(fpscr), n),
        Some(r) => round(r, n, fpscr, exc),
    }
}

/// `FPSqrt()`: under the FPSCR (`fpscr` is the FPSCR itself).
pub fn sqrt(op: u64, n: u32, fpscr: u32, exc: &mut u32) -> u64 {
    let a = unpack(op, n, fpscr, exc);
    match a.ty {
        FpType::SNaN | FpType::QNaN => process_nan(a.ty, op, n, fpscr, exc),
        FpType::Zero => zero(a.sign, n),
        FpType::Infinity if !a.sign => infinity(false, n),
        _ if a.sign => {
            *exc |= IOC;
            default_nan(n)
        }
        _ => round(sqrt_exact(&a), n, fpscr, exc),
    }
}

/// The order of two non-NaN unpacked values (zeros equal whatever their
/// signs, infinities beyond every number).
fn cmp_values(a: &Unpacked, b: &Unpacked) -> Ordering {
    // A key: (class, magnitude), class -2 -inf, -1 negative, 0 zero, ...
    fn class(u: &Unpacked) -> i32 {
        match (u.ty, u.sign) {
            (FpType::Zero, _) => 0,
            (FpType::Infinity, true) => -2,
            (FpType::Infinity, false) => 2,
            (_, true) => -1,
            (_, false) => 1,
        }
    }
    let (ca, cb) = (class(a), class(b));
    if ca != cb || ca.abs() != 1 {
        return ca.cmp(&cb);
    }
    // Both finite nonzero of one sign: compare magnitudes.
    let norm = |u: &Unpacked| {
        let s = u.mant.leading_zeros() as i32;
        (u.exp - s, u.mant << s)
    };
    let mag = norm(a).cmp(&norm(b));
    if ca < 0 {
        mag.reverse()
    } else {
        mag
    }
}

/// `FPCompare()`: `(N, Z, C, V)` as FPSCR<31:28>.
pub fn compare(op1: u64, op2: u64, quiet_nan_exc: bool, n: u32, fpscr: u32, exc: &mut u32) -> u32 {
    let a = unpack(op1, n, fpscr, exc);
    let b = unpack(op2, n, fpscr, exc);
    if a.ty.is_nan() || b.ty.is_nan() {
        if a.ty == FpType::SNaN || b.ty == FpType::SNaN || quiet_nan_exc {
            *exc |= IOC;
        }
        return 0b0011;
    }
    match cmp_values(&a, &b) {
        Ordering::Equal => 0b0110,
        Ordering::Less => 0b1000,
        Ordering::Greater => 0b0010,
    }
}

/// `FPCompareEQ()`, `FPCompareGE()`, `FPCompareGT()`.
pub fn compare_eq(op1: u64, op2: u64, n: u32, fpscr: u32, exc: &mut u32) -> bool {
    let a = unpack(op1, n, fpscr, exc);
    let b = unpack(op2, n, fpscr, exc);
    if a.ty.is_nan() || b.ty.is_nan() {
        if a.ty == FpType::SNaN || b.ty == FpType::SNaN {
            *exc |= IOC;
        }
        return false;
    }
    cmp_values(&a, &b) == Ordering::Equal
}

pub fn compare_ge(op1: u64, op2: u64, n: u32, fpscr: u32, exc: &mut u32) -> bool {
    let a = unpack(op1, n, fpscr, exc);
    let b = unpack(op2, n, fpscr, exc);
    if a.ty.is_nan() || b.ty.is_nan() {
        *exc |= IOC;
        return false;
    }
    cmp_values(&a, &b) != Ordering::Less
}

pub fn compare_gt(op1: u64, op2: u64, n: u32, fpscr: u32, exc: &mut u32) -> bool {
    let a = unpack(op1, n, fpscr, exc);
    let b = unpack(op2, n, fpscr, exc);
    if a.ty.is_nan() || b.ty.is_nan() {
        *exc |= IOC;
        return false;
    }
    cmp_values(&a, &b) == Ordering::Greater
}

/// `FPMax()` (`max`) and `FPMin()`.
pub fn max_min(op1: u64, op2: u64, max: bool, n: u32, fpscr: u32, exc: &mut u32) -> u64 {
    let a = unpack(op1, n, fpscr, exc);
    let b = unpack(op2, n, fpscr, exc);
    if let Some(r) = process_nans(&a, &b, op1, op2, n, fpscr, exc) {
        return r;
    }
    let o = cmp_values(&a, &b);
    let pick_a = if max { o == Ordering::Greater } else { o == Ordering::Less };
    let u = if pick_a { a } else { b };
    match u.ty {
        FpType::Infinity => infinity(u.sign, n),
        // Use the most positive (FPMax) or most negative (FPMin) sign.
        FpType::Zero => zero(if max { a.sign && b.sign } else { a.sign || b.sign }, n),
        _ => round(Real::of(&u), n, fpscr, exc),
    }
}

/// `FPHalvedSub()`: `(op1 - op2) / 2`.
pub fn halved_sub(op1: u64, op2: u64, n: u32, fpscr: u32, exc: &mut u32) -> u64 {
    let a = unpack(op1, n, fpscr, exc);
    let b = unpack(op2, n, fpscr, exc);
    if let Some(r) = process_nans(&a, &b, op1, op2, n, fpscr, exc) {
        return r;
    }
    let (inf1, inf2) = (a.ty == FpType::Infinity, b.ty == FpType::Infinity);
    let (zero1, zero2) = (a.ty == FpType::Zero, b.ty == FpType::Zero);
    if inf1 && inf2 && a.sign == b.sign {
        *exc |= IOC;
        return default_nan(n);
    }
    if (inf1 && !a.sign) || (inf2 && b.sign) {
        return infinity(false, n);
    }
    if (inf1 && a.sign) || (inf2 && !b.sign) {
        return infinity(true, n);
    }
    if zero1 && zero2 && a.sign != b.sign {
        return zero(a.sign, n);
    }
    let y = Real { sign: !b.sign, ..Real::of(&b) };
    match add_exact(Real::of(&a), y) {
        None => zero(zero_sum_sign(fpscr), n),
        Some(r) => round(Real { exp: r.exp - 1, ..r }, n, fpscr, exc),
    }
}

/// `recip_estimate()`, the C function of A2.7.8 (IEEE double arithmetic,
/// round to nearest).
fn recip_estimate(a: f64) -> f64 {
    let q = (a * 512.0) as i32;
    let r = 1.0 / ((q as f64 + 0.5) / 512.0);
    let s = (256.0 * r + 0.5) as i32;
    s as f64 / 256.0
}

/// `recip_sqrt_estimate()`, the C function of A2.7.8.
fn recip_sqrt_estimate(a: f64) -> f64 {
    let r = if a < 0.5 {
        let q0 = (a * 512.0) as i32;
        1.0 / ((q0 as f64 + 0.5) / 512.0).sqrt()
    } else {
        let q1 = (a * 256.0) as i32;
        1.0 / ((q1 as f64 + 0.5) / 256.0).sqrt()
    };
    let s = (256.0 * r + 0.5) as i32;
    s as f64 / 256.0
}

/// `FPRecipEstimate()` (single precision, the standard FPSCR value).
pub fn recip_estimate32(op: u32, fpscr: u32, exc: &mut u32) -> u32 {
    let std = standard_fpscr(fpscr);
    let a = unpack(op as u64, 32, std, exc);
    match a.ty {
        FpType::SNaN | FpType::QNaN => process_nan(a.ty, op as u64, 32, std, exc) as u32,
        FpType::Infinity => zero(a.sign, 32) as u32,
        FpType::Zero => {
            *exc |= DZC;
            infinity(a.sign, 32) as u32
        }
        // Abs(value) >= 2^126: the exponent field is 253 or more.
        _ if (op >> 23) & 0xff >= 253 => {
            *exc |= UFC;
            zero(a.sign, 32) as u32
        }
        _ => {
            let scaled = f64::from_bits(0x3fe0_0000_0000_0000 | ((op as u64 & 0x7f_ffff) << 29));
            let result_exp = 253 - ((op >> 23) & 0xff);
            let estimate = recip_estimate(scaled).to_bits();
            (op & 0x8000_0000) | (result_exp & 0xff) << 23 | ((estimate >> 29) as u32 & 0x7f_ffff)
        }
    }
}

/// `UnsignedRecipEstimate()`.
pub fn unsigned_recip_estimate(op: u32) -> u32 {
    if op >> 31 == 0 {
        return u32::MAX;
    }
    let dp = f64::from_bits(0x3fe0_0000_0000_0000 | ((op as u64 & 0x7fff_ffff) << 21));
    let estimate = recip_estimate(dp).to_bits();
    0x8000_0000 | ((estimate >> 21) as u32 & 0x7fff_ffff)
}

/// `FPRSqrtEstimate()`.
pub fn rsqrt_estimate32(op: u32, fpscr: u32, exc: &mut u32) -> u32 {
    let std = standard_fpscr(fpscr);
    let a = unpack(op as u64, 32, std, exc);
    match a.ty {
        FpType::SNaN | FpType::QNaN => process_nan(a.ty, op as u64, 32, std, exc) as u32,
        FpType::Zero => {
            *exc |= DZC;
            infinity(a.sign, 32) as u32
        }
        _ if a.sign => {
            *exc |= IOC;
            default_nan(32) as u32
        }
        FpType::Infinity => zero(false, 32) as u32,
        _ => {
            let frac = (op as u64 & 0x7f_ffff) << 29;
            let scaled = if op >> 23 & 1 == 0 { 0x3fe0_0000_0000_0000 | frac } else { 0x3fd0_0000_0000_0000 | frac };
            let result_exp = (380 - ((op >> 23) & 0xff)) / 2;
            let estimate = recip_sqrt_estimate(f64::from_bits(scaled)).to_bits();
            (result_exp & 0xff) << 23 | ((estimate >> 29) as u32 & 0x7f_ffff)
        }
    }
}

/// `UnsignedRSqrtEstimate()`.
pub fn unsigned_rsqrt_estimate(op: u32) -> u32 {
    if op >> 30 == 0 {
        return u32::MAX;
    }
    let dp = if op >> 31 == 1 {
        0x3fe0_0000_0000_0000 | ((op as u64 & 0x7fff_ffff) << 21)
    } else {
        0x3fd0_0000_0000_0000 | ((op as u64 & 0x3fff_ffff) << 22)
    };
    let estimate = recip_sqrt_estimate(f64::from_bits(dp)).to_bits();
    0x8000_0000 | ((estimate >> 21) as u32 & 0x7fff_ffff)
}

/// `FPRecipStep()` (`rsqrt` false) and `FPRSqrtStep()`.
pub fn step32(op1: u32, op2: u32, rsqrt: bool, fpscr: u32, exc: &mut u32) -> u32 {
    let std = standard_fpscr(fpscr);
    let (o1, o2) = (op1 as u64, op2 as u64);
    let a = unpack(o1, 32, std, exc);
    let b = unpack(o2, 32, std, exc);
    if let Some(r) = process_nans(&a, &b, o1, o2, 32, std, exc) {
        return r as u32;
    }
    let (inf1, inf2) = (a.ty == FpType::Infinity, b.ty == FpType::Infinity);
    let (zero1, zero2) = (a.ty == FpType::Zero, b.ty == FpType::Zero);
    let product = if (inf1 && zero2) || (zero1 && inf2) { zero(false, 32) } else { mul(o1, o2, 32, std, exc) };
    let r = if rsqrt { halved_sub(three(32), product, 32, std, exc) } else { sub(two(32), product, 32, std, exc) };
    r as u32
}

/// `FPHalfToSingle()`.
pub fn half_to_single(op: u16, fpscr: u32, exc: &mut u32) -> u32 {
    let a = unpack(op as u64, 16, fpscr, exc);
    match a.ty {
        FpType::SNaN | FpType::QNaN => {
            let r = if fpscr & DN != 0 { default_nan(32) as u32 } else { (a.sign as u32) << 31 | 0x7fc0_0000 | (op as u32 & 0x1ff) << 13 };
            if a.ty == FpType::SNaN {
                *exc |= IOC;
            }
            r
        }
        FpType::Infinity => infinity(a.sign, 32) as u32,
        FpType::Zero => zero(a.sign, 32) as u32,
        FpType::Nonzero => round(Real::of(&a), 32, fpscr, exc) as u32,
    }
}

/// `FPSingleToHalf()`.
pub fn single_to_half(op: u32, fpscr: u32, exc: &mut u32) -> u16 {
    let a = unpack(op as u64, 32, fpscr, exc);
    let ahp = fpscr & AHP != 0;
    match a.ty {
        FpType::SNaN | FpType::QNaN => {
            let r = if ahp {
                zero(a.sign, 16) as u16
            } else if fpscr & DN != 0 {
                default_nan(16) as u16
            } else {
                (a.sign as u16) << 15 | 0x7e00 | ((op >> 13) & 0x1ff) as u16
            };
            if a.ty == FpType::SNaN || ahp {
                *exc |= IOC;
            }
            r
        }
        FpType::Infinity => {
            if ahp {
                *exc |= IOC;
                (a.sign as u16) << 15 | 0x7fff
            } else {
                infinity(a.sign, 16) as u16
            }
        }
        FpType::Zero => zero(a.sign, 16) as u16,
        FpType::Nonzero => round(Real::of(&a), 16, fpscr, exc) as u16,
    }
}

/// `FPSingleToDouble()`.
pub fn single_to_double(op: u32, fpscr: u32, exc: &mut u32) -> u64 {
    let a = unpack(op as u64, 32, fpscr, exc);
    match a.ty {
        FpType::SNaN | FpType::QNaN => {
            let r = if fpscr & DN != 0 { default_nan(64) } else { (a.sign as u64) << 63 | 0x7ff8_0000_0000_0000 | (op as u64 & 0x3f_ffff) << 29 };
            if a.ty == FpType::SNaN {
                *exc |= IOC;
            }
            r
        }
        FpType::Infinity => infinity(a.sign, 64),
        FpType::Zero => zero(a.sign, 64),
        FpType::Nonzero => round(Real::of(&a), 64, fpscr, exc),
    }
}

/// `FPDoubleToSingle()`.
pub fn double_to_single(op: u64, fpscr: u32, exc: &mut u32) -> u32 {
    let a = unpack(op, 64, fpscr, exc);
    match a.ty {
        FpType::SNaN | FpType::QNaN => {
            let r = if fpscr & DN != 0 { default_nan(32) as u32 } else { (a.sign as u32) << 31 | 0x7fc0_0000 | ((op >> 29) as u32 & 0x3f_ffff) };
            if a.ty == FpType::SNaN {
                *exc |= IOC;
            }
            r
        }
        FpType::Infinity => infinity(a.sign, 32) as u32,
        FpType::Zero => zero(a.sign, 32) as u32,
        FpType::Nonzero => round(Real::of(&a), 32, fpscr, exc) as u32,
    }
}

/// `FPToFixed(operand, M, fraction_bits, unsigned, round_towards_zero,
/// fpscr_val)`: the low `m` bits of the result.
pub fn to_fixed(op: u64, n: u32, m: u32, fbits: u32, unsigned: bool, round_zero: bool, fpscr: u32, exc: &mut u32) -> u64 {
    let fpscr = if round_zero { fpscr | RMODE } else { fpscr };
    let a = unpack(op, n, fpscr, exc);
    if a.ty.is_nan() {
        *exc |= IOC;
    }
    // value * 2^fraction_bits as an integer part and a fraction; NaNs are
    // 0.0 and infinities too large for any destination.
    let (ip, frac): (Option<u128>, Err) = match a.ty {
        FpType::Zero | FpType::QNaN | FpType::SNaN => (Some(0), Err { nonzero: false, vs_half: Ordering::Less }),
        FpType::Infinity => (None, Err { nonzero: false, vs_half: Ordering::Less }),
        FpType::Nonzero => {
            let e2 = a.exp + fbits as i32;
            if e2 > 70 {
                (None, Err { nonzero: false, vs_half: Ordering::Less })
            } else {
                let (i, f) = split(a.mant as u128, -e2, false);
                (Some(i), f)
            }
        }
    };
    let neg = a.sign && a.ty != FpType::Zero && !a.ty.is_nan();
    // int_result = RoundDown(value); error = value - int_result.
    let (int, error) = match ip {
        None => (if neg { i128::MIN } else { i128::MAX }, Err { nonzero: false, vs_half: Ordering::Less }),
        Some(ip) if !neg => (ip as i128, frac),
        Some(ip) if !frac.nonzero => (-(ip as i128), frac),
        Some(ip) => (-(ip as i128) - 1, Err { nonzero: true, vs_half: frac.vs_half.reverse() }),
    };
    let round_up = match (fpscr >> 22) & 3 {
        0 => error.vs_half == Ordering::Greater || (error.vs_half == Ordering::Equal && int & 1 == 1),
        1 => error.nonzero,
        2 => false,
        _ => error.nonzero && int < 0,
    };
    let int = if round_up && int != i128::MAX { int + 1 } else { int };
    let (lo, hi) = if unsigned { (0i128, (1i128 << m) - 1) } else { (-(1i128 << (m - 1)), (1i128 << (m - 1)) - 1) };
    let (r, overflow) = if int > hi {
        (hi, true)
    } else if int < lo {
        (lo, true)
    } else {
        (int, false)
    };
    if overflow {
        *exc |= IOC;
    } else if error.nonzero {
        *exc |= IXC;
    }
    r as u64 & mask(m)
}

/// `FixedToFP(operand, N, fraction_bits, unsigned, round_to_nearest,
/// fpscr_val)`, `operand` the low `m` bits of `op`.
pub fn from_fixed(op: u64, m: u32, n: u32, fbits: u32, unsigned: bool, round_nearest: bool, fpscr: u32, exc: &mut u32) -> u64 {
    let fpscr = if round_nearest { fpscr & !RMODE } else { fpscr };
    let v = op & mask(m);
    let (sign, mag) = if unsigned || v >> (m - 1) & 1 == 0 { (false, v) } else { (true, v.wrapping_neg() & mask(m)) };
    // The magnitude of -2^(M-1) is 2^(M-1), which the masked negation
    // gives for M < 64 and 0 for M = 64.
    let mag = if sign && mag == 0 { 1u128 << (m - 1) } else { mag as u128 };
    if mag == 0 {
        return zero(false, n);
    }
    round(Real { sign, mant: mag, exp: -(fbits as i32), sticky: false }, n, fpscr, exc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn next(s: &mut u64) -> u64 {
        // xorshift64*
        *s ^= *s >> 12;
        *s ^= *s << 25;
        *s ^= *s >> 27;
        s.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A random operand of width `n`: any bits, a value near one, a
    /// denormal, a value near the overflow threshold, or a special.
    fn operand(s: &mut u64, n: u32) -> u64 {
        let (e, f) = fmt(n);
        let r = next(s);
        let sign = (r >> 63) << (n - 1);
        let frac = next(s) & ((1 << f) - 1);
        let bias = (1u64 << (e - 1)) - 1;
        let max_e = (1u64 << e) - 1;
        let exp = match r % 8 {
            0 => return next(s) & mask(n),
            1 | 2 => bias - 4 + (r >> 8) % 9,
            3 => 0,
            4 => max_e - 1 - (r >> 8) % 3,
            5 => 1 + (r >> 8) % 3,
            6 => return sign | [0, infinity(false, n), default_nan(n), max_normal(false, n), 1 << (f - 1) | (max_e << f) | 1, (max_e << f) | 1][((r >> 8) % 6) as usize],
            _ => (r >> 8) % (max_e + 1),
        };
        sign | exp << f | frac
    }

    fn is_nan(v: u64, n: u32) -> bool {
        let (e, f) = fmt(n);
        (v >> f) & ((1 << e) - 1) == (1 << e) - 1 && v & ((1 << f) - 1) != 0
    }

    fn quiet(v: u64, n: u32) -> u64 {
        v | 1 << (fmt(n).1 - 1)
    }

    /// The NaN result A2.7.6 gives for operands `ops` (FPSCR.DN clear).
    fn nan_result(ops: &[u64], n: u32) -> Option<u64> {
        let f = fmt(n).1;
        let snan = |v: u64| is_nan(v, n) && v >> (f - 1) & 1 == 0;
        ops.iter().find(|&&v| snan(v)).or_else(|| ops.iter().find(|&&v| is_nan(v, n))).map(|&v| quiet(v, n))
    }

    fn host2(op: usize, a: u64, b: u64, n: u32) -> u64 {
        if n == 64 {
            let (x, y) = (f64::from_bits(a), f64::from_bits(b));
            [x + y, x - y, x * y, x / y][op].to_bits()
        } else {
            let (x, y) = (f32::from_bits(a as u32), f32::from_bits(b as u32));
            [x + y, x - y, x * y, x / y][op].to_bits() as u64
        }
    }

    /// Round to Nearest without Flush-to-zero or Default NaN is IEEE 754's
    /// arithmetic, which the host's is: every non-NaN result agrees, and a
    /// NaN result is the one A2.7.6 propagates.
    #[test]
    fn ieee_round_to_nearest_matches_the_host() {
        let mut s = 0x1234_5678_9abc_def1u64;
        for n in [32u32, 64] {
            for _ in 0..200_000 {
                let (a, b, c) = (operand(&mut s, n), operand(&mut s, n), operand(&mut s, n));
                let mut x = 0;
                let got = [add(a, b, n, 0, &mut x), sub(a, b, n, 0, &mut x), mul(a, b, n, 0, &mut x), div(a, b, n, 0, &mut x)];
                for (op, &g) in got.iter().enumerate() {
                    let h = host2(op, a, b, n);
                    if is_nan(h, n) {
                        let want = nan_result(&[a, b], n).unwrap_or(default_nan(n));
                        assert_eq!(g, want, "op {op} n {n} {a:#x} {b:#x}");
                    } else {
                        assert_eq!(g, h, "op {op} n {n} {a:#x} {b:#x}");
                    }
                }
                let g = sqrt(a, n, 0, &mut x);
                let h = if n == 64 { f64::from_bits(a).sqrt().to_bits() } else { f32::from_bits(a as u32).sqrt().to_bits() as u64 };
                if is_nan(h, n) {
                    assert_eq!(g, nan_result(&[a], n).unwrap_or(default_nan(n)), "sqrt {a:#x}");
                } else {
                    assert_eq!(g, h, "sqrt {a:#x}");
                }
                // FPMulAdd(c, a, b) = c + a*b.
                let g = mul_add(c, a, b, n, 0, &mut x);
                let h = if n == 64 {
                    f64::from_bits(a).mul_add(f64::from_bits(b), f64::from_bits(c)).to_bits()
                } else {
                    f32::from_bits(a as u32).mul_add(f32::from_bits(b as u32), f32::from_bits(c as u32)).to_bits() as u64
                };
                if is_nan(h, n) {
                    let inf_zero = |p: u64, q: u64| {
                        let (pu, qu) = (unpack(p, n, 0, &mut 0), unpack(q, n, 0, &mut 0));
                        (pu.ty == FpType::Infinity && qu.ty == FpType::Zero) || (pu.ty == FpType::Zero && qu.ty == FpType::Infinity)
                    };
                    let qnan_c = is_nan(c, n) && c >> (fmt(n).1 - 1) & 1 == 1;
                    let want = if qnan_c && inf_zero(a, b) { default_nan(n) } else { nan_result(&[c, a, b], n).unwrap_or(default_nan(n)) };
                    assert_eq!(g, want, "fma {c:#x} {a:#x} {b:#x}");
                } else {
                    assert_eq!(g, h, "fma {c:#x} {a:#x} {b:#x}");
                }
            }
        }
    }

    /// The directed roundings, against the exact error the host computes:
    /// TwoSum for a sum, the fused residual for a product, a quotient and a
    /// square root, in ranges where those are exact.
    #[test]
    fn directed_rounding_against_exact_residuals() {
        let mut s = 0x0fed_cba9_8765_4321u64;
        let next_toward = |v: f64, up: bool| {
            let b = v.to_bits();
            let r = if v == 0.0 {
                if up { 1 } else { 1 | 1 << 63 }
            } else if (v > 0.0) == up {
                b + 1
            } else {
                b - 1
            };
            f64::from_bits(r)
        };
        for _ in 0..200_000 {
            let mk = |s: &mut u64| {
                let e = 1023 - 300 + next(s) % 600;
                f64::from_bits((next(s) >> 63) << 63 | e << 52 | (next(s) & ((1 << 52) - 1)))
            };
            let (a, b) = (mk(&mut s), mk(&mut s));
            let cases: [(usize, f64, f64); 4] = [
                (0, a + b, {
                    // TwoSum.
                    let sum = a + b;
                    let bb = sum - a;
                    (a - (sum - bb)) + (b - bb)
                }),
                (2, a * b, a.mul_add(b, -(a * b))),
                (3, a / b, {
                    let q = a / b;
                    // a - q*b, with the sign of the error of q times b's.
                    (-q).mul_add(b, a) * b.signum()
                }),
                (4, a.abs().sqrt(), {
                    let r = a.abs().sqrt();
                    (-r).mul_add(r, a.abs())
                }),
            ];
            for (op, rn, err) in cases {
                for (mode, name) in [(1u32, "RP"), (2, "RM"), (3, "RZ")] {
                    let want = if err == 0.0 {
                        rn
                    } else {
                        let exact_above = err > 0.0;
                        match mode {
                            1 => if exact_above { next_toward(rn, true) } else { rn },
                            2 => if exact_above { rn } else { next_toward(rn, false) },
                            _ => if exact_above == (rn > 0.0) { rn } else { next_toward(rn, rn < 0.0) },
                        }
                    };
                    let fpscr = mode << 22;
                    let mut x = 0;
                    let (ab, bb) = (a.to_bits(), b.to_bits());
                    let got = match op {
                        0 => add(ab, bb, 64, fpscr, &mut x),
                        2 => mul(ab, bb, 64, fpscr, &mut x),
                        3 => div(ab, bb, 64, fpscr, &mut x),
                        _ => sqrt(a.abs().to_bits(), 64, fpscr, &mut x),
                    };
                    assert_eq!(got, want.to_bits(), "{name} op {op} {a:e} {b:e}");
                    assert_eq!(x & IXC != 0, err != 0.0, "{name} op {op} inexact {a:e} {b:e}");
                }
            }
        }
    }

    #[test]
    fn flush_to_zero_and_the_flags() {
        let denorm = 0x0000_0000_0000_0001u64;
        let min_norm = 0x0010_0000_0000_0000u64;
        let one = 1.0f64.to_bits();
        // FZ: a denormal input is a zero (IDC); a tiny result is a zero (UFC)
        // without Inexact.
        let mut x = 0;
        assert_eq!(add(denorm, 0, 64, FZ, &mut x), 0);
        assert_eq!(x, IDC);
        x = 0;
        assert_eq!(mul(min_norm, 0.5f64.to_bits(), 64, FZ, &mut x), 0);
        assert_eq!(x, UFC);
        // Without FZ: a denormal result that is inexact underflows.
        x = 0;
        assert_eq!(mul(min_norm, 0.5f64.to_bits(), 64, 0, &mut x), 0x0008_0000_0000_0000);
        assert_eq!(x, 0, "exact denormal: no Underflow");
        x = 0;
        let third = (1.0f64 / 3.0).to_bits();
        mul(min_norm, third, 64, 0, &mut x);
        assert_eq!(x, UFC | IXC);
        // Overflow: the infinity or the largest normal by the rounding mode.
        x = 0;
        let max = max_normal(false, 64);
        assert_eq!(add(max, max, 64, 0, &mut x), infinity(false, 64));
        assert_eq!(x, OFC | IXC);
        assert_eq!(add(max, max, 64, 3 << 22, &mut x), max);
        assert_eq!(add(neg(max, 64), neg(max, 64), 64, 1 << 22, &mut x), neg(max, 64));
        // Division by zero, invalid operations.
        x = 0;
        assert_eq!(div(one, 0, 64, 0, &mut x), infinity(false, 64));
        assert_eq!(x, DZC);
        x = 0;
        assert_eq!(div(0, 0, 64, 0, &mut x), default_nan(64));
        assert_eq!(x, IOC);
        // The sign of an exact zero sum.
        assert_eq!(sub(one, one, 64, 0, &mut x), 0);
        assert_eq!(sub(one, one, 64, 2 << 22, &mut x), 1 << 63);
        // NaNs: the first signaling NaN, quieted, before any quiet one; DN
        // gives the default NaN.
        let qnan = 0x7ff8_0000_0000_0042u64;
        let snan = 0xfff0_0000_0000_0007u64;
        x = 0;
        assert_eq!(add(qnan, snan, 64, 0, &mut x), 0xfff8_0000_0000_0007);
        assert_eq!(x, IOC);
        x = 0;
        assert_eq!(add(qnan, one, 64, DN, &mut x), default_nan(64));
        assert_eq!(x, 0);
        // FPMulAdd: a quiet NaN addend with infinity times zero.
        x = 0;
        assert_eq!(mul_add(qnan, infinity(false, 64), 0, 64, 0, &mut x), default_nan(64));
        assert_eq!(x, IOC);
        // Comparisons.
        x = 0;
        assert_eq!(compare(qnan, one, false, 64, 0, &mut x), 0b0011);
        assert_eq!(x, 0);
        assert_eq!(compare(qnan, one, true, 64, 0, &mut x), 0b0011);
        assert_eq!(x, IOC);
        assert_eq!(compare(0, 1 << 63, false, 64, 0, &mut x), 0b0110, "+0 == -0");
        assert_eq!(compare(neg(one, 64), one, false, 64, 0, &mut x), 0b1000);
        assert_eq!(compare(infinity(false, 64), max, false, 64, 0, &mut x), 0b0010);
        // FPMax/FPMin of zeros.
        assert_eq!(max_min(0, 1 << 63, true, 64, 0, &mut x), 0);
        assert_eq!(max_min(0, 1 << 63, false, 64, 0, &mut x), 1 << 63);
    }

    #[test]
    fn conversions_to_and_from_integers() {
        let f = |v: f32| v.to_bits() as u64;
        let cases: [(f32, u32, bool, bool, u64, u32); 12] = [
            // value, rounding mode, unsigned, round_zero, result, flags
            (2.5, 0, false, false, 2, IXC),
            (-2.5, 0, false, false, (-2i32) as u32 as u64, IXC),
            (3.5, 0, false, false, 4, IXC),
            (1.5, 2, false, false, 1, IXC),
            (-1.5, 2, false, false, (-2i32) as u32 as u64, IXC),
            (-1.5, 1, false, false, (-1i32) as u32 as u64, IXC),
            (-0.5, 0, false, true, 0, IXC),
            (-1.0, 0, true, true, 0, IOC),
            (2147483648.0, 0, false, true, 0x7fff_ffff, IOC),
            (-2147483648.0, 0, false, true, 0x8000_0000, 0),
            (4294967040.0, 0, true, true, 0xffff_ff00, 0),
            (f32::INFINITY, 0, true, true, 0xffff_ffff, IOC),
        ];
        for (v, mode, u, rz, want, flags) in cases {
            let mut x = 0;
            assert_eq!(to_fixed(f(v), 32, 32, 0, u, rz, mode << 22, &mut x), want, "{v} mode {mode}");
            assert_eq!(x, flags, "{v} mode {mode} flags");
        }
        let mut x = 0;
        assert_eq!(to_fixed(default_nan(32), 32, 32, 0, false, true, 0, &mut x), 0);
        assert_eq!(x, IOC);
        // Fixed point: 1.75 with two fraction bits is 7; 16-bit saturation.
        x = 0;
        assert_eq!(to_fixed(f(1.75), 32, 16, 2, false, true, 0, &mut x), 7);
        assert_eq!(to_fixed(f(1e9), 32, 16, 0, false, true, 0, &mut x), 0x7fff);
        // From integers: u32 max rounds to 2^32 (inexact); fixed point.
        x = 0;
        assert_eq!(from_fixed(0xffff_ffff, 32, 32, 0, true, false, 0, &mut x), f(4294967296.0));
        assert_eq!(x, IXC);
        assert_eq!(from_fixed(0xffff_ffff, 32, 32, 0, true, false, 3 << 22, &mut x), f(4294967040.0));
        assert_eq!(from_fixed(0x8000_0000, 32, 64, 0, false, false, 0, &mut x), (-2147483648.0f64).to_bits());
        assert_eq!(from_fixed(0xfffe, 16, 32, 1, false, true, 3 << 22, &mut x), f(-1.0));
        assert_eq!(from_fixed(0, 32, 32, 0, false, false, 0, &mut x), 0);
    }

    #[test]
    fn half_precision() {
        let mut x = 0;
        // 65520 rounds to infinity in IEEE half precision, and is a number
        // in the alternative format.
        assert_eq!(single_to_half(65520.0f32.to_bits(), 0, &mut x), 0x7c00);
        assert_eq!(x, OFC | IXC);
        x = 0;
        assert_eq!(single_to_half(65520.0f32.to_bits(), AHP, &mut x), 0x7c00, "65536, a tie rounded to even");
        assert_eq!(x, IXC);
        x = 0;
        assert_eq!(single_to_half(1e6f32.to_bits(), AHP, &mut x), 0x7fff);
        assert_eq!(x, IOC);
        x = 0;
        assert_eq!(single_to_half(f32::NAN.to_bits(), AHP, &mut x), 0);
        assert_eq!(x, IOC);
        assert_eq!(half_to_single(0x7c00, AHP, &mut x), 65536.0f32.to_bits());
        assert_eq!(half_to_single(0x7c00, 0, &mut x), f32::INFINITY.to_bits());
        // A denormal half is a normal single, even with Flush-to-zero.
        assert_eq!(half_to_single(0x0001, FZ, &mut x), (2.0f32).powi(-24).to_bits());
        // Single to half denormal results: Flush-to-zero does not apply.
        x = 0;
        assert_eq!(single_to_half((2.0f32).powi(-24).to_bits(), FZ, &mut x), 1);
        assert_eq!(x, 0);
        // NaN payloads.
        x = 0;
        assert_eq!(half_to_single(0x7d01, 0, &mut x), 0x7fe0_2000);
        assert_eq!(x, IOC);
        assert_eq!(single_to_double(0x7fc0_0001, 0, &mut x), 0x7ff8_0000_2000_0000);
        assert_eq!(double_to_single(0xfff8_0000_2000_0000, 0, &mut x), 0xffc0_0001);
    }

    #[test]
    fn estimates_and_steps() {
        let mut x = 0;
        let std = standard_fpscr(0);
        // VRECPE(1.0) and VRSQRTE(1.0) are 511/512.
        assert_eq!(recip_estimate32(0x3f80_0000, std, &mut x), 0x3f7f_8000);
        assert_eq!(rsqrt_estimate32(0x3f80_0000, std, &mut x), 0x3f7f_8000);
        assert_eq!(x, 0);
        assert_eq!(unsigned_recip_estimate(0x8000_0000), 0xff80_0000);
        assert_eq!(unsigned_recip_estimate(0x7fff_ffff), 0xffff_ffff);
        assert_eq!(unsigned_rsqrt_estimate(0x3fff_ffff), 0xffff_ffff);
        // Every table entry: the estimate is a multiple of 1/256 in [1, 2)
        // and within the table's error of 1/x and 1/sqrt(x).
        for q in 256..512u32 {
            let a = (q as f64 + 0.25) / 512.0;
            let r = recip_estimate(a);
            assert!((1.0..2.0).contains(&r) && (r * 256.0).fract() == 0.0);
            assert!((r - 1.0 / a).abs() <= 1.0 / 256.0 + 1.0 / 128.0, "{a} {r}");
        }
        for q in 128..512u32 {
            let a = (q as f64 + 0.25) / 512.0;
            let r = recip_sqrt_estimate(a);
            assert!((1.0..2.0).contains(&r) && (r * 256.0).fract() == 0.0);
            assert!((r - 1.0 / a.sqrt()).abs() <= 1.0 / 64.0, "{a} {r}");
        }
        // Out of range inputs (Tables A2-10, A2-12).
        x = 0;
        assert_eq!(recip_estimate32(0x0000_0001, std, &mut x), 0x7f80_0000);
        assert_eq!(x, IDC | DZC);
        x = 0;
        assert_eq!(recip_estimate32(0x7e80_0000, std, &mut x), 0);
        assert_eq!(x, UFC);
        assert_eq!(recip_estimate32(0xff80_0000, std, &mut x), 0x8000_0000);
        x = 0;
        assert_eq!(rsqrt_estimate32(0xbf80_0000, std, &mut x), default_nan(32) as u32);
        assert_eq!(x, IOC);
        assert_eq!(rsqrt_estimate32(0x8000_0000, std, &mut x), 0xff80_0000);
        assert_eq!(rsqrt_estimate32(0x7f80_0000, std, &mut x), 0);
        // Steps: 2 - a*b and (3 - a*b)/2, inf*0 giving 2.0 and 1.5.
        assert_eq!(step32(0x7f80_0000, 0, false, std, &mut x), 2.0f32.to_bits());
        assert_eq!(step32(0x0000_0001, 0xff80_0000, true, std, &mut x), 1.5f32.to_bits());
        assert_eq!(step32(3.0f32.to_bits(), 0.5f32.to_bits(), false, std, &mut x), 0.5f32.to_bits());
        assert_eq!(step32(1.0f32.to_bits(), 1.0f32.to_bits(), true, std, &mut x), 1.0f32.to_bits());
    }
}
