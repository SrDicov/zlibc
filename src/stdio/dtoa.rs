//! Floating-point conversion (musl `vfprintf.c:fmt_fp`, reimplemented).
//!
//! Pure converters over already-extracted values: the caller supplies
//! the raw bits (`f64`) or the 10 little-endian bytes (`f80` long
//! double) plus a [`FmtSpec`]; these functions never touch varargs or
//! streams (the printf arm wires them at integration).
//!
//! Method: the exact binary value `M * 2^E` (`M: u64`, integer `E`) is
//! expanded to exact base-1e9 digits, then rounded half-to-even at the
//! requested cutoff — the same observable rule as musl's limb code, but
//! with integer compares instead of musl's `round+small` float probe.
//! `%a` works straight off the mantissa bits (binary→hex terminates).
//! Zero `f80` arithmetic: only `u64`/`i64` math with wrapping ops.
//!
//! Deviations from musl, one line each:
//! - Rounding uses exact integer half-even; musl's float probe agrees
//!   everywhere except pathological near-tie limbs we round correctly.
//! - Outputs wider than `INT_MAX` are truncated to `buf` (musl returns
//!   -1); the return is bytes actually stored.
//! - `f80` pseudo-specials (max exponent, nonzero mantissa without the
//!   integer bit) classify as NaN; a zero mantissa classifies as inf.
//! - Limb scratch is a fixed 2400-word stack buffer (~21100 digits,
//!   covers worst-case `f80` denormal expansion); larger needs truncate.
//! - Unknown spec bytes store nothing and return 0 (orchestrator only
//!   passes `f F e E g G a A`).

/// Conversion flags, same bit positions as the parent `Spec`
/// (`bit0 -`, `bit1 +`, `bit2 space`, `bit3 0`, `bit4 #`).
pub(crate) const F_MINUS: u32 = 1;
/// See [`F_MINUS`].
pub(crate) const F_PLUS: u32 = 2;
/// See [`F_MINUS`].
pub(crate) const F_SPACE: u32 = 4;
/// See [`F_MINUS`].
pub(crate) const F_ZERO: u32 = 8;
/// See [`F_MINUS`].
pub(crate) const F_ALT: u32 = 16;

/// Parsed conversion, mirroring the parent `sp` fields (`spec`, `w` =
/// width, `prec` = precision with -1 unset, `flags` = parent flag bits).
pub(crate) struct FmtSpec {
    /// Conversion letter (`f F e E g G a A`).
    pub spec: u8,
    /// Field width.
    pub w: usize,
    /// Precision, negative when unset (default 6).
    pub prec: isize,
    /// [`F_MINUS`] et al.
    pub flags: u32,
}

/// Format an `f64` (given as bits) into `buf`; returns bytes stored.
///
/// Handles `f F e E g G a A` (either case), default-6 and zero
/// precision, `- + space 0 #` flags, width padding, `inf`/`nan` in the
/// spec's case, and signed zero. Truncates (returns `buf.len()`) when
/// the output does not fit.
pub(crate) fn fmt_f64_bits(buf: &mut [u8], bits: u64, fm: &FmtSpec) -> usize {
    let sign = bits >> 63 != 0;
    let exp = ((bits >> 52) & 0x7ff) as u16;
    let mant = bits & 0xf_ffff_ffff_ffff;
    if exp == 0x7ff {
        return word(buf, fm, sign, mant != 0);
    }
    if exp == 0 {
        if mant == 0 {
            return zero(buf, fm, sign);
        }
        return finite(buf, fm, sign, mant, -1074);
    }
    finite(buf, fm, sign, mant | (1 << 52), exp as i32 - 1075)
}

/// Format an 80-bit extended `long double` (10 LE bytes: `u64` explicit
/// mantissa, then sign + 15-bit exponent) into `buf`; same contract as
/// [`fmt_f64_bits`].
pub(crate) fn fmt_f80_bits(buf: &mut [u8], ext10: &[u8; 10], fm: &FmtSpec) -> usize {
    let mant = u64::from_le_bytes([
        ext10[0], ext10[1], ext10[2], ext10[3], ext10[4], ext10[5], ext10[6], ext10[7],
    ]);
    let se = u16::from_le_bytes([ext10[8], ext10[9]]);
    let sign = se >> 15 != 0;
    let exp = se & 0x7fff;
    if exp == 0x7fff {
        // Integer bit set + zero mantissa, or clear + zero, is infinity;
        // any other nonzero pattern here is NaN (pseudo-specials).
        let nan = mant != 0 && mant != 0x8000_0000_0000_0000;
        return word(buf, fm, sign, nan);
    }
    if mant == 0 {
        // True zero and pseudo-denormal-zero both render as zero.
        return zero(buf, fm, sign);
    }
    let unbiased = if exp == 0 { -16382 } else { exp as i32 - 16383 };
    finite(buf, fm, sign, mant, unbiased - 63)
}

// ---- shared machinery ------------------------------------------------------

/// Base-1e9 scratch words; 2400 words hold ~21100 decimal digits, past
/// the worst exact case (`f80` min denormal: 16445 fractional digits).
// ponytail: fixed stack scratch; heap iff a version needs bigger exact output.
const NLIMB: usize = 2400;
const BASE: u64 = 1_000_000_000;
const POW10: [u32; 9] = [
    1,
    10,
    100,
    1000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
];

/// Truncating writer: counts nothing beyond stores; every loop using it
/// must stop at [`W::full`] so hostile precision/width stays O(buf).
struct W<'a> {
    b: &'a mut [u8],
    pos: usize,
}

impl<'a> W<'a> {
    fn new(b: &'a mut [u8]) -> W<'a> {
        W { b, pos: 0 }
    }
    fn full(&self) -> bool {
        self.pos >= self.b.len()
    }
    fn put(&mut self, c: u8) {
        if !self.full() {
            self.b[self.pos] = c;
            self.pos += 1;
        }
    }
    fn slice(&mut self, s: &[u8]) {
        let room = self.b.len().saturating_sub(self.pos);
        let k = room.min(s.len());
        self.b[self.pos..self.pos + k].copy_from_slice(&s[..k]);
        self.pos += k;
    }
    fn repeat(&mut self, c: u8, k: usize) {
        let room = self.b.len().saturating_sub(self.pos);
        let k = room.min(k);
        self.b[self.pos..self.pos + k].fill(c);
        self.pos += k;
    }
}

fn signlen(fm: &FmtSpec, sign: bool) -> usize {
    if sign || fm.flags & (F_PLUS | F_SPACE) != 0 {
        1
    } else {
        0
    }
}

fn signch(w: &mut W, fm: &FmtSpec, sign: bool) {
    if sign {
        w.put(b'-');
    } else if fm.flags & F_PLUS != 0 {
        w.put(b'+');
    } else if fm.flags & F_SPACE != 0 {
        w.put(b' ');
    }
}

/// Right spaces for `-`.
fn endpad(w: &mut W, fm: &FmtSpec, tot: usize) {
    if fm.flags & F_MINUS != 0 {
        w.repeat(b' ', fm.w.saturating_sub(tot));
    }
}

/// `inf`/`nan` (musl `fmt_fp:207-215`): sign + 3-letter word, space
/// padding only (`0` ignored), width is a minimum.
fn word(buf: &mut [u8], fm: &FmtSpec, sign: bool, nan: bool) -> usize {
    let lower = fm.spec & 32 != 0;
    let s: &[u8; 3] = if nan {
        if lower {
            b"nan"
        } else {
            b"NAN"
        }
    } else if lower {
        b"inf"
    } else {
        b"INF"
    };
    let pl = signlen(fm, sign);
    let mut w = W::new(buf);
    if fm.flags & F_MINUS == 0 {
        w.repeat(b' ', fm.w.saturating_sub(3 + pl));
    }
    signch(&mut w, fm, sign);
    w.slice(s);
    endpad(&mut w, fm, 3 + pl);
    w.pos
}

/// Exact signed zero in all four styles (`%g` of zero is always fixed).
fn zero(buf: &mut [u8], fm: &FmtSpec, sign: bool) -> usize {
    let lower = fm.spec & 32 != 0;
    let alt = fm.flags & F_ALT != 0;
    let p = if fm.prec < 0 { 6 } else { fm.prec as usize };
    let pl = signlen(fm, sign);
    let mut w = W::new(buf);
    match fm.spec | 32 {
        b'a' => {
            return hexfmt(
                buf,
                fm,
                sign,
                0,
                0,
                if fm.prec < 0 { -1 } else { fm.prec as i64 },
                true,
            );
        }
        b'e' => {
            let point = p > 0 || alt;
            let body = 1 + if point { 1 } else { 0 } + p + 4; // e+00
            if fm.flags & (F_MINUS | F_ZERO) == 0 {
                w.repeat(b' ', fm.w.saturating_sub(pl + body));
            }
            signch(&mut w, fm, sign);
            if fm.flags & F_ZERO != 0 && fm.flags & F_MINUS == 0 {
                w.repeat(b'0', fm.w.saturating_sub(pl + body));
            }
            w.put(b'0');
            if point {
                w.put(b'.');
            }
            w.repeat(b'0', p);
            w.put(if lower { b'e' } else { b'E' });
            w.slice(b"+00");
            endpad(&mut w, fm, pl + body);
        }
        b'f' => {
            let point = p > 0 || alt;
            let body = 1 + if point { 1 } else { 0 } + p;
            if fm.flags & (F_MINUS | F_ZERO) == 0 {
                w.repeat(b' ', fm.w.saturating_sub(pl + body));
            }
            signch(&mut w, fm, sign);
            if fm.flags & F_ZERO != 0 && fm.flags & F_MINUS == 0 {
                w.repeat(b'0', fm.w.saturating_sub(pl + body));
            }
            w.put(b'0');
            if point {
                w.put(b'.');
            }
            w.repeat(b'0', p);
            endpad(&mut w, fm, pl + body);
        }
        _ => {
            // %g: precision means significant digits (0 -> 1); fixed
            // style always wins for zero; zeros strip unless #.
            let mut frac = p.max(1) - 1;
            if !alt {
                frac = 0;
            }
            let body = 1 + if frac > 0 || alt { 1 } else { 0 } + frac;
            if fm.flags & (F_MINUS | F_ZERO) == 0 {
                w.repeat(b' ', fm.w.saturating_sub(pl + body));
            }
            signch(&mut w, fm, sign);
            if fm.flags & F_ZERO != 0 && fm.flags & F_MINUS == 0 {
                w.repeat(b'0', fm.w.saturating_sub(pl + body));
            }
            w.put(b'0');
            if frac > 0 || alt {
                w.put(b'.');
            }
            w.repeat(b'0', frac);
            endpad(&mut w, fm, pl + body);
        }
    }
    w.pos
}

/// Exact digits of `M * 2^E`: value `S * 10^k`, `n` digits, `e` the
/// decimal exponent (value in `[1,10) * 10^e`).
struct Dec {
    g: [u32; NLIMB],
    ng: usize,
    k: i32,
    n: usize,
    e: i32,
}

fn scale(m: u64, e: i32) -> Dec {
    let mut d = Dec {
        g: [0; NLIMB],
        ng: 0,
        k: 0,
        n: 1,
        e: 0,
    };
    let mut nl = 0;
    let mut mm = m;
    while mm > 0 && nl < NLIMB {
        d.g[nl] = (mm % BASE) as u32;
        mm /= BASE;
        nl += 1;
    }
    if e >= 0 {
        let mut s = e as u32;
        while s >= 27 && nl < NLIMB {
            nl = mul_small(&mut d.g, nl, 1 << 27);
            s -= 27;
        }
        if s > 0 && nl < NLIMB {
            nl = mul_small(&mut d.g, nl, 1u64 << s);
        }
        d.k = 0;
    } else {
        let mut t = (-(e as i64)) as u64;
        while t >= 13 && nl < NLIMB {
            nl = mul_small(&mut d.g, nl, 1_220_703_125); // 5^13
            t -= 13;
        }
        if t > 0 && nl < NLIMB {
            nl = mul_small(&mut d.g, nl, 5u64.pow(t as u32));
        }
        d.k = e;
    }
    while nl > 0 && d.g[nl - 1] == 0 {
        nl -= 1;
    }
    d.ng = nl;
    d.n = if nl == 0 {
        1
    } else {
        9 * (nl - 1) + dlen(d.g[nl - 1])
    };
    d.e = d.n as i32 - 1 + d.k;
    d
}

fn mul_small(g: &mut [u32; NLIMB], nl: usize, m: u64) -> usize {
    let mut carry = 0u64;
    let mut n = nl.min(NLIMB);
    let mut i = 0;
    while i < n {
        let t = g[i] as u64 * m + carry;
        g[i] = (t % BASE) as u32;
        carry = t / BASE;
        i += 1;
    }
    while carry > 0 && n < NLIMB {
        g[n] = (carry % BASE) as u32;
        carry /= BASE;
        n += 1;
    }
    n
}

fn dlen(mut x: u32) -> usize {
    let mut n = 1;
    while x >= 10 {
        x /= 10;
        n += 1;
    }
    n
}

impl Dec {
    /// `i`-th digit from the MSD (0-based); past the end reads as 0.
    fn at(&self, i: usize) -> u8 {
        if self.ng == 0 {
            return 0;
        }
        let place = self.n as i64 - 1 - i as i64;
        if place < 0 {
            return 0;
        }
        let limb = (place as usize) / 9;
        if limb >= self.ng {
            return 0;
        }
        ((self.g[limb] / POW10[(place as usize) % 9]) % 10) as u8
    }
}

/// Round the first `c` digits half-to-even. Returns `(overflow, inc)`:
/// `overflow` means 999..→1000.. (caller bumps the exponent);
/// otherwise `inc` is the lowest kept index to increment (`c` = exact,
/// no increment).
fn roundinfo(d: &Dec, c: usize) -> (bool, usize) {
    if c >= d.n {
        return (false, c);
    }
    let first = d.at(c);
    let mut rest = false;
    let mut i = c + 1;
    while i < d.n {
        if d.at(i) != 0 {
            rest = true;
            break;
        }
        i += 1;
    }
    let up = first > 5 || (first == 5 && (rest || (c > 0 && d.at(c - 1) % 2 == 1)));
    if !up {
        return (false, c);
    }
    let mut j = c;
    while j > 0 && d.at(j - 1) == 9 {
        j -= 1;
    }
    if j == 0 {
        return (true, 0);
    }
    (false, j - 1)
}

/// Digit at MSD index `i` under rounding increment `inc`
/// (`usize::MAX` = overflowed, every digit reads 0).
fn kept_digit(d: &Dec, i: usize, inc: usize) -> u8 {
    if inc == usize::MAX {
        return 0;
    }
    if i == inc {
        d.at(i) + 1
    } else if i > inc {
        0
    } else {
        d.at(i)
    }
}

/// Finite nonzero `M * 2^E` (sign already split).
fn finite(buf: &mut [u8], fm: &FmtSpec, sign: bool, m: u64, e: i32) -> usize {
    match fm.spec | 32 {
        b'a' => {
            let shift = m.leading_zeros(); // m != 0: MSB lands exactly at 63
            let mn = m << shift;
            let eu = e + (63 - shift as i32);
            hexfmt(
                buf,
                fm,
                sign,
                mn,
                eu,
                if fm.prec < 0 { -1 } else { fm.prec as i64 },
                false,
            )
        }
        b'e' => {
            let p = if fm.prec < 0 { 6 } else { fm.prec as usize };
            let d = scale(m, e);
            let (ovf, inc) = roundinfo(&d, p + 1);
            let einc = if ovf { usize::MAX } else { inc };
            expfmt_r(buf, fm, sign, &d, if ovf { d.e + 1 } else { d.e }, einc, p)
        }
        b'f' => {
            let p = if fm.prec < 0 { 6 } else { fm.prec as usize };
            let d = scale(m, e);
            let c = (d.e as i64 + 1 + p as i64).max(0) as usize;
            let (ovf, inc) = roundinfo(&d, c);
            let einc = if ovf { usize::MAX } else { inc };
            fixedfmt_r(buf, fm, sign, &d, if ovf { d.e + 1 } else { d.e }, einc, p)
        }
        _ => {
            // %g: round to p sig digits, restyle, strip unless #.
            let p = (if fm.prec < 0 { 6 } else { fm.prec as usize }).max(1);
            let d = scale(m, e);
            let (ovf, inc) = roundinfo(&d, p);
            let ee = if ovf { d.e + 1 } else { d.e };
            let einc = if ovf { usize::MAX } else { inc };
            let alt = fm.flags & F_ALT != 0;
            if (p as i64) > ee as i64 && ee >= -4 {
                // Fixed with p-1-ee decimals, then strip.
                let mut frac = (p as i64 - 1 - ee as i64) as usize;
                if !alt {
                    frac = strip_fixed(&d, ee, einc, frac);
                }
                fixedfmt_r(buf, fm, sign, &d, ee, einc, frac)
            } else {
                // Scientific with p-1 decimals, then strip.
                let mut frac = p - 1;
                if !alt {
                    frac = strip_exp(&d, einc, frac);
                }
                expfmt_r(buf, fm, sign, &d, ee, einc, frac)
            }
        }
    }
}

/// Strip trailing zero fraction digits of a fixed rendering (`frac` in,
/// stripped count out; overflowed values are exactly `10^k`: strip all).
fn strip_fixed(d: &Dec, e: i32, inc: usize, frac: usize) -> usize {
    if inc == usize::MAX {
        return 0;
    }
    let mut f = frac;
    while f > 0 {
        let idx = e as i64 + f as i64; // MSD index of place -f
        let dig = if idx < 0 {
            0
        } else {
            kept_digit(d, idx as usize, inc)
        };
        if dig != 0 {
            break;
        }
        f -= 1;
    }
    f
}

/// Strip trailing zero fraction digits of a scientific rendering.
fn strip_exp(d: &Dec, inc: usize, frac: usize) -> usize {
    if inc == usize::MAX {
        return 0;
    }
    let mut f = frac;
    while f > 0 {
        if kept_digit(d, f, inc) != 0 {
            break;
        }
        f -= 1;
    }
    f
}

/// `%e`: 1 digit, point, `p` decimals, `e±XX` (≥2 digits).
/// `inc == usize::MAX` marks the 999..→1000.. overflow (emit 1 + zeros).
fn expfmt_r(
    buf: &mut [u8],
    fm: &FmtSpec,
    sign: bool,
    d: &Dec,
    e: i32,
    inc: usize,
    p: usize,
) -> usize {
    let lower = fm.spec & 32 != 0;
    let alt = fm.flags & F_ALT != 0;
    let mut estr = [0u8; 12];
    let el = fmtexp(&mut estr, e, lower);
    let point = p > 0 || alt;
    let body = 1 + if point { 1 } else { 0 } + p + el;
    let pl = signlen(fm, sign);
    let mut w = W::new(buf);
    if fm.flags & (F_MINUS | F_ZERO) == 0 {
        w.repeat(b' ', fm.w.saturating_sub(pl + body));
    }
    signch(&mut w, fm, sign);
    if fm.flags & F_ZERO != 0 && fm.flags & F_MINUS == 0 {
        w.repeat(b'0', fm.w.saturating_sub(pl + body));
    }
    if inc == usize::MAX {
        w.put(b'1');
        if point {
            w.put(b'.');
        }
        let mut i = 0;
        while i < p && !w.full() {
            w.put(b'0');
            i += 1;
        }
    } else {
        w.put(b'0' + kept_digit(d, 0, inc));
        if point {
            w.put(b'.');
        }
        let mut i = 1;
        while i < p + 1 && !w.full() {
            w.put(b'0' + kept_digit(d, i, inc));
            i += 1;
        }
    }
    w.slice(&estr[..el]);
    endpad(&mut w, fm, pl + body);
    w.pos
}

/// `%f`: integer part, point, `p` decimals.
fn fixedfmt_r(
    buf: &mut [u8],
    fm: &FmtSpec,
    sign: bool,
    d: &Dec,
    e: i32,
    inc: usize,
    p: usize,
) -> usize {
    let alt = fm.flags & F_ALT != 0;
    let point = p > 0 || alt;
    let intlen = if e >= 0 { e as usize + 1 } else { 1 };
    let body = intlen + if point { 1 } else { 0 } + p;
    let pl = signlen(fm, sign);
    let mut w = W::new(buf);
    if fm.flags & (F_MINUS | F_ZERO) == 0 {
        w.repeat(b' ', fm.w.saturating_sub(pl + body));
    }
    signch(&mut w, fm, sign);
    if fm.flags & F_ZERO != 0 && fm.flags & F_MINUS == 0 {
        w.repeat(b'0', fm.w.saturating_sub(pl + body));
    }
    if inc == usize::MAX {
        // 999.. carried: 1 followed by zeros, exponent already bumped.
        w.put(b'1');
        let mut i = 1;
        while i < intlen && !w.full() {
            w.put(b'0');
            i += 1;
        }
    } else if e >= 0 {
        let mut i = 0;
        while i <= e as usize && !w.full() {
            w.put(b'0' + kept_digit(d, i, inc));
            i += 1;
        }
    } else {
        w.put(b'0');
    }
    if point {
        w.put(b'.');
    }
    // Fraction places -1..-p live at MSD indices e+1...
    let mut k = 0;
    while k < p && !w.full() {
        let idx = e as i64 + 1 + k as i64;
        if idx < 0 {
            w.put(b'0');
        } else {
            w.put(b'0' + kept_digit(d, idx as usize, inc));
        }
        k += 1;
    }
    endpad(&mut w, fm, pl + body);
    w.pos
}

/// Exponent tail `e±XX`/`E±XX` (≥2 digits); returns length.
fn fmtexp(out: &mut [u8; 12], e: i32, lower: bool) -> usize {
    let mut tmp = [0u8; 12];
    let mut n = 0;
    let mut v = (e as i64).wrapping_abs() as u64;
    if v == 0 {
        tmp[11] = b'0';
        n = 1;
    } else {
        while v > 0 {
            tmp[11 - n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
    }
    while n < 2 {
        tmp[11 - n] = b'0';
        n += 1;
    }
    out[0] = if lower { b'e' } else { b'E' };
    out[1] = if e < 0 { b'-' } else { b'+' };
    out[2..2 + n].copy_from_slice(&tmp[12 - n..12]);
    2 + n
}

/// `%a`: `0x1.frac p±exp` off normalized `mn` (MSB at 63), exponent
/// `eu`. `p < 0` emits exact digits (trailing zero nibbles dropped);
/// otherwise exactly `p` hex fraction digits, rounded half-to-even.
/// `is_zero` prints the `0x0p+0` shape.
fn hexfmt(
    buf: &mut [u8],
    fm: &FmtSpec,
    sign: bool,
    mn: u64,
    eu: i32,
    p: i64,
    is_zero: bool,
) -> usize {
    let lower = fm.spec & 32 != 0;
    let alt = fm.flags & F_ALT != 0;
    // Fraction bits sit at 62..0 under the leading 1 (no shift needed).
    // A rounded-up `0x2` leading digit is emitted as-is with the
    // exponent untouched (musl's float rounding lands on `y=2.0` while
    // `e2` stays put, printing `0x2p+0`, never renormalized).
    let (lead, frac, eu) = if p < 0 {
        (if is_zero { 0 } else { 1 }, mn, eu)
    } else {
        round_hex(mn, p as usize, eu, is_zero)
    };
    let nd = if p < 0 {
        exact_nibbles(mn, is_zero)
    } else {
        p as usize
    };
    let point = nd > 0 || alt;
    // Exponent tail: p/P, sign, ≥1 digit.
    let mut digits = [0u8; 20];
    let mut nl = 0;
    let mut v = (eu as i64).wrapping_abs() as u64;
    if v == 0 {
        digits[19] = b'0';
        nl = 1;
    } else {
        while v > 0 {
            digits[19 - nl] = b'0' + (v % 10) as u8;
            v /= 10;
            nl += 1;
        }
    }
    let el = 2 + nl;
    let body = 1 + if point { 1 } else { 0 } + nd + el;
    let pl = 2 + signlen(fm, sign);
    let mut w = W::new(buf);
    if fm.flags & (F_MINUS | F_ZERO) == 0 {
        w.repeat(b' ', fm.w.saturating_sub(pl + body));
    }
    signch(&mut w, fm, sign);
    w.put(b'0');
    w.put(if lower { b'x' } else { b'X' });
    if fm.flags & F_ZERO != 0 && fm.flags & F_MINUS == 0 {
        w.repeat(b'0', fm.w.saturating_sub(pl + body));
    }
    w.put(if lead == 0 {
        b'0'
    } else if lead == 1 {
        b'1'
    } else {
        b'2'
    });
    if point {
        w.put(b'.');
    }
    let mut i = 0;
    while i < nd && !w.full() {
        // Nibble i covers bits (62-4i)..(59-4i); negative reads as 0.
        let mut nib = 0u8;
        let mut j = 0;
        while j < 4 {
            let bpos = 62 - 4 * i as i64 - j;
            nib *= 2;
            if bpos >= 0 {
                nib += ((frac >> (bpos as u32)) & 1) as u8;
            }
            j += 1;
        }
        w.put(hexdig(nib, lower));
        i += 1;
    }
    w.put(if lower { b'p' } else { b'P' });
    w.put(if eu < 0 { b'-' } else { b'+' });
    w.slice(&digits[20 - nl..20]);
    endpad(&mut w, fm, pl + body);
    w.pos
}

fn hexdig(n: u8, lower: bool) -> u8 {
    if n < 10 {
        b'0' + n
    } else if lower {
        b'a' + (n - 10)
    } else {
        b'A' + (n - 10)
    }
}

/// Exact nibble count: down to the lowest set fraction bit
/// (`trailing_zeros` is ≤ 62 for any nonzero fraction under a bit-63
/// leading 1, and exactly 63 for the bare `2^63`, which yields 0).
fn exact_nibbles(frac: u64, is_zero: bool) -> usize {
    if is_zero || frac == 0 {
        return 0;
    }
    (63 - frac.trailing_zeros()).div_ceil(4) as usize
}

/// Round normalized `mn` (leading 1 at bit 63) to `nd` hex fraction
/// digits half-to-even; returns `(lead, frac, eu)` where `lead` is the
/// digit before the point (0, 1, or a carried-up 2 with `eu` untouched).
fn round_hex(mn: u64, nd: usize, eu: i32, is_zero: bool) -> (u8, u64, i32) {
    if is_zero || mn == 0 {
        return (0, 0, if is_zero { 0 } else { eu });
    }
    let need = (nd as u64).saturating_mul(4);
    if need >= 63 {
        return (1, mn, eu); // every exact bit kept; tail pads with zeros
    }
    // Keep the leading 1 plus `need` fraction bits; round the rest.
    let drop = 63 - need; // 1..=63
    let kept = mn >> drop; // need+1 bits, top bit set
    let rest = mn & ((1u64 << drop) - 1);
    let half = 1u64 << (drop - 1);
    if rest < half || (rest == half && kept & 1 == 0) {
        return (1, kept << drop, eu);
    }
    if kept + 1 == 1u64 << (need + 1) {
        return (2, 0, eu); // 0x2p+eu, exponent untouched (musl shape)
    }
    (1, (kept + 1) << drop, eu)
}

#[cfg(test)]
mod tests {
    use super::{fmt_f64_bits, fmt_f80_bits, FmtSpec, F_ALT, F_MINUS, F_PLUS, F_SPACE, F_ZERO};
    use std::format;
    use std::string::{String, ToString};

    fn sp(spec: u8, prec: isize, flags: u32, w: usize) -> FmtSpec {
        FmtSpec {
            spec,
            w,
            prec,
            flags,
        }
    }

    fn s(bits: u64, fm: &FmtSpec) -> String {
        let mut buf = [0u8; 4096];
        let n = fmt_f64_bits(&mut buf, bits, fm);
        String::from_utf8(buf[..n].to_vec()).unwrap()
    }

    fn run80(ext10: &[u8; 10], fm: &FmtSpec) -> String {
        let mut buf = [0u8; 4096];
        let n = fmt_f80_bits(&mut buf, ext10, fm);
        String::from_utf8(buf[..n].to_vec()).unwrap()
    }

    fn f80_of(mant: u64, exp: u16, sign: bool) -> [u8; 10] {
        let se = (if sign { 0x8000 } else { 0 }) | (exp & 0x7fff);
        let m = mant.to_le_bytes();
        let e = se.to_le_bytes();
        [m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], e[0], e[1]]
    }

    // ---- std oracles -------------------------------------------------
    // Rust prints `%e` exponents bare (`1.23e4`); C pads to ≥2 digits.
    fn c_exp(t: &str) -> String {
        let pos = t.rfind(['e', 'E']).unwrap();
        let (m, e) = t.split_at(pos);
        let up = e.starts_with('E');
        // The exponent runs to the next space or end (width pads trails).
        let b = e.as_bytes();
        let mut len = 1;
        while len < b.len() && (b[len] == b'+' || b[len] == b'-' || b[len].is_ascii_digit()) {
            len += 1;
        }
        let ev: i32 = e[1..len].parse().unwrap();
        format!("{}{}{:+03}{}", m, if up { 'E' } else { 'e' }, ev, &e[len..])
    }

    fn oracle_f(x: f64, prec: usize, flags: u32, w: usize) -> String {
        if flags == F_SPACE && w == 0 && !x.is_sign_negative() {
            return format!(" {}", format_args!("{x:.prec$}"));
        }
        match (flags, w) {
            (0, 0) => format!("{x:.prec$}"),
            (f, 0) if f == F_PLUS => format!("{x:+.prec$}"),
            (f, 0) if f == F_SPACE => format!("{x:.prec$}"),
            (f, w) if f == F_ZERO => format!("{x:0w$.prec$}"),
            (f, w) if f == F_MINUS => format!("{x:<w$.prec$}"),
            (f, w) if f == F_PLUS | F_ZERO => format!("{x:+0w$.prec$}"),
            (f, w) if f == F_PLUS | F_MINUS => format!("{x:<+w$.prec$}"),
            _ => panic!("oracle_f: flags={flags} w={w}"),
        }
    }

    fn oracle_e(x: f64, prec: usize, up: bool, flags: u32, w: usize) -> String {
        let t = match (flags, w, up) {
            (0, 0, false) => format!("{x:.prec$e}"),
            (0, 0, true) => format!("{x:.prec$E}"),
            (f, 0, false) if f == F_PLUS => format!("{x:+.prec$e}"),
            (f, 0, true) if f == F_PLUS => format!("{x:+.prec$E}"),
            (f, w, false) if f == F_ZERO => format!("{x:0w$.prec$e}"),
            (f, w, true) if f == F_ZERO => format!("{x:0w$.prec$E}"),
            (f, w, false) if f == F_MINUS => format!("{x:<w$.prec$e}"),
            (f, w, true) if f == F_MINUS => format!("{x:<w$.prec$E}"),
            _ => panic!("oracle_e: {flags} {w} {up}"),
        };
        c_exp(&t)
    }

    const FVALS: [f64; 25] = [
        0.0,
        -0.0,
        1.0,
        -1.5,
        0.1,
        1.0 / 3.0,
        123456.789,
        1e-10,
        1e20,
        1e308,
        5e-324,
        2.2250738585072014e-308,
        0.5,
        1.5,
        2.5,
        0.125,
        0.375,
        2.675,
        core::f64::consts::PI,
        -123.456e-7,
        999.9995,
        999.5,
        9.9995,
        1.7976931348623157e308,
        f64::from_bits(1),
    ];
    const PRECS: [isize; 7] = [-1, 0, 1, 2, 5, 10, 17];

    #[test]
    fn f_matches_std_sweep() {
        for &x in &FVALS {
            for &pr in &PRECS {
                let prec = if pr < 0 { 6 } else { pr as usize };
                for &(flags, w) in &[
                    (0, 0),
                    (F_PLUS, 0),
                    (F_SPACE, 0),
                    (F_ZERO, 15),
                    (F_MINUS, 15),
                    (F_PLUS | F_ZERO, 15),
                    (F_PLUS | F_MINUS, 15),
                ] {
                    // Exact binary ties go through the hand-vector
                    // table (std tie rules are not our contract).
                    if pr == 0 && [0.5f64, 1.5, 2.5, 999.5].contains(&x.abs()) {
                        continue;
                    }
                    let fm = sp(b'f', pr, flags, w);
                    assert_eq!(
                        s(x.to_bits(), &fm),
                        oracle_f(x, prec, flags, w),
                        "f x={x:e} prec={pr} flags={flags} w={w}"
                    );
                    let fm = sp(b'F', pr, flags, w);
                    assert_eq!(
                        s(x.to_bits(), &fm),
                        oracle_f(x, prec, flags, w),
                        "F x={x:e} prec={pr} flags={flags} w={w}"
                    );
                }
            }
        }
    }

    #[test]
    fn e_matches_std_sweep() {
        for &x in &FVALS {
            for &pr in &PRECS {
                let prec = if pr < 0 { 6 } else { pr as usize };
                for &(flags, w, up) in &[
                    (0, 0, false),
                    (0, 0, true),
                    (F_PLUS, 0, false),
                    (F_PLUS, 0, true),
                    // No width or F_ZERO here: Rust pads `{:w$e}` around
                    // the mantissa (`0.000000e+00      `), never C-style;
                    // both covered by hand below.
                ] {
                    if pr == 0 && [0.5f64, 1.5, 2.5].contains(&x.abs()) {
                        continue;
                    }
                    let fm = sp(if up { b'E' } else { b'e' }, pr, flags, w);
                    assert_eq!(
                        s(x.to_bits(), &fm),
                        oracle_e(x, prec, up, flags, w),
                        "e x={x:e} prec={pr} flags={flags} w={w} up={up}"
                    );
                }
            }
        }
    }

    // ---- %g model oracle (std digits + C style/strip rules) --------------
    fn strip(mut t: String) -> String {
        if t.contains('.') {
            while t.ends_with('0') {
                t.pop();
            }
            if t.ends_with('.') {
                t.pop();
            }
        }
        t
    }

    fn oracle_g(x: f64, prec: usize, up: bool) -> String {
        if x == 0.0 {
            return String::from(if x.is_sign_negative() { "-0" } else { "0" });
        }
        let se = format!("{x:.pp$e}", pp = prec.max(1) - 1);
        let pos = se.rfind(['e', 'E']).unwrap();
        let e: i32 = se[pos + 1..].parse().unwrap();
        let out = if (prec as i32) > e && e >= -4 {
            strip(format!("{:.*}", (prec as i32 - 1 - e) as usize, x))
        } else {
            let full = format!("{:.*e}", prec - 1, x);
            let pos = full.rfind(['e', 'E']).unwrap();
            c_exp(&format!(
                "{}e{}",
                strip(full[..pos].to_string()),
                &full[pos + 1..]
            ))
        };
        if up {
            out.replace('e', "E")
        } else {
            out
        }
    }

    #[test]
    fn g_matches_model_sweep() {
        for &x in &FVALS {
            for &pr in &PRECS {
                let prec = if pr < 0 {
                    6
                } else if pr == 0 {
                    1
                } else {
                    pr as usize
                };
                for up in [false, true] {
                    if pr == 0 && [0.5f64, 1.5, 2.5].contains(&x.abs()) {
                        continue;
                    }
                    let fm = sp(if up { b'G' } else { b'g' }, pr, 0, 0);
                    assert_eq!(
                        s(x.to_bits(), &fm),
                        oracle_g(x, prec, up),
                        "g x={x:e} prec={pr} up={up}"
                    );
                }
            }
        }
    }

    #[test]
    fn hand_vectors() {
        // Half-even ties (exact binary): 0.5->0, 1.5->2, 2.5->2, -0.5->-0.
        assert_eq!(s(0.5f64.to_bits(), &sp(b'f', 0, 0, 0)), "0");
        assert_eq!(s(1.5f64.to_bits(), &sp(b'f', 0, 0, 0)), "2");
        assert_eq!(s(2.5f64.to_bits(), &sp(b'f', 0, 0, 0)), "2");
        assert_eq!(s((-0.5f64).to_bits(), &sp(b'f', 0, 0, 0)), "-0");
        assert_eq!(s(0.125f64.to_bits(), &sp(b'f', 2, 0, 0)), "0.12");
        assert_eq!(s(0.375f64.to_bits(), &sp(b'f', 2, 0, 0)), "0.38");
        // Famous inexact case: 2.675 is really 2.67499... -> "2.67".
        assert_eq!(s(2.675f64.to_bits(), &sp(b'f', 2, 0, 0)), "2.67");
        // Default-6, zero precision, # flag, width/zero-pad, signs.
        assert_eq!(s((1.0f64 / 3.0).to_bits(), &sp(b'f', -1, 0, 0)), "0.333333");
        assert_eq!(s(3.0f64.to_bits(), &sp(b'f', 0, 0, 0)), "3");
        assert_eq!(s(3.0f64.to_bits(), &sp(b'f', 0, F_ALT, 0)), "3.");
        assert_eq!(s(1.5f64.to_bits(), &sp(b'f', 2, F_ZERO, 8)), "00001.50");
        assert_eq!(s(1.5f64.to_bits(), &sp(b'f', 2, F_MINUS, 8)), "1.50    ");
        assert_eq!(s(1.5f64.to_bits(), &sp(b'f', 2, F_PLUS, 0)), "+1.50");
        assert_eq!(s(1.5f64.to_bits(), &sp(b'f', 2, F_SPACE, 0)), " 1.50");
        // inf/nan in spec case, signed zero.
        assert_eq!(s(f64::INFINITY.to_bits(), &sp(b'f', 2, 0, 0)), "inf");
        assert_eq!(
            s(f64::INFINITY.to_bits(), &sp(b'E', 2, F_ZERO, 8)),
            "     INF"
        );
        assert_eq!(s(f64::NAN.to_bits(), &sp(b'e', 2, 0, 0)), "nan");
        assert_eq!(s(f64::NAN.to_bits(), &sp(b'E', 2, 0, 0)), "NAN");
        assert_eq!(s((-0.0f64).to_bits(), &sp(b'f', 1, 0, 0)), "-0.0");
        assert_eq!(s((-0.0f64).to_bits(), &sp(b'e', 2, F_PLUS, 0)), "-0.00e+00");
        assert_eq!(s(0.0f64.to_bits(), &sp(b'e', -1, 0, 0)), "0.000000e+00");
        assert_eq!(s(0.0f64.to_bits(), &sp(b'g', -1, 0, 0)), "0");
        assert_eq!(s(0.0f64.to_bits(), &sp(b'g', -1, F_ALT, 0,)), "0.00000");
        // %e shape: ≥2 exponent digits, E case.
        assert_eq!(s(12345.0f64.to_bits(), &sp(b'e', 2, 0, 0)), "1.23e+04");
        assert_eq!(s(12345.0f64.to_bits(), &sp(b'E', 2, 0, 0)), "1.23E+04");
        assert_eq!(s(1e-5f64.to_bits(), &sp(b'e', -1, 0, 0)), "1.000000e-05");
        // C `0`-pad for %e (Rust pads pre-exponent instead; see sweep).
        assert_eq!(
            s(1.5f64.to_bits(), &sp(b'e', -1, F_ZERO, 16)),
            "00001.500000e+00"
        );
        assert_eq!(
            s(0.0f64.to_bits(), &sp(b'e', -1, F_ZERO, 16)),
            "00000.000000e+00"
        );
        assert_eq!(s(1.5f64.to_bits(), &sp(b'e', 2, F_ZERO, 3)), "1.50e+00");
        // C width for %e (Rust pads around the mantissa instead).
        assert_eq!(
            s(1.5f64.to_bits(), &sp(b'e', -1, 0, 20)),
            "        1.500000e+00"
        );
        assert_eq!(
            s(1.5f64.to_bits(), &sp(b'e', -1, F_MINUS, 20)),
            "1.500000e+00        "
        );
        assert_eq!(
            s(1.5f64.to_bits(), &sp(b'E', 2, F_PLUS, 20)),
            "           +1.50E+00"
        );
        assert_eq!(s(1.5f64.to_bits(), &sp(b'e', 2, F_SPACE, 0)), " 1.50e+00");
        assert_eq!(s(1.5f64.to_bits(), &sp(b'e', 0, F_ALT, 0)), "2.e+00");
        assert_eq!(s(3.0f64.to_bits(), &sp(b'E', 0, F_ALT, 0)), "3.E+00");
        // Rounding carries across magnitudes.
        assert_eq!(s(999.5f64.to_bits(), &sp(b'f', 0, 0, 0)), "1000");
        // %g style switch + strip + # + prec-0 + carry.
        assert_eq!(s(123456.0f64.to_bits(), &sp(b'g', 6, 0, 0)), "123456");
        assert_eq!(s(1234567.0f64.to_bits(), &sp(b'g', 6, 0, 0)), "1.23457e+06");
        assert_eq!(s(0.0001f64.to_bits(), &sp(b'g', 6, 0, 0)), "0.0001");
        assert_eq!(s(0.00001f64.to_bits(), &sp(b'g', 6, 0, 0)), "1e-05");
        assert_eq!(s(1.5f64.to_bits(), &sp(b'g', 6, F_ALT, 0)), "1.50000");
        assert_eq!(s(1.5f64.to_bits(), &sp(b'g', 0, 0, 0)), "2");
        assert_eq!(s(100.0f64.to_bits(), &sp(b'G', 2, 0, 0)), "1E+02");
        assert_eq!(s(999.9995f64.to_bits(), &sp(b'g', 4, 0, 0)), "1000");
        assert_eq!(s(999.5f64.to_bits(), &sp(b'g', 3, 0, 0)), "1e+03");
        // %a exact shapes.
        assert_eq!(s(1.0f64.to_bits(), &sp(b'a', -1, 0, 0)), "0x1p+0");
        assert_eq!(s(1.5f64.to_bits(), &sp(b'a', -1, 0, 0)), "0x1.8p+0");
        assert_eq!(s(1.5f64.to_bits(), &sp(b'A', -1, 0, 0)), "0X1.8P+0");
        assert_eq!(
            s(0.1f64.to_bits(), &sp(b'a', -1, 0, 0)),
            "0x1.999999999999ap-4"
        );
        assert_eq!(s(3.5f64.to_bits(), &sp(b'a', -1, 0, 0)), "0x1.cp+1");
        assert_eq!(s(1.0f64.to_bits(), &sp(b'a', 1, 0, 0)), "0x1.0p+0");
        assert_eq!(s(1.5f64.to_bits(), &sp(b'a', 0, 0, 0)), "0x2p+0");
        assert_eq!(s(1.25f64.to_bits(), &sp(b'a', 0, 0, 0)), "0x1p+0");
        assert_eq!(s(0.0f64.to_bits(), &sp(b'a', -1, 0, 0)), "0x0p+0");
        assert_eq!(s((-0.0f64).to_bits(), &sp(b'a', -1, 0, 0)), "-0x0p+0");
        assert_eq!(s(0.0f64.to_bits(), &sp(b'a', -1, F_ALT, 0)), "0x0.p+0");
        assert_eq!(s(0.0f64.to_bits(), &sp(b'a', 3, 0, 0)), "0x0.000p+0");
        assert_eq!(
            s(f64::MAX.to_bits(), &sp(b'a', -1, 0, 0)),
            "0x1.fffffffffffffp+1023"
        );
        assert_eq!(s(5e-324f64.to_bits(), &sp(b'a', -1, 0, 0)), "0x1p-1074");
        assert_eq!(
            s(2.2250738585072014e-308f64.to_bits(), &sp(b'a', -1, 0, 0)),
            "0x1p-1022"
        );
    }

    #[test]
    fn f80_vectors() {
        let one = f80_of(0x8000_0000_0000_0000, 0x3fff, false);
        assert_eq!(run80(&one, &sp(b'f', -1, 0, 0)), "1.000000");
        assert_eq!(run80(&one, &sp(b'e', 2, 0, 0)), "1.00e+00");
        assert_eq!(run80(&one, &sp(b'a', -1, 0, 0)), "0x1p+0");
        assert_eq!(run80(&one, &sp(b'G', 4, 0, 0)), "1");
        let negz = f80_of(0, 0, true);
        assert_eq!(run80(&negz, &sp(b'f', 1, 0, 0)), "-0.0");
        assert_eq!(run80(&negz, &sp(b'a', -1, 0, 0)), "-0x0p+0");
        let threehalf = f80_of(0xe000_0000_0000_0000, 0x4000, false);
        assert_eq!(run80(&threehalf, &sp(b'f', 2, 0, 0)), "3.50");
        assert_eq!(run80(&threehalf, &sp(b'a', -1, 0, 0)), "0x1.cp+1");
        let ten = f80_of(0xa000_0000_0000_0000, 0x4002, false);
        assert_eq!(run80(&ten, &sp(b'f', 0, 0, 0)), "10");
        assert_eq!(run80(&ten, &sp(b'a', -1, 0, 0)), "0x1.4p+3");
        let inf = f80_of(0x8000_0000_0000_0000, 0x7fff, false);
        assert_eq!(run80(&inf, &sp(b'f', 2, 0, 0)), "inf");
        assert_eq!(run80(&inf, &sp(b'A', 2, 0, 0)), "INF");
        let nan = f80_of(0xc000_0000_0000_0000, 0x7fff, false);
        assert_eq!(run80(&nan, &sp(b'e', 2, 0, 0)), "nan");
        let max = f80_of(0xffff_ffff_ffff_ffff, 0x7ffe, false);
        assert_eq!(
            run80(&max, &sp(b'a', -1, 0, 0)),
            "0x1.fffffffffffffffep+16383"
        );
        let tiny = f80_of(1, 0, false);
        assert_eq!(run80(&tiny, &sp(b'a', -1, 0, 0)), "0x1p-16445");
        // Same value in both widths formats the same for f/e/g.
        for (bits, ext) in [
            (3.5f64.to_bits(), threehalf),
            (1.0f64.to_bits(), one),
            ((-0.0f64).to_bits(), negz),
        ] {
            for t in *b"feg" {
                assert_eq!(run80(&ext, &sp(t, 4, 0, 0)), s(bits, &sp(t, 4, 0, 0)));
            }
        }
    }

    #[test]
    fn truncation_never_panics() {
        let mut tiny = [0u8; 4];
        let n = fmt_f64_bits(&mut tiny, 123456.789f64.to_bits(), &sp(b'f', 10, 0, 100));
        assert_eq!(n, 4);
        let mut empty: [u8; 0] = [];
        let n = fmt_f64_bits(&mut empty, 1.0f64.to_bits(), &sp(b'e', -1, 0, 0));
        assert_eq!(n, 0);
    }
}
