//! Integer/float conversions, sorting, searching, small math helpers.
//!
//! musl `src/stdlib/{strtol,strtod,atoi,atol,atoll,abs,labs,llabs,imaxabs,
//! div,ldiv,lldiv,imaxdiv,qsort,qsort_nr,bsearch,ecvt,fcvt,gcvt}.c`,
//! `src/internal/{intscan,floatscan}.c` (engines), `src/misc/{a64l (also
//! `l64a`),getsubopt}.c`. Only this file may contain these symbols.
//!
//! Deviations from musl, one line each:
//! - `strtold` returns the 80-bit value in ST(0) via one `fldt` (SysV
//!   x86_64 returns `long double` in ST(0); stable Rust cannot name `f80`,
//!   so the body computes exact 10-byte extended bytes, not an `f64`).
//! - The float engine is integer-limb exact (32 decimal digits + sticky,
//!   then round-to-even); bit-exact with musl, no `f80` arithmetic used.
//! - `ecvt`/`fcvt` of inf/nan return `"inf"`/`"nan"` (`dp = 0`); musl
//!   over-reads its buffer there.
//! - `fcvt` formats `%f` into a truncating 1500-byte buffer; musl's fixed
//!   `tmp[1500]` overflows on e.g. `fcvt(1e308, 1400)`, this one cannot.
//! - `gcvt` clamps precision to 1100 (invisible: a `double` prints at most
//!   ~775 significant chars, so output is identical for every input).
//! - `div`-family on divide-by-zero traps like musl (`idiv` faults; Rust
//!   panics); `INT_MIN / -1` wraps (C UB either way).
//! - `ecvt`/`l64a` static buffers are MT-unsafe, exactly like musl's.
//! - NULL inputs return 0/`NULL` with `EINVAL` (musl would fault); NULL
//!   `qsort`/`bsearch` comparators are a no-op/`NULL` (musl would fault).

use core::ffi::{
    c_char, c_double, c_float, c_int, c_long, c_longlong, c_uint, c_ulong, c_ulonglong, c_void,
};
use core::ptr::null_mut;

use crate::stdio::dtoa::{fmt_f64_bits, FmtSpec};

const EINVAL: c_int = 22;
const ERANGE: c_int = 34;

/// musl `src/errno/__errno_location.c`: store through the per-thread cell.
#[inline]
fn set_errno(v: c_int) {
    unsafe {
        crate::errno::errno_store(crate::errno::__errno_location(), v);
    }
}

/// musl `stdlib.h` (`div_t`): quotient + remainder.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct div_t {
    pub quot: c_int,
    pub rem: c_int,
}

/// musl `stdlib.h` (`ldiv_t`).
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct ldiv_t {
    pub quot: c_long,
    pub rem: c_long,
}

/// musl `stdlib.h` (`lldiv_t`).
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct lldiv_t {
    pub quot: c_longlong,
    pub rem: c_longlong,
}

/// musl `inttypes.h` (`imaxdiv_t`); x86_64 `intmax_t` is 64-bit.
#[allow(non_camel_case_types)]
pub type intmax_t = i64;
/// musl `inttypes.h` (`uintmax_t`); x86_64 unsigned 64-bit.
#[allow(non_camel_case_types)]
pub type uintmax_t = u64;

/// musl `inttypes.h` (`imaxdiv_t`).
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct imaxdiv_t {
    pub quot: intmax_t,
    pub rem: intmax_t,
}

// ---- shared string cursor ---------------------------------------------------
// musl `src/internal/shgetc.h` over a NUL-terminated string: `get` yields
// the NUL once as `0` (then sticks at end-of-input, never reading past
// it); every terminator is pushed back exactly once, so `pos` at return
// is the `endptr` offset (musl `shcnt`).

struct Cur {
    s: *const u8,
    pos: usize,
    eof: bool,
}

impl Cur {
    /// Next byte, or `0` at/past the terminator (musl string-`shgetc`).
    ///
    /// # Safety
    ///
    /// `s` must point at a valid NUL-terminated string.
    unsafe fn get(&mut self) -> i32 {
        unsafe {
            if self.eof {
                return 0;
            }
            let b = *self.s.add(self.pos);
            self.pos += 1;
            if b == 0 {
                self.eof = true;
            }
            b as i32
        }
    }

    /// Push back one byte (musl `shunget`; string streams rewind freely).
    fn unget(&mut self) {
        if self.pos > 0 {
            self.pos -= 1;
        }
        self.eof = false;
    }
}

/// musl `src/ctype/isspace.c`: `C` locale whitespace.
#[inline]
fn is_space(c: i32) -> bool {
    matches!(c, 9..=13 | 32)
}

/// musl `src/internal/intscan.c:7-24` digit table, branch form:
/// `0-9`/`a-z`/`A-Z` values, `255` (`-1`) invalid (covers `EOF` as `-1`).
#[inline]
fn digit_val(c: i32) -> u32 {
    if c >= '0' as i32 && c <= '9' as i32 {
        (c - '0' as i32) as u32
    } else if (c | 32) >= 'a' as i32 && (c | 32) <= 'z' as i32 {
        ((c | 32) - 'a' as i32) as u32 + 10
    } else {
        255
    }
}

/// Write `*endp = s + pos` when `endp` is non-NULL.
///
/// # Safety
///
/// `s` must be the caller's string base; `endp` NULL or writable.
unsafe fn set_endp(s: *const c_char, endp: *mut *mut c_char, pos: usize) {
    unsafe {
        if !endp.is_null() {
            *endp = s.cast_mut().add(pos);
        }
    }
}

// ---- integer engine (musl `__intscan`, `pok = 1`) ----------------------------

/// Core of `strtol`/`strtoll`/`strtoul`/`strtoull`/`strtoimax`/`strtoumax`.
///
/// `lim` selects signedness/range exactly like musl's `strtox` (`LLONG_MIN`
/// pattern for signed, `ULLONG_MAX` for unsigned); returns the value bits.
/// Sets `errno` (`EINVAL` no-conversion/bad-base, `ERANGE` overflow) and
/// `*endp` (no conversion leaves it at `s`, musl `shlim`-rebase shape).
///
/// # Safety
///
/// `s` must point at a valid NUL-terminated string; `endp` NULL or writable.
unsafe fn intscan(s: *const c_char, endp: *mut *mut c_char, base_in: u32, lim: u64) -> u64 {
    unsafe {
        if s.is_null() {
            set_errno(EINVAL);
            return 0;
        }
        if base_in > 36 || base_in == 1 {
            set_errno(EINVAL);
            set_endp(s, endp, 0);
            return 0;
        }
        let mut cur = Cur {
            s: s as *const u8,
            pos: 0,
            eof: false,
        };
        let mut c = cur.get();
        while is_space(c) {
            c = cur.get();
        }
        let mut neg = false;
        if c == '+' as i32 || c == '-' as i32 {
            neg = c == '-' as i32;
            c = cur.get();
        }
        let mut base = base_in;
        if (base == 0 || base == 16) && c == '0' as i32 {
            c = cur.get();
            if (c | 32) == 'x' as i32 {
                c = cur.get();
                if digit_val(c) >= 16 {
                    cur.unget();
                    cur.unget();
                    set_endp(s, endp, cur.pos);
                    return 0;
                }
                base = 16;
            } else if base == 0 {
                base = 8;
            }
        } else {
            if base == 0 {
                base = 10;
            }
            if digit_val(c) >= base {
                cur.unget();
                set_errno(EINVAL);
                set_endp(s, endp, 0);
                return 0;
            }
        }
        let mut y: u64;
        if base == 10 {
            let mut x: u32 = 0;
            while c >= '0' as i32 && c <= '9' as i32 && x < u32::MAX / 10 {
                x = x * 10 + (c - '0' as i32) as u32;
                c = cur.get();
            }
            y = x as u64;
            while c >= '0' as i32
                && c <= '9' as i32
                && y <= u64::MAX / 10
                && 10 * y <= u64::MAX - (c - '0' as i32) as u64
            {
                y = y * 10 + (c - '0' as i32) as u64;
                c = cur.get();
            }
            if c < '0' as i32 || c > '9' as i32 {
                cur.unget();
            } else {
                while digit_val(c) < 10 {
                    c = cur.get();
                }
                cur.unget();
                set_errno(ERANGE);
                y = lim;
                if lim & 1 != 0 {
                    neg = false;
                }
            }
        } else if base & (base - 1) == 0 {
            let bs = b"\0\x01\x02\x04\x07\x03\x06\x05"[(0x17 * base as usize) >> 5 & 7] as u32;
            let mut x: u32 = 0;
            while digit_val(c) < base && x <= u32::MAX / 32 {
                x = (x << bs) | digit_val(c);
                c = cur.get();
            }
            y = x as u64;
            while digit_val(c) < base && y <= u64::MAX >> bs {
                y = (y << bs) | digit_val(c) as u64;
                c = cur.get();
            }
            if digit_val(c) >= base {
                cur.unget();
            } else {
                while digit_val(c) < base {
                    c = cur.get();
                }
                cur.unget();
                set_errno(ERANGE);
                y = lim;
                if lim & 1 != 0 {
                    neg = false;
                }
            }
        } else {
            let mut x: u32 = 0;
            while digit_val(c) < base && x < u32::MAX / 36 {
                x = x * base + digit_val(c);
                c = cur.get();
            }
            y = x as u64;
            while digit_val(c) < base
                && y <= u64::MAX / base as u64
                && (base as u64) * y <= u64::MAX - digit_val(c) as u64
            {
                y = y * base as u64 + digit_val(c) as u64;
                c = cur.get();
            }
            if digit_val(c) >= base {
                cur.unget();
            } else {
                while digit_val(c) < base {
                    c = cur.get();
                }
                cur.unget();
                set_errno(ERANGE);
                y = lim;
                if lim & 1 != 0 {
                    neg = false;
                }
            }
        }
        let end = cur.pos;
        if y >= lim {
            if lim & 1 == 0 && !neg {
                set_errno(ERANGE);
                set_endp(s, endp, end);
                return lim.wrapping_sub(1);
            } else if y > lim {
                set_errno(ERANGE);
                set_endp(s, endp, end);
                return lim;
            }
        }
        set_endp(s, endp, end);
        if neg {
            y.wrapping_neg()
        } else {
            y
        }
    }
}

/// musl `src/stdlib/strtol.c:36-39` (`lim` is `LONG_MIN` as `u64`).
///
/// # Safety
///
/// `s` NUL-terminated; `endp` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn strtol(s: *const c_char, endp: *mut *mut c_char, base: c_int) -> c_long {
    unsafe { intscan(s, endp, base as u32, 0x8000_0000_0000_0000) as c_long }
}

/// musl `src/stdlib/strtol.c:26-29`.
///
/// # Safety
///
/// `s` NUL-terminated; `endp` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn strtoll(
    s: *const c_char,
    endp: *mut *mut c_char,
    base: c_int,
) -> c_longlong {
    unsafe { intscan(s, endp, base as u32, 0x8000_0000_0000_0000) as c_longlong }
}

/// musl `src/stdlib/strtol.c:31-34`.
///
/// # Safety
///
/// `s` NUL-terminated; `endp` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn strtoul(s: *const c_char, endp: *mut *mut c_char, base: c_int) -> c_ulong {
    unsafe { intscan(s, endp, base as u32, u64::MAX) as c_ulong }
}

/// musl `src/stdlib/strtol.c:21-24`.
///
/// # Safety
///
/// `s` NUL-terminated; `endp` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn strtoull(
    s: *const c_char,
    endp: *mut *mut c_char,
    base: c_int,
) -> c_ulonglong {
    unsafe { intscan(s, endp, base as u32, u64::MAX) as c_ulonglong }
}

/// musl `src/stdlib/strtol.c:41-44` (`strtoimax` is `strtoll`).
///
/// # Safety
///
/// `s` NUL-terminated; `endp` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn strtoimax(
    s: *const c_char,
    endp: *mut *mut c_char,
    base: c_int,
) -> intmax_t {
    unsafe { intscan(s, endp, base as u32, 0x8000_0000_0000_0000) as intmax_t }
}

/// musl `src/stdlib/strtol.c:46-49` (`strtoumax` is `strtoull`).
///
/// # Safety
///
/// `s` NUL-terminated; `endp` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn strtoumax(
    s: *const c_char,
    endp: *mut *mut c_char,
    base: c_int,
) -> uintmax_t {
    unsafe { intscan(s, endp, base as u32, u64::MAX) }
}

// ---- float engine (musl `__floatscan`, `pok = 1`; integer limbs) --------------
// Decimal input becomes `(M, E)` with `value = M * 10^E` (`M: u128`, first
// 32 significant digits, further digits folded into `sticky`; 32 digits are
// ~106 bits, far past the ~73 guard bits any rounding needs, so a boolean
// sticky is exact). Binary conversion is exact bignum math, then one
// round-to-even to the target precision: bit-exact with musl, and no `f80`
// arithmetic anywhere (the `strtold` result ships out via `fldt`).

/// Target precision: mantissa bits, max/min normal binary exponent,
/// max decimal exponent (early overflow cutoff), early-zero cutoff
/// (`E + 32 < zcut10` means even 32 nines sit below half the min denormal:
/// f32/f64 denormals end ~1 decade below 10^emin10, f80 ~19 (2^-16445)).
#[derive(Clone, Copy)]
struct Prec {
    p: u32,
    emax2: i64,
    emin2: i64,
    emax10: i64,
    zcut10: i64,
}

const P32: Prec = Prec {
    p: 24,
    emax2: 127,
    emin2: -126,
    emax10: 38,
    zcut10: -46,
};
const P64: Prec = Prec {
    p: 53,
    emax2: 1023,
    emin2: -1022,
    emax10: 308,
    zcut10: -325,
};
const P80: Prec = Prec {
    p: 64,
    emax2: 16383,
    emin2: -16382,
    emax10: 4932,
    zcut10: -4950,
};

/// Parsed float result, one variant per precision.
enum FVal {
    F32(u32),
    F64(u64),
    F80([u8; 10]),
}

fn zero_of(pr: Prec, neg: bool) -> FVal {
    match pr.p {
        24 => FVal::F32((neg as u32) << 31),
        53 => FVal::F64((neg as u64) << 63),
        _ => {
            let mut b = [0u8; 10];
            b[9] = (neg as u8) << 7;
            FVal::F80(b)
        }
    }
}

fn inf_of(pr: Prec, neg: bool) -> FVal {
    match pr.p {
        24 => FVal::F32((neg as u32) << 31 | 0x7f80_0000),
        53 => FVal::F64((neg as u64) << 63 | 0x7ff0_0000_0000_0000),
        _ => {
            let mut b = [0u8; 10];
            b[0..8].copy_from_slice(&0x8000_0000_0000_0000u64.to_le_bytes());
            let se = ((neg as u16) << 15) | 0x7fff;
            b[8..10].copy_from_slice(&se.to_le_bytes());
            FVal::F80(b)
        }
    }
}

/// musl returns bare `NAN` for `nan`, ignoring the sign.
fn nan_of(pr: Prec) -> FVal {
    match pr.p {
        24 => FVal::F32(0x7fc0_0000),
        53 => FVal::F64(0x7ff8_0000_0000_0000),
        _ => {
            let mut b = [0u8; 10];
            b[0..8].copy_from_slice(&0xc000_0000_0000_0000u64.to_le_bytes());
            b[8..10].copy_from_slice(&0x7fffu16.to_le_bytes());
            FVal::F80(b)
        }
    }
}

/// musl `floatscan.c:36-60` exponent scanner; `None` = no digits (cursor
/// rewound to entry, caller pushes back its own `e`/`p`).
///
/// # Safety
///
/// Cursor over a valid NUL-terminated string.
unsafe fn scanexp(cur: &mut Cur) -> Option<i64> {
    unsafe {
        let mark = (cur.pos, cur.eof);
        let mut c = cur.get();
        let mut neg = false;
        if c == '+' as i32 || c == '-' as i32 {
            neg = c == '-' as i32;
            c = cur.get();
        }
        if c < '0' as i32 || c > '9' as i32 {
            cur.pos = mark.0;
            cur.eof = mark.1;
            return None;
        }
        let mut x: u32 = 0;
        while c >= '0' as i32 && c <= '9' as i32 && x < u32::MAX / 10 {
            x = x * 10 + (c - '0' as i32) as u32;
            c = cur.get();
        }
        let mut y: i64 = x as i64;
        while c >= '0' as i32 && c <= '9' as i32 && y < i64::MAX / 100 {
            y = y * 10 + (c - '0' as i32) as i64;
            c = cur.get();
        }
        while c >= '0' as i32 && c <= '9' as i32 {
            c = cur.get();
        }
        cur.unget();
        Some(if neg { -y } else { y })
    }
}

enum Pin {
    Inf,
    Nan,
    More(i32),
    Fail,
}

/// musl `__floatscan` inf/nan prefix handling (`pok = 1`): `inf` + up to
/// `infinity`, rewound to 3 chars when longer; bare `NAN` (sign ignored);
/// `nan(payload)` with alnum/`_` payload, else rewind to `nan`.
fn parse_inf_nan(cur: &mut Cur, mut c: i32) -> Pin {
    const INF: &[u8; 8] = b"infinity";
    let mut i = 0usize;
    while i < 8 && (c | 32) == INF[i] as i32 {
        if i < 7 {
            c = unsafe { cur.get() };
        }
        i += 1;
    }
    if i == 3 || i == 8 || i > 3 {
        if i != 8 {
            cur.unget();
            while i > 3 {
                cur.unget();
                i -= 1;
            }
        }
        return Pin::Inf;
    }
    if i == 0 {
        const NAN: &[u8; 3] = b"nan";
        i = 0;
        while i < 3 && (c | 32) == NAN[i] as i32 {
            if i < 2 {
                c = unsafe { cur.get() };
            }
            i += 1;
        }
        if i == 3 {
            c = unsafe { cur.get() };
            if c != '(' as i32 {
                cur.unget();
                return Pin::Nan;
            }
            let mut n = 0u32;
            loop {
                c = unsafe { cur.get() };
                let ok = (c >= '0' as i32 && c <= '9' as i32)
                    || (c >= 'A' as i32 && c <= 'Z' as i32)
                    || (c >= 'a' as i32 && c <= 'z' as i32)
                    || c == '_' as i32;
                if ok {
                    n += 1;
                    continue;
                }
                if c == ')' as i32 {
                    return Pin::Nan;
                }
                cur.unget();
                let mut k = n + 1;
                while k > 0 {
                    cur.unget();
                    k -= 1;
                }
                return Pin::Nan;
            }
        }
    }
    if i != 0 {
        cur.unget();
        Pin::Fail
    } else {
        Pin::More(c)
    }
}

/// Normalize a `u128` wide value to exactly `p` bits; returns
/// `(H, e2adj, guard, sticky)`. `H != 0` required. Truncates (never
/// rounds): `guard` is the top dropped bit, `sticky` folds every lower
/// dropped bit plus the incoming `sticky`, so [`finish`] performs the one
/// and only round-to-even (two roundings would double-round halfway cases
/// in denormal results).
fn norm_u128(h: u128, e2: i64, sticky: bool, p: u32) -> (u64, i64, bool, bool) {
    let l = 128 - h.leading_zeros();
    if l > p {
        let s = l - p;
        let low = h & ((1u128 << s) - 1);
        let guard = (low >> (s - 1)) & 1 != 0;
        let rest = low & ((1u128 << (s - 1)) - 1) != 0;
        ((h >> s) as u64, e2 + s as i64, guard, sticky || rest)
    } else if l < p {
        ((h << (p - l)) as u64, e2 - (p - l) as i64, false, sticky)
    } else {
        (h as u64, e2, false, sticky)
    }
}

const NL: usize = 272;

fn limbs_len(a: &[u64; NL]) -> usize {
    let mut i = NL;
    while i > 1 && a[i - 1] == 0 {
        i -= 1;
    }
    i
}

fn limbs_bitlen(a: &[u64; NL], len: usize) -> u64 {
    64 * (len as u64 - 1) + (64 - a[len - 1].leading_zeros() as u64)
}

/// `a *= m` (`m <= 1e9`); `true` = overflow past the array (value is then
/// known-huge, caller maps to infinity).
fn mul_small(a: &mut [u64; NL], len: &mut usize, m: u64) -> bool {
    let mut carry = 0u64;
    let mut i = 0;
    while i < *len {
        let t = a[i] as u128 * m as u128 + carry as u128;
        a[i] = t as u64;
        carry = (t >> 64) as u64;
        i += 1;
    }
    if carry != 0 {
        if *len >= NL {
            return true;
        }
        a[*len] = carry;
        *len += 1;
    }
    false
}

/// Normalize a limb array (`bitlen L`) to exactly `p` bits (`H != 0`).
/// Same truncate + guard contract as [`norm_u128`].
fn norm_limbs(
    a: &mut [u64; NL],
    len: &mut usize,
    l: u64,
    e2: i64,
    p: u32,
) -> (u64, i64, bool, bool) {
    if l > p as u64 {
        let s = l - p as u64;
        let hw = ((s - 1) / 64) as usize;
        let hb = ((s - 1) % 64) as u32;
        let guard = hw < *len && (a[hw] >> hb) & 1 != 0;
        let mut rest = false;
        let mut i = 0;
        while i < hw && i < *len {
            if a[i] != 0 {
                rest = true;
                break;
            }
            i += 1;
        }
        if hw < *len && hb != 0 && a[hw] & ((1u64 << hb) - 1) != 0 {
            rest = true;
        }
        let ws = (s / 64) as usize;
        let bs = (s % 64) as u32;
        let mut j = 0;
        while j + ws < *len {
            let lo = a[j + ws] >> bs;
            let hi = if bs != 0 && j + ws + 1 < *len {
                a[j + ws + 1] << (64 - bs)
            } else {
                0
            };
            a[j] = lo | hi;
            j += 1;
        }
        while j < *len {
            a[j] = 0;
            j += 1;
        }
        *len = limbs_len(a);
        // Floor: the shifted array is the truncated value (bitlen <= p, so
        // a[0] holds it all); rounding happens once in finish().
        (a[0], e2 + s as i64, guard, rest)
    } else if l < p as u64 {
        let s = (p as u64 - l) as u32;
        let mut carry = 0u64;
        let mut i = 0;
        while i < *len {
            let nl = (a[i] << s) | carry;
            carry = a[i] >> (64 - s);
            a[i] = nl;
            i += 1;
        }
        if carry != 0 && *len < NL {
            a[*len] = carry;
            *len += 1;
        }
        (a[0], e2 - s as i64, false, false)
    } else {
        (a[0], e2, false, false)
    }
}

/// Full-width limb compare/sub/shift for the quotient path.
fn cmp_ge(a: &[u64; NL], b: &[u64; NL]) -> bool {
    let mut i = NL;
    while i > 0 {
        i -= 1;
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

fn sub_limbs(a: &mut [u64; NL], b: &[u64; NL]) {
    let mut borrow = 0u64;
    let mut i = 0;
    while i < NL {
        let t = (a[i] as u128).wrapping_sub(b[i] as u128 + borrow as u128);
        a[i] = t as u64;
        borrow = if (t >> 127) & 1 != 0 { 1 } else { 0 };
        i += 1;
    }
}

/// Exact `M * 10^E` (`E >= 0`) or `M / 10^-E` (`E < 0`) as
/// `(H: u64, e2, sticky)` with `value = H * 2^e2`, `H != 0`;
/// `Inf`/`Zero` short-circuit musl's range fast paths.
enum DecRes {
    Inf,
    Zero,
    /// `(H, e2, guard, sticky)`: `H` a `p`-bit floor, single rounding left
    /// to [`finish`].
    Wide(u64, i64, bool, bool),
}

fn dec_to_bin(m: u128, e: i64, pr: Prec) -> DecRes {
    if e > pr.emax10 {
        return DecRes::Inf;
    }
    if e.saturating_add(32) < pr.zcut10 {
        return DecRes::Zero;
    }
    if e >= 0 {
        let mut t = [0u64; NL];
        t[0] = m as u64;
        t[1] = (m >> 64) as u64;
        let mut len = if t[1] != 0 { 2 } else { 1 };
        let eu = e as u64;
        let mut q = eu / 9;
        while q > 0 {
            if mul_small(&mut t, &mut len, 1_000_000_000) {
                return DecRes::Inf;
            }
            q -= 1;
        }
        const P10: [u64; 9] = [
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
        if P10[(eu % 9) as usize] != 1 && mul_small(&mut t, &mut len, P10[(eu % 9) as usize]) {
            return DecRes::Inf;
        }
        let l = limbs_bitlen(&t, len);
        let (h, e2, guard, sticky) = norm_limbs(&mut t, &mut len, l, 0, pr.p);
        DecRes::Wide(h, e2, guard, sticky)
    } else {
        let f = (-e) as u64;
        let mut d = [0u64; NL];
        d[0] = 1;
        let mut lend = 1usize;
        let mut q = f / 9;
        while q > 0 {
            if mul_small(&mut d, &mut lend, 1_000_000_000) {
                return DecRes::Zero;
            }
            q -= 1;
        }
        const P10: [u64; 9] = [
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
        if P10[(f % 9) as usize] != 1 && mul_small(&mut d, &mut lend, P10[(f % 9) as usize]) {
            return DecRes::Zero;
        }
        lend = limbs_len(&d);
        let kbitd = limbs_bitlen(&d, lend) as i64;
        let kbitm = (128 - m.leading_zeros()) as i64;
        let k = kbitd + pr.p as i64 + 8 - kbitm;
        let kk = if k > 0 { k as u64 } else { 0 };
        // Long divide N = m << kk by D (quotient ~2^(p+8), exact remainder).
        // Textbook restoring division streams dividend bits MSB-first with
        // rem = 0, so starting the loop at `top` needs the top kbitd-1 bits
        // preloaded (rem = N >> (top+1)); starting with rem = 0 would compute
        // floor((N mod 2^(top+1))/D instead (usually 0).
        let mut rem = [0u64; NL];
        let top = kbitm + kk as i64 - kbitd;
        let r = kbitm - kbitd + 1; // == top + 1 - kk
        if r >= 0 {
            let t = m >> (r as u32);
            rem[0] = t as u64;
            rem[1] = (t >> 64) as u64;
        } else {
            // rem = m << (-r): kbitd-1 bits fanned into limbs.
            let sh = (-r) as u64;
            let ws = (sh / 64) as usize;
            let bs = (sh % 64) as u32;
            let m0 = m as u64;
            let m1 = (m >> 64) as u64;
            debug_assert!(ws + 3 <= NL);
            if bs == 0 {
                rem[ws] = m0;
                rem[ws + 1] = m1;
            } else {
                rem[ws] = m0 << bs;
                rem[ws + 1] = (m1 << bs) | (m0 >> (64 - bs));
                rem[ws + 2] = m1 >> (64 - bs);
            }
        }
        let mut qq: u128 = 0;
        let mut i = top;
        while i >= 0 {
            // rem = rem * 2 + bit_i(N)
            let mut carry = 0u64;
            let mut j = 0;
            while j < NL {
                let nl = (rem[j] << 1) | carry;
                carry = rem[j] >> 63;
                rem[j] = nl;
                j += 1;
            }
            let bit = if (i as u64) < kk {
                0
            } else {
                let jj = i as u64 - kk;
                if jj >= 128 {
                    0
                } else {
                    ((m >> jj) & 1) as u64
                }
            };
            rem[0] |= bit;
            if cmp_ge(&rem, &d) {
                sub_limbs(&mut rem, &d);
                qq |= 1u128 << (i as u32);
            }
            i -= 1;
        }
        let mut sticky = false;
        let mut j = 0;
        while j < NL {
            if rem[j] != 0 {
                sticky = true;
                break;
            }
            j += 1;
        }
        let l = 128 - qq.leading_zeros();
        debug_assert!(l >= 1);
        let (h, e2, guard, sticky) = norm_u128(qq, -(kk as i64), sticky, pr.p);
        DecRes::Wide(h, e2, guard, sticky)
    }
}

/// Pack a normal `p`-bit `h` at binary exponent `exp2`.
fn pack_normal(pr: Prec, neg: bool, h: u64, exp2: i64) -> FVal {
    match pr.p {
        24 => {
            let bits = ((neg as u32) << 31) | ((exp2 + 127) as u32) << 23 | (h as u32 & 0x7f_ffff);
            FVal::F32(bits)
        }
        53 => {
            let bits =
                ((neg as u64) << 63) | ((exp2 + 1023) as u64) << 52 | (h & 0xf_ffff_ffff_ffff);
            FVal::F64(bits)
        }
        _ => {
            let mut b = [0u8; 10];
            b[0..8].copy_from_slice(&h.to_le_bytes());
            let se = (neg as u16) << 15 | (exp2 + 16383) as u16;
            b[8..10].copy_from_slice(&se.to_le_bytes());
            FVal::F80(b)
        }
    }
}

/// Pack `(H, e2, guard, sticky)` (`H` a `p`-bit floor, `value = H*2^e2`,
/// `true >= value`, `sticky` ⟺ mass below the guard): the one and only
/// round-to-even in the pipeline. Returns `(value, erange)`; mirrors
/// musl's overflow (`ERANGE` + inf) and denormal (`ERANGE` iff inexact)
/// rules.
fn finish(pr: Prec, neg: bool, mut h: u64, e2: i64, guard: bool, sticky: bool) -> (FVal, bool) {
    if h == 0 {
        return (zero_of(pr, neg), true);
    }
    let p = pr.p as u64;
    let mut exp2 = e2.saturating_add(p as i64 - 1);
    if exp2 > pr.emax2 {
        return (inf_of(pr, neg), true);
    }
    if exp2 >= pr.emin2 {
        if guard && (sticky || (h & 1 != 0)) {
            let (nh, ov) = h.overflowing_add(1);
            if ov || (p < 64 && nh >> p != 0) {
                // Carried out of `p` bits (`ov` is the `p == 64` wrap).
                h = 1u64 << (p - 1);
                exp2 += 1;
                if exp2 > pr.emax2 {
                    return (inf_of(pr, neg), true);
                }
            } else {
                h = nh;
            }
        }
        return (pack_normal(pr, neg, h, exp2), false);
    }
    // Denormal: drop `s` bits, rounding once with `guard` below `H`.
    let s = (pr.emin2 - exp2) as u64;
    if s > 64 {
        return (zero_of(pr, neg), true);
    }
    let (kept, dh, halfdh) = if s < 64 {
        (h >> s, h & ((1u64 << s) - 1), 1u64 << (s - 1))
    } else {
        (0, h, 1u64 << 63)
    };
    let up = dh > halfdh || (dh == halfdh && (guard || sticky || (kept & 1 != 0)));
    let h2 = kept + up as u64;
    let inexact = dh != 0 || guard || sticky;
    if h2 >> (p - 1) != 0 {
        // Rounded up into normal range: exactly 2^emin2, zero fraction
        // (pack_normal would keep the stale fraction bits of h).
        let v = match pr.p {
            24 => FVal::F32(((neg as u32) << 31) | ((pr.emin2 + 127) as u32) << 23),
            53 => FVal::F64(((neg as u64) << 63) | ((pr.emin2 + 1023) as u64) << 52),
            _ => {
                let mut b = [0u8; 10];
                b[0..8].copy_from_slice(&(1u64 << 63).to_le_bytes());
                let se = ((neg as u16) << 15) | (pr.emin2 + 16383) as u16;
                b[8..10].copy_from_slice(&se.to_le_bytes());
                FVal::F80(b)
            }
        };
        return (v, inexact);
    }
    if h2 == 0 {
        return (zero_of(pr, neg), true);
    }
    let v = match pr.p {
        24 => FVal::F32(((neg as u32) << 31) | (h2 as u32 & 0x7f_ffff)),
        53 => FVal::F64(((neg as u64) << 63) | (h2 & 0xf_ffff_ffff_ffff)),
        _ => {
            let mut b = [0u8; 10];
            b[0..8].copy_from_slice(&h2.to_le_bytes());
            b[8..10].copy_from_slice(&((neg as u16) << 15).to_le_bytes());
            FVal::F80(b)
        }
    };
    (v, inexact)
}

/// Full `strtof`/`strtod`/`strtold` parse: musl `strtox` shape (whitespace,
/// sign, inf/nan, `0x` hex, decimal, `endptr`, `errno`).
///
/// # Safety
///
/// `s` must point at a valid NUL-terminated string; `endp` NULL or writable.
unsafe fn parse_float(s: *const c_char, endp: *mut *mut c_char, pr: Prec) -> FVal {
    unsafe {
        if s.is_null() {
            set_errno(EINVAL);
            return zero_of(pr, false);
        }
        let mut cur = Cur {
            s: s as *const u8,
            pos: 0,
            eof: false,
        };
        let mut c = cur.get();
        while is_space(c) {
            c = cur.get();
        }
        let mut neg = false;
        if c == '+' as i32 || c == '-' as i32 {
            neg = c == '-' as i32;
            c = cur.get();
        }
        match parse_inf_nan(&mut cur, c) {
            Pin::Inf => {
                set_endp(s, endp, cur.pos);
                return inf_of(pr, neg);
            }
            Pin::Nan => {
                set_endp(s, endp, cur.pos);
                return nan_of(pr);
            }
            Pin::Fail => {
                set_errno(EINVAL);
                set_endp(s, endp, 0);
                return zero_of(pr, false);
            }
            Pin::More(held) => {
                c = held;
            }
        }
        // Hexfloat.
        if c == '0' as i32 {
            let c2 = cur.get();
            if (c2 | 32) == 'x' as i32 {
                let zero_end = cur.pos - 1;
                return hex_parse(s, endp, pr, neg, &mut cur, zero_end);
            }
            cur.unget();
            c = '0' as i32;
        }
        // Decimal.
        let mut m: u128 = 0;
        let mut ndig: u32 = 0;
        let mut e: i64 = 0;
        let mut sticky = false;
        let mut gotdig = false;
        while c == '0' as i32 {
            gotdig = true;
            c = cur.get();
        }
        while c >= '0' as i32 && c <= '9' as i32 {
            gotdig = true;
            let d = (c - '0' as i32) as u64;
            if ndig < 32 {
                m = m * 10 + d as u128;
                ndig += 1;
            } else {
                sticky |= d != 0;
                e = e.saturating_add(1);
            }
            c = cur.get();
        }
        if c == '.' as i32 {
            c = cur.get();
            while c >= '0' as i32 && c <= '9' as i32 {
                gotdig = true;
                let d = (c - '0' as i32) as u64;
                if ndig == 0 && d == 0 {
                    e = e.saturating_sub(1);
                } else if ndig < 32 {
                    m = m * 10 + d as u128;
                    ndig += 1;
                    e = e.saturating_sub(1);
                } else {
                    sticky |= d != 0;
                }
                c = cur.get();
            }
        }
        if gotdig && (c | 32) == 'e' as i32 {
            match scanexp(&mut cur) {
                Some(e10) => {
                    e = e.saturating_add(e10);
                }
                None => {
                    cur.unget();
                }
            }
        } else {
            cur.unget();
        }
        if !gotdig {
            set_errno(EINVAL);
            set_endp(s, endp, 0);
            return zero_of(pr, false);
        }
        let end = cur.pos;
        if m == 0 {
            set_endp(s, endp, end);
            return zero_of(pr, neg);
        }
        let (h, e2, guard, inexact) = match dec_to_bin(m, e, pr) {
            DecRes::Inf => {
                set_errno(ERANGE);
                set_endp(s, endp, end);
                return inf_of(pr, neg);
            }
            DecRes::Zero => {
                set_errno(ERANGE);
                set_endp(s, endp, end);
                return zero_of(pr, neg);
            }
            DecRes::Wide(h, e2, guard, inexact) => (h, e2, guard, inexact),
        };
        let (v, erange) = finish(pr, neg, h, e2, guard, inexact || sticky);
        if erange {
            set_errno(ERANGE);
        }
        set_endp(s, endp, end);
        v
    }
}

/// Hex payload parse, factored out for clarity: cursor sits after `0x`,
/// `zero_end` is the `endptr` for the no-digits case (musl consumes `0`).
///
/// # Safety
///
/// Same contract as [`parse_float`], cursor already past `0x`.
unsafe fn hex_parse(
    s: *const c_char,
    endp: *mut *mut c_char,
    pr: Prec,
    neg: bool,
    cur: &mut Cur,
    zero_end: usize,
) -> FVal {
    unsafe {
        let mut hm: u64 = 0;
        let mut hsticky = false;
        let mut gotdig = false;
        let mut fracd: i64 = 0;
        let mut c = cur.get();
        while c == '0' as i32 {
            gotdig = true;
            c = cur.get();
        }
        let mut gotrad = false;
        if c == '.' as i32 {
            gotrad = true;
            c = cur.get();
            while c == '0' as i32 {
                gotdig = true;
                fracd = fracd.saturating_sub(1);
                c = cur.get();
            }
        }
        let mut kept: u32 = 0;
        let mut in_frac = gotrad;
        loop {
            if c == '.' as i32 {
                if gotrad {
                    break;
                }
                gotrad = true;
                in_frac = true;
                c = cur.get();
                continue;
            }
            let d = digit_val(c);
            if d > 15 {
                break;
            }
            gotdig = true;
            if kept < 16 {
                hm = hm * 16 + d as u64;
                kept += 1;
            } else {
                hsticky |= d != 0;
            }
            if in_frac {
                fracd = fracd.saturating_sub(1);
            }
            c = cur.get();
        }
        if !gotdig {
            set_endp(s, endp, zero_end);
            return zero_of(pr, neg);
        }
        let mut e2 = fracd.saturating_mul(4);
        if (c | 32) == 'p' as i32 {
            match scanexp(cur) {
                Some(p10) => {
                    e2 = e2.saturating_add(p10);
                }
                None => {
                    cur.unget();
                }
            }
        } else {
            cur.unget();
        }
        let end = cur.pos;
        if hm == 0 {
            set_endp(s, endp, end);
            return zero_of(pr, neg);
        }
        let (h, e, guard, inexact) = norm_u128(hm as u128, e2, hsticky, pr.p);
        let (v, erange) = finish(pr, neg, h, e, guard, inexact);
        if erange {
            set_errno(ERANGE);
        }
        set_endp(s, endp, end);
        v
    }
}

/// musl `src/stdlib/strtod.c:17-20`.
///
/// # Safety
///
/// `s` NUL-terminated; `endp` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn strtof(s: *const c_char, endp: *mut *mut c_char) -> c_float {
    unsafe {
        let FVal::F32(b) = parse_float(s, endp, P32) else {
            return 0.0;
        };
        f32::from_bits(b)
    }
}

/// musl `src/stdlib/strtod.c:22-25`.
///
/// # Safety
///
/// `s` NUL-terminated; `endp` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn strtod(s: *const c_char, endp: *mut *mut c_char) -> c_double {
    unsafe {
        let FVal::F64(b) = parse_float(s, endp, P64) else {
            return 0.0;
        };
        f64::from_bits(b)
    }
}

/// Fill 10-byte extended `out` (musl `strtox` with `prec = 2`).
///
/// # Safety
///
/// `s` NUL-terminated; `endp` NULL or writable; `out` writable 10 bytes.
unsafe fn strtold_into(s: *const c_char, endp: *mut *mut c_char, out: *mut u8) {
    unsafe {
        let FVal::F80(b) = parse_float(s, endp, P80) else {
            for i in 0..10 {
                *out.add(i) = 0;
            }
            return;
        };
        let mut i = 0;
        while i < 10 {
            *out.add(i) = b[i];
            i += 1;
        }
    }
}

/// musl `src/stdlib/strtod.c:27-30`.
///
/// SysV x86_64 returns `long double` in ST(0), which stable Rust cannot
/// name: the exact 10-byte extended value is computed in integer limbs and
/// loaded with one `fldt`, so C callers read a correct 80-bit result.
/// (Returning `f64` here would leave ST(0) garbage — never do that.)
///
/// # Safety
///
/// `s` NUL-terminated; `endp` NULL or writable. Leaves exactly one value
/// pushed on the x87 stack, per the ABI.
#[no_mangle]
pub unsafe extern "C" fn strtold(s: *const c_char, endp: *mut *mut c_char) {
    unsafe {
        let mut ext = [0u8; 10];
        strtold_into(s, endp, ext.as_mut_ptr());
        core::arch::asm!("fldt ({0})", in(reg) ext.as_ptr(), options(att_syntax, nostack, preserves_flags));
    }
}

/// musl `src/stdlib/atof.c:4-7`.
///
/// # Safety
///
/// `s` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn atof(s: *const c_char) -> c_double {
    unsafe { strtod(s, null_mut()) }
}

/// musl `src/stdlib/atoi.c`: negative accumulation (exact at `INT_MIN`).
///
/// # Safety
///
/// `s` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn atoi(s: *const c_char) -> c_int {
    unsafe {
        if s.is_null() {
            return 0;
        }
        let mut p = s as *const u8;
        while *p == b' ' || (*p >= 9 && *p <= 13) {
            p = p.add(1);
        }
        let mut neg = false;
        if *p == b'-' || *p == b'+' {
            neg = *p == b'-';
            p = p.add(1);
        }
        let mut n: c_int = 0;
        while *p >= b'0' && *p <= b'9' {
            n = n.wrapping_mul(10).wrapping_sub((*p - b'0') as c_int);
            p = p.add(1);
        }
        if neg {
            n
        } else {
            n.wrapping_neg()
        }
    }
}

/// musl `src/stdlib/atol.c`.
///
/// # Safety
///
/// `s` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn atol(s: *const c_char) -> c_long {
    unsafe {
        if s.is_null() {
            return 0;
        }
        let mut p = s as *const u8;
        while *p == b' ' || (*p >= 9 && *p <= 13) {
            p = p.add(1);
        }
        let mut neg = false;
        if *p == b'-' || *p == b'+' {
            neg = *p == b'-';
            p = p.add(1);
        }
        let mut n: c_long = 0;
        while *p >= b'0' && *p <= b'9' {
            n = n.wrapping_mul(10).wrapping_sub((*p - b'0') as c_long);
            p = p.add(1);
        }
        if neg {
            n
        } else {
            n.wrapping_neg()
        }
    }
}

/// musl `src/stdlib/atoll.c`.
///
/// # Safety
///
/// `s` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn atoll(s: *const c_char) -> c_longlong {
    unsafe {
        if s.is_null() {
            return 0;
        }
        let mut p = s as *const u8;
        while *p == b' ' || (*p >= 9 && *p <= 13) {
            p = p.add(1);
        }
        let mut neg = false;
        if *p == b'-' || *p == b'+' {
            neg = *p == b'-';
            p = p.add(1);
        }
        let mut n: c_longlong = 0;
        while *p >= b'0' && *p <= b'9' {
            n = n.wrapping_mul(10).wrapping_sub((*p - b'0') as c_longlong);
            p = p.add(1);
        }
        if neg {
            n
        } else {
            n.wrapping_neg()
        }
    }
}

// ---- ecvt/fcvt/gcvt (musl shapes over `crate::stdio::dtoa`) ------------------

/// `ecvt` static buffer (musl `ecvt.c:7`); MT-unsafe like musl's.
static mut ECVT_BUF: [c_char; 16] = [0; 16];

/// musl `src/stdlib/ecvt.c`: `n` digits of `x` (`%.*e`, clamped to 15),
/// decimal point after `*dp`, sign in `*sign`.
///
/// # Safety
///
/// `dp`/`sign` must be writable; result lives in a shared static buffer.
#[no_mangle]
pub unsafe extern "C" fn ecvt(
    x: c_double,
    n: c_int,
    dp: *mut c_int,
    sign: *mut c_int,
) -> *mut c_char {
    unsafe {
        if dp.is_null() || sign.is_null() {
            return null_mut();
        }
        let mut nn = n;
        if nn.wrapping_sub(1) as c_uint > 15 {
            nn = 15;
        }
        let buf = core::ptr::addr_of_mut!(ECVT_BUF);
        if !x.is_finite() {
            let word = if x.is_nan() { b"nan" } else { b"inf" };
            (*buf)[0] = word[0] as c_char;
            (*buf)[1] = word[1] as c_char;
            (*buf)[2] = word[2] as c_char;
            (*buf)[3] = 0;
            *dp = 0;
            *sign = x.is_sign_negative() as c_int;
            return buf as *mut c_char;
        }
        let neg = x.is_sign_negative();
        let mut tmp = [0u8; 32];
        let spec = FmtSpec {
            spec: b'e',
            w: 0,
            prec: (nn - 1) as isize,
            flags: 0,
        };
        let len = fmt_f64_bits(&mut tmp, x.to_bits(), &spec);
        // `[-]d[.ddd]e±xx` -> digits + exponent.
        let mut i = 0usize;
        if len > 0 && tmp[0] == b'-' {
            i = 1;
        }
        if i >= len || tmp[i] < b'0' || tmp[i] > b'9' {
            (*buf)[0] = b'0' as c_char;
            (*buf)[1] = 0;
            *dp = 1;
            *sign = neg as c_int;
            return buf as *mut c_char;
        }
        let mut j = 0usize;
        (*buf)[j] = tmp[i] as c_char;
        j += 1;
        i += 1;
        if i < len && tmp[i] == b'.' {
            i += 1;
            while i < len && tmp[i] != b'e' && tmp[i] != b'E' {
                if j < 15 {
                    (*buf)[j] = tmp[i] as c_char;
                    j += 1;
                }
                i += 1;
            }
        }
        let mut exp: c_int = 0;
        if i < len && (tmp[i] == b'e' || tmp[i] == b'E') {
            i += 1;
            let mut esign = 1;
            if i < len && (tmp[i] == b'+' || tmp[i] == b'-') {
                if tmp[i] == b'-' {
                    esign = -1;
                }
                i += 1;
            }
            while i < len && tmp[i] >= b'0' && tmp[i] <= b'9' {
                exp = exp * 10 + (tmp[i] - b'0') as c_int;
                i += 1;
            }
            exp *= esign;
        }
        (*buf)[j] = 0;
        *dp = exp + 1;
        *sign = neg as c_int;
        buf as *mut c_char
    }
}

/// musl `src/stdlib/fcvt.c`: `n` digits after the point (`%.​*f`, `n`
/// clamped to 1400); tiny values return into the static `"000..."` tail.
///
/// # Safety
///
/// `dp`/`sign` must be writable; result static (see [`ecvt`]).
#[no_mangle]
pub unsafe extern "C" fn fcvt(
    x: c_double,
    n: c_int,
    dp: *mut c_int,
    sign: *mut c_int,
) -> *mut c_char {
    unsafe {
        if dp.is_null() || sign.is_null() {
            return null_mut();
        }
        let mut nn = n;
        if nn as c_uint > 1400 {
            nn = 1400;
        }
        let mut tmp = [0u8; 1500];
        let spec = FmtSpec {
            spec: b'f',
            w: 0,
            prec: nn as isize,
            flags: 0,
        };
        let len = fmt_f64_bits(&mut tmp, x.to_bits(), &spec);
        let mut i = 0usize;
        if len > 0 && tmp[0] == b'-' {
            i = 1;
        }
        // Split `int.frac`.
        let mut dot = len;
        let mut k = i;
        while k < len {
            if tmp[k] == b'.' {
                dot = k;
                break;
            }
            k += 1;
        }
        let int_len = dot - i;
        let lz: c_int = if int_len == 1 && tmp[i] == b'0' {
            let mut z = 0;
            let mut k = dot + 1;
            while k < len && tmp[k] == b'0' {
                z += 1;
                k += 1;
            }
            z
        } else {
            -(int_len as c_int)
        };
        if nn <= lz {
            *sign = i as c_int;
            *dp = 1;
            let mut m = nn;
            if m as c_uint > 14 {
                m = 14;
            }
            return (c"000000000000000".as_ptr() as *mut c_char).add((14 - m) as usize);
        }
        ecvt(x, nn - lz, dp, sign)
    }
}

/// musl `src/stdlib/gcvt.c:8-12`: `%.*g` into the caller's buffer.
///
/// # Safety
///
/// `b` must fit the output (bounded: a `double` prints < 800 chars).
#[no_mangle]
pub unsafe extern "C" fn gcvt(x: c_double, n: c_int, b: *mut c_char) -> *mut c_char {
    unsafe {
        if b.is_null() {
            return null_mut();
        }
        let mut prec = n;
        if prec > 1100 {
            prec = 1100;
        }
        let mut tmp = [0u8; 1024];
        let spec = FmtSpec {
            spec: b'g',
            w: 0,
            prec: prec as isize,
            flags: 0,
        };
        let len = fmt_f64_bits(&mut tmp, x.to_bits(), &spec);
        let mut k = 0usize;
        while k < len {
            *b.add(k) = tmp[k] as c_char;
            k += 1;
        }
        *b.add(len) = 0;
        b
    }
}

// ---- qsort / qsort_r / bsearch (musl smoothsort, verbatim algorithm) ----------

/// 3-arg comparator (musl `qsort.c:35` `cmpfun`).
type Cmp3 = unsafe extern "C" fn(*const c_void, *const c_void, *mut c_void) -> c_int;

/// Working-set slots: musl `qsort.c:97` (`16 * sizeof(size_t)`).
const AR_LEN: usize = 16 * core::mem::size_of::<usize>();
const AR_MASK: usize = AR_LEN - 1;
/// Leonardo table slots: musl `qsort.c:168` (`12 * sizeof(size_t)`).
const LP_LEN: usize = 12 * core::mem::size_of::<usize>();

/// musl `qsort.c:39-43` (`a_ctz_l` is `trailing_zeros`).
#[inline]
fn pntz(p: &[usize; 2]) -> i32 {
    if p[0] != 1 {
        p[0].wrapping_sub(1).trailing_zeros() as i32
    } else if p[1] != 0 {
        64 + p[1].trailing_zeros() as i32
    } else {
        0
    }
}

/// musl `qsort.c:68-79` (`n == 0` only arises with `p == (1, 0)`, a no-op).
#[inline]
fn shl(p: &mut [usize; 2], mut n: i32) {
    if n <= 0 {
        debug_assert!(n == 0);
        return;
    }
    if n >= 64 {
        n -= 64;
        p[1] = p[0];
        p[0] = 0;
        if n == 0 {
            return;
        }
    }
    let n = n as u32;
    p[1] = (p[1] << n) | (p[0] >> (64 - n));
    p[0] <<= n;
}

/// musl `qsort.c:81-92` (same `n == 0` note).
#[inline]
fn shr(p: &mut [usize; 2], mut n: i32) {
    if n <= 0 {
        debug_assert!(n == 0);
        return;
    }
    if n >= 64 {
        n -= 64;
        p[0] = p[1];
        p[1] = 0;
        if n == 0 {
            return;
        }
    }
    let n = n as u32;
    p[0] = (p[0] >> n) | (p[1] << (64 - n));
    p[1] >>= n;
}

/// musl `qsort.c:45-65` element rotation through a 256-byte window.
///
/// # Safety
///
/// `ar[0..=n]` must point at `width`-byte elements (plus scratch at `ar[n]`).
unsafe fn cycle(width: usize, ar: &mut [*mut u8; AR_LEN], n: usize) {
    unsafe {
        if n < 2 {
            return;
        }
        let mut tmp = [0u8; 256];
        ar[n] = tmp.as_mut_ptr();
        let mut w = width;
        while w > 0 {
            let l = if 256 < w { 256 } else { w };
            core::ptr::copy_nonoverlapping(ar[0], ar[n], l);
            let mut i = 0;
            while i < n {
                core::ptr::copy_nonoverlapping(ar[i + 1], ar[i], l);
                ar[i] = ar[i].wrapping_add(l);
                i += 1;
            }
            w -= l;
        }
    }
}

/// musl `qsort.c:100-125`.
///
/// # Safety
///
/// `head` points at a heap root of `width`-byte elements; `cmp` valid.
unsafe fn sift(
    head: *mut u8,
    width: usize,
    cmp: Cmp3,
    arg: *mut c_void,
    mut pshift: i32,
    lp: &[usize; LP_LEN],
) {
    unsafe {
        let mut ar: [*mut u8; AR_LEN] = [null_mut(); AR_LEN];
        let mut i: usize = 1;
        let mut head = head;
        ar[0] = head;
        while pshift > 1 {
            let rt = head.wrapping_sub(width);
            let lf = rt.wrapping_sub(lp[(pshift - 2) as usize]);
            if cmp(ar[0] as *const c_void, lf as *const c_void, arg) >= 0
                && cmp(ar[0] as *const c_void, rt as *const c_void, arg) >= 0
            {
                break;
            }
            if cmp(lf as *const c_void, rt as *const c_void, arg) >= 0 {
                ar[i & AR_MASK] = lf;
                i = i.wrapping_add(1);
                head = lf;
                pshift -= 1;
            } else {
                ar[i & AR_MASK] = rt;
                i = i.wrapping_add(1);
                head = rt;
                pshift -= 2;
            }
        }
        cycle(width, &mut ar, i & AR_MASK);
    }
}

/// musl `qsort.c:127-164`.
///
/// # Safety
///
/// Same contract as [`sift`].
///
/// Eight params mirror musl's smoothsort helper signature exactly.
#[allow(clippy::too_many_arguments)]
unsafe fn trinkle(
    head: *mut u8,
    width: usize,
    cmp: Cmp3,
    arg: *mut c_void,
    pp: &[usize; 2],
    mut pshift: i32,
    mut trusty: i32,
    lp: &[usize; LP_LEN],
) {
    unsafe {
        let mut p = [pp[0], pp[1]];
        let mut ar: [*mut u8; AR_LEN] = [null_mut(); AR_LEN];
        let mut i: usize = 1;
        let mut head = head;
        ar[0] = head;
        while p[0] != 1 || p[1] != 0 {
            let stepson = head.wrapping_sub(lp[pshift as usize]);
            if cmp(stepson as *const c_void, ar[0] as *const c_void, arg) <= 0 {
                break;
            }
            if trusty == 0 && pshift > 1 {
                let rt = head.wrapping_sub(width);
                let lf = rt.wrapping_sub(lp[(pshift - 2) as usize]);
                if cmp(rt as *const c_void, stepson as *const c_void, arg) >= 0
                    || cmp(lf as *const c_void, stepson as *const c_void, arg) >= 0
                {
                    break;
                }
            }
            ar[i & AR_MASK] = stepson;
            i = i.wrapping_add(1);
            head = stepson;
            let trail = pntz(&p);
            shr(&mut p, trail);
            pshift += trail;
            trusty = 0;
        }
        if trusty == 0 {
            cycle(width, &mut ar, i & AR_MASK);
            sift(head, width, cmp, arg, pshift, lp);
        }
    }
}

/// musl `qsort.c:166-227` (`__qsort_r`).
///
/// # Safety
///
/// `base` must cover `nel * width` bytes; `cmp` valid; `arg` passed through.
unsafe fn qsort_r_inner(base: *mut u8, nel: usize, width: usize, cmp: Cmp3, arg: *mut c_void) {
    unsafe {
        let mut lp = [0usize; LP_LEN];
        let size = width.wrapping_mul(nel);
        if size == 0 {
            return;
        }
        let mut head = base;
        let high = base.wrapping_add(size).wrapping_sub(width);
        lp[0] = width;
        lp[1] = width;
        let mut i = 2;
        while i + 1 < LP_LEN {
            let v = lp[i - 2].wrapping_add(lp[i - 1]).wrapping_add(width);
            lp[i] = v;
            if v >= size {
                break;
            }
            i += 1;
        }
        let mut p = [1usize, 0usize];
        let mut pshift: i32 = 1;
        while head < high {
            if p[0] & 3 == 3 {
                sift(head, width, cmp, arg, pshift, &lp);
                shr(&mut p, 2);
                pshift += 2;
            } else {
                // `pshift == 0` cannot reach here: it is only set by the
                // `pshift == 1` arm below, after which `p[0] |= 1` forces
                // `p[0] & 3 == 3` (odd `p[0]` gives `2*odd+1 ≡ 3 mod 4),
                // so the next iteration takes the branch above.
                let need = if pshift <= 0 {
                    0
                } else {
                    lp[(pshift - 1) as usize]
                };
                if need >= (high as usize).wrapping_sub(head as usize) {
                    trinkle(head, width, cmp, arg, &p, pshift, 0, &lp);
                } else {
                    sift(head, width, cmp, arg, pshift, &lp);
                }
                if pshift == 1 {
                    shl(&mut p, 1);
                    pshift = 0;
                } else {
                    shl(&mut p, pshift - 1);
                    pshift = 1;
                }
            }
            p[0] |= 1;
            head = head.wrapping_add(width);
        }
        trinkle(head, width, cmp, arg, &p, pshift, 0, &lp);
        while pshift != 1 || p[0] != 1 || p[1] != 0 {
            if pshift <= 1 {
                let trail = pntz(&p);
                shr(&mut p, trail);
                pshift += trail;
            } else {
                shl(&mut p, 2);
                pshift -= 2;
                p[0] ^= 7;
                shr(&mut p, 1);
                trinkle(
                    head.wrapping_sub(lp[pshift as usize]).wrapping_sub(width),
                    width,
                    cmp,
                    arg,
                    &p,
                    pshift + 1,
                    1,
                    &lp,
                );
                shl(&mut p, 1);
                p[0] |= 1;
                trinkle(
                    head.wrapping_sub(width),
                    width,
                    cmp,
                    arg,
                    &p,
                    pshift,
                    1,
                    &lp,
                );
            }
            head = head.wrapping_sub(width);
        }
    }
}

/// musl `src/stdlib/qsort_nr.c` + `qsort.c` smoothsort; a NULL comparator
/// is a no-op (musl would fault).
///
/// # Safety
///
/// `base` must cover `nel * width` bytes; `compar` valid if non-NULL.
#[no_mangle]
pub unsafe extern "C" fn qsort(
    base: *mut c_void,
    nel: usize,
    width: usize,
    compar: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>,
) {
    unsafe {
        unsafe extern "C" fn wrap(a: *const c_void, b: *const c_void, ctx: *mut c_void) -> c_int {
            unsafe {
                let f =
                    *(ctx as *const unsafe extern "C" fn(*const c_void, *const c_void) -> c_int);
                f(a, b)
            }
        }
        let compar = match compar {
            Some(f) => f,
            None => return,
        };
        if base.is_null() {
            return;
        }
        qsort_r_inner(
            base as *mut u8,
            nel,
            width,
            wrap,
            &compar as *const _ as *mut c_void,
        );
    }
}

/// musl `qsort.c:229` (`qsort_r` is the `__qsort_r` alias target).
///
/// # Safety
///
/// `base` must cover `nel * width` bytes; `compar` valid if non-NULL.
#[no_mangle]
pub unsafe extern "C" fn qsort_r(
    base: *mut c_void,
    nel: usize,
    width: usize,
    compar: Option<unsafe extern "C" fn(*const c_void, *const c_void, *mut c_void) -> c_int>,
    arg: *mut c_void,
) {
    unsafe {
        let cmp = match compar {
            Some(f) => f,
            None => return,
        };
        if base.is_null() {
            return;
        }
        qsort_r_inner(base as *mut u8, nel, width, cmp, arg);
    }
}

/// musl `src/stdlib/bsearch.c`.
///
/// # Safety
///
/// `base` must cover `nel * width` bytes; `compar` valid if non-NULL.
#[no_mangle]
pub unsafe extern "C" fn bsearch(
    key: *const c_void,
    base: *const c_void,
    nel: usize,
    width: usize,
    compar: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>,
) -> *mut c_void {
    unsafe {
        let cmp = match compar {
            Some(f) => f,
            None => return null_mut(),
        };
        let mut b = base as *const u8;
        let mut n = nel;
        while n > 0 {
            let t = b.wrapping_add(width.wrapping_mul(n / 2));
            let s = cmp(key, t as *const c_void);
            if s < 0 {
                n /= 2;
            } else if s > 0 {
                b = t.wrapping_add(width);
                n -= n / 2 + 1;
            } else {
                return t as *mut c_void;
            }
        }
        null_mut()
    }
}

// ---- abs / div families ------------------------------------------------------

/// musl `src/stdlib/abs.c` (`wrapping_neg` is what `negl` does at `MIN`).
///
/// # Safety
///
/// Pure integer op; `unsafe` for surface uniformity.
#[no_mangle]
pub unsafe extern "C" fn abs(a: c_int) -> c_int {
    if a > 0 {
        a
    } else {
        a.wrapping_neg()
    }
}

/// musl `src/stdlib/labs.c`.
///
/// # Safety
///
/// Pure integer op; `unsafe` for surface uniformity.
#[no_mangle]
pub unsafe extern "C" fn labs(a: c_long) -> c_long {
    if a > 0 {
        a
    } else {
        a.wrapping_neg()
    }
}

/// musl `src/stdlib/llabs.c`.
///
/// # Safety
///
/// Pure integer op; `unsafe` for surface uniformity.
#[no_mangle]
pub unsafe extern "C" fn llabs(a: c_longlong) -> c_longlong {
    if a > 0 {
        a
    } else {
        a.wrapping_neg()
    }
}

/// musl `src/stdlib/imaxabs.c`.
///
/// # Safety
///
/// Pure integer op; `unsafe` for surface uniformity.
#[no_mangle]
pub unsafe extern "C" fn imaxabs(a: intmax_t) -> intmax_t {
    if a > 0 {
        a
    } else {
        a.wrapping_neg()
    }
}

/// musl `src/stdlib/div.c` (C truncation; zero divisor traps like `idiv`).
///
/// # Safety
///
/// Pure integer op; `unsafe` for surface uniformity.
#[no_mangle]
pub unsafe extern "C" fn div(num: c_int, den: c_int) -> div_t {
    div_t {
        quot: num / den,
        rem: num % den,
    }
}

/// musl `src/stdlib/ldiv.c`.
///
/// # Safety
///
/// Pure integer op; `unsafe` for surface uniformity.
#[no_mangle]
pub unsafe extern "C" fn ldiv(num: c_long, den: c_long) -> ldiv_t {
    ldiv_t {
        quot: num / den,
        rem: num % den,
    }
}

/// musl `src/stdlib/lldiv.c`.
///
/// # Safety
///
/// Pure integer op; `unsafe` for surface uniformity.
#[no_mangle]
pub unsafe extern "C" fn lldiv(num: c_longlong, den: c_longlong) -> lldiv_t {
    lldiv_t {
        quot: num / den,
        rem: num % den,
    }
}

/// musl `src/stdlib/imaxdiv.c`.
///
/// # Safety
///
/// Pure integer op; `unsafe` for surface uniformity.
#[no_mangle]
pub unsafe extern "C" fn imaxdiv(num: intmax_t, den: intmax_t) -> imaxdiv_t {
    imaxdiv_t {
        quot: num / den,
        rem: num % den,
    }
}

// ---- a64l / l64a / getsubopt --------------------------------------------------

/// musl `src/misc/a64l.c:6-10` base-64 alphabet.
const A64_DIGITS: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// musl `src/misc/a64l.c:12-24`.
///
/// # Safety
///
/// `s` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn a64l(s: *const c_char) -> c_long {
    unsafe {
        if s.is_null() {
            return 0;
        }
        let mut x: u32 = 0;
        let mut e = 0u32;
        let mut p = s as *const u8;
        while e < 36 && *p != 0 {
            let mut v = 64u32;
            let mut i = 0usize;
            while i < 64 {
                if A64_DIGITS[i] == *p {
                    v = i as u32;
                    break;
                }
                i += 1;
            }
            if v == 64 {
                break;
            }
            x |= v << e;
            e += 6;
            p = p.add(1);
        }
        x as i32 as c_long
    }
}

/// `l64a` static buffer (musl `a64l.c:22`); MT-unsafe like musl's.
static mut L64A_BUF: [c_char; 7] = [0; 7];

/// musl `src/misc/a64l.c:26-35`.
///
/// # Safety
///
/// Result lives in a shared static buffer.
#[no_mangle]
pub unsafe extern "C" fn l64a(x0: c_long) -> *mut c_char {
    unsafe {
        let buf = core::ptr::addr_of_mut!(L64A_BUF);
        let mut x = x0 as u32;
        let mut p = buf as *mut u8;
        while x != 0 {
            *p = A64_DIGITS[(x & 63) as usize];
            p = p.add(1);
            x >>= 6;
        }
        *p = 0;
        buf as *mut c_char
    }
}

/// NUL-terminated length (local; `string.rs` exports no `strlen`).
///
/// # Safety
///
/// `s` must point at a valid NUL-terminated string.
unsafe fn c_strlen(s: *const c_char) -> usize {
    unsafe {
        let mut n = 0usize;
        while *s.add(n) != 0 {
            n += 1;
        }
        n
    }
}

/// musl `src/misc/getsubopt.c` over `crate::string` primitives.
///
/// # Safety
///
/// `opt`/`val` writable pointers; `*opt` a mutable NUL-terminated string;
/// `keys` a NULL-terminated list of NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn getsubopt(
    opt: *mut *mut c_char,
    keys: *const *mut c_char,
    val: *mut *mut c_char,
) -> c_int {
    unsafe {
        if opt.is_null() || (*opt).is_null() || keys.is_null() || val.is_null() {
            return -1;
        }
        let s = *opt;
        *val = null_mut();
        let comma = crate::string::strchr(s, ',' as c_int);
        if !comma.is_null() {
            *comma = 0;
            *opt = comma.add(1);
        } else {
            *opt = s.add(c_strlen(s));
        }
        let mut i = 0usize;
        loop {
            let k = *keys.add(i);
            if k.is_null() {
                break;
            }
            let l = c_strlen(k);
            if crate::string::strncmp(k, s, l) == 0 {
                if *s.add(l) == '=' as c_char {
                    *val = s.add(l + 1);
                } else if *s.add(l) != 0 {
                    i += 1;
                    continue;
                }
                return i as c_int;
            }
            i += 1;
        }
        -1
    }
}

// ---- tests -------------------------------------------------------------------

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use core::ffi::{c_char, c_int, c_void};
    use core::ptr::null_mut;

    use crate::errno::{__errno_location, errno_load, errno_store};

    fn reset_errno() {
        unsafe {
            errno_store(__errno_location(), 0);
        }
    }

    fn last_errno() -> c_int {
        unsafe { errno_load(__errno_location()) }
    }

    fn end_off(s: *const c_char, end: *mut c_char) -> usize {
        (end as usize).wrapping_sub(s as usize)
    }

    #[test]
    fn strtol_bases_and_prefixes() {
        let _guard = crate::ldso::testlock::lock();
        let mut end: *mut c_char = null_mut();
        unsafe {
            reset_errno();
            let s = c"123".as_ptr();
            assert_eq!(strtol(s, &mut end, 10), 123);
            assert_eq!(end_off(s, end), 3);
            assert_eq!(last_errno(), 0);
            let s = c"  -42abc".as_ptr();
            assert_eq!(strtol(s, &mut end, 10), -42);
            assert_eq!(end_off(s, end), 5);
            let s = c"+0x1F".as_ptr();
            assert_eq!(strtol(s, &mut end, 0), 31);
            assert_eq!(end_off(s, end), 5);
            let s = c"010".as_ptr();
            assert_eq!(strtol(s, &mut end, 0), 8);
            let s = c"010".as_ptr();
            assert_eq!(strtol(s, &mut end, 10), 10);
            let s = c"0b101".as_ptr();
            assert_eq!(strtol(s, &mut end, 0), 0);
            assert_eq!(end_off(s, end), 1);
            let s = c"zz".as_ptr();
            assert_eq!(strtol(s, &mut end, 36), 35 * 36 + 35);
            assert_eq!(end_off(s, end), 2);
            let s = c"101".as_ptr();
            assert_eq!(strtol(s, &mut end, 2), 5);
            let s = c"77".as_ptr();
            assert_eq!(strtol(s, &mut end, 8), 63);
            // Bare 0x consumes only the 0.
            let s = c"0x".as_ptr();
            reset_errno();
            assert_eq!(strtol(s, &mut end, 0), 0);
            assert_eq!(end_off(s, end), 1);
            assert_eq!(last_errno(), 0);
            let s = c"0x".as_ptr();
            assert_eq!(strtol(s, &mut end, 16), 0);
            assert_eq!(end_off(s, end), 1);
            // No conversion: endptr at start, EINVAL.
            let s = c"xyz".as_ptr();
            reset_errno();
            assert_eq!(strtol(s, &mut end, 10), 0);
            assert_eq!(end_off(s, end), 0);
            assert_eq!(last_errno(), EINVAL);
            let s = c"  -xyz".as_ptr();
            reset_errno();
            assert_eq!(strtol(s, &mut end, 0), 0);
            assert_eq!(end_off(s, end), 0);
            assert_eq!(last_errno(), EINVAL);
            let s = c"".as_ptr();
            reset_errno();
            assert_eq!(strtol(s, &mut end, 10), 0);
            assert_eq!(last_errno(), EINVAL);
            reset_errno();
            assert_eq!(strtol(s, &mut end, 37), 0);
            assert_eq!(last_errno(), EINVAL);
            reset_errno();
            assert_eq!(strtol(s, &mut end, 1), 0);
            assert_eq!(last_errno(), EINVAL);
        }
    }

    #[test]
    fn strtol_clamps() {
        let _guard = crate::ldso::testlock::lock();
        let mut end: *mut c_char = null_mut();
        unsafe {
            let s = c"9223372036854775807".as_ptr();
            reset_errno();
            assert_eq!(strtol(s, &mut end, 10), c_long::MAX);
            assert_eq!(last_errno(), 0);
            let s = c"9223372036854775808".as_ptr();
            reset_errno();
            assert_eq!(strtol(s, &mut end, 10), c_long::MAX);
            assert_eq!(last_errno(), ERANGE);
            assert_eq!(end_off(s, end), 19);
            let s = c"-9223372036854775808".as_ptr();
            reset_errno();
            assert_eq!(strtol(s, &mut end, 10), c_long::MIN);
            assert_eq!(last_errno(), 0);
            let s = c"-9223372036854775809".as_ptr();
            reset_errno();
            assert_eq!(strtol(s, &mut end, 10), c_long::MIN);
            assert_eq!(last_errno(), ERANGE);
            let s = c"99999999999999999999999".as_ptr();
            reset_errno();
            assert_eq!(strtol(s, &mut end, 10), c_long::MAX);
            assert_eq!(last_errno(), ERANGE);
            assert_eq!(end_off(s, end), 23);
            // strtoll/strtoimax share the signed engine.
            let s = c"-9223372036854775809".as_ptr();
            reset_errno();
            assert_eq!(strtoll(s, &mut end, 10), c_longlong::MIN);
            assert_eq!(last_errno(), ERANGE);
            let s = c"9223372036854775808".as_ptr();
            reset_errno();
            assert_eq!(strtoimax(s, &mut end, 10), intmax_t::MAX);
            assert_eq!(last_errno(), ERANGE);
            // Unsigned: wrap on leading '-', clamp at MAX+1.
            let s = c"-1".as_ptr();
            reset_errno();
            assert_eq!(strtoul(s, &mut end, 10), c_ulong::MAX);
            assert_eq!(last_errno(), 0);
            let s = c"18446744073709551615".as_ptr();
            reset_errno();
            assert_eq!(strtoull(s, &mut end, 10), u64::MAX);
            assert_eq!(last_errno(), 0);
            let s = c"18446744073709551616".as_ptr();
            reset_errno();
            assert_eq!(strtoumax(s, &mut end, 10), u64::MAX);
            assert_eq!(last_errno(), ERANGE);
            let s = c"0xFFFFFFFFFFFFFFFFF".as_ptr();
            reset_errno();
            assert_eq!(strtoul(s, &mut end, 16), c_ulong::MAX);
            assert_eq!(last_errno(), ERANGE);
        }
    }

    #[test]
    fn atoi_family() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            assert_eq!(atoi(c"  -0012abc".as_ptr()), -12);
            assert_eq!(atoi(c"+7".as_ptr()), 7);
            assert_eq!(atoi(c"2147483647".as_ptr()), c_int::MAX);
            assert_eq!(atoi(c"-2147483648".as_ptr()), c_int::MIN);
            assert_eq!(atol(c"-9223372036854775808".as_ptr()), c_long::MIN);
            assert_eq!(atoll(c"9223372036854775807".as_ptr()), 9223372036854775807);
            assert_eq!(atof(c"0.5".as_ptr()), 0.5);
        }
    }

    #[test]
    fn strtod_vectors() {
        let _guard = crate::ldso::testlock::lock();
        let mut end: *mut c_char = null_mut();
        unsafe {
            reset_errno();
            let s = c"0.1".as_ptr();
            assert_eq!(strtod(s, &mut end).to_bits(), 0x3FB9_9999_9999_999Au64);
            assert_eq!(end_off(s, end), 3);
            assert_eq!(last_errno(), 0);
            let s = c"3.141592653589793".as_ptr();
            assert_eq!(strtod(s, &mut end).to_bits(), 0x4009_21FB_5444_2D18u64);
            let s = c"1e300".as_ptr();
            assert_eq!(
                strtod(s, &mut end).to_bits(),
                "1e300".parse::<f64>().unwrap().to_bits()
            );
            let s = c"5e-324".as_ptr();
            reset_errno();
            assert_eq!(strtod(s, &mut end).to_bits(), 1);
            // Inexact tiny result: musl and glibc both set ERANGE here
            // (verified against system libc, errno 34).
            assert_eq!(last_errno(), ERANGE);
            let s = c"2.5e-324".as_ptr();
            assert_eq!(strtod(s, &mut end).to_bits(), 1);
            let s = c"1e-324".as_ptr();
            reset_errno();
            assert_eq!(strtod(s, &mut end).to_bits(), 0);
            assert_eq!(last_errno(), ERANGE);
            let s = c"1e309".as_ptr();
            reset_errno();
            assert_eq!(strtod(s, &mut end), f64::INFINITY);
            assert_eq!(last_errno(), ERANGE);
            let s = c"1.7976931348623159e308".as_ptr();
            reset_errno();
            assert_eq!(strtod(s, &mut end), f64::INFINITY);
            assert_eq!(last_errno(), ERANGE);
            let s = c"-0.0".as_ptr();
            assert!(strtod(s, &mut end).is_sign_negative());
            assert_eq!(strtod(s, &mut end).to_bits(), 0x8000_0000_0000_0000u64);
            // inf/nan shapes.
            let s = c"-Infinity and beyond".as_ptr();
            assert_eq!(strtod(s, &mut end), f64::NEG_INFINITY);
            assert_eq!(end_off(s, end), 9);
            let s = c"infix".as_ptr();
            assert_eq!(strtod(s, &mut end), f64::INFINITY);
            assert_eq!(end_off(s, end), 3);
            let s = c"nan".as_ptr();
            let v = strtod(s, &mut end);
            assert!(v.is_nan() && !v.is_sign_negative());
            assert_eq!(end_off(s, end), 3);
            let s = c"-nan(payload_1)".as_ptr();
            let v = strtod(s, &mut end);
            assert!(v.is_nan() && !v.is_sign_negative());
            // Hex floats.
            let s = c"0x1p3".as_ptr();
            assert_eq!(strtod(s, &mut end), 8.0);
            assert_eq!(end_off(s, end), 5);
            let s = c"0x1.8p1".as_ptr();
            assert_eq!(strtod(s, &mut end), 3.0);
            let s = c"0x1p-1074".as_ptr();
            reset_errno();
            assert_eq!(strtod(s, &mut end).to_bits(), 1);
            assert_eq!(last_errno(), 0);
            let s = c"0x1p-1075".as_ptr();
            reset_errno();
            assert_eq!(strtod(s, &mut end).to_bits(), 0);
            assert_eq!(last_errno(), ERANGE);
            let s = c"0x1p1024".as_ptr();
            reset_errno();
            assert_eq!(strtod(s, &mut end), f64::INFINITY);
            assert_eq!(last_errno(), ERANGE);
            // Trailing-garbage endptr.
            let s = c"12.5xyz".as_ptr();
            assert_eq!(strtod(s, &mut end), 12.5);
            assert_eq!(end_off(s, end), 4);
            let s = c"1e".as_ptr();
            assert_eq!(strtod(s, &mut end), 1.0);
            assert_eq!(end_off(s, end), 1);
            let s = c"0x".as_ptr();
            reset_errno();
            assert_eq!(strtod(s, &mut end), 0.0);
            assert_eq!(end_off(s, end), 1);
            assert_eq!(last_errno(), 0);
            let s = c"e5".as_ptr();
            reset_errno();
            assert_eq!(strtod(s, &mut end), 0.0);
            assert_eq!(end_off(s, end), 0);
            assert_eq!(last_errno(), EINVAL);
            // Exact halfway above the tie rounds up (2^-53 + epsilon).
            let s = c"0.50000000000000011102230246251565404236316680908203125".as_ptr();
            assert_eq!(strtod(s, &mut end).to_bits(), 0x3FE0_0000_0000_0001u64);
        }
    }

    #[test]
    fn strtod_roundtrip_oracle() {
        let _guard = crate::ldso::testlock::lock();
        // Random bit patterns through shortest repr must round-trip (both
        // oracles correctly rounded). Includes denormals.
        let mut st: u64 = 0x1234_5678_9abc_def1;
        let mut next = || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        let mut buf = [0u8; 64];
        for i in 0..2000 {
            let mut b = next();
            if i % 3 == 0 {
                b &= 0x000F_FFFF_FFFF_FFFF; // denormal range
            } else {
                // Clear the top exponent bit: always finite (same NaN
                // reasoning as the f32 oracle), sign preserved.
                b &= 0xBFFF_FFFF_FFFF_FFFF;
            }
            let f = f64::from_bits(b);
            let txt = std::format!("{f:e}");
            let n = txt.len().min(63);
            buf[..n].copy_from_slice(&txt.as_bytes()[..n]);
            buf[n] = 0;
            let mut end: *mut c_char = null_mut();
            unsafe {
                let v = strtod(buf.as_ptr() as *const c_char, &mut end);
                assert_eq!(v.to_bits(), b, "roundtrip {txt}");
                assert_eq!(end_off(buf.as_ptr() as *const c_char, end), n);
            }
        }
    }

    #[test]
    fn strtof_vectors_and_roundtrip() {
        let _guard = crate::ldso::testlock::lock();
        let mut end: *mut c_char = null_mut();
        unsafe {
            reset_errno();
            let s = c"0.1".as_ptr();
            assert_eq!(strtof(s, &mut end).to_bits(), 0x3DCC_CCCDu32);
            assert_eq!(end_off(s, end), 3);
            // Exact halfway tie goes to even (0.5).
            let s = c"0.5000000298023223876953125".as_ptr();
            assert_eq!(strtof(s, &mut end).to_bits(), 0x3F00_0000u32);
            // Exact representable neighbor.
            let s = c"0.500000059604644775390625".as_ptr();
            assert_eq!(strtof(s, &mut end).to_bits(), 0x3F00_0001u32);
            let s = c"3.4028235e38".as_ptr();
            reset_errno();
            assert_eq!(strtof(s, &mut end).to_bits(), 0x7F7F_FFFFu32);
            assert_eq!(last_errno(), 0);
            let s = c"1e39".as_ptr();
            reset_errno();
            assert_eq!(strtof(s, &mut end), f32::INFINITY);
            assert_eq!(last_errno(), ERANGE);
            let s = c"1e-46".as_ptr();
            reset_errno();
            assert_eq!(strtof(s, &mut end), 0.0);
            assert_eq!(last_errno(), ERANGE);
        }
        let mut st: u32 = 0x9e37_79b9;
        for i in 0..2000 {
            st ^= st << 13;
            st ^= st >> 17;
            st ^= st << 5;
            let mut b = st;
            if i % 3 == 0 {
                b &= 0x007F_FFFF;
            } else {
                // Clear the top exponent bit: always finite (musl/strtof
                // return bare NAN, so NaN payloads can never round-trip).
                b &= 0x7F7F_FFFF;
            }
            let f = f32::from_bits(b);
            let txt = std::format!("{f:e}");
            let cs = std::ffi::CString::new(txt.clone()).unwrap();
            let mut end: *mut c_char = null_mut();
            unsafe {
                let v = strtof(cs.as_ptr(), &mut end);
                assert_eq!(v.to_bits(), b, "roundtrip {txt}");
            }
        }
    }

    #[test]
    fn strtold_bytes_via_st0() {
        let _guard = crate::ldso::testlock::lock();
        // Reads ST(0) right after the call, exactly like a C caller.
        unsafe fn call(s: *const c_char, endp: *mut *mut c_char, out: *mut u8) {
            unsafe {
                strtold(s, endp);
                core::arch::asm!("fstpt ({0})", in(reg) out, options(att_syntax, nostack, preserves_flags));
            }
        }
        let mut end: *mut c_char = null_mut();
        let mut out = [0u8; 10];
        unsafe {
            let s = c"1.0".as_ptr();
            reset_errno();
            call(s, &mut end, out.as_mut_ptr());
            assert_eq!(
                u64::from_le_bytes(out[0..8].try_into().unwrap()),
                0x8000_0000_0000_0000
            );
            assert_eq!(u16::from_le_bytes(out[8..10].try_into().unwrap()), 0x3fff);
            assert_eq!(end_off(s, end), 3);
            assert_eq!(last_errno(), 0);
            let s = c"0.1".as_ptr();
            call(s, &mut end, out.as_mut_ptr());
            assert_eq!(
                u64::from_le_bytes(out[0..8].try_into().unwrap()),
                0xCCCC_CCCC_CCCC_CCCD
            );
            assert_eq!(u16::from_le_bytes(out[8..10].try_into().unwrap()), 0x3ffb);
            let s = c"3.14159265358979323846".as_ptr();
            call(s, &mut end, out.as_mut_ptr());
            assert_eq!(
                u64::from_le_bytes(out[0..8].try_into().unwrap()),
                0xC90F_DAA2_2168_C235
            );
            assert_eq!(u16::from_le_bytes(out[8..10].try_into().unwrap()), 0x4000);
            let s = c"-0.0".as_ptr();
            call(s, &mut end, out.as_mut_ptr());
            assert_eq!(out, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80]);
            // Exact f80 min denormal via hex (decimal would need 11k digits).
            let s = c"0x1p-16445".as_ptr();
            reset_errno();
            call(s, &mut end, out.as_mut_ptr());
            assert_eq!(u64::from_le_bytes(out[0..8].try_into().unwrap()), 1);
            assert_eq!(u16::from_le_bytes(out[8..10].try_into().unwrap()), 0);
            assert_eq!(last_errno(), 0);
            let s = c"0x1p-16446".as_ptr();
            reset_errno();
            call(s, &mut end, out.as_mut_ptr());
            assert_eq!(out, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(last_errno(), ERANGE);
            let s = c"1e4932".as_ptr();
            reset_errno();
            call(s, &mut end, out.as_mut_ptr());
            assert_eq!(u16::from_le_bytes(out[8..10].try_into().unwrap()), 0x7ffe);
            assert_ne!(
                u64::from_le_bytes(out[0..8].try_into().unwrap()) & (1 << 63),
                0
            );
            assert_eq!(last_errno(), 0);
            let s = c"1e4933".as_ptr();
            reset_errno();
            call(s, &mut end, out.as_mut_ptr());
            assert_eq!(
                u64::from_le_bytes(out[0..8].try_into().unwrap()),
                0x8000_0000_0000_0000
            );
            assert_eq!(u16::from_le_bytes(out[8..10].try_into().unwrap()), 0x7fff);
            assert_eq!(last_errno(), ERANGE);
            let s = c"1e-5000".as_ptr();
            reset_errno();
            call(s, &mut end, out.as_mut_ptr());
            assert_eq!(out, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(last_errno(), ERANGE);
        }
    }

    fn read_cstr(p: *const c_char) -> std::vec::Vec<u8> {
        let mut v = std::vec::Vec::new();
        unsafe {
            let mut i = 0;
            while *p.add(i) != 0 {
                v.push(*p.add(i) as u8);
                i += 1;
            }
        }
        v
    }

    #[test]
    fn cvt_family() {
        unsafe {
            let mut dp = 0;
            let mut sign = 0;
            // ecvt(123.456, 6): "%.5e" = 1.23456e+02.
            let p = ecvt(123.456, 6, &mut dp, &mut sign);
            assert_eq!(read_cstr(p), b"123456");
            assert_eq!((dp, sign), (3, 0));
            // ecvt(-0.00123, 3): "-1.23e-03".
            let p = ecvt(-0.00123, 3, &mut dp, &mut sign);
            assert_eq!(read_cstr(p), b"123");
            assert_eq!((dp, sign), (-2, 1));
            // ecvt clamps n to 15 digits.
            let p = ecvt(1.0, 100, &mut dp, &mut sign);
            assert_eq!(read_cstr(p).len(), 15);
            assert_eq!((dp, sign), (1, 0));
            // fcvt(123.456, 2) -> "12346", dp 3.
            let p = fcvt(123.456, 2, &mut dp, &mut sign);
            assert_eq!(read_cstr(p), b"12346");
            assert_eq!((dp, sign), (3, 0));
            // fcvt(0.000123, 5) -> "%.5f" = "0.00012" -> "12", dp -3
            // (musl fcvt.c calls ecvt(x, n-lz); verified against glibc).
            let p = fcvt(0.000123, 5, &mut dp, &mut sign);
            assert_eq!(read_cstr(p), b"12");
            assert_eq!((dp, sign), (-3, 0));
            // fcvt tiny -> static zeros (musl fcvt.c: 15-zero literal
            // +14-n, so n=3 yields four chars, dp=1).
            let p = fcvt(0.00001, 3, &mut dp, &mut sign);
            assert_eq!(read_cstr(p), b"0000");
            assert_eq!((dp, sign), (1, 0));
            // Non-finite never crashes.
            let p = ecvt(f64::INFINITY, 6, &mut dp, &mut sign);
            assert_eq!(read_cstr(p), b"inf");
            let p = ecvt(f64::NAN, 6, &mut dp, &mut sign);
            assert_eq!(read_cstr(p), b"nan");
            // gcvt shapes.
            let mut b = [0 as c_char; 64];
            assert_eq!(read_cstr(gcvt(123.456, 6, b.as_mut_ptr())), b"123.456");
            assert_eq!(read_cstr(gcvt(1e20, 6, b.as_mut_ptr())), b"1e+20");
            assert_eq!(read_cstr(gcvt(0.00001234, 3, b.as_mut_ptr())), b"1.23e-05");
        }
    }

    unsafe extern "C" fn cmp_i32(a: *const c_void, b: *const c_void) -> c_int {
        unsafe {
            let x = *(a as *const i32);
            let y = *(b as *const i32);
            match x.cmp(&y) {
                core::cmp::Ordering::Less => -1,
                core::cmp::Ordering::Equal => 0,
                core::cmp::Ordering::Greater => 1,
            }
        }
    }

    #[test]
    fn qsort_reversed_and_random() {
        unsafe {
            // Reversed.
            let mut a: [i32; 100] = core::array::from_fn(|i| 99 - i as i32);
            qsort(a.as_mut_ptr() as *mut c_void, 100, 4, Some(cmp_i32));
            for (i, v) in a.iter().enumerate() {
                assert_eq!(*v, i as i32);
            }
            // Random vs std oracle (duplicates included).
            let mut st: u64 = 0xdead_beef_cafe_f00d;
            let mut a = [0i32; 256];
            for v in a.iter_mut() {
                st ^= st << 13;
                st ^= st >> 7;
                st ^= st << 17;
                *v = (st % 50) as i32;
            }
            let mut want = a;
            want.sort();
            qsort(a.as_mut_ptr() as *mut c_void, 256, 4, Some(cmp_i32));
            assert_eq!(a, want);
            // Degenerate sizes.
            let mut one = [7i32];
            qsort(one.as_mut_ptr() as *mut c_void, 1, 4, Some(cmp_i32));
            assert_eq!(one, [7]);
            qsort(null_mut(), 0, 4, Some(cmp_i32));
            // Wide elements (300-byte stride exercises multi-chunk cycle).
            #[repr(C)]
            #[derive(Clone, Copy, PartialEq, Eq)]
            struct Big {
                key: u32,
                pad: [u8; 296],
            }
            unsafe extern "C" fn cmp_big(a: *const c_void, b: *const c_void) -> c_int {
                unsafe {
                    let x = (*(a as *const Big)).key;
                    let y = (*(b as *const Big)).key;
                    match x.cmp(&y) {
                        core::cmp::Ordering::Less => -1,
                        core::cmp::Ordering::Equal => 0,
                        core::cmp::Ordering::Greater => 1,
                    }
                }
            }
            let mut w: [Big; 50] = core::array::from_fn(|i| Big {
                key: 49 - i as u32,
                pad: [i as u8; 296],
            });
            qsort(
                w.as_mut_ptr() as *mut c_void,
                50,
                core::mem::size_of::<Big>(),
                Some(cmp_big),
            );
            for (i, e) in w.iter().enumerate() {
                assert_eq!(e.key, i as u32);
                assert_eq!(e.pad, [(49 - i) as u8; 296]);
            }
        }
    }

    static QSORT_CALLS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

    unsafe extern "C" fn cmp_ctx(a: *const c_void, b: *const c_void, arg: *mut c_void) -> c_int {
        unsafe {
            QSORT_CALLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let dir = *(arg as *const c_int);
            let x = *(a as *const i32);
            let y = *(b as *const i32);
            (match x.cmp(&y) {
                core::cmp::Ordering::Less => -1,
                core::cmp::Ordering::Equal => 0,
                core::cmp::Ordering::Greater => 1,
            }) * dir
        }
    }

    #[test]
    fn qsort_r_context() {
        unsafe {
            let mut a = [3i32, 1, 4, 1, 5, 9, 2, 6];
            let mut dir = -1;
            QSORT_CALLS.store(0, core::sync::atomic::Ordering::Relaxed);
            qsort_r(
                a.as_mut_ptr() as *mut c_void,
                8,
                4,
                Some(cmp_ctx),
                &mut dir as *mut c_int as *mut c_void,
            );
            assert_eq!(a, [9, 6, 5, 4, 3, 2, 1, 1]);
            assert!(QSORT_CALLS.load(core::sync::atomic::Ordering::Relaxed) > 0);
        }
    }

    #[test]
    fn bsearch_hits_and_misses() {
        unsafe {
            let a = [1i32, 3, 5, 7, 9, 11];
            for (k, want) in [(1, 0), (7, 3), (11, 5)] {
                let p = bsearch(
                    &k as *const i32 as *const c_void,
                    a.as_ptr() as *const c_void,
                    6,
                    4,
                    Some(cmp_i32),
                );
                assert_eq!(p as *const i32, a.as_ptr().add(want));
            }
            for k in [0, 2, 6, 12] {
                let p = bsearch(
                    &k as *const i32 as *const c_void,
                    a.as_ptr() as *const c_void,
                    6,
                    4,
                    Some(cmp_i32),
                );
                assert!(p.is_null(), "miss {k}");
            }
            let k = 1;
            assert!(bsearch(
                &k as *const i32 as *const c_void,
                null_mut(),
                0,
                4,
                Some(cmp_i32)
            )
            .is_null());
        }
    }

    #[test]
    fn div_and_abs() {
        unsafe {
            let d = div(-7, 3);
            assert_eq!((d.quot, d.rem), (-2, -1));
            let d = div(7, -3);
            assert_eq!((d.quot, d.rem), (-2, 1));
            let d = ldiv(-7, 3);
            assert_eq!((d.quot, d.rem), (-2, -1));
            let d = lldiv(7, -3);
            assert_eq!((d.quot, d.rem), (-2, 1));
            let d = imaxdiv(-7, 3);
            assert_eq!((d.quot, d.rem), (-2, -1));
            assert_eq!(abs(-5), 5);
            assert_eq!(abs(c_int::MIN), c_int::MIN);
            assert_eq!(labs(c_long::MIN), c_long::MIN);
            assert_eq!(llabs(c_longlong::MIN), c_longlong::MIN);
            assert_eq!(imaxabs(-9), 9);
        }
    }

    #[test]
    fn a64l_roundtrip() {
        unsafe {
            assert_eq!(a64l(c"".as_ptr()), 0);
            assert_eq!(a64l(c"/".as_ptr()), 1);
            // l64a is MT-unsafe static: single test holds it end to end.
            let s = l64a(1);
            assert_eq!(read_cstr(s), b"/");
            let s = l64a(0);
            assert_eq!(read_cstr(s), b"");
            for v in [0i64, 1, 63, 64, 123456789, -1, c_long::MIN, c_long::MAX] {
                let s = l64a(v as c_long);
                let back = a64l(s);
                assert_eq!(back, (v as u32) as i32 as c_long, "roundtrip {v}");
            }
        }
    }

    #[test]
    fn getsubopt_shape() {
        unsafe {
            let keys = [
                c"ro".as_ptr() as *mut c_char,
                c"name".as_ptr() as *mut c_char,
                c"bar".as_ptr() as *mut c_char,
                null_mut(),
            ];
            let mut buf = *b"ro,name=foo,bar\0";
            let mut opt = buf.as_mut_ptr() as *mut c_char;
            let mut val: *mut c_char = null_mut();
            assert_eq!(getsubopt(&mut opt, keys.as_ptr(), &mut val), 0);
            assert!(val.is_null());
            assert_eq!(getsubopt(&mut opt, keys.as_ptr(), &mut val), 1);
            assert_eq!(read_cstr(val), b"foo");
            assert_eq!(getsubopt(&mut opt, keys.as_ptr(), &mut val), 2);
            let mut buf2 = *b"nope=x\0";
            let mut opt2 = buf2.as_mut_ptr() as *mut c_char;
            assert_eq!(getsubopt(&mut opt2, keys.as_ptr(), &mut val), -1);
            assert!(val.is_null());
        }
    }
}
