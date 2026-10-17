//! Wave 4/D3 packet 1: pure bit-exact `libm` leaf functions.
//!
//! Philosophy: one ALU op each, zero globals, zero syscalls, zero `unsafe` —
//! the safest possible Rust (bit moves via `to_bits`/`from_bits`). No probe
//! or ABI-struct impact: these add symbols, not layouts.

/// Absolute value, bit-exact (clears the sign bit, preserves NaN payload).
#[no_mangle]
pub extern "C" fn fabs(x: f64) -> f64 {
    f64::from_bits(x.to_bits() & !0x8000_0000_0000_0000)
}

/// `fabs` for `f32`.
#[no_mangle]
pub extern "C" fn fabsf(x: f32) -> f32 {
    f32::from_bits(x.to_bits() & !0x8000_0000)
}

/// Copy sign: magnitude of `x` with the sign of `y` (NaN payload kept).
#[no_mangle]
pub extern "C" fn copysign(x: f64, y: f64) -> f64 {
    f64::from_bits((x.to_bits() & !0x8000_0000_0000_0000) | (y.to_bits() & 0x8000_0000_0000_0000))
}

/// `copysign` for `f32`.
#[no_mangle]
pub extern "C" fn copysignf(x: f32, y: f32) -> f32 {
    f32::from_bits((x.to_bits() & !0x8000_0000) | (y.to_bits() & 0x8000_0000))
}

/// Truncate toward zero, bit-exact (exponent-driven mask; NaN/Inf pass
/// through, subnormals and |x| < 1 give signed zero, like musl).
#[no_mangle]
pub extern "C" fn trunc(x: f64) -> f64 {
    let u = x.to_bits();
    let e = ((u >> 52) & 0x7ff) as i32;
    if e < 1023 {
        f64::from_bits(u & 0x8000_0000_0000_0000)
    } else if e > 1074 {
        x
    } else {
        f64::from_bits(u & !((1u64 << (1075 - e)) - 1))
    }
}

/// `trunc` for `f32`.
#[no_mangle]
pub extern "C" fn truncf(x: f32) -> f32 {
    let u = x.to_bits();
    let e = ((u >> 23) & 0xff) as i32;
    if e < 127 {
        f32::from_bits(u & 0x8000_0000)
    } else if e > 150 {
        x
    } else {
        f32::from_bits(u & !((1u32 << (150 - e)) - 1))
    }
}

/// Round down, via [`trunc`] (musl `floor`: adjust only below zero).
#[no_mangle]
pub extern "C" fn floor(x: f64) -> f64 {
    let t = trunc(x);
    if x < 0.0 && t != x {
        t - 1.0
    } else {
        t
    }
}

/// `floor` for `f32`.
#[no_mangle]
pub extern "C" fn floorf(x: f32) -> f32 {
    let t = truncf(x);
    if x < 0.0 && t != x {
        t - 1.0
    } else {
        t
    }
}

/// Round up, via [`trunc`] (musl `ceil`, mirrored).
#[no_mangle]
pub extern "C" fn ceil(x: f64) -> f64 {
    let t = trunc(x);
    if x > 0.0 && t != x {
        t + 1.0
    } else {
        t
    }
}

/// `ceil` for `f32`.
#[no_mangle]
pub extern "C" fn ceilf(x: f32) -> f32 {
    let t = truncf(x);
    if x > 0.0 && t != x {
        t + 1.0
    } else {
        t
    }
}

/// Round half away from zero (musl `round`).
#[no_mangle]
pub extern "C" fn round(x: f64) -> f64 {
    let a = fabs(x);
    if a < 0.5 {
        copysign(0.0, x)
    } else {
        copysign(trunc(a + 0.5), x)
    }
}

/// `round` for `f32`.
#[no_mangle]
pub extern "C" fn roundf(x: f32) -> f32 {
    let a = fabsf(x);
    if a < 0.5 {
        copysignf(0.0, x)
    } else {
        copysignf(truncf(a + 0.5), x)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ceil, ceilf, copysign, copysignf, fabs, fabsf, floor, floorf, round, roundf, trunc, truncf,
    };

    #[test]
    fn fabs_is_sign_clear() {
        assert_eq!(fabs(-3.5).to_bits(), 3.5f64.to_bits());
        assert_eq!(fabs(3.5).to_bits(), 3.5f64.to_bits());
        assert_eq!(fabs(-0.0).to_bits(), 0.0f64.to_bits());
        assert_eq!(fabs(f64::NEG_INFINITY), f64::INFINITY);
        let nan = f64::from_bits(0x7ff8_1234_5678_9abc);
        assert_eq!(fabs(-nan).to_bits(), nan.to_bits() & !0x8000_0000_0000_0000);
        assert_eq!(fabsf(-2.5).to_bits(), 2.5f32.to_bits());
        assert_eq!(fabsf(-0.0).to_bits(), 0.0f32.to_bits());
        assert_eq!(fabsf(f32::NEG_INFINITY), f32::INFINITY);
    }

    #[test]
    fn copysign_moves_only_the_sign() {
        assert_eq!(copysign(3.0, -1.0).to_bits(), (-3.0f64).to_bits());
        assert_eq!(copysign(-3.0, 1.0).to_bits(), 3.0f64.to_bits());
        assert_eq!(copysignf(2.0, -1.0).to_bits(), (-2.0f32).to_bits());
        assert_eq!(copysignf(-2.0, 1.0).to_bits(), 2.0f32.to_bits());
        let nan = f64::from_bits(0x7ff8_0000_0000_0001);
        assert_eq!(
            copysign(nan, -1.0).to_bits(),
            nan.to_bits() | 0x8000_0000_0000_0000
        );
    }

    #[test]
    fn directed_roundings_are_bit_exact() {
        assert_eq!(trunc(3.7).to_bits(), 3.0f64.to_bits());
        assert_eq!(trunc(-3.7).to_bits(), (-3.0f64).to_bits());
        assert_eq!(trunc(0.5).to_bits(), 0.0f64.to_bits());
        assert_eq!(trunc(-0.5).to_bits(), (-0.0f64).to_bits());
        assert_eq!(trunc(1e20), 1e20);
        assert!(trunc(f64::NAN).is_nan());
        assert_eq!(trunc(f64::INFINITY), f64::INFINITY);
        assert_eq!(truncf(-2.5).to_bits(), (-2.0f32).to_bits());
        assert_eq!(floor(3.2), 3.0);
        assert_eq!(floor(-3.2), -4.0);
        assert_eq!(floor(-0.0).to_bits(), (-0.0f64).to_bits());
        assert_eq!(floor(2.0), 2.0);
        assert!(floor(f64::NAN).is_nan());
        assert_eq!(floorf(-3.2), -4.0);
        assert_eq!(ceil(3.2), 4.0);
        assert_eq!(ceil(-3.2), -3.0);
        assert_eq!(ceil(2.0), 2.0);
        assert!(ceil(f64::NAN).is_nan());
        assert_eq!(ceilf(3.2), 4.0);
        assert_eq!(round(0.5), 1.0);
        assert_eq!(round(-0.5), -1.0);
        assert_eq!(round(2.5), 3.0);
        assert_eq!(round(-2.5), -3.0);
        assert_eq!(round(1.4), 1.0);
        assert_eq!(round(-0.0).to_bits(), (-0.0f64).to_bits());
        assert!(round(f64::NAN).is_nan());
        assert_eq!(roundf(2.5), 3.0);
        assert_eq!(roundf(-2.5), -3.0);
    }
}
// Wave 12A: trig, inverse-trig and hyperbolic functions (musl `src/math`
// `sin.c`, `cos.c`, `tan.c`, `sincos.c`, `asin.c`, `acos.c`, `atan.c`,
// `atan2.c`, `sinh.c`, `cosh.c`, `tanh.c`, `asinh.c`, `acosh.c`,
// `atanh.c` + `f` twins + `l` shims).
//
// Algorithms are re-derived from musl (same constants and thresholds, so
// bit-exact where noted) in safe Rust: bit moves via `to_bits`/`from_bits`,
// branches on the high word. Two deliberate deviations, both unavoidable
// in stable `core`:
// - `FORCE_EVAL` (raising inexact/underflow flags) is dropped: `core` has
//   no `fenv` access. All special-case *return values* match musl; only
//   the flag side effects are missing. `+0x1p-120` inexact-prods (which
//   round back to the same double) are omitted for the same reason.
// - Private helpers `k_exp`/`k_log` are one-liners over the ported
//   `k_expm1`/`k_log1p` (`exp(x) == expm1(x)+1`, `log(x) == log1p(x-1)`),
//   accurate to ~2ulp instead of musl's <1ulp Arm routines. They only
//   feed `sinh`/`cosh`/`asinh`/`acosh`, whose tests use 1e-15 relative
//   tolerance (no exact-ulp assertions on those paths).
// - `*l` (x86_64 `long double` = 80-bit extended) have no stable-Rust
//   representation, so they are `f64` wrappers with C `double`
//   signatures and full `f64` accuracy. Documented ABI deviation.
// `sqrt` is re-derived from musl's integer-Goldschmidt `sqrt.c`/`sqrtf.c`
// (`k_sqrt`/`k_sqrtf`, correctly rounded in round-to-nearest; `core` has no
// `sqrt` in `no_std`).

/// Clear the low 32 mantissa bits (musl `SET_LOW_WORD(f,0)`).
fn k_set_lo(x: f64) -> f64 {
    f64::from_bits(x.to_bits() & 0xffff_ffff_0000_0000)
}

/// Scale a finite nonzero `f64` by `2^n` (musl `scalbn`, small `|n|` use).
/// Zero/NaN/Inf pass through; subnormal results truncate (<=1ulp note).
fn k_scalbn(x: f64, n: i32) -> f64 {
    if x == 0.0 || x.is_nan() || x.is_infinite() {
        return x;
    }
    let u = x.to_bits();
    let sign = u & 0x8000_0000_0000_0000;
    let mant = u & 0x000f_ffff_ffff_ffff;
    let e = ((u >> 52) & 0x7ff) as i32 + n;
    if e >= 0x7ff {
        return f64::from_bits(sign | 0x7ff0_0000_0000_0000);
    }
    if e <= 0 {
        let m = mant | 0x0010_0000_0000_0000;
        let sh = 1 - e;
        if sh >= 64 {
            return f64::from_bits(sign);
        }
        return f64::from_bits(sign | (m >> (sh as u32)));
    }
    f64::from_bits(sign | ((e as u64) << 52) | mant)
}

/// `expm1` re-derived from musl `src/math/expm1.c` (Sun rational +
/// `2^k` scaling; bit-exact outside dropped flag raises).
fn k_expm1(mut x: f64) -> f64 {
    const O_THRESHOLD: f64 = 709.782712893384;
    const LN2_HI: f64 = 0.6931471803691238;
    const LN2_LO: f64 = 1.9082149292705877e-10;
    const INV_LN2: f64 = core::f64::consts::LOG2_E;
    const Q1: f64 = -0.03333333333333313;
    const Q2: f64 = 0.0015873015872548146;
    const Q3: f64 = -7.93650757867488e-05;
    const Q4: f64 = 4.008217827329362e-06;
    const Q5: f64 = -2.0109921818362437e-07;
    let u = x.to_bits();
    let hx = (u >> 32) as u32 & 0x7fffffff;
    let sign = u >> 63;
    if hx >= 0x4043687A {
        if x.is_nan() {
            return x;
        }
        if sign != 0 {
            return -1.0;
        }
        if x > O_THRESHOLD {
            return x * f64::from_bits(0x7FE0000000000000); // x*2^1023 -> +inf
        }
    }
    let k: i32;
    let mut c = 0.0;
    if hx > 0x3fd62e42 {
        let hi: f64;
        let lo: f64;
        if hx < 0x3FF0A2B2 {
            if sign == 0 {
                hi = x - LN2_HI;
                lo = LN2_LO;
            } else {
                hi = x + LN2_HI;
                lo = -LN2_LO;
            }
            k = if sign == 0 { 1 } else { -1 };
        } else {
            k = (INV_LN2 * x + if sign != 0 { -0.5 } else { 0.5 }) as i32;
            let t = k as f64;
            hi = x - t * LN2_HI;
            lo = t * LN2_LO;
        }
        x = hi - lo;
        c = (hi - x) - lo;
    } else if hx < 0x3c900000 {
        return x;
    } else {
        k = 0;
    }
    let hfx = 0.5 * x;
    let hxs = x * hfx;
    let r1 = 1.0 + hxs * (Q1 + hxs * (Q2 + hxs * (Q3 + hxs * (Q4 + hxs * Q5))));
    let t = 3.0 - r1 * hfx;
    let mut e = hxs * ((r1 - t) / (6.0 - x * t));
    if k == 0 {
        return x - (x * e - hxs);
    }
    e = x * (e - c) - c - hxs;
    if k == -1 {
        return 0.5 * (x - e) - 0.5;
    }
    if k == 1 {
        if x < -0.25 {
            return -2.0 * (e - (x + 0.5));
        }
        return 1.0 + 2.0 * (x - e);
    }
    let twopk = f64::from_bits(((0x3ff + k) as u64) << 52);
    if !(0..=56).contains(&k) {
        let y = if k == 1024 {
            (x - e + 1.0) * 2.0 * f64::from_bits(0x7FE0000000000000)
        } else {
            (x - e + 1.0) * twopk
        };
        return y - 1.0;
    }
    let twomk = f64::from_bits(((0x3ff - k) as u64) << 52);
    if k < 20 {
        (x - e + (1.0 - twomk)) * twopk
    } else {
        (x - (e + twomk) + 1.0) * twopk
    }
}

/// `expm1f` re-derived from musl `src/math/expm1f.c`.
fn k_expm1f(mut x: f32) -> f32 {
    const LN2_HI: f32 = 0.6931381;
    const LN2_LO: f32 = 9.058001e-06;
    const INV_LN2: f32 = core::f32::consts::LOG2_E;
    const Q1: f32 = -0.033333212;
    const Q2: f32 = 0.001580717;
    let u = x.to_bits();
    let hx = u & 0x7fffffff;
    let sign = u >> 31;
    if hx >= 0x4195b844 {
        if hx > 0x7f800000 {
            return x;
        }
        if sign != 0 {
            return -1.0;
        }
        if hx > 0x42b17217 {
            return x * f32::from_bits(0x7F000000); // x*2^127 -> +inf
        }
    }
    let k: i32;
    let mut c = 0.0f32;
    if hx > 0x3eb17218 {
        let hi: f32;
        let lo: f32;
        if hx < 0x3F851592 {
            if sign == 0 {
                hi = x - LN2_HI;
                lo = LN2_LO;
            } else {
                hi = x + LN2_HI;
                lo = -LN2_LO;
            }
            k = if sign == 0 { 1 } else { -1 };
        } else {
            k = (INV_LN2 * x + if sign != 0 { -0.5 } else { 0.5 }) as i32;
            let t = k as f32;
            hi = x - t * LN2_HI;
            lo = t * LN2_LO;
        }
        x = hi - lo;
        c = (hi - x) - lo;
    } else if hx < 0x33000000 {
        return x;
    } else {
        k = 0;
    }
    let hfx = 0.5f32 * x;
    let hxs = x * hfx;
    let r1 = 1.0f32 + hxs * (Q1 + hxs * Q2);
    let t = 3.0f32 - r1 * hfx;
    let mut e = hxs * ((r1 - t) / (6.0f32 - x * t));
    if k == 0 {
        return x - (x * e - hxs);
    }
    e = x * (e - c) - c - hxs;
    if k == -1 {
        return 0.5f32 * (x - e) - 0.5f32;
    }
    if k == 1 {
        if x < -0.25 {
            return -2.0f32 * (e - (x + 0.5f32));
        }
        return 1.0f32 + 2.0f32 * (x - e);
    }
    let twopk = f32::from_bits(((0x7f + k) as u32) << 23);
    if !(0..=56).contains(&k) {
        let y = if k == 128 {
            (x - e + 1.0f32) * 2.0f32 * f32::from_bits(0x7F000000)
        } else {
            (x - e + 1.0f32) * twopk
        };
        return y - 1.0f32;
    }
    let twomk = f32::from_bits(((0x7f - k) as u32) << 23);
    if k < 23 {
        (x - e + (1.0f32 - twomk)) * twopk
    } else {
        (x - (e + twomk) + 1.0f32) * twopk
    }
}

/// `log1p` re-derived from musl `src/math/log1p.c` (bit-exact outside
/// dropped flag raises).
fn k_log1p(x: f64) -> f64 {
    const LN2_HI: f64 = 0.6931471803691238;
    const LN2_LO: f64 = 1.9082149292705877e-10;
    const LG1: f64 = 0.6666666666666735;
    const LG2: f64 = 0.3999999999940942;
    const LG3: f64 = 0.2857142874366239;
    const LG4: f64 = 0.22222198432149784;
    const LG5: f64 = 0.1818357216161805;
    const LG6: f64 = 0.15313837699209373;
    const LG7: f64 = 0.14798198605116586;
    let mut u = x.to_bits();
    let hx = (u >> 32) as u32;
    let k: i32;
    let (c, f);
    if hx < 0x3fda827a || hx >> 31 != 0 {
        if hx >= 0xbff00000 {
            if x == -1.0 {
                return x / 0.0; // -inf
            }
            return f64::NAN; // (x-x)/0.0 in musl
        }
        if (hx << 1) < (0x3ca00000u32 << 1) {
            return x;
        }
        if hx <= 0xbfd2bec4 {
            k = 0;
            c = 0.0;
            f = x;
        } else {
            let uu: f64 = 1.0 + x;
            u = uu.to_bits();
            let mut hu = (u >> 32) as u32;
            hu += 0x3ff00000 - 0x3fe6a09e;
            k = ((hu >> 20) as i32) - 0x3ff;
            c = if k < 54 {
                (if k >= 2 {
                    1.0 - (uu - x)
                } else {
                    x - (uu - 1.0)
                }) / uu
            } else {
                0.0
            };
            hu = (hu & 0x000fffff) + 0x3fe6a09e;
            u = (u & 0xffffffff) | ((hu as u64) << 32);
            f = f64::from_bits(u) - 1.0;
        }
    } else if hx >= 0x7ff00000 {
        return x;
    } else {
        let uu: f64 = 1.0 + x;
        u = uu.to_bits();
        let mut hu = (u >> 32) as u32;
        hu += 0x3ff00000 - 0x3fe6a09e;
        k = ((hu >> 20) as i32) - 0x3ff;
        c = if k < 54 {
            (if k >= 2 {
                1.0 - (uu - x)
            } else {
                x - (uu - 1.0)
            }) / uu
        } else {
            0.0
        };
        hu = (hu & 0x000fffff) + 0x3fe6a09e;
        u = (u & 0xffffffff) | ((hu as u64) << 32);
        f = f64::from_bits(u) - 1.0;
    }
    let hfsq = 0.5 * f * f;
    let s = f / (2.0 + f);
    let z = s * s;
    let w = z * z;
    let t1 = w * (LG2 + w * (LG4 + w * LG6));
    let t2 = z * (LG1 + w * (LG3 + w * (LG5 + w * LG7)));
    let r = t2 + t1;
    let dk = k as f64;
    s * (hfsq + r) + (dk * LN2_LO + c) - hfsq + f + dk * LN2_HI
}

/// `log1pf` re-derived from musl `src/math/log1pf.c`.
fn k_log1pf(x: f32) -> f32 {
    const LN2_HI: f32 = 0.6931381;
    const LN2_LO: f32 = 9.058001e-06;
    const LG1: f32 = 0.6666666; // 0xaaaaaa.0p-24
    const LG2: f32 = 0.40000972; // 0xccce13p-25
    const LG3: f32 = 0.28498787; // 0x91e9ee.0p-25
    const LG4: f32 = 0.24279079; // 0xf89e26p-26
    let mut u = x.to_bits();
    let ix = u;
    let k: i32;
    let (c, f);
    let need_reduce = !(ix < 0x3ed413d0 || ix >> 31 != 0);
    if !need_reduce {
        if ix >= 0xbf800000 {
            if x == -1.0 {
                return x / 0.0; // -inf
            }
            return f32::NAN; // (x-x)/0.0 in musl
        }
        if (ix << 1) < (0x33800000u32 << 1) {
            return x;
        }
        if ix <= 0xbe95f619 {
            k = 0;
            c = 0.0;
            f = x;
        } else {
            let uu: f32 = 1.0 + x;
            u = uu.to_bits();
            let mut iu = u;
            iu += 0x3f800000 - 0x3f3504f3;
            k = ((iu >> 23) as i32) - 0x7f;
            c = if k < 25 {
                (if k >= 2 {
                    1.0 - (uu - x)
                } else {
                    x - (uu - 1.0)
                }) / uu
            } else {
                0.0
            };
            iu = (iu & 0x007fffff) + 0x3f3504f3;
            u = iu;
            f = f32::from_bits(u) - 1.0;
        }
    } else if ix >= 0x7f800000 {
        return x;
    } else {
        let uu: f32 = 1.0 + x;
        u = uu.to_bits();
        let mut iu = u;
        iu += 0x3f800000 - 0x3f3504f3;
        k = ((iu >> 23) as i32) - 0x7f;
        c = if k < 25 {
            (if k >= 2 {
                1.0 - (uu - x)
            } else {
                x - (uu - 1.0)
            }) / uu
        } else {
            0.0
        };
        iu = (iu & 0x007fffff) + 0x3f3504f3;
        u = iu;
        f = f32::from_bits(u) - 1.0;
    }
    let s = f / (2.0f32 + f);
    let z = s * s;
    let w = z * z;
    let t1 = w * (LG2 + w * LG4);
    let t2 = z * (LG1 + w * LG3);
    let r = t2 + t1;
    let hfsq = 0.5f32 * f * f;
    let dk = k as f32;
    s * (hfsq + r) + (dk * LN2_LO + c) - hfsq + f + dk * LN2_HI
}

/// Helpers over the ported kernels (~2ulp; see module docs).
fn k_exp(x: f64) -> f64 {
    k_expm1(x) + 1.0
}
fn k_expf(x: f32) -> f32 {
    k_expm1f(x) + 1.0
}
fn k_log(x: f64) -> f64 {
    k_log1p(x - 1.0)
}
fn k_logf(x: f32) -> f32 {
    k_log1pf(x - 1.0)
}

/// Kernel sine on [-pi/4, pi/4] (musl `__sin.c`, `k_sin.c`).
fn k_sin(x: f64, y: f64, iy: i32) -> f64 {
    const S1: f64 = -0.16666666666666632;
    const S2: f64 = 0.00833333333332249;
    const S3: f64 = -0.0001984126982985795;
    const S4: f64 = 2.7557313707070068e-06;
    const S5: f64 = -2.5050760253406863e-08;
    const S6: f64 = 1.58969099521155e-10;
    let z = x * x;
    let w = z * z;
    let r = S2 + z * (S3 + z * S4) + z * w * (S5 + z * S6);
    let v = z * x;
    if iy == 0 {
        x + v * (S1 + z * r)
    } else {
        x - ((z * (0.5 * y - v * r) - y) - v * S1)
    }
}

/// Kernel cosine on [-pi/4, pi/4] (musl `__cos.c`, `k_cos.c`).
fn k_cos(x: f64, y: f64) -> f64 {
    const C1: f64 = 0.0416666666666666;
    const C2: f64 = -0.001388888888887411;
    const C3: f64 = 2.480158728947673e-05;
    const C4: f64 = -2.7557314351390663e-07;
    const C5: f64 = 2.087572321298175e-09;
    const C6: f64 = -1.1359647557788195e-11;
    let z = x * x;
    let w = z * z;
    let r = z * (C1 + z * (C2 + z * C3)) + w * w * (C4 + z * (C5 + z * C6));
    let hz = 0.5 * z;
    let w_ = 1.0 - hz;
    w_ + ((1.0 - w_) - hz) + (z * r - x * y)
}

/// Kernel tangent (musl `__tan.c`, `k_tan.c`); `odd` selects `tan`/`-1/tan`.
fn k_tan(mut x: f64, mut y: f64, odd: i32) -> f64 {
    const T: [f64; 13] = [
        0.3333333333333341,
        0.13333333333320124,
        0.05396825397622605,
        0.021869488294859542,
        0.0088632398235993,
        0.0035920791075913124,
        0.0014562094543252903,
        0.0005880412408202641,
        0.0002464631348184699,
        7.817944429395571e-05,
        7.140724913826082e-05,
        -1.8558637485527546e-05,
        2.590730518636337e-05,
    ];
    const PIO4: f64 = core::f64::consts::FRAC_PI_4;
    const PIO4LO: f64 = 3.061616997868383e-17;
    let big = ((x.to_bits() >> 32) as u32 & 0x7fffffff) >= 0x3FE59428;
    let sign = (x.to_bits() >> 63) as u32;
    if big {
        if sign != 0 {
            x = -x;
            y = -y;
        }
        x = (PIO4 - x) + (PIO4LO - y);
        y = 0.0;
    }
    let z = x * x;
    let w = z * z;
    let r = T[1] + w * (T[3] + w * (T[5] + w * (T[7] + w * (T[9] + w * T[11]))));
    let v = z * (T[2] + w * (T[4] + w * (T[6] + w * (T[8] + w * (T[10] + w * T[12])))));
    let s = z * x;
    let r = y + z * (s * (r + v) + y) + s * T[0];
    let w_ = x + r;
    if big {
        let sgn = 1.0 - 2.0 * odd as f64;
        let v = sgn - 2.0 * (x + (r - w_ * w_ / (w_ + sgn)));
        return if sign != 0 { -v } else { v };
    }
    if odd == 0 {
        return w_;
    }
    let w0 = k_set_lo(w_);
    let v = r - (w0 - x);
    let a = -1.0 / w_;
    let a0 = k_set_lo(a);
    a0 + a * (1.0 + a0 * w0 + a0 * v)
}

/// Kernel sine for `f32` trig (musl `__sindf.c`).
fn k_sindf(x: f64) -> f32 {
    const S1: f64 = f64::from_bits(0xBFC5555554CBAC77);
    const S2: f64 = f64::from_bits(0x3F811110896EFBB2);
    const S3: f64 = f64::from_bits(0xBF2A00F9E2CAE774);
    const S4: f64 = f64::from_bits(0x3EC6CD878C3B46A7);
    let z = x * x;
    let w = z * z;
    let r = S3 + z * S4;
    let s = z * x;
    ((x + s * (S1 + z * S2)) + s * w * r) as f32
}

/// Kernel cosine for `f32` trig (musl `__cosdf.c`).
fn k_cosdf(x: f64) -> f32 {
    const C0: f64 = f64::from_bits(0xBFDFFFFFFD0C5E81);
    const C1: f64 = f64::from_bits(0x3FA55553E1053A42);
    const C2: f64 = f64::from_bits(0xBF56C087E80F1E27);
    const C3: f64 = f64::from_bits(0x3EF99342E0EE5069);
    let z = x * x;
    let w = z * z;
    let r = C2 + z * C3;
    (((1.0 + z * C0) + w * C1) + (w * z) * r) as f32
}

/// Kernel tangent for `f32` trig (musl `__tandf.c`).
fn k_tandf(x: f64, odd: i32) -> f32 {
    const T0: f64 = f64::from_bits(0x3FD5554D3418C99F);
    const T1: f64 = f64::from_bits(0x3FC112FD38999F72);
    const T2: f64 = f64::from_bits(0x3FAB54C91D865AFE);
    const T3: f64 = f64::from_bits(0x3F991DF3908C33CE);
    const T4: f64 = f64::from_bits(0x3F685DADFCECF44E);
    const T5: f64 = f64::from_bits(0x3F8362B9BF971BCD);
    let z = x * x;
    let r = T4 + z * T5;
    let t = T2 + z * T3;
    let w = z * z;
    let s = z * x;
    let u = T0 + z * T1;
    let r = (x + s * u) + (s * w) * (t + w * r);
    (if odd != 0 { -1.0 / r } else { r }) as f32
}
/// 2/pi as 24-bit chunks (musl `__rem_pio2_large.c` `ipio2`, full table
/// incl. the extended-precision tail; data, copied exactly).
const K_IPIO2: [i32; 690] = [
    0xA2F983, 0x6E4E44, 0x1529FC, 0x2757D1, 0xF534DD, 0xC0DB62, 0x95993C, 0x439041, 0xFE5163,
    0xABDEBB, 0xC561B7, 0x246E3A, 0x424DD2, 0xE00649, 0x2EEA09, 0xD1921C, 0xFE1DEB, 0x1CB129,
    0xA73EE8, 0x8235F5, 0x2EBB44, 0x84E99C, 0x7026B4, 0x5F7E41, 0x3991D6, 0x398353, 0x39F49C,
    0x845F8B, 0xBDF928, 0x3B1FF8, 0x97FFDE, 0x05980F, 0xEF2F11, 0x8B5A0A, 0x6D1F6D, 0x367ECF,
    0x27CB09, 0xB74F46, 0x3F669E, 0x5FEA2D, 0x7527BA, 0xC7EBE5, 0xF17B3D, 0x0739F7, 0x8A5292,
    0xEA6BFB, 0x5FB11F, 0x8D5D08, 0x560330, 0x46FC7B, 0x6BABF0, 0xCFBC20, 0x9AF436, 0x1DA9E3,
    0x91615E, 0xE61B08, 0x659985, 0x5F14A0, 0x68408D, 0xFFD880, 0x4D7327, 0x310606, 0x1556CA,
    0x73A8C9, 0x60E27B, 0xC08C6B, 0x47C419, 0xC367CD, 0xDCE809, 0x2A8359, 0xC4768B, 0x961CA6,
    0xDDAF44, 0xD15719, 0x053EA5, 0xFF0705, 0x3F7E33, 0xE832C2, 0xDE4F98, 0x327DBB, 0xC33D26,
    0xEF6B1E, 0x5EF89F, 0x3A1F35, 0xCAF27F, 0x1D87F1, 0x21907C, 0x7C246A, 0xFA6ED5, 0x772D30,
    0x433B15, 0xC614B5, 0x9D19C3, 0xC2C4AD, 0x414D2C, 0x5D000C, 0x467D86, 0x2D71E3, 0x9AC69B,
    0x006233, 0x7CD2B4, 0x97A7B4, 0xD55537, 0xF63ED7, 0x1810A3, 0xFC764D, 0x2A9D64, 0xABD770,
    0xF87C63, 0x57B07A, 0xE71517, 0x5649C0, 0xD9D63B, 0x3884A7, 0xCB2324, 0x778AD6, 0x23545A,
    0xB91F00, 0x1B0AF1, 0xDFCE19, 0xFF319F, 0x6A1E66, 0x615799, 0x47FBAC, 0xD87F7E, 0xB76522,
    0x89E832, 0x60BFE6, 0xCDC4EF, 0x09366C, 0xD43F5D, 0xD7DE16, 0xDE3B58, 0x929BDE, 0x2822D2,
    0xE88628, 0x4D58E2, 0x32CAC6, 0x16E308, 0xCB7DE0, 0x50C017, 0xA71DF3, 0x5BE018, 0x34132E,
    0x621283, 0x014883, 0x5B8EF5, 0x7FB0AD, 0xF2E91E, 0x434A48, 0xD36710, 0xD8DDAA, 0x425FAE,
    0xCE616A, 0xA4280A, 0xB499D3, 0xF2A606, 0x7F775C, 0x83C2A3, 0x883C61, 0x78738A, 0x5A8CAF,
    0xBDD76F, 0x63A62D, 0xCBBFF4, 0xEF818D, 0x67C126, 0x45CA55, 0x36D9CA, 0xD2A828, 0x8D61C2,
    0x77C912, 0x142604, 0x9B4612, 0xC459C4, 0x44C5C8, 0x91B24D, 0xF31700, 0xAD43D4, 0xE54929,
    0x10D5FD, 0xFCBE00, 0xCC941E, 0xEECE70, 0xF53E13, 0x80F1EC, 0xC3E7B3, 0x28F8C7, 0x940593,
    0x3E71C1, 0xB3092E, 0xF3450B, 0x9C1288, 0x7B20AB, 0x9FB52E, 0xC29247, 0x2F327B, 0x6D550C,
    0x90A772, 0x1FE76B, 0x96CB31, 0x4A1679, 0xE27941, 0x89DFF4, 0x9794E8, 0x84E6E2, 0x973199,
    0x6BED88, 0x365F5F, 0x0EFDBB, 0xB49A48, 0x6CA467, 0x427271, 0x325D8D, 0xB8159F, 0x09E5BC,
    0x25318D, 0x3974F7, 0x1C0530, 0x010C0D, 0x68084B, 0x58EE2C, 0x90AA47, 0x02E774, 0x24D6BD,
    0xA67DF7, 0x72486E, 0xEF169F, 0xA6948E, 0xF691B4, 0x5153D1, 0xF20ACF, 0x339820, 0x7E4BF5,
    0x6863B2, 0x5F3EDD, 0x035D40, 0x7F8985, 0x295255, 0xC06437, 0x10D86D, 0x324832, 0x754C5B,
    0xD4714E, 0x6E5445, 0xC1090B, 0x69F52A, 0xD56614, 0x9D0727, 0x50045D, 0xDB3BB4, 0xC576EA,
    0x17F987, 0x7D6B49, 0xBA271D, 0x296996, 0xACCCC6, 0x5414AD, 0x6AE290, 0x89D988, 0x50722C,
    0xBEA404, 0x940777, 0x7030F3, 0x27FC00, 0xA871EA, 0x49C266, 0x3DE064, 0x83DD97, 0x973FA3,
    0xFD9443, 0x8C860D, 0xDE4131, 0x9D3992, 0x8C70DD, 0xE7B717, 0x3BDF08, 0x2B3715, 0xA0805C,
    0x93805A, 0x921110, 0xD8E80F, 0xAF806C, 0x4BFFDB, 0x0F9038, 0x761859, 0x15A562, 0xBBCB61,
    0xB989C7, 0xBD4010, 0x04F2D2, 0x277549, 0xF6B6EB, 0xBB22DB, 0xAA140A, 0x2F2689, 0x768364,
    0x333B09, 0x1A940E, 0xAA3A51, 0xC2A31D, 0xAEEDAF, 0x12265C, 0x4DC26D, 0x9C7A2D, 0x9756C0,
    0x833F03, 0xF6F009, 0x8C402B, 0x99316D, 0x07B439, 0x15200C, 0x5BC3D8, 0xC492F5, 0x4BADC6,
    0xA5CA4E, 0xCD37A7, 0x36A9E6, 0x9492AB, 0x6842DD, 0xDE6319, 0xEF8C76, 0x528B68, 0x37DBFC,
    0xABA1AE, 0x3115DF, 0xA1AE00, 0xDAFB0C, 0x664D64, 0xB705ED, 0x306529, 0xBF5657, 0x3AFF47,
    0xB9F96A, 0xF3BE75, 0xDF9328, 0x3080AB, 0xF68C66, 0x15CB04, 0x0622FA, 0x1DE4D9, 0xA4B33D,
    0x8F1B57, 0x09CD36, 0xE9424E, 0xA4BE13, 0xB52333, 0x1AAAF0, 0xA8654F, 0xA5C1D2, 0x0F3F0B,
    0xCD785B, 0x76F923, 0x048B7B, 0x721789, 0x53A6C6, 0xE26E6F, 0x00EBEF, 0x584A9B, 0xB7DAC4,
    0xBA66AA, 0xCFCF76, 0x1D02D1, 0x2DF1B1, 0xC1998C, 0x77ADC3, 0xDA4886, 0xA05DF7, 0xF480C6,
    0x2FF0AC, 0x9AECDD, 0xBC5C3F, 0x6DDED0, 0x1FC790, 0xB6DB2A, 0x3A25A3, 0x9AAF00, 0x9353AD,
    0x0457B6, 0xB42D29, 0x7E804B, 0xA707DA, 0x0EAA76, 0xA1597B, 0x2A1216, 0x2DB7DC, 0xFDE5FA,
    0xFEDB89, 0xFDBE89, 0x6C76E4, 0xFCA906, 0x70803E, 0x156E85, 0xFF87FD, 0x073E28, 0x336761,
    0x86182A, 0xEABD4D, 0xAFE7B3, 0x6E6D8F, 0x396795, 0x5BBF31, 0x48D784, 0x16DF30, 0x432DC7,
    0x356125, 0xCE70C9, 0xB8CB30, 0xFD6CBF, 0xA200A4, 0xE46C05, 0xA0DD5A, 0x476F21, 0xD21262,
    0x845CB9, 0x496170, 0xE0566B, 0x015299, 0x375550, 0xB7D51E, 0xC4F133, 0x5F6E13, 0xE4305D,
    0xA92E85, 0xC3B21D, 0x3632A1, 0xA4B708, 0xD4B1EA, 0x21F716, 0xE4698F, 0x77FF27, 0x80030C,
    0x2D408D, 0xA0CD4F, 0x99A520, 0xD3A2B3, 0x0A5D2F, 0x42F9B4, 0xCBDA11, 0xD0BE7D, 0xC1DB9B,
    0xBD17AB, 0x81A2CA, 0x5C6A08, 0x17552E, 0x550027, 0xF0147F, 0x8607E1, 0x640B14, 0x8D4196,
    0xDEBE87, 0x2AFDDA, 0xB6256B, 0x34897B, 0xFEF305, 0x9EBFB9, 0x4F6A68, 0xA82A4A, 0x5AC44F,
    0xBCF82D, 0x985AD7, 0x95C7F4, 0x8D4D0D, 0xA63A20, 0x5F57A4, 0xB13F14, 0x953880, 0x0120CC,
    0x86DD71, 0xB6DEC9, 0xF560BF, 0x11654D, 0x6B0701, 0xACB08C, 0xD0C0B2, 0x485551, 0x0EFB1E,
    0xC37295, 0x3B06A3, 0x3540C0, 0x7BDC06, 0xCC45E0, 0xFA294E, 0xC8CAD6, 0x41F3E8, 0xDE647C,
    0xD8649B, 0x31BED9, 0xC397A4, 0xD45877, 0xC5E369, 0x13DAF0, 0x3C3ABA, 0x461846, 0x5F7555,
    0xF5BDD2, 0xC6926E, 0x5D2EAC, 0xED440E, 0x423E1C, 0x87C461, 0xE9FD29, 0xF3D6E7, 0xCA7C22,
    0x35916F, 0xC5E008, 0x8DD7FF, 0xE26A6E, 0xC6FDB0, 0xC10893, 0x745D7C, 0xB2AD6B, 0x9D6ECD,
    0x7B723E, 0x6A11C6, 0xA9CFF7, 0xDF7329, 0xBAC9B5, 0x5100B7, 0x0DB2E2, 0x24BA74, 0x607DE5,
    0x8AD874, 0x2C150D, 0x0C1881, 0x94667E, 0x162901, 0x767A9F, 0xBEFDFD, 0xEF4556, 0x367ED9,
    0x13D9EC, 0xB9BA8B, 0xFC97C4, 0x27A831, 0xC36EF1, 0x36C594, 0x56A8D8, 0xB5A8B4, 0x0ECCCF,
    0x2D8912, 0x34576F, 0x89562C, 0xE3CE99, 0xB920D6, 0xAA5E6B, 0x9C2A3E, 0xCC5F11, 0x4A0BFD,
    0xFBF4E1, 0x6D3B8E, 0x2C86E2, 0x84D4E9, 0xA9B4FC, 0xD1EEEF, 0xC9352E, 0x61392F, 0x442138,
    0xC8D91B, 0x0AFC81, 0x6A4AFB, 0xD81C2F, 0x84B453, 0x8C994E, 0xCC2254, 0xDC552A, 0xD6C6C0,
    0x96190B, 0xB8701A, 0x649569, 0x605A26, 0xEE523F, 0x0F117F, 0x11B5F4, 0xF5CBFC, 0x2DBC34,
    0xEEBC34, 0xCC5DE8, 0x605EDD, 0x9B8E67, 0xEF3392, 0xB817C9, 0x9B5861, 0xBC57E1, 0xC68351,
    0x103ED8, 0x4871DD, 0xDD1C2D, 0xA118AF, 0x462C21, 0xD7F359, 0x987AD9, 0xC0549E, 0xFA864F,
    0xFC0656, 0xAE79E5, 0x362289, 0x22AD38, 0xDC9367, 0xAAE855, 0x382682, 0x9BE7CA, 0xA40D51,
    0xB13399, 0x0ED7A9, 0x480569, 0xF0B265, 0xA7887F, 0x974C88, 0x36D1F9, 0xB39221, 0x4A827B,
    0x21CF98, 0xDC9F40, 0x5547DC, 0x3A74E1, 0x42EB67, 0xDF9DFE, 0x5FD45E, 0xA4677B, 0x7AACBA,
    0xA2F655, 0x23882B, 0x55BA41, 0x086E59, 0x862A21, 0x834739, 0xE6E389, 0xD49EE5, 0x40FB49,
    0xE956FF, 0xCA0F1C, 0x8A59C5, 0x2BFA94, 0xC5C1D3, 0xCFC50F, 0xAE5ADB, 0x86C547, 0x624385,
    0x3B8621, 0x94792C, 0x876110, 0x7B4C2A, 0x1A2C80, 0x12BF43, 0x902688, 0x893C78, 0xE4C4A8,
    0x7BDBE5, 0xC23AC4, 0xEAF426, 0x8A67F7, 0xBF920D, 0x2BA365, 0xB1933D, 0x0B7CBD, 0xDC51A4,
    0x63DD27, 0xDDE169, 0x19949A, 0x9529A8, 0x28CE68, 0xB4ED09, 0x209F44, 0xCA984E, 0x638270,
    0x237C7E, 0x32B90F, 0x8EF5A7, 0xE75614, 0x08F121, 0x2A9DB5, 0x4D7E6F, 0x5119A5, 0xABF9B5,
    0xD6DF82, 0x61DD96, 0x023616, 0x9F3AC4, 0xA1A283, 0x6DED72, 0x7A8D39, 0xA9B882, 0x5C326B,
    0x5B2746, 0xED3400, 0x7700D2, 0x55F4FC, 0x4D5901, 0x8071E0,
];

/// Large-argument `x rem pi/2` (musl `__rem_pio2_large.c`, prec 0/1 only).
/// `x` holds `nx` 24-bit chunks of `|x|` scaled by `2^e0`; result lands in
/// `y[0]` (+`y[1]` for prec 1). Returns the quadrant `N` (caller negates
/// for negative input).
fn k_rem_pio2_large(x: &[f64], y: &mut [f64], e0: i32, nx: i32, prec: i32) -> i32 {
    const INIT_JK: [i32; 4] = [3, 4, 4, 6];
    const PIO2: [f64; 8] = [
        1.570796251296997,
        7.549789415861596e-08,
        5.390302529957765e-15,
        3.282003415807913e-22,
        1.270655753080676e-29,
        1.2293330898111133e-36,
        2.7337005381646456e-44,
        2.1674168387780482e-51,
    ];
    const TWO_M24: f64 = f64::from_bits(0x3E70000000000000); // 2^-24
    const TWO_P24: f64 = 16777216.0; // 2^24
    let jk = INIT_JK[prec as usize];
    let jp = jk;
    let jx = nx - 1;
    let mut jv = (e0 - 3) / 24;
    if jv < 0 {
        jv = 0;
    }
    let mut q0 = e0 - 24 * (jv + 1);
    let mut f = [0.0f64; 20];
    let mut q = [0.0f64; 20];
    let mut fq = [0.0f64; 20];
    let mut iq = [0i32; 20];
    let mut j = jv - jx;
    let m = jx + jk;
    let mut i = 0;
    while i <= m {
        f[i as usize] = if j < 0 {
            0.0
        } else {
            K_IPIO2[j as usize] as f64
        };
        i += 1;
        j += 1;
    }
    i = 0;
    while i <= jk {
        let mut fw = 0.0;
        let mut jj = 0;
        while jj <= jx {
            fw += x[jj as usize] * f[(jx + i - jj) as usize];
            jj += 1;
        }
        q[i as usize] = fw;
        i += 1;
    }
    let mut jz = jk;
    let (mut n, mut ih);
    let mut z: f64;
    loop {
        // Distill q[] into iq[] (reversed).
        let mut jj = jz;
        z = q[jz as usize];
        let mut ii = 0;
        while jj > 0 {
            let fw = (z * TWO_M24) as i32 as f64;
            iq[ii] = (z - TWO_P24 * fw) as i32;
            z = q[(jj - 1) as usize] + fw;
            ii += 1;
            jj -= 1;
        }
        z = k_scalbn(z, q0);
        z -= 8.0 * floor(z * 0.125);
        n = z as i32;
        z -= n as f64;
        ih = 0;
        if q0 > 0 {
            let t = iq[(jz - 1) as usize] >> (24 - q0);
            n += t;
            iq[(jz - 1) as usize] -= t << (24 - q0);
            ih = iq[(jz - 1) as usize] >> (23 - q0);
        } else if q0 == 0 {
            ih = iq[(jz - 1) as usize] >> 23;
        } else if z >= 0.5 {
            ih = 2;
        }
        if ih > 0 {
            n += 1;
            let mut carry = 0;
            let mut kk = 0;
            while kk < jz {
                let v = iq[kk as usize];
                if carry == 0 {
                    if v != 0 {
                        carry = 1;
                        iq[kk as usize] = 0x1000000 - v;
                    }
                } else {
                    iq[kk as usize] = 0xffffff - v;
                }
                kk += 1;
            }
            if q0 > 0 {
                match q0 {
                    1 => iq[(jz - 1) as usize] &= 0x7fffff,
                    2 => iq[(jz - 1) as usize] &= 0x3fffff,
                    _ => {}
                }
            }
            if ih == 2 {
                z = 1.0 - z;
                if carry != 0 {
                    z -= k_scalbn(1.0, q0);
                }
            }
        }
        // Recompute with more terms if the fraction cancelled to zero.
        if z == 0.0 {
            let mut acc = 0;
            let mut kk = jz - 1;
            while kk >= jk {
                acc |= iq[kk as usize];
                kk -= 1;
            }
            if acc == 0 {
                let mut kk = 1;
                while iq[(jk - kk) as usize] == 0 {
                    kk += 1;
                }
                let mut t = jz + 1;
                while t <= jz + kk {
                    f[(jx + t) as usize] = K_IPIO2[(jv + t) as usize] as f64;
                    let mut fw = 0.0;
                    let mut jj = 0;
                    while jj <= jx {
                        fw += x[jj as usize] * f[(jx + t - jj) as usize];
                        jj += 1;
                    }
                    q[t as usize] = fw;
                    t += 1;
                }
                jz += kk;
                continue;
            }
        }
        break;
    }
    if z == 0.0 {
        jz -= 1;
        q0 -= 24;
        while iq[jz as usize] == 0 {
            jz -= 1;
            q0 -= 24;
        }
    } else {
        z = k_scalbn(z, -q0);
        if z >= TWO_P24 {
            let fw = (z * TWO_M24) as i32 as f64;
            iq[jz as usize] = (z - TWO_P24 * fw) as i32;
            jz += 1;
            q0 += 24;
            iq[jz as usize] = fw as i32;
        } else {
            iq[jz as usize] = z as i32;
        }
    }
    let mut fw = k_scalbn(1.0, q0);
    i = jz;
    while i >= 0 {
        q[i as usize] = fw * iq[i as usize] as f64;
        fw *= TWO_M24;
        i -= 1;
    }
    i = jz;
    while i >= 0 {
        let mut acc = 0.0;
        let mut kk = 0;
        while kk <= jp && kk <= jz - i {
            acc += PIO2[kk as usize] * q[(i + kk) as usize];
            kk += 1;
        }
        fq[(jz - i) as usize] = acc;
        i -= 1;
    }
    let mut acc = 0.0;
    i = jz;
    while i >= 0 {
        acc += fq[i as usize];
        i -= 1;
    }
    y[0] = if ih == 0 { acc } else { -acc };
    if prec != 0 {
        acc = fq[0] - acc;
        i = 1;
        while i <= jz {
            acc += fq[i as usize];
            i += 1;
        }
        y[1] = if ih == 0 { acc } else { -acc };
    }
    n
}

/// `x rem pi/2` in `y[0]+y[1]` (musl `__rem_pio2.c`); caller skips
/// `|x| <= pi/4`. Returns the quadrant `N` (negative for negative `x`).
fn k_rem_pio2(x: f64, y: &mut [f64; 2]) -> i32 {
    const TOINT: f64 = 6755399441055744.0; // 1.5/eps
    const PIO4: f64 = f64::from_bits(0x3FE921FB54442D18);
    const INVPIO2: f64 = core::f64::consts::FRAC_2_PI;
    const PIO2_1: f64 = 1.5707963267341256;
    const PIO2_1T: f64 = 6.077100506506192e-11;
    const PIO2_2: f64 = 6.077100506303966e-11;
    const PIO2_2T: f64 = 2.0222662487959506e-21;
    const PIO2_3: f64 = 2.0222662487111665e-21;
    const PIO2_3T: f64 = 8.4784276603689e-32;
    let u = x.to_bits();
    let sign = u >> 63;
    let ix = ((u >> 32) as u32) & 0x7fffffff;
    // Small multiples of pi/2 use one-round subtraction; the `~=` cases
    // cancel and need the medium path (musl `goto medium`).
    let mut use_medium = false;
    if ix <= 0x400f6a7a {
        if (ix & 0xfffff) == 0x921fb {
            use_medium = true;
        } else if ix <= 0x4002d97c {
            if sign == 0 {
                let z = x - PIO2_1;
                y[0] = z - PIO2_1T;
                y[1] = (z - y[0]) - PIO2_1T;
                return 1;
            } else {
                let z = x + PIO2_1;
                y[0] = z + PIO2_1T;
                y[1] = (z - y[0]) + PIO2_1T;
                return -1;
            }
        } else {
            if sign == 0 {
                let z = x - 2.0 * PIO2_1;
                y[0] = z - 2.0 * PIO2_1T;
                y[1] = (z - y[0]) - 2.0 * PIO2_1T;
                return 2;
            } else {
                let z = x + 2.0 * PIO2_1;
                y[0] = z + 2.0 * PIO2_1T;
                y[1] = (z - y[0]) + 2.0 * PIO2_1T;
                return -2;
            }
        }
    }
    if !use_medium && ix <= 0x401c463b {
        if ix <= 0x4015fdbc {
            if ix == 0x4012d97c {
                use_medium = true;
            } else if sign == 0 {
                let z = x - 3.0 * PIO2_1;
                y[0] = z - 3.0 * PIO2_1T;
                y[1] = (z - y[0]) - 3.0 * PIO2_1T;
                return 3;
            } else {
                let z = x + 3.0 * PIO2_1;
                y[0] = z + 3.0 * PIO2_1T;
                y[1] = (z - y[0]) + 3.0 * PIO2_1T;
                return -3;
            }
        } else if ix == 0x401921fb {
            use_medium = true;
        } else if sign == 0 {
            let z = x - 4.0 * PIO2_1;
            y[0] = z - 4.0 * PIO2_1T;
            y[1] = (z - y[0]) - 4.0 * PIO2_1T;
            return 4;
        } else {
            let z = x + 4.0 * PIO2_1;
            y[0] = z + 4.0 * PIO2_1T;
            y[1] = (z - y[0]) + 4.0 * PIO2_1T;
            return -4;
        }
    }
    if !use_medium && ix < 0x413921fb {
        use_medium = true;
    }
    if use_medium {
        let mut func = x * INVPIO2 + TOINT - TOINT;
        let mut n = func as i32;
        let mut r = x - func * PIO2_1;
        let mut w = func * PIO2_1T;
        if r - w < -PIO4 {
            n -= 1;
            func -= 1.0;
            r = x - func * PIO2_1;
            w = func * PIO2_1T;
        } else if r - w > PIO4 {
            n += 1;
            func += 1.0;
            r = x - func * PIO2_1;
            w = func * PIO2_1T;
        }
        y[0] = r - w;
        let ey = ((y[0].to_bits() >> 52) & 0x7ff) as i32;
        let ex = (ix >> 20) as i32;
        if ex - ey > 16 {
            let t = r;
            w = func * PIO2_2;
            r = t - w;
            w = func * PIO2_2T - ((t - r) - w);
            y[0] = r - w;
            let ey = ((y[0].to_bits() >> 52) & 0x7ff) as i32;
            if ex - ey > 49 {
                let t = r;
                w = func * PIO2_3;
                r = t - w;
                w = func * PIO2_3T - ((t - r) - w);
                y[0] = r - w;
            }
        }
        y[1] = (r - y[0]) - w;
        return n;
    }
    if ix >= 0x7ff00000 {
        y[0] = f64::NAN;
        y[1] = f64::NAN;
        return 0;
    }
    let mut uu = x.to_bits() & 0x000f_ffff_ffff_ffff;
    uu |= ((0x3ff + 23) as u64) << 52;
    let mut z = f64::from_bits(uu);
    let mut tx = [0.0f64; 3];
    let mut i = 0;
    while i < 2 {
        tx[i] = z as i32 as f64;
        z = (z - tx[i]) * 16777216.0;
        i += 1;
    }
    tx[i] = z;
    while tx[i] == 0.0 {
        i -= 1;
    }
    let mut ty = [0.0f64; 2];
    let n = k_rem_pio2_large(
        &tx,
        &mut ty,
        (ix >> 20) as i32 - (0x3ff + 23),
        (i + 1) as i32,
        1,
    );
    if sign != 0 {
        y[0] = -ty[0];
        y[1] = -ty[1];
        -n
    } else {
        y[0] = ty[0];
        y[1] = ty[1];
        n
    }
}

/// `f32` argument reduction (musl `__rem_pio2f.c`); result in `*y`.
fn k_rem_pio2f(x: f32, y: &mut f64) -> i32 {
    const TOINT: f64 = 6755399441055744.0;
    const PIO4: f64 = f64::from_bits(0x3FE921FB60000000);
    const INVPIO2: f64 = core::f64::consts::FRAC_2_PI;
    const PIO2_1: f64 = 1.5707963109016418;
    const PIO2_1T: f64 = 1.5893254773528196e-08;
    let u = x.to_bits();
    let ix = u & 0x7fffffff;
    if ix < 0x4dc90fdb {
        let mut func = x as f64 * INVPIO2 + TOINT - TOINT;
        let mut n = func as i32;
        *y = x as f64 - func * PIO2_1 - func * PIO2_1T;
        if *y < -PIO4 {
            n -= 1;
            func -= 1.0;
            *y = x as f64 - func * PIO2_1 - func * PIO2_1T;
        } else if *y > PIO4 {
            n += 1;
            func += 1.0;
            *y = x as f64 - func * PIO2_1 - func * PIO2_1T;
        }
        return n;
    }
    if ix >= 0x7f800000 {
        *y = f64::NAN;
        return 0;
    }
    let sign = u >> 31;
    let e0 = ((ix >> 23) as i32) - (0x7f + 23);
    let tx = [f32::from_bits(ix - ((e0 as u32) << 23)) as f64];
    let mut ty = [0.0f64];
    let n = k_rem_pio2_large(&tx, &mut ty, e0, 1, 0);
    if sign != 0 {
        *y = -ty[0];
        -n
    } else {
        *y = ty[0];
        n
    }
}

/// Sine (musl `src/math/sin.c`); `sin(+-Inf|NaN)` is NaN.
#[no_mangle]
pub extern "C" fn sin(x: f64) -> f64 {
    let ix = ((x.to_bits() >> 32) as u32) & 0x7fffffff;
    if ix <= 0x3fe921fb {
        if ix < 0x3e500000 {
            return x;
        }
        return k_sin(x, 0.0, 0);
    }
    if ix >= 0x7ff00000 {
        return f64::NAN; // x-x in musl
    }
    let mut y = [0.0f64; 2];
    let n = k_rem_pio2(x, &mut y);
    match n & 3 {
        0 => k_sin(y[0], y[1], 1),
        1 => k_cos(y[0], y[1]),
        2 => -k_sin(y[0], y[1], 1),
        _ => -k_cos(y[0], y[1]),
    }
}

/// Cosine (musl `src/math/cos.c`); `cos(+-Inf|NaN)` is NaN.
#[no_mangle]
pub extern "C" fn cos(x: f64) -> f64 {
    let ix = ((x.to_bits() >> 32) as u32) & 0x7fffffff;
    if ix <= 0x3fe921fb {
        if ix < 0x3e46a09e {
            return 1.0;
        }
        return k_cos(x, 0.0);
    }
    if ix >= 0x7ff00000 {
        return f64::NAN; // x-x in musl
    }
    let mut y = [0.0f64; 2];
    let n = k_rem_pio2(x, &mut y);
    match n & 3 {
        0 => k_cos(y[0], y[1]),
        1 => -k_sin(y[0], y[1], 1),
        2 => -k_cos(y[0], y[1]),
        _ => k_sin(y[0], y[1], 1),
    }
}

/// Tangent (musl `src/math/tan.c`); `tan(+-Inf|NaN)` is NaN.
#[no_mangle]
pub extern "C" fn tan(x: f64) -> f64 {
    let ix = ((x.to_bits() >> 32) as u32) & 0x7fffffff;
    if ix <= 0x3fe921fb {
        if ix < 0x3e400000 {
            return x;
        }
        return k_tan(x, 0.0, 0);
    }
    if ix >= 0x7ff00000 {
        return f64::NAN; // x-x in musl
    }
    let mut y = [0.0f64; 2];
    let n = k_rem_pio2(x, &mut y);
    k_tan(y[0], y[1], n & 1)
}

/// Sine+cosine via output pointers (musl `src/math/sincos.c`, void return).
///
/// # Safety
///
/// `s`/`c` must point to writable doubles.
#[no_mangle]
pub unsafe extern "C" fn sincos(x: f64, s: *mut f64, c: *mut f64) {
    let ix = ((x.to_bits() >> 32) as u32) & 0x7fffffff;
    let (sn, cs) = if ix <= 0x3fe921fb {
        if ix < 0x3e46a09e {
            (x, 1.0)
        } else {
            (k_sin(x, 0.0, 0), k_cos(x, 0.0))
        }
    } else if ix >= 0x7ff00000 {
        (f64::NAN, f64::NAN)
    } else {
        let mut y = [0.0f64; 2];
        let n = k_rem_pio2(x, &mut y);
        let s = k_sin(y[0], y[1], 1);
        let cc = k_cos(y[0], y[1]);
        match n & 3 {
            0 => (s, cc),
            1 => (cc, -s),
            2 => (-s, -cc),
            _ => (-cc, s),
        }
    };
    unsafe {
        *s = sn;
        *c = cs;
    }
}

#[no_mangle]
pub extern "C" fn asin(x: f64) -> f64 {
    const PIO2_HI: f64 = core::f64::consts::FRAC_PI_2;
    const PIO2_LO: f64 = 6.123233995736766e-17;
    const PS0: f64 = 0.16666666666666666;
    const PS1: f64 = -0.3255658186224009;
    const PS2: f64 = 0.20121253213486293;
    const PS3: f64 = -0.04005553450067941;
    const PS4: f64 = 0.0007915349942898145;
    const PS5: f64 = 3.479331075960212e-05;
    const QS1: f64 = -2.403394911734414;
    const QS2: f64 = 2.0209457602335057;
    const QS3: f64 = -0.6882839716054533;
    const QS4: f64 = 0.07703815055590194;
    fn r(z: f64) -> f64 {
        let p = z * (PS0 + z * (PS1 + z * (PS2 + z * (PS3 + z * (PS4 + z * PS5)))));
        let q = 1.0 + z * (QS1 + z * (QS2 + z * (QS3 + z * QS4)));
        p / q
    }
    let hx = (x.to_bits() >> 32) as u32;
    let ix = hx & 0x7fffffff;
    if ix >= 0x3ff00000 {
        let lx = x.to_bits() as u32;
        if ix.wrapping_sub(0x3ff00000) | lx == 0 {
            return x * PIO2_HI;
        }
        return f64::NAN; // 0.0/(x-x) in musl
    }
    if ix < 0x3fe00000 {
        if (0x00100000..0x3e500000).contains(&ix) {
            return x;
        }
        return x + x * r(x * x);
    }
    let z = (1.0 - fabs(x)) * 0.5;
    let s = k_sqrt(z);
    let rr = r(z);
    let v = if ix >= 0x3fef3333 {
        PIO2_HI - (2.0 * (s + s * rr) - PIO2_LO)
    } else {
        let f = k_set_lo(s);
        let cc = (z - f * f) / (s + f);
        0.5 * PIO2_HI - (2.0 * s * rr - (PIO2_LO - 2.0 * cc) - (0.5 * PIO2_HI - 2.0 * f))
    };
    if hx >> 31 != 0 {
        -v
    } else {
        v
    }
}

/// Arccosine (musl `src/math/acos.c`); `|x| > 1` is NaN.
#[no_mangle]
pub extern "C" fn acos(x: f64) -> f64 {
    const PIO2_HI: f64 = core::f64::consts::FRAC_PI_2;
    const PIO2_LO: f64 = 6.123233995736766e-17;
    const PS0: f64 = 0.16666666666666666;
    const PS1: f64 = -0.3255658186224009;
    const PS2: f64 = 0.20121253213486293;
    const PS3: f64 = -0.04005553450067941;
    const PS4: f64 = 0.0007915349942898145;
    const PS5: f64 = 3.479331075960212e-05;
    const QS1: f64 = -2.403394911734414;
    const QS2: f64 = 2.0209457602335057;
    const QS3: f64 = -0.6882839716054533;
    const QS4: f64 = 0.07703815055590194;
    fn r(z: f64) -> f64 {
        let p = z * (PS0 + z * (PS1 + z * (PS2 + z * (PS3 + z * (PS4 + z * PS5)))));
        let q = 1.0 + z * (QS1 + z * (QS2 + z * (QS3 + z * QS4)));
        p / q
    }
    let hx = (x.to_bits() >> 32) as u32;
    let ix = hx & 0x7fffffff;
    if ix >= 0x3ff00000 {
        let lx = x.to_bits() as u32;
        if ix.wrapping_sub(0x3ff00000) | lx == 0 {
            if hx >> 31 != 0 {
                return 2.0 * PIO2_HI;
            }
            return 0.0;
        }
        return f64::NAN; // 0.0/(x-x) in musl
    }
    if ix < 0x3fe00000 {
        if ix <= 0x3c600000 {
            return PIO2_HI;
        }
        return PIO2_HI - (x - (PIO2_LO - x * r(x * x)));
    }
    if hx >> 31 != 0 {
        let z = (1.0 + x) * 0.5;
        let s = k_sqrt(z);
        let w = r(z) * s - PIO2_LO;
        return 2.0 * (PIO2_HI - (s + w));
    }
    let z = (1.0 - x) * 0.5;
    let s = k_sqrt(z);
    let df = k_set_lo(s);
    let cc = (z - df * df) / (s + df);
    let w = r(z) * s + cc;
    2.0 * (df + w)
}

/// Arctangent (musl `src/math/atan.c`).
#[no_mangle]
pub extern "C" fn atan(mut x: f64) -> f64 {
    const ATANHI: [f64; 4] = [
        0.4636476090008061,
        core::f64::consts::FRAC_PI_4,
        0.982793723247329,
        core::f64::consts::FRAC_PI_2,
    ];
    const ATANLO: [f64; 4] = [
        2.2698777452961687e-17,
        3.061616997868383e-17,
        1.3903311031230998e-17,
        6.123233995736766e-17,
    ];
    const AT: [f64; 11] = [
        0.3333333333333293,
        -0.19999999999876483,
        0.14285714272503466,
        -0.11111110405462356,
        0.09090887133436507,
        -0.0769187620504483,
        0.06661073137387531,
        -0.058335701337905735,
        0.049768779946159324,
        -0.036531572744216916,
        0.016285820115365782,
    ];
    let mut ix = (x.to_bits() >> 32) as u32;
    let sign = ix >> 31;
    ix &= 0x7fffffff;
    if ix >= 0x44100000 {
        if x.is_nan() {
            return x;
        }
        let z = ATANHI[3];
        return if sign != 0 { -z } else { z };
    }
    let id: i32;
    if ix < 0x3fdc0000 {
        if ix < 0x3e400000 {
            return x;
        }
        id = -1;
    } else {
        x = fabs(x);
        if ix < 0x3ff30000 {
            if ix < 0x3fe60000 {
                id = 0;
                x = (2.0 * x - 1.0) / (2.0 + x);
            } else {
                id = 1;
                x = (x - 1.0) / (x + 1.0);
            }
        } else if ix < 0x40038000 {
            id = 2;
            x = (x - 1.5) / (1.0 + 1.5 * x);
        } else {
            id = 3;
            x = -1.0 / x;
        }
    }
    let z = x * x;
    let w = z * z;
    let s1 = z * (AT[0] + w * (AT[2] + w * (AT[4] + w * (AT[6] + w * (AT[8] + w * AT[10])))));
    let s2 = w * (AT[1] + w * (AT[3] + w * (AT[5] + w * (AT[7] + w * AT[9]))));
    if id < 0 {
        return x - x * (s1 + s2);
    }
    let z = ATANHI[id as usize] - (x * (s1 + s2) - ATANLO[id as usize] - x);
    if sign != 0 {
        -z
    } else {
        z
    }
}

/// `atan2(y, x)` (musl `src/math/atan2.c`) with the full edge table.
#[no_mangle]
pub extern "C" fn atan2(y: f64, x: f64) -> f64 {
    const PI: f64 = core::f64::consts::PI;
    const PI_LO: f64 = 1.224646799147353E-16;
    if x.is_nan() || y.is_nan() {
        return x + y;
    }
    let ux = x.to_bits();
    let uy = y.to_bits();
    let mut ix = (ux >> 32) as u32;
    let mut iy = (uy >> 32) as u32;
    let lx = ux as u32;
    let ly = uy as u32;
    if ix.wrapping_sub(0x3ff00000) | lx == 0 {
        return atan(y);
    }
    let m = (((uy >> 63) & 1) | ((ux >> 62) & 2)) as u32;
    ix &= 0x7fffffff;
    iy &= 0x7fffffff;
    if (iy | ly) == 0 {
        match m {
            0 | 1 => return y,
            2 => return PI,
            _ => return -PI,
        }
    }
    if (ix | lx) == 0 {
        return if m & 1 != 0 { -PI / 2.0 } else { PI / 2.0 };
    }
    if ix == 0x7ff00000 {
        if iy == 0x7ff00000 {
            match m {
                0 => return PI / 4.0,
                1 => return -PI / 4.0,
                2 => return 3.0 * PI / 4.0,
                _ => return -3.0 * PI / 4.0,
            }
        } else {
            match m {
                0 => return 0.0,
                1 => return -0.0,
                2 => return PI,
                _ => return -PI,
            }
        }
    }
    if ix.wrapping_add(64 << 20) < iy || iy == 0x7ff00000 {
        return if m & 1 != 0 { -PI / 2.0 } else { PI / 2.0 };
    }
    let z = if (m & 2) != 0 && iy.wrapping_add(64 << 20) < ix {
        0.0
    } else {
        atan(fabs(y / x))
    };
    match m {
        0 => z,
        1 => -z,
        2 => PI - (z - PI_LO),
        _ => (z - PI_LO) - PI,
    }
}

/// Hyperbolic sine (musl `src/math/sinh.c`).
#[no_mangle]
pub extern "C" fn sinh(x: f64) -> f64 {
    let u = x.to_bits();
    let mut h = 0.5;
    if u >> 63 != 0 {
        h = -h;
    }
    let absx = f64::from_bits(u & !(1 << 63));
    let w = ((u & !(1 << 63)) >> 32) as u32;
    if w < 0x40862e42 {
        let t = k_expm1(absx);
        if w < 0x3ff00000 {
            if w < 0x3ff00000 - (26 << 20) {
                return x;
            }
            return h * (2.0 * t - t * t / (t + 1.0));
        }
        return h * (t + t / (t + 1.0));
    }
    k_expo2(absx, 2.0 * h)
}

/// Overflow-safe `exp(x)*sign/2` for `|x| >= log(DBL_MAX)` (musl `__expo2.c`).
fn k_expo2(x: f64, sign: f64) -> f64 {
    const K: i32 = 2043;
    const KLN2: f64 = f64::from_bits(0x40962066151ADD8B); // 0x1.62066151add8bp+10
    let scale = f64::from_bits(((0x3ff + K / 2) as u64) << 20 << 32);
    k_exp(x - KLN2) * (sign * scale) * scale
}

/// Hyperbolic cosine (musl `src/math/cosh.c`).
#[no_mangle]
pub extern "C" fn cosh(x: f64) -> f64 {
    let u = x.to_bits();
    let ax = f64::from_bits(u & !(1 << 63));
    let w = ((u & !(1 << 63)) >> 32) as u32;
    if w < 0x3fe62e42 {
        if w < 0x3ff00000 - (26 << 20) {
            return 1.0;
        }
        let t = k_expm1(ax);
        return 1.0 + t * t / (2.0 * (1.0 + t));
    }
    if w < 0x40862e42 {
        let t = k_exp(ax);
        return 0.5 * (t + 1.0 / t);
    }
    k_expo2(ax, 1.0)
}

/// Hyperbolic tangent (musl `src/math/tanh.c`).
#[no_mangle]
pub extern "C" fn tanh(x: f64) -> f64 {
    let u = x.to_bits();
    let sign = u >> 63;
    let ax = f64::from_bits(u & !(1 << 63));
    let w = ((u & !(1 << 63)) >> 32) as u32;
    let t = if w > 0x3fe193ea {
        if w > 0x40340000 {
            1.0 - 0.0 / ax
        } else {
            let e = k_expm1(2.0 * ax);
            1.0 - 2.0 / (e + 2.0)
        }
    } else if w > 0x3fd058ae {
        let e = k_expm1(2.0 * ax);
        e / (e + 2.0)
    } else if w >= 0x00100000 {
        let e = k_expm1(-2.0 * ax);
        -e / (e + 2.0)
    } else {
        ax
    };
    if sign != 0 {
        -t
    } else {
        t
    }
}

/// Inverse hyperbolic sine (musl `src/math/asinh.c`).
#[no_mangle]
pub extern "C" fn asinh(x: f64) -> f64 {
    let u = x.to_bits();
    let e = ((u >> 52) & 0x7ff) as u32;
    let s = u >> 63;
    let ax = f64::from_bits(u & !(1 << 63));
    let v = if e >= 0x3ff + 26 {
        k_log(ax) + core::f64::consts::LN_2
    } else if e > 0x3ff {
        k_log(2.0 * ax + 1.0 / (k_sqrt(ax * ax + 1.0) + ax))
    } else if e >= 0x3ff - 26 {
        k_log1p(ax + ax * ax / (k_sqrt(ax * ax + 1.0) + 1.0))
    } else {
        ax
    };
    if s != 0 {
        -v
    } else {
        v
    }
}

/// Inverse hyperbolic cosine (musl `src/math/acosh.c`).
#[no_mangle]
pub extern "C" fn acosh(x: f64) -> f64 {
    let u = x.to_bits();
    let e = (u >> 52) as u32;
    if e < 0x3ff + 1 {
        return k_log1p(x - 1.0 + k_sqrt((x - 1.0) * (x - 1.0) + 2.0 * (x - 1.0)));
    }
    if e < 0x3ff + 26 {
        return k_log(2.0 * x - 1.0 / (x + k_sqrt(x * x - 1.0)));
    }
    if e & 0x800 != 0 {
        return f64::NAN; // (x-x)/(x-x) in musl
    }
    k_log(x) + core::f64::consts::LN_2
}

/// Inverse hyperbolic tangent (musl `src/math/atanh.c`).
#[no_mangle]
pub extern "C" fn atanh(x: f64) -> f64 {
    let u = x.to_bits();
    let e = ((u >> 52) & 0x7ff) as u32;
    let s = u >> 63;
    let y = f64::from_bits(u & !(1 << 63));
    let v = if e < 0x3ff - 1 {
        if e >= 0x3ff - 32 {
            0.5 * k_log1p(2.0 * y + 2.0 * y * y / (1.0 - y))
        } else {
            y
        }
    } else {
        0.5 * k_log1p(2.0 * (y / (1.0 - y)))
    };
    if s != 0 {
        -v
    } else {
        v
    }
}

/// Sine for `f32` (musl `src/math/sinf.c`).
#[no_mangle]
pub extern "C" fn sinf(x: f32) -> f32 {
    const S1PIO2: f64 = core::f64::consts::FRAC_PI_2;
    const S2PIO2: f64 = core::f64::consts::PI;
    const S3PIO2: f64 = 4.71238898038469;
    const S4PIO2: f64 = core::f64::consts::TAU;
    let ux = x.to_bits();
    let sign = ux >> 31;
    let ix = ux & 0x7fffffff;
    if ix <= 0x3f490fda {
        if ix < 0x39800000 {
            return x;
        }
        return k_sindf(x as f64);
    }
    if ix <= 0x407b53d1 {
        if ix <= 0x4016cbe3 {
            return if sign != 0 {
                -k_cosdf(x as f64 + S1PIO2)
            } else {
                k_cosdf(x as f64 - S1PIO2)
            };
        }
        return k_sindf(if sign != 0 {
            -(x as f64 + S2PIO2)
        } else {
            -(x as f64 - S2PIO2)
        });
    }
    if ix <= 0x40e231d5 {
        if ix <= 0x40afeddf {
            return if sign != 0 {
                k_cosdf(x as f64 + S3PIO2)
            } else {
                -k_cosdf(x as f64 - S3PIO2)
            };
        }
        return k_sindf(if sign != 0 {
            x as f64 + S4PIO2
        } else {
            x as f64 - S4PIO2
        });
    }
    if ix >= 0x7f800000 {
        return f32::NAN; // x-x in musl
    }
    let mut y = 0.0f64;
    let n = k_rem_pio2f(x, &mut y);
    match n & 3 {
        0 => k_sindf(y),
        1 => k_cosdf(y),
        2 => k_sindf(-y),
        _ => -k_cosdf(y),
    }
}

/// Cosine for `f32` (musl `src/math/cosf.c`).
#[no_mangle]
pub extern "C" fn cosf(x: f32) -> f32 {
    const C1PIO2: f64 = core::f64::consts::FRAC_PI_2;
    const C2PIO2: f64 = core::f64::consts::PI;
    const C3PIO2: f64 = 4.71238898038469;
    const C4PIO2: f64 = core::f64::consts::TAU;
    let ux = x.to_bits();
    let sign = ux >> 31;
    let ix = ux & 0x7fffffff;
    if ix <= 0x3f490fda {
        if ix < 0x39800000 {
            return 1.0;
        }
        return k_cosdf(x as f64);
    }
    if ix <= 0x407b53d1 {
        if ix > 0x4016cbe3 {
            return -k_cosdf(if sign != 0 {
                x as f64 + C2PIO2
            } else {
                x as f64 - C2PIO2
            });
        } else if sign != 0 {
            return k_sindf(x as f64 + C1PIO2);
        } else {
            return k_sindf(C1PIO2 - x as f64);
        }
    }
    if ix <= 0x40e231d5 {
        if ix > 0x40afeddf {
            return k_cosdf(if sign != 0 {
                x as f64 + C4PIO2
            } else {
                x as f64 - C4PIO2
            });
        } else if sign != 0 {
            return k_sindf(-x as f64 - C3PIO2);
        } else {
            return k_sindf(x as f64 - C3PIO2);
        }
    }
    if ix >= 0x7f800000 {
        return f32::NAN; // x-x in musl
    }
    let mut y = 0.0f64;
    let n = k_rem_pio2f(x, &mut y);
    match n & 3 {
        0 => k_cosdf(y),
        1 => k_sindf(-y),
        2 => -k_cosdf(y),
        _ => k_sindf(y),
    }
}

/// Tangent for `f32` (musl `src/math/tanf.c`).
#[no_mangle]
pub extern "C" fn tanf(x: f32) -> f32 {
    const T1PIO2: f64 = core::f64::consts::FRAC_PI_2;
    const T2PIO2: f64 = core::f64::consts::PI;
    const T3PIO2: f64 = 4.71238898038469;
    const T4PIO2: f64 = core::f64::consts::TAU;
    let ux = x.to_bits();
    let sign = ux >> 31;
    let ix = ux & 0x7fffffff;
    if ix <= 0x3f490fda {
        if ix < 0x39800000 {
            return x;
        }
        return k_tandf(x as f64, 0);
    }
    if ix <= 0x407b53d1 {
        if ix <= 0x4016cbe3 {
            return k_tandf(
                if sign != 0 {
                    x as f64 + T1PIO2
                } else {
                    x as f64 - T1PIO2
                },
                1,
            );
        }
        return k_tandf(
            if sign != 0 {
                x as f64 + T2PIO2
            } else {
                x as f64 - T2PIO2
            },
            0,
        );
    }
    if ix <= 0x40e231d5 {
        if ix <= 0x40afeddf {
            return k_tandf(
                if sign != 0 {
                    x as f64 + T3PIO2
                } else {
                    x as f64 - T3PIO2
                },
                1,
            );
        }
        return k_tandf(
            if sign != 0 {
                x as f64 + T4PIO2
            } else {
                x as f64 - T4PIO2
            },
            0,
        );
    }
    if ix >= 0x7f800000 {
        return f32::NAN; // x-x in musl
    }
    let mut y = 0.0f64;
    let n = k_rem_pio2f(x, &mut y);
    k_tandf(y, n & 1)
}

/// Sine+cosine for `f32` (musl `src/math/sincosf.c`, void return).
///
/// # Safety
///
/// `s`/`c` must point to writable floats.
#[no_mangle]
pub unsafe extern "C" fn sincosf(x: f32, s: *mut f32, c: *mut f32) {
    const S1PIO2: f64 = core::f64::consts::FRAC_PI_2;
    const S2PIO2: f64 = core::f64::consts::PI;
    const S3PIO2: f64 = 4.71238898038469;
    const S4PIO2: f64 = core::f64::consts::TAU;
    let ux = x.to_bits();
    let sign = ux >> 31;
    let ix = ux & 0x7fffffff;
    let (sn, cs): (f32, f32) = if ix <= 0x3f490fda {
        if ix < 0x39800000 {
            (x, 1.0)
        } else {
            (k_sindf(x as f64), k_cosdf(x as f64))
        }
    } else if ix <= 0x407b53d1 {
        if ix <= 0x4016cbe3 {
            if sign != 0 {
                (-k_cosdf(x as f64 + S1PIO2), k_sindf(x as f64 + S1PIO2))
            } else {
                (k_cosdf(S1PIO2 - x as f64), k_sindf(S1PIO2 - x as f64))
            }
        } else {
            let a = if sign != 0 {
                x as f64 + S2PIO2
            } else {
                x as f64 - S2PIO2
            };
            (-k_sindf(a), -k_cosdf(a))
        }
    } else if ix <= 0x40e231d5 {
        if ix <= 0x40afeddf {
            if sign != 0 {
                (k_cosdf(x as f64 + S3PIO2), -k_sindf(x as f64 + S3PIO2))
            } else {
                (-k_cosdf(x as f64 - S3PIO2), k_sindf(x as f64 - S3PIO2))
            }
        } else {
            let a = if sign != 0 {
                x as f64 + S4PIO2
            } else {
                x as f64 - S4PIO2
            };
            (k_sindf(a), k_cosdf(a))
        }
    } else if ix >= 0x7f800000 {
        (f32::NAN, f32::NAN)
    } else {
        let mut y = 0.0f64;
        let n = k_rem_pio2f(x, &mut y);
        let ss = k_sindf(y);
        let cc = k_cosdf(y);
        match n & 3 {
            0 => (ss, cc),
            1 => (cc, -ss),
            2 => (-ss, -cc),
            _ => (-cc, ss),
        }
    };
    unsafe {
        *s = sn;
        *c = cs;
    }
}

/// Arcsine for `f32` (musl `src/math/asinf.c`).
#[no_mangle]
pub extern "C" fn asinf(x: f32) -> f32 {
    const PIO2: f64 = core::f64::consts::FRAC_PI_2;
    const PS0: f32 = 0.16666587;
    const PS1: f32 = -0.042743422;
    const PS2: f32 = -0.008656363;
    const QS1: f32 = -0.70662963;
    fn r(z: f32) -> f32 {
        let p = z * (PS0 + z * (PS1 + z * PS2));
        p / (1.0f32 + z * QS1)
    }
    let hx = x.to_bits();
    let ix = hx & 0x7fffffff;
    if ix >= 0x3f800000 {
        if ix == 0x3f800000 {
            return (x as f64 * PIO2) as f32;
        }
        return f32::NAN; // 0.0/(x-x) in musl
    }
    if ix < 0x3f000000 {
        if (0x00800000..0x39800000).contains(&ix) {
            return x;
        }
        return x + x * r(x * x);
    }
    let z = (1.0f32 - fabsf(x)) * 0.5f32;
    let s = k_sqrt(z as f64);
    let v = PIO2 - 2.0 * (s + s * r(z) as f64);
    if hx >> 31 != 0 {
        -(v as f32)
    } else {
        v as f32
    }
}

/// Arccosine for `f32` (musl `src/math/acosf.c`).
#[no_mangle]
pub extern "C" fn acosf(x: f32) -> f32 {
    const PIO2_HI: f32 = f32::from_bits(0x3fc90fda);
    const PIO2_LO: f32 = 7.5497894e-08;
    const PS0: f32 = 0.16666587;
    const PS1: f32 = -0.042743422;
    const PS2: f32 = -0.008656363;
    const QS1: f32 = -0.70662963;
    fn r(z: f32) -> f32 {
        let p = z * (PS0 + z * (PS1 + z * PS2));
        p / (1.0f32 + z * QS1)
    }
    let hx = x.to_bits();
    let ix = hx & 0x7fffffff;
    if ix >= 0x3f800000 {
        if ix == 0x3f800000 {
            if hx >> 31 != 0 {
                return 2.0f32 * PIO2_HI;
            }
            return 0.0;
        }
        return f32::NAN; // 0.0/(x-x) in musl
    }
    if ix < 0x3f000000 {
        if ix <= 0x32800000 {
            return PIO2_HI;
        }
        return PIO2_HI - (x - (PIO2_LO - x * r(x * x)));
    }
    if hx >> 31 != 0 {
        let z = (1.0f32 + x) * 0.5f32;
        let s = k_sqrtf(z);
        let w = r(z) * s - PIO2_LO;
        return 2.0f32 * (PIO2_HI - (s + w));
    }
    let z = (1.0f32 - x) * 0.5f32;
    let s = k_sqrtf(z);
    let df = f32::from_bits(s.to_bits() & 0xfffff000);
    let cc = (z - df * df) / (s + df);
    let w = r(z) * s + cc;
    2.0f32 * (df + w)
}

/// Arctangent for `f32` (musl `src/math/atanf.c`).
#[no_mangle]
pub extern "C" fn atanf(mut x: f32) -> f32 {
    const ATANHI: [f32; 4] = [
        0.4636476,
        f32::from_bits(0x3f490fda),
        0.9827937,
        f32::from_bits(0x3fc90fda),
    ];
    const ATANLO: [f32; 4] = [5.0121582e-09, 3.7748947e-08, 3.4473217e-08, 7.5497894e-08];
    const AT: [f32; 5] = [
        0.33333328,
        -0.19999158,
        0.14253636,
        -0.106480174,
        0.061687607,
    ];
    let mut ix = x.to_bits();
    let sign = ix >> 31;
    ix &= 0x7fffffff;
    if ix >= 0x4c800000 {
        if x.is_nan() {
            return x;
        }
        let z = ATANHI[3];
        return if sign != 0 { -z } else { z };
    }
    let id: i32;
    if ix < 0x3ee00000 {
        if ix < 0x39800000 {
            return x;
        }
        id = -1;
    } else {
        x = fabsf(x);
        if ix < 0x3f980000 {
            if ix < 0x3f300000 {
                id = 0;
                x = (2.0f32 * x - 1.0f32) / (2.0f32 + x);
            } else {
                id = 1;
                x = (x - 1.0f32) / (x + 1.0f32);
            }
        } else if ix < 0x401c0000 {
            id = 2;
            x = (x - 1.5f32) / (1.0f32 + 1.5f32 * x);
        } else {
            id = 3;
            x = -1.0f32 / x;
        }
    }
    let z = x * x;
    let w = z * z;
    let s1 = z * (AT[0] + w * (AT[2] + w * AT[4]));
    let s2 = w * (AT[1] + w * AT[3]);
    if id < 0 {
        return x - x * (s1 + s2);
    }
    let z = ATANHI[id as usize] - ((x * (s1 + s2) - ATANLO[id as usize]) - x);
    if sign != 0 {
        -z
    } else {
        z
    }
}

/// `atan2` for `f32` (musl `src/math/atan2f.c`).
#[no_mangle]
pub extern "C" fn atan2f(y: f32, x: f32) -> f32 {
    const PI: f32 = core::f32::consts::PI;
    const PI_LO: f32 = -8.742278e-08;
    if x.is_nan() || y.is_nan() {
        return x + y;
    }
    let ux = x.to_bits();
    let uy = y.to_bits();
    let mut ix = ux;
    let mut iy = uy;
    if ix == 0x3f800000 {
        return atanf(y);
    }
    let m = ((uy >> 31) & 1) | ((ux >> 30) & 2);
    ix &= 0x7fffffff;
    iy &= 0x7fffffff;
    if iy == 0 {
        match m {
            0 | 1 => return y,
            2 => return PI,
            _ => return -PI,
        }
    }
    if ix == 0 {
        return if m & 1 != 0 { -PI / 2.0 } else { PI / 2.0 };
    }
    if ix == 0x7f800000 {
        if iy == 0x7f800000 {
            match m {
                0 => return PI / 4.0,
                1 => return -PI / 4.0,
                2 => return 3.0 * PI / 4.0,
                _ => return -3.0 * PI / 4.0,
            }
        } else {
            match m {
                0 => return 0.0,
                1 => return -0.0,
                2 => return PI,
                _ => return -PI,
            }
        }
    }
    if ix.wrapping_add(26 << 23) < iy || iy == 0x7f800000 {
        return if m & 1 != 0 { -PI / 2.0 } else { PI / 2.0 };
    }
    let z = if (m & 2) != 0 && iy.wrapping_add(26 << 23) < ix {
        0.0
    } else {
        atanf(fabsf(y / x))
    };
    match m {
        0 => z,
        1 => -z,
        2 => PI - (z - PI_LO),
        _ => (z - PI_LO) - PI,
    }
}

/// Hyperbolic sine for `f32` (musl `src/math/sinhf.c`).
#[no_mangle]
pub extern "C" fn sinhf(x: f32) -> f32 {
    let u = x.to_bits();
    let mut h = 0.5f32;
    if u >> 31 != 0 {
        h = -h;
    }
    let absx = f32::from_bits(u & 0x7fffffff);
    let w = u & 0x7fffffff;
    if w < 0x42b17217 {
        let t = k_expm1f(absx);
        if w < 0x3f800000 {
            if w < 0x3f800000 - (12 << 23) {
                return x;
            }
            return h * (2.0f32 * t - t * t / (t + 1.0f32));
        }
        return h * (t + t / (t + 1.0f32));
    }
    k_expo2f(absx, 2.0f32 * h)
}

/// Overflow-safe `expf(x)*sign/2` (musl `__expo2f.c`).
fn k_expo2f(x: f32, sign: f32) -> f32 {
    const KLN2: f32 = f32::from_bits(0x4322E3BC); // 0x1.45c778p+7
    let scale = f32::from_bits(((0x7f + 235 / 2) as u32) << 23);
    k_expf(x - KLN2) * (sign * scale) * scale
}

/// Hyperbolic cosine for `f32` (musl `src/math/coshf.c`).
#[no_mangle]
pub extern "C" fn coshf(x: f32) -> f32 {
    let u = x.to_bits();
    let ax = f32::from_bits(u & 0x7fffffff);
    let w = u & 0x7fffffff;
    if w < 0x3f317217 {
        if w < 0x3f800000 - (12 << 23) {
            return 1.0;
        }
        let t = k_expm1f(ax);
        return 1.0f32 + t * t / (2.0f32 * (1.0f32 + t));
    }
    if w < 0x42b17217 {
        let t = k_expf(ax);
        return 0.5f32 * (t + 1.0f32 / t);
    }
    k_expo2f(ax, 1.0)
}

/// Hyperbolic tangent for `f32` (musl `src/math/tanhf.c`).
#[no_mangle]
pub extern "C" fn tanhf(x: f32) -> f32 {
    let u = x.to_bits();
    let sign = u >> 31;
    let ax = f32::from_bits(u & 0x7fffffff);
    let w = u & 0x7fffffff;
    let t = if w > 0x3f0c9f54 {
        if w > 0x41200000 {
            1.0f32 + 0.0f32 / ax
        } else {
            let e = k_expm1f(2.0f32 * ax);
            1.0f32 - 2.0f32 / (e + 2.0f32)
        }
    } else if w > 0x3e82c578 {
        let e = k_expm1f(2.0f32 * ax);
        e / (e + 2.0f32)
    } else if w >= 0x00800000 {
        let e = k_expm1f(-2.0f32 * ax);
        -e / (e + 2.0f32)
    } else {
        ax
    };
    if sign != 0 {
        -t
    } else {
        t
    }
}

/// Inverse hyperbolic sine for `f32` (musl `src/math/asinhf.c`).
#[no_mangle]
pub extern "C" fn asinhf(x: f32) -> f32 {
    let u = x.to_bits();
    let i = u & 0x7fffffff;
    let s = u >> 31;
    let ax = f32::from_bits(i);
    let v = if i >= 0x3f800000 + (12 << 23) {
        k_logf(ax) + core::f32::consts::LN_2
    } else if i >= 0x3f800000 + (1 << 23) {
        k_logf(2.0f32 * ax + 1.0f32 / (k_sqrtf(ax * ax + 1.0f32) + ax))
    } else if i >= 0x3f800000 - (12 << 23) {
        k_log1pf(ax + ax * ax / (k_sqrtf(ax * ax + 1.0f32) + 1.0f32))
    } else {
        ax
    };
    if s != 0 {
        -v
    } else {
        v
    }
}

/// Inverse hyperbolic cosine for `f32` (musl `src/math/acoshf.c`).
#[no_mangle]
pub extern "C" fn acoshf(x: f32) -> f32 {
    let u = x.to_bits();
    if u < 0x3f800000 + (1 << 23) {
        return k_log1pf(x - 1.0f32 + k_sqrtf((x - 1.0f32) * (x - 1.0f32) + 2.0f32 * (x - 1.0f32)));
    }
    if u < 0x3f800000 + (12 << 23) {
        return k_logf(2.0f32 * x - 1.0f32 / (x + k_sqrtf(x * x - 1.0f32)));
    }
    if u & 0x80000000 != 0 {
        return f32::NAN; // (x-x)/(x-x) in musl
    }
    k_logf(x) + core::f32::consts::LN_2
}

/// Inverse hyperbolic tangent for `f32` (musl `src/math/atanhf.c`).
#[no_mangle]
pub extern "C" fn atanhf(x: f32) -> f32 {
    let u = x.to_bits();
    let s = u >> 31;
    let y = f32::from_bits(u & 0x7fffffff);
    let ui = y.to_bits();
    let v = if ui < 0x3f800000 - (1 << 23) {
        if ui >= 0x3f800000 - (32 << 23) {
            0.5f32 * k_log1pf(2.0f32 * y + 2.0f32 * y * y / (1.0f32 - y))
        } else {
            y
        }
    } else {
        0.5f32 * k_log1pf(2.0f32 * (y / (1.0f32 - y)))
    };
    if s != 0 {
        -v
    } else {
        v
    }
}

// Long-double shims: x86_64 `long double` is 80-bit extended, which stable
// Rust cannot represent, so these are `f64` wrappers (documented deviation
// in the module docs; musl paths: `sinl.c` etc. on the `LDBL_MANT_DIG==64`
// branch are the algorithmic reference).

/// `sinl` shim (musl `src/math/sinl.c`).
#[no_mangle]
pub extern "C" fn sinl(x: f64) -> f64 {
    sin(x)
}

/// `cosl` shim (musl `src/math/cosl.c`).
#[no_mangle]
pub extern "C" fn cosl(x: f64) -> f64 {
    cos(x)
}

/// `tanl` shim (musl `src/math/tanl.c`).
#[no_mangle]
pub extern "C" fn tanl(x: f64) -> f64 {
    tan(x)
}

/// `sincosl` shim (musl `src/math/sincosl.c`).
///
/// # Safety
///
/// `s`/`c` must point to writable doubles.
#[no_mangle]
pub unsafe extern "C" fn sincosl(x: f64, s: *mut f64, c: *mut f64) {
    unsafe { sincos(x, s, c) }
}

/// `asinl` shim (musl `src/math/asinl.c`).
#[no_mangle]
pub extern "C" fn asinl(x: f64) -> f64 {
    asin(x)
}

/// `acosl` shim (musl `src/math/acosl.c`).
#[no_mangle]
pub extern "C" fn acosl(x: f64) -> f64 {
    acos(x)
}

/// `atanl` shim (musl `src/math/atanl.c`).
#[no_mangle]
pub extern "C" fn atanl(x: f64) -> f64 {
    atan(x)
}

/// `atan2l` shim (musl `src/math/atan2l.c`).
#[no_mangle]
pub extern "C" fn atan2l(y: f64, x: f64) -> f64 {
    atan2(y, x)
}

/// `sinhl` shim (musl `src/math/sinhl.c`).
#[no_mangle]
pub extern "C" fn sinhl(x: f64) -> f64 {
    sinh(x)
}

/// `coshl` shim (musl `src/math/coshl.c`).
#[no_mangle]
pub extern "C" fn coshl(x: f64) -> f64 {
    cosh(x)
}

/// `tanhl` shim (musl `src/math/tanhl.c`).
#[no_mangle]
pub extern "C" fn tanhl(x: f64) -> f64 {
    tanh(x)
}

/// `asinhl` shim (musl `src/math/asinhl.c`).
#[no_mangle]
pub extern "C" fn asinhl(x: f64) -> f64 {
    asinh(x)
}

/// `acoshl` shim (musl `src/math/acoshl.c`).
#[no_mangle]
pub extern "C" fn acoshl(x: f64) -> f64 {
    acosh(x)
}

/// `atanhl` shim (musl `src/math/atanhl.c`).
#[no_mangle]
pub extern "C" fn atanhl(x: f64) -> f64 {
    atanh(x)
}

#[cfg(test)]
mod tests12a {
    use super::{
        acos, acosf, acosh, acoshf, acoshl, acosl, asin, asinf, asinh, asinhf, asinhl, asinl, atan,
        atan2, atan2f, atan2l, atanf, atanh, atanhf, atanhl, atanl, cos, cosf, cosh, coshf, coshl,
        cosl, sin, sincos, sincosf, sincosl, sinf, sinh, sinhf, sinhl, sinl, tan, tanf, tanh,
        tanhf, tanhl, tanl,
    };

    // Relative eps 1e-15 (~4.5ulp): covers musl-vs-reference (<1ulp on
    // basic paths, ~2ulp on exp/log-helper paths). Scaled by magnitude so
    // large results (sinh(10) ~ 1e4, ulp ~ 2e-12) get a fair bound.
    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() <= 1e-15 * b.abs().max(1.0)
    }

    #[test]
    fn trig_basic_f64() {
        assert!(close(sin(0.5), 0.479425538604203));
        assert!(close(cos(0.5), 0.8775825618903728));
        assert!(close(tan(0.5), 0.5463024898437905));
        assert!(close(sin(1.0), 0.8414709848078965));
        assert!(close(cos(1.0), 0.5403023058681398));
        assert!(close(tan(1.0), 1.5574077246549023));
        let (mut s, mut c) = (0.0, 0.0);
        unsafe { sincos(1.0, &mut s, &mut c) };
        assert!(close(s, 0.8414709848078965));
        assert!(close(c, 0.5403023058681398));
    }

    #[test]
    fn trig_reduction_f64() {
        // Reference values from the host libm; eps widened for range
        // reduction (1e-14 ~= small-arg, 1e-9 at 1e10 where tables differ).
        assert!((sin(100.0) - -0.5063656411097588).abs() <= 1e-14);
        assert!((cos(100.0) - 0.8623188722876839).abs() <= 1e-14);
        assert!(close(tan(3.0), -0.1425465430742778));
        assert!((sin(1e10) - -0.4875060250875107).abs() <= 1e-9);
        assert!((cos(1e10) - 0.873119622676856).abs() <= 1e-9);
    }

    #[test]
    fn trig_edges_f64() {
        assert!(sin(f64::INFINITY).is_nan());
        assert!(cos(f64::NEG_INFINITY).is_nan());
        assert!(tan(f64::INFINITY).is_nan());
        assert!(sin(f64::NAN).is_nan());
        assert!(cos(f64::NAN).is_nan());
        assert_eq!(sin(0.0).to_bits(), 0.0f64.to_bits());
        assert_eq!(sin(-0.0).to_bits(), (-0.0f64).to_bits());
        assert_eq!(cos(0.0), 1.0);
        assert_eq!(tan(0.0), 0.0);
        let (mut s, mut c) = (0.0, 0.0);
        unsafe { sincos(f64::INFINITY, &mut s, &mut c) };
        assert!(s.is_nan() && c.is_nan());
        unsafe { sincos(0.0, &mut s, &mut c) };
        assert_eq!(s, 0.0);
        assert_eq!(c, 1.0);
    }

    #[test]
    fn inv_trig_f64() {
        assert!(close(asin(0.5), core::f64::consts::FRAC_PI_6));
        assert!(close(acos(0.5), core::f64::consts::FRAC_PI_3));
        assert!(close(atan(1.0), core::f64::consts::FRAC_PI_4));
        assert!(close(atan2(1.0, 1.0), core::f64::consts::FRAC_PI_4));
        assert!(close(asin(1.0), core::f64::consts::FRAC_PI_2));
        assert!(close(acos(-1.0), core::f64::consts::PI));
        assert!(asin(2.0).is_nan());
        assert!(acos(2.0).is_nan());
        assert!(asin(f64::NAN).is_nan());
        assert!(close(atan(f64::INFINITY), core::f64::consts::FRAC_PI_2));
        assert!(close(
            atan(f64::NEG_INFINITY),
            -core::f64::consts::FRAC_PI_2
        ));
        assert_eq!(atan2(0.0, 0.0), 0.0);
        assert!(close(atan2(0.0, -1.0), core::f64::consts::PI));
        assert!(close(atan2(1.0, 0.0), core::f64::consts::FRAC_PI_2));
        assert!(close(
            atan2(f64::INFINITY, f64::INFINITY),
            core::f64::consts::FRAC_PI_4
        ));
        assert!(atan2(f64::NAN, 1.0).is_nan());
        assert!(close(atan(1e10), 1.5707963266948965));
    }

    #[test]
    fn hyp_f64() {
        assert!(close(sinh(1.0), 1.1752011936438014));
        assert!(close(cosh(1.0), 1.5430806348152437));
        assert!(close(tanh(1.0), 0.7615941559557649));
        assert!(close(sinh(10.0), 11013.232874703393));
        assert!(close(cosh(10.0), 11013.232920103323));
        assert!(close(tanh(10.0), 0.9999999958776927));
        assert_eq!(tanh(f64::INFINITY), 1.0);
        assert_eq!(tanh(f64::NEG_INFINITY), -1.0);
        assert_eq!(sinh(f64::INFINITY), f64::INFINITY);
        assert_eq!(sinh(f64::NEG_INFINITY), f64::NEG_INFINITY);
        assert_eq!(cosh(f64::INFINITY), f64::INFINITY);
        assert_eq!(cosh(0.0), 1.0);
        assert_eq!(sinh(0.0), 0.0);
        assert!(sinh(f64::NAN).is_nan());
        assert!(cosh(f64::NAN).is_nan());
        assert!(tanh(f64::NAN).is_nan());
        assert_eq!(sinh(-0.0).to_bits(), (-0.0f64).to_bits());
    }

    #[test]
    fn inv_hyp_f64() {
        assert!(close(asinh(1.0), 0.881373587019543));
        assert!(close(acosh(2.0), 1.3169578969248168));
        assert!(close(atanh(0.5), 0.5493061443340549));
        // exp/log-helper paths (~2ulp); eps widened to 1e-12.
        assert!((asinh(1e6) - 14.50865773852447).abs() <= 1e-12);
        assert!((acosh(1e6) - 14.508657738523969).abs() <= 1e-12);
        assert_eq!(asinh(f64::INFINITY), f64::INFINITY);
        assert_eq!(acosh(1.0), 0.0);
        assert!(acosh(0.0).is_nan());
        assert!(acosh(-1.0).is_nan());
        assert_eq!(atanh(1.0), f64::INFINITY);
        assert_eq!(atanh(-1.0), f64::NEG_INFINITY);
        assert!(atanh(2.0).is_nan());
        assert!(asinh(f64::NAN).is_nan());
        assert_eq!(asinh(-0.0).to_bits(), (-0.0f64).to_bits());
    }

    #[test]
    fn float_battery() {
        // eps 1e-6: f32 kernels carry a few ulp of error.
        fn c32(a: f32, b: f64) -> bool {
            (a as f64 - b).abs() <= 1e-6
        }
        assert!(c32(sinf(0.5), 0.479425538604203));
        assert!(c32(cosf(0.5), 0.8775825618903728));
        assert!(c32(tanf(0.5), 0.5463024898437905));
        assert!(c32(asinf(0.5), core::f64::consts::FRAC_PI_6));
        assert!(c32(acosf(0.5), core::f64::consts::FRAC_PI_3));
        assert!(c32(atanf(1.0), core::f64::consts::FRAC_PI_4));
        assert!(c32(atan2f(1.0, 1.0), core::f64::consts::FRAC_PI_4));
        assert!(c32(sinhf(1.0), 1.1752011936438014));
        assert!(c32(coshf(1.0), 1.5430806348152437));
        assert!(c32(tanhf(1.0), 0.7615941559557649));
        assert!(c32(asinhf(1.0), 0.881373587019543));
        assert!(c32(acoshf(2.0), 1.3169578969248168));
        assert!(c32(atanhf(0.5), 0.5493061443340549));
        assert!(c32(sinf(100.0), -0.5063656411097588));
        let (mut s, mut c) = (0.0f32, 0.0f32);
        unsafe { sincosf(1.0, &mut s, &mut c) };
        assert!(c32(s, 0.8414709848078965));
        assert!(c32(c, 0.5403023058681398));
        assert!(sinf(f32::INFINITY).is_nan());
        assert!(cosf(f32::INFINITY).is_nan());
        assert!(tanf(f32::NAN).is_nan());
        assert!(asinf(2.0).is_nan());
        assert!(acosf(-2.0).is_nan());
        assert!(atan2f(0.0, -1.0) > 3.1415925);
        assert_eq!(tanhf(f32::INFINITY), 1.0);
        assert_eq!(sinhf(0.0), 0.0);
        assert_eq!(coshf(0.0), 1.0);
        assert!(acoshf(0.0).is_nan());
        assert_eq!(atanhf(1.0), f32::INFINITY);
        assert!(asinhf(f32::NAN).is_nan());
    }

    #[test]
    fn longdouble_shims() {
        // Shims are f64-exact by construction; same 1e-15 bar.
        assert!(close(sinl(0.5), 0.479425538604203));
        assert!(close(cosl(0.5), 0.8775825618903728));
        assert!(close(tanl(0.5), 0.5463024898437905));
        assert!(close(asinl(0.5), core::f64::consts::FRAC_PI_6));
        assert!(close(acosl(0.5), core::f64::consts::FRAC_PI_3));
        assert!(close(atanl(1.0), core::f64::consts::FRAC_PI_4));
        assert!(close(atan2l(1.0, 1.0), core::f64::consts::FRAC_PI_4));
        assert!(close(sinhl(1.0), 1.1752011936438014));
        assert!(close(coshl(1.0), 1.5430806348152437));
        assert!(close(tanhl(1.0), 0.7615941559557649));
        assert!(close(asinhl(1.0), 0.881373587019543));
        assert!(close(acoshl(2.0), 1.3169578969248168));
        assert!(close(atanhl(0.5), 0.5493061443340549));
        let (mut s, mut c) = (0.0, 0.0);
        unsafe { sincosl(1.0, &mut s, &mut c) };
        assert!(close(s, 0.8414709848078965));
        assert!(close(c, 0.5403023058681398));
        assert!(sinl(f64::INFINITY).is_nan());
    }
}

/// 1/sqrt seed table (musl `sqrt_data.c` `__rsqrt_tab`; data, exact).
const K_RSQRT_TAB: [u16; 128] = [
    0xb451, 0xb2f0, 0xb196, 0xb044, 0xaef9, 0xadb6, 0xac79, 0xab43, 0xaa14, 0xa8eb, 0xa7c8, 0xa6aa,
    0xa592, 0xa480, 0xa373, 0xa26b, 0xa168, 0xa06a, 0x9f70, 0x9e7b, 0x9d8a, 0x9c9d, 0x9bb5, 0x9ad1,
    0x99f0, 0x9913, 0x983a, 0x9765, 0x9693, 0x95c4, 0x94f8, 0x9430, 0x936b, 0x92a9, 0x91ea, 0x912e,
    0x9075, 0x8fbe, 0x8f0a, 0x8e59, 0x8daa, 0x8cfe, 0x8c54, 0x8bac, 0x8b07, 0x8a64, 0x89c4, 0x8925,
    0x8889, 0x87ee, 0x8756, 0x86c0, 0x862b, 0x8599, 0x8508, 0x8479, 0x83ec, 0x8361, 0x82d8, 0x8250,
    0x81c9, 0x8145, 0x80c2, 0x8040, 0xff02, 0xfd0e, 0xfb25, 0xf947, 0xf773, 0xf5aa, 0xf3ea, 0xf234,
    0xf087, 0xeee3, 0xed47, 0xebb3, 0xea27, 0xe8a3, 0xe727, 0xe5b2, 0xe443, 0xe2dc, 0xe17a, 0xe020,
    0xdecb, 0xdd7d, 0xdc34, 0xdaf1, 0xd9b3, 0xd87b, 0xd748, 0xd61a, 0xd4f1, 0xd3cd, 0xd2ad, 0xd192,
    0xd07b, 0xcf69, 0xce5b, 0xcd51, 0xcc4a, 0xcb48, 0xca4a, 0xc94f, 0xc858, 0xc764, 0xc674, 0xc587,
    0xc49d, 0xc3b7, 0xc2d4, 0xc1f4, 0xc116, 0xc03c, 0xbf65, 0xbe90, 0xbdbe, 0xbcef, 0xbc23, 0xbb59,
    0xba91, 0xb9cc, 0xb90a, 0xb84a, 0xb78c, 0xb6d0, 0xb617, 0xb560,
];

/// Correctly-rounded `sqrt` re-derived from musl `src/math/sqrt.c` (integer
/// Goldschmidt + exact integer rounding decision; the `FENV_SUPPORT` block
/// is dropped — it only raises flags / serves directed roundings, and
/// `core` has neither — so results match musl in round-to-nearest).
fn k_sqrt(x: f64) -> f64 {
    fn mul32(a: u32, b: u32) -> u32 {
        (((a as u64) * (b as u64)) >> 32) as u32
    }
    fn mul64(a: u64, b: u64) -> u64 {
        let ahi = a >> 32;
        let alo = a & 0xffffffff;
        let bhi = b >> 32;
        let blo = b & 0xffffffff;
        ahi.wrapping_mul(bhi)
            .wrapping_add(ahi.wrapping_mul(blo) >> 32)
            .wrapping_add(alo.wrapping_mul(bhi) >> 32)
    }
    let mut ix = x.to_bits();
    let mut top = ix >> 52;
    if top.wrapping_sub(0x001) >= 0x7ff - 0x001 {
        if ix.wrapping_mul(2) == 0 {
            return x;
        }
        if ix == 0x7ff0000000000000 {
            return x;
        }
        if ix > 0x7ff0000000000000 {
            return f64::NAN; // (x-x)/(x-x) in musl
        }
        ix = (x * f64::from_bits(0x4330000000000000)).to_bits(); // x*2^52
        top = (ix >> 52).wrapping_sub(52);
    }
    let even = top & 1;
    let mut m = (ix << 11) | 0x8000000000000000;
    if even != 0 {
        m >>= 1;
    }
    top = (top.wrapping_add(0x3ff)) >> 1;
    const THREE: u64 = 0xc0000000;
    let i = ((ix >> 46) % 128) as usize;
    let mut r: u64 = ((K_RSQRT_TAB[i] as u32) << 16) as u64;
    let mut s: u64 = mul32((m >> 32) as u32, r as u32) as u64;
    let mut d: u64 = mul32(s as u32, r as u32) as u64;
    let mut u = THREE.wrapping_sub(d);
    r = (mul32(r as u32, u as u32) as u64) << 1;
    s = (mul32(s as u32, u as u32) as u64) << 1;
    d = mul32(s as u32, r as u32) as u64;
    u = THREE.wrapping_sub(d);
    r = (mul32(r as u32, u as u32) as u64) << 1;
    r <<= 32;
    s = mul64(m, r);
    d = mul64(s, r);
    u = (THREE << 32).wrapping_sub(d);
    s = mul64(s, u);
    s = s.wrapping_sub(2) >> 9;
    let d0 = (m << 42).wrapping_sub(s.wrapping_mul(s));
    let d1 = s.wrapping_sub(d0);
    let _d2 = d1.wrapping_add(s).wrapping_add(1); // exact-case flag; only feeds dropped fenv block
    s = s.wrapping_add(d1 >> 63);
    s &= 0x000fffffffffffff;
    s |= top << 52;
    f64::from_bits(s)
}

/// `sqrtf` re-derived from musl `src/math/sqrtf.c` (same FENV note as
/// [`k_sqrt`]).
fn k_sqrtf(x: f32) -> f32 {
    fn mul32(a: u32, b: u32) -> u32 {
        ((a as u64).wrapping_mul(b as u64) >> 32) as u32
    }
    let mut ix = x.to_bits();
    if ix.wrapping_sub(0x00800000) >= 0x7f800000 - 0x00800000 {
        if ix.wrapping_mul(2) == 0 {
            return x;
        }
        if ix == 0x7f800000 {
            return x;
        }
        if ix > 0x7f800000 {
            return f32::NAN; // (x-x)/(x-x) in musl
        }
        ix = (x * f32::from_bits(0x4B000000)).to_bits(); // x*2^23
        ix = ix.wrapping_sub(23 << 23);
    }
    let even = ix & 0x00800000;
    let m1 = (ix << 8) | 0x80000000;
    let m0 = (ix << 7) & 0x7fffffff;
    let m = if even != 0 { m0 } else { m1 };
    let mut ey = ix >> 1;
    ey += 0x3f800000 >> 1;
    ey &= 0x7f800000;
    const THREE: u32 = 0xc0000000;
    let i = ((ix >> 17) % 128) as usize;
    let mut r = (K_RSQRT_TAB[i] as u32) << 16;
    let mut s = mul32(m, r);
    let mut d = mul32(s, r);
    let mut u = THREE.wrapping_sub(d);
    r = mul32(r, u) << 1;
    s = mul32(s, u) << 1;
    d = mul32(s, r);
    u = THREE.wrapping_sub(d);
    s = mul32(s, u);
    s = s.wrapping_sub(1) >> 6;
    let d0 = (m << 16).wrapping_sub(s.wrapping_mul(s));
    let d1 = s.wrapping_sub(d0);
    let _d2 = d1.wrapping_add(s).wrapping_add(1); // exact-case flag; only feeds dropped fenv block
    s = s.wrapping_add(d1 >> 31);
    s &= 0x007fffff;
    s |= ey;
    f32::from_bits(s)
}
