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
        f64::from_bits(u & !((1u64 << (1074 - e)) - 1))
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
    if x < 0.0 && t != x { t - 1.0 } else { t }
}

/// `floor` for `f32`.
#[no_mangle]
pub extern "C" fn floorf(x: f32) -> f32 {
    let t = truncf(x);
    if x < 0.0 && t != x { t - 1.0 } else { t }
}

/// Round up, via [`trunc`] (musl `ceil`, mirrored).
#[no_mangle]
pub extern "C" fn ceil(x: f64) -> f64 {
    let t = trunc(x);
    if x > 0.0 && t != x { t + 1.0 } else { t }
}

/// `ceil` for `f32`.
#[no_mangle]
pub extern "C" fn ceilf(x: f32) -> f32 {
    let t = truncf(x);
    if x > 0.0 && t != x { t + 1.0 } else { t }
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
    use super::{ceil, ceilf, copysign, copysignf, fabs, fabsf, floor, floorf, round, roundf, trunc, truncf};

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
