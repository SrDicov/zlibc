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

#[cfg(test)]
mod tests {
    use super::{copysign, copysignf, fabs, fabsf};

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
}
