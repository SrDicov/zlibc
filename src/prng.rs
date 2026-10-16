//! Pseudorandom generators (musl `src/prng/rand.c`, `rand_r.c`,
//! `random.c`, `drand48.c`, `lrand48.c`, `mrand48.c`, `seed48.c`,
//! `srand48.c`, `lcong48.c`, `__rand48_step.c`, `__seed48.c`).
//!
//! Algorithms are musl-verbatim: `rand` is the 64-bit LCG
//! (`6364136223846793005*seed+1`, output `seed>>33`); `random` is musl's
//! nonlinear additive-feedback generator with the same `init` tableaux,
//! sizes (0/7/15/31/63) and seed scrambling; the `*48` family is the
//! 48-bit `a=0x5DEECE66D, c=0xB` step over `u16[3]` with musl's default
//! `__seed48` words. All arithmetic uses wrapping ops (identical values
//! on any build profile).
//!
//! State lives in plain `static mut` globals, like musl's BSS state, and
//! — like musl's data-race-tolerant PRNGs — there is deliberately no
//! locking: concurrent callers race exactly the way musl's do, so the
//! observable contract is identical single-threaded and no stronger
//! multi-threaded. musl's internal `__rand48_step`/`__seed48` stay
//! private here (no `weak_alias` needed).

use core::ffi::{c_char, c_int, c_long, c_uint};

// ---- rand (musl rand.c) -----------------------------------------------------

/// musl `rand.c`: BSS seed (behaves as if `srand(1)` until seeded).
static mut RAND_SEED: u64 = 0;

/// Seed the `rand` LCG (musl `srand`: `seed = s-1`, computed in 32 bits
/// so `srand(0)` wraps to `UINT_MAX` before widening, exactly like the
/// C unsigned arithmetic).
///
/// # Safety
///
/// Writes process-global state; single-threaded contract only (see
/// module docs).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn srand(s: c_uint) {
    unsafe {
        RAND_SEED = s.wrapping_sub(1) as u64;
    }
}

/// Next `rand` value in `0..=RAND_MAX` (musl `rand`: `seed>>33`, which
/// tops out at `2^31-1`).
///
/// # Safety
///
/// Reads/writes process-global state; single-threaded contract only
/// (see module docs).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn rand() -> c_int {
    unsafe {
        RAND_SEED = RAND_SEED.wrapping_mul(6364136223846793005).wrapping_add(1);
        (RAND_SEED >> 33) as c_int
    }
}

// ---- rand_r (musl rand_r.c) -------------------------------------------------

/// musl `rand_r.c` tempering pass, verbatim.
fn temper(mut x: u32) -> u32 {
    x ^= x >> 11;
    x ^= (x << 7) & 0x9D2C_5680;
    x ^= (x << 15) & 0xEFC6_0000;
    x ^= x >> 18;
    x
}

/// Reentrant `rand` on an explicit seed (musl `rand_r`: no globals —
/// `*seed = *seed*1103515245+12345`, tempered, halved).
///
/// # Safety
///
/// `seed` must point to a writable `unsigned`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn rand_r(seed: *mut c_uint) -> c_int {
    unsafe {
        let s = (*seed).wrapping_mul(1103515245).wrapping_add(12345);
        *seed = s;
        (temper(s) / 2) as c_int
    }
}

// ---- random (musl random.c) -------------------------------------------------

/// musl `random.c` default tableaux (`init[32]`).
static mut R_INIT: [u32; 32] = [
    0x00000000, 0x5851f42d, 0xc0b18ccf, 0xcbb5f646, 0xc7033129, 0x30705b04, 0x20fd5db4, 0x9a8b7f78,
    0x502959d8, 0xab894868, 0x6c0356a7, 0x88cdb7ff, 0xb477d43f, 0x70a3a52b, 0xa8e4baf1, 0xfd8341fc,
    0x8ae16fd9, 0x742d2f7a, 0x0d1f0796, 0x76035e09, 0x40f7702c, 0x6fa72ca5, 0xaaa84157, 0x58a0df74,
    0xc74a0364, 0xae533cc4, 0x04185faf, 0x6de3b115, 0x0cab8628, 0xf043bfa4, 0x398150e9, 0x37521657,
];
/// musl `random.c` globals (`n`, `i`, `j`, `x`; `x` starts at
/// `init+1` — lazily, since Rust statics cannot point at each other).
static mut R_N: c_int = 31;
static mut R_I: c_int = 3;
static mut R_J: c_int = 0;
static mut R_X: *mut u32 = core::ptr::null_mut();

/// Current tableaux pointer, binding `R_X` to `R_INIT+1` on first use
/// (observably identical to musl's load-time `x = init+1`).
unsafe fn rx() -> *mut u32 {
    unsafe {
        if R_X.is_null() {
            R_X = core::ptr::addr_of_mut!(R_INIT).cast::<u32>().add(1);
        }
        R_X
    }
}

/// musl `lcg31` (the `n == 0` short-state path).
fn lcg31(x: u32) -> u32 {
    1103515245u32.wrapping_mul(x).wrapping_add(12345) & 0x7fff_ffff
}

/// musl `lcg64` (the seeder).
fn lcg64(x: u64) -> u64 {
    6364136223846793005u64.wrapping_mul(x).wrapping_add(1)
}

/// musl `savestate`: stamp `(n<<16)|(i<<8)|j` into `x[-1]`, return `x-1`.
unsafe fn savestate() -> *mut c_char {
    unsafe {
        let x = rx();
        *x.sub(1) = ((R_N << 16) | (R_I << 8) | R_J) as u32;
        x.sub(1) as *mut c_char
    }
}

/// musl `loadstate`.
unsafe fn loadstate(state: *mut c_char) {
    unsafe {
        let x = state as *mut u32;
        R_X = x.add(1);
        let hdr = *x;
        R_N = (hdr >> 16) as c_int;
        R_I = ((hdr >> 8) & 0xff) as c_int;
        R_J = (hdr & 0xff) as c_int;
    }
}

/// musl `__srandom`.
unsafe fn srandom_inner(seed: c_uint) {
    unsafe {
        if R_N == 0 {
            *rx() = seed;
            return;
        }
        R_I = if R_N == 31 || R_N == 7 { 3 } else { 1 };
        R_J = 0;
        let x = rx();
        let mut s = seed as u64;
        let mut k: usize = 0;
        while k < R_N as usize {
            s = lcg64(s);
            *x.add(k) = (s >> 32) as u32;
            k = k.wrapping_add(1);
        }
        // musl: at least one odd word.
        *x |= 1;
    }
}

/// Seed the `random` generator (musl `srandom`).
///
/// # Safety
///
/// Writes process-global state; single-threaded contract only (see
/// module docs).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn srandom(seed: c_uint) {
    unsafe {
        srandom_inner(seed);
    }
}

/// Install `state` (`size` bytes) as the `random` tableaux for `seed`,
/// returning the previous state (musl `initstate`: `size < 8` fails
/// with null; degree from `8/32/64/128/256` boundaries).
///
/// # Safety
///
/// `state` must point to `size` writable bytes usable as `u32` words
/// (4-byte aligned like `malloc`'d memory). The returned pointer stays
/// valid while its backing lives (static tableaux or a previous
/// `state` argument).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn initstate(seed: c_uint, state: *mut c_char, size: usize) -> *mut c_char {
    unsafe {
        if size < 8 {
            return core::ptr::null_mut();
        }
        let old = savestate();
        if size < 32 {
            R_N = 0;
        } else if size < 64 {
            R_N = 7;
        } else if size < 128 {
            R_N = 15;
        } else if size < 256 {
            R_N = 31;
        } else {
            R_N = 63;
        }
        R_X = (state as *mut u32).add(1);
        srandom_inner(seed);
        savestate();
        old
    }
}

/// Swap the `random` tableaux to a state from [`initstate`], returning
/// the previous one (musl `setstate`).
///
/// # Safety
///
/// Same backing-lifetime contract as [`initstate`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setstate(state: *mut c_char) -> *mut c_char {
    unsafe {
        let old = savestate();
        loadstate(state);
        old
    }
}

/// Next `random` value (musl `random`: additive feedback `x[i]+x[j]`,
/// halved; 31-bit LCG when the state is short).
///
/// # Safety
///
/// Reads/writes process-global state; single-threaded contract only
/// (see module docs).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn random() -> c_long {
    unsafe {
        let x = rx();
        if R_N == 0 {
            let k = lcg31(*x);
            *x = k;
            return k as c_long;
        }
        let v = (*x.add(R_I as usize)).wrapping_add(*x.add(R_J as usize));
        *x.add(R_I as usize) = v;
        let k = v >> 1;
        R_I = if R_I.wrapping_add(1) == R_N {
            0
        } else {
            R_I.wrapping_add(1)
        };
        R_J = if R_J.wrapping_add(1) == R_N {
            0
        } else {
            R_J.wrapping_add(1)
        };
        k as c_long
    }
}

// ---- drand48 family (musl __rand48_step.c, __seed48.c, seed48.c, -------
// ---- srand48.c, lcong48.c, drand48.c, lrand48.c, mrand48.c) -------------

/// musl `__seed48[7]`: 48-bit `xi` + multiplier `0x5DEECE66D` + addend
/// `0xB`, little-word-first.
static mut SEED48: [u16; 7] = [0, 0, 0, 0xe66d, 0xdeec, 0x5, 0xb];

/// musl `__rand48_step`: `x = a*x + c` over the `u16[3]` state, low 48
/// bits kept; returns the new 48-bit value.
unsafe fn rand48_step(xi: *mut u16, lc: *mut u16) -> u64 {
    unsafe {
        let x = (*xi.add(0) as u64) | ((*xi.add(1) as u64) << 16) | ((*xi.add(2) as u64) << 32);
        let a = (*lc.add(0) as u64) | ((*lc.add(1) as u64) << 16) | ((*lc.add(2) as u64) << 32);
        let v = a.wrapping_mul(x).wrapping_add(*lc.add(3) as u64) & 0xffff_ffff_ffff;
        *xi.add(0) = v as u16;
        *xi.add(1) = (v >> 16) as u16;
        *xi.add(2) = (v >> 32) as u16;
        v
    }
}

/// Multiplier/addend words inside [`SEED48`].
unsafe fn seed48_lc() -> *mut u16 {
    unsafe { core::ptr::addr_of_mut!(SEED48).cast::<u16>().add(3) }
}

/// Reentrant 48-bit uniform in `[0, 1)` (musl `erand48`: bit-stuff the
/// step into a `1.xxx` double, subtract 1).
///
/// # Safety
///
/// `s` must point to 3 writable `unsigned short` words.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn erand48(s: *mut u16) -> f64 {
    unsafe { f64::from_bits(0x3ff0_0000_0000_0000u64 | (rand48_step(s, seed48_lc()) << 4)) - 1.0 }
}

/// Uniform `double` in `[0, 1)` from the global 48-bit state (musl
/// `drand48`).
///
/// # Safety
///
/// Reads/writes process-global state; single-threaded contract only
/// (see module docs).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn drand48() -> f64 {
    unsafe { erand48(core::ptr::addr_of_mut!(SEED48).cast::<u16>()) }
}

/// Reentrant non-negative 48-bit `long` (musl `nrand48`: step `>> 17`).
///
/// # Safety
///
/// `s` must point to 3 writable `unsigned short` words.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn nrand48(s: *mut u16) -> c_long {
    unsafe { (rand48_step(s, seed48_lc()) >> 17) as c_long }
}

/// Non-negative `long` from the global 48-bit state (musl `lrand48`).
///
/// # Safety
///
/// Reads/writes process-global state; single-threaded contract only
/// (see module docs).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn lrand48() -> c_long {
    unsafe { nrand48(core::ptr::addr_of_mut!(SEED48).cast::<u16>()) }
}

/// Reentrant signed 48-bit `long` (musl `jrand48`: step `>> 16`,
/// truncated to `i32`).
///
/// # Safety
///
/// `s` must point to 3 writable `unsigned short` words.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn jrand48(s: *mut u16) -> c_long {
    unsafe { (rand48_step(s, seed48_lc()) >> 16) as i32 as c_long }
}

/// Signed `long` from the global 48-bit state (musl `mrand48`).
///
/// # Safety
///
/// Reads/writes process-global state; single-threaded contract only
/// (see module docs).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mrand48() -> c_long {
    unsafe { jrand48(core::ptr::addr_of_mut!(SEED48).cast::<u16>()) }
}

/// Seed the global 48-bit state (musl `srand48`: `xi = {0x330e,
/// seed, seed>>16}`, C-truncated to 16 bits).
///
/// # Safety
///
/// Writes process-global state; single-threaded contract only (see
/// module docs).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn srand48(seed: c_long) {
    unsafe {
        let mut tmp = [0x330eu16, seed as u16, (seed >> 16) as u16];
        seed48(tmp.as_mut_ptr());
    }
}

/// Swap the whole 7-word global 48-bit state, returning the previous
/// `xi` (musl `seed48`: function-static 3-word slot).
///
/// # Safety
///
/// `s` must point to 3 readable `unsigned short` words. The returned
/// pointer stays valid until the next `seed48` call; do not free it.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn seed48(s: *mut u16) -> *mut u16 {
    static mut P: [u16; 3] = [0; 3];
    unsafe {
        core::ptr::copy_nonoverlapping(
            core::ptr::addr_of!(SEED48).cast::<u16>(),
            core::ptr::addr_of_mut!(P).cast::<u16>(),
            3,
        );
        core::ptr::copy_nonoverlapping(
            s as *const u16,
            core::ptr::addr_of_mut!(SEED48).cast::<u16>(),
            3,
        );
        core::ptr::addr_of_mut!(P).cast::<u16>()
    }
}

/// Install a full 7-word 48-bit parameter set (musl `lcong48`).
///
/// # Safety
///
/// `p` must point to 7 readable `unsigned short` words.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn lcong48(p: *mut u16) {
    unsafe {
        core::ptr::copy_nonoverlapping(
            p as *const u16,
            core::ptr::addr_of_mut!(SEED48).cast::<u16>(),
            7,
        );
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;

    /// musl `rand.c` compiled with gcc: `srand(1)` yields
    /// `0, 740882966, 1616430695` (`seed = 1 → 1>>33 = 0` by hand for
    /// the first; the rest cross-checked against the reference build).
    #[test]
    fn rand_matches_musl() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            srand(1);
            assert_eq!(rand(), 0);
            assert_eq!(rand(), 740882966);
            assert_eq!(rand(), 1616430695);
        }
    }

    /// `rand_r` threads state through the pointer: same seed repeats,
    /// distinct seeds diverge (both values musl-verified).
    #[test]
    fn rand_r_uses_only_its_seed() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut a: c_uint = 1;
            assert_eq!(rand_r(core::ptr::addr_of_mut!(a)), 1993684161);
            assert_eq!(rand_r(core::ptr::addr_of_mut!(a)), 1388323688);
            let mut a2: c_uint = 1;
            assert_eq!(rand_r(core::ptr::addr_of_mut!(a2)), 1993684161);
            let mut b: c_uint = 2;
            assert_ne!(rand_r(core::ptr::addr_of_mut!(b)), 1993684161);
        }
    }

    /// `srandom(1)` replays the same `random()` run (first triple
    /// musl-verified: `262836907, 2022765545, 1985587709`). The degree
    /// is pinned to 31 first: like musl's, `srandom` reseeds within the
    /// *current* degree, so the triple only holds at `n == 31`.
    #[test]
    fn random_reseeds_deterministically() {
        // Static park: musl's `x` is a live pointer (see
        // `initstate_setstate_roundtrip`).
        static mut DEG31: [u32; 32] = [0; 32];
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            initstate(1, core::ptr::addr_of_mut!(DEG31).cast::<c_char>(), 128);
            srandom(1);
            let first = [random(), random(), random()];
            assert_eq!(first, [262836907, 2022765545, 1985587709]);
            srandom(1);
            assert_eq!([random(), random(), random()], first);
        }
    }

    /// `initstate` reseeds repeatably, `setstate` restores a snapshot,
    /// and `size < 8` fails with null (all musl-verified).
    #[test]
    fn initstate_setstate_roundtrip() {
        // musl's `x` is a live pointer: leaving it aimed at `buf`/`snap`
        // below would dangle (the C equivalent of free()ing an
        // `initstate` buffer), so the test parks globals here on exit.
        static mut STABLE_STATE: [u32; 64] = [0; 64];
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut buf = [0u32; 32];
            let bp = buf.as_mut_ptr().cast::<c_char>();
            assert!(!initstate(1, bp, 128).is_null());
            let a1 = random();
            // Same seed over the same buffer replays.
            assert!(!initstate(1, bp, 128).is_null());
            let mut snap = [0u32; 32];
            snap.copy_from_slice(&buf);
            let a2 = random();
            assert_eq!(a1, a2);
            // A snapshot restores the unconsumed stream.
            setstate(snap.as_mut_ptr().cast::<c_char>());
            assert_eq!(random(), a2);
            let mut tiny = [0u32; 1];
            assert!(initstate(1, tiny.as_mut_ptr().cast::<c_char>(), 4).is_null());
            initstate(
                0,
                core::ptr::addr_of_mut!(STABLE_STATE).cast::<c_char>(),
                256,
            );
        }
    }

    /// `*48` values after `srand48(1)` (musl-verified): `lrand48`
    /// `89400484, 976015093, 1792756325`; `mrand48`/`jrand48`
    /// `178800969`; `drand48`/`erand48` `0.04163…`; zero state steps
    /// to `0xB >> 17 == 0`; `seed48`/`lcong48` reinstall state.
    #[test]
    fn drand48_family_matches_musl() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            srand48(1);
            assert_eq!(lrand48(), 89400484);
            assert_eq!(lrand48(), 976015093);
            assert_eq!(lrand48(), 1792756325);
            srand48(1);
            assert_eq!(mrand48(), 178800969);
            srand48(1);
            assert_eq!(drand48(), 0.041630344771878214);
            assert_eq!(drand48(), 0.45449244472862915);
            let mut x = [0x330eu16, 1, 0];
            assert_eq!(nrand48(x.as_mut_ptr()), 89400484);
            let mut y = [0x330eu16, 1, 0];
            assert_eq!(jrand48(y.as_mut_ptr()), 178800969);
            let mut z = [0x330eu16, 1, 0];
            assert_eq!(erand48(z.as_mut_ptr()), 0.041630344771878214);
            // Zero state: single addend step, still zero after >> 17.
            let mut zero = [0u16; 3];
            assert_eq!(nrand48(zero.as_mut_ptr()), 0);
            // seed48 snapshot/restore roundtrip.
            srand48(1);
            let mut tmp = [0u16; 3];
            let p = seed48(tmp.as_mut_ptr());
            let mut saved = [0u16; 3];
            saved[0] = *p.add(0);
            saved[1] = *p.add(1);
            saved[2] = *p.add(2);
            seed48(saved.as_mut_ptr());
            assert_eq!(lrand48(), 89400484);
            // lcong48 installs a full parameter set verbatim.
            let mut full = [0x330eu16, 1, 0, 0xe66d, 0xdeec, 0x5, 0xb];
            lcong48(full.as_mut_ptr());
            assert_eq!(lrand48(), 89400484);
        }
    }
}
