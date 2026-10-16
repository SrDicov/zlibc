//! Multibyte/wide conversion + iconv (musl `src/multibyte/*`,
//! `src/locale/iconv.c`, `src/locale/iconv_close.c`).
//!
//! Reference map: the `src/multibyte/iconv.c` + `iconv_open.c` names do not
//! exist in musl; both live in `src/locale/iconv.c` (`iconv_open` is
//! `iconv.c:144-170`), `iconv_close` in `src/locale/iconv_close.c:4-8`.
//! `mbstate_t` is 8 bytes (musl `include/alltypes.h.in:73`: two `unsigned`s,
//! compile-asserted below); `mbsinit` reads the first word only, like musl's
//! `!*(unsigned *)st` (`src/multibyte/mbsinit.c:5`).
//!
//! C-LOCALE SCOPE (musl with `MB_CUR_MAX == 1`, i.e. `!CURRENT_UTF8`,
//! `src/internal/locale_impl.h:45`): every function below is ASCII-only —
//! bytes `>= 0x80` fail with `EILSEQ` and consume nothing, and `wchar_t`
//! values outside `0x00..=0x7F` (including negatives) fail the same way. No
//! UTF-8 decoding/encoding is implemented; it arrives with the locale-data
//! wave (dtoa/scanf already assume single bytes consistently).
//!
//! Deviations from musl, one line each:
//! - musl single-byte locales map `0x80..=0xFF` through `CODEUNIT` to
//!   `U+DF80..=U+DFFF` (`src/multibyte/internal.h:20`); here those bytes
//!   are `EILSEQ` (full code-unit tables arrive with locale data).
//! - musl `iconv` supports dozens of charsets (the `charmaps` table in
//!   `src/locale/iconv.c`); `iconv_open` here accepts only the
//!   ASCII-preserving C-locale set (byte units: `""`, `C`, `ASCII`,
//!   `US-ASCII`, `646`, `ISO-646`, `ISO-646-US`, `UTF-8` never decoded;
//!   native units: `WCHAR_T`, `WCHAR`) and fails the rest with `EINVAL`.
//! - `iconv` converts within that set, counts 0 non-reversible conversions,
//!   and keeps musl's stop-and-update pointer discipline (`EILSEQ` bad byte,
//!   `E2BIG` output full without consuming, `EINVAL` starved `wchar_t` tail).
//! - Descriptors are inline pointer-tagged (`f<<16|t<<1|1`, musl's
//!   `combine_to_from` shape) so `iconv_close` frees nothing, returns 0.
//! - `NULL` inputs return `0`/`NULL`/error with `errno` (musl would fault);
//!   `iconv` with pending input but no output room is `E2BIG` (musl faults).
//!
//! x86_64 gating comes from `lib.rs` (`pub mod multibyte` is
//! `#[cfg(target_arch = "x86_64")]`); no per-item gates needed.

use core::ffi::{c_char, c_int, c_void};

const E2BIG: c_int = 7;
const EINVAL: c_int = 22;
const EILSEQ: c_int = 84;
const WEOF: u32 = 0xffff_ffff;

/// musl `uchar.h` (`char16_t`); x86_64-gated via the module.
#[allow(non_camel_case_types)]
pub type char16_t = u16;
/// musl `uchar.h` (`char32_t`); x86_64-gated via the module.
#[allow(non_camel_case_types)]
pub type char32_t = u32;
/// musl `iconv.h` (`typedef void *iconv_t`).
#[allow(non_camel_case_types)]
pub type iconv_t = *mut c_void;

/// musl `include/alltypes.h.in:73` (`struct __mbstate_t`): opaque 8 bytes.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct Mbstate {
    pub __opaque1: u32,
    pub __opaque2: u32,
}

const _: () = assert!(core::mem::size_of::<Mbstate>() == 8);

/// musl `src/errno/__errno_location.c`: store through the per-thread cell.
#[inline]
fn set_errno(v: c_int) {
    unsafe {
        crate::errno::errno_store(crate::errno::__errno_location(), v);
    }
}

// One internal fallback state per musl function that owns one
// (`mbrtowc`/`mbrlen`/`mbsnrtowcs`/`mbrtoc16`/`mbrtoc32`/`c16rtomb` each
// declare their own `static unsigned internal_state`); never written in the
// C locale (no partial sequences exist), kept for shape fidelity.
static mut MBRTOWC_INTERNAL: u32 = 0;
static mut MBRLEN_INTERNAL: u32 = 0;
static mut MBSNRTOWCS_INTERNAL: u32 = 0;
static mut MBRTOC16_INTERNAL: u32 = 0;
static mut MBRTOC32_INTERNAL: u32 = 0;
static mut C16RTOMB_INTERNAL: u32 = 0;

/// First state word, or the caller's fallback when `st` is NULL (musl's
/// `if (!st) st = (void *)&internal_state`). Pure pointer arithmetic.
fn state_word(st: *mut Mbstate, fb: *mut u32) -> *mut u32 {
    if st.is_null() {
        fb
    } else {
        st.cast::<u32>()
    }
}

/// musl `src/multibyte/mbrtowc.c`: C-locale path only (`*s < 0x80` return,
/// `MB_CUR_MAX == 1` arm without the `CODEUNIT` map — see header).
///
/// # Safety
///
/// `wc` NULL or writable; `src` NULL (reset query) or readable for `n` bytes
/// (only byte 0 is read); `st` NULL or valid.
#[no_mangle]
pub unsafe extern "C" fn mbrtowc(
    wc: *mut c_int,
    src: *const c_char,
    n: usize,
    st: *mut Mbstate,
) -> usize {
    unsafe {
        let stw = state_word(st, core::ptr::addr_of_mut!(MBRTOWC_INTERNAL));
        if src.is_null() {
            if *stw != 0 {
                set_errno(EILSEQ);
                *stw = 0;
                return (-1isize) as usize;
            }
            return 0;
        }
        if *stw != 0 {
            // No partial states exist in the C locale; an alien resume state
            // cannot be honored (musl would continue a UTF-8 sequence).
            set_errno(EILSEQ);
            *stw = 0;
            return (-1isize) as usize;
        }
        let mut dummy: c_int = 0;
        let out = if wc.is_null() { &mut dummy } else { &mut *wc };
        if n == 0 {
            return (-2isize) as usize;
        }
        let b = *(src as *const u8);
        if b < 0x80 {
            *out = b as c_int;
            return (b != 0) as usize;
        }
        set_errno(EILSEQ);
        *stw = 0;
        (-1isize) as usize
    }
}

/// musl `src/multibyte/wcrtomb.c:6-17`: `!s` probe and ASCII arm (`st`
/// untouched, like musl); multibyte/`CODEUNIT` arms are EILSEQ here.
///
/// # Safety
///
/// `s` NULL (length probe) or writable 1 byte.
#[no_mangle]
pub unsafe extern "C" fn wcrtomb(s: *mut c_char, wc: c_int, _st: *mut Mbstate) -> usize {
    unsafe {
        if s.is_null() {
            return 1;
        }
        if (wc as u32) < 0x80 {
            *s = wc as c_char;
            return 1;
        }
        set_errno(EILSEQ);
        (-1isize) as usize
    }
}

/// musl `src/multibyte/mbsinit.c:3-6`, verbatim.
///
/// # Safety
///
/// `st` NULL or readable.
#[no_mangle]
pub unsafe extern "C" fn mbsinit(st: *const Mbstate) -> c_int {
    unsafe { (st.is_null() || (*st).__opaque1 == 0) as c_int }
}

/// musl `src/multibyte/mbrlen.c:3-7` (own internal state).
///
/// # Safety
///
/// `s` NULL or readable for `n` bytes; `st` NULL or valid.
#[no_mangle]
pub unsafe extern "C" fn mbrlen(s: *const c_char, n: usize, st: *mut Mbstate) -> usize {
    unsafe {
        let p = if st.is_null() {
            core::ptr::addr_of_mut!(MBRLEN_INTERNAL).cast::<Mbstate>()
        } else {
            st
        };
        mbrtowc(core::ptr::null_mut(), s, n, p)
    }
}

/// musl `src/multibyte/mbtowc.c`: `!s`/`!n`/ASCII arms; the UTF-8 and
/// `CODEUNIT` arms are EILSEQ here (see header).
///
/// # Safety
///
/// `wc` NULL or writable; `src` NULL or readable for `n` bytes.
#[no_mangle]
pub unsafe extern "C" fn mbtowc(wc: *mut c_int, src: *const c_char, n: usize) -> c_int {
    unsafe {
        if src.is_null() {
            return 0;
        }
        if n == 0 {
            set_errno(EILSEQ);
            return -1;
        }
        let mut dummy: c_int = 0;
        let out = if wc.is_null() { &mut dummy } else { &mut *wc };
        let b = *(src as *const u8);
        if b < 0x80 {
            *out = b as c_int;
            return (b != 0) as c_int;
        }
        set_errno(EILSEQ);
        -1
    }
}

/// musl `src/multibyte/mblen.c:3-6` (`mbtowc` with NULL `wc`).
///
/// # Safety
///
/// `s` NULL or readable for `n` bytes.
#[no_mangle]
pub unsafe extern "C" fn mblen(s: *const c_char, n: usize) -> c_int {
    unsafe { mbtowc(core::ptr::null_mut(), s, n) }
}

/// musl `src/multibyte/wctomb.c:4-8`.
///
/// # Safety
///
/// `s` NULL (encoding-query, returns 0) or writable 1 byte.
#[no_mangle]
pub unsafe extern "C" fn wctomb(s: *mut c_char, wc: c_int) -> c_int {
    unsafe {
        if s.is_null() {
            return 0;
        }
        wcrtomb(s, wc, core::ptr::null_mut()) as c_int
    }
}

/// musl `src/multibyte/mbsrtowcs.c`: the `MB_CUR_MAX == 1` loop with the
/// `CODEUNIT` store replaced by ASCII-or-`EILSEQ`; `!ws` measures like
/// musl's `strlen` fast path but still rejects high bytes.
///
/// # Safety
///
/// `ws` NULL (measure) or writable `wn` units; `src` writable pointer to a
/// readable NUL-terminated string; `st` NULL or valid (must be initial —
/// nonzero is `EILSEQ`, see [`mbrtowc`]).
#[no_mangle]
pub unsafe extern "C" fn mbsrtowcs(
    ws: *mut c_int,
    src: *mut *const c_char,
    wn: usize,
    st: *mut Mbstate,
) -> usize {
    unsafe {
        if src.is_null() {
            set_errno(EINVAL);
            return (-1isize) as usize;
        }
        let mut s = *src as *const u8;
        if s.is_null() {
            return 0;
        }
        if !st.is_null() && (*st).__opaque1 != 0 {
            set_errno(EILSEQ);
            return (-1isize) as usize;
        }
        if ws.is_null() {
            let mut k = 0usize;
            loop {
                let b = *s.add(k);
                if b == 0 {
                    return k;
                }
                if b >= 0x80 {
                    set_errno(EILSEQ);
                    return (-1isize) as usize;
                }
                k = k.wrapping_add(1);
            }
        }
        let mut w = ws;
        let mut n = wn;
        loop {
            if n == 0 {
                *src = s as *const c_char;
                return wn;
            }
            let b = *s;
            if b == 0 {
                *w = 0;
                *src = core::ptr::null();
                return wn.wrapping_sub(n);
            }
            if b >= 0x80 {
                set_errno(EILSEQ);
                *src = s as *const c_char;
                return (-1isize) as usize;
            }
            *w = b as c_int;
            w = w.add(1);
            s = s.add(1);
            n -= 1;
        }
    }
}

/// musl `src/multibyte/mbsnrtowcs.c`: direct ASCII loop with the same bounds
/// (`wn` units / `n` bytes, NUL clears `*src`, errors update `*src`).
///
/// # Safety
///
/// `wcs` NULL (count) or writable `wn` units; `src` writable pointer to a
/// readable byte range (`NULL` `*src` yields 0); `st` NULL or valid initial.
#[no_mangle]
pub unsafe extern "C" fn mbsnrtowcs(
    wcs: *mut c_int,
    src: *mut *const c_char,
    n: usize,
    wn: usize,
    st: *mut Mbstate,
) -> usize {
    unsafe {
        if src.is_null() {
            set_errno(EINVAL);
            return (-1isize) as usize;
        }
        let stw = state_word(st, core::ptr::addr_of_mut!(MBSNRTOWCS_INTERNAL));
        if *stw != 0 {
            set_errno(EILSEQ);
            return (-1isize) as usize;
        }
        let null_dst = wcs.is_null();
        let mut p = *src as *const u8;
        let mut w = wcs;
        let mut nn = n;
        let mut m = wn;
        let mut cnt = 0usize;
        while !p.is_null() && m > 0 && nn > 0 {
            let b = *p;
            if b == 0 {
                p = core::ptr::null();
                break;
            }
            if b >= 0x80 {
                set_errno(EILSEQ);
                if !null_dst {
                    *src = p as *const c_char;
                }
                return (-1isize) as usize;
            }
            if !null_dst {
                *w = b as c_int;
                w = w.add(1);
            }
            p = p.add(1);
            nn -= 1;
            m -= 1;
            cnt = cnt.wrapping_add(1);
        }
        if !null_dst {
            *src = p as *const c_char;
        }
        cnt
    }
}

/// musl `src/multibyte/wcsrtombs.c`: single-byte loop (every unit is 1 byte
/// or `EILSEQ`); `!s` measures; `*ws` is left at the unconverted unit on
/// truncation and untouched on error, like musl.
///
/// # Safety
///
/// `s` NULL (measure) or writable `n` bytes; `ws` writable pointer to a
/// readable NUL-terminated wide string; `st` ignored (musl passes 0 on).
#[no_mangle]
pub unsafe extern "C" fn wcsrtombs(
    s: *mut c_char,
    ws: *mut *const c_int,
    n: usize,
    _st: *mut Mbstate,
) -> usize {
    unsafe {
        if ws.is_null() {
            set_errno(EINVAL);
            return (-1isize) as usize;
        }
        let mut p = *ws;
        if p.is_null() {
            return 0;
        }
        if s.is_null() {
            let mut k = 0usize;
            loop {
                let wc = *p.add(k);
                if wc == 0 {
                    return k;
                }
                if (wc as u32) >= 0x80 {
                    set_errno(EILSEQ);
                    return (-1isize) as usize;
                }
                k = k.wrapping_add(1);
            }
        }
        let mut out = s;
        let mut rem = n;
        loop {
            if rem == 0 {
                *ws = p;
                return n;
            }
            let wc = *p;
            if wc == 0 {
                *out = 0;
                *ws = core::ptr::null();
                return n.wrapping_sub(rem);
            }
            if (wc as u32) >= 0x80 {
                set_errno(EILSEQ);
                return (-1isize) as usize;
            }
            *out = wc as c_char;
            out = out.add(1);
            rem -= 1;
            p = p.add(1);
        }
    }
}

/// musl `src/multibyte/wcsnrtombs.c`: ASCII loop (every unit is 1 byte or
/// `EILSEQ`); the NUL terminator is stored but not counted; `*wcs` updates
/// only when `dst` is non-NULL, like musl.
///
/// # Safety
///
/// `dst` NULL (count against `wn`/shape only) or writable; `wcs` writable
/// pointer to a readable wide range (`NULL` `*wcs` yields 0).
#[no_mangle]
pub unsafe extern "C" fn wcsnrtombs(
    dst: *mut c_char,
    wcs: *mut *const c_int,
    wn: usize,
    n: usize,
    _st: *mut Mbstate,
) -> usize {
    unsafe {
        if wcs.is_null() {
            set_errno(EINVAL);
            return (-1isize) as usize;
        }
        let mut p = *wcs;
        let null_dst = dst.is_null();
        let mut d = dst;
        let mut rem = if null_dst { 0 } else { n };
        let mut m = wn;
        let mut cnt = 0usize;
        while !p.is_null() && m > 0 {
            let wc = *p;
            if (wc as u32) >= 0x80 {
                set_errno(EILSEQ);
                if !null_dst {
                    *wcs = p;
                }
                return (-1isize) as usize;
            }
            if !null_dst {
                if rem < 1 {
                    break;
                }
                *d = wc as c_char;
                d = d.add(1);
                rem -= 1;
            }
            if wc == 0 {
                p = core::ptr::null();
                break;
            }
            p = p.add(1);
            m -= 1;
            cnt = cnt.wrapping_add(1);
        }
        if !null_dst {
            *wcs = p;
        }
        cnt
    }
}

/// musl `src/multibyte/btowc.c:9`: ASCII arm; the `CODEUNIT` arm is `WEOF`
/// here (see header). `EOF` (`-1`) truncates to byte `0xFF`, hence `WEOF`.
/// Convert single byte to wide char, EOF on invalid (musl `btowc`).
///
/// # Safety
///
/// Pure function of its argument.
#[no_mangle]
pub unsafe extern "C" fn btowc(c: c_int) -> u32 {
    let b = c as u8;
    if (b as u32) < 128 {
        b as u32
    } else {
        WEOF
    }
}

/// musl `src/multibyte/wctob.c:6-11`: ASCII arm; the `IS_CODEUNIT` roundtrip
/// arm is gone with the code-unit tables (see header).
/// Convert wide char to single byte, EOF if unrepresentable (musl `wctob`).
///
/// # Safety
///
/// Pure function of its argument.
#[no_mangle]
pub unsafe extern "C" fn wctob(c: u32) -> c_int {
    if c < 128 {
        c as c_int
    } else {
        -1
    }
}

/// musl `src/multibyte/c16rtomb.c`: `!s` probe and musl-exact pending-high
/// encoding (`c16 - 0xd7c0 << 10`); any completed pair is `>= 0x10000`,
/// hence `EILSEQ` in the C locale; lone lows / non-ASCII are `EILSEQ`.
///
/// # Safety
///
/// `s` NULL (state probe) or writable 1 byte; `ps` NULL or valid.
#[no_mangle]
pub unsafe extern "C" fn c16rtomb(s: *mut c_char, c16: char16_t, ps: *mut Mbstate) -> usize {
    unsafe {
        let pw = state_word(ps, core::ptr::addr_of_mut!(C16RTOMB_INTERNAL));
        if s.is_null() {
            if *pw != 0 {
                set_errno(EILSEQ);
                *pw = 0;
                return (-1isize) as usize;
            }
            return 1;
        }
        if *pw != 0 {
            // Pending high surrogate met its pair (or didn't — a lone low
            // fails in musl too); either way the result is non-ASCII.
            *pw = 0;
            set_errno(EILSEQ);
            return (-1isize) as usize;
        }
        if (c16 as u32).wrapping_sub(0xd800) < 0x400 {
            *pw = (c16 as u32).wrapping_sub(0xd7c0) << 10;
            return 0;
        }
        if (c16 as u32) < 0x80 {
            *s = c16 as c_char;
            return 1;
        }
        set_errno(EILSEQ);
        (-1isize) as usize
    }
}

/// musl `src/multibyte/c32rtomb.c:4-7` (`wcrtomb` passthrough).
///
/// # Safety
///
/// `s` NULL (returns 1) or writable 1 byte; `ps` ignored like musl's `0`.
#[no_mangle]
pub unsafe extern "C" fn c32rtomb(s: *mut c_char, c32: char32_t, ps: *mut Mbstate) -> usize {
    unsafe { wcrtomb(s, c32 as c_int, ps) }
}

/// musl `src/multibyte/mbrtoc16.c`: pending-surrogate emission (`-3`) and
/// `!s` reset through the empty string; the astral split is unreachable in
/// the C locale (`mbrtowc` never yields `>= 0x10000`).
///
/// # Safety
///
/// `pc16` NULL or writable; `s` NULL (reset) or readable `n` bytes; `ps`
/// NULL or valid.
#[no_mangle]
pub unsafe extern "C" fn mbrtoc16(
    pc16: *mut char16_t,
    s: *const c_char,
    n: usize,
    ps: *mut Mbstate,
) -> usize {
    unsafe {
        let pw = state_word(ps, core::ptr::addr_of_mut!(MBRTOC16_INTERNAL));
        let pst = pw.cast::<Mbstate>();
        if s.is_null() {
            if (*pw as i32) > 0 {
                if !pc16.is_null() {
                    *pc16 = *pw as char16_t;
                }
                *pw = 0;
                return (-3isize) as usize;
            }
            let mut wc: c_int = 0;
            let r = mbrtowc(&mut wc, c"".as_ptr(), 1, pst);
            if r <= 4 && !pc16.is_null() {
                *pc16 = wc as char16_t;
            }
            return r;
        }
        let mut wc: c_int = 0;
        let r = mbrtowc(&mut wc, s, n, pst);
        if r <= 4 && !pc16.is_null() {
            *pc16 = wc as char16_t;
        }
        r
    }
}

/// musl `src/multibyte/mbrtoc32.c`: `mbrtowc` plus store.
///
/// # Safety
///
/// `pc32` NULL or writable; `s` NULL (reset) or readable `n` bytes; `ps`
/// NULL or valid.
#[no_mangle]
pub unsafe extern "C" fn mbrtoc32(
    pc32: *mut char32_t,
    s: *const c_char,
    n: usize,
    ps: *mut Mbstate,
) -> usize {
    unsafe {
        let pw = state_word(ps, core::ptr::addr_of_mut!(MBRTOC32_INTERNAL));
        let pst = pw.cast::<Mbstate>();
        if s.is_null() {
            let mut wc: c_int = 0;
            let r = mbrtowc(&mut wc, c"".as_ptr(), 1, pst);
            if r <= 4 && !pc32.is_null() {
                *pc32 = wc as char32_t;
            }
            return r;
        }
        let mut wc: c_int = 0;
        let r = mbrtowc(&mut wc, s, n, pst);
        if r <= 4 && !pc32.is_null() {
            *pc32 = wc as char32_t;
        }
        r
    }
}

// ---- iconv (C-locale subset of musl `src/locale/iconv.c`) --------------------

const ENC_BYTE: u32 = 0;
const ENC_WCHAR: u32 = 1;

/// Lowercase-alnum fold of a NUL-terminated name (musl's `fuzzycmp` skips
/// non-alnum and case-folds); returns the folded bytes.
///
/// # Safety
///
/// `name` must point at a valid NUL-terminated string.
unsafe fn fold_name(name: *const c_char, out: &mut [u8; 32]) -> usize {
    unsafe {
        let mut k = 0usize;
        let mut p = name as *const u8;
        loop {
            let b = *p;
            p = p.add(1);
            if b == 0 {
                break;
            }
            let mut c = b;
            if c.is_ascii_uppercase() {
                c = c.wrapping_add(32);
            }
            let alnum = c.is_ascii_lowercase() || c.is_ascii_digit();
            if alnum && k < out.len() {
                out[k] = c;
                k = k.wrapping_add(1);
            }
        }
        k
    }
}

/// Classify a charset name: byte units, `wchar_t` units, or unknown.
///
/// # Safety
///
/// `name` must point at a valid NUL-terminated string.
unsafe fn classify(name: *const c_char) -> Option<u32> {
    unsafe {
        let mut f = [0u8; 32];
        let k = fold_name(name, &mut f);
        let s = &f[..k];
        if s.is_empty()
            || s == b"c"
            || s == b"ascii"
            || s == b"usascii"
            || s == b"utf8"
            || s == b"646"
            || s == b"iso646"
            || s == b"iso646us"
        {
            Some(ENC_BYTE)
        } else if s == b"wchart" {
            // Folded `WCHAR_T`/`wchar` (musl's alias keeps the same typo).
            Some(ENC_WCHAR)
        } else {
            None
        }
    }
}

/// musl `src/locale/iconv.c:144-170` reduced to the C-locale set (see
/// header): descriptor is `combine_to_from` inline-tagged, never heap.
/// Unknown names fail with `EINVAL` (musl: `EINVAL`, `iconv_t -1`).
///
/// # Safety
///
/// `to`/`from` NULL (fails `EINVAL`) or NUL-terminated names.
#[no_mangle]
pub unsafe extern "C" fn iconv_open(to: *const c_char, from: *const c_char) -> iconv_t {
    unsafe {
        if to.is_null() || from.is_null() {
            set_errno(EINVAL);
            return usize::MAX as iconv_t;
        }
        let t = match classify(to) {
            Some(x) => x,
            None => {
                set_errno(EINVAL);
                return usize::MAX as iconv_t;
            }
        };
        let f = match classify(from) {
            Some(x) => x,
            None => {
                set_errno(EINVAL);
                return usize::MAX as iconv_t;
            }
        };
        (f.wrapping_shl(16) | t.wrapping_shl(1) | 1) as usize as iconv_t
    }
}

/// musl `src/locale/iconv.c:233-258` loop reduced to ASCII-preserving pairs:
/// byte units are single bytes, `wchar_t` units native 4-byte words; every
/// value `>= 0x80` is `EILSEQ`, a short `wchar_t` tail is `EINVAL`, a full
/// output is `E2BIG` — all with stop-and-update pointers. Success counts 0.
///
/// # Safety
///
/// `cd` from [`iconv_open`]; `inn`/`inb` NULL or valid (NULL/empty input
/// returns 0); `out`/`outb` valid once input is pending.
#[no_mangle]
pub unsafe extern "C" fn iconv(
    cd: iconv_t,
    inn: *mut *mut c_char,
    inb: *mut usize,
    out: *mut *mut c_char,
    outb: *mut usize,
) -> usize {
    unsafe {
        if inn.is_null() || inb.is_null() {
            return 0;
        }
        let mut pi = *inn as *const u8;
        if pi.is_null() || *inb == 0 {
            return 0;
        }
        let v = cd as usize;
        if v == usize::MAX || (v & 1) == 0 {
            set_errno(EINVAL);
            return (-1isize) as usize;
        }
        let f = (v >> 16) as u32;
        let t = ((v >> 1) & 0x7fff) as u32;
        if f > ENC_WCHAR || t > ENC_WCHAR {
            set_errno(EINVAL);
            return (-1isize) as usize;
        }
        if out.is_null() || outb.is_null() || (*out).is_null() {
            set_errno(E2BIG);
            return (-1isize) as usize;
        }
        let mut ni = *inb;
        let mut po = *out as *mut u8;
        let mut no = *outb;
        let tunit = if t == ENC_WCHAR { 4 } else { 1 };
        // ponytail: single ASCII fast path; per-charset tables arrive with locale data.
        while ni > 0 {
            let (wc, ulen): (u32, usize) = if f == ENC_WCHAR {
                if ni < 4 {
                    *inn = pi as *mut c_char;
                    *inb = ni;
                    *out = po as *mut c_char;
                    *outb = no;
                    set_errno(EINVAL);
                    return (-1isize) as usize;
                }
                let w = core::ptr::read_unaligned(pi as *const u32);
                if w >= 0x80 {
                    *inn = pi as *mut c_char;
                    *inb = ni;
                    *out = po as *mut c_char;
                    *outb = no;
                    set_errno(EILSEQ);
                    return (-1isize) as usize;
                }
                (w, 4)
            } else {
                let b = *pi;
                if b >= 0x80 {
                    *inn = pi as *mut c_char;
                    *inb = ni;
                    *out = po as *mut c_char;
                    *outb = no;
                    set_errno(EILSEQ);
                    return (-1isize) as usize;
                }
                (b as u32, 1)
            };
            if no < tunit {
                *inn = pi as *mut c_char;
                *inb = ni;
                *out = po as *mut c_char;
                *outb = no;
                set_errno(E2BIG);
                return (-1isize) as usize;
            }
            if t == ENC_WCHAR {
                core::ptr::write_unaligned(po as *mut u32, wc);
                po = po.add(4);
                no -= 4;
            } else {
                *po = wc as u8;
                po = po.add(1);
                no -= 1;
            }
            pi = pi.add(ulen);
            ni -= ulen;
        }
        *inn = pi as *mut c_char;
        *inb = ni;
        *out = po as *mut c_char;
        *outb = no;
        0
    }
}

/// musl `src/locale/iconv_close.c:4-8`: our descriptors are inline-tagged
/// (never heap), so close frees nothing and returns 0.
/// Close a conversion descriptor, no-op for inline tags (musl `iconv_close`).
///
/// # Safety
///
/// `cd` must be a descriptor from [`iconv_open`] (or null, also 0).
#[no_mangle]
pub unsafe extern "C" fn iconv_close(_cd: iconv_t) -> c_int {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::{c_char, c_int};
    use core::ptr::{null, null_mut};

    use crate::errno::{__errno_location, errno_load, errno_store};

    fn reset_errno() {
        unsafe {
            errno_store(__errno_location(), 0);
        }
    }

    fn last_errno() -> c_int {
        unsafe { errno_load(__errno_location()) }
    }

    fn zero_state() -> Mbstate {
        Mbstate {
            __opaque1: 0,
            __opaque2: 0,
        }
    }

    #[test]
    fn mbrtowc_ascii_nul_and_empty() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut st = zero_state();
            let mut wc: c_int = -1;
            reset_errno();
            assert_eq!(mbrtowc(&mut wc, c"A".as_ptr(), 1, &mut st), 1);
            assert_eq!(wc, 65);
            assert_eq!(last_errno(), 0);
            assert_eq!(mbsinit(&st), 1);
            // NUL stores L'\0', returns 0.
            wc = -1;
            assert_eq!(mbrtowc(&mut wc, c"".as_ptr(), 1, &mut st), 0);
            assert_eq!(wc, 0);
            // n == 0 is -2 without touching wc.
            wc = -1;
            assert_eq!(
                mbrtowc(&mut wc, c"A".as_ptr(), 0, &mut st),
                (-2isize) as usize
            );
            assert_eq!(wc, -1);
            // NULL src resets: clean state returns 0.
            assert_eq!(mbrtowc(&mut wc, null(), 5, &mut st), 0);
            // NULL wc still consumes and reports length.
            assert_eq!(mbrtowc(null_mut(), c"Z".as_ptr(), 9, &mut st), 1);
        }
    }

    #[test]
    fn mbrtowc_rejects_high_bytes() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut st = zero_state();
            let mut wc: c_int = -1;
            for b in [0x80u8, 0xC3, 0xFF] {
                let buf = [b, 0];
                reset_errno();
                assert_eq!(
                    mbrtowc(&mut wc, buf.as_ptr() as *const c_char, 1, &mut st),
                    (-1isize) as usize
                );
                assert_eq!(last_errno(), EILSEQ);
                assert_eq!(mbsinit(&st), 1);
            }
            // Alien resume state cannot be honored either.
            let mut bad = Mbstate {
                __opaque1: 0xdead,
                __opaque2: 0,
            };
            reset_errno();
            assert_eq!(
                mbrtowc(&mut wc, c"A".as_ptr(), 1, &mut bad),
                (-1isize) as usize
            );
            assert_eq!(last_errno(), EILSEQ);
        }
    }

    #[test]
    fn restartable_calls_share_state() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            // C locale has no partial sequences: successive calls through one
            // state each consume exactly one byte and leave it initial.
            let mut st = zero_state();
            let src = c"hey".as_ptr() as *const u8;
            let mut wc: c_int = 0;
            for (i, want) in b"hey".iter().enumerate() {
                reset_errno();
                let r = mbrtowc(&mut wc, src.add(i) as *const c_char, 1, &mut st);
                assert_eq!(r, 1);
                assert_eq!(wc, *want as c_int);
                assert_eq!(last_errno(), 0);
                assert_eq!(mbsinit(&st), 1);
            }
            // mbsrtowcs restarts across calls via the updated src pointer.
            let mut p: *const c_char = c"ab".as_ptr();
            let mut ws = [0 as c_int; 4];
            let r = mbsrtowcs(ws.as_mut_ptr(), &mut p, 1, &mut st);
            assert_eq!(r, 1);
            assert_eq!(ws[0], b'a' as c_int);
            assert!(!p.is_null());
            let r = mbsrtowcs(ws.as_mut_ptr(), &mut p, 4, &mut st);
            assert_eq!(r, 1);
            assert_eq!(ws[0], b'b' as c_int);
            assert!(p.is_null());
        }
    }

    #[test]
    fn mbsinit_zero_and_nonzero() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let z = zero_state();
            assert_eq!(mbsinit(&z), 1);
            assert_eq!(mbsinit(null()), 1);
            let nz = Mbstate {
                __opaque1: 7,
                __opaque2: 0,
            };
            assert_eq!(mbsinit(&nz), 0);
            assert_eq!(core::mem::size_of::<Mbstate>(), 8);
        }
    }

    #[test]
    fn mbrlen_mblen_mbtowc_wctomb_shapes() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut st = zero_state();
            reset_errno();
            assert_eq!(mbrlen(c"AB".as_ptr(), 2, &mut st), 1);
            assert_eq!(last_errno(), 0);
            assert_eq!(mbrlen(c"AB".as_ptr(), 2, null_mut()), 1);
            assert_eq!(mblen(c"A".as_ptr(), 1), 1);
            assert_eq!(mblen(c"".as_ptr(), 1), 0);
            assert_eq!(mblen(null(), 1), 0);
            reset_errno();
            assert_eq!(mblen(c"A".as_ptr(), 0), -1);
            assert_eq!(last_errno(), EILSEQ);
            let mut wc: c_int = 0;
            assert_eq!(mbtowc(&mut wc, c"q".as_ptr(), 4), 1);
            assert_eq!(wc, b'q' as c_int);
            let mut buf = [0 as c_char; 4];
            assert_eq!(wctomb(buf.as_mut_ptr(), b'B' as c_int), 1);
            assert_eq!(buf[0], b'B' as c_char);
            assert_eq!(wctomb(null_mut(), b'B' as c_int), 0);
            reset_errno();
            assert_eq!(wctomb(buf.as_mut_ptr(), 0xC3), -1);
            assert_eq!(last_errno(), EILSEQ);
            // wcrtomb probe + roundtrip + reject.
            assert_eq!(wcrtomb(null_mut(), 0, &mut st), 1);
            reset_errno();
            assert_eq!(wcrtomb(buf.as_mut_ptr(), b'~' as c_int, &mut st), 1);
            assert_eq!(buf[0], b'~' as c_char);
            reset_errno();
            assert_eq!(wcrtomb(buf.as_mut_ptr(), -5, &mut st), (-1isize) as usize);
            assert_eq!(last_errno(), EILSEQ);
        }
    }

    #[test]
    fn srtombs_roundtrip_and_caps() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut st = zero_state();
            // mbsrtowcs measure.
            let p0: *const c_char = c"hello".as_ptr();
            assert_eq!(
                mbsrtowcs(null_mut(), &mut (p0 as *const c_char), 99, &mut st),
                5
            );
            // mbsrtowcs convert + NUL termination clears src.
            let mut p: *const c_char = c"hi".as_ptr();
            let mut ws = [0 as c_int; 4];
            reset_errno();
            assert_eq!(mbsrtowcs(ws.as_mut_ptr(), &mut p, 4, &mut st), 2);
            assert_eq!(&ws[..3], &[b'h' as c_int, b'i' as c_int, 0]);
            assert!(p.is_null());
            assert_eq!(last_errno(), 0);
            // Truncation stops and updates src.
            let mut p: *const c_char = c"abcd".as_ptr();
            let mut ws = [0 as c_int; 2];
            assert_eq!(mbsrtowcs(ws.as_mut_ptr(), &mut p, 2, &mut st), 2);
            assert_eq!(&ws[..2], &[b'a' as c_int, b'b' as c_int]);
            assert_eq!(*p, b'c' as c_char);
            // High byte fails with src at the offender.
            let bad = [b'a' as c_char, 0x80u8 as c_char, 0];
            let mut p: *const c_char = bad.as_ptr();
            reset_errno();
            assert_eq!(
                mbsrtowcs(ws.as_mut_ptr(), &mut p, 2, &mut st),
                (-1isize) as usize
            );
            assert_eq!(last_errno(), EILSEQ);
            assert_eq!(*p, 0x80u8 as c_char);
            // wcsrtombs measure + convert + truncate.
            let w = [b'x' as c_int, b'y' as c_int, 0];
            let mut q: *const c_int = w.as_ptr();
            assert_eq!(wcsrtombs(null_mut(), &mut q, 9, &mut st), 2);
            let mut q: *const c_int = w.as_ptr();
            let mut out = [0 as c_char; 8];
            assert_eq!(wcsrtombs(out.as_mut_ptr(), &mut q, 8, &mut st), 2);
            assert_eq!(&out[..3], &[b'x' as c_char, b'y' as c_char, 0]);
            assert!(q.is_null());
            let mut q: *const c_int = w.as_ptr();
            let mut out = [0 as c_char; 8];
            assert_eq!(wcsrtombs(out.as_mut_ptr(), &mut q, 1, &mut st), 1);
            assert_eq!(out[0], b'x' as c_char);
            assert_eq!(*q, b'y' as c_int);
            // wcsrtombs rejects non-ASCII, src untouched.
            let wb = [0xE9 as c_int, 0];
            let mut q: *const c_int = wb.as_ptr();
            reset_errno();
            assert_eq!(
                wcsrtombs(out.as_mut_ptr(), &mut q, 8, &mut st),
                (-1isize) as usize
            );
            assert_eq!(last_errno(), EILSEQ);
            assert_eq!(*q, 0xE9 as c_int);
        }
    }

    #[test]
    fn snrtowcs_bounds_and_errors() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut st = zero_state();
            // n caps the input.
            let mut p: *const c_char = c"hello".as_ptr();
            let mut ws = [0 as c_int; 8];
            assert_eq!(mbsnrtowcs(ws.as_mut_ptr(), &mut p, 3, 8, &mut st), 3);
            assert_eq!(&ws[..3], &[b'h' as c_int, b'e' as c_int, b'l' as c_int]);
            assert_eq!(*p, b'l' as c_char);
            // wn caps the output.
            let mut p: *const c_char = c"hello".as_ptr();
            assert_eq!(mbsnrtowcs(ws.as_mut_ptr(), &mut p, 9, 2, &mut st), 2);
            // NUL inside n clears src.
            let mut p: *const c_char = c"ab".as_ptr();
            assert_eq!(mbsnrtowcs(ws.as_mut_ptr(), &mut p, 9, 8, &mut st), 2);
            assert!(p.is_null());
            // NULL dst counts without touching src.
            let mut p: *const c_char = c"abcd".as_ptr();
            assert_eq!(mbsnrtowcs(null_mut(), &mut p, 3, 8, &mut st), 3);
            assert_eq!(*p, b'a' as c_char);
            // High byte errors.
            let bad = [b'a' as c_char, 0xFFu8 as c_char, 0];
            let mut p: *const c_char = bad.as_ptr();
            reset_errno();
            assert_eq!(
                mbsnrtowcs(ws.as_mut_ptr(), &mut p, 3, 8, &mut st),
                (-1isize) as usize
            );
            assert_eq!(last_errno(), EILSEQ);
            // wcsnrtombs: wn cap, NUL stored-not-counted, dst-NULL shape.
            let w = [b'p' as c_int, b'q' as c_int, 0];
            let mut q: *const c_int = w.as_ptr();
            let mut out = [0 as c_char; 8];
            assert_eq!(wcsnrtombs(out.as_mut_ptr(), &mut q, 1, 8, &mut st), 1);
            assert_eq!(out[0], b'p' as c_char);
            let mut q: *const c_int = w.as_ptr();
            assert_eq!(wcsnrtombs(out.as_mut_ptr(), &mut q, 9, 8, &mut st), 2);
            assert_eq!(&out[..3], &[b'p' as c_char, b'q' as c_char, 0]);
            assert!(q.is_null());
            let mut q: *const c_int = w.as_ptr();
            assert_eq!(wcsnrtombs(null_mut(), &mut q, 9, 8, &mut st), 2);
            assert!(!q.is_null());
            // wcsnrtombs rejects non-ASCII.
            let wb = [0x100 as c_int, 0];
            let mut q: *const c_int = wb.as_ptr();
            reset_errno();
            assert_eq!(
                wcsnrtombs(out.as_mut_ptr(), &mut q, 9, 8, &mut st),
                (-1isize) as usize
            );
            assert_eq!(last_errno(), EILSEQ);
        }
    }

    #[test]
    fn btowc_wctob_edges() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            assert_eq!(btowc(b'A' as c_int), b'A' as u32);
            assert_eq!(btowc(0), 0);
            assert_eq!(btowc(0x7F), 0x7F);
            assert_eq!(btowc(0x80), WEOF);
            assert_eq!(btowc(0xFF), WEOF);
            assert_eq!(btowc(-1), WEOF);
            assert_eq!(wctob(b'A' as u32), b'A' as c_int);
            assert_eq!(wctob(0), 0);
            assert_eq!(wctob(0x7F), 0x7F);
            assert_eq!(wctob(0x80), -1);
            assert_eq!(wctob(WEOF), -1);
        }
    }

    #[test]
    fn c16_c32_roundtrip_and_surrogates() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut st = zero_state();
            let mut buf = [0 as c_char; 4];
            // c16/c32 encode ASCII.
            reset_errno();
            assert_eq!(c16rtomb(buf.as_mut_ptr(), b'G' as u16, &mut st), 1);
            assert_eq!(buf[0], b'G' as c_char);
            assert_eq!(c32rtomb(buf.as_mut_ptr(), b'H' as u32, &mut st), 1);
            assert_eq!(buf[0], b'H' as c_char);
            assert_eq!(last_errno(), 0);
            // Probes.
            assert_eq!(c16rtomb(null_mut(), b'A' as u16, &mut st), 1);
            assert_eq!(c32rtomb(null_mut(), b'A' as u32, null_mut()), 1);
            // Non-ASCII rejected.
            reset_errno();
            assert_eq!(
                c16rtomb(buf.as_mut_ptr(), 0xE9, &mut st),
                (-1isize) as usize
            );
            assert_eq!(last_errno(), EILSEQ);
            reset_errno();
            assert_eq!(
                c32rtomb(buf.as_mut_ptr(), 0x1F600, &mut st),
                (-1isize) as usize
            );
            assert_eq!(last_errno(), EILSEQ);
            // High surrogate parks (returns 0); completing it is non-ASCII.
            let mut ps = zero_state();
            assert_eq!(c16rtomb(buf.as_mut_ptr(), 0xD834, &mut ps), 0);
            assert_eq!(mbsinit(&ps), 0);
            reset_errno();
            assert_eq!(
                c16rtomb(buf.as_mut_ptr(), 0xDD1E, &mut ps),
                (-1isize) as usize
            );
            assert_eq!(last_errno(), EILSEQ);
            assert_eq!(mbsinit(&ps), 1);
            // Lone low surrogate is EILSEQ.
            reset_errno();
            assert_eq!(
                c16rtomb(buf.as_mut_ptr(), 0xDC00, &mut ps),
                (-1isize) as usize
            );
            assert_eq!(last_errno(), EILSEQ);
            // mbrtoc16/32 decode ASCII, store, pass through NUL/empty/errors.
            let mut c16: char16_t = 0;
            assert_eq!(mbrtoc16(&mut c16, c"K".as_ptr(), 1, &mut st), 1);
            assert_eq!(c16, b'K' as char16_t);
            let mut c32: char32_t = 0;
            assert_eq!(mbrtoc32(&mut c32, c"K".as_ptr(), 1, &mut st), 1);
            assert_eq!(c32, b'K' as char32_t);
            assert_eq!(mbrtoc16(&mut c16, c"".as_ptr(), 1, &mut st), 0);
            assert_eq!(c16, 0);
            assert_eq!(mbrtoc32(&mut c32, c"".as_ptr(), 1, &mut st), 0);
            assert_eq!(c32, 0);
            assert_eq!(mbrtoc16(null_mut(), c"K".as_ptr(), 1, &mut st), 1);
            let bad = [0x80u8, 0];
            reset_errno();
            assert_eq!(
                mbrtoc16(&mut c16, bad.as_ptr() as *const c_char, 1, &mut st),
                (-1isize) as usize
            );
            assert_eq!(last_errno(), EILSEQ);
            reset_errno();
            assert_eq!(
                mbrtoc32(&mut c32, bad.as_ptr() as *const c_char, 1, &mut st),
                (-1isize) as usize
            );
            assert_eq!(last_errno(), EILSEQ);
            // NULL-src reset drains a parked surrogate with -3 (musl shape).
            let mut ps = zero_state();
            assert_eq!(c16rtomb(buf.as_mut_ptr(), 0xD834, &mut ps), 0);
            let mut c16: char16_t = 0;
            assert_eq!(mbrtoc16(&mut c16, null(), 0, &mut ps), (-3isize) as usize);
            assert_eq!(mbsinit(&ps), 1);
        }
    }

    #[test]
    fn iconv_ascii_pairs_and_rejections() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            // Supported pairs open.
            for (to, from) in [
                (c"UTF-8".as_ptr(), c"ASCII".as_ptr()),
                (c"ASCII".as_ptr(), c"UTF-8".as_ptr()),
                (c"C".as_ptr(), c"C".as_ptr()),
                (c"".as_ptr(), c"".as_ptr()),
                (c"us-ascii".as_ptr(), c"utf-8".as_ptr()),
            ] {
                reset_errno();
                let cd = iconv_open(to, from);
                assert_ne!(cd as usize, usize::MAX);
                assert_eq!(last_errno(), 0);
                assert_eq!(iconv_close(cd), 0);
            }
            // Bogus pairs fail EINVAL.
            for (to, from) in [
                (c"BOGUS".as_ptr(), c"ASCII".as_ptr()),
                (c"ASCII".as_ptr(), c"BOGUS".as_ptr()),
                (c"SHIFT_JIS".as_ptr(), c"UTF-8".as_ptr()),
                (c"UTF-8".as_ptr(), c"LATIN1".as_ptr()),
            ] {
                reset_errno();
                assert_eq!(iconv_open(to, from) as usize, usize::MAX);
                assert_eq!(last_errno(), EINVAL);
            }
            reset_errno();
            assert_eq!(iconv_open(null(), c"ASCII".as_ptr()) as usize, usize::MAX);
            assert_eq!(last_errno(), EINVAL);
            // Byte roundtrip with stop-and-update pointers.
            let cd = iconv_open(c"UTF-8".as_ptr(), c"ASCII".as_ptr());
            let src = c"Hello".as_ptr();
            let mut inp = src as *mut c_char;
            let mut inb = 5usize;
            let mut outb_buf = [0 as c_char; 8];
            let mut outp = outb_buf.as_mut_ptr();
            let mut outb = 8usize;
            reset_errno();
            assert_eq!(iconv(cd, &mut inp, &mut inb, &mut outp, &mut outb), 0);
            assert_eq!(inb, 0);
            assert_eq!(outb, 3);
            assert_eq!(
                &outb_buf[..5],
                &[
                    b'H' as c_char,
                    b'e' as c_char,
                    b'l' as c_char,
                    b'l' as c_char,
                    b'o' as c_char
                ]
            );
            assert_eq!(last_errno(), 0);
            assert_eq!(iconv_close(cd), 0);
            // High byte is EILSEQ, pointers parked at the offender.
            let cd = iconv_open(c"ASCII".as_ptr(), c"UTF-8".as_ptr());
            let bad = [b'A' as c_char, 0xC3u8 as c_char, b'B' as c_char, 0];
            let mut inp = bad.as_ptr() as *mut c_char;
            let mut inb = 3usize;
            let mut outb_buf = [0 as c_char; 8];
            let mut outp = outb_buf.as_mut_ptr();
            let mut outb = 8usize;
            reset_errno();
            assert_eq!(
                iconv(cd, &mut inp, &mut inb, &mut outp, &mut outb),
                (-1isize) as usize
            );
            assert_eq!(last_errno(), EILSEQ);
            assert_eq!(*inp, 0xC3u8 as c_char);
            assert_eq!(inb, 2);
            assert_eq!(outb_buf[0], b'A' as c_char);
            assert_eq!(iconv_close(cd), 0);
            // Full output is E2BIG without consuming.
            let cd = iconv_open(c"ASCII".as_ptr(), c"ASCII".as_ptr());
            let mut inp = src as *mut c_char;
            let mut inb = 5usize;
            let mut outb_buf = [0 as c_char; 2];
            let mut outp = outb_buf.as_mut_ptr();
            let mut outb = 2usize;
            reset_errno();
            assert_eq!(
                iconv(cd, &mut inp, &mut inb, &mut outp, &mut outb),
                (-1isize) as usize
            );
            assert_eq!(last_errno(), E2BIG);
            assert_eq!(inb, 3);
            assert_eq!(iconv_close(cd), 0);
            // Empty query returns 0.
            let cd = iconv_open(c"ASCII".as_ptr(), c"ASCII".as_ptr());
            let mut z = 0usize;
            assert_eq!(iconv(cd, null_mut(), &mut z, null_mut(), &mut z), 0);
            assert_eq!(iconv_close(cd), 0);
        }
    }

    #[test]
    fn iconv_wchar_pairs() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            // WCHAR_T -> ASCII.
            let cd = iconv_open(c"ASCII".as_ptr(), c"WCHAR_T".as_ptr());
            assert_ne!(cd as usize, usize::MAX);
            let w = [b'A' as c_int, b'z' as c_int];
            let mut inp = w.as_ptr() as *mut c_char;
            let mut inb = 8usize;
            let mut outb_buf = [0 as c_char; 8];
            let mut outp = outb_buf.as_mut_ptr();
            let mut outb = 8usize;
            reset_errno();
            assert_eq!(iconv(cd, &mut inp, &mut inb, &mut outp, &mut outb), 0);
            assert_eq!(inb, 0);
            assert_eq!(&outb_buf[..2], &[b'A' as c_char, b'z' as c_char]);
            assert_eq!(last_errno(), 0);
            // Short wchar tail is EINVAL.
            let mut inp = w.as_ptr() as *mut c_char;
            let mut inb = 3usize;
            let mut outp = outb_buf.as_mut_ptr();
            let mut outb = 8usize;
            reset_errno();
            assert_eq!(
                iconv(cd, &mut inp, &mut inb, &mut outp, &mut outb),
                (-1isize) as usize
            );
            assert_eq!(last_errno(), EINVAL);
            // Non-ASCII wchar is EILSEQ.
            let wb = [0xE9 as c_int];
            let mut inp = wb.as_ptr() as *mut c_char;
            let mut inb = 4usize;
            let mut outp = outb_buf.as_mut_ptr();
            let mut outb = 8usize;
            reset_errno();
            assert_eq!(
                iconv(cd, &mut inp, &mut inb, &mut outp, &mut outb),
                (-1isize) as usize
            );
            assert_eq!(last_errno(), EILSEQ);
            assert_eq!(iconv_close(cd), 0);
            // ASCII -> WCHAR_T writes native words; short room is E2BIG.
            let cd = iconv_open(c"WCHAR_T".as_ptr(), c"ASCII".as_ptr());
            assert_ne!(cd as usize, usize::MAX);
            let src = c"Q".as_ptr();
            let mut inp = src as *mut c_char;
            let mut inb = 1usize;
            let mut wout = [0 as c_int; 2];
            let mut outp = wout.as_mut_ptr() as *mut c_char;
            let mut outb = 8usize;
            assert_eq!(iconv(cd, &mut inp, &mut inb, &mut outp, &mut outb), 0);
            assert_eq!(wout[0], b'Q' as c_int);
            assert_eq!(inb, 0);
            let mut inp = src as *mut c_char;
            let mut inb = 1usize;
            let mut outp = wout.as_mut_ptr() as *mut c_char;
            let mut outb = 3usize;
            reset_errno();
            assert_eq!(
                iconv(cd, &mut inp, &mut inb, &mut outp, &mut outb),
                (-1isize) as usize
            );
            assert_eq!(last_errno(), E2BIG);
            assert_eq!(inb, 1);
            assert_eq!(iconv_close(cd), 0);
        }
    }
}
