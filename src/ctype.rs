//! Character classes, musl `src/ctype/is*.c` + `to*.c` (C locale only,
//! matching our locale stub: every `*_l` collapses to the plain form,
//! so only the plain symbols are emitted).
//!
//! Each predicate is musl's arithmetic one-liner ported verbatim
//! (`(unsigned)c` becomes `c as u32` + [`u32::wrapping_sub`]); the
//! unsigned wrap is what makes EOF(-1) and every other out-of-range
//! value yield 0 (is*) / pass through unchanged (to*) with no
//! branches. `__ctype_b_loc`'s legacy bit-table is deliberately NOT
//! ported: musl's own is* functions never consult it.
//!
//! All symbols exist on x86_64 (this module is gated in `lib.rs`).

use core::ffi::c_int;

fn alpha(c: c_int) -> bool {
    (c as u32 | 32).wrapping_sub(b'a' as u32) < 26
}
fn digit(c: c_int) -> bool {
    (c as u32).wrapping_sub(b'0' as u32) < 10
}
fn upper(c: c_int) -> bool {
    (c as u32).wrapping_sub(b'A' as u32) < 26
}
fn lower(c: c_int) -> bool {
    (c as u32).wrapping_sub(b'a' as u32) < 26
}
fn graph(c: c_int) -> bool {
    (c as u32).wrapping_sub(0x21) < 0x5e
}

/// musl `src/ctype/isalnum.c:4`: `isalpha(c) || isdigit(c)`.
///
/// # Safety
/// Trivially safe: pure function of an `int`; no memory accessed.
#[no_mangle]
pub unsafe extern "C" fn isalnum(c: c_int) -> c_int {
    (alpha(c) || digit(c)) as c_int
}

/// musl `src/ctype/isalpha.c:5`: `((unsigned)c|32)-'a' < 26`.
///
/// # Safety
/// Trivially safe: pure function of an `int`; no memory accessed.
#[no_mangle]
pub unsafe extern "C" fn isalpha(c: c_int) -> c_int {
    alpha(c) as c_int
}

/// musl `src/ctype/isascii.c:5`: `!(c&~0x7f)`.
///
/// # Safety
/// Trivially safe: pure function of an `int`; no memory accessed.
#[no_mangle]
pub unsafe extern "C" fn isascii(c: c_int) -> c_int {
    (c & !0x7f == 0) as c_int
}

/// musl `src/ctype/isblank.c:3`: `c == ' ' || c == '\t'`.
///
/// # Safety
/// Trivially safe: pure function of an `int`; no memory accessed.
#[no_mangle]
pub unsafe extern "C" fn isblank(c: c_int) -> c_int {
    (c == b' ' as c_int || c == b'\t' as c_int) as c_int
}

/// musl `src/ctype/iscntrl.c:3`: `(unsigned)c < 0x20 || c == 0x7f`.
///
/// # Safety
/// Trivially safe: pure function of an `int`; no memory accessed.
#[no_mangle]
pub unsafe extern "C" fn iscntrl(c: c_int) -> c_int {
    ((c as u32) < 0x20 || c == 0x7f) as c_int
}

/// musl `src/ctype/isdigit.c:5`: `(unsigned)c-'0' < 10`.
///
/// # Safety
/// Trivially safe: pure function of an `int`; no memory accessed.
#[no_mangle]
pub unsafe extern "C" fn isdigit(c: c_int) -> c_int {
    digit(c) as c_int
}

/// musl `src/ctype/isgraph.c:5`: `(unsigned)c-0x21 < 0x5e`.
///
/// # Safety
/// Trivially safe: pure function of an `int`; no memory accessed.
#[no_mangle]
pub unsafe extern "C" fn isgraph(c: c_int) -> c_int {
    graph(c) as c_int
}

/// musl `src/ctype/islower.c:5`: `(unsigned)c-'a' < 26`.
///
/// # Safety
/// Trivially safe: pure function of an `int`; no memory accessed.
#[no_mangle]
pub unsafe extern "C" fn islower(c: c_int) -> c_int {
    lower(c) as c_int
}

/// musl `src/ctype/isprint.c:5`: `(unsigned)c-0x20 < 0x5f`.
///
/// # Safety
/// Trivially safe: pure function of an `int`; no memory accessed.
#[no_mangle]
pub unsafe extern "C" fn isprint(c: c_int) -> c_int {
    ((c as u32).wrapping_sub(0x20) < 0x5f) as c_int
}

/// musl `src/ctype/ispunct.c:3`: `isgraph(c) && !isalnum(c)`.
///
/// # Safety
/// Trivially safe: pure function of an `int`; no memory accessed.
#[no_mangle]
pub unsafe extern "C" fn ispunct(c: c_int) -> c_int {
    (graph(c) && !(alpha(c) || digit(c))) as c_int
}

/// musl `src/ctype/isspace.c:5`: `c == ' ' || (unsigned)c-'\t' < 5`
/// (covers `' '`, `\t..\r`).
///
/// # Safety
/// Trivially safe: pure function of an `int`; no memory accessed.
#[no_mangle]
pub unsafe extern "C" fn isspace(c: c_int) -> c_int {
    (c == b' ' as c_int || (c as u32).wrapping_sub(b'\t' as u32) < 5) as c_int
}

/// musl `src/ctype/isupper.c:5`: `(unsigned)c-'A' < 26`.
///
/// # Safety
/// Trivially safe: pure function of an `int`; no memory accessed.
#[no_mangle]
pub unsafe extern "C" fn isupper(c: c_int) -> c_int {
    upper(c) as c_int
}

/// musl `src/ctype/isxdigit.c:3`: `isdigit(c) || ((unsigned)c|32)-'a' < 6`.
///
/// # Safety
/// Trivially safe: pure function of an `int`; no memory accessed.
#[no_mangle]
pub unsafe extern "C" fn isxdigit(c: c_int) -> c_int {
    (digit(c) || (c as u32 | 32).wrapping_sub(b'a' as u32) < 6) as c_int
}

/// musl `src/ctype/toascii.c:5`: `c & 0x7f`.
///
/// # Safety
/// Trivially safe: pure function of an `int`; no memory accessed.
#[no_mangle]
pub unsafe extern "C" fn toascii(c: c_int) -> c_int {
    c & 0x7f
}

/// musl `src/ctype/tolower.c:3`: maps `A-Z` to `a-z`, rest unchanged.
///
/// # Safety
/// Trivially safe: pure function of an `int`; no memory accessed.
#[no_mangle]
pub unsafe extern "C" fn tolower(c: c_int) -> c_int {
    if upper(c) {
        return c | 32;
    }
    c
}

/// musl `src/ctype/toupper.c:3`: maps `a-z` to `A-Z`, rest unchanged.
///
/// # Safety
/// Trivially safe: pure function of an `int`; no memory accessed.
#[no_mangle]
pub unsafe extern "C" fn toupper(c: c_int) -> c_int {
    if lower(c) {
        return c & 0x5f;
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn oracle(c: c_int) -> (Vec<(&'static str, bool)>, c_int, c_int, c_int) {
        if !(0..128).contains(&c) {
            return (
                Vec::from([
                    ("alnum", false),
                    ("alpha", false),
                    ("blank", false),
                    ("cntrl", false),
                    ("digit", false),
                    ("graph", false),
                    ("lower", false),
                    ("print", false),
                    ("punct", false),
                    ("space", false),
                    ("upper", false),
                    ("xdigit", false),
                ]),
                c & 0x7f,
                c,
                c,
            );
        }
        let ch = (c as u8) as char;
        (
            Vec::from([
                ("alnum", ch.is_ascii_alphanumeric()),
                ("alpha", ch.is_ascii_alphabetic()),
                ("blank", ch == ' ' || ch == '\t'),
                ("cntrl", ch.is_ascii_control()),
                ("digit", ch.is_ascii_digit()),
                ("graph", ch.is_ascii_graphic()),
                ("lower", ch.is_ascii_lowercase()),
                ("print", ch == ' ' || ch.is_ascii_graphic()),
                ("punct", ch.is_ascii_punctuation()),
                // NB: `is_ascii_whitespace` wrongly excludes '\x0b' here
                // (musl covers \t..\r); the Unicode `is_whitespace`
                // matches C isspace exactly over ASCII.
                ("space", ch.is_whitespace()),
                ("upper", ch.is_ascii_uppercase()),
                ("xdigit", ch.is_ascii_hexdigit()),
            ]),
            c & 0x7f,
            ch.to_ascii_lowercase() as c_int,
            ch.to_ascii_uppercase() as c_int,
        )
    }

    #[test]
    fn exhaustive_c_locale_sweep() {
        for c in -2..=300 {
            let (preds, ascii, lo, hi) = oracle(c);
            for (name, want) in preds {
                let got = unsafe {
                    match name {
                        "alnum" => isalnum(c),
                        "alpha" => isalpha(c),
                        "blank" => isblank(c),
                        "cntrl" => iscntrl(c),
                        "digit" => isdigit(c),
                        "graph" => isgraph(c),
                        "lower" => islower(c),
                        "print" => isprint(c),
                        "punct" => ispunct(c),
                        "space" => isspace(c),
                        "upper" => isupper(c),
                        _ => isxdigit(c),
                    }
                };
                assert_eq!(got, want as c_int, "is{name}({c})");
            }
            assert_eq!(
                unsafe { isascii(c) },
                ((0..128).contains(&c)) as c_int,
                "isascii({c})"
            );
            assert_eq!(unsafe { toascii(c) }, ascii, "toascii({c})");
            assert_eq!(unsafe { tolower(c) }, lo, "tolower({c})");
            assert_eq!(unsafe { toupper(c) }, hi, "toupper({c})");
        }
    }

    #[test]
    fn edges() {
        unsafe {
            // EOF(-1): every is* is 0, every to* passes through.
            for f in [
                isalnum as unsafe extern "C" fn(c_int) -> c_int,
                isalpha,
                isblank,
                iscntrl,
                isdigit,
                isgraph,
                islower,
                isprint,
                ispunct,
                isspace,
                isupper,
                isxdigit,
            ] {
                assert_eq!(f(-1), 0);
                assert_eq!(f(256), 0);
                assert_eq!(f(-2), 0);
            }
            assert_eq!(isascii(-1), 0);
            assert_eq!(isascii(128), 0);
            assert_eq!(isascii(127), 1);
            assert_eq!(toascii(-1), 0x7f);
            assert_eq!(tolower(-1), -1);
            assert_eq!(toupper(-1), -1);
            assert_eq!(tolower(256), 256);
            assert_eq!(toupper(256), 256);
            assert_eq!(tolower(b'A' as c_int), b'a' as c_int);
            assert_eq!(toupper(b'a' as c_int), b'A' as c_int);
        }
    }
}
