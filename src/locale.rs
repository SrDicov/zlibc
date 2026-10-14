//! D4 packet 1: locale stubs, musl-observable behavior.
//!
//! Mirrors musl `src/locale/setlocale.c` + `localeconv.c` contracts
//! (verified, reimplemented): the builtins `C`/`POSIX`/`C.UTF-8`/`""`
//! all behave as C; any other name is kept (musl succeeds with a stub
//! map) while contents stay C; `LC_ALL` queries join with `;` when
//! categories differ. `localeconv` serves one static C `lconv`
//! (`decimal_point = "."`, the rest empty/`CHAR_MAX`).
//!
//! shortcut(no message catalogs): real `*.mo`/locpath loading is OUT —
//! contents are always C, only the reported name varies, exactly like a
//! musl build without `MUSL_LOCPATH` data.
//!
//! All `static mut` traffic goes through `addr_of_mut!` + raw arithmetic
//! (never indexed places — the `static_mut_refs` lint forbids those
//! under `-D warnings`).

use core::ffi::{c_char, c_int};
use core::ptr::addr_of_mut;

/// musl `include/locale.h:5-11` categories.
pub const LC_CTYPE: c_int = 0;
pub const LC_NUMERIC: c_int = 1;
pub const LC_TIME: c_int = 2;
pub const LC_COLLATE: c_int = 3;
pub const LC_MONETARY: c_int = 4;
pub const LC_MESSAGES: c_int = 5;
pub const LC_ALL: c_int = 6;
const NCAT: usize = 6;
/// Stored names are capped (musl keeps the full string; 63 chars + NUL
/// covers every real-world locale tag with room — `shortcut:`, heap-store
/// names if a longer tag ever appears in the wild).
const NAME_CAP: usize = 64;

/// Current name per category, NUL-terminated.
static mut CURRENT: [[u8; NAME_CAP]; NCAT] = [[0; NAME_CAP]; NCAT];
static mut INIT: bool = false;

unsafe fn cur_byte(k: usize, j: usize) -> u8 {
    unsafe { *addr_of_mut!(CURRENT).cast::<u8>().add(k * NAME_CAP + j) }
}

unsafe fn set_byte(k: usize, j: usize, v: u8) {
    unsafe {
        *addr_of_mut!(CURRENT).cast::<u8>().add(k * NAME_CAP + j) = v;
    }
}

unsafe fn cur_name(k: usize) -> *mut c_char {
    unsafe { addr_of_mut!(CURRENT).cast::<u8>().add(k * NAME_CAP) as *mut c_char }
}

fn ensure_init() {
    unsafe {
        if addr_of_mut!(INIT).read() {
            return;
        }
        let mut k = 0;
        while k < NCAT {
            set_byte(k, 0, b'C');
            set_byte(k, 1, 0);
            k += 1;
        }
        addr_of_mut!(INIT).write(true);
    }
}

fn is_builtin(s: &[u8]) -> bool {
    s == b"C" || s == b"POSIX" || s == b"C.UTF-8" || s.is_empty()
}

fn c_len(p: *const c_char) -> usize {
    let mut n = 0usize;
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
    }
    n
}

/// Store `bytes` into slot `k`, mapped through the builtin rule.
unsafe fn store_name(k: usize, bytes: &[u8]) {
    unsafe {
        let src: &[u8] = if is_builtin(bytes) && bytes != b"C.UTF-8" {
            b"C"
        } else {
            bytes
        };
        let n = src.len().min(NAME_CAP - 1);
        let mut j = 0;
        while j < n {
            set_byte(k, j, src[j]);
            j += 1;
        }
        set_byte(k, n, 0);
    }
}

/// Select/query the locale (musl `setlocale`, same return contract:
/// stored name on success, NULL on a bad category).
///
/// # Safety
///
/// `name` must be null (query) or a valid NUL-terminated string. The
/// returned pointer stays valid until the next successful `setlocale`
/// call touching its category (static storage, like musl).
#[no_mangle]
pub unsafe extern "C" fn setlocale(cat: c_int, name: *const c_char) -> *mut c_char {
    unsafe {
        ensure_init();
        if !(0..=LC_ALL).contains(&cat) {
            return core::ptr::null_mut();
        }
        if name.is_null() {
            // Query: LC_ALL joins differing categories with ';'.
            if cat == LC_ALL {
                let mut k = 1;
                while k < NCAT {
                    let mut j = 0;
                    while j < NAME_CAP && cur_byte(k, j) == cur_byte(0, j) {
                        if cur_byte(0, j) == 0 {
                            break;
                        }
                        j += 1;
                    }
                    if cur_byte(k, j) != cur_byte(0, j) {
                        break;
                    }
                    k += 1;
                }
                if k == NCAT {
                    return cur_name(0);
                }
                // Differing: join into a dedicated static buffer.
                static mut JOINED: [u8; NCAT * NAME_CAP + NCAT] = [0; NCAT * NAME_CAP + NCAT];
                let base = addr_of_mut!(JOINED).cast::<u8>();
                let mut w = 0usize;
                let mut c = 0;
                while c < NCAT {
                    let mut j = 0;
                    while cur_byte(c, j) != 0 {
                        *base.add(w) = cur_byte(c, j);
                        w += 1;
                        j += 1;
                    }
                    if c + 1 < NCAT {
                        *base.add(w) = b';';
                        w += 1;
                    }
                    c += 1;
                }
                *base.add(w) = 0;
                return base as *mut c_char;
            }
            return cur_name(cat as usize);
        }
        let bytes = core::slice::from_raw_parts(name as *const u8, c_len(name));
        if cat == LC_ALL {
            // Setting LC_ALL applies one name everywhere.
            let mut c = 0;
            while c < NCAT {
                store_name(c, bytes);
                c += 1;
            }
            return cur_name(0);
        }
        store_name(cat as usize, bytes);
        cur_name(cat as usize)
    }
}

/// musl `struct lconv` (`include/locale.h:20-42`): ten string slots then
/// twelve `char` fields. Only `decimal_point` differs from empty/CHAR_MAX
/// in the C locale, but the full shape is reproduced for ABI callers.
#[repr(C)]
pub struct Lconv {
    pub decimal_point: *mut c_char,
    pub thousands_sep: *mut c_char,
    pub grouping: *mut c_char,
    pub int_curr_symbol: *mut c_char,
    pub currency_symbol: *mut c_char,
    pub mon_decimal_point: *mut c_char,
    pub mon_thousands_sep: *mut c_char,
    pub mon_grouping: *mut c_char,
    pub positive_sign: *mut c_char,
    pub negative_sign: *mut c_char,
    pub int_frac_digits: c_char,
    pub frac_digits: c_char,
    pub p_cs_precedes: c_char,
    pub p_sep_by_space: c_char,
    pub n_cs_precedes: c_char,
    pub n_sep_by_space: c_char,
    pub p_sign_posn: c_char,
    pub n_sign_posn: c_char,
    pub int_p_cs_precedes: c_char,
    pub int_p_sep_by_space: c_char,
    pub int_n_cs_precedes: c_char,
    pub int_n_sep_by_space: c_char,
}

static mut DOT: [u8; 2] = [b'.', 0];
static mut EMPTY: [u8; 1] = [0];
static mut POSIX_LCONV: Lconv = Lconv {
    decimal_point: addr_of_mut!(DOT) as *mut c_char,
    thousands_sep: addr_of_mut!(EMPTY) as *mut c_char,
    grouping: addr_of_mut!(EMPTY) as *mut c_char,
    int_curr_symbol: addr_of_mut!(EMPTY) as *mut c_char,
    currency_symbol: addr_of_mut!(EMPTY) as *mut c_char,
    mon_decimal_point: addr_of_mut!(EMPTY) as *mut c_char,
    mon_thousands_sep: addr_of_mut!(EMPTY) as *mut c_char,
    mon_grouping: addr_of_mut!(EMPTY) as *mut c_char,
    positive_sign: addr_of_mut!(EMPTY) as *mut c_char,
    negative_sign: addr_of_mut!(EMPTY) as *mut c_char,
    int_frac_digits: 127,
    frac_digits: 127,
    p_cs_precedes: 127,
    p_sep_by_space: 127,
    n_cs_precedes: 127,
    n_sep_by_space: 127,
    p_sign_posn: 127,
    n_sign_posn: 127,
    int_p_cs_precedes: 127,
    int_p_sep_by_space: 127,
    int_n_cs_precedes: 127,
    int_n_sep_by_space: 127,
};

/// Numeric formatting conventions for the C locale (musl `localeconv`).
///
/// # Safety
///
/// The returned pointer stays valid forever (static storage); the
/// pointee must only be read, never written.
#[no_mangle]
pub unsafe extern "C" fn localeconv() -> *mut Lconv {
    addr_of_mut!(POSIX_LCONV)
}

#[cfg(test)]
mod tests {
    use super::{localeconv, setlocale, LC_ALL, LC_CTYPE, LC_NUMERIC};
    use core::ffi::c_char;
    use core::ptr::null;

    unsafe fn to_str(p: *const c_char) -> &'static str {
        unsafe {
            let mut n = 0usize;
            while *p.add(n) != 0 {
                n += 1;
            }
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(p as *const u8, n))
        }
    }

    #[test]
    fn setlocale_contracts_hold() {
        unsafe {
            // Fresh query is "C" everywhere; LC_ALL agrees when uniform.
            assert_eq!(to_str(setlocale(LC_CTYPE, null())), "C");
            assert_eq!(to_str(setlocale(LC_ALL, null())), "C");
            // Builtins collapse ("" like musl's env-default).
            assert_eq!(to_str(setlocale(LC_NUMERIC, c"POSIX".as_ptr())), "C");
            assert_eq!(to_str(setlocale(LC_NUMERIC, c"".as_ptr())), "C");
            assert_eq!(to_str(setlocale(LC_CTYPE, c"C.UTF-8".as_ptr())), "C.UTF-8");
            // Foreign names are kept (stub success, C contents).
            assert_eq!(to_str(setlocale(LC_CTYPE, c"es_ES".as_ptr())), "es_ES");
            // Now LC_ALL joins the differing categories.
            assert_eq!(to_str(setlocale(LC_ALL, null())), "es_ES;C;C;C;C;C");
            // One name everywhere through LC_ALL; bad category is NULL.
            assert_eq!(to_str(setlocale(LC_ALL, c"C".as_ptr())), "C");
            assert!(setlocale(99, null()).is_null());
            assert!(setlocale(-2, null()).is_null());
        }
    }

    #[test]
    fn localeconv_is_plain_c() {
        unsafe {
            let l = localeconv();
            assert!(!l.is_null());
            assert_eq!(to_str((*l).decimal_point), ".");
            assert_eq!(to_str((*l).thousands_sep), "");
            assert_eq!((*l).frac_digits, 127);
            assert_eq!((*l).p_sign_posn, 127);
        }
    }
}
