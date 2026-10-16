//! Wide chars (musl `src/string/wcs*.c` + `wmem*.c`, `src/ctype/isw*.c` +
//! `towctrans.c` + `wcwidth.c` + `wcswidth.c`, verified, reimplemented).
//!
//! Types mirror musl on x86_64 (`arch/x86_64/bits/alltypes.h.in:9`,
//! `include/alltypes.h.in:38-39`, `include/wctype.h:20`): `wchar_t` is
//! `i32` (4 bytes), `wint_t` is `u32`, `wctype_t` is `unsigned long`
//! (a `usize` handle holding musl's `WCTYPE_*` values 1-12), `wctrans_t`
//! is `const int *` (a `usize` handle holding musl's pointer values
//! 1 = toupper, 2 = tolower). `WEOF` is `0xffffffffU`.
//!
//! C-locale scope (documented deviations from musl): musl implements
//! the `isw*` classes and `tow*` maps over full Unicode tables
//! (`alpha.h`, `punct.h`, `casemap.h`) regardless of locale. Here the
//! 12 classes and both case maps are ASCII-only, which is exactly the
//! C-locale behavior (glibc agrees: non-ASCII is not alpha, has no
//! case, has no width). Concretely: `iswcntrl`/`iswprint`/`iswspace`
//! drop musl's 5 extra Unicode controls (`U+2028/2029`, `U+FFF9-FFFB`)
//! and non-ASCII spaces (`U+0085`, `U+2000-200A`, `U+2028/2029`,
//! `U+205F`, `U+3000`); `wcwidth` returns -1 for everything outside
//! `0x20..=0x7E` (musl consults `nonspacing.h`/`wide.h` there instead).
//! `wcsstr` is a naive O(nm) scan, not musl's two-way algorithm.
//! No multibyte conversion here (`mbrtowc`/`wcrtomb` belong to the
//! locale wave).

use core::ffi::{c_char, c_int};

/// `sizeof(wchar_t)` on x86_64 Linux.
const WSZ: usize = core::mem::size_of::<i32>();

// ---- private helpers (safe wrappers, unsafe inside) -------------------------

fn wlen(s: *const i32) -> usize {
    unsafe {
        let mut n = 0usize;
        while !(*s.add(n) == 0) {
            n = n.wrapping_add(1);
        }
        n
    }
}

fn wchr(s: *const i32, c: i32) -> *mut i32 {
    unsafe {
        if c == 0 {
            return (s as *mut i32).add(wlen(s));
        }
        let mut p = s;
        while *p != 0 && *p != c {
            p = p.add(1);
        }
        if *p == c {
            p as *mut i32
        } else {
            core::ptr::null_mut()
        }
    }
}

fn wspn(s: *const i32, c: *const i32) -> usize {
    unsafe {
        let mut n = 0usize;
        while *s.add(n) != 0 && !wchr(c, *s.add(n)).is_null() {
            n = n.wrapping_add(1);
        }
        n
    }
}

fn wcspn(s: *const i32, c: *const i32) -> usize {
    unsafe {
        let mut n = 0usize;
        while *s.add(n) != 0 && wchr(c, *s.add(n)).is_null() {
            n = n.wrapping_add(1);
        }
        n
    }
}

fn wlower(wc: u32) -> u32 {
    if (wc.wrapping_sub('A' as u32)) < 26 {
        wc.wrapping_add(32)
    } else {
        wc
    }
}

fn wupper(wc: u32) -> u32 {
    if (wc.wrapping_sub('a' as u32)) < 26 {
        wc.wrapping_sub(32)
    } else {
        wc
    }
}

fn walpha(wc: u32) -> bool {
    matches!(wc, 0x41..=0x5A | 0x61..=0x7A)
}

fn wdigit(wc: u32) -> bool {
    wc.wrapping_sub('0' as u32) < 10
}

fn wspace(wc: u32) -> bool {
    matches!(wc, 9..=13 | 32)
}

fn wprint(wc: u32) -> bool {
    matches!(wc, 32..=126)
}

fn wcntrl(wc: u32) -> bool {
    wc < 32 || (0x7f..0xa0).contains(&wc)
}

fn wlower_p(wc: u32) -> bool {
    wupper(wc) != wc
}

fn wupper_p(wc: u32) -> bool {
    wlower(wc) != wc
}

fn walnum(wc: u32) -> bool {
    walpha(wc) || wdigit(wc)
}

fn wgraph(wc: u32) -> bool {
    !wspace(wc) && wprint(wc)
}

fn wpunct(wc: u32) -> bool {
    wgraph(wc) && !walnum(wc)
}

fn wxdigit(wc: u32) -> bool {
    wdigit(wc) || (wc | 32).wrapping_sub('a' as u32) < 6
}

/// `strcmp`-style match of a NUL-terminated `p` against `name`.
fn name_eq(p: *const c_char, name: &[u8]) -> bool {
    unsafe {
        let mut k = 0usize;
        loop {
            let b = *p.add(k) as u8;
            if k == name.len() {
                return b == 0;
            }
            if b != name[k] {
                return false;
            }
            k = k.wrapping_add(1);
        }
    }
}

// ---- wcs* -------------------------------------------------------------------

/// String length in wide chars, not counting NUL (musl `wcslen.c`).
///
/// # Safety
///
/// `s` must point to a NUL-terminated wide string.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wcslen(s: *const i32) -> usize {
    wlen(s)
}

/// Copy `src` (with NUL) to `d`, return `d` (musl `wcscpy.c`).
///
/// # Safety
///
/// `src` must be NUL-terminated; `d` must fit it.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wcscpy(d: *mut i32, s: *const i32) -> *mut i32 {
    unsafe {
        let mut k = 0usize;
        loop {
            let c = *s.add(k);
            *d.add(k) = c;
            if c == 0 {
                break;
            }
            k = k.wrapping_add(1);
        }
        d
    }
}

/// Copy at most `n` wide chars, NUL-pad the rest (musl `wcsncpy.c`).
///
/// # Safety
///
/// `d` must fit `n` wide chars; `src` must be valid for `min(n, len)`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wcsncpy(d: *mut i32, s: *const i32, n: usize) -> *mut i32 {
    unsafe {
        let mut k = 0usize;
        while k < n && *s.add(k) != 0 {
            *d.add(k) = *s.add(k);
            k = k.wrapping_add(1);
        }
        wmemset(d.add(k), 0, n.wrapping_sub(k));
        d
    }
}

/// Append `src` to `dest`, return `dest` (musl `wcscat.c`).
///
/// # Safety
///
/// `dest` must be NUL-terminated with room for `src`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wcscat(dest: *mut i32, src: *const i32) -> *mut i32 {
    unsafe {
        wcscpy(dest.add(wlen(dest)), src);
        dest
    }
}

/// Append at most `n` wide chars of `s` to `d`, always NUL-terminate
/// (musl `wcsncat.c`).
///
/// # Safety
///
/// `d` must be NUL-terminated with room for `n` chars + NUL.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wcsncat(d: *mut i32, s: *const i32, mut n: usize) -> *mut i32 {
    unsafe {
        let a = d;
        let mut t = d.add(wlen(d));
        let mut k = 0usize;
        while n != 0 && *s.add(k) != 0 {
            *t = *s.add(k);
            t = t.add(1);
            k = k.wrapping_add(1);
            n -= 1;
        }
        *t = 0;
        a
    }
}

/// Compare, normalising to -1/0/1 (musl `wcscmp.c`).
///
/// # Safety
///
/// Both must be NUL-terminated.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wcscmp(l: *const i32, r: *const i32) -> c_int {
    unsafe {
        let mut k = 0usize;
        while *l.add(k) == *r.add(k) && *l.add(k) != 0 {
            k = k.wrapping_add(1);
        }
        let (a, b) = (*l.add(k), *r.add(k));
        if a < b {
            -1
        } else if a > b {
            1
        } else {
            0
        }
    }
}

/// Compare at most `n` wide chars, -1/0/1 (musl `wcsncmp.c`).
///
/// # Safety
///
/// Both must be valid for `min(n, len + 1)` wide chars.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wcsncmp(l: *const i32, r: *const i32, mut n: usize) -> c_int {
    unsafe {
        let mut k = 0usize;
        while n != 0 && *l.add(k) == *r.add(k) && *l.add(k) != 0 {
            k = k.wrapping_add(1);
            n -= 1;
        }
        if n == 0 {
            return 0;
        }
        let (a, b) = (*l.add(k), *r.add(k));
        if a < b {
            -1
        } else if a > b {
            1
        } else {
            0
        }
    }
}

/// First occurrence of `c`, matching NUL too (musl `wcschr.c`).
///
/// # Safety
///
/// `s` must be NUL-terminated.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wcschr(s: *const i32, c: i32) -> *mut i32 {
    wchr(s, c)
}

/// Last occurrence of `c`, matching NUL too (musl `wcsrchr.c`).
///
/// # Safety
///
/// `s` must be NUL-terminated.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wcsrchr(s: *const i32, c: i32) -> *mut i32 {
    unsafe {
        let mut p = s.add(wlen(s));
        loop {
            if *p == c {
                return p as *mut i32;
            }
            if p == s {
                return core::ptr::null_mut();
            }
            p = p.sub(1);
        }
    }
}

/// First occurrence of `n` in `h`; empty needle returns `h`
/// (musl `wcsstr.c` contract, naive scan — ponytail: musl's two-way
/// algorithm only pays off on long needles).
///
/// # Safety
///
/// Both must be NUL-terminated.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wcsstr(h: *const i32, n: *const i32) -> *mut i32 {
    unsafe {
        if *n == 0 {
            return h as *mut i32;
        }
        let mut i = 0usize;
        while *h.add(i) != 0 {
            let mut k = 0usize;
            while *n.add(k) != 0 {
                let hc = *h.add(i.wrapping_add(k));
                if hc == 0 || hc != *n.add(k) {
                    break;
                }
                k = k.wrapping_add(1);
            }
            if *n.add(k) == 0 {
                return h.add(i) as *mut i32;
            }
            i = i.wrapping_add(1);
        }
        core::ptr::null_mut()
    }
}

/// First char of `s` found in `b`, else NULL (musl `wcspbrk.c`).
///
/// # Safety
///
/// Both must be NUL-terminated.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wcspbrk(s: *const i32, b: *const i32) -> *mut i32 {
    unsafe {
        let p = s.add(wcspn(s, b));
        if *p != 0 {
            p as *mut i32
        } else {
            core::ptr::null_mut()
        }
    }
}

/// Length of the leading run of chars found in `c` (musl `wcsspn.c`).
///
/// # Safety
///
/// Both must be NUL-terminated.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wcsspn(s: *const i32, c: *const i32) -> usize {
    wspn(s, c)
}

/// Length of the leading run of chars absent from `c` (musl `wcscspn.c`).
///
/// # Safety
///
/// Both must be NUL-terminated.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wcscspn(s: *const i32, c: *const i32) -> usize {
    wcspn(s, c)
}

/// Tokenise on `sep`, context in `*p` (musl `wcstok.c`, POSIX 3-arg).
///
/// # Safety
///
/// `sep` must be NUL-terminated; either `s` or `*p` must be a live
/// token string; `p` must be writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wcstok(s: *mut i32, sep: *const i32, p: *mut *mut i32) -> *mut i32 {
    unsafe {
        let mut s = s;
        if s.is_null() {
            s = *p;
            if s.is_null() {
                return core::ptr::null_mut();
            }
        }
        s = s.add(wspn(s, sep));
        if *s == 0 {
            *p = core::ptr::null_mut();
            return core::ptr::null_mut();
        }
        let end = s.add(wcspn(s, sep));
        if *end != 0 {
            *end = 0;
            *p = end.add(1);
        } else {
            *p = core::ptr::null_mut();
        }
        s
    }
}

/// Duplicate `s` via the crate allocator (musl `wcsdup.c`).
///
/// # Safety
///
/// `s` must be NUL-terminated. The result must be freed with
/// [`crate::malloc::free`]; NULL means out of memory.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wcsdup(s: *const i32) -> *mut i32 {
    unsafe {
        let l = wlen(s);
        let d = crate::malloc::malloc(l.wrapping_add(1).wrapping_mul(WSZ)) as *mut i32;
        if d.is_null() {
            return core::ptr::null_mut();
        }
        wmemcpy(d, s, l.wrapping_add(1));
        d
    }
}

/// Bounded length: `min(n, wcslen(s))` (musl `wcsnlen.c`).
///
/// # Safety
///
/// `s` must be valid for `min(n, len + 1)` wide chars.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wcsnlen(s: *const i32, n: usize) -> usize {
    unsafe {
        let z = wmemchr(s, 0, n);
        if z.is_null() {
            n
        } else {
            z.offset_from(s) as usize
        }
    }
}

// ---- wmem* ------------------------------------------------------------------

/// First `c` among `n` wide chars, else NULL (musl `wmemchr.c`).
///
/// # Safety
///
/// `s` must be valid for `n` wide chars.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wmemchr(s: *const i32, c: i32, mut n: usize) -> *mut i32 {
    unsafe {
        let mut p = s;
        while n != 0 && *p != c {
            p = p.add(1);
            n -= 1;
        }
        if n != 0 {
            p as *mut i32
        } else {
            core::ptr::null_mut()
        }
    }
}

/// Compare `n` wide chars, -1/0/1 (musl `wmemcmp.c`).
///
/// # Safety
///
/// Both must be valid for `n` wide chars.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wmemcmp(l: *const i32, r: *const i32, mut n: usize) -> c_int {
    unsafe {
        let mut k = 0usize;
        while n != 0 && *l.add(k) == *r.add(k) {
            k = k.wrapping_add(1);
            n -= 1;
        }
        if n == 0 {
            return 0;
        }
        let (a, b) = (*l.add(k), *r.add(k));
        if a < b {
            -1
        } else if a > b {
            1
        } else {
            0
        }
    }
}

/// Copy `n` wide chars, return `d` (musl `wmemcpy.c`).
///
/// # Safety
///
/// Both must be valid for `n` wide chars; regions must not overlap.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wmemcpy(d: *mut i32, s: *const i32, n: usize) -> *mut i32 {
    unsafe {
        let mut k = 0usize;
        while k < n {
            *d.add(k) = *s.add(k);
            k = k.wrapping_add(1);
        }
        d
    }
}

/// Copy `n` wide chars, overlap-safe (musl `wmemmove.c`: copies
/// backwards when `d - s < n * WSZ` under wrapping arithmetic).
///
/// # Safety
///
/// Both must be valid for `n` wide chars.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wmemmove(d: *mut i32, s: *const i32, n: usize) -> *mut i32 {
    unsafe {
        if core::ptr::eq(d, s) {
            return d;
        }
        if (d as usize).wrapping_sub(s as usize) < n.wrapping_mul(WSZ) {
            let mut k = n;
            while k != 0 {
                k -= 1;
                *d.add(k) = *s.add(k);
            }
        } else {
            let mut k = 0usize;
            while k < n {
                *d.add(k) = *s.add(k);
                k = k.wrapping_add(1);
            }
        }
        d
    }
}

/// Fill `n` wide chars with `c`, return `d` (musl `wmemset.c`).
///
/// # Safety
///
/// `d` must be valid for `n` wide chars.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wmemset(d: *mut i32, c: i32, n: usize) -> *mut i32 {
    unsafe {
        let mut k = 0usize;
        while k < n {
            *d.add(k) = c;
            k = k.wrapping_add(1);
        }
        d
    }
}

// ---- isw* / tow* / wctype ----------------------------------------------------

/// Alphanumeric: alpha or digit (musl `iswalnum.c` structure).
pub fn iswalnum_inner(wc: u32) -> c_int {
    (walnum(wc)) as c_int
}

/// Alphabetic, C locale: ASCII letters (musl uses `alpha.h` Unicode table).
pub fn iswalpha_inner(wc: u32) -> c_int {
    walpha(wc) as c_int
}

/// Blank: space or tab (musl `iswblank.c` = `isblank`, verbatim).
pub fn iswblank_inner(wc: u32) -> c_int {
    (wc == 32 || wc == 9) as c_int
}

/// Control, C locale: C0 + DEL + C1 (musl adds `U+2028/2029/FFF9-FFFB`).
pub fn iswcntrl_inner(wc: u32) -> c_int {
    wcntrl(wc) as c_int
}

/// Digit: `0-9` (musl `iswdigit.c`, verbatim).
pub fn iswdigit_inner(wc: u32) -> c_int {
    wdigit(wc) as c_int
}

/// Graphic: printable and not space (musl `iswgraph.c`, verbatim shape).
pub fn iswgraph_inner(wc: u32) -> c_int {
    wgraph(wc) as c_int
}

/// Lowercase: `towupper` changes it (musl `iswlower.c`, verbatim shape).
pub fn iswlower_inner(wc: u32) -> c_int {
    wlower_p(wc) as c_int
}

/// Printable, C locale: `0x20..=0x7E` (musl `iswprint.c` covers Unicode).
pub fn iswprint_inner(wc: u32) -> c_int {
    wprint(wc) as c_int
}

/// Punctuation: graphic but not alnum (exact C-locale definition).
pub fn iswpunct_inner(wc: u32) -> c_int {
    wpunct(wc) as c_int
}

/// Whitespace, C locale: `\t\n\v\f\r` + space (musl adds Unicode spaces).
pub fn iswspace_inner(wc: u32) -> c_int {
    wspace(wc) as c_int
}

/// Uppercase: `towlower` changes it (musl `iswupper.c`, verbatim shape).
pub fn iswupper_inner(wc: u32) -> c_int {
    wupper_p(wc) as c_int
}

/// Hex digit (musl `iswxdigit.c`, verbatim).
pub fn iswxdigit_inner(wc: u32) -> c_int {
    wxdigit(wc) as c_int
}

/// # Safety
///
/// Pure function of `wc`; no memory accessed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn iswalnum(wc: u32) -> c_int {
    iswalnum_inner(wc)
}

/// # Safety
///
/// Pure function of `wc`; no memory accessed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn iswalpha(wc: u32) -> c_int {
    iswalpha_inner(wc)
}

/// # Safety
///
/// Pure function of `wc`; no memory accessed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn iswblank(wc: u32) -> c_int {
    iswblank_inner(wc)
}

/// # Safety
///
/// Pure function of `wc`; no memory accessed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn iswcntrl(wc: u32) -> c_int {
    iswcntrl_inner(wc)
}

/// # Safety
///
/// Pure function of `wc`; no memory accessed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn iswdigit(wc: u32) -> c_int {
    iswdigit_inner(wc)
}

/// # Safety
///
/// Pure function of `wc`; no memory accessed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn iswgraph(wc: u32) -> c_int {
    iswgraph_inner(wc)
}

/// # Safety
///
/// Pure function of `wc`; no memory accessed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn iswlower(wc: u32) -> c_int {
    iswlower_inner(wc)
}

/// # Safety
///
/// Pure function of `wc`; no memory accessed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn iswprint(wc: u32) -> c_int {
    iswprint_inner(wc)
}

/// # Safety
///
/// Pure function of `wc`; no memory accessed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn iswpunct(wc: u32) -> c_int {
    iswpunct_inner(wc)
}

/// # Safety
///
/// Pure function of `wc`; no memory accessed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn iswspace(wc: u32) -> c_int {
    iswspace_inner(wc)
}

/// # Safety
///
/// Pure function of `wc`; no memory accessed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn iswupper(wc: u32) -> c_int {
    iswupper_inner(wc)
}

/// # Safety
///
/// Pure function of `wc`; no memory accessed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn iswxdigit(wc: u32) -> c_int {
    iswxdigit_inner(wc)
}

/// ASCII lowercase, identity otherwise (musl `towctrans.c` +
/// full-Unicode `casemap.h`; C locale needs only ASCII).
///
/// # Safety
///
/// Pure function; no memory accessed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn towlower(wc: u32) -> u32 {
    wlower(wc)
}

/// ASCII uppercase, identity otherwise (same scope note as [`towlower`]).
///
/// # Safety
///
/// Pure function; no memory accessed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn towupper(wc: u32) -> u32 {
    wupper(wc)
}

/// Class name to descriptor: musl's `WCTYPE_*` values 1-12 in the
/// same order (`alnum`..`xdigit`); unknown names give 0
/// (musl `iswctype.c:wctype`, verbatim order/table).
///
/// # Safety
///
/// `s` must be a NUL-terminated byte string (NULL gives 0).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wctype(s: *const c_char) -> usize {
    if s.is_null() {
        return 0;
    }
    // Order must match the WCTYPE_* values below.
    const NAMES: [&[u8]; 12] = [
        b"alnum", b"alpha", b"blank", b"cntrl", b"digit", b"graph", b"lower", b"print", b"punct",
        b"space", b"upper", b"xdigit",
    ];
    let mut i = 0usize;
    while i < NAMES.len() {
        if name_eq(s, NAMES[i]) {
            return i.wrapping_add(1);
        }
        i = i.wrapping_add(1);
    }
    0
}

/// Classify `wc` by descriptor from [`wctype`]; unknown types give 0
/// (musl `iswctype.c:iswctype`, verbatim dispatch).
///
/// # Safety
///
/// Pure function; no memory accessed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn iswctype(wc: u32, t: usize) -> c_int {
    match t {
        1 => iswalnum_inner(wc),
        2 => iswalpha_inner(wc),
        3 => iswblank_inner(wc),
        4 => iswcntrl_inner(wc),
        5 => iswdigit_inner(wc),
        6 => iswgraph_inner(wc),
        7 => iswlower_inner(wc),
        8 => iswprint_inner(wc),
        9 => iswpunct_inner(wc),
        10 => iswspace_inner(wc),
        11 => iswupper_inner(wc),
        12 => iswxdigit_inner(wc),
        _ => 0,
    }
}

/// Transform name to descriptor: `toupper` = 1, `tolower` = 2, else 0
/// (musl `wctrans.c`, verbatim).
///
/// # Safety
///
/// `class` must be a NUL-terminated byte string (NULL gives 0).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wctrans(class: *const c_char) -> usize {
    if class.is_null() {
        return 0;
    }
    if name_eq(class, b"toupper") {
        return 1;
    }
    if name_eq(class, b"tolower") {
        return 2;
    }
    0
}

/// Apply a [`wctrans`] descriptor; unknown transforms are the identity
/// (musl `wctrans.c:towctrans`, verbatim).
///
/// # Safety
///
/// Pure function; no memory accessed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn towctrans(wc: u32, t: usize) -> u32 {
    match t {
        1 => wupper(wc),
        2 => wlower(wc),
        _ => wc,
    }
}

/// Column width, C locale: 0 for NUL, 1 for ASCII printables, -1 for
/// everything else (musl `wcwidth.c` fast path for `< 0xff` plus
/// `nonspacing.h`/`wide.h` tables above it; tables are locale data,
/// out of scope — non-ASCII goes -1).
///
/// # Safety
///
/// Pure function; no memory accessed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wcwidth(wc: i32) -> c_int {
    if wc == 0 {
        0
    } else if (32..=126).contains(&wc) {
        1
    } else {
        -1
    }
}

/// Width of at most `n` wide chars; NUL or `n` stops the sum, a
/// non-printable propagates -1 (musl `wcswidth.c`, verbatim).
///
/// # Safety
///
/// `s` must be valid for `min(n, len + 1)` wide chars.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wcswidth(s: *const i32, mut n: usize) -> c_int {
    unsafe {
        let mut l: c_int = 0;
        let mut k: c_int = 0;
        let mut p = s;
        while n != 0 {
            n -= 1;
            let c = *p;
            if c == 0 {
                break;
            }
            // Same-file call: inner unsafe covers it.
            k = wcwidth(c);
            if k < 0 {
                break;
            }
            l = l.wrapping_add(k);
            p = p.add(1);
        }
        if k < 0 {
            k
        } else {
            l
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_void;

    fn w(s: &str) -> std::vec::Vec<i32> {
        let mut v: std::vec::Vec<i32> = s.chars().map(|c| c as i32).collect();
        v.push(0);
        v
    }

    unsafe fn slen_eq(s: *const i32, n: usize) {
        unsafe {
            assert_eq!(wcslen(s), n);
        }
    }

    #[test]
    fn len_covers_empty_and_ascii() {
        unsafe {
            slen_eq(w("").as_ptr(), 0);
            slen_eq(w("hello").as_ptr(), 5);
        }
    }

    #[test]
    fn cpy_roundtrip() {
        unsafe {
            let src = w("abc");
            let mut d = [0i32; 8];
            assert_eq!(wcscpy(d.as_mut_ptr(), src.as_ptr()), d.as_mut_ptr());
            assert_eq!(wcslen(d.as_ptr()), 3);
            assert_eq!(wcscmp(d.as_ptr(), src.as_ptr()), 0);
        }
    }

    #[test]
    fn ncpy_pads_nul() {
        unsafe {
            let src = w("hi");
            let mut d = [9i32; 8];
            wcsncpy(d.as_mut_ptr(), src.as_ptr(), 5);
            assert_eq!(d, [104, 105, 0, 0, 0, 9, 9, 9]);
            // Truncation: no NUL written past n.
            let long = w("abcdef");
            let mut t = [0i32; 4];
            wcsncpy(t.as_mut_ptr(), long.as_ptr(), 3);
            assert_eq!(t, [97, 98, 99, 0]);
        }
    }

    #[test]
    fn cat_appends() {
        unsafe {
            let mut d = [0i32; 12];
            wcscpy(d.as_mut_ptr(), w("foo").as_ptr());
            assert_eq!(wcscat(d.as_mut_ptr(), w("bar").as_ptr()), d.as_mut_ptr());
            assert_eq!(wcscmp(d.as_ptr(), w("foobar").as_ptr()), 0);
        }
    }

    #[test]
    fn ncat_truncates_and_nuls() {
        unsafe {
            let mut d = [0i32; 12];
            wcscpy(d.as_mut_ptr(), w("ab").as_ptr());
            wcsncat(d.as_mut_ptr(), w("cdef").as_ptr(), 2);
            assert_eq!(wcscmp(d.as_ptr(), w("abcd").as_ptr()), 0);
            // n larger than src: whole src plus NUL.
            let mut e = [0i32; 12];
            wcscpy(e.as_mut_ptr(), w("x").as_ptr());
            wcsncat(e.as_mut_ptr(), w("yz").as_ptr(), 99);
            assert_eq!(wcscmp(e.as_ptr(), w("xyz").as_ptr()), 0);
        }
    }

    #[test]
    fn cmp_signs() {
        unsafe {
            assert_eq!(wcscmp(w("a").as_ptr(), w("a").as_ptr()), 0);
            assert_eq!(wcscmp(w("a").as_ptr(), w("b").as_ptr()), -1);
            assert_eq!(wcscmp(w("b").as_ptr(), w("a").as_ptr()), 1);
            assert_eq!(wcscmp(w("ab").as_ptr(), w("a").as_ptr()), 1);
            assert_eq!(wcscmp(w("").as_ptr(), w("a").as_ptr()), -1);
        }
    }

    #[test]
    fn ncmp_caps_at_n() {
        unsafe {
            assert_eq!(wcsncmp(w("abc").as_ptr(), w("abd").as_ptr(), 2), 0);
            assert_eq!(wcsncmp(w("abc").as_ptr(), w("abd").as_ptr(), 3), -1);
            assert_eq!(wcsncmp(w("abc").as_ptr(), w("ab").as_ptr(), 99), 1);
            assert_eq!(wcsncmp(w("a").as_ptr(), w("b").as_ptr(), 0), 0);
        }
    }

    #[test]
    fn chr_finds_and_matches_nul() {
        unsafe {
            let s = w("hello");
            let p = wcschr(s.as_ptr(), 'l' as i32);
            assert_eq!(p.offset_from(s.as_ptr()), 2);
            assert!(wcschr(s.as_ptr(), 'z' as i32).is_null());
            // NUL match returns the terminator.
            assert_eq!(wcschr(s.as_ptr(), 0).offset_from(s.as_ptr()), 5);
        }
    }

    #[test]
    fn rchr_finds_last_and_nul() {
        unsafe {
            let s = w("hello");
            assert_eq!(wcsrchr(s.as_ptr(), 'l' as i32).offset_from(s.as_ptr()), 3);
            assert!(wcsrchr(s.as_ptr(), 'z' as i32).is_null());
            assert_eq!(wcsrchr(s.as_ptr(), 0).offset_from(s.as_ptr()), 5);
        }
    }

    #[test]
    fn str_finds_substring() {
        unsafe {
            let h = w("hello world");
            let f = wcsstr(h.as_ptr(), w("world").as_ptr());
            assert_eq!(f.offset_from(h.as_ptr()), 6);
            // Empty needle returns h; empty haystack misses.
            assert_eq!(wcsstr(h.as_ptr(), w("").as_ptr()), h.as_ptr() as *mut i32);
            assert!(wcsstr(w("").as_ptr(), w("x").as_ptr()).is_null());
            assert!(wcsstr(h.as_ptr(), w("zzz").as_ptr()).is_null());
            // Needle longer than haystack cannot match (no OOB read).
            assert!(wcsstr(w("ab").as_ptr(), w("abcdef").as_ptr()).is_null());
            // Tail match.
            assert_eq!(
                wcsstr(h.as_ptr(), w("o w").as_ptr()).offset_from(h.as_ptr()),
                4
            );
        }
    }

    #[test]
    fn pbrk_spans() {
        unsafe {
            let s = w("abcde");
            assert_eq!(
                wcspbrk(s.as_ptr(), w("d").as_ptr()).offset_from(s.as_ptr()),
                3
            );
            assert!(wcspbrk(s.as_ptr(), w("z").as_ptr()).is_null());
            assert_eq!(wcsspn(w("aaab").as_ptr(), w("a").as_ptr()), 3);
            assert_eq!(wcscspn(w("aaab").as_ptr(), w("b").as_ptr()), 3);
            assert_eq!(wcscspn(w("abc").as_ptr(), w("").as_ptr()), 3);
        }
    }

    #[test]
    fn tok_sequence() {
        unsafe {
            let mut s = w(",,one,two,,three,");
            let sep = w(",");
            let mut ctx: *mut i32 = core::ptr::null_mut();
            let t1 = wcstok(s.as_mut_ptr(), sep.as_ptr(), &mut ctx);
            assert_eq!(wcscmp(t1, w("one").as_ptr()), 0);
            let t2 = wcstok(core::ptr::null_mut(), sep.as_ptr(), &mut ctx);
            assert_eq!(wcscmp(t2, w("two").as_ptr()), 0);
            let t3 = wcstok(core::ptr::null_mut(), sep.as_ptr(), &mut ctx);
            assert_eq!(wcscmp(t3, w("three").as_ptr()), 0);
            assert!(wcstok(core::ptr::null_mut(), sep.as_ptr(), &mut ctx).is_null());
            // Fresh string, no separators.
            let mut solo = w("abc");
            let mut c2: *mut i32 = core::ptr::null_mut();
            let u = wcstok(solo.as_mut_ptr(), sep.as_ptr(), &mut c2);
            assert_eq!(wcscmp(u, w("abc").as_ptr()), 0);
            assert!(wcstok(core::ptr::null_mut(), sep.as_ptr(), &mut c2).is_null());
        }
    }

    #[test]
    fn dup_heap_roundtrip() {
        unsafe {
            let s = w("hi!");
            let d = wcsdup(s.as_ptr());
            assert!(!d.is_null());
            assert_eq!(wcslen(d), 3);
            assert_eq!(wcscmp(d, s.as_ptr()), 0);
            crate::malloc::free(d as *mut c_void);
        }
    }

    #[test]
    fn nlen_caps() {
        unsafe {
            assert_eq!(wcsnlen(w("abc").as_ptr(), 10), 3);
            assert_eq!(wcsnlen(w("abc").as_ptr(), 2), 2);
            assert_eq!(wcsnlen(w("").as_ptr(), 5), 0);
        }
    }

    #[test]
    fn memchr_memcmp() {
        unsafe {
            let s = w("abc");
            assert_eq!(
                wmemchr(s.as_ptr(), 'b' as i32, 3).offset_from(s.as_ptr()),
                1
            );
            assert!(wmemchr(s.as_ptr(), 'z' as i32, 3).is_null());
            // NUL is findable within bounds.
            assert_eq!(wmemchr(s.as_ptr(), 0, 4).offset_from(s.as_ptr()), 3);
            assert!(wmemchr(s.as_ptr(), 0, 3).is_null());
            assert_eq!(wmemcmp(w("a").as_ptr(), w("a").as_ptr(), 1), 0);
            assert_eq!(wmemcmp(w("a").as_ptr(), w("b").as_ptr(), 1), -1);
            assert_eq!(wmemcmp(w("b").as_ptr(), w("a").as_ptr(), 1), 1);
            assert_eq!(wmemcmp(w("ax").as_ptr(), w("ay").as_ptr(), 1), 0);
            assert_eq!(wmemcmp(w("a").as_ptr(), w("b").as_ptr(), 0), 0);
        }
    }

    #[test]
    fn memcpy_memset() {
        unsafe {
            let s = w("abcd");
            let mut d = [0i32; 6];
            assert_eq!(wmemcpy(d.as_mut_ptr(), s.as_ptr(), 5), d.as_mut_ptr());
            assert_eq!(wcscmp(d.as_ptr(), s.as_ptr()), 0);
            let mut z = [7i32; 4];
            assert_eq!(wmemset(z.as_mut_ptr(), 0, 4), z.as_mut_ptr());
            assert_eq!(z, [0, 0, 0, 0]);
            wmemset(z.as_mut_ptr(), -5, 2);
            assert_eq!(z, [-5, -5, 0, 0]);
        }
    }

    #[test]
    fn memmove_overlap_both_directions() {
        unsafe {
            // Forward overlap: dest above src.
            let mut f = [1i32, 2, 3, 4, 5];
            wmemmove(f.as_mut_ptr().add(1), f.as_ptr(), 4);
            assert_eq!(f, [1, 1, 2, 3, 4]);
            // Backward overlap: dest below src.
            let mut b = [1i32, 2, 3, 4, 5];
            wmemmove(b.as_mut_ptr(), b.as_ptr().add(1), 4);
            assert_eq!(b, [2, 3, 4, 5, 5]);
            // Identity is a no-op.
            let mut e = [1i32, 2, 3];
            wmemmove(e.as_mut_ptr(), e.as_ptr(), 3);
            assert_eq!(e, [1, 2, 3]);
        }
    }

    #[test]
    fn isw_all_twelve() {
        assert_eq!(iswalnum_inner('A' as u32), 1);
        assert_eq!(iswalnum_inner('5' as u32), 1);
        assert_eq!(iswalnum_inner('_' as u32), 0);
        assert_eq!(iswalpha_inner('z' as u32), 1);
        assert_eq!(iswalpha_inner('5' as u32), 0);
        assert_eq!(iswblank_inner(' ' as u32), 1);
        assert_eq!(iswblank_inner('\t' as u32), 1);
        assert_eq!(iswblank_inner('\n' as u32), 0);
        assert_eq!(iswcntrl_inner(0x1b), 1);
        assert_eq!(iswcntrl_inner(0x7f), 1);
        assert_eq!(iswcntrl_inner('A' as u32), 0);
        assert_eq!(iswdigit_inner('0' as u32), 1);
        assert_eq!(iswdigit_inner('a' as u32), 0);
        assert_eq!(iswgraph_inner('A' as u32), 1);
        assert_eq!(iswgraph_inner(' ' as u32), 0);
        assert_eq!(iswlower_inner('a' as u32), 1);
        assert_eq!(iswlower_inner('A' as u32), 0);
        assert_eq!(iswprint_inner('~' as u32), 1);
        assert_eq!(iswprint_inner('\n' as u32), 0);
        assert_eq!(iswpunct_inner('!' as u32), 1);
        assert_eq!(iswpunct_inner('A' as u32), 0);
        assert_eq!(iswspace_inner('\n' as u32), 1);
        assert_eq!(iswspace_inner('A' as u32), 0);
        assert_eq!(iswupper_inner('A' as u32), 1);
        assert_eq!(iswupper_inner('a' as u32), 0);
        assert_eq!(iswxdigit_inner('f' as u32), 1);
        assert_eq!(iswxdigit_inner('F' as u32), 1);
        assert_eq!(iswxdigit_inner('g' as u32), 0);
        // Same through the exported symbols (spot check).
        unsafe {
            assert_eq!(iswalpha('Q' as u32), 1);
            assert_eq!(iswspace('\t' as u32), 1);
        }
    }

    #[test]
    fn case_maps() {
        unsafe {
            assert_eq!(towlower('A' as u32), 'a' as u32);
            assert_eq!(towlower('a' as u32), 'a' as u32);
            assert_eq!(towlower('!' as u32), '!' as u32);
            assert_eq!(towupper('a' as u32), 'A' as u32);
            assert_eq!(towupper('Z' as u32), 'Z' as u32);
            assert_eq!(towupper('!' as u32), '!' as u32);
        }
    }

    #[test]
    fn wctype_roundtrips_all_twelve_plus_bad() {
        unsafe {
            for (name, probe, neg) in [
                ("alnum", 'A' as u32, '_' as u32),
                ("alpha", 'A' as u32, '5' as u32),
                ("blank", ' ' as u32, '\n' as u32),
                ("cntrl", 0x1bu32, 'A' as u32),
                ("digit", '5' as u32, 'a' as u32),
                ("graph", 'A' as u32, ' ' as u32),
                ("lower", 'a' as u32, 'A' as u32),
                ("print", 'A' as u32, '\n' as u32),
                ("punct", '!' as u32, 'A' as u32),
                ("space", ' ' as u32, 'A' as u32),
                ("upper", 'A' as u32, 'a' as u32),
                ("xdigit", 'f' as u32, 'g' as u32),
            ] {
                let cs = std::ffi::CString::new(name).unwrap();
                let t = wctype(cs.as_ptr());
                assert!((1..=12).contains(&t), "bad handle for {name}");
                assert_ne!(iswctype(probe, t), 0, "roundtrip failed for {name}");
                assert_eq!(iswctype(neg, t), 0, "negative failed for {name}");
            }
            for bad in ["bogus", "", "ALNUM", "alnum "] {
                let cs = std::ffi::CString::new(bad).unwrap();
                assert_eq!(wctype(cs.as_ptr()), 0);
            }
            assert_eq!(iswctype('A' as u32, 0), 0);
            assert_eq!(iswctype('A' as u32, 99), 0);
        }
    }

    #[test]
    fn wctrans_maps() {
        unsafe {
            let up = std::ffi::CString::new("toupper").unwrap();
            let lo = std::ffi::CString::new("tolower").unwrap();
            let bad = std::ffi::CString::new("bogus").unwrap();
            assert_eq!(wctrans(up.as_ptr()), 1);
            assert_eq!(wctrans(lo.as_ptr()), 2);
            assert_eq!(wctrans(bad.as_ptr()), 0);
            assert_eq!(towctrans('a' as u32, 1), 'A' as u32);
            assert_eq!(towctrans('A' as u32, 2), 'a' as u32);
            assert_eq!(towctrans('a' as u32, 99), 'a' as u32);
        }
    }

    #[test]
    fn width_edges() {
        unsafe {
            assert_eq!(wcwidth(0), 0);
            assert_eq!(wcwidth('A' as i32), 1);
            assert_eq!(wcwidth(' ' as i32), 1);
            assert_eq!(wcwidth(0x1b), -1);
            assert_eq!(wcwidth(0x7f), -1);
            assert_eq!(wcwidth(0x80), -1);
            assert_eq!(wcwidth(0xe9), -1);
            assert_eq!(wcwidth(0x300), -1);
        }
    }

    #[test]
    fn width_sums_propagates_caps() {
        unsafe {
            assert_eq!(wcswidth(w("AB").as_ptr(), 5), 2);
            assert_eq!(wcswidth(w("").as_ptr(), 5), 0);
            // n cap counts at most n chars.
            assert_eq!(wcswidth(w("ABC").as_ptr(), 2), 2);
            // A control char propagates -1.
            let mut bad = w("AB");
            bad[1] = 0x1b;
            assert_eq!(wcswidth(bad.as_ptr(), 5), -1);
            // NUL stops the sum, no error.
            assert_eq!(wcswidth(w("AB").as_ptr(), 99), 2);
        }
    }
}
