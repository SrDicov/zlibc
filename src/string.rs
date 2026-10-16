//! Byte strings (musl `src/string/*`, `src/locale/strcoll.c`,
//! `src/locale/strxfrm.c`, `src/errno/strerror.c`, `src/misc/ffs.c`).
//!
//! Clean reimplementation — zero copied musl code. Behavior mirrors the
//! musl originals (same signatures, same return contracts), but every
//! body is a plain byte loop (musl's word-at-a-time fast paths omitted).
//!
//! C locale only: [`strcoll`] is `strcmp`, [`strxfrm`] is a bounded copy
//! (musl `src/locale/strcoll.c`, `strxfrm.c` do the same in the C locale).
//!
//! shortcut: byte-at-a-time loops; word-at-a-time like musl when measured.

use core::ffi::{c_char, c_int, c_long, c_longlong, c_void};
use core::ptr::{addr_of_mut, null_mut};

/// Length to the terminator (private [`crate::mem::strlen`] twin: local so
/// this module links the same with or without `mem`).
///
/// # Safety
///
/// `s` must point at a valid NUL-terminated string.
unsafe fn raw_len(s: *const c_char) -> usize {
    unsafe {
        let mut n = 0usize;
        while *s.add(n) != 0 {
            n = n.wrapping_add(1);
        }
        n
    }
}

/// Bounded length: `min(strlen(s), n)` (musl `strnlen`).
///
/// # Safety
///
/// `s` must be readable for `n` bytes or up to its terminator.
unsafe fn raw_nlen(s: *const c_char, n: usize) -> usize {
    unsafe {
        let mut i = 0usize;
        while i < n && *s.add(i) != 0 {
            i = i.wrapping_add(1);
        }
        i
    }
}

/// First `c` or the terminator, whichever comes first (musl `__strchrnul`).
///
/// # Safety
///
/// `s` must point at a valid NUL-terminated string.
unsafe fn raw_chrnul(s: *const c_char, c: u8) -> *mut c_char {
    unsafe {
        let mut p = s;
        while *p != 0 && *p as u8 != c {
            p = p.add(1);
        }
        p as *mut c_char
    }
}

/// Forward byte copy (private [`crate::mem::memcpy`] twin; overlap is UB).
///
/// # Safety
///
/// `[d, d+n)` writable, `[s, s+n)` readable, ranges disjoint.
unsafe fn copy_fwd(d: *mut u8, s: *const u8, n: usize) {
    unsafe {
        let mut i = 0usize;
        while i < n {
            *d.add(i) = *s.add(i);
            i = i.wrapping_add(1);
        }
    }
}

/// C-locale case fold (musl `strcasecmp.c` goes through `tolower`; in the
/// C locale that is exactly this ASCII map).
fn low(b: u8) -> u8 {
    if b.is_ascii_uppercase() {
        b.wrapping_add(32)
    } else {
        b
    }
}

/// ASCII digit test (musl `strverscmp.c` uses `isdigit`; C locale).
fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}

/// Span length: bytes of `s` all present in `acc` (musl `strspn` shape).
///
/// # Safety
///
/// Both must point at valid NUL-terminated strings.
unsafe fn raw_spn(s: *const c_char, acc: *const c_char) -> usize {
    // ponytail: O(n*m) scan; 256-bit table like musl if measured.
    unsafe {
        let mut n = 0usize;
        while *s.add(n) != 0 {
            let b = *s.add(n);
            let mut c = acc;
            let mut ok = false;
            while *c != 0 {
                if *c == b {
                    ok = true;
                    break;
                }
                c = c.add(1);
            }
            if !ok {
                break;
            }
            n = n.wrapping_add(1);
        }
        n
    }
}

/// Complement span: bytes of `s` before any byte of `rej` (musl `strcspn`).
///
/// # Safety
///
/// Both must point at valid NUL-terminated strings.
unsafe fn raw_cspn(s: *const c_char, rej: *const c_char) -> usize {
    // ponytail: O(n*m) scan; 256-bit table like musl if measured.
    unsafe {
        let mut n = 0usize;
        while *s.add(n) != 0 {
            let b = *s.add(n);
            let mut c = rej;
            while *c != 0 {
                if *c == b {
                    return n;
                }
                c = c.add(1);
            }
            n = n.wrapping_add(1);
        }
        n
    }
}

/// musl `strncpy` (`src/string/strncpy.c`): copy at most `n`, NUL-pad the
/// rest, return `d`.
///
/// # Safety
///
/// `d` writable for `n` bytes; `s` a valid string; ranges must not overlap.
#[no_mangle]
pub unsafe extern "C" fn strncpy(d: *mut c_char, s: *const c_char, n: usize) -> *mut c_char {
    unsafe {
        stpncpy(d, s, n);
    }
    d
}

/// musl `strcpy` (`src/string/strcpy.c`): copy incl. NUL, return `dest`.
///
/// # Safety
///
/// `dest` must fit `strlen(src)+1` bytes; ranges must not overlap.
#[no_mangle]
pub unsafe extern "C" fn strcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    unsafe {
        stpcpy(dest, src);
        dest
    }
}

/// musl `strchrnul` (`src/string/strchrnul.c`): like `strchr`, but a
/// miss returns the terminator instead of null.
///
/// # Safety
///
/// `s` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn strchrnul(s: *const c_char, c: c_int) -> *mut c_char {
    unsafe { raw_chrnul(s, c as u8) }
}

/// musl `strnlen` (`src/string/strnlen.c`): bounded `strlen`, capped at
/// `n`.
///
/// # Safety
///
/// `s` must be readable for `min(strlen, n)+1` bytes.
#[no_mangle]
pub unsafe extern "C" fn strnlen(s: *const c_char, n: usize) -> usize {
    unsafe { raw_nlen(s, n) }
}

/// musl `stpcpy` (`src/string/stpcpy.c`): copy incl. NUL, return pointer
/// to the written terminator.
///
/// # Safety
///
/// `d` must fit `strlen(s)+1` bytes; `s` valid; ranges must not overlap.
#[no_mangle]
pub unsafe extern "C" fn stpcpy(d: *mut c_char, s: *const c_char) -> *mut c_char {
    unsafe {
        let mut dd = d;
        let mut ss = s;
        while *ss != 0 {
            *dd = *ss;
            dd = dd.add(1);
            ss = ss.add(1);
        }
        *dd = 0;
        dd
    }
}

/// musl `stpncpy` (`src/string/stpncpy.c`): copy at most `n`, NUL-pad the
/// rest, return `d` advanced past the copied (non-pad) bytes.
///
/// # Safety
///
/// Same as [`strncpy`].
#[no_mangle]
pub unsafe extern "C" fn stpncpy(d: *mut c_char, s: *const c_char, n: usize) -> *mut c_char {
    unsafe {
        let mut dd = d;
        let mut ss = s;
        let mut left = n;
        while left != 0 && *ss != 0 {
            *dd = *ss;
            dd = dd.add(1);
            ss = ss.add(1);
            left -= 1;
        }
        // Pad in place: musl's memset(d, 0, n) leaves d stationary, so
        // the return stays past the last copied byte, not past the pad.
        let mut q = dd;
        while left != 0 {
            *q = 0;
            q = q.add(1);
            left -= 1;
        }
        dd
    }
}

/// musl `strcat` (`src/string/strcat.c`): append `src`, return `dest`.
///
/// # Safety
///
/// `dest` must fit `strlen(dest)+strlen(src)+1`; ranges must not overlap.
#[no_mangle]
pub unsafe extern "C" fn strcat(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    unsafe {
        stpcpy(dest.add(raw_len(dest)), src);
    }
    dest
}

/// musl `strncat` (`src/string/strncat.c`): append at most `n` bytes plus
/// a terminator (the terminator is written even when `n == 0`).
///
/// # Safety
///
/// `dest` must fit `strlen(dest)+min(n,strlen(src))+1`; no overlap.
#[no_mangle]
pub unsafe extern "C" fn strncat(d: *mut c_char, s: *const c_char, n: usize) -> *mut c_char {
    unsafe {
        let mut dd = d.add(raw_len(d));
        let mut ss = s;
        let mut left = n;
        while left != 0 && *ss != 0 {
            *dd = *ss;
            dd = dd.add(1);
            ss = ss.add(1);
            left -= 1;
        }
        *dd = 0;
    }
    d
}

/// musl `strlcpy`: copy up to `n-1` bytes plus NUL (untouched when
/// `n == 0`); returns `strlen(s)` regardless of truncation.
///
/// # Safety
///
/// `d` writable for `min(n, strlen(s)+1)` bytes (`n == 0` needs nothing);
/// `s` a valid string.
#[no_mangle]
pub unsafe extern "C" fn strlcpy(d: *mut c_char, s: *const c_char, n: usize) -> usize {
    unsafe {
        let slen = raw_len(s);
        if n != 0 {
            let take = raw_nlen(s, n.wrapping_sub(1));
            copy_fwd(d as *mut u8, s as *const u8, take);
            *d.add(take) = 0;
        }
        slen
    }
}

/// musl `strlcat`: append bounded by `n` total (`strnlen(d, n)` prefix);
/// returns `l + strlen(s)` where `l` is the clamped prefix length.
///
/// # Safety
///
/// `d` must be readable for `min(n, strlen(d)+1)` bytes and writable for
/// what gets appended; `s` a valid string.
#[no_mangle]
pub unsafe extern "C" fn strlcat(d: *mut c_char, s: *const c_char, n: usize) -> usize {
    unsafe {
        let l = raw_nlen(d, n);
        if l == n {
            return n.wrapping_add(raw_len(s));
        }
        l.wrapping_add(strlcpy(d.add(l), s, n.wrapping_sub(l)))
    }
}

/// musl `strcmp` (`src/string/strcmp.c`): unsigned-byte ordering.
///
/// # Safety
///
/// Both must point at valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn strcmp(l: *const c_char, r: *const c_char) -> c_int {
    unsafe {
        let mut a = l as *const u8;
        let mut b = r as *const u8;
        while *a == *b && *a != 0 {
            a = a.add(1);
            b = b.add(1);
        }
        (*a as c_int) - (*b as c_int)
    }
}

/// musl `strncmp` (`src/string/strncmp.c`): at most `n` bytes; `n == 0`
/// compares nothing and returns 0.
///
/// # Safety
///
/// Both readable for `n` bytes or up to their terminators.
#[no_mangle]
pub unsafe extern "C" fn strncmp(l: *const c_char, r: *const c_char, n: usize) -> c_int {
    unsafe {
        if n == 0 {
            return 0;
        }
        let mut a = l as *const u8;
        let mut b = r as *const u8;
        let mut left = n.wrapping_sub(1);
        while *a != 0 && *b != 0 && left != 0 && *a == *b {
            a = a.add(1);
            b = b.add(1);
            left -= 1;
        }
        (*a as c_int) - (*b as c_int)
    }
}

/// musl `strcasecmp`: ASCII case-insensitive `strcmp` (C locale).
///
/// # Safety
///
/// Both must point at valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn strcasecmp(l: *const c_char, r: *const c_char) -> c_int {
    unsafe {
        let mut a = l as *const u8;
        let mut b = r as *const u8;
        while *a != 0 && *b != 0 && (*a == *b || low(*a) == low(*b)) {
            a = a.add(1);
            b = b.add(1);
        }
        (low(*a) as c_int) - (low(*b) as c_int)
    }
}

/// musl `strncasecmp`: bounded ASCII case-insensitive compare.
///
/// # Safety
///
/// Both readable for `n` bytes or up to their terminators.
#[no_mangle]
pub unsafe extern "C" fn strncasecmp(l: *const c_char, r: *const c_char, n: usize) -> c_int {
    unsafe {
        if n == 0 {
            return 0;
        }
        let mut a = l as *const u8;
        let mut b = r as *const u8;
        let mut left = n.wrapping_sub(1);
        while *a != 0 && *b != 0 && left != 0 && (*a == *b || low(*a) == low(*b)) {
            a = a.add(1);
            b = b.add(1);
            left -= 1;
        }
        (low(*a) as c_int) - (low(*b) as c_int)
    }
}

/// C locale collation is code-point order: exactly `strcmp`
/// (musl `src/locale/strcoll.c` does the same).
///
/// # Safety
///
/// Both must point at valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn strcoll(l: *const c_char, r: *const c_char) -> c_int {
    unsafe { strcmp(l, r) }
}

/// C locale transform is the identity copy: `strlen` bytes (musl
/// `src/locale/strxfrm.c` does the same).
///
/// # Safety
///
/// `src` valid; `dest` writable for `min(n, strlen(src)+1)` (`n == 0`
/// writes nothing, so `dest` may be null then).
#[no_mangle]
pub unsafe extern "C" fn strxfrm(dest: *mut c_char, src: *const c_char, n: usize) -> usize {
    unsafe {
        let l = raw_len(src);
        if n > l {
            copy_fwd(dest as *mut u8, src as *const u8, l.wrapping_add(1));
        }
        l
    }
}

/// musl `strchr` (`src/string/strchr.c`): first `c` (as `unsigned char`),
/// including a match on the terminator; null when absent.
///
/// # Safety
///
/// `s` must point at a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn strchr(s: *const c_char, c: c_int) -> *mut c_char {
    unsafe {
        let r = raw_chrnul(s, c as u8);
        if *r as u8 == c as u8 {
            r
        } else {
            null_mut()
        }
    }
}

/// musl `strrchr` (`src/string/strrchr.c` = `__memrchr(s, c, len+1)`):
/// last `c`, terminator included; null when absent.
///
/// # Safety
///
/// `s` must point at a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn strrchr(s: *const c_char, c: c_int) -> *mut c_char {
    unsafe {
        let n = raw_len(s).wrapping_add(1);
        let mut i = n;
        while i > 0 {
            i -= 1;
            if *s.add(i) as u8 == c as u8 {
                return s.add(i) as *mut c_char;
            }
        }
        null_mut()
    }
}

/// `strstr`: first occurrence of `n` in `h`; `h` when `n` is empty, null
/// when absent. Naive scan with musl-identical edge contracts (musl's
/// two-way fast path omitted).
///
/// # Safety
///
/// Both must point at valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn strstr(h: *const c_char, n: *const c_char) -> *mut c_char {
    // ponytail: naive O(n*m); two-way like musl if measured.
    unsafe {
        if *n == 0 {
            return h as *mut c_char;
        }
        let mut hh = h;
        while *hh != 0 {
            if *hh == *n {
                let mut a = hh;
                let mut b = n;
                while *b != 0 && *a == *b {
                    a = a.add(1);
                    b = b.add(1);
                }
                if *b == 0 {
                    return hh as *mut c_char;
                }
            }
            hh = hh.add(1);
        }
        null_mut()
    }
}

/// musl `strcasestr`: `strstr` with ASCII case folding; `h` when `n` is
/// empty, null when absent.
///
/// # Safety
///
/// Both must point at valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn strcasestr(h: *const c_char, n: *const c_char) -> *mut c_char {
    // ponytail: naive O(n*m) like strstr above.
    unsafe {
        let l = raw_len(n);
        if l == 0 {
            return h as *mut c_char;
        }
        let mut hh = h;
        while *hh != 0 {
            let mut i = 0usize;
            while i < l {
                let a = *hh.add(i);
                if a == 0 || low(a as u8) != low(*n.add(i) as u8) {
                    break;
                }
                i = i.wrapping_add(1);
            }
            if i == l {
                return hh as *mut c_char;
            }
            hh = hh.add(1);
        }
        null_mut()
    }
}

/// musl `strpbrk` (`src/string/strpbrk.c`): first byte of `s` present in
/// `b`; null when none.
///
/// # Safety
///
/// Both must point at valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn strpbrk(s: *const c_char, b: *const c_char) -> *mut c_char {
    unsafe {
        let hit = s.add(raw_cspn(s, b));
        if *hit != 0 {
            hit as *mut c_char
        } else {
            null_mut()
        }
    }
}

/// musl `strspn`: length of the leading run of bytes present in `c`
/// (0 when `c` is empty).
///
/// # Safety
///
/// Both must point at valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn strspn(s: *const c_char, c: *const c_char) -> usize {
    unsafe { raw_spn(s, c) }
}

/// musl `strcspn`: length of the leading run of bytes absent from `c`
/// (`strlen(s)` when `c` is empty).
///
/// # Safety
///
/// Both must point at valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn strcspn(s: *const c_char, c: *const c_char) -> usize {
    unsafe { raw_cspn(s, c) }
}

/// Saved position for [`strtok`] (musl `strtok.c` keeps the same static
/// internal pointer; plain `.bss`, no alias).
static mut STRTOK_S: *mut c_char = null_mut();

/// musl `strtok` (`src/string/strtok.c`): non-reentrant tokenizer over the
/// static position above; null `s` continues, null return ends the run.
///
/// # Safety
///
/// Non-null `s` must be a writable string; `sep` a valid string. Not
/// thread-safe (same as musl).
#[no_mangle]
pub unsafe extern "C" fn strtok(s: *mut c_char, sep: *const c_char) -> *mut c_char {
    unsafe {
        let mut cur = if s.is_null() {
            addr_of_mut!(STRTOK_S).read()
        } else {
            s
        };
        if cur.is_null() {
            return null_mut();
        }
        cur = cur.add(raw_spn(cur, sep));
        if *cur == 0 {
            addr_of_mut!(STRTOK_S).write(null_mut());
            return null_mut();
        }
        let end = cur.add(raw_cspn(cur, sep));
        if *end != 0 {
            *end = 0;
            addr_of_mut!(STRTOK_S).write(end.add(1));
        } else {
            addr_of_mut!(STRTOK_S).write(null_mut());
        }
        cur
    }
}

/// musl `strtok_r` (`src/string/strtok_r.c`): reentrant twin; caller
/// state lives in `*p`.
///
/// # Safety
///
/// Same string validity as [`strtok`]; `p` must be a writable pointer.
#[no_mangle]
pub unsafe extern "C" fn strtok_r(
    s: *mut c_char,
    sep: *const c_char,
    p: *mut *mut c_char,
) -> *mut c_char {
    unsafe {
        let mut cur = if s.is_null() { *p } else { s };
        if cur.is_null() {
            return null_mut();
        }
        cur = cur.add(raw_spn(cur, sep));
        if *cur == 0 {
            *p = null_mut();
            return null_mut();
        }
        let end = cur.add(raw_cspn(cur, sep));
        if *end != 0 {
            *end = 0;
            *p = end.add(1);
        } else {
            *p = null_mut();
        }
        cur
    }
}

/// musl `strsep`: next chunk up to `sep` (empty chunks kept, unlike
/// [`strtok`]); `*str` advances past the separator or becomes null; null
/// when `*str` is already null.
///
/// # Safety
///
/// `str` must be a writable pointer holding null or a writable string;
/// `sep` a valid string.
#[no_mangle]
pub unsafe extern "C" fn strsep(str: *mut *mut c_char, sep: *const c_char) -> *mut c_char {
    unsafe {
        let s = *str;
        if s.is_null() {
            return null_mut();
        }
        let end = s.add(raw_cspn(s, sep));
        if *end != 0 {
            *end = 0;
            *str = end.add(1);
        } else {
            *str = null_mut();
        }
        s
    }
}

/// musl `strdup`: fresh copy via [`crate::malloc::malloc`]; null with
/// `ENOMEM` when allocation fails.
///
/// # Safety
///
/// `s` must point at a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn strdup(s: *const c_char) -> *mut c_char {
    unsafe {
        let l = raw_len(s);
        let d = crate::malloc::malloc(l.wrapping_add(1)) as *mut u8;
        if d.is_null() {
            return null_mut();
        }
        copy_fwd(d, s as *const u8, l.wrapping_add(1));
        d as *mut c_char
    }
}

/// musl `strndup`: copy of at most `n` bytes plus NUL; same alloc contract
/// as [`strdup`].
///
/// # Safety
///
/// `s` readable for `n` bytes or up to its terminator.
#[no_mangle]
pub unsafe extern "C" fn strndup(s: *const c_char, n: usize) -> *mut c_char {
    unsafe {
        let l = raw_nlen(s, n);
        let d = crate::malloc::malloc(l.wrapping_add(1)) as *mut u8;
        if d.is_null() {
            return null_mut();
        }
        copy_fwd(d, s as *const u8, l);
        *d.add(l) = 0;
        d as *mut c_char
    }
}

/// musl `memchr` (`src/string/memchr.c` shape, byte loop): first `c`
/// (as `unsigned char`) in `n` bytes; null when absent.
///
/// # Safety
///
/// `src` readable for `n` bytes.
#[no_mangle]
pub unsafe extern "C" fn memchr(src: *const c_void, c: c_int, n: usize) -> *mut c_void {
    unsafe {
        let s = src as *const u8;
        let mut i = 0usize;
        while i < n {
            if *s.add(i) == c as u8 {
                return s.add(i) as *mut c_void;
            }
            i = i.wrapping_add(1);
        }
        null_mut()
    }
}

/// musl `memrchr`: last `c` in `n` bytes; null when absent.
///
/// # Safety
///
/// `m` readable for `n` bytes.
#[no_mangle]
pub unsafe extern "C" fn memrchr(m: *const c_void, c: c_int, n: usize) -> *mut c_void {
    unsafe {
        let s = m as *const u8;
        let mut i = n;
        while i > 0 {
            i -= 1;
            if *s.add(i) == c as u8 {
                return s.add(i) as *mut c_void;
            }
        }
        null_mut()
    }
}

/// `memmem`: first occurrence of `n0[..l]` in `h0[..k]`; `h0` when `l` is
/// 0, null when absent or `k < l`. Naive scan, same contracts as musl.
///
/// # Safety
///
/// `h0` readable for `k` bytes, `n0` for `l` bytes.
#[no_mangle]
pub unsafe extern "C" fn memmem(
    h0: *const c_void,
    k: usize,
    n0: *const c_void,
    l: usize,
) -> *mut c_void {
    // ponytail: naive O(k*l); two-way like musl if measured.
    unsafe {
        let h = h0 as *const u8;
        let n = n0 as *const u8;
        if l == 0 {
            return h0 as *mut c_void;
        }
        if k < l {
            return null_mut();
        }
        let mut i = 0usize;
        while i <= k.wrapping_sub(l) {
            let mut j = 0usize;
            while j < l && *h.add(i.wrapping_add(j)) == *n.add(j) {
                j = j.wrapping_add(1);
            }
            if j == l {
                return h.add(i) as *mut c_void;
            }
            i = i.wrapping_add(1);
        }
        null_mut()
    }
}

/// musl `memccpy`: copy until `c` (inclusive) or `n` bytes; returns the
/// destination pointer just past the copied `c`, null when `c` never hit.
///
/// # Safety
///
/// `dest` writable for `n` bytes, `src` readable for the bytes actually
/// copied; ranges must not overlap.
#[no_mangle]
pub unsafe extern "C" fn memccpy(
    dest: *mut c_void,
    src: *const c_void,
    c: c_int,
    n: usize,
) -> *mut c_void {
    unsafe {
        let mut d = dest as *mut u8;
        let mut s = src as *const u8;
        let mut left = n;
        while left != 0 {
            *d = *s;
            let hit = *s == c as u8;
            d = d.add(1);
            s = s.add(1);
            left -= 1;
            if hit {
                return d as *mut c_void;
            }
        }
        null_mut()
    }
}

/// musl `mempcpy`: `memcpy` returning `dest + n`.
///
/// # Safety
///
/// Same as `memcpy`: `n` readable/writable bytes, ranges disjoint.
#[no_mangle]
pub unsafe extern "C" fn mempcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    unsafe {
        copy_fwd(dest as *mut u8, src as *const u8, n);
        (dest as *mut u8).add(n) as *mut c_void
    }
}

/// musl `bzero` (`src/string/bzero.c`): `memset(s, 0, n)`.
///
/// # Safety
///
/// `s` writable for `n` bytes.
#[no_mangle]
pub unsafe extern "C" fn bzero(s: *mut c_void, n: usize) {
    unsafe {
        crate::mem::memset(s, 0, n);
    }
}

/// musl `explicit_bzero`: zero through `volatile` writes plus a compiler
/// barrier so the stores are never optimized away.
///
/// # Safety
///
/// `d` writable for `n` bytes.
#[no_mangle]
pub unsafe extern "C" fn explicit_bzero(d: *mut c_void, n: usize) {
    unsafe {
        let mut p = d as *mut u8;
        let mut left = n;
        while left != 0 {
            core::ptr::write_volatile(p, 0);
            p = p.add(1);
            left -= 1;
        }
        core::hint::black_box(d);
    }
}

/// musl `ffs` (`src/misc/ffs.c`): 1-based position of the lowest set bit;
/// `ffs(0) == 0`.
/// Find first set bit, 1-based, 0 for zero input (musl `ffs`).
///
/// # Safety
///
/// Pure function of its argument.
#[no_mangle]
pub unsafe extern "C" fn ffs(i: c_int) -> c_int {
    if i == 0 {
        0
    } else {
        (i.trailing_zeros() as c_int).wrapping_add(1)
    }
}

/// musl `ffsl`: [`ffs`] over `long`.
/// `ffs` for `long` (musl `ffsl`).
///
/// # Safety
///
/// Pure function of its argument.
#[no_mangle]
pub unsafe extern "C" fn ffsl(i: c_long) -> c_int {
    if i == 0 {
        0
    } else {
        (i.trailing_zeros() as c_int).wrapping_add(1)
    }
}

/// musl `ffsll`: [`ffs`] over `long long`.
/// `ffs` for `long long` (musl `ffsll`).
///
/// # Safety
///
/// Pure function of its argument.
#[no_mangle]
pub unsafe extern "C" fn ffsll(i: c_longlong) -> c_int {
    if i == 0 {
        0
    } else {
        (i.trailing_zeros() as c_int).wrapping_add(1)
    }
}

/// musl `strverscmp`: version-aware ordering (longest non-degenerate digit
/// run wins; all-zero digit prefixes sort below non-digits).
///
/// # Safety
///
/// Both must point at valid NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn strverscmp(l0: *const c_char, r0: *const c_char) -> c_int {
    unsafe {
        let l = l0 as *const u8;
        let r = r0 as *const u8;
        let mut i = 0usize;
        let mut dp = 0usize;
        let mut z = true;
        while *l.add(i) == *r.add(i) {
            let c = *l.add(i);
            if c == 0 {
                return 0;
            }
            if !is_digit(c) {
                dp = i.wrapping_add(1);
                z = true;
            } else if c != b'0' {
                z = false;
            }
            i = i.wrapping_add(1);
        }
        if (*l.add(dp)).wrapping_sub(b'1') < 9 && (*r.add(dp)).wrapping_sub(b'1') < 9 {
            let mut j = i;
            while is_digit(*l.add(j)) {
                if !is_digit(*r.add(j)) {
                    return 1;
                }
                j = j.wrapping_add(1);
            }
            if is_digit(*r.add(j)) {
                return -1;
            }
        } else if z && dp < i && (is_digit(*l.add(i)) || is_digit(*r.add(i))) {
            return ((*l.add(i)).wrapping_sub(b'0') as c_int)
                .wrapping_sub((*r.add(i)).wrapping_sub(b'0') as c_int);
        }
        (*l.add(i) as c_int) - (*r.add(i) as c_int)
    }
}

/// musl `strerror` message table: strings copied VERBATIM from
/// `src/errno/__strerror.h` (data, not logic). Lookup mirrors musl's
/// `errmsgidx` table: any code without a listed message — including
/// negative and out-of-range codes (musl reads out of bounds there; we
/// return the catch-all instead) — yields entry 0, "No error information".
fn errmsg(e: c_int) -> *const c_char {
    match e {
        1 => c"Operation not permitted".as_ptr(),
        2 => c"No such file or directory".as_ptr(),
        3 => c"No such process".as_ptr(),
        4 => c"Interrupted system call".as_ptr(),
        5 => c"I/O error".as_ptr(),
        6 => c"No such device or address".as_ptr(),
        7 => c"Argument list too long".as_ptr(),
        8 => c"Exec format error".as_ptr(),
        9 => c"Bad file descriptor".as_ptr(),
        10 => c"No child process".as_ptr(),
        11 => c"Resource temporarily unavailable".as_ptr(),
        12 => c"Out of memory".as_ptr(),
        13 => c"Permission denied".as_ptr(),
        14 => c"Bad address".as_ptr(),
        15 => c"Block device required".as_ptr(),
        16 => c"Resource busy".as_ptr(),
        17 => c"File exists".as_ptr(),
        18 => c"Cross-device link".as_ptr(),
        19 => c"No such device".as_ptr(),
        20 => c"Not a directory".as_ptr(),
        21 => c"Is a directory".as_ptr(),
        22 => c"Invalid argument".as_ptr(),
        23 => c"Too many open files in system".as_ptr(),
        24 => c"No file descriptors available".as_ptr(),
        25 => c"Not a tty".as_ptr(),
        26 => c"Text file busy".as_ptr(),
        27 => c"File too large".as_ptr(),
        28 => c"No space left on device".as_ptr(),
        29 => c"Invalid seek".as_ptr(),
        30 => c"Read-only file system".as_ptr(),
        31 => c"Too many links".as_ptr(),
        32 => c"Broken pipe".as_ptr(),
        33 => c"Domain error".as_ptr(),
        34 => c"Result not representable".as_ptr(),
        35 => c"Resource deadlock would occur".as_ptr(),
        36 => c"Filename too long".as_ptr(),
        37 => c"No locks available".as_ptr(),
        38 => c"Function not implemented".as_ptr(),
        39 => c"Directory not empty".as_ptr(),
        40 => c"Symbolic link loop".as_ptr(),
        42 => c"No message of desired type".as_ptr(),
        43 => c"Identifier removed".as_ptr(),
        60 => c"Device not a stream".as_ptr(),
        61 => c"No data available".as_ptr(),
        62 => c"Device timeout".as_ptr(),
        63 => c"Out of streams resources".as_ptr(),
        67 => c"Link has been severed".as_ptr(),
        71 => c"Protocol error".as_ptr(),
        72 => c"Multihop attempted".as_ptr(),
        74 => c"Bad message".as_ptr(),
        75 => c"Value too large for data type".as_ptr(),
        77 => c"File descriptor in bad state".as_ptr(),
        84 => c"Illegal byte sequence".as_ptr(),
        88 => c"Not a socket".as_ptr(),
        89 => c"Destination address required".as_ptr(),
        90 => c"Message too large".as_ptr(),
        91 => c"Protocol wrong type for socket".as_ptr(),
        92 => c"Protocol not available".as_ptr(),
        93 => c"Protocol not supported".as_ptr(),
        94 => c"Socket type not supported".as_ptr(),
        95 => c"Not supported".as_ptr(),
        96 => c"Protocol family not supported".as_ptr(),
        97 => c"Address family not supported by protocol".as_ptr(),
        98 => c"Address in use".as_ptr(),
        99 => c"Address not available".as_ptr(),
        100 => c"Network is down".as_ptr(),
        101 => c"Network unreachable".as_ptr(),
        102 => c"Connection reset by network".as_ptr(),
        103 => c"Connection aborted".as_ptr(),
        104 => c"Connection reset by peer".as_ptr(),
        105 => c"No buffer space available".as_ptr(),
        106 => c"Socket is connected".as_ptr(),
        107 => c"Socket not connected".as_ptr(),
        108 => c"Cannot send after socket shutdown".as_ptr(),
        110 => c"Operation timed out".as_ptr(),
        111 => c"Connection refused".as_ptr(),
        112 => c"Host is down".as_ptr(),
        113 => c"Host is unreachable".as_ptr(),
        114 => c"Operation already in progress".as_ptr(),
        115 => c"Operation in progress".as_ptr(),
        116 => c"Stale file handle".as_ptr(),
        117 => c"Data consistency error".as_ptr(),
        119 => c"Resource not available".as_ptr(),
        121 => c"Remote I/O error".as_ptr(),
        122 => c"Quota exceeded".as_ptr(),
        123 => c"No medium found".as_ptr(),
        124 => c"Wrong medium type".as_ptr(),
        125 => c"Operation canceled".as_ptr(),
        126 => c"Required key not available".as_ptr(),
        127 => c"Key has expired".as_ptr(),
        128 => c"Key has been revoked".as_ptr(),
        129 => c"Key was rejected by service".as_ptr(),
        130 => c"Previous owner died".as_ptr(),
        131 => c"State not recoverable".as_ptr(),
        _ => c"No error information".as_ptr(),
    }
}

/// musl `strerror` (`src/errno/strerror.c`): static message for `e`,
/// never null.
/// Error string for `e` (musl `strerror`).
///
/// # Safety
///
/// Returns a pointer to static read-only storage; never null.
#[no_mangle]
pub unsafe extern "C" fn strerror(e: c_int) -> *mut c_char {
    errmsg(e) as *mut c_char
}

/// musl `strerror_r` (`src/string/strerror_r.c`, the single int-returning
/// XSI form): copies into `buf`, `ERANGE` (34) on truncation (partial
/// copy + NUL when `buflen > 0`), 0 on success. Unknown codes stringify
/// via [`strerror`], never `EINVAL`.
///
/// # Safety
///
/// `buf` writable for `buflen` bytes.
#[no_mangle]
pub unsafe extern "C" fn strerror_r(err: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    unsafe {
        let msg = strerror(err);
        let l = raw_len(msg);
        if l >= buflen {
            if buflen != 0 {
                copy_fwd(buf as *mut u8, msg as *const u8, buflen.wrapping_sub(1));
                *buf.add(buflen.wrapping_sub(1)) = 0;
            }
            return 34;
        }
        copy_fwd(buf as *mut u8, msg as *const u8, l.wrapping_add(1));
        0
    }
}

/// musl `strsignal` string blob: copied VERBATIM from
/// `src/string/strsignal.c` (x86_64 hits the `sigmap(x) == x` fast path,
/// `_NSIG == 65`, `SIGSTKFLT` present). Entry 0 is "Unknown signal".
const SIGSTR: &[u8] = b"Unknown signal\0Hangup\0Interrupt\0Quit\0Illegal instruction\0Trace/breakpoint trap\0Aborted\0Bus error\0Arithmetic exception\0Killed\0User defined signal 1\0Segmentation fault\0User defined signal 2\0Broken pipe\0Alarm clock\0Terminated\0Stack fault\0Child process status\0Continued\0Stopped (signal)\0Stopped\0Stopped (tty input)\0Stopped (tty output)\0Urgent I/O condition\0CPU time limit exceeded\0File size limit exceeded\0Virtual timer expired\0Profiling timer expired\0Window changed\0I/O possible\0Power failure\0Bad system call\0RT32\0RT33\0RT34\0RT35\0RT36\0RT37\0RT38\0RT39\0RT40\0RT41\0RT42\0RT43\0RT44\0RT45\0RT46\0RT47\0RT48\0RT49\0RT50\0RT51\0RT52\0RT53\0RT54\0RT55\0RT56\0RT57\0RT58\0RT59\0RT60\0RT61\0RT62\0RT63\0RT64\0";

/// musl `strsignal`: static description for `signum` (1..=64); anything
/// else yields "Unknown signal". Same walk as musl's `for (; signum--; …)`.
/// Signal description for `signum` (musl `strsignal`).
///
/// # Safety
///
/// Returns a pointer to static read-only storage; never null.
#[no_mangle]
pub unsafe extern "C" fn strsignal(signum: c_int) -> *mut c_char {
    unsafe {
        let mut i = if (1..=64).contains(&signum) {
            signum
        } else {
            0
        };
        let mut s = SIGSTR.as_ptr();
        while i > 0 {
            while *s != 0 {
                s = s.add(1);
            }
            s = s.add(1);
            i -= 1;
        }
        s as *mut c_char
    }
}

/// musl `swab`: swap each adjacent byte pair; a trailing odd byte is left
/// alone.
///
/// # Safety
///
/// `src` readable and `dest` writable for `n` bytes when `n > 0` (nothing
/// is touched when `n <= 1`).
#[no_mangle]
pub unsafe extern "C" fn swab(src: *const c_void, dest: *mut c_void, n: isize) {
    unsafe {
        let mut s = src as *const u8;
        let mut d = dest as *mut u8;
        let mut left = n;
        while left > 1 {
            let a = *s;
            let b = *s.add(1);
            *d = b;
            *d.add(1) = a;
            s = s.add(2);
            d = d.add(2);
            left -= 2;
        }
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::{c_char, c_void};
    use core::ptr::null_mut;

    unsafe fn bytes(p: *const c_char) -> &'static [u8] {
        unsafe { core::ffi::CStr::from_ptr(p).to_bytes() }
    }

    #[test]
    fn strncpy_pads_and_truncates() {
        unsafe {
            let mut d = [0x7fu8; 8];
            let r = crate::string::strncpy(d.as_mut_ptr() as *mut c_char, c"hi".as_ptr(), 8);
            assert_eq!(r as usize, d.as_mut_ptr() as usize);
            assert_eq!(&d, b"hi\0\0\0\0\0\0");
            let mut t = [0u8; 2];
            crate::string::strncpy(t.as_mut_ptr() as *mut c_char, c"hello".as_ptr(), 2);
            assert_eq!(&t, b"he");
        }
    }

    #[test]
    fn stpcpy_returns_terminator() {
        unsafe {
            let mut d = [0u8; 8];
            let r = crate::string::stpcpy(d.as_mut_ptr() as *mut c_char, c"hey".as_ptr());
            assert_eq!(r as usize, d.as_mut_ptr().add(3) as usize);
            assert_eq!(&d[..4], b"hey\0");
            let e = crate::string::stpcpy(d.as_mut_ptr() as *mut c_char, c"".as_ptr());
            assert_eq!(e as usize, d.as_mut_ptr() as usize);
            assert_eq!(d[0], 0);
        }
    }

    #[test]
    fn stpncpy_zero_fill_and_end() {
        unsafe {
            let mut d = [0x7fu8; 8];
            let r = crate::string::stpncpy(d.as_mut_ptr() as *mut c_char, c"hi".as_ptr(), 8);
            assert_eq!(r as usize, d.as_mut_ptr().add(2) as usize);
            assert_eq!(&d, b"hi\0\0\0\0\0\0");
            let mut t = [0u8; 3];
            let r2 = crate::string::stpncpy(t.as_mut_ptr() as *mut c_char, c"hello".as_ptr(), 3);
            assert_eq!(r2 as usize, t.as_mut_ptr().add(3) as usize);
            assert_eq!(&t, b"hel");
            let mut z = [0x7fu8; 4];
            let r3 = crate::string::stpncpy(z.as_mut_ptr() as *mut c_char, c"hi".as_ptr(), 0);
            assert_eq!(r3 as usize, z.as_mut_ptr() as usize);
            assert_eq!(&z, &[0x7f; 4]);
        }
    }

    #[test]
    fn strcat_appends() {
        unsafe {
            let mut d = [0u8; 8];
            d[0] = b'a';
            d[1] = b'b';
            let r = crate::string::strcat(d.as_mut_ptr() as *mut c_char, c"c".as_ptr());
            assert_eq!(r as usize, d.as_mut_ptr() as usize);
            assert_eq!(&d[..4], b"abc\0");
            assert_eq!(bytes(d.as_ptr() as *const c_char), b"abc");
            crate::string::strcat(d.as_mut_ptr() as *mut c_char, c"".as_ptr());
            assert_eq!(bytes(d.as_ptr() as *const c_char), b"abc");
        }
    }

    #[test]
    fn strncat_bounded_and_zero() {
        unsafe {
            let mut d = [0u8; 8];
            d[0] = b'a';
            let r = crate::string::strncat(d.as_mut_ptr() as *mut c_char, c"xyz".as_ptr(), 2);
            assert_eq!(r as usize, d.as_mut_ptr() as usize);
            assert_eq!(bytes(d.as_ptr() as *const c_char), b"axy");
            let mut e = [0u8; 8];
            e[0] = b'a';
            e[1] = b'b';
            crate::string::strncat(e.as_mut_ptr() as *mut c_char, c"xy".as_ptr(), 0);
            assert_eq!(bytes(e.as_ptr() as *const c_char), b"ab");
        }
    }

    #[test]
    fn strlcpy_truncates_but_counts() {
        unsafe {
            let mut d = [0x7fu8; 4];
            let r = crate::string::strlcpy(d.as_mut_ptr() as *mut c_char, c"hello".as_ptr(), 4);
            assert_eq!(r, 5);
            assert_eq!(&d, b"hel\0");
            let mut z = [0x7fu8; 2];
            let r0 = crate::string::strlcpy(z.as_mut_ptr() as *mut c_char, c"hello".as_ptr(), 0);
            assert_eq!(r0, 5);
            assert_eq!(&z, &[0x7f; 2]);
            let mut f = [0u8; 8];
            assert_eq!(
                crate::string::strlcpy(f.as_mut_ptr() as *mut c_char, c"".as_ptr(), 8),
                0
            );
            assert_eq!(f[0], 0);
        }
    }

    #[test]
    fn strlcat_joins_and_reports() {
        unsafe {
            let mut d = [0u8; 8];
            d[0] = b'a';
            d[1] = b'b';
            let r = crate::string::strlcat(d.as_mut_ptr() as *mut c_char, c"cde".as_ptr(), 8);
            assert_eq!(r, 5);
            assert_eq!(bytes(d.as_ptr() as *const c_char), b"abcde");
            let mut f = [0u8; 4];
            f[0] = b'a';
            f[1] = b'b';
            f[2] = b'c';
            f[3] = b'd';
            let rf = crate::string::strlcat(f.as_mut_ptr() as *mut c_char, c"xy".as_ptr(), 4);
            assert_eq!(rf, 6);
        }
    }

    #[test]
    fn strcmp_orders_unsigned() {
        unsafe {
            assert_eq!(crate::string::strcmp(c"".as_ptr(), c"".as_ptr()), 0);
            assert_eq!(crate::string::strcmp(c"abc".as_ptr(), c"abc".as_ptr()), 0);
            assert!(crate::string::strcmp(c"a".as_ptr(), c"ab".as_ptr()) < 0);
            assert!(crate::string::strcmp(c"ab".as_ptr(), c"a".as_ptr()) > 0);
            assert_eq!(crate::string::strcmp(c"abd".as_ptr(), c"abc".as_ptr()), 1);
            let hi = [0xffu8, 0];
            let lo = [0x01u8, 0];
            assert!(
                crate::string::strcmp(hi.as_ptr() as *const c_char, lo.as_ptr() as *const c_char)
                    > 0
            );
        }
    }

    #[test]
    fn strncmp_bounded() {
        unsafe {
            assert_eq!(
                crate::string::strncmp(c"abc".as_ptr(), c"abd".as_ptr(), 2),
                0
            );
            assert!(crate::string::strncmp(c"abc".as_ptr(), c"abd".as_ptr(), 3) < 0);
            assert_eq!(
                crate::string::strncmp(c"abc".as_ptr(), c"xyz".as_ptr(), 0),
                0
            );
            assert_eq!(crate::string::strncmp(c"".as_ptr(), c"".as_ptr(), 5), 0);
        }
    }

    #[test]
    fn strcasecmp_folds_ascii() {
        unsafe {
            assert_eq!(
                crate::string::strcasecmp(c"AbC".as_ptr(), c"abc".as_ptr()),
                0
            );
            assert_eq!(crate::string::strcasecmp(c"".as_ptr(), c"".as_ptr()), 0);
            assert!(crate::string::strcasecmp(c"a".as_ptr(), c"B".as_ptr()) < 0);
            assert!(crate::string::strcasecmp(c"B".as_ptr(), c"a".as_ptr()) > 0);
        }
    }

    #[test]
    fn strncasecmp_bounded_fold() {
        unsafe {
            assert_eq!(
                crate::string::strncasecmp(c"AbX".as_ptr(), c"aby".as_ptr(), 2),
                0
            );
            assert!(crate::string::strncasecmp(c"AbX".as_ptr(), c"aby".as_ptr(), 3) < 0);
            assert_eq!(
                crate::string::strncasecmp(c"a".as_ptr(), c"B".as_ptr(), 0),
                0
            );
        }
    }

    #[test]
    fn strcoll_is_strcmp_in_c_locale() {
        unsafe {
            assert_eq!(
                crate::string::strcoll(c"abc".as_ptr(), c"abd".as_ptr()),
                crate::string::strcmp(c"abc".as_ptr(), c"abd".as_ptr())
            );
            assert_eq!(crate::string::strcoll(c"".as_ptr(), c"".as_ptr()), 0);
        }
    }

    #[test]
    fn strxfrm_copies_identity() {
        unsafe {
            let mut d = [0x7fu8; 8];
            let r = crate::string::strxfrm(d.as_mut_ptr() as *mut c_char, c"hey".as_ptr(), 8);
            assert_eq!(r, 3);
            assert_eq!(&d[..4], b"hey\0");
            let mut z = [0x7fu8; 2];
            let r0 = crate::string::strxfrm(z.as_mut_ptr() as *mut c_char, c"hey".as_ptr(), 0);
            assert_eq!(r0, 3);
            assert_eq!(&z, &[0x7f; 2]);
        }
    }

    #[test]
    fn strchr_hits_and_nul() {
        unsafe {
            let s = c"abca".as_ptr();
            assert_eq!(crate::string::strchr(s, b'a' as i32) as usize, s as usize);
            assert_eq!(
                crate::string::strchr(s, b'c' as i32) as usize,
                s.wrapping_add(2) as usize
            );
            assert_eq!(
                crate::string::strchr(s, 0) as usize,
                s.wrapping_add(4) as usize
            );
            assert!(crate::string::strchr(s, b'z' as i32).is_null());
            assert!(crate::string::strchr(c"".as_ptr(), b'a' as i32).is_null());
            assert_eq!(
                crate::string::strchr(c"".as_ptr(), 0) as usize,
                c"".as_ptr() as usize
            );
        }
    }

    #[test]
    fn strrchr_finds_last() {
        unsafe {
            let s = c"abca".as_ptr();
            assert_eq!(
                crate::string::strrchr(s, b'a' as i32) as usize,
                s.wrapping_add(3) as usize
            );
            assert_eq!(
                crate::string::strrchr(s, 0) as usize,
                s.wrapping_add(4) as usize
            );
            assert!(crate::string::strrchr(s, b'z' as i32).is_null());
        }
    }

    #[test]
    fn strstr_finds_and_edges() {
        unsafe {
            let h = c"xxabcxx".as_ptr();
            assert_eq!(crate::string::strstr(h, c"".as_ptr()) as usize, h as usize);
            assert_eq!(
                crate::string::strstr(h, c"abc".as_ptr()) as usize,
                h.wrapping_add(2) as usize
            );
            assert!(crate::string::strstr(h, c"abcd".as_ptr()).is_null());
            assert!(crate::string::strstr(c"a".as_ptr(), c"aa".as_ptr()).is_null());
            assert_eq!(
                crate::string::strstr(h, c"xxabcxx!".as_ptr()).is_null() as usize,
                1
            );
        }
    }

    #[test]
    fn strcasestr_folds() {
        unsafe {
            let h = c"xxABCxx".as_ptr();
            assert_eq!(
                crate::string::strcasestr(h, c"".as_ptr()) as usize,
                h as usize
            );
            assert_eq!(
                crate::string::strcasestr(h, c"abc".as_ptr()) as usize,
                h.wrapping_add(2) as usize
            );
            assert!(crate::string::strcasestr(h, c"abd".as_ptr()).is_null());
            assert!(crate::string::strcasestr(c"a".as_ptr(), c"aa".as_ptr()).is_null());
        }
    }

    #[test]
    fn strpbrk_set_search() {
        unsafe {
            let s = c"hello".as_ptr();
            assert_eq!(
                crate::string::strpbrk(s, c"lo".as_ptr()) as usize,
                s.wrapping_add(2) as usize
            );
            assert!(crate::string::strpbrk(s, c"z".as_ptr()).is_null());
            assert!(crate::string::strpbrk(s, c"".as_ptr()).is_null());
        }
    }

    #[test]
    fn strspn_prefix_run() {
        unsafe {
            assert_eq!(crate::string::strspn(c"aaab".as_ptr(), c"a".as_ptr()), 3);
            assert_eq!(crate::string::strspn(c"aaab".as_ptr(), c"ab".as_ptr()), 4);
            assert_eq!(crate::string::strspn(c"aaab".as_ptr(), c"".as_ptr()), 0);
            assert_eq!(crate::string::strspn(c"".as_ptr(), c"a".as_ptr()), 0);
        }
    }

    #[test]
    fn strcspn_stop_run() {
        unsafe {
            assert_eq!(crate::string::strcspn(c"aaab".as_ptr(), c"b".as_ptr()), 3);
            assert_eq!(crate::string::strcspn(c"aaab".as_ptr(), c"".as_ptr()), 4);
            assert_eq!(crate::string::strcspn(c"".as_ptr(), c"b".as_ptr()), 0);
            assert_eq!(crate::string::strcspn(c"abc".as_ptr(), c"z".as_ptr()), 3);
        }
    }

    #[test]
    fn strtok_full_sequence() {
        unsafe {
            let mut buf = *b"a,b,,c\0";
            let sep = c",".as_ptr();
            let t1 = crate::string::strtok(buf.as_mut_ptr() as *mut c_char, sep);
            assert_eq!(bytes(t1), b"a");
            let t2 = crate::string::strtok(null_mut(), sep);
            assert_eq!(bytes(t2), b"b");
            let t3 = crate::string::strtok(null_mut(), sep);
            assert_eq!(bytes(t3), b"c");
            assert!(crate::string::strtok(null_mut(), sep).is_null());
            assert!(crate::string::strtok(null_mut(), sep).is_null());
            let mut all = *b",,,\0";
            assert!(crate::string::strtok(all.as_mut_ptr() as *mut c_char, sep).is_null());
        }
    }

    #[test]
    fn strtok_r_interleaved() {
        unsafe {
            let mut a = *b"x:yy\0";
            let mut b = *b"1;22;333\0";
            let mut pa: *mut c_char = null_mut();
            let mut pb: *mut c_char = null_mut();
            let a1 = crate::string::strtok_r(a.as_mut_ptr() as *mut c_char, c":".as_ptr(), &mut pa);
            let b1 = crate::string::strtok_r(b.as_mut_ptr() as *mut c_char, c";".as_ptr(), &mut pb);
            assert_eq!(bytes(a1), b"x");
            assert_eq!(bytes(b1), b"1");
            let a2 = crate::string::strtok_r(null_mut(), c":".as_ptr(), &mut pa);
            let b2 = crate::string::strtok_r(null_mut(), c";".as_ptr(), &mut pb);
            assert_eq!(bytes(a2), b"yy");
            assert_eq!(bytes(b2), b"22");
            assert!(crate::string::strtok_r(null_mut(), c":".as_ptr(), &mut pa).is_null());
            let b3 = crate::string::strtok_r(null_mut(), c";".as_ptr(), &mut pb);
            assert_eq!(bytes(b3), b"333");
            assert!(crate::string::strtok_r(null_mut(), c";".as_ptr(), &mut pb).is_null());
        }
    }

    #[test]
    fn strsep_keeps_empties() {
        unsafe {
            let mut buf = *b"a:b:\0";
            let mut p = buf.as_mut_ptr() as *mut c_char;
            let sep = c":".as_ptr();
            assert_eq!(bytes(crate::string::strsep(&mut p, sep)), b"a");
            assert_eq!(bytes(crate::string::strsep(&mut p, sep)), b"b");
            let e = crate::string::strsep(&mut p, sep);
            assert!(!e.is_null() && bytes(e).is_empty());
            assert!(p.is_null());
            assert!(crate::string::strsep(&mut p, sep).is_null());
            let mut n: *mut c_char = null_mut();
            assert!(crate::string::strsep(&mut n, sep).is_null());
        }
    }

    #[test]
    fn strdup_heap_copy() {
        unsafe {
            let d = crate::string::strdup(c"hello".as_ptr());
            assert!(!d.is_null());
            assert_ne!(d as usize, c"hello".as_ptr() as usize);
            assert_eq!(bytes(d), b"hello");
            crate::malloc::free(d as *mut c_void);
            let e = crate::string::strdup(c"".as_ptr());
            assert!(!e.is_null() && bytes(e).is_empty());
            crate::malloc::free(e as *mut c_void);
        }
    }

    #[test]
    fn strndup_truncates() {
        unsafe {
            let d = crate::string::strndup(c"hello".as_ptr(), 2);
            assert!(!d.is_null());
            assert_eq!(bytes(d), b"he");
            crate::malloc::free(d as *mut c_void);
            let f = crate::string::strndup(c"hi".as_ptr(), 10);
            assert_eq!(bytes(f), b"hi");
            crate::malloc::free(f as *mut c_void);
            let z = crate::string::strndup(c"hello".as_ptr(), 0);
            assert!(!z.is_null() && bytes(z).is_empty());
            crate::malloc::free(z as *mut c_void);
        }
    }

    #[test]
    fn memchr_scans_bytes() {
        unsafe {
            let b = *b"ab\0cd";
            let p = b.as_ptr() as *const c_void;
            assert_eq!(
                crate::string::memchr(p, b'c' as i32, 5) as usize,
                p.add(3) as usize
            );
            assert_eq!(crate::string::memchr(p, 0, 5) as usize, p.add(2) as usize);
            assert!(crate::string::memchr(p, b'z' as i32, 5).is_null());
            assert!(crate::string::memchr(p, b'a' as i32, 0).is_null());
        }
    }

    #[test]
    fn memrchr_scans_back() {
        unsafe {
            let b = *b"abca";
            let p = b.as_ptr() as *const c_void;
            assert_eq!(
                crate::string::memrchr(p, b'a' as i32, 4) as usize,
                p.add(3) as usize
            );
            assert!(crate::string::memrchr(p, b'z' as i32, 4).is_null());
            assert!(crate::string::memrchr(p, b'a' as i32, 0).is_null());
        }
    }

    #[test]
    fn memmem_finds_subslice() {
        unsafe {
            let h = *b"xxabcxx";
            let hp = h.as_ptr() as *const c_void;
            assert_eq!(
                crate::string::memmem(hp, 7, b"abc".as_ptr() as *const c_void, 3) as usize,
                hp.add(2) as usize
            );
            assert_eq!(
                crate::string::memmem(hp, 7, b"".as_ptr() as *const c_void, 0) as usize,
                hp as usize
            );
            assert!(crate::string::memmem(hp, 7, b"abcd".as_ptr() as *const c_void, 4).is_null());
            assert!(crate::string::memmem(hp, 2, b"abc".as_ptr() as *const c_void, 3).is_null());
            assert_eq!(
                crate::string::memmem(hp, 7, b"c".as_ptr() as *const c_void, 1) as usize,
                hp.add(4) as usize
            );
        }
    }

    #[test]
    fn memccpy_stops_at_byte() {
        unsafe {
            let mut d = [0u8; 4];
            let r = crate::string::memccpy(
                d.as_mut_ptr() as *mut c_void,
                b"abc".as_ptr() as *const c_void,
                b'b' as i32,
                3,
            );
            assert_eq!(r as usize, d.as_mut_ptr().add(2) as usize);
            assert_eq!(&d[..2], b"ab");
            let mut e = [0u8; 4];
            assert!(crate::string::memccpy(
                e.as_mut_ptr() as *mut c_void,
                b"abc".as_ptr() as *const c_void,
                b'z' as i32,
                3
            )
            .is_null());
            assert_eq!(&e[..3], b"abc");
            assert!(crate::string::memccpy(
                e.as_mut_ptr() as *mut c_void,
                b"abc".as_ptr() as *const c_void,
                b'a' as i32,
                0
            )
            .is_null());
        }
    }

    #[test]
    fn mempcpy_returns_end() {
        unsafe {
            let mut d = [0u8; 4];
            let r = crate::string::mempcpy(
                d.as_mut_ptr() as *mut c_void,
                b"abc".as_ptr() as *const c_void,
                3,
            );
            assert_eq!(r as usize, d.as_mut_ptr().add(3) as usize);
            assert_eq!(&d[..3], b"abc");
        }
    }

    #[test]
    fn bzero_clears() {
        unsafe {
            let mut b = [0xabu8; 8];
            crate::string::bzero(b.as_mut_ptr() as *mut c_void, 8);
            assert_eq!(&b, &[0; 8]);
            crate::string::bzero(b.as_mut_ptr() as *mut c_void, 0);
        }
    }

    #[test]
    fn explicit_bzero_clears() {
        unsafe {
            let mut b = [0xabu8; 8];
            crate::string::explicit_bzero(b.as_mut_ptr() as *mut c_void, 8);
            assert_eq!(&b, &[0; 8]);
            crate::string::explicit_bzero(b.as_mut_ptr() as *mut c_void, 0);
            assert_eq!(&b, &[0; 8]);
        }
    }

    #[test]
    fn ffs_bit_positions() {
        unsafe {
            assert_eq!(crate::string::ffs(0), 0);
            assert_eq!(crate::string::ffs(1), 1);
            assert_eq!(crate::string::ffs(0x8000), 16);
            assert_eq!(crate::string::ffs(-1), 1);
            assert_eq!(crate::string::ffs(i32::MIN), 32);
            assert_eq!(crate::string::ffs(0b1100), 3);
        }
    }

    #[test]
    fn ffsl_ffsll_wide_positions() {
        unsafe {
            assert_eq!(crate::string::ffsl(0), 0);
            assert_eq!(crate::string::ffsl(1), 1);
            assert_eq!(crate::string::ffsl(1i64 << 40), 41);
            assert_eq!(crate::string::ffsll(0), 0);
            assert_eq!(crate::string::ffsll(1), 1);
            assert_eq!(crate::string::ffsll(i64::MIN), 64);
        }
    }

    #[test]
    fn strverscmp_version_order() {
        unsafe {
            assert_eq!(crate::string::strverscmp(c"a".as_ptr(), c"a".as_ptr()), 0);
            assert_eq!(crate::string::strverscmp(c"".as_ptr(), c"".as_ptr()), 0);
            assert!(crate::string::strverscmp(c"file-1.2".as_ptr(), c"file-1.10".as_ptr()) < 0);
            assert!(crate::string::strverscmp(c"file-1.10".as_ptr(), c"file-1.2".as_ptr()) > 0);
            assert!(crate::string::strverscmp(c"a".as_ptr(), c"b".as_ptr()) < 0);
        }
    }

    #[test]
    fn strerror_table() {
        unsafe {
            assert_eq!(bytes(crate::string::strerror(0)), b"No error information");
            assert_eq!(
                bytes(crate::string::strerror(2)),
                b"No such file or directory"
            );
            assert_eq!(
                bytes(crate::string::strerror(34)),
                b"Result not representable"
            );
            assert_eq!(bytes(crate::string::strerror(12)), b"Out of memory");
            assert_eq!(
                bytes(crate::string::strerror(9999)),
                b"No error information"
            );
            assert_eq!(bytes(crate::string::strerror(-1)), b"No error information");
        }
    }

    #[test]
    fn strerror_r_fits_and_truncates() {
        unsafe {
            let mut b = [0u8; 64];
            let r = crate::string::strerror_r(2, b.as_mut_ptr() as *mut c_char, 64);
            assert_eq!(r, 0);
            assert_eq!(
                bytes(b.as_ptr() as *const c_char),
                b"No such file or directory"
            );
            let mut t = [0u8; 4];
            let r2 = crate::string::strerror_r(2, t.as_mut_ptr() as *mut c_char, 4);
            assert_eq!(r2, 34);
            assert_eq!(&t, b"No \0");
            let mut z = [0x7fu8; 4];
            let r3 = crate::string::strerror_r(2, z.as_mut_ptr() as *mut c_char, 0);
            assert_eq!(r3, 34);
            assert_eq!(&z, &[0x7f; 4]);
        }
    }

    #[test]
    fn strsignal_names() {
        unsafe {
            assert_eq!(bytes(crate::string::strsignal(11)), b"Segmentation fault");
            assert_eq!(bytes(crate::string::strsignal(1)), b"Hangup");
            assert_eq!(bytes(crate::string::strsignal(32)), b"RT32");
            assert_eq!(bytes(crate::string::strsignal(64)), b"RT64");
            assert_eq!(bytes(crate::string::strsignal(0)), b"Unknown signal");
            assert_eq!(bytes(crate::string::strsignal(99)), b"Unknown signal");
            assert_eq!(bytes(crate::string::strsignal(-5)), b"Unknown signal");
        }
    }

    #[test]
    fn swab_swaps_pairs() {
        unsafe {
            let s = [1u8, 2, 3, 4, 5];
            let mut d = [0x7fu8; 5];
            crate::string::swab(
                s.as_ptr() as *const c_void,
                d.as_mut_ptr() as *mut c_void,
                5,
            );
            // Odd tail byte is never written (musl leaves it alone).
            assert_eq!(&d, &[2, 1, 4, 3, 0x7f]);
            crate::string::swab(
                s.as_ptr() as *const c_void,
                d.as_mut_ptr() as *mut c_void,
                0,
            );
            assert_eq!(&d, &[2, 1, 4, 3, 0x7f]);
            crate::string::swab(
                s.as_ptr() as *const c_void,
                d.as_mut_ptr() as *mut c_void,
                1,
            );
            assert_eq!(&d, &[2, 1, 4, 3, 0x7f]);
        }
    }
}
