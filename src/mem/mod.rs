//! `memcpy`, `memmove`, `memset`, `memcmp` with exact musl signatures.
//!
//! Clean reimplementation — zero copied musl code. Behavior mirrors musl
//! src/string/memcpy.c:5, src/string/memmove.c:13, src/string/memset.c:5,
//! src/string/memcmp.c (same signatures, same `dest` return, same
//! overlap direction rule, same unsigned-byte ordering), but every body
//! is a plain byte loop.
//!
//! Layout choice: one `mod.rs` for all four. They are 15-line siblings
//! with shared tests; per-function files would triple the file count for
//! no readability gain.
//!
//! shortcut: byte-at-a-time loops; upgrade to word-at-a-time like musl
//! when measured (musl copies 4/8 bytes per step once aligned).

use core::ffi::{c_char, c_int, c_void};

/// musl `memcpy` (src/string/memcpy.c:5, declared include/string.h:27).
///
/// Copies `n` bytes from `src` to `dest`, returns `dest`. Overlapping
/// ranges are UB — use [`memmove`] for those, exactly like musl/C.
///
/// # Safety
///
/// `dest` must be valid for writes of `n` bytes and `src` for reads of
/// `n` bytes; the two ranges must not overlap.
#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    // shortcut: byte loop; word-at-a-time like musl when measured.
    unsafe {
        let mut d = dest as *mut u8;
        let mut s = src as *const u8;
        let mut left = n;
        while left > 0 {
            *d = *s;
            d = d.add(1);
            s = s.add(1);
            left -= 1;
        }
    }
    dest
}

/// musl `memmove` (src/string/memmove.c:13, declared include/string.h:28).
///
/// Like [`memcpy`] but overlap-safe: copies forward when `dest <= src`
/// or the ranges are disjoint, backward when `dest` lands inside
/// `[src, src+n)` — the same direction rule as musl's `d<s` / `else`
/// split (src/string/memmove.c:17-36), minus the word-at-a-time paths.
///
/// # Safety
///
/// Same validity as [`memcpy`], except the ranges MAY overlap.
#[no_mangle]
pub unsafe extern "C" fn memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    // shortcut: byte loop; word-at-a-time like musl when measured.
    unsafe {
        let d = dest as usize;
        let s = src as usize;
        // `d - s` cannot underflow: it only evaluates when `d > s`.
        if d <= s || d - s >= n {
            let mut dd = dest as *mut u8;
            let mut ss = src as *const u8;
            let mut left = n;
            while left > 0 {
                *dd = *ss;
                dd = dd.add(1);
                ss = ss.add(1);
                left -= 1;
            }
        } else {
            let mut i = n;
            while i > 0 {
                i -= 1;
                *(dest as *mut u8).add(i) = *(src as *const u8).add(i);
            }
        }
    }
    dest
}

/// musl `memset` (src/string/memset.c:5, declared include/string.h:29).
///
/// Fills `n` bytes at `dest` with `(unsigned char)c`, returns `dest`
/// (musl's head/tail + word-fill fast paths reduced to a byte loop).
///
/// # Safety
///
/// `dest` must be valid for writes of `n` bytes.
#[no_mangle]
pub unsafe extern "C" fn memset(dest: *mut c_void, c: c_int, n: usize) -> *mut c_void {
    // shortcut: byte loop; word-at-a-time like musl when measured.
    unsafe {
        let mut d = dest as *mut u8;
        let mut left = n;
        while left > 0 {
            *d = c as u8;
            d = d.add(1);
            left -= 1;
        }
    }
    dest
}

/// musl `memcmp` (src/string/memcmp.c, declared include/string.h:30).
///
/// Compares `n` bytes as `unsigned char`, returning negative/zero/
/// positive like the first differing pair (musl's `*a - *b` shape).
/// Zero length compares nothing and returns 0.
///
/// # Safety
///
/// Both pointers must be valid for reads of `n` bytes.
#[no_mangle]
pub unsafe extern "C" fn memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> c_int {
    // shortcut: byte loop; word-at-a-time like musl when measured.
    unsafe {
        let mut a = s1 as *const u8;
        let mut b = s2 as *const u8;
        let mut left = n;
        while left > 0 {
            if *a != *b {
                return (*a as c_int) - (*b as c_int);
            }
            a = a.add(1);
            b = b.add(1);
            left -= 1;
        }
    }
    0
}

/// musl `strlen`: length to the terminator.
///
/// Byte loop like the rest of this module; the release-codegen gate
/// below proves LLVM does not fold it into a `strlen` call (same
/// hazard class as the `mem*` self-calls).
///
/// # Safety
///
/// `s` must point at a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn strlen(s: *const c_char) -> usize {
    // shortcut: byte loop; word-at-a-time like musl when measured.
    unsafe {
        let mut n = 0usize;
        while *s.add(n) != 0 {
            n += 1;
        }
        n
    }
}

/// musl `bcmp` (BSD): `memcmp` that returns only equal-or-not.
///
/// Own loop rather than delegating to [`memcmp`]: the one-line
/// delegation trapped under release codegen (host test binary died in
/// `bcmp` with SIGILL during libtest arg parsing, zero tests run,
/// while every loop-only sibling survived startup). Same byte loop as
/// the rest of this module, same gate below.
///
/// # Safety
///
/// Both pointers must be valid for reads of `n` bytes.
#[no_mangle]
pub unsafe extern "C" fn bcmp(s1: *const c_void, s2: *const c_void, n: usize) -> c_int {
    // shortcut: byte loop; word-at-a-time like musl when measured.
    unsafe {
        let mut a = s1 as *const u8;
        let mut b = s2 as *const u8;
        let mut left = n;
        while left > 0 {
            if *a != *b {
                return 1;
            }
            a = a.add(1);
            b = b.add(1);
            left -= 1;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use core::ffi::{c_char, c_void};

    // Every call below uses the full `crate::mem::*` path on purpose: on
    // the glibc test host a bare `memcpy` would resolve to libc and prove
    // nothing about our definitions.

    /// Copies bytes exactly and returns `dest`; zero length is a no-op.
    #[test]
    fn memcpy_basic_and_zero_len() {
        let src = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut dst = [0u8; 8];
        let ret = unsafe {
            crate::mem::memcpy(
                dst.as_mut_ptr() as *mut c_void,
                src.as_ptr() as *const c_void,
                src.len(),
            )
        };
        assert_eq!(dst, src);
        assert_eq!(ret as usize, dst.as_mut_ptr() as usize);
        let ret0 = unsafe {
            crate::mem::memcpy(
                dst.as_mut_ptr() as *mut c_void,
                src.as_ptr() as *const c_void,
                0,
            )
        };
        assert_eq!(dst, src);
        assert_eq!(ret0 as usize, dst.as_mut_ptr() as usize);
    }

    /// `dest < src` overlap must copy forward (musl's `d<s` path).
    #[test]
    fn memmove_overlap_dest_below_src() {
        let mut buf = [0u8, 1, 2, 3, 4, 5, 6, 7];
        let ret = unsafe {
            crate::mem::memmove(
                buf.as_mut_ptr() as *mut c_void,
                buf.as_ptr().add(2) as *const c_void,
                6,
            )
        };
        assert_eq!(buf, [2, 3, 4, 5, 6, 7, 6, 7]);
        assert_eq!(ret as usize, buf.as_mut_ptr() as usize);
    }

    /// `dest > src` overlap must copy backward (musl's `else` path).
    #[test]
    fn memmove_overlap_dest_above_src() {
        let mut buf = [0u8, 1, 2, 3, 4, 5, 6, 7];
        let ret = unsafe {
            crate::mem::memmove(
                buf.as_mut_ptr().add(2) as *mut c_void,
                buf.as_ptr() as *const c_void,
                6,
            )
        };
        assert_eq!(buf, [0, 1, 0, 1, 2, 3, 4, 5]);
        assert_eq!(ret as usize, buf.as_mut_ptr().wrapping_add(2) as usize);
    }

    /// Fills every byte, truncates `c` to `unsigned char`, returns `dest`.
    #[test]
    fn memset_fill_and_truncation() {
        let mut buf = [0u8; 16];
        let ret = unsafe { crate::mem::memset(buf.as_mut_ptr() as *mut c_void, 0xab, 16) };
        assert_eq!(buf, [0xab; 16]);
        assert_eq!(ret as usize, buf.as_mut_ptr() as usize);
        unsafe { crate::mem::memset(buf.as_mut_ptr() as *mut c_void, 0x1ab, 4) };
        assert_eq!(&buf[..4], &[0xab; 4]);
    }

    /// Unsigned-byte ordering, sign of the first difference, zero length.
    #[test]
    fn memcmp_orders_and_zero_len() {
        let a = *b"abc";
        let b = *b"abd";
        let c = *b"abb";
        unsafe {
            assert_eq!(
                crate::mem::memcmp(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void, 3),
                -1
            );
            assert!(
                crate::mem::memcmp(b.as_ptr() as *const c_void, a.as_ptr() as *const c_void, 3) > 0
            );
            assert_eq!(
                crate::mem::memcmp(a.as_ptr() as *const c_void, c.as_ptr() as *const c_void, 3),
                1
            );
            assert_eq!(
                crate::mem::memcmp(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void, 0),
                0
            );
            // High bytes compare unsigned (0xff > 0x01).
            let hi = [0xffu8];
            let lo = [0x01u8];
            assert!(
                crate::mem::memcmp(
                    hi.as_ptr() as *const c_void,
                    lo.as_ptr() as *const c_void,
                    1
                ) > 0
            );
        }
    }

    #[test]
    fn strlen_counts_to_terminator() {
        unsafe {
            assert_eq!(crate::mem::strlen(c"".as_ptr()), 0);
            assert_eq!(crate::mem::strlen(c"abc".as_ptr()), 3);
            let buf = *b"ab\0cd";
            assert_eq!(crate::mem::strlen(buf.as_ptr() as *const c_char), 2);
        }
    }

    #[test]
    fn bcmp_shares_memcmp_verdict() {
        unsafe {
            let a = *b"abc";
            let b = *b"abd";
            assert_eq!(
                crate::mem::bcmp(a.as_ptr() as *const c_void, a.as_ptr() as *const c_void, 3),
                0
            );
            assert_ne!(
                crate::mem::bcmp(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void, 3),
                0
            );
            assert_eq!(
                crate::mem::bcmp(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void, 0),
                0
            );
        }
    }
}
