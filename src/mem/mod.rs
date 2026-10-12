//! `memcpy`, `memmove`, `memset` with exact musl signatures.
//!
//! Clean reimplementation — zero copied musl code. Behavior mirrors musl
//! src/string/memcpy.c:5, src/string/memmove.c:13, src/string/memset.c:5
//! and the declarations in musl include/string.h:27-29 (same signatures,
//! same `dest` return, same overlap direction rule), but every body is a
//! plain byte loop.
//!
//! Layout choice: one `mod.rs` for all three. They are 15-line siblings
//! with shared tests; per-function files would triple the file count for
//! no readability gain.
//!
//! shortcut: byte-at-a-time loops; upgrade to word-at-a-time like musl
//! when measured (musl copies 4/8 bytes per step once aligned).

use core::ffi::{c_int, c_void};

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

#[cfg(test)]
mod tests {
    use core::ffi::c_void;

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
        assert_eq!(ret as usize, buf.as_mut_ptr() as usize);
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
}
