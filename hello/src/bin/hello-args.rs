//! Wave 5, packet 4: real kernel argv/env in a binary.
//!
//! Same build as hello (abort + nostdlib). Prints argc, argv[1..], and
//! one pinned env var — everything else in the environment varies per
//! runner and stays out of the assertion. The CI step invokes it with
//! fixed args plus `TEST_MARKER=zzq`.

#![no_std]
#![no_main]

use core::ffi::{c_char, c_int};
use core::ptr::null;

#[path = "../personality.rs"]
mod personality;

extern "C" {
    fn printf(fmt: *const c_char, ...) -> c_int;
}

/// Env lookup over raw envp (kept local: one test needs no lib surface).
/// Pointer + length (never a slice): this binary avoids every construct
/// the sibling bins do not use, keeping the three binaries structurally
/// identical for the toolchain.
unsafe fn getenv(envp: *mut *mut c_char, key: *const u8, klen: usize) -> *const c_char {
    unsafe {
        let mut k = 0isize;
        while !(*envp.offset(k)).is_null() {
            let s = *envp.offset(k) as *const u8;
            let mut j = 0usize;
            while j < klen && *s.add(j) == *key.add(j) {
                j += 1;
            }
            if j == klen && *s.add(j) == b'=' {
                return s.add(j + 1) as *const c_char;
            }
            k += 1;
        }
        null()
    }
}

/// Application entry for our `_start_c` (exact signature it calls).
#[no_mangle]
pub extern "C" fn main(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char) -> c_int {
    unsafe {
        printf(c"argc=%d\n".as_ptr(), argc);
        let mut i = 1isize;
        while i < argc as isize {
            printf(c"argv=%s\n".as_ptr(), *argv.offset(i));
            i += 1;
        }
        printf(
            c"env=%s\n".as_ptr(),
            getenv(envp, b"TEST_MARKER".as_ptr(), 11),
        );
        0
    }
}
