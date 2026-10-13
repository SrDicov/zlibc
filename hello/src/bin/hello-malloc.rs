//! Wave 5, packet 3: malloc + printf in a real binary (no harness).
//!
//! Same build as hello (abort + nostdlib). Allocates three size classes
//! (list reuse, split, fresh `mmap` arena), plus calloc-zero and
//! realloc-grow, then reports over our own `printf`. Deterministic bytes.

#![no_std]
#![no_main]

use core::ffi::{c_char, c_int, c_void};

use zlibc::malloc::{calloc, free, malloc, realloc};

#[path = "../personality.rs"]
mod personality;

extern "C" {
    fn printf(fmt: *const c_char, ...) -> c_int;
    fn snprintf(s: *mut c_char, n: usize, fmt: *const c_char, ...) -> c_int;
}

/// Application entry for our `_start_c` (exact signature it calls).
#[no_mangle]
pub extern "C" fn main(
    _argc: c_int,
    _argv: *mut *mut c_char,
    _envp: *mut *mut c_char,
) -> c_int {
    unsafe {
        // Three size classes: list reuse, split, fresh mmap arena.
        let a = malloc(16);
        let b = malloc(1024);
        let c = malloc(70000);
        if a.is_null() || b.is_null() || c.is_null() {
            return 1;
        }
        // calloc arrives zeroed.
        let z = calloc(64, 8) as *mut u8;
        if z.is_null() {
            return 1;
        }
        let mut k = 0usize;
        while k < 512 {
            if *z.add(k) != 0 {
                return 1;
            }
            k += 1;
        }
        // realloc grows and preserves bytes.
        let r = malloc(32) as *mut u8;
        if r.is_null() {
            return 1;
        }
        *r = 0x5a;
        let g = realloc(r as *mut c_void, 4096) as *mut u8;
        if g.is_null() || *g != 0x5a {
            return 1;
        }
        // Report through our own printf (also smokes %d/%s in-binary).
        let mut line = [0u8; 64];
        let n = snprintf(
            line.as_mut_ptr() as *mut c_char,
            line.len(),
            c"malloc ok %d %d %d\n".as_ptr(),
            16 as c_int,
            1024 as c_int,
            70000 as c_int,
        );
        if n <= 0 {
            return 1;
        }
        printf(c"%s".as_ptr(), line.as_ptr());
        printf(c"calloc zero ok\n".as_ptr());
        printf(c"realloc ok\n".as_ptr());
        free(a);
        free(b);
        free(c);
        free(z as *mut c_void);
        free(g as *mut c_void);
        0
    }
}
