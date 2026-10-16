//! Gate 6E, binary (deps): a minimal dynamic program with a DT_NEEDED
//! edge to its own libmine.so and a call into it. Validates `load_deps`,
//! `add_syms` and `reloc_all` on a real shared object, not a mock.

#![no_std]
#![no_main]

use core::ffi::{c_char, c_int};

#[path = "../personality.rs"]
mod personality;

// Load-bearing: ensure zlibc rlib metadata (panic handler) is linked.
extern crate zlibc;

// Linked through `ZLIBC_GATE_LIBDIR` (see hello/build.rs) in the 6E
// smoke job; the SONAME lands in DT_NEEDED exactly like musl-gcc would.
#[link(name = "mine", kind = "dylib")]
extern "C" {
    fn mine_value() -> c_int;
}

extern "C" {
    fn printf(fmt: *const c_char, ...) -> c_int;
}

/// Application entry for our `_start_c` (exact signature it calls).
#[no_mangle]
pub extern "C" fn main(_argc: c_int, _argv: *mut *mut c_char, _envp: *mut *mut c_char) -> c_int {
    unsafe {
        let v = mine_value();
        printf(c"gate-deps %d\n".as_ptr(), v);
    }
    0
}
