//! Wave 5 gate, packet 1: a real binary running on zlibc only.
//!
//! `_start` + `__libc_start_main` + `puts` + `exit` are all ours; the
//! kernel is the only other party. Linked with `-nostdlib` (scoped from
//! `build.rs` so host build tools keep their start files) and built
//! under `panic=abort` (no unwinder without a host libc).

#![no_std]
#![no_main]

use core::ffi::{c_char, c_int};

/// Unwinder personality stub: unreachable under this crate's
/// `panic=abort`, but prebuilt `core` objects reference the symbol and
/// `-nostdlib` drops the library that would otherwise provide it. Kept
/// here (not in the lib) so a future unwinding world still gets a link
/// error instead of a silent abort.
#[no_mangle]
pub extern "C" fn rust_eh_personality() -> ! {
    loop {}
}

/// Application entry for our `_start_c` (exact signature it calls).
/// Returns through `exit` in stage-2, exercising that path too.
#[no_mangle]
pub extern "C" fn main(_argc: c_int, _argv: *mut *mut c_char, _envp: *mut *mut c_char) -> c_int {
    unsafe {
        zlibc::stdio::puts(c"hello from zlibc".as_ptr());
    }
    0
}
