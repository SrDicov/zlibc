//! Wave 5, packet 5: real file I/O in a binary.
//!
//! Same build as hello (abort + nostdlib). `fopen`/`fwrite`/`fclose` a
//! scratch file, reopens it for reading, verifies every byte, unlinks
//! it. Unit tests only ever exercised pipes — this is the first touch
//! of the real filesystem.

#![no_std]
#![no_main]

use core::ffi::{c_char, c_int, c_void};

use zlibc::stdio::{fclose, fopen, fread, fwrite};

#[path = "../personality.rs"]
mod personality;

extern "C" {
    fn printf(fmt: *const c_char, ...) -> c_int;
}

/// Raw unlink for the scratch file (one syscall, no lib surface creep).
unsafe fn unlink(path: *const c_char) {
    unsafe {
        const SYS_UNLINK: usize = 87;
        let _ = zlibc::syscall::syscall1(SYS_UNLINK, path as usize);
    }
}

/// Application entry for our `_start_c` (exact signature it calls).
#[no_mangle]
pub unsafe extern "C" fn main(
    _argc: c_int,
    _argv: *mut *mut c_char,
    _envp: *mut *mut c_char,
) -> c_int {
    unsafe {
        let path = c"zlibc-fs-probe.tmp".as_ptr();
        let w = fopen(path, c"w".as_ptr());
        if w.is_null() {
            printf(c"open w failed\n".as_ptr());
            return 1;
        }
        let msg = b"file io 123";
        if fwrite(msg.as_ptr() as *const c_void, 1, msg.len(), w) != msg.len() {
            return 1;
        }
        if fclose(w) != 0 {
            return 1;
        }
        let r = fopen(path, c"r".as_ptr());
        if r.is_null() {
            return 1;
        }
        let mut back = [0u8; 32];
        let n = fread(back.as_mut_ptr() as *mut c_void, 1, back.len(), r);
        if fclose(r) != 0 {
            return 1;
        }
        unlink(path);
        if n != msg.len() || &back[..n] != &msg[..] {
            printf(c"mismatch\n".as_ptr());
            return 1;
        }
        printf(c"fs ok %d bytes\n".as_ptr(), n as c_int);
        0
    }
}
