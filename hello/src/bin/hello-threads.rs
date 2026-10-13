//! Wave 5, packet 2: threads in a real binary (real boot TP path).
//!
//! Same build as hello (abort + nostdlib, own crate). Two of our threads
//! partial-sum 0..100; the main thread joins, checks the total (4950),
//! and prints it. This exercises the path unit tests never touch:
//! `ensure_main_tp` taking over `FS` at real boot (under `cargo test` it
//! early-returns for glibc), plus clone/join/printf on virgin stacks.

#![no_std]
#![no_main]

use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU32, Ordering};

use zlibc::abi::PthreadT;
use zlibc::thread::create::{__pthread_create, __pthread_join};

#[path = "../personality.rs"]
mod personality;

extern "C" {
    fn printf(fmt: *const c_char, ...) -> c_int;
}

static PART0: AtomicU32 = AtomicU32::new(0);
static PART1: AtomicU32 = AtomicU32::new(0);

/// Child code: pure GPR/atomics + our syscalls only. Never touches host
/// TLS (its `FS` is our TCB) and never panics.
unsafe extern "C" fn worker(arg: *mut c_void) -> *mut c_void {
    unsafe {
        let lo = *(arg as *const c_int);
        let mut acc = 0u32;
        let mut k = lo as u32;
        while k < (lo + 50) as u32 {
            acc = acc.wrapping_add(k);
            k += 1;
        }
        if lo == 0 {
            PART0.store(acc, Ordering::SeqCst);
        } else {
            PART1.store(acc, Ordering::SeqCst);
        }
    }
    null_mut()
}

/// Application entry for our `_start_c` (exact signature it calls).
#[no_mangle]
pub extern "C" fn main(_argc: c_int, _argv: *mut *mut c_char, _envp: *mut *mut c_char) -> c_int {
    unsafe {
        let mut lo0 = 0 as c_int;
        let mut lo1 = 50 as c_int;
        let mut t0: PthreadT = null_mut();
        let mut t1: PthreadT = null_mut();
        if __pthread_create(
            &mut t0,
            null_mut(),
            Some(worker),
            &mut lo0 as *mut c_int as *mut c_void,
        ) != 0
        {
            return 1;
        }
        if __pthread_create(
            &mut t1,
            null_mut(),
            Some(worker),
            &mut lo1 as *mut c_int as *mut c_void,
        ) != 0
        {
            return 1;
        }
        if __pthread_join(t0, null_mut()) != 0 {
            return 1;
        }
        if __pthread_join(t1, null_mut()) != 0 {
            return 1;
        }
        let total = PART0
            .load(Ordering::SeqCst)
            .wrapping_add(PART1.load(Ordering::SeqCst));
        printf(c"threads total %d\n".as_ptr(), total as c_int);
        if total == 4950 {
            0
        } else {
            1
        }
    }
}
