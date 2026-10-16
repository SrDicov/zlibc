//! Thin `mmap` wrappers (musl `src/mman/mmap.c`, `munmap.c`,
//! `mprotect.c`).
//!
//! Each entry is one raw syscall returning through `syscall_ret`, so
//! `errno` follows musl's contract. `mmap` keeps musl's page-offset
//! check (`EINVAL` before any syscall) and its error shape: a failed
//! map returns `MAP_FAILED` (`(void *)-1`), never null.

use core::ffi::{c_int, c_void};

use crate::errno::__errno_location;
use crate::syscall::{syscall3, syscall6, syscall_ret};

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_MMAP: usize = 9; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_MPROTECT: usize = 10; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_MUNMAP: usize = 11; // TODO: generate from arch bits/syscall.h

/// musl `include/sys/mman.h`.
pub const PROT_NONE: c_int = 0;
pub const PROT_READ: c_int = 1;
pub const PROT_WRITE: c_int = 2;
pub const PROT_EXEC: c_int = 4;

/// musl `include/sys/mman.h`.
pub const MAP_SHARED: c_int = 0x01;
pub const MAP_PRIVATE: c_int = 0x02;
pub const MAP_FIXED: c_int = 0x10;
pub const MAP_ANON: c_int = 0x20;
pub const MAP_ANONYMOUS: c_int = MAP_ANON;
/// musl `MAP_FAILED ((void *) -1)`.
pub const MAP_FAILED: *mut c_void = !0usize as *mut c_void;

/// musl `include/errno.h`.
const EINVAL: c_int = 22;

/// Map memory (musl `mmap`).
///
/// A non-page-aligned `off` fails with `EINVAL` before any syscall
/// (musl `mmap.c`); on any failure the return is `MAP_FAILED` with
/// `errno` set — `syscall_ret` already maps kernel errors to `-1`,
/// which as a pointer is exactly `MAP_FAILED`.
///
/// # Safety
///
/// `off`/`len` semantics follow the kernel; a file-backed `fd` must
/// be open compatibly with `prot`/`flags`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mmap(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    off: i64,
) -> *mut c_void {
    unsafe {
        if off & 4095 != 0 {
            crate::errno::errno_store(__errno_location(), EINVAL);
            return MAP_FAILED;
        }
        syscall_ret(syscall6(
            SYS_MMAP,
            addr as usize,
            len,
            prot as usize,
            flags as usize,
            fd as usize,
            off as usize,
        )) as *mut c_void
    }
}

/// Unmap memory (musl `munmap`).
///
/// # Safety
///
/// `addr`/`len` must describe a mapped region owned by the caller.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn munmap(addr: *mut c_void, len: usize) -> c_int {
    unsafe { syscall_ret(syscall3(SYS_MUNMAP, addr as usize, len, 0)) as c_int }
}

/// Change protection (musl `mprotect`; `addr`/`len` must be
/// page-aligned — the kernel rejects anything else).
///
/// # Safety
///
/// `addr`/`len` must describe a mapped region owned by the caller.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> c_int {
    unsafe { syscall_ret(syscall3(SYS_MPROTECT, addr as usize, len, prot as usize)) as c_int }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::{
        mmap, mprotect, munmap, MAP_ANON, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_READ,
        PROT_WRITE,
    };
    use core::ptr::null_mut;

    use crate::errno::{__errno_location, errno_load};

    #[test]
    fn mmap_anon_write_read_protect_unmap() {
        unsafe {
            assert_eq!(MAP_ANONYMOUS, MAP_ANON);
            let len = 4096usize;
            let p = mmap(
                null_mut(),
                len,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            );
            assert_ne!(p, MAP_FAILED);
            assert!(!p.is_null());
            (p as *mut u64).write(0x1234_5678_dead_beef);
            assert_eq!((p as *const u64).read(), 0x1234_5678_dead_beef);
            assert_eq!(mprotect(p, len, PROT_READ), 0);
            assert_eq!((p as *const u64).read(), 0x1234_5678_dead_beef);
            assert_eq!(mprotect(p, len, PROT_READ | PROT_WRITE), 0);
            assert_eq!(munmap(p, len), 0);
        }
    }

    #[test]
    fn mmap_bad_offset_is_einval() {
        // Asserts an exact errno value: serialize (see testlock docs).
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let p = mmap(null_mut(), 4096, PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 1);
            assert_eq!(p, MAP_FAILED);
            assert_eq!(errno_load(__errno_location()), 22);
        }
    }
}
