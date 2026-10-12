//! Futex operations and the `__wait` helper (x86_64).
//!
//! Clean-room mirrors of musl `src/internal/futex.h` (op constants),
//! `src/internal/pthread_impl.h:168-180` (`__wake`/`__futexwait`), and
//! `src/thread/__wait.c` (`__wait`). Re-derived, not copied.

use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::syscall::{syscall3, syscall4};

/// musl `src/internal/futex.h:4` (`FUTEX_WAIT`).
pub const FUTEX_WAIT: c_int = 0;
/// musl `src/internal/futex.h:5` (`FUTEX_WAKE`).
pub const FUTEX_WAKE: c_int = 1;
/// musl `src/internal/futex.h:15` (`FUTEX_PRIVATE`).
pub const FUTEX_PRIVATE: c_int = 128;
/// musl `src/internal/futex.h:17` (`FUTEX_CLOCK_REALTIME`).
pub const FUTEX_CLOCK_REALTIME: c_int = 256;

/// musl `arch/x86_64/bits/syscall.h.in` (`__NR_futex` is 202).
#[cfg(target_arch = "x86_64")]
pub const SYS_FUTEX: usize = 202; // TODO: generate from arch bits/syscall.h

/// musl `arch/generic/bits/errno.h:38` (`ENOSYS`).
const ENOSYS: c_int = 38;

/// Reinterpret an `int` futex word as an atomic word.
///
/// Same size and alignment; every access through the result must use
/// atomic operations, never a plain read-modify-write.
pub(crate) fn as_atomic(p: *mut c_int) -> *const AtomicI32 {
    p as *const AtomicI32
}

/// Sleep while `*addr == val`, process-private op.
///
/// Falls back to the shared op when the kernel predates private futexes
/// (musl `src/internal/pthread_impl.h:175-180`, `__futexwait`).
///
/// # Safety
///
/// `addr` must point to a live, 4-byte-aligned `c_int` the caller may
/// block on. Returns the raw kernel result (negative errno on error).
pub unsafe fn futex_wait_private(addr: *mut c_int, val: c_int) -> isize {
    unsafe {
        let r = syscall4(
            SYS_FUTEX,
            addr as usize,
            (FUTEX_WAIT | FUTEX_PRIVATE) as usize,
            val as usize,
            0,
        );
        if r != -(ENOSYS as isize) {
            return r;
        }
        syscall4(
            SYS_FUTEX,
            addr as usize,
            FUTEX_WAIT as usize,
            val as usize,
            0,
        )
    }
}

/// Sleep while `*addr == val`, process-shared op.
///
/// # Safety
///
/// Same contract as [`futex_wait_private`].
pub unsafe fn futex_wait_shared(addr: *mut c_int, val: c_int) -> isize {
    unsafe {
        syscall4(
            SYS_FUTEX,
            addr as usize,
            FUTEX_WAIT as usize,
            val as usize,
            0,
        )
    }
}

/// Wake up to `cnt` sleepers (`cnt < 0` wakes all), private op.
///
/// Same `-ENOSYS` fallback as musl `pthread_impl.h:168-174` (`__wake`).
///
/// # Safety
///
/// `addr` must point to a live, 4-byte-aligned `c_int`.
pub unsafe fn futex_wake_private(addr: *mut c_int, cnt: c_int) -> isize {
    let cnt = if cnt < 0 { c_int::MAX } else { cnt };
    unsafe {
        let r = syscall3(
            SYS_FUTEX,
            addr as usize,
            (FUTEX_WAKE | FUTEX_PRIVATE) as usize,
            cnt as usize,
        );
        if r != -(ENOSYS as isize) {
            return r;
        }
        syscall3(SYS_FUTEX, addr as usize, FUTEX_WAKE as usize, cnt as usize)
    }
}

/// Wake up to `cnt` sleepers (`cnt < 0` wakes all), shared op.
///
/// # Safety
///
/// Same contract as [`futex_wake_private`].
pub unsafe fn futex_wake_shared(addr: *mut c_int, cnt: c_int) -> isize {
    let cnt = if cnt < 0 { c_int::MAX } else { cnt };
    unsafe { syscall3(SYS_FUTEX, addr as usize, FUTEX_WAKE as usize, cnt as usize) }
}

/// Block until `*addr != val` (musl `src/thread/__wait.c:3-17`).
///
/// Spins up to 100 times while no waiter is recorded in `waiters`, then
/// counts this thread in `waiters` and sleeps in `FUTEX_WAIT` until
/// `*addr` changes. `priv_` nonzero selects the private op (with the
/// shared fallback); `waiters` may be null to skip the counting.
///
/// # Safety
///
/// `addr` must point to a live, 4-byte-aligned `c_int`. `waiters` must
/// be null or point to a live, 4-byte-aligned `c_int` used only for
/// this protocol.
pub unsafe fn wait(addr: *mut c_int, waiters: *mut c_int, val: c_int, priv_: c_int) {
    let op = FUTEX_WAIT | if priv_ != 0 { FUTEX_PRIVATE } else { 0 };
    unsafe {
        // __wait.c:5-10: spin while nobody is queued, then fall through
        // to the counting sleep. `a_spin` is arch-specific; the portable
        // spelling is `spin_loop`.
        let mut spins = 100;
        loop {
            if spins == 0 {
                break;
            }
            spins -= 1;
            if !waiters.is_null() && (*as_atomic(waiters)).load(Ordering::SeqCst) != 0 {
                break;
            }
            if core::ptr::read_volatile(addr) == val {
                core::hint::spin_loop();
            } else {
                return;
            }
        }
        if !waiters.is_null() {
            let _ = (*as_atomic(waiters)).fetch_add(1, Ordering::SeqCst);
        }
        // __wait.c:12-15: sleep while unchanged; a failed private op
        // retries as shared. Returns (EAGAIN/EINTR) just re-check.
        while core::ptr::read_volatile(addr) == val {
            let r = syscall4(SYS_FUTEX, addr as usize, op as usize, val as usize, 0);
            if r == -(ENOSYS as isize) {
                syscall4(
                    SYS_FUTEX,
                    addr as usize,
                    FUTEX_WAIT as usize,
                    val as usize,
                    0,
                );
            }
        }
        if !waiters.is_null() {
            let _ = (*as_atomic(waiters)).fetch_sub(1, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The op constants track musl `src/internal/futex.h:4-17`.
    #[test]
    fn futex_op_constants_match_musl() {
        assert_eq!(FUTEX_WAIT, 0);
        assert_eq!(FUTEX_WAKE, 1);
        assert_eq!(FUTEX_PRIVATE, 128);
        assert_eq!(FUTEX_CLOCK_REALTIME, 256);
    }

    /// `wait` returns at once when the word already differs (the
    /// `__wait.c:9` early-out), leaving a non-null `waiters` untouched.
    #[test]
    fn wait_returns_at_once_when_value_differs() {
        let word: c_int = 7;
        let waiters: c_int = 0;
        unsafe {
            crate::futex::wait(
                core::ptr::addr_of_mut!(word),
                core::ptr::addr_of_mut!(waiters),
                42,
                1,
            );
        }
        assert_eq!(waiters, 0);
    }
}
