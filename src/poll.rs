//! I/O multiplexing (musl `src/select/select.c`, `pselect.c`, `poll.c`, `ppoll.c`).
//!
//! Thin wrappers over the raw traps, exactly musl's ABI boundary: `select`
//! goes through `SYS_select` with a `timeval`, `pselect` through
//! `SYS_pselect6` with a `timespec` plus the `{mask, len}` pair, `poll`
//! through `SYS_poll`, `ppoll` through `SYS_ppoll`. Like the rest of this
//! crate there is no cancellation-point handling (musl's `syscall_cp`
//! dance); blocking here is plain blocking, same as `src/net.rs`.
//!
//! `sigset_t` is reused from [`crate::signal`]; the kernel only reads its
//! first 8 bytes (`_NSIG/8`). `Timespec` is local: the clocks wave owns the
//! public one, merge on contact.

use core::ffi::{c_int, c_long, c_ulong};

use crate::syscall::{syscall3, syscall5, syscall6, syscall_ret};

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_POLL: usize = 7; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_SELECT: usize = 23; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_PSELECT6: usize = 270; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_PPOLL: usize = 271; // TODO: generate from arch bits/syscall.h

/// musl `EINVAL` (`include/errno.h`).
#[cfg(target_arch = "x86_64")]
const EINVAL: c_int = 22;

/// Kernel signal-mask length (`_NSIG/8`, `_NSIG` is 65 on x86_64 per
/// `arch/x86_64/bits/signal.h:152`; `65/8` truncates to 8).
#[cfg(target_arch = "x86_64")]
const K_SIGSET_LEN: usize = 8;

/// musl `FD_SETSIZE` (`include/sys/select.h:18`).
#[cfg(target_arch = "x86_64")]
pub const FD_SETSIZE: c_int = 1024;

/// musl `fd_set` on 64-bit (`include/sys/select.h:22-24`): 1024 bits as
/// 16 `u64` words (`unsigned long fds_bits[16]`).
#[cfg(target_arch = "x86_64")]
#[allow(non_camel_case_types)]
pub type fd_set = [u64; 16];

/// Local `struct timespec` (clocks wave owns the public one; note the
/// future merge). Field order matches musl: seconds, nanoseconds.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Timespec {
    pub tv_sec: c_long,
    pub tv_nsec: c_long,
}

/// musl `struct pollfd` (`include/poll.h:31-35`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Pollfd {
    pub fd: c_int,
    pub events: i16,
    pub revents: i16,
}

// musl `include/poll.h:12-17`.
#[cfg(target_arch = "x86_64")]
pub const POLLIN: i16 = 0x001;
#[cfg(target_arch = "x86_64")]
pub const POLLPRI: i16 = 0x002;
#[cfg(target_arch = "x86_64")]
pub const POLLOUT: i16 = 0x004;
#[cfg(target_arch = "x86_64")]
pub const POLLERR: i16 = 0x008;
#[cfg(target_arch = "x86_64")]
pub const POLLHUP: i16 = 0x010;
#[cfg(target_arch = "x86_64")]
pub const POLLNVAL: i16 = 0x020;

#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<Pollfd>() == 8);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<Timespec>() == 16);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<fd_set>() == 128);

/// Clear a set (musl `FD_ZERO`, `include/sys/select.h:26`).
///
/// # Safety
///
/// `set` must point to a writable [`fd_set`].
#[cfg(target_arch = "x86_64")]
#[allow(non_snake_case)]
pub unsafe fn FD_ZERO(set: *mut fd_set) {
    unsafe {
        *set = [0; 16];
    }
}

/// Add a fd (musl `FD_SET`, `include/sys/select.h:27`): word `d/64`,
/// bit `d%64`.
///
/// # Safety
///
/// `set` must point to a writable [`fd_set`] and `fd` must satisfy
/// `0 <= fd < FD_SETSIZE`.
#[cfg(target_arch = "x86_64")]
#[allow(non_snake_case)]
pub unsafe fn FD_SET(fd: c_int, set: *mut fd_set) {
    unsafe {
        let d = fd as usize;
        (*set)[d.wrapping_div(64)] |= 1u64.wrapping_shl(d.wrapping_rem(64) as u32);
    }
}

/// Remove a fd (musl `FD_CLR`, `include/sys/select.h:28`).
///
/// # Safety
///
/// Same contract as [`FD_SET`].
#[cfg(target_arch = "x86_64")]
#[allow(non_snake_case)]
pub unsafe fn FD_CLR(fd: c_int, set: *mut fd_set) {
    unsafe {
        let d = fd as usize;
        (*set)[d.wrapping_div(64)] &= !1u64.wrapping_shl(d.wrapping_rem(64) as u32);
    }
}

/// Test a fd (musl `FD_ISSET`, `include/sys/select.h:29`).
///
/// # Safety
///
/// `set` must point to a readable [`fd_set`] and `fd` must satisfy
/// `0 <= fd < FD_SETSIZE`.
#[cfg(target_arch = "x86_64")]
#[allow(non_snake_case)]
pub unsafe fn FD_ISSET(fd: c_int, set: *const fd_set) -> c_int {
    unsafe {
        let d = fd as usize;
        (((*set)[d.wrapping_div(64)] >> d.wrapping_rem(64)) & 1) as c_int
    }
}

/// Wait on fd sets with a `timeval` timeout (musl `select.c`).
///
/// Negative `tv_sec`/`tv_usec` fails with `EINVAL` before any trap, and an
/// overflowing timeout clamps to musl's `max_time`, both exactly like musl.
/// `nfds < 0` or `nfds > FD_SETSIZE` fails with `EINVAL` (what the kernel
/// reports for those; musl itself passes them through). A null `timeout`
/// waits indefinitely; null sets are passed through (the kernel treats a
/// null set as empty). The caller's `timeout` is never updated: musl passes
/// a stack copy to the trap, and so do we.
///
/// # Safety
///
/// Each non-null set pointer must point to a readable/writable [`fd_set`]
/// covering `nfds` bits; `timeout`, when non-null, must point to a readable
/// [`crate::process::Timeval`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn select(
    nfds: c_int,
    readfds: *mut fd_set,
    writefds: *mut fd_set,
    exceptfds: *mut fd_set,
    timeout: *mut crate::process::Timeval,
) -> c_int {
    unsafe {
        if !(0..=FD_SETSIZE).contains(&nfds) {
            return syscall_ret(-(EINVAL as isize)) as c_int;
        }
        // musl `select.c:12-26`: split tv, reject negatives, clamp overflow.
        let max_time: c_long = c_long::MAX.wrapping_sub(1);
        let tvp = if timeout.is_null() {
            0
        } else {
            let s = (*timeout).tv_sec;
            let us = (*timeout).tv_usec;
            if s < 0 || us < 0 {
                return syscall_ret(-(EINVAL as isize)) as c_int;
            }
            let tv = if us.wrapping_div(1_000_000) > max_time.wrapping_sub(s) {
                [max_time, 999_999]
            } else {
                [
                    s.wrapping_add(us.wrapping_div(1_000_000)),
                    us.wrapping_rem(1_000_000),
                ]
            };
            &tv as *const [c_long; 2] as usize
        };
        syscall_ret(syscall5(
            SYS_SELECT,
            nfds as usize,
            readfds as usize,
            writefds as usize,
            exceptfds as usize,
            tvp,
        )) as c_int
    }
}

/// Wait on fd sets with a `timespec` timeout and signal mask (musl
/// `pselect.c`). The mask pair passed to the trap is `{mask, 8}`: a null
/// mask leaves the signal mask alone, and the kernel only reads the first
/// 8 bytes of a non-null one. `nfds` validation and null-set handling are
/// the same as [`select`].
///
/// # Safety
///
/// Same set/`nfds` contract as [`select`]; `timeout`, when non-null, must
/// point to a readable [`Timespec`]; `sigmask`, when non-null, must point
/// to a readable [`crate::signal::sigset_t`] (only the first 8 bytes are
/// read, like musl).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn pselect(
    nfds: c_int,
    readfds: *mut fd_set,
    writefds: *mut fd_set,
    exceptfds: *mut fd_set,
    timeout: *const Timespec,
    sigmask: *const crate::signal::sigset_t,
) -> c_int {
    unsafe {
        if !(0..=FD_SETSIZE).contains(&nfds) {
            return syscall_ret(-(EINVAL as isize)) as c_int;
        }
        // musl `pselect.c:12-13`: stack timespec copy, `{mask, _NSIG/8}`.
        let ts = if timeout.is_null() {
            [0 as c_long, 0]
        } else {
            [(*timeout).tv_sec, (*timeout).tv_nsec]
        };
        let tsp = if timeout.is_null() {
            0
        } else {
            &ts as *const [c_long; 2] as usize
        };
        let data: [usize; 2] = [sigmask as usize, K_SIGSET_LEN];
        syscall_ret(syscall6(
            SYS_PSELECT6,
            nfds as usize,
            readfds as usize,
            writefds as usize,
            exceptfds as usize,
            tsp,
            &data as *const [usize; 2] as usize,
        )) as c_int
    }
}

/// Wait on pollfds with a millisecond timeout (musl `poll.c`): one
/// `SYS_poll` trap. A negative `timeout` waits indefinitely; the timeout
/// is passed through untouched, so a null/empty `fds` with `nfds == 0`
/// just sleeps.
///
/// # Safety
///
/// `fds`, when non-null, must point to `nfds` writable [`Pollfd`]s.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn poll(fds: *mut Pollfd, nfds: c_ulong, timeout: c_int) -> c_int {
    unsafe {
        syscall_ret(syscall3(
            SYS_POLL,
            fds as usize,
            nfds as usize,
            timeout as usize,
        )) as c_int
    }
}

/// Wait on pollfds with a `timespec` timeout and signal mask (musl
/// `ppoll.c`): one `SYS_ppoll` trap with the kernel mask length 8.
/// Timeout validation is the kernel's (`EINVAL` on negative seconds or an
/// out-of-range nanosecond field); musl validates nothing itself, neither
/// do we.
///
/// # Safety
///
/// `fds`, when non-null, must point to `nfds` writable [`Pollfd`]s;
/// `timeout`, when non-null, must point to a readable [`Timespec`];
/// `sigmask` follows the [`pselect`] contract.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ppoll(
    fds: *mut Pollfd,
    nfds: c_ulong,
    timeout: *const Timespec,
    sigmask: *const crate::signal::sigset_t,
) -> c_int {
    unsafe {
        // musl `ppoll.c:12-13,24-25`: stack timespec copy, raw mask + len.
        let ts = if timeout.is_null() {
            [0 as c_long, 0]
        } else {
            [(*timeout).tv_sec, (*timeout).tv_nsec]
        };
        let tsp = if timeout.is_null() {
            0
        } else {
            &ts as *const [c_long; 2] as usize
        };
        syscall_ret(syscall5(
            SYS_PPOLL,
            fds as usize,
            nfds as usize,
            tsp,
            sigmask as usize,
            K_SIGSET_LEN,
        )) as c_int
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use core::ffi::{c_int, c_void};

    use super::{ppoll, pselect, select, Timespec, FD_CLR, FD_ISSET, FD_SET, FD_ZERO, POLLIN};
    use crate::errno::{__errno_location, errno_load};
    use crate::process::Timeval;
    use crate::unistd::{close, pipe, read, write};

    unsafe fn mkpipe() -> [c_int; 2] {
        unsafe {
            let mut fds = [0 as c_int; 2];
            assert_eq!(pipe(fds.as_mut_ptr()), 0);
            fds
        }
    }

    #[test]
    fn fd_macros_match_musl_bit_logic() {
        unsafe {
            let mut set: super::fd_set = [0; 16];
            FD_ZERO(&mut set as *mut _);
            assert!(set.iter().all(|&w| w == 0));
            FD_SET(0, &mut set as *mut _);
            FD_SET(63, &mut set as *mut _);
            FD_SET(64, &mut set as *mut _);
            FD_SET(1023, &mut set as *mut _);
            assert_eq!(set[0], (1u64 << 0) | (1u64 << 63));
            assert_eq!(set[1], 1);
            assert_eq!(set[15], 1u64 << 63);
            assert_eq!(FD_ISSET(0, &set as *const _), 1);
            assert_eq!(FD_ISSET(1, &set as *const _), 0);
            assert_eq!(FD_ISSET(1023, &set as *const _), 1);
            FD_CLR(63, &mut set as *mut _);
            assert_eq!(FD_ISSET(63, &set as *const _), 0);
            assert_eq!(FD_ISSET(0, &set as *const _), 1);
        }
    }

    #[test]
    fn select_rejects_bad_nfds_and_timeval() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut tv = Timeval {
                tv_sec: -1,
                tv_usec: 0,
            };
            assert_eq!(
                select(
                    -1,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut()
                ),
                -1
            );
            assert_eq!(errno_load(__errno_location()), 22);
            assert_eq!(
                select(
                    1025,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut()
                ),
                -1
            );
            assert_eq!(errno_load(__errno_location()), 22);
            assert_eq!(
                select(
                    0,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    &mut tv as *mut _
                ),
                -1
            );
            assert_eq!(errno_load(__errno_location()), 22);
        }
    }

    #[test]
    fn poll_sees_pipe_write() {
        unsafe {
            let fds = mkpipe();
            let msg = b"x";
            assert_eq!(write(fds[1], msg.as_ptr() as *const c_void, msg.len()), 1);
            let mut pfd = super::Pollfd {
                fd: fds[0],
                events: POLLIN,
                revents: 0,
            };
            assert_eq!(super::poll(&mut pfd as *mut _, 1, 0), 1);
            assert!(pfd.revents & POLLIN != 0);
            let mut back = [0u8; 1];
            assert_eq!(read(fds[0], back.as_mut_ptr() as *mut c_void, 1), 1);
            assert_eq!(close(fds[0]), 0);
            assert_eq!(close(fds[1]), 0);
        }
    }

    #[test]
    fn poll_empty_pipe_timeout_zero_returns_zero() {
        unsafe {
            let fds = mkpipe();
            let mut pfd = super::Pollfd {
                fd: fds[0],
                events: POLLIN,
                revents: 0,
            };
            assert_eq!(super::poll(&mut pfd as *mut _, 1, 0), 0);
            assert_eq!(close(fds[0]), 0);
            assert_eq!(close(fds[1]), 0);
        }
    }

    #[test]
    fn select_read_set_ready() {
        unsafe {
            let fds = mkpipe();
            let msg = b"y";
            assert_eq!(write(fds[1], msg.as_ptr() as *const c_void, msg.len()), 1);
            let mut set: super::fd_set = [0; 16];
            FD_ZERO(&mut set as *mut _);
            FD_SET(fds[0], &mut set as *mut _);
            let mut tv = Timeval {
                tv_sec: 0,
                tv_usec: 0,
            };
            assert_eq!(
                select(
                    fds[0] + 1,
                    &mut set as *mut _,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    &mut tv as *mut _
                ),
                1
            );
            assert_eq!(FD_ISSET(fds[0], &set as *const _), 1);
            let mut back = [0u8; 1];
            assert_eq!(read(fds[0], back.as_mut_ptr() as *mut c_void, 1), 1);
            assert_eq!(close(fds[0]), 0);
            assert_eq!(close(fds[1]), 0);
        }
    }

    #[test]
    fn pselect_null_mask_ready() {
        unsafe {
            let fds = mkpipe();
            let msg = b"z";
            assert_eq!(write(fds[1], msg.as_ptr() as *const c_void, msg.len()), 1);
            let mut set: super::fd_set = [0; 16];
            FD_ZERO(&mut set as *mut _);
            FD_SET(fds[0], &mut set as *mut _);
            let ts = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            assert_eq!(
                pselect(
                    fds[0] + 1,
                    &mut set as *mut _,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    &ts as *const _,
                    core::ptr::null()
                ),
                1
            );
            assert_eq!(FD_ISSET(fds[0], &set as *const _), 1);
            let mut back = [0u8; 1];
            assert_eq!(read(fds[0], back.as_mut_ptr() as *mut c_void, 1), 1);
            assert_eq!(close(fds[0]), 0);
            assert_eq!(close(fds[1]), 0);
        }
    }

    #[test]
    fn ppoll_zero_timeout_on_empty_pipe() {
        unsafe {
            let fds = mkpipe();
            let mut pfd = super::Pollfd {
                fd: fds[0],
                events: POLLIN,
                revents: 0,
            };
            let ts = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            assert_eq!(
                ppoll(&mut pfd as *mut _, 1, &ts as *const _, core::ptr::null()),
                0
            );
            assert_eq!(close(fds[0]), 0);
            assert_eq!(close(fds[1]), 0);
        }
    }
}
