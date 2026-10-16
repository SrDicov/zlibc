//! Pseudoterminals (musl `src/misc/pty.c`, `src/misc/ptsname.c`).
//!
//! `posix_openpt` passes `flags` straight to `open("/dev/ptmx")` and
//! maps `ENOSPC` to `EAGAIN`, exactly like musl. `grantpt` is musl's
//! stub returning 0 (devpts owns the slave nodes in the kernel).
//! `unlockpt` clears the pty lock via `TIOCSPTLCK`; `ptsname` formats
//! `"/dev/pts/N"` from the `TIOCGPTN` number with musl's `ERANGE`
//! overflow rule. All kernel talk is one raw `SYS_ioctl` trap through
//! the existing [`crate::termios::ioctl`].

use core::ffi::{c_char, c_int, c_ulong, c_void};

use crate::errno::{__errno_location, errno_load, errno_store};
use crate::fcntl::open;

// ---- Requests (musl arch/generic/bits/ioctl.h) ------------------------------
const TIOCGPTN: c_ulong = 0x80045430;
const TIOCSPTLCK: c_ulong = 0x40045431;

/// musl `include/errno.h` via `arch/generic/bits/errno.h` (local: only
/// this module needs these two; anything else rides on `syscall_ret`).
const ENOSPC: c_int = 28;
const EAGAIN: c_int = 11;
const ERANGE: c_int = 34;

/// musl `ptsname.c`: `static char buf[9 + sizeof(int)*3 + 1]`.
const PTSNAME_BUF: usize = 9 + 4 * 3 + 1;

/// Open a pty master (musl `posix_openpt`).
///
/// # Safety
///
/// `flags` go to `open` untouched. Returns a fd, or -1 with `errno`
/// set (`ENOSPC` is reported as `EAGAIN`, like musl).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_openpt(flags: c_int) -> c_int {
    unsafe {
        let fd = open(c"/dev/ptmx".as_ptr(), flags, 0);
        if fd < 0 && errno_load(__errno_location()) == ENOSPC {
            errno_store(__errno_location(), EAGAIN);
        }
        fd
    }
}

/// Prepare a pty slave (musl `grantpt`: always 0 — devpts handles
/// ownership in the kernel, so there is nothing to `chown`/`chmod`).
///
/// # Safety
///
/// `fd` must be open (it is ignored).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn grantpt(fd: c_int) -> c_int {
    let _ = fd;
    0
}

/// Unlock a pty pair (musl `unlockpt`: `TIOCSPTLCK` with 0).
///
/// # Safety
///
/// `fd` must be open.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn unlockpt(fd: c_int) -> c_int {
    unsafe {
        let mut unlock: c_int = 0;
        crate::termios::ioctl(
            fd,
            TIOCSPTLCK,
            core::ptr::addr_of_mut!(unlock) as *mut c_void,
        )
    }
}

/// Slave pathname into a caller buffer (musl `__ptsname_r`/`ptsname_r`:
/// `TIOCGPTN` number as `"/dev/pts/N"`; `ERANGE` when the rendering
/// does not fit, ioctl errno otherwise; null `buf` counts as zero
/// length, hence `ERANGE` after a successful ioctl).
///
/// # Safety
///
/// `buf` must be writable for `len` bytes (or null, which always fails
/// with `ERANGE` on a valid fd).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ptsname_r(fd: c_int, buf: *mut c_char, len: usize) -> c_int {
    unsafe {
        let mut pty: c_int = 0;
        if crate::termios::ioctl(fd, TIOCGPTN, core::ptr::addr_of_mut!(pty) as *mut c_void) < 0 {
            return errno_load(__errno_location());
        }
        if buf.is_null() {
            return ERANGE;
        }
        // musl `snprintf(buf, len, "/dev/pts/%d", pty)`: decimal with
        // sign, `need` chars excluding NUL, `ERANGE` when `need >= len`.
        let neg = pty < 0;
        let mut u = pty.unsigned_abs();
        let mut digits: usize = 0;
        loop {
            digits = digits.wrapping_add(1);
            u = u.wrapping_div(10);
            if u == 0 {
                break;
            }
        }
        let need = 9usize.wrapping_add(digits).wrapping_add(neg as usize);
        if need >= len {
            return ERANGE;
        }
        let prefix = b"/dev/pts/";
        let mut i = 0;
        while i < prefix.len() {
            *buf.add(i) = prefix[i] as c_char;
            i = i.wrapping_add(1);
        }
        if neg {
            *buf.add(i) = b'-' as c_char;
            i = i.wrapping_add(1);
        }
        let mut j = i.wrapping_add(digits);
        *buf.add(j) = 0;
        let mut w = pty.unsigned_abs();
        while j != i {
            j = j.wrapping_sub(1);
            *buf.add(j) = b'0'.wrapping_add(w.wrapping_rem(10) as u8) as c_char;
            w = w.wrapping_div(10);
        }
        0
    }
}

/// Slave pathname in a shared static buffer (musl `ptsname`).
///
/// # Safety
///
/// `fd` must be open. The returned pointer is valid until the next
/// `ptsname` call in the process; do not free it.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ptsname(fd: c_int) -> *mut c_char {
    static mut BUF: [c_char; PTSNAME_BUF] = [0; PTSNAME_BUF];
    unsafe {
        let buf = core::ptr::addr_of_mut!(BUF).cast::<c_char>();
        let err = ptsname_r(fd, buf, PTSNAME_BUF);
        if err != 0 {
            errno_store(__errno_location(), err);
            return core::ptr::null_mut();
        }
        buf
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::{grantpt, posix_openpt, ptsname, ptsname_r, unlockpt};
    use core::ffi::c_int;

    use crate::errno::{__errno_location, errno_load};
    use crate::syscall::{syscall3, syscall_ret};

    /// musl `arch/generic/bits/fcntl.h` (test open flags only).
    const O_NOCTTY: c_int = 0o400;
    /// musl `arch/x86_64/bits/syscall.h.in` (test cleanup only).
    const SYS_CLOSE: usize = 3; // TODO: generate from arch bits/syscall.h

    unsafe fn close(fd: c_int) {
        unsafe {
            let _ = syscall_ret(syscall3(SYS_CLOSE, fd as usize, 0, 0));
        }
    }

    /// musl `include/errno.h`: bad-fd trap errno.
    const EBADF: c_int = 9;

    /// Invalid fds fail without touching the pty layer: `ptsname`
    /// reports null + `errno`, `ptsname_r`/`unlockpt` the error, while
    /// musl's `grantpt` stub still returns 0.
    #[test]
    fn bad_fd_fails_cleanly() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            assert!(ptsname(-1).is_null());
            assert_eq!(errno_load(__errno_location()), EBADF);
            let mut buf = [0 as core::ffi::c_char; 64];
            assert_eq!(ptsname_r(-1, buf.as_mut_ptr(), 64), EBADF);
            assert_eq!(unlockpt(-1), -1);
            assert_eq!(errno_load(__errno_location()), EBADF);
            assert_eq!(grantpt(-1), 0);
        }
    }

    /// Full `posix_openpt → grantpt → unlockpt → ptsname` chain, with
    /// `ptsname_r` agreement and the `ERANGE` edge. Skips (never fails)
    /// when `/dev/ptmx` is absent.
    #[test]
    fn master_slave_chain_when_ptmx_present() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let fd = posix_openpt(crate::fcntl::O_RDWR | O_NOCTTY);
            if fd < 0 {
                return;
            }
            assert_eq!(grantpt(fd), 0);
            assert_eq!(unlockpt(fd), 0);
            let name = ptsname(fd);
            assert!(!name.is_null());
            // Shape "/dev/pts/N": prefix literal, digits, NUL.
            let prefix = b"/dev/pts/";
            let mut i = 0;
            while i < 64 && *name.add(i) != 0 {
                i = i.wrapping_add(1);
            }
            assert!(*name.add(i) == 0 && i > prefix.len());
            let mut k = 0;
            while k < prefix.len() {
                assert_eq!(*name.add(k), prefix[k] as core::ffi::c_char);
                k = k.wrapping_add(1);
            }
            while k < i {
                let c = *name.add(k);
                assert!(c >= b'0' as core::ffi::c_char && c <= b'9' as core::ffi::c_char);
                k = k.wrapping_add(1);
            }
            // `ptsname_r` agrees byte-for-byte, `ERANGE` on a 4-byte buf.
            let mut buf = [0 as core::ffi::c_char; 64];
            assert_eq!(ptsname_r(fd, buf.as_mut_ptr(), 64), 0);
            let mut k = 0;
            loop {
                assert_eq!(buf[k], *name.add(k));
                if buf[k] == 0 {
                    break;
                }
                k = k.wrapping_add(1);
            }
            let mut tiny = [0 as core::ffi::c_char; 4];
            assert_eq!(ptsname_r(fd, tiny.as_mut_ptr(), 4), super::ERANGE);
            close(fd);
        }
    }
}
