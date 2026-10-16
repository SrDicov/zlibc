//! POSIX unistd wrappers (musl `src/unistd/*`): thin syscalls, musl's error map.
//!
//! Each entry is one raw trap returning through `syscall_ret` (stores the
//! calling thread's errno, returns -1 on error) — musl's ABI-boundary
//! contract — except where musl itself remaps an error, which is mirrored
//! verbatim: `close` turns `EINTR` into success (`close.c`), `pwrite`
//! turns an `O_APPEND` target into `EOPNOTSUPP` (`pwrite.c`). Cancellation
//! points (`syscall_cp` in musl) collapse to plain traps: no cancellation
//! exists, same as `crate::net`. The `__aio_close` hook in `close` is the
//! default identity (aio is another wave).

use core::ffi::{c_int, c_long, c_uint, c_void};

use crate::syscall::{syscall0, syscall1, syscall2, syscall3, syscall4, syscall6, syscall_ret};

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_READ: usize = 0; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_WRITE: usize = 1; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_CLOSE: usize = 3; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_LSEEK: usize = 8; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_PREAD: usize = 17; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_PWRITE: usize = 18; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_READV: usize = 19; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_WRITEV: usize = 20; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_PIPE: usize = 22; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_DUP: usize = 32; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_DUP2: usize = 33; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_PAUSE: usize = 34; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_NANOSLEEP: usize = 35; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_GETPID: usize = 39; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_FCNTL: usize = 72; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_GETUID: usize = 102; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_GETGID: usize = 104; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_GETEUID: usize = 107; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_GETEGID: usize = 108; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_GETPPID: usize = 110; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_DUP3: usize = 292; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_PIPE2: usize = 293; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_PWRITEV2: usize = 328; // TODO: generate from arch bits/syscall.h

// ---- Local errno/flag values (musl arch/generic/bits/errno.h, ----------
// ---- arch/generic/bits/fcntl.h, include/sys/uio.h, include/fcntl.h) ------
#[cfg(target_arch = "x86_64")]
const EINTR: c_int = 4;
#[cfg(target_arch = "x86_64")]
const EBUSY: c_int = 16;
#[cfg(target_arch = "x86_64")]
const EINVAL: c_int = 22;
#[cfg(target_arch = "x86_64")]
const ENOSYS: c_int = 38;
#[cfg(target_arch = "x86_64")]
const EOPNOTSUPP: c_int = 95;
#[cfg(target_arch = "x86_64")]
const O_APPEND: c_int = 0o2000;
#[cfg(target_arch = "x86_64")]
const O_CLOEXEC: c_int = 0o2000000;
#[cfg(target_arch = "x86_64")]
const F_GETFL: c_int = 3;
#[cfg(target_arch = "x86_64")]
const F_SETFD: c_int = 2;
#[cfg(target_arch = "x86_64")]
const FD_CLOEXEC: c_int = 1;
#[cfg(target_arch = "x86_64")]
const RWF_NOAPPEND: c_int = 0x20;

/// musl `struct iovec` (`include/sys/uio.h:26-29`).
#[repr(C)]
pub struct Iovec {
    pub base: *mut c_void,
    pub len: usize,
}

/// Private `struct timespec` for the raw `nanosleep` traps behind
/// `sleep`/`usleep` (clocks belong to another wave; this never leaves).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct Timespec {
    sec: c_long,
    nsec: c_long,
}

/// musl `SEEK_SET` (`include/stdio.h:42`).
pub const SEEK_SET: c_int = 0;
/// musl `SEEK_CUR` (`include/stdio.h:43`).
pub const SEEK_CUR: c_int = 1;
/// musl `SEEK_END` (`include/stdio.h:44`).
pub const SEEK_END: c_int = 2;

/// Read bytes (musl `read`).
///
/// # Safety
///
/// `buf` must be writable for `n` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize {
    unsafe { syscall_ret(syscall3(SYS_READ, fd as usize, buf as usize, n)) }
}

/// Write bytes (musl `write`).
///
/// # Safety
///
/// `buf` must be readable for `n` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn write(fd: c_int, buf: *const c_void, n: usize) -> isize {
    unsafe { syscall_ret(syscall3(SYS_WRITE, fd as usize, buf as usize, n)) }
}

/// Positional read (musl `pread`; `SYS_pread` is `SYS_pread64` on x86_64,
/// `src/internal/syscall.h:187`, so the offset is one word).
///
/// # Safety
///
/// `buf` must be writable for `n` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn pread(fd: c_int, buf: *mut c_void, n: usize, off: i64) -> isize {
    unsafe {
        syscall_ret(syscall4(
            SYS_PREAD,
            fd as usize,
            buf as usize,
            n,
            off as usize,
        ))
    }
}

/// Positional write (musl `pwrite`: `pwritev2` with `RWF_NOAPPEND` first,
/// `EOPNOTSUPP` on `O_APPEND` targets, `SYS_pwrite` fallback).
///
/// The `fcntl` probe is a raw `SYS_fcntl` trap, not the libc wrapper
/// (that wrapper is another wave's); observable behavior is identical.
///
/// # Safety
///
/// `buf` must be readable for `n` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn pwrite(fd: c_int, buf: *const c_void, n: usize, off: i64) -> isize {
    unsafe {
        let mut pos = off;
        if pos == -1 {
            pos = pos.wrapping_sub(1);
        }
        let iov = Iovec {
            base: buf as *mut c_void,
            len: n,
        };
        let r = syscall6(
            SYS_PWRITEV2,
            fd as usize,
            &iov as *const Iovec as usize,
            1,
            pos as usize,
            (pos >> 32) as usize,
            RWF_NOAPPEND as usize,
        );
        if r != -(EOPNOTSUPP as isize) && r != -(ENOSYS as isize) {
            return syscall_ret(r);
        }
        let flags = syscall_ret(syscall3(SYS_FCNTL, fd as usize, F_GETFL as usize, 0));
        if (flags & O_APPEND as isize) != 0 {
            return syscall_ret(-(EOPNOTSUPP as isize));
        }
        syscall_ret(syscall4(
            SYS_PWRITE,
            fd as usize,
            buf as usize,
            n,
            pos as usize,
        ))
    }
}

/// Scatter read (musl `readv`).
///
/// # Safety
///
/// `iov` must point to `n` valid elements with writable segments.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn readv(fd: c_int, iov: *const Iovec, n: c_int) -> isize {
    unsafe { syscall_ret(syscall3(SYS_READV, fd as usize, iov as usize, n as usize)) }
}

/// Scatter write (musl `writev`).
///
/// # Safety
///
/// `iov` must point to `n` valid elements with readable segments.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn writev(fd: c_int, iov: *const Iovec, n: c_int) -> isize {
    unsafe { syscall_ret(syscall3(SYS_WRITEV, fd as usize, iov as usize, n as usize)) }
}

/// Reposition the file offset (musl `lseek`; x86_64 has no `SYS__llseek`,
/// so this is one `SYS_lseek` trap).
///
/// # Safety
///
/// `fd` must be open; behavior on pipes/sockets is the kernel's `ESPIPE`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn lseek(fd: c_int, off: i64, whence: c_int) -> i64 {
    unsafe {
        syscall_ret(syscall3(
            SYS_LSEEK,
            fd as usize,
            off as usize,
            whence as usize,
        )) as i64
    }
}

/// Duplicate onto the lowest free fd (musl `dup`: one `SYS_dup` trap,
/// i.e. `fcntl(fd, F_DUPFD, 0)`).
///
/// # Safety
///
/// `fd` must be open.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn dup(fd: c_int) -> c_int {
    unsafe { syscall_ret(syscall1(SYS_DUP, fd as usize)) as c_int }
}

/// Duplicate onto a chosen fd (musl `dup2`: x86_64 has `SYS_dup2`, so the
/// `EBUSY` loop around that trap; same-fd success comes from the kernel).
///
/// # Safety
///
/// `old` must be open; `new` is closed first when valid and different.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn dup2(old: c_int, new: c_int) -> c_int {
    unsafe {
        let mut r;
        loop {
            r = syscall2(SYS_DUP2, old as usize, new as usize);
            if r != -(EBUSY as isize) {
                break;
            }
        }
        syscall_ret(r) as c_int
    }
}

/// Duplicate with flags (musl `__dup3`: `EINVAL` on same-fd, `SYS_dup3`
/// loop while flags are set with the `ENOSYS` fallback onto `SYS_dup2`,
/// `O_CLOEXEC` applied by raw `SYS_fcntl`, not the other wave's wrapper).
///
/// # Safety
///
/// Same contract as [`dup2`]; `flags` may only carry `O_CLOEXEC`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn dup3(old: c_int, new: c_int, flags: c_int) -> c_int {
    unsafe {
        if old == new {
            return syscall_ret(-(EINVAL as isize)) as c_int;
        }
        if flags != 0 {
            let mut r;
            loop {
                r = syscall3(SYS_DUP3, old as usize, new as usize, flags as usize);
                if r != -(EBUSY as isize) {
                    break;
                }
            }
            if r != -(ENOSYS as isize) {
                return syscall_ret(r) as c_int;
            }
            if (flags & !O_CLOEXEC) != 0 {
                return syscall_ret(-(EINVAL as isize)) as c_int;
            }
        }
        let mut r;
        loop {
            r = syscall2(SYS_DUP2, old as usize, new as usize);
            if r != -(EBUSY as isize) {
                break;
            }
        }
        if r >= 0 && (flags & O_CLOEXEC) != 0 {
            syscall3(
                SYS_FCNTL,
                new as usize,
                F_SETFD as usize,
                FD_CLOEXEC as usize,
            );
        }
        syscall_ret(r) as c_int
    }
}

/// Create a pipe (musl `pipe`: x86_64 has `SYS_pipe`).
///
/// # Safety
///
/// `fds` must hold two writable ints.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn pipe(fds: *mut c_int) -> c_int {
    unsafe { syscall_ret(syscall1(SYS_PIPE, fds as usize)) as c_int }
}

/// Create a pipe with flags (musl `pipe2`: flagless defers to [`pipe`];
/// the `ENOSYS`+`fcntl` fallback is dead on x86_64 — `SYS_pipe2` is
/// always present and the kernel validates flags itself).
///
/// # Safety
///
/// Same contract as [`pipe`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn pipe2(fds: *mut c_int, flags: c_int) -> c_int {
    unsafe {
        if flags == 0 {
            return pipe(fds);
        }
        syscall_ret(syscall2(SYS_PIPE2, fds as usize, flags as usize)) as c_int
    }
}

/// Close a fd (musl `close`: `EINTR` counts as success; the `__aio_close`
/// hook is its default identity — aio is another wave).
///
/// # Safety
///
/// `fd` must be open; closing twice races like in C.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn close(fd: c_int) -> c_int {
    unsafe {
        let r = syscall1(SYS_CLOSE, fd as usize);
        if r == -(EINTR as isize) {
            return 0;
        }
        syscall_ret(r) as c_int
    }
}

/// Own pid (musl `getpid`: raw trap, never fails).
///
/// # Safety
///
/// Pure syscall wrapper; no pointers involved.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getpid() -> c_int {
    unsafe { syscall0(SYS_GETPID) as c_int }
}

/// Parent pid (musl `getppid`: raw trap, never fails).
///
/// # Safety
///
/// Pure syscall wrapper; no pointers involved.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getppid() -> c_int {
    unsafe { syscall0(SYS_GETPPID) as c_int }
}

/// Real uid (musl `getuid`: raw trap, never fails).
///
/// # Safety
///
/// Pure syscall wrapper; no pointers involved.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getuid() -> c_int {
    unsafe { syscall0(SYS_GETUID) as c_int }
}

/// Effective uid (musl `geteuid`: raw trap, never fails).
///
/// # Safety
///
/// Pure syscall wrapper; no pointers involved.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn geteuid() -> c_int {
    unsafe { syscall0(SYS_GETEUID) as c_int }
}

/// Real gid (musl `getgid`: raw trap, never fails).
///
/// # Safety
///
/// Pure syscall wrapper; no pointers involved.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getgid() -> c_int {
    unsafe { syscall0(SYS_GETGID) as c_int }
}

/// Effective gid (musl `getegid`: raw trap, never fails).
///
/// # Safety
///
/// Pure syscall wrapper; no pointers involved.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getegid() -> c_int {
    unsafe { syscall0(SYS_GETEGID) as c_int }
}

/// Sleep in seconds, returning the unslept remainder (musl `sleep.c`:
/// one `Timespec` doubling as request and remainder across the raw
/// `nanosleep` loop; no clock wrapper involved).
///
/// # Safety
///
/// Pure syscall wrapper; no pointers involved.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sleep(secs: c_uint) -> c_uint {
    unsafe {
        let mut tv = Timespec {
            sec: secs as c_long,
            nsec: 0,
        };
        let p = &mut tv as *mut Timespec;
        loop {
            let r = syscall2(SYS_NANOSLEEP, p as usize, p as usize);
            if r == 0 {
                return 0;
            }
            if r != -(EINTR as isize) {
                return tv.sec as c_uint;
            }
        }
    }
}

/// Sleep in microseconds (musl `usleep.c`: one raw `nanosleep`, no retry).
///
/// # Safety
///
/// Pure syscall wrapper; no pointers involved.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn usleep(usecs: c_uint) -> c_int {
    unsafe {
        let mut tv = Timespec {
            sec: (usecs / 1_000_000) as c_long,
            nsec: ((usecs % 1_000_000) * 1000) as c_long,
        };
        let p = &mut tv as *mut Timespec;
        syscall_ret(syscall2(SYS_NANOSLEEP, p as usize, p as usize)) as c_int
    }
}

/// Wait for a signal (musl `pause`: x86_64 has `SYS_pause`, so one trap
/// that always comes back `EINTR`, i.e. `-1` through `syscall_ret`).
///
/// # Safety
///
/// Pure syscall wrapper; blocks until a caught signal arrives.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn pause() -> c_int {
    unsafe { syscall_ret(syscall0(SYS_PAUSE)) as c_int }
}

#[cfg(test)]
mod tests {
    use core::ffi::{c_int, c_void};

    use super::*;
    use crate::syscall::syscall_ret;

    #[test]
    fn pipe_write_read_roundtrip() {
        unsafe {
            let mut fds = [0 as c_int; 2];
            assert_eq!(pipe(fds.as_mut_ptr()), 0);
            let msg = b"ping";
            assert_eq!(
                write(fds[1], msg.as_ptr() as *const c_void, msg.len()),
                msg.len() as isize
            );
            let mut back = [0u8; 8];
            assert_eq!(
                read(fds[0], back.as_mut_ptr() as *mut c_void, back.len()),
                msg.len() as isize
            );
            assert_eq!(&back[..msg.len()], msg);
            assert_eq!(close(fds[0]), 0);
            assert_eq!(close(fds[1]), 0);
        }
    }

    #[test]
    fn dup2_shares_pipe_description() {
        unsafe {
            let mut p = [0 as c_int; 2];
            assert_eq!(pipe(p.as_mut_ptr()), 0);
            let spare = dup(p[1]);
            assert!(spare >= 0);
            assert_eq!(dup2(p[1], spare), spare);
            assert_eq!(dup2(p[0], p[0]), p[0]);
            let msg = b"dup";
            assert_eq!(
                write(spare, msg.as_ptr() as *const c_void, msg.len()),
                msg.len() as isize
            );
            let mut back = [0u8; 8];
            assert_eq!(
                read(p[0], back.as_mut_ptr() as *mut c_void, back.len()),
                msg.len() as isize
            );
            assert_eq!(&back[..msg.len()], msg);
            let spare2 = dup3(p[0], spare, 0);
            assert_eq!(spare2, spare);
            assert_eq!(dup3(p[0], p[0], 0), -1);
            assert_eq!(close(p[0]), 0);
            assert_eq!(close(p[1]), 0);
            assert_eq!(close(spare), 0);
        }
    }

    #[test]
    fn pread_pwrite_lseek_on_memfd() {
        use crate::syscall::syscall2;
        const SYS_MEMFD_CREATE: usize = 319; // TODO: generate from arch bits/syscall.h
        unsafe {
            let name = b"zlibc-unistd\0";
            let fd = syscall_ret(syscall2(SYS_MEMFD_CREATE, name.as_ptr() as usize, 0)) as c_int;
            assert!(fd >= 0);
            let msg = b"hello";
            assert_eq!(
                write(fd, msg.as_ptr() as *const c_void, msg.len()),
                msg.len() as isize
            );
            assert_eq!(lseek(fd, 0, SEEK_SET), 0);
            let mut back = [0u8; 8];
            assert_eq!(
                pread(fd, back.as_mut_ptr() as *mut c_void, msg.len(), 0),
                msg.len() as isize
            );
            assert_eq!(&back[..msg.len()], msg);
            let patch = b"XY";
            assert_eq!(
                pwrite(fd, patch.as_ptr() as *const c_void, patch.len(), 1),
                patch.len() as isize
            );
            assert_eq!(
                pread(fd, back.as_mut_ptr() as *mut c_void, msg.len(), 0),
                msg.len() as isize
            );
            assert_eq!(&back[..msg.len()], b"hXYlo");
            assert_eq!(lseek(fd, 0, SEEK_END), msg.len() as i64);
            assert_eq!(lseek(fd, -(msg.len() as i64), SEEK_CUR), 0);
            let one = [0u8; 1];
            assert_eq!(
                read(fd, back.as_mut_ptr() as *mut c_void, one.len()),
                one.len() as isize
            );
            assert_eq!(back[0], b'h');
            assert_eq!(close(fd), 0);
        }
    }

    #[test]
    fn readv_writev_roundtrip() {
        unsafe {
            let mut fds = [0 as c_int; 2];
            assert_eq!(pipe(fds.as_mut_ptr()), 0);
            let a = b"foo";
            let b = b"bar";
            let iov = [
                Iovec {
                    base: a.as_ptr() as *mut c_void,
                    len: a.len(),
                },
                Iovec {
                    base: b.as_ptr() as *mut c_void,
                    len: b.len(),
                },
            ];
            assert_eq!(writev(fds[1], iov.as_ptr(), iov.len() as c_int), 6);
            let mut back = [0u8; 8];
            let riov = [Iovec {
                base: back.as_mut_ptr() as *mut c_void,
                len: back.len(),
            }];
            assert_eq!(readv(fds[0], riov.as_ptr(), 1), 6);
            assert_eq!(&back[..6], b"foobar");
            assert_eq!(close(fds[0]), 0);
            assert_eq!(close(fds[1]), 0);
        }
    }

    #[test]
    fn ids_and_zero_sleeps() {
        unsafe {
            assert!(getpid() > 0);
            assert!(getppid() > 0);
            assert!(getuid() >= 0);
            assert!(geteuid() >= 0);
            assert!(getgid() >= 0);
            assert!(getegid() >= 0);
            assert_eq!(sleep(0), 0);
            assert_eq!(usleep(0), 0);
        }
    }

    /// `pause` only returns via a caught signal: pound our own tid with a
    /// queued real-time signal from a helper (no sleeps anywhere — a
    /// pre-pause delivery still leaves it pending, so there is no race)
    /// and check `-1`/`EINTR`. Restores `SIG_DFL` afterwards.
    #[cfg(target_arch = "x86_64")]
    #[test]
    #[allow(function_casts_as_integer)]
    fn pause_returns_eintr_after_signal() {
        // Exact errno + process signal disposition: serialize (see testlock docs).
        let _guard = crate::ldso::testlock::lock();
        use core::sync::atomic::{AtomicI32, Ordering};

        use crate::syscall::{syscall0, syscall2, syscall4};
        use crate::thread::synccall::__restore_rt;

        const SYS_RT_SIGACTION: usize = 13; // TODO: share when generated
        const SYS_TKILL: usize = 200; // TODO: share when generated
        const SYS_GETTID: usize = 186; // TODO: share with sync.rs
        const SIG_TEST: c_int = 36; // real-time: queues, unused elsewhere
        const SA_RESTORER: usize = 0x04000000;
        const K_SIGSET_LEN: usize = 8;

        #[repr(C)]
        struct Act {
            handler: usize,
            flags: usize,
            restorer: usize,
            mask: u64,
        }
        unsafe extern "C" fn noop() {}
        static READY: AtomicI32 = AtomicI32::new(0);
        static DONE: AtomicI32 = AtomicI32::new(0);

        unsafe {
            let tid = syscall0(SYS_GETTID);
            let act = Act {
                handler: noop as usize,
                flags: SA_RESTORER,
                restorer: __restore_rt as usize,
                mask: 0,
            };
            assert_eq!(
                syscall4(
                    SYS_RT_SIGACTION,
                    SIG_TEST as usize,
                    &act as *const Act as usize,
                    0,
                    K_SIGSET_LEN
                ),
                0
            );
            DONE.store(0, Ordering::SeqCst);
            READY.store(0, Ordering::SeqCst);
            // Paced pokes, never a storm: a back-to-back tkill loop queues
            // real-time signals faster than this thread can run, pinning it
            // in the handler until the loop ends. One poke per ~ms of
            // userspace spins lands inside pause() within a few rounds.
            let helper = std::thread::spawn(move || {
                while READY.load(Ordering::SeqCst) == 0 {
                    core::hint::spin_loop();
                }
                let mut rounds = 0u32;
                while DONE.load(Ordering::SeqCst) == 0 && rounds < 500 {
                    syscall2(SYS_TKILL, tid as usize, SIG_TEST as usize);
                    for _ in 0..1_000_000 {
                        core::hint::spin_loop();
                    }
                    rounds = rounds.wrapping_add(1);
                }
            });
            READY.store(1, Ordering::SeqCst);
            assert_eq!(pause(), -1);
            DONE.store(1, Ordering::SeqCst);
            let _ = helper.join();
            let dfl = Act {
                handler: 0,
                flags: 0,
                restorer: 0,
                mask: 0,
            };
            syscall4(
                SYS_RT_SIGACTION,
                SIG_TEST as usize,
                &dfl as *const Act as usize,
                0,
                K_SIGSET_LEN,
            );
            assert_eq!(
                crate::errno::errno_load(crate::errno::__errno_location()),
                EINTR
            );
        }
    }
}
