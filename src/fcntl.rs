//! Thin `open`/`fcntl` wrappers (musl `src/fcntl/open.c`, `openat.c`,
//! `creat.c`, `fcntl.c`).
//!
//! Each entry is one raw syscall returning through `syscall_ret`, so
//! `errno` follows musl's contract. Stable Rust has no C variadics, so
//! `open`/`openat` take a fixed `mode` argument: a two-argument caller
//! leaves whatever was in `rdx` as `mode`, which is ignored unless
//! `O_CREAT` is set — the same definedness boundary musl's `va_arg`
//! read has.

use core::ffi::{c_char, c_int};

use crate::errno::__errno_location;
use crate::syscall::{syscall3, syscall4, syscall_ret};

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_OPENAT: usize = 257; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_FCNTL: usize = 72; // TODO: generate from arch bits/syscall.h

/// musl `include/fcntl.h` + `arch/generic/bits/fcntl.h`.
pub const O_RDONLY: c_int = 0;
pub const O_WRONLY: c_int = 1;
pub const O_RDWR: c_int = 2;
/// musl `O_ACCMODE (03|O_SEARCH)` with `O_SEARCH` = `O_PATH` = 0o10000000.
pub const O_ACCMODE: c_int = 0o10000003;
pub const O_CREAT: c_int = 0o100;
pub const O_EXCL: c_int = 0o200;
pub const O_TRUNC: c_int = 0o1000;
pub const O_APPEND: c_int = 0o2000;
pub const O_NONBLOCK: c_int = 0o4000;
pub const O_CLOEXEC: c_int = 0o2000000;

/// musl `arch/generic/bits/fcntl.h`: ORed into `openat` flags like
/// musl's `open.c`/`openat.c` do; a no-op bit on x86_64.
const O_LARGEFILE: c_int = 0o100000;

/// musl `include/fcntl.h`.
pub const AT_FDCWD: c_int = -100;

/// musl `arch/generic/bits/fcntl.h`: the only `fcntl` commands with a
/// kernel contract here (`F_DUPFD_CLOEXEC` is native on Linux, so no
/// musl-style emulation fallback); every other command is opaque and
/// fails with `EINVAL` (see [`fcntl`]).
pub const F_DUPFD: c_int = 0;
pub const F_GETFD: c_int = 1;
pub const F_SETFD: c_int = 2;
pub const F_GETFL: c_int = 3;
pub const F_SETFL: c_int = 4;
pub const F_DUPFD_CLOEXEC: c_int = 1030;
pub const FD_CLOEXEC: c_int = 1;

/// musl `include/errno.h`.
const EINVAL: c_int = 22;

/// Open a file (musl `open`: `openat` with `AT_FDCWD`).
///
/// # Safety
///
/// `path` must point to a NUL-terminated string. `mode` is only read
/// when `flags` contains `O_CREAT` (see module docs).
// `std` declares `open` as a 2-or-3-arg variadic runtime symbol, which
// stable Rust cannot express; the fixed 3-arg shape is register-
// identical at every real call site (`mode` arrives in `rdx` either
// way and is ignored unless `O_CREAT`), so the lint is allowed here.
#[allow(invalid_runtime_symbol_definitions)]
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mode: c_int) -> c_int {
    unsafe { openat(AT_FDCWD, path, flags, mode) }
}

/// Open a file relative to `dirfd` (musl `openat`).
///
/// # Safety
///
/// `path` must point to a NUL-terminated string. `mode` is only read
/// when `flags` contains `O_CREAT` (see module docs).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn openat(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: c_int,
) -> c_int {
    unsafe {
        syscall_ret(syscall4(
            SYS_OPENAT,
            dirfd as usize,
            path as usize,
            (flags | O_LARGEFILE) as usize,
            mode as usize,
        )) as c_int
    }
}

/// Create a file (musl `creat`: `open` with `O_WRONLY|O_CREAT|O_TRUNC`).
///
/// # Safety
///
/// `path` must point to a NUL-terminated string.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn creat(path: *const c_char, mode: c_int) -> c_int {
    unsafe { open(path, O_WRONLY | O_CREAT | O_TRUNC, mode) }
}

/// File-descriptor control (musl `fcntl.c`, minimal).
///
/// The `DUP`/`GET`/`SET` `FD`+`FL` commands go straight to the kernel
/// (`F_SETFL` ORs in `O_LARGEFILE` like musl); lock/owner/lease and
/// every other command is opaque here and fails with `EINVAL` instead
/// of reaching the kernel.
///
/// # Safety
///
/// Pure syscall wrapper; `arg` is a word-sized value, never dereferenced.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fcntl(fd: c_int, cmd: c_int, arg: usize) -> c_int {
    unsafe {
        match cmd {
            F_DUPFD | F_DUPFD_CLOEXEC | F_GETFD | F_SETFD | F_GETFL | F_SETFL => {
                let a = if cmd == F_SETFL {
                    arg | (O_LARGEFILE as usize)
                } else {
                    arg
                };
                syscall_ret(syscall3(SYS_FCNTL, fd as usize, cmd as usize, a)) as c_int
            }
            _ => {
                crate::errno::errno_store(__errno_location(), EINVAL);
                -1
            }
        }
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::{
        creat, fcntl, open, openat, AT_FDCWD, FD_CLOEXEC, F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD,
        F_GETFL, F_SETFD, F_SETFL, O_APPEND, O_CREAT, O_RDWR,
    };
    use core::ffi::{c_char, c_int};

    use crate::errno::{__errno_location, errno_load};
    use crate::syscall::{syscall3, syscall_ret};

    /// musl `arch/x86_64/bits/syscall.h.in` (test I/O + cleanup only).
    const SYS_READ: usize = 0; // TODO: generate from arch bits/syscall.h
    const SYS_WRITE: usize = 1; // TODO: generate from arch bits/syscall.h
    const SYS_CLOSE: usize = 3; // TODO: generate from arch bits/syscall.h
    const SYS_UNLINK: usize = 87; // TODO: generate from arch bits/syscall.h

    unsafe fn close(fd: c_int) {
        unsafe {
            let _ = syscall_ret(syscall3(SYS_CLOSE, fd as usize, 0, 0));
        }
    }

    // Per-test tag: the two tests below run in parallel threads of one
    // process (same pid), so a bare pid-unique name collides.
    fn tmp_cstr(tag: &str) -> std::ffi::CString {
        std::ffi::CString::new(std::format!(
            "/tmp/zlibc-7cc-{tag}-{}.tmp",
            std::process::id()
        ))
        .unwrap()
    }

    #[test]
    fn open_write_read_close_roundtrip() {
        // Opens a missing path (ENOENT into the shared fallback cell).
        let _guard = crate::ldso::testlock::lock();
        let path = tmp_cstr("rw");
        unsafe {
            // creat(2) covers the O_WRONLY|O_CREAT|O_TRUNC shape.
            let fd = creat(path.as_ptr(), 0o644);
            assert!(fd >= 0);
            let msg = b"7cc";
            let w = syscall_ret(syscall3(
                SYS_WRITE,
                fd as usize,
                msg.as_ptr() as usize,
                msg.len(),
            ));
            assert_eq!(w, msg.len() as isize);
            close(fd);
            // openat(2) with AT_FDCWD covers open(2)'s path too.
            let fd = openat(AT_FDCWD, path.as_ptr(), O_RDWR, 0);
            assert!(fd >= 0);
            let mut back = [0u8; 8];
            let r = syscall_ret(syscall3(
                SYS_READ,
                fd as usize,
                back.as_mut_ptr() as usize,
                back.len(),
            ));
            assert_eq!(r, msg.len() as isize);
            assert_eq!(&back[..msg.len()], msg);
            close(fd);
            let u = syscall_ret(syscall3(SYS_UNLINK, path.as_ptr() as usize, 0, 0));
            assert_eq!(u, 0);
            // open(2) itself on the now-missing path must fail cleanly.
            let fd = open(path.as_ptr() as *const c_char, O_RDWR, 0);
            assert_eq!(fd, -1);
        }
    }

    #[test]
    fn fcntl_dup_and_flags_roundtrip() {
        // Asserts an exact errno value: serialize (see testlock docs).
        let _guard = crate::ldso::testlock::lock();
        let path = tmp_cstr("dup");
        unsafe {
            let fd = open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
            assert!(fd >= 0);
            let dup = fcntl(fd, F_DUPFD, 0);
            assert!(dup >= 0 && dup != fd);
            assert_eq!(fcntl(dup, F_GETFD, 0), 0);
            assert_eq!(fcntl(dup, F_SETFD, FD_CLOEXEC as usize), 0);
            assert_eq!(fcntl(dup, F_GETFD, 0), FD_CLOEXEC);
            let fl = fcntl(fd, F_GETFL, 0);
            assert!(fl >= 0);
            assert_eq!(fcntl(fd, F_SETFL, (fl as usize) | (O_APPEND as usize)), 0);
            assert_eq!(fcntl(fd, F_GETFL, 0) & O_APPEND, O_APPEND);
            let clo = fcntl(fd, F_DUPFD_CLOEXEC, 0);
            assert!(clo >= 0);
            assert_eq!(fcntl(clo, F_GETFD, 0) & FD_CLOEXEC, FD_CLOEXEC);
            // Opaque command: EINVAL, errno set, kernel untouched.
            assert_eq!(fcntl(fd, 0xdead, 0), -1);
            assert_eq!(errno_load(__errno_location()), 22);
            close(clo);
            close(dup);
            close(fd);
            assert_eq!(
                syscall_ret(syscall3(SYS_UNLINK, path.as_ptr() as usize, 0, 0)),
                0
            );
        }
    }
}
