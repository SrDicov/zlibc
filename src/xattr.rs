//! Extended attributes, one raw trap each (musl `src/linux/xattr.c`).
//!
//! Each entry passes its arguments straight to the kernel and returns
//! through `syscall_ret`, so `errno` follows musl's contract.

use core::ffi::{c_char, c_int, c_void};

use crate::syscall::{syscall2, syscall3, syscall4, syscall5, syscall_ret};

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_SETXATTR: usize = 188; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_LSETXATTR: usize = 189; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_FSETXATTR: usize = 190; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_GETXATTR: usize = 191; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_LGETXATTR: usize = 192; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_FGETXATTR: usize = 193; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_LISTXATTR: usize = 194; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_LLISTXATTR: usize = 195; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_FLISTXATTR: usize = 196; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_REMOVEXATTR: usize = 197; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_LREMOVEXATTR: usize = 198; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_FREMOVEXATTR: usize = 199; // TODO: generate from arch bits/syscall.h

/// musl `include/sys/xattr.h`.
pub const XATTR_CREATE: c_int = 1;
pub const XATTR_REPLACE: c_int = 2;

/// Set an attribute, following symlinks (musl `setxattr`).
///
/// # Safety
///
/// `path`/`name` must point to NUL-terminated strings; `value` must
/// point to `size` readable bytes (nullable when `size` is 0).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: c_int,
) -> c_int {
    unsafe {
        syscall_ret(syscall5(
            SYS_SETXATTR,
            path as usize,
            name as usize,
            value as usize,
            size,
            flags as usize,
        )) as c_int
    }
}

/// Set an attribute without following symlinks (musl `lsetxattr`).
///
/// # Safety
///
/// Same contract as [`setxattr`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn lsetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: c_int,
) -> c_int {
    unsafe {
        syscall_ret(syscall5(
            SYS_LSETXATTR,
            path as usize,
            name as usize,
            value as usize,
            size,
            flags as usize,
        )) as c_int
    }
}

/// Set an attribute on an open descriptor (musl `fsetxattr`).
///
/// # Safety
///
/// `fd` must be open; `name`/`value` follow [`setxattr`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fsetxattr(
    fd: c_int,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: c_int,
) -> c_int {
    unsafe {
        syscall_ret(syscall5(
            SYS_FSETXATTR,
            fd as usize,
            name as usize,
            value as usize,
            size,
            flags as usize,
        )) as c_int
    }
}

/// Get an attribute, following symlinks (musl `getxattr`).
///
/// # Safety
///
/// `path`/`name` must point to NUL-terminated strings; `value` must
/// point to `size` writable bytes (nullable when `size` is 0, which
/// queries the value's size).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
) -> isize {
    unsafe {
        syscall_ret(syscall4(
            SYS_GETXATTR,
            path as usize,
            name as usize,
            value as usize,
            size,
        ))
    }
}

/// Get an attribute without following symlinks (musl `lgetxattr`).
///
/// # Safety
///
/// Same contract as [`getxattr`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn lgetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
) -> isize {
    unsafe {
        syscall_ret(syscall4(
            SYS_LGETXATTR,
            path as usize,
            name as usize,
            value as usize,
            size,
        ))
    }
}

/// Get an attribute on an open descriptor (musl `fgetxattr`).
///
/// # Safety
///
/// `fd` must be open; `name`/`value` follow [`getxattr`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fgetxattr(
    fd: c_int,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
) -> isize {
    unsafe {
        syscall_ret(syscall4(
            SYS_FGETXATTR,
            fd as usize,
            name as usize,
            value as usize,
            size,
        ))
    }
}

/// List attributes, following symlinks (musl `listxattr`).
///
/// # Safety
///
/// `path` must point to a NUL-terminated string; `list` must point to
/// `size` writable bytes (nullable when `size` is 0, which queries the
/// list's size).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn listxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    unsafe { syscall_ret(syscall3(SYS_LISTXATTR, path as usize, list as usize, size)) }
}

/// List attributes without following symlinks (musl `llistxattr`).
///
/// # Safety
///
/// Same contract as [`listxattr`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn llistxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    unsafe { syscall_ret(syscall3(SYS_LLISTXATTR, path as usize, list as usize, size)) }
}

/// List attributes on an open descriptor (musl `flistxattr`).
///
/// # Safety
///
/// `fd` must be open; `list` follows [`listxattr`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn flistxattr(fd: c_int, list: *mut c_char, size: usize) -> isize {
    unsafe { syscall_ret(syscall3(SYS_FLISTXATTR, fd as usize, list as usize, size)) }
}

/// Remove an attribute, following symlinks (musl `removexattr`).
///
/// # Safety
///
/// `path`/`name` must point to NUL-terminated strings.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn removexattr(path: *const c_char, name: *const c_char) -> c_int {
    unsafe { syscall_ret(syscall2(SYS_REMOVEXATTR, path as usize, name as usize)) as c_int }
}

/// Remove an attribute without following symlinks (musl `lremovexattr`).
///
/// # Safety
///
/// Same contract as [`removexattr`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn lremovexattr(path: *const c_char, name: *const c_char) -> c_int {
    unsafe { syscall_ret(syscall2(SYS_LREMOVEXATTR, path as usize, name as usize)) as c_int }
}

/// Remove an attribute on an open descriptor (musl `fremovexattr`).
///
/// # Safety
///
/// `fd` must be open; `name` must point to a NUL-terminated string.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fremovexattr(fd: c_int, name: *const c_char) -> c_int {
    unsafe { syscall_ret(syscall2(SYS_FREMOVEXATTR, fd as usize, name as usize)) as c_int }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use core::ffi::c_int;
    use core::sync::atomic::{AtomicU64, Ordering};

    use crate::errno::{__errno_location, errno_load};
    use crate::fcntl::{open, O_CREAT, O_RDONLY, O_RDWR, O_TRUNC};
    use crate::syscall::{syscall3, syscall_ret};

    /// musl `arch/x86_64/bits/syscall.h.in` (test cleanup only).
    const SYS_CLOSE: usize = 3; // TODO: generate from arch bits/syscall.h
    const SYS_UNLINK: usize = 87; // TODO: generate from arch bits/syscall.h

    /// musl `arch/generic/bits/errno.h` (failure-shape assertions only).
    const EEXIST: c_int = 17;
    const ENODATA: c_int = 61;

    static CTR: AtomicU64 = AtomicU64::new(1000);

    // Unique per test: parallel tests share one process (one pid), so
    // pid alone collides — pid + tag + counter is unique.
    fn tmp_cstr(tag: &str) -> std::ffi::CString {
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        std::ffi::CString::new(std::format!(
            "/tmp/zlibc-8e2-{tag}-{}-{n}.tmp",
            std::process::id()
        ))
        .unwrap()
    }

    unsafe fn close(fd: c_int) {
        unsafe {
            let _ = syscall_ret(syscall3(SYS_CLOSE, fd as usize, 0, 0));
        }
    }

    unsafe fn unlink(path: *const c_char) {
        unsafe {
            let _ = syscall_ret(syscall3(SYS_UNLINK, path as usize, 0, 0));
        }
    }

    // NUL-terminated needle search over a listxattr blob.
    fn list_contains(list: &[u8], len: usize, name: &[u8]) -> bool {
        list[..len].split(|b| *b == 0).any(|e| e == name)
    }

    #[test]
    fn xattr_path_roundtrip() {
        // Asserts exact errno values: serialize (see testlock docs).
        let _guard = crate::ldso::testlock::lock();
        let path = tmp_cstr("xp");
        let name = c"user.zlibc-8e2";
        let val = b"value-8e2";
        unsafe {
            let fd = open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o600);
            assert!(fd >= 0);
            // set + lset (plain set first, then REPLACE via the l-variant).
            assert_eq!(
                setxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    val.as_ptr() as *const c_void,
                    val.len(),
                    0
                ),
                0
            );
            // CREATE on an existing name must fail EEXIST, not overwrite.
            assert_eq!(
                setxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    val.as_ptr() as *const c_void,
                    val.len(),
                    XATTR_CREATE
                ),
                -1
            );
            assert_eq!(errno_load(__errno_location()), EEXIST);
            assert_eq!(
                lsetxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    val.as_ptr() as *const c_void,
                    val.len(),
                    XATTR_REPLACE
                ),
                0
            );
            // Size query, then the value itself, via both path variants.
            assert_eq!(
                getxattr(path.as_ptr(), name.as_ptr(), core::ptr::null_mut(), 0),
                val.len() as isize
            );
            let mut back = [0u8; 32];
            assert_eq!(
                lgetxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    back.as_mut_ptr() as *mut c_void,
                    back.len()
                ),
                val.len() as isize
            );
            assert_eq!(&back[..val.len()], val);
            // List queries name the attribute via both path variants.
            let n = listxattr(path.as_ptr(), core::ptr::null_mut(), 0);
            assert!(n > 0);
            let mut list = [0u8; 256];
            let n = llistxattr(path.as_ptr(), list.as_mut_ptr() as *mut c_char, list.len());
            assert!(n > 0);
            assert!(list_contains(&list, n as usize, b"user.zlibc-8e2"));
            // Remove via the l-variant; the value is gone afterwards.
            assert_eq!(lremovexattr(path.as_ptr(), name.as_ptr()), 0);
            assert_eq!(
                getxattr(path.as_ptr(), name.as_ptr(), core::ptr::null_mut(), 0),
                -1
            );
            assert_eq!(errno_load(__errno_location()), ENODATA);
            // REPLACE on a missing name must fail ENODATA, not create.
            assert_eq!(
                setxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    val.as_ptr() as *const c_void,
                    val.len(),
                    XATTR_REPLACE
                ),
                -1
            );
            assert_eq!(errno_load(__errno_location()), ENODATA);
            close(fd);
            unlink(path.as_ptr());
        }
    }

    #[test]
    fn xattr_fd_roundtrip() {
        let _guard = crate::ldso::testlock::lock();
        let path = tmp_cstr("xf");
        let name = c"user.zlibc-8e2-fd";
        let val = b"fd-value-8e2";
        unsafe {
            let fd = open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o600);
            assert!(fd >= 0);
            assert_eq!(
                fsetxattr(
                    fd,
                    name.as_ptr(),
                    val.as_ptr() as *const c_void,
                    val.len(),
                    0
                ),
                0
            );
            assert_eq!(
                fgetxattr(fd, name.as_ptr(), core::ptr::null_mut(), 0),
                val.len() as isize
            );
            let mut back = [0u8; 32];
            assert_eq!(
                fgetxattr(
                    fd,
                    name.as_ptr(),
                    back.as_mut_ptr() as *mut c_void,
                    back.len()
                ),
                val.len() as isize
            );
            assert_eq!(&back[..val.len()], val);
            // The fd-visible attribute also shows up via the path.
            let n = listxattr(path.as_ptr(), core::ptr::null_mut(), 0);
            assert!(n > 0);
            let mut list = [0u8; 256];
            let n = flistxattr(fd, list.as_mut_ptr() as *mut c_char, list.len());
            assert!(n > 0);
            assert!(list_contains(&list, n as usize, b"user.zlibc-8e2-fd"));
            // Remove via fd; confirm gone through the path getter too.
            assert_eq!(fremovexattr(fd, name.as_ptr()), 0);
            // O_RDONLY fd still reads removals: reopen check via path.
            let rfd = open(path.as_ptr(), O_RDONLY, 0);
            assert!(rfd >= 0);
            assert_eq!(fgetxattr(rfd, name.as_ptr(), core::ptr::null_mut(), 0), -1);
            assert_eq!(errno_load(__errno_location()), ENODATA);
            close(rfd);
            // Plain path remove of the (already gone) name: ENODATA.
            assert_eq!(removexattr(path.as_ptr(), name.as_ptr()), -1);
            assert_eq!(errno_load(__errno_location()), ENODATA);
            close(fd);
            unlink(path.as_ptr());
        }
    }
}
