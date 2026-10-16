//! Thin `stat` wrappers (musl `src/stat/stat.c`, `lstat.c`, `fstat.c`,
//! `fstatat.c`).
//!
//! `stat`/`lstat` are `newfstatat` with `AT_FDCWD` (flags `0` /
//! `AT_SYMLINK_NOFOLLOW`), and `fstat` is `newfstatat` with an empty
//! path plus `AT_EMPTY_PATH` — exactly musl's `__fstat` shape. `Stat`
//! mirrors `arch/x86_64/bits/stat.h` field for field, so the kernel
//! writes it directly with no translation.

use core::ffi::{c_char, c_int};

use crate::fcntl::AT_FDCWD;
use crate::syscall::{syscall4, syscall_ret};

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_NEWFSTATAT: usize = 262; // TODO: generate from arch bits/syscall.h

/// musl `include/fcntl.h` (local: only `stat.rs` needs these two).
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const AT_EMPTY_PATH: c_int = 0x1000;

/// musl `struct timespec` on x86_64 (`time_t` + `long`: two `i64`s).
#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// musl `arch/x86_64/bits/stat.h`, field for field: `dev`/`ino`/`nlink`
/// are `u64`, `mode`/`uid`/`gid`/`__pad0` are `u32`, `rdev` is `u64`,
/// `size`/`blksize`/`blocks` are `i64`, three `timespec` pairs, then
/// three reserved `long`s (144 bytes total).
#[repr(C)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atim: Timespec,
    pub st_mtim: Timespec,
    pub st_ctim: Timespec,
    pub __unused: [i64; 3],
}

/// musl `include/sys/stat.h`.
pub const S_IFMT: u32 = 0o170000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFDIR: u32 = 0o040000;

/// musl `S_ISREG` as a `const fn` (a C macro, not a symbol).
#[allow(non_snake_case)]
pub const fn S_ISREG(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFREG
}

/// musl `S_ISDIR` as a `const fn` (a C macro, not a symbol).
#[allow(non_snake_case)]
pub const fn S_ISDIR(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFDIR
}

#[cfg(target_arch = "x86_64")]
unsafe fn fstatat_raw(dirfd: c_int, path: *const c_char, buf: *mut Stat, flags: c_int) -> c_int {
    unsafe {
        syscall_ret(syscall4(
            SYS_NEWFSTATAT,
            dirfd as usize,
            path as usize,
            buf as usize,
            flags as usize,
        )) as c_int
    }
}

/// File status (musl `stat`: `fstatat(AT_FDCWD, path, buf, 0)`).
///
/// # Safety
///
/// `path` must point to a NUL-terminated string; `buf` must point to a
/// writable [`Stat`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn stat(path: *const c_char, buf: *mut Stat) -> c_int {
    unsafe { fstatat_raw(AT_FDCWD, path, buf, 0) }
}

/// File status without following symlinks (musl `lstat`).
///
/// # Safety
///
/// Same contract as [`stat`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn lstat(path: *const c_char, buf: *mut Stat) -> c_int {
    unsafe { fstatat_raw(AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW) }
}

/// File status by descriptor (musl `__fstat` shape: `fstatat` with an
/// empty path and `AT_EMPTY_PATH`).
///
/// # Safety
///
/// `fd` must be an open file description; `buf` must point to a
/// writable [`Stat`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fstat(fd: c_int, buf: *mut Stat) -> c_int {
    let empty = [0 as c_char];
    unsafe { fstatat_raw(fd, empty.as_ptr(), buf, AT_EMPTY_PATH) }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::{fstat, lstat, stat, Stat, S_IFDIR, S_IFMT, S_IFREG, S_ISDIR, S_ISREG};
    use core::ffi::c_int;
    use core::mem::{offset_of, size_of};

    use crate::fcntl::{O_CREAT, O_RDWR};
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

    #[test]
    fn stat_layout_is_kernel_exact() {
        assert_eq!(size_of::<Stat>(), 144);
        assert_eq!(offset_of!(Stat, st_ino), 8);
        assert_eq!(offset_of!(Stat, st_mode), 24);
        assert_eq!(offset_of!(Stat, st_rdev), 40);
        assert_eq!(offset_of!(Stat, st_size), 48);
        assert_eq!(offset_of!(Stat, st_atim), 72);
        assert_eq!(offset_of!(Stat, st_ctim), 104);
        assert_eq!(S_IFMT, 0o170000);
        assert_eq!(S_IFREG, 0o100000);
        assert_eq!(S_IFDIR, 0o040000);
        assert!(S_ISREG(S_IFREG | 0o644));
        assert!(S_ISDIR(S_IFDIR | 0o755));
        assert!(!S_ISREG(S_IFDIR | 0o755));
    }

    #[test]
    fn stat_and_fstat_report_size() {
        let path = std::ffi::CString::new(std::format!(
            "/tmp/zlibc-7cc-stat-{}.tmp",
            std::process::id()
        ))
        .unwrap();
        unsafe {
            let fd = crate::fcntl::open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
            assert!(fd >= 0);
            let msg = b"hello stat";
            assert_eq!(
                syscall_ret(syscall3(
                    SYS_WRITE,
                    fd as usize,
                    msg.as_ptr() as usize,
                    msg.len()
                )),
                msg.len() as isize
            );
            let mut a: Stat = core::mem::zeroed();
            assert_eq!(stat(path.as_ptr(), &mut a), 0);
            assert!(S_ISREG(a.st_mode));
            assert_eq!(a.st_size, msg.len() as i64);
            let mut b: Stat = core::mem::zeroed();
            assert_eq!(fstat(fd, &mut b), 0);
            assert!(S_ISREG(b.st_mode));
            assert_eq!(b.st_size, msg.len() as i64);
            assert_eq!(a.st_ino, b.st_ino);
            // Exercise the raw read path too, so size is cross-checked.
            let mut back = [0u8; 16];
            assert_eq!(
                syscall_ret(syscall3(
                    SYS_READ,
                    crate::fcntl::open(path.as_ptr(), O_RDWR, 0) as usize,
                    back.as_mut_ptr() as usize,
                    msg.len()
                )),
                msg.len() as isize
            );
            assert_eq!(&back[..msg.len()], msg);
            close(fd);
            assert_eq!(
                syscall_ret(syscall3(SYS_UNLINK, path.as_ptr() as usize, 0, 0)),
                0
            );
        }
    }

    #[test]
    fn lstat_sees_link_stat_follows_it() {
        let pid = std::process::id();
        let dir = std::env::temp_dir();
        let target = dir.join(std::format!("zlibc-7cc-target-{pid}"));
        let link = dir.join(std::format!("zlibc-7cc-link-{pid}"));
        let body = b"hello stat";
        std::fs::write(&target, body).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let t = std::ffi::CString::new(target.to_str().unwrap()).unwrap();
        let l = std::ffi::CString::new(link.to_str().unwrap()).unwrap();
        unsafe {
            let mut st: Stat = core::mem::zeroed();
            assert_eq!(stat(t.as_ptr(), &mut st), 0);
            assert!(S_ISREG(st.st_mode));
            assert_eq!(st.st_size, body.len() as i64);
            // By path through the link: same regular file.
            let mut via: Stat = core::mem::zeroed();
            assert_eq!(stat(l.as_ptr(), &mut via), 0);
            assert!(S_ISREG(via.st_mode));
            assert_eq!(via.st_size, body.len() as i64);
            // lstat: the link itself, not a regular file, sized as the
            // target path string.
            let mut lst: Stat = core::mem::zeroed();
            assert_eq!(lstat(l.as_ptr(), &mut lst), 0);
            assert!(!S_ISREG(lst.st_mode));
            assert!(!S_ISDIR(lst.st_mode));
            assert_ne!(lst.st_mode & S_IFMT, via.st_mode & S_IFMT);
            assert_eq!(lst.st_size, target.to_str().unwrap().len() as i64);
            assert_eq!(
                syscall_ret(syscall3(SYS_UNLINK, l.as_ptr() as usize, 0, 0)),
                0
            );
            assert_eq!(
                syscall_ret(syscall3(SYS_UNLINK, t.as_ptr() as usize, 0, 0)),
                0
            );
        }
    }
}
