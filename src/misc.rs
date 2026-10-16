//! Misc Linux syscalls: mount/statvfs/sendfile/prctl/random (musl
//! `src/linux/mount.c`, `src/stat/statvfs.c`, `src/linux/sendfile.c`,
//! `src/linux/prctl.c`, `src/linux/getrandom.c`, `src/linux/memfd_create.c`).
//!
//! Each entry is one raw syscall returning through `syscall_ret`, so
//! `errno` follows musl's contract. `statvfs`/`fstatvfs` have no kernel
//! trap: like musl they call `statfs`/`fstatfs` and translate the result
//! userspace-side (`fixup`).

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};

use crate::syscall::{syscall2, syscall3, syscall4, syscall5, syscall_ret};

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_SENDFILE: usize = 40; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_STATFS: usize = 137; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_FSTATFS: usize = 138; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_PRCTL: usize = 157; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_MOUNT: usize = 165; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_UMOUNT2: usize = 166; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_GETRANDOM: usize = 318; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_MEMFD_CREATE: usize = 319; // TODO: generate from arch bits/syscall.h

/// musl `include/errno.h` (`EINTR`: retried inside [`getrandom`]).
const EINTR: c_int = 4;

/// musl `include/sys/statfs.h` (`fsid_t`, via `arch/generic/bits/statfs.h`
/// on x86_64).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Fsid {
    pub __val: [c_int; 2],
}

/// musl `arch/generic/bits/statfs.h` (`struct statfs`, field-for-field).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Statfs {
    pub f_type: u64,
    pub f_bsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_fsid: Fsid,
    pub f_namelen: u64,
    pub f_frsize: u64,
    pub f_flags: u64,
    pub f_spare: [u64; 4],
}

/// musl `include/sys/statvfs.h` (`struct statvfs`, field-for-field; the
/// zero-width padding beside `f_fsid` vanishes on 64-bit).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Statvfs {
    pub f_bsize: u64,
    pub f_frsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_favail: u64,
    pub f_fsid: u64,
    pub f_flag: u64,
    pub f_namemax: u64,
    pub f_type: c_uint,
    pub __reserved: [c_int; 5],
}

const _: () = assert!(core::mem::size_of::<Statfs>() == 120);
const _: () = assert!(core::mem::size_of::<Statvfs>() == 112);

/// musl `include/sys/mount.h`.
pub const MS_RDONLY: c_ulong = 1;
pub const MS_NOSUID: c_ulong = 2;
pub const MS_NODEV: c_ulong = 4;
pub const MS_NOEXEC: c_ulong = 8;
pub const MS_SYNCHRONOUS: c_ulong = 16;
pub const MS_REMOUNT: c_ulong = 32;
pub const MS_MANDLOCK: c_ulong = 64;
pub const MS_DIRSYNC: c_ulong = 128;
pub const MS_NOSYMFOLLOW: c_ulong = 256;
pub const MS_NOATIME: c_ulong = 1024;
pub const MS_NODIRATIME: c_ulong = 2048;
pub const MS_BIND: c_ulong = 4096;
pub const MS_MOVE: c_ulong = 8192;
pub const MS_REC: c_ulong = 16384;
pub const MS_SILENT: c_ulong = 32768;
pub const MS_POSIXACL: c_ulong = 1 << 16;
pub const MS_UNBINDABLE: c_ulong = 1 << 17;
pub const MS_PRIVATE: c_ulong = 1 << 18;
pub const MS_SLAVE: c_ulong = 1 << 19;
pub const MS_SHARED: c_ulong = 1 << 20;
pub const MS_RELATIME: c_ulong = 1 << 21;
pub const MS_KERNMOUNT: c_ulong = 1 << 22;
pub const MS_I_VERSION: c_ulong = 1 << 23;
pub const MS_STRICTATIME: c_ulong = 1 << 24;
pub const MS_LAZYTIME: c_ulong = 1 << 25;

/// musl `include/sys/mount.h` (`umount2` flags).
pub const MNT_FORCE: c_int = 1;
pub const MNT_DETACH: c_int = 2;
pub const MNT_EXPIRE: c_int = 4;
pub const UMOUNT_NOFOLLOW: c_int = 8;

/// musl `include/sys/statvfs.h`.
pub const ST_RDONLY: c_ulong = 1;
pub const ST_NOSUID: c_ulong = 2;
pub const ST_NODEV: c_ulong = 4;
pub const ST_NOEXEC: c_ulong = 8;
pub const ST_SYNCHRONOUS: c_ulong = 16;
pub const ST_MANDLOCK: c_ulong = 64;
pub const ST_WRITE: c_ulong = 128;
pub const ST_APPEND: c_ulong = 256;
pub const ST_IMMUTABLE: c_ulong = 512;
pub const ST_NOATIME: c_ulong = 1024;
pub const ST_NODIRATIME: c_ulong = 2048;
pub const ST_RELATIME: c_ulong = 4096;

/// musl `include/sys/mman.h` (`memfd_create` flags).
pub const MFD_CLOEXEC: c_uint = 0x0001;
pub const MFD_ALLOW_SEALING: c_uint = 0x0002;
pub const MFD_HUGETLB: c_uint = 0x0004;

/// musl `include/sys/random.h` (`getrandom` flags).
pub const GRND_NONBLOCK: c_uint = 0x0001;
pub const GRND_RANDOM: c_uint = 0x0002;
pub const GRND_INSECURE: c_uint = 0x0004;

/// Mount a filesystem (musl `mount`).
///
/// # Safety
///
/// `special`/`dir`/`fstype` must point to NUL-terminated strings;
/// `data` is an opaque mount-option blob (nullable per filesystem).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mount(
    special: *const c_char,
    dir: *const c_char,
    fstype: *const c_char,
    flags: c_ulong,
    data: *const c_void,
) -> c_int {
    unsafe {
        syscall_ret(syscall5(
            SYS_MOUNT,
            special as usize,
            dir as usize,
            fstype as usize,
            flags as usize,
            data as usize,
        )) as c_int
    }
}

/// Unmount a filesystem (musl `umount`: `umount2` with flags 0).
///
/// # Safety
///
/// `special` must point to a NUL-terminated string.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn umount(special: *const c_char) -> c_int {
    unsafe { umount2(special, 0) }
}

/// Unmount a filesystem with flags (musl `umount2`).
///
/// # Safety
///
/// Same contract as [`umount`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn umount2(special: *const c_char, flags: c_int) -> c_int {
    unsafe { syscall_ret(syscall2(SYS_UMOUNT2, special as usize, flags as usize)) as c_int }
}

/// Filesystem statistics for a path (musl `statfs`, via `__statfs`).
///
/// # Safety
///
/// `path` must point to a NUL-terminated string; `buf` must point to a
/// writable [`Statfs`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn statfs(path: *const c_char, buf: *mut Statfs) -> c_int {
    unsafe {
        buf.write_bytes(0, 1);
        syscall_ret(syscall2(SYS_STATFS, path as usize, buf as usize)) as c_int
    }
}

/// Filesystem statistics for a descriptor (musl `fstatfs`, via `__fstatfs`).
///
/// # Safety
///
/// `fd` must be open; `buf` must point to a writable [`Statfs`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fstatfs(fd: c_int, buf: *mut Statfs) -> c_int {
    unsafe {
        buf.write_bytes(0, 1);
        syscall_ret(syscall2(SYS_FSTATFS, fd as usize, buf as usize)) as c_int
    }
}

/// Translate a kernel `statfs` result into `statvfs` shape (musl `fixup`
/// in `src/stat/statvfs.c`).
fn fixup(out: &mut Statvfs, inp: &Statfs) {
    *out = Statvfs {
        f_bsize: inp.f_bsize,
        f_frsize: if inp.f_frsize != 0 {
            inp.f_frsize
        } else {
            inp.f_bsize
        },
        f_blocks: inp.f_blocks,
        f_bfree: inp.f_bfree,
        f_bavail: inp.f_bavail,
        f_files: inp.f_files,
        f_ffree: inp.f_ffree,
        f_favail: inp.f_ffree,
        f_fsid: inp.f_fsid.__val[0] as u64,
        f_flag: inp.f_flags,
        f_namemax: inp.f_namelen,
        f_type: inp.f_type as c_uint,
        __reserved: [0; 5],
    };
}

/// POSIX filesystem statistics for a path (musl `statvfs`: `statfs` plus
/// [`fixup`] — there is no `statvfs` trap on Linux).
///
/// # Safety
///
/// `path` must point to a NUL-terminated string; `buf` must point to a
/// writable [`Statvfs`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn statvfs(path: *const c_char, buf: *mut Statvfs) -> c_int {
    unsafe {
        let mut kbuf: Statfs = core::mem::zeroed();
        if statfs(path, &mut kbuf) < 0 {
            return -1;
        }
        fixup(&mut *buf, &kbuf);
        0
    }
}

/// POSIX filesystem statistics for a descriptor (musl `fstatvfs`).
///
/// # Safety
///
/// `fd` must be open; `buf` must point to a writable [`Statvfs`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fstatvfs(fd: c_int, buf: *mut Statvfs) -> c_int {
    unsafe {
        let mut kbuf: Statfs = core::mem::zeroed();
        if fstatfs(fd, &mut kbuf) < 0 {
            return -1;
        }
        fixup(&mut *buf, &kbuf);
        0
    }
}

/// Copy bytes between descriptors without round-tripping userspace
/// (musl `sendfile`).
///
/// # Safety
///
/// `out_fd` must be writable, `in_fd` readable; `ofs` is a nullable
/// in/out file offset (null uses and updates `in_fd`'s position).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sendfile(
    out_fd: c_int,
    in_fd: c_int,
    ofs: *mut c_long,
    count: usize,
) -> isize {
    unsafe {
        syscall_ret(syscall4(
            SYS_SENDFILE,
            out_fd as usize,
            in_fd as usize,
            ofs as usize,
            count,
        ))
    }
}

/// Process control (musl `prctl`).
///
/// musl's `prctl` is C-variadic; stable Rust has no variadics, so this
/// takes the fixed 5-argument shape (option plus four words), like the
/// `open` precedent in `crate::fcntl`: a caller passing fewer arguments
/// leaves whatever was in the remaining registers, which the kernel only
/// reads for options that take that many — the same definedness boundary
/// musl's `va_arg` reads have. Pass 0 for unused trailing arguments.
///
/// # Safety
///
/// Pure syscall wrapper; pointer-carrying options must point to valid
/// memory (e.g. `PR_SET_NAME` reads 16 bytes).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn prctl(
    option: c_int,
    arg2: c_ulong,
    arg3: c_ulong,
    arg4: c_ulong,
    arg5: c_ulong,
) -> c_int {
    unsafe {
        syscall_ret(syscall5(
            SYS_PRCTL,
            option as usize,
            arg2 as usize,
            arg3 as usize,
            arg4 as usize,
            arg5 as usize,
        )) as c_int
    }
}

/// Fill a buffer with random bytes (musl `getrandom`, EINTR-retried).
///
/// # Safety
///
/// `buf` must point to `buflen` writable bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getrandom(buf: *mut c_void, buflen: usize, flags: c_uint) -> isize {
    unsafe {
        loop {
            let r = syscall3(SYS_GETRANDOM, buf as usize, buflen, flags as usize);
            if r != -(EINTR as isize) {
                return syscall_ret(r);
            }
        }
    }
}

/// Create an anonymous memory-backed file (musl `memfd_create`).
///
/// # Safety
///
/// `name` must point to a NUL-terminated string (used for debugging only).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn memfd_create(name: *const c_char, flags: c_uint) -> c_int {
    unsafe { syscall_ret(syscall2(SYS_MEMFD_CREATE, name as usize, flags as usize)) as c_int }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use core::ffi::c_int;
    use core::sync::atomic::{AtomicU64, Ordering};

    use crate::errno::{__errno_location, errno_load};
    use crate::fcntl::{open, O_CREAT, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY};
    use crate::syscall::{syscall0, syscall3, syscall_ret};

    /// musl `arch/x86_64/bits/syscall.h.in` (test I/O + cleanup only).
    const SYS_READ: usize = 0; // TODO: generate from arch bits/syscall.h
    const SYS_WRITE: usize = 1; // TODO: generate from arch bits/syscall.h
    const SYS_CLOSE: usize = 3; // TODO: generate from arch bits/syscall.h
    const SYS_UNLINK: usize = 87; // TODO: generate from arch bits/syscall.h
    const SYS_GETEUID: usize = 107; // TODO: generate from arch bits/syscall.h

    /// musl `arch/generic/bits/errno.h` (failure-shape assertions only).
    const EPERM: c_int = 1;
    const EACCES: c_int = 13;
    const EINVAL: c_int = 22;
    const EROFS: c_int = 30;

    /// musl `include/sys/prctl.h` (test probe only; no state change).
    const PR_GET_DUMPABLE: c_int = 3;

    static CTR: AtomicU64 = AtomicU64::new(0);

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

    #[test]
    fn mount_umount_fail_unprivileged() {
        // Asserts an exact failure shape: serialize (see testlock docs).
        let _guard = crate::ldso::testlock::lock();
        // Privileged runners can mount for real; nothing safe to assert.
        if unsafe { syscall0(SYS_GETEUID) } == 0 {
            return;
        }
        unsafe {
            assert_eq!(
                mount(
                    c"none".as_ptr(),
                    c"/tmp".as_ptr(),
                    c"tmpfs".as_ptr(),
                    0,
                    core::ptr::null(),
                ),
                -1
            );
            let e = errno_load(__errno_location());
            assert!(e == EPERM || e == EACCES || e == EROFS, "mount errno {e}");
            // "/tmp" exists, so lookup succeeds and only the privilege
            // (or mountpoint) check can fail.
            assert_eq!(umount(c"/tmp".as_ptr()), -1);
            let e = errno_load(__errno_location());
            assert!(e == EPERM || e == EACCES || e == EINVAL, "umount errno {e}");
            assert_eq!(umount2(c"/tmp".as_ptr(), MNT_DETACH), -1);
            let e = errno_load(__errno_location());
            assert!(
                e == EPERM || e == EACCES || e == EINVAL,
                "umount2 errno {e}"
            );
        }
    }

    #[test]
    fn statfs_statvfs_tmp() {
        unsafe {
            let mut s: Statfs = core::mem::zeroed();
            assert_eq!(statfs(c"/tmp".as_ptr(), &mut s), 0);
            assert!(s.f_bsize > 0);
            assert!(s.f_blocks > 0);
            let mut v: Statvfs = core::mem::zeroed();
            assert_eq!(statvfs(c"/tmp".as_ptr(), &mut v), 0);
            assert_eq!(v.f_bsize, s.f_bsize);
            assert_eq!(
                v.f_frsize,
                if s.f_frsize != 0 {
                    s.f_frsize
                } else {
                    s.f_bsize
                }
            );
            assert_eq!(v.f_blocks, s.f_blocks);
            assert_eq!(v.f_bfree, s.f_bfree);
            assert_eq!(v.f_bavail, s.f_bavail);
            assert_eq!(v.f_files, s.f_files);
            assert_eq!(v.f_ffree, s.f_ffree);
            assert_eq!(v.f_favail, s.f_ffree);
            assert_eq!(v.f_namemax, s.f_namelen);
            assert_eq!(v.f_flag, s.f_flags);
            // Missing path: clean -1, never a partial struct.
            let mut v2: Statvfs = core::mem::zeroed();
            assert_eq!(statvfs(c"/tmp/zlibc-8e2-no-such-dir".as_ptr(), &mut v2), -1);
        }
    }

    #[test]
    fn fstatfs_fstatvfs_fd() {
        let path = tmp_cstr("fs");
        unsafe {
            let fd = open(path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o600);
            assert!(fd >= 0);
            let mut s: Statfs = core::mem::zeroed();
            assert_eq!(fstatfs(fd, &mut s), 0);
            assert!(s.f_bsize > 0);
            let mut v: Statvfs = core::mem::zeroed();
            assert_eq!(fstatvfs(fd, &mut v), 0);
            assert_eq!(v.f_bsize, s.f_bsize);
            assert_eq!(v.f_blocks, s.f_blocks);
            close(fd);
            unlink(path.as_ptr());
        }
    }

    #[test]
    fn sendfile_file_to_file() {
        // Reads errno on the old-kernel path: serialize (see testlock docs).
        let _guard = crate::ldso::testlock::lock();
        let src = tmp_cstr("sfs");
        let dst = tmp_cstr("sfd");
        let msg = b"sendfile-8e2-payload";
        unsafe {
            let wfd = open(src.as_ptr(), O_WRONLY | O_CREAT | O_TRUNC, 0o600);
            assert!(wfd >= 0);
            assert_eq!(
                syscall_ret(syscall3(
                    SYS_WRITE,
                    wfd as usize,
                    msg.as_ptr() as usize,
                    msg.len()
                )),
                msg.len() as isize
            );
            close(wfd);
            let rfd = open(src.as_ptr(), O_RDONLY, 0);
            assert!(rfd >= 0);
            let wfd = open(dst.as_ptr(), O_WRONLY | O_CREAT | O_TRUNC, 0o600);
            assert!(wfd >= 0);
            let n = sendfile(wfd, rfd, core::ptr::null_mut(), msg.len());
            close(rfd);
            close(wfd);
            if n == msg.len() as isize {
                let rfd = open(dst.as_ptr(), O_RDONLY, 0);
                assert!(rfd >= 0);
                let mut back = [0u8; 32];
                let r = syscall_ret(syscall3(
                    SYS_READ,
                    rfd as usize,
                    back.as_mut_ptr() as usize,
                    msg.len(),
                ));
                close(rfd);
                assert_eq!(r, msg.len() as isize);
                assert_eq!(&back[..msg.len()], msg);
            } else {
                // Old kernels only allow socket out_fds: clean -1, no crash.
                assert_eq!(n, -1);
                assert_ne!(errno_load(__errno_location()), 0);
            }
            unlink(src.as_ptr());
            unlink(dst.as_ptr());
        }
    }

    #[test]
    fn prctl_get_dumpable() {
        unsafe {
            let r = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
            assert!(r == 0 || r == 1, "PR_GET_DUMPABLE returned {r}");
        }
    }

    #[test]
    fn getrandom_fills() {
        unsafe {
            let mut b = [0u8; 32];
            let r = getrandom(b.as_mut_ptr() as *mut c_void, b.len(), 0);
            assert_eq!(r, b.len() as isize);
        }
    }

    #[test]
    fn memfd_create_write_read() {
        /// musl `arch/x86_64/bits/syscall.h.in` (rewind only).
        const SYS_LSEEK: usize = 8; // TODO: generate from arch bits/syscall.h
        let msg = b"memfd-8e2";
        unsafe {
            let fd = memfd_create(c"zlibc-8e2".as_ptr(), MFD_CLOEXEC);
            assert!(fd >= 0);
            assert_eq!(
                syscall_ret(syscall3(
                    SYS_WRITE,
                    fd as usize,
                    msg.as_ptr() as usize,
                    msg.len()
                )),
                msg.len() as isize
            );
            assert_eq!(syscall_ret(syscall3(SYS_LSEEK, fd as usize, 0, 0)), 0);
            let mut back = [0u8; 16];
            assert_eq!(
                syscall_ret(syscall3(
                    SYS_READ,
                    fd as usize,
                    back.as_mut_ptr() as usize,
                    msg.len()
                )),
                msg.len() as isize
            );
            assert_eq!(&back[..msg.len()], msg);
            close(fd);
        }
    }
}
