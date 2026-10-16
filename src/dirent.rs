//! Directory streams (musl `src/dirent/*`).
//!
//! `Dirent` mirrors `arch/generic/bits/dirent.h` field for field
//! (`d_ino:u64`, `d_off:i64`, `d_reclen:u16`, `d_type:u8`,
//! `d_name:[c_char;256]`, 280 bytes); `Dir` mirrors the `DIR` struct in
//! `src/dirent/__dirent.h` (`tell`, `fd`, `buf_pos`, `buf_end`, lock,
//! `buf[2048]` with `buf` at offset 24, i.e. `buf % 8 == 0`). The kernel
//! writes `linux_dirent64` records straight into `Dir.buf`, so
//! `readdir` just hands out pointers into it — exactly musl's shape.
//!
//! Locking: musl serialises each `DIR` with its embedded lock; here the
//! lock word is kept for layout but never waited on (single-threaded
//! streams; one `DIR` per thread like the rest of the crate).

use core::ffi::{c_char, c_int, c_long, c_void};

use crate::errno::{__errno_location, errno_store};
use crate::syscall::{syscall3, syscall_ret};

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_GETDENTS64: usize = 217; // TODO: generate from arch bits/syscall.h

// ---- Local consts (musl arch/generic/bits/fcntl.h, errno.h) -----------------
/// musl `O_DIRECTORY` (`0200000`); not re-exported by `crate::fcntl`.
#[cfg(target_arch = "x86_64")]
const O_DIRECTORY: c_int = 0o200000;
/// musl `O_PATH` (`010000000`); only used for the `fdopendir` probe.
#[cfg(target_arch = "x86_64")]
const O_PATH: c_int = 0o10000000;
#[cfg(target_arch = "x86_64")]
const EBADF: c_int = 9;
#[cfg(target_arch = "x86_64")]
const ENOENT: c_int = 2;
#[cfg(target_arch = "x86_64")]
const ENOMEM: c_int = 12;
#[cfg(target_arch = "x86_64")]
const ENOTDIR: c_int = 20;
#[cfg(target_arch = "x86_64")]
const EOVERFLOW: c_int = 75;
#[cfg(target_arch = "x86_64")]
const EOPNOTSUPP: c_int = 95;
#[cfg(target_arch = "x86_64")]
const INT_MAX: c_int = 2147483647;

/// musl `struct dirent` (`arch/generic/bits/dirent.h:5-11`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Dirent {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_name: [c_char; 256],
}

/// Opaque directory stream (musl `struct __dirstream`,
/// `src/dirent/__dirent.h:1-11`). The lock word is layout only (see
/// module docs); `buf` must stay at offset 24 (`% sizeof(off_t) == 0`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Dir {
    tell: i64,
    fd: c_int,
    buf_pos: c_int,
    buf_end: c_int,
    lock: [c_int; 1],
    buf: [u8; 2048],
}

// musl `include/dirent.h:50-58`.
#[cfg(target_arch = "x86_64")]
pub const DT_UNKNOWN: u8 = 0;
#[cfg(target_arch = "x86_64")]
pub const DT_FIFO: u8 = 1;
#[cfg(target_arch = "x86_64")]
pub const DT_CHR: u8 = 2;
#[cfg(target_arch = "x86_64")]
pub const DT_DIR: u8 = 4;
#[cfg(target_arch = "x86_64")]
pub const DT_BLK: u8 = 6;
#[cfg(target_arch = "x86_64")]
pub const DT_REG: u8 = 8;
#[cfg(target_arch = "x86_64")]
pub const DT_LNK: u8 = 10;
#[cfg(target_arch = "x86_64")]
pub const DT_SOCK: u8 = 12;
#[cfg(target_arch = "x86_64")]
pub const DT_WHT: u8 = 14;

/// Fetch the next buffered record, refilling from the kernel on
/// exhaustion (musl `readdir.c`: raw `SYS_getdents64`, `ENOENT` reads as
/// end-of-stream, any other raw error is stored as `errno`).
#[cfg(target_arch = "x86_64")]
unsafe fn readdir_raw(dir: *mut Dir) -> *mut Dirent {
    unsafe {
        if (*dir).buf_pos >= (*dir).buf_end {
            let len = syscall3(
                SYS_GETDENTS64,
                (*dir).fd as usize,
                (*dir).buf.as_mut_ptr() as usize,
                (*dir).buf.len(),
            );
            if len <= 0 {
                if len < 0 && len != -(ENOENT as isize) {
                    errno_store(__errno_location(), (-len) as c_int);
                }
                return core::ptr::null_mut();
            }
            (*dir).buf_end = len as c_int;
            (*dir).buf_pos = 0;
        }
        let de = (*dir).buf.as_mut_ptr().add((*dir).buf_pos as usize) as *mut Dirent;
        (*dir).buf_pos = (*dir).buf_pos.wrapping_add((*de).d_reclen as c_int);
        (*dir).tell = (*de).d_off;
        de
    }
}

/// Open a directory stream (musl `opendir.c`: `open` with
/// `O_RDONLY|O_DIRECTORY|O_CLOEXEC`, zeroed `DIR`, close-on-alloc-fail).
///
/// # Safety
///
/// `name` must point to a NUL-terminated string.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn opendir(name: *const c_char) -> *mut Dir {
    unsafe {
        let fd = crate::fcntl::open(
            name,
            crate::fcntl::O_RDONLY | O_DIRECTORY | crate::fcntl::O_CLOEXEC,
            0,
        );
        if fd < 0 {
            return core::ptr::null_mut();
        }
        let dir = crate::malloc::calloc(1, core::mem::size_of::<Dir>()) as *mut Dir;
        if dir.is_null() {
            crate::unistd::close(fd);
            return core::ptr::null_mut();
        }
        (*dir).fd = fd;
        dir
    }
}

/// Wrap a fd as a directory stream (musl `fdopendir.c`: `fstat` must say
/// directory, `O_PATH` fds are `EBADF`, `FD_CLOEXEC` is set).
///
/// # Safety
///
/// `fd` must be open; ownership moves into the stream on success (close
/// it with [`closedir`], not `close`).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fdopendir(fd: c_int) -> *mut Dir {
    unsafe {
        let mut st: crate::stat::Stat = core::mem::zeroed();
        if crate::stat::fstat(fd, &mut st) < 0 {
            return core::ptr::null_mut();
        }
        if crate::fcntl::fcntl(fd, crate::fcntl::F_GETFL, 0) & O_PATH != 0 {
            errno_store(__errno_location(), EBADF);
            return core::ptr::null_mut();
        }
        if !crate::stat::S_ISDIR(st.st_mode) {
            errno_store(__errno_location(), ENOTDIR);
            return core::ptr::null_mut();
        }
        let dir = crate::malloc::calloc(1, core::mem::size_of::<Dir>()) as *mut Dir;
        if dir.is_null() {
            return core::ptr::null_mut();
        }
        crate::fcntl::fcntl(fd, crate::fcntl::F_SETFD, crate::fcntl::FD_CLOEXEC as usize);
        (*dir).fd = fd;
        dir
    }
}

/// Read the next entry (musl `readdir.c`).
///
/// # Safety
///
/// `dir` must be a live stream from [`opendir`]/[`fdopendir`]. The
/// result borrows `dir`'s buffer — it dies at the next `readdir`,
/// `seekdir`, `rewinddir` or [`closedir`]. NULL means end (check `errno`
/// for an error).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn readdir(dir: *mut Dir) -> *mut Dirent {
    unsafe { readdir_raw(dir) }
}

/// Reentrant read (musl `readdir_r.c`: `errno`-preserving, copies
/// `d_reclen` bytes into the caller buffer, `*result = NULL` at end).
///
/// # Safety
///
/// `dir` must be live; `buf` must be writable for at least one maximal
/// entry (`size_of::<Dirent>()`); `result` must be writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn readdir_r(
    dir: *mut Dir,
    buf: *mut Dirent,
    result: *mut *mut Dirent,
) -> c_int {
    unsafe {
        // Error state rides an out-param, not the errno cell: under
        // libtest threads the process-global fallback cell is shared,
        // so musl's clear-and-reread protocol can observe another
        // thread's error here (observed: stale ENOENT at end-of-dir).
        // Production threads have private cells and see identical
        // values either way.
        let mut err = 0 as c_int;
        let de = readdir_raw_err(dir, &mut err);
        if err != 0 {
            return err;
        }
        if de.is_null() {
            *result = core::ptr::null_mut();
        } else {
            crate::mem::memcpy(
                buf as *mut c_void,
                de as *const c_void,
                (*de).d_reclen as usize,
            );
            *result = buf;
        }
        0
    }
}

/// [`readdir_raw`] plus an error out-param (`0` end-of-stream, else the
/// errno). Lets [`readdir_r`] report failures without reading the
/// (possibly shared) errno cell.
///
/// # Safety
///
/// Same contract as [`readdir_raw`]; `err` must be writable.
#[cfg(target_arch = "x86_64")]
unsafe fn readdir_raw_err(dir: *mut Dir, err: *mut c_int) -> *mut Dirent {
    unsafe {
        if (*dir).buf_pos >= (*dir).buf_end {
            let len = syscall3(
                SYS_GETDENTS64,
                (*dir).fd as usize,
                (*dir).buf.as_mut_ptr() as usize,
                (*dir).buf.len(),
            );
            if len <= 0 {
                if len < 0 && len != -(ENOENT as isize) {
                    *err = (-len) as c_int;
                }
                return core::ptr::null_mut();
            }
            (*dir).buf_end = len as c_int;
            (*dir).buf_pos = 0;
        }
        let de = (*dir).buf.as_mut_ptr().add((*dir).buf_pos as usize) as *mut Dirent;
        (*dir).buf_pos = (*dir).buf_pos.wrapping_add((*de).d_reclen as c_int);
        (*dir).tell = (*de).d_off;
        de
    }
}

/// Close a stream (musl `closedir.c`: `close` the fd, `free` the `DIR`).
///
/// # Safety
///
/// `dir` must be live; it dies here.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn closedir(dir: *mut Dir) -> c_int {
    unsafe {
        let ret = crate::unistd::close((*dir).fd);
        crate::malloc::free(dir as *mut c_void);
        ret
    }
}

/// Restart a stream (musl `rewinddir.c`: `lseek(0)`, drop the buffer).
///
/// # Safety
///
/// `dir` must be live.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn rewinddir(dir: *mut Dir) {
    unsafe {
        crate::unistd::lseek((*dir).fd, 0, crate::unistd::SEEK_SET);
        (*dir).buf_pos = 0;
        (*dir).buf_end = 0;
        (*dir).tell = 0;
    }
}

/// Reposition a stream on a `telldir` cookie (musl `seekdir.c`: `lseek`
/// to the cookie, drop the buffer).
///
/// # Safety
///
/// `dir` must be live; `off` must be a cookie from [`telldir`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn seekdir(dir: *mut Dir, off: c_long) {
    unsafe {
        (*dir).tell = crate::unistd::lseek((*dir).fd, off, crate::unistd::SEEK_SET);
        (*dir).buf_pos = 0;
        (*dir).buf_end = 0;
    }
}

/// Current stream cookie (musl `telldir.c`).
///
/// # Safety
///
/// `dir` must be live.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn telldir(dir: *mut Dir) -> c_long {
    unsafe { (*dir).tell as c_long }
}

/// Stream's fd (musl `dirfd.c`).
///
/// # Safety
///
/// `dir` must be live; the fd stays owned by the stream.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn dirfd(dir: *mut Dir) -> c_int {
    unsafe { (*dir).fd }
}

/// Raw entries into a caller buffer (musl `getdents` under `_GNU_SOURCE`:
/// one `SYS_getdents64` trap through `syscall_ret`).
///
/// # Safety
///
/// `dirp` must be writable for `count` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getdents(fd: c_int, dirp: *mut Dirent, count: usize) -> c_int {
    unsafe { syscall_ret(syscall3(SYS_GETDENTS64, fd as usize, dirp as usize, count)) as c_int }
}

/// Flag-gated raw entries (musl `posix_getdents.c`: nonzero flags are
/// `EOPNOTSUPP`, length clamps to `INT_MAX`).
///
/// # Safety
///
/// `buf` must be writable for `len` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_getdents(
    fd: c_int,
    buf: *mut c_void,
    len: usize,
    flags: c_int,
) -> isize {
    unsafe {
        if flags != 0 {
            return syscall_ret(-(EOPNOTSUPP as isize));
        }
        let n = if len > INT_MAX as usize {
            INT_MAX as usize
        } else {
            len
        };
        syscall_ret(syscall3(SYS_GETDENTS64, fd as usize, buf as usize, n))
    }
}

/// Byte-wise (`strcmp`-order) name compare: unsigned bytes to NUL.
/// musl uses `strcoll` (locale wave, Ola 9); byte order is the portable
/// subset and sorts `scripts/` before locales exist.
#[cfg(target_arch = "x86_64")]
unsafe fn name_cmp(a: *const c_char, b: *const c_char) -> c_int {
    unsafe {
        let mut i: usize = 0;
        loop {
            let ca = *(a.add(i) as *const u8);
            let cb = *(b.add(i) as *const u8);
            if ca != cb {
                return ca as c_int - cb as c_int;
            }
            if ca == 0 {
                return 0;
            }
            i = i.wrapping_add(1);
        }
    }
}

/// Numeric-run-aware name compare (musl `versionsort.c` uses
/// `strverscmp`, also Ola 9): non-digit runs compare byte-wise, digit
/// runs compare by value (longer run wins, then first differing digit),
/// ties break toward fewer leading zeros. Approximation of glibc's
/// `strverscmp` — enough that `file2 < file10`; full version
/// semantics come with the locale wave.
#[cfg(target_arch = "x86_64")]
unsafe fn name_verscmp(a: *const c_char, b: *const c_char) -> c_int {
    unsafe {
        let mut i: usize = 0;
        let mut j: usize = 0;
        loop {
            let ca = *(a.add(i) as *const u8);
            let cb = *(b.add(j) as *const u8);
            if ca == 0 && cb == 0 {
                return 0;
            }
            if ca == 0 {
                return -1;
            }
            if cb == 0 {
                return 1;
            }
            if ca.is_ascii_digit() && cb.is_ascii_digit() {
                let mut z1: usize = 0;
                while *(a.add(i) as *const u8) == b'0' {
                    i = i.wrapping_add(1);
                    z1 = z1.wrapping_add(1);
                }
                let mut z2: usize = 0;
                while *(b.add(j) as *const u8) == b'0' {
                    j = j.wrapping_add(1);
                    z2 = z2.wrapping_add(1);
                }
                let mut l1: usize = 0;
                while (*(a.add(i.wrapping_add(l1)) as *const u8)).is_ascii_digit() {
                    l1 = l1.wrapping_add(1);
                }
                let mut l2: usize = 0;
                while (*(b.add(j.wrapping_add(l2)) as *const u8)).is_ascii_digit() {
                    l2 = l2.wrapping_add(1);
                }
                if l1 != l2 {
                    return if l1 > l2 { 1 } else { -1 };
                }
                let mut k: usize = 0;
                while k < l1 {
                    let da = *(a.add(i.wrapping_add(k)) as *const u8);
                    let db = *(b.add(j.wrapping_add(k)) as *const u8);
                    if da != db {
                        return da as c_int - db as c_int;
                    }
                    k = k.wrapping_add(1);
                }
                if z1 != z2 {
                    return if z1 < z2 { -1 } else { 1 };
                }
                i = i.wrapping_add(l1);
                j = j.wrapping_add(l2);
            } else {
                if ca != cb {
                    return ca as c_int - cb as c_int;
                }
                i = i.wrapping_add(1);
                j = j.wrapping_add(1);
            }
        }
    }
}

/// Sort callback: byte order (musl `alphasort.c`; `strcoll`→`strcmp`
/// downgrade, see [`name_cmp`]).
///
/// # Safety
///
/// Both double-pointers must be readable with valid entry pointers.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn alphasort(a: *const *const Dirent, b: *const *const Dirent) -> c_int {
    unsafe { name_cmp((**a).d_name.as_ptr(), (**b).d_name.as_ptr()) }
}

/// Sort callback: version order (musl `versionsort.c`; approximation,
/// see [`name_verscmp`]).
///
/// # Safety
///
/// Same contract as [`alphasort`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn versionsort(a: *const *const Dirent, b: *const *const Dirent) -> c_int {
    unsafe { name_verscmp((**a).d_name.as_ptr(), (**b).d_name.as_ptr()) }
}

/// Scan a directory into a `malloc`'d, optionally filtered and sorted
/// name list (musl `scandir.c`: `opendir`/`readdir`/`closedir`, grow
/// `2*len+1`, `EOVERFLOW` past `INT_MAX`, entry copies sized
/// `d_reclen`).
///
/// Sort is an in-place O(n²) selection calling `compar` directly.
// ponytail: bubble-grade sort, qsort (Ola 9) replaces it when big dirs show up.
// Cancellation points collapse (no cancellation exists, like `crate::net`).
///
/// # Safety
///
/// `path` NUL; `res` writable; `sel`/`compar` nullable callbacks with
/// the `alphasort` signature. On success `*res` holds `malloc`'d
/// entries the caller frees entry-by-entry plus the list itself.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn scandir(
    path: *const c_char,
    res: *mut *mut *mut Dirent,
    sel: Option<unsafe extern "C" fn(*const Dirent) -> c_int>,
    compar: Option<unsafe extern "C" fn(*const *const Dirent, *const *const Dirent) -> c_int>,
) -> c_int {
    unsafe {
        let d = opendir(path);
        if d.is_null() {
            return -1;
        }
        // Fill errors ride an out-param, not the errno cell: under
        // shared-cell threads a stale value here fails successful scans
        // (same class as the old readdir_r protocol, now fixed there).
        let mut err = 0 as c_int;
        let mut names: *mut *mut Dirent = core::ptr::null_mut();
        let mut cnt: usize = 0;
        let mut len: usize = 0;
        loop {
            let de = readdir_raw_err(d, &mut err);
            if de.is_null() {
                break;
            }
            if let Some(sel) = sel {
                if sel(de as *const Dirent) == 0 {
                    continue;
                }
            }
            if cnt >= INT_MAX as usize {
                err = EOVERFLOW;
                break;
            }
            if cnt >= len {
                len = len.wrapping_mul(2).wrapping_add(1);
                if len > usize::MAX / core::mem::size_of::<*mut Dirent>() {
                    err = EOVERFLOW;
                    break;
                }
                let tmp = crate::malloc::realloc(
                    names as *mut c_void,
                    len.wrapping_mul(core::mem::size_of::<*mut Dirent>()),
                ) as *mut *mut Dirent;
                if tmp.is_null() {
                    err = ENOMEM;
                    break;
                }
                names = tmp;
            }
            let cp = crate::malloc::malloc((*de).d_reclen as usize) as *mut Dirent;
            if cp.is_null() {
                err = ENOMEM;
                break;
            }
            crate::mem::memcpy(
                cp as *mut c_void,
                de as *const c_void,
                (*de).d_reclen as usize,
            );
            *names.add(cnt) = cp;
            cnt = cnt.wrapping_add(1);
        }
        closedir(d);
        if err != 0 {
            if !names.is_null() {
                while cnt > 0 {
                    cnt = cnt.wrapping_sub(1);
                    crate::malloc::free(*names.add(cnt) as *mut c_void);
                }
                crate::malloc::free(names as *mut c_void);
            }
            errno_store(__errno_location(), err);
            return -1;
        }
        if let Some(cmp) = compar {
            let mut i: usize = 0;
            while i < cnt {
                let mut m = i;
                let mut k = i.wrapping_add(1);
                while k < cnt {
                    if cmp(
                        names.add(k) as *const *const Dirent,
                        names.add(m) as *const *const Dirent,
                    ) < 0
                    {
                        m = k;
                    }
                    k = k.wrapping_add(1);
                }
                let t = *names.add(i);
                *names.add(i) = *names.add(m);
                *names.add(m) = t;
                i = i.wrapping_add(1);
            }
        }
        *res = names;
        cnt as c_int
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use crate::errno::errno_load;
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::string::{String, ToString};
    use std::vec::Vec;

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn fresh_dir(tag: &str) -> std::path::PathBuf {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(std::format!(
            "zlibc-dirent-{tag}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir(&p).unwrap();
        p
    }

    fn cstr(p: &std::path::Path) -> std::ffi::CString {
        std::ffi::CString::new(p.to_str().unwrap()).unwrap()
    }

    // No remove_dir_all: std lists dirs via glibc readdir64_r, outside this
    // module's surface, which misreads our DIR layout. List with our own
    // readdir and unlink explicitly instead.
    fn cleanup(dir: &std::path::Path) {
        let c = cstr(dir);
        unsafe {
            let d = opendir(c.as_ptr());
            assert!(!d.is_null());
            let names = collect_names(d);
            assert_eq!(closedir(d), 0);
            for n in &names {
                if n != "." && n != ".." {
                    std::fs::remove_file(dir.join(n)).unwrap();
                }
            }
        }
        std::fs::remove_dir(dir).unwrap();
    }

    unsafe fn collect_names(d: *mut Dir) -> Vec<String> {
        unsafe {
            let mut out = Vec::new();
            loop {
                let de = readdir(d);
                if de.is_null() {
                    break;
                }
                assert!((*de).d_reclen > 0);
                out.push(
                    std::ffi::CStr::from_ptr((*de).d_name.as_ptr())
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            out
        }
    }

    unsafe extern "C" fn sel_no_dots(de: *const Dirent) -> c_int {
        unsafe {
            if (*de).d_name[0] as u8 == b'.' {
                0
            } else {
                1
            }
        }
    }

    #[test]
    fn layout_matches_musl() {
        assert_eq!(core::mem::size_of::<Dirent>(), 280);
        assert_eq!(core::mem::offset_of!(Dirent, d_ino), 0);
        assert_eq!(core::mem::offset_of!(Dirent, d_off), 8);
        assert_eq!(core::mem::offset_of!(Dirent, d_reclen), 16);
        assert_eq!(core::mem::offset_of!(Dirent, d_type), 18);
        assert_eq!(core::mem::offset_of!(Dirent, d_name), 19);
        // __dirent.h: buf % sizeof(off_t) == 0.
        assert_eq!(core::mem::offset_of!(Dir, buf), 24);
        assert_eq!(core::mem::offset_of!(Dir, buf) % 8, 0);
        assert_eq!((DT_UNKNOWN, DT_FIFO, DT_CHR, DT_DIR), (0, 1, 2, 4));
        assert_eq!(
            (DT_BLK, DT_REG, DT_LNK, DT_SOCK, DT_WHT),
            (6, 8, 10, 12, 14)
        );
    }

    #[test]
    fn opendir_readdir_finds_files() {
        let dir = fresh_dir("read");
        std::fs::write(dir.join("alpha"), b"a").unwrap();
        std::fs::write(dir.join("beta"), b"b").unwrap();
        std::fs::write(dir.join("gamma"), b"c").unwrap();
        let c = cstr(&dir);
        unsafe {
            let d = opendir(c.as_ptr());
            assert!(!d.is_null());
            let names = collect_names(d);
            assert!(names.contains(&"alpha".to_string()));
            assert!(names.contains(&"beta".to_string()));
            assert!(names.contains(&"gamma".to_string()));
            assert_eq!(closedir(d), 0);
        }
        cleanup(&dir);
    }

    #[test]
    fn opendir_missing_is_null() {
        let _guard = crate::ldso::testlock::lock();
        let dir = fresh_dir("miss");
        let ghost = cstr(&dir.join("ghost"));
        unsafe {
            assert!(opendir(ghost.as_ptr()).is_null());
            assert_eq!(errno_load(__errno_location()), ENOENT);
        }
        cleanup(&dir);
    }

    #[test]
    fn fdopendir_dirfd_closedir() {
        let _guard = crate::ldso::testlock::lock();
        let dir = fresh_dir("fd");
        std::fs::write(dir.join("x"), b"x").unwrap();
        let c = cstr(&dir);
        unsafe {
            let fd = crate::fcntl::open(c.as_ptr(), crate::fcntl::O_RDONLY | O_DIRECTORY, 0);
            assert!(fd >= 0);
            let d = fdopendir(fd);
            assert!(!d.is_null());
            assert_eq!(dirfd(d), fd);
            assert!(collect_names(d).contains(&"x".to_string()));
            assert_eq!(closedir(d), 0);
            // Regular file fd is ENOTDIR.
            let f = cstr(&dir.join("x"));
            let rfd = crate::fcntl::open(f.as_ptr(), crate::fcntl::O_RDONLY, 0);
            assert!(rfd >= 0);
            assert!(fdopendir(rfd).is_null());
            assert_eq!(errno_load(__errno_location()), ENOTDIR);
            crate::unistd::close(rfd);
            // Dead fd fails.
            assert!(fdopendir(-1).is_null());
        }
        cleanup(&dir);
    }

    #[test]
    fn telldir_seekdir_roundtrip() {
        let dir = fresh_dir("seek");
        for n in ["s1", "s2", "s3", "s4"] {
            std::fs::write(dir.join(n), b"v").unwrap();
        }
        let c = cstr(&dir);
        unsafe {
            let d = opendir(c.as_ptr());
            assert!(!d.is_null());
            // Skip "." / "..", whatever order the fs gives.
            let mut first = std::ffi::CStr::from_ptr((*readdir(d)).d_name.as_ptr())
                .to_string_lossy()
                .into_owned();
            while first == "." || first == ".." {
                first = std::ffi::CStr::from_ptr((*readdir(d)).d_name.as_ptr())
                    .to_string_lossy()
                    .into_owned();
            }
            let cookie = telldir(d);
            let second = std::ffi::CStr::from_ptr((*readdir(d)).d_name.as_ptr())
                .to_string_lossy()
                .into_owned();
            // Drain to end so the re-seek replays buffered records too.
            while !readdir(d).is_null() {}
            seekdir(d, cookie);
            let replay = std::ffi::CStr::from_ptr((*readdir(d)).d_name.as_ptr())
                .to_string_lossy()
                .into_owned();
            assert_eq!(replay, second);
            assert_eq!(closedir(d), 0);
        }
        cleanup(&dir);
    }

    #[test]
    fn rewinddir_restarts() {
        let dir = fresh_dir("rew");
        std::fs::write(dir.join("only"), b"v").unwrap();
        let c = cstr(&dir);
        unsafe {
            let d = opendir(c.as_ptr());
            assert!(!d.is_null());
            let a = collect_names(d);
            rewinddir(d);
            let b = collect_names(d);
            assert_eq!(a, b);
            assert!(b.contains(&"only".to_string()));
            assert_eq!(closedir(d), 0);
        }
        cleanup(&dir);
    }

    #[test]
    fn readdir_r_matches_readdir() {
        let dir = fresh_dir("rr");
        for n in ["r1", "r2", "r3"] {
            std::fs::write(dir.join(n), b"v").unwrap();
        }
        let c = cstr(&dir);
        unsafe {
            let d = opendir(c.as_ptr());
            assert!(!d.is_null());
            let want = collect_names(d);
            rewinddir(d);
            let mut got = Vec::new();
            loop {
                let mut buf: Dirent = core::mem::zeroed();
                let mut out: *mut Dirent = core::ptr::null_mut();
                assert_eq!(readdir_r(d, &mut buf, &mut out), 0);
                if out.is_null() {
                    break;
                }
                assert_eq!(out, &mut buf as *mut Dirent);
                got.push(
                    std::ffi::CStr::from_ptr(buf.d_name.as_ptr())
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            assert_eq!(got, want);
            assert_eq!(closedir(d), 0);
        }
        cleanup(&dir);
    }

    #[test]
    fn scandir_sorts_and_filters() {
        let dir = fresh_dir("scan");
        for n in ["b10", "b2", "b1"] {
            std::fs::write(dir.join(n), b"v").unwrap();
        }
        let c = cstr(&dir);
        unsafe {
            // alphasort: pure byte order.
            let mut list: *mut *mut Dirent = core::ptr::null_mut();
            let n = scandir(c.as_ptr(), &mut list, Some(sel_no_dots), Some(alphasort));
            assert_eq!(n, 3);
            let names: Vec<String> = (0..n as usize)
                .map(|i| {
                    std::ffi::CStr::from_ptr((**list.add(i)).d_name.as_ptr())
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();
            assert_eq!(names, ["b1", "b10", "b2"]);
            // versionsort: numeric runs win.
            let mut list2: *mut *mut Dirent = core::ptr::null_mut();
            let m = scandir(c.as_ptr(), &mut list2, Some(sel_no_dots), Some(versionsort));
            assert_eq!(m, 3);
            let names2: Vec<String> = (0..m as usize)
                .map(|i| {
                    std::ffi::CStr::from_ptr((**list2.add(i)).d_name.as_ptr())
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();
            assert_eq!(names2, ["b1", "b2", "b10"]);
            // Compar callbacks agree directly.
            let a = &**list.add(0) as *const Dirent;
            let b = &**list.add(1) as *const Dirent;
            assert!(
                alphasort(
                    &(a as *const Dirent) as *const *const Dirent,
                    &(b as *const Dirent) as *const *const Dirent
                ) != 0
            );
            for i in 0..n as usize {
                crate::malloc::free(*list.add(i) as *mut c_void);
            }
            crate::malloc::free(list as *mut c_void);
            for i in 0..m as usize {
                crate::malloc::free(*list2.add(i) as *mut c_void);
            }
            crate::malloc::free(list2 as *mut c_void);
        }
        cleanup(&dir);
    }

    #[test]
    fn scandir_missing_is_minus_one() {
        let _guard = crate::ldso::testlock::lock();
        let dir = fresh_dir("scanmiss");
        let ghost = cstr(&dir.join("ghost"));
        unsafe {
            let mut list: *mut *mut Dirent = core::ptr::null_mut();
            assert_eq!(
                scandir(ghost.as_ptr(), &mut list, None, Some(alphasort)),
                -1
            );
            assert_eq!(errno_load(__errno_location()), ENOENT);
        }
        cleanup(&dir);
    }

    #[test]
    fn getdents_raw_parses() {
        let _guard = crate::ldso::testlock::lock();
        let dir = fresh_dir("raw");
        std::fs::write(dir.join("rawfile"), b"v").unwrap();
        let c = cstr(&dir);
        unsafe {
            let fd = crate::fcntl::open(c.as_ptr(), crate::fcntl::O_RDONLY | O_DIRECTORY, 0);
            assert!(fd >= 0);
            // posix_getdents rejects flags.
            let mut pad = [0u64; 64];
            assert_eq!(
                posix_getdents(fd, pad.as_mut_ptr() as *mut c_void, 512, 1),
                -1
            );
            assert_eq!(errno_load(__errno_location()), EOPNOTSUPP);
            // Both raw paths return records from a rewound offset.
            crate::unistd::lseek(fd, 0, crate::unistd::SEEK_SET);
            let n = getdents(fd, pad.as_mut_ptr() as *mut Dirent, 512);
            assert!(n > 0);
            crate::unistd::lseek(fd, 0, crate::unistd::SEEK_SET);
            let m = posix_getdents(fd, pad.as_mut_ptr() as *mut c_void, 512, 0);
            assert!(m > 0);
            let mut off = 0;
            let mut found = false;
            while off < n as usize {
                let de = (pad.as_mut_ptr() as *mut u8).add(off) as *mut Dirent;
                assert!((*de).d_reclen >= 19);
                let nm = std::ffi::CStr::from_ptr((*de).d_name.as_ptr())
                    .to_string_lossy()
                    .into_owned();
                if nm == "rawfile" {
                    found = true;
                }
                off = off.wrapping_add((*de).d_reclen as usize);
            }
            assert!(found);
            crate::unistd::close(fd);
        }
        cleanup(&dir);
    }
}
