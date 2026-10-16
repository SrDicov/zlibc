//! Temp names/files/dirs + path resolution (musl `src/temp/*` and
//! `src/misc/realpath.c`).
//!
//! Clean-room mirrors: template rules (`XXXXXX` position checks,
//! `EINVAL` restores, `EEXIST` retries), `O_ACCMODE` stripping,
//! `0600`/`0700` modes, and musl's `realpath` stack/output algorithm
//! are verbatim in behavior; only the helpers underneath differ:
//!
//! - Randomness: musl's `__randname` mixes `CLOCK_REALTIME` + tid; here
//!   one raw `getrandom` trap (318) fills the 30 bits the mapping
//!   consumes, falling back to a static atomic counter mixed with the
//!   pid when the trap fails (early boot, seccomp). The `A-P,a-p`
//!   mapping itself is musl's, 5 bits per char.
//! - `stat` (mktemp) is a raw `newfstatat` (262) into a 144-byte sink
//!   (the kernel `struct stat` size on x86_64; never parsed, only the
//!   return code matters); `mkdir` a raw `mkdirat` (258); `getcwd` a
//!   raw trap (79). `open`/`readlink` reuse `crate::fcntl::open` and
//!   `crate::ldso::dso::readlink` (ladder rung 2: already in-tree).
//! - `PATH_MAX` is 4096, `SYMLOOP_MAX` 40 (musl `limits.h`).

use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::errno::{__errno_location, errno_load, errno_store};
use crate::fcntl::{open, AT_FDCWD, O_ACCMODE, O_CREAT, O_EXCL, O_RDWR};
use crate::ldso::dso::readlink;
use crate::mem::{memcmp, memcpy, memmove, strlen};
use crate::string::{strchrnul, strdup, strnlen};
use crate::syscall::{syscall0, syscall2, syscall3, syscall4, syscall_ret};

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_GETPID: usize = 39; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_GETCWD: usize = 79; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_MKDIRAT: usize = 258; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_NEWFSTATAT: usize = 262; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_GETRANDOM: usize = 318; // TODO: generate from arch bits/syscall.h

// ---- Errnos (musl arch/generic/bits/errno.h) --------------------------------
#[cfg(target_arch = "x86_64")]
const ENOENT: c_int = 2;
#[cfg(target_arch = "x86_64")]
const EEXIST: c_int = 17;
#[cfg(target_arch = "x86_64")]
const EINVAL: c_int = 22;
#[cfg(target_arch = "x86_64")]
const ENAMETOOLONG: c_int = 36;
#[cfg(target_arch = "x86_64")]
const ELOOP: c_int = 40;

/// musl `include/limits.h` (`PATH_MAX`, `SYMLOOP_MAX`).
#[cfg(target_arch = "x86_64")]
const PATH_MAX: usize = 4096;
#[cfg(target_arch = "x86_64")]
const SYMLOOP_MAX: usize = 40;

/// Fallback entropy counter (see [`rand_fill`]).
static RAND_CTR: AtomicU64 = AtomicU64::new(0x9E3779B97F4A7C15);

/// Fill 6 bytes at `tail` with musl `__randname`'s mapping
/// (`'A'+(r&15)+(r&16)*2`, 5 bits per char): `getrandom` entropy when
/// the trap yields 6 bytes, else a pid-mixed atomic counter diffused
/// with one splitmix64 round (documented deviation, same alphabet).
///
/// # Safety
///
/// `tail` must be writable for 6 bytes.
unsafe fn rand_fill(tail: *mut c_char) {
    unsafe {
        let mut r: u64 = 0;
        let got = syscall3(SYS_GETRANDOM, (&mut r as *mut u64) as usize, 6, 0);
        if got != 6 {
            let pid = syscall0(SYS_GETPID) as u64;
            let c = RAND_CTR.fetch_add(1, Ordering::Relaxed);
            r = c
                .wrapping_add(pid.wrapping_mul(0xBF58476D1CE4E5B9))
                .wrapping_add(0x9E3779B97F4A7C15);
            r = (r ^ (r >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            r ^= r >> 27;
        }
        let mut v = r;
        let mut i = 0usize;
        while i < 6 {
            *tail.add(i) =
                b'A'.wrapping_add((v & 15) as u8)
                    .wrapping_add(((v & 16) as u8).wrapping_mul(2)) as c_char;
            v >>= 5;
            i = i.wrapping_add(1);
        }
    }
}

/// Byte offset of the `XXXXXX` run for a template of length `l` with a
/// `len`-byte suffix (caller validated: `l >= 6`, `len <= l - 6`).
fn xpos(l: usize, len: usize) -> usize {
    l.wrapping_sub(6).wrapping_sub(len)
}

/// True when the `len`-suffixed template ends its stem with `XXXXXX`.
/// (`template` valid for `l` reads; called only after the length gate.)
///
/// # Safety
///
/// Same validity as `strlen` + 6 readable bytes at the run.
unsafe fn has_run(template: *const c_char, l: usize, len: usize) -> bool {
    unsafe {
        memcmp(
            template.add(xpos(l, len)) as *const c_void,
            c"XXXXXX".as_ptr() as *const c_void,
            6,
        ) == 0
    }
}

/// Restore the `XXXXXX` run (musl's failure epilogue in `__mkostemps`
/// and `mkdtemp`).
///
/// # Safety
///
/// `template` must be writable for `l` bytes; run position as in
/// [`xpos`].
unsafe fn restore_run(template: *mut c_char, l: usize, len: usize) {
    unsafe {
        memcpy(
            template.add(xpos(l, len)) as *mut c_void,
            c"XXXXXX".as_ptr() as *const c_void,
            6,
        );
    }
}

/// musl `__mkostemps` (src/temp/mkostemps.c), crate-private: open
/// `O_RDWR|O_CREAT|O_EXCL` (`0600`) on successive random names, up to
/// 100 tries while the kernel reports `EEXIST`; any other failure (or
/// a bad template: `EINVAL`) restores the run and returns `-1`.
///
/// # Safety
///
/// `template` must be a writable NUL-terminated string.
unsafe fn mkostemps_inner(template: *mut c_char, len: c_int, flags: c_int) -> c_int {
    unsafe {
        let l = strlen(template);
        let ulen = len as usize;
        if l < 6 || len < 0 || ulen > l.wrapping_sub(6) || !has_run(template, l, ulen) {
            errno_store(__errno_location(), EINVAL);
            return -1;
        }
        let fl = flags.wrapping_sub(flags & O_ACCMODE) | O_RDWR | O_CREAT | O_EXCL;
        let mut retries = 100;
        loop {
            rand_fill(template.add(xpos(l, ulen)));
            let fd = open(template, fl, 0o600);
            if fd >= 0 {
                return fd;
            }
            if errno_load(__errno_location()) != EEXIST {
                break;
            }
            retries -= 1;
            if retries == 0 {
                break;
            }
        }
        restore_run(template, l, ulen);
        -1
    }
}

/// Count leading slashes (musl `realpath.c:slash_len`).
///
/// # Safety
///
/// `s` must be readable up to and including the first non-`/` byte.
unsafe fn slash_len(s: *const u8) -> usize {
    unsafe {
        let mut n = 0usize;
        while *s.add(n) == b'/' {
            n = n.wrapping_add(1);
        }
        n
    }
}

/// `ENAMETOOLONG` + null (musl `realpath.c:toolong`).
unsafe fn toolong() -> *mut c_char {
    unsafe {
        errno_store(__errno_location(), ENAMETOOLONG);
        null_mut()
    }
}

/// Generate a unique temp name without creating anything (musl
/// `mktemp`): 100 random tries, first name absent from the filesystem
/// wins; a bad template empties `*template` with `EINVAL`, no
/// testable name after 100 hits with `EEXIST`.
///
/// # Safety
///
/// `template` must be a writable NUL-terminated string.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mktemp(template: *mut c_char) -> *mut c_char {
    unsafe {
        let l = strlen(template);
        if l < 6 || !has_run(template, l, 0) {
            errno_store(__errno_location(), EINVAL);
            *template = 0;
            return template;
        }
        let mut retries = 100;
        loop {
            rand_fill(template.add(xpos(l, 0)));
            // Kernel `struct stat` (144 bytes on x86_64): never parsed,
            // only the return code matters (0 = name taken, retry).
            let mut st = [0u8; 144];
            let r = syscall_ret(syscall4(
                SYS_NEWFSTATAT,
                AT_FDCWD as usize,
                template as usize,
                st.as_mut_ptr() as usize,
                0,
            ));
            if r != 0 {
                if errno_load(__errno_location()) != ENOENT {
                    *template = 0;
                }
                return template;
            }
            retries -= 1;
            if retries == 0 {
                break;
            }
        }
        *template = 0;
        errno_store(__errno_location(), EEXIST);
        template
    }
}

/// Create and open a unique temp file (musl `mkstemp`).
///
/// # Safety
///
/// `template` must be a writable NUL-terminated string ending in
/// `XXXXXX`; the run is replaced by the chosen name.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mkstemp(template: *mut c_char) -> c_int {
    unsafe { mkostemps_inner(template, 0, 0) }
}

/// Create and open a unique temp file with a suffix (musl `mkstemps`):
/// `len` bytes after the `XXXXXX` run are kept verbatim.
///
/// # Safety
///
/// Same as [`mkstemp`], plus the run must sit exactly `len` bytes
/// before the terminator.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mkstemps(template: *mut c_char, len: c_int) -> c_int {
    unsafe { mkostemps_inner(template, len, 0) }
}

/// Create and open a unique temp file honoring `flags` (notably
/// `O_CLOEXEC`; access-mode bits are stripped like musl).
///
/// # Safety
///
/// Same as [`mkstemp`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mkostemp(template: *mut c_char, flags: c_int) -> c_int {
    unsafe { mkostemps_inner(template, 0, flags) }
}

/// Suffix variant of [`mkostemp`] (musl `mkostemps`).
///
/// # Safety
///
/// Same as [`mkstemps`], plus `flags` as in [`mkostemp`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mkostemps(template: *mut c_char, len: c_int, flags: c_int) -> c_int {
    unsafe { mkostemps_inner(template, len, flags) }
}

/// Create a unique temp directory with mode `0700` (musl `mkdtemp`):
/// null on a bad template (`EINVAL`) or 100 `EEXIST` collisions.
///
/// # Safety
///
/// `template` must be a writable NUL-terminated string ending in
/// `XXXXXX`; the run is replaced by the chosen name.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mkdtemp(template: *mut c_char) -> *mut c_char {
    unsafe {
        let l = strlen(template);
        if l < 6 || !has_run(template, l, 0) {
            errno_store(__errno_location(), EINVAL);
            return null_mut();
        }
        let mut retries = 100;
        loop {
            rand_fill(template.add(xpos(l, 0)));
            let r = syscall_ret(syscall3(
                SYS_MKDIRAT,
                AT_FDCWD as usize,
                template as usize,
                0o700,
            ));
            if r == 0 {
                return template;
            }
            if errno_load(__errno_location()) != EEXIST {
                break;
            }
            retries -= 1;
            if retries == 0 {
                break;
            }
        }
        restore_run(template, l, 0);
        null_mut()
    }
}

/// Canonicalize a path (musl `realpath`, src/misc/realpath.c): resolves
/// symlinks, `.`/`..`, and duplicate slashes against the live
/// filesystem (raw `readlink`/`getcwd` traps), capped at `PATH_MAX`
/// (`ENAMETOOLONG`) and `SYMLOOP_MAX` links (`ELOOP`). A null
/// `filename` is `EINVAL`, an empty one `ENOENT`. With null
/// `resolved` the result is `malloc`'d (free it); otherwise it is
/// copied into `resolved` (which must fit `PATH_MAX` bytes).
///
/// # Safety
///
/// `filename` must be a valid NUL-terminated string; `resolved` null
/// or writable for `PATH_MAX` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn realpath(filename: *const c_char, resolved: *mut c_char) -> *mut c_char {
    unsafe {
        if filename.is_null() {
            errno_store(__errno_location(), EINVAL);
            return null_mut();
        }
        let mut stack = [0u8; PATH_MAX + 1];
        let mut output = [0u8; PATH_MAX];
        let mut l = strnlen(filename, stack.len());
        if l == 0 {
            errno_store(__errno_location(), ENOENT);
            return null_mut();
        }
        if l >= PATH_MAX {
            return toolong();
        }
        let mut p = stack.len().wrapping_sub(l).wrapping_sub(1);
        let mut q = 0usize;
        let mut cnt = 0usize;
        let mut nup = 0usize;
        let mut check_dir: u8 = 0;
        memcpy(
            stack.as_mut_ptr().add(p) as *mut c_void,
            filename as *const c_void,
            l.wrapping_add(1),
        );
        // musl's `for (; ; p+=slash_len(stack+p))`: the skip runs as
        // the loop *increment* (after every `continue`), never before
        // the first `/` test — `goto restart` skips it too.
        macro_rules! next {
            () => {{
                p = p.wrapping_add(slash_len(stack.as_ptr().add(p)));
                continue;
            }};
        }
        'outer: loop {
            loop {
                if stack[p] == b'/' {
                    check_dir = 0;
                    nup = 0;
                    q = 0;
                    output[q] = b'/';
                    q = q.wrapping_add(1);
                    p = p.wrapping_add(1);
                    if stack[p] == b'/' && stack[p.wrapping_add(1)] != b'/' {
                        output[q] = b'/';
                        q = q.wrapping_add(1);
                    }
                    next!();
                }
                let zp =
                    strchrnul(stack.as_ptr().add(p) as *const c_char, b'/' as c_int) as *const u8;
                let l0 = (zp as usize)
                    .wrapping_sub(stack.as_ptr() as usize)
                    .wrapping_sub(p);
                let mut ll = l0;
                if ll == 0 && check_dir == 0 {
                    break;
                }
                if ll == 1 && stack[p] == b'.' {
                    p = p.wrapping_add(ll);
                    next!();
                }
                if q != 0 && output[q.wrapping_sub(1)] != b'/' {
                    if p == 0 {
                        return toolong();
                    }
                    p = p.wrapping_sub(1);
                    stack[p] = b'/';
                    ll = ll.wrapping_add(1);
                }
                if q.wrapping_add(ll) >= PATH_MAX {
                    return toolong();
                }
                memcpy(
                    output.as_mut_ptr().add(q) as *mut c_void,
                    stack.as_ptr().add(p) as *const c_void,
                    ll,
                );
                output[q.wrapping_add(ll)] = 0;
                p = p.wrapping_add(ll);
                let mut up = false;
                if l0 == 2 && stack[p.wrapping_sub(2)] == b'.' && stack[p.wrapping_sub(1)] == b'.' {
                    up = true;
                    if q <= 3usize.wrapping_mul(nup) {
                        nup = nup.wrapping_add(1);
                        q = q.wrapping_add(ll);
                        next!();
                    }
                    if check_dir == 0 {
                        while q != 0 && output[q.wrapping_sub(1)] != b'/' {
                            q = q.wrapping_sub(1);
                        }
                        if q > 1 && (q > 2 || output[0] != b'/') {
                            q = q.wrapping_sub(1);
                        }
                        next!();
                    }
                }
                let k = readlink(
                    output.as_ptr() as *const c_char,
                    stack.as_mut_ptr() as *mut c_char,
                    p,
                );
                if k == p as isize {
                    return toolong();
                }
                if k == 0 {
                    errno_store(__errno_location(), ENOENT);
                    return null_mut();
                }
                if k < 0 {
                    if errno_load(__errno_location()) != EINVAL {
                        return null_mut();
                    }
                    check_dir = 0;
                    if up {
                        while q != 0 && output[q.wrapping_sub(1)] != b'/' {
                            q = q.wrapping_sub(1);
                        }
                        if q > 1 && (q > 2 || output[0] != b'/') {
                            q = q.wrapping_sub(1);
                        }
                        next!();
                    }
                    if l0 != 0 {
                        q = q.wrapping_add(ll);
                    }
                    check_dir = stack[p];
                    next!();
                }
                cnt = cnt.wrapping_add(1);
                if cnt == SYMLOOP_MAX {
                    errno_store(__errno_location(), ELOOP);
                    return null_mut();
                }
                let k = k as usize;
                if stack[k.wrapping_sub(1)] == b'/' {
                    while stack[p] == b'/' {
                        p = p.wrapping_add(1);
                    }
                }
                p = p.wrapping_sub(k);
                memmove(
                    stack.as_mut_ptr().add(p) as *mut c_void,
                    stack.as_ptr() as *const c_void,
                    k,
                );
                continue 'outer;
            }
            break;
        }
        output[q] = 0;
        if output[0] != b'/' {
            let r = syscall_ret(syscall2(
                SYS_GETCWD,
                stack.as_mut_ptr() as usize,
                stack.len(),
            ));
            if r == -1 {
                return null_mut();
            }
            l = strlen(stack.as_ptr() as *const c_char);
            p = 0;
            while nup > 0 {
                nup = nup.wrapping_sub(1);
                while l > 1 && stack[l.wrapping_sub(1)] != b'/' {
                    l = l.wrapping_sub(1);
                }
                if l > 1 {
                    l = l.wrapping_sub(1);
                }
                p = p.wrapping_add(2);
                if p < q {
                    p = p.wrapping_add(1);
                }
            }
            if q.wrapping_sub(p) != 0 && stack[l.wrapping_sub(1)] != b'/' {
                stack[l] = b'/';
                l = l.wrapping_add(1);
            }
            if l.wrapping_add(q.wrapping_sub(p)).wrapping_add(1) >= PATH_MAX {
                return toolong();
            }
            memmove(
                output.as_mut_ptr().add(l) as *mut c_void,
                output.as_ptr().add(p) as *const c_void,
                q.wrapping_sub(p).wrapping_add(1),
            );
            memcpy(
                output.as_mut_ptr() as *mut c_void,
                stack.as_ptr() as *const c_void,
                l,
            );
            q = l.wrapping_add(q).wrapping_sub(p);
        }
        if !resolved.is_null() {
            memcpy(
                resolved as *mut c_void,
                output.as_ptr() as *const c_void,
                q.wrapping_add(1),
            );
            return resolved;
        }
        strdup(output.as_ptr() as *const c_char)
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::{mkdtemp, mkostemp, mkostemps, mkstemp, mkstemps, mktemp, realpath};
    use core::ffi::{c_char, c_void};
    use core::sync::atomic::{AtomicU32, Ordering};

    use crate::errno::{__errno_location, errno_load};
    use crate::fcntl::{fcntl, FD_CLOEXEC, F_GETFD, O_CLOEXEC};
    use crate::malloc::free;
    use crate::unistd::close;
    use std::string::ToString;

    static CTR: AtomicU32 = AtomicU32::new(0);

    fn pat(tag: &str, suffix: &str) -> std::ffi::CString {
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        std::ffi::CString::new(std::format!(
            "/tmp/zlibc-9b2-{tag}-{}-{n}-XXXXXX{suffix}",
            std::process::id()
        ))
        .unwrap()
    }

    fn link_path(tag: &str) -> std::ffi::CString {
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        std::ffi::CString::new(std::format!(
            "/tmp/zlibc-9b2-{tag}-{}-{n}",
            std::process::id()
        ))
        .unwrap()
    }

    unsafe fn cstr(p: *const c_char) -> std::string::String {
        unsafe { std::ffi::CStr::from_ptr(p).to_str().unwrap().to_string() }
    }

    #[test]
    fn mkstemp_creates_unique_exclusive() {
        let a = pat("mst", "");
        let b = pat("mst", "");
        unsafe {
            let fa = mkstemp(a.as_ptr() as *mut c_char);
            assert!(fa >= 0);
            let fb = mkstemp(b.as_ptr() as *mut c_char);
            assert!(fb >= 0);
            let na = cstr(a.as_ptr());
            let nb = cstr(b.as_ptr());
            assert_ne!(na, nb);
            assert!(!na.ends_with("XXXXXX") && !nb.ends_with("XXXXXX"));
            assert!(std::path::Path::new(&na).exists());
            assert!(std::path::Path::new(&nb).exists());
            assert_eq!(close(fa), 0);
            assert_eq!(close(fb), 0);
            std::fs::remove_file(&na).unwrap();
            std::fs::remove_file(&nb).unwrap();
        }
    }

    #[test]
    fn mkstemps_keeps_suffix() {
        let t = pat("mss", ".log");
        unsafe {
            let fd = mkstemps(t.as_ptr() as *mut c_char, 4);
            assert!(fd >= 0);
            let n = cstr(t.as_ptr());
            assert!(n.ends_with(".log"));
            assert!(!n[..n.len() - 4].ends_with("XXXXXX"));
            assert_eq!(close(fd), 0);
            std::fs::remove_file(&n).unwrap();
            // Suffix length past the run is EINVAL.
            let bad = pat("mss", ".log");
            assert_eq!(mkstemps(bad.as_ptr() as *mut c_char, 5), -1);
        }
    }

    #[test]
    fn mkostemp_honors_cloexec() {
        let t = pat("moc", "");
        unsafe {
            let fd = mkostemp(t.as_ptr() as *mut c_char, O_CLOEXEC);
            assert!(fd >= 0);
            assert_ne!(fcntl(fd, F_GETFD, 0) & FD_CLOEXEC, 0);
            let n = cstr(t.as_ptr());
            assert_eq!(close(fd), 0);
            std::fs::remove_file(&n).unwrap();
            // Suffix + flags combined.
            let u = pat("moc", ".d");
            let fd = mkostemps(u.as_ptr() as *mut c_char, 2, O_CLOEXEC);
            assert!(fd >= 0);
            assert_ne!(fcntl(fd, F_GETFD, 0) & FD_CLOEXEC, 0);
            let n = cstr(u.as_ptr());
            assert!(n.ends_with(".d"));
            assert_eq!(close(fd), 0);
            std::fs::remove_file(&n).unwrap();
        }
    }

    #[test]
    fn mkstemp_bad_template_is_einval() {
        let _guard = crate::ldso::testlock::lock();
        let bad = std::ffi::CString::new(std::format!(
            "/tmp/zlibc-9b2-bad-{}-{}",
            std::process::id(),
            "no-run-here"
        ))
        .unwrap();
        unsafe {
            assert_eq!(mkstemp(bad.as_ptr() as *mut c_char), -1);
            assert_eq!(errno_load(__errno_location()), super::EINVAL);
        }
    }

    #[test]
    fn mkdtemp_mode_0700() {
        use std::os::unix::fs::PermissionsExt;
        let t = pat("mdt", "");
        unsafe {
            let r = mkdtemp(t.as_ptr() as *mut c_char);
            assert!(!r.is_null());
            let n = cstr(t.as_ptr());
            let md = std::fs::metadata(&n).unwrap();
            assert!(md.is_dir());
            assert_eq!(md.permissions().mode() & 0o700, 0o700);
            std::fs::remove_dir(&n).unwrap();
            // Bad template: null, errno set.
            let _guard = crate::ldso::testlock::lock();
            let bad = std::ffi::CString::new("/tmp/no-run").unwrap();
            assert!(mkdtemp(bad.as_ptr() as *mut c_char).is_null());
            assert_eq!(errno_load(__errno_location()), super::EINVAL);
        }
    }

    #[test]
    fn mktemp_mutates_without_creating() {
        let _guard = crate::ldso::testlock::lock();
        let t = pat("mtp", "");
        unsafe {
            let r = mktemp(t.as_ptr() as *mut c_char);
            assert_eq!(r, t.as_ptr() as *mut c_char);
            let n = cstr(t.as_ptr());
            assert!(!n.ends_with("XXXXXX"));
            assert!(!std::path::Path::new(&n).exists());
            // Bad template empties the string.
            let bad =
                std::ffi::CString::new(std::format!("/tmp/zlibc-9b2-bad-{}", std::process::id()))
                    .unwrap();
            let p = bad.as_ptr() as *mut c_char;
            assert_eq!(mktemp(p), p);
            assert_eq!(*p, 0);
            assert_eq!(errno_load(__errno_location()), super::EINVAL);
        }
    }

    #[test]
    fn realpath_resolves_dots() {
        let mut buf = [0u8; 4096];
        unsafe {
            let r = realpath(c"/tmp/.".as_ptr(), buf.as_mut_ptr() as *mut c_char);
            assert_eq!(r, buf.as_mut_ptr() as *mut c_char);
            assert_eq!(cstr(r), "/tmp");
            // NULL resolved: malloc'd answer, ours to free.
            let r = realpath(c"/tmp/../tmp".as_ptr(), core::ptr::null_mut());
            assert!(!r.is_null());
            assert_eq!(cstr(r), "/tmp");
            free(r as *mut c_void);
            // Relative input resolves against a live cwd to an absolute path.
            let r = realpath(c".".as_ptr(), core::ptr::null_mut());
            assert!(!r.is_null());
            assert!(cstr(r).starts_with('/'));
            free(r as *mut c_void);
        }
    }

    #[test]
    fn realpath_symlink_and_loop() {
        let _guard = crate::ldso::testlock::lock();
        let link = link_path("rpl");
        unsafe {
            std::os::unix::fs::symlink("/tmp", link.to_str().unwrap()).unwrap();
            let r = realpath(link.as_ptr(), core::ptr::null_mut());
            assert!(!r.is_null());
            assert_eq!(cstr(r), "/tmp");
            free(r as *mut c_void);
            std::fs::remove_file(link.to_str().unwrap()).unwrap();
            // Loop: a -> b -> a must fail ELOOP, not hang.
            let a = link_path("rla");
            let b = link_path("rlb");
            std::os::unix::fs::symlink(b.to_str().unwrap(), a.to_str().unwrap()).unwrap();
            std::os::unix::fs::symlink(a.to_str().unwrap(), b.to_str().unwrap()).unwrap();
            assert!(realpath(a.as_ptr(), core::ptr::null_mut()).is_null());
            assert_eq!(errno_load(__errno_location()), super::ELOOP);
            std::fs::remove_file(a.to_str().unwrap()).unwrap();
            std::fs::remove_file(b.to_str().unwrap()).unwrap();
        }
    }
}
