//! User/group/shadow databases (musl `src/passwd/*`): plain file reads, no NSS.
//!
//! Parsing mirrors musl exactly: colon-separated `/etc/passwd` fields with
//! `atou` numeric conversion (stops at the first non-digit, empty field is
//! 0), comma-separated `/etc/group` member lists, and musl's `__parsespent`
//! shadow rules (empty numeric fields are -1, entry must end with `\n`).
//! There is no nss/nscd lookup: entries absent from the files are absent,
//! period. Static return storage follows musl (`getpwnam`/`getpwuid` share
//! one static, `getpwent` owns another, same split for group/shadow), so
//! the non-`_r` functions are not thread-safe — like musl's own.
//!
//! The `getpwent`/`getgrent` iterators keep one static file image plus an
//! offset (musl keeps a static `FILE *` open across calls); `setpwent`
//! frees it, `endpwent` is the same call. Only one iteration is live at a
//! time per database.
//!
//! Deviations from musl, all deliberate: file tails without a trailing
//! `\n` keep their last byte (musl's `line[l-1]=0` eats it); `setgroups`
//! is one trap instead of musl's `__synccall` wave over every thread
//! (single-threaded equivalent; divergence-kill logic does not apply);
//! `crypt`-style modular hashes are not here (see `crate::sysconf`).

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};
use core::ptr::null_mut;

use crate::errno::{__errno_location, errno_load, errno_store};
use crate::malloc::{calloc, free, malloc, realloc};

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_READ: usize = 0; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_CLOSE: usize = 3; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_GETGROUPS: usize = 115; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_SETGROUPS: usize = 116; // TODO: generate from arch bits/syscall.h

// ---- Local errno/flag values (musl arch/generic/bits/errno.h, -------------
// ---- arch/generic/bits/fcntl.h) --------------------------------------------
#[cfg(target_arch = "x86_64")]
const ENOENT: c_int = 2;
#[cfg(target_arch = "x86_64")]
const ENXIO: c_int = 6;
#[cfg(target_arch = "x86_64")]
const ENOMEM: c_int = 12;
#[cfg(target_arch = "x86_64")]
const EINVAL: c_int = 22;
#[cfg(target_arch = "x86_64")]
const ERANGE: c_int = 34;
#[cfg(target_arch = "x86_64")]
const O_NOFOLLOW: c_int = 0o400000;

#[cfg(target_arch = "x86_64")]
use crate::fcntl::{open, O_CLOEXEC, O_NONBLOCK};
#[cfg(target_arch = "x86_64")]
use crate::stat::{fstat, S_ISREG};

// ---- Types (musl include/pwd.h, include/grp.h, include/shadow.h) ------------
/// musl `struct passwd` (`include/pwd.h:19-27`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Passwd {
    pub pw_name: *mut c_char,
    pub pw_passwd: *mut c_char,
    pub pw_uid: u32,
    pub pw_gid: u32,
    pub pw_gecos: *mut c_char,
    pub pw_dir: *mut c_char,
    pub pw_shell: *mut c_char,
}

/// musl `struct group` (`include/grp.h:22-27`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Group {
    pub gr_name: *mut c_char,
    pub gr_passwd: *mut c_char,
    pub gr_gid: u32,
    pub gr_mem: *mut *mut c_char,
}

/// musl `struct spwd` (`include/shadow.h:17-26`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Spwd {
    pub sp_namp: *mut c_char,
    pub sp_pwdp: *mut c_char,
    pub sp_lstchg: c_long,
    pub sp_min: c_long,
    pub sp_max: c_long,
    pub sp_warn: c_long,
    pub sp_inact: c_long,
    pub sp_expire: c_long,
    pub sp_flag: c_ulong,
}

#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<Passwd>() == 48);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<Group>() == 32);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<Spwd>() == 72);

/// musl `FILE` as this crate spells it (packet-1 compact `File`, not yet
/// full `struct _IO_FILE`; the pointer width is what the ABI needs).
#[cfg(target_arch = "x86_64")]
type File = crate::stdio::File;

// ---- Whole-file loader (raw open/read, no stdio) ---------------------------
/// Read an entire file into a malloc'd buffer, NUL-padded past the end.
///
/// Returns null on open failure (errno is the open errno, like musl's
/// `fopen` failure); read errors free the buffer and report null with the
/// read errno. A missing trailing newline is appended so every line ends
/// with `\n`, matching what musl's `fgets`/`getline` hands its parsers.
///
/// # Safety
///
/// `path` must point to a NUL-terminated string.
#[cfg(target_arch = "x86_64")]
unsafe fn load_file(path: *const c_char, len_out: *mut usize) -> *mut u8 {
    unsafe {
        *len_out = 0;
        let fd = open(path, 0, 0);
        if fd < 0 {
            return null_mut();
        }
        let mut cap = 8192usize;
        let mut buf = malloc(cap) as *mut u8;
        if buf.is_null() {
            errno_store(__errno_location(), ENOMEM);
            let _ = crate::syscall::syscall_ret(crate::syscall::syscall1(SYS_CLOSE, fd as usize));
            return null_mut();
        }
        let mut len = 0usize;
        loop {
            if len == cap {
                cap = cap.wrapping_mul(2);
                let nb = realloc(buf as *mut c_void, cap) as *mut u8;
                if nb.is_null() {
                    free(buf as *mut c_void);
                    let _ = crate::syscall::syscall_ret(crate::syscall::syscall1(
                        SYS_CLOSE,
                        fd as usize,
                    ));
                    errno_store(__errno_location(), ENOMEM);
                    return null_mut();
                }
                buf = nb;
            }
            let r = crate::syscall::syscall_ret(crate::syscall::syscall3(
                SYS_READ,
                fd as usize,
                buf.add(len) as usize,
                cap - len,
            ));
            if r < 0 {
                if errno_load(__errno_location()) == 4 {
                    continue;
                }
                free(buf as *mut c_void);
                let _ =
                    crate::syscall::syscall_ret(crate::syscall::syscall1(SYS_CLOSE, fd as usize));
                return null_mut();
            }
            if r == 0 {
                break;
            }
            len += r as usize;
        }
        let _ = crate::syscall::syscall_ret(crate::syscall::syscall1(SYS_CLOSE, fd as usize));
        if len == 0 || *buf.add(len - 1) != b'\n' {
            if len + 1 >= cap {
                let nb = realloc(buf as *mut c_void, len + 2) as *mut u8;
                if nb.is_null() {
                    free(buf as *mut c_void);
                    errno_store(__errno_location(), ENOMEM);
                    return null_mut();
                }
                buf = nb;
            }
            *buf.add(len) = b'\n';
            len += 1;
        }
        *buf.add(len) = 0;
        *len_out = len;
        buf
    }
}

/// Read an open fd to EOF (musl's TCB-`fdopen` path, minus the `FILE`).
#[cfg(target_arch = "x86_64")]
unsafe fn load_fd(fd: c_int, len_out: *mut usize) -> *mut u8 {
    unsafe {
        *len_out = 0;
        let mut cap = 1024usize;
        let mut buf = malloc(cap) as *mut u8;
        if buf.is_null() {
            return null_mut();
        }
        let mut len = 0usize;
        loop {
            if len == cap {
                cap = cap.wrapping_mul(2);
                let nb = realloc(buf as *mut c_void, cap) as *mut u8;
                if nb.is_null() {
                    free(buf as *mut c_void);
                    return null_mut();
                }
                buf = nb;
            }
            let r = crate::syscall::syscall_ret(crate::syscall::syscall3(
                SYS_READ,
                fd as usize,
                buf.add(len) as usize,
                cap - len,
            ));
            if r < 0 {
                if errno_load(__errno_location()) == 4 {
                    continue;
                }
                free(buf as *mut c_void);
                return null_mut();
            }
            if r == 0 {
                break;
            }
            len += r as usize;
        }
        if len == 0 || *buf.add(len - 1) != b'\n' {
            if len + 1 >= cap {
                let nb = realloc(buf as *mut c_void, len + 2) as *mut u8;
                if nb.is_null() {
                    free(buf as *mut c_void);
                    return null_mut();
                }
                buf = nb;
            }
            *buf.add(len) = b'\n';
            len += 1;
        }
        *buf.add(len) = 0;
        *len_out = len;
        buf
    }
}

// ---- Field parsers (musl getpwent_a.c, getgrent_a.c, getspnam_r.c) ----------
/// musl `atou` (`getpwent_a.c:4-9`): digits only, stops at the first other
/// byte; empty is 0.
#[cfg(target_arch = "x86_64")]
unsafe fn atou(s: *mut *mut c_char) -> u32 {
    unsafe {
        let mut x = 0u32;
        while (**s as u8).wrapping_sub(b'0') < 10 {
            x = x.wrapping_mul(10).wrapping_add((**s as u8 - b'0') as u32);
            *s = (*s).add(1);
        }
        x
    }
}

/// musl `xatol` (`getspnam_r.c:15-21`): -1 on empty, else the digits.
#[cfg(target_arch = "x86_64")]
unsafe fn xatol(s: *mut *mut c_char) -> c_long {
    unsafe {
        if **s == b':' as c_char || **s == b'\n' as c_char {
            return -1;
        }
        let mut x = 0 as c_long;
        while (**s as u8).wrapping_sub(b'0') < 10 {
            x = x * 10 + (**s as u8 - b'0') as c_long;
            *s = (*s).add(1);
        }
        x
    }
}

/// Split a NUL-terminated `line` into `pw` (musl `__getpwent_a` line half).
/// Malformed lines (missing colons) report false and are skipped by callers.
///
/// # Safety
///
/// `line` must be writable past its terminator; `pw` writable.
#[cfg(target_arch = "x86_64")]
unsafe fn parse_pw(line: *mut c_char, pw: *mut Passwd) -> bool {
    unsafe {
        let mut s = line;
        (*pw).pw_name = s;
        s = crate::string::strchr(s, b':' as c_int);
        if s.is_null() {
            return false;
        }
        *s = 0;
        s = s.add(1);
        (*pw).pw_passwd = s;
        s = crate::string::strchr(s, b':' as c_int);
        if s.is_null() {
            return false;
        }
        *s = 0;
        s = s.add(1);
        (*pw).pw_uid = atou(&mut s);
        if *s != b':' as c_char {
            return false;
        }
        *s = 0;
        s = s.add(1);
        (*pw).pw_gid = atou(&mut s);
        if *s != b':' as c_char {
            return false;
        }
        *s = 0;
        s = s.add(1);
        (*pw).pw_gecos = s;
        s = crate::string::strchr(s, b':' as c_int);
        if s.is_null() {
            return false;
        }
        *s = 0;
        s = s.add(1);
        (*pw).pw_dir = s;
        s = crate::string::strchr(s, b':' as c_int);
        if s.is_null() {
            return false;
        }
        *s = 0;
        s = s.add(1);
        (*pw).pw_shell = s;
        true
    }
}

#[cfg(target_arch = "x86_64")]
static mut GR_MEM: *mut *mut c_char = null_mut();
#[cfg(target_arch = "x86_64")]
static mut GR_MEMCAP: usize = 0;

/// Split a NUL-terminated `line` into `gr` (musl `__getgrent_a` line half,
/// comma-separated members into the shared member vector).
///
/// # Safety
///
/// Same contract as [`parse_pw`]; `gr` writable.
#[cfg(target_arch = "x86_64")]
unsafe fn parse_gr(line: *mut c_char, gr: *mut Group) -> bool {
    unsafe {
        let mut s = line;
        (*gr).gr_name = s;
        s = crate::string::strchr(s, b':' as c_int);
        if s.is_null() {
            return false;
        }
        *s = 0;
        s = s.add(1);
        (*gr).gr_passwd = s;
        s = crate::string::strchr(s, b':' as c_int);
        if s.is_null() {
            return false;
        }
        *s = 0;
        s = s.add(1);
        (*gr).gr_gid = atou(&mut s);
        if *s != b':' as c_char {
            return false;
        }
        *s = 0;
        let mems = s.add(1);
        // Count members (musl counts commas + !!*s).
        s = mems;
        let mut nmem = if *s != 0 { 1 } else { 0 };
        while *s != 0 {
            if *s == b',' as c_char {
                nmem += 1;
            }
            s = s.add(1);
        }
        if nmem + 1 > GR_MEMCAP {
            let m = realloc(
                GR_MEM as *mut c_void,
                (nmem + 1) * core::mem::size_of::<*mut c_char>(),
            ) as *mut *mut c_char;
            if m.is_null() {
                return false;
            }
            GR_MEM = m;
            GR_MEMCAP = nmem + 1;
        }
        if *mems != 0 {
            let mut i = 0usize;
            *GR_MEM.add(0) = mems;
            s = mems;
            while *s != 0 {
                if *s == b',' as c_char {
                    *s = 0;
                    i += 1;
                    *GR_MEM.add(i) = s.add(1);
                }
                s = s.add(1);
            }
            *GR_MEM.add(i + 1) = null_mut();
        } else {
            *GR_MEM.add(0) = null_mut();
        }
        (*gr).gr_mem = GR_MEM;
        true
    }
}

/// musl `__parsespent` (`getspnam_r.c:23-54`): 0 ok, -1 malformed.
///
/// # Safety
///
/// `s` must be a writable NUL-terminated line ending in `\n`; `sp` writable.
#[cfg(target_arch = "x86_64")]
unsafe fn parse_sp(s: *mut c_char, sp: *mut Spwd) -> bool {
    unsafe {
        let mut p = s;
        (*sp).sp_namp = p;
        p = crate::string::strchr(p, b':' as c_int);
        if p.is_null() {
            return false;
        }
        *p = 0;
        p = p.add(1);
        (*sp).sp_pwdp = p;
        p = crate::string::strchr(p, b':' as c_int);
        if p.is_null() {
            return false;
        }
        *p = 0;
        p = p.add(1);
        (*sp).sp_lstchg = xatol(&mut p);
        if *p != b':' as c_char {
            return false;
        }
        p = p.add(1);
        (*sp).sp_min = xatol(&mut p);
        if *p != b':' as c_char {
            return false;
        }
        p = p.add(1);
        (*sp).sp_max = xatol(&mut p);
        if *p != b':' as c_char {
            return false;
        }
        p = p.add(1);
        (*sp).sp_warn = xatol(&mut p);
        if *p != b':' as c_char {
            return false;
        }
        p = p.add(1);
        (*sp).sp_inact = xatol(&mut p);
        if *p != b':' as c_char {
            return false;
        }
        p = p.add(1);
        (*sp).sp_expire = xatol(&mut p);
        if *p != b':' as c_char {
            return false;
        }
        p = p.add(1);
        (*sp).sp_flag = xatol(&mut p) as c_ulong;
        if *p != b'\n' as c_char {
            return false;
        }
        true
    }
}

// ---- Static storage (musl's per-db statics, same split) --------------------
#[cfg(target_arch = "x86_64")]
static mut PW_BUF: *mut c_char = null_mut();
#[cfg(target_arch = "x86_64")]
static mut PW_CAP: usize = 0;
#[cfg(target_arch = "x86_64")]
static mut PW_VAL: Passwd = Passwd {
    pw_name: null_mut(),
    pw_passwd: null_mut(),
    pw_uid: 0,
    pw_gid: 0,
    pw_gecos: null_mut(),
    pw_dir: null_mut(),
    pw_shell: null_mut(),
};
#[cfg(target_arch = "x86_64")]
static mut PW_DATA: *mut u8 = null_mut();
#[cfg(target_arch = "x86_64")]
static mut PW_LEN: usize = 0;
#[cfg(target_arch = "x86_64")]
static mut PW_POS: usize = 0;

#[cfg(target_arch = "x86_64")]
static mut GR_BUF: *mut c_char = null_mut();
#[cfg(target_arch = "x86_64")]
static mut GR_CAP: usize = 0;
#[cfg(target_arch = "x86_64")]
static mut GR_VAL: Group = Group {
    gr_name: null_mut(),
    gr_passwd: null_mut(),
    gr_gid: 0,
    gr_mem: null_mut(),
};
#[cfg(target_arch = "x86_64")]
static mut GR_DATA: *mut u8 = null_mut();
#[cfg(target_arch = "x86_64")]
static mut GR_LEN: usize = 0;
#[cfg(target_arch = "x86_64")]
static mut GR_POS: usize = 0;

#[cfg(target_arch = "x86_64")]
static mut SP_BUF: *mut c_char = null_mut();
#[cfg(target_arch = "x86_64")]
static mut SP_VAL: Spwd = Spwd {
    sp_namp: null_mut(),
    sp_pwdp: null_mut(),
    sp_lstchg: 0,
    sp_min: 0,
    sp_max: 0,
    sp_warn: 0,
    sp_inact: 0,
    sp_expire: 0,
    sp_flag: 0,
};

/// Grow a static line buffer to `need` bytes (NUL included).
///
/// # Safety
///
/// `slot`/`cap` are the buffer statics; `need` counts the terminator.
#[cfg(target_arch = "x86_64")]
unsafe fn grow(slot: *mut *mut c_char, cap: *mut usize, need: usize) -> *mut c_char {
    unsafe {
        if need > *cap {
            let m = realloc(*slot as *mut c_void, need) as *mut c_char;
            if m.is_null() {
                return null_mut();
            }
            *slot = m;
            *cap = need;
        }
        *slot
    }
}

/// Copy the `[start, end)` line (no `\n`) into the static buffer, NUL it.
///
/// # Safety
///
/// `data` must hold at least `end` readable bytes; statics as in [`grow`].
#[cfg(target_arch = "x86_64")]
unsafe fn stash(
    data: *mut u8,
    start: usize,
    end: usize,
    slot: *mut *mut c_char,
    cap: *mut usize,
) -> *mut c_char {
    unsafe {
        let line = grow(slot, cap, end - start + 1);
        if line.is_null() {
            return null_mut();
        }
        core::ptr::copy_nonoverlapping(data.add(start), line as *mut u8, end - start);
        *line.add(end - start) = 0;
        line
    }
}

// ---- passwd ------------------------------------------------------------------
/// Look up one passwd entry by name (`name` null matches `uid`).
///
/// Returns the static value or null, errno preserved like musl's
/// `__getpw_a` file half (nscd half omitted: no NSS here).
///
/// # Safety
///
/// `name` null or NUL-terminated.
#[cfg(target_arch = "x86_64")]
unsafe fn lookup_pw(name: *const c_char, uid: u32) -> *mut Passwd {
    unsafe {
        let mut len = 0usize;
        let data = load_file(c"/etc/passwd".as_ptr(), &mut len);
        if data.is_null() {
            return null_mut();
        }
        let mut out: *mut Passwd = null_mut();
        let mut pos = 0usize;
        while pos < len {
            let mut end = pos;
            while *data.add(end) != b'\n' {
                end += 1;
            }
            let line = stash(
                data,
                pos,
                end,
                &mut *core::ptr::addr_of_mut!(PW_BUF),
                &mut *core::ptr::addr_of_mut!(PW_CAP),
            );
            pos = end + 1;
            if line.is_null() || !parse_pw(line, &mut *core::ptr::addr_of_mut!(PW_VAL)) {
                continue;
            }
            let hit = if !name.is_null() {
                crate::string::strcmp(name, PW_VAL.pw_name) == 0
            } else {
                PW_VAL.pw_uid == uid
            };
            if hit {
                out = core::ptr::addr_of_mut!(PW_VAL);
                break;
            }
        }
        free(data as *mut c_void);
        out
    }
}

/// Find a passwd entry by name (musl `getpwnam`).
///
/// # Safety
///
/// `name` must point to a NUL-terminated string. Static return: not
/// thread-safe, overwritten by the next lookup call.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getpwnam(name: *const c_char) -> *mut Passwd {
    unsafe { lookup_pw(name, 0) }
}

/// Find a passwd entry by uid (musl `getpwuid`).
///
/// # Safety
///
/// Static return: same caveat as [`getpwnam`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getpwuid(uid: u32) -> *mut Passwd {
    unsafe { lookup_pw(null_mut(), uid) }
}

/// Rewind the passwd iterator (musl `setpwent`: closes the static stream).
///
/// # Safety
///
/// Discards iterator state; concurrent iteration is already unsupported.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setpwent() {
    unsafe {
        free(PW_DATA as *mut c_void);
        PW_DATA = null_mut();
        PW_LEN = 0;
        PW_POS = 0;
    }
}

/// End passwd iteration (musl `endpwent`, its weak alias of `setpwent`).
///
/// # Safety
///
/// Same contract as [`setpwent`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn endpwent() {
    unsafe { setpwent() }
}

/// Next passwd entry (musl `getpwent`).
///
/// # Safety
///
/// Static return: same caveat as [`getpwnam`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getpwent() -> *mut Passwd {
    unsafe {
        if PW_DATA.is_null() {
            PW_DATA = load_file(
                c"/etc/passwd".as_ptr(),
                &mut *core::ptr::addr_of_mut!(PW_LEN),
            );
            PW_POS = 0;
            if PW_DATA.is_null() {
                return null_mut();
            }
        }
        while PW_POS < PW_LEN {
            let mut end = PW_POS;
            while *PW_DATA.add(end) != b'\n' {
                end += 1;
            }
            let line = stash(
                PW_DATA,
                PW_POS,
                end,
                &mut *core::ptr::addr_of_mut!(PW_BUF),
                &mut *core::ptr::addr_of_mut!(PW_CAP),
            );
            PW_POS = end + 1;
            if line.is_null() {
                return null_mut();
            }
            if parse_pw(line, &mut *core::ptr::addr_of_mut!(PW_VAL)) {
                return core::ptr::addr_of_mut!(PW_VAL);
            }
        }
        null_mut()
    }
}

/// Next passwd entry from a stream (musl `fgetpwent`).
///
/// # Safety
///
/// `f` must be a readable open stream. Static return, not thread-safe.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fgetpwent(f: *mut File) -> *mut Passwd {
    unsafe {
        static mut LINE: *mut c_char = null_mut();
        static mut SIZE: usize = 0;
        static mut PW: Passwd = Passwd {
            pw_name: null_mut(),
            pw_passwd: null_mut(),
            pw_uid: 0,
            pw_gid: 0,
            pw_gecos: null_mut(),
            pw_dir: null_mut(),
            pw_shell: null_mut(),
        };
        loop {
            let l = crate::stdio::file::getline(
                &mut *core::ptr::addr_of_mut!(LINE),
                &mut *core::ptr::addr_of_mut!(SIZE),
                f,
            );
            if l < 0 {
                return null_mut();
            }
            let n = l as usize;
            if n > 0 && *LINE.add(n - 1) == b'\n' as c_char {
                *LINE.add(n - 1) = 0;
            }
            if parse_pw(LINE, &mut *core::ptr::addr_of_mut!(PW)) {
                return core::ptr::addr_of_mut!(PW);
            }
        }
    }
}

/// Write a passwd entry (musl `putpwent`: `name:passwd:uid:gid:gecos:dir:shell`).
///
/// # Safety
///
/// `pw` readable with all string fields NUL-terminated; `f` writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn putpwent(pw: *const Passwd, f: *mut File) -> c_int {
    unsafe {
        if crate::stdio::fputs((*pw).pw_name, f) < 0 {
            return -1;
        }
        if crate::stdio::file::fputc(b':' as c_int, f) < 0 {
            return -1;
        }
        if crate::stdio::fputs((*pw).pw_passwd, f) < 0 {
            return -1;
        }
        if put_u32(f, (*pw).pw_uid) < 0 {
            return -1;
        }
        if put_u32(f, (*pw).pw_gid) < 0 {
            return -1;
        }
        if crate::stdio::file::fputc(b':' as c_int, f) < 0 {
            return -1;
        }
        if crate::stdio::fputs((*pw).pw_gecos, f) < 0 {
            return -1;
        }
        if crate::stdio::file::fputc(b':' as c_int, f) < 0 {
            return -1;
        }
        if crate::stdio::fputs((*pw).pw_dir, f) < 0 {
            return -1;
        }
        if crate::stdio::file::fputc(b':' as c_int, f) < 0 {
            return -1;
        }
        if crate::stdio::fputs((*pw).pw_shell, f) < 0 {
            return -1;
        }
        if crate::stdio::file::fputc(b'\n' as c_int, f) < 0 {
            return -1;
        }
        0
    }
}

/// Print `:N` for a uid/gid field.
///
/// # Safety
///
/// `f` must be writable.
#[cfg(target_arch = "x86_64")]
unsafe fn put_u32(f: *mut File, v: u32) -> c_int {
    unsafe {
        if crate::stdio::file::fputc(b':' as c_int, f) < 0 {
            return -1;
        }
        put_dec(f, v as c_ulong)
    }
}

/// Print an unsigned decimal (put* helpers; no `fprintf` on stable).
///
/// # Safety
///
/// `f` must be writable.
#[cfg(target_arch = "x86_64")]
unsafe fn put_dec(f: *mut File, mut v: c_ulong) -> c_int {
    unsafe {
        let mut tmp = [0 as c_char; 24];
        let mut i = tmp.len();
        loop {
            i -= 1;
            tmp[i] = (b'0' + (v % 10) as u8) as c_char;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        while i < tmp.len() {
            if crate::stdio::file::fputc(tmp[i] as c_int, f) < 0 {
                return -1;
            }
            i += 1;
        }
        0
    }
}

// ---- group -------------------------------------------------------------------
/// Look up one group entry by name (`name` null matches `gid`).
///
/// # Safety
///
/// `name` null or NUL-terminated.
#[cfg(target_arch = "x86_64")]
unsafe fn lookup_gr(name: *const c_char, gid: u32) -> *mut Group {
    unsafe {
        let mut len = 0usize;
        let data = load_file(c"/etc/group".as_ptr(), &mut len);
        if data.is_null() {
            return null_mut();
        }
        let mut out: *mut Group = null_mut();
        let mut pos = 0usize;
        while pos < len {
            let mut end = pos;
            while *data.add(end) != b'\n' {
                end += 1;
            }
            let line = stash(
                data,
                pos,
                end,
                &mut *core::ptr::addr_of_mut!(GR_BUF),
                &mut *core::ptr::addr_of_mut!(GR_CAP),
            );
            pos = end + 1;
            if line.is_null() || !parse_gr(line, &mut *core::ptr::addr_of_mut!(GR_VAL)) {
                continue;
            }
            let hit = if !name.is_null() {
                crate::string::strcmp(name, GR_VAL.gr_name) == 0
            } else {
                GR_VAL.gr_gid == gid
            };
            if hit {
                out = core::ptr::addr_of_mut!(GR_VAL);
                break;
            }
        }
        free(data as *mut c_void);
        out
    }
}

/// Find a group entry by name (musl `getgrnam`).
///
/// # Safety
///
/// `name` must point to a NUL-terminated string. Static return: not
/// thread-safe, overwritten by the next lookup call.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getgrnam(name: *const c_char) -> *mut Group {
    unsafe { lookup_gr(name, 0) }
}

/// Find a group entry by gid (musl `getgrgid`).
///
/// # Safety
///
/// Static return: same caveat as [`getgrnam`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getgrgid(gid: u32) -> *mut Group {
    unsafe { lookup_gr(null_mut(), gid) }
}

/// Rewind the group iterator (musl `setgrent`).
///
/// # Safety
///
/// Discards iterator state; concurrent iteration is already unsupported.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setgrent() {
    unsafe {
        free(GR_DATA as *mut c_void);
        GR_DATA = null_mut();
        GR_LEN = 0;
        GR_POS = 0;
    }
}

/// End group iteration (musl `endgrent`, its weak alias of `setgrent`).
///
/// # Safety
///
/// Same contract as [`setgrent`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn endgrent() {
    unsafe { setgrent() }
}

/// Next group entry (musl `getgrent`).
///
/// # Safety
///
/// Static return: same caveat as [`getgrnam`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getgrent() -> *mut Group {
    unsafe {
        if GR_DATA.is_null() {
            GR_DATA = load_file(
                c"/etc/group".as_ptr(),
                &mut *core::ptr::addr_of_mut!(GR_LEN),
            );
            GR_POS = 0;
            if GR_DATA.is_null() {
                return null_mut();
            }
        }
        while GR_POS < GR_LEN {
            let mut end = GR_POS;
            while *GR_DATA.add(end) != b'\n' {
                end += 1;
            }
            let line = stash(
                GR_DATA,
                GR_POS,
                end,
                &mut *core::ptr::addr_of_mut!(GR_BUF),
                &mut *core::ptr::addr_of_mut!(GR_CAP),
            );
            GR_POS = end + 1;
            if line.is_null() {
                return null_mut();
            }
            if parse_gr(line, &mut *core::ptr::addr_of_mut!(GR_VAL)) {
                return core::ptr::addr_of_mut!(GR_VAL);
            }
        }
        null_mut()
    }
}

/// Next group entry from a stream (musl `fgetgrent`).
///
/// # Safety
///
/// `f` must be a readable open stream. Static return, not thread-safe.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fgetgrent(f: *mut File) -> *mut Group {
    unsafe {
        static mut LINE: *mut c_char = null_mut();
        static mut SIZE: usize = 0;
        static mut MEM: *mut *mut c_char = null_mut();
        static mut NMEM: usize = 0;
        static mut GR: Group = Group {
            gr_name: null_mut(),
            gr_passwd: null_mut(),
            gr_gid: 0,
            gr_mem: null_mut(),
        };
        loop {
            let l = crate::stdio::file::getline(
                &mut *core::ptr::addr_of_mut!(LINE),
                &mut *core::ptr::addr_of_mut!(SIZE),
                f,
            );
            if l < 0 {
                return null_mut();
            }
            let n = l as usize;
            if n > 0 && *LINE.add(n - 1) == b'\n' as c_char {
                *LINE.add(n - 1) = 0;
            }
            // Parse into the shared statics, then repoint at the local
            // value: one entry is live at a time either way.
            if !parse_gr_into(
                LINE,
                &mut *core::ptr::addr_of_mut!(GR),
                &mut *core::ptr::addr_of_mut!(MEM),
                &mut *core::ptr::addr_of_mut!(NMEM),
            ) {
                continue;
            }
            return core::ptr::addr_of_mut!(GR);
        }
    }
}

/// [`parse_gr`] with an explicit member vector (for `fgetgrent`'s own static).
///
/// # Safety
///
/// Same contract as [`parse_gr`]; `mem`/`nmem` are the vector statics.
#[cfg(target_arch = "x86_64")]
unsafe fn parse_gr_into(
    line: *mut c_char,
    gr: *mut Group,
    mem: *mut *mut *mut c_char,
    nmem: *mut usize,
) -> bool {
    unsafe {
        let saved_mem = GR_MEM;
        let saved_cap = GR_MEMCAP;
        GR_MEM = *mem;
        GR_MEMCAP = *nmem;
        let ok = parse_gr(line, gr);
        *mem = GR_MEM;
        *nmem = GR_MEMCAP;
        GR_MEM = saved_mem;
        GR_MEMCAP = saved_cap;
        ok
    }
}

/// Write a group entry (musl `putgrent`: `name:passwd:gid:members...`).
///
/// # Safety
///
/// `gr` readable with NUL-terminated strings; `f` writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn putgrent(gr: *const Group, f: *mut File) -> c_int {
    unsafe {
        if crate::stdio::fputs((*gr).gr_name, f) < 0 {
            return -1;
        }
        if crate::stdio::file::fputc(b':' as c_int, f) < 0 {
            return -1;
        }
        if crate::stdio::fputs((*gr).gr_passwd, f) < 0 {
            return -1;
        }
        if put_u32(f, (*gr).gr_gid) < 0 {
            return -1;
        }
        if crate::stdio::file::fputc(b':' as c_int, f) < 0 {
            return -1;
        }
        if !(*gr).gr_mem.is_null() {
            let mut i = 0usize;
            while !(*(*gr).gr_mem.add(i)).is_null() {
                if i > 0 && crate::stdio::file::fputc(b',' as c_int, f) < 0 {
                    return -1;
                }
                if crate::stdio::fputs(*(*gr).gr_mem.add(i), f) < 0 {
                    return -1;
                }
                i += 1;
            }
        }
        if crate::stdio::file::fputc(b'\n' as c_int, f) < 0 {
            return -1;
        }
        0
    }
}

// ---- shadow --------------------------------------------------------------------
#[cfg(target_arch = "x86_64")]
const SP_LINE_LIM: usize = 256;

/// Shadow lookup in one loaded image: first line whose name matches and
/// parses wins (musl `getspnam_r` loop body). Returns 0 on match (sp/buf
/// filled), 1 when no line matches, or an errno value.
///
/// # Safety
///
/// `data` holds `len` readable bytes ending in `\n`; `name` NUL-terminated
/// with length `l`; `sp`/`buf`(`size`) are the caller slots.
#[cfg(target_arch = "x86_64")]
unsafe fn scan_sp(
    data: *mut u8,
    len: usize,
    name: *const c_char,
    l: usize,
    sp: *mut Spwd,
    buf: *mut c_char,
    size: usize,
) -> c_int {
    unsafe {
        let mut pos = 0usize;
        let mut skip = false;
        while pos < len {
            let mut end = pos;
            while *data.add(end) != b'\n' {
                end += 1;
            }
            let linelen = end - pos + 1; // keep the '\n': __parsespent wants it
            let good_head = !skip
                && linelen > l + 1
                && crate::string::strncmp(name, data.add(pos) as *const c_char, l) == 0
                && *data.add(pos + l) == b':';
            if !good_head {
                skip = *data.add(end) != b'\n';
                pos = end + 1;
                continue;
            }
            if linelen > size {
                return ERANGE;
            }
            core::ptr::copy_nonoverlapping(data.add(pos), buf as *mut u8, linelen);
            *buf.add(linelen) = 0;
            if parse_sp(buf, sp) {
                return 0;
            }
            pos = end + 1;
        }
        1
    }
}

/// Find a shadow entry by name into caller storage (musl `getspnam_r`).
///
/// Tries Openwall-style `/etc/tcb/<name>/shadow` first (no symlinks, no
/// fifos: `O_NOFOLLOW`, regular-file check), then `/etc/shadow`. Returns
/// the errno value (0 with `*res` set on success, 0 with null `*res` when
/// the files are simply absent/unreadable-by-policy, like musl).
///
/// # Safety
///
/// `name` NUL-terminated; `sp` writable; `buf` writable for `size` bytes;
/// `res` writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getspnam_r(
    name: *const c_char,
    sp: *mut Spwd,
    buf: *mut c_char,
    size: usize,
    res: *mut *mut Spwd,
) -> c_int {
    unsafe {
        *res = null_mut();
        let l = crate::mem::strlen(name);
        if *name == b'.' as c_char || l == 0 {
            return EINVAL;
        }
        let mut bad = false;
        for i in 0..l {
            if *name.add(i) == b'/' as c_char {
                bad = true;
                break;
            }
        }
        if bad {
            return EINVAL;
        }
        if size < l + 100 {
            return ERANGE;
        }
        // TCB path: "/etc/tcb/<name>/shadow" must fit (musl: 20+NAME_MAX).
        if l > 255 {
            return EINVAL;
        }
        let mut path = [0 as c_char; 281];
        let pre = c"/etc/tcb/".as_ptr();
        let mid = c"/shadow".as_ptr();
        let mut k = 0usize;
        while *pre.add(k) != 0 {
            path[k] = *pre.add(k);
            k += 1;
        }
        core::ptr::copy_nonoverlapping(name, path.as_mut_ptr().add(k), l);
        k += l;
        let mut j = 0usize;
        while *mid.add(j) != 0 {
            path[k] = *mid.add(j);
            k += 1;
            j += 1;
        }
        path[k] = 0;
        let fd = open(path.as_ptr(), O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, 0);
        if fd >= 0 {
            let mut st: crate::stat::Stat = core::mem::zeroed();
            let mut rv = EINVAL;
            if fstat(fd, &mut st) == 0 && S_ISREG(st.st_mode) {
                let mut len = 0usize;
                let data = load_fd(fd, &mut len);
                if !data.is_null() {
                    // 0 = match (sp/buf filled), 1 = no match, else errno.
                    rv = scan_sp(data, len, name, l, sp, buf, size);
                    if rv == 0 {
                        *res = sp;
                    } else if rv == 1 {
                        rv = 0;
                    }
                    free(data as *mut c_void);
                } else {
                    rv = errno_load(__errno_location());
                }
            }
            let _ = crate::syscall::syscall_ret(crate::syscall::syscall1(SYS_CLOSE, fd as usize));
            if !(*res).is_null() || rv != 0 {
                return rv;
            }
            // TCB file present but no match: musl falls through to shadow.
        } else {
            let e = errno_load(__errno_location());
            if e != ENOENT && e != 20 {
                return e;
            }
        }
        let mut len = 0usize;
        let data = load_file(c"/etc/shadow".as_ptr(), &mut len);
        if data.is_null() {
            let e = errno_load(__errno_location());
            if e == ENOENT || e == 20 {
                return 0;
            }
            return e;
        }
        let rv = scan_sp(data, len, name, l, sp, buf, size);
        if rv == 0 {
            *res = sp;
            free(data as *mut c_void);
            return 0;
        }
        free(data as *mut c_void);
        if rv == 1 {
            0
        } else {
            rv
        }
    }
}

/// Find a shadow entry by name (musl `getspnam`: static 256-byte line).
///
/// # Safety
///
/// `name` must point to a NUL-terminated string. Static return: same
/// thread caveat as [`getpwnam`]; errno is preserved on success like musl.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getspnam(name: *const c_char) -> *mut Spwd {
    unsafe {
        if SP_BUF.is_null() {
            SP_BUF = malloc(SP_LINE_LIM) as *mut c_char;
            if SP_BUF.is_null() {
                return null_mut();
            }
        }
        let mut res: *mut Spwd = null_mut();
        let e = getspnam_r(
            name,
            &mut *core::ptr::addr_of_mut!(SP_VAL),
            SP_BUF,
            SP_LINE_LIM,
            &mut res,
        );
        let keep = errno_load(__errno_location());
        if e != 0 {
            errno_store(__errno_location(), e);
        } else {
            errno_store(__errno_location(), keep);
        }
        res
    }
}

/// Next shadow entry from a stream (musl `fgetspent`).
///
/// # Safety
///
/// `f` must be a readable open stream. Static return, not thread-safe.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fgetspent(f: *mut File) -> *mut Spwd {
    unsafe {
        static mut LINE: *mut c_char = null_mut();
        static mut SIZE: usize = 0;
        static mut SP: Spwd = Spwd {
            sp_namp: null_mut(),
            sp_pwdp: null_mut(),
            sp_lstchg: 0,
            sp_min: 0,
            sp_max: 0,
            sp_warn: 0,
            sp_inact: 0,
            sp_expire: 0,
            sp_flag: 0,
        };
        if crate::stdio::file::getline(
            &mut *core::ptr::addr_of_mut!(LINE),
            &mut *core::ptr::addr_of_mut!(SIZE),
            f,
        ) < 0
        {
            return null_mut();
        }
        if parse_sp(LINE, &mut *core::ptr::addr_of_mut!(SP)) {
            return core::ptr::addr_of_mut!(SP);
        }
        null_mut()
    }
}

/// Next shadow entry from the default source (musl `getspent`: always null).
///
/// # Safety
///
/// Pure stub like musl's own: no pointers involved.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getspent() -> *mut Spwd {
    null_mut()
}

/// Rewind the shadow source (musl `setspent`: a no-op stub).
///
/// # Safety
///
/// Pure stub like musl's own: no pointers involved.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setspent() {}

/// End shadow iteration (musl `endspent`: a no-op stub).
///
/// # Safety
///
/// Pure stub like musl's own: no pointers involved.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn endspent() {}

/// Write a shadow entry (musl `putspent`; -1 numerics print as empty, the
/// `%.*ld` precision trick spelled out).
///
/// # Safety
///
/// `sp` readable with NUL-terminated strings; `f` writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn putspent(sp: *const Spwd, f: *mut File) -> c_int {
    unsafe {
        let empty = c"".as_ptr();
        let namp = if (*sp).sp_namp.is_null() {
            empty
        } else {
            (*sp).sp_namp as *const c_char
        };
        let pwdp = if (*sp).sp_pwdp.is_null() {
            empty
        } else {
            (*sp).sp_pwdp as *const c_char
        };
        if crate::stdio::fputs(namp, f) < 0 {
            return -1;
        }
        if crate::stdio::file::fputc(b':' as c_int, f) < 0 {
            return -1;
        }
        if crate::stdio::fputs(pwdp, f) < 0 {
            return -1;
        }
        let nums = [
            (*sp).sp_lstchg,
            (*sp).sp_min,
            (*sp).sp_max,
            (*sp).sp_warn,
            (*sp).sp_inact,
            (*sp).sp_expire,
        ];
        for v in nums {
            if crate::stdio::file::fputc(b':' as c_int, f) < 0 {
                return -1;
            }
            if v != -1 && put_dec(f, v as c_ulong) < 0 {
                return -1;
            }
        }
        if crate::stdio::file::fputc(b':' as c_int, f) < 0 {
            return -1;
        }
        if (*sp).sp_flag as c_long != -1 && put_dec(f, (*sp).sp_flag) < 0 {
            return -1;
        }
        if crate::stdio::file::fputc(b'\n' as c_int, f) < 0 {
            return -1;
        }
        0
    }
}

// ---- groups by user ------------------------------------------------------------
/// Supplementary groups for `user` (musl `getgrouplist`, file half only).
///
/// `*ngroups` in: room in `groups`; out: entries that would fit plus the
/// primary. Returns the count, or -1 with `*ngroups` set to the needed
/// size when the room is short. No nscd half: file membership only.
///
/// # Safety
///
/// `user` NUL-terminated; `groups` writable for `*ngroups` entries when
/// positive; `ngroups` writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getgrouplist(
    user: *const c_char,
    gid: u32,
    groups: *mut u32,
    ngroups: *mut c_int,
) -> c_int {
    unsafe {
        let nlim = *ngroups;
        let mut n: c_int = 1;
        if nlim >= 1 {
            *groups = gid;
        }
        let mut len = 0usize;
        let data = load_file(c"/etc/group".as_ptr(), &mut len);
        if data.is_null() {
            let e = errno_load(__errno_location());
            if e != ENOENT && e != 20 {
                return -1;
            }
        } else {
            let mut gr = Group {
                gr_name: null_mut(),
                gr_passwd: null_mut(),
                gr_gid: 0,
                gr_mem: null_mut(),
            };
            let mut pos = 0usize;
            let mut ok = true;
            while pos < len {
                let mut end = pos;
                while *data.add(end) != b'\n' {
                    end += 1;
                }
                let line = stash(
                    data,
                    pos,
                    end,
                    &mut *core::ptr::addr_of_mut!(GR_BUF),
                    &mut *core::ptr::addr_of_mut!(GR_CAP),
                );
                pos = end + 1;
                if line.is_null() || !parse_gr(line, &mut gr) {
                    if line.is_null() {
                        ok = false;
                        break;
                    }
                    continue;
                }
                let mut i = 0usize;
                while !(*gr.gr_mem.add(i)).is_null() {
                    if crate::string::strcmp(user, *gr.gr_mem.add(i)) == 0 {
                        break;
                    }
                    i += 1;
                }
                if (*gr.gr_mem.add(i)).is_null() {
                    continue;
                }
                n += 1;
                if n <= nlim {
                    *groups.add((n - 1) as usize) = gr.gr_gid;
                }
            }
            free(data as *mut c_void);
            if !ok {
                return -1;
            }
        }
        *ngroups = n;
        if n > nlim {
            -1
        } else {
            n
        }
    }
}

/// Initialize the supplementary group list (musl `initgroups`: 32-slot
/// stack probe, growing `calloc` retries, then [`setgroups`]).
///
/// # Safety
///
/// `user` must point to a NUL-terminated string.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn initgroups(user: *const c_char, gid: u32) -> c_int {
    unsafe {
        let mut stack = [0_u32; 32];
        let mut groups = stack.as_mut_ptr();
        let mut count = 32 as c_int;
        let mut prev = count;
        let mut owned = false;
        loop {
            let mut c = count;
            let r = getgrouplist(user, gid, groups, &mut c);
            if r >= 0 {
                let ret = setgroups(c as usize, groups);
                if owned {
                    free(groups as *mut c_void);
                }
                return ret;
            }
            if owned {
                free(groups as *mut c_void);
            }
            if c <= prev {
                return -1;
            }
            if c < prev + (prev >> 1) {
                c = prev + (prev >> 1);
            }
            let m = calloc(c as usize, core::mem::size_of::<u32>()) as *mut u32;
            if m.is_null() {
                return -1;
            }
            groups = m;
            owned = true;
            prev = c;
            count = c;
        }
    }
}

/// Set the supplementary group list (musl `setgroups`, single-trap half:
/// musl waves the call over every thread and SIGKILLs on divergence —
/// without that machinery this is one `SYS_setgroups` trap).
///
/// # Safety
///
/// `list` must hold `count` readable gids.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setgroups(count: usize, list: *const u32) -> c_int {
    unsafe {
        crate::syscall::syscall_ret(crate::syscall::syscall2(
            SYS_SETGROUPS,
            count,
            list as usize,
        )) as c_int
    }
}

/// Get the supplementary group list (musl `getgroups`: one trap).
///
/// # Safety
///
/// `list` null or writable for `count` gids.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getgroups(count: c_int, list: *mut u32) -> c_int {
    unsafe {
        crate::syscall::syscall_ret(crate::syscall::syscall2(
            SYS_GETGROUPS,
            count as usize,
            list as usize,
        )) as c_int
    }
}

// ---- login name ------------------------------------------------------------------
extern "C" {
    #[cfg(target_arch = "x86_64")]
    static environ: *const *mut c_char;
}

/// Process login name (musl `getlogin`: the `LOGNAME` variable).
///
/// # Safety
///
/// Reads the process environment; the pointer stays valid while the
/// variable is set (same lifetime caveat as `getenv`).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getlogin() -> *mut c_char {
    unsafe {
        if environ.is_null() {
            return null_mut();
        }
        let mut i = 0usize;
        while !(*environ.add(i)).is_null() {
            let e = *environ.add(i);
            if crate::string::strncmp(e, c"LOGNAME=".as_ptr(), 8) == 0 {
                return e.add(8);
            }
            i += 1;
        }
        null_mut()
    }
}

/// Login name into caller storage (musl `getlogin_r`: `ENXIO` when unset,
/// `ERANGE` when short).
///
/// # Safety
///
/// `name` must be writable for `size` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getlogin_r(name: *mut c_char, size: usize) -> c_int {
    unsafe {
        let logname = getlogin();
        if logname.is_null() {
            return ENXIO;
        }
        if crate::mem::strlen(logname) >= size {
            return ERANGE;
        }
        crate::string::strcpy(name, logname);
        0
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    const EACCES: c_int = 13;
    use core::ffi::{c_int, c_void};

    #[test]
    fn root_passwd_roundtrip() {
        unsafe {
            let pw = getpwnam(c"root".as_ptr());
            assert!(!pw.is_null(), "no root in /etc/passwd");
            assert_eq!((*pw).pw_uid, 0);
            assert_eq!(crate::string::strcmp((*pw).pw_name, c"root".as_ptr()), 0);
            assert!(!(*pw).pw_dir.is_null() && *(*pw).pw_dir != 0);
            assert!(!(*pw).pw_shell.is_null() && *(*pw).pw_shell != 0);
            let by_uid = getpwuid(0);
            assert!(!by_uid.is_null());
            assert_eq!(
                crate::string::strcmp((*by_uid).pw_name, c"root".as_ptr()),
                0
            );
            // Lookup statics are shared: the second call owns the storage,
            // so only compare content, never pointers across calls.
            assert!(getpwnam(c"no-such-user-zlibc".as_ptr()).is_null());
            assert!(getpwuid(0xfffffffe).is_null());
        }
    }

    #[test]
    fn root_group_roundtrip() {
        unsafe {
            let gr = getgrnam(c"root".as_ptr());
            assert!(!gr.is_null(), "no root in /etc/group");
            assert_eq!((*gr).gr_gid, 0);
            let by_gid = getgrgid(0);
            assert!(!by_gid.is_null());
            assert_eq!(
                crate::string::strcmp((*by_gid).gr_name, c"root".as_ptr()),
                0
            );
            assert!(getgrnam(c"no-such-group-zlibc".as_ptr()).is_null());
        }
    }

    #[test]
    fn pwent_iterates_and_rewinds() {
        unsafe {
            let mut n = 0;
            loop {
                let e = getpwent();
                if e.is_null() {
                    break;
                }
                assert!(!(*e).pw_name.is_null() && *(*e).pw_name != 0);
                n += 1;
                assert!(n < 100000, "runaway /etc/passwd?");
            }
            assert!(n > 0, "/etc/passwd parsed empty");
            setpwent();
            assert!(!getpwent().is_null(), "setpwent did not rewind");
            endpwent();
        }
    }

    #[test]
    fn grent_iterates_and_rewinds() {
        unsafe {
            let mut n = 0;
            loop {
                let e = getgrent();
                if e.is_null() {
                    break;
                }
                assert!(!(*e).gr_name.is_null());
                assert!(!(*e).gr_mem.is_null());
                n += 1;
                assert!(n < 100000, "runaway /etc/group?");
            }
            assert!(n > 0, "/etc/group parsed empty");
            setgrent();
            assert!(!getgrent().is_null(), "setgrent did not rewind");
            endgrent();
        }
    }

    #[test]
    fn grouplist_sizes_then_fills() {
        unsafe {
            let mut n = 0 as c_int;
            assert_eq!(getgrouplist(c"root".as_ptr(), 0, null_mut(), &mut n), -1);
            assert!(n >= 1, "root needs at least its primary gid");
            let m = calloc(n as usize, core::mem::size_of::<u32>()) as *mut u32;
            assert!(!m.is_null());
            let mut n2 = n;
            let r = getgrouplist(c"root".as_ptr(), 0, m, &mut n2);
            assert!(r >= 1);
            assert_eq!(*m, 0, "primary gid goes first");
            free(m as *mut c_void);
        }
    }

    #[test]
    fn spnam_graceful_without_shadow_access() {
        unsafe {
            // Permission, not absence: passes whether or not we can read it.
            let sp = getspnam(c"root".as_ptr());
            if !sp.is_null() {
                assert_eq!(crate::string::strcmp((*sp).sp_namp, c"root".as_ptr()), 0);
            }
            let mut val: Spwd = core::mem::zeroed();
            let mut buf = [0 as c_char; 512];
            let mut res: *mut Spwd = null_mut();
            let r = getspnam_r(
                c"root".as_ptr(),
                &mut val,
                buf.as_mut_ptr(),
                buf.len(),
                &mut res,
            );
            // Root reads shadow (0); unprivileged gets EACCES (neither is
            // ENOENT/ENOTDIR, which would mean a broken lookup path).
            assert!(r == 0 || r == EACCES, "getspnam_r root: {r}");
            assert!((res.is_null() && sp.is_null()) || (!res.is_null() && !sp.is_null()));
            // Bad names and short buffers fail cleanly, never touch storage.
            assert_eq!(
                getspnam_r(
                    c"../x".as_ptr(),
                    &mut val,
                    buf.as_mut_ptr(),
                    buf.len(),
                    &mut res
                ),
                EINVAL
            );
            assert_eq!(
                getspnam_r(c"root".as_ptr(), &mut val, buf.as_mut_ptr(), 8, &mut res),
                ERANGE
            );
            // Stubs mirror musl's own no-op getspent.c.
            assert!(getspent().is_null());
            setspent();
            endspent();
        }
    }

    #[test]
    fn groups_and_login_do_not_crash() {
        unsafe {
            let n = getgroups(0, null_mut());
            assert!(n >= 0);
            if n > 0 {
                let m = calloc(n as usize, core::mem::size_of::<u32>()) as *mut u32;
                assert!(!m.is_null());
                assert_eq!(getgroups(n, m), n);
                free(m as *mut c_void);
            }
            // initgroups needs privilege; either outcome is fine, no crash.
            let _ = initgroups(c"root".as_ptr(), 0);
            // LOGNAME present or not: both paths are clean.
            let mut buf = [0 as c_char; 256];
            let r = getlogin_r(buf.as_mut_ptr(), buf.len());
            let lv = std::env::var("LOGNAME").ok();
            if let Some(v) = lv {
                assert_eq!(r, 0);
                assert_eq!(
                    crate::string::strcmp(buf.as_ptr(), c"root".as_ptr()) == 0,
                    v == "root"
                );
            } else {
                assert_eq!(r, ENXIO);
                assert!(getlogin().is_null());
            }
            assert_eq!(
                getlogin_r(buf.as_mut_ptr(), 1),
                if r == 0 { ERANGE } else { ENXIO }
            );
        }
    }

    #[test]
    fn putent_roundtrips_through_memstream() {
        unsafe {
            // put* write through our own FILE layer; read the bytes back.
            let mut bp: *mut c_char = null_mut();
            let mut np: usize = 0;
            let f = crate::stdio::file::open_memstream(&mut bp, &mut np);
            assert!(!f.is_null());
            let pw = getpwnam(c"root".as_ptr());
            assert!(!pw.is_null());
            assert_eq!(putpwent(pw, f), 0);
            let gr = getgrnam(c"root".as_ptr());
            assert!(!gr.is_null());
            assert_eq!(putgrent(gr, f), 0);
            crate::stdio::fflush(f);
            std::eprintln!("DBG after fflush: bpnull={} np={}", bp.is_null(), np);
            crate::stdio::fclose(f);
            std::eprintln!("DBG after fclose: bpnull={} np={}", bp.is_null(), np);
            assert!(!bp.is_null() && np > 0);
            let s = std::ffi::CStr::from_ptr(bp as *const c_char).to_string_lossy();
            assert!(s.starts_with("root:"), "putpwent line: {s:?}");
            assert!(s.contains("\nroot:"), "putgrent line missing: {s:?}");
            crate::malloc::free(bp as *mut c_void);
        }
    }

    #[test]
    fn fgetent_reads_from_stream() {
        unsafe {
            // fget* parse through our FILE layer from a real file.
            let f = crate::stdio::fopen(c"/etc/passwd".as_ptr(), c"r".as_ptr());
            if f.is_null() {
                return;
            }
            let e = fgetpwent(f);
            assert!(!e.is_null());
            assert!(!(*e).pw_name.is_null());
            crate::stdio::fclose(f);
            let g = crate::stdio::fopen(c"/etc/group".as_ptr(), c"r".as_ptr());
            if g.is_null() {
                return;
            }
            let ge = fgetgrent(g);
            assert!(!ge.is_null());
            crate::stdio::fclose(g);
        }
    }
}
