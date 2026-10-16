//! `getopt`, `getopt_long`, `getopt_long_only` and `struct option`.
//!
//! Byte-level port of musl `src/misc/getopt.c` + `src/misc/getopt_long.c`:
//! same permutation, `--` handling, `:`/`?` returns and `opterr` gating.
//! Multibyte option chars go through a local UTF-8 decoder matching
//! musl's `mbtowc` in the C.UTF-8 locale (invalid byte: `U+FFFD`, 1 byte).
//!
//! Deviations from musl (all verified against the reference source):
//! - No `W;` handling: musl's `getopt.c`/`getopt_long.c` contain none
//!   (verified by grep), so there is nothing to mirror.
//! - `__getopt_msg` is NOT in the ABI baseline, so the message writer is
//!   a private helper emitting the same bytes (`argv[0]`, middle text,
//!   offending bytes, `\n`) to fd 2 with a raw `SYS_WRITE` (no stdio, no
//!   errno side effects, no message translation: musl's `__lctrans_cur`
//!   is the identity under the default locale).
//! - musl declares `optreset` as a weak alias of the strong `__optreset`
//!   (`weak_alias(__optreset, optreset)`); the order below is the inverse
//!   `(new, old)` per `crate::weak_alias!`, same meaning. Likewise
//!   `__posix_getopt` is a weak alias of `getopt` (both in the baseline).

use core::ffi::{c_char, c_int};
use core::ptr::null_mut;

/// musl `char *optarg` (`getopt.c:10`).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub static mut optarg: *mut c_char = null_mut();

/// musl `int optind = 1` (`getopt.c:10`).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub static mut optind: c_int = 1;

/// musl `int opterr = 1` (`getopt.c:10`).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub static mut opterr: c_int = 1;

/// musl `int optopt` (`getopt.c:10`, zero-initialised).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub static mut optopt: c_int = 0;

/// musl `int __optpos` (`getopt.c:10`, zero-initialised): byte offset of
/// the next short option inside the current argv element.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub static mut __optpos: c_int = 0;

/// musl `int __optreset = 0` (`getopt.c:10`): nonzero forces a fresh scan
/// on the next call. `optreset` below is its weak alias.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub static mut __optreset: c_int = 0;

// musl `weak_alias(__optreset, optreset)` (`getopt.c:14`): `optreset` is
// the weak alias, `__optreset` the strong target. Argument order is
// `(new, old)` — the inverse of musl's `(old, new)` — same meaning.
#[cfg(target_arch = "x86_64")]
crate::weak_alias!(optreset, __optreset);

// musl `weak_alias(getopt, __posix_getopt)` (`getopt.c:106`).
#[cfg(target_arch = "x86_64")]
crate::weak_alias!(__posix_getopt, getopt);

/// musl `struct option` (`include/getopt.h:12-17`).
#[cfg(target_arch = "x86_64")]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct option {
    pub name: *const c_char,
    pub has_arg: c_int,
    pub flag: *mut c_int,
    pub val: c_int,
}

/// musl `no_argument` (`include/getopt.h:22`).
#[cfg(target_arch = "x86_64")]
#[allow(non_upper_case_globals)]
pub const no_argument: c_int = 0;

/// musl `required_argument` (`include/getopt.h:23`).
#[cfg(target_arch = "x86_64")]
#[allow(non_upper_case_globals)]
pub const required_argument: c_int = 1;

/// musl `optional_argument` (`include/getopt.h:24`).
#[cfg(target_arch = "x86_64")]
#[allow(non_upper_case_globals)]
pub const optional_argument: c_int = 2;

/// NUL-terminated string length (musl `strlen`, local: no string dep).
#[cfg(target_arch = "x86_64")]
unsafe fn c_strlen(p: *const c_char) -> usize {
    unsafe {
        let mut n: usize = 0;
        while *p.add(n) != 0 {
            n = n.wrapping_add(1);
        }
        n
    }
}

/// Write all of `[ptr, ptr+len)` to fd 2, ignoring errors (musl's
/// `__getopt_msg` discards its stdio result the same way). Raw
/// `syscall3`, never `syscall_ret`: error reporting must not clobber
/// errno.
#[cfg(target_arch = "x86_64")]
unsafe fn fd2_write(mut ptr: *const u8, mut len: usize) {
    unsafe {
        while len > 0 {
            let r = crate::syscall::syscall3(crate::syscall::SYS_WRITE, 2, ptr as usize, len);
            if r <= 0 {
                break;
            }
            let n = r as usize;
            ptr = ptr.add(n);
            len -= n;
        }
    }
}

/// musl `__getopt_msg(argv[0], mid, tail, tail_len)` (`getopt.c:16-26`):
/// `argv[0]` + `mid` + the first `tail_len` bytes at `tail` + `\n`.
#[cfg(target_arch = "x86_64")]
unsafe fn emit_msg(prog: *const c_char, mid: &'static [u8], tail: *const u8, tail_len: usize) {
    unsafe {
        fd2_write(prog as *const u8, c_strlen(prog));
        fd2_write(mid.as_ptr(), mid.len());
        fd2_write(tail, tail_len);
        fd2_write(b"\n".as_ptr(), 1);
    }
}

/// One UTF-8 char at `p`, like musl's `mbtowc` in the C.UTF-8 locale.
/// Returns `(codepoint, byte_len)`; NUL gives `(0, 0)`; an invalid lead
/// or continuation byte gives `(0xFFFD, -1)` (musl returns `-1`, and
/// `getopt.c:59-62` then substitutes `U+FFFD` with length 1).
#[cfg(target_arch = "x86_64")]
unsafe fn mb_decode(p: *const u8) -> (u32, c_int) {
    unsafe {
        let b0 = *p;
        if b0 < 0x80 {
            if b0 == 0 {
                return (0, 0);
            }
            return (b0 as u32, 1);
        }
        let mut cp: u32;
        let len: usize;
        if b0 >> 5 == 0b110 {
            cp = (b0 & 0x1F) as u32;
            len = 2;
        } else if b0 >> 4 == 0b1110 {
            cp = (b0 & 0x0F) as u32;
            len = 3;
        } else if b0 >> 3 == 0b11110 {
            cp = (b0 & 0x07) as u32;
            len = 4;
        } else {
            return (0xFFFD, -1);
        }
        let mut i: usize = 1;
        while i < len {
            let b = *p.add(i);
            if b >> 6 != 0b10 {
                return (0xFFFD, -1);
            }
            cp = (cp << 6) | (b & 0x3F) as u32;
            i = i.wrapping_add(1);
        }
        let min = if len == 2 {
            0x80
        } else if len == 3 {
            0x800
        } else {
            0x10000
        };
        if cp < min || cp > 0x10FFFF || (0xD800..0xE000).contains(&cp) {
            return (0xFFFD, -1);
        }
        (cp, len as c_int)
    }
}

/// musl `getopt` (`src/misc/getopt.c:28-104`).
///
/// Scans `argv` for short options described by `optstring`. Leading `-`
/// (return 1 with `optarg` set for non-options) and `+` (strict POSIX
/// stop at the first non-option) are honoured; `--` ends the scan.
///
/// # Safety
///
/// `argv` must hold at least `argc` readable entries plus the customary
/// trailing NULL (`argv[argc]` is read when an argument is missing);
/// `optstring` must be a valid NUL-terminated string. Returned `optarg`
/// borrows `argv` and must not outlive it.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getopt(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
) -> c_int {
    unsafe {
        if optind == 0 || __optreset != 0 {
            __optreset = 0;
            __optpos = 0;
            optind = 1;
        }

        if optind >= argc || (*argv.add(optind as usize)).is_null() {
            return -1;
        }
        let arg = *argv.add(optind as usize);

        if *arg != b'-' as c_char {
            if *optstring == b'-' as c_char {
                optarg = arg;
                optind = optind.wrapping_add(1);
                return 1;
            }
            return -1;
        }

        if *arg.add(1) == 0 {
            return -1;
        }

        if *arg.add(1) == b'-' as c_char && *arg.add(2) == 0 {
            optind = optind.wrapping_add(1);
            return -1;
        }

        if __optpos == 0 {
            __optpos = 1;
        }
        let (c0, k0) = mb_decode(arg.add(__optpos as usize) as *const u8);
        let (c, k) = if k0 < 0 { (0xFFFD, 1) } else { (c0, k0) };
        let optchar = arg.add(__optpos as usize);
        __optpos = __optpos.wrapping_add(k);

        if *arg.add(__optpos as usize) == 0 {
            optind = optind.wrapping_add(1);
            __optpos = 0;
        }

        let mut os = optstring;
        if *os == b'-' as c_char || *os == b'+' as c_char {
            os = os.add(1);
        }
        let osu = os as *const u8;

        let mut i: usize = 0;
        let mut d: u32 = 0;
        loop {
            let (dd, l) = mb_decode(osu.add(i));
            if l == 0 {
                d = 0;
                break;
            }
            if l > 0 {
                i = i.wrapping_add(l as usize);
                d = dd;
            } else {
                i = i.wrapping_add(1);
            }
            if d == c {
                break;
            }
        }

        if d != c || c == b':' as u32 {
            optopt = c as c_int;
            if *os != b':' as c_char && opterr != 0 {
                emit_msg(
                    *argv,
                    b": unrecognized option: ",
                    optchar as *const u8,
                    k as usize,
                );
            }
            return b'?' as c_int;
        }
        if *osu.add(i) == b':' {
            optarg = null_mut();
            if *osu.add(i.wrapping_add(1)) != b':' || __optpos != 0 {
                optarg = *argv.add(optind as usize);
                optind = optind.wrapping_add(1);
                if __optpos != 0 {
                    optarg = (optarg as *mut u8).add(__optpos as usize) as *mut c_char;
                }
                __optpos = 0;
            }
            if optind > argc {
                optopt = c as c_int;
                if *os == b':' as c_char {
                    return b':' as c_int;
                }
                if opterr != 0 {
                    emit_msg(
                        *argv,
                        b": option requires an argument: ",
                        optchar as *const u8,
                        k as usize,
                    );
                }
                return b'?' as c_int;
            }
        }
        c as c_int
    }
}

/// musl `permute` (`getopt_long.c:12-20`): move `av[src]` to `dest`,
/// shifting `[dest, src)` one slot right.
#[cfg(target_arch = "x86_64")]
unsafe fn permute(argv: *const *mut c_char, dest: c_int, src: c_int) {
    unsafe {
        let av = argv as *mut *mut c_char;
        let tmp = *av.add(src as usize);
        let mut i = src;
        while i > dest {
            *av.add(i as usize) = *av.add((i.wrapping_sub(1)) as usize);
            i = i.wrapping_sub(1);
        }
        *av.add(dest as usize) = tmp;
    }
}

/// musl `__getopt_long_core` (`getopt_long.c:53-138`).
#[cfg(target_arch = "x86_64")]
#[allow(clippy::too_many_arguments)]
unsafe fn getopt_long_core(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
    longopts: *const option,
    idx: *mut c_int,
    longonly: c_int,
) -> c_int {
    unsafe {
        optarg = null_mut();
        let cur = *argv.add(optind as usize);
        if !longopts.is_null()
            && *cur == b'-' as c_char
            && ((longonly != 0 && *cur.add(1) != 0 && *cur.add(1) != b'-' as c_char)
                || (*cur.add(1) == b'-' as c_char && *cur.add(2) != 0))
        {
            let osu = optstring as *const u8;
            let skip = if *osu == b'+' || *osu == b'-' { 1 } else { 0 };
            let colon = *osu.add(skip) == b':';
            let start = cur.add(1);
            let startu = start as *const u8;
            let mut cnt: c_int = 0;
            let mut matched: c_int = 0;
            let mut argp: *const u8 = null_mut();
            let mut li: c_int = 0;
            while !(*longopts.add(li as usize)).name.is_null() {
                let mut name = (*longopts.add(li as usize)).name as *const u8;
                let mut opt = startu;
                if *opt == b'-' {
                    opt = opt.add(1);
                }
                while *opt != 0 && *opt != b'=' && *opt == *name {
                    name = name.add(1);
                    opt = opt.add(1);
                }
                if *opt != 0 && *opt != b'=' {
                    li = li.wrapping_add(1);
                    continue;
                }
                argp = opt;
                matched = li;
                if *name == 0 {
                    cnt = 1;
                    break;
                }
                cnt = cnt.wrapping_add(1);
                li = li.wrapping_add(1);
            }
            // `mblen(start)`: byte length of one char, 0 at NUL, -1 if invalid.
            let mb1 = mb_decode(startu).1;
            if cnt == 1
                && longonly != 0
                && (argp as usize).wrapping_sub(startu as usize) as c_int == mb1
            {
                let l = (argp as usize).wrapping_sub(startu as usize);
                let mut oi: usize = 0;
                while *osu.add(oi) != 0 {
                    let mut j: usize = 0;
                    while j < l && *startu.add(j) == *osu.add(oi.wrapping_add(j)) {
                        j = j.wrapping_add(1);
                    }
                    if j == l {
                        cnt = cnt.wrapping_add(1);
                        break;
                    }
                    oi = oi.wrapping_add(1);
                }
            }
            if cnt == 1 {
                let mi = matched as usize;
                let has_arg = (*longopts.add(mi)).has_arg;
                let val = (*longopts.add(mi)).val;
                let nm = (*longopts.add(mi)).name;
                let opt = argp;
                optind = optind.wrapping_add(1);
                if *opt == b'=' {
                    if has_arg == 0 {
                        optopt = val;
                        if colon || opterr == 0 {
                            return b'?' as c_int;
                        }
                        emit_msg(
                            *argv,
                            b": option does not take an argument: ",
                            nm as *const u8,
                            c_strlen(nm),
                        );
                        return b'?' as c_int;
                    }
                    optarg = opt.add(1) as *mut c_char;
                } else if has_arg == required_argument {
                    let nxt = *argv.add(optind as usize);
                    if nxt.is_null() {
                        optopt = val;
                        if colon {
                            return b':' as c_int;
                        }
                        if opterr == 0 {
                            return b'?' as c_int;
                        }
                        emit_msg(
                            *argv,
                            b": option requires an argument: ",
                            nm as *const u8,
                            c_strlen(nm),
                        );
                        return b'?' as c_int;
                    }
                    optarg = nxt;
                    optind = optind.wrapping_add(1);
                }
                if !idx.is_null() {
                    *idx = matched;
                }
                let flag = (*longopts.add(mi)).flag;
                if !flag.is_null() {
                    *flag = val;
                    return 0;
                }
                return val;
            }
            if *cur.add(1) == b'-' as c_char {
                optopt = 0;
                if !colon && opterr != 0 {
                    if cnt != 0 {
                        emit_msg(
                            *argv,
                            b": option is ambiguous: ",
                            cur.add(2) as *const u8,
                            c_strlen(cur.add(2)),
                        );
                    } else {
                        emit_msg(
                            *argv,
                            b": unrecognized option: ",
                            cur.add(2) as *const u8,
                            c_strlen(cur.add(2)),
                        );
                    }
                }
                optind = optind.wrapping_add(1);
                return b'?' as c_int;
            }
        }
        getopt(argc, argv, optstring)
    }
}

/// musl `__getopt_long` (`getopt_long.c:24-51`): permutation wrapper.
#[cfg(target_arch = "x86_64")]
unsafe fn getopt_long_impl(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
    longopts: *const option,
    idx: *mut c_int,
    longonly: c_int,
) -> c_int {
    unsafe {
        if optind == 0 || __optreset != 0 {
            __optreset = 0;
            __optpos = 0;
            optind = 1;
        }
        if optind >= argc || (*argv.add(optind as usize)).is_null() {
            return -1;
        }
        let skipped = optind;
        if *optstring != b'+' as c_char && *optstring != b'-' as c_char {
            let mut i = optind;
            loop {
                if i >= argc || (*argv.add(i as usize)).is_null() {
                    return -1;
                }
                let a = *argv.add(i as usize);
                if *a == b'-' as c_char && *a.add(1) != 0 {
                    break;
                }
                i = i.wrapping_add(1);
            }
            optind = i;
        }
        let resumed = optind;
        let ret = getopt_long_core(argc, argv, optstring, longopts, idx, longonly);
        if resumed > skipped {
            let cnt = optind.wrapping_sub(resumed);
            let mut i: c_int = 0;
            while i < cnt {
                permute(argv, skipped, optind.wrapping_sub(1));
                i = i.wrapping_add(1);
            }
            optind = skipped.wrapping_add(cnt);
        }
        ret
    }
}

/// musl `getopt_long` (`getopt_long.c:140-143`).
///
/// Like [`getopt`], plus `--name` / `--name=value` long options from
/// `longopts` (NULL entry terminates). Exact and unambiguous prefix
/// matches win; `--name=x` with `has_arg == 0` and a missing required
/// argument report `?` (or `:` with a leading `:` in `optstring`).
/// Non-option elements are permuted after the options unless
/// `optstring` starts with `+` or `-`.
///
/// # Safety
///
/// Same `argv`/`optstring` contract as [`getopt`], plus: `longopts` must
/// be NULL or point at a NULL-`name`-terminated array of valid
/// `option`s; `idx` must be NULL or a writable `c_int`; each `flag`
/// must be NULL or writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getopt_long(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
    longopts: *const option,
    longindex: *mut c_int,
) -> c_int {
    unsafe { getopt_long_impl(argc, argv, optstring, longopts, longindex, 0) }
}

/// musl `getopt_long_only` (`getopt_long.c:145-148`).
///
/// Like [`getopt_long`], except single-dash `-name` is also tried as a
/// long option first (falling back to short options on no match, or
/// when the match is also a prefix of `optstring`).
///
/// # Safety
///
/// Same contract as [`getopt_long`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getopt_long_only(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
    longopts: *const option,
    longindex: *mut c_int,
) -> c_int {
    unsafe { getopt_long_impl(argc, argv, optstring, longopts, longindex, 1) }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::{__optpos, __optreset, getopt, getopt_long, getopt_long_only, optarg, opterr};
    use super::{no_argument, optional_argument, required_argument};
    use super::{optind, option, optopt};
    use core::ffi::{c_char, c_int};
    use core::ptr::{addr_of, addr_of_mut, null, null_mut};
    use core::sync::atomic::{AtomicI32, Ordering};

    /// Serializes the stateful tests below (libtest runs them on
    /// parallel threads; the getopt globals are process-global).
    static TEST_LOCK: AtomicI32 = AtomicI32::new(0);
    struct TGuard;
    impl Drop for TGuard {
        fn drop(&mut self) {
            TEST_LOCK.store(0, Ordering::SeqCst);
        }
    }
    fn test_lock() -> TGuard {
        while TEST_LOCK
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            core::hint::spin_loop();
        }
        TGuard
    }

    /// Full global reset (stronger than musl's lazy `optreset` path, so
    /// each test starts deterministic).
    unsafe fn reset() {
        unsafe {
            addr_of_mut!(optarg).write(null_mut());
            addr_of_mut!(optind).write(1);
            addr_of_mut!(opterr).write(1);
            addr_of_mut!(optopt).write(0);
            addr_of_mut!(__optpos).write(0);
            addr_of_mut!(__optreset).write(0);
        }
    }

    /// NUL-terminated argv with the customary trailing NULL entry.
    struct Argv {
        _own: std::vec::Vec<std::ffi::CString>,
        ptr: std::vec::Vec<*mut c_char>,
    }
    impl Argv {
        fn new(words: &[&str]) -> Self {
            let own: std::vec::Vec<std::ffi::CString> = words
                .iter()
                .map(|w| std::ffi::CString::new(*w).unwrap())
                .collect();
            let mut ptr: std::vec::Vec<*mut c_char> =
                own.iter().map(|c| c.as_ptr() as *mut c_char).collect();
            ptr.push(null_mut());
            Self { _own: own, ptr }
        }
        fn argc(&self) -> c_int {
            self.ptr.len().wrapping_sub(1) as c_int
        }
        unsafe fn short(&mut self, opt: &core::ffi::CStr) -> c_int {
            unsafe {
                getopt(
                    self.argc(),
                    self.ptr.as_mut_ptr() as *const *mut c_char,
                    opt.as_ptr(),
                )
            }
        }
        unsafe fn long(
            &mut self,
            opt: &core::ffi::CStr,
            lo: *const option,
            idx: *mut c_int,
            only: bool,
        ) -> c_int {
            unsafe {
                let av = self.ptr.as_mut_ptr() as *const *mut c_char;
                if only {
                    getopt_long_only(self.argc(), av, opt.as_ptr(), lo, idx)
                } else {
                    getopt_long(self.argc(), av, opt.as_ptr(), lo, idx)
                }
            }
        }
    }

    unsafe fn cstr_eq(p: *mut c_char, want: &[u8]) -> bool {
        unsafe {
            if p.is_null() {
                return false;
            }
            let mut i: usize = 0;
            while i < want.len() {
                if *p.add(i) as u8 != want[i] {
                    return false;
                }
                i = i.wrapping_add(1);
            }
            *p.add(want.len()) == 0
        }
    }

    fn has(hay: &[u8], ndl: &[u8]) -> bool {
        !ndl.is_empty() && hay.windows(ndl.len()).any(|w| w == ndl)
    }

    const SENTINEL: option = option {
        name: null(),
        has_arg: 0,
        flag: null_mut(),
        val: 0,
    };

    #[test]
    fn short_opts_with_separate_and_attached_args() {
        let _g = test_lock();
        unsafe {
            reset();
            let mut av = Argv::new(&["prog", "-a", "-bfoo", "-c", "-b", "baz"]);
            let o = c"ab:c";
            assert_eq!(av.short(o), b'a' as c_int);
            assert_eq!(av.short(o), b'b' as c_int);
            assert!(cstr_eq(addr_of!(optarg).read(), b"foo"));
            assert_eq!(av.short(o), b'c' as c_int);
            assert_eq!(av.short(o), b'b' as c_int);
            assert!(cstr_eq(addr_of!(optarg).read(), b"baz"));
            assert_eq!(av.short(o), -1);
            assert_eq!(addr_of!(optind).read(), av.argc());
        }
    }

    #[test]
    fn double_dash_terminates_scan() {
        let _g = test_lock();
        unsafe {
            reset();
            let mut av = Argv::new(&["prog", "-a", "--", "-b"]);
            let o = c"ab";
            assert_eq!(av.short(o), b'a' as c_int);
            assert_eq!(av.short(o), -1);
            assert_eq!(addr_of!(optind).read(), 3);
            // Scan stopped before the `-b` past `--` (musl resumes there
            // on the next call; it is never consumed as `--` itself).
            assert!(cstr_eq(av.ptr[addr_of!(optind).read() as usize], b"-b"));
        }
    }

    #[test]
    fn bare_dash_and_plain_getopt_stops_at_nonoption() {
        let _g = test_lock();
        unsafe {
            reset();
            // Bare "-" is not an option.
            let mut av = Argv::new(&["prog", "-", "-a"]);
            assert_eq!(av.short(c"a"), -1);
            assert_eq!(addr_of!(optind).read(), 1);
            // Plain getopt does NOT permute: stops at "file".
            let mut av = Argv::new(&["prog", "file", "-a"]);
            assert_eq!(av.short(c"a"), -1);
            assert_eq!(addr_of!(optind).read(), 1);
        }
    }

    #[test]
    fn unknown_short_option_reports_question_and_optopt() {
        let _g = test_lock();
        unsafe {
            reset();
            addr_of_mut!(opterr).write(0); // keep test output clean; gating covered below
            let mut av = Argv::new(&["prog", "-z"]);
            assert_eq!(av.short(c"ab"), b'?' as c_int);
            assert_eq!(addr_of!(optopt).read(), b'z' as c_int);
            assert_eq!(addr_of!(optind).read(), 2);
        }
    }

    #[test]
    fn missing_arg_colon_vs_question() {
        let _g = test_lock();
        unsafe {
            reset();
            addr_of_mut!(opterr).write(0);
            let mut av = Argv::new(&["prog", "-b"]);
            assert_eq!(av.short(c"ab:"), b'?' as c_int);
            assert_eq!(addr_of!(optopt).read(), b'b' as c_int);
            reset();
            addr_of_mut!(opterr).write(0);
            let mut av = Argv::new(&["prog", "-b"]);
            assert_eq!(av.short(c":ab:"), b':' as c_int);
            assert_eq!(addr_of!(optopt).read(), b'b' as c_int);
        }
    }

    #[test]
    fn leading_dash_optstring_returns_one_for_nonoptions() {
        let _g = test_lock();
        unsafe {
            reset();
            let mut av = Argv::new(&["prog", "foo", "-a"]);
            let o = c"-a";
            assert_eq!(av.short(o), 1);
            assert!(cstr_eq(addr_of!(optarg).read(), b"foo"));
            assert_eq!(av.short(o), b'a' as c_int);
            assert_eq!(av.short(o), -1);
        }
    }

    #[test]
    fn long_exact_abbrev_equals_and_optional() {
        let _g = test_lock();
        unsafe {
            reset();
            addr_of_mut!(opterr).write(0);
            let lo = [
                option {
                    name: c"alpha".as_ptr(),
                    has_arg: no_argument,
                    flag: null_mut(),
                    val: b'a' as c_int,
                },
                option {
                    name: c"beta".as_ptr(),
                    has_arg: required_argument,
                    flag: null_mut(),
                    val: b'b' as c_int,
                },
                option {
                    name: c"delta".as_ptr(),
                    has_arg: optional_argument,
                    flag: null_mut(),
                    val: b'd' as c_int,
                },
                SENTINEL,
            ];
            let mut idx: c_int = -1;
            // Exact.
            let mut av = Argv::new(&["prog", "--alpha"]);
            assert_eq!(
                av.long(c"", lo.as_ptr(), addr_of_mut!(idx), false),
                b'a' as c_int
            );
            assert_eq!(idx, 0);
            // Unambiguous abbreviation.
            reset();
            addr_of_mut!(opterr).write(0);
            let mut av = Argv::new(&["prog", "--alp"]);
            assert_eq!(
                av.long(c"", lo.as_ptr(), addr_of_mut!(idx), false),
                b'a' as c_int
            );
            // Attached argument.
            reset();
            addr_of_mut!(opterr).write(0);
            let mut av = Argv::new(&["prog", "--beta=x"]);
            assert_eq!(
                av.long(c"", lo.as_ptr(), addr_of_mut!(idx), false),
                b'b' as c_int
            );
            assert!(cstr_eq(addr_of!(optarg).read(), b"x"));
            assert_eq!(idx, 1);
            // Separate argument.
            reset();
            addr_of_mut!(opterr).write(0);
            let mut av = Argv::new(&["prog", "--beta", "x"]);
            assert_eq!(
                av.long(c"", lo.as_ptr(), addr_of_mut!(idx), false),
                b'b' as c_int
            );
            assert!(cstr_eq(addr_of!(optarg).read(), b"x"));
            // Optional arg omitted stays NULL; attached is taken.
            reset();
            addr_of_mut!(opterr).write(0);
            let mut av = Argv::new(&["prog", "--delta"]);
            assert_eq!(
                av.long(c"", lo.as_ptr(), addr_of_mut!(idx), false),
                b'd' as c_int
            );
            assert!(addr_of!(optarg).read().is_null());
            reset();
            addr_of_mut!(opterr).write(0);
            let mut av = Argv::new(&["prog", "--delta=x"]);
            assert_eq!(
                av.long(c"", lo.as_ptr(), addr_of_mut!(idx), false),
                b'd' as c_int
            );
            assert!(cstr_eq(addr_of!(optarg).read(), b"x"));
        }
    }

    #[test]
    fn long_ambiguous_and_unknown() {
        let _g = test_lock();
        unsafe {
            reset();
            addr_of_mut!(opterr).write(0);
            let lo = [
                option {
                    name: c"alpha".as_ptr(),
                    has_arg: no_argument,
                    flag: null_mut(),
                    val: b'a' as c_int,
                },
                option {
                    name: c"alphabet".as_ptr(),
                    has_arg: no_argument,
                    flag: null_mut(),
                    val: b'A' as c_int,
                },
                SENTINEL,
            ];
            let mut idx: c_int = -1;
            let mut av = Argv::new(&["prog", "--alph"]);
            assert_eq!(
                av.long(c"", lo.as_ptr(), addr_of_mut!(idx), false),
                b'?' as c_int
            );
            assert_eq!(addr_of!(optind).read(), 2);
            reset();
            addr_of_mut!(opterr).write(0);
            let mut av = Argv::new(&["prog", "--nope"]);
            assert_eq!(
                av.long(c"", lo.as_ptr(), addr_of_mut!(idx), false),
                b'?' as c_int
            );
        }
    }

    #[test]
    fn long_flag_store_and_index() {
        let _g = test_lock();
        unsafe {
            reset();
            static mut FLAG: c_int = 0;
            let lo = [
                option {
                    name: c"gamma".as_ptr(),
                    has_arg: no_argument,
                    flag: addr_of_mut!(FLAG),
                    val: 99,
                },
                SENTINEL,
            ];
            let mut idx: c_int = -1;
            let mut av = Argv::new(&["prog", "--gamma"]);
            assert_eq!(av.long(c"", lo.as_ptr(), addr_of_mut!(idx), false), 0);
            assert_eq!(addr_of!(FLAG).read(), 99);
            assert_eq!(idx, 0);
        }
    }

    #[test]
    fn long_missing_arg_and_arg_rejected() {
        let _g = test_lock();
        unsafe {
            reset();
            addr_of_mut!(opterr).write(0);
            let lo = [
                option {
                    name: c"alpha".as_ptr(),
                    has_arg: no_argument,
                    flag: null_mut(),
                    val: b'a' as c_int,
                },
                option {
                    name: c"beta".as_ptr(),
                    has_arg: required_argument,
                    flag: null_mut(),
                    val: b'b' as c_int,
                },
                SENTINEL,
            ];
            let mut idx: c_int = -1;
            // Missing required arg: '?' (or ':' with leading-colon optstring).
            let mut av = Argv::new(&["prog", "--beta"]);
            assert_eq!(
                av.long(c"", lo.as_ptr(), addr_of_mut!(idx), false),
                b'?' as c_int
            );
            assert_eq!(addr_of!(optopt).read(), b'b' as c_int);
            reset();
            addr_of_mut!(opterr).write(0);
            let mut av = Argv::new(&["prog", "--beta"]);
            assert_eq!(
                av.long(c":", lo.as_ptr(), addr_of_mut!(idx), false),
                b':' as c_int
            );
            // Argument given to a no-arg option.
            reset();
            addr_of_mut!(opterr).write(0);
            let mut av = Argv::new(&["prog", "--alpha=x"]);
            assert_eq!(
                av.long(c"", lo.as_ptr(), addr_of_mut!(idx), false),
                b'?' as c_int
            );
            assert_eq!(addr_of!(optopt).read(), b'a' as c_int);
        }
    }

    #[test]
    fn long_only_single_dash_and_short_fallback() {
        let _g = test_lock();
        unsafe {
            reset();
            addr_of_mut!(opterr).write(0);
            let lo = [
                option {
                    name: c"alpha".as_ptr(),
                    has_arg: no_argument,
                    flag: null_mut(),
                    val: b'a' as c_int,
                },
                SENTINEL,
            ];
            let mut idx: c_int = -1;
            // Single-dash long match (exact and abbreviated).
            let mut av = Argv::new(&["prog", "-alpha"]);
            assert_eq!(
                av.long(c"", lo.as_ptr(), addr_of_mut!(idx), true),
                b'a' as c_int
            );
            reset();
            addr_of_mut!(opterr).write(0);
            let mut av = Argv::new(&["prog", "-alp"]);
            assert_eq!(
                av.long(c"", lo.as_ptr(), addr_of_mut!(idx), true),
                b'a' as c_int
            );
            // No long match: falls back to short options.
            reset();
            addr_of_mut!(opterr).write(0);
            let mut av = Argv::new(&["prog", "-b", "x"]);
            assert_eq!(
                av.long(c"b:", lo.as_ptr(), addr_of_mut!(idx), true),
                b'b' as c_int
            );
            assert!(cstr_eq(addr_of!(optarg).read(), b"x"));
        }
    }

    #[test]
    fn long_only_prefers_short_when_long_matches_optstring() {
        let _g = test_lock();
        unsafe {
            reset();
            static mut FLAG: c_int = 0;
            let lo = [
                option {
                    name: c"alpha".as_ptr(),
                    has_arg: no_argument,
                    flag: addr_of_mut!(FLAG),
                    val: 99,
                },
                SENTINEL,
            ];
            // "-a" matches long "alpha" exactly, but is also a prefix of
            // optstring "a": musl routes it to short getopt instead.
            let mut idx: c_int = -1;
            let mut av = Argv::new(&["prog", "-a"]);
            assert_eq!(
                av.long(c"a", lo.as_ptr(), addr_of_mut!(idx), true),
                b'a' as c_int
            );
            assert_eq!(addr_of!(FLAG).read(), 0);
        }
    }

    #[test]
    fn permutation_moves_nonoptions_after_options() {
        let _g = test_lock();
        unsafe {
            reset();
            addr_of_mut!(opterr).write(0);
            let mut av = Argv::new(&["prog", "file.txt", "-a"]);
            let o = c"a";
            assert_eq!(av.long(o, null(), null_mut(), false), b'a' as c_int);
            assert_eq!(av.long(o, null(), null_mut(), false), -1);
            assert_eq!(addr_of!(optind).read(), 2);
            // argv itself was permuted: option first.
            assert!(cstr_eq(av.ptr[1], b"-a"));
            assert!(cstr_eq(av.ptr[2], b"file.txt"));
        }
    }

    #[test]
    fn optreset_restarts_scan() {
        let _g = test_lock();
        unsafe {
            reset();
            addr_of_mut!(opterr).write(0);
            let mut av = Argv::new(&["prog", "-a", "-b"]);
            let o = c"ab";
            assert_eq!(av.short(o), b'a' as c_int);
            addr_of_mut!(__optreset).write(1);
            assert_eq!(av.short(o), b'a' as c_int);
            assert_eq!(av.short(o), b'b' as c_int);
            assert_eq!(av.short(o), -1);
        }
    }

    // ---- fd-2 capture for the addr_of!(opterr).read() gate -------------------------------

    const SYS_READ: usize = 0;
    const SYS_CLOSE: usize = 3;
    const SYS_PIPE: usize = 22;
    const SYS_DUP: usize = 32;
    const SYS_DUP2: usize = 33;

    /// Redirects fd 2 into a pipe; `finish` restores fd 2 and returns
    /// what was written. `Drop` restores without reading (panic-safe).
    struct StderrCap {
        saved: c_int,
        rd: c_int,
        wr: c_int,
        live: bool,
    }
    impl StderrCap {
        unsafe fn take() -> Self {
            unsafe {
                let mut fds = [0 as c_int; 2];
                let r = crate::syscall::syscall3(SYS_PIPE, fds.as_mut_ptr() as usize, 0, 0);
                assert_eq!(r, 0, "pipe failed");
                let saved = crate::syscall::syscall1(SYS_DUP, 2) as c_int;
                assert!(saved >= 0, "dup failed");
                let d = crate::syscall::syscall3(SYS_DUP2, fds[1] as usize, 2, 0);
                assert_eq!(d, 2, "dup2 failed");
                Self {
                    saved,
                    rd: fds[0],
                    wr: fds[1],
                    live: true,
                }
            }
        }
        unsafe fn restore(&mut self) -> std::vec::Vec<u8> {
            unsafe {
                let mut out = std::vec::Vec::new();
                if !self.live {
                    return out;
                }
                self.live = false;
                crate::syscall::syscall3(SYS_DUP2, self.saved as usize, 2, 0);
                crate::syscall::syscall1(SYS_CLOSE, self.saved as usize);
                crate::syscall::syscall1(SYS_CLOSE, self.wr as usize);
                let mut buf = [0u8; 512];
                loop {
                    let n = crate::syscall::syscall3(
                        SYS_READ,
                        self.rd as usize,
                        buf.as_mut_ptr() as usize,
                        buf.len(),
                    );
                    if n <= 0 {
                        break;
                    }
                    out.extend_from_slice(&buf[..n as usize]);
                }
                crate::syscall::syscall1(SYS_CLOSE, self.rd as usize);
                out
            }
        }
        unsafe fn finish(mut self) -> std::vec::Vec<u8> {
            unsafe {
                let out = self.restore();
                core::mem::forget(self);
                out
            }
        }
    }
    impl Drop for StderrCap {
        fn drop(&mut self) {
            if self.live {
                unsafe {
                    crate::syscall::syscall3(SYS_DUP2, self.saved as usize, 2, 0);
                    crate::syscall::syscall1(SYS_CLOSE, self.saved as usize);
                    crate::syscall::syscall1(SYS_CLOSE, self.wr as usize);
                    crate::syscall::syscall1(SYS_CLOSE, self.rd as usize);
                }
                self.live = false;
            }
        }
    }

    #[test]
    fn opterr_gate_silence_and_noise() {
        let _g = test_lock();
        unsafe {
            // addr_of!(opterr).read()=1: exact musl bytes `prog: unrecognized option: z\n`.
            reset();
            let mut av = Argv::new(&["prog", "-z"]);
            let cap = StderrCap::take();
            let r = av.short(c"ab:");
            let out = cap.finish();
            assert_eq!(r, b'?' as c_int);
            assert_eq!(out.as_slice(), b"prog: unrecognized option: z\n");
            // addr_of!(opterr).read()=0: silent.
            reset();
            addr_of_mut!(opterr).write(0);
            let mut av = Argv::new(&["prog", "-z"]);
            let cap = StderrCap::take();
            let r = av.short(c"ab:");
            let out = cap.finish();
            assert_eq!(r, b'?' as c_int);
            assert!(out.is_empty(), "addr_of!(opterr).read()=0 wrote {out:?}");
            // Leading ':' also suppresses the unknown-option message.
            reset();
            let mut av = Argv::new(&["prog", "-z"]);
            let cap = StderrCap::take();
            let r = av.short(c":ab:");
            let out = cap.finish();
            assert_eq!(r, b'?' as c_int);
            assert!(out.is_empty(), "leading ':' wrote {out:?}");
            assert!(has(b"a: unrecognized option: b", b"unrecognized option"));
        }
    }
}
