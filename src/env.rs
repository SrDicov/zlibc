//! Environment mutation (musl `src/env/setenv.c`, `unsetenv.c`,
//! `putenv.c`, `clearenv.c`).
//!
//! Clean-room mirrors: `__environ` is manipulated exactly like musl
//! manipulates `environ` (grow/replace/compact through
//! `crate::malloc`, trailing NULL kept; `setenv` overwrite flag;
//! `unsetenv` compacts; `putenv` takes ownership of the caller's
//! string; `clearenv` frees what we own and empties). `getenv` is NOT
//! here — it already exists in `crate::start`; redefining it would be
//! a duplicate symbol.
//!
//! `__environ` is declared `extern` and resolved at link time: the
//! production staticlib provides `crate::start::__environ`, while
//! under `cargo test` (where `start.rs` gates it out) it binds the
//! host libc's `__environ`, so the same machine code is exercised
//! against the real process environment. No `weak_alias!` is needed:
//! musl's `__env_rm_add` dummy aliases exist only for partial linking,
//! and this module always ships the tracker with its users.
//!
//! `ENV_ALLOCED`/`ENV_ALLOCED_N` (musl `__env_rm_add`'s
//! function-statics) record exactly the strings this module installed,
//! so replacement/removal frees only what we own — never a
//! kernel/host-provided original. The zero-init statics below are
//! plain `.bss`, which is fine: the COMMON rule only constrains
//! `weak_alias!` targets, and none is aliased here.

use core::ffi::{c_char, c_int, c_void};
use core::ptr::{addr_of_mut, null_mut};

use crate::errno::{__errno_location, errno_store};
use crate::malloc::{free, malloc, realloc};
use crate::mem::memcpy;
use crate::string::{strchrnul, strncmp};

/// musl `arch/generic/bits/errno.h:22`.
#[cfg(target_arch = "x86_64")]
const EINVAL: c_int = 22;

extern "C" {
    static mut __environ: *mut *mut c_char;
}

/// musl `__env_rm_add`'s `static char **env_alloced` (setenv.c).
static mut ENV_ALLOCED: *mut *mut c_char = null_mut();
/// musl `__env_rm_add`'s `static size_t env_alloced_n` (setenv.c).
static mut ENV_ALLOCED_N: usize = 0;
/// musl `__putenv`'s `static char **oldenv` (putenv.c): last array we
/// installed, so a later call grows it with `realloc` instead of a
/// fresh copy.
static mut OLDENV: *mut *mut c_char = null_mut();

/// Current environment array (may be null after [`clearenv`]).
///
/// # Safety
///
/// Reads the linked `__environ` (ours in production, the host's under
/// test); the caller must treat the array as musl does.
unsafe fn environ_get() -> *mut *mut c_char {
    unsafe { addr_of_mut!(__environ).read() }
}

/// Install a new environment array.
///
/// # Safety
///
/// Same contract as [`environ_get`]; `p` must be null or point at a
/// null-terminated array that stays alive.
unsafe fn environ_set(p: *mut *mut c_char) {
    unsafe {
        addr_of_mut!(__environ).write(p);
    }
}

/// musl `__env_rm_add` (src/env/setenv.c): retire `old`, adopt `new`.
///
/// If `old` is tracked, its slot takes `new` and `old` is freed;
/// otherwise an empty slot adopts a non-null `new`, else `new` is
/// appended (realloc failure drops it silently, like musl). A null
/// `new` with untracked `old` is a no-op — untracked originals are
/// never freed.
///
/// # Safety
///
/// `old`/`new` must be null or valid strings with the ownership
/// discipline above.
unsafe fn env_rm_add(old: *mut c_char, mut new: *mut c_char) {
    unsafe {
        let base = addr_of_mut!(ENV_ALLOCED).read();
        let n = addr_of_mut!(ENV_ALLOCED_N).read();
        let mut i = 0usize;
        while i < n {
            let slot = base.add(i);
            if slot.read() == old {
                slot.write(new);
                free(old as *mut c_void);
                return;
            } else if slot.read().is_null() && !new.is_null() {
                slot.write(new);
                new = null_mut();
            }
            i = i.wrapping_add(1);
        }
        if new.is_null() {
            return;
        }
        let t = realloc(
            base as *mut c_void,
            n.wrapping_add(1).wrapping_mul(size_of::<*mut c_char>()),
        ) as *mut *mut c_char;
        if t.is_null() {
            return;
        }
        t.add(n).write(new);
        addr_of_mut!(ENV_ALLOCED).write(t);
        addr_of_mut!(ENV_ALLOCED_N).write(n.wrapping_add(1));
    }
}

/// First environ slot whose entry is `name[..l]` followed by `=`
/// (musl's inline scan in `getenv`/`__putenv`/`unsetenv`, factored
/// once); null when absent or the array is null.
///
/// # Safety
///
/// `envp` must be null or a null-terminated array of valid strings;
/// `name` must be readable for `l` bytes.
unsafe fn find_slot(envp: *mut *mut c_char, name: *const c_char, l: usize) -> *mut *mut c_char {
    unsafe {
        if envp.is_null() {
            return null_mut();
        }
        let mut e = envp;
        while !e.read().is_null() {
            let s = e.read();
            if strncmp(s, name, l) == 0 && *s.add(l) == b'=' as c_char {
                return e;
            }
            e = e.wrapping_add(1);
        }
        null_mut()
    }
}

/// musl `__putenv` (src/env/putenv.c), crate-private: install `s`
/// (`name` is `l` bytes); on a name hit the old entry is retired via
/// [`env_rm_add`] with `r`, else the array grows and a non-null `r` is
/// adopted for tracking. `setenv` passes its fresh copy as both `s`
/// and `r` (tracked, so a later replace frees it); `putenv` passes
/// null `r` (caller's string stays untracked, like musl).
///
/// # Safety
///
/// `s` must be a live `l`-byte name followed by `=value\0`; `r` null
/// or a live string to adopt.
unsafe fn __putenv(s: *mut c_char, l: usize, r: *mut c_char) -> c_int {
    unsafe {
        let envp = environ_get();
        let mut i = 0usize;
        if !envp.is_null() {
            let mut e = envp;
            while !e.read().is_null() {
                if strncmp(s, e.read(), l.wrapping_add(1)) == 0 {
                    let tmp = e.read();
                    e.write(s);
                    env_rm_add(tmp, r);
                    return 0;
                }
                e = e.wrapping_add(1);
                i = i.wrapping_add(1);
            }
        }
        let oldenv = addr_of_mut!(OLDENV).read();
        let newenv: *mut *mut c_char;
        if envp == oldenv {
            newenv = realloc(
                oldenv as *mut c_void,
                i.wrapping_add(2).wrapping_mul(size_of::<*mut c_char>()),
            ) as *mut *mut c_char;
            if newenv.is_null() {
                free(r as *mut c_void);
                return -1;
            }
        } else {
            newenv = malloc(i.wrapping_add(2).wrapping_mul(size_of::<*mut c_char>()))
                as *mut *mut c_char;
            if newenv.is_null() {
                free(r as *mut c_void);
                return -1;
            }
            if i != 0 {
                memcpy(
                    newenv as *mut c_void,
                    envp as *const c_void,
                    i.wrapping_mul(size_of::<*mut c_char>()),
                );
            }
            free(oldenv as *mut c_void);
        }
        newenv.add(i).write(s);
        newenv.add(i.wrapping_add(1)).write(null_mut());
        environ_set(newenv);
        addr_of_mut!(OLDENV).write(newenv);
        if !r.is_null() {
            env_rm_add(null_mut(), r);
        }
        0
    }
}

/// Set an environment variable (musl `setenv`).
///
/// `EINVAL` + `-1` on an empty name or a name containing `=`; with
/// `overwrite == 0` an existing value is kept (`0` returned).
///
/// # Safety
///
/// `var`/`value` must be valid NUL-terminated strings.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setenv(
    var: *const c_char,
    value: *const c_char,
    overwrite: c_int,
) -> c_int {
    unsafe {
        if var.is_null() {
            errno_store(__errno_location(), EINVAL);
            return -1;
        }
        let end = strchrnul(var, b'=' as c_int);
        let l1 = (end as usize).wrapping_sub(var as usize);
        if l1 == 0 || *var.add(l1) != 0 {
            errno_store(__errno_location(), EINVAL);
            return -1;
        }
        if overwrite == 0 && !find_slot(environ_get(), var, l1).is_null() {
            return 0;
        }
        let l2 = crate::mem::strlen(value);
        let s = malloc(l1.wrapping_add(l2).wrapping_add(2)) as *mut c_char;
        if s.is_null() {
            return -1;
        }
        memcpy(s as *mut c_void, var as *const c_void, l1);
        *s.add(l1) = b'=' as c_char;
        memcpy(
            s.add(l1.wrapping_add(1)) as *mut c_void,
            value as *const c_void,
            l2.wrapping_add(1),
        );
        __putenv(s, l1, s)
    }
}

/// Remove an environment variable (musl `unsetenv`).
///
/// `EINVAL` + `-1` on an empty name or a name containing `=`; removing
/// a missing name is `0`. Tracked strings are freed, originals are
/// only unlinked (see [`env_rm_add`]).
///
/// # Safety
///
/// `name` must be a valid NUL-terminated string.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn unsetenv(name: *const c_char) -> c_int {
    unsafe {
        let end = strchrnul(name, b'=' as c_int);
        let l = (end as usize).wrapping_sub(name as usize);
        if l == 0 || *name.add(l) != 0 {
            errno_store(__errno_location(), EINVAL);
            return -1;
        }
        let envp = environ_get();
        if !envp.is_null() {
            let mut e = envp;
            let mut eo = envp;
            while !e.read().is_null() {
                let s = e.read();
                if strncmp(name, s, l) == 0 && *s.add(l) == b'=' as c_char {
                    env_rm_add(s, null_mut());
                } else if eo != e {
                    eo.write(s);
                    eo = eo.wrapping_add(1);
                } else {
                    eo = eo.wrapping_add(1);
                }
                e = e.wrapping_add(1);
            }
            if eo != e {
                eo.write(null_mut());
            }
        }
        0
    }
}

/// Install a caller-owned `name=value` string (musl `putenv`): the
/// array aliases `s` itself — no copy, ownership taken like musl. A
/// string without `=` removes that name instead (`unsetenv` path).
///
/// # Safety
///
/// `s` must be a valid NUL-terminated string that stays alive until
/// replaced or unset; it must come from an allocator our [`free`]
/// serves only if it can also be freed that way — untracked putenv
/// strings are never freed by us, so any allocation works.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn putenv(s: *mut c_char) -> c_int {
    unsafe {
        let end = strchrnul(s, b'=' as c_int);
        let l = (end as usize).wrapping_sub(s as usize);
        if l == 0 || *s.add(l) == 0 {
            return unsetenv(s);
        }
        __putenv(s, l, null_mut())
    }
}

/// Drop every variable (musl `clearenv`): `__environ` goes null and
/// each entry is retired — tracked strings freed, originals only
/// unlinked. Always `0`.
///
/// # Safety
///
/// Destroys process-global state; after this, `environ` reads null
/// until the next `setenv`/`putenv` (musl contract verbatim).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn clearenv() -> c_int {
    unsafe {
        let e = environ_get();
        environ_set(null_mut());
        if !e.is_null() {
            let mut p = e;
            while !p.read().is_null() {
                let s = p.read();
                p = p.wrapping_add(1);
                env_rm_add(s, null_mut());
            }
        }
        0
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::{clearenv, putenv, setenv, unsetenv};
    use core::ffi::{c_char, c_void};

    use crate::errno::{__errno_location, errno_load};
    use crate::malloc::{free, malloc};
    use crate::mem::{memcpy, strlen};
    use std::string::ToString;

    // Host libc's getenv for observation only: zlibc defines no getenv
    // under `cargo test` (start.rs gates it out), so this binds glibc.
    extern "C" {
        fn getenv(name: *const c_char) -> *mut c_char;
    }

    fn var_cstr(tag: &str) -> std::ffi::CString {
        std::ffi::CString::new(std::format!("ZLIBC_9B2_{tag}_{}", std::process::id())).unwrap()
    }

    unsafe fn live(name: *const c_char) -> Option<std::string::String> {
        unsafe {
            let v = getenv(name);
            if v.is_null() {
                None
            } else {
                Some(std::ffi::CStr::from_ptr(v).to_str().unwrap().to_string())
            }
        }
    }

    #[test]
    fn setenv_overwrite_flags() {
        let _guard = crate::ldso::testlock::lock();
        let name = var_cstr("SETO");
        unsafe {
            assert_eq!(setenv(name.as_ptr(), c"one".as_ptr(), 1), 0);
            assert_eq!(live(name.as_ptr()), Some("one".into()));
            assert_eq!(setenv(name.as_ptr(), c"two".as_ptr(), 0), 0);
            assert_eq!(live(name.as_ptr()), Some("one".into()));
            assert_eq!(setenv(name.as_ptr(), c"two".as_ptr(), 1), 0);
            assert_eq!(live(name.as_ptr()), Some("two".into()));
            assert_eq!(unsetenv(name.as_ptr()), 0);
            assert_eq!(live(name.as_ptr()), None);
            assert_eq!(setenv(c"A=B".as_ptr(), c"v".as_ptr(), 1), -1);
            assert_eq!(errno_load(__errno_location()), super::EINVAL);
            assert_eq!(setenv(c"".as_ptr(), c"v".as_ptr(), 1), -1);
            assert_eq!(errno_load(__errno_location()), super::EINVAL);
        }
    }

    #[test]
    fn unsetenv_removes_exact_name() {
        let _guard = crate::ldso::testlock::lock();
        let pid = std::process::id();
        let short = std::ffi::CString::new(std::format!("ZLIBC_9B2_UN_{pid}")).unwrap();
        let long = std::ffi::CString::new(std::format!("ZLIBC_9B2_UN_{pid}_X")).unwrap();
        unsafe {
            assert_eq!(setenv(short.as_ptr(), c"1".as_ptr(), 1), 0);
            assert_eq!(setenv(long.as_ptr(), c"2".as_ptr(), 1), 0);
            // Prefix sharing must not over-match: only the exact name goes.
            assert_eq!(unsetenv(short.as_ptr()), 0);
            assert_eq!(live(short.as_ptr()), None);
            assert_eq!(live(long.as_ptr()), Some("2".into()));
            assert_eq!(unsetenv(long.as_ptr()), 0);
            assert_eq!(live(long.as_ptr()), None);
            // Missing names and bad names: 0 / EINVAL.
            assert_eq!(unsetenv(long.as_ptr()), 0);
            assert_eq!(unsetenv(c"BAD=NAME".as_ptr()), -1);
            assert_eq!(errno_load(__errno_location()), super::EINVAL);
        }
    }

    #[test]
    fn putenv_takes_ownership() {
        let _guard = crate::ldso::testlock::lock();
        let name = var_cstr("PUTO");
        let text = std::format!("{}=V1", name.to_str().unwrap());
        unsafe {
            // Caller-owned string via our own allocator (musl's contract).
            let s = malloc(text.len().wrapping_add(1)) as *mut c_char;
            assert!(!s.is_null());
            memcpy(s as *mut c_void, text.as_ptr() as *const c_void, text.len());
            *s.add(text.len()) = 0;
            assert_eq!(putenv(s), 0);
            // Ownership: the array aliases `s` itself — the value lives
            // at `s + namelen + 1`, not in a copy.
            let nl = strlen(name.as_ptr());
            assert_eq!(getenv(name.as_ptr()), s.add(nl.wrapping_add(1)));
            assert_eq!(live(name.as_ptr()), Some("V1".into()));
            // A string without `=` unsets instead (musl putenv.c).
            let bare = malloc(nl.wrapping_add(1)) as *mut c_char;
            assert!(!bare.is_null());
            memcpy(
                bare as *mut c_void,
                name.as_ptr() as *const c_void,
                nl.wrapping_add(1),
            );
            assert_eq!(putenv(bare), 0);
            assert_eq!(live(name.as_ptr()), None);
            // Both strings were untracked: freed by us, never by unsetenv.
            free(s as *mut c_void);
            free(bare as *mut c_void);
        }
    }

    #[test]
    fn clearenv_empties_then_restores() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            // Defensive: drop any suite leftovers so the snapshot holds
            // only pristine host strings (untracked, so clearenv frees
            // nothing and the restore below is sound).
            let pid = std::process::id();
            for tag in [
                std::format!("ZLIBC_9B2_SETO_{pid}"),
                std::format!("ZLIBC_9B2_UN_{pid}"),
                std::format!("ZLIBC_9B2_UN_{pid}_X"),
                std::format!("ZLIBC_9B2_PUTO_{pid}"),
            ] {
                let c = std::ffi::CString::new(tag).unwrap();
                assert_eq!(unsetenv(c.as_ptr()), 0);
            }
            let snap = super::environ_get();
            assert!(!snap.is_null());
            let mut n = 0usize;
            while !snap.add(n).read().is_null() {
                n = n.wrapping_add(1);
            }
            assert!(n > 0);
            assert_eq!(clearenv(), 0);
            assert!(super::environ_get().is_null());
            super::environ_set(snap);
            assert_eq!(super::environ_get(), snap);
            // Raw walk only: libc getenv's NULL-environ handling is not
            // our contract to test.
            let mut m = 0usize;
            while !snap.add(m).read().is_null() {
                m = m.wrapping_add(1);
            }
            assert_eq!(m, n);
        }
    }
}
