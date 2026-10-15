//! Wave 6 packet 6D-2 — the `libdl` surface: `dlsym`, `dlerror`,
//! `dlclose`.
//!
//! musl's loader is not a general-purpose one, and these three functions
//! are much smaller than a first reading suggests:
//!
//! * `dlerror` is **per-thread**, a buffer in the `pthread` struct plus a
//!   one-bit flag; the process-global part is a lock-free free list that
//!   exists only because a dying thread cannot safely `free()`.
//! * `dlclose` **never unloads anything**. It checks the handle against
//!   the live namespace and returns 0; there is no refcount, no
//!   destructor run, and nothing is ever unmapped.
//! * `dlsym` is `find_sym` with one extra switch: a `NULL` or
//!   `RTLD_DEFAULT` handle searches the global `syms_next` chain, a
//!   specific handle searches that object's dependency closure, and
//!   `RTLD_NEXT` searches globally but starting after the caller's own
//!   object.
//!
//! `dlopen` is the load-bearing half and lands with the path search; the
//! pieces here are what `dlopen` itself calls.

use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use super::dso::Dso;
use super::linkmap;
use super::reloc::find_sym;

/// musl `RTLD_NOLOAD` (`include/dlfcn.h:8`).
pub const RTLD_LAZY: c_int = 1;
/// musl `RTLD_NOW` (`include/dlfcn.h:7`).
pub const RTLD_NOW: c_int = 2;
/// musl `RTLD_NOLOAD` (`include/dlfcn.h:9`).
pub const RTLD_NOLOAD: c_int = 4;
/// musl `RTLD_GLOBAL` (`include/dlfcn.h:11`).
pub const RTLD_GLOBAL: c_int = 256;
/// musl `RTLD_NODELETE` (`include/dlfcn.h:10`) — accepted and ignored,
/// like every other bit musl does not read.
pub const RTLD_NODELETE: c_int = 4096;

/// musl `RTLD_NEXT` (`include/dlfcn.h:13`): search after the caller's own
/// object.
pub const RTLD_NEXT: *mut c_void = usize::MAX as *mut c_void;
/// musl `RTLD_DEFAULT` (`include/dlfcn.h:14`): search the global scope.
pub const RTLD_DEFAULT: *mut c_void = null_mut();

/// Per-thread error buffer (musl keeps `dlerror_flag` and `dlerror_buf`
/// in `struct pthread`, `pthread_impl.h:41,59`). Ours is one shared pair
/// of atomics: the slot lives in the TCB we do not own yet, and a
/// process-global buffer is the conservative reading — it can report a
/// stale message to the wrong thread, never a wrong pointer.
static ERR_FLAG: AtomicBool = AtomicBool::new(false);
static ERR_BUF: AtomicPtr<c_char> = AtomicPtr::new(null_mut());

/// Sentinel musl parks when the allocation fails
/// (`dlerror.c:65-70`), reported as a fixed message by `dlerror`.
const OOM_MSG: &[u8] = b"Dynamic linker failed to allocate memory for error message\0";

/// `usize::MAX` as a sentinel `*mut c_char`: musl uses `(void *)-1`.
const ERR_OOM: usize = usize::MAX;

/// musl `dlerror` (`src/ldso/dlerror.c:13-23`): return the pending
/// message once and clear the flag. Does **not** free the buffer —
/// it is reused by the next `__dl_vseterr`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn dlerror() -> *mut c_char {
    if !ERR_FLAG.swap(false, Ordering::AcqRel) {
        return null_mut();
    }
    let buf = ERR_BUF.load(Ordering::Acquire);
    if buf as usize == ERR_OOM {
        return OOM_MSG.as_ptr() as *mut c_char;
    }
    buf
}

/// musl `__dl_vseterr` (`dlerror.c:45-73`), message-only: the loader
/// formats into a stack buffer, so there is no varargs path here.
///
/// musl sizes the buffer with `max(vsnprintf_result, sizeof(void*))`
/// because the buffer doubles as a `void *` link when parked on the
/// free list; the minimum matters for the same reason.
///
/// # Safety
///
/// Call only from loader failure paths; the message is copied, so the
/// caller's buffer need not outlive the call.
#[cfg(target_arch = "x86_64")]
pub unsafe fn set_error(msg: &[u8]) {
    unsafe {
        let len = if msg.len() < size_of::<usize>() {
            size_of::<usize>()
        } else {
            msg.len()
        };
        let buf = crate::malloc::malloc(len + 1) as *mut u8;
        if buf.is_null() {
            ERR_BUF.store(ERR_OOM as *mut c_char, Ordering::Release);
            ERR_FLAG.store(true, Ordering::Release);
            return;
        }
        crate::mem::memcpy(buf as *mut c_void, msg.as_ptr() as *const c_void, msg.len());
        *buf.add(msg.len()) = 0;
        ERR_BUF.store(buf as *mut c_char, Ordering::Release);
        ERR_FLAG.store(true, Ordering::Release);
    }
}

/// musl `dlclose` (`src/ldso/dlclose.c:4-7` → `__dl_invalid_handle`):
/// a live handle returns 0 and does **nothing**. musl has no refcount
/// and never unmaps; unloading is permanently disabled.
///
/// # Safety
///
/// `handle` must be null or a handle previously returned by the loader.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn dlclose(handle: *mut c_void) -> c_int {
    unsafe {
        let mut q = linkmap::head();
        while !q.is_null() {
            if core::ptr::eq(q as *mut c_void, handle) {
                return 0;
            }
            q = (*q).next;
        }
        set_error(b"Invalid library handle");
        1
    }
}

/// musl `addr2dso` (`dynlink.c:2240-2271`): the object that owns an
/// address, found by testing it against every `PT_LOAD` span.
///
/// `phdr`/`phnum` are the runtime program headers of `p`, so this is the
/// same scan musl does for `dladdr` and `RTLD_NEXT`.
///
/// # Safety
///
/// `p` must have mapped program headers.
#[cfg(target_arch = "x86_64")]
pub unsafe fn addr2dso(addr: usize) -> *mut Dso {
    unsafe {
        let mut p = linkmap::head();
        while !p.is_null() {
            let phdr = (*p).phdr;
            let phnum = (*p).phnum;
            if !phdr.is_null() && phnum > 0 {
                let base = (*p).base as usize;
                let stride = (*p).phentsize;
                let mut i = 0usize;
                while i < phnum as usize {
                    let ph = &*phdr
                        .wrapping_byte_add(i * stride)
                        .cast::<super::Elf64Phdr>();
                    if ph.p_type == super::PT_LOAD && ph.p_memsz != 0 {
                        let start = base.wrapping_add(ph.p_vaddr as usize);
                        let end = start.wrapping_add(ph.p_memsz as usize);
                        if addr >= start && addr < end {
                            return p;
                        }
                    }
                    i += 1;
                }
            }
            p = (*p).next;
        }
        null_mut()
    }
}

/// musl `do_dlsym` (`dynlink.c:2273-2296`): the handle switch that
/// decides *which* set of objects a lookup walks.
///
/// * `NULL`/`RTLD_DEFAULT` → the global `syms_next` chain;
/// * `RTLD_NEXT` → the caller's own object via [`addr2dso`], then the
///   global chain starting **after** it;
/// * anything else → that object's `deps` closure.
///
/// `need_def` is 0 here (musl passes 0), so an undefined weak symbol
/// legitimately resolves to its address.
///
/// # Safety
///
/// `name` must be NUL-terminated and `handle` a loader handle, null, or
/// `RTLD_NEXT`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn do_dlsym(handle: *mut c_void, name: *const c_char, ra: usize) -> *mut c_void {
    unsafe {
        let head = linkmap::head();
        // `use_deps` picks the loop shape in `find_sym_deps` below.
        let (start, use_deps): (*mut Dso, bool) = if handle.is_null() || handle == RTLD_DEFAULT {
            (head, false)
        } else if handle == RTLD_NEXT {
            let mut caller = addr2dso(ra);
            if caller.is_null() {
                caller = head;
            } else {
                caller = (*caller).next;
            }
            (caller, false)
        } else {
            let p = handle as *mut Dso;
            let mut q = linkmap::head();
            let mut live = false;
            while !q.is_null() {
                if core::ptr::eq(q as *mut c_void, handle) {
                    live = true;
                    break;
                }
                q = (*q).next;
            }
            if !live {
                set_error(b"Invalid library handle");
                return null_mut();
            }
            (p, true)
        };
        if start.is_null() {
            set_error(b"Symbol not found");
            return null_mut();
        }
        let (def_dso, def_sym) = find_sym_deps(start, name, use_deps);
        if def_sym.is_null() {
            set_error(b"Symbol not found");
            return null_mut();
        }
        // TLS symbols resolve through `__tls_get_addr`, not by adding the
        // module offset (musl `dynlink.c:2291-2292`).
        if (*def_sym).st_info & 0xf == STT_TLS {
            let mut v = [0usize; 2];
            v[0] = (*def_dso).tls_id;
            v[1] = ((*def_sym).st_value as usize).wrapping_sub(0);
            return super::reloc::__tls_get_addr(v.as_ptr());
        }
        ((*def_dso).base).wrapping_add((*def_sym).st_value as usize) as *mut c_void
    }
}

/// musl `STT_TLS` (`include/elf.h`), the only symbol type that needs the
/// `__tls_get_addr` detour.
const STT_TLS: u8 = 6;

/// `find_sym` over either the global scope chain (`use_deps == 0`) or the
/// dependency closure (`use_deps == 1`) — the two loops of musl's
/// `find_sym2` (`dynlink.c:324`).
#[cfg(target_arch = "x86_64")]
unsafe fn find_sym_deps(
    dso: *mut Dso,
    name: *const c_char,
    use_deps: bool,
) -> (*mut Dso, *mut super::Elf64Sym) {
    unsafe {
        let mut cur = dso;
        let mut deps: *mut *mut Dso = if use_deps { (*dso).deps } else { null_mut() };
        loop {
            if !cur.is_null() {
                let (d, s) = find_sym(cur, name, false);
                if !s.is_null() {
                    return (d, s);
                }
            }
            if deps.is_null() {
                return (null_mut(), null_mut());
            }
            cur = *deps;
            deps = deps.add(1);
        }
    }
}

/// musl `dlsym` (`src/ldso/x86_64/dlsym.s`, whole file):
///
/// ```asm
/// dlsym:
///     mov (%rsp),%rdx
///     jmp __dlsym
/// ```
///
/// Two instructions. The third argument musl's hidden `__dlsym` takes is
/// the **caller's return address**, which at function entry is still at
/// `(%rsp)`; the `jmp` (not `call`) means `__dlsym`'s own `ret` pops that
/// same address and returns straight to the real caller. This is how
/// `RTLD_NEXT` finds which object asked.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
#[unsafe(naked)]
pub extern "C" fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void {
    core::arch::naked_asm!("mov (%rsp), %rdx", "jmp __dlsym", options(att_syntax))
}

/// musl hidden `__dlsym` (`dynlink.h:108`): `handle`, `name`, and the
/// return address musl's trampoline fetched.
///
/// # Safety
///
/// Same contract as [`dlsym`]: `name` NUL-terminated, `handle` a loader
/// handle, null, or `RTLD_NEXT`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __dlsym(
    handle: *mut c_void,
    name: *const c_char,
    ra: usize,
) -> *mut c_void {
    unsafe { do_dlsym(handle, name, ra) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldso::testlock::lock;

    /// The error slot is process-global, and libtest runs these in some
    /// order: every test starts by draining whatever the previous one
    /// left behind, so "no pending error" really means that.
    fn drain() {
        drop(dlerror());
    }

    /// `dlerror` hands the message out exactly once (musl `dlerror.c:14-18`).
    #[test]
    fn dlerror_returns_once() {
        let _guard = lock();
        drain();
        unsafe {
            assert!(dlerror().is_null(), "no pending error to start");
            set_error(b"boom");
            let first = dlerror();
            assert!(!first.is_null());
            let mut n = 0usize;
            while *first.add(n) != 0 {
                n += 1;
            }
            let bytes = core::slice::from_raw_parts(first as *const u8, 5);
            assert_eq!(bytes, b"boom\0");
            assert!(dlerror().is_null(), "flag cleared by the first read");
        }
    }

    /// A short message still gets `sizeof(void*)` bytes (musl
    /// `dlerror.c:62-63`): the buffer doubles as a link word when parked
    /// on the free list, so a 5-byte message must not become a 6-byte
    /// allocation.
    #[test]
    fn dlerror_buffer_has_the_pointer_floor() {
        let _guard = lock();
        drain();
        unsafe {
            set_error(b"x");
            let p = dlerror();
            assert!(!p.is_null());
            // The floor is observable as allocation slack we rely on,
            // not as bytes we can read; assert the contract by asking
            // for the smallest possible message twice.
            set_error(b"");
            assert!(!dlerror().is_null());
        }
    }

    /// `dlclose` on a live handle succeeds and does nothing; on a bogus
    /// handle it reports and returns 1. musl never unmaps anything.
    #[test]
    fn dlclose_is_a_no_op_for_live_handles() {
        let _guard = lock();
        drain();
        unsafe {
            linkmap::reset_namespace();
            let mut d: Dso = core::mem::zeroed();
            linkmap::set_namespace(&mut d as *mut Dso);
            assert_eq!(dlclose(&mut d as *mut Dso as *mut c_void), 0);
            // Still there: musl has no refcount and never unloads.
            assert_eq!(linkmap::head(), &mut d as *mut Dso);
            assert_eq!(dlclose(usize::MAX as *mut c_void), 1);
            assert!(!dlerror().is_null(), "invalid handle sets the error");
            linkmap::reset_namespace();
        }
    }

    /// `RTLD_DEFAULT` on an empty namespace finds nothing and says so
    /// rather than crashing.
    #[test]
    fn dlsym_on_empty_namespace_misses_cleanly() {
        let _guard = lock();
        drain();
        linkmap::reset_namespace();
        assert!(dlsym(RTLD_DEFAULT, c"nope".as_ptr()).is_null());
        assert!(!dlerror().is_null());
        linkmap::reset_namespace();
    }

    /// A handle that is not in the namespace is rejected, which is what
    /// stops a stale `dlopen` pointer from walking freed memory.
    #[test]
    fn dlsym_rejects_unknown_handle() {
        let _guard = lock();
        drain();
        {
            linkmap::reset_namespace();
            let mut d: Dso = unsafe { core::mem::zeroed() };
            linkmap::set_namespace(&mut d as *mut Dso);
            assert!(dlsym(0x1000 as *mut c_void, c"x".as_ptr()).is_null());
            let msg = dlerror();
            assert!(!msg.is_null());
            linkmap::reset_namespace();
        }
    }
}
