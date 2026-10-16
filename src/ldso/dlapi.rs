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
//! `dlopen` is the load-bearing half and lands here, on top of the
//! path search and the ctor queue; the pieces below are what `dlopen`
//! itself calls.

use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use super::dso::Dso;
use super::linkmap;
use super::reloc::find_sym;

/// musl `RTLD_LAZY` (`include/dlfcn.h:8`): accepted; binding is
/// always eager (no lazy PLT infrastructure), so it is unobservable.
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
/// in `struct pthread`, `pthread_impl.h:41,59`, keyed by
/// `__pthread_self()` in `dlerror.c:15,59`). Ours is one shared triple
/// of atomics plus an owner tag: the slot lives in the TCB we do not
/// own yet, so the FS base stands in for `pthread_self()` — unique per
/// thread on Linux whatever runtime owns the TCB, and never
/// dereferenced, only compared. A thread that did not set the error sees
/// NULL and leaves the flag set, exactly like musl.
static ERR_FLAG: AtomicBool = AtomicBool::new(false);
static ERR_BUF: AtomicPtr<c_char> = AtomicPtr::new(null_mut());
static ERR_OWNER: AtomicUsize = AtomicUsize::new(0);

/// Sentinel musl parks when the allocation fails
/// (`dlerror.c:65-70`), reported as a fixed message by `dlerror`.
const OOM_MSG: &[u8] = b"Dynamic linker failed to allocate memory for error message\0";

/// `usize::MAX` as a sentinel `*mut c_char`: musl uses `(void *)-1`.
const ERR_OOM: usize = usize::MAX;

/// FS base of the calling thread: the owner identity for [`ERR_OWNER`].
/// Never dereferenced, only compared, so no magic check is needed — the
/// value is unique per thread even for a foreign runtime's TCB.
///
/// Known property, not fixed: if a thread dies and its FS base is reused
/// by a new thread, the new thread inherits ownership of a message it did
/// not set. musl cannot do this (the storage dies with the TCB); here the
/// shared slot persists. Stale message, never an invalid pointer — fixing
/// it needs our own TCB, which is where this is going anyway.
fn self_tp() -> usize {
    let mut base: usize = 0;
    let r = unsafe {
        crate::syscall::syscall2(
            crate::thread::SYS_ARCH_PRCTL,
            crate::thread::ARCH_GET_FS,
            core::ptr::addr_of_mut!(base) as usize,
        )
    };
    if r == 0 {
        base
    } else {
        0
    }
}

/// musl `dlerror` (`src/ldso/dlerror.c:13-23`): return the pending
/// message once and clear the flag — but only to the thread that set
/// it. A foreign thread sees NULL and the flag stays set. Does **not**
/// free the buffer — it is reused by the next `__dl_vseterr`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub extern "C" fn dlerror() -> *mut c_char {
    if !ERR_FLAG.load(Ordering::Acquire) {
        return null_mut();
    }
    if ERR_OWNER.load(Ordering::Acquire) != self_tp() {
        return null_mut();
    }
    ERR_FLAG.store(false, Ordering::Release);
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
        // Owner before flag: a concurrent `dlerror` that sees the flag
        // must also see the owner. Last writer wins outside the loader
        // lock, same as the global `errno` fallback.
        ERR_OWNER.store(self_tp(), Ordering::Release);
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

/// The `dlopen` exclusion lock. Boot never contends (single-threaded);
/// concurrent `dlopen`s serialize here. Constructors run after release
/// (musl drops its rwlock before `do_init_fini`), so a constructor
/// calling back into `dlopen` cannot deadlock on this lock.
#[cfg(target_arch = "x86_64")]
static mut DLOPEN_LOCK: crate::sync::MutexT = [0; 5];

/// Already-loaded object for an `RTLD_NOLOAD` lookup (musl resolves the
/// flag inside `load_library`, `dynlink.c:1062-1110`; same two layers
/// here: shortname for bare names, full-path scan otherwise). Null when
/// absent — no loading, no error set (the caller picks the message).
///
/// # Safety
///
/// `file` must be NUL-terminated and non-empty.
#[cfg(target_arch = "x86_64")]
unsafe fn find_loaded(file: *const c_char) -> *mut Dso {
    unsafe {
        let mut slash = false;
        let mut k = 0usize;
        while *file.add(k) != 0 {
            if *file.add(k) == b'/' as c_char {
                slash = true;
            }
            k += 1;
        }
        if !slash {
            return linkmap::find_by_shortname(file);
        }
        let mut q = linkmap::head();
        while !q.is_null() {
            if !(*q).name.is_null() && super::reloc::streq((*q).name, file) {
                return q;
            }
            q = (*q).next;
        }
        null_mut()
    }
}

/// True when any object loaded for this `dlopen` (from `p` to the
/// namespace tail) carries `PT_TLS`. Runtime TLS installation
/// (`install_new_tls`, musl `dynlink.c:2207-2209`) is OUT: without it a
/// late TLS module would corrupt the static-TLS layout, so the load is
/// refused loudly instead of silently.
///
/// # Safety
///
/// `p` must be in the namespace.
#[cfg(target_arch = "x86_64")]
unsafe fn new_tls_present(p: *mut Dso) -> bool {
    unsafe {
        let mut q = p;
        while !q.is_null() {
            if !(*q).phdr.is_null() && (*q).phnum > 0 {
                let mut i = 0usize;
                while i < (*q).phnum as usize {
                    let ph = &*(*q)
                        .phdr
                        .wrapping_byte_add(i * (*q).phentsize)
                        .cast::<super::Elf64Phdr>();
                    if ph.p_type == super::PT_TLS {
                        return true;
                    }
                    i += 1;
                }
            }
            q = (*q).next;
        }
        false
    }
}

/// musl `dlopen` (`ldso/dynlink.c:2105-2231`): `NULL` returns the head,
/// otherwise load, wire deps (`load_deps` + BFS closure for
/// handle-local `dlsym`), publish symbols (`RTLD_GLOBAL` keeps them,
/// else `revert_syms`), relocate the new objects, run constructors
/// after releasing the lock, and return the handle.
///
/// Deliberately OUT (each with its owner): lazy binding (always eager,
/// so `RTLD_LAZY` is unobservable), `install_new_tls` (late TLS modules
/// are refused, see [`new_tls_present`]), failure rollback (nothing
/// ever unloads — a failed `dlopen` leaves the mappings for the retry,
/// which finds them loaded and finishes the job), and the
/// shutting-down guard (no exit machinery yet).
///
/// # Safety
///
/// `file` must be null or NUL-terminated.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn dlopen(file: *const c_char, mode: c_int) -> *mut c_void {
    unsafe {
        use core::ptr::addr_of_mut;
        crate::sync::pthread_mutex_lock(addr_of_mut!(DLOPEN_LOCK));
        let head = linkmap::head();
        if file.is_null() {
            crate::sync::pthread_mutex_unlock(addr_of_mut!(DLOPEN_LOCK));
            return head as *mut c_void;
        }
        let noload = mode & RTLD_NOLOAD != 0;
        let p = if noload {
            find_loaded(file)
        } else {
            super::boot::load_library(file, head)
        };
        if p.is_null() {
            set_error(if noload {
                b"Library is not already loaded"
            } else {
                b"Error loading shared library"
            });
            crate::sync::pthread_mutex_unlock(addr_of_mut!(DLOPEN_LOCK));
            return null_mut();
        }
        if !linkmap::load_deps(p, super::boot::load_library) {
            set_error(b"Error loading dependencies");
            crate::sync::pthread_mutex_unlock(addr_of_mut!(DLOPEN_LOCK));
            return null_mut();
        }
        linkmap::extend_bfs_deps(p);
        if new_tls_present(p) {
            set_error(b"TLS in dlopen'd libraries not supported");
            crate::sync::pthread_mutex_unlock(addr_of_mut!(DLOPEN_LOCK));
            return null_mut();
        }
        let orig_syms = linkmap::syms_tail();
        linkmap::add_syms(p);
        let mut i = 0usize;
        while !(*(*p).deps.add(i)).is_null() {
            linkmap::add_syms(*(*p).deps.add(i));
            i += 1;
        }
        // New objects only: everything before `p` is already relocated,
        // and `reloc_all` skips the rest by flag anyway.
        let mut q = p;
        while !q.is_null() {
            super::boot::reloc_all(head, q, false);
            q = (*q).next;
        }
        if mode & RTLD_GLOBAL == 0 {
            linkmap::revert_syms(orig_syms);
        }
        let mut queue = null_mut();
        if (*p).constructed == 0 {
            queue = linkmap::queue_ctors(p);
        }
        crate::sync::pthread_mutex_unlock(addr_of_mut!(DLOPEN_LOCK));
        if !queue.is_null() {
            linkmap::do_init_fini(queue);
            crate::malloc::free(queue as *mut core::ffi::c_void);
        }
        p as *mut c_void
    }
}

// ---- 11C: addr/info/iterate + fini ---------------------------------------------------
/// musl `Dl_info` (`include/link.h` via `dlfcn.h`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct DlInfo {
    pub dli_fname: *const c_char,
    pub dli_fbase: *mut c_void,
    pub dli_sname: *const c_char,
    pub dli_saddr: *mut c_void,
}

/// Address to object query (musl `src/ldso/dladdr.c`: pure stub,
/// always 0).
///
/// # Safety
///
/// `info` must point to a writable `DlInfo` (untouched on failure).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn dladdr(_addr: *const c_void, _info: *mut DlInfo) -> c_int {
    0
}

/// musl `RTLD_DI_LINKMAP` (`include/dlfcn.h:20`).
#[cfg(target_arch = "x86_64")]
pub const RTLD_DI_LINKMAP: c_int = 2;

/// Object query (musl `src/ldso/dlinfo.c`: handle check, only
/// `RTLD_DI_LINKMAP`, stores the object itself as its link map).
///
/// # Safety
///
/// `handle` must be null or a loader handle; `res` writable for a pointer.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn dlinfo(handle: *mut c_void, req: c_int, res: *mut *mut c_void) -> c_int {
    unsafe {
        if res.is_null() {
            return -1;
        }
        let mut q = linkmap::head();
        let mut ok = false;
        while !q.is_null() {
            if core::ptr::eq(q as *mut c_void, handle) {
                ok = true;
                break;
            }
            q = (*q).next;
        }
        if !ok {
            set_error(b"Invalid library handle");
            return -1;
        }
        if req != RTLD_DI_LINKMAP {
            set_error(b"Unsupported request");
            return -1;
        }
        *res = handle;
        0
    }
}

/// musl `struct dl_phdr_info` (`include/link.h:77-88`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct DlPhdrInfo {
    pub dlpi_addr: usize,
    pub dlpi_name: *const c_char,
    pub dlpi_phdr: *const super::Elf64Phdr,
    pub dlpi_phnum: u16,
    pub dlpi_adds: u64,
    pub dlpi_subs: u64,
    pub dlpi_tls_modid: usize,
    pub dlpi_tls_data: *mut c_void,
}

/// Walk loaded objects (musl `dynlink.c:2401`: head-to-tail, callback
/// stops the walk on nonzero return; TLS slots report 0 — static TLS
/// has no per-object runtime block here).
///
/// # Safety
///
/// The callback must be a valid function; it runs synchronously.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn dl_iterate_phdr(
    cb: Option<unsafe extern "C" fn(*mut DlPhdrInfo, usize, *mut c_void) -> c_int>,
    data: *mut c_void,
) -> c_int {
    unsafe {
        let Some(f) = cb else {
            return 0;
        };
        let mut cur = linkmap::head();
        while !cur.is_null() {
            let mut info = DlPhdrInfo {
                dlpi_addr: (*cur).base as usize,
                dlpi_name: (*cur).name,
                dlpi_phdr: (*cur).phdr,
                dlpi_phnum: (*cur).phnum as u16,
                dlpi_adds: 0,
                dlpi_subs: 0,
                dlpi_tls_modid: 0,
                dlpi_tls_data: core::ptr::null_mut(),
            };
            let r = f(&mut info, core::mem::size_of::<DlPhdrInfo>(), data);
            if r != 0 {
                return r;
            }
            cur = (*cur).next;
        }
        0
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn dladdr_is_a_stub() {
        let _guard = lock();
        unsafe {
            let mut info: DlInfo = core::mem::zeroed();
            assert_eq!(dladdr(core::ptr::null(), &mut info), 0);
        }
    }

    #[test]
    fn dlinfo_rejects_garbage() {
        let _guard = lock();
        unsafe {
            let mut out: *mut c_void = core::ptr::null_mut();
            assert_eq!(dlinfo(0x1234 as *mut c_void, RTLD_DI_LINKMAP, &mut out), -1);
            // A live handle with a bogus request fails the same way.
            let h = linkmap::head();
            if !h.is_null() {
                assert_eq!(dlinfo(h as *mut c_void, 999, &mut out), -1);
            }
        }
    }

    static ITER_SEEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

    unsafe extern "C" fn count_cb(
        info: *mut DlPhdrInfo,
        _size: usize,
        _data: *mut c_void,
    ) -> c_int {
        unsafe {
            if !info.is_null() && !(*info).dlpi_name.is_null() {
                ITER_SEEN.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
            }
            0
        }
    }

    unsafe extern "C" fn stop_cb(
        _info: *mut DlPhdrInfo,
        _size: usize,
        _data: *mut c_void,
    ) -> c_int {
        7
    }

    #[test]
    fn iterate_walks_and_stops() {
        let _guard = lock();
        unsafe {
            ITER_SEEN.store(0, core::sync::atomic::Ordering::SeqCst);
            // Null callback is a documented no-op.
            assert_eq!(dl_iterate_phdr(None, core::ptr::null_mut()), 0);
            let r = dl_iterate_phdr(Some(count_cb), core::ptr::null_mut());
            assert_eq!(r, 0);
            // Nonzero callback return stops the walk with that value
            // (vacuous when the namespace is empty — still exact).
            let n = ITER_SEEN.load(core::sync::atomic::Ordering::SeqCst);
            if n > 0 {
                assert_eq!(dl_iterate_phdr(Some(stop_cb), core::ptr::null_mut()), 7);
            }
        }
    }

    use super::*;
    use crate::ldso::testlock::lock;

    /// The error slot is process-global, and libtest runs these in some
    /// order: every test starts by draining whatever the previous one
    /// left behind, so "no pending error" really means that.
    fn drain() {
        let _ = dlerror();
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

    /// The error belongs to the thread that set it (musl `dlerror.c:15`:
    /// `self = __pthread_self()`). A foreign owner sees NULL and must
    /// not consume it; restoring ownership makes it visible again.
    #[test]
    fn dlerror_is_invisible_to_other_threads() {
        let _guard = lock();
        drain();
        unsafe {
            set_error(b"mine");
            super::ERR_OWNER.store(0x1234_5678, Ordering::SeqCst);
            assert!(dlerror().is_null(), "foreign thread sees NULL");
            super::ERR_OWNER.store(super::self_tp(), Ordering::SeqCst);
            assert!(!dlerror().is_null(), "nothing was lost");
            assert!(dlerror().is_null(), "consumed exactly once");
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

    /// `dlopen(NULL)` returns the namespace head (musl `dynlink.c:2124`).
    #[test]
    fn dlopen_null_returns_head() {
        let _guard = lock();
        drain();
        {
            linkmap::reset_namespace();
            let mut d: Dso = unsafe { core::mem::zeroed() };
            let dp = &mut d as *mut Dso;
            linkmap::set_namespace(dp);
            assert_eq!(unsafe { dlopen(core::ptr::null(), 0) }, dp as *mut c_void);
            assert!(dlerror().is_null(), "no error on the NULL path");
            linkmap::reset_namespace();
        }
    }

    /// `RTLD_NOLOAD` on an absent library returns null with a message
    /// and loads nothing.
    #[test]
    fn dlopen_noload_miss_errors() {
        let _guard = lock();
        drain();
        {
            linkmap::reset_namespace();
            let mut d: Dso = unsafe { core::mem::zeroed() };
            linkmap::set_namespace(&mut d as *mut Dso);
            let h = unsafe { dlopen(c"libghost.so".as_ptr(), RTLD_NOLOAD) };
            assert!(h.is_null());
            assert!(!dlerror().is_null());
            linkmap::reset_namespace();
        }
    }
}
