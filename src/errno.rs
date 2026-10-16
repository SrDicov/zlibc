//! Per-thread `errno` cell through the thread pointer, musl-style.
//!
//! Mirrors musl `src/errno/__errno_location.c` (`int *__errno_location`,
//! plus the `weak_alias(__errno_location, ___errno_location)` which lives
//! in `crate::symbols`): musl reads the cell through the thread pointer,
//! giving each thread its own `errno`.
//!
//! x86_64: `FS` is fetched with `arch_prctl(ARCH_GET_FS)` (one syscall,
//! error paths only — shortcut vs a raw `%fs` base read, which needs
//! `rdfsbase` and is not portable). When `FS` points at our [`Thread`]
//! (magic matches), its `errno_val` is served; otherwise the
//! process-global fallback is served, so foreign threads (host std under
//! `cargo test`, or pre-TLS boot) keep a working `errno`.
//!
//! [`Thread`]: crate::thread::Thread

use core::ffi::c_int;
use core::mem::offset_of;
use core::sync::atomic::{AtomicI32, Ordering};

/// Process-global fallback cell. An atomics cell (not a plain cell):
/// foreign threads share it, so every access must be atomic in the Rust
/// model; `Relaxed` compiles to the same plain `mov` musl emits, at zero
/// cost. Own threads never touch it (they own their cell).
static ERRNO: AtomicI32 = AtomicI32::new(0);

fn global_errno() -> *mut c_int {
    &ERRNO as *const AtomicI32 as *mut c_int
}

/// Store through an errno pointer with the shared-cell discipline:
/// `Relaxed` is exact on real hardware for both the atomic fallback and
/// the plain per-thread cells behind the same pointer type.
///
/// # Safety
///
/// `p` must come from [`__errno_location`].
pub(crate) unsafe fn errno_store(p: *mut c_int, v: c_int) {
    unsafe {
        (*p.cast::<AtomicI32>()).store(v, Ordering::Relaxed);
    }
}

/// Load through an errno pointer (same discipline as [`errno_store`]).
///
/// # Safety
///
/// `p` must come from [`__errno_location`].
pub(crate) unsafe fn errno_load(p: *mut c_int) -> c_int {
    unsafe { (*p.cast::<AtomicI32>()).load(Ordering::Relaxed) }
}

/// Pointer to the calling thread's `errno` cell.
///
/// # Safety
///
/// The pointer is valid for the program's lifetime. Own threads get
/// their private cell; foreign threads share the fallback. Reading 8
/// bytes at `FS + magic_offset` on a foreign thread touches mapped TCB
/// memory in practice (glibc/musl TCBs are kilobytes); a foreign runtime
/// with a sub-136-byte `FS` area would fault here — no user-space fault
/// barrier exists, so the residual is documented, not fixed. (A self-word
/// pre-check buys nothing: it faults on exactly the same mappings.) A
/// 2^-64 magic collision would merely alias one access, never corrupt
/// control state.
#[no_mangle]
pub unsafe extern "C" fn __errno_location() -> *mut c_int {
    #[cfg(target_arch = "x86_64")]
    {
        let mut base: usize = 0;
        let r = unsafe {
            crate::syscall::syscall2(
                crate::thread::SYS_ARCH_PRCTL,
                crate::thread::ARCH_GET_FS,
                core::ptr::addr_of_mut!(base) as usize,
            )
        };
        if r == 0 && base != 0 {
            let tp = base as *const u8;
            let magic = unsafe {
                tp.add(offset_of!(crate::thread::Thread, magic))
                    .cast::<u64>()
                    .read()
            };
            if magic == crate::thread::THREAD_MAGIC {
                return unsafe {
                    (base as *mut u8)
                        .add(offset_of!(crate::thread::Thread, errno_val))
                        .cast::<c_int>()
                };
            }
        }
        global_errno()
    }
    #[cfg(not(target_arch = "x86_64"))]
    global_errno()
}

// NOTE: musl defines `___errno_location` as a WEAK alias of
// `__errno_location` (src/errno/__errno_location.c:9), but a `.set` to an
// externally-defined target leaves no linkable weak record with this
// toolchain's assembler (proven by link failure in CI), so the alias is
// a plain forwarding definition instead. Observable contract is
// identical (per-thread cell with global fallback); revisit when real
// linking lands.
///
/// # Safety
///
/// Same contract as [`__errno_location`].
#[no_mangle]
pub unsafe extern "C" fn ___errno_location() -> *mut c_int {
    unsafe { __errno_location() }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_void;
    use core::ptr::null_mut;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use crate::abi::PthreadT;
    use crate::thread::create::{__pthread_create, __pthread_join};

    static CHILD_CELL: AtomicUsize = AtomicUsize::new(0);
    static CHILD_SAW: AtomicUsize = AtomicUsize::new(0);

    /// Child code: pure cell access only. Must not touch host TLS (its
    /// `FS` is our TCB) and must not assert (see `raw_clone` discipline).
    unsafe extern "C" fn errno_child(_arg: *mut c_void) -> *mut c_void {
        unsafe {
            let p = super::__errno_location();
            CHILD_CELL.store(p as usize, Ordering::SeqCst);
            super::errno_store(p, 7);
            CHILD_SAW.store(super::errno_load(p) as usize, Ordering::SeqCst);
        }
        null_mut()
    }

    /// Own threads get private cells; foreign (host) threads share the
    /// global fallback. The global-stability check lives in
    /// [`errno_global_cell_undisturbed_by_child`] (serial-only): it needs
    /// a quiescent fallback cell, which no parallel suite can promise.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn errno_is_per_thread_with_global_fallback() {
        // Pointer topology only here (no global writes asserted): green
        // under any parallelism.
        let mine = unsafe { super::__errno_location() };
        assert!(!mine.is_null());
        // A fresh host thread never ran our clone path: same global cell.
        let host_cell = std::thread::spawn(|| unsafe { super::__errno_location() } as usize)
            .join()
            .unwrap();
        assert_eq!(host_cell, mine as usize);
        // Our clone()d thread: a different cell, value contained.
        CHILD_CELL.store(0, Ordering::SeqCst);
        CHILD_SAW.store(0, Ordering::SeqCst);
        let mut td: PthreadT = null_mut();
        let rc = unsafe { __pthread_create(&mut td, null_mut(), Some(errno_child), null_mut()) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { __pthread_join(td, null_mut()) }, 0);
        assert_eq!(CHILD_SAW.load(Ordering::SeqCst), 7);
        assert_ne!(CHILD_CELL.load(Ordering::SeqCst), mine as usize);
    }

    /// The child must not disturb the global fallback cell. `#[ignore]`d
    /// by design: it asserts quiescence no parallel run can promise, so
    /// it runs only in CI's serial step (`-- --ignored`). musl's own
    /// suite is serial for the same reason.
    #[cfg(target_arch = "x86_64")]
    #[test]
    #[ignore]
    fn errno_global_cell_undisturbed_by_child() {
        let mine = unsafe { super::__errno_location() };
        unsafe {
            super::errno_store(mine, 0);
        }
        CHILD_CELL.store(0, Ordering::SeqCst);
        CHILD_SAW.store(0, Ordering::SeqCst);
        let mut td: PthreadT = null_mut();
        let rc = unsafe { __pthread_create(&mut td, null_mut(), Some(errno_child), null_mut()) };
        assert_eq!(rc, 0);
        assert_eq!(unsafe { __pthread_join(td, null_mut()) }, 0);
        assert_eq!(CHILD_SAW.load(Ordering::SeqCst), 7);
        assert_eq!(unsafe { super::errno_load(mine) }, 0);
    }
}
