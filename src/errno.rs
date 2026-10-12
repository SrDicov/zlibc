//! Process-global `errno` cell and `__errno_location`.
//!
//! Mirrors musl `src/errno/__errno_location.c` (`int *__errno_location`,
//! plus the `weak_alias(__errno_location, ___errno_location)` which lives
//! in `crate::symbols`).
//!
//! shortcut(single-threaded errno): musl reads the cell through the
//! thread pointer, giving each thread its own `errno`. With no threads
//! and no TP yet, one process-global cell is observationally identical.
//! Upgrade to true TLS in Wave 3 when the TP exists (stable
//! `#[thread_local]` is unavailable: rustc E0658).
//!
//! # Safety
//!
//! The cell has no synchronization; like musl's contract, each thread
//! must use only its own cell once threads exist.

use core::cell::UnsafeCell;
use core::ffi::c_int;

struct ErrnoCell(UnsafeCell<c_int>);

/// `Sync` for the cell. Sound only while single-threaded (see module
/// docs); Wave 3 deletes this with the TLS upgrade.
// SAFETY: no thread exists yet that could race on the cell.
unsafe impl Sync for ErrnoCell {}

static ERRNO: ErrnoCell = ErrnoCell(UnsafeCell::new(0));

/// Pointer to the `errno` cell.
///
/// # Safety
///
/// The pointer is valid for the program's lifetime. Until Wave 3 lands
/// thread-local storage, all threads share this one cell.
#[no_mangle]
pub unsafe extern "C" fn __errno_location() -> *mut c_int {
    ERRNO.0.get()
}

// NOTE: musl defines `___errno_location` as a WEAK alias of
// `__errno_location` (src/errno/__errno_location.c:9), but a `.set` to an
// externally-defined target leaves no linkable weak record with this
// toolchain's assembler (proven by link failure in CI), so the alias is
// a plain forwarding definition instead. Observable contract is
// identical today (one shared cell); revisit when real linking lands.
//
// # Safety
//
// Same contract as [`__errno_location`].
#[no_mangle]
pub unsafe extern "C" fn ___errno_location() -> *mut c_int {
    unsafe { __errno_location() }
}
