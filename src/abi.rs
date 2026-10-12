//! ABI-exact mirrors of musl's internal structures.
//!
//! Every type here is `#[repr(C)]` and field-for-field identical to the
//! musl source it mirrors. The build script (build.rs) measures the real
//! musl headers with gcc and lib.rs static-asserts each size/offset —
//! a mismatch fails the build, it can never silently drift.
//!
//! Currently x86_64 only. Other archs get their own `#[cfg]` blocks.

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};

/// musl: `struct _IO_FILE` (src/internal/stdio_impl.h).
///
/// C `volatile int lock` has no Rust qualifier equivalent: the field stays
/// `c_int` (same size/offset) and all accesses MUST go through
/// `core::ptr::read_volatile` / `write_volatile` at use sites.
/// `long lockcount` stays `c_long` (8 bytes on 64-bit) — do NOT shrink it
/// to `AtomicI32`, that would shift every field after it.
#[repr(C)]
pub struct IoFile {
    pub flags: c_uint,
    pub rpos: *mut u8,
    pub rend: *mut u8,
    pub close: Option<unsafe extern "C" fn(*mut IoFile) -> c_int>,
    pub wend: *mut u8,
    pub wpos: *mut u8,
    pub mustbezero_1: *mut u8,
    pub wbase: *mut u8,
    pub read: Option<unsafe extern "C" fn(*mut IoFile, *mut u8, usize) -> usize>,
    pub write: Option<unsafe extern "C" fn(*mut IoFile, *const u8, usize) -> usize>,
    pub seek: Option<unsafe extern "C" fn(*mut IoFile, c_long, c_int) -> c_long>,
    pub buf: *mut u8,
    pub buf_size: usize,
    pub prev: *mut IoFile,
    pub next: *mut IoFile,
    pub fd: c_int,
    pub pipe_pid: c_int,
    pub lockcount: c_long,
    pub mode: c_int,
    pub lock: c_int, // volatile in C — see note above
    pub lbf: c_int,
    pub cookie: *mut c_void,
    pub off: c_long,
    pub getln_buf: *mut c_char,
    pub mustbezero_2: *mut c_void,
    pub shend: *mut u8,
    pub shlim: c_long,
    pub shcnt: c_long,
    pub prev_locked: *mut IoFile,
    pub next_locked: *mut IoFile,
    pub locale: *mut c_void, // opaque struct __locale_struct
}

/// musl `struct pthread`, Part 1 ONLY (src/internal/pthread_impl.h).
///
/// Part 1 fields are ABI ("Do not change"); Part 2 (`tid`,
/// `detach_state`, `cancelbuf`, `robust_list`, …) is explicitly non-ABI
/// and stays free for us to reorganize; Part 3 is empty on x86_64
/// (no `TLS_ABOVE_TP`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct PthreadHead {
    pub this: *mut PthreadHead, // C name is `self`
    pub dtv: *mut usize,
    pub prev: *mut PthreadHead, // non-ABI link, kept for shape parity
    pub next: *mut PthreadHead, // non-ABI link, kept for shape parity
    pub sysinfo: usize,
    pub canary: usize,
}

/// musl `pthread_t` (include/alltypes.h.in).
///
/// The generic header spells it two ways: `unsigned long` for C++ TUs,
/// `struct __pthread *` for C TUs (`struct pthread` in
/// src/internal/pthread_impl.h, renamed by its own
/// `#define pthread __pthread`). No arch overrides it
/// (arch/x86_64/bits/alltypes.h.in has no `pthread_t`), so x86_64 C
/// code — including the probe — sees the pointer form. Both spellings
/// are 8 bytes on 64-bit, so this one alias is ABI-exact for both.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct PthreadOpaque {
    _opaque: [u8; 0],
}

/// musl `pthread_t` on x86_64: pointer to the opaque thread struct.
#[cfg(target_arch = "x86_64")]
pub type PthreadT = *mut PthreadOpaque;
