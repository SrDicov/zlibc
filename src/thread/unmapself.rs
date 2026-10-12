//! `__unmapself`: unmap the current stack, then exit (x86_64).
//!
//! Clean-room mirror of musl `src/thread/x86_64/__unmapself.s:5-10`:
//! `munmap` (11) of the caller's own stack mapping, then `exit` (60)
//! with status 0. Naked: no prologue may touch the stack being unmapped,
//! and none is needed — the args arrive in `rdi`/`rsi` (SysV), which is
//! already the kernel's argument order, so the body is two traps plus a
//! `ud2` fallback that can never execute. Used on detached-thread
//! death (see `thread_exit`).
//!
//! # Safety
//!
//! `base`/`size` must exactly cover the calling thread's live stack
//! mapping (nothing else the thread will touch, including the TCB).
//! Never returns; the mapping (and this frame) is gone after the first
//! trap. The caller must be unreachable-after-call by construction.
//! (Params are underscore-prefixed: the naked body takes them straight
//! from `rdi`/`rsi`, so Rust never names them.)
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
pub unsafe extern "C" fn __unmapself(_base: *mut u8, _size: usize) {
    core::arch::naked_asm!(
        "mov eax, 11",
        "syscall",
        "xor edi, edi",
        "mov eax, 60",
        "syscall",
        "ud2",
    )
}
