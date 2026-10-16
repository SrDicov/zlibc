//! Non-local jumps (musl `src/setjmp/x86_64/setjmp.s`, `longjmp.s`,
//! `src/signal/x86_64/sigsetjmp.s`, `src/signal/sigsetjmp_tail.c`,
//! `src/signal/siglongjmp.c`, `include/setjmp.h:10-14`,
//! `arch/x86_64/bits/setjmp.h:1`).
//!
//! `setjmp`/`longjmp` are instruction ports of musl's x86_64 asm
//! (callee-saved regs + rsp/rip; `longjmp` maps 0 to 1); `sigsetjmp`
//! is musl's save-mask trampoline with `__sigsetjmp_tail` doing the raw
//! `rt_sigprocmask` save/restore, and `siglongjmp` just `longjmp`s (the
//! mask is restored in the returned-to context, per musl's comment in
//! `siglongjmp.c:8-11`). Calls into `setjmp` use direct `call`/`jmp`
//! (no `@PLT`: this crate links static).

use core::ffi::c_int;

use crate::syscall::syscall4;

// ---- Traps (musl arch/x86_64/bits/syscall.h.in) -----------------------------
#[cfg(target_arch = "x86_64")]
const SYS_RT_SIGPROCMASK: usize = 14;
#[cfg(target_arch = "x86_64")]
const SIG_SETMASK: usize = 2;
/// Kernel mask length (`_NSIG/8`, `sigsetjmp_tail.c:8`).
#[cfg(target_arch = "x86_64")]
const K_SIGSET_LEN: usize = 8;

// ---- Types (musl include/setjmp.h:10-14, arch/x86_64/bits/setjmp.h:1) --------
/// musl `__jmp_buf`: the 8 saved words (rbx, rbp, r12-r15, rsp, rip).
#[cfg(target_arch = "x86_64")]
pub type JmpBuf = [u64; 8];

/// musl `struct __jmp_buf_tag` (`jmp_buf`/`sigjmp_buf` are one-element
/// arrays of it): register area, `__fl` scratch, 128-byte mask store.
/// The kernel only reads the first 8 mask bytes (`_NSIG/8`); on x86_64
/// musl uses `__fl`/`__ss[1]` as spill slots in `sigsetjmp`, never as
/// a consulted flag, so this port does the same.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct SigJmpBuf {
    pub jb: JmpBuf,
    pub fl: u64,
    pub ss: [u64; 16],
}

#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<JmpBuf>() == 64);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<SigJmpBuf>() == 200);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(SigJmpBuf, fl) == 64);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(SigJmpBuf, ss) == 72);

// ---- Cores (musl src/setjmp/x86_64/setjmp.s:11-22, longjmp.s:8-18) -----------
// Naked so no prologue can shift rsp/rip out from under the capture
// (`#[inline]` is rejected on naked functions: they never inline, so
// the `ret`/`jmp` cannot leak into a caller).

/// Save context, return 0.
///
/// # Safety
///
/// `env` must point at 8 writable `u64`s that outlive every `longjmp`
/// using them; the caller must not `longjmp` after unwinding past the
/// `setjmp` frame. Returns twice: `longjmp` resumes the caller with
/// its value.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
#[unsafe(naked)]
pub unsafe extern "C" fn setjmp(env: *mut JmpBuf) -> c_int {
    core::arch::naked_asm!(
        "mov qword ptr [rdi], rbx",
        "mov qword ptr [rdi + 8], rbp",
        "mov qword ptr [rdi + 16], r12",
        "mov qword ptr [rdi + 24], r13",
        "mov qword ptr [rdi + 32], r14",
        "mov qword ptr [rdi + 40], r15",
        "lea rdx, [rsp + 8]",
        "mov qword ptr [rdi + 48], rdx",
        "mov rdx, qword ptr [rsp]",
        "mov qword ptr [rdi + 56], rdx",
        "xor eax, eax",
        "ret",
    )
}

/// Restore context; `val == 0` becomes 1.
///
/// # Safety
///
/// `env` must hold a buffer filled by [`setjmp`]/[`sigsetjmp`] whose
/// frame is still live. Never returns.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
#[unsafe(naked)]
pub unsafe extern "C" fn longjmp(env: *mut JmpBuf, val: c_int) -> ! {
    core::arch::naked_asm!(
        "xor eax, eax",
        "cmp esi, 1",
        "adc eax, esi",
        "mov rbx, qword ptr [rdi]",
        "mov rbp, qword ptr [rdi + 8]",
        "mov r12, qword ptr [rdi + 16]",
        "mov r13, qword ptr [rdi + 24]",
        "mov r14, qword ptr [rdi + 32]",
        "mov r15, qword ptr [rdi + 40]",
        "mov rsp, qword ptr [rdi + 48]",
        "jmp qword ptr [rdi + 56]",
    )
}

// musl defines these pairs on one shared asm label (`setjmp.s:8-10`,
// `longjmp.s:6-7`); the `.set` sits next to its target so alias and
// definition share an object (a re-exporting mod.rs lost symbols to
// CGU repartition before). Order is `(new, strong)`, inverse of musl's
// `weak_alias(old, new)`.
#[cfg(target_arch = "x86_64")]
crate::weak_alias!(_setjmp, setjmp);
#[cfg(target_arch = "x86_64")]
crate::weak_alias!(_longjmp, longjmp);

// ---- Signal variants (musl src/signal/x86_64/sigsetjmp.s:5-24) --------------

/// Save context plus, when `savemask != 0`, the signal mask.
///
/// # Safety
///
/// Same frame-liveness contract as [`setjmp`]; `env` must point at a
/// writable [`SigJmpBuf`]. Returns twice like [`setjmp`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
#[unsafe(naked)]
pub unsafe extern "C" fn sigsetjmp(env: *mut SigJmpBuf, savemask: c_int) -> c_int {
    core::arch::naked_asm!(
        "test esi, esi",
        "jz 1f",
        "pop qword ptr [rdi + 64]",
        "mov qword ptr [rdi + 80], rbx",
        "mov rbx, rdi",
        "call setjmp",
        "push qword ptr [rbx + 64]",
        "mov rdi, rbx",
        "mov esi, eax",
        "mov rbx, qword ptr [rbx + 80]",
        "jmp __sigsetjmp_tail",
        "1:",
        "jmp setjmp",
    )
}

// Hidden like musl's (`dynlink.h`): the version script would hide it
// anyway, but the directive documents the intent at the definition
// site. Lives next to its only asm caller (CGU rule).
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(".hidden __sigsetjmp_tail");

/// Save-or-restore half of [`sigsetjmp`] (musl
/// `src/signal/sigsetjmp_tail.c:5-10`): `ret == 0` (first return)
/// saves the mask into the buffer, otherwise restores it. Raw trap,
/// no errno touch, like musl's `__syscall`.
///
/// # Safety
///
/// `env` must point at a writable [`SigJmpBuf`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __sigsetjmp_tail(env: *mut SigJmpBuf, ret: c_int) -> c_int {
    unsafe {
        let p = core::ptr::addr_of_mut!((*env).ss) as usize;
        if ret == 0 {
            syscall4(SYS_RT_SIGPROCMASK, SIG_SETMASK, 0, p, K_SIGSET_LEN);
        } else {
            syscall4(SYS_RT_SIGPROCMASK, SIG_SETMASK, p, 0, K_SIGSET_LEN);
        }
        ret
    }
}

/// `longjmp` for a [`SigJmpBuf`] (musl `src/signal/siglongjmp.c:6-14`):
/// the mask is restored in the returned-to context (inside
/// `sigsetjmp`'s tail when `savemask` was nonzero), so this forwards.
///
/// # Safety
///
/// Same contract as [`longjmp`]. Never returns.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn siglongjmp(env: *mut SigJmpBuf, val: c_int) -> ! {
    unsafe { longjmp(core::ptr::addr_of_mut!((*env).jb), val) }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_int;
    use core::sync::atomic::{AtomicI32, Ordering};

    use super::*;

    /// `sigsetjmp(1)` roundtrip always blocks this RT signal (never
    /// raised, so nothing is ever delivered).
    const SIG_RT: u32 = 46;

    /// Read the current 8-byte kernel mask with a raw trap.
    ///
    /// # Safety
    ///
    /// `out` must be writable for 8 bytes.
    #[cfg(target_arch = "x86_64")]
    unsafe fn read_mask(out: *mut u64) -> isize {
        unsafe { syscall4(SYS_RT_SIGPROCMASK, 0, 0, out as usize, K_SIGSET_LEN) }
    }

    /// `setjmp` returns 0; `longjmp(0)` resumes with 1; other values
    /// pass through. The counter is atomic and every value crossing
    /// the jump goes through `black_box`, so release cannot fold the
    /// twice-returning call into a single-return latch.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn setjmp_longjmp_value_roundtrip() {
        static HITS: AtomicI32 = AtomicI32::new(0);
        unsafe {
            let mut env: JmpBuf = [0; 8];
            let envp = std::hint::black_box(&mut env as *mut JmpBuf);
            HITS.store(0, Ordering::SeqCst);
            let r = std::hint::black_box(setjmp(envp));
            HITS.fetch_add(1, Ordering::SeqCst);
            match std::hint::black_box(r) {
                0 => longjmp(std::hint::black_box(envp), std::hint::black_box(0)),
                1 => longjmp(std::hint::black_box(envp), std::hint::black_box(42)),
                42 => {}
                v => panic!("longjmp delivered {v}"),
            }
            assert_eq!(HITS.load(Ordering::SeqCst), 3);
        }
    }

    /// `_setjmp`/`_longjmp` are the same addresses as `setjmp`/`longjmp`
    /// (musl's shared asm labels, via `weak_alias!` in this file) and
    /// jump correctly.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn underscore_aliases_share_targets() {
        extern "C" {
            fn _setjmp(env: *mut JmpBuf) -> c_int;
            fn _longjmp(env: *mut JmpBuf, val: c_int) -> !;
        }
        assert_eq!(_setjmp as *const () as usize, setjmp as *const () as usize);
        assert_eq!(
            _longjmp as *const () as usize,
            longjmp as *const () as usize
        );
        static HITS: AtomicI32 = AtomicI32::new(0);
        unsafe {
            let mut env: JmpBuf = [0; 8];
            let envp = std::hint::black_box(&mut env as *mut JmpBuf);
            HITS.store(0, Ordering::SeqCst);
            let r = std::hint::black_box(_setjmp(envp));
            HITS.fetch_add(1, Ordering::SeqCst);
            if std::hint::black_box(r) == 0 {
                _longjmp(std::hint::black_box(envp), std::hint::black_box(0));
            }
            assert_eq!(r, 1);
            assert_eq!(HITS.load(Ordering::SeqCst), 2);
        }
    }

    /// Block an RT signal, `sigsetjmp(1)`, drop the mask, `siglongjmp`
    /// back, and confirm the mask (and the saved copy) was restored.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn sigsetjmp_savemask_roundtrip() {
        let _guard = crate::ldso::testlock::lock();
        let bit: u64 = 1u64 << (SIG_RT - 1);
        unsafe {
            let mut saved: u64 = 0;
            assert_eq!(read_mask(&mut saved), 0);
            let blk: u64 = bit;
            assert_eq!(
                syscall4(
                    SYS_RT_SIGPROCMASK,
                    0,
                    &blk as *const u64 as usize,
                    0,
                    K_SIGSET_LEN
                ),
                0
            );
            let mut before: u64 = 0;
            assert_eq!(read_mask(&mut before), 0);
            let mut env = SigJmpBuf {
                jb: [0; 8],
                fl: 0,
                ss: [0; 16],
            };
            let envp = std::hint::black_box(&mut env as *mut SigJmpBuf);
            let r = std::hint::black_box(sigsetjmp(envp, std::hint::black_box(1)));
            if std::hint::black_box(r) == 0 {
                let zero: u64 = 0;
                syscall4(
                    SYS_RT_SIGPROCMASK,
                    SIG_SETMASK,
                    &zero as *const u64 as usize,
                    0,
                    K_SIGSET_LEN,
                );
                siglongjmp(std::hint::black_box(envp), std::hint::black_box(7));
            }
            let mut after: u64 = 0;
            assert_eq!(read_mask(&mut after), 0);
            let got_saved_copy = env.ss[0];
            syscall4(
                SYS_RT_SIGPROCMASK,
                SIG_SETMASK,
                &saved as *const u64 as usize,
                0,
                K_SIGSET_LEN,
            );
            assert_eq!(r, 7);
            assert_eq!(before & bit, bit);
            assert_eq!(after & bit, bit);
            assert_eq!(got_saved_copy & bit, bit);
        }
    }

    /// `sigsetjmp(0)` neither saves nor restores: unblock after capture,
    /// jump back, and the mask stays unblocked.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn sigsetjmp_zero_savemask_leaves_mask_alone() {
        let _guard = crate::ldso::testlock::lock();
        let bit: u64 = 1u64 << (SIG_RT - 1);
        unsafe {
            let mut saved: u64 = 0;
            assert_eq!(read_mask(&mut saved), 0);
            let blk: u64 = bit;
            assert_eq!(
                syscall4(
                    SYS_RT_SIGPROCMASK,
                    0,
                    &blk as *const u64 as usize,
                    0,
                    K_SIGSET_LEN
                ),
                0
            );
            let mut env = SigJmpBuf {
                jb: [0; 8],
                fl: 0,
                ss: [0; 16],
            };
            let envp = std::hint::black_box(&mut env as *mut SigJmpBuf);
            let r = std::hint::black_box(sigsetjmp(envp, std::hint::black_box(0)));
            if std::hint::black_box(r) == 0 {
                let zero: u64 = 0;
                syscall4(
                    SYS_RT_SIGPROCMASK,
                    SIG_SETMASK,
                    &zero as *const u64 as usize,
                    0,
                    K_SIGSET_LEN,
                );
                siglongjmp(std::hint::black_box(envp), std::hint::black_box(3));
            }
            let mut after: u64 = 0;
            assert_eq!(read_mask(&mut after), 0);
            syscall4(
                SYS_RT_SIGPROCMASK,
                SIG_SETMASK,
                &saved as *const u64 as usize,
                0,
                K_SIGSET_LEN,
            );
            assert_eq!(r, 3);
            assert_eq!(after & bit, 0);
        }
    }
}
