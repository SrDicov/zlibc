//! Raw syscall dispatch for x86_64 (PoC, 0–3 args).
//!
//! Mirrors musl's `__syscall0..3` (arch/x86_64/syscall_arch.h):
//! nr in `rax`, args in `rdi/rsi/rdx`, `rcx`/`r11` clobbered.
//! No `nomem` (syscalls read/write memory) and no `preserves_flags`
//! (`syscall` clobbers rflags via `r11`). Extend to 0–7 following
//! the same pattern.

use core::ffi::c_int;

#[cfg(target_arch = "x86_64")]
pub const SYS_WRITE: usize = 1; // TODO: generate from arch bits/syscall.h

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn syscall0(n: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") n as isize => ret,
            out("rcx") _, out("r11") _,
        );
    }
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn syscall1(n: usize, a1: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") n as isize => ret,
            in("rdi") a1,
            out("rcx") _, out("r11") _,
        );
    }
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn syscall2(n: usize, a1: usize, a2: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") n as isize => ret,
            in("rdi") a1, in("rsi") a2,
            out("rcx") _, out("r11") _,
        );
    }
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") n as isize => ret,
            in("rdi") a1, in("rsi") a2, in("rdx") a3,
            out("rcx") _, out("r11") _,
        );
    }
    ret
}

/// musl `__syscall_ret`: kernel returns -4095..-1 on error.
/// Negate to get the errno, store via `__errno_location`, return -1.
#[inline(always)]
pub unsafe fn syscall_ret(r: isize) -> isize {
    if r >= -4095 && r <= -1 {
        unsafe {
            *__errno_location() = (-r) as c_int;
        }
        -1
    } else {
        r
    }
}

extern "C" {
    fn __errno_location() -> *mut c_int;
}

/// C-style dispatcher: `__syscall!(SYS_WRITE, fd, buf, len)`.
#[macro_export]
macro_rules! __syscall {
    ($n:expr) => {
        unsafe { $crate::syscall::syscall_ret($crate::syscall::syscall0($n)) }
    };
    ($n:expr, $a1:expr) => {
        unsafe { $crate::syscall::syscall_ret($crate::syscall::syscall1($n, $a1 as usize)) }
    };
    ($n:expr, $a1:expr, $a2:expr) => {
        unsafe {
            $crate::syscall::syscall_ret($crate::syscall::syscall2($n, $a1 as usize, $a2 as usize))
        }
    };
    ($n:expr, $a1:expr, $a2:expr, $a3:expr) => {
        unsafe {
            $crate::syscall::syscall_ret($crate::syscall::syscall3(
                $n, $a1 as usize, $a2 as usize, $a3 as usize,
            ))
        }
    };
}
