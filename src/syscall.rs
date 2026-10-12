//! Raw syscall dispatch for x86_64 (0–6 args).
//!
//! Mirrors musl's `__syscall0..6` (arch/x86_64/syscall_arch.h):
//! nr in `rax`, args in `rdi`/`rsi`/`rdx`/`r10`/`r8`/`r9`,
//! `rcx`/`r11` clobbered. No `nomem` (syscalls read/write memory)
//! and no `preserves_flags` (`syscall` clobbers rflags via `r11`).

use core::ffi::c_int;

#[cfg(target_arch = "x86_64")]
pub const SYS_WRITE: usize = 1; // TODO: generate from arch bits/syscall.h

#[cfg(target_arch = "x86_64")]
#[inline(always)]
/// Raw 0-arg syscall.
///
/// # Safety
///
/// Executes the `syscall` instruction with the given number. The caller
/// must ensure `n` is a valid syscall number and that entering the
/// kernel with no arguments is sound (no memory is touched by this).
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
/// Raw 1-arg syscall.
///
/// # Safety
///
/// Like [`syscall0`]; additionally `a1` is passed in `rdi`, so the
/// caller must ensure the callee may legally observe that word.
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
/// Raw 2-arg syscall.
///
/// # Safety
///
/// Like [`syscall1`]; `a1`/`a2` go in `rdi`/`rsi`.
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
/// Raw 3-arg syscall.
///
/// # Safety
///
/// Like [`syscall1`]; `a1`/`a2`/`a3` go in `rdi`/`rsi`/`rdx`.
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

#[cfg(target_arch = "x86_64")]
#[inline(always)]
/// Raw 4-arg syscall.
///
/// # Safety
///
/// Like [`syscall1`]; `a1`/`a2`/`a3`/`a4` go in `rdi`/`rsi`/`rdx`/`r10`.
pub unsafe fn syscall4(n: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") n as isize => ret,
            in("rdi") a1, in("rsi") a2, in("rdx") a3, in("r10") a4,
            out("rcx") _, out("r11") _,
        );
    }
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
/// Raw 5-arg syscall.
///
/// # Safety
///
/// Like [`syscall1`]; `a1`/`a2`/`a3`/`a4`/`a5` go in
/// `rdi`/`rsi`/`rdx`/`r10`/`r8`.
pub unsafe fn syscall5(n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") n as isize => ret,
            in("rdi") a1, in("rsi") a2, in("rdx") a3, in("r10") a4, in("r8") a5,
            out("rcx") _, out("r11") _,
        );
    }
    ret
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
/// Raw 6-arg syscall.
///
/// # Safety
///
/// Like [`syscall1`]; `a1`/`a2`/`a3`/`a4`/`a5`/`a6` go in
/// `rdi`/`rsi`/`rdx`/`r10`/`r8`/`r9`.
pub unsafe fn syscall6(
    n: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") n as isize => ret,
            in("rdi") a1, in("rsi") a2, in("rdx") a3,
            in("r10") a4, in("r8") a5, in("r9") a6,
            out("rcx") _, out("r11") _,
        );
    }
    ret
}

/// musl `__syscall_ret`: kernel returns -4095..-1 on error.
/// Negate to get the errno, store via `__errno_location`, return -1.
///
/// # Safety
///
/// `r` must be a value returned by one of the raw `syscallN`
/// wrappers. On the error path this writes the current thread's errno
/// through the `__errno_location` symbol, which must resolve at link
/// time to musl-compatible thread-local storage.
#[inline(always)]
pub unsafe fn syscall_ret(r: isize) -> isize {
    if (-4095..=-1).contains(&r) {
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
                $n,
                $a1 as usize,
                $a2 as usize,
                $a3 as usize,
            ))
        }
    };
    ($n:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {
        unsafe {
            $crate::syscall::syscall_ret($crate::syscall::syscall4(
                $n,
                $a1 as usize,
                $a2 as usize,
                $a3 as usize,
                $a4 as usize,
            ))
        }
    };
    ($n:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr) => {
        unsafe {
            $crate::syscall::syscall_ret($crate::syscall::syscall5(
                $n,
                $a1 as usize,
                $a2 as usize,
                $a3 as usize,
                $a4 as usize,
                $a5 as usize,
            ))
        }
    };
    ($n:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr, $a6:expr) => {
        unsafe {
            $crate::syscall::syscall_ret($crate::syscall::syscall6(
                $n,
                $a1 as usize,
                $a2 as usize,
                $a3 as usize,
                $a4 as usize,
                $a5 as usize,
                $a6 as usize,
            ))
        }
    };
}

#[cfg(test)]
mod tests {
    /// Proves raw dispatch works on real Linux: SYS_getpid (39, x86_64)
    /// takes no args and must return a positive pid. Also forces the
    /// linker to retain the syscall path in the test binary.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn raw_syscall_getpid_works() {
        let pid = unsafe { crate::syscall::syscall0(39) };
        assert!(pid > 0, "getpid returned {pid}");
    }

    /// Proves `___errno_location` exists as an alias of
    /// `__errno_location`: both addresses must coincide. (On a glibc
    /// host they resolve to glibc's definition; on freestanding zlibc
    /// they will resolve to ours. A missing alias would fail here at
    /// link time instead.) The alias stays WEAK (see musl
    /// src/errno/__errno_location.c:9), so a future strong definition
    /// overrides it without duplicate-symbol errors.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn weak_alias_targets_errno_location() {
        extern "C" {
            static ___errno_location: u8;
            fn __errno_location() -> *mut core::ffi::c_int;
        }
        let alias = core::ptr::addr_of!(___errno_location) as usize;
        let target = __errno_location as *const () as usize;
        assert_eq!(alias, target, "weak alias does not track __errno_location");
    }
}
