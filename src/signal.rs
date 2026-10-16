//! Signal handling (musl `src/signal/*`, x86_64): thin wrappers plus set ops.
//!
//! Raw traps (`rt_sigaction`, `rt_sigprocmask`, `kill`, `tkill`, …) go
//! through `syscall_ret` exactly like musl's ABI boundary; the `sigset_t`
//! bit ops are pure userspace copies of musl's (`sigaddset.c` etc.).
//! `raise` uses raw `gettid`+`tkill` (no TCB deref); `sigwait` is
//! `sigtimedwait` with a null timeout; `siginterrupt` flips `SA_RESTART`
//! via `sigaction`. The restorer always installed is
//! [`crate::thread::synccall::__restore_rt`], never the vDSO fallback.

use core::ffi::{c_char, c_int, c_long, c_void};

use crate::syscall::{syscall0, syscall2, syscall3, syscall4, syscall_ret};
use crate::thread::synccall::__restore_rt;

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_WRITE: usize = 1; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_RT_SIGACTION: usize = 13; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_RT_SIGPROCMASK: usize = 14; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_GETPID: usize = 39; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_KILL: usize = 62; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_GETUID: usize = 102; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_RT_SIGPENDING: usize = 127; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_RT_SIGTIMEDWAIT: usize = 128; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_RT_SIGQUEUEINFO: usize = 129; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_RT_SIGSUSPEND: usize = 130; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_SIGALTSTACK: usize = 131; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_GETTID: usize = 186; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_TKILL: usize = 200; // TODO: generate from arch bits/syscall.h

/// Kernel mask length (`_NSIG/8`, `sigaction.c`).
#[cfg(target_arch = "x86_64")]
const K_SIGSET_LEN: usize = 8;

// ---- Local errnos (musl arch/generic/bits/errno.h) --------------------------
#[cfg(target_arch = "x86_64")]
const EINTR: c_int = 4;
#[cfg(target_arch = "x86_64")]
const EINVAL: c_int = 22;
#[cfg(target_arch = "x86_64")]
const ENOMEM: c_int = 12;

// ---- Signals (musl arch/x86_64/bits/signal.h:117-152) -----------------------
pub const SIGHUP: c_int = 1;
pub const SIGINT: c_int = 2;
pub const SIGQUIT: c_int = 3;
pub const SIGILL: c_int = 4;
pub const SIGTRAP: c_int = 5;
pub const SIGABRT: c_int = 6;
pub const SIGIOT: c_int = SIGABRT;
pub const SIGBUS: c_int = 7;
pub const SIGFPE: c_int = 8;
pub const SIGKILL: c_int = 9;
pub const SIGUSR1: c_int = 10;
pub const SIGSEGV: c_int = 11;
pub const SIGUSR2: c_int = 12;
pub const SIGPIPE: c_int = 13;
pub const SIGALRM: c_int = 14;
pub const SIGTERM: c_int = 15;
pub const SIGSTKFLT: c_int = 16;
pub const SIGCHLD: c_int = 17;
pub const SIGCONT: c_int = 18;
pub const SIGSTOP: c_int = 19;
pub const SIGTSTP: c_int = 20;
pub const SIGTTIN: c_int = 21;
pub const SIGTTOU: c_int = 22;
pub const SIGURG: c_int = 23;
pub const SIGXCPU: c_int = 24;
pub const SIGXFSZ: c_int = 25;
pub const SIGVTALRM: c_int = 26;
pub const SIGPROF: c_int = 27;
pub const SIGWINCH: c_int = 28;
pub const SIGIO: c_int = 29;
pub const SIGPOLL: c_int = SIGIO;
pub const SIGPWR: c_int = 30;
pub const SIGSYS: c_int = 31;
pub const SIGUNUSED: c_int = SIGSYS;

/// musl `_NSIG` (`bits/signal.h:152`); `SIGRTMIN`/`SIGRTMAX` are runtime
/// calls in musl (`sigrtmin.c`/`sigrtmax.c`), so they stay functions of
/// another wave, never consts here.
pub const _NSIG: c_int = 65;
pub const NSIG: c_int = _NSIG;

/// Handler values (musl `include/signal.h:283-285` + `SIG_HOLD`).
pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;
pub const SIG_HOLD: usize = 2;
pub const SIG_ERR: usize = usize::MAX;

/// Mask actions (musl `include/signal.h:30-32`).
pub const SIG_BLOCK: c_int = 0;
pub const SIG_UNBLOCK: c_int = 1;
pub const SIG_SETMASK: c_int = 2;

/// `SA_*` flags (musl `arch/x86_64/bits/signal.h:106-113`).
pub const SA_NOCLDSTOP: c_int = 1;
pub const SA_NOCLDWAIT: c_int = 2;
pub const SA_SIGINFO: c_int = 4;
pub const SA_ONSTACK: c_int = 0x08000000;
pub const SA_RESTART: c_int = 0x10000000;
pub const SA_NODEFER: c_int = 0x40000000;
pub const SA_RESETHAND: c_int = -0x80000000;
pub const SA_RESTORER: c_int = 0x04000000;

/// Alternate-stack flags (musl `include/signal.h:258-260`) and minimum
/// (musl `arch/x86_64/bits/signal.h:5`; `sigaltstack.c` reads it via
/// `sysconf`, which reports this same constant on Linux).
pub const SS_ONSTACK: c_int = 1;
pub const SS_DISABLE: c_int = 2;
pub const MINSIGSTKSZ: usize = 2048;
pub const SIGSTKSZ: usize = 8192;

/// Queued-signal code (musl `include/signal.h:47`).
pub const SI_QUEUE: c_int = -1;

/// musl `sigset_t` (`include/alltypes.h.in:77`): 1024 bits on 64-bit.
/// The kernel only reads the first 8 bytes (`_NSIG/8`).
#[allow(non_camel_case_types)]
pub type sigset_t = [u64; 16];

/// musl `struct sigaction` (`include/signal.h:169-177`): handler, mask,
/// flags, restorer.
#[repr(C)]
pub struct Sigaction {
    pub handler: usize,
    pub mask: sigset_t,
    pub flags: c_int,
    pub restorer: usize,
}

/// Raw kernel shape (musl `arch/x86_64/ksigaction.h:3-8`): handler,
/// flags, restorer, then the 8-byte kernel mask.
#[repr(C)]
struct Ksigaction {
    handler: usize,
    flags: usize,
    restorer: usize,
    mask: u64,
}

/// musl `union sigval` (`include/signal.h:93-96`).
#[repr(C)]
#[derive(Copy, Clone)]
pub union Sigval {
    pub sival_int: c_int,
    pub sival_ptr: *mut c_void,
}

/// musl `siginfo_t` (`include/signal.h:99-130`, x86_64 order): the
/// offsets below are probed against glibc (`si_pid` 16, `si_uid` 20,
/// `si_value` 24, size 128).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Siginfo {
    pub si_signo: c_int,
    pub si_errno: c_int,
    pub si_code: c_int,
    pub _pad0: c_int,
    pub si_pid: c_int,
    pub si_uid: u32,
    pub si_value: Sigval,
    pub _pad: [u8; 96],
}

/// musl `struct sigaltstack` (`arch/x86_64/bits/signal.h:91-95`).
#[repr(C)]
pub struct StackT {
    pub ss_sp: *mut c_void,
    pub ss_flags: c_int,
    pub ss_size: usize,
}

/// musl `struct timespec` for the `sigtimedwait` timeout (clocks live in
/// another wave; this never leaves this module's boundary).
#[repr(C)]
pub struct Timespec {
    pub tv_sec: c_long,
    pub tv_nsec: c_long,
}

const _: () = assert!(core::mem::size_of::<Sigaction>() == 152);
const _: () = assert!(core::mem::size_of::<Siginfo>() == 128);
const _: () = assert!(core::mem::size_of::<StackT>() == 24);

/// Valid installable signal (musl `sigaction.c:__sigaction`): 1..=64
/// except the reserved 32-34.
#[cfg(target_arch = "x86_64")]
fn sig_valid(sig: c_int) -> bool {
    let s = sig as u32;
    s.wrapping_sub(32) >= 3 && s.wrapping_sub(1) < (_NSIG as u32 - 1)
}

/// Valid set member (musl `sigaddset.c`/`sigdelset.c`): same as above.
#[cfg(target_arch = "x86_64")]
fn set_member_valid(sig: c_int) -> bool {
    sig_valid(sig)
}

/// Block every signal, saving the old mask (musl `block.c`).
///
/// # Safety
///
/// `set` must hold one writable `u64` (the 8-byte kernel mask).
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn __block_all_sigs(set: *mut sigset_t) {
    unsafe {
        let all: u64 = !0;
        syscall4(
            SYS_RT_SIGPROCMASK,
            SIG_BLOCK as usize,
            &all as *const u64 as usize,
            set as usize,
            K_SIGSET_LEN,
        );
    }
}

/// Block the application set, saving the old mask (musl `block.c`).
///
/// # Safety
///
/// Same contract as [`__block_all_sigs`].
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn __block_app_sigs(set: *mut sigset_t) {
    unsafe {
        let app: u64 = 0xfffffffc7fffffff;
        syscall4(
            SYS_RT_SIGPROCMASK,
            SIG_BLOCK as usize,
            &app as *const u64 as usize,
            set as usize,
            K_SIGSET_LEN,
        );
    }
}

/// Restore a mask saved by the block helpers (musl `block.c`).
///
/// # Safety
///
/// `set` must point at 8 valid mask bytes from a block helper.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn __restore_sigs(set: *const sigset_t) {
    unsafe {
        syscall4(
            SYS_RT_SIGPROCMASK,
            SIG_SETMASK as usize,
            set as usize,
            0,
            K_SIGSET_LEN,
        );
    }
}

/// Install or query a disposition (musl `sigaction.c:__sigaction`).
///
/// # Safety
///
/// `act`/`old` follow the C contract (nullable; otherwise valid).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigaction(
    sig: c_int,
    act: *const Sigaction,
    old: *mut Sigaction,
) -> c_int {
    unsafe {
        if !sig_valid(sig) {
            return syscall_ret(-(EINVAL as isize)) as c_int;
        }
        let mut k = Ksigaction {
            handler: 0,
            flags: 0,
            restorer: 0,
            mask: 0,
        };
        let mut ko = Ksigaction {
            handler: 0,
            flags: 0,
            restorer: 0,
            mask: 0,
        };
        let kp = if act.is_null() {
            0
        } else {
            let a = &*act;
            k.handler = a.handler;
            k.flags = (a.flags as usize) | (SA_RESTORER as usize);
            k.restorer = __restore_rt as *const () as usize;
            k.mask = a.mask[0];
            &k as *const Ksigaction as usize
        };
        let kop = if old.is_null() {
            0
        } else {
            &mut ko as *mut Ksigaction as usize
        };
        let r = syscall4(SYS_RT_SIGACTION, sig as usize, kp, kop, K_SIGSET_LEN);
        if r == 0 && !old.is_null() {
            let o = &mut *old;
            o.handler = ko.handler;
            o.flags = ko.flags as c_int;
            o.mask = [0; 16];
            o.mask[0] = ko.mask;
            o.restorer = ko.restorer;
        }
        syscall_ret(r) as c_int
    }
}

/// Examine or change the blocked set (musl `pthread_sigmask.c`: returns
/// the errno itself, never -1; reserved bits 32-34 are cleared in `old`).
///
/// # Safety
///
/// `set`/`old` follow the C contract (nullable; otherwise valid).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn pthread_sigmask(
    how: c_int,
    set: *const sigset_t,
    old: *mut sigset_t,
) -> c_int {
    unsafe {
        if !set.is_null() && (how as u32) > 2 {
            return EINVAL;
        }
        if !old.is_null() {
            *old = [0; 16];
        }
        let r = syscall4(
            SYS_RT_SIGPROCMASK,
            how as usize,
            set as usize,
            old as usize,
            K_SIGSET_LEN,
        );
        if r == 0 {
            if !old.is_null() {
                (*old)[0] &= !0x380000000u64;
            }
            return 0;
        }
        r.wrapping_neg() as c_int
    }
}

/// Examine or change the blocked set (musl `sigprocmask.c`: errno-style
/// wrapper over [`pthread_sigmask`]).
///
/// # Safety
///
/// Same contract as [`pthread_sigmask`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigprocmask(
    how: c_int,
    set: *const sigset_t,
    old: *mut sigset_t,
) -> c_int {
    unsafe {
        let r = pthread_sigmask(how, set, old);
        if r == 0 {
            return 0;
        }
        syscall_ret(-(r as isize)) as c_int
    }
}

/// Send a signal (musl `kill.c`: one `SYS_kill` trap).
///
/// # Safety
///
/// Pure syscall wrapper; `pid`/`sig` are kernel-checked.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn kill(pid: c_int, sig: c_int) -> c_int {
    unsafe { syscall_ret(syscall2(SYS_KILL, pid as usize, sig as usize)) as c_int }
}

/// Send to a process group (musl `killpg.c`: `EINVAL` on negative
/// `pgid`, else `kill(-pgid, sig)`).
///
/// # Safety
///
/// Same contract as [`kill`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn killpg(pgid: c_int, sig: c_int) -> c_int {
    unsafe {
        if pgid < 0 {
            return syscall_ret(-(EINVAL as isize)) as c_int;
        }
        kill(pgid.wrapping_neg(), sig)
    }
}

/// Send to the calling thread (musl `raise.c`: block app sigs, raw
/// `gettid`+`tkill`, restore).
///
/// # Safety
///
/// Pure syscall wrapper; `sig` is kernel-checked.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn raise(sig: c_int) -> c_int {
    unsafe {
        let mut set: sigset_t = [0; 16];
        __block_app_sigs(&mut set);
        let tid = syscall0(SYS_GETTID);
        let r = syscall_ret(syscall2(SYS_TKILL, tid as usize, sig as usize)) as c_int;
        __restore_sigs(&set);
        r
    }
}

/// Empty a set (musl `sigemptyset.c`).
///
/// # Safety
///
/// `set` must be writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigemptyset(set: *mut sigset_t) -> c_int {
    unsafe {
        if set.is_null() {
            return syscall_ret(-(EINVAL as isize)) as c_int;
        }
        *set = [0; 16];
        0
    }
}

/// Fill a set (musl `sigfillset.c`: everything except reserved 32-34).
///
/// # Safety
///
/// `set` must be writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigfillset(set: *mut sigset_t) -> c_int {
    unsafe {
        if set.is_null() {
            return syscall_ret(-(EINVAL as isize)) as c_int;
        }
        *set = [0; 16];
        (*set)[0] = 0xfffffffc7fffffff;
        0
    }
}

/// Add a signal (musl `sigaddset.c`).
///
/// # Safety
///
/// `set` must be writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigaddset(set: *mut sigset_t, sig: c_int) -> c_int {
    unsafe {
        if set.is_null() || !set_member_valid(sig) {
            return syscall_ret(-(EINVAL as isize)) as c_int;
        }
        let s = (sig as u32).wrapping_sub(1);
        (*set)[0] |= 1u64.wrapping_shl(s);
        0
    }
}

/// Remove a signal (musl `sigdelset.c`).
///
/// # Safety
///
/// `set` must be writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigdelset(set: *mut sigset_t, sig: c_int) -> c_int {
    unsafe {
        if set.is_null() || !set_member_valid(sig) {
            return syscall_ret(-(EINVAL as isize)) as c_int;
        }
        let s = (sig as u32).wrapping_sub(1);
        (*set)[0] &= !1u64.wrapping_shl(s);
        0
    }
}

/// Test membership (musl `sigismember.c`: out-of-range reads 0, no
/// errno).
///
/// # Safety
///
/// `set` must be readable (null reads 0).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigismember(set: *const sigset_t, sig: c_int) -> c_int {
    unsafe {
        if set.is_null() {
            return 0;
        }
        let s = (sig as u32).wrapping_sub(1);
        if s >= (_NSIG as u32 - 1) {
            return 0;
        }
        (((*set)[0] >> s) & 1) as c_int
    }
}

/// Test for empty (musl `sigisemptyset.c`).
///
/// # Safety
///
/// `set` must be readable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigisemptyset(set: *const sigset_t) -> c_int {
    unsafe {
        if set.is_null() {
            return syscall_ret(-(EINVAL as isize)) as c_int;
        }
        for w in (*set).iter() {
            if *w != 0 {
                return 0;
            }
        }
        1
    }
}

/// Intersect two sets (musl `sigandset.c`).
///
/// # Safety
///
/// All three pointers must be valid (`dest` writable).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigandset(
    dest: *mut sigset_t,
    left: *const sigset_t,
    right: *const sigset_t,
) -> c_int {
    unsafe {
        if dest.is_null() || left.is_null() || right.is_null() {
            return syscall_ret(-(EINVAL as isize)) as c_int;
        }
        for i in 0..16 {
            (*dest)[i] = (*left)[i] & (*right)[i];
        }
        0
    }
}

/// Unite two sets (musl `sigorset.c`).
///
/// # Safety
///
/// All three pointers must be valid (`dest` writable).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigorset(
    dest: *mut sigset_t,
    left: *const sigset_t,
    right: *const sigset_t,
) -> c_int {
    unsafe {
        if dest.is_null() || left.is_null() || right.is_null() {
            return syscall_ret(-(EINVAL as isize)) as c_int;
        }
        for i in 0..16 {
            (*dest)[i] = (*left)[i] | (*right)[i];
        }
        0
    }
}

/// Wait with a replaced mask (musl `sigsuspend.c`: one trap).
///
/// # Safety
///
/// `mask` is kernel-checked (null faults like musl's passthrough).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigsuspend(mask: *const sigset_t) -> c_int {
    unsafe { syscall_ret(syscall2(SYS_RT_SIGSUSPEND, mask as usize, K_SIGSET_LEN)) as c_int }
}

/// Pending set (musl `sigpending.c`: one trap).
///
/// # Safety
///
/// `set` must hold one writable `u64` (kernel writes 8 bytes).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigpending(set: *mut sigset_t) -> c_int {
    unsafe {
        if set.is_null() {
            return syscall_ret(-(EINVAL as isize)) as c_int;
        }
        *set = [0; 16];
        syscall_ret(syscall2(SYS_RT_SIGPENDING, set as usize, K_SIGSET_LEN)) as c_int
    }
}

/// Wait for a set member, with timeout (musl `sigtimedwait.c`: retry on
/// `EINTR`; x86_64 needs no time64 split).
///
/// # Safety
///
/// `mask`/`si`/`timeout` follow the C contract (all nullable together
/// like musl's passthrough, except `si` may stay null).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigtimedwait(
    mask: *const sigset_t,
    si: *mut Siginfo,
    timeout: *const Timespec,
) -> c_int {
    unsafe {
        loop {
            let r = syscall4(
                SYS_RT_SIGTIMEDWAIT,
                mask as usize,
                si as usize,
                timeout as usize,
                K_SIGSET_LEN,
            );
            if r != -(EINTR as isize) {
                return syscall_ret(r) as c_int;
            }
        }
    }
}

/// Wait for a set member (musl `sigwait.c`: `sigtimedwait` with no
/// timeout; returns -1 on error like musl, not the errno).
///
/// # Safety
///
/// `mask` must be valid; `sig` must be writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigwait(mask: *const sigset_t, sig: *mut c_int) -> c_int {
    unsafe {
        let mut si = core::mem::zeroed::<Siginfo>();
        if sigtimedwait(mask, &mut si, core::ptr::null()) < 0 {
            return -1;
        }
        if sig.is_null() {
            return syscall_ret(-(EINVAL as isize)) as c_int;
        }
        *sig = si.si_signo;
        0
    }
}

/// Wait for a set member with info (musl `sigwaitinfo.c`: `sigtimedwait`
/// with no timeout).
///
/// # Safety
///
/// Same contract as [`sigtimedwait`] with a null timeout.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigwaitinfo(mask: *const sigset_t, si: *mut Siginfo) -> c_int {
    unsafe { sigtimedwait(mask, si, core::ptr::null()) }
}

/// Set or query the alternate stack (musl `sigaltstack.c`: `ENOMEM`
/// under the minimum, `EINVAL` on `SS_ONSTACK`, else one trap).
///
/// # Safety
///
/// `ss`/`old` follow the C contract (nullable; otherwise valid).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigaltstack(ss: *const StackT, old: *mut StackT) -> c_int {
    unsafe {
        if !ss.is_null() {
            let s = &*ss;
            if (s.ss_flags & SS_DISABLE) == 0 && s.ss_size < MINSIGSTKSZ {
                return syscall_ret(-(ENOMEM as isize)) as c_int;
            }
            if (s.ss_flags & SS_ONSTACK) != 0 {
                return syscall_ret(-(EINVAL as isize)) as c_int;
            }
        }
        syscall_ret(syscall2(SYS_SIGALTSTACK, ss as usize, old as usize)) as c_int
    }
}

/// Queue a signal with a value (musl `sigqueue.c`: `SI_QUEUE` info with
/// own pid/uid under blocked app sigs, one `rt_sigqueueinfo` trap).
///
/// # Safety
///
/// Pure syscall wrapper; `pid`/`sig` are kernel-checked.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigqueue(pid: c_int, sig: c_int, value: Sigval) -> c_int {
    unsafe {
        let mut si = core::mem::zeroed::<Siginfo>();
        si.si_signo = sig;
        si.si_code = SI_QUEUE;
        si.si_value = value;
        si.si_uid = syscall0(SYS_GETUID) as u32;
        let mut set: sigset_t = [0; 16];
        __block_app_sigs(&mut set);
        si.si_pid = syscall0(SYS_GETPID) as c_int;
        let r = syscall_ret(syscall3(
            SYS_RT_SIGQUEUEINFO,
            pid as usize,
            sig as usize,
            &si as *const Siginfo as usize,
        )) as c_int;
        __restore_sigs(&set);
        r
    }
}

/// musl `strsignal.c` descriptions for 0..=31 (0 is "Unknown signal").
#[cfg(target_arch = "x86_64")]
const SIGDESC: [&str; 32] = [
    "Unknown signal",
    "Hangup",
    "Interrupt",
    "Quit",
    "Illegal instruction",
    "Trace/breakpoint trap",
    "Aborted",
    "Bus error",
    "Arithmetic exception",
    "Killed",
    "User defined signal 1",
    "Segmentation fault",
    "User defined signal 2",
    "Broken pipe",
    "Alarm clock",
    "Terminated",
    "Stack fault",
    "Child process status",
    "Continued",
    "Stopped (signal)",
    "Stopped",
    "Stopped (tty input)",
    "Stopped (tty output)",
    "Urgent I/O condition",
    "CPU time limit exceeded",
    "File size limit exceeded",
    "Virtual timer expired",
    "Profiling timer expired",
    "Window changed",
    "I/O possible",
    "Power failure",
    "Bad system call",
];

/// Raw write ignoring the result (psignal never reports errors and must
/// not touch errno, so this skips `syscall_ret`).
///
/// # Safety
///
/// `p` must be readable for `n` bytes.
#[cfg(target_arch = "x86_64")]
unsafe fn fd_write(fd: usize, p: *const u8, n: usize) {
    unsafe {
        let _ = syscall3(SYS_WRITE, fd, p as usize, n);
    }
}

/// Print a one-line description (musl `psignal.c`: `msg: description`
/// on stderr; stdio orientation has no meaning without stdio, so the
/// bytes go straight through `SYS_write`).
///
/// # Safety
///
/// `msg` must be null or a valid NUL-terminated string.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn psignal(sig: c_int, msg: *const c_char) {
    unsafe {
        if !msg.is_null() {
            let mut n = 0usize;
            while *msg.wrapping_add(n) != 0 {
                n = n.wrapping_add(1);
            }
            if n > 0 {
                fd_write(2, msg as *const u8, n);
                fd_write(2, c": ".as_ptr() as *const u8, 2);
            }
        }
        if (sig as u32) < 32 {
            let d = SIGDESC[sig as usize].as_bytes();
            fd_write(2, d.as_ptr(), d.len());
        } else if (32..=64).contains(&sig) {
            // musl prints RT32..RT64 (strsignal.c).
            let v = sig as u32;
            let mut digits = [0u8; 2];
            let mut len = 0usize;
            if v >= 10 {
                digits[0] = b'0'.wrapping_add((v / 10) as u8);
                len = 1;
            }
            digits[len] = b'0'.wrapping_add((v % 10) as u8);
            len = len.wrapping_add(1);
            fd_write(2, c"RT".as_ptr() as *const u8, 2);
            fd_write(2, digits.as_ptr(), len);
        } else {
            let d = SIGDESC[0].as_bytes();
            fd_write(2, d.as_ptr(), d.len());
        }
        fd_write(2, c"\n".as_ptr() as *const u8, 1);
    }
}

/// Print a `siginfo`'s signal description (musl `psiginfo.c`).
///
/// # Safety
///
/// `si` must be null or valid; `msg` follows [`psignal`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn psiginfo(si: *const Siginfo, msg: *const c_char) {
    unsafe {
        let sig = if si.is_null() { 0 } else { (*si).si_signo };
        psignal(sig, msg);
    }
}

/// BSD handler install (musl `signal.c`: `SA_RESTART` action roundtrip).
///
/// # Safety
///
/// `func` is a handler value (`SIG_DFL`/`SIG_IGN`/function address).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn signal(sig: c_int, func: usize) -> usize {
    unsafe {
        let sa = Sigaction {
            handler: func,
            mask: [0; 16],
            flags: SA_RESTART,
            restorer: 0,
        };
        let mut old = Sigaction {
            handler: SIG_DFL,
            mask: [0; 16],
            flags: 0,
            restorer: 0,
        };
        if sigaction(sig, &sa, &mut old) < 0 {
            return SIG_ERR;
        }
        old.handler
    }
}

/// Same as [`signal`] (musl keeps it as a weak alias; alias machinery is
/// another wave's, so this is a plain forwarder).
///
/// # Safety
///
/// Same contract as [`signal`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn bsd_signal(sig: c_int, func: usize) -> usize {
    unsafe { signal(sig, func) }
}

/// Hold a signal (musl `sighold.c`: block one member).
///
/// # Safety
///
/// Pure mask wrapper; invalid `sig` returns -1/`EINVAL`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sighold(sig: c_int) -> c_int {
    unsafe {
        let mut mask: sigset_t = [0; 16];
        if sigemptyset(&mut mask) < 0 {
            return -1;
        }
        if sigaddset(&mut mask, sig) < 0 {
            return -1;
        }
        sigprocmask(SIG_BLOCK, &mask, core::ptr::null_mut())
    }
}

/// Ignore a signal (musl `sigignore.c`: empty-mask `SIG_IGN` install).
///
/// # Safety
///
/// Invalid `sig` returns -1/`EINVAL` from the install.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigignore(sig: c_int) -> c_int {
    unsafe {
        let sa = Sigaction {
            handler: SIG_IGN,
            mask: [0; 16],
            flags: 0,
            restorer: 0,
        };
        sigaction(sig, &sa, core::ptr::null_mut())
    }
}

/// Pause with one signal enabled (musl `sigpause.c`: current mask minus
/// `sig`, then `sigsuspend`).
///
/// # Safety
///
/// Invalid `sig` returns -1/`EINVAL`; else blocks like [`sigsuspend`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigpause(sig: c_int) -> c_int {
    unsafe {
        let mut mask: sigset_t = [0; 16];
        sigprocmask(0, core::ptr::null(), &mut mask);
        if sigdelset(&mut mask, sig) != 0 {
            return -1;
        }
        sigsuspend(&mask)
    }
}

/// Release a held signal (musl `sigrelse.c`: unblock one member).
///
/// # Safety
///
/// Same contract as [`sighold`] with `SIG_UNBLOCK`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sigrelse(sig: c_int) -> c_int {
    unsafe {
        let mut mask: sigset_t = [0; 16];
        if sigemptyset(&mut mask) < 0 {
            return -1;
        }
        if sigaddset(&mut mask, sig) < 0 {
            return -1;
        }
        sigprocmask(SIG_UNBLOCK, &mask, core::ptr::null_mut())
    }
}

/// Toggle restart behavior (musl `siginterrupt.c`: read the action,
/// flip `SA_RESTART`, reinstall).
///
/// # Safety
///
/// Follows the nested-`sigaction` contract; invalid `sig` propagates
/// its -1/`EINVAL`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn siginterrupt(sig: c_int, flag: c_int) -> c_int {
    unsafe {
        let mut sa = Sigaction {
            handler: SIG_DFL,
            mask: [0; 16],
            flags: 0,
            restorer: 0,
        };
        sigaction(sig, core::ptr::null(), &mut sa);
        if flag != 0 {
            sa.flags &= !SA_RESTART;
        } else {
            sa.flags |= SA_RESTART;
        }
        sigaction(sig, &sa, core::ptr::null_mut())
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_int;

    use super::*;

    #[test]
    fn set_op_vectors() {
        unsafe {
            let mut set: sigset_t = [0xdead_beef; 16];
            assert_eq!(sigemptyset(&mut set), 0);
            assert_eq!(set, [0; 16]);
            assert_eq!(sigisemptyset(&set), 1);
            // Valid members stick; reserved/out-of-range fail.
            assert_eq!(sigaddset(&mut set, SIGUSR1), 0);
            assert_eq!(sigaddset(&mut set, 64), 0);
            assert_eq!(sigaddset(&mut set, 0), -1);
            assert_eq!(sigaddset(&mut set, 32), -1);
            assert_eq!(sigaddset(&mut set, 33), -1);
            assert_eq!(sigaddset(&mut set, 34), -1);
            assert_eq!(sigaddset(&mut set, 65), -1);
            assert_eq!(sigismember(&set, SIGUSR1), 1);
            assert_eq!(sigismember(&set, 64), 1);
            assert_eq!(sigismember(&set, SIGUSR2), 0);
            assert_eq!(sigismember(&set, 0), 0);
            assert_eq!(sigismember(&set, 200), 0);
            assert_eq!(sigisemptyset(&set), 0);
            assert_eq!(sigdelset(&mut set, SIGUSR1), 0);
            assert_eq!(sigismember(&set, SIGUSR1), 0);
            assert_eq!(sigdelset(&mut set, 32), -1);
            // Fill covers everything but the reserved three.
            assert_eq!(sigfillset(&mut set), 0);
            assert_eq!(sigismember(&set, 1), 1);
            assert_eq!(sigismember(&set, 31), 1);
            assert_eq!(sigismember(&set, 32), 0);
            assert_eq!(sigismember(&set, 33), 0);
            assert_eq!(sigismember(&set, 34), 0);
            assert_eq!(sigismember(&set, 35), 1);
            assert_eq!(sigismember(&set, 64), 1);
            // and/or over two disjoint halves.
            let mut a: sigset_t = [0; 16];
            let mut b: sigset_t = [0; 16];
            let mut out: sigset_t = [0; 16];
            assert_eq!(sigaddset(&mut a, SIGUSR1), 0);
            assert_eq!(sigaddset(&mut b, SIGUSR2), 0);
            assert_eq!(sigandset(&mut out, &a, &b), 0);
            assert_eq!(sigisemptyset(&out), 1);
            assert_eq!(sigorset(&mut out, &a, &b), 0);
            assert_eq!(sigismember(&out, SIGUSR1), 1);
            assert_eq!(sigismember(&out, SIGUSR2), 1);
            assert_eq!(sigandset(&mut out, &out, &a), 0);
            assert_eq!(sigismember(&out, SIGUSR1), 1);
            assert_eq!(sigismember(&out, SIGUSR2), 0);
        }
    }

    /// Install a handler for an RT signal, `raise` it, confirm delivery,
    /// then restore `SIG_DFL` (mask + disposition restored before any
    /// assert, so a failure cannot leak state into sibling tests).
    #[cfg(target_arch = "x86_64")]
    #[test]
    #[allow(function_casts_as_integer)]
    fn action_install_raise_restore_roundtrip() {
        use core::sync::atomic::{AtomicI32, Ordering};

        let _guard = crate::ldso::testlock::lock();
        const SIG_TEST: c_int = 44;
        static HIT: AtomicI32 = AtomicI32::new(0);
        unsafe extern "C" fn on_test(sig: c_int) {
            HIT.store(sig, Ordering::SeqCst);
        }

        unsafe {
            let mut saved: sigset_t = [0; 16];
            assert_eq!(sigprocmask(SIG_SETMASK, core::ptr::null(), &mut saved), 0);
            HIT.store(0, Ordering::SeqCst);
            let sa = Sigaction {
                handler: on_test as usize,
                mask: [0; 16],
                flags: 0,
                restorer: 0,
            };
            assert_eq!(sigaction(SIG_TEST, &sa, core::ptr::null_mut()), 0);
            assert_eq!(raise(SIG_TEST), 0);
            let hit = HIT.load(Ordering::SeqCst);
            let dfl = Sigaction {
                handler: SIG_DFL,
                mask: [0; 16],
                flags: 0,
                restorer: 0,
            };
            assert_eq!(sigaction(SIG_TEST, &dfl, core::ptr::null_mut()), 0);
            assert_eq!(sigprocmask(SIG_SETMASK, &saved, core::ptr::null_mut()), 0);
            assert_eq!(hit, SIG_TEST);
            // `signal`/`bsd_signal` roundtrip through the same path.
            let prev = signal(SIG_TEST, on_test as usize);
            assert_eq!(prev, SIG_DFL);
            assert_eq!(raise(SIG_TEST), 0);
            let hit2 = HIT.load(Ordering::SeqCst);
            assert_eq!(signal(SIG_TEST, SIG_DFL), on_test as usize);
            assert_eq!(hit2, SIG_TEST);
            assert_eq!(bsd_signal(SIG_TEST, SIG_IGN), SIG_DFL);
            assert_eq!(bsd_signal(SIG_TEST, SIG_DFL), SIG_IGN);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn procmask_save_restore_and_kill_self() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut saved: sigset_t = [0; 16];
            assert_eq!(sigprocmask(SIG_SETMASK, core::ptr::null(), &mut saved), 0);
            let mut blk: sigset_t = [0; 16];
            assert_eq!(sigemptyset(&mut blk), 0);
            assert_eq!(sigaddset(&mut blk, SIGUSR1), 0);
            assert_eq!(sigprocmask(SIG_BLOCK, &blk, core::ptr::null_mut()), 0);
            let mut cur: sigset_t = [0; 16];
            assert_eq!(sigprocmask(SIG_SETMASK, core::ptr::null(), &mut cur), 0);
            assert_eq!(sigismember(&cur, SIGUSR1), 1);
            assert_eq!(sigprocmask(SIG_SETMASK, &saved, core::ptr::null_mut()), 0);
            assert_eq!(kill(crate::unistd::getpid(), 0), 0);
            assert_eq!(killpg(-1, 0), -1);
        }
    }

    /// Block an RT signal, `raise` it, see it pending, dequeue it with
    /// `sigwaitinfo`, then restore the mask (never unblock-then-deliver
    /// under `SIG_DFL`, which would kill the test process).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn pending_after_block_then_dequeue() {
        let _guard = crate::ldso::testlock::lock();
        const SIG_TEST: c_int = 45;
        unsafe {
            let mut saved: sigset_t = [0; 16];
            assert_eq!(sigprocmask(SIG_SETMASK, core::ptr::null(), &mut saved), 0);
            let mut blk: sigset_t = [0; 16];
            assert_eq!(sigemptyset(&mut blk), 0);
            assert_eq!(sigaddset(&mut blk, SIG_TEST), 0);
            assert_eq!(sigprocmask(SIG_BLOCK, &blk, core::ptr::null_mut()), 0);
            assert_eq!(raise(SIG_TEST), 0);
            let mut pend: sigset_t = [0; 16];
            assert_eq!(sigpending(&mut pend), 0);
            let member = sigismember(&pend, SIG_TEST);
            let mut si = core::mem::zeroed::<Siginfo>();
            let got = sigwaitinfo(&blk, &mut si);
            let signo = si.si_signo;
            assert_eq!(sigprocmask(SIG_SETMASK, &saved, core::ptr::null_mut()), 0);
            assert_eq!(member, 1);
            assert!(got >= 0);
            assert_eq!(signo, SIG_TEST);
        }
    }
}
