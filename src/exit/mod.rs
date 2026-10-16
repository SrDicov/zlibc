//! Exit and termination (x86_64).
//!
//! Ports of musl `src/exit/_Exit.c`, `abort.c` (+`abort_lock.c`),
//! `exit.c`, `atexit.c`, `quick_exit.c`, `at_quick_exit.c`. Syscall
//! numbers from musl `arch/x86_64/bits/syscall.h.in`, signal constants
//! from musl `include/signal.h` + `arch/x86_64/bits/signal.h`. Raw
//! `syscallN` dispatch only (no errno wrappers), in particular on the
//! `abort` path.
//!
//! Test/binary split (same rule as `crate::start`/`crate::thread`): the
//! diverging names (`abort`, `_Exit`, `exit`, `quick_exit`, `_exit`)
//! exist only for real links (`not(test)`); the test binary shares its
//! address space with host std, which owns those names. The handler
//! lists are plain logic and stay testable.

use core::ffi::{c_int, c_void};
use core::mem::size_of;
#[cfg(all(not(test), target_arch = "x86_64"))]
use core::ptr::addr_of;
use core::ptr::{addr_of_mut, null_mut};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicUsize, Ordering};

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(all(not(test), target_arch = "x86_64"))]
const SYS_EXIT: usize = 60; // TODO: generate from arch bits/syscall.h
#[cfg(all(not(test), target_arch = "x86_64"))]
const SYS_RT_SIGACTION: usize = 13; // TODO: generate from arch bits/syscall.h
#[cfg(all(not(test), target_arch = "x86_64"))]
const SYS_RT_SIGPROCMASK: usize = 14; // TODO: generate from arch bits/syscall.h
#[cfg(all(not(test), target_arch = "x86_64"))]
const SYS_EXIT_GROUP: usize = 231; // TODO: generate from arch bits/syscall.h
#[cfg(all(not(test), target_arch = "x86_64"))]
const SYS_GETTID: usize = 186; // TODO: generate from arch bits/syscall.h
#[cfg(all(not(test), target_arch = "x86_64"))]
const SYS_TKILL: usize = 200; // TODO: generate from arch bits/syscall.h
                              // NOTE: syscall.h.in:200 is `tkill`, :234 is `tgkill`; musl abort.c
                              // calls `SYS_tkill`, so 200 is the faithful number here.

// ---- Signals (musl include/signal.h, arch/x86_64/bits/signal.h) -------------
#[cfg(all(not(test), target_arch = "x86_64"))]
const SIGABRT: c_int = 6; // bits/signal.h:122
#[cfg(all(not(test), target_arch = "x86_64"))]
const SIGKILL: c_int = 9; // bits/signal.h:126
#[cfg(all(not(test), target_arch = "x86_64"))]
const SIG_UNBLOCK: c_int = 1; // include/signal.h:31
/// `rt_sigaction`/`rt_sigprocmask` sigsetsize (`_NSIG/8`, _NSIG=65).
#[cfg(all(not(test), target_arch = "x86_64"))]
const NSIG_DIV8: usize = 8;

// ---- Locks ------------------------------------------------------------------
/// musl `LOCK`/`UNLOCK` over an `AtomicI32` (async-signal-safe; no MutexT).
// ponytail: pure spin, no futex sleep like musl lock.h; add it if contended atexit registration ever shows in profiles.
#[cfg(target_arch = "x86_64")]
fn spin_lock(l: &AtomicI32) {
    while l
        .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[cfg(target_arch = "x86_64")]
fn spin_unlock(l: &AtomicI32) {
    l.store(0, Ordering::SeqCst);
}

/// musl `exit.c:37` (`static volatile int exit_lock[1]`), as an atomic.
#[cfg(all(not(test), target_arch = "x86_64"))]
static EXIT_LOCK: AtomicI32 = AtomicI32::new(0);
/// musl `abort_lock.c:1` (`volatile int __abort_lock[1]`), as an atomic.
#[cfg(all(not(test), target_arch = "x86_64"))]
static ABORT_LOCK: AtomicI32 = AtomicI32::new(0);
/// musl `atexit.c:24` (`static volatile int lock[1]`).
#[cfg(target_arch = "x86_64")]
static ATEXIT_LOCK: AtomicI32 = AtomicI32::new(0);
/// musl `at_quick_exit.c:10` (`static volatile int lock[1]`).
#[cfg(target_arch = "x86_64")]
static QUICK_LOCK: AtomicI32 = AtomicI32::new(0);

// ---- atexit list (musl src/exit/atexit.c) ------------------------------------
/// At least 32 handlers register without malloc (atexit.c:13).
#[cfg(target_arch = "x86_64")]
const COUNT: usize = 32;

/// musl `struct fl` (atexit.c:15-20): one 32-slot block of the chain.
#[cfg(target_arch = "x86_64")]
struct Fl {
    next: *mut Fl,
    f: [Option<unsafe extern "C" fn(*mut c_void)>; COUNT],
    a: [*mut c_void; COUNT],
}

/// musl `static struct fl builtin` (atexit.c:20), zero-init, no weak
/// alias targets it so plain `.bss` is fine (see COMMON rule in docs).
#[cfg(target_arch = "x86_64")]
static mut BUILTIN: Fl = Fl {
    next: null_mut(),
    f: [None; COUNT],
    a: [null_mut(); COUNT],
};
/// musl `head` (atexit.c:20), deferred to `&BUILTIN` on first register.
#[cfg(target_arch = "x86_64")]
static HEAD: AtomicPtr<Fl> = AtomicPtr::new(null_mut());
/// musl `slot` (atexit.c:23).
#[cfg(target_arch = "x86_64")]
static SLOT: AtomicUsize = AtomicUsize::new(0);
/// musl `finished_atexit` (atexit.c:22): further registers return -1.
#[cfg(target_arch = "x86_64")]
static FINISHED: AtomicBool = AtomicBool::new(false);

/// musl `__funcs_on_exit` (atexit.c:27-42): run the chain LIFO,
/// unlocking around each call, then latch `FINISHED`.
#[cfg(target_arch = "x86_64")]
unsafe fn __funcs_on_exit() {
    unsafe {
        spin_lock(&ATEXIT_LOCK);
        loop {
            let head = HEAD.load(Ordering::SeqCst);
            if head.is_null() {
                break;
            }
            let slot = SLOT.load(Ordering::SeqCst);
            if slot == 0 {
                // Drained block (only reachable via reentrant register
                // + run); unlink exactly like the outer-for step.
                HEAD.store((*head).next, Ordering::SeqCst);
                SLOT.store(COUNT, Ordering::SeqCst);
                continue;
            }
            SLOT.store(slot - 1, Ordering::SeqCst);
            let func = (*head).f[slot - 1];
            let arg = (*head).a[slot - 1];
            if slot - 1 == 0 {
                HEAD.store((*head).next, Ordering::SeqCst);
                SLOT.store(COUNT, Ordering::SeqCst);
            }
            spin_unlock(&ATEXIT_LOCK);
            if let Some(g) = func {
                g(arg);
            }
            spin_lock(&ATEXIT_LOCK);
        }
        // Unlock-first pattern per musl: a global dtor calling atexit
        // past this point must get -1, not a deadlock.
        FINISHED.store(true, Ordering::SeqCst);
        spin_unlock(&ATEXIT_LOCK);
    }
}

/// musl `__cxa_finalize` (atexit.c:44-46): empty stub (no dlclose yet).
///
/// # Safety
///
/// Never dereferences `dso`; always safe to call.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __cxa_finalize(_dso: *mut c_void) {}

/// musl `__cxa_atexit` (atexit.c:48-81): `dso` ignored (no dlclose yet).
///
/// # Safety
///
/// `func` must be callable with `arg` when exit runs (or `None`).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __cxa_atexit(
    func: Option<unsafe extern "C" fn(*mut c_void)>,
    arg: *mut c_void,
    _dso: *mut c_void,
) -> c_int {
    unsafe {
        spin_lock(&ATEXIT_LOCK);
        if FINISHED.load(Ordering::SeqCst) {
            spin_unlock(&ATEXIT_LOCK);
            return -1;
        }
        let mut head = HEAD.load(Ordering::SeqCst);
        if head.is_null() {
            head = addr_of_mut!(BUILTIN);
            HEAD.store(head, Ordering::SeqCst);
        }
        let mut slot = SLOT.load(Ordering::SeqCst);
        if slot == COUNT {
            let fresh = crate::malloc::calloc(size_of::<Fl>(), 1) as *mut Fl;
            if fresh.is_null() {
                spin_unlock(&ATEXIT_LOCK);
                return -1;
            }
            (*fresh).next = head;
            head = fresh;
            HEAD.store(head, Ordering::SeqCst);
            slot = 0;
        }
        (*head).f[slot] = func;
        (*head).a[slot] = arg;
        SLOT.store(slot + 1, Ordering::SeqCst);
        spin_unlock(&ATEXIT_LOCK);
        0
    }
}

/// Adapter so `atexit(void (*)(void))` shares the `(void *)` list.
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn call_adapter(p: *mut c_void) {
    unsafe {
        let f: unsafe extern "C" fn() = core::mem::transmute(p);
        f();
    }
}

/// musl `atexit` (atexit.c:88-91): wrap `f` with a null arg, like musl.
///
/// # Safety
///
/// `f` must be callable with no arguments when exit runs (or `None`).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn atexit(f: Option<unsafe extern "C" fn()>) -> c_int {
    let arg = match f {
        Some(g) => g as *mut c_void,
        None => null_mut(),
    };
    unsafe { __cxa_atexit(Some(call_adapter), arg, null_mut()) }
}

// ---- at_quick_exit list (musl src/exit/at_quick_exit.c) ---------------------
/// musl `static void (*funcs[COUNT])(void)` (at_quick_exit.c:8).
#[cfg(target_arch = "x86_64")]
static mut QUICK: [Option<unsafe extern "C" fn()>; COUNT] = [None; COUNT];
/// musl `count` (at_quick_exit.c:9).
#[cfg(target_arch = "x86_64")]
static QUICK_N: AtomicUsize = AtomicUsize::new(0);

/// musl `__funcs_on_quick_exit` (at_quick_exit.c:13-23): drain LIFO.
/// Unlike `exit`'s runner this leaves no latch (musl sets none), so the
/// list is reusable after a drain; the trailing unlock (musl falls off
/// the end still holding the lock, unobservable before `_Exit`) keeps
/// it so under test.
#[cfg(target_arch = "x86_64")]
unsafe fn __funcs_on_quick_exit() {
    unsafe {
        spin_lock(&QUICK_LOCK);
        loop {
            let n = QUICK_N.load(Ordering::SeqCst);
            if n == 0 {
                break;
            }
            QUICK_N.store(n - 1, Ordering::SeqCst);
            let func = QUICK[n - 1];
            spin_unlock(&QUICK_LOCK);
            if let Some(g) = func {
                g();
            }
            spin_lock(&QUICK_LOCK);
        }
        spin_unlock(&QUICK_LOCK);
    }
}

/// musl `at_quick_exit` (at_quick_exit.c:25-33): -1 when the 32 static
/// slots are full.
///
/// # Safety
///
/// `f` must be callable with no arguments when quick_exit runs.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn at_quick_exit(f: Option<unsafe extern "C" fn()>) -> c_int {
    unsafe {
        spin_lock(&QUICK_LOCK);
        let n = QUICK_N.load(Ordering::SeqCst);
        if n == COUNT {
            spin_unlock(&QUICK_LOCK);
            return -1;
        }
        QUICK[n] = f;
        QUICK_N.store(n + 1, Ordering::SeqCst);
        spin_unlock(&QUICK_LOCK);
        0
    }
}

// ---- Process termination ----------------------------------------------------
// Not-yet-owned exit hooks, same extern shape `crate::start` declares
// today (`__funcs_on_exit` is NOT here: this file defines it above).
#[cfg(all(not(test), target_arch = "x86_64"))]
extern "C" {
    fn __libc_exit_fini();
    fn __stdio_exit();
}

/// musl `_Exit` (src/exit/_Exit.c:4-7): `SYS_exit_group`, falling back
/// to `SYS_exit` forever. Raw dispatch, no errno translation.
///
/// # Safety
///
/// Diverges unconditionally; never returns.
#[cfg(all(not(test), target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn _Exit(code: c_int) -> ! {
    unsafe { crate::syscall::syscall1(SYS_EXIT_GROUP, code as usize) };
    loop {
        unsafe { crate::syscall::syscall1(SYS_EXIT, code as usize) };
    }
}

#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(_exit, _Exit);

/// musl `exit` (src/exit/exit.c:30-47): recursion trap, then
/// `__funcs_on_exit` → `__libc_exit_fini` → `__stdio_exit` → `_Exit`,
/// in exactly this order. No `fflush` here: exit-time full flush lives
/// in the stdio wave's `__stdio_exit`, not in `exit`.
///
/// # Safety
///
/// Diverges unconditionally (runs handlers, then `_Exit`); never returns.
#[cfg(all(not(test), target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn exit(code: c_int) -> ! {
    if EXIT_LOCK
        .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        // Trap: musl `a_crash()` equivalent for recursive `exit`.
        unsafe {
            core::arch::asm!("ud2", options(noreturn));
        }
    }
    unsafe { __funcs_on_exit() };
    unsafe { __libc_exit_fini() };
    unsafe { __stdio_exit() };
    unsafe { _Exit(code) }
}

/// musl `quick_exit` (src/exit/quick_exit.c:7-11): quick handlers only
/// (atexit handlers do NOT run), then `_Exit`.
///
/// # Safety
///
/// Diverges unconditionally; never returns.
#[cfg(all(not(test), target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn quick_exit(code: c_int) -> ! {
    unsafe { __funcs_on_quick_exit() };
    unsafe { _Exit(code) }
}

/// musl `struct k_sigaction` (src/internal/ksigaction.h:6-16, x86_64
/// has `SA_RESTORER` so the `restorer` arm applies): the
/// `rt_sigaction` trap argument for resetting `SIGABRT` to `SIG_DFL`.
#[cfg(all(not(test), target_arch = "x86_64"))]
#[repr(C)]
struct KSigaction {
    handler: usize,
    flags: u64,
    restorer: usize,
    mask: [u32; 2],
}

/// musl `abort` (src/exit/abort.c:9-30), adapted: `raise(3)` does not
/// exist yet, so the raises are raw `tkill(gettid())`. No malloc, stdio,
/// or errno wrappers anywhere on this path.
///
/// # Safety
///
/// Diverges unconditionally (terminates by signal or `_Exit`); never returns.
#[cfg(all(not(test), target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn abort() -> ! {
    unsafe {
        let tid = crate::syscall::syscall0(SYS_GETTID) as usize;
        // First attempt with the current disposition (musl: raise).
        crate::syscall::syscall2(SYS_TKILL, tid, SIGABRT as usize);
        // Handler returned, or SIGABRT was blocked/ignored: lock out
        // new handlers, reset to default, re-raise.
        spin_lock(&ABORT_LOCK);
        let reset = KSigaction {
            handler: 0, // SIG_DFL (include/signal.h:284)
            flags: 0,
            restorer: 0,
            mask: [0, 0],
        };
        crate::syscall::syscall4(
            SYS_RT_SIGACTION,
            SIGABRT as usize,
            addr_of!(reset) as usize,
            0,
            NSIG_DIV8,
        );
        crate::syscall::syscall2(SYS_TKILL, tid, SIGABRT as usize);
        let unblock: u64 = 1 << ((SIGABRT as u64) - 1);
        crate::syscall::syscall4(
            SYS_RT_SIGPROCMASK,
            SIG_UNBLOCK as usize,
            addr_of!(unblock) as usize,
            0,
            NSIG_DIV8,
        );
        // Unreachable unless the traps above were caught: crash, then
        // SIGKILL, then 127 (musl: a_crash + raise + _Exit). Plain
        // `ud2` (no `noreturn`: a caught trap falls through, like musl).
        core::arch::asm!("ud2");
        crate::syscall::syscall2(SYS_TKILL, tid, SIGKILL as usize);
        _Exit(127)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        __cxa_atexit, __funcs_on_exit, __funcs_on_quick_exit, addr_of_mut, at_quick_exit, atexit,
        c_void, null_mut, AtomicI32, AtomicUsize, Ordering, BUILTIN, HEAD, QUICK_N,
    };

    /// Serializes the stateful tests below (libtest runs them on
    /// parallel threads; the handler lists are process-global).
    static TEST_LOCK: AtomicI32 = AtomicI32::new(0);
    struct TGuard;
    impl Drop for TGuard {
        fn drop(&mut self) {
            TEST_LOCK.store(0, Ordering::SeqCst);
        }
    }
    fn test_lock() -> TGuard {
        while TEST_LOCK
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            core::hint::spin_loop();
        }
        TGuard
    }

    // ---- exit-list log ------------------------------------------------------
    static LOG_N: AtomicUsize = AtomicUsize::new(0);
    static mut LOG: [u64; 64] = [0; 64];
    fn push(id: u64) {
        let n = LOG_N.load(Ordering::SeqCst);
        assert!(n < 64, "log overflow");
        unsafe { LOG[n] = id };
        LOG_N.store(n + 1, Ordering::SeqCst);
    }
    unsafe extern "C" fn rec(arg: *mut c_void) {
        push(arg as u64);
    }
    const SENTINEL: u64 = u64::MAX;
    unsafe extern "C" fn plain_rec() {
        push(SENTINEL);
    }

    // ---- quick-list log -----------------------------------------------------
    static QLOG_N: AtomicUsize = AtomicUsize::new(0);
    static mut QLOG: [u32; 40] = [0; 40];
    fn qpush(id: u32) {
        let n = QLOG_N.load(Ordering::SeqCst);
        assert!(n < 40, "qlog overflow");
        unsafe { QLOG[n] = id };
        QLOG_N.store(n + 1, Ordering::SeqCst);
    }
    unsafe extern "C" fn qa() {
        qpush(1);
    }
    unsafe extern "C" fn qb() {
        qpush(2);
    }
    unsafe extern "C" fn qc() {
        qpush(3);
    }
    unsafe extern "C" fn qnoop() {}
    unsafe extern "C" fn unused() {}
    // Private quick-probe for the lifecycle test (its own counter: the
    // shared QLOG belongs to `quick_list_lifo_and_reuse`).
    static QL2_N: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn qrec2() {
        QL2_N.store(QL2_N.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
    }

    /// Full exit-list lifecycle in one serial test (the finished-flag
    /// latches permanently, so it cannot span tests): quick/exit list
    /// independence, builtin-32 without malloc, heap chain past 32,
    /// LIFO order, -1 after finish.
    #[test]
    fn exit_list_lifecycle() {
        let _g = test_lock();
        unsafe {
            // atexit wrapper takes the (void) shape; runs last (LIFO).
            assert_eq!(atexit(Some(plain_rec)), 0);
            // Independence: drain the quick list, exit list untouched.
            assert_eq!(__cxa_atexit(Some(rec), 100 as *mut c_void, null_mut()), 0);
            assert_eq!(at_quick_exit(Some(qrec2)), 0);
            __funcs_on_quick_exit();
            assert_eq!(QL2_N.load(Ordering::SeqCst), 1);
            assert_eq!(LOG_N.load(Ordering::SeqCst), 0);
            // Still on the static block: no malloc for the common case.
            assert_eq!(HEAD.load(Ordering::SeqCst), addr_of_mut!(BUILTIN));
            for id in 101u64..=130u64 {
                assert_eq!(__cxa_atexit(Some(rec), id as *mut c_void, null_mut()), 0);
            }
            assert_eq!(HEAD.load(Ordering::SeqCst), addr_of_mut!(BUILTIN));
            // 33rd registration spills onto a malloc'd block.
            assert_eq!(__cxa_atexit(Some(rec), 131 as *mut c_void, null_mut()), 0);
            assert_ne!(HEAD.load(Ordering::SeqCst), addr_of_mut!(BUILTIN));
            assert_eq!(__cxa_atexit(Some(rec), 200 as *mut c_void, null_mut()), 0);
            for id in 201u64..=207u64 {
                assert_eq!(__cxa_atexit(Some(rec), id as *mut c_void, null_mut()), 0);
            }
            __funcs_on_exit();
            // LIFO: 207..=201, 200, 131..=101, 100, SENTINEL (41 total).
            assert_eq!(LOG_N.load(Ordering::SeqCst), 41);
            let mut i = 0;
            for want in (201u64..=207u64).rev() {
                assert_eq!(LOG[i], want, "slot {i}");
                i += 1;
            }
            assert_eq!(LOG[i], 200);
            i += 1;
            for want in (101u64..=131u64).rev() {
                assert_eq!(LOG[i], want, "slot {i}");
                i += 1;
            }
            assert_eq!(LOG[i], 100);
            assert_eq!(LOG[i + 1], SENTINEL);
            // Finished gate: every further register fails.
            assert_eq!(atexit(Some(unused)), -1);
            assert_eq!(__cxa_atexit(Some(rec), null_mut(), null_mut()), -1);
        }
    }

    /// Quick list is independent and reusable: LIFO drain, -1 at cap,
    /// re-register works after a drain (no finished latch, like musl).
    #[test]
    fn quick_list_lifo_and_reuse() {
        let _g = test_lock();
        unsafe {
            assert_eq!(at_quick_exit(Some(qa)), 0);
            assert_eq!(at_quick_exit(Some(qb)), 0);
            assert_eq!(at_quick_exit(Some(qc)), 0);
            __funcs_on_quick_exit();
            assert_eq!(QLOG_N.load(Ordering::SeqCst), 3);
            assert_eq!((QLOG[0], QLOG[1], QLOG[2]), (3, 2, 1));
            assert_eq!(QUICK_N.load(Ordering::SeqCst), 0);
            for _ in 0..32 {
                assert_eq!(at_quick_exit(Some(qnoop)), 0);
            }
            assert_eq!(at_quick_exit(Some(qnoop)), -1);
            __funcs_on_quick_exit();
            assert_eq!(QUICK_N.load(Ordering::SeqCst), 0);
            assert_eq!(at_quick_exit(Some(qa)), 0);
            __funcs_on_quick_exit();
            assert_eq!(QLOG_N.load(Ordering::SeqCst), 4);
            assert_eq!(QLOG[3], 1);
        }
    }
}
