//! Thread registry and synchronous cross-thread calls (x86_64).
//!
//! Clean-room mirror of musl `src/thread/synccall.c` (the `__synccall`
//! protocol) plus the registry musl keeps behind `__tl_lock` with the
//! `next`/`prev` ring (`src/thread/pthread_create.c:372-376`). Signal and
//! syscall numbers from `src/internal/pthread_impl.h:131` (`SIGSYNCCALL`)
//! and `arch/x86_64/bits/syscall.h.in` (`rt_sigaction`, `rt_sigprocmask`,
//! `tkill`). Re-derived, not copied.
//!
//! Design: the registry (head + futex lock) lives here, not in `create.rs`,
//! which only calls `register_thread` after a successful `clone` and
//! `unregister_thread` at the top of both `thread_exit` paths.
//! `__synccall` blocks `SIGSYNCCALL`, takes the registry lock, `tkill`s
//! every other registered thread, runs the callback on each (serialized)
//! plus the caller, then releases the wave.
//!
//! The handler (`synccall_handler`) is AS-safe by construction: atomic ops
//! and raw futex waits only — no allocation, no locks, no panics. It must
//! stay that way; anything else hangs or corrupts the process.
//!
//! shortcut(main thread): the main thread never registers (its TCB comes
//! from `ensure_main_tp`, which this module may not hook), so a wave
//! started elsewhere misses it as a *target*. Main-as-caller is exact (it
//! always runs the callback itself). Wiring main registration into boot is
//! a later wave's job.
//!
//! shortcut(no cancel): musl also disables cancellation around the wave
//! (synccall.c:61); there is no cancellation yet, so nothing to disable.

use core::ffi::{c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use crate::futex::{futex_wait_private, futex_wake_private};
use crate::syscall::{syscall2, syscall4};

use super::tls::get_tp;
use super::{Thread, EAGAIN};

/// musl `src/internal/pthread_impl.h:131`.
const SIGSYNCCALL: c_int = 34;

/// musl `arch/x86_64/bits/syscall.h.in` (line cited per constant).
const SYS_RT_SIGACTION: usize = 13; // syscall.h.in:14
const SYS_RT_SIGPROCMASK: usize = 14; // syscall.h.in:15
const SYS_TKILL: usize = 200; // syscall.h.in:201

// Signal constants (musl `include/signal.h:30-32,285`,
// `arch/x86_64/bits/signal.h:109-110`).
const SIG_BLOCK: usize = 0;
const SIG_SETMASK: usize = 2;
const SIG_IGN: usize = 1;
const SA_ONSTACK: usize = 0x08000000;
const SA_RESTART: usize = 0x10000000;

/// Kernel sigset size for the raw calls (`_NSIG/8`, sigaction.c:54).
const K_SIGSET_LEN: usize = 8;

/// musl `void (*)(void *)` callback (`src/thread/synccall.c:13`).
pub type SynccallFn = unsafe extern "C" fn(*mut c_void);

// musl marks `__synccall` hidden (src/internal/libc.h:55): keep it out
// of the dynamic symbol table in real links. Link-inert in tests.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(".hidden __synccall");

/// Raw `rt_sigaction` argument (musl `arch/x86_64/ksigaction.h:3-8`):
/// handler, flags, restorer, then an 8-byte kernel mask (`_NSIG/8`).
/// No `SA_RESTORER`: on x86_64 the kernel falls back to the vDSO
/// `__kernel_rt_sigreturn` trampoline, so no userspace restorer is needed.
#[repr(C)]
struct KernelSigaction {
    handler: usize,
    flags: usize,
    restorer: usize,
    mask: u64,
}

/// Registry head: one node of the `head.next`/`prev` ring, or null when
/// empty. Touched only with `REG_LOCK` held (see `register_thread`).
static mut REG_HEAD: *mut Thread = null_mut();

/// Registry lock word: 0 free, 1 held; waiters sleep in the private futex
/// (the `__tl_lock` role, synccall.c:59).
static REG_LOCK: AtomicI32 = AtomicI32::new(0);

/// Address of a lock/semaphore word for the raw futex calls (`AtomicI32`
/// and `c_int` share size and alignment; all access stays atomic).
fn futex_addr(w: &AtomicI32) -> *mut c_int {
    w as *const AtomicI32 as *mut c_int
}

/// Take the registry lock (one optimistic CAS, then sleep while held).
fn reg_lock() {
    unsafe {
        loop {
            match REG_LOCK.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return,
                // Lost the race: sleep until the holder wakes us. Any
                // wakeup (spurious, or EINTR from a caught wave signal)
                // just re-checks the word, so this is signal-safe.
                Err(_) => {
                    let _ = futex_wait_private(futex_addr(&REG_LOCK), 1);
                }
            }
        }
    }
}

/// Release the registry lock.
fn reg_unlock() {
    REG_LOCK.store(0, Ordering::SeqCst);
    unsafe {
        let _ = futex_wake_private(futex_addr(&REG_LOCK), 1);
    }
}

/// Wave semaphores (the `target_sem`/`caller_sem`/`exit_sem` roles,
/// synccall.c:14): counting sleepers from atomics + private futex. Zeroed
/// under the registry lock before each wave; the handler touches them only
/// mid-wave, so no wave ever observes a stale count.
static CALLER_SEM: AtomicI32 = AtomicI32::new(0);
static TARGET_SEM: AtomicI32 = AtomicI32::new(0);
static EXIT_SEM: AtomicI32 = AtomicI32::new(0);

/// Record one permit, waking a sleeper when there is one.
fn sem_post(sem: &AtomicI32) {
    sem.fetch_add(1, Ordering::SeqCst);
    unsafe {
        let _ = futex_wake_private(futex_addr(sem), 1);
    }
}

/// Take one permit, sleeping while the count is empty. Every wakeup just
/// re-checks the count — no failure mode, no panic (handler-safe).
fn sem_wait(sem: &AtomicI32) {
    unsafe {
        loop {
            let v = sem.load(Ordering::SeqCst);
            if v > 0 {
                if sem
                    .compare_exchange(v, v - 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    return;
                }
            } else {
                let _ = futex_wait_private(futex_addr(sem), v);
            }
        }
    }
}

/// Thread currently being caught (0 = none); the handler joins the wave
/// only when its own TID matches (synccall.c:22).
static TARGET_TID: AtomicI32 = AtomicI32::new(0);

/// Wave callback + context as address words. Atomics are the only
/// handler-visible channel — the handler takes no locks, by design.
static WAVE_FN: AtomicUsize = AtomicUsize::new(0);
static WAVE_CTX: AtomicUsize = AtomicUsize::new(0);

/// Abort callback: runs in place of the wave when a `tkill` fails
/// mid-catch (synccall.c:87 assigns `callback = func = dummy`).
///
/// # Safety
///
/// Callable in any thread context; touches nothing.
unsafe extern "C" fn dummy_wave(_ctx: *mut c_void) {}

/// Link a new thread into the registry ring.
///
/// shortcut(no start handshake, like C1): the child may already be dead
/// when this runs — then its `unregister` no-op'd on the absent node and
/// the joiner is about to free it, so a `tid == 0` node (the kernel clears
/// the `CHILD_CLEARTID` word at death) is skipped, never listed. A child
/// dying *during* the splice still unregisters normally (it needs this
/// same lock, so it unlinks after us).
///
/// # Safety
///
/// `td` must be a `Thread` whose `clone` just succeeded (kernel-written
/// `tid`, TLS carved) and which is not already registered. The caller must
/// hold no locks; this takes `REG_LOCK` (briefly; may sleep mid-wave).
pub(crate) unsafe fn register_thread(td: *mut Thread) {
    unsafe {
        reg_lock();
        // Fully dead before we got here (see shortcut above): list nothing.
        if core::ptr::addr_of!((*td).tid).read() == 0 {
            reg_unlock();
            return;
        }
        let head = core::ptr::addr_of_mut!(REG_HEAD).read();
        if head.is_null() {
            (*td).head.next = td.cast();
            (*td).head.prev = td.cast();
            core::ptr::addr_of_mut!(REG_HEAD).write(td);
        } else {
            // Insert after head, fixing both back-links.
            let next = (*head).head.next;
            (*td).head.next = next;
            (*td).head.prev = head.cast();
            (*head).head.next = td.cast();
            (*next.cast::<Thread>()).head.prev = td.cast();
        }
        reg_unlock();
    }
}

/// Cut `td` out of the ring, moving the head when it points at `td`.
/// The caller must hold `REG_LOCK` and have established that `td` is
/// listed. Never writes `td` itself: a pruned node may be dead memory —
/// only its neighbors (listed, therefore live) are written.
///
/// # Safety
///
/// Same contract as [`register_thread`]: caller holds `REG_LOCK`, `td`
/// listed; neighbors live.
unsafe fn cut_locked(td: *mut Thread) {
    unsafe {
        let next = (*td).head.next;
        let prev = (*td).head.prev;
        (*prev.cast::<Thread>()).head.next = next;
        (*next.cast::<Thread>()).head.prev = prev;
        if td == core::ptr::addr_of_mut!(REG_HEAD).read() {
            let rest = if next == td.cast() {
                null_mut()
            } else {
                next.cast()
            };
            core::ptr::addr_of_mut!(REG_HEAD).write(rest);
        }
    }
}

/// Unlink a dying thread from the registry ring.
///
/// # Safety
///
/// `td` must be the calling thread's live `Thread`, or an already-gone one
/// (absence is a no-op: the child may run before its parent registers).
/// Restores the self-links `copy_tls` installed, so no walk can follow a
/// stale pointer. Must run *before* death is visible — joinable: ahead of
/// the `DT_EXITED` store; detached: ahead of `__unmapself` — because the
/// joiner may free this memory the moment death publishes.
pub(crate) unsafe fn unregister_thread(td: *mut Thread) {
    unsafe {
        reg_lock();
        let head = core::ptr::addr_of_mut!(REG_HEAD).read();
        if !head.is_null() {
            let mut cur = head;
            loop {
                if cur == td {
                    cut_locked(cur);
                    (*td).head.next = td.cast();
                    (*td).head.prev = td.cast();
                    break;
                }
                cur = (*cur).head.next.cast::<Thread>();
                if cur == head {
                    break;
                }
            }
        }
        reg_unlock();
    }
}

/// `SIGSYNCCALL` handler (synccall.c:20-42): rendezvous with the caller
/// through the wave semaphores, run the wave callback, rendezvous out.
/// AS-safe: atomic ops + raw futex waits only. No locks (the caller holds
/// the registry lock for the whole wave), no allocation, no panics — any
/// of those here hangs or corrupts the process. `errno` is saved and
/// restored like musl, since the callback may run syscalls.
///
/// # Safety
///
/// Runs only as a wave signal handler (installed by [`__synccall`]);
/// never call directly.
unsafe extern "C" fn synccall_handler(_sig: c_int) {
    unsafe {
        // DIAG ONLY (revert): prove handler entry with one raw byte.
        static DIAG_H: u8 = b'H';
        let _ = crate::syscall::syscall3(
            crate::syscall::SYS_WRITE,
            2,
            core::ptr::addr_of!(DIAG_H) as usize,
            1,
        );
        // Not our catch (stray signal, or the wave already moved on): do
        // nothing. A null TP (boot, no thread yet) also bails — it must
        // never be dereferenced.
        let tp = get_tp() as *mut Thread;
        if tp.is_null() {
            return;
        }
        if core::ptr::addr_of!((*tp).tid).read() != TARGET_TID.load(Ordering::SeqCst) {
            return;
        }
        let saved_errno = *crate::errno::__errno_location();
        // Tell the caller we arrived, then wait for our turn to run.
        sem_post(&CALLER_SEM);
        sem_wait(&TARGET_SEM);
        let bits = WAVE_FN.load(Ordering::SeqCst);
        let f: SynccallFn = core::mem::transmute::<usize, SynccallFn>(bits);
        f(WAVE_CTX.load(Ordering::SeqCst) as *mut c_void);
        // Tell the caller we ran, then wait for release.
        sem_post(&CALLER_SEM);
        sem_wait(&EXIT_SEM);
        // Tell the caller we are leaving; the wave state may be torn down.
        sem_post(&CALLER_SEM);
        *crate::errno::__errno_location() = saved_errno;
    }
}

/// Run `func(ctx)` on every live thread — each target serialized, then the
/// caller — per musl `src/thread/synccall.c:44-122`.
///
/// Blocks `SIGSYNCCALL` for the caller, installs the wave handler,
/// `tkill`s each registered thread except the caller, walks every caught
/// thread through the callback, runs it on the caller too, and releases
/// the wave. A failed `tkill` aborts the wave (caught threads run the
/// dummy, like synccall.c:87, and the dead node is pruned); with no other
/// threads the callback just runs once on the caller.
///
/// shortcut(no app-signal block): musl blocks app signals before taking
/// its lock (synccall.c:58-60); only the wave signal is blocked here, so
/// an app handler interrupting the wave must not call back into thread
/// management (it would deadlock on the registry lock, musl's reason for
/// the two-step block). Full signal plumbing is a later wave's job.
///
/// # Safety
///
/// `func` must be non-null and safe to run on every live thread with `ctx`
/// (targets run it inside a signal handler — atomics and raw syscalls
/// only, never locks or allocation, and never a nested `__synccall`: the
/// registry lock is not reentrant); `ctx` must stay valid until this
/// returns. Thread creation/exit may proceed concurrently (both take the
/// registry lock, which this holds for the whole wave).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __synccall(func: Option<SynccallFn>, ctx: *mut c_void) {
    unsafe {
        // synccall.c:58: block the wave signal before taking the lock.
        let mut oldmask: u64 = 0;
        let block = 1u64 << (SIGSYNCCALL as u64 - 1);
        let _ = syscall4(
            SYS_RT_SIGPROCMASK,
            SIG_BLOCK,
            core::ptr::addr_of!(block) as usize,
            core::ptr::addr_of_mut!(oldmask) as usize,
            K_SIGSET_LEN,
        );
        reg_lock();
        CALLER_SEM.store(0, Ordering::SeqCst);
        TARGET_SEM.store(0, Ordering::SeqCst);
        EXIT_SEM.store(0, Ordering::SeqCst);
        TARGET_TID.store(0, Ordering::SeqCst);
        let mut run = func.unwrap_or(dummy_wave);
        WAVE_FN.store(run as *const () as usize, Ordering::SeqCst);
        WAVE_CTX.store(ctx as usize, Ordering::SeqCst);

        // synccall.c:76-77: catch-all handler mask, restart + onstack.
        let wave = KernelSigaction {
            handler: synccall_handler as *const () as usize,
            flags: SA_ONSTACK | SA_RESTART,
            restorer: 0,
            mask: !0,
        };
        let _ = syscall4(
            SYS_RT_SIGACTION,
            SIGSYNCCALL as usize,
            core::ptr::addr_of!(wave) as usize,
            0,
            K_SIGSET_LEN,
        );

        // synccall.c:80-93: signal every thread but the caller. The node
        // derefs are safe: removal happens only under this lock, and every
        // listed thread unregisters before dying (the `thread_exit`
        // hooks); a fully dead node never gets listed (see
        // `register_thread`), and an `ESRCH` node is pruned below.
        let caller = get_tp();
        let mut count = 0;
        let head = core::ptr::addr_of_mut!(REG_HEAD).read();
        if !head.is_null() {
            let mut td = head;
            loop {
                let tid = core::ptr::addr_of!((*td).tid).read();
                if td as usize != caller && tid != 0 {
                    TARGET_TID.store(tid, Ordering::SeqCst);
                    let mut r;
                    loop {
                        r = syscall2(SYS_TKILL, tid as usize, SIGSYNCCALL as usize);
                        if r != -(EAGAIN as isize) {
                            break;
                        }
                    }
                    if r != 0 {
                        // synccall.c:83-89: a dead target aborts the wave;
                        // caught threads run out the dummy instead. Prune
                        // the stale node while the lock is held.
                        run = dummy_wave;
                        WAVE_FN.store(run as *const () as usize, Ordering::SeqCst);
                        cut_locked(td);
                        break;
                    }
                    sem_wait(&CALLER_SEM);
                    count += 1;
                }
                td = (*td).head.next.cast::<Thread>();
                if td == head {
                    break;
                }
            }
        }
        TARGET_TID.store(0, Ordering::SeqCst);

        // synccall.c:97-100: run each caught thread through the callback.
        // The caller advances only after the current target confirms, so a
        // late-delivered signal can never strand this wait: confirmation
        // strictly precedes each step.
        let mut i = 0;
        while i < count {
            sem_post(&TARGET_SEM);
            sem_wait(&CALLER_SEM);
            i += 1;
        }

        // synccall.c:102-103: ignore the wave signal from here on.
        let ignore = KernelSigaction {
            handler: SIG_IGN,
            flags: 0,
            restorer: 0,
            mask: 0,
        };
        let _ = syscall4(
            SYS_RT_SIGACTION,
            SIGSYNCCALL as usize,
            core::ptr::addr_of!(ignore) as usize,
            0,
            K_SIGSET_LEN,
        );

        // synccall.c:105-106: the caller always runs the callback too.
        run(ctx);

        // synccall.c:110-113: release the wave only after every thread,
        // caller included, has returned from the callback.
        let mut j = 0;
        while j < count {
            sem_post(&EXIT_SEM);
            j += 1;
        }
        let mut k = 0;
        while k < count {
            sem_wait(&CALLER_SEM);
            k += 1;
        }

        let _ = syscall4(
            SYS_RT_SIGPROCMASK,
            SIG_SETMASK,
            core::ptr::addr_of!(oldmask) as usize,
            0,
            K_SIGSET_LEN,
        );
        reg_unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::super::create::{__pthread_create, __pthread_join};
    use super::super::tls::ensure_main_tp;
    use super::*;
    use crate::abi::PthreadT;
    use core::sync::atomic::AtomicU32;

    static RUNS: AtomicU32 = AtomicU32::new(0);
    static READY: AtomicU32 = AtomicU32::new(0);
    static DONE: AtomicU32 = AtomicU32::new(0);

    /// Wave callback: one atomic increment through the context pointer.
    /// Pure atomics, no TLS or host calls — targets run this inside the
    /// wave signal handler on their own stacks (same discipline as the
    /// `sum_routine` child in `create.rs` tests).
    unsafe extern "C" fn count_runs(ctx: *mut c_void) {
        unsafe {
            (*ctx.cast::<AtomicU32>()).fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Child: announce liveness, then spin until the parent releases us.
    /// Cannot exit early, so the wave always finds live targets.
    unsafe extern "C" fn spin_child(_arg: *mut c_void) -> *mut c_void {
        READY.fetch_add(1, Ordering::SeqCst);
        while DONE.load(Ordering::SeqCst) == 0 {
            core::hint::spin_loop();
        }
        null_mut()
    }

    static PROBE_HIT: AtomicU32 = AtomicU32::new(0);

    /// Trivial wave-independent handler for the delivery probe below.
    ///
    /// # Safety
    ///
    /// Runs only as a signal handler; touches one static counter.
    unsafe extern "C" fn probe_handler(_sig: c_int) {
        PROBE_HIT.store(1, Ordering::SeqCst);
    }

    /// Delivery probe (diagnostic ladder step 1): a trivial handler
    /// installed through OUR `KernelSigaction` path for an otherwise
    /// unused RT signal must run when we tkill ourselves. Minimal flags
    /// (no ONSTACK, empty mask) to isolate install/delivery/entry from
    /// wave logic. Bounded spin: a hang becomes a message, never a CI
    /// timeout. If this passes and the wave still hangs, the fault is in
    /// wave protocol, not delivery.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn signal_delivery_runs_handler() {
        use crate::syscall::{syscall0, syscall2, syscall4};
        const SIG_PROBE: c_int = 35; // SIGRTMIN+3, unused anywhere else
        const SYS_GETTID: usize = 186; // TODO: share with sync.rs
        unsafe {
            let act = KernelSigaction {
                handler: probe_handler as *const () as usize,
                flags: 0,
                restorer: 0,
                mask: 0,
            };
            let r = syscall4(
                SYS_RT_SIGACTION,
                SIG_PROBE as usize,
                core::ptr::addr_of!(act) as usize,
                0,
                K_SIGSET_LEN,
            );
            assert_eq!(r, 0, "rt_sigaction install failed: {r}");
            let tid = syscall0(SYS_GETTID);
            PROBE_HIT.store(0, Ordering::SeqCst);
            let r = syscall2(SYS_TKILL, tid as usize, SIG_PROBE as usize);
            assert_eq!(r, 0, "tkill self failed: {r}");
            let mut spins = 0u32;
            while PROBE_HIT.load(Ordering::SeqCst) == 0 && spins < 10_000_000 {
                core::hint::spin_loop();
                spins += 1;
            }
            assert_eq!(PROBE_HIT.load(Ordering::SeqCst), 1, "handler never ran");
            // Leave no trace: restore default disposition.
            let dfl = KernelSigaction {
                handler: 0,
                flags: 0,
                restorer: 0,
                mask: 0,
            };
            let _ = syscall4(
                SYS_RT_SIGACTION,
                SIG_PROBE as usize,
                core::ptr::addr_of!(dfl) as usize,
                0,
                K_SIGSET_LEN,
            );
        }
    }

    /// One wave over N spinning children runs the callback exactly N times
    /// on targets plus once on the caller. Retries on contamination: the
    /// registry is process-global, so another test's threads may be caught
    /// mid-wave (harmless to them — the callback touches only our counter;
    /// they never time out). Each attempt is exact-checked, so only a clean
    /// wave passes; attempts are cheap and the other tests are finite, so
    /// this converges without any timing assumption.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn synccall_runs_once_per_thread_plus_caller() {
        const N: usize = 3;
        const TRIES: usize = 200;
        unsafe {
            ensure_main_tp();
            let mut ok = false;
            let mut attempt = 0;
            while attempt < TRIES && !ok {
                attempt += 1;
                RUNS.store(0, Ordering::SeqCst);
                READY.store(0, Ordering::SeqCst);
                DONE.store(0, Ordering::SeqCst);
                let mut tids: [PthreadT; N] = [null_mut(); N];
                let mut k = 0;
                while k < N {
                    let slot = core::ptr::addr_of_mut!(tids).cast::<PthreadT>().add(k);
                    if __pthread_create(slot, null_mut(), Some(spin_child), null_mut()) != 0 {
                        break;
                    }
                    k += 1;
                }
                if k != N {
                    // Creation failed (practically unreachable: OOM); park
                    // what started, join it, and retry rather than assert.
                    DONE.store(1, Ordering::SeqCst);
                    let mut j = 0;
                    while j < k {
                        let _ = __pthread_join(tids[j], null_mut());
                        j += 1;
                    }
                    continue;
                }
                // All children are spinning (and so alive) before the wave.
                while READY.load(Ordering::SeqCst) != N as u32 {
                    core::hint::spin_loop();
                }
                __synccall(Some(count_runs), &RUNS as *const AtomicU32 as *mut c_void);
                DONE.store(1, Ordering::SeqCst);
                let mut j = 0;
                while j < N {
                    let _ = __pthread_join(tids[j], null_mut());
                    j += 1;
                }
                ok = RUNS.load(Ordering::SeqCst) == N as u32 + 1;
            }
            assert!(
                ok,
                "no clean wave in {TRIES} tries (runs={})",
                RUNS.load(Ordering::SeqCst)
            );
        }
    }
}
