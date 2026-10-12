//! Mutex and condvar (x86_64).
//!
//! Clean-room mirrors of musl `src/thread/pthread_mutex_init.c`,
//! `pthread_mutex_lock.c`, `pthread_mutex_trylock.c`,
//! `pthread_mutex_unlock.c`, `pthread_cond_init.c`,
//! `pthread_cond_signal.c`, `pthread_cond_broadcast.c`,
//! `pthread_cond_destroy.c`, and the process-shared path of
//! `src/thread/pthread_cond_timedwait.c`. The `_m_*`/`_c_*` overlays
//! are re-derived from `src/internal/pthread_impl.h:86-97` and the lock
//! encoding from `pthread_mutex_trylock.c:11-35`. Re-derived, not
//! copied.
//!
//! Deferred: robust/PI/PP mutexes, timed lock/wait (needs clock), and
//! the private waiter-list protocol (`pthread_cond_timedwait.c:176-211`
//! needs cancellation, which lands with C1 threads). Until then both
//! shared and private condvars use the sequence protocol, and every
//! deferral carries a `shortcut:` comment at the exact spot.

use core::ffi::{c_int, c_uint, c_void};
use core::sync::atomic::Ordering;

use crate::futex::as_atomic;
use crate::futex::{futex_wait_private, futex_wait_shared};
use crate::futex::{futex_wake_private, futex_wake_shared};

/// musl `pthread_mutex_t` storage (`include/alltypes.h.in:87`): 10
/// `int` slots / 5 pointer slots = 40 bytes on 64-bit.
pub type MutexT = [u64; 5];

/// musl `pthread_cond_t` storage (`include/alltypes.h.in:89`): 12
/// `int` slots / 6 pointer slots = 48 bytes on 64-bit.
pub type CondT = [u64; 6];

/// musl `pthread_mutexattr_t` (`include/alltypes.h.in:62`).
#[repr(C)]
pub struct MutexAttrT {
    /// musl `__attr`: kind in the low 2 bits, robust in bit 2, PI/PP in
    /// bit 3, pshared in bit 7 (see the `set*` sources cited at init).
    pub attr: c_uint,
}

/// musl `pthread_condattr_t` (`include/alltypes.h.in:63`).
#[repr(C)]
pub struct CondAttrT {
    /// musl `__attr`: clock id in the low 31 bits, pshared at the top
    /// (`pthread_condattr_setclock.c`, `pthread_condattr_setpshared.c`).
    pub attr: c_uint,
}

// Errnos (musl `arch/generic/bits/errno.h`, line cited per constant).
const EPERM: c_int = 1; // errno.h:1
const EBUSY: c_int = 16; // errno.h:16
const EINVAL: c_int = 22; // errno.h:22
const EDEADLK: c_int = 35; // errno.h:35
const EAGAIN: c_int = 11; // errno.h:11
const ENOTSUP: c_int = 95; // errno.h:96
const ENOTRECOVERABLE: c_int = 131; // errno.h:132

// Mutex kinds (musl `include/pthread.h:36-39`).
const MUTEX_NORMAL: c_int = 0;
const MUTEX_RECURSIVE: c_int = 1;
const MUTEX_ERRORCHECK: c_int = 2;

// Attr bits above the kind (robust: `setrobust.c:18`; PI/PP:
// `setprotocol.c:21`; pshared: `setpshared.c:6-8`).
const MUTEX_UNSUPPORTED_BITS: c_int = 4 | 8 | 128;

// Lock-word encoding (musl `pthread_mutex_trylock.c:11,35`): owner TID
// in the low 30 bits, waiter mark at the top bit. The robust-death
// sticky bit (`0x40000000`) is never set by us; a foreign word showing
// owner `0x3fffffff` still reports `ENOTRECOVERABLE` (trylock.c:24).
const OWNER_MASK: c_int = 0x3fffffff;
const MAYBE_WAITERS: c_int = i32::MIN; // 0x80000000

/// musl `arch/x86_64/bits/syscall.h.in` (`__NR_gettid` is 186).
#[cfg(target_arch = "x86_64")]
const SYS_GETTID: usize = 186; // TODO: generate from arch bits/syscall.h

// Slot accessors. Each mirrors one `_m_*`/`_c_*` macro from musl
// `src/internal/pthread_impl.h:86-97`, where the number is the index
// into the `int` overlay (`__i`/`__vi`); `_c_shared` alone indexes the
// pointer overlay (`__p[0]`).

/// `pthread_impl.h:86` (`_m_type`).
fn m_type(m: *mut MutexT) -> *mut c_int {
    m.cast::<c_int>()
}

/// `pthread_impl.h:87` (`_m_lock`).
fn m_lock(m: *mut MutexT) -> *mut c_int {
    m.cast::<c_int>().wrapping_add(1)
}

/// `pthread_impl.h:88` (`_m_waiters`).
fn m_waiters(m: *mut MutexT) -> *mut c_int {
    m.cast::<c_int>().wrapping_add(2)
}

/// `pthread_impl.h:91` (`_m_count`).
fn m_count(m: *mut MutexT) -> *mut c_int {
    m.cast::<c_int>().wrapping_add(5)
}

// shortcut: `_m_prev`/`_m_next` (pthread_impl.h:89-90, robust list) get
// accessors when robust mutexes land; their slots stay zeroed meanwhile.

/// `pthread_impl.h:92` (`_c_shared`, pointer slot 0).
fn c_shared(c: *mut CondT) -> *mut *mut c_void {
    c.cast::<*mut c_void>()
}

/// `pthread_impl.h:93` (`_c_seq`).
fn c_seq(c: *mut CondT) -> *mut c_int {
    c.cast::<c_int>().wrapping_add(2)
}

/// `pthread_impl.h:94` (`_c_waiters`).
fn c_waiters(c: *mut CondT) -> *mut c_int {
    c.cast::<c_int>().wrapping_add(3)
}

/// `pthread_impl.h:95` (`_c_clock`; stored for ABI fidelity, honored
/// when timedwait lands — shortcut: needs clock).
fn c_clock(c: *mut CondT) -> *mut c_int {
    c.cast::<c_int>().wrapping_add(4)
}

// shortcut: `_c_lock`/`_c_head`/`_c_tail` (pthread_impl.h:96-98) belong
// to the private waiter-list protocol, deferred with cancellation;
// `_c_lock`'s offset is still probed (OFF_C_LOCK) for layout fidelity.

/// musl `a_cas` (`src/internal/atomic.h:20-29`): CAS, returns the old
/// value.
///
/// # Safety
///
/// `p` must be live, 4-byte aligned, and accessed only atomically.
unsafe fn ai_cas(p: *mut c_int, old: c_int, new: c_int) -> c_int {
    unsafe {
        let a = &*as_atomic(p);
        match a.compare_exchange(old, new, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(v) | Err(v) => v,
        }
    }
}

/// musl `a_swap` (`src/internal/atomic.h:33-42`): swap, returns old.
///
/// # Safety
///
/// Same contract as [`ai_cas`].
unsafe fn ai_swap(p: *mut c_int, v: c_int) -> c_int {
    unsafe { (*as_atomic(p)).swap(v, Ordering::SeqCst) }
}

/// Atomic load of a word owned by this protocol.
///
/// # Safety
///
/// Same contract as [`ai_cas`].
unsafe fn ai_load(p: *mut c_int) -> c_int {
    unsafe { (*as_atomic(p)).load(Ordering::SeqCst) }
}

/// Atomic store to a word owned by this protocol.
///
/// # Safety
///
/// Same contract as [`ai_cas`].
unsafe fn ai_store(p: *mut c_int, v: c_int) {
    unsafe { (*as_atomic(p)).store(v, Ordering::SeqCst) }
}

/// musl `a_inc`/`a_dec` (fetch-add family): adjust, ignore the old.
///
/// # Safety
///
/// Same contract as [`ai_cas`].
unsafe fn ai_add(p: *mut c_int, v: c_int) {
    unsafe {
        let _ = (*as_atomic(p)).fetch_add(v, Ordering::SeqCst);
    }
}

/// Current thread id, masked to the 30-bit owner field.
///
/// # Safety
///
/// Issues a raw `gettid` syscall, which cannot fail; callable from any
/// thread context.
unsafe fn self_tid() -> c_int {
    unsafe { (crate::syscall::syscall0(SYS_GETTID) as c_int) & OWNER_MASK }
}

/// Reject kinds C2 cannot serve. musl validates at attr-set time
/// (`settype`/`setrobust`/`setprotocol`, outside C2 scope), so init is
/// our only gate and use sites re-check for hand-built memory.
fn check_type(type_: c_int) -> c_int {
    // shortcut: robust/PI/PP need the robust list + PI futex ops (C1/C3).
    if (type_ & MUTEX_UNSUPPORTED_BITS) != 0 {
        return ENOTSUP;
    }
    match type_ & 15 {
        MUTEX_NORMAL | MUTEX_RECURSIVE | MUTEX_ERRORCHECK => 0,
        _ => EINVAL,
    }
}

/// Nonblocking acquire (musl `pthread_mutex_trylock.c:3-72`, robust/PI
/// branches removed — rejected by [`check_type`]).
///
/// # Safety
///
/// `m` must point to a live, 8-byte-aligned `MutexT` accessed only
/// through these functions.
unsafe fn mutex_trylock_inner(m: *mut MutexT) -> c_int {
    unsafe {
        let type_ = ai_load(m_type(m));
        let gate = check_type(type_);
        if gate != 0 {
            return gate;
        }
        if (type_ & 15) == MUTEX_NORMAL {
            // trylock.c:69-70: the EBUSY word doubles as "locked".
            return if ai_cas(m_lock(m), 0, EBUSY) == 0 {
                0
            } else {
                EBUSY
            };
        }
        let tid = self_tid();
        let old = ai_load(m_lock(m));
        let own = old & OWNER_MASK;
        if own == tid {
            if (type_ & 3) == MUTEX_RECURSIVE {
                // trylock.c:18-22.
                let count = ai_load(m_count(m));
                if count == c_int::MAX {
                    return EAGAIN;
                }
                ai_store(m_count(m), count + 1);
                return 0;
            }
            // trylock.c:25: errorcheck self-lock reports BUSY here
            // (EDEADLK is only for the blocking path).
            return EBUSY;
        }
        // trylock.c:24: previous robust owner died. Recovery is OUT, so
        // report it instead of taking the lock.
        if own == OWNER_MASK {
            return ENOTRECOVERABLE;
        }
        // trylock.c:25 (`old && !(type & 4)`): any other nonzero word
        // means held or mid-handoff; without robust nothing is stealable.
        if old != 0 {
            return EBUSY;
        }
        if ai_cas(m_lock(m), old, tid) == old {
            0
        } else {
            EBUSY
        }
    }
}

/// Blocking acquire (musl `pthread_mutex_lock.c:3-10` plus the
/// `at == NULL` path of `pthread_mutex_timedlock.c:56-90`, PI removed).
///
/// # Safety
///
/// Same contract as [`mutex_trylock_inner`].
unsafe fn mutex_lock_inner(m: *mut MutexT) -> c_int {
    unsafe {
        let mut r = mutex_trylock_inner(m);
        if r != EBUSY {
            // Fast success and every fast error (EINVAL/ENOTSUP/EAGAIN),
            // exactly like timedlock.c:65-66.
            return r;
        }
        let type_ = ai_load(m_type(m));
        // timedlock.c:70-71: spin while locked with no recorded waiters.
        let mut spins = 100;
        while spins != 0 {
            if ai_load(m_lock(m)) == 0 || ai_load(m_waiters(m)) != 0 {
                break;
            }
            core::hint::spin_loop();
            spins -= 1;
        }
        // timedlock.c:73-88: mark, sleep, retry. The wait is indefinite
        // (`at == NULL`); any futex return just retries the trylock.
        // shortcut: EINTR retries instead of cancelling — cancellation
        // needs C1 thread state.
        loop {
            r = mutex_trylock_inner(m);
            if r != EBUSY {
                return r;
            }
            let cur = ai_load(m_lock(m));
            if (cur & OWNER_MASK) == 0 {
                // timedlock.c:76-77: free or mid-handoff; retry at once.
                continue;
            }
            if (type_ & 3) == MUTEX_ERRORCHECK && (cur & OWNER_MASK) == self_tid() {
                // timedlock.c:78-80.
                return EDEADLK;
            }
            ai_add(m_waiters(m), 1);
            let marked = cur | MAYBE_WAITERS;
            // Plant the waiter mark if the word is unchanged; a lost race
            // only costs a spurious wakeup (timedlock.c:83-84).
            ai_cas(m_lock(m), cur, marked);
            // Pshared mutexes are ENOTSUP, so PRIVATE always applies here.
            futex_wait_private(m_lock(m), marked);
            ai_add(m_waiters(m), -1);
        }
    }
}

/// Release (musl `pthread_mutex_unlock.c:3-50`, robust/PI/`__vm_*`
/// removed — those only guard the robust list, which is OUT).
///
/// # Safety
///
/// Same contract as [`mutex_trylock_inner`].
unsafe fn mutex_unlock_inner(m: *mut MutexT) -> c_int {
    unsafe {
        let type_ = ai_load(m_type(m));
        let gate = check_type(type_);
        if gate != 0 {
            return gate;
        }
        if (type_ & 15) != MUTEX_NORMAL {
            // unlock.c:15-20: ownership plus the recursive count.
            if (ai_load(m_lock(m)) & OWNER_MASK) != self_tid() {
                return EPERM;
            }
            if (type_ & 3) == MUTEX_RECURSIVE {
                let count = ai_load(m_count(m));
                if count != 0 {
                    ai_store(m_count(m), count - 1);
                    return 0;
                }
            }
            // unlock.c:21-22 (robust-dead sticky word) is unreachable:
            // only robust take paths set it, and those are ENOTSUP.
        }
        // unlock.c:6,41,47-48: swap in unlocked, wake one if waiters were
        // recorded or the waiter mark survived (`cont < 0`).
        let waiters = ai_load(m_waiters(m));
        let prev = ai_swap(m_lock(m), 0);
        if waiters != 0 || prev < 0 {
            futex_wake_private(m_lock(m), 1);
        }
        0
    }
}

/// Wake waiters on `_c_seq`: shared op for shared condvars, private op
/// otherwise.
///
/// # Safety
///
/// `c` must point to a live, 8-byte-aligned `CondT`.
unsafe fn cond_wake(c: *mut CondT, cnt: c_int) {
    unsafe {
        let shared = !(*c_shared(c)).is_null();
        if shared {
            futex_wake_shared(c_seq(c), cnt);
        } else {
            futex_wake_private(c_seq(c), cnt);
        }
    }
}

/// Sleep until `_c_seq` differs from `seq` (the `ts == NULL` loop of
/// musl `pthread_cond_timedwait.c:100-101`).
///
/// # Safety
///
/// Same contract as [`cond_wake`].
unsafe fn cond_sleep(c: *mut CondT, seq: c_int) {
    unsafe {
        let shared = !(*c_shared(c)).is_null();
        let s = c_seq(c);
        loop {
            if shared {
                futex_wait_shared(s, seq);
            } else {
                futex_wait_private(s, seq);
            }
            if ai_load(s) != seq {
                break;
            }
        }
    }
}

/// Initialize a mutex (musl `src/thread/pthread_mutex_init.c:3-8`,
/// exact signature per `include/pthread.h:106`).
///
/// `attr` may be null for defaults; otherwise its `__attr` word carries
/// the kind in the low 2 bits. Kinds needing robust/PI/PP are rejected
/// with `ENOTSUP` here because C2 is their only gate (musl validates at
/// attr-set time instead).
///
/// # Safety
///
/// `m` must point to a live, 8-byte-aligned `MutexT`. `attr` must be
/// null or point to a live `MutexAttrT`. The mutex must not be used
/// concurrently with this call.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_init(m: *mut MutexT, a: *const MutexAttrT) -> c_int {
    unsafe {
        core::ptr::write(m, [0; 5]);
        if a.is_null() {
            return 0;
        }
        let type_ = (*a).attr as c_int;
        let gate = check_type(type_);
        if gate != 0 {
            return gate;
        }
        ai_store(m_type(m), type_);
        0
    }
}

/// Destroy a mutex (musl `pthread_mutex_destroy.c`: waits out a robust
/// pending slot, else no-op; exact signature, `pthread.h:111`). With
/// robust OUT there is nothing to wait for; always succeeds.
///
/// # Safety
///
/// `m` must point to a live, 8-byte-aligned `MutexT` no thread uses
/// concurrently with this call.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_destroy(_m: *mut MutexT) -> c_int {
    0
}

/// Lock a mutex (musl `src/thread/pthread_mutex_lock.c:3-10`, exact
/// signature per `include/pthread.h:107`).
///
/// # Safety
///
/// `m` must point to a live, 8-byte-aligned `MutexT` accessed only
/// through these functions.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_lock(m: *mut MutexT) -> c_int {
    unsafe { mutex_lock_inner(m) }
}

/// Unlock a mutex (musl `src/thread/pthread_mutex_unlock.c:3-50`,
/// exact signature per `include/pthread.h:108`).
///
/// # Safety
///
/// Same contract as [`pthread_mutex_lock`].
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_unlock(m: *mut MutexT) -> c_int {
    unsafe { mutex_unlock_inner(m) }
}

/// Nonblocking lock attempt (musl `pthread_mutex_trylock.c:67-72`,
/// exact signature per `include/pthread.h:109`).
///
/// # Safety
///
/// Same contract as [`pthread_mutex_lock`].
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_trylock(m: *mut MutexT) -> c_int {
    unsafe { mutex_trylock_inner(m) }
}

// NOT exported yet (each needs machinery from a later wave):
// - pthread_mutex_timedlock / pthread_cond_timedwait: need clock (Wave 4).
// - pthread_mutex_consistent: needs robust (OUT).
// - pthread_mutex_get/setprioceiling: need PI (OUT).

/// Initialize a condvar (musl `src/thread/pthread_cond_init.c:3-10`,
/// exact signature per `include/pthread.h:117`).
///
/// The attr clock id and pshared bit are stored for ABI fidelity; the
/// clock is honored when timedwait lands (shortcut: needs clock).
///
/// # Safety
///
/// `c` must point to a live, 8-byte-aligned `CondT`. `attr` must be
/// null or point to a live `CondAttrT`. The condvar must not be used
/// concurrently with this call.
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_init(c: *mut CondT, a: *const CondAttrT) -> c_int {
    unsafe {
        core::ptr::write(c, [0; 6]);
        if !a.is_null() {
            let attr = (*a).attr;
            ai_store(c_clock(c), (attr & 0x7fffffff) as c_int);
            if (attr >> 31) != 0 {
                // musl stores `(void *)-1` for process-shared.
                core::ptr::write(c_shared(c), usize::MAX as *mut c_void);
            }
        }
        0
    }
}

/// Destroy a condvar (musl `src/thread/pthread_cond_destroy.c`, exact
/// signature per `include/pthread.h:118`).
///
/// musl drains shared waiters before returning; C2 applies the same
/// drain to private waiters too, since both sleep on `_c_seq` here.
/// Destroying a condvar with waiters is still declared UB by POSIX —
/// the drain only avoids stranding them.
///
/// # Safety
///
/// `c` must point to a live, 8-byte-aligned `CondT` no thread uses
/// concurrently with this call, except for threads already leaving.
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_destroy(c: *mut CondT) -> c_int {
    unsafe {
        if ai_load(c_waiters(c)) != 0 {
            ai_add(c_seq(c), 1);
            cond_wake(c, i32::MAX);
        }
        0
    }
}

/// Wait on a condvar (musl `pthread_cond_wait.c:3-6` delegates to
/// timedwait with `ts == NULL`; sequence protocol from the shared path
/// of `pthread_cond_timedwait.c:62-174`; exact signature,
/// `include/pthread.h:119`).
///
/// The caller must hold `m` and re-check its predicate after return:
/// spurious wakeups are permitted, as in musl.
///
/// # Safety
///
/// `c` must point to a live, 8-byte-aligned `CondT`, `m` to a live,
/// 8-byte-aligned `MutexT` locked by the calling thread.
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_wait(c: *mut CondT, m: *mut MutexT) -> c_int {
    unsafe {
        // timedwait.c:68: ownership-tracking mutexes must be ours.
        let mtype = ai_load(m_type(m));
        if (mtype & 15) != MUTEX_NORMAL && (ai_load(m_lock(m)) & i32::MAX) != self_tid() {
            return EPERM;
        }
        // timedwait.c:76-81 unified: snapshot the sequence and count this
        // waiter BEFORE releasing the mutex. The kernel re-checks the
        // value on sleep, so a signal between snapshot and sleep is
        // never lost.
        let seq = ai_load(c_seq(c));
        ai_add(c_waiters(c), 1);
        // timedwait.c:95: unlock errors are ignored here...
        mutex_unlock_inner(m);
        cond_sleep(c, seq);
        ai_add(c_waiters(c), -1);
        // timedwait.c:141-145: relock errors override, then done.
        mutex_lock_inner(m)
    }
}

/// Wake one waiter (musl `pthread_cond_signal.c:3-10`, shared path
/// applied uniformly — every waiter sleeps on `_c_seq`, so bumping it
/// and waking one is exactly "wake one waiter"; exact signature,
/// `include/pthread.h:122`).
///
/// # Safety
///
/// `c` must point to a live, 8-byte-aligned `CondT`.
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_signal(c: *mut CondT) -> c_int {
    unsafe {
        // signal.c:6: nothing to do with no waiters.
        if ai_load(c_waiters(c)) == 0 {
            return 0;
        }
        // signal.c:7-8: advance the sequence, wake one.
        ai_add(c_seq(c), 1);
        cond_wake(c, 1);
        0
    }
}

/// Wake all waiters (musl `pthread_cond_broadcast.c:3-10`; `-1` wakes
/// all, mapped to `i32::MAX` like musl `__wake`; exact signature,
/// `include/pthread.h:121`).
///
/// # Safety
///
/// Same contract as [`pthread_cond_signal`].
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_broadcast(c: *mut CondT) -> c_int {
    unsafe {
        if ai_load(c_waiters(c)) == 0 {
            return 0;
        }
        ai_add(c_seq(c), 1);
        cond_wake(c, i32::MAX);
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};

    /// N threads x M increments under one mutex must total exactly N*M.
    /// The counter uses a racy load/spin/store on purpose: any lost
    /// mutual exclusion shows up as a short total. Every call uses the
    /// full `crate::sync::` path so it proves OUR code, never the host's
    /// (house rule, cf. `src/mem` tests).
    #[test]
    fn mutex_threaded_counter_is_exact() {
        static MUT: MutexT = [0; 5];
        static COUNT: AtomicU64 = AtomicU64::new(0);
        const NTHREADS: u32 = 8;
        const PER_THREAD: u32 = 2000;

        let mut handles = std::vec::Vec::new();
        for _ in 0..NTHREADS {
            handles.push(std::thread::spawn(|| {
                for _ in 0..PER_THREAD {
                    unsafe {
                        let m = core::ptr::addr_of_mut!(MUT);
                        assert_eq!(crate::sync::pthread_mutex_lock(m), 0);
                        let v = COUNT.load(Ordering::Relaxed);
                        // Widen the race window: a broken lock fails loudly.
                        core::hint::spin_loop();
                        COUNT.store(v + 1, Ordering::Relaxed);
                        assert_eq!(crate::sync::pthread_mutex_unlock(m), 0);
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(
            COUNT.load(Ordering::Relaxed),
            (NTHREADS * PER_THREAD) as u64
        );
    }

    /// Kinds and init validation, single-threaded: errorcheck reports
    /// BUSY on trylock but DEADLK on blocking lock; recursive nests;
    /// robust/PI/pshared attrs and garbage kinds are rejected at init.
    #[test]
    fn mutex_kinds_trylock_unlock_errors() {
        unsafe {
            let m: MutexT = [0; 5];
            let mp = core::ptr::addr_of_mut!(m);
            let err = MutexAttrT { attr: 2 }; // ERRORCHECK
            assert_eq!(crate::sync::pthread_mutex_init(mp, &err), 0);
            assert_eq!(crate::sync::pthread_mutex_trylock(mp), 0);
            assert_eq!(crate::sync::pthread_mutex_trylock(mp), EBUSY);
            assert_eq!(crate::sync::pthread_mutex_unlock(mp), 0);
            assert_eq!(crate::sync::pthread_mutex_lock(mp), 0);
            assert_eq!(crate::sync::pthread_mutex_lock(mp), EDEADLK);
            assert_eq!(crate::sync::pthread_mutex_unlock(mp), 0);
            assert_eq!(crate::sync::pthread_mutex_destroy(mp), 0);

            let rec = MutexAttrT { attr: 1 }; // RECURSIVE
            assert_eq!(crate::sync::pthread_mutex_init(mp, &rec), 0);
            assert_eq!(crate::sync::pthread_mutex_lock(mp), 0);
            assert_eq!(crate::sync::pthread_mutex_lock(mp), 0);
            assert_eq!(crate::sync::pthread_mutex_unlock(mp), 0);
            assert_eq!(crate::sync::pthread_mutex_unlock(mp), 0);
            assert_eq!(crate::sync::pthread_mutex_unlock(mp), EPERM);

            let robust = MutexAttrT { attr: 4 }; // ROBUST, OUT
            assert_eq!(crate::sync::pthread_mutex_init(mp, &robust), ENOTSUP);
            let pi = MutexAttrT { attr: 8 }; // PRIO_INHERIT, OUT
            assert_eq!(crate::sync::pthread_mutex_init(mp, &pi), ENOTSUP);
            let bad = MutexAttrT { attr: 3 }; // no such kind
            assert_eq!(crate::sync::pthread_mutex_init(mp, &bad), EINVAL);
            // Normal trylock on a free lock always takes it.
            assert_eq!(crate::sync::pthread_mutex_init(mp, core::ptr::null()), 0);
            assert_eq!(crate::sync::pthread_mutex_trylock(mp), 0);
            assert_eq!(crate::sync::pthread_mutex_trylock(mp), EBUSY);
            assert_eq!(crate::sync::pthread_mutex_unlock(mp), 0);
        }
    }

    /// One waiter sleeps in `pthread_cond_wait` until a signaler sets a
    /// flag under the same mutex and signals. The ENTERED handshake
    /// makes the signaler block on the mutex until the waiter is asleep
    /// inside `cond_wait`, so the wakeup path is exercised every run —
    /// no timing assumptions.
    #[test]
    fn cond_signal_rendezvous() {
        static M: MutexT = [0; 5];
        static C: CondT = [0; 6];
        static ENTERED: AtomicU64 = AtomicU64::new(0);
        static FLAG: AtomicU64 = AtomicU64::new(0);

        let waiter = std::thread::spawn(|| unsafe {
            let m = core::ptr::addr_of_mut!(M);
            let c = core::ptr::addr_of_mut!(C);
            assert_eq!(crate::sync::pthread_mutex_lock(m), 0);
            ENTERED.store(1, Ordering::Relaxed);
            while FLAG.load(Ordering::Relaxed) == 0 {
                assert_eq!(crate::sync::pthread_cond_wait(c, m), 0);
              }
            assert_eq!(crate::sync::pthread_mutex_unlock(m), 0);
          });
        unsafe {
            while ENTERED.load(Ordering::Relaxed) == 0 {
                core::hint::spin_loop();
            }
            let m = core::ptr::addr_of_mut!(M);
            let c = core::ptr::addr_of_mut!(C);
            // Blocks until the waiter releases M inside cond_wait.
            assert_eq!(crate::sync::pthread_mutex_lock(m), 0);
            FLAG.store(1, Ordering::Relaxed);
            assert_eq!(crate::sync::pthread_cond_signal(c), 0);
            assert_eq!(crate::sync::pthread_mutex_unlock(m), 0);
        }
        waiter.join().unwrap();
        assert_eq!(FLAG.load(Ordering::Relaxed), 1);
    }

    /// Three waiters rendezvous as above; one broadcast wakes all three.
    #[test]
    fn cond_broadcast_wakes_all() {
        static M: MutexT = [0; 5];
        static C: CondT = [0; 6];
        static ENTERED: AtomicU64 = AtomicU64::new(0);
        static FLAG: AtomicU64 = AtomicU64::new(0);
        static WOKE: AtomicU64 = AtomicU64::new(0);
        const NWAITERS: u64 = 3;

        let mut handles = std::vec::Vec::new();
        for _ in 0..NWAITERS {
            handles.push(std::thread::spawn(|| unsafe {
                let m = core::ptr::addr_of_mut!(M);
                let c = core::ptr::addr_of_mut!(C);
                assert_eq!(crate::sync::pthread_mutex_lock(m), 0);
                let _ = ENTERED.fetch_add(1, Ordering::Relaxed);
                while FLAG.load(Ordering::Relaxed) == 0 {
                    assert_eq!(crate::sync::pthread_cond_wait(c, m), 0);
                  }
                let _ = WOKE.fetch_add(1, Ordering::Relaxed);
                assert_eq!(crate::sync::pthread_mutex_unlock(m), 0);
              }));
        }
        unsafe {
            while ENTERED.load(Ordering::Relaxed) != NWAITERS {
                core::hint::spin_loop();
            }
            let m = core::ptr::addr_of_mut!(M);
            let c = core::ptr::addr_of_mut!(C);
            assert_eq!(crate::sync::pthread_mutex_lock(m), 0);
            FLAG.store(1, Ordering::Relaxed);
            assert_eq!(crate::sync::pthread_cond_broadcast(c), 0);
            assert_eq!(crate::sync::pthread_mutex_unlock(m), 0);
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(WOKE.load(Ordering::Relaxed), NWAITERS);
    }
}
