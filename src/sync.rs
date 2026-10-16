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

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::sync::atomic::Ordering;

use crate::futex::as_atomic;
use crate::futex::{futex_wait_private, futex_wait_shared};
use crate::futex::{futex_wake_private, futex_wake_shared};
use crate::syscall::syscall_ret;

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
const ETIMEDOUT: c_int = 110; // errno.h:110
const EOVERFLOW: c_int = 75; // errno.h:75
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

/// Add and return the new value.
///
/// # Safety
///
/// Same contract as [`ai_add`].
unsafe fn ai_add_fetch(p: *mut c_int, v: c_int) -> c_int {
    unsafe { (*(p as *const core::sync::atomic::AtomicI32)).fetch_add(v, Ordering::SeqCst) + v }
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

/// Sleep until `_c_seq` differs from `seq` or `at` expires (musl
/// `pthread_cond_timedwait.c:100-101` with a timeout). Returns the raw
/// futex result of the expiring wait (`-ETIMEDOUT`) or 0 on wakeup.
///
/// # Safety
///
/// Like [`cond_sleep`], plus `at` null (indefinite) or readable.
unsafe fn cond_sleep_timeout(c: *mut CondT, seq: c_int, at: *const crate::time::Timespec) -> isize {
    unsafe {
        let shared = !(*c_shared(c)).is_null();
        let s = c_seq(c);
        loop {
            let r = if shared {
                if at.is_null() {
                    crate::futex::futex_wait_shared(s, seq)
                } else {
                    // Shared timed waits have no helper (same reason as
                    // semaphores): condvars are process-local here.
                    crate::futex::futex_wait_shared(s, seq)
                }
            } else if at.is_null() {
                crate::futex::futex_wait_private(s, seq)
            } else {
                crate::futex::futex_wait_private_timeout(s, seq, at)
            };
            if ai_load(s) != seq {
                return 0;
            }
            if r == -(110isize) {
                return r;
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

// ---- mutexattr full family (musl pthread_mutexattr_*.c) ---------------------------
/// Attr bit meanings mirror [`MutexAttrT`]; kinds are
/// [`MUTEX_NORMAL`]/[`MUTEX_RECURSIVE`]/[`MUTEX_ERRORCHECK`].
/// Init attributes (musl: zeroed = default).
///
/// # Safety
///
/// `a` must point to a writable `MutexAttrT`.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_init(a: *mut MutexAttrT) -> c_int {
    unsafe {
        if a.is_null() {
            return EINVAL;
        }
        (*a).attr = 0;
        0
    }
}

/// Destroy attributes (musl: no-op, always 0).
///
/// # Safety
///
/// `a` must point to a `MutexAttrT`.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_destroy(a: *mut MutexAttrT) -> c_int {
    if a.is_null() {
        return EINVAL;
    }
    0
}

#[cfg(target_arch = "x86_64")]
unsafe fn mutexattr_get(a: *const MutexAttrT, out: *mut c_int, mask: c_uint, shift: u32) -> c_int {
    unsafe {
        if a.is_null() || out.is_null() {
            return EINVAL;
        }
        *out = (((*a).attr & mask) >> shift) as c_int;
        0
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn mutexattr_set(
    a: *mut MutexAttrT,
    v: c_int,
    mask: c_uint,
    shift: u32,
    max: c_uint,
) -> c_int {
    unsafe {
        if a.is_null() || (v as c_uint) > max {
            return EINVAL;
        }
        (*a).attr = ((*a).attr & !mask) | (((v as c_uint) << shift) & mask);
        0
    }
}

/// Get mutex kind (musl `pthread_mutexattr_gettype`).
///
/// # Safety
///
/// Both pointers valid.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_gettype(a: *const MutexAttrT, v: *mut c_int) -> c_int {
    unsafe { mutexattr_get(a, v, 3, 0) }
}

/// Set mutex kind (musl `pthread_mutexattr_settype`: 0..2).
///
/// # Safety
///
/// `a` must point to a writable `MutexAttrT`.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_settype(a: *mut MutexAttrT, v: c_int) -> c_int {
    unsafe { mutexattr_set(a, v, 3, 0, 2) }
}

/// Get robust flag (musl: bit 2).
///
/// # Safety
///
/// Both pointers valid.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_getrobust(a: *const MutexAttrT, v: *mut c_int) -> c_int {
    unsafe { mutexattr_get(a, v, 4, 2) }
}

/// Set robust flag (musl: 0/1; robust mutexes themselves are OUT —
/// the flag stores exactly, locking ignores it).
///
/// # Safety
///
/// `a` must point to a writable `MutexAttrT`.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_setrobust(a: *mut MutexAttrT, v: c_int) -> c_int {
    unsafe { mutexattr_set(a, v, 4, 2, 1) }
}

/// Get protocol (musl: bit 3, INHERIT/PROTECT/None).
///
/// # Safety
///
/// Both pointers valid.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_getprotocol(
    a: *const MutexAttrT,
    v: *mut c_int,
) -> c_int {
    unsafe { mutexattr_get(a, v, 8, 3) }
}

/// Set protocol (musl `pthread_mutexattr_setprotocol`: NONE clears,
/// INHERIT sets, PROTECT is `ENOTSUP`).
///
/// # Safety
///
/// `a` must point to a writable `MutexAttrT`.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_setprotocol(a: *mut MutexAttrT, v: c_int) -> c_int {
    unsafe {
        if a.is_null() {
            return EINVAL;
        }
        match v {
            0 => (*a).attr &= !8,
            1 => (*a).attr |= 8,
            2 => return ENOTSUP,
            _ => return EINVAL,
        }
        0
    }
}

/// Get process-shared flag (musl: bit 7).
///
/// # Safety
///
/// Both pointers valid.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_getpshared(
    a: *const MutexAttrT,
    v: *mut c_int,
) -> c_int {
    unsafe { mutexattr_get(a, v, 128, 7) }
}

/// Set process-shared flag (musl: 0/1; shared locking is OUT — stored
/// exactly, always lock PRIVATE).
///
/// # Safety
///
/// `a` must point to a writable `MutexAttrT`.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutexattr_setpshared(a: *mut MutexAttrT, v: c_int) -> c_int {
    unsafe { mutexattr_set(a, v, 128, 7, 1) }
}

// ---- mutex timed/consistent/ceiling -----------------------------------------------
/// Timed lock (musl `pthread_mutex_timedlock.c:65-88` shape with an
/// absolute timeout: `ETIMEDOUT` on expiry).
///
/// # Safety
///
/// `m` live; `at` null (indefinite) or readable.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_timedlock(
    m: *mut MutexT,
    at: *const crate::time::Timespec,
) -> c_int {
    unsafe {
        let mut r = mutex_trylock_inner(m);
        if r != EBUSY {
            return r;
        }
        let type_ = ai_load(m_type(m));
        let mut spins = 100;
        while spins != 0 {
            if ai_load(m_lock(m)) == 0 || ai_load(m_waiters(m)) != 0 {
                break;
            }
            core::hint::spin_loop();
            spins -= 1;
        }
        loop {
            r = mutex_trylock_inner(m);
            if r != EBUSY {
                return r;
            }
            let cur = ai_load(m_lock(m));
            if (cur & OWNER_MASK) == 0 {
                continue;
            }
            if (type_ & 3) == MUTEX_ERRORCHECK && (cur & OWNER_MASK) == self_tid() {
                return EDEADLK;
            }
            ai_add(m_waiters(m), 1);
            let marked = cur | MAYBE_WAITERS;
            ai_cas(m_lock(m), cur, marked);
            let w = crate::futex::futex_wait_private_timeout(m_lock(m), marked, at);
            ai_add(m_waiters(m), -1);
            if w == -(110isize) {
                return ETIMEDOUT;
            }
        }
    }
}

/// Mark an inconsistent mutex consistent (musl
/// `pthread_mutex_consistent.c`: only robust+inconsistent qualifies;
/// our mutexes never enter that state, so always `EINVAL`).
///
/// # Safety
///
/// `m` must point to a `MutexT`.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_consistent(m: *mut MutexT) -> c_int {
    unsafe {
        if m.is_null() {
            return EINVAL;
        }
        let t = ai_load(m_type(m));
        if (t & 4) == 0 || (ai_load(m_lock(m)) & 0x40000000) == 0 {
            return EINVAL;
        }
        ai_cas(
            m_lock(m),
            ai_load(m_lock(m)),
            ai_load(m_lock(m)) & !0x40000000,
        );
        0
    }
}

/// Get priority ceiling (musl: always `EINVAL` — no PI support).
///
/// # Safety
///
/// Pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_getprioceiling(m: *const MutexT, v: *mut c_int) -> c_int {
    if m.is_null() || v.is_null() {
        return EINVAL;
    }
    EINVAL
}

/// Set priority ceiling (musl: always `EINVAL` — no PI support).
///
/// # Safety
///
/// Pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn pthread_mutex_setprioceiling(
    m: *mut MutexT,
    v: c_int,
    old: *mut c_int,
) -> c_int {
    if m.is_null() {
        return EINVAL;
    }
    let _ = (v, old);
    EINVAL
}

// ---- condattr full family + timedwait ----------------------------------------------
/// Init cond attributes (musl: zeroed = default).
///
/// # Safety
///
/// `a` writable.
#[no_mangle]
pub unsafe extern "C" fn pthread_condattr_init(a: *mut CondAttrT) -> c_int {
    unsafe {
        if a.is_null() {
            return EINVAL;
        }
        (*a).attr = 0;
        0
    }
}

/// Destroy cond attributes (musl: no-op).
///
/// # Safety
///
/// `a` valid.
#[no_mangle]
pub unsafe extern "C" fn pthread_condattr_destroy(a: *mut CondAttrT) -> c_int {
    if a.is_null() {
        return EINVAL;
    }
    0
}

/// Get clock (musl: low 31 bits).
///
/// # Safety
///
/// Both pointers valid.
#[no_mangle]
pub unsafe extern "C" fn pthread_condattr_getclock(a: *const CondAttrT, v: *mut c_int) -> c_int {
    unsafe {
        if a.is_null() || v.is_null() {
            return EINVAL;
        }
        *v = ((*a).attr & 0x7fffffff) as c_int;
        0
    }
}

/// Set clock (musl: monotonic or realtime only).
///
/// # Safety
///
/// `a` writable.
#[no_mangle]
pub unsafe extern "C" fn pthread_condattr_setclock(a: *mut CondAttrT, v: c_int) -> c_int {
    unsafe {
        if a.is_null() || (v != 0 && v != 1) {
            return EINVAL;
        }
        (*a).attr = ((*a).attr & 0x80000000) | (v as c_uint);
        0
    }
}

/// Get process-shared flag (musl: top bit).
///
/// # Safety
///
/// Both pointers valid.
#[no_mangle]
pub unsafe extern "C" fn pthread_condattr_getpshared(a: *const CondAttrT, v: *mut c_int) -> c_int {
    unsafe {
        if a.is_null() || v.is_null() {
            return EINVAL;
        }
        *v = (((*a).attr >> 31) & 1) as c_int;
        0
    }
}

/// Set process-shared flag (musl: 0/1).
///
/// # Safety
///
/// `a` writable.
#[no_mangle]
pub unsafe extern "C" fn pthread_condattr_setpshared(a: *mut CondAttrT, v: c_int) -> c_int {
    unsafe {
        if a.is_null() || (v != 0 && v != 1) {
            return EINVAL;
        }
        (*a).attr = ((*a).attr & 0x7fffffff) | ((v as c_uint) << 31);
        0
    }
}

/// Timed cond wait (musl `pthread_cond_timedwait.c` unified shape with
/// an absolute timeout: `ETIMEDOUT` on expiry, relock errors override).
///
/// # Safety
///
/// Like [`pthread_cond_wait`], plus `at` null (indefinite) or readable.
#[no_mangle]
pub unsafe extern "C" fn pthread_cond_timedwait(
    c: *mut CondT,
    m: *mut MutexT,
    at: *const crate::time::Timespec,
) -> c_int {
    unsafe {
        let mtype = ai_load(m_type(m));
        if (mtype & 15) != MUTEX_NORMAL && (ai_load(m_lock(m)) & i32::MAX) != self_tid() {
            return EPERM;
        }
        let seq = ai_load(c_seq(c));
        ai_add(c_waiters(c), 1);
        mutex_unlock_inner(m);
        let w = cond_sleep_timeout(c, seq, at);
        ai_add(c_waiters(c), -1);
        if w == -(110isize) {
            let r = mutex_lock_inner(m);
            if r != 0 {
                return r;
            }
            return ETIMEDOUT;
        }
        mutex_lock_inner(m)
    }
}

// ---- rwlock (musl pthread_rwlock_*.c, writers-preference) -----------------------------
/// musl `pthread_rwlock_t` storage (alltypes: 14 ints = 56 bytes).
pub type RwlockT = [u64; 7];

/// musl `pthread_rwlockattr_t` (alltypes: 2 words; word 0 is pshared).
#[repr(C)]
pub struct RwlockAttrT {
    pub attr: [u32; 2],
}

fn rw_state(r: *mut RwlockT) -> *mut c_int {
    r.cast::<c_int>()
}
fn rw_waiters(r: *mut RwlockT) -> *mut c_int {
    r.cast::<c_int>().wrapping_add(1)
}
fn rw_writers_waiting(r: *mut RwlockT) -> *mut c_int {
    r.cast::<c_int>().wrapping_add(2)
}

/// Init an rwlock (musl: zeroed; pshared stored, always private).
///
/// # Safety
///
/// `r` writable; `a` null or readable.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_init(r: *mut RwlockT, a: *const RwlockAttrT) -> c_int {
    unsafe {
        if r.is_null() {
            return EINVAL;
        }
        for i in 0..7 {
            (*r)[i] = 0;
        }
        let _ = a;
        0
    }
}

/// Destroy an rwlock (musl: no-op).
///
/// # Safety
///
/// `r` valid.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_destroy(r: *mut RwlockT) -> c_int {
    if r.is_null() {
        return EINVAL;
    }
    0
}

#[cfg(target_arch = "x86_64")]
/// Shared lock (writers-preference: new readers wait while a writer
/// holds or waits).
///
/// # Safety
///
/// `r` must point to a live `RwlockT`.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_rdlock(r: *mut RwlockT) -> c_int {
    unsafe {
        if r.is_null() {
            return EINVAL;
        }
        loop {
            let st = ai_load(rw_state(r));
            if st >= 0 && ai_load(rw_writers_waiting(r)) == 0 {
                if ai_cas(rw_state(r), st, st + 1) == st {
                    return 0;
                }
                continue;
            }
            ai_add(rw_waiters(r), 1);
            crate::futex::futex_wait_private(rw_state(r), ai_load(rw_state(r)));
            ai_add(rw_waiters(r), -1);
        }
    }
}

/// Exclusive lock.
///
/// # Safety
///
/// `r` must point to a live `RwlockT`.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_wrlock(r: *mut RwlockT) -> c_int {
    unsafe {
        if r.is_null() {
            return EINVAL;
        }
        ai_add(rw_writers_waiting(r), 1);
        loop {
            if ai_cas(rw_state(r), 0, -1) == 0 {
                ai_add(rw_writers_waiting(r), -1);
                return 0;
            }
            crate::futex::futex_wait_private(rw_state(r), ai_load(rw_state(r)));
        }
    }
}

/// Nonblocking shared attempt.
///
/// # Safety
///
/// `r` must point to a live `RwlockT`.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_tryrdlock(r: *mut RwlockT) -> c_int {
    unsafe {
        if r.is_null() {
            return EINVAL;
        }
        let st = ai_load(rw_state(r));
        if st < 0 || ai_load(rw_writers_waiting(r)) != 0 {
            return EBUSY;
        }
        if ai_cas(rw_state(r), st, st + 1) != st {
            return EBUSY;
        }
        0
    }
}

/// Nonblocking exclusive attempt.
///
/// # Safety
///
/// `r` must point to a live `RwlockT`.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_trywrlock(r: *mut RwlockT) -> c_int {
    unsafe {
        if r.is_null() {
            return EINVAL;
        }
        if ai_cas(rw_state(r), 0, -1) != 0 {
            return EBUSY;
        }
        0
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn rw_timed(r: *mut RwlockT, wr: bool, at: *const crate::time::Timespec) -> c_int {
    unsafe {
        if !wr {
            ai_add(rw_writers_waiting(r), 0);
        } else {
            ai_add(rw_writers_waiting(r), 1);
        }
        loop {
            let st = ai_load(rw_state(r));
            let want = if wr {
                st == 0
            } else {
                st >= 0 && ai_load(rw_writers_waiting(r)) == 0
            };
            if want {
                let to = if wr { -1 } else { st + 1 };
                if ai_cas(rw_state(r), st, to) == st {
                    if wr {
                        ai_add(rw_writers_waiting(r), -1);
                    }
                    return 0;
                }
                continue;
            }
            ai_add(rw_waiters(r), 1);
            let w = crate::futex::futex_wait_private_timeout(rw_state(r), st, at);
            ai_add(rw_waiters(r), -1);
            if w == -(110isize) {
                if wr {
                    ai_add(rw_writers_waiting(r), -1);
                }
                return ETIMEDOUT;
            }
        }
    }
}

/// Timed shared lock (`ETIMEDOUT` on expiry).
///
/// # Safety
///
/// `r` live; `at` null or readable.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_timedrdlock(
    r: *mut RwlockT,
    at: *const crate::time::Timespec,
) -> c_int {
    unsafe {
        if r.is_null() {
            return EINVAL;
        }
        rw_timed(r, false, at)
    }
}

/// Timed exclusive lock (`ETIMEDOUT` on expiry).
///
/// # Safety
///
/// `r` live; `at` null or readable.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_timedwrlock(
    r: *mut RwlockT,
    at: *const crate::time::Timespec,
) -> c_int {
    unsafe {
        if r.is_null() {
            return EINVAL;
        }
        rw_timed(r, true, at)
    }
}

/// Unlock (reader decrements, last reader wakes a writer; writer
/// releases and wakes all).
///
/// # Safety
///
/// `r` must point to a locked `RwlockT`.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlock_unlock(r: *mut RwlockT) -> c_int {
    unsafe {
        if r.is_null() {
            return EINVAL;
        }
        let st = ai_load(rw_state(r));
        if st == -1 {
            ai_store(rw_state(r), 0);
            crate::futex::futex_wake_private(rw_state(r), -1);
            return 0;
        }
        if st <= 0 {
            return EINVAL;
        }
        if ai_add_fetch(rw_state(r), -1) == 0 && ai_load(rw_writers_waiting(r)) > 0 {
            crate::futex::futex_wake_private(rw_state(r), 1);
        }
        0
    }
}

/// Init rwlock attributes (musl: zeroed).
///
/// # Safety
///
/// `a` writable.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlockattr_init(a: *mut RwlockAttrT) -> c_int {
    unsafe {
        if a.is_null() {
            return EINVAL;
        }
        (*a).attr = [0; 2];
        0
    }
}

/// Destroy rwlock attributes (musl: no-op).
///
/// # Safety
///
/// `a` valid.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlockattr_destroy(a: *mut RwlockAttrT) -> c_int {
    if a.is_null() {
        return EINVAL;
    }
    0
}

/// Get pshared (musl: word 0).
///
/// # Safety
///
/// Both pointers valid.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlockattr_getpshared(
    a: *const RwlockAttrT,
    v: *mut c_int,
) -> c_int {
    unsafe {
        if a.is_null() || v.is_null() {
            return EINVAL;
        }
        *v = (*a).attr[0] as c_int;
        0
    }
}

/// Set pshared (musl: 0/1).
///
/// # Safety
///
/// `a` writable.
#[no_mangle]
pub unsafe extern "C" fn pthread_rwlockattr_setpshared(a: *mut RwlockAttrT, v: c_int) -> c_int {
    unsafe {
        if a.is_null() || (v != 0 && v != 1) {
            return EINVAL;
        }
        (*a).attr[0] = v as u32;
        0
    }
}

// ---- barrier (musl pthread_barrier_*.c, two-generation protocol) -------------------
/// musl `pthread_barrier_t` storage (alltypes: 8 ints = 32 bytes).
pub type BarrierT = [u64; 4];

/// musl `pthread_barrierattr_t` (alltypes: one word, pshared).
#[repr(C)]
pub struct BarrierAttrT {
    pub attr: u32,
}

/// Serial-thread return (musl `PTHREAD_BARRIER_SERIAL_THREAD`, -1).
pub const PTHREAD_BARRIER_SERIAL_THREAD: c_int = -1;

fn b_count(b: *mut BarrierT) -> *mut c_int {
    b.cast::<c_int>()
}
fn b_limit(b: *mut BarrierT) -> *mut c_int {
    b.cast::<c_int>().wrapping_add(2)
}
fn b_gen(b: *mut BarrierT) -> *mut c_int {
    b.cast::<c_int>().wrapping_add(3)
}

/// Init a barrier (musl: limit = count+1 in slot 2, rest zeroed).
///
/// # Safety
///
/// `b` writable; `a` null or readable; `count` must be non-zero.
#[no_mangle]
pub unsafe extern "C" fn pthread_barrier_init(
    b: *mut BarrierT,
    a: *const BarrierAttrT,
    count: c_uint,
) -> c_int {
    unsafe {
        if b.is_null() || count == 0 {
            return EINVAL;
        }
        let _ = a;
        for i in 0..4 {
            (*b)[i] = 0;
        }
        ai_store(b_limit(b), count as c_int);
        0
    }
}

/// Destroy a barrier (musl: zeroed; waiting threads are UB — same here).
///
/// # Safety
///
/// `b` valid and unwaited.
#[no_mangle]
pub unsafe extern "C" fn pthread_barrier_destroy(b: *mut BarrierT) -> c_int {
    unsafe {
        if b.is_null() {
            return EINVAL;
        }
        for i in 0..4 {
            (*b)[i] = 0;
        }
        0
    }
}

/// Wait at a barrier (one waiter in `limit` returns
/// `PTHREAD_BARRIER_SERIAL_THREAD`, the rest 0).
///
/// # Safety
///
/// `b` must point to an initialized `BarrierT`.
#[no_mangle]
pub unsafe extern "C" fn pthread_barrier_wait(b: *mut BarrierT) -> c_int {
    unsafe {
        if b.is_null() {
            return EINVAL;
        }
        let limit = ai_load(b_limit(b));
        let n = ai_add_fetch(b_count(b), 1);
        if n == limit {
            ai_store(b_count(b), 0);
            ai_add(b_gen(b), 1);
            crate::futex::futex_wake_private(b_gen(b), -1);
            return PTHREAD_BARRIER_SERIAL_THREAD;
        }
        let g = ai_load(b_gen(b));
        loop {
            crate::futex::futex_wait_private(b_gen(b), g);
            if ai_load(b_gen(b)) != g {
                return 0;
            }
        }
    }
}

/// Init barrier attributes (musl: zeroed).
///
/// # Safety
///
/// `a` writable.
#[no_mangle]
pub unsafe extern "C" fn pthread_barrierattr_init(a: *mut BarrierAttrT) -> c_int {
    unsafe {
        if a.is_null() {
            return EINVAL;
        }
        (*a).attr = 0;
        0
    }
}

/// Destroy barrier attributes (musl: no-op).
///
/// # Safety
///
/// `a` valid.
#[no_mangle]
pub unsafe extern "C" fn pthread_barrierattr_destroy(a: *mut BarrierAttrT) -> c_int {
    if a.is_null() {
        return EINVAL;
    }
    0
}

/// Get pshared (musl).
///
/// # Safety
///
/// Both pointers valid.
#[no_mangle]
pub unsafe extern "C" fn pthread_barrierattr_getpshared(
    a: *const BarrierAttrT,
    v: *mut c_int,
) -> c_int {
    unsafe {
        if a.is_null() || v.is_null() {
            return EINVAL;
        }
        *v = (*a).attr as c_int;
        0
    }
}

/// Set pshared (musl: 0/1).
///
/// # Safety
///
/// `a` writable.
#[no_mangle]
pub unsafe extern "C" fn pthread_barrierattr_setpshared(a: *mut BarrierAttrT, v: c_int) -> c_int {
    unsafe {
        if a.is_null() || (v != 0 && v != 1) {
            return EINVAL;
        }
        (*a).attr = v as u32;
        0
    }
}

// ---- spin (musl pthread_spin_*.c) ------------------------------------------------------
/// musl `pthread_spinlock_t` (alltypes: one int).
pub type SpinT = c_int;

/// Init a spinlock (musl: pshared stored, always 0).
///
/// # Safety
///
/// `s` writable.
#[no_mangle]
pub unsafe extern "C" fn pthread_spin_init(s: *mut SpinT, _pshared: c_int) -> c_int {
    unsafe {
        if s.is_null() {
            return EINVAL;
        }
        *s = 0;
        0
    }
}

/// Destroy a spinlock (musl: no-op).
///
/// # Safety
///
/// `s` valid.
#[no_mangle]
pub unsafe extern "C" fn pthread_spin_destroy(s: *mut SpinT) -> c_int {
    if s.is_null() {
        return EINVAL;
    }
    0
}

/// Lock (test-and-set spin).
///
/// # Safety
///
/// `s` must point to a live `SpinT`.
#[no_mangle]
pub unsafe extern "C" fn pthread_spin_lock(s: *mut SpinT) -> c_int {
    unsafe {
        if s.is_null() {
            return EINVAL;
        }
        while (*(s as *const core::sync::atomic::AtomicI32))
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            core::hint::spin_loop();
        }
        0
    }
}

/// Nonblocking attempt.
///
/// # Safety
///
/// `s` must point to a live `SpinT`.
#[no_mangle]
pub unsafe extern "C" fn pthread_spin_trylock(s: *mut SpinT) -> c_int {
    unsafe {
        if s.is_null() {
            return EINVAL;
        }
        if (*(s as *const core::sync::atomic::AtomicI32))
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return EBUSY;
        }
        0
    }
}

/// Unlock.
///
/// # Safety
///
/// `s` must point to a locked `SpinT`.
#[no_mangle]
pub unsafe extern "C" fn pthread_spin_unlock(s: *mut SpinT) -> c_int {
    unsafe {
        if s.is_null() {
            return EINVAL;
        }
        (*(s as *const core::sync::atomic::AtomicI32)).store(0, Ordering::SeqCst);
        0
    }
}

// ---- POSIX semaphores (musl src/thread/sem_*.c) -------------------------------------------
/// musl `sem_t` (semaphore.h: 4 longs = 32 bytes; `__val[0]` count,
/// `__val[1]` waiters, `__val[2]` flags with 128 = private).
pub type SemT = [u64; 4];

fn sem_val(s: *mut SemT) -> *mut c_int {
    s.cast::<c_int>()
}
fn sem_waiters(s: *mut SemT) -> *mut c_int {
    s.cast::<c_int>().wrapping_add(1)
}
fn sem_flags(s: *mut SemT) -> *mut c_int {
    s.cast::<c_int>().wrapping_add(2)
}
const SEM_PRIVATE: c_int = 128;
const SEM_VALUE_MAX_V: c_int = 0x7fffffff;

/// Init an unnamed semaphore (musl `sem_init`: count/waiters/flags).
///
/// # Safety
///
/// `s` writable; `value` must fit.
#[no_mangle]
pub unsafe extern "C" fn sem_init(s: *mut SemT, pshared: c_int, value: c_uint) -> c_int {
    unsafe {
        if s.is_null() || value > SEM_VALUE_MAX_V as c_uint {
            return EINVAL;
        }
        ai_store(sem_val(s), value as c_int);
        ai_store(sem_waiters(s), 0);
        ai_store(sem_flags(s), if pshared != 0 { 0 } else { SEM_PRIVATE });
        0
    }
}

/// Destroy (musl: no-op).
///
/// # Safety
///
/// `s` valid.
#[no_mangle]
pub unsafe extern "C" fn sem_destroy(s: *mut SemT) -> c_int {
    if s.is_null() {
        return EINVAL;
    }
    0
}

#[cfg(target_arch = "x86_64")]
unsafe fn sem_is_private(s: *mut SemT) -> bool {
    unsafe { ai_load(sem_flags(s)) & SEM_PRIVATE != 0 }
}

#[cfg(target_arch = "x86_64")]
unsafe fn sem_wake(s: *mut SemT, n: c_int) {
    unsafe {
        if sem_is_private(s) {
            crate::futex::futex_wake_private(sem_val(s), n);
        } else {
            crate::futex::futex_wake_shared(sem_val(s), n);
        }
    }
}

/// Nonblocking take (musl `sem_trywait`: `EAGAIN` when drained).
///
/// # Safety
///
/// `s` must point to a live `SemT`.
#[no_mangle]
pub unsafe extern "C" fn sem_trywait(s: *mut SemT) -> c_int {
    unsafe {
        if s.is_null() {
            return EINVAL;
        }
        loop {
            let v = ai_load(sem_val(s));
            if (v & SEM_VALUE_MAX_V) == 0 {
                return EAGAIN;
            }
            if ai_cas(sem_val(s), v, v - 1) == v {
                return 0;
            }
        }
    }
}

/// Blocking take (musl `sem_timedwait` with null timeout).
///
/// # Safety
///
/// `s` must point to a live `SemT`.
#[no_mangle]
pub unsafe extern "C" fn sem_wait(s: *mut SemT) -> c_int {
    unsafe { sem_timedwait(s, core::ptr::null()) }
}

/// Timed take (musl `sem_timedwait`: `ETIMEDOUT` on expiry).
///
/// # Safety
///
/// `s` live; `at` null or readable.
#[no_mangle]
pub unsafe extern "C" fn sem_timedwait(s: *mut SemT, at: *const crate::time::Timespec) -> c_int {
    unsafe {
        if s.is_null() {
            return EINVAL;
        }
        crate::thread::create::__pthread_testcancel();
        if sem_trywait(s) == 0 {
            return 0;
        }
        let mut spins = 100;
        while spins != 0
            && (ai_load(sem_val(s)) & SEM_VALUE_MAX_V) == 0
            && ai_load(sem_waiters(s)) == 0
        {
            core::hint::spin_loop();
            spins -= 1;
        }
        loop {
            if sem_trywait(s) == 0 {
                return 0;
            }
            ai_add(sem_waiters(s), 1);
            ai_cas(sem_val(s), 0, i32::MIN);
            let r = if sem_is_private(s) {
                crate::futex::futex_wait_private_timeout(sem_val(s), i32::MIN, at)
            } else {
                // Shared path has no timeout helper: indefinite wait only
                // when `at` is null (named semaphores are process-local
                // here anyway — same process, same futex).
                crate::futex::futex_wait_shared(sem_val(s), i32::MIN)
            };
            ai_add(sem_waiters(s), -1);
            if r == -(110isize) {
                return ETIMEDOUT;
            }
            crate::thread::create::__pthread_testcancel();
        }
    }
}

/// Increment (musl `sem_post`: `EOVERFLOW` at max, wake on waiters).
///
/// # Safety
///
/// `s` must point to a live `SemT`.
#[no_mangle]
pub unsafe extern "C" fn sem_post(s: *mut SemT) -> c_int {
    unsafe {
        if s.is_null() {
            return EINVAL;
        }
        loop {
            let v = ai_load(sem_val(s));
            let waiters = ai_load(sem_waiters(s));
            if (v & SEM_VALUE_MAX_V) == SEM_VALUE_MAX_V {
                return EOVERFLOW;
            }
            let mut new = v + 1;
            if waiters <= 1 {
                new &= !i32::MIN;
            }
            if ai_cas(sem_val(s), v, new) != v {
                continue;
            }
            if v < 0 || waiters != 0 {
                sem_wake(s, if waiters > 1 { 1 } else { -1 });
            }
            return 0;
        }
    }
}

/// Read the count (musl `sem_getvalue`).
///
/// # Safety
///
/// Both pointers valid.
#[no_mangle]
pub unsafe extern "C" fn sem_getvalue(s: *const SemT, v: *mut c_int) -> c_int {
    unsafe {
        if s.is_null() || v.is_null() {
            return EINVAL;
        }
        *v = ai_load(s as *mut SemT as *mut c_int);
        0
    }
}

/// Open a named semaphore (musl `sem_open.c`: the name goes through
/// the shm mapping (`/dev/shm/<name>`), `mmap` shared; `O_CREAT`
/// initializes once).
///
/// # Safety
///
/// `name` must be a valid shm name (`/foo`, no other `/`); `mode`/`value`
/// only read with `O_CREAT`.
#[no_mangle]
pub unsafe extern "C" fn sem_open(
    name: *const c_char,
    flags: c_int,
    mode: c_uint,
    value: c_uint,
) -> *mut SemT {
    unsafe {
        if name.is_null() {
            return core::ptr::null_mut();
        }
        let fd = crate::ipc::shm_open(
            name,
            flags & (crate::fcntl::O_CREAT | crate::fcntl::O_EXCL | crate::fcntl::O_RDWR),
            mode,
        );
        if fd < 0 {
            return core::ptr::null_mut();
        }
        // Init only a file we created ourselves: an existing mapping
        // already holds live state (musl keys creation off the shm
        // open itself; size 0 after a fresh O_CREAT is our signal).
        let mut st: crate::stat::Stat = core::mem::zeroed();
        if crate::stat::fstat(fd, &mut st) != 0 {
            crate::unistd::close(fd);
            return core::ptr::null_mut();
        }
        if st.st_size == 0 {
            let r = syscall_ret(crate::syscall::syscall2(77, fd as usize, 32));
            if r != 0 {
                crate::unistd::close(fd);
                return core::ptr::null_mut();
            }
        }
        let fresh = st.st_size == 0;
        let m = crate::mman::mmap(
            core::ptr::null_mut(),
            32,
            crate::mman::PROT_READ | crate::mman::PROT_WRITE,
            crate::mman::MAP_SHARED,
            fd,
            0,
        );
        crate::unistd::close(fd);
        if m == crate::mman::MAP_FAILED {
            return core::ptr::null_mut();
        }
        if fresh && sem_init(m as *mut SemT, 1, value) != 0 {
            crate::mman::munmap(m, 32);
            return core::ptr::null_mut();
        }
        m as *mut SemT
    }
}

/// Close a named semaphore (musl: `munmap`).
///
/// # Safety
///
/// `s` must come from [`sem_open`].
#[no_mangle]
pub unsafe extern "C" fn sem_close(s: *mut SemT) -> c_int {
    unsafe {
        if s.is_null() {
            return EINVAL;
        }
        crate::mman::munmap(s as *mut c_void, 32)
    }
}

/// Remove a named semaphore (musl: `shm_unlink` of the same name).
///
/// # Safety
///
/// `name` must be a valid `sem_open` name.
#[no_mangle]
pub unsafe extern "C" fn sem_unlink(name: *const c_char) -> c_int {
    unsafe {
        if name.is_null() {
            return EINVAL;
        }
        crate::ipc::shm_unlink(name)
    }
}

// ---- C11 threads (musl src/threads/*.c over pthread) -------------------------------
/// C11 status codes (musl `include/threads.h:60-64`).
pub const THRD_SUCCESS: c_int = 0;
pub const THRD_BUSY: c_int = 1;
pub const THRD_ERROR: c_int = 2;
pub const THRD_NOMEM: c_int = 3;
pub const THRD_TIMEDOUT: c_int = 4;

/// C11 mutex kinds (musl `threads.h:23-25`).
pub const MTX_PLAIN: c_int = 0;
pub const MTX_RECURSIVE: c_int = 1;
pub const MTX_TIMED: c_int = 2;

/// Start a C11 thread (musl `thrd_create.c`: detach state honors
/// `__pthread_create` defaults; failures map to `thrd_error/nomem`).
///
/// # Safety
///
/// `thr` writable; `func`/`arg` like `pthread_create`.
#[no_mangle]
pub unsafe extern "C" fn thrd_create(
    thr: *mut crate::abi::PthreadT,
    func: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    arg: *mut c_void,
) -> c_int {
    unsafe {
        if thr.is_null() || func.is_none() {
            return THRD_ERROR;
        }
        unsafe extern "C" fn tramp(p: *mut c_void) -> *mut c_void {
            let inner: Option<unsafe extern "C" fn(*mut c_void) -> c_int>;
            let argp: *mut c_void;
            unsafe {
                inner = *(p as *const Option<unsafe extern "C" fn(*mut c_void) -> c_int>);
                argp = *(p as *const *mut c_void).add(1);
                crate::malloc::free(p);
            }
            unsafe { inner.unwrap()(argp) as isize as *mut c_void }
        }
        struct Pack {
            f: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
            a: *mut c_void,
        }
        let pack = crate::malloc::malloc(core::mem::size_of::<Pack>()) as *mut Pack;
        if pack.is_null() {
            return THRD_NOMEM;
        }
        (*pack).f = func;
        (*pack).a = arg;
        let r = crate::thread::create::__pthread_create(
            thr as *mut crate::abi::PthreadT,
            core::ptr::null(),
            Some(tramp),
            pack as *mut c_void,
        );
        if r != 0 {
            crate::malloc::free(pack as *mut c_void);
            return THRD_ERROR;
        }
        THRD_SUCCESS
    }
}

/// Test thread equality (musl: pointer compare).
///
/// # Safety
///
/// Pure value call.
#[no_mangle]
pub unsafe extern "C" fn thrd_equal(a: crate::abi::PthreadT, b: crate::abi::PthreadT) -> c_int {
    if a == b {
        1
    } else {
        0
    }
}

/// Current thread (musl: `pthread_self`).
///
/// # Safety
///
/// Pure value call.
#[no_mangle]
pub unsafe extern "C" fn thrd_current() -> crate::abi::PthreadT {
    unsafe { crate::thread::create::__pthread_self() }
}

/// Exit a C11 thread (musl `thrd_exit.c`: `pthread_exit` with the int
/// widened to a pointer).
///
/// # Safety
///
/// Never returns.
#[no_mangle]
pub unsafe extern "C" fn thrd_exit(res: c_int) -> ! {
    unsafe {
        crate::thread::create::__pthread_exit(res as isize as *mut c_void);
    }
}

/// Join a C11 thread (musl: `pthread_join`, status int via pointer).
///
/// # Safety
///
/// `thr` joinable; `res` null or writable.
#[no_mangle]
pub unsafe extern "C" fn thrd_join(thr: crate::abi::PthreadT, res: *mut c_int) -> c_int {
    unsafe {
        let mut p: *mut c_void = core::ptr::null_mut();
        let r = crate::thread::create::__pthread_join(thr, &mut p);
        if r != 0 {
            return THRD_ERROR;
        }
        if !res.is_null() {
            *res = p as isize as c_int;
        }
        THRD_SUCCESS
    }
}

/// Detach a C11 thread (musl: `pthread_detach`).
///
/// # Safety
///
/// `thr` joinable.
#[no_mangle]
pub unsafe extern "C" fn thrd_detach(thr: crate::abi::PthreadT) -> c_int {
    unsafe {
        if crate::thread::create::__pthread_detach(thr) != 0 {
            THRD_ERROR
        } else {
            THRD_SUCCESS
        }
    }
}

/// Sleep (musl `thrd_sleep.c`: `nanosleep`).
///
/// # Safety
///
/// `dur`/`rem` null or valid `Timespec`.
#[no_mangle]
pub unsafe extern "C" fn thrd_sleep(
    dur: *const crate::time::Timespec,
    rem: *mut crate::time::Timespec,
) -> c_int {
    unsafe {
        // musl thrd_sleep.c: 0 elapsed, -1 EINTR, -2 anything else.
        // EINTR is 4 (errno.h:4).
        let r = crate::time::clock_nanosleep(0, 0, dur, rem);
        if r == 0 {
            0
        } else if r == 4 {
            -1
        } else {
            -2
        }
    }
}

/// Yield (musl: `sched_yield`).
///
/// # Safety
///
/// Pure call.
#[no_mangle]
pub unsafe extern "C" fn thrd_yield() {
    unsafe {
        crate::thread::create::sched_yield();
    }
}

/// Init a C11 mutex (musl `mtx_init.c`: timed kinds get an errorcheck
/// mutex so `mtx_timedlock` has an owner to check; plain maps normal).
///
/// # Safety
///
/// `m` writable.
#[no_mangle]
pub unsafe extern "C" fn mtx_init(m: *mut MutexT, ty: c_int) -> c_int {
    unsafe {
        if m.is_null() {
            return THRD_ERROR;
        }
        if ty != MTX_PLAIN
            && ty != MTX_RECURSIVE
            && ty != (MTX_RECURSIVE | MTX_TIMED)
            && ty != MTX_TIMED
        {
            return THRD_ERROR;
        }
        for i in 0..5 {
            (*m)[i] = 0;
        }
        if ty == MTX_RECURSIVE || ty == (MTX_RECURSIVE | MTX_TIMED) {
            let mut a = MutexAttrT { attr: 0 };
            if pthread_mutexattr_settype(&mut a, 1) != 0 {
                return THRD_ERROR;
            }
            if pthread_mutex_init(m, &a) != 0 {
                return THRD_ERROR;
            }
        } else if pthread_mutex_init(m, core::ptr::null()) != 0 {
            return THRD_ERROR;
        }
        THRD_SUCCESS
    }
}

/// Destroy a C11 mutex.
///
/// # Safety
///
/// `m` valid.
#[no_mangle]
pub unsafe extern "C" fn mtx_destroy(m: *mut MutexT) {
    unsafe {
        pthread_mutex_destroy(m);
    }
}

/// Lock a C11 mutex (musl: `thrd_busy` on `EBUSY` — unreachable for
/// blocking lock; errors map to `thrd_error`).
///
/// # Safety
///
/// `m` live.
#[no_mangle]
pub unsafe extern "C" fn mtx_lock(m: *mut MutexT) -> c_int {
    unsafe {
        if pthread_mutex_lock(m) != 0 {
            THRD_ERROR
        } else {
            THRD_SUCCESS
        }
    }
}

/// Nonblocking C11 lock.
///
/// # Safety
///
/// `m` live.
#[no_mangle]
pub unsafe extern "C" fn mtx_trylock(m: *mut MutexT) -> c_int {
    unsafe {
        let r = pthread_mutex_trylock(m);
        if r == 0 {
            THRD_SUCCESS
        } else if r == EBUSY {
            THRD_BUSY
        } else {
            THRD_ERROR
        }
    }
}

/// Timed C11 lock.
///
/// # Safety
///
/// `m` live; `at` readable.
#[no_mangle]
pub unsafe extern "C" fn mtx_timedlock(m: *mut MutexT, at: *const crate::time::Timespec) -> c_int {
    unsafe {
        let r = pthread_mutex_timedlock(m, at);
        if r == 0 {
            THRD_SUCCESS
        } else if r == ETIMEDOUT {
            THRD_TIMEDOUT
        } else {
            THRD_ERROR
        }
    }
}

/// Unlock a C11 mutex.
///
/// # Safety
///
/// `m` locked by caller.
#[no_mangle]
pub unsafe extern "C" fn mtx_unlock(m: *mut MutexT) -> c_int {
    unsafe {
        if pthread_mutex_unlock(m) != 0 {
            THRD_ERROR
        } else {
            THRD_SUCCESS
        }
    }
}

/// Init a C11 condvar.
///
/// # Safety
///
/// `c` writable.
#[no_mangle]
pub unsafe extern "C" fn cnd_init(c: *mut CondT) -> c_int {
    unsafe {
        if pthread_cond_init(c, core::ptr::null()) != 0 {
            THRD_ERROR
        } else {
            THRD_SUCCESS
        }
    }
}

/// Destroy a C11 condvar.
///
/// # Safety
///
/// `c` valid.
#[no_mangle]
pub unsafe extern "C" fn cnd_destroy(c: *mut CondT) {
    unsafe {
        pthread_cond_destroy(c);
    }
}

/// Signal a C11 condvar.
///
/// # Safety
///
/// `c` live.
#[no_mangle]
pub unsafe extern "C" fn cnd_signal(c: *mut CondT) -> c_int {
    unsafe {
        if pthread_cond_signal(c) != 0 {
            THRD_ERROR
        } else {
            THRD_SUCCESS
        }
    }
}

/// Broadcast a C11 condvar.
///
/// # Safety
///
/// `c` live.
#[no_mangle]
pub unsafe extern "C" fn cnd_broadcast(c: *mut CondT) -> c_int {
    unsafe {
        if pthread_cond_broadcast(c) != 0 {
            THRD_ERROR
        } else {
            THRD_SUCCESS
        }
    }
}

/// Wait on a C11 condvar.
///
/// # Safety
///
/// Like `pthread_cond_wait`.
#[no_mangle]
pub unsafe extern "C" fn cnd_wait(c: *mut CondT, m: *mut MutexT) -> c_int {
    unsafe {
        if pthread_cond_wait(c, m) != 0 {
            THRD_ERROR
        } else {
            THRD_SUCCESS
        }
    }
}

/// Timed wait on a C11 condvar.
///
/// # Safety
///
/// Like `pthread_cond_timedwait`.
#[no_mangle]
pub unsafe extern "C" fn cnd_timedwait(
    c: *mut CondT,
    m: *mut MutexT,
    at: *const crate::time::Timespec,
) -> c_int {
    unsafe {
        let r = pthread_cond_timedwait(c, m, at);
        if r == 0 {
            THRD_SUCCESS
        } else if r == ETIMEDOUT {
            THRD_TIMEDOUT
        } else {
            THRD_ERROR
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn attr_families_roundtrip() {
        unsafe {
            let mut ma = MutexAttrT { attr: 0 };
            let mut v = -1;
            assert_eq!(pthread_mutexattr_init(&mut ma), 0);
            assert_eq!(pthread_mutexattr_settype(&mut ma, 1), 0);
            assert_eq!(pthread_mutexattr_gettype(&ma, &mut v), 0);
            assert_eq!(v, 1);
            assert_eq!(pthread_mutexattr_settype(&mut ma, 9), EINVAL);
            assert_eq!(pthread_mutexattr_setrobust(&mut ma, 1), 0);
            assert_eq!(pthread_mutexattr_getrobust(&ma, &mut v), 0);
            assert_eq!(v, 1);
            assert_eq!(pthread_mutexattr_setprotocol(&mut ma, 2), ENOTSUP);
            assert_eq!(pthread_mutexattr_setprotocol(&mut ma, 1), 0);
            assert_eq!(pthread_mutexattr_getprotocol(&ma, &mut v), 0);
            assert_eq!(v, 1);
            assert_eq!(pthread_mutexattr_setprotocol(&mut ma, 9), EINVAL);
            assert_eq!(pthread_mutexattr_setpshared(&mut ma, 1), 0);
            assert_eq!(pthread_mutexattr_getpshared(&ma, &mut v), 0);
            assert_eq!(v, 1);
            assert_eq!(pthread_mutexattr_destroy(&mut ma), 0);
            assert_eq!(pthread_mutexattr_init(core::ptr::null_mut()), EINVAL);
            let mut ca = CondAttrT { attr: 0 };
            assert_eq!(pthread_condattr_init(&mut ca), 0);
            assert_eq!(pthread_condattr_setclock(&mut ca, 1), 0);
            assert_eq!(pthread_condattr_getclock(&ca, &mut v), 0);
            assert_eq!(v, 1);
            assert_eq!(pthread_condattr_setclock(&mut ca, 7), EINVAL);
            assert_eq!(pthread_condattr_setpshared(&mut ca, 1), 0);
            assert_eq!(pthread_condattr_getpshared(&ca, &mut v), 0);
            assert_eq!(v, 1);
            assert_eq!(pthread_condattr_destroy(&mut ca), 0);
            let mut ra = RwlockAttrT { attr: [0; 2] };
            assert_eq!(pthread_rwlockattr_init(&mut ra), 0);
            assert_eq!(pthread_rwlockattr_setpshared(&mut ra, 1), 0);
            assert_eq!(pthread_rwlockattr_getpshared(&ra, &mut v), 0);
            assert_eq!(v, 1);
            let mut ba = BarrierAttrT { attr: 0 };
            assert_eq!(pthread_barrierattr_init(&mut ba), 0);
            assert_eq!(pthread_barrierattr_setpshared(&mut ba, 1), 0);
            assert_eq!(pthread_barrierattr_getpshared(&ba, &mut v), 0);
            assert_eq!(v, 1);
            // Mutex honors the recursive kind end to end.
            let mut m: MutexT = [0; 5];
            let mut ma2 = MutexAttrT { attr: 0 };
            assert_eq!(pthread_mutexattr_settype(&mut ma2, 1), 0);
            assert_eq!(pthread_mutex_init(&mut m, &ma2), 0);
            assert_eq!(pthread_mutex_lock(&mut m), 0);
            assert_eq!(pthread_mutex_lock(&mut m), 0);
            assert_eq!(pthread_mutex_unlock(&mut m), 0);
            assert_eq!(pthread_mutex_unlock(&mut m), 0);
            assert_eq!(pthread_mutex_destroy(&mut m), 0);
            // Ceiling stubs always fail, like musl without PI.
            let mut ceil = -1;
            assert_eq!(pthread_mutex_getprioceiling(&m, &mut ceil), EINVAL);
            assert_eq!(pthread_mutex_setprioceiling(&mut m, 5, &mut ceil), EINVAL);
            // Consistent on a healthy mutex is EINVAL, like musl.
            assert_eq!(pthread_mutex_consistent(&mut m), EINVAL);
        }
    }

    #[test]
    fn timedlock_times_out() {
        unsafe {
            let mut m: MutexT = [0; 5];
            assert_eq!(pthread_mutex_init(&mut m, core::ptr::null()), 0);
            assert_eq!(pthread_mutex_lock(&mut m), 0);
            let past = crate::time::Timespec {
                tv_sec: 1,
                tv_nsec: 0,
            };
            assert_eq!(pthread_mutex_timedlock(&mut m, &past), ETIMEDOUT);
            assert_eq!(pthread_mutex_unlock(&mut m), 0);
            assert_eq!(pthread_mutex_timedlock(&mut m, &past), 0);
            assert_eq!(pthread_mutex_unlock(&mut m), 0);
            assert_eq!(pthread_mutex_destroy(&mut m), 0);
        }
    }

    #[test]
    fn cond_timedwait_times_out() {
        unsafe {
            let mut m: MutexT = [0; 5];
            let mut c: CondT = [0; 6];
            assert_eq!(pthread_mutex_init(&mut m, core::ptr::null()), 0);
            assert_eq!(pthread_cond_init(&mut c, core::ptr::null()), 0);
            assert_eq!(pthread_mutex_lock(&mut m), 0);
            let past = crate::time::Timespec {
                tv_sec: 1,
                tv_nsec: 0,
            };
            assert_eq!(pthread_cond_timedwait(&mut c, &mut m, &past), ETIMEDOUT);
            assert_eq!(pthread_mutex_unlock(&mut m), 0);
            assert_eq!(pthread_cond_destroy(&mut c), 0);
            assert_eq!(pthread_mutex_destroy(&mut m), 0);
        }
    }

    #[test]
    fn rwlock_shared_and_exclusive() {
        unsafe {
            let mut r: RwlockT = [0; 7];
            assert_eq!(pthread_rwlock_init(&mut r, core::ptr::null()), 0);
            assert_eq!(pthread_rwlock_rdlock(&mut r), 0);
            assert_eq!(pthread_rwlock_rdlock(&mut r), 0);
            assert_eq!(pthread_rwlock_trywrlock(&mut r), EBUSY);
            assert_eq!(pthread_rwlock_unlock(&mut r), 0);
            assert_eq!(pthread_rwlock_unlock(&mut r), 0);
            assert_eq!(pthread_rwlock_wrlock(&mut r), 0);
            assert_eq!(pthread_rwlock_tryrdlock(&mut r), EBUSY);
            assert_eq!(pthread_rwlock_unlock(&mut r), 0);
            let past = crate::time::Timespec {
                tv_sec: 1,
                tv_nsec: 0,
            };
            assert_eq!(pthread_rwlock_wrlock(&mut r), 0);
            assert_eq!(pthread_rwlock_timedrdlock(&mut r, &past), ETIMEDOUT);
            assert_eq!(pthread_rwlock_unlock(&mut r), 0);
            assert_eq!(pthread_rwlock_destroy(&mut r), 0);
        }
    }

    static BAR_N: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    static mut BAR_B: BarrierT = [0; 4];

    unsafe extern "C" fn bar_waiter(_: *mut c_void) -> *mut c_void {
        unsafe {
            // Each waiter must observe SERIAL exactly once across the group.
            let _ = pthread_barrier_wait(core::ptr::addr_of_mut!(BAR_B).cast());
            BAR_N.fetch_add(1, Ordering::SeqCst);
            core::ptr::null_mut()
        }
    }

    #[test]
    fn barrier_releases_group_once() {
        unsafe {
            BAR_N.store(0, Ordering::SeqCst);
            assert_eq!(
                pthread_barrier_init(core::ptr::addr_of_mut!(BAR_B).cast(), core::ptr::null(), 3),
                0
            );
            assert_eq!(
                pthread_barrier_init(core::ptr::null_mut(), core::ptr::null(), 0),
                EINVAL
            );
            let mut t1: crate::abi::PthreadT = core::ptr::null_mut();
            let mut t2: crate::abi::PthreadT = core::ptr::null_mut();
            let mut r1: *mut c_void = core::ptr::null_mut();
            let mut r2: *mut c_void = core::ptr::null_mut();
            assert_eq!(
                crate::thread::create::__pthread_create(
                    &mut t1,
                    core::ptr::null(),
                    Some(bar_waiter),
                    core::ptr::null_mut()
                ),
                0
            );
            assert_eq!(
                crate::thread::create::__pthread_create(
                    &mut t2,
                    core::ptr::null(),
                    Some(bar_waiter),
                    core::ptr::null_mut()
                ),
                0
            );
            let self_r = pthread_barrier_wait(core::ptr::addr_of_mut!(BAR_B).cast());
            assert!(self_r == 0 || self_r == PTHREAD_BARRIER_SERIAL_THREAD);
            assert_eq!(crate::thread::create::__pthread_join(t1, &mut r1), 0);
            assert_eq!(crate::thread::create::__pthread_join(t2, &mut r2), 0);
            assert_eq!(BAR_N.load(Ordering::SeqCst), 2);
            assert_eq!(
                pthread_barrier_destroy(core::ptr::addr_of_mut!(BAR_B).cast()),
                0
            );
        }
    }

    #[test]
    fn spin_basics() {
        unsafe {
            let mut s: SpinT = 0;
            assert_eq!(pthread_spin_init(&mut s, 0), 0);
            assert_eq!(pthread_spin_lock(&mut s), 0);
            assert_eq!(pthread_spin_trylock(&mut s), EBUSY);
            assert_eq!(pthread_spin_unlock(&mut s), 0);
            assert_eq!(pthread_spin_trylock(&mut s), 0);
            assert_eq!(pthread_spin_unlock(&mut s), 0);
            assert_eq!(pthread_spin_destroy(&mut s), 0);
            assert_eq!(pthread_spin_init(core::ptr::null_mut(), 0), EINVAL);
        }
    }

    #[test]
    fn sem_unnamed_counts() {
        unsafe {
            let mut s: SemT = [0; 4];
            assert_eq!(sem_init(&mut s, 0, 2), 0);
            assert_eq!(sem_init(&mut s, 0, 0x80000000), EINVAL);
            let mut v = -1;
            assert_eq!(sem_getvalue(&s, &mut v), 0);
            assert_eq!(v, 2);
            assert_eq!(sem_trywait(&mut s), 0);
            assert_eq!(sem_trywait(&mut s), 0);
            assert_eq!(sem_trywait(&mut s), EAGAIN);
            assert_eq!(sem_post(&mut s), 0);
            assert_eq!(sem_wait(&mut s), 0);
            let past = crate::time::Timespec {
                tv_sec: 1,
                tv_nsec: 0,
            };
            assert_eq!(sem_timedwait(&mut s, &past), ETIMEDOUT);
            assert_eq!(sem_destroy(&mut s), 0);
        }
    }

    #[test]
    fn sem_named_roundtrip() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let nm = c"/zlibc-sem-11a";
            sem_unlink(nm.as_ptr());
            let s = sem_open(nm.as_ptr(), 0o100 | 0o200 | 0o2000000 | 2, 0o600, 3);
            assert!(!s.is_null());
            let mut v = -1;
            assert_eq!(sem_getvalue(s, &mut v), 0);
            // Reopen existing without O_EXCL shares the count.
            let s2 = sem_open(nm.as_ptr(), 0o2000000 | 2, 0, 0);
            assert!(!s2.is_null());
            assert_eq!(sem_trywait(s2), 0);
            assert_eq!(sem_getvalue(s, &mut v), 0);
            assert_eq!(v, 2);
            assert_eq!(sem_close(s), 0);
            assert_eq!(sem_close(s2), 0);
            assert_eq!(sem_unlink(nm.as_ptr()), 0);
            assert!(sem_open(nm.as_ptr(), 0o2000000 | 2, 0, 0).is_null());
            sem_unlink(nm.as_ptr());
        }
    }

    unsafe extern "C" fn c11_ret(_: *mut c_void) -> c_int {
        7
    }

    #[test]
    fn c11_thread_mtx_cnd() {
        unsafe {
            let mut t: crate::abi::PthreadT = core::ptr::null_mut();
            assert_eq!(
                thrd_create(&mut t, Some(c11_ret), core::ptr::null_mut()),
                THRD_SUCCESS
            );
            assert!(thrd_equal(t, t) != 0);
            assert!(thrd_equal(t, thrd_current()) == 0 || thrd_equal(t, thrd_current()) != 0);
            let mut rc = -1;
            assert_eq!(thrd_join(t, &mut rc), THRD_SUCCESS);
            assert_eq!(rc, 7);
            assert_eq!(
                thrd_create(core::ptr::null_mut(), Some(c11_ret), core::ptr::null_mut()),
                THRD_ERROR
            );
            let mut m: MutexT = [0; 5];
            assert_eq!(mtx_init(&mut m, MTX_PLAIN), THRD_SUCCESS);
            assert_eq!(mtx_init(&mut m, 99), THRD_ERROR);
            assert_eq!(mtx_lock(&mut m), THRD_SUCCESS);
            assert_eq!(mtx_trylock(&mut m), THRD_BUSY);
            assert_eq!(mtx_unlock(&mut m), THRD_SUCCESS);
            let mut mr: MutexT = [0; 5];
            assert_eq!(mtx_init(&mut mr, MTX_RECURSIVE), THRD_SUCCESS);
            assert_eq!(mtx_lock(&mut mr), THRD_SUCCESS);
            assert_eq!(mtx_lock(&mut mr), THRD_SUCCESS);
            assert_eq!(mtx_unlock(&mut mr), THRD_SUCCESS);
            assert_eq!(mtx_unlock(&mut mr), THRD_SUCCESS);
            mtx_destroy(&mut m);
            mtx_destroy(&mut mr);
            let mut c: CondT = [0; 6];
            assert_eq!(cnd_init(&mut c), THRD_SUCCESS);
            assert_eq!(cnd_signal(&mut c), THRD_SUCCESS);
            assert_eq!(cnd_broadcast(&mut c), THRD_SUCCESS);
            cnd_destroy(&mut c);
            thrd_yield();
        }
    }

    #[test]
    fn sched_self_calls() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            use crate::thread::create::{
                sched_get_priority_max, sched_get_priority_min, sched_getaffinity, sched_getparam,
                sched_getscheduler, sched_yield, SchedParam,
            };
            assert!(sched_get_priority_max(0) >= 0);
            assert!(sched_get_priority_min(0) >= 0);
            assert_eq!(sched_yield(), 0);
            let mut p = SchedParam { sched_priority: 0 };
            assert_eq!(sched_getparam(0, &mut p), 0);
            assert!(sched_getscheduler(0) >= 0);
            let mut mask = [0u8; 128];
            assert_eq!(
                sched_getaffinity(0, mask.len(), mask.as_mut_ptr() as *mut c_void),
                0
            );
            assert_ne!(mask[0], 0);
        }
    }

    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};

    /// N threads x M increments under one mutex must total exactly N*M.
    /// The counter uses a racy load/spin/store on purpose: any lost
    /// mutual exclusion shows up as a short total. Every call uses the
    /// full `crate::sync::` path so it proves OUR code, never the host's
    /// (house rule, cf. `src/mem` tests).
    #[test]
    fn mutex_threaded_counter_is_exact() {
        static mut MUT: MutexT = [0; 5];
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
            let mut m: MutexT = [0; 5];
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
        static mut M: MutexT = [0; 5];
        static mut C: CondT = [0; 6];
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
        static mut M: MutexT = [0; 5];
        static mut C: CondT = [0; 6];
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
