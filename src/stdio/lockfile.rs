//! Stream locking (musl `__lockfile.c`, `flockfile.c`, `ftrylockfile.c`,
//! `funlockfile.c`, reimplemented).
//!
//! Shape mirrors musl: `lock: AtomicI32` holds the owner tid plus
//! `MAYBE_WAITERS`; `lockcount` is the recursive-hold depth. The fast
//! path is compare-exchange only (async-signal-safe); contended waits
//! sleep in `futex_wait_private` and wake one sleeper on unlock.
//!
//! Deviations from musl, one line each:
//! - NO `stdio_locks`/`next_locked`/`prev_locked` list (our Thread struct
//!   has no such fields), so a thread dying while holding a FILE lock
//!   leaves waiters hanging; orphan recovery returns with the thread wave.
//! - `ftrylockfile` saturates `lockcount` at `c_long::MAX`, returning -1.
//! - `flockfile` after a saturated `ftrylockfile` leaves `lockcount` at
//!   MAX (musl would reset it to 1 via `__register_locked_file`).
//! - Null `f`: `flockfile`/`funlockfile` no-op, `ftrylockfile` returns -1
//!   (musl would segfault).
//! - Owner identity is a raw `SYS_gettid` syscall (186, verified against
//!   musl `arch/x86_64/bits/syscall.h.in`: `__NR_gettid 186`); no
//!   thread-pointer dereference anywhere (`%fs:0` forbidden).
//! - No `MutexT` anywhere here (it would recurse with the global slock).

use core::ffi::{c_int, c_long};
use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicI32, Ordering};

use super::File;
use crate::futex::{futex_wait_private, futex_wake_private};
use crate::syscall::syscall0;

/// musl `arch/x86_64/bits/syscall.h.in` (`__NR_gettid 186`, verified).
#[cfg(target_arch = "x86_64")]
const SYS_GETTID: usize = 186;
/// musl `src/internal/stdio_impl.h:93`.
const MAYBE_WAITERS: c_int = 0x4000_0000;

/// Raw owner identity (sync-signal-safe single syscall, no TLS read).
#[cfg(target_arch = "x86_64")]
#[inline]
fn gettid() -> c_int {
    unsafe { syscall0(SYS_GETTID) as c_int }
}

/// musl `a_cas`: swap only when `*atom == old`, return the previous value.
#[cfg(target_arch = "x86_64")]
#[inline]
fn cas(atom: &AtomicI32, old: c_int, new: c_int) -> c_int {
    atom.compare_exchange(old, new, Ordering::SeqCst, Ordering::SeqCst)
        .unwrap_or_else(|actual| actual)
}

/// Lock `f`, blocking (musl `__lockfile.c:4-17`).
///
/// Returns 1 when newly acquired, 0 when already owned by this thread
/// (the caller then handles `lockcount`). Never touches `lockcount`.
///
/// # Safety
///
/// `f` must point to a live `File`.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn __lockfile(f: *mut File) -> c_int {
    unsafe {
        let tid = gettid();
        let atom = &(*f).lock;
        let mut owner = atom.load(Ordering::SeqCst);
        if (owner & !MAYBE_WAITERS) == tid {
            return 0;
        }
        owner = cas(atom, 0, tid);
        if owner == 0 {
            return 1;
        }
        loop {
            owner = cas(atom, 0, tid | MAYBE_WAITERS);
            if owner == 0 {
                return 1;
            }
            if (owner & MAYBE_WAITERS) != 0 || cas(atom, owner, owner | MAYBE_WAITERS) == owner {
                let addr = addr_of_mut!((*f).lock) as *mut c_int;
                futex_wait_private(addr, owner | MAYBE_WAITERS);
            }
        }
    }
}

/// Release `f`, waking one waiter if flagged (musl `__lockfile.c:19-23`).
///
/// # Safety
///
/// `f` must point to a live `File` locked by this thread; never touches
/// `lockcount` (the caller owns it).
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn __unlockfile(f: *mut File) {
    unsafe {
        let prev = (*f).lock.swap(0, Ordering::SeqCst);
        if (prev & MAYBE_WAITERS) != 0 {
            let addr = addr_of_mut!((*f).lock) as *mut c_int;
            futex_wake_private(addr, 1);
        }
    }
}

/// Lock `f`, blocking; recursive takes bump `lockcount` (musl
/// `flockfile.c:4-9` minus the locked-file list).
///
/// # Safety
///
/// `f` must point to a live `File` (null is a no-op, see above).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn flockfile(f: *mut File) {
    unsafe {
        if f.is_null() {
            return;
        }
        if ftrylockfile(f) == 0 {
            return;
        }
        // Contention path won the lock; recursion-at-saturation (0) keeps MAX.
        if __lockfile(f) != 0 {
            (*f).lockcount = 1;
        }
    }
}

/// Try to lock `f` (musl `ftrylockfile.c:30-46` minus the locked-file
/// list): 0 on success (recursive takes bump `lockcount`, saturating at
/// `c_long::MAX`), -1 when held by another thread, orphaned-negative
/// words reset to 0 exactly like musl's `if (owner < 0)` line.
///
/// # Safety
///
/// `f` must point to a live `File` (null returns -1, see above).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ftrylockfile(f: *mut File) -> c_int {
    unsafe {
        if f.is_null() {
            return -1;
        }
        let tid = gettid();
        let atom = &(*f).lock;
        let mut owner = atom.load(Ordering::SeqCst);
        if (owner & !MAYBE_WAITERS) == tid {
            if (*f).lockcount == c_long::MAX {
                return -1;
            }
            (*f).lockcount += 1;
            return 0;
        }
        if owner < 0 {
            atom.store(0, Ordering::SeqCst);
            owner = 0;
        }
        if owner != 0 || cas(atom, 0, tid) != 0 {
            return -1;
        }
        (*f).lockcount = 1;
        0
    }
}

/// Unlock `f` (musl `funlockfile.c:4-13` minus the locked-file list):
/// the last hold clears the futex word (waking one waiter), outer holds
/// just decrement `lockcount`.
///
/// # Safety
///
/// `f` must point to a live `File` locked by this thread (null is a
/// no-op, see above); unlocking another thread's lock is undefined.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn funlockfile(f: *mut File) {
    unsafe {
        if f.is_null() {
            return;
        }
        if (*f).lockcount == 1 {
            (*f).lockcount = 0;
            __unlockfile(f);
        } else {
            (*f).lockcount -= 1;
        }
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::{__lockfile, __unlockfile, flockfile, ftrylockfile, funlockfile, gettid, File};
    use core::ptr::{addr_of_mut, null_mut};
    use core::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
    use std::vec::Vec;

    fn fresh() -> File {
        File {
            fd: -1,
            flags: 0,
            line_buf: false,
            buf: null_mut(),
            cap: 0,
            wpos: 0,
            rpos: 0,
            rlen: 0,
            next: null_mut(),
            lock: AtomicI32::new(0),
            lockcount: 0,
        }
    }

    #[test]
    fn lock_unlock_relock_sequence() {
        let mut f = fresh();
        let f = addr_of_mut!(f);
        unsafe {
            flockfile(f);
            assert_eq!((*f).lockcount, 1);
            assert_eq!((*f).lock.load(Ordering::SeqCst), gettid());
            flockfile(f); // recursive: bumps, same owner
            assert_eq!((*f).lockcount, 2);
            assert_eq!(ftrylockfile(f), 0); // recursive try: bumps too
            assert_eq!((*f).lockcount, 3);
            funlockfile(f);
            funlockfile(f);
            assert_eq!((*f).lockcount, 1);
            assert_ne!((*f).lock.load(Ordering::SeqCst), 0);
            funlockfile(f);
            assert_eq!((*f).lockcount, 0);
            assert_eq!((*f).lock.load(Ordering::SeqCst), 0);
            // Relock after full release works.
            assert_eq!(ftrylockfile(f), 0);
            assert_eq!((*f).lockcount, 1);
            funlockfile(f);
            assert_eq!((*f).lock.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn null_is_noop_or_fail() {
        unsafe {
            flockfile(null_mut());
            funlockfile(null_mut());
            assert_eq!(ftrylockfile(null_mut()), -1);
        }
    }

    #[test]
    fn lockfile_pair_returns_owner_hint() {
        let mut f = fresh();
        let f = addr_of_mut!(f);
        unsafe {
            assert_eq!(__lockfile(f), 1);
            assert_eq!(__lockfile(f), 0); // recursive: already owned
            __unlockfile(f);
            assert_eq!((*f).lock.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn gettid_nonzero_and_distinct_across_threads() {
        let t0 = gettid();
        assert!(t0 > 0);
        let t1 = std::thread::spawn(gettid).join().unwrap();
        assert!(t1 > 0);
        assert_ne!(t0, t1);
    }

    static mut CONT_F: File = File {
        fd: -1,
        flags: 0,
        line_buf: false,
        buf: null_mut(),
        cap: 0,
        wpos: 0,
        rpos: 0,
        rlen: 0,
        next: null_mut(),
        lock: AtomicI32::new(0),
        lockcount: 0,
    };
    static TRIED: AtomicBool = AtomicBool::new(false);
    static GO: AtomicBool = AtomicBool::new(false);
    static DONE: AtomicBool = AtomicBool::new(false);

    #[test]
    fn trylock_fails_while_held_then_succeeds() {
        unsafe {
            let f = addr_of_mut!(CONT_F);
            TRIED.store(false, Ordering::SeqCst);
            GO.store(false, Ordering::SeqCst);
            DONE.store(false, Ordering::SeqCst);
            flockfile(f);
            let faddr = f as usize;
            let h = std::thread::spawn(move || {
                let f = faddr as *mut File;
                // Contended: must fail while main holds it.
                assert_ne!(ftrylockfile(f), 0);
                TRIED.store(true, Ordering::SeqCst);
                // Spin until main releases, then take it (no sleeps).
                while ftrylockfile(f) != 0 {
                    while !GO.load(Ordering::SeqCst) {
                        core::hint::spin_loop();
                    }
                }
                funlockfile(f);
                DONE.store(true, Ordering::SeqCst);
            });
            while !TRIED.load(Ordering::SeqCst) {
                core::hint::spin_loop();
            }
            funlockfile(f);
            GO.store(true, Ordering::SeqCst);
            while !DONE.load(Ordering::SeqCst) {
                core::hint::spin_loop();
            }
            h.join().unwrap();
            assert_eq!((*f).lock.load(Ordering::SeqCst), 0);
        }
    }

    static mut EXCL_F: File = File {
        fd: -1,
        flags: 0,
        line_buf: false,
        buf: null_mut(),
        cap: 0,
        wpos: 0,
        rpos: 0,
        rlen: 0,
        next: null_mut(),
        lock: AtomicI32::new(0),
        lockcount: 0,
    };
    static CNT: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn contended_counter_stays_exact() {
        unsafe {
            let f = addr_of_mut!(EXCL_F);
            (*f).lock.store(0, Ordering::SeqCst);
            (*f).lockcount = 0;
        }
        CNT.store(0, Ordering::SeqCst);
        let mut hs = Vec::new();
        for _ in 0..4 {
            hs.push(std::thread::spawn(|| unsafe {
                let f = addr_of_mut!(EXCL_F);
                for _ in 0..1000 {
                    flockfile(f); // blocking path under real contention
                    CNT.fetch_add(1, Ordering::Relaxed);
                    funlockfile(f);
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(CNT.load(Ordering::SeqCst), 4000);
    }

    static mut PING_F: File = File {
        fd: -1,
        flags: 0,
        line_buf: false,
        buf: null_mut(),
        cap: 0,
        wpos: 0,
        rpos: 0,
        rlen: 0,
        next: null_mut(),
        lock: AtomicI32::new(0),
        lockcount: 0,
    };
    static PING: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn two_thread_ping_pong_alternates() {
        unsafe {
            let f = addr_of_mut!(PING_F);
            (*f).lock.store(0, Ordering::SeqCst);
            (*f).lockcount = 0;
        }
        PING.store(0, Ordering::SeqCst);
        unsafe {
            // Seed an odd turn before spawning so the peer's parity holds.
            let f = addr_of_mut!(PING_F);
            flockfile(f);
            PING.store(1, Ordering::Relaxed);
            funlockfile(f);
        }
        let h = std::thread::spawn(|| unsafe {
            let f = addr_of_mut!(PING_F);
            for _ in 0..500 {
                flockfile(f);
                // Wait for the odd turn the same way main waits for even.
                while PING.load(Ordering::Relaxed) % 2 != 1 {
                    funlockfile(f);
                    core::hint::spin_loop();
                    flockfile(f);
                }
                let v = PING.load(Ordering::Relaxed);
                assert!(v % 2 == 1, "pong saw even turn {v}");
                PING.store(v + 1, Ordering::Relaxed);
                funlockfile(f);
            }
        });
        unsafe {
            let f = addr_of_mut!(PING_F);
            for _ in 0..500 {
                flockfile(f);
                // Spin until the peer hands us an even turn (no sleeps).
                while !PING.load(Ordering::Relaxed).is_multiple_of(2) {
                    funlockfile(f);
                    core::hint::spin_loop();
                    flockfile(f);
                }
                let v = PING.load(Ordering::Relaxed);
                PING.store(v + 1, Ordering::Relaxed);
                funlockfile(f);
            }
        }
        h.join().unwrap();
        assert_eq!(PING.load(Ordering::SeqCst), 1001);
    }
}
