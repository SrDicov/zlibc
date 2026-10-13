//! D2 packet 1: `mmap`-backed free-list allocator (lite class).
//!
//! Semantics mirror musl `src/malloc/lite_malloc.c` + `calloc.c` +
//! `realloc.c` + `free.c` (verified, reimplemented): `ALIGN = 16`,
//! `malloc(0)` gives the smallest object (never NULL), oversize
//! (`> SIZE_MAX/2`) fails with `ENOMEM`, arenas never unmap, `free`
//! coalesces neighbours. The full size-class engine (`mallocng`) stays
//! OUT: one ordered free list with split/coalesce is the smallest engine
//! with identical observable contracts (`shortcut:` — upgrade when
//! fragmentation is measured, not before).
//!
//! Thread safety: one global `NORMAL` mutex (C2 primitives, atomics +
//! futex — no `FS` needed, so host threads are served too). No function
//! here allocates (only raw syscalls + atomics), so there is no
//! self-recursion.

use core::ffi::{c_int, c_void};
use core::ptr::{addr_of_mut, null_mut};

use crate::errno::__errno_location;
use crate::mem::{memcpy, memset};
use crate::sync::{pthread_mutex_lock, pthread_mutex_unlock, MutexT};
use crate::syscall::{syscall6, syscall_ret};

// ---- Syscalls/consts (musl arch/x86_64/bits/syscall.h.in) -------------------
#[cfg(target_arch = "x86_64")]
const SYS_MMAP: usize = 9; // TODO: generate from arch bits/syscall.h
/// musl `arch/generic/bits/errno.h:12`.
const ENOMEM: c_int = 12;
/// musl `include/sys/mman.h`.
const PROT_RW: c_int = 1 | 2; // PROT_READ | PROT_WRITE
const MAP_ANON: c_int = 0x02 | 0x20; // MAP_PRIVATE | MAP_ANONYMOUS

const ALIGN: usize = 16;
/// Smallest arena per `mmap` (musl lite rounds the same way).
const ARENA_MIN: usize = 65536;
/// Header + smallest payload: splits leaving less never pay off.
const MIN_CHUNK: usize = 32;

/// Chunk header: total size (this header included) + intrusive free link.
/// Exactly 16 bytes, so payload stays 16-aligned.
struct Chunk {
    size: usize,
    next: *mut Chunk,
}

static mut FREE_HEAD: *mut Chunk = null_mut();
static mut HEAP_LOCK: MutexT = [0; 5];

fn lock() {
    unsafe {
        pthread_mutex_lock(addr_of_mut!(HEAP_LOCK));
    }
}

fn unlock() {
    unsafe {
        pthread_mutex_unlock(addr_of_mut!(HEAP_LOCK));
    }
}

fn align_up(n: usize) -> Option<usize> {
    n.checked_add(ALIGN - 1).map(|m| m & !(ALIGN - 1))
}

/// Carve `[ptr, ptr+len)` into the free list as one chunk (caller holds
/// the lock; no coalescing — fresh arenas never neighbour old chunks).
unsafe fn feed(ptr: *mut u8, len: usize) {
    unsafe {
        let c = ptr as *mut Chunk;
        (*c).size = len;
        (*c).next = addr_of_mut!(FREE_HEAD).read();
        addr_of_mut!(FREE_HEAD).write(c);
    }
}

/// Take `need` bytes (already aligned, header included) from the list.
/// Splits when the leftover fits another chunk; single exit, no early
/// returns while the lock is conceptually held by the caller.
unsafe fn take(need: usize) -> *mut u8 {
    unsafe {
        let mut link = addr_of_mut!(FREE_HEAD);
        while !(*link).is_null() {
            let c = *link;
            if (*c).size >= need {
                let rest = (*c).size - need;
                if rest >= MIN_CHUNK {
                    (*c).size = need;
                    let tail = (c as *mut u8).add(need) as *mut Chunk;
                    (*tail).size = rest;
                    (*tail).next = (*c).next;
                    *link = tail;
                } else {
                    *link = (*c).next;
                }
                return (c as *mut u8).add(size_of::<Chunk>());
            }
            link = addr_of_mut!((*c).next);
        }
        null_mut()
    }
}

/// Insert a freed chunk address-ordered, merging live neighbours.
unsafe fn give(ptr: *mut u8, len: usize) {
    unsafe {
        // First chunk above `ptr`; `prev` trails one behind.
        let mut prev: *mut Chunk = null_mut();
        let mut cur = addr_of_mut!(FREE_HEAD).read();
        while !cur.is_null() && (cur as usize) < ptr as usize {
            prev = cur;
            cur = (*cur).next;
        }
        let base = ptr as usize;
        let mut size = len;
        // Absorb the successor when adjacent.
        if !cur.is_null() && base + size == cur as usize {
            size += (*cur).size;
            cur = (*cur).next;
        }
        // Absorb into the predecessor when adjacent, else link fresh.
        if !prev.is_null() && (prev as usize) + (*prev).size == base {
            (*prev).size += size;
            (*prev).next = cur;
        } else {
            let c = ptr as *mut Chunk;
            (*c).size = size;
            (*c).next = cur;
            if prev.is_null() {
                addr_of_mut!(FREE_HEAD).write(c);
            } else {
                (*prev).next = c;
            }
        }
    }
}

fn set_oom() {
    unsafe {
        *__errno_location() = ENOMEM;
    }
}

/// Allocate `n` bytes (musl `malloc`, `src/malloc/mallocng/malloc.c`
/// contract: 0 → smallest object, oversize → `ENOMEM` + NULL).
///
/// # Safety
///
/// The returned pointer (when non-null) is writable for `n` bytes until
/// [`free`] runs on it. Never panics; safe to call from any thread.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn malloc(n: usize) -> *mut c_void {
    unsafe {
        let mut need = match align_up(n.max(1)) {
            Some(m) => m,
            None => {
                set_oom();
                return null_mut();
            }
        };
        need = match need.checked_add(size_of::<Chunk>()) {
            Some(m) => m,
            None => {
                set_oom();
                return null_mut();
            }
        };
        // musl oversize gate (`SIZE_MAX/2`, lite_malloc.c).
        if n > usize::MAX / 2 {
            set_oom();
            return null_mut();
        }
        lock();
        let mut out = take(need);
        if out.is_null() {
            let mut arena = need.max(ARENA_MIN);
            arena = (arena + 4095) & !4095;
            let map = syscall_ret(syscall6(
                SYS_MMAP,
                0,
                arena,
                PROT_RW as usize,
                MAP_ANON as usize,
                usize::MAX,
                0,
            ));
            if map == -1 {
                unlock();
                set_oom();
                return null_mut();
            }
            feed(map as *mut u8, arena);
            out = take(need);
        }
        unlock();
        if out.is_null() {
            set_oom();
        }
        out as *mut c_void
    }
}

/// Release `p` (musl `free`: NULL is a no-op).
///
/// # Safety
///
/// `p` must be null or a live pointer from [`malloc`]/[`calloc`]/
/// [`realloc`], freed exactly once.
#[no_mangle]
pub unsafe extern "C" fn free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    unsafe {
        lock();
        let c = (p as *mut u8).sub(size_of::<Chunk>()) as *mut Chunk;
        give(p as *mut u8, (*c).size);
        unlock();
    }
}

/// Allocate `m*n` zeroed bytes (musl `calloc`: overflow → `ENOMEM`).
///
/// # Safety
///
/// Same validity contract as [`malloc`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn calloc(m: usize, n: usize) -> *mut c_void {
    unsafe {
        if m != 0 && n > usize::MAX / m {
            set_oom();
            return null_mut();
        }
        let p = malloc(m.wrapping_mul(n));
        if !p.is_null() {
            memset(p, 0, m.wrapping_mul(n));
        }
        p
    }
}

/// Resize `p` to `n` bytes (musl `realloc`: NULL → `malloc`, 0 →
/// smallest object, shrink-in-place when it fits, else move).
///
/// # Safety
///
/// `p` must be null or live; the old pointer dies on success when the
/// result differs from it.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn realloc(p: *mut c_void, n: usize) -> *mut c_void {
    unsafe {
        if p.is_null() {
            return malloc(n);
        }
        if n > usize::MAX / 2 {
            set_oom();
            return null_mut();
        }
        let need = align_up(n.max(1)).and_then(|m| m.checked_add(size_of::<Chunk>()));
        let need = match need {
            Some(m) => m,
            None => {
                set_oom();
                return null_mut();
            }
        };
        lock();
        let c = (p as *mut u8).sub(size_of::<Chunk>()) as *mut Chunk;
        let old = (*c).size;
        if need <= old {
            // Shrink in place; the leftover stays wasted (cold path,
            // no split — simplicity over a few bytes).
            unlock();
            return p;
        }
        unlock();
        let q = malloc(n);
        if q.is_null() {
            return null_mut();
        }
        memcpy(q, p, old - size_of::<Chunk>());
        free(p);
        q
    }
}

#[cfg(test)]
mod tests {
    use super::{calloc, free, malloc, realloc};
    use core::ptr::null_mut;

    unsafe fn sum(p: *mut u8, n: usize) -> usize {
        unsafe {
            let mut s = 0usize;
            let mut k = 0;
            while k < n {
                s += *p.add(k) as usize;
                k += 1;
            }
            s
        }
    }

    #[test]
    fn malloc_free_roundtrip_and_reuse() {
        unsafe {
            let a = malloc(64) as *mut u8;
            assert!(!a.is_null());
            let mut k = 0;
            while k < 64 {
                *a.add(k) = (k & 0xff) as u8;
                k += 1;
            }
            assert_eq!(sum(a, 64), 2016);
            free(a as *mut core::ffi::c_void);
            let b = malloc(64) as *mut u8;
            assert!(!b.is_null());
            free(b as *mut core::ffi::c_void);
        }
    }

    #[test]
    fn edge_contracts_match_musl() {
        unsafe {
            // malloc(0) is a live smallest object, never NULL.
            let z = malloc(0);
            assert!(!z.is_null());
            *(z as *mut u8) = 0xaa;
            free(z);
            // free(NULL) is a no-op.
            free(null_mut());
            // Oversize fails clean, never panics.
            assert!(malloc(usize::MAX).is_null());
            assert!(malloc(usize::MAX / 2 + 1).is_null());
            assert!(calloc(usize::MAX, 2).is_null());
            assert!(realloc(null_mut(), usize::MAX).is_null());
        }
    }

    #[test]
    fn calloc_zeroes_and_realloc_moves_bytes() {
        unsafe {
            let c = calloc(16, 32) as *mut u8;
            assert!(!c.is_null());
            assert_eq!(sum(c, 512), 0);
            let mut k = 0;
            while k < 512 {
                *c.add(k) = 0x5a;
                k += 1;
            }
            // realloc(NULL, n) == malloc(n).
            let r = realloc(null_mut(), 128) as *mut u8;
            assert!(!r.is_null());
            // Grow preserves the payload.
            let g = realloc(c as *mut core::ffi::c_void, 2048) as *mut u8;
            assert!(!g.is_null());
            assert_eq!(sum(g, 512), 0x5a * 512);
            // realloc(p, 0) gives a live smallest object (musl, not free).
            let s = realloc(g as *mut core::ffi::c_void, 0);
            assert!(!s.is_null());
            free(r as *mut core::ffi::c_void);
            free(s);
        }
    }

    #[test]
    fn churn_and_thread_storm_hold() {
        unsafe {
            // 300 mixed-size cycles: split/coalesce churn.
            let mut k = 0;
            while k < 300 {
                let n = 1 + (k * 7919) % 5000;
                let p = malloc(n) as *mut u8;
                assert!(!p.is_null());
                *p = (k & 0xff) as u8;
                *(p.add(n - 1)) = (k & 0xff) as u8;
                assert_eq!(*p, (k & 0xff) as u8);
                free(p as *mut core::ffi::c_void);
                k += 1;
            }
        }
        // Host threads share the heap through the global lock.
        let mut hs = [None, None, None, None];
        let mut k = 0;
        while k < 4 {
            hs[k] = Some(std::thread::spawn(|| {
                let mut j = 0;
                while j < 100 {
                    unsafe {
                        let p = malloc(8 + j) as *mut u8;
                        assert!(!p.is_null());
                        *p = j as u8;
                        assert_eq!(*p, j as u8);
                        free(p as *mut core::ffi::c_void);
                    }
                    j += 1;
                }
            }));
            k += 1;
        }
        let mut k = 0;
        while k < 4 {
            hs[k].take().unwrap().join().unwrap();
            k += 1;
        }
    }
}
