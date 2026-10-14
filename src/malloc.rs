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
/// musl `arch/generic/bits/errno.h:22`.
const EINVAL: c_int = 22;
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

/// One live over-aligned object: payload address → chunk base + total.
#[derive(Clone, Copy)]
struct AlignRec {
    addr: usize,
    orig: usize,
    total: usize,
}

static mut FREE_HEAD: *mut Chunk = null_mut();
static mut HEAP_LOCK: MutexT = [0; 5];
/// Over-aligned records live here, not in-band: a magic stamp before the
/// payload would be ambiguous with a plain chunk header's link word.
/// 1024 concurrent over-aligned objects; beyond that aligned requests
/// fail clean instead of corrupting (documented lite-scope bound —
/// `mallocng` keeps no map at all).
const AMAP_CAP: usize = 1024;
static mut AMAP: [AlignRec; AMAP_CAP] = [AlignRec {
    addr: 0,
    orig: 0,
    total: 0,
}; AMAP_CAP];

/// Arena bounds for ownership checks, linked intrusively (no cap, no
/// extra mapping): 32 header bytes per arena keep every chunk
/// 16-aligned. `free`/`realloc` reject pointers outside all arenas
/// instead of corrupting the list (musl `mallocng` aborts the same way
/// on detectable corruption; mid-live-chunk frees stay UB, as in C).
struct Arena {
    base: usize,
    len: usize,
    next: *mut Arena,
}
const ARENA_HDR: usize = 32;

static mut ARENA_HEAD: *mut Arena = null_mut();

/// True when `[ptr, ptr+len)` lies fully inside one live arena.
unsafe fn in_heap_range(ptr: usize, len: usize) -> bool {
    unsafe {
        let end = match ptr.checked_add(len) {
            Some(e) => e,
            None => return false,
        };
        let mut a = addr_of_mut!(ARENA_HEAD).read();
        while !a.is_null() {
            if (*a).base <= ptr && end <= (*a).base.wrapping_add((*a).len) {
                return true;
            }
            a = (*a).next;
        }
        false
    }
}

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

/// Chunk total needed for `size` payload bytes at `alignment` (power of
/// two, ≥ 16): header + payload + worst-case pad. Chunk bases are always
/// 16-aligned, so padding above 16 tops out at `alignment - 16`.
fn want_total(alignment: usize, size: usize) -> Option<usize> {
    align_up(size.max(1))
        .and_then(|m| m.checked_add(size_of::<Chunk>()))
        .and_then(|m| m.checked_add(alignment - 16))
}

/// Take an `alignment`-aligned payload (lock held). Records over-aligned
/// objects in the side map; 16-aligned payloads need no record (their
/// header sits right before them, like plain chunks). Null on miss, full
/// map, or overflow — the caller mmaps and retries once.
unsafe fn take_aligned(alignment: usize, size: usize) -> *mut u8 {
    unsafe {
        let want = match want_total(alignment, size) {
            Some(m) => m,
            None => return null_mut(),
        };
        let raw = take(want);
        if raw.is_null() {
            return null_mut();
        }
        // `raw` is 16-aligned and so is every power-of-two step above.
        let addr = (raw as usize + alignment - 1) & !(alignment - 1);
        if addr != raw as usize {
            let mut slot = null_mut::<AlignRec>();
            let mut k = 0;
            while k < AMAP_CAP {
                let r = addr_of_mut!(AMAP).cast::<AlignRec>().add(k);
                if (*r).addr == 0 && slot.is_null() {
                    slot = r;
                }
                k += 1;
            }
            if slot.is_null() {
                give(raw, want);
                return null_mut();
            }
            let orig = (raw as usize - size_of::<Chunk>()) as *mut Chunk;
            (*slot).addr = addr;
            (*slot).orig = orig as usize;
            (*slot).total = (*orig).size;
        }
        addr as *mut u8
    }
}

/// Fresh address space for a `want`-sized chunk (lock held): one rounded
/// arena, header-linked for ownership checks, remainder fed whole;
/// splitting happens in `take`.
unsafe fn refill(want: usize) -> bool {
    unsafe {
        let arena = match want.max(ARENA_MIN).checked_add(4095).map(|m| m & !4095) {
            Some(m) => m,
            None => return false,
        };
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
            return false;
        }
        let head = map as *mut Arena;
        (*head).base = map as usize;
        (*head).len = arena;
        (*head).next = addr_of_mut!(ARENA_HEAD).read();
        addr_of_mut!(ARENA_HEAD).write(head);
        feed((map as *mut u8).add(ARENA_HDR), arena - ARENA_HDR);
        true
    }
}

/// Release a live payload (lock held): side-map hit for over-aligned,
/// validated header math for plain. Validation failures unlock and
/// panic (musl `mallocng` aborts the same way); the list is untouched
/// at that point, so the heap stays consistent for everyone else.
unsafe fn free_inner(addr: usize) {
    unsafe {
        let mut k = 0;
        while k < AMAP_CAP {
            let r = addr_of_mut!(AMAP).cast::<AlignRec>().add(k);
            if (*r).addr == addr {
                (*r).addr = 0;
                give((*r).orig as *mut u8, (*r).total);
                return;
            }
            k += 1;
        }
        let orig = match addr.checked_sub(size_of::<Chunk>()) {
            Some(o) if in_heap_range(o, size_of::<Chunk>()) && in_heap_range(addr, 1) => o,
            _ => {
                unlock();
                panic!("zlibc malloc: free of foreign pointer");
            }
        };
        give(orig as *mut u8, (*(orig as *mut Chunk)).size);
    }
}

/// Usable bytes behind a live payload (lock held): side-map hit for
/// over-aligned, validated header math for plain (same abort contract
/// as [`free_inner`]).
unsafe fn usable(addr: usize) -> usize {
    unsafe {
        let mut k = 0;
        while k < AMAP_CAP {
            let r = addr_of_mut!(AMAP).cast::<AlignRec>().add(k);
            if (*r).addr == addr {
                return (*r).orig + (*r).total - addr;
            }
            k += 1;
        }
        let orig = match addr.checked_sub(size_of::<Chunk>()) {
            Some(o) if in_heap_range(o, size_of::<Chunk>()) && in_heap_range(addr, 1) => o,
            _ => {
                unlock();
                panic!("zlibc malloc: realloc of foreign pointer");
            }
        };
        (*(orig as *mut Chunk)).size - size_of::<Chunk>()
    }
}

/// Insert a freed chunk address-ordered, merging live neighbours.
/// Rejects an already-listed node first: linking one node twice would
/// close a cycle and hang `take` forever (double free aborts like musl
/// `mallocng`; the lock is released before panicking so the heap — and
/// every other thread — survives).
unsafe fn give(ptr: *mut u8, len: usize) {
    unsafe {
        let mut c = addr_of_mut!(FREE_HEAD).read();
        while !c.is_null() {
            if c as usize == ptr as usize {
                unlock();
                panic!("zlibc malloc: double free");
            }
            // Alias strictly inside a listed range (mid-chunk free of
            // free space): same abort, same reason.
            if (c as usize) < ptr as usize && (ptr as usize) < (c as usize) + (*c).size {
                unlock();
                panic!("zlibc malloc: free inside free space");
            }
            c = (*c).next;
        }
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
        crate::errno::errno_store(__errno_location(), ENOMEM);
    }
}

fn set_err(e: c_int) {
    unsafe {
        crate::errno::errno_store(__errno_location(), e);
    }
}

/// Shared engine for every entry point (lock inside): `size` payload
/// bytes at `alignment` (power of two, ≥ 16), one arena refill on miss.
unsafe fn aligned_body(alignment: usize, size: usize) -> *mut c_void {
    unsafe {
        // musl oversize gate (`SIZE_MAX/2`, lite_malloc.c).
        if size > usize::MAX / 2 {
            set_oom();
            return null_mut();
        }
        let want = match want_total(alignment, size) {
            Some(m) => m,
            None => {
                set_oom();
                return null_mut();
            }
        };
        lock();
        let mut out = take_aligned(alignment, size);
        if out.is_null() && refill(want) {
            out = take_aligned(alignment, size);
        }
        unlock();
        if out.is_null() {
            set_oom();
        }
        out as *mut c_void
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
    unsafe { aligned_body(16, n) }
}

/// Release `p` (musl `free`: NULL is a no-op).
///
/// # Safety
///
/// `p` must be null or a live pointer from any entry point in this
/// module (plain or over-aligned), freed exactly once. Double frees and
/// foreign pointers abort the process (musl `mallocng` fails the same
/// way); the heap stays consistent for everyone else.
#[no_mangle]
pub unsafe extern "C" fn free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    unsafe {
        lock();
        free_inner(p as usize);
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
        let aligned = match align_up(n.max(1)) {
            Some(m) => m,
            None => {
                set_oom();
                return null_mut();
            }
        };
        lock();
        let old = usable(p as usize);
        if aligned <= old {
            // In place when it fits (aligned payloads keep their
            // alignment; plain shrink wastes the leftover — cold path
            // simplicity, same as before).
            unlock();
            return p;
        }
        let keep = old.min(n);
        unlock();
        let q = malloc(n);
        if q.is_null() {
            return null_mut();
        }
        memcpy(q, p, keep);
        free(p);
        q
    }
}

/// Aligned allocation, C11 (musl `aligned_alloc`: non-zero power-of-two
/// alignment with `size` a multiple of it, else `EINVAL` + NULL).
///
/// # Safety
///
/// Same validity contract as [`malloc`], plus `p % alignment == 0`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn aligned_alloc(alignment: usize, size: usize) -> *mut c_void {
    unsafe {
        if alignment == 0 || alignment & (alignment - 1) != 0 || !size.is_multiple_of(alignment) {
            set_err(EINVAL);
            return null_mut();
        }
        aligned_body(alignment.max(16), size)
    }
}

/// Aligned allocation, POSIX (musl `posix_memalign`: power-of-two
/// alignment, else `EINVAL`; NULL `memptr` is `EINVAL`, never a fault).
///
/// # Safety
///
/// `memptr` must be writable; on success it holds a live aligned object.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_memalign(
    memptr: *mut *mut c_void,
    alignment: usize,
    size: usize,
) -> c_int {
    if memptr.is_null() {
        return EINVAL;
    }
    unsafe {
        if alignment == 0 || alignment & (alignment - 1) != 0 {
            *memptr = null_mut();
            return EINVAL;
        }
        let p = aligned_body(alignment.max(16), size);
        *memptr = p;
        if p.is_null() {
            ENOMEM
        } else {
            0
        }
    }
}

/// Aligned allocation, lenient (musl `memalign`: rounds the alignment up
/// to a usable power of two instead of failing).
///
/// # Safety
///
/// Same validity contract as [`aligned_alloc`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn memalign(alignment: usize, size: usize) -> *mut c_void {
    unsafe {
        // Bit-trick pow2 ceiling (no version-sensitive helpers). A wrapped
        // ceiling (absurd input) would silently under-align SIMD/page
        // tricks downstream: fail clean instead.
        let mut a = alignment.max(16).wrapping_sub(1);
        a |= a >> 1;
        a |= a >> 2;
        a |= a >> 4;
        a |= a >> 8;
        a |= a >> 16;
        #[cfg(target_pointer_width = "64")]
        let a = a | (a >> 32);
        let a = a.wrapping_add(1);
        if a < alignment || a < 16 {
            set_oom();
            return null_mut();
        }
        aligned_body(a, size)
    }
}

#[cfg(test)]
mod tests {
    use super::{aligned_alloc, calloc, free, malloc, memalign, posix_memalign, realloc, EINVAL};
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
    fn aligned_entry_points_roundtrip() {
        unsafe {
            // posix_memalign across alignments, content survives, free works.
            let mut k = 0;
            while k < 6 {
                let al = 16 << k; // 16..512
                let mut p: *mut core::ffi::c_void = null_mut();
                assert_eq!(posix_memalign(&mut p, al, 1000), 0);
                assert!(!p.is_null());
                assert!((p as usize).is_multiple_of(al));
                *(p as *mut u8) = 0x77;
                *((p as *mut u8).add(999)) = 0x77;
                free(p);
                k += 1;
            }
            // aligned_alloc strictness (C11): bad input is NULL, errno set.
            assert!(aligned_alloc(0, 64).is_null());
            assert!(aligned_alloc(24, 64).is_null());
            assert!(aligned_alloc(64, 100).is_null());
            let a = aligned_alloc(64, 128);
            assert!(!a.is_null() && (a as usize).is_multiple_of(64));
            // realloc keeps the bytes (alignment may relax to 16, C-legal).
            *(a as *mut u8) = 0x3c;
            let g = realloc(a, 4096);
            assert!(!g.is_null() && *(g as *mut u8) == 0x3c);
            free(g);
            // memalign rounds leniently instead of failing.
            let m = memalign(24, 64);
            assert!(!m.is_null() && (m as usize).is_multiple_of(32));
            free(m);
            // posix_memalign rejects without touching live state.
            let mut q: *mut core::ffi::c_void = null_mut();
            assert_eq!(posix_memalign(null_mut(), 16, 16), EINVAL);
            assert_eq!(posix_memalign(&mut q, 20, 16), EINVAL);
            assert!(q.is_null());
            // Sequential churn reuses the side-map slots forever.
            let mut j = 0;
            while j < 200 {
                let mut r: *mut core::ffi::c_void = null_mut();
                assert_eq!(posix_memalign(&mut r, 64, 64), 0);
                free(r);
                j += 1;
            }
        }
    }

    /// A second free of one object aborts instead of hanging `take` on
    /// a closed cycle (the heap stays consistent: detection precedes
    /// any link write, and the lock is released before panicking).
    #[test]
    #[should_panic(expected = "double free")]
    fn double_free_aborts() {
        unsafe {
            let p = malloc(64);
            assert!(!p.is_null());
            free(p);
            free(p);
        }
    }

    /// A stack address is not heap memory: clean abort, no corruption.
    #[test]
    #[should_panic(expected = "foreign pointer")]
    fn foreign_free_aborts() {
        let mut x = [0u8; 64];
        unsafe {
            free(x.as_mut_ptr() as *mut core::ffi::c_void);
        }
    }

    /// Absurd alignments fail clean (NULL), never under-aligned.
    #[test]
    fn memalign_huge_alignment_fails_clean() {
        unsafe {
            assert!(memalign(usize::MAX, 64).is_null());
            let a = aligned_alloc(64, 64);
            assert!(!a.is_null());
            free(a);
        }
    }

    /// 65 live over-aligned objects: no spurious 64-cap failure.
    #[test]
    fn sixty_five_live_aligned_holds() {
        unsafe {
            let mut ps = [null_mut::<core::ffi::c_void>(); 65];
            let mut k = 0;
            while k < 65 {
                let mut r: *mut core::ffi::c_void = null_mut();
                assert_eq!(posix_memalign(&mut r, 64, 64), 0);
                ps[k] = r;
                k += 1;
            }
            let mut k = 0;
            while k < 65 {
                free(ps[k]);
                k += 1;
            }
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
