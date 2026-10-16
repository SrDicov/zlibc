//! Wave 6 packet 6B — the link map: namespace list, `DT_NEEDED` walk,
//! and the global symbol-scope chain.
//!
//! musl owns three list heads in one line (`ldso/dynlink.c:141`):
//! `head, tail, fini_head, syms_tail, lazy_head`. Two of them matter
//! here — the doubly-linked namespace whose **order is the load order**,
//! and `syms_tail`, which threads `syms_next` to define the global
//! symbol scope that [`super::reloc`] walks.
//!
//! The dependency walk is the part worth reading twice. musl does not
//! recurse and does not use an explicit queue: `load_deps`
//! (`dynlink.c:1300-1305`) walks the namespace list itself, and
//! `load_direct_deps` appends the newly loaded objects **at the tail**,
//! so the cursor simply continues into them on the next step. That is
//! breadth-first, level-order, pre-order, and it is what gives a
//! diamond (`app→{B,C}`, `B→{D}`, `C→{D}`) the order `app,B,C,D` with
//! `D` loaded once. It replaced a recursive walk in musl commit
//! `40355569` (2019-02-26), so this shape is the one to mirror.

use core::ffi::c_char;
use core::ptr::{addr_of_mut, null_mut};
use core::sync::atomic::{AtomicPtr, Ordering};

use super::dso::Dso;
use super::{DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_NEEDED, DYN_CNT};

// Namespace (musl `head`/`tail`, `dynlink.c:141`) and the scope tail
// (`syms_tail`). `#[no_mangle]`-adjacent loader state has no thread
// owner yet: 6B is single-threaded bootstrap, and dlopen-time locking
// lands with 6D.
static HEAD: AtomicPtr<Dso> = AtomicPtr::new(null_mut());
static TAIL: AtomicPtr<Dso> = AtomicPtr::new(null_mut());
static SYMS_TAIL: AtomicPtr<Dso> = AtomicPtr::new(null_mut());

/// musl `no_deps` (an empty, const array) and `builtin_deps[2]`
/// (`dynlink.c:157-158`). `load_direct_deps` points a dependency-free
/// object at these instead of `calloc`, deliberately keeping "no
/// runtime failure path" for the common case (musl:1274-1277); a
/// failing `calloc` for an app with real deps stays fatal there.
static mut NO_DEPS: [*mut Dso; 1] = [null_mut()];
static mut BUILTIN_DEPS: [*mut Dso; 2] = [null_mut(), null_mut()];

/// Loads one dependency by name, musl `load_library` (`dynlink.c:1062`)
/// reduced to the contract the walk needs: return the mapped `Dso`
/// (already appended to the namespace) or null on failure.
///
/// A function pointer, not a direct call, because the BFS order is the
/// only genuinely subtle thing here and it has to be testable without a
/// filesystem: production passes [`load_library`], tests pass a fake.
/// musl tests the same layer by injecting the search path instead.
pub type LoadFn = unsafe fn(name: *const c_char, needed_by: *mut Dso) -> *mut Dso;

/// Current namespace head (musl `head`).
pub fn head() -> *mut Dso {
    HEAD.load(Ordering::Acquire)
}

/// Current namespace tail (musl `tail`).
pub fn tail() -> *mut Dso {
    TAIL.load(Ordering::Acquire)
}

/// Current global-scope tail (musl `syms_tail`).
pub fn syms_tail() -> *mut Dso {
    SYMS_TAIL.load(Ordering::Acquire)
}

/// Install the namespace starting point (musl `__dls2`/`__dls3`: `head`
/// is re-pointed once the main program is known, `dynlink.c:1760`,
/// `:1959`).
pub fn set_namespace(first: *mut Dso) {
    HEAD.store(first, Ordering::Release);
    TAIL.store(first, Ordering::Release);
    SYMS_TAIL.store(first, Ordering::Release);
}

/// Forget every list (test isolation and the 6D `dlclose` reset). The
/// `Dso`s themselves are untouched — only the three heads.
pub fn reset_namespace() {
    set_namespace(null_mut());
}

/// Append `p` at the namespace tail (musl `dynlink.c:1252-1254`): the
/// load order *is* the list order, and the BFS cursor relies on it.
///
/// # Safety
///
/// `p` must be a valid, unlinked `Dso`.
pub unsafe fn append_namespace(p: *mut Dso) {
    unsafe {
        let t = TAIL.load(Ordering::Acquire);
        if t.is_null() {
            HEAD.store(p, Ordering::Release);
            TAIL.store(p, Ordering::Release);
            if SYMS_TAIL.load(Ordering::Acquire).is_null() {
                SYMS_TAIL.store(p, Ordering::Release);
            }
        } else {
            (*t).next = p;
            (*p).prev = t;
            TAIL.store(p, Ordering::Release);
        }
        (*p).next = null_mut();
    }
}

/// Number of `DT_NEEDED` entries in `p`'s dynamic vector (musl sizing
/// pass, `dynlink.c:1272-1273`).
///
/// # Safety
///
/// `p->dynv` must point at a mapped `(tag, value)` array terminated by a
/// zero tag.
pub unsafe fn count_needed(p: *const Dso) -> usize {
    unsafe {
        let mut cnt = 0usize;
        let mut i = 0usize;
        while (*p).dynv.add(i).read() != 0 {
            if (*p).dynv.add(i).read() == DT_NEEDED {
                cnt += 1;
            }
            i += 2;
        }
        cnt
    }
}

/// Load `p`'s **direct** dependencies into `p->deps` (musl
/// `load_direct_deps`, `dynlink.c:1263-1298`).
///
/// Idempotent through `p->deps` (`dynlink.c:1267`), which is what makes
/// the diamond case load `D` once: the second parent hits the existing
/// object inside `load_library`, and the array gets the same pointer
/// twice — musl has no per-parent dedup, and neither do we.
///
/// `builtin_deps`/`no_deps` back a dependency-free namespace so the
/// common boot path cannot fail on allocation. Returns false when a
/// dependency could not be loaded; musl prints, keeps walking, and lets
/// the caller decide (startup continues, runtime `longjmp`s —
/// `dynlink.c:1288-1293`). We return the verdict and leave the message
/// to 6D's `dlerror` plumbing.
///
/// # Safety
///
/// `p->strings` must be the strtab `DT_NEEDED` offsets index into, and
/// `load` must behave like [`LoadFn`].
pub unsafe fn load_direct_deps(p: *mut Dso, load: LoadFn) -> bool {
    unsafe {
        if !(*p).deps.is_null() {
            return true;
        }
        let is_head = core::ptr::eq(p, HEAD.load(Ordering::Acquire));
        let mut cnt = 0usize;
        let needed = count_needed(p);
        cnt += needed;
        let preload_cnt = if is_head {
            let mut n = 0usize;
            let mut q = (*p).next;
            while !q.is_null() {
                n += 1;
                q = (*q).next;
            }
            n
        } else {
            0
        };
        cnt += preload_cnt;
        // musl: `(p==head && cnt<2) ? builtin_deps : calloc(cnt+1, ...)`
        // (`dynlink.c:1276-1277`). The static covers the main program
        // with at most one dependency (one LD_PRELOAD, or one DT_NEEDED)
        // so the common boot path has no allocation and therefore no
        // runtime failure path; everything else, a plain library with
        // zero deps included, allocates one terminator slot.
        if is_head && cnt < 2 {
            // `addr_of_mut!` rather than `as_ptr()`: the latter creates a shared
            // reference to mutable static storage. musl hands this
            // array out the same way — write-only through the pointer.
            (*p).deps = addr_of_mut!(BUILTIN_DEPS).cast::<*mut Dso>();
        } else {
            let slots = crate::malloc::calloc(cnt + 1, size_of::<*mut Dso>());
            if slots.is_null() {
                // musl prints and (at startup) keeps going into a NULL
                // `deps`; we stop before that and report the failure.
                (*p).deps = addr_of_mut!(NO_DEPS).cast::<*mut Dso>();
                return false;
            }
            (*p).deps = slots as *mut *mut Dso;
        }
        let mut filled = 0usize;
        // For head, every already-loaded object is a direct
        // pseudo-dependency (the LD_PRELOADs), prepended
        // (`dynlink.c:1283-1284`).
        if is_head {
            let mut q = (*p).next;
            while !q.is_null() {
                *(*p).deps.add(filled) = q;
                filled += 1;
                q = (*q).next;
            }
        }
        let mut i = 0usize;
        let mut ok = true;
        while (*p).dynv.add(i).read() != 0 {
            let tag = (*p).dynv.add(i).read();
            let off = (*p).dynv.add(i + 1).read();
            if tag == DT_NEEDED {
                let name = (*p).strings.wrapping_add(off);
                let dep = load(name, p);
                if dep.is_null() {
                    // musl: print, `continue` — the array keeps a hole
                    // and the namespace carries on (`dynlink.c:1288`).
                    ok = false;
                    i += 2;
                    continue;
                }
                *(*p).deps.add(filled) = dep;
                filled += 1;
            }
            i += 2;
        }
        *(*p).deps.add(filled) = null_mut();
        (*p).ndeps_direct = filled;
        ok
    }
}

/// Walk the namespace breadth-first from `from`, loading every object's
/// direct dependencies (musl `load_deps`, `dynlink.c:1300-1305`).
///
/// The whole algorithm is that two-line loop: because `load_direct_deps`
/// appends at the tail, the cursor `p = p->next` walks into the
/// dependencies it just added. Level-order, pre-order, no recursion, no
/// queue, and `p->deps` on the entry object makes a second call a
/// no-op (`dynlink.c:1302`).
///
/// Returns false if any dependency failed to load.
///
/// # Safety
///
/// `from` must be in the namespace list and `load` must behave like
/// [`LoadFn`].
pub unsafe fn load_deps(from: *mut Dso, load: LoadFn) -> bool {
    unsafe {
        if !(*from).deps.is_null() {
            return true;
        }
        let mut ok = true;
        let mut p = from;
        while !p.is_null() {
            if !load_direct_deps(p, load) {
                ok = false;
            }
            p = (*p).next;
        }
        ok
    }
}

/// Link `p` into the global symbol scope (musl `add_syms`,
/// `dynlink.c:1372-1378`). The chain *is* the scope: `syms_next`
/// threaded from `syms_tail`, which is what [`super::reloc::find_sym`]
/// walks so the executable interposes over its libraries.
///
/// # Safety
///
/// `p` must be a valid `Dso` not already in the chain.
pub unsafe fn add_syms(p: *mut Dso) {
    unsafe {
        let st = SYMS_TAIL.load(Ordering::Acquire);
        if (*p).syms_next.is_null() && !core::ptr::eq(st, p) {
            (*st).syms_next = p;
            SYMS_TAIL.store(p, Ordering::Release);
        }
    }
}

/// Chop the scope chain back to `old_tail`, restoring the objects above
/// it to local visibility (musl `revert_syms`, `dynlink.c:1380-1390`).
///
/// # Safety
///
/// `old_tail` must be a `syms_tail` previously saved by the caller.
pub unsafe fn revert_syms(old_tail: *mut Dso) {
    unsafe {
        let mut p = old_tail;
        while !p.is_null() {
            let next = (*p).syms_next;
            (*p).syms_next = null_mut();
            p = next;
        }
        SYMS_TAIL.store(old_tail, Ordering::Release);
    }
}

/// Grow `p->deps` from the direct list into the transitive closure,
/// breadth-first, without duplicates (musl `extend_bfs_deps`,
/// `dynlink.c:1307-1359`). This is the array a `dlopen` handle's local
/// `dlsym` walks, and the bound `queue_ctors` sizes from.
///
/// No `realloc` when `deps` is the static `BUILTIN_DEPS` (or the head's,
/// which musl guards with `no_realloc` for a replaced malloc; we never
/// replace malloc, so the static check is the whole guard). Idempotent
/// through `bfs_built`.
///
/// # Safety
///
/// `p` must be in the namespace with direct deps loaded.
pub unsafe fn extend_bfs_deps(p: *mut Dso) {
    unsafe {
        if (*p).bfs_built != 0 {
            return;
        }
        let mut ndeps_all = (*p).ndeps_direct;
        let mut i = 0usize;
        while !(*(*p).deps.add(i)).is_null() {
            (**(*p).deps.add(i)).mark = 1;
            i += 1;
        }
        let mut j = 0usize;
        // The caller's direct-deps array is never freed or written past
        // its terminator (musl's `no_realloc` first pass): growth lands
        // in a fresh array, later passes `realloc` it.
        let mut fresh: *mut *mut Dso = null_mut();
        while !(*(*p).deps.add(j)).is_null() {
            let dep = *(*p).deps.add(j);
            let mut cnt = 0usize;
            let mut k = 0usize;
            while k < (*dep).ndeps_direct {
                if (**(*dep).deps.add(k)).mark == 0 {
                    cnt += 1;
                }
                k += 1;
            }
            fresh = if fresh.is_null() {
                let t = crate::malloc::malloc((ndeps_all + cnt + 1) * size_of::<*mut Dso>())
                    as *mut *mut Dso;
                if t.is_null() {
                    break;
                }
                crate::mem::memcpy(
                    t as *mut core::ffi::c_void,
                    (*p).deps as *const core::ffi::c_void,
                    (ndeps_all + 1) * size_of::<*mut Dso>(),
                );
                t
            } else {
                let t = crate::malloc::realloc(
                    fresh as *mut core::ffi::c_void,
                    (ndeps_all + cnt + 1) * size_of::<*mut Dso>(),
                ) as *mut *mut Dso;
                if t.is_null() {
                    break;
                }
                t
            };
            (*p).deps = fresh;
            let mut m = 0usize;
            while m < (*dep).ndeps_direct {
                let dd = *(*dep).deps.add(m);
                if (*dd).mark == 0 {
                    (*dd).mark = 1;
                    *(*p).deps.add(ndeps_all) = dd;
                    ndeps_all += 1;
                }
                m += 1;
            }
            *(*p).deps.add(ndeps_all) = null_mut();
            j += 1;
        }
        (*p).bfs_built = 1;
        let mut q = HEAD.load(Ordering::Acquire);
        while !q.is_null() {
            (*q).mark = 0;
            q = (*q).next;
        }
    }
}

/// Constructor queue in dependency-first order (musl `queue_ctors`,
/// `dynlink.c:1513-1580`): pseudo-DFS over the direct-deps graph, so
/// every library runs before its parents and the root runs last.
/// Returns a NUL-terminated queue the caller frees, or null when the
/// `calloc` fails (musl `longjmp`s at runtime; at boot the caller runs
/// nothing — same observable outcome as musl's pre-`runtime` path).
///
/// The fork-consistency check (`ctor_visitor->tid < 0`,
/// `dynlink.c:1571-1577`) is OUT: our `ctor_visitor` is a bare pointer
/// with no tid behind it. It returns with the thread wave that owns it.
///
/// # Safety
///
/// `dso` must be in the namespace with direct deps loaded.
pub unsafe fn queue_ctors(dso: *mut Dso) -> *mut *mut Dso {
    unsafe {
        let mut cnt = 0usize;
        if (*dso).bfs_built != 0 {
            let mut i = 0usize;
            while !(*(*dso).deps.add(i)).is_null() {
                (**(*dso).deps.add(i)).mark = 0;
                i += 1;
            }
            cnt = i + 1;
        } else {
            let mut p = HEAD.load(Ordering::Acquire);
            while !p.is_null() {
                (*p).mark = 0;
                cnt += 1;
                p = (*p).next;
            }
        }
        cnt += 1;
        let queue = crate::malloc::calloc(cnt, size_of::<*mut Dso>()) as *mut *mut Dso;
        if queue.is_null() {
            return null_mut();
        }
        let mut qpos = 0usize;
        let mut spos = cnt;
        *queue.add(spos - 1) = dso;
        spos -= 1;
        (*dso).next_dep = 0;
        (*dso).mark = 1;
        while spos < cnt {
            let mut p = *queue.add(spos);
            spos += 1;
            while (*p).next_dep < (*p).ndeps_direct {
                let d = *(*p).deps.add((*p).next_dep);
                if (*d).mark != 0 {
                    (*p).next_dep += 1;
                } else {
                    *queue.add(spos - 1) = p;
                    spos -= 1;
                    p = d;
                    (*p).next_dep = 0;
                    (*p).mark = 1;
                }
            }
            *queue.add(qpos) = p;
            qpos += 1;
        }
        *queue.add(qpos) = null_mut();
        let mut i = 0usize;
        while i < qpos {
            (**queue.add(i)).mark = 0;
            i += 1;
        }
        queue
    }
}

/// The init/fini exclusion lock (musl `init_fini_lock`, zero-init like
/// every other loader mutex: no FS needed, so boot-time ctors work).
static mut INIT_FINI_LOCK: crate::sync::MutexT = [0; 5];

/// Run a constructor queue (musl `do_init_fini`, `dynlink.c:1582-1620`):
/// `DT_INIT` then `DT_INIT_ARRAY` per object, `constructed = 1` after.
/// Exactly-once across threads: the flag check-and-claim runs under
/// `INIT_FINI_LOCK`, and a thread finding another thread's claim spins
/// (musl's `pthread_cond_wait` on the same lock; a spin is the same
/// wait without the condvar — ponytail: cond when ctor contention is
/// measured). The lock is never held across user code, so a
/// constructor calling back into `dlopen` cannot deadlock; a claim by
/// the calling thread itself (`ctor_visitor == self`, only possible
/// reentrantly) proceeds inline like musl's.
///
/// FS-base 0 (boot ctors run before `__init_libc` sets the TP) is
/// harmless: no thread exists yet, so claim `visitor == self == 0`
/// cannot race.
///
/// `DT_FINI`/`DT_FINI_ARRAY` are parsed nowhere: `dlclose` never
/// unloads (tested no-op), so there is nobody to run them. They land
/// with a `dlclose` that has teeth.
///
/// # Safety
///
/// `queue` must be a NUL-terminated `queue_ctors` product; caller frees
/// it afterwards.
pub unsafe fn do_init_fini(queue: *mut *mut Dso) {
    unsafe {
        let this = crate::thread::create::__pthread_self();
        let mut i = 0usize;
        while !(*queue.add(i)).is_null() {
            let p = *queue.add(i);
            // Claim: skip constructed, spin on foreign claims.
            loop {
                crate::sync::pthread_mutex_lock(addr_of_mut!(INIT_FINI_LOCK));
                let v = (*p).ctor_visitor;
                if (*p).constructed != 0 {
                    crate::sync::pthread_mutex_unlock(addr_of_mut!(INIT_FINI_LOCK));
                    break;
                }
                if v.is_null() || core::ptr::eq(v, this) {
                    (*p).ctor_visitor = this;
                    crate::sync::pthread_mutex_unlock(addr_of_mut!(INIT_FINI_LOCK));
                    break;
                }
                crate::sync::pthread_mutex_unlock(addr_of_mut!(INIT_FINI_LOCK));
                core::hint::spin_loop();
            }
            if (*p).constructed != 0 {
                i += 1;
                continue;
            }
            // Run with no lock held (musl unlocks across user code).
            let mut dynv = [0usize; DYN_CNT];
            super::dso::decode_vec((*p).dynv, dynv.as_mut_ptr(), DYN_CNT);
            type Ctor = unsafe extern "C" fn();
            if dynv[0] & (1usize << DT_INIT) != 0 && dynv[DT_INIT] != 0 {
                let f: Ctor = core::mem::transmute::<usize, Ctor>(
                    ((*p).base as usize).wrapping_add(dynv[DT_INIT]),
                );
                f();
            }
            if dynv[0] & (1usize << DT_INIT_ARRAY) != 0 {
                let n = dynv[DT_INIT_ARRAYSZ] / size_of::<usize>();
                let mut fns = ((*p).base as usize).wrapping_add(dynv[DT_INIT_ARRAY]) as *mut usize;
                let mut k = 0usize;
                while k < n {
                    let f: Ctor = core::mem::transmute::<usize, Ctor>(*fns);
                    if !(f as usize == 0) {
                        f();
                    }
                    fns = fns.add(1);
                    k += 1;
                }
            }
            crate::sync::pthread_mutex_lock(addr_of_mut!(INIT_FINI_LOCK));
            (*p).ctor_visitor = core::ptr::null_mut();
            (*p).constructed = 1;
            crate::sync::pthread_mutex_unlock(addr_of_mut!(INIT_FINI_LOCK));
            i += 1;
        }
    }
}

/// Already-loaded object with this short name, skipping the main
/// program (musl's pre-open dedup layer, `dynlink.c:1113-1118`).
///
/// `name` is only matched when it carries no `/`: a `DT_NEEDED` entry
/// that is an explicit pathname never gets a `shortname` in musl
/// (`dynlink.c:1230`) and so cannot be found by name.
///
/// # Safety
///
/// `name` must be a NUL-terminated string; the namespace must be valid.
pub unsafe fn find_by_shortname(name: *const c_char) -> *mut Dso {
    unsafe {
        // A `/` anywhere means an explicit pathname, which musl never
        // gives a `shortname` (`dynlink.c:1230`), so it cannot be found
        // by this layer.
        let mut k = 0usize;
        while *name.wrapping_add(k) != 0 {
            if *name.wrapping_add(k) == b'/' as c_char {
                return null_mut();
            }
            k += 1;
        }
        let h = HEAD.load(Ordering::Acquire);
        let mut p = if h.is_null() { null_mut() } else { (*h).next };
        while !p.is_null() {
            if !(*p).shortname.is_null() && super::reloc::streq((*p).shortname, name) {
                return p;
            }
            p = (*p).next;
        }
        null_mut()
    }
}

/// Deferred-relocation list head (musl `lazy_head`, `dynlink.c:141`),
/// threaded through `Dso::lazy_next`.
static LAZY_HEAD: AtomicPtr<Dso> = AtomicPtr::new(null_mut());

/// Link `p` onto the deferred-relocation list (musl `dynlink.c:2101-2102`).
///
/// # Safety
///
/// `p` must be a `Dso` with a freshly allocated `lazy` table.
pub unsafe fn push_lazy(p: *mut Dso) {
    unsafe {
        (*p).lazy_next = LAZY_HEAD.load(Ordering::Acquire);
        LAZY_HEAD.store(p, Ordering::Release);
    }
}

/// Detach and return the whole deferred-relocation list (musl
/// `dynlink.c:584`: the list is taken off before iterating, so a retry
/// that re-queues an entry cannot extend the loop).
///
/// # Safety
///
/// Only during loader single ownership.
pub fn take_lazy_head() -> *mut Dso {
    let h = LAZY_HEAD.load(Ordering::Acquire);
    LAZY_HEAD.store(null_mut(), Ordering::Release);
    h
}

/// Already-loaded object with this `(dev, ino)`, skipping the main
///
/// # Safety
///
/// The namespace must be valid.
pub unsafe fn find_by_inode(dev: u64, ino: u64) -> *mut Dso {
    unsafe {
        let h = HEAD.load(Ordering::Acquire);
        let mut p = if h.is_null() { null_mut() } else { (*h).next };
        while !p.is_null() {
            if (*p).dev == dev && (*p).ino == ino {
                return p;
            }
            p = (*p).next;
        }
        null_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of, addr_of_mut, null_mut};
    use core::sync::atomic::{AtomicUsize, Ordering};

    use crate::ldso::dso::Dso;
    use crate::ldso::reloc::streq;
    use crate::ldso::testlock::lock;
    use crate::ldso::{DT_NEEDED, DT_NULL};

    /// Fake loader registry: `(name, dso)` pairs; a null name marks an
    /// empty slot. `mark` doubles as the "already appended" flag, so a
    /// diamond loads its shared dependency once exactly like musl's
    /// inode dedup returning the existing object.
    type Entry = (*const c_char, *mut Dso);
    static mut TABLE: [Entry; 8] = [(core::ptr::null(), core::ptr::null_mut()); 8];
    static CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe fn fake_load(name: *const c_char, _needed_by: *mut Dso) -> *mut Dso {
        unsafe {
            CALLS.fetch_add(1, Ordering::SeqCst);
            for k in 0..8 {
                let (want, dso) = *addr_of!(TABLE).cast::<Entry>().add(k);
                if !want.is_null() && streq(want, name) {
                    if (*dso).mark == 0 {
                        (*dso).mark = 1;
                        append_namespace(dso);
                    }
                    return dso;
                }
            }
            null_mut()
        }
    }

    fn register(name: &'static [u8], dso: *mut Dso) {
        unsafe {
            for k in 0..8 {
                let slot = addr_of_mut!(TABLE).cast::<Entry>().add(k);
                if (*slot).0.is_null() {
                    *slot = (name.as_ptr() as *const c_char, dso);
                    return;
                }
            }
        }
    }

    fn unregister_all() {
        CALLS.store(0, Ordering::SeqCst);
        unsafe {
            for k in 0..8 {
                let empty = (core::ptr::null(), core::ptr::null_mut());
                *addr_of_mut!(TABLE).cast::<Entry>().add(k) = empty;
            }
        }
    }

    fn zeroed_dso() -> Dso {
        unsafe { core::mem::zeroed() }
    }

    /// Namespace order as a list of the `name` fields, so a wrong BFS
    /// order reads as `["app","libC.so","libB.so",...]` in the failure.
    fn namespace() -> [*const c_char; 8] {
        unsafe {
            let mut out = [core::ptr::null(); 8];
            let mut n = 0usize;
            let mut p = head();
            while !p.is_null() && n < 8 {
                out[n] = (*p).name;
                n += 1;
                p = (*p).next;
            }
            out
        }
    }

    /// The diamond from musl's own traversal: `app→{B,C}`, `B→{D}`,
    /// `C→{D}`. Level-order puts `D` after both parents, and the
    /// existing-`D` hit means it is appended once.
    #[test]
    fn bfs_order_is_app_b_c_d() {
        unsafe {
            let _guard = lock();
            reset_namespace();
            unregister_all();

            let mut app = zeroed_dso();
            let mut b = zeroed_dso();
            let mut c = zeroed_dso();
            let mut d = zeroed_dso();

            let mut app_str = *b"libB.so\0libC.so\0\0";
            let mut b_str = *b"libD.so\0\0\0\0";
            let mut empty = [0u8; 8];
            // "libB.so\0" is 8 bytes, so libC.so starts at offset 8. Offsets are
            // strtab positions: counting them by eye is how this test first read
            // 'o' instead of "libC.so".
            let mut app_dyn = [DT_NEEDED, 0usize, DT_NEEDED, 8usize, DT_NULL, 0];
            let mut one_need = [DT_NEEDED, 0usize, DT_NULL, 0];
            let mut none = [DT_NULL, 0usize];

            app.name = app_str.as_ptr() as *mut c_char;
            app.strings = app_str.as_mut_ptr() as *mut c_char;
            app.dynv = app_dyn.as_mut_ptr();
            b.name = b_str.as_ptr() as *mut c_char;
            b.strings = b_str.as_mut_ptr() as *mut c_char;
            b.dynv = one_need.as_mut_ptr();
            c.name = b_str.as_ptr() as *mut c_char;
            c.strings = b_str.as_mut_ptr() as *mut c_char;
            c.dynv = one_need.as_mut_ptr();
            d.name = empty.as_mut_ptr() as *mut c_char;
            d.strings = empty.as_mut_ptr() as *mut c_char;
            d.dynv = none.as_mut_ptr();

            set_namespace(&mut app as *mut Dso);
            register(b"libB.so\0", &mut b as *mut Dso);
            register(b"libD.so\0", &mut d as *mut Dso);
            register(b"libC.so\0", &mut c as *mut Dso);

            assert!(load_deps(&mut app as *mut Dso, fake_load));

            let order = namespace();
            assert_eq!(order[0], app.name);
            assert_eq!(order[1], b.name);
            assert_eq!(order[2], c.name);
            assert_eq!(order[3], d.name);
            assert!(order[4].is_null(), "nothing beyond D: {:?}", order[4]);

            // Direct deps only, NUL-terminated.
            assert_eq!(app.ndeps_direct, 2);
            assert_eq!(*app.deps.add(0), &mut b as *mut Dso);
            assert_eq!(*app.deps.add(1), &mut c as *mut Dso);
            assert!((*app.deps.add(2)).is_null());
            // The diamond: both parents point at the *same* D.
            assert_eq!(b.ndeps_direct, 1);
            assert_eq!(c.ndeps_direct, 1);
            assert_eq!(*b.deps.add(0), &mut d as *mut Dso);
            assert_eq!(*c.deps.add(0), &mut d as *mut Dso);
            // D has no deps of its own.
            assert_eq!(d.ndeps_direct, 0);

            reset_namespace();
            unregister_all();
        }
    }

    /// `load_deps` short-circuits on an already-populated `deps`, and
    /// `load_direct_deps` on each visited object: the second pass must
    /// not call the loader again.
    #[test]
    fn load_deps_is_idempotent() {
        unsafe {
            let _guard = lock();
            reset_namespace();
            unregister_all();
            let mut app = zeroed_dso();
            let mut b = zeroed_dso();
            let mut app_str = *b"libB.so\0\0\0\0\0";
            let mut empty = [0u8; 8];
            let mut app_dyn = [DT_NEEDED, 0usize, DT_NULL, 0];
            app.name = app_str.as_ptr() as *mut c_char;
            app.strings = app_str.as_mut_ptr() as *mut c_char;
            app.dynv = app_dyn.as_mut_ptr();
            b.name = empty.as_mut_ptr() as *mut c_char;
            b.strings = empty.as_mut_ptr() as *mut c_char;
            let mut none = [DT_NULL, 0usize];
            b.dynv = none.as_mut_ptr();
            set_namespace(&mut app as *mut Dso);
            register(b"libB.so\0", &mut b as *mut Dso);

            CALLS.store(0, Ordering::SeqCst);
            assert!(load_deps(&mut app as *mut Dso, fake_load));
            let first = CALLS.load(Ordering::SeqCst);
            assert_eq!(first, 1, "one DT_NEEDED, one load");
            assert!(load_deps(&mut app as *mut Dso, fake_load));
            assert_eq!(
                CALLS.load(Ordering::SeqCst),
                first,
                "second walk must not reload"
            );

            reset_namespace();
            unregister_all();
        }
    }

    /// A dependency that cannot be loaded leaves a hole and keeps the
    /// rest (musl `dynlink.c:1288-1293`: print, `continue`).
    #[test]
    fn missing_dependency_reports_and_continues() {
        unsafe {
            let _guard = lock();
            reset_namespace();
            unregister_all();
            let mut app = zeroed_dso();
            let mut b = zeroed_dso();
            let mut strs = *b"libMissing.so\0libB.so\0\0";
            let mut empty = [0u8; 8];
            // "libMissing.so\0" is 14 bytes, so libB.so starts at offset 14.
            let mut needs = [DT_NEEDED, 0usize, DT_NEEDED, 14usize, DT_NULL, 0];
            app.name = strs.as_ptr() as *mut c_char;
            app.strings = strs.as_mut_ptr() as *mut c_char;
            app.dynv = needs.as_mut_ptr();
            b.name = empty.as_mut_ptr() as *mut c_char;
            b.strings = empty.as_mut_ptr() as *mut c_char;
            let mut none = [DT_NULL, 0usize];
            b.dynv = none.as_mut_ptr();
            set_namespace(&mut app as *mut Dso);
            register(b"libB.so\0", &mut b as *mut Dso);

            assert!(!load_deps(&mut app as *mut Dso, fake_load));
            // The surviving dependency is still recorded.
            assert_eq!(app.ndeps_direct, 1);
            assert_eq!(*app.deps.add(0), &mut b as *mut Dso);
            assert!((*app.deps.add(1)).is_null());

            reset_namespace();
            unregister_all();
        }
    }

    /// `add_syms` threads the scope in insertion order; `revert_syms`
    /// chops it back so a later object resolves as if it were absent.
    #[test]
    fn add_and_revert_syms_chain() {
        unsafe {
            let _guard = lock();
            reset_namespace();
            unregister_all();
            let mut a = zeroed_dso();
            let mut b = zeroed_dso();
            let mut c = zeroed_dso();
            set_namespace(&mut a as *mut Dso);

            add_syms(&mut b as *mut Dso);
            add_syms(&mut c as *mut Dso);
            assert_eq!(syms_tail(), &mut c as *mut Dso);
            assert_eq!(a.syms_next, &mut b as *mut Dso);
            assert_eq!(b.syms_next, &mut c as *mut Dso);
            assert!(c.syms_next.is_null());

            // Re-adding an already-linked object must not splice it twice.
            add_syms(&mut b as *mut Dso);
            assert_eq!(syms_tail(), &mut c as *mut Dso);

            revert_syms(&mut a as *mut Dso);
            assert_eq!(syms_tail(), &mut a as *mut Dso);
            assert!(a.syms_next.is_null());
            assert!(b.syms_next.is_null());
            assert!(c.syms_next.is_null());

            reset_namespace();
            unregister_all();
        }
    }

    /// Both dedup layers start at `head->next`: the main program is
    /// never a dependency candidate.
    #[test]
    fn dedup_lookups_skip_the_main_program() {
        unsafe {
            let _guard = lock();
            reset_namespace();
            unregister_all();
            let mut app = zeroed_dso();
            let mut lib = zeroed_dso();
            let mut empty = [0u8; 8];
            let mut none = [DT_NULL, 0usize];
            app.name = empty.as_mut_ptr() as *mut c_char;
            app.shortname = c"app.bin".as_ptr() as *mut c_char;
            app.dev = 1;
            app.ino = 1;
            app.dynv = none.as_mut_ptr();
            lib.name = empty.as_mut_ptr() as *mut c_char;
            lib.shortname = c"libz.so".as_ptr() as *mut c_char;
            lib.dev = 2;
            lib.ino = 7;
            lib.dynv = none.as_mut_ptr();
            set_namespace(&mut app as *mut Dso);
            append_namespace(&mut lib as *mut Dso);

            assert_eq!(find_by_shortname(c"libz.so".as_ptr()), &mut lib as *mut Dso);
            assert!(find_by_shortname(c"app.bin".as_ptr()).is_null());
            assert!(find_by_shortname(c"/abs/libz.so".as_ptr()).is_null());
            assert_eq!(find_by_inode(2, 7), &mut lib as *mut Dso);
            assert!(find_by_inode(1, 1).is_null(), "head is skipped");
            assert!(find_by_inode(9, 9).is_null());

            reset_namespace();
            unregister_all();
        }
    }

    /// Sizing pass: only `DT_NEEDED` tags count, and the walk stops at
    /// the first zero tag.
    #[test]
    fn count_needed_counts_only_needed() {
        // Pure function over caller-owned memory: no globals, no lock.
        unsafe {
            let mut d = zeroed_dso();
            let mut dynv = [
                DT_NEEDED,
                0usize,
                0x6ffffef5usize,
                0,
                DT_NEEDED,
                9usize,
                DT_NULL,
                0,
                DT_NEEDED,
                99usize,
            ];
            d.dynv = dynv.as_mut_ptr();
            assert_eq!(count_needed(&d as *const Dso), 2);
            let mut none = [DT_NULL, 0usize];
            d.dynv = none.as_mut_ptr();
            assert_eq!(count_needed(&d as *const Dso), 0);
        }
    }

    /// Diamond direct deps: app→{B,C}, B→D, C→D. Wire them by hand
    /// (namespace order app,B,C,D, direct arrays on the stack).
    #[allow(clippy::too_many_arguments)]
    unsafe fn wire_diamond(
        app: *mut Dso,
        b: *mut Dso,
        c: *mut Dso,
        d: *mut Dso,
        app_d: *mut *mut Dso,
        b_d: *mut *mut Dso,
        c_d: *mut *mut Dso,
        d_d: *mut *mut Dso,
    ) {
        unsafe {
            reset_namespace();
            for o in [app, b, c, d] {
                append_namespace(o);
            }
            (*app).deps = app_d;
            (*app).ndeps_direct = 2;
            (*b).deps = b_d;
            (*b).ndeps_direct = 1;
            (*c).deps = c_d;
            (*c).ndeps_direct = 1;
            (*d).deps = d_d;
            (*d).ndeps_direct = 0;
        }
    }

    /// `extend_bfs_deps`: transitive closure, D once, `bfs_built` set,
    /// second call a no-op.
    #[test]
    fn extend_bfs_builds_deduped_closure() {
        let _guard = lock();
        unsafe {
            let mut app = zeroed_dso();
            let mut b = zeroed_dso();
            let mut c = zeroed_dso();
            let mut d = zeroed_dso();
            let (ap, bp, cp, dp) = (
                &mut app as *mut Dso,
                &mut b as *mut Dso,
                &mut c as *mut Dso,
                &mut d as *mut Dso,
            );
            let mut app_d = [bp, cp, null_mut()];
            let mut b_d = [dp, null_mut()];
            let mut c_d = [dp, null_mut()];
            let mut d_d = [null_mut()];
            wire_diamond(
                ap,
                bp,
                cp,
                dp,
                app_d.as_mut_ptr(),
                b_d.as_mut_ptr(),
                c_d.as_mut_ptr(),
                d_d.as_mut_ptr(),
            );
            extend_bfs_deps(ap);
            assert_eq!((*ap).bfs_built, 1);
            let mut got = [null_mut(); 4];
            let mut n = 0usize;
            while !(*(*ap).deps.add(n)).is_null() {
                got[n] = *(*ap).deps.add(n);
                n += 1;
            }
            assert_eq!(n, 3, "B,C plus D once");
            assert_eq!(got[0], bp);
            assert_eq!(got[1], cp);
            assert_eq!(got[2], dp);
            let before = (*ap).deps;
            extend_bfs_deps(ap);
            assert!(core::ptr::eq((*ap).deps, before), "idempotent");
            crate::malloc::free((*ap).deps as *mut core::ffi::c_void);
            reset_namespace();
            unregister_all();
        }
    }

    /// `queue_ctors`: dependencies before parents, root last,
    /// NUL-terminated.
    #[test]
    fn queue_ctors_orders_deps_first() {
        let _guard = lock();
        unsafe {
            let mut app = zeroed_dso();
            let mut b = zeroed_dso();
            let mut c = zeroed_dso();
            let mut d = zeroed_dso();
            let (ap, bp, cp, dp) = (
                &mut app as *mut Dso,
                &mut b as *mut Dso,
                &mut c as *mut Dso,
                &mut d as *mut Dso,
            );
            let mut app_d = [bp, cp, null_mut()];
            let mut b_d = [dp, null_mut()];
            let mut c_d = [dp, null_mut()];
            let mut d_d = [null_mut()];
            wire_diamond(
                ap,
                bp,
                cp,
                dp,
                app_d.as_mut_ptr(),
                b_d.as_mut_ptr(),
                c_d.as_mut_ptr(),
                d_d.as_mut_ptr(),
            );
            let q = queue_ctors(ap);
            assert!(!q.is_null());
            let mut v = [null_mut(); 5];
            let mut n = 0usize;
            while !(*q.add(n)).is_null() {
                v[n] = *q.add(n);
                n += 1;
            }
            assert_eq!(n, 4);
            assert!(v.contains(&dp));
            assert_eq!(v[3], ap, "root runs last");
            let di = v.iter().position(|x| *x == dp).unwrap();
            let bi = v.iter().position(|x| *x == bp).unwrap();
            let ci = v.iter().position(|x| *x == cp).unwrap();
            assert!(di < bi && di < ci, "D before its parents");
            crate::malloc::free(q as *mut core::ffi::c_void);
            reset_namespace();
            unregister_all();
        }
    }

    static CTOR_RAN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn test_ctor() {
        CTOR_RAN.fetch_add(1, Ordering::SeqCst);
    }

    /// `do_init_fini`: runs `DT_INIT_ARRAY` once, marks constructed,
    /// second run is a no-op.
    #[test]
    fn do_init_fini_runs_once_and_marks() {
        let _guard = lock();
        CTOR_RAN.store(0, Ordering::SeqCst);
        unsafe {
            let mut d = zeroed_dso();
            // base 0 with absolute addresses: the array holds fn
            // pointers, the tag points at the array.
            let fns = [test_ctor as *const () as usize];
            let mut dynv = [
                DT_INIT_ARRAY,
                fns.as_ptr() as usize,
                DT_INIT_ARRAYSZ,
                size_of::<usize>(),
                DT_NULL,
                0usize,
            ];
            d.dynv = dynv.as_mut_ptr();
            d.base = core::ptr::null_mut();
            let dp = &mut d as *mut Dso;
            let mut q = [dp, null_mut()];
            do_init_fini(q.as_mut_ptr());
            assert_eq!(CTOR_RAN.load(Ordering::SeqCst), 1);
            assert_eq!((*dp).constructed, 1);
            do_init_fini(q.as_mut_ptr());
            assert_eq!(CTOR_RAN.load(Ordering::SeqCst), 1, "exactly once");
        }
    }
}
