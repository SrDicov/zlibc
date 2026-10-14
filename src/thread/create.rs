//! Thread creation, joining, and attributes (x86_64).
//!
//! Clean-room mirrors of musl `src/thread/pthread_create.c:237-397`,
//! `src/thread/x86_64/clone.s`, `src/thread/pthread_join.c`,
//! `pthread_detach.c`, the `pthread_attr_*` family, `pthread_self.c`,
//! and `pthread_equal.c`. Exact musl signatures (`include/pthread.h`).

use core::ffi::{c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::Ordering;

use crate::abi::PthreadT;
use crate::futex::futex_wait_private;
use crate::ldso::{MAP_ANONYMOUS, MAP_PRIVATE, PAGE_SIZE, PROT_NONE, PROT_READ, PROT_WRITE};
use crate::syscall::{syscall1, syscall2, syscall3, syscall6, syscall_ret};

use super::tls::{copy_tls, ensure_main_tp, get_tp, set_tp};
use super::unmapself::__unmapself;
use super::{
    AttrT, StartFn, Thread, CLONE_FLAGS, DT_DETACHED, DT_EXITED, DT_EXITING, DT_JOINABLE, EAGAIN,
    EINVAL, ENOTSUP, ESRCH, SYS_EXIT, SYS_MMAP, SYS_MPROTECT, SYS_MUNMAP, SYS_SET_TID_ADDRESS,
};

/// musl `include/limits.h:67` (`PTHREAD_STACK_MIN`), used for the exact
/// `setstacksize`/`setstack` range check.
const PTHREAD_STACK_MIN: usize = 2048;

/// musl `include/pthread.h:33-34` (create detach states).
const PTHREAD_CREATE_DETACHED: c_int = 1;

/// musl `include/pthread.h:50-51` (scope values: `SYSTEM` accepted,
/// `PROCESS` refused with `ENOTSUP`).
const PTHREAD_SCOPE_SYSTEM: c_int = 0;
const PTHREAD_SCOPE_PROCESS: c_int = 1;

/// musl `struct sched_param` (`include/sched.h`): one priority word.
#[repr(C)]
pub struct SchedParam {
    pub sched_priority: c_int,
}

/// Round up to the page size (`ROUND` in `pthread_create.c:219`).
fn round_page(x: usize) -> Option<usize> {
    x.checked_add(PAGE_SIZE - 1).map(|v| v & !(PAGE_SIZE - 1))
}

/// Address of the `detach_state` futex word (no dereference).
fn detach_word(td: *mut Thread) -> *mut c_int {
    unsafe { core::ptr::addr_of_mut!((*td).detach_state).cast::<c_int>() }
}

/// Byte offset of the `detach_state` word (exit sequence below).
const DETACH_OFF: usize = core::mem::offset_of!(super::Thread, detach_state);

/// Address of the `tid` word (no dereference).
fn tid_word(td: *mut Thread) -> *mut c_int {
    unsafe { core::ptr::addr_of_mut!((*td).tid) }
}

/// Raw `clone` (56) with the musl `clone.s:5-28` child discipline.
///
/// Moves the kernel args into place (`flags`->`rdi`, `stack`->`rsi`,
/// `ptid`->`rdx`, `ctid`->`r10`, `tls`->`r8`), aligns the child stack to
/// 16 and pushes `arg`/`func` onto it, then traps. The parent returns the
/// child TID (or a negative errno). The child pops `arg` into `rdi` and
/// `func` into `r9` (same value the parent passed; `r9` survives the
/// trap since the kernel only clobbers `rcx`/`r11`), `call`s it, and
/// `exit`s with its return value — never returning here.
///
/// Register discipline is honest: every register the body rewrites
/// (`rsi`/`rdi`/`rdx`/`r8`/`r10`) is `inlateout`, and the trap-clobbered
/// `rcx`/`r11` are declared `out` (the pre-`clone` values only the trap
/// may read stay valid inputs).
///
/// # Safety
///
/// `flags` must be a valid clone combination; `stack` must be the top of
/// a writable mapping with at least 16 bytes below it; `ptid`/`ctid` must
/// be valid `c_int` cells (or null, to skip that write/clear); `tls` is
/// the new thread's TCB for `CLONE_SETTLS`; `func` must be a valid
/// `extern "C" fn(usize) -> c_int` entry point and `arg` its argument.
/// Must be called with the parent's stack intact (it is: only the child's
/// words are touched). The child's `func` must never panic (unwinding
/// through the trap frame aborts the process).
///
/// `inlateout` operands are read by the trap below; the lint cannot see
/// into asm, hence the targeted allow.
#[cfg(target_arch = "x86_64")]
#[allow(unused_assignments)]
unsafe fn raw_clone(
    mut flags: u32,
    mut stack: usize,
    mut ptid: usize,
    ctid: usize,
    mut tls: usize,
    func: usize,
    mut arg: usize,
) -> isize {
    let mut ret: isize;
    unsafe {
        core::arch::asm!(
            "and rsi, -16",
            "sub rsi, 16",
            "mov [rsi], rcx",
            "mov [rsi + 8], r9",
            "mov rdi, rdx",
            "mov rdx, r8",
            "mov r8, r10",
            "mov r10, {ctid}",
            "mov eax, 56",
            "syscall",
            "test eax, eax",
            "jnz 2f",
            "pop rdi",
            "pop r9",
            "call r9",
            "mov edi, eax",
            "mov eax, 60",
            "syscall",
            "ud2",
            "2:",
            inlateout("rdx") flags,
            inlateout("rsi") stack,
            inlateout("rcx") arg,
            in("r9") func,
            inlateout("r8") ptid,
            inlateout("r10") tls,
            ctid = in(reg) ctid,
            out("rax") ret,
            out("rdi") _,
            out("r11") _,
        );
    }
    ret
}

/// Child trampoline, entered by `call` from [`raw_clone`] with the
/// `Thread` pointer in `rdi`: `SET_FS`, TID, run, exit. Diverges.
///
/// # Safety
///
/// `arg` must be the `Thread` pointer passed to [`raw_clone`], with its
/// TLS block, `start`, and `arg` fields initialized. Runs on the child's
/// fresh stack; the start routine must not panic (see [`raw_clone`]).
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn child_entry(arg: usize) -> c_int {
    let td = arg as *mut Thread;
    unsafe {
        // `__init_tp` order (`__init_tls.c:18,22`): SET_FS, then TID.
        if set_tp(td as usize) < 0 {
            syscall1(SYS_EXIT, 127);
            loop {
                syscall1(SYS_EXIT, 127);
            }
        }
        (*td).tid = syscall1(SYS_SET_TID_ADDRESS, tid_word(td) as usize) as c_int;
        let res = match (*td).start {
            Some(f) => f((*td).arg),
            // create() guarantees `Some`; never call through null.
            None => null_mut(),
        };
        thread_exit(td, res);
    }
}

/// Thread death: store the result, then either publish `DT_EXITED` (waking
/// the joiner, which frees the stack) or, when detached, free the stack
/// ourselves via [`__unmapself`]. Mirrors the tail of musl
/// `__pthread_exit` (`pthread_create.c:169-172` for the joinable wake,
/// `:152-166` for detached self-unmap). Diverges.
///
/// # Safety
///
/// `td` must be the calling thread's live `Thread`; `res` is stored for
/// the joiner. Callers on the joinable path must already be past any use
/// of the stack after the final trap (they are: exit never returns).
///
/// Post-publish discipline (joinable branch): the joiner may unmap this
/// stack the instant `DT_EXITED` is visible, so everything past the store
/// is registers-only inside one opaque trap block. A plain `wake` call
/// uses the stack (call + body spills) — the joiner freeing it mid-call
/// was the flaky SIGSEGV (null-rip cores in lifecycle/validation).
/// Store discipline mirrors musl (plain store + wake trap as the
/// barrier; TSO orders it before the traps). No ENOSYS fallback:
/// `PRIVATE` needs 2.6.22+, like all of NPTL.
///
/// Keep the publish fused inside the trap block below: splitting the
/// store out would reintroduce the unmap window the block closes. The
/// `mov` formally aliases an `AtomicI32` store — operationally exact on
/// TSO like musl, invisible to the model either way.
#[cfg(target_arch = "x86_64")]
unsafe fn thread_exit(td: *mut Thread, res: *mut c_void) -> ! {
    unsafe {
        (*td).result = res;
        // `__pthread_exit` CASes JOINABLE->EXITING so a racing detach owns
        // the outcome (pthread_create.c:76); the loser frees.
        let st = match (*td).detach_state.compare_exchange(
            DT_JOINABLE,
            DT_EXITING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(s) | Err(s) => s,
        };
        if st == DT_JOINABLE {
            super::synccall::unregister_thread(td); // C3: unlink before DT_EXITED wakes join.
            core::arch::asm!(
                "mov dword ptr [{td} + {off}], {exited}",
                "lea rdi, [{td} + {off}]",
                "mov esi, {op}",
                "mov edx, 1",
                "mov eax, {sys}",
                "syscall",
                "xor edi, edi",
                "mov eax, {esys}",
                "syscall",
                "ud2",
                td = in(reg) td,
                off = const DETACH_OFF,
                exited = const DT_EXITED,
                op = const { crate::futex::FUTEX_WAKE | crate::futex::FUTEX_PRIVATE },
                sys = const crate::futex::SYS_FUTEX,
                esys = const SYS_EXIT,
                options(noreturn),
            );
        } else {
            // C3: unlink before __unmapself frees us.
            super::synccall::unregister_thread(td);
            // Detached (created so, or a concurrent detach won): unmap our
            // own stack and die. `map_base` is always set here — user
            // stacks are rejected at create — but exit rather than fault.
            let base = (*td).map_base;
            let size = (*td).map_size;
            if base.is_null() {
                syscall1(SYS_EXIT, 0);
                loop {
                    syscall1(SYS_EXIT, 0);
                }
            }
            __unmapself(base, size);
            loop {
                syscall1(SYS_EXIT, 0);
            }
        }
    }
}

/// Create a thread (musl `__pthread_create`, `pthread_create.c:237-397`,
/// exact signature per `include/pthread.h:80`).
///
/// `mmap`s a guarded stack, carves the TCB/TLS out of its top
/// (`__copy_tls`), and `clone`s with all 10 musl flags. Attrs: null means
/// defaults; `detachstate`/`stacksize`/`guardsize` are honored, everything
/// else is `ENOTSUP`. All clone/`mmap` failures are `EAGAIN` (create.c).
/// The main-thread TP is set up first (`ensure_main_tp`).
///
/// shortcut(no signals): musl blocks app signals around create
/// (create.c:344,381); C1 takes no signal handling — no handlers exist
/// yet to protect. shortcut(no ptc/tsd): `__acquire_ptc` and the
/// `__pthread_tsd_size` carve-out (create.c:265,306,320) are skipped;
/// `tsd` contributes 0 to the sizing until keys land. shortcut(no thread
/// list): new threads self-link instead of joining the global list
/// (create.c:372-376); join waits on `detach_state` only.
///
/// # Safety
///
/// `res` must be a writable pointer; `attr` must be null or point to a
/// valid `AttrT`; `start` must be `Some` (null is `EINVAL`); the pointee
/// behind `arg` must stay valid until the start routine runs. The start
/// routine must not panic (see [`raw_clone`]).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_create(
    res: *mut PthreadT,
    attr: *const AttrT,
    start: StartFn,
    arg: *mut c_void,
) -> c_int {
    unsafe {
        ensure_main_tp();
        if res.is_null() || start.is_none() {
            return EINVAL;
        }
        let mut stacksize = super::DEFAULT_STACKSIZE;
        let mut guardsize = super::DEFAULT_GUARDSIZE;
        let mut detached = false;
        if !attr.is_null() {
            let a = &*attr;
            // shortcut(no explicit sched): the start-control handshake
            // (create.c:339,363-370) needs scheduler syscalls — reject.
            if a.sched() != 0 || a.policy() != 0 || a.prio() != 0 {
                return ENOTSUP;
            }
            // shortcut(no user stacks): carving TLS out of caller memory
            // (create.c:271-286) needs the size heuristic — reject.
            if a.stackaddr() != 0 {
                return ENOTSUP;
            }
            if a.detach() != 0 && a.detach() != PTHREAD_CREATE_DETACHED {
                return EINVAL;
            }
            stacksize = a.stacksize();
            guardsize = a.guardsize();
            detached = a.detach() != 0;
        }
        // create.c:288-290: guard + stack + TLS (+ 0 tsd, see docs above).
        let tls_size = super::tls::current_tls_size();
        let guard = match round_page(guardsize) {
            Some(g) => g,
            None => return EAGAIN,
        };
        let sized = stacksize
            .checked_add(tls_size)
            .and_then(round_page)
            .and_then(|s| guard.checked_add(s));
        let size = match sized {
            Some(s) => s,
            None => return EAGAIN,
        };
        // -1 fd for MAP_ANONYMOUS, spelled as usize::MAX: `-1 as usize`
        // parses as `-(1 as usize)` and does not compile.
        // Direct calls (not the macro): the macro wraps itself in
        // `unsafe`, which would be redundant inside this block.
        let map = syscall_ret(syscall6(
            SYS_MMAP,
            0,
            size,
            (PROT_READ | PROT_WRITE) as usize,
            (MAP_PRIVATE | MAP_ANONYMOUS) as usize,
            usize::MAX,
            0,
        ));
        if map == -1 {
            return EAGAIN;
        }
        if guard != 0 {
            // create.c:297-301 maps NONE then opens the usable part;
            // mapping RW and closing the guard is the same end state. Any
            // failure unmaps and reports EAGAIN (`mprotect` is
            // unconditional on x86_64 Linux).
            let r = syscall_ret(syscall3(
                SYS_MPROTECT,
                map as usize,
                guard,
                PROT_NONE as usize,
            ));
            if r == -1 {
                let _ = syscall_ret(syscall2(SYS_MUNMAP, map as usize, size));
                return EAGAIN;
            }
        }
        let base = map as *mut u8;
        // TLS block at the top, like musl's `__copy_tls(tsd - tls_size)`
        // (create.c:318): never inside the PROT_NONE guard at `base`,
        // where the DTV write would fault.
        let td = copy_tls(base.wrapping_add(size - tls_size), tls_size);
        (*td).tid = 0;
        (*td).detach_state.store(
            if detached { DT_DETACHED } else { DT_JOINABLE },
            Ordering::SeqCst,
        );
        // Per-thread errno cell, claimed by `errno.rs` via the magic.
        (*td).errno_val = 0;
        (*td).magic = super::THREAD_MAGIC;
        (*td).map_base = base;
        (*td).map_size = size;
        let top = td as usize;
        (*td).stack = top as *mut u8;
        (*td).stack_size = top.wrapping_sub(base as usize).wrapping_sub(guard);
        (*td).guard_size = guard;
        (*td).result = null_mut();
        (*td).start = start;
        (*td).arg = arg;
        // create.c:328-329: the child inherits canary/sysinfo from a
        // proven-ours parent; a foreign TP (host glibc under test, or
        // unset) contributes zeros instead of foreign bytes (same magic
        // discipline as `errno.rs`).
        let parent = get_tp() as *mut Thread;
        let ours = !parent.is_null() && (*parent).magic == super::THREAD_MAGIC;
        if ours {
            (*td).head.canary = (*parent).head.canary;
            (*td).head.sysinfo = (*parent).head.sysinfo;
        } else {
            (*td).head.canary = 0;
            (*td).head.sysinfo = 0;
        }
        let tid_cell = tid_word(td) as usize;
        // `ptid`+`ctid` share the tid word: the kernel reports the TID at
        // creation and clears it (futex wake) at thread exit.
        // Register BEFORE clone (see `register_thread`): a detached child
        // may die and unmap itself before `clone` returns to us.
        super::synccall::register_thread(td);
        let r = raw_clone(
            CLONE_FLAGS,
            top,
            tid_cell,
            tid_cell,
            td as usize,
            child_entry as *const () as usize,
            td as usize,
        );
        if r < 0 {
            // Never ran: unlink the pre-clone node, then free the stack.
            super::synccall::unregister_thread(td);
            let _ = syscall_ret(syscall2(SYS_MUNMAP, base as usize, size));
            return EAGAIN;
        }
        res.write(td as PthreadT);
        0
    }
}

/// Join a thread (musl `__pthread_join`, `pthread_join.c:28-31`, exact
/// signature per `include/pthread.h:83`).
///
/// Sleeps on `detach_state` until `DT_EXITED` (the indefinite-wait shape
/// of `__pthread_timedjoin_np`, join.c:10-26, minus cancel/clock), then
/// collects the result and unmaps the stack. Joining a detached thread
/// returns `EINVAL` (musl traps via `a_crash`, join.c:17 — same contract,
/// non-fatal spelling).
/// shortcut(main join): joining the main thread (null mapping, never
/// exits) blocks forever; musl `exit(0)`s via its thread-list check
/// (create.c:100-106), which needs the list C1 skips.
///
/// # Safety
///
/// `t` must be a live joinable thread from [`__pthread_create`] not
/// joined/detached before; `res` must be null or writable. After success
/// `t` dangles (its stack is unmapped) and must not be reused.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_join(t: PthreadT, res: *mut *mut c_void) -> c_int {
    if t.is_null() {
        return ESRCH;
    }
    let td = t as *mut Thread;
    unsafe {
        loop {
            let st = (*td).detach_state.load(Ordering::SeqCst);
            if st == DT_EXITED {
                break;
            }
            if st == DT_JOINABLE || st == DT_EXITING {
                let _ = futex_wait_private(detach_word(td), st);
            } else {
                return EINVAL;
            }
        }
        // The `SeqCst` EXITED load pairs with the exiter's store: `result`
        // is visible (this is join.c:22's `__tl_sync` role).
        if !res.is_null() {
            res.write((*td).result);
        }
        let base = (*td).map_base;
        let size = (*td).map_size;
        if !base.is_null() {
            let _ = syscall_ret(syscall2(SYS_MUNMAP, base as usize, size));
        }
        0
    }
}

/// Detach a thread (musl `__pthread_detach`, `pthread_detach.c:4-15`,
/// exact signature per `include/pthread.h:81`).
///
/// Winners (JOINABLE->DETACHED) return 0 and the thread frees itself on
/// death; losers against exit reap via join (detach.c:9-12). Detaching an
/// already-detached thread returns `EINVAL` (musl traps inside its join).
///
/// # Safety
///
/// `t` must be a live thread from [`__pthread_create`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_detach(t: PthreadT) -> c_int {
    if t.is_null() {
        return ESRCH;
    }
    let td = t as *mut Thread;
    unsafe {
        match (*td).detach_state.compare_exchange(
            DT_JOINABLE,
            DT_DETACHED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => 0,
            Err(DT_DETACHED) => EINVAL,
            Err(_) => __pthread_join(t, null_mut()),
        }
    }
}

/// Current thread (musl `pthread_self`, `pthread_self.c:4-10`, exact
/// signature per `include/pthread.h:88`): the `FS:0` word
/// (`arch/x86_64/pthread_arch.h:1-6`, `__get_tp`).
///
/// # Safety
///
/// The calling thread's `FS` must point at our TCB (true after
/// [`__pthread_create`]/`ensure_main_tp`; foreign threads see their own
/// platform value, which must only be compared, never dereferenced).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_self() -> PthreadT {
    get_tp() as PthreadT
}

/// Thread equality (musl `__pthread_equal`, `pthread_equal.c:4-10`, exact
/// signature per `include/pthread.h:90`): pointer comparison.
///
/// # Safety
///
/// Both arguments must be null or valid thread pointers (only compared).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_equal(a: PthreadT, b: PthreadT) -> c_int {
    (a == b) as c_int
}

/// Init an attr object with defaults (musl `pthread_attr_init.c:3-11`,
/// exact signature per `include/pthread.h:150`).
///
/// # Safety
///
/// `a` must point to a writable `AttrT`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_attr_init(a: *mut AttrT) -> c_int {
    if a.is_null() {
        return EINVAL;
    }
    unsafe {
        // No ptc lock (attr_init.c:6,8): keys are OUT, nothing to guard.
        core::ptr::write(a, AttrT::default());
        (*a).set_stacksize(super::DEFAULT_STACKSIZE);
        (*a).set_guardsize(super::DEFAULT_GUARDSIZE);
        0
    }
}

/// Destroy an attr object (musl `pthread_attr_destroy.c:3-6`, exact
/// signature per `include/pthread.h:151`): no-op, always succeeds.
///
/// # Safety
///
/// `a` must point to a valid `AttrT` (unchecked, like musl).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_attr_destroy(_a: *mut AttrT) -> c_int {
    0
}

/// Set detach state (musl `pthread_attr_setdetachstate.c:3-8`, exact
/// signature per `include/pthread.h:157`).
///
/// # Safety
///
/// `a` must point to a valid `AttrT`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_attr_setdetachstate(a: *mut AttrT, state: c_int) -> c_int {
    if a.is_null() {
        return EINVAL;
    }
    // `state > 1U` in C also catches negatives; spell both (setdetachstate.c:5).
    if state != 0 && state != PTHREAD_CREATE_DETACHED {
        return EINVAL;
    }
    unsafe {
        (*a).set_detach(state);
    }
    0
}

/// Get detach state (musl `pthread_attr_get.c`, exact signature per
/// `include/pthread.h:156`).
///
/// # Safety
///
/// `a` must point to a valid `AttrT`; `state` must be writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_attr_getdetachstate(
    a: *const AttrT,
    state: *mut c_int,
) -> c_int {
    if a.is_null() || state.is_null() {
        return EINVAL;
    }
    unsafe {
        state.write((*a).detach());
    }
    0
}

/// Set stack size (musl `pthread_attr_setstacksize.c:3-9`, exact signature
/// per `include/pthread.h:155`).
///
/// # Safety
///
/// `a` must point to a valid `AttrT`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_attr_setstacksize(a: *mut AttrT, size: usize) -> c_int {
    if a.is_null() {
        return EINVAL;
    }
    // Exact check (setstacksize.c:5): below-min wraps huge, over-max stays.
    if size.wrapping_sub(PTHREAD_STACK_MIN) > usize::MAX / 4 {
        return EINVAL;
    }
    unsafe {
        (*a).set_stackaddr(0);
        (*a).set_stacksize(size);
    }
    0
}

/// Get stack size (musl `pthread_attr_get.c`, exact signature per
/// `include/pthread.h:154`).
///
/// # Safety
///
/// `a` must point to a valid `AttrT`; `size` must be writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_attr_getstacksize(a: *const AttrT, size: *mut usize) -> c_int {
    if a.is_null() || size.is_null() {
        return EINVAL;
    }
    unsafe {
        size.write((*a).stacksize());
    }
    0
}

/// Set guard size (musl `pthread_attr_setguardsize.c:3-8`, exact signature
/// per `include/pthread.h:153`).
///
/// # Safety
///
/// `a` must point to a valid `AttrT`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_attr_setguardsize(a: *mut AttrT, size: usize) -> c_int {
    if a.is_null() {
        return EINVAL;
    }
    if size > usize::MAX / 8 {
        return EINVAL;
    }
    unsafe {
        (*a).set_guardsize(size);
    }
    0
}

/// Get guard size (musl `pthread_attr_get.c`, exact signature per
/// `include/pthread.h:152`).
///
/// # Safety
///
/// `a` must point to a valid `AttrT`; `size` must be writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_attr_getguardsize(a: *const AttrT, size: *mut usize) -> c_int {
    if a.is_null() || size.is_null() {
        return EINVAL;
    }
    unsafe {
        size.write((*a).guardsize());
    }
    0
}

/// Set an explicit stack (musl `pthread_attr_setstack.c`, exact signature
/// per `include/pthread.h:159`): `ENOTSUP` — caller stacks need the TLS
/// carve-out create rejects (see [`__pthread_create`]).
///
/// # Safety
///
/// `a` must point to a valid `AttrT`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_attr_setstack(
    a: *mut AttrT,
    _addr: *mut c_void,
    _size: usize,
) -> c_int {
    if a.is_null() {
        return EINVAL;
    }
    ENOTSUP
}

/// Get the explicit stack (musl `pthread_attr_get.c`, exact signature per
/// `include/pthread.h:158`): `EINVAL`, since no stack is ever set (musl
/// reports `EINVAL` when `_a_stackaddr` is unset).
///
/// # Safety
///
/// `a` must point to a valid `AttrT`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_attr_getstack(
    a: *const AttrT,
    _addr: *mut *mut c_void,
    _size: *mut usize,
) -> c_int {
    if a.is_null() {
        return EINVAL;
    }
    EINVAL
}

/// Set scope (musl `pthread_attr_setscope.c`, exact signature per
/// `include/pthread.h:161`): `SYSTEM` accepted, `PROCESS` is `ENOTSUP`,
/// anything else `EINVAL`. Like musl, stores nothing.
///
/// # Safety
///
/// `a` must point to a valid `AttrT`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_attr_setscope(a: *mut AttrT, scope: c_int) -> c_int {
    if a.is_null() {
        return EINVAL;
    }
    match scope {
        PTHREAD_SCOPE_SYSTEM => 0,
        PTHREAD_SCOPE_PROCESS => ENOTSUP,
        _ => EINVAL,
    }
}

/// Get scope (musl `pthread_attr_get.c`, exact signature per
/// `include/pthread.h:160`): always `SYSTEM`, like musl.
///
/// # Safety
///
/// `a` must point to a valid `AttrT`; `scope` must be writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_attr_getscope(a: *const AttrT, scope: *mut c_int) -> c_int {
    if a.is_null() || scope.is_null() {
        return EINVAL;
    }
    unsafe {
        scope.write(PTHREAD_SCOPE_SYSTEM);
    }
    0
}

/// Set scheduling policy (musl `pthread_attr_setschedpolicy.c`, exact
/// signature per `include/pthread.h:163`): `ENOTSUP` (explicit scheduling
/// is rejected at create; see [`__pthread_create`]).
///
/// # Safety
///
/// `a` must point to a valid `AttrT`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_attr_setschedpolicy(a: *mut AttrT, _policy: c_int) -> c_int {
    if a.is_null() {
        return EINVAL;
    }
    ENOTSUP
}

/// Get scheduling policy (musl `pthread_attr_get.c`, exact signature per
/// `include/pthread.h:162`): the stored word (always 0: sets are refused).
///
/// # Safety
///
/// `a` must point to a valid `AttrT`; `policy` must be writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_attr_getschedpolicy(
    a: *const AttrT,
    policy: *mut c_int,
) -> c_int {
    if a.is_null() || policy.is_null() {
        return EINVAL;
    }
    unsafe {
        policy.write((*a).policy());
    }
    0
}

/// Set scheduling params (musl `pthread_attr_setschedparam.c`, exact
/// signature per `include/pthread.h:165`): `ENOTSUP` (see
/// [`__pthread_create`]).
///
/// # Safety
///
/// `a` must point to a valid `AttrT`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_attr_setschedparam(
    a: *mut AttrT,
    _param: *const SchedParam,
) -> c_int {
    if a.is_null() {
        return EINVAL;
    }
    ENOTSUP
}

/// Get scheduling params (musl `pthread_attr_get.c`, exact signature per
/// `include/pthread.h:164`): stored priority (always 0: sets are refused).
///
/// # Safety
///
/// `a` must point to a valid `AttrT`; `param` must be writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_attr_getschedparam(
    a: *const AttrT,
    param: *mut SchedParam,
) -> c_int {
    if a.is_null() || param.is_null() {
        return EINVAL;
    }
    unsafe {
        (*param).sched_priority = (*a).prio();
    }
    0
}

/// Set inherit-scheduler (musl `pthread_attr_setinheritsched.c`, exact
/// signature per `include/pthread.h:167`): `ENOTSUP` (see
/// [`__pthread_create`]).
///
/// # Safety
///
/// `a` must point to a valid `AttrT`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_attr_setinheritsched(a: *mut AttrT, _inherit: c_int) -> c_int {
    if a.is_null() {
        return EINVAL;
    }
    ENOTSUP
}

/// Get inherit-scheduler (musl `pthread_attr_get.c`, exact signature per
/// `include/pthread.h:166`): stored word (always 0: sets are refused).
///
/// # Safety
///
/// `a` must point to a valid `AttrT`; `inherit` must be writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_attr_getinheritsched(
    a: *const AttrT,
    inherit: *mut c_int,
) -> c_int {
    if a.is_null() || inherit.is_null() {
        return EINVAL;
    }
    unsafe {
        inherit.write((*a).sched());
    }
    0
}

#[cfg(test)]
mod tests {
    use super::super::{ARCH_GET_FS, ARCH_SET_FS, SYS_ARCH_PRCTL};
    use super::*;
    use crate::syscall::syscall2;
    use core::sync::atomic::AtomicU32;

    /// Save the current `FS` base (`arch_prctl(ARCH_GET_FS)`).
    fn save_fs() -> usize {
        let mut base: usize = 0;
        unsafe {
            let _ = syscall2(
                SYS_ARCH_PRCTL,
                ARCH_GET_FS,
                core::ptr::addr_of_mut!(base) as usize,
            );
        }
        base
    }

    /// Restore an `FS` base saved by [`save_fs`].
    fn restore_fs(base: usize) {
        unsafe {
            let _ = syscall2(SYS_ARCH_PRCTL, ARCH_SET_FS, base);
        }
    }

    /// Attr defaults plus every validation path. Touches no threads or
    /// `FS`, so plain asserts are safe here.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn attr_defaults_and_validation() {
        unsafe {
            let mut a = AttrT::default();
            let ap = core::ptr::addr_of_mut!(a);
            assert_eq!(__pthread_attr_init(ap), 0);
            let mut v = 0usize;
            let mut i = -1;
            assert_eq!(__pthread_attr_getstacksize(ap, &mut v), 0);
            assert_eq!(v, 131072);
            assert_eq!(__pthread_attr_getguardsize(ap, &mut v), 0);
            assert_eq!(v, 8192);
            assert_eq!(__pthread_attr_getdetachstate(ap, &mut i), 0);
            assert_eq!(i, 0);
            // Detach round-trip; out-of-range (either side) is EINVAL.
            assert_eq!(__pthread_attr_setdetachstate(ap, 1), 0);
            assert_eq!(__pthread_attr_getdetachstate(ap, &mut i), 0);
            assert_eq!(i, 1);
            assert_eq!(__pthread_attr_setdetachstate(ap, 2), EINVAL);
            assert_eq!(__pthread_attr_setdetachstate(ap, -1), EINVAL);
            // Sizes: below-min and huge are EINVAL (exact musl check).
            assert_eq!(__pthread_attr_setstacksize(ap, 1 << 16), 0);
            assert_eq!(__pthread_attr_getstacksize(ap, &mut v), 0);
            assert_eq!(v, 1 << 16);
            assert_eq!(__pthread_attr_setstacksize(ap, 1024), EINVAL);
            assert_eq!(__pthread_attr_setstacksize(ap, usize::MAX), EINVAL);
            assert_eq!(__pthread_attr_setguardsize(ap, 1 << 20), 0);
            assert_eq!(__pthread_attr_getguardsize(ap, &mut v), 0);
            assert_eq!(v, 1 << 20);
            assert_eq!(__pthread_attr_setguardsize(ap, usize::MAX), EINVAL);
            // Everything else: sets refused, gets report defaults.
            assert_eq!(__pthread_attr_setstack(ap, null_mut(), 1 << 16), ENOTSUP);
            assert_eq!(__pthread_attr_getstack(ap, null_mut(), null_mut()), EINVAL);
            assert_eq!(__pthread_attr_setscope(ap, 0), 0);
            assert_eq!(__pthread_attr_setscope(ap, 1), ENOTSUP);
            assert_eq!(__pthread_attr_setscope(ap, 7), EINVAL);
            assert_eq!(__pthread_attr_getscope(ap, &mut i), 0);
            assert_eq!(i, 0);
            assert_eq!(__pthread_attr_setschedpolicy(ap, 0), ENOTSUP);
            assert_eq!(__pthread_attr_getschedpolicy(ap, &mut i), 0);
            assert_eq!(i, 0);
            let p = SchedParam { sched_priority: 5 };
            assert_eq!(__pthread_attr_setschedparam(ap, &p), ENOTSUP);
            let mut q = SchedParam { sched_priority: -7 };
            assert_eq!(__pthread_attr_getschedparam(ap, &mut q), 0);
            assert_eq!(q.sched_priority, 0);
            assert_eq!(__pthread_attr_setinheritsched(ap, 0), ENOTSUP);
            assert_eq!(__pthread_attr_getinheritsched(ap, &mut i), 0);
            assert_eq!(i, 0);
            assert_eq!(__pthread_attr_destroy(ap), 0);
        }
    }

    #[derive(Clone, Copy)]
    struct SumSlot {
        base: u64,
        n: u64,
        out: u64,
        me: usize,
    }

    static mut SLOTS: [SumSlot; 4] = [SumSlot {
        base: 0,
        n: 0,
        out: 0,
        me: 0,
    }; 4];

    /// Child code: pure GPR/atomics only. Must not touch host TLS (its
    /// `FS` is our TCB) and must not panic (see [`raw_clone`]).
    unsafe extern "C" fn sum_routine(arg: *mut c_void) -> *mut c_void {
        let s = arg as *mut SumSlot;
        unsafe {
            let mut acc = 0u64;
            let mut k = 0u64;
            while k < (*s).n {
                acc += (*s).base + k;
                k += 1;
            }
            (*s).out = acc;
            (*s).me = __pthread_self() as usize;
            acc as usize as *mut c_void
        }
    }

    static DT_GO: AtomicU32 = AtomicU32::new(0);

    /// Child code for the detach test: spin until released, then die.
    /// Spinning (never early-exiting) is load-bearing: both detaches
    /// below must observe a live thread, or the second one would touch
    /// memory the first already freed (join+unmap of a dead joinable is
    /// silent, the rerun use-after-free is a nondeterministic SIGSEGV).
    unsafe extern "C" fn spin_release(_arg: *mut c_void) -> *mut c_void {
        while DT_GO.load(Ordering::SeqCst) == 0 {
            core::hint::spin_loop();
        }
        null_mut()
    }

    /// One serial lifecycle test (self/equal, N-way join sums, detached
    /// flag). Serial on purpose: `FS` juggling is per-thread global state
    /// and must not interleave with another FS user. The clobbered window
    /// performs no asserts (a failing assert would unwind through host
    /// TLS); everything is collected, `FS` restored, then asserted.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn thread_lifecycle_end_to_end() {
        const N: usize = 4;
        const PER: u64 = 2500;
        let host_fs = save_fs();
        let mut tids: [PthreadT; N] = [null_mut(); N];
        let mut rets: [*mut c_void; N] = [null_mut(); N];
        let mut mes: [usize; N] = [0; N];
        let mut outs: [u64; N] = [0; N];
        ensure_main_tp();
        let me: PthreadT = unsafe { __pthread_self() };
        let eq_self = unsafe { __pthread_equal(me, me) };
        let eq_null = unsafe { __pthread_equal(me, null_mut()) };
        let eq_nulls = unsafe { __pthread_equal(null_mut(), null_mut()) };
        unsafe {
            let mut k = 0;
            while k < N {
                let s = core::ptr::addr_of_mut!(SLOTS).cast::<SumSlot>().add(k);
                (*s).base = (k as u64) * PER;
                (*s).n = PER;
                let tp = core::ptr::addr_of_mut!(tids).cast::<PthreadT>().add(k);
                let rp = core::ptr::addr_of_mut!(rets).cast::<*mut c_void>().add(k);
                let rc = __pthread_create(tp, null_mut(), Some(sum_routine), s as *mut c_void);
                if rc == 0 {
                    let _ = __pthread_join(*tp, rp);
                }
                k += 1;
            }
            let mut k = 0;
            while k < N {
                let s = core::ptr::addr_of!(SLOTS).cast::<SumSlot>().add(k);
                mes[k] = (*s).me;
                outs[k] = (*s).out;
                k += 1;
            }
        }
        DT_GO.store(0, Ordering::SeqCst);
        let mut attr = AttrT::default();
        let mut dt: PthreadT = null_mut();
        // Detach-twice on a GUARANTEED-live thread: it spins until we
        // release it, so detach once reports 0 and detach again EINVAL,
        // deterministically. Releasing it lets it die detached (the
        // __unmapself path runs); dt is never touched afterwards.
        let (detach_rc, detach_again) = unsafe {
            if __pthread_attr_init(&mut attr) == 0
                && __pthread_create(&mut dt, &attr, Some(spin_release), null_mut()) == 0
            {
                (__pthread_detach(dt), __pthread_detach(dt))
            } else {
                (-1, -1)
            }
        };
        DT_GO.store(1, Ordering::SeqCst);
        restore_fs(host_fs);
        // Now safe to assert (host TLS intact).
        assert!(!me.is_null());
        assert_ne!(eq_self, 0);
        assert_eq!(eq_null, 0);
        assert_ne!(eq_nulls, 0);
        let mut total = 0u64;
        let mut k = 0;
        while k < N {
            let want = PER * ((k as u64) * PER) + PER * (PER - 1) / 2;
            assert_eq!(outs[k], want);
            assert_eq!(rets[k] as usize as u64, want);
            assert_eq!(mes[k], tids[k] as usize);
            total += outs[k];
            k += 1;
        }
        assert_eq!(total, (N as u64) * PER * ((N as u64) * PER - 1) / 2);
        assert_eq!(detach_rc, 0);
        assert_eq!(detach_again, EINVAL);
    }
}
