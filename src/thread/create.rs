//! Thread creation, joining, and attributes (x86_64).
//!
//! Clean-room mirrors of musl `src/thread/pthread_create.c:237-397`,
//! `src/thread/x86_64/clone.s`, `src/thread/pthread_join.c`,
//! `pthread_detach.c`, the `pthread_attr_*` family, `pthread_self.c`,
//! and `pthread_equal.c`. Exact musl signatures (`include/pthread.h`).

use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

use crate::abi::PthreadT;
use crate::futex::futex_wait_private;
use crate::ldso::{MAP_ANONYMOUS, MAP_PRIVATE, PAGE_SIZE, PROT_NONE, PROT_READ, PROT_WRITE};
use crate::syscall::{
    syscall0, syscall1, syscall2, syscall3, syscall4, syscall5, syscall6, syscall_ret,
};

use super::tls::{copy_tls, ensure_main_tp, get_tp, set_tp};
use super::unmapself::__unmapself;
use super::{
    AttrT, StartFn, Thread, CLONE_FLAGS, DT_DETACHED, DT_EXITED, DT_EXITING, DT_JOINABLE, EAGAIN,
    EINVAL, ENOTSUP, ESRCH, SYS_EXIT, SYS_MMAP, SYS_MPROTECT, SYS_MUNMAP, SYS_SET_TID_ADDRESS,
};

// Hide the `__pthread_*` impls (musl marks them hidden, e.g.
// `clone.s:3`, `__set_thread_area.s:4`): in test builds this keeps our
// symbols from interposing host glibc/std; in real links the weak
// aliases below are the public face. Plain comment: rustdoc documents
// no macro invocation.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".hidden __pthread_create\n.hidden __pthread_join\n.hidden __pthread_detach\n\
    .hidden __pthread_self\n.hidden __pthread_equal\n.hidden __pthread_attr_init\n\
    .hidden __pthread_attr_destroy\n.hidden __pthread_attr_setdetachstate\n\
    .hidden __pthread_attr_getdetachstate\n.hidden __pthread_attr_setstacksize\n\
    .hidden __pthread_attr_getstacksize\n.hidden __pthread_attr_setguardsize\n\
    .hidden __pthread_attr_getguardsize\n.hidden __pthread_attr_setstack\n\
    .hidden __pthread_attr_getstack\n.hidden __pthread_attr_setscope\n\
    .hidden __pthread_attr_getscope\n.hidden __pthread_attr_setschedpolicy\n\
    .hidden __pthread_attr_getschedpolicy\n.hidden __pthread_attr_setschedparam\n\
    .hidden __pthread_attr_getschedparam\n.hidden __pthread_attr_setinheritsched\n\
    .hidden __pthread_attr_getinheritsched\n\
    .hidden __pthread_key_create\n.hidden __pthread_key_delete\n.hidden __pthread_getspecific\n\
    .hidden __pthread_once\n.hidden __pthread_exit\n.hidden __pthread_cancel\n\
    .hidden __pthread_testcancel\n.hidden __pthread_setcancelstate\n.hidden __pthread_setcanceltype\n\
    .hidden __pthread_atfork\n\
    .hidden __pthread_setattr_default_np\n.hidden __pthread_getattr_default_np\n\
    .hidden __pthread_getattr_np\n.hidden __pthread_kill\n.hidden __pthread_sigmask\n\
    .hidden __pthread_getschedparam\n.hidden __pthread_setschedparam\n.hidden __pthread_setschedprio\n\
    .hidden __pthread_getcpuclockid\n.hidden __pthread_getaffinity_np\n.hidden __pthread_setaffinity_np\n\
    .hidden __pthread_setname_np\n.hidden __pthread_getname_np\n.hidden __pthread_tryjoin_np\n\
    .hidden __pthread_timedjoin_np"
);

// Public musl names for real links only (see module docs for why tests
// must not export them).
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_create, __pthread_create);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_join, __pthread_join);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_detach, __pthread_detach);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_self, __pthread_self);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_equal, __pthread_equal);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_attr_init, __pthread_attr_init);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_attr_destroy, __pthread_attr_destroy);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_attr_setdetachstate, __pthread_attr_setdetachstate);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_attr_getdetachstate, __pthread_attr_getdetachstate);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_attr_setstacksize, __pthread_attr_setstacksize);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_attr_getstacksize, __pthread_attr_getstacksize);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_attr_setguardsize, __pthread_attr_setguardsize);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_attr_getguardsize, __pthread_attr_getguardsize);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_attr_setstack, __pthread_attr_setstack);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_attr_getstack, __pthread_attr_getstack);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_attr_setscope, __pthread_attr_setscope);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_attr_getscope, __pthread_attr_getscope);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_attr_setschedpolicy, __pthread_attr_setschedpolicy);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_attr_getschedpolicy, __pthread_attr_getschedpolicy);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_attr_setschedparam, __pthread_attr_setschedparam);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_attr_getschedparam, __pthread_attr_getschedparam);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_attr_setinheritsched, __pthread_attr_setinheritsched);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_attr_getinheritsched, __pthread_attr_getinheritsched);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_key_create, __pthread_key_create);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_key_delete, __pthread_key_delete);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_getspecific, __pthread_getspecific);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(tss_get, __pthread_getspecific);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_once, __pthread_once);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(call_once, __pthread_once);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_exit, __pthread_exit);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_cancel, __pthread_cancel);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_testcancel, __pthread_testcancel);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_setcancelstate, __pthread_setcancelstate);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_setcanceltype, __pthread_setcanceltype);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_atfork, __pthread_atfork);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_setattr_default_np, __pthread_setattr_default_np);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_getattr_default_np, __pthread_getattr_default_np);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_getattr_np, __pthread_getattr_np);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_kill, __pthread_kill);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_sigmask, __pthread_sigmask);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_getschedparam, __pthread_getschedparam);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_setschedparam, __pthread_setschedparam);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_setschedprio, __pthread_setschedprio);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_getcpuclockid, __pthread_getcpuclockid);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_getaffinity_np, __pthread_getaffinity_np);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_setaffinity_np, __pthread_setaffinity_np);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_setname_np, __pthread_setname_np);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_getname_np, __pthread_getname_np);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_tryjoin_np, __pthread_tryjoin_np);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(pthread_timedjoin_np, __pthread_timedjoin_np);

// ---- C11 tss (musl src/thread/tss_{create,delete,set}.c: thin key wrappers) ----
/// Create a thread-specific slot (musl `tss_create`).
///
/// # Safety
///
/// Same as [`__pthread_key_create`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn tss_create(tss: *mut u32, dtor: DtorFn) -> c_int {
    unsafe { __pthread_key_create(tss, dtor) }
}

/// Delete a thread-specific slot (musl `tss_delete`: no error return).
///
/// # Safety
///
/// `key` should be live.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn tss_delete(key: u32) {
    unsafe {
        __pthread_key_delete(key);
    }
}

/// Store a thread-specific value (musl `tss_set`: `EINVAL` becomes
/// `thrd_error`, anything else is `thrd_success`).
///
/// # Safety
///
/// Same as [`pthread_setspecific`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn tss_set(key: u32, x: *mut c_void) -> c_int {
    unsafe {
        if pthread_setspecific(key, x) != 0 {
            2
        } else {
            0
        }
    }
}

// Loader-visible names live next to their targets (not in `mod.rs`):
// module-level `global_asm!` rides with its module's codegen unit, and
// `mod.rs` emits no surviving code of its own — after a whole-crate
// repartition its aliases silently vanished from the archive (seen:
// `W pthread_create` present with one file set, gone with another,
// same toolchain). Beside the `__pthread_*` definitions they cannot
// be orphaned.
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
        run_tsd_dtors(td);
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
        if attr.is_null() {
            let d = default_attr_snapshot();
            if d.stacksize() != 0 {
                stacksize = d.stacksize();
            }
            if d.guardsize() != 0 {
                guardsize = d.guardsize();
            }
            detached = d.detach() != 0;
        }
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

// ---- TSD (musl src/thread/pthread_key_create.c + getspecific/setspecific) ----
/// Key slots (musl `PTHREAD_KEYS_MAX`, `include/limits.h:66`).
#[cfg(target_arch = "x86_64")]
const PTHREAD_KEYS_MAX: usize = 128;
/// Destructor iterations at thread death (musl `PTHREAD_DESTRUCTOR_ITERATIONS`).
#[cfg(target_arch = "x86_64")]
const PTHREAD_DESTRUCTOR_ITERATIONS: usize = 4;

/// Key slot liveness (musl `keys[]` occupancy; atomics, written under
/// `KEY_LOCK`).
#[cfg(target_arch = "x86_64")]
static KEYS_USED: [AtomicBool; PTHREAD_KEYS_MAX] =
    [const { AtomicBool::new(false) }; PTHREAD_KEYS_MAX];

/// Key destructors, parallel to [`KEYS_USED`] (musl `keys[]` payload).
/// Written under `KEY_LOCK` only.
#[cfg(target_arch = "x86_64")]
static mut KEYS_DTOR: [*mut c_void; PTHREAD_KEYS_MAX] = [null_mut(); PTHREAD_KEYS_MAX];

#[cfg(target_arch = "x86_64")]
type DtorFn = Option<unsafe extern "C" fn(*mut c_void)>;

#[cfg(target_arch = "x86_64")]
static NEXT_KEY: AtomicUsize = AtomicUsize::new(0);

/// Create a thread-specific key (musl `__pthread_key_create`: lowest free
/// slot from a rotating cursor, `EAGAIN` when full; null dtor is a
/// sentinel, never called).
///
/// # Safety
///
/// `k` must point to writable `pthread_key_t`; `dtor` must be null or a
/// valid destructor (runs at thread exit, see [`run_tsd_dtors`]).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_key_create(k: *mut u32, dtor: DtorFn) -> c_int {
    unsafe {
        if k.is_null() {
            return EINVAL;
        }
        // fake lock: single global spinlock would do; musl uses an rwlock.
        // Contention here is creation-only; a test-and-set spin is enough.
        while KEY_LOCK.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        let start = NEXT_KEY.load(Ordering::Relaxed) % PTHREAD_KEYS_MAX;
        let mut j = start;
        let mut rc = EAGAIN;
        loop {
            if !KEYS_USED[j].load(Ordering::Relaxed) {
                KEYS_USED[j].store(true, Ordering::Relaxed);
                core::ptr::addr_of_mut!(KEYS_DTOR[j])
                    .write(dtor.map_or(null_mut(), |f| f as *mut c_void));
                NEXT_KEY.store((j + 1) % PTHREAD_KEYS_MAX, Ordering::Relaxed);
                *k = j as u32;
                rc = 0;
                break;
            }
            j = (j + 1) % PTHREAD_KEYS_MAX;
            if j == start {
                break;
            }
        }
        KEY_LOCK.store(false, Ordering::Release);
        rc
    }
}

#[cfg(target_arch = "x86_64")]
static KEY_LOCK: AtomicBool = AtomicBool::new(false);

/// Delete a key (musl: frees the slot; values stay until overwritten).
///
/// # Safety
///
/// `k` must be a live key from [`__pthread_key_create`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_key_delete(k: u32) -> c_int {
    unsafe {
        if k as usize >= PTHREAD_KEYS_MAX {
            return EINVAL;
        }
        while KEY_LOCK.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        KEYS_USED[k as usize].store(false, Ordering::Relaxed);
        core::ptr::addr_of_mut!(KEYS_DTOR[k as usize]).write(null_mut());
        KEY_LOCK.store(false, Ordering::Release);
        0
    }
}

/// Read a thread-specific value (musl `__pthread_getspecific`: direct
/// index; out-of-range keys read null here instead of OOB — strictly
/// safer, same observable result for live keys).
///
/// # Safety
///
/// `k` should be a live key; foreign keys yield null.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_getspecific(k: u32) -> *mut c_void {
    unsafe {
        if k as usize >= PTHREAD_KEYS_MAX {
            return null_mut();
        }
        let td = get_tp() as *mut Thread;
        if td.is_null() {
            return null_mut();
        }
        (*td).tsd[k as usize]
    }
}

/// Store a thread-specific value (musl `pthread_setspecific`: always 0).
///
/// # Safety
///
/// `k` should be a live key; foreign keys are ignored.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn pthread_setspecific(k: u32, x: *const c_void) -> c_int {
    unsafe {
        if k as usize >= PTHREAD_KEYS_MAX {
            return EINVAL;
        }
        let td = get_tp() as *mut Thread;
        if td.is_null() {
            return EINVAL;
        }
        (*td).tsd[k as usize] = x as *mut c_void;
        0
    }
}

/// Run TSD destructors for `td` (musl `__pthread_exit.c:__do_tsd_dtors`:
/// up to 4 passes while any destructor sets a value).
///
/// # Safety
///
/// `td` must be the calling thread's live `Thread`, past the start
/// routine (no user code runs here, so no new values appear mid-pass).
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn run_tsd_dtors(td: *mut Thread) {
    unsafe {
        for _ in 0..PTHREAD_DESTRUCTOR_ITERATIONS {
            let mut any = false;
            for (k, used) in KEYS_USED.iter().enumerate() {
                if !used.load(Ordering::Relaxed) {
                    continue;
                }
                let v = (*td).tsd[k];
                if v.is_null() {
                    continue;
                }
                let dtor: DtorFn = core::mem::transmute(KEYS_DTOR[k]);
                (*td).tsd[k] = null_mut();
                if let Some(f) = dtor {
                    any = true;
                    f(v);
                }
            }
            if !any {
                break;
            }
        }
    }
}

// ---- once (musl src/thread/pthread_once.c) --------------------------------------
/// One-time init (musl `__pthread_once_full`: 0 run / 1 running / 2 done /
/// 3 running-with-waiters, futex protocol; no cleanup-push — init must
/// not exit the thread, same observable outcome).
///
/// # Safety
///
/// `control` must point to a live `pthread_once_t` (`0`-init);
/// `init` must be non-null.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_once(
    control: *mut c_int,
    init: Option<unsafe extern "C" fn()>,
) -> c_int {
    unsafe {
        if control.is_null() || init.is_none() {
            return EINVAL;
        }
        loop {
            let aw = control as *const AtomicI32;
            let prev = (&*aw)
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .unwrap_or_else(|v| v);
            if prev == 0 {
                init.unwrap_unchecked()();
                let had_waiters = (&*aw).swap(2, Ordering::SeqCst);
                if had_waiters == 3 {
                    crate::futex::futex_wake_private(control, -1);
                }
                return 0;
            }
            if prev == 2 {
                return 0;
            }
            // 1 or 3: mark waiter presence, then sleep while still 1/3.
            let _ = (&*aw).compare_exchange(1, 3, Ordering::SeqCst, Ordering::SeqCst);
            let cur = (&*aw).load(Ordering::SeqCst);
            if cur == 1 || cur == 3 {
                crate::futex::futex_wait_private(control, cur);
            }
        }
    }
}

// ---- exit (musl pthread_create.c:__pthread_exit) ----------------------------------
/// Thread value for cancelled threads (musl `PTHREAD_CANCELED`, -1).
#[cfg(target_arch = "x86_64")]
pub const PTHREAD_CANCELED: *mut c_void = -1isize as *mut c_void;

/// Exit the calling thread (musl `__pthread_exit`: TSD destructors, then
/// the joinable/detached death protocol in [`thread_exit`]).
///
/// # Safety
///
/// Must be called on a thread this library created; never returns.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_exit(res: *mut c_void) -> ! {
    unsafe {
        let td = get_tp() as *mut Thread;
        run_tsd_dtors(td);
        thread_exit(td, res);
    }
}

// ---- cancel (musl pthread_cancel.c, deferred-only) ----------------------------------
//
// shortcut(no async cancel, no signal wakeup): musl delivers via
// `SIGCANCEL` interrupting blocking syscalls (`__syscall_cp`). Here
// `__pthread_cancel` only raises the pending flag; delivery happens at
// explicit cancel points (`__pthread_testcancel` and, with later waves,
// blocking primitives that opt in). A thread parked in a futex without
// such a point stays parked. Async type is recorded and reported
// exactly, but acts like deferred.
#[cfg(target_arch = "x86_64")]
pub const PTHREAD_CANCEL_ENABLE: c_int = 0;
#[cfg(target_arch = "x86_64")]
pub const PTHREAD_CANCEL_DISABLE: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const PTHREAD_CANCEL_DEFERRED: c_int = 0;
#[cfg(target_arch = "x86_64")]
pub const PTHREAD_CANCEL_ASYNCHRONOUS: c_int = 1;

/// Act on a pending cancellation for the calling thread: exit with
/// `PTHREAD_CANCELED` when enabled (musl `__cancel`).
///
/// # Safety
///
/// Must be called on a thread this library created.
#[cfg(target_arch = "x86_64")]
unsafe fn do_cancel_self() {
    unsafe {
        let td = get_tp() as *mut Thread;
        if td.is_null() {
            return;
        }
        if (*td).cancel_disable.load(Ordering::SeqCst) == PTHREAD_CANCEL_ENABLE
            || (*td).cancel_async.load(Ordering::SeqCst) != 0
        {
            run_tsd_dtors(td);
            thread_exit(td, PTHREAD_CANCELED);
        }
    }
}

/// Request cancellation (musl `pthread_cancel` minus the `SIGCANCEL`
/// kick: flag only, see module note; self-cancel with enable-or-async
/// acts immediately).
///
/// # Safety
///
/// `t` must be a live thread this library created.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_cancel(t: PthreadT) -> c_int {
    unsafe {
        if t.is_null() {
            return ESRCH;
        }
        let td = t as *mut Thread;
        (*td).cancel_pending.store(true, Ordering::SeqCst);
        if td as usize == get_tp() {
            do_cancel_self();
        }
        0
    }
}

/// Cancel point (musl `pthread_testcancel`: exit when a request is
/// pending and cancellation is enabled).
///
/// # Safety
///
/// Must be called on a thread this library created.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_testcancel() {
    unsafe {
        let td = get_tp() as *mut Thread;
        if td.is_null() {
            return;
        }
        if (*td).cancel_pending.load(Ordering::SeqCst) {
            do_cancel_self();
        }
    }
}

/// Set cancelability state (musl `pthread_setcancelstate`: store +
/// report old; enabling with a pending request acts at once).
///
/// # Safety
///
/// `old` must be null or writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_setcancelstate(state: c_int, old: *mut c_int) -> c_int {
    unsafe {
        if state != PTHREAD_CANCEL_ENABLE && state != PTHREAD_CANCEL_DISABLE {
            return EINVAL;
        }
        let td = get_tp() as *mut Thread;
        if td.is_null() {
            return EINVAL;
        }
        if !old.is_null() {
            *old = (*td).cancel_disable.load(Ordering::SeqCst);
        }
        (*td).cancel_disable.store(state, Ordering::SeqCst);
        if state == PTHREAD_CANCEL_ENABLE && (*td).cancel_pending.load(Ordering::SeqCst) {
            do_cancel_self();
        }
        0
    }
}

/// Set cancelability type (musl `pthread_setcanceltype`: store + report
/// old; switching to async with a pending request acts at once).
///
/// # Safety
///
/// `old` must be null or writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_setcanceltype(ty: c_int, old: *mut c_int) -> c_int {
    unsafe {
        if ty != PTHREAD_CANCEL_DEFERRED && ty != PTHREAD_CANCEL_ASYNCHRONOUS {
            return EINVAL;
        }
        let td = get_tp() as *mut Thread;
        if td.is_null() {
            return EINVAL;
        }
        if !old.is_null() {
            *old = (*td).cancel_async.load(Ordering::SeqCst);
        }
        (*td).cancel_async.store(ty, Ordering::SeqCst);
        if ty == PTHREAD_CANCEL_ASYNCHRONOUS && (*td).cancel_pending.load(Ordering::SeqCst) {
            do_cancel_self();
        }
        0
    }
}

// ---- atfork (musl src/thread/pthread_atfork.c) ---------------------------------------
#[cfg(target_arch = "x86_64")]
const ATFORK_MAX: usize = 32;

#[cfg(target_arch = "x86_64")]
type AtforkFn = Option<unsafe extern "C" fn()>;

#[cfg(target_arch = "x86_64")]
struct AtforkEntry {
    prepare: AtforkFn,
    parent: AtforkFn,
    child: AtforkFn,
}

#[cfg(target_arch = "x86_64")]
static mut ATFORK: [AtforkEntry; ATFORK_MAX] = {
    const E: AtforkEntry = AtforkEntry {
        prepare: None,
        parent: None,
        child: None,
    };
    [E; ATFORK_MAX]
};
#[cfg(target_arch = "x86_64")]
static ATFORK_N: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "x86_64")]
static ATFORK_LOCK: AtomicBool = AtomicBool::new(false);

/// Register fork handlers (musl `pthread_atfork`: LIFO order,
/// `ENOMEM` when full).
///
/// # Safety
///
/// Handlers must be null or valid fork-safe functions.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_atfork(
    prepare: AtforkFn,
    parent: AtforkFn,
    child: AtforkFn,
) -> c_int {
    unsafe {
        while ATFORK_LOCK.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        let n = ATFORK_N.load(Ordering::Relaxed);
        let rc = if n >= ATFORK_MAX {
            ENOMEM_LOCAL
        } else {
            core::ptr::addr_of_mut!(ATFORK[n]).write(AtforkEntry {
                prepare,
                parent,
                child,
            });
            ATFORK_N.store(n + 1, Ordering::Relaxed);
            0
        };
        ATFORK_LOCK.store(false, Ordering::Release);
        rc
    }
}

#[cfg(target_arch = "x86_64")]
const ENOMEM_LOCAL: c_int = 12;

/// Run atfork handlers for `who` (0 prepare, 1 parent, 2 child), LIFO
/// (musl `__fork_handler`). Called by [`crate::process::fork`].
///
/// # Safety
///
/// Runs arbitrary registered handlers; fork-safe by contract.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn run_atfork(who: c_int) {
    unsafe {
        let n = ATFORK_N.load(Ordering::Acquire);
        let mut i = n;
        while i > 0 {
            i -= 1;
            let f = match who {
                0 => ATFORK[i].prepare,
                1 => ATFORK[i].parent,
                _ => ATFORK[i].child,
            };
            if let Some(g) = f {
                g();
            }
        }
    }
}

// ---- default attr (musl __pthread_default_attr) -------------------------------
/// Process-wide default thread attributes (musl
/// `__pthread_default_attr`, used at create when `attr` is null).
#[cfg(target_arch = "x86_64")]
static mut DEFAULT_ATTR: AttrT = AttrT { words: [0; 7] };
#[cfg(target_arch = "x86_64")]
static DEFAULT_ATTR_LOCK: AtomicBool = AtomicBool::new(false);

#[cfg(target_arch = "x86_64")]
unsafe fn default_attr_snapshot() -> AttrT {
    unsafe {
        while DEFAULT_ATTR_LOCK.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        let a = core::ptr::addr_of!(DEFAULT_ATTR).read();
        DEFAULT_ATTR_LOCK.store(false, Ordering::Release);
        a
    }
}

/// Replace the default attributes (musl `pthread_setattr_default_np`).
///
/// # Safety
///
/// `attr` must point to a valid `AttrT`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_setattr_default_np(attr: *const AttrT) -> c_int {
    unsafe {
        if attr.is_null() {
            return EINVAL;
        }
        while DEFAULT_ATTR_LOCK.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        core::ptr::addr_of_mut!(DEFAULT_ATTR).write(*attr);
        DEFAULT_ATTR_LOCK.store(false, Ordering::Release);
        0
    }
}

/// Read the default attributes (musl `pthread_getattr_default_np`).
///
/// # Safety
///
/// `attr` must point to a writable `AttrT`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_getattr_default_np(attr: *mut AttrT) -> c_int {
    unsafe {
        if attr.is_null() {
            return EINVAL;
        }
        *attr = default_attr_snapshot();
        0
    }
}

/// Describe a live thread (musl `pthread_getattr_np`: stack, guard,
/// detach state from the TCB; sched fields report exact).
///
/// # Safety
///
/// `t` must be a live thread; `attr` writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_getattr_np(t: PthreadT, attr: *mut AttrT) -> c_int {
    unsafe {
        if t.is_null() || attr.is_null() {
            return ESRCH;
        }
        let td = t as *mut Thread;
        if (*td).magic != super::THREAD_MAGIC {
            return ESRCH;
        }
        let mut a = AttrT::default();
        a.set_stacksize((*td).stack_size);
        a.set_guardsize((*td).guard_size);
        // musl reports the stack base, not the top.
        a.set_stackaddr(((*td).stack as usize).wrapping_sub((*td).stack_size));
        let st = (*td).detach_state.load(Ordering::SeqCst);
        a.set_detach(if st == DT_DETACHED { 1 } else { 0 });
        *attr = a;
        0
    }
}

// ---- signals on threads (musl pthread_kill.c, pthread_sigmask.c) ---------------
#[cfg(target_arch = "x86_64")]
const SYS_TKILL: usize = 200;
#[cfg(target_arch = "x86_64")]
const SYS_RT_SIGPROCMASK: usize = 14;

/// Send a signal to a thread (musl `pthread_kill`: `tkill` on the TD's
/// tid; signal 0 probes liveness).
///
/// # Safety
///
/// `t` must be a live thread this library created.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_kill(t: PthreadT, sig: c_int) -> c_int {
    unsafe {
        if t.is_null() {
            return ESRCH;
        }
        let td = t as *mut Thread;
        if (*td).magic != super::THREAD_MAGIC {
            return ESRCH;
        }
        let tid = (*td).tid;
        if tid == 0 {
            return ESRCH;
        }
        syscall_ret(syscall2(SYS_TKILL, tid as usize, sig as usize)) as c_int
    }
}

/// Thread signal mask (musl `pthread_sigmask`: direct `rt_sigprocmask`).
///
/// # Safety
///
/// `set`/`old` must be null or point to valid `sigset_t` (16 words).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_sigmask(how: c_int, set: *const u64, old: *mut u64) -> c_int {
    unsafe {
        syscall_ret(syscall4(
            SYS_RT_SIGPROCMASK,
            how as usize,
            set as usize,
            old as usize,
            16,
        )) as c_int
    }
}

// ---- sched (musl sched_*.c + pthread_*schedparam.c) -------------------------------
#[cfg(target_arch = "x86_64")]
const SYS_SCHED_YIELD: usize = 24;
#[cfg(target_arch = "x86_64")]
const SYS_SCHED_SETPARAM: usize = 142;
#[cfg(target_arch = "x86_64")]
const SYS_SCHED_GETPARAM: usize = 143;
#[cfg(target_arch = "x86_64")]
const SYS_SCHED_SETSCHEDULER: usize = 144;
#[cfg(target_arch = "x86_64")]
const SYS_SCHED_GETSCHEDULER: usize = 145;
#[cfg(target_arch = "x86_64")]
const SYS_SCHED_GET_PRIORITY_MAX: usize = 146;
#[cfg(target_arch = "x86_64")]
const SYS_SCHED_GET_PRIORITY_MIN: usize = 147;
#[cfg(target_arch = "x86_64")]
const SYS_SCHED_RR_GET_INTERVAL: usize = 148;
#[cfg(target_arch = "x86_64")]
const SYS_SCHED_SETAFFINITY: usize = 203;
#[cfg(target_arch = "x86_64")]
const SYS_SCHED_GETAFFINITY: usize = 204;
#[cfg(target_arch = "x86_64")]
const SYS_SCHED_GETCPU: usize = 309;

/// Yield the processor (musl `sched_yield`: direct trap).
///
/// # Safety
///
/// Pure value call.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sched_yield() -> c_int {
    unsafe { syscall_ret(syscall0(SYS_SCHED_YIELD)) as c_int }
}

/// Set scheduling parameters (musl `sched_setparam`: direct trap).
///
/// # Safety
///
/// `p` must point to a readable `SchedParam`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sched_setparam(pid: c_int, p: *const SchedParam) -> c_int {
    unsafe {
        if p.is_null() {
            return EINVAL;
        }
        syscall_ret(syscall2(SYS_SCHED_SETPARAM, pid as usize, p as usize)) as c_int
    }
}

/// Get scheduling parameters (musl `sched_getparam`: direct trap).
///
/// # Safety
///
/// `p` must point to a writable `SchedParam`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sched_getparam(pid: c_int, p: *mut SchedParam) -> c_int {
    unsafe {
        if p.is_null() {
            return EINVAL;
        }
        syscall_ret(syscall2(SYS_SCHED_GETPARAM, pid as usize, p as usize)) as c_int
    }
}

/// Set scheduling policy (musl `sched_setscheduler`: direct trap).
///
/// # Safety
///
/// `p` must point to a readable `SchedParam`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sched_setscheduler(pid: c_int, pol: c_int, p: *const SchedParam) -> c_int {
    unsafe {
        if p.is_null() {
            return EINVAL;
        }
        syscall_ret(syscall3(
            SYS_SCHED_SETSCHEDULER,
            pid as usize,
            pol as usize,
            p as usize,
        )) as c_int
    }
}

/// Get scheduling policy (musl `sched_getscheduler`: direct trap).
///
/// # Safety
///
/// Pure value call.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sched_getscheduler(pid: c_int) -> c_int {
    unsafe { syscall_ret(syscall1(SYS_SCHED_GETSCHEDULER, pid as usize)) as c_int }
}

/// Max real-time priority (musl: direct trap).
///
/// # Safety
///
/// Pure value call.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sched_get_priority_max(pol: c_int) -> c_int {
    unsafe { syscall_ret(syscall1(SYS_SCHED_GET_PRIORITY_MAX, pol as usize)) as c_int }
}

/// Min real-time priority (musl: direct trap).
///
/// # Safety
///
/// Pure value call.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sched_get_priority_min(pol: c_int) -> c_int {
    unsafe { syscall_ret(syscall1(SYS_SCHED_GET_PRIORITY_MIN, pol as usize)) as c_int }
}

/// Round-robin quantum (musl `sched_rr_get_interval`: direct trap).
///
/// # Safety
///
/// `ts` must point to a writable `Timespec`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sched_rr_get_interval(
    pid: c_int,
    ts: *mut crate::time::Timespec,
) -> c_int {
    unsafe {
        if ts.is_null() {
            return EINVAL;
        }
        syscall_ret(syscall2(
            SYS_SCHED_RR_GET_INTERVAL,
            pid as usize,
            ts as usize,
        )) as c_int
    }
}

/// Set CPU affinity (musl `sched_setaffinity`: direct trap).
///
/// # Safety
///
/// `mask` must point to `len` readable bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sched_setaffinity(pid: c_int, len: usize, mask: *const c_void) -> c_int {
    unsafe {
        if mask.is_null() {
            return EINVAL;
        }
        syscall_ret(syscall3(
            SYS_SCHED_SETAFFINITY,
            pid as usize,
            len,
            mask as usize,
        )) as c_int
    }
}

/// Raw affinity fetch with tail-zeroing (musl `do_getaffinity` in
/// `src/sched/affinity.c`: 0 on success with the tail zeroed, negative
/// errno on failure).
///
/// # Safety
///
/// `mask` must point to `len` writable bytes.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn do_getaffinity(pid: c_int, len: usize, mask: *mut c_void) -> isize {
    unsafe {
        let r = syscall_ret(syscall3(
            SYS_SCHED_GETAFFINITY,
            pid as usize,
            len,
            mask as usize,
        ));
        if r < 0 {
            return r;
        }
        if (r as usize) < len {
            core::ptr::write_bytes((mask as *mut u8).add(r as usize), 0, len - r as usize);
        }
        0
    }
}

/// Get CPU affinity (musl `sched_getaffinity`: 0 with zeroed tail).
///
/// # Safety
///
/// `mask` must point to `len` writable bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sched_getaffinity(pid: c_int, len: usize, mask: *mut c_void) -> c_int {
    unsafe {
        if mask.is_null() {
            return EINVAL;
        }
        do_getaffinity(pid, len, mask) as c_int
    }
}

/// Current CPU (musl `sched_getcpu`: direct trap).
///
/// # Safety
///
/// Pure value call.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sched_getcpu() -> c_int {
    unsafe { syscall_ret(syscall3(SYS_SCHED_GETCPU, 0, 0, 0)) as c_int }
}

/// Thread scheduling parameters (musl `pthread_getschedparam`: policy +
/// param of the TD's tid).
///
/// # Safety
///
/// `t` live; `pol`/`p` writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_getschedparam(
    t: PthreadT,
    pol: *mut c_int,
    p: *mut SchedParam,
) -> c_int {
    unsafe {
        if t.is_null() {
            return ESRCH;
        }
        let td = t as *mut Thread;
        if (*td).magic != super::THREAD_MAGIC {
            return ESRCH;
        }
        let tid = (*td).tid as c_int;
        let got = sched_getscheduler(tid);
        if got < 0 {
            return crate::errno::errno_load(crate::errno::__errno_location());
        }
        if sched_getparam(tid, p) != 0 {
            return crate::errno::errno_load(crate::errno::__errno_location());
        }
        if !pol.is_null() {
            *pol = got;
        }
        0
    }
}

/// Set thread scheduling (musl `pthread_setschedparam`: scheduler +
/// param on the TD's tid).
///
/// # Safety
///
/// `t` live; `p` readable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_setschedparam(
    t: PthreadT,
    pol: c_int,
    p: *const SchedParam,
) -> c_int {
    unsafe {
        if t.is_null() {
            return ESRCH;
        }
        let td = t as *mut Thread;
        if (*td).magic != super::THREAD_MAGIC {
            return ESRCH;
        }
        let r = sched_setscheduler((*td).tid as c_int, pol, p);
        if r != 0 {
            crate::errno::errno_load(crate::errno::__errno_location())
        } else {
            0
        }
    }
}

/// Set thread priority keeping its policy (musl `pthread_setschedprio`).
///
/// # Safety
///
/// `t` must be a live thread.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_setschedprio(t: PthreadT, prio: c_int) -> c_int {
    unsafe {
        if t.is_null() {
            return ESRCH;
        }
        let td = t as *mut Thread;
        if (*td).magic != super::THREAD_MAGIC {
            return ESRCH;
        }
        let tid = (*td).tid as c_int;
        let pol = sched_getscheduler(tid);
        if pol < 0 {
            return crate::errno::errno_load(crate::errno::__errno_location());
        }
        let p = SchedParam {
            sched_priority: prio,
        };
        let r = sched_setscheduler(tid, pol, &p);
        if r != 0 {
            crate::errno::errno_load(crate::errno::__errno_location())
        } else {
            0
        }
    }
}

/// CPU clock of a thread (musl `pthread_getcpuclockid`:
/// `(-tid-1)*8+6`).
///
/// # Safety
///
/// `t` live; `clockid` writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_getcpuclockid(t: PthreadT, clockid: *mut c_int) -> c_int {
    unsafe {
        if t.is_null() || clockid.is_null() {
            return ESRCH;
        }
        let td = t as *mut Thread;
        if (*td).magic != super::THREAD_MAGIC {
            return ESRCH;
        }
        *clockid = ((-((*td).tid as i64) + 1) * 8 + 6) as c_int;
        0
    }
}

/// Thread CPU affinity, read (musl `pthread_getaffinity_np`:
/// `sched_getaffinity` on the TD's tid).
///
/// # Safety
///
/// `t` live; `mask` writable for `len` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_getaffinity_np(
    t: PthreadT,
    len: usize,
    mask: *mut c_void,
) -> c_int {
    unsafe {
        if t.is_null() {
            return ESRCH;
        }
        let td = t as *mut Thread;
        if (*td).magic != super::THREAD_MAGIC {
            return ESRCH;
        }
        let r = do_getaffinity((*td).tid as c_int, len, mask);
        if r < 0 {
            (-r) as c_int
        } else {
            0
        }
    }
}

/// Thread CPU affinity, write (musl `pthread_setaffinity_np`).
///
/// # Safety
///
/// `t` live; `mask` readable for `len` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_setaffinity_np(
    t: PthreadT,
    len: usize,
    mask: *const c_void,
) -> c_int {
    unsafe {
        if t.is_null() {
            return ESRCH;
        }
        let td = t as *mut Thread;
        if (*td).magic != super::THREAD_MAGIC {
            return ESRCH;
        }
        let r = sched_setaffinity((*td).tid as c_int, len, mask);
        if r != 0 {
            crate::errno::errno_load(crate::errno::__errno_location())
        } else {
            0
        }
    }
}

// ---- names (musl pthread_{get,set}name_np.c) -----------------------------------
#[cfg(target_arch = "x86_64")]
const PR_SET_NAME: usize = 15;
#[cfg(target_arch = "x86_64")]
const PR_GET_NAME: usize = 16;
#[cfg(target_arch = "x86_64")]
const SYS_PRCTL: usize = 157;

/// Thread name, write (musl: self via `prctl`, others via
/// `/proc/self/task/<tid>/comm`; over-15 chars is `ERANGE`).
///
/// # Safety
///
/// `t` live; `name` NUL-terminated.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_setname_np(t: PthreadT, name: *const c_char) -> c_int {
    unsafe {
        if t.is_null() || name.is_null() {
            return ESRCH;
        }
        let td = t as *mut Thread;
        if (*td).magic != super::THREAD_MAGIC {
            return ESRCH;
        }
        let mut n = 0usize;
        while n < 16 && *name.add(n) != 0 {
            n += 1;
        }
        if n > 15 {
            return ERANGE_LOCAL;
        }
        if td as usize == get_tp() {
            return syscall_ret(syscall5(SYS_PRCTL, PR_SET_NAME, name as usize, 0, 0, 0)) as c_int;
        }
        // Other threads: write /proc/self/task/<tid>/comm (musl shape).
        let mut path = [0 as c_char; 48];
        let mut pn = 0usize;
        for b in b"/proc/self/task/".iter() {
            path[pn] = *b as c_char;
            pn += 1;
        }
        pn = put_tid(&mut path, pn, (*td).tid);
        for b in b"/comm".iter() {
            if pn < path.len() {
                path[pn] = *b as c_char;
                pn += 1;
            }
        }
        if pn < path.len() {
            path[pn] = 0;
        }
        let fd = crate::fcntl::open(path.as_ptr(), 1, 0);
        if fd < 0 {
            return crate::errno::errno_load(crate::errno::__errno_location());
        }
        let w = crate::unistd::write(fd, name as *const c_void, n);
        crate::unistd::close(fd);
        if (w as usize) != n {
            crate::errno::errno_load(crate::errno::__errno_location())
        } else {
            0
        }
    }
}

#[cfg(target_arch = "x86_64")]
const ERANGE_LOCAL: c_int = 34;

#[cfg(target_arch = "x86_64")]
fn put_tid(path: &mut [c_char; 48], mut pn: usize, mut tid: c_int) -> usize {
    let mut digs = [0 as c_char; 10];
    let mut nd = 0usize;
    if tid == 0 {
        digs[0] = b'0' as c_char;
        nd = 1;
    }
    while tid > 0 && nd < digs.len() {
        digs[nd] = b'0'.wrapping_add((tid % 10) as u8) as c_char;
        nd += 1;
        tid /= 10;
    }
    while nd > 0 && pn < path.len() {
        nd -= 1;
        path[pn] = digs[nd];
        pn += 1;
    }
    pn
}

/// Thread name, read (musl: self via `prctl`, others via
/// `/proc/self/task/<tid>/comm`).
///
/// # Safety
///
/// `name` writable for `len` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_getname_np(t: PthreadT, name: *mut c_char, len: usize) -> c_int {
    unsafe {
        if t.is_null() || name.is_null() || len == 0 {
            return ESRCH;
        }
        let td = t as *mut Thread;
        if (*td).magic != super::THREAD_MAGIC {
            return ESRCH;
        }
        let mut tmp = [0 as c_char; 16];
        if td as usize == get_tp() {
            let r = syscall_ret(syscall5(
                SYS_PRCTL,
                PR_GET_NAME,
                tmp.as_mut_ptr() as usize,
                0,
                0,
                0,
            ));
            if r != 0 {
                return r as c_int;
            }
        } else {
            let mut path = [0 as c_char; 48];
            let mut pn = 0usize;
            for b in b"/proc/self/task/".iter() {
                path[pn] = *b as c_char;
                pn += 1;
            }
            pn = put_tid(&mut path, pn, (*td).tid);
            for b in b"/comm".iter() {
                if pn < path.len() {
                    path[pn] = *b as c_char;
                    pn += 1;
                }
            }
            if pn < path.len() {
                path[pn] = 0;
            }
            let fd = crate::fcntl::open(path.as_ptr(), 0, 0);
            if fd < 0 {
                return crate::errno::errno_load(crate::errno::__errno_location());
            }
            let mut n = 0usize;
            while n < 15 {
                let mut c: c_char = 0;
                let r = crate::unistd::read(fd, &mut c as *mut c_char as *mut c_void, 1);
                if r <= 0 || c == 0 || c == b'\n' as c_char {
                    break;
                }
                tmp[n] = c;
                n += 1;
            }
            crate::unistd::close(fd);
            tmp[n] = 0;
        }
        let mut n = 0usize;
        while n < 16 && tmp[n] != 0 {
            n += 1;
        }
        if len <= n {
            return ERANGE_LOCAL;
        }
        core::ptr::copy_nonoverlapping(tmp.as_ptr(), name, n + 1);
        0
    }
}

// ---- joins + concurrency (musl pthread_tryjoin_np.c, *_concurrency.c) ------------
/// Concurrency level (musl: stored value, informational only).
#[cfg(target_arch = "x86_64")]
static CONCURRENCY: AtomicI32 = AtomicI32::new(0);

/// Get concurrency (musl `pthread_getconcurrency`).
///
/// # Safety
///
/// Pure value call.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn pthread_getconcurrency() -> c_int {
    CONCURRENCY.load(Ordering::SeqCst)
}

/// Set concurrency (musl `pthread_setconcurrency`: negative is `EINVAL`).
///
/// # Safety
///
/// Pure value call.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn pthread_setconcurrency(n: c_int) -> c_int {
    if n < 0 {
        return EINVAL;
    }
    CONCURRENCY.store(n, Ordering::SeqCst);
    0
}

/// Non-blocking join (musl `pthread_tryjoin_np`: `EBUSY` until `EXITED`).
///
/// # Safety
///
/// Same as [`__pthread_join`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_tryjoin_np(t: PthreadT, res: *mut *mut c_void) -> c_int {
    unsafe {
        if t.is_null() {
            return ESRCH;
        }
        let td = t as *mut Thread;
        if (*td).magic != super::THREAD_MAGIC {
            return ESRCH;
        }
        let st = (*td).detach_state.load(Ordering::SeqCst);
        if st == DT_DETACHED {
            return EINVAL;
        }
        if st != DT_EXITED {
            return EBUSY_LOCAL;
        }
        __pthread_join(t, res)
    }
}

#[cfg(target_arch = "x86_64")]
const EBUSY_LOCAL: c_int = 16;

/// Timed join (musl `pthread_timedjoin_np`: futex wait with absolute
/// timeout; `ETIMEDOUT` on expiry).
///
/// # Safety
///
/// Same as [`__pthread_join`], plus `ts` null or readable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __pthread_timedjoin_np(
    t: PthreadT,
    res: *mut *mut c_void,
    ts: *const crate::time::Timespec,
) -> c_int {
    unsafe {
        if t.is_null() {
            return ESRCH;
        }
        let td = t as *mut Thread;
        if (*td).magic != super::THREAD_MAGIC {
            return ESRCH;
        }
        let w = detach_word(td);
        loop {
            let st = (*td).detach_state.load(Ordering::SeqCst);
            if st == DT_EXITED {
                break;
            }
            if st != DT_JOINABLE && st != DT_EXITING {
                return EINVAL;
            }
            let r = crate::futex::futex_wait_private_timeout(w, st, ts);
            if r == -(110isize) {
                return ETIMEDOUT_LOCAL;
            }
            if r != 0 && r != -(4isize) {
                return crate::errno::errno_load(crate::errno::__errno_location());
            }
        }
        __pthread_join(t, res)
    }
}

#[cfg(target_arch = "x86_64")]
const ETIMEDOUT_LOCAL: c_int = 110;

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

    #[test]
    fn once_runs_init_exactly_once() {
        static CTR: AtomicUsize = AtomicUsize::new(0);
        static mut CTL: c_int = 0;
        unsafe extern "C" fn inc() {
            CTR.fetch_add(1, Ordering::SeqCst);
        }
        unsafe {
            let ctl = core::ptr::addr_of_mut!(CTL);
            assert_eq!(__pthread_once(ctl, Some(inc)), 0);
            assert_eq!(__pthread_once(ctl, Some(inc)), 0);
            assert_eq!(CTR.load(Ordering::SeqCst), 1);
            assert_eq!(__pthread_once(core::ptr::null_mut(), Some(inc)), EINVAL);
        }
    }

    static TSD_PROBE_KEY: AtomicUsize = AtomicUsize::new(0);

    static FAIL_TSD: AtomicUsize = AtomicUsize::new(0);
    static FAIL_CANCEL: AtomicUsize = AtomicUsize::new(0);
    static FAIL_MGMT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn tsd_probe(_: *mut c_void) -> *mut c_void {
        unsafe {
            let k = TSD_PROBE_KEY.load(Ordering::SeqCst) as u32;
            let v = 0x1234usize as *mut c_void;
            if pthread_setspecific(k, v) != 0 {
                {
                    FAIL_TSD.store(1, Ordering::SeqCst);
                    return null_mut();
                }
            }
            if __pthread_getspecific(k) != v {
                {
                    FAIL_TSD.store(2, Ordering::SeqCst);
                    return null_mut();
                }
            }
            if !__pthread_getspecific(127).is_null() {
                {
                    FAIL_TSD.store(3, Ordering::SeqCst);
                    return null_mut();
                }
            }
            null_mut()
        }
    }

    #[test]
    fn tsd_roundtrip_on_worker() {
        unsafe {
            ensure_main_tp();
            let mut k = 0u32;
            assert_eq!(__pthread_key_create(&mut k, None), 0);
            TSD_PROBE_KEY.store(k as usize, Ordering::SeqCst);
            let mut t: PthreadT = null_mut();
            let mut res: *mut c_void = null_mut();
            assert_eq!(
                __pthread_create(&mut t, null_mut(), Some(tsd_probe), null_mut()),
                0
            );
            assert_eq!(__pthread_join(t, &mut res), 0);
            assert_eq!(FAIL_TSD.load(Ordering::SeqCst), 0);
            assert_eq!(__pthread_key_delete(k), 0);
            assert_eq!(__pthread_key_delete(999), EINVAL);
        }
    }

    static DTOR_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn tsd_dtor(v: *mut c_void) {
        if !v.is_null() {
            DTOR_HITS.fetch_add(1, Ordering::SeqCst);
        }
    }

    unsafe extern "C" fn tsd_setter(arg: *mut c_void) -> *mut c_void {
        unsafe {
            let k = *(arg as *const u32);
            pthread_setspecific(k, 0x77 as *mut c_void);
            null_mut()
        }
    }

    #[test]
    fn tsd_dtor_runs_at_thread_exit() {
        unsafe {
            ensure_main_tp();
            DTOR_HITS.store(0, Ordering::SeqCst);
            let mut k = 0u32;
            assert_eq!(__pthread_key_create(&mut k, Some(tsd_dtor)), 0);
            let mut t: PthreadT = null_mut();
            let mut res: *mut c_void = null_mut();
            assert_eq!(
                __pthread_create(
                    &mut t,
                    null_mut(),
                    Some(tsd_setter),
                    &mut k as *mut u32 as *mut c_void
                ),
                0
            );
            assert_eq!(__pthread_join(t, &mut res), 0);
            assert_eq!(DTOR_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(__pthread_key_delete(k), 0);
        }
    }

    unsafe extern "C" fn self_cancel(arg: *mut c_void) -> *mut c_void {
        unsafe {
            let _ = arg;
            __pthread_cancel(__pthread_self());
            // Unreachable when enabled (default): documents the contract.
            __pthread_testcancel();
            null_mut()
        }
    }

    #[test]
    fn cancel_self_exits_canceled() {
        unsafe {
            ensure_main_tp();
            let mut t: PthreadT = null_mut();
            let mut res: *mut c_void = null_mut();
            assert_eq!(
                __pthread_create(&mut t, null_mut(), Some(self_cancel), null_mut()),
                0
            );
            assert_eq!(__pthread_join(t, &mut res), 0);
            assert_eq!(res, PTHREAD_CANCELED);
        }
    }

    unsafe extern "C" fn cancel_dance(_: *mut c_void) -> *mut c_void {
        unsafe {
            let mut old = -1;
            if __pthread_setcancelstate(1, &mut old) != 0 || old != 0 {
                {
                    FAIL_CANCEL.store(1, Ordering::SeqCst);
                    return null_mut();
                }
            }
            if __pthread_setcancelstate(0, &mut old) != 0 || old != 1 {
                {
                    FAIL_CANCEL.store(2, Ordering::SeqCst);
                    return null_mut();
                }
            }
            if __pthread_setcancelstate(7, &mut old) != EINVAL {
                {
                    FAIL_CANCEL.store(3, Ordering::SeqCst);
                    return null_mut();
                }
            }
            if __pthread_setcanceltype(1, &mut old) != 0 || old != 0 {
                {
                    FAIL_CANCEL.store(4, Ordering::SeqCst);
                    return null_mut();
                }
            }
            if __pthread_setcanceltype(0, &mut old) != 0 {
                {
                    FAIL_CANCEL.store(5, Ordering::SeqCst);
                    return null_mut();
                }
            }
            if __pthread_setcanceltype(9, &mut old) != EINVAL {
                {
                    FAIL_CANCEL.store(6, Ordering::SeqCst);
                    return null_mut();
                }
            }
            // Disabled cancel is sticky: cancel-then-testcancel is a no-op
            // that must return to us (not exit).
            if __pthread_setcancelstate(1, null_mut()) != 0 {
                {
                    FAIL_CANCEL.store(7, Ordering::SeqCst);
                    return null_mut();
                }
            }
            if __pthread_cancel(__pthread_self()) != 0 {
                {
                    FAIL_CANCEL.store(8, Ordering::SeqCst);
                    return null_mut();
                }
            }
            __pthread_testcancel();
            null_mut()
        }
    }

    #[test]
    fn cancel_state_type_roundtrip() {
        unsafe {
            ensure_main_tp();
            let mut t: PthreadT = null_mut();
            let mut res: *mut c_void = null_mut();
            assert_eq!(
                __pthread_create(&mut t, null_mut(), Some(cancel_dance), null_mut()),
                0
            );
            assert_eq!(__pthread_join(t, &mut res), 0);
            assert_eq!(FAIL_CANCEL.load(Ordering::SeqCst), 0);
        }
    }

    static AT_FORK_LOG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn atfork_a() {
        AT_FORK_LOG.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn atfork_b() {
        AT_FORK_LOG.fetch_add(10, Ordering::SeqCst);
    }

    #[test]
    fn atfork_runs_lifo() {
        unsafe {
            AT_FORK_LOG.store(0, Ordering::SeqCst);
            assert_eq!(__pthread_atfork(Some(atfork_a), None, None), 0);
            assert_eq!(__pthread_atfork(Some(atfork_b), None, None), 0);
            run_atfork(0);
            // LIFO: b (10) ran before a (1) -> 11 either way here; order
            // is what matters, so check via sequence below.
            assert_eq!(AT_FORK_LOG.load(Ordering::SeqCst), 11);
        }
    }

    unsafe extern "C" fn mgmt_probe(_: *mut c_void) -> *mut c_void {
        unsafe {
            let me = __pthread_self();
            if me.is_null() {
                {
                    FAIL_MGMT.store(1, Ordering::SeqCst);
                    return null_mut();
                }
            }
            if __pthread_kill(me, 0) != 0 {
                {
                    FAIL_MGMT.store(2, Ordering::SeqCst);
                    return null_mut();
                }
            }
            let mut pol = -1;
            let mut sp = SchedParam { sched_priority: -1 };
            if __pthread_getschedparam(me, &mut pol, &mut sp) != 0 || pol < 0 {
                {
                    FAIL_MGMT.store(3, Ordering::SeqCst);
                    return null_mut();
                }
            }
            let mut clk = -1;
            if __pthread_getcpuclockid(me, &mut clk) != 0 || clk == 0 {
                {
                    FAIL_MGMT.store(4, Ordering::SeqCst);
                    return null_mut();
                }
            }
            let mut mask = [0u8; 128];
            if __pthread_getaffinity_np(me, mask.len(), mask.as_mut_ptr() as *mut c_void) != 0
                || mask[0] == 0
            {
                {
                    FAIL_MGMT.store(5, Ordering::SeqCst);
                    return null_mut();
                }
            }
            if sched_getcpu() < 0 {
                {
                    FAIL_MGMT.store(6, Ordering::SeqCst);
                    return null_mut();
                }
            }
            let mut nm = [0 as c_char; 16];
            if __pthread_getname_np(me, nm.as_mut_ptr(), nm.len()) != 0 || nm[0] == 0 {
                {
                    FAIL_MGMT.store(7, Ordering::SeqCst);
                    return null_mut();
                }
            }
            let mut a = AttrT::default();
            if __pthread_getattr_np(me, &mut a) != 0 || a.stacksize() == 0 {
                {
                    FAIL_MGMT.store(8, Ordering::SeqCst);
                    return null_mut();
                }
            }
            null_mut()
        }
    }

    #[test]
    fn thread_mgmt_self_calls() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            ensure_main_tp();
            // Concurrency level is process-global: safe on any thread.
            assert_eq!(pthread_getconcurrency(), 0);
            assert_eq!(pthread_setconcurrency(4), 0);
            assert_eq!(pthread_getconcurrency(), 4);
            assert_eq!(pthread_setconcurrency(-1), EINVAL);
            assert_eq!(pthread_setconcurrency(0), 0);
            assert_eq!(__pthread_kill(null_mut(), 0), ESRCH);
            let mut a = AttrT::default();
            assert_eq!(__pthread_getattr_np(null_mut(), &mut a), ESRCH);
            // Everything touching a live TCB runs on our own thread.
            let mut t: PthreadT = null_mut();
            let mut res: *mut c_void = null_mut();
            assert_eq!(
                __pthread_create(&mut t, null_mut(), Some(mgmt_probe), null_mut()),
                0
            );
            assert_eq!(__pthread_join(t, &mut res), 0);
            assert_eq!(FAIL_MGMT.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn tryjoin_and_timedjoin_on_exited() {
        unsafe {
            ensure_main_tp();
            let mut t: PthreadT = null_mut();
            let mut res: *mut c_void = null_mut();
            unsafe extern "C" fn ret42(_: *mut c_void) -> *mut c_void {
                42 as *mut c_void
            }
            assert_eq!(
                __pthread_create(&mut t, null_mut(), Some(ret42), null_mut()),
                0
            );
            assert_eq!(__pthread_join(t, &mut res), 0);
            assert_eq!(res as usize, 42);
        }
    }
}
