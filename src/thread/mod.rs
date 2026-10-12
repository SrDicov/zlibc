//! Thread creation, joining, and TLS setup (x86_64).
//!
//! Clean-room mirrors of musl `src/thread/pthread_create.c:237-397`
//! (stack/guard sizing, clone flags, detach mapping),
//! `src/thread/x86_64/clone.s` (child discipline),
//! `src/thread/x86_64/__set_thread_area.s` (ARCH_SET_FS),
//! `src/env/__init_tls.c:14-72` (`__init_tp`, `__copy_tls`),
//! `src/thread/pthread_join.c`, `pthread_detach.c`,
//! `pthread_attr_init.c`, `pthread_attr_setdetachstate.c`,
//! `pthread_attr_setstacksize.c`, `pthread_attr_setguardsize.c`,
//! `pthread_attr_setstack.c`, `pthread_attr_get.c`,
//! `pthread_self.c`, `pthread_equal.c`, and
//! `src/internal/pthread_impl.h:18-75` (thread layout, `DT_*`).
//! Layouts re-derived, algorithms reimplemented; no musl code is copied.
//!
//! Layout (pthread_impl.h:18-68): Part 1 (ABI, "Do not change") is reused
//! verbatim as [`crate::abi::PthreadHead`], never redefined; Part 2 is
//! explicitly non-ABI, so [`Thread`] extends the head freely; Part 3 is
//! empty on x86_64 (no `TLS_ABOVE_TP`).
//!
//! Public musl names (`pthread_create`, ...) are weak aliases over the
//! `__pthread_*` impls, emitted only for real links (`not(test)`): the
//! test binary shares its address space with host std, whose threads call
//! `pthread_create` — exporting that name in tests would interpose and
//! corrupt the harness. (musl defines the attr fns directly; the alias
//! here is only name provision with the identical observable contract.)
//!
//! OUT (later waves, each a `shortcut:` at its site): cancel points,
//! `pthread_exit`/`pthread_cancel`, keys/`tsd`, atfork handlers,
//! barriers, robust list, signals around create, global thread list,
//! per-thread `errno` (slot reserved, `errno.rs` still global),
//! user-provided stacks, explicit scheduling.

pub mod create;
pub mod tls;
pub mod unmapself;

use core::ffi::{c_int, c_void};
use core::sync::atomic::AtomicI32;

use crate::abi::PthreadHead;

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MMAP: usize = 9; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MPROTECT: usize = 10; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_MUNMAP: usize = 11; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_EXIT: usize = 60; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_ARCH_PRCTL: usize = 158; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
pub(crate) const SYS_SET_TID_ADDRESS: usize = 218; // TODO: generate from arch bits/syscall.h

/// musl `src/thread/x86_64/__set_thread_area.s:8` (`ARCH_SET_FS`).
#[cfg(target_arch = "x86_64")]
pub(crate) const ARCH_SET_FS: usize = 0x1002;
/// `ARCH_GET_FS` pair (test save/restore only; same `asm/prctl.h` family).
#[cfg(target_arch = "x86_64")]
pub(crate) const ARCH_GET_FS: usize = 0x1003;

// ---- Clone flags (musl include/sched.h:53-67) --------------------------------
// All 10 from musl `src/thread/pthread_create.c:243-245`.
#[cfg(target_arch = "x86_64")]
pub(crate) const CLONE_VM: u32 = 0x0000_0100;
#[cfg(target_arch = "x86_64")]
pub(crate) const CLONE_FS: u32 = 0x0000_0200;
#[cfg(target_arch = "x86_64")]
pub(crate) const CLONE_FILES: u32 = 0x0000_0400;
#[cfg(target_arch = "x86_64")]
pub(crate) const CLONE_SIGHAND: u32 = 0x0000_0800;
#[cfg(target_arch = "x86_64")]
pub(crate) const CLONE_THREAD: u32 = 0x0001_0000;
#[cfg(target_arch = "x86_64")]
pub(crate) const CLONE_SYSVSEM: u32 = 0x0004_0000;
#[cfg(target_arch = "x86_64")]
pub(crate) const CLONE_SETTLS: u32 = 0x0008_0000;
#[cfg(target_arch = "x86_64")]
pub(crate) const CLONE_PARENT_SETTID: u32 = 0x0010_0000;
#[cfg(target_arch = "x86_64")]
pub(crate) const CLONE_CHILD_CLEARTID: u32 = 0x0020_0000;
#[cfg(target_arch = "x86_64")]
pub(crate) const CLONE_DETACHED: u32 = 0x0040_0000;
/// The full musl set above, ORed (== 0x7D0F00).
#[cfg(target_arch = "x86_64")]
pub(crate) const CLONE_FLAGS: u32 = CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_THREAD
    | CLONE_SYSVSEM
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_DETACHED;

// ---- Errnos (musl arch/generic/bits/errno.h) ---------------------------------
pub(crate) const ESRCH: c_int = 3; // errno.h:3
pub(crate) const EAGAIN: c_int = 11; // errno.h:11
pub(crate) const EINVAL: c_int = 22; // errno.h:22
pub(crate) const ENOTSUP: c_int = 95; // errno.h:96 (`ENOTSUP=EOPNOTSUPP`)

// ---- Detach states (musl src/internal/pthread_impl.h:70-75) ------------------
pub(crate) const DT_EXITED: c_int = 0;
pub(crate) const DT_EXITING: c_int = 1;
pub(crate) const DT_JOINABLE: c_int = 2;
pub(crate) const DT_DETACHED: c_int = 3;

// ---- Stack defaults (musl pthread_impl.h:197-198 via default_attr.c:3-4) -----
pub(crate) const DEFAULT_STACKSIZE: usize = 131072;
pub(crate) const DEFAULT_GUARDSIZE: usize = 8192;

/// musl `pthread_create` start routine (`include/pthread.h:80`): takes an
/// argument pointer, returns a result pointer collected by `pthread_join`.
pub type StartFn = Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>;

/// musl `pthread_attr_t` (`include/alltypes.h.in:86`): 14 `int` slots
/// (7 words, 56 bytes on 64-bit). Slot meanings mirror the `_a_*` macros
/// (pthread_impl.h:79-85): words 0/1/2 are stacksize/guardsize/stackaddr
/// (`__s`), `int` slots 6/7/8/9 are detach/sched/policy/prio (`__i`,
/// with `__SU = 2` words per `size_t` on 64-bit).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AttrT {
    words: [u64; 7],
}

impl AttrT {
    fn i(&self, k: usize) -> c_int {
        unsafe { (self as *const AttrT).cast::<c_int>().add(k).read() }
    }

    fn set_i(&mut self, k: usize, v: c_int) {
        unsafe { (self as *mut AttrT).cast::<c_int>().add(k).write(v) }
    }

    pub(crate) fn stacksize(&self) -> usize {
        self.words[0] as usize
    }

    pub(crate) fn set_stacksize(&mut self, v: usize) {
        self.words[0] = v as u64;
    }

    pub(crate) fn guardsize(&self) -> usize {
        self.words[1] as usize
    }

    pub(crate) fn set_guardsize(&mut self, v: usize) {
        self.words[1] = v as u64;
    }

    pub(crate) fn stackaddr(&self) -> usize {
        self.words[2] as usize
    }

    pub(crate) fn set_stackaddr(&mut self, v: usize) {
        self.words[2] = v as u64;
    }

    pub(crate) fn detach(&self) -> c_int {
        self.i(6)
    }

    pub(crate) fn set_detach(&mut self, v: c_int) {
        self.set_i(6, v);
    }

    pub(crate) fn sched(&self) -> c_int {
        self.i(7)
    }

    pub(crate) fn policy(&self) -> c_int {
        self.i(8)
    }

    pub(crate) fn prio(&self) -> c_int {
        self.i(9)
    }
}

/// Working thread struct (x86_64): [`PthreadHead`] (Part 1, ABI-frozen)
/// plus Part 2 (free per pthread_impl.h:34 — every field justified below).
#[repr(C)]
pub struct Thread {
    /// Part 1 head: self pointer, DTV, list links, sysinfo, canary.
    /// Reused, never redefined (ABI-frozen per `crate::abi`).
    pub head: PthreadHead,
    /// Kernel tid. Also the `CLONE_CHILD_CLEARTID` word: the kernel zeroes
    /// it (plus a futex wake) when the thread dies.
    pub tid: c_int,
    /// `DT_*` join/detach protocol; the futex word joiners sleep on.
    pub detach_state: AtomicI32,
    /// Per-thread errno value. Reserved for the TLS upgrade of `errno.rs`,
    /// which still serves one process-global cell (see module docs).
    pub errno_val: c_int,
    /// `mmap` base of this thread's stack mapping (null for the main
    /// thread, which runs on the process stack).
    pub map_base: *mut u8,
    /// `mmap` length; unmapped by the joiner, or by `__unmapself` on
    /// detached-thread death.
    pub map_size: usize,
    /// Initial `rsp` top (the TCB address itself; informational).
    pub stack: *mut u8,
    /// Usable stack bytes below the TCB (`top - base - guard`).
    pub stack_size: usize,
    /// `PROT_NONE` prefix bytes (zero when guards are disabled).
    pub guard_size: usize,
    /// Start-routine return value, stored before `DT_EXITED` so the joiner
    /// (ordered by the `SeqCst` state transition) reads it safely.
    pub result: *mut c_void,
    /// Start routine set by create, run once by the child trampoline.
    pub start: StartFn,
    /// Opaque argument forwarded to `start`.
    pub arg: *mut c_void,
    // Deliberately absent (all OUT, see module docs): cancel state,
    // cancel buffer, tsd/keys, robust list, locale, killlock, timer id,
    // stdio locks, dlerror buffer. Each returns with its owning wave.
}

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
    .hidden __pthread_attr_getinheritsched"
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

#[cfg(test)]
mod tests {
    use super::tls::current_tls_size;
    use super::{AttrT, Thread};

    use core::mem::{offset_of, size_of};

    /// Hand-computed x86_64 layout: head 48, tid+detach 8, errno+pad 8,
    /// then 8 pointer/word fields (64); attr is 7 words (56); TLS block
    /// for zero modules is 16 (DTV head) + 128, already 16-aligned.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn thread_layout_matches_hand_computation() {
        assert_eq!(offset_of!(Thread, head), 0);
        assert_eq!(size_of::<Thread>(), 128);
        assert_eq!(size_of::<AttrT>(), 56);
        assert_eq!(current_tls_size(), 144);
    }
}
