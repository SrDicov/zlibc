//! `posix_spawn` family (musl `src/process/posix_spawn*`, x86_64).
//!
//! Fork+exec spawner plus the file-actions list and spawn-attr
//! objects. Every syscall number re-verified against musl
//! `arch/x86_64/bits/syscall.h.in` (read 0, write 1, close 3,
//! rt_sigaction 13, rt_sigprocmask 14, dup 32, dup2 33, fork 57,
//! exit 60, wait4 61, fcntl 72, chdir 80, fchdir 81, getuid 102,
//! getgid 104, setuid 105, setgid 106, setpgid 109, setsid 112,
//! exit_group 231, openat 257, pipe2 293); flags from musl
//! `include/spawn.h`; `Fdop` layout from `src/process/fdop.h`.
//!
//! Deviations from musl, each load-bearing and documented at its site:
//! plain `fork` instead of musl's `CLONE_VM|CLONE_VFORK` clone (no
//! clone wrapper exists in this crate; a full address-space copy is
//! slower but semantically identical, and the error pipe makes the
//! parent's wait identical); no `pthread_setcancelstate` /
//! `__abort_lock` pairing (neither exists here); scheduler attrs are
//! accepted by `setflags` but ignored at spawn, exactly like musl's
//! `ENOSYS` sched stubs; signal reset probes dispositions with
//! `sigaction` instead of musl's internal handler-set tracker; the
//! parent's saved mask is staged into a private attr copy (musl hands
//! the child a separate args struct).

use core::ffi::{c_char, c_int, c_short, c_void};

use crate::errno::{__errno_location, errno_load};
use crate::signal::{
    __block_all_sigs, __restore_sigs, sigaction, sigismember, Sigaction, SIGKILL, SIGSTOP, SIG_DFL,
    SIG_IGN, SIG_SETMASK,
};
use crate::syscall::{syscall0, syscall1, syscall2, syscall3, syscall4};
use crate::thread::create::SchedParam;

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in, all re-verified) ---------
#[cfg(target_arch = "x86_64")]
const SYS_READ: usize = 0;
#[cfg(target_arch = "x86_64")]
const SYS_WRITE: usize = 1;
#[cfg(target_arch = "x86_64")]
const SYS_CLOSE: usize = 3;
#[cfg(target_arch = "x86_64")]
const SYS_RT_SIGPROCMASK: usize = 14;
#[cfg(target_arch = "x86_64")]
const SYS_DUP: usize = 32;
#[cfg(target_arch = "x86_64")]
const SYS_DUP2: usize = 33;
#[cfg(target_arch = "x86_64")]
const SYS_FORK: usize = 57;
#[cfg(target_arch = "x86_64")]
const SYS_EXIT: usize = 60;
#[cfg(target_arch = "x86_64")]
const SYS_FCNTL: usize = 72;
#[cfg(target_arch = "x86_64")]
const SYS_CHDIR: usize = 80;
#[cfg(target_arch = "x86_64")]
const SYS_FCHDIR: usize = 81;
#[cfg(target_arch = "x86_64")]
const SYS_GETUID: usize = 102;
#[cfg(target_arch = "x86_64")]
const SYS_GETGID: usize = 104;
#[cfg(target_arch = "x86_64")]
const SYS_SETUID: usize = 105;
#[cfg(target_arch = "x86_64")]
const SYS_SETGID: usize = 106;
#[cfg(target_arch = "x86_64")]
const SYS_SETPGID: usize = 109;
#[cfg(target_arch = "x86_64")]
const SYS_SETSID: usize = 112;
#[cfg(target_arch = "x86_64")]
const SYS_EXIT_GROUP: usize = 231;
#[cfg(target_arch = "x86_64")]
const SYS_OPENAT: usize = 257;
#[cfg(target_arch = "x86_64")]
const SYS_PIPE2: usize = 293;

// ---- Errnos (musl arch/generic/bits/errno.h) --------------------------------
#[cfg(target_arch = "x86_64")]
const EBADF: c_int = 9;
#[cfg(target_arch = "x86_64")]
const ENOMEM: c_int = 12;
#[cfg(target_arch = "x86_64")]
const EINVAL: c_int = 22;
#[cfg(target_arch = "x86_64")]
const ENOSYS: c_int = 38;
#[cfg(target_arch = "x86_64")]
const EPIPE: c_int = 32;

// ---- openat/fcntl bits (musl include/fcntl.h, arch/generic/bits/fcntl.h) ----
#[cfg(target_arch = "x86_64")]
const AT_FDCWD: c_int = -100;
#[cfg(target_arch = "x86_64")]
const O_CLOEXEC: c_int = 0o2000000;
#[cfg(target_arch = "x86_64")]
const F_GETFD: c_int = 1;
#[cfg(target_arch = "x86_64")]
const F_SETFD: c_int = 2;
#[cfg(target_arch = "x86_64")]
const FD_CLOEXEC: c_int = 1;

// ---- Spawn flags (musl include/spawn.h:17-24) ------------------------------
/// Reset uid/gid (musl `POSIX_SPAWN_RESETIDS`).
#[cfg(target_arch = "x86_64")]
pub const POSIX_SPAWN_RESETIDS: c_int = 1;
/// Set the child's process group (musl `POSIX_SPAWN_SETPGROUP`).
#[cfg(target_arch = "x86_64")]
pub const POSIX_SPAWN_SETPGROUP: c_int = 2;
/// Reset defaulted signals (musl `POSIX_SPAWN_SETSIGDEF`).
#[cfg(target_arch = "x86_64")]
pub const POSIX_SPAWN_SETSIGDEF: c_int = 4;
/// Install the attr signal mask (musl `POSIX_SPAWN_SETSIGMASK`).
#[cfg(target_arch = "x86_64")]
pub const POSIX_SPAWN_SETSIGMASK: c_int = 8;
/// Accepted, ignored at spawn like musl (musl `POSIX_SPAWN_SETSCHEDPARAM`).
#[cfg(target_arch = "x86_64")]
pub const POSIX_SPAWN_SETSCHEDPARAM: c_int = 16;
/// Accepted, ignored at spawn like musl (musl `POSIX_SPAWN_SETSCHEDULER`).
#[cfg(target_arch = "x86_64")]
pub const POSIX_SPAWN_SETSCHEDULER: c_int = 32;
/// Accepted; plain fork already serialises like vfork here (musl `POSIX_SPAWN_USEVFORK`).
#[cfg(target_arch = "x86_64")]
pub const POSIX_SPAWN_USEVFORK: c_int = 64;
/// Create a new session (musl `POSIX_SPAWN_SETSID`).
#[cfg(target_arch = "x86_64")]
pub const POSIX_SPAWN_SETSID: c_int = 128;

// ---- Types (musl include/spawn.h:26-40, repr(C) mirrors) --------------------
/// musl `posix_spawnattr_t`: flags, pgroup, default/mask sets,
/// priority/policy words, exec override, padding.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct posix_spawnattr_t {
    pub __flags: c_int,
    pub __pgrp: c_int,
    pub __def: crate::signal::sigset_t,
    pub __mask: crate::signal::sigset_t,
    pub __prio: c_int,
    pub __pol: c_int,
    pub __fn: *mut c_void,
    pub __pad: [u8; 56],
}

/// musl `posix_spawn_file_actions_t`: two pad words, the action-list
/// head, sixteen pad words.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct posix_spawn_file_actions_t {
    pub __pad0: [c_int; 2],
    pub __actions: *mut c_void,
    pub __pad: [c_int; 16],
}

#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<posix_spawnattr_t>() == 336);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(posix_spawnattr_t, __pgrp) == 4);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(posix_spawnattr_t, __def) == 8);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(posix_spawnattr_t, __mask) == 136);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(posix_spawnattr_t, __prio) == 264);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(posix_spawnattr_t, __pol) == 268);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(posix_spawnattr_t, __fn) == 272);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<posix_spawn_file_actions_t>() == 80);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(posix_spawn_file_actions_t, __actions) == 8);

// ---- Action list (musl src/process/fdop.h) ----------------------------------
#[cfg(target_arch = "x86_64")]
const FDOP_CLOSE: c_int = 1;
#[cfg(target_arch = "x86_64")]
const FDOP_DUP2: c_int = 2;
#[cfg(target_arch = "x86_64")]
const FDOP_OPEN: c_int = 3;
#[cfg(target_arch = "x86_64")]
const FDOP_CHDIR: c_int = 4;
#[cfg(target_arch = "x86_64")]
const FDOP_FCHDIR: c_int = 5;

/// musl `struct fdop`: doubly linked node plus one op; `path[1]`
/// stands in for the flexible tail (alloc `size + len`: the counted
/// slot already holds one byte, covering `len + 1` exactly).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct Fdop {
    next: *mut Fdop,
    prev: *mut Fdop,
    cmd: c_int,
    fd: c_int,
    srcfd: c_int,
    oflag: c_int,
    mode: u32,
    path: [c_char; 1],
}

#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(Fdop, path) == 36);

// ---- Small locals -----------------------------------------------------------
/// NUL length (local; the `process.rs` equivalent is private).
///
/// # Safety
///
/// `s` must be a valid NUL-terminated string.
#[cfg(target_arch = "x86_64")]
unsafe fn strlen(s: *const c_char) -> usize {
    unsafe {
        let mut n = 0usize;
        while s.wrapping_add(n).read() != 0 {
            n = n.wrapping_add(1);
        }
        n
    }
}

/// Copy a NUL-terminated string (local `strcpy`).
///
/// # Safety
///
/// `dst` must be writable for `strlen(src) + 1` bytes; ranges must not
/// overlap.
#[cfg(target_arch = "x86_64")]
unsafe fn strcpy(dst: *mut c_char, src: *const c_char) {
    unsafe {
        let mut i = 0usize;
        loop {
            let c = src.wrapping_add(i).read();
            dst.wrapping_add(i).write(c);
            if c == 0 {
                break;
            }
            i = i.wrapping_add(1);
        }
    }
}

/// Whether a raw trap result is `-errno`.
#[cfg(target_arch = "x86_64")]
fn trap_err(r: isize) -> bool {
    (-4095..=-1).contains(&r)
}

/// Diverging child exit (the `process.rs` `child_halt` shape, local —
/// that one is private and `crate::exit::_Exit` is compiled out under
/// test: `SYS_exit_group` then `SYS_exit` forever; no errno, no locks).
#[cfg(target_arch = "x86_64")]
unsafe fn child_halt(code: c_int) -> ! {
    unsafe {
        syscall1(SYS_EXIT_GROUP, code as usize);
        loop {
            syscall1(SYS_EXIT, code as usize);
        }
    }
}

/// Allocate a list node with room for `len` path bytes plus NUL
/// (parent-side only; the fork child never allocates — a fork while
/// another thread holds the malloc lock plus a child malloc would
/// wedge the child).
///
/// # Safety
///
/// `len` must be the `strlen` of a valid string; returns null on OOM.
#[cfg(target_arch = "x86_64")]
unsafe fn op_alloc(len: usize) -> *mut Fdop {
    unsafe {
        let p = crate::malloc::malloc(core::mem::size_of::<Fdop>().wrapping_add(len)) as *mut Fdop;
        if !p.is_null() {
            (*p).next = core::ptr::null_mut();
            (*p).prev = core::ptr::null_mut();
        }
        p
    }
}

/// Push a node at the list head (musl's prepend; the child applies
/// tail-first so execution order matches insertion order).
///
/// # Safety
///
/// `fa` must be valid; `op` must be a live node.
#[cfg(target_arch = "x86_64")]
unsafe fn op_push(fa: *mut posix_spawn_file_actions_t, op: *mut Fdop) {
    unsafe {
        let head = (*fa).__actions as *mut Fdop;
        (*op).next = head;
        if !head.is_null() {
            (*head).prev = op;
        }
        (*fa).__actions = op as *mut c_void;
    }
}

// ---- File actions -----------------------------------------------------------
/// Initialise an empty action list (musl
/// `posix_spawn_file_actions_init.c`).
///
/// # Safety
///
/// `fa` must be writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_init(
    fa: *mut posix_spawn_file_actions_t,
) -> c_int {
    unsafe {
        (*fa).__actions = core::ptr::null_mut();
        0
    }
}

/// Free the action list (musl `posix_spawn_file_actions_destroy.c`).
///
/// # Safety
///
/// `fa` must hold a live list from [`posix_spawn_file_actions_init`];
/// each node is freed exactly once.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_destroy(
    fa: *mut posix_spawn_file_actions_t,
) -> c_int {
    unsafe {
        let mut op = (*fa).__actions as *mut Fdop;
        while !op.is_null() {
            let next = (*op).next;
            crate::malloc::free(op as *mut c_void);
            op = next;
        }
        0
    }
}

/// Queue an open (musl `posix_spawn_file_actions_addopen.c`).
///
/// # Safety
///
/// `fa` must be valid; `path` must be a valid NUL-terminated string.
/// Returns the errno (`EBADF`/`ENOMEM`), never -1.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_addopen(
    fa: *mut posix_spawn_file_actions_t,
    fd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: u32,
) -> c_int {
    unsafe {
        if fd < 0 {
            return EBADF;
        }
        let op = op_alloc(strlen(path));
        if op.is_null() {
            return ENOMEM;
        }
        (*op).cmd = FDOP_OPEN;
        (*op).fd = fd;
        (*op).oflag = flags;
        (*op).mode = mode;
        strcpy((*op).path.as_mut_ptr(), path);
        op_push(fa, op);
        0
    }
}

/// Queue a close (musl `posix_spawn_file_actions_addclose.c`).
///
/// # Safety
///
/// `fa` must be valid. Returns the errno, never -1.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_addclose(
    fa: *mut posix_spawn_file_actions_t,
    fd: c_int,
) -> c_int {
    unsafe {
        if fd < 0 {
            return EBADF;
        }
        let op = op_alloc(0);
        if op.is_null() {
            return ENOMEM;
        }
        (*op).cmd = FDOP_CLOSE;
        (*op).fd = fd;
        op_push(fa, op);
        0
    }
}

/// Queue a dup2 (musl `posix_spawn_file_actions_adddup2.c`).
///
/// # Safety
///
/// `fa` must be valid. Returns the errno, never -1.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_adddup2(
    fa: *mut posix_spawn_file_actions_t,
    srcfd: c_int,
    fd: c_int,
) -> c_int {
    unsafe {
        if srcfd < 0 || fd < 0 {
            return EBADF;
        }
        let op = op_alloc(0);
        if op.is_null() {
            return ENOMEM;
        }
        (*op).cmd = FDOP_DUP2;
        (*op).srcfd = srcfd;
        (*op).fd = fd;
        op_push(fa, op);
        0
    }
}

/// Queue a chdir (musl `posix_spawn_file_actions_addchdir_np`: the
/// `_np` name is musl's own, see `include/spawn.h` and
/// `tools/musl-exports.txt`).
///
/// # Safety
///
/// `fa` must be valid; `path` must be a valid NUL-terminated string.
/// Returns the errno, never -1.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_addchdir_np(
    fa: *mut posix_spawn_file_actions_t,
    path: *const c_char,
) -> c_int {
    unsafe {
        let op = op_alloc(strlen(path));
        if op.is_null() {
            return ENOMEM;
        }
        (*op).cmd = FDOP_CHDIR;
        (*op).fd = -1;
        strcpy((*op).path.as_mut_ptr(), path);
        op_push(fa, op);
        0
    }
}

/// Queue an fchdir (musl `posix_spawn_file_actions_addfchdir_np`: the
/// `_np` name is musl's own, see `include/spawn.h` and
/// `tools/musl-exports.txt`).
///
/// # Safety
///
/// `fa` must be valid. Returns the errno, never -1.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_addfchdir_np(
    fa: *mut posix_spawn_file_actions_t,
    fd: c_int,
) -> c_int {
    unsafe {
        if fd < 0 {
            return EBADF;
        }
        let op = op_alloc(0);
        if op.is_null() {
            return ENOMEM;
        }
        (*op).cmd = FDOP_FCHDIR;
        (*op).fd = fd;
        op_push(fa, op);
        0
    }
}

// ---- Attributes -------------------------------------------------------------
/// Zero an attr object (musl `posix_spawnattr_init.c`).
///
/// # Safety
///
/// `attr` must be writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_init(attr: *mut posix_spawnattr_t) -> c_int {
    unsafe {
        core::ptr::write_bytes(
            attr as *mut u8,
            0,
            core::mem::size_of::<posix_spawnattr_t>(),
        );
        0
    }
}

/// Destroy an attr object (musl `posix_spawnattr_destroy.c`: no-op).
///
/// # Safety
///
/// `attr` must be valid (otherwise unused).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_destroy(_attr: *mut posix_spawnattr_t) -> c_int {
    0
}

/// Read flags (musl `posix_spawnattr_getflags.c`).
///
/// # Safety
///
/// Both pointers must be valid.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_getflags(
    attr: *const posix_spawnattr_t,
    flags: *mut c_short,
) -> c_int {
    unsafe {
        *flags = (*attr).__flags as c_short;
        0
    }
}

/// Write flags (musl `posix_spawnattr_setflags.c`: reject unknown bits
/// with `EINVAL`).
///
/// # Safety
///
/// `attr` must be valid.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_setflags(
    attr: *mut posix_spawnattr_t,
    flags: c_short,
) -> c_int {
    unsafe {
        const ALL: c_int = POSIX_SPAWN_RESETIDS
            | POSIX_SPAWN_SETPGROUP
            | POSIX_SPAWN_SETSIGDEF
            | POSIX_SPAWN_SETSIGMASK
            | POSIX_SPAWN_SETSCHEDPARAM
            | POSIX_SPAWN_SETSCHEDULER
            | POSIX_SPAWN_USEVFORK
            | POSIX_SPAWN_SETSID;
        if ((flags as c_int) & !ALL) != 0 {
            return EINVAL;
        }
        (*attr).__flags = flags as c_int;
        0
    }
}

/// Read the process group (musl `posix_spawnattr_getpgroup.c`).
///
/// # Safety
///
/// Both pointers must be valid.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_getpgroup(
    attr: *const posix_spawnattr_t,
    pgrp: *mut c_int,
) -> c_int {
    unsafe {
        *pgrp = (*attr).__pgrp;
        0
    }
}

/// Write the process group (musl `posix_spawnattr_setpgroup.c`).
///
/// # Safety
///
/// `attr` must be valid.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_setpgroup(
    attr: *mut posix_spawnattr_t,
    pgrp: c_int,
) -> c_int {
    unsafe {
        (*attr).__pgrp = pgrp;
        0
    }
}

/// Read the defaulted-signal set (musl `posix_spawnattr_getsigdefault.c`).
///
/// # Safety
///
/// Both pointers must be valid.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_getsigdefault(
    attr: *const posix_spawnattr_t,
    def: *mut crate::signal::sigset_t,
) -> c_int {
    unsafe {
        *def = (*attr).__def;
        0
    }
}

/// Write the defaulted-signal set (musl `posix_spawnattr_setsigdefault.c`).
///
/// # Safety
///
/// Both pointers must be valid.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_setsigdefault(
    attr: *mut posix_spawnattr_t,
    def: *const crate::signal::sigset_t,
) -> c_int {
    unsafe {
        (*attr).__def = *def;
        0
    }
}

/// Read the spawn signal mask (musl `posix_spawnattr_getsigmask.c`).
///
/// # Safety
///
/// Both pointers must be valid.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_getsigmask(
    attr: *const posix_spawnattr_t,
    mask: *mut crate::signal::sigset_t,
) -> c_int {
    unsafe {
        *mask = (*attr).__mask;
        0
    }
}

/// Write the spawn signal mask (musl `posix_spawnattr_setsigmask.c`).
///
/// # Safety
///
/// Both pointers must be valid.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_setsigmask(
    attr: *mut posix_spawnattr_t,
    mask: *const crate::signal::sigset_t,
) -> c_int {
    unsafe {
        (*attr).__mask = *mask;
        0
    }
}

/// Stub (musl `posix_spawnattr_sched.c`: `ENOSYS`).
///
/// # Safety
///
/// Both pointers must be valid (otherwise unused).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_getschedparam(
    _attr: *const posix_spawnattr_t,
    _param: *mut SchedParam,
) -> c_int {
    ENOSYS
}

/// Stub (musl `posix_spawnattr_sched.c`: `ENOSYS`).
///
/// # Safety
///
/// Both pointers must be valid (otherwise unused).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_setschedparam(
    _attr: *mut posix_spawnattr_t,
    _param: *const SchedParam,
) -> c_int {
    ENOSYS
}

/// Stub (musl `posix_spawnattr_sched.c`: `ENOSYS`).
///
/// # Safety
///
/// Both pointers must be valid (otherwise unused).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_getschedpolicy(
    _attr: *const posix_spawnattr_t,
    _policy: *mut c_int,
) -> c_int {
    ENOSYS
}

/// Stub (musl `posix_spawnattr_sched.c`: `ENOSYS`).
///
/// # Safety
///
/// `attr` must be valid.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_setschedpolicy(
    _attr: *mut posix_spawnattr_t,
    _policy: c_int,
) -> c_int {
    ENOSYS
}

// ---- Child ------------------------------------------------------------------
/// Reset every caught disposition to `SIG_DFL`, plus every member of
/// `def` when `SETSIGDEF` is set (musl's child loop minus the
/// handler-set tracker: dispositions are probed with `sigaction`
/// instead; `SIGKILL`/`SIGSTOP` are never probed, the reserved
/// 32-34 are skipped like `signal.rs` validity does).
///
/// # Safety
///
/// Fork-child only; `def` must be valid when `want_def` is set.
#[cfg(target_arch = "x86_64")]
unsafe fn child_sigreset(want_def: bool, def: *const crate::signal::sigset_t) {
    unsafe {
        let dfl = Sigaction {
            handler: SIG_DFL,
            mask: [0; 16],
            flags: 0,
            restorer: 0,
        };
        let mut sig = 1 as c_int;
        while sig < 65 {
            if sig == 32 {
                sig = 35;
                continue;
            }
            if want_def && sigismember(def, sig) == 1 {
                sigaction(sig, &dfl, core::ptr::null_mut());
            } else if sig != SIGKILL && sig != SIGSTOP {
                let mut old: Sigaction = core::mem::zeroed();
                if sigaction(sig, core::ptr::null(), &mut old) == 0
                    && old.handler != SIG_DFL
                    && old.handler != SIG_IGN
                {
                    sigaction(sig, &dfl, core::ptr::null_mut());
                }
            }
            sig = sig.wrapping_add(1);
        }
    }
}

/// Apply the action list oldest-first with raw traps only (musl's
/// child `fa` loop: pipe-fd clobber guard, `dup2`-same-fd clears
/// `CLOEXEC`, `openat` for opens). Returns 0 or the errno.
///
/// # Safety
///
/// Fork-child only; `fa` must be null or a live list; `*pipe` is
/// updated when the error pipe itself is moved.
#[cfg(target_arch = "x86_64")]
unsafe fn child_actions(fa: *const posix_spawn_file_actions_t, pipe: *mut c_int) -> c_int {
    unsafe {
        if fa.is_null() || (*fa).__actions.is_null() {
            return 0;
        }
        let mut op = (*fa).__actions as *mut Fdop;
        while !(*op).next.is_null() {
            op = (*op).next;
        }
        while !op.is_null() {
            if (*op).fd == *pipe {
                let n = syscall1(SYS_DUP, *pipe as usize);
                if trap_err(n) {
                    return n.wrapping_neg() as c_int;
                }
                syscall1(SYS_CLOSE, *pipe as usize);
                *pipe = n as c_int;
            }
            let r = match (*op).cmd {
                FDOP_CLOSE => {
                    syscall1(SYS_CLOSE, (*op).fd as usize);
                    0
                }
                FDOP_DUP2 => {
                    if (*op).srcfd == *pipe {
                        -(EBADF as isize)
                    } else if (*op).srcfd != (*op).fd {
                        syscall2(SYS_DUP2, (*op).srcfd as usize, (*op).fd as usize)
                    } else {
                        let f = syscall2(SYS_FCNTL, (*op).fd as usize, F_GETFD as usize);
                        if trap_err(f) {
                            f
                        } else {
                            syscall3(
                                SYS_FCNTL,
                                (*op).fd as usize,
                                F_SETFD as usize,
                                (f as c_int & !FD_CLOEXEC) as usize,
                            )
                        }
                    }
                }
                FDOP_OPEN => {
                    let fd = syscall4(
                        SYS_OPENAT,
                        AT_FDCWD as usize,
                        (*op).path.as_ptr() as usize,
                        (*op).oflag as usize,
                        (*op).mode as usize,
                    );
                    if trap_err(fd) {
                        fd
                    } else if fd as c_int != (*op).fd {
                        let d = syscall2(SYS_DUP2, fd as usize, (*op).fd as usize);
                        syscall1(SYS_CLOSE, fd as usize);
                        d
                    } else {
                        0
                    }
                }
                FDOP_CHDIR => syscall1(SYS_CHDIR, (*op).path.as_ptr() as usize),
                FDOP_FCHDIR => syscall1(SYS_FCHDIR, (*op).fd as usize),
                _ => 0,
            };
            if trap_err(r) {
                return r.wrapping_neg() as c_int;
            }
            op = (*op).prev;
        }
        syscall3(
            SYS_FCNTL,
            *pipe as usize,
            F_SETFD as usize,
            FD_CLOEXEC as usize,
        );
        0
    }
}

/// Exec-function shape behind `attr.__fn` (musl's `attr->__fn` cast to
/// `execve`-shaped; `posix_spawnp` installs `execvpe`).
#[cfg(target_arch = "x86_64")]
type ExecFn = unsafe extern "C" fn(*const c_char, *const *mut c_char, *const *mut c_char) -> c_int;

/// The fork child: signal reset, session/group/ids, actions, mask,
/// exec (musl's `child()`; scheduler flags ignored like musl's).
/// Diverges.
///
/// # Safety
///
/// Fork-child only: signal wrappers plus raw traps, then exec or
/// `_exit(127)`; never returns, never touches the heap. `attr` must
/// be the staged copy (its `__mask` always applies).
#[cfg(target_arch = "x86_64")]
unsafe fn spawn_child(
    errpipe: c_int,
    fa: *const posix_spawn_file_actions_t,
    attr: *const posix_spawnattr_t,
    path: *const c_char,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> ! {
    unsafe {
        let mut p = errpipe;
        let flags = (*attr).__flags;
        child_sigreset((flags & POSIX_SPAWN_SETSIGDEF) != 0, &(*attr).__def);
        // Straight-line fallthrough (a `loop` holding only `break`s trips
        // `never_loop`); each fallible step returns its errno early.
        let mut run = || {
            if (flags & POSIX_SPAWN_SETSID) != 0 {
                let r = syscall0(SYS_SETSID);
                if trap_err(r) {
                    return r.wrapping_neg() as c_int;
                }
            }
            if (flags & POSIX_SPAWN_SETPGROUP) != 0 {
                let r = syscall2(SYS_SETPGID, 0, (*attr).__pgrp as usize);
                if trap_err(r) {
                    return r.wrapping_neg() as c_int;
                }
            }
            if (flags & POSIX_SPAWN_RESETIDS) != 0 {
                let g = syscall0(SYS_GETGID);
                let r = syscall1(SYS_SETGID, g as usize);
                if trap_err(r) {
                    return r.wrapping_neg() as c_int;
                }
                let u = syscall0(SYS_GETUID);
                let r = syscall1(SYS_SETUID, u as usize);
                if trap_err(r) {
                    return r.wrapping_neg() as c_int;
                }
            }
            let e = child_actions(fa, &mut p);
            if e != 0 {
                return e;
            }
            syscall4(
                SYS_RT_SIGPROCMASK,
                SIG_SETMASK as usize,
                &(*attr).__mask as *const crate::signal::sigset_t as usize,
                0,
                8,
            );
            let f = (*attr).__fn;
            if f.is_null() {
                crate::process::execve(path, argv, envp);
            } else {
                let e: ExecFn = core::mem::transmute(f);
                e(path, argv, envp);
            }
            errno_load(__errno_location())
        };
        let ec: c_int = run();
        // Atomic error report (`sizeof errno < PIPE_BUF`); `EPIPE`
        // means the parent went away, nothing left to do.
        if ec != 0 {
            loop {
                let r = syscall3(SYS_WRITE, p as usize, &ec as *const c_int as usize, 4);
                if !trap_err(r) || r == -(EPIPE as isize) {
                    break;
                }
            }
        }
        child_halt(127);
    }
}

// ---- Spawn ------------------------------------------------------------------
/// Spawn a process (musl `posix_spawn`: block-all mask, `CLOEXEC`
/// error pipe, fork; the parent reads the pipe and reaps failures).
/// Returns 0 or the errno; `res` takes the pid on success.
///
/// # Safety
///
/// `path`/`argv`/`envp` follow `execve`; `fa`/`attr` must be null or
/// valid; `res` must be null or writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawn(
    res: *mut c_int,
    path: *const c_char,
    fa: *const posix_spawn_file_actions_t,
    attr: *const posix_spawnattr_t,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    unsafe {
        // Private attr copy: a null attr spawns bare, and the
        // parent's saved mask is staged here so the child restores it
        // without a second channel (musl passes a separate args
        // struct through clone instead).
        let mut staged: posix_spawnattr_t = core::mem::zeroed();
        if !attr.is_null() {
            core::ptr::copy_nonoverlapping(attr, &mut staged, 1);
        }
        let mut old: crate::signal::sigset_t = [0; 16];
        __block_all_sigs(&mut old);
        if (staged.__flags & POSIX_SPAWN_SETSIGMASK) == 0 {
            staged.__mask = old;
            staged.__flags |= POSIX_SPAWN_SETSIGMASK;
        }
        let mut p = [0 as c_int; 2];
        let pr = syscall2(SYS_PIPE2, p.as_mut_ptr() as usize, O_CLOEXEC as usize);
        if trap_err(pr) {
            let ec = pr.wrapping_neg() as c_int;
            __restore_sigs(&old);
            return ec;
        }
        let pid = syscall0(SYS_FORK);
        if trap_err(pid) {
            let ec = pid.wrapping_neg() as c_int;
            syscall1(SYS_CLOSE, p[0] as usize);
            syscall1(SYS_CLOSE, p[1] as usize);
            __restore_sigs(&old);
            return ec;
        }
        if pid == 0 {
            syscall1(SYS_CLOSE, p[0] as usize);
            spawn_child(p[1], fa, &staged, path, argv, envp);
        }
        syscall1(SYS_CLOSE, p[1] as usize);
        // A 4-byte read means the child failed: reap it (its 127 exit
        // is unreachable and unwaited-for otherwise) and return its
        // errno; EOF means it execed and the pipe died with it.
        let mut ec: c_int = 0;
        let got = syscall3(
            SYS_READ,
            p[0] as usize,
            &mut ec as *mut c_int as usize,
            core::mem::size_of::<c_int>(),
        );
        syscall1(SYS_CLOSE, p[0] as usize);
        if got == core::mem::size_of::<c_int>() as isize {
            crate::process::waitpid(pid as c_int, core::ptr::null_mut(), 0);
        } else {
            ec = 0;
        }
        if ec == 0 && !res.is_null() {
            *res = pid as c_int;
        }
        __restore_sigs(&old);
        ec
    }
}

/// Spawn with `PATH` search (musl `posix_spawnp.c`: copy the attr,
/// install `execvpe` as the exec override, delegate).
///
/// # Safety
///
/// Same contract as [`posix_spawn`] with `file` searched like
/// `execvp` when it holds no slash.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn posix_spawnp(
    res: *mut c_int,
    file: *const c_char,
    fa: *const posix_spawn_file_actions_t,
    attr: *const posix_spawnattr_t,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    unsafe {
        let mut staged: posix_spawnattr_t = core::mem::zeroed();
        if !attr.is_null() {
            core::ptr::copy_nonoverlapping(attr, &mut staged, 1);
        }
        staged.__fn = crate::process::execvpe as *const c_void as *mut c_void;
        posix_spawn(res, file, fa, &staged, argv, envp)
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use core::ffi::{c_char, c_int};

    use crate::signal::{sigaddset, sigemptyset, sigprocmask, SIGUSR1, SIG_BLOCK, SIG_SETMASK};

    const ENOENT: c_int = 2;
    const ECHILD: c_int = 10;

    fn wifexited(s: c_int) -> bool {
        (s & 0x7f) == 0
    }

    fn wexitstatus(s: c_int) -> c_int {
        (s & 0xff00) >> 8
    }

    /// Empty environment (null-terminated, no variables).
    fn empty_env() -> [*mut c_char; 1] {
        [core::ptr::null_mut()]
    }

    #[test]
    fn spawn_true_exits_zero() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let env = empty_env();
            let argv = [c"true".as_ptr() as *mut c_char, core::ptr::null_mut()];
            let mut pid = -1;
            // Absolute path: /bin first, /usr/bin fallback.
            let mut rc = posix_spawn(
                &mut pid,
                c"/bin/true".as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
                argv.as_ptr(),
                env.as_ptr(),
            );
            if rc == ENOENT {
                rc = posix_spawn(
                    &mut pid,
                    c"/usr/bin/true".as_ptr(),
                    core::ptr::null(),
                    core::ptr::null(),
                    argv.as_ptr(),
                    env.as_ptr(),
                );
            }
            assert_eq!(rc, 0);
            assert!(pid > 0);
            let mut status = 0;
            assert_eq!(crate::process::waitpid(pid, &mut status, 0), pid);
            assert!(wifexited(status));
            assert_eq!(wexitstatus(status), 0);
            // Reaped: no zombie left behind.
            assert_eq!(crate::process::waitpid(pid, &mut status, 0), -1);
            assert_eq!(errno_load(__errno_location()), ECHILD);
        }
    }

    #[test]
    fn spawnp_sh_reports_exit_five() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let env = empty_env();
            let argv = [
                c"sh".as_ptr() as *mut c_char,
                c"-c".as_ptr() as *mut c_char,
                c"exit 5".as_ptr() as *mut c_char,
                core::ptr::null_mut(),
            ];
            let mut pid = -1;
            assert_eq!(
                posix_spawnp(
                    &mut pid,
                    c"sh".as_ptr(),
                    core::ptr::null(),
                    core::ptr::null(),
                    argv.as_ptr(),
                    env.as_ptr(),
                ),
                0
            );
            assert!(pid > 0);
            let mut status = 0;
            assert_eq!(crate::process::waitpid(pid, &mut status, 0), pid);
            assert!(wifexited(status));
            assert_eq!(wexitstatus(status), 5);
        }
    }

    #[test]
    fn file_actions_wire_stdout_to_pipe() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut fds = [0 as c_int; 2];
            assert_eq!(crate::unistd::pipe(fds.as_mut_ptr()), 0);
            let mut fa: posix_spawn_file_actions_t = core::mem::zeroed();
            assert_eq!(posix_spawn_file_actions_init(&mut fa), 0);
            // Child drops the read end, dups the write end onto
            // stdout (applied oldest-first: close runs first).
            assert_eq!(posix_spawn_file_actions_addclose(&mut fa, fds[0]), 0);
            assert_eq!(posix_spawn_file_actions_adddup2(&mut fa, fds[1], 1), 0);
            let env = empty_env();
            let argv = [
                c"sh".as_ptr() as *mut c_char,
                c"-c".as_ptr() as *mut c_char,
                c"printf wired".as_ptr() as *mut c_char,
                core::ptr::null_mut(),
            ];
            let mut pid = -1;
            assert_eq!(
                posix_spawnp(
                    &mut pid,
                    c"sh".as_ptr(),
                    &fa,
                    core::ptr::null(),
                    argv.as_ptr(),
                    env.as_ptr(),
                ),
                0
            );
            assert_eq!(posix_spawn_file_actions_destroy(&mut fa), 0);
            assert_eq!(crate::unistd::close(fds[1]), 0);
            // Drain exactly the 5 wired bytes, then EOF.
            let mut got = [0u8; 5];
            let mut n = 0usize;
            while n < got.len() {
                let r = crate::unistd::read(
                    fds[0],
                    got.as_mut_ptr().wrapping_add(n) as *mut c_void,
                    got.len().wrapping_sub(n),
                );
                assert!(r > 0);
                n = n.wrapping_add(r as usize);
            }
            assert_eq!(&got, b"wired");
            assert_eq!(crate::unistd::close(fds[0]), 0);
            let mut status = 0;
            assert_eq!(crate::process::waitpid(pid, &mut status, 0), pid);
            assert!(wifexited(status));
            assert_eq!(wexitstatus(status), 0);
        }
    }

    #[test]
    fn attr_flags_roundtrip_and_reject() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut a: posix_spawnattr_t = core::mem::zeroed();
            assert_eq!(posix_spawnattr_init(&mut a), 0);
            let mut f = 0 as c_short;
            assert_eq!(posix_spawnattr_getflags(&a, &mut f), 0);
            assert_eq!(f, 0);
            let all = (POSIX_SPAWN_RESETIDS
                | POSIX_SPAWN_SETPGROUP
                | POSIX_SPAWN_SETSIGDEF
                | POSIX_SPAWN_SETSIGMASK
                | POSIX_SPAWN_SETSCHEDPARAM
                | POSIX_SPAWN_SETSCHEDULER
                | POSIX_SPAWN_USEVFORK
                | POSIX_SPAWN_SETSID) as c_short;
            assert_eq!(posix_spawnattr_setflags(&mut a, all), 0);
            assert_eq!(posix_spawnattr_getflags(&a, &mut f), 0);
            assert_eq!(f, all);
            // Unknown bit rejected, old flags kept.
            assert_eq!(posix_spawnattr_setflags(&mut a, 0x1000), EINVAL);
            assert_eq!(posix_spawnattr_getflags(&a, &mut f), 0);
            assert_eq!(f, all);
            // pgroup roundtrip.
            assert_eq!(posix_spawnattr_setpgroup(&mut a, 4242), 0);
            let mut p = 0;
            assert_eq!(posix_spawnattr_getpgroup(&a, &mut p), 0);
            assert_eq!(p, 4242);
            // sigmask/sigdefault roundtrips.
            let mut m: crate::signal::sigset_t = [0; 16];
            assert_eq!(sigemptyset(&mut m), 0);
            assert_eq!(sigaddset(&mut m, SIGUSR1), 0);
            assert_eq!(posix_spawnattr_setsigmask(&mut a, &m), 0);
            let mut m2: crate::signal::sigset_t = [0; 16];
            assert_eq!(posix_spawnattr_getsigmask(&a, &mut m2), 0);
            assert_eq!(m2, m);
            assert_eq!(posix_spawnattr_setsigdefault(&mut a, &m), 0);
            assert_eq!(posix_spawnattr_getsigdefault(&a, &mut m2), 0);
            assert_eq!(m2, m);
            // Scheduler stubs are ENOSYS like musl.
            let par = SchedParam { sched_priority: 3 };
            assert_eq!(posix_spawnattr_setschedparam(&mut a, &par), ENOSYS);
            let mut q = SchedParam { sched_priority: 0 };
            assert_eq!(posix_spawnattr_getschedparam(&a, &mut q), ENOSYS);
            let mut pol = 0;
            assert_eq!(posix_spawnattr_getschedpolicy(&a, &mut pol), ENOSYS);
            assert_eq!(posix_spawnattr_setschedpolicy(&mut a, 1), ENOSYS);
            // Action-list validation without forking.
            let mut fa: posix_spawn_file_actions_t = core::mem::zeroed();
            assert_eq!(posix_spawn_file_actions_init(&mut fa), 0);
            assert_eq!(
                posix_spawn_file_actions_addopen(&mut fa, -1, c"/x".as_ptr(), 0, 0,),
                EBADF
            );
            assert_eq!(posix_spawn_file_actions_addclose(&mut fa, -1), EBADF);
            assert_eq!(posix_spawn_file_actions_adddup2(&mut fa, -1, 1), EBADF);
            assert_eq!(posix_spawn_file_actions_adddup2(&mut fa, 1, -1), EBADF);
            assert_eq!(posix_spawn_file_actions_addfchdir_np(&mut fa, -1), EBADF);
            assert_eq!(
                posix_spawn_file_actions_addopen(&mut fa, 3, c"/dev/null".as_ptr(), 0, 0),
                0
            );
            assert_eq!(
                posix_spawn_file_actions_addchdir_np(&mut fa, c"/tmp".as_ptr()),
                0
            );
            assert_eq!(posix_spawn_file_actions_destroy(&mut fa), 0);
            assert_eq!(posix_spawnattr_destroy(&mut a), 0);
        }
    }

    #[test]
    fn spawn_with_sigmask_attr() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            // Parent mask snapshot: the spawn must not leak the
            // child's mask back into us.
            let mut before: crate::signal::sigset_t = [0; 16];
            assert_eq!(sigprocmask(SIG_SETMASK, core::ptr::null(), &mut before), 0);
            let mut a: posix_spawnattr_t = core::mem::zeroed();
            assert_eq!(posix_spawnattr_init(&mut a), 0);
            assert_eq!(
                posix_spawnattr_setflags(&mut a, POSIX_SPAWN_SETSIGMASK as c_short),
                0
            );
            let mut m: crate::signal::sigset_t = [0; 16];
            assert_eq!(sigemptyset(&mut m), 0);
            assert_eq!(sigaddset(&mut m, SIGUSR1), 0);
            assert_eq!(posix_spawnattr_setsigmask(&mut a, &m), 0);
            let env = empty_env();
            let argv = [c"true".as_ptr() as *mut c_char, core::ptr::null_mut()];
            let mut pid = -1;
            let mut rc = posix_spawn(
                &mut pid,
                c"/bin/true".as_ptr(),
                core::ptr::null(),
                &a,
                argv.as_ptr(),
                env.as_ptr(),
            );
            if rc == ENOENT {
                rc = posix_spawn(
                    &mut pid,
                    c"/usr/bin/true".as_ptr(),
                    core::ptr::null(),
                    &a,
                    argv.as_ptr(),
                    env.as_ptr(),
                );
            }
            assert_eq!(rc, 0);
            let mut status = 0;
            assert_eq!(crate::process::waitpid(pid, &mut status, 0), pid);
            assert!(wifexited(status));
            assert_eq!(wexitstatus(status), 0);
            let mut after: crate::signal::sigset_t = [0; 16];
            // Prove the block-all dance restored the parent mask.
            assert_eq!(sigprocmask(SIG_BLOCK, core::ptr::null(), &mut after), 0);
            assert_eq!(sigprocmask(SIG_SETMASK, &before, core::ptr::null_mut()), 0);
            assert_eq!(after, before);
            assert_eq!(posix_spawnattr_destroy(&mut a), 0);
        }
    }
}
