//! Process control (musl `src/process/*`: fork/exec/wait/system, x86_64).
//!
//! Thin trap wrappers plus musl's userspace shapes (`execvp` PATH search,
//! `system` signal dance, variadic `execl` family). Syscall numbers from
//! musl `arch/x86_64/bits/syscall.h.in` (fork 57, vfork 58, execve 59,
//! wait4 61, waitid 247, execveat 322); wait macros from musl
//! `include/sys/wait.h`; `CLD_*` from musl `include/signal.h`.
//!
//! Deviations from musl, each load-bearing and documented at its site:
//! no pthread_atfork handlers yet (Ola 11), so `fork` runs without
//! prepare/parent/child hooks; `execvpe` is a direct wrapper, not a weak
//! alias (no alias machinery in this wave); `RUsage` is the 144-byte
//! kernel prefix (musl's `struct rusage` carries a 16-long reserved tail
//! this omits); `execl`/`execlp`/`execle` read SysV varargs with the
//! `crate::stdio` walker shape (named `rdi`/`rsi` stay in registers,
//! `...` runs `rdx`..`r9` then the overflow stack; every slot is an
//! 8-byte pointer, NULL-terminated) instead of nightly `c_variadic`,
//! gathering into a 256-slot stack buffer (`E2BIG` past that, musl
//! would VLA without bound).

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr::null_mut;

use crate::errno::{__errno_location, errno_load, errno_store};
use crate::signal::{
    __block_all_sigs, __block_app_sigs, __restore_sigs, sigaction, sigaddset, sigemptyset,
    sigprocmask, sigset_t, Sigaction, Siginfo, SIGCHLD, SIGINT, SIGQUIT, SIG_BLOCK, SIG_DFL,
    SIG_IGN, SIG_SETMASK,
};
use crate::syscall::{syscall0, syscall1, syscall3, syscall4, syscall5, syscall_ret};

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_FORK: usize = 57;
#[cfg(target_arch = "x86_64")]
const SYS_VFORK: usize = 58;
#[cfg(target_arch = "x86_64")]
const SYS_EXECVE: usize = 59;
#[cfg(target_arch = "x86_64")]
const SYS_EXIT: usize = 60;
#[cfg(target_arch = "x86_64")]
const SYS_WAIT4: usize = 61;
#[cfg(target_arch = "x86_64")]
const SYS_EXIT_GROUP: usize = 231;
#[cfg(target_arch = "x86_64")]
const SYS_WAITID: usize = 247;
#[cfg(target_arch = "x86_64")]
const SYS_EXECVEAT: usize = 322;

// ---- Errnos (musl arch/generic/bits/errno.h) --------------------------------
#[cfg(target_arch = "x86_64")]
const ENOENT: c_int = 2;
#[cfg(target_arch = "x86_64")]
const EINTR: c_int = 4;
#[cfg(target_arch = "x86_64")]
const EBADF: c_int = 9;
#[cfg(target_arch = "x86_64")]
const EACCES: c_int = 13;
#[cfg(target_arch = "x86_64")]
const ENOTDIR: c_int = 20;
#[cfg(target_arch = "x86_64")]
const ENAMETOOLONG: c_int = 36;
#[cfg(target_arch = "x86_64")]
const ENOSYS: c_int = 38;
/// Argument list too long (musl `arch/generic/bits/errno.h:7`): the
/// `execl`-family cap below reports this instead of musl's VLA.
#[cfg(target_arch = "x86_64")]
const E2BIG: c_int = 7;

// ---- Wait options (musl include/sys/wait.h:36-43) ---------------------------
/// Do not block (musl `WNOHANG`).
#[cfg(target_arch = "x86_64")]
pub const WNOHANG: c_int = 1;
/// Report stopped children (musl `WUNTRACED`).
#[cfg(target_arch = "x86_64")]
pub const WUNTRACED: c_int = 2;
/// Alias of `WUNTRACED` (musl `WSTOPPED`).
#[cfg(target_arch = "x86_64")]
pub const WSTOPPED: c_int = 2;
/// Report exited children to `waitid` (musl `WEXITED`).
#[cfg(target_arch = "x86_64")]
pub const WEXITED: c_int = 4;
/// Report continued children (musl `WCONTINUED`).
#[cfg(target_arch = "x86_64")]
pub const WCONTINUED: c_int = 8;
/// Leave the child waitable (musl `WNOWAIT`).
#[cfg(target_arch = "x86_64")]
pub const WNOWAIT: c_int = 0x1000000;

// ---- waitid types (musl include/sys/wait.h:12-17) ---------------------------
/// Wait for any child (musl `P_ALL`).
#[cfg(target_arch = "x86_64")]
pub const P_ALL: c_int = 0;
/// Wait for one pid (musl `P_PID`).
#[cfg(target_arch = "x86_64")]
pub const P_PID: c_int = 1;
/// Wait for one process group (musl `P_PGID`).
#[cfg(target_arch = "x86_64")]
pub const P_PGID: c_int = 2;
/// Wait on a pidfd (musl `P_PIDFD`).
#[cfg(target_arch = "x86_64")]
pub const P_PIDFD: c_int = 3;

// ---- waitid result codes (musl include/signal.h:87-92) ----------------------
/// Child exited (musl `CLD_EXITED`).
#[cfg(target_arch = "x86_64")]
pub const CLD_EXITED: c_int = 1;
/// Child killed by signal (musl `CLD_KILLED`).
#[cfg(target_arch = "x86_64")]
pub const CLD_KILLED: c_int = 2;
/// Child dumped core (musl `CLD_DUMPED`).
#[cfg(target_arch = "x86_64")]
pub const CLD_DUMPED: c_int = 3;
/// Traced child trapped (musl `CLD_TRAPPED`).
#[cfg(target_arch = "x86_64")]
pub const CLD_TRAPPED: c_int = 4;
/// Child stopped (musl `CLD_STOPPED`).
#[cfg(target_arch = "x86_64")]
pub const CLD_STOPPED: c_int = 5;
/// Child continued (musl `CLD_CONTINUED`).
#[cfg(target_arch = "x86_64")]
pub const CLD_CONTINUED: c_int = 6;

/// musl `struct timeval` on x86_64 (`time_t` + `suseconds_t`: two `c_long`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Timeval {
    pub tv_sec: c_long,
    pub tv_usec: c_long,
}

/// Minimal musl `struct rusage` (`include/sys/resource.h` field order):
/// the two timevals plus the 14 `long` counters the kernel actually
/// writes (144 bytes on x86_64). musl appends `__reserved[16]` (272
/// bytes total); that tail is omitted here, so this must only back a
/// `wait3`/`wait4` out-param, never a larger kernel write.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct RUsage {
    pub ru_utime: Timeval,
    pub ru_stime: Timeval,
    pub ru_maxrss: c_long,
    pub ru_ixrss: c_long,
    pub ru_idrss: c_long,
    pub ru_isrss: c_long,
    pub ru_minflt: c_long,
    pub ru_majflt: c_long,
    pub ru_nswap: c_long,
    pub ru_inblock: c_long,
    pub ru_oublock: c_long,
    pub ru_msgsnd: c_long,
    pub ru_msgrcv: c_long,
    pub ru_nsignals: c_long,
    pub ru_nvcsw: c_long,
    pub ru_nivcsw: c_long,
}

#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<RUsage>() == 144);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(RUsage, ru_maxrss) == 32);

/// Fork without handlers (musl `fork`, `src/process/fork.c` minus the
/// atfork/lock dance): block app signals, `_Fork`, restore. No
/// pthread_atfork handlers exist yet (Ola 11): prepare/parent/child hooks are skipped — single-threaded behavior is identical; a multithreaded fork racing a held malloc lock can wedge the child like any atfork-less libc.
///
/// # Safety
///
/// Duplicates the calling thread; the child returns here with 0 and
/// shares nothing but the address space copy.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fork() -> c_int {
    unsafe {
        let mut set: sigset_t = [0; 16];
        __block_app_sigs(&mut set);
        let ret = _Fork();
        __restore_sigs(&set);
        ret
    }
}

/// Raw fork (musl `_Fork`, `src/process/_Fork.c` minus the abort-lock
/// pairing, which no wave owns yet): block all signals, `SYS_fork`
/// (57, present on x86_64 so no `clone` fallback), restore.
///
/// # Safety
///
/// Same contract as [`fork`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn _Fork() -> c_int {
    unsafe {
        let mut set: sigset_t = [0; 16];
        __block_all_sigs(&mut set);
        let r = syscall0(SYS_FORK);
        __restore_sigs(&set);
        syscall_ret(r) as c_int
    }
}

/// Raw-error sink for [`vfork`]: store the errno, return -1. Runs only
/// when the trap failed, which creates no child, so this normal call is
/// parent-only and safe.
///
/// # Safety
///
/// `r` must be a raw `-errno` in `[-4095, -1]`.
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn vfork_error(r: isize) -> c_int {
    unsafe {
        errno_store(__errno_location(), r.wrapping_neg() as c_int);
        -1
    }
}

/// Spawn sharing the caller's memory (musl `x86_64/vfork.s` shape:
/// `SYS_vfork`, 58, is `clone(CLONE_VFORK|CLONE_VM|SIGCHLD)` with the
/// parent parked until the child execs or exits).
///
/// Naked trap with the return address popped across the syscall and
/// pushed back after: the child shares this stack, so its first `call`
/// lands exactly on the slot holding the parent's pending return
/// address — the post-resume `push` repairs that slot in each process
/// before its `ret` (a plain Rust wrapper cannot do this; its `ret`
/// pops the child's garbage as `SIGILL`). The scratch register is
/// `rdx`: `syscall` itself destroys `rcx`/`r11`, so a popped `rcx`
/// would hand the child the kernel resume address as its return
/// (observed: child spins on `push`/`ret`, parent parks forever).
/// The error check is inline (`jae` on the unsigned `-4095` bound,
/// musl `__syscall_ret` shape); only the no-child error path calls
/// out ([`vfork_error`]).
///
/// # Safety
///
/// The child runs on the parent's stack: it must exec or exit without
/// returning from the calling function, touching only async-signal-safe
/// state. Returning corrupts the resumed parent.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
#[unsafe(naked)]
pub unsafe extern "C" fn vfork() -> c_int {
    core::arch::naked_asm!(
        "pop rdx",
        "mov eax, {nr}",
        "syscall",
        "push rdx",
        "cmp rax, -4095",
        "jae 2f",
        "ret",
        "2:",
        "mov rdi, rax",
        "call {err}",
        "ret",
        nr = const SYS_VFORK,
        err = sym vfork_error,
    )
}

/// Replace the process image (musl `execve`: one `SYS_execve` trap).
/// Returns only on error, with errno set.
///
/// # Safety
///
/// `path` must be a valid NUL-terminated string; `argv`/`envp` must be
/// NULL-terminated arrays of valid strings (either may be NULL only if
/// the kernel accepts it — pass an empty array, not NULL, for portable
/// empty environments).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn execve(
    path: *const c_char,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    unsafe {
        syscall_ret(syscall3(
            SYS_EXECVE,
            path as usize,
            argv as usize,
            envp as usize,
        )) as c_int
    }
}

/// Current environment for the `execv`/`execvp` family (musl
/// `__environ`). Under test the crate's `__environ` is compiled out,
/// so the host's `environ` is read instead (same layout, real `PATH`).
#[cfg(all(not(test), target_arch = "x86_64"))]
unsafe fn current_environ() -> *mut *mut c_char {
    unsafe { crate::start::__environ }
}
#[cfg(all(test, target_arch = "x86_64"))]
unsafe fn current_environ() -> *mut *mut c_char {
    unsafe {
        extern "C" {
            static environ: *mut *mut c_char;
        }
        environ
    }
}

/// Execute with the current environment (musl `execv`: `execve` with
/// `__environ`). Returns only on error, with errno set.
///
/// # Safety
///
/// Same contract as [`execve`] with `envp` supplied implicitly.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn execv(path: *const c_char, argv: *const *mut c_char) -> c_int {
    unsafe { execve(path, argv, current_environ()) }
}

/// Byte length capped at `max` (musl `strnlen`, local: no string wave).
///
/// # Safety
///
/// `s` must be readable up to the first NUL or `max` bytes.
#[cfg(target_arch = "x86_64")]
unsafe fn strnlen(s: *const c_char, max: usize) -> usize {
    unsafe {
        let mut n = 0usize;
        while n < max && s.add(n).read() != 0 {
            n = n.wrapping_add(1);
        }
        n
    }
}

/// First `c` or NUL (musl `__strchrnul`, local).
///
/// # Safety
///
/// `s` must be a valid NUL-terminated string.
#[cfg(target_arch = "x86_64")]
unsafe fn strchrnul(s: *const c_char, c: c_char) -> *const c_char {
    unsafe {
        let mut p = s;
        while p.read() != 0 && p.read() != c {
            p = p.wrapping_add(1);
        }
        p
    }
}

/// Whether the string contains a slash (musl `strchr(file, '/')`, local).
///
/// # Safety
///
/// Same contract as [`strchrnul`].
#[cfg(target_arch = "x86_64")]
unsafe fn has_slash(s: *const c_char) -> bool {
    unsafe {
        let mut p = s;
        loop {
            let c = p.read();
            if c == 0 {
                return false;
            }
            if c == b'/' as c_char {
                return true;
            }
            p = p.wrapping_add(1);
        }
    }
}

/// Copy `n` bytes (musl `memcpy`, local).
///
/// # Safety
///
/// `src` readable and `dst` writable for `n` bytes; ranges must not overlap.
#[cfg(target_arch = "x86_64")]
unsafe fn copy_bytes(dst: *mut c_char, src: *const c_char, n: usize) {
    unsafe {
        let mut i = 0usize;
        while i < n {
            dst.add(i).write(src.add(i).read());
            i = i.wrapping_add(1);
        }
    }
}

/// First `PATH` value for `name` (musl `getenv` scan, local: the real
/// one is `not(test)`-gated in `crate::start`).
///
/// # Safety
///
/// `envp` must be a NULL-terminated array of valid strings; `name`
/// must be a valid NUL-terminated string without `=`.
#[cfg(target_arch = "x86_64")]
unsafe fn getenv_in(envp: *const *mut c_char, name: *const c_char) -> *const c_char {
    unsafe {
        if envp.is_null() || name.is_null() {
            return null_mut();
        }
        let mut nl = 0usize;
        while name.add(nl).read() != 0 {
            nl = nl.wrapping_add(1);
        }
        let mut i = 0usize;
        loop {
            let e = envp.add(i).read();
            if e.is_null() {
                return null_mut();
            }
            let mut k = 0usize;
            while k < nl && e.add(k).read() == name.add(k).read() {
                k = k.wrapping_add(1);
            }
            if k == nl && e.add(nl).read() == b'=' as c_char {
                return e.add(nl.wrapping_add(1));
            }
            i = i.wrapping_add(1);
        }
    }
}

/// `PATH` search behind `execvp`/`execvpe` (musl `__execvpe`,
/// `src/process/execvp.c:9-58`, verbatim logic: `ENOENT` preset, empty
/// `file` rejected, slash path direct, overlong `file` is `ENAMETOOLONG`,
/// per-component `execve` retrying on `EACCES`/`ENOENT`/`ENOTDIR`,
/// trailing `EACCES` preferred). The VLA becomes a max-size stack
/// buffer (`PATH_MAX + NAME_MAX + 2`: `l` caps `PATH` at `PATH_MAX`,
/// `k` caps `file` at `NAME_MAX`, so every musl-accepted write fits).
/// Returns only on error, with errno set.
///
/// # Safety
///
/// `file` must be a valid non-empty NUL-terminated string; `argv`/`envp`
/// follow [`execve`].
#[cfg(target_arch = "x86_64")]
unsafe fn execvpe_search(
    file: *const c_char,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    unsafe {
        const PATH_MAX: usize = 4096; // musl include/limits.h: PATH_MAX
        const NAME_MAX: usize = 255; // musl include/limits.h: NAME_MAX
        const DEFAULT_PATH: &[u8] = b"/usr/local/bin:/bin:/usr/bin\0";
        errno_store(__errno_location(), ENOENT);
        if file.read() == 0 {
            return -1;
        }
        if has_slash(file) {
            return execve(file, argv, envp);
        }
        let mut path = getenv_in(current_environ() as *const *mut c_char, c"PATH".as_ptr());
        if path.is_null() {
            path = DEFAULT_PATH.as_ptr() as *const c_char;
        }
        let k = strnlen(file, NAME_MAX.wrapping_add(1));
        if k > NAME_MAX {
            errno_store(__errno_location(), ENAMETOOLONG);
            return -1;
        }
        let l = strnlen(path, PATH_MAX.wrapping_sub(1)).wrapping_add(1);
        let mut b = [0 as c_char; PATH_MAX + NAME_MAX + 2];
        let mut p = path;
        let mut seen_eacces = false;
        loop {
            let z = strchrnul(p, b':' as c_char);
            let seg = (z as usize).wrapping_sub(p as usize);
            if seg >= l {
                if z.read() == 0 {
                    break;
                }
                p = z.wrapping_add(1);
                continue;
            }
            copy_bytes(b.as_mut_ptr(), p, seg);
            b[seg] = b'/' as c_char;
            let off = seg.wrapping_add(if z > p { 1 } else { 0 });
            copy_bytes(b.as_mut_ptr().wrapping_add(off), file, k.wrapping_add(1));
            execve(b.as_ptr(), argv, envp);
            let e = errno_load(__errno_location());
            if e == EACCES {
                seen_eacces = true;
            } else if e != ENOENT && e != ENOTDIR {
                return -1;
            }
            if z.read() == 0 {
                break;
            }
            p = z.wrapping_add(1);
        }
        if seen_eacces {
            errno_store(__errno_location(), EACCES);
        }
        -1
    }
}

/// Search `PATH` with the current environment (musl `execvp`).
/// Returns only on error, with errno set.
///
/// # Safety
///
/// Same contract as [`execvpe_search`] with `envp` supplied implicitly.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn execvp(file: *const c_char, argv: *const *mut c_char) -> c_int {
    unsafe { execvpe_search(file, argv, current_environ()) }
}

/// Search `PATH` with an explicit environment (musl `execvpe`; spelled
/// as a direct wrapper, not a weak alias — no alias machinery here).
/// Returns only on error, with errno set.
///
/// # Safety
///
/// Same contract as [`execvpe_search`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn execvpe(
    file: *const c_char,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    unsafe { execvpe_search(file, argv, envp) }
}

// ---- SysV vararg reading (execl family) --------------------------------------
// Same shape as the `crate::stdio` trampolines (see its docs for the
// layout proof): spill the caller's GP/XMM file into a private area,
// stage a tag, tail-call the inner. All three entries have two named GP
// args (`rdi`, `rsi`), so `...` starts at `rdx` (`gp` = 16); overflow is
// the first stack arg above the return address. Every slot read here is
// an 8-byte pointer, so only the GP cursor moves.

/// C `va_list` for x86_64 SysV (same four words as `crate::stdio`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
struct VaList {
    gp: u32,
    fp: u32,
    overflow: *mut u8,
    regsave: *mut u8,
}

/// Next vararg pointer (registers, then overflow stack).
///
/// # Safety
///
/// `tag` must be a live tag staged by the trampoline (or a test-built
/// equivalent) with a pointer slot remaining.
#[cfg(target_arch = "x86_64")]
unsafe fn va_next(tag: *mut VaList) -> *mut c_void {
    unsafe {
        let t = &mut *tag;
        if t.gp < 48 {
            let v = (t.regsave.add(t.gp as usize) as *const usize).read_unaligned();
            t.gp = t.gp.wrapping_add(8);
            v as *mut c_void
        } else {
            let v = (t.overflow as *const usize).read_unaligned();
            t.overflow = t.overflow.wrapping_add(8);
            v as *mut c_void
        }
    }
}

/// Collect `argv0` plus the NULL-terminated varargs into a fresh
/// NULL-terminated array on the caller's stack frame (musl's counting
/// pass + VLA, with a fixed 256-slot buffer in place of the VLA: no
/// heap, so the `execl` family stays fork-safe — a fork-child blocked
/// on a `malloc` lock held at fork time would wedge the parent's
/// `waitpid` and, under test, the suite; longer lists fail `E2BIG`).
/// Returns the slot count incl. NULL, or 0 with `E2BIG` set.
///
/// # Safety
///
/// `tag` must hold a NULL-terminated pointer list after `argv0`;
/// `slots` must fit 256 pointers.
#[cfg(target_arch = "x86_64")]
unsafe fn collect_argv(argv0: *const c_char, tag: *mut VaList, slots: *mut *mut c_char) -> usize {
    unsafe {
        const CAP: usize = 256;
        let mut cur = *tag;
        let mut argc = 1usize;
        while !va_next(&mut cur).is_null() {
            argc = argc.wrapping_add(1);
            if argc >= CAP {
                syscall_ret(-(E2BIG as isize));
                return 0;
            }
        }
        slots.write(argv0 as *mut c_char);
        let mut fill = *tag;
        let mut i = 1usize;
        loop {
            let a = va_next(&mut fill);
            if a.is_null() {
                break;
            }
            slots.add(i).write(a as *mut c_char);
            i = i.wrapping_add(1);
        }
        slots.add(i).write(null_mut());
        argc.wrapping_add(1)
    }
}

/// `execl` body: collect, `execv` (error-only tail; the slots die
/// with the frame, no free).
///
/// # Safety
///
/// `path` valid; `tag` a NULL-terminated pointer list after `argv0`.
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn execl_inner(
    path: *const c_char,
    argv0: *const c_char,
    tag: *mut VaList,
) -> c_int {
    unsafe {
        let mut slots = [null_mut::<c_char>(); 256];
        if collect_argv(argv0, tag, slots.as_mut_ptr()) == 0 {
            return -1;
        }
        execv(path, slots.as_ptr())
    }
}

/// `execle` body: collect, take `envp` past the NULL, `execve`
/// (slots die with the frame, no free).
///
/// # Safety
///
/// Like [`execl_inner`], plus a valid `envp` pointer after the NULL.
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn execle_inner(
    path: *const c_char,
    argv0: *const c_char,
    tag: *mut VaList,
) -> c_int {
    unsafe {
        let mut slots = [null_mut::<c_char>(); 256];
        if collect_argv(argv0, tag, slots.as_mut_ptr()) == 0 {
            return -1;
        }
        let mut cur = *tag;
        while !va_next(&mut cur).is_null() {}
        let envp = va_next(&mut cur) as *const *mut c_char;
        execve(path, slots.as_ptr(), envp)
    }
}

/// `execlp` body: collect, `execvp` (slots die with the frame).
///
/// # Safety
///
/// Like [`execl_inner`] with `file` in place of `path`.
#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn execlp_inner(
    file: *const c_char,
    argv0: *const c_char,
    tag: *mut VaList,
) -> c_int {
    unsafe {
        let mut slots = [null_mut::<c_char>(); 256];
        if collect_argv(argv0, tag, slots.as_mut_ptr()) == 0 {
            return -1;
        }
        execvp(file, slots.as_ptr())
    }
}

/// C-variadic entry: spill the caller's register file and tail-call the
/// inner (see the layout note above; `gp` = 16 named-word offset,
/// tag delivered in `rdx` after the two named args).
///
/// # Safety
///
/// The caller's `...` must be a NULL-terminated pointer list
/// (`execle` additionally needs `envp` past the NULL).
#[cfg(target_arch = "x86_64")]
macro_rules! exec_trampoline {
    ($name:ident, $inner:ident) => {
        /// Variadic exec entry: spills the caller's register file and
        /// tail-calls the inner collector (same shape as the stdio
        /// trampoline).
        ///
        /// # Safety
        ///
        /// The caller's `...` must be a NULL-terminated pointer list
        /// (`execle` additionally needs `envp` past the NULL). Diverges
        /// into the new image on success.
        #[no_mangle]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "mov rax, rsp",
                "sub rsp, 312",
                "mov [rsp], rdi",
                "mov [rsp+8], rsi",
                "mov [rsp+16], rdx",
                "mov [rsp+24], rcx",
                "mov [rsp+32], r8",
                "mov [rsp+40], r9",
                "movups [rsp+48], xmm0",
                "movups [rsp+64], xmm1",
                "movups [rsp+80], xmm2",
                "movups [rsp+96], xmm3",
                "movups [rsp+112], xmm4",
                "movups [rsp+128], xmm5",
                "movups [rsp+144], xmm6",
                "movups [rsp+160], xmm7",
                "mov dword ptr [rsp+176], 16",
                "mov dword ptr [rsp+180], 48",
                "lea rcx, [rax+8]",
                "mov [rsp+184], rcx",
                "mov [rsp+192], rsp",
                "lea rdx, [rsp+176]",
                "call {inner}",
                "add rsp, 312",
                "ret",
                inner = sym $inner,
            )
        }
    };
}

#[cfg(target_arch = "x86_64")]
exec_trampoline!(execl, execl_inner);
#[cfg(target_arch = "x86_64")]
exec_trampoline!(execle, execle_inner);
#[cfg(target_arch = "x86_64")]
exec_trampoline!(execlp, execlp_inner);

/// Empty path for `execveat` (musl passes `""`).
#[cfg(target_arch = "x86_64")]
static EMPTY_PATH: [u8; 1] = [0];

/// Execute via an open fd (musl `fexecve`, `src/process/fexecve.c`:
/// `execveat(AT_EMPTY_PATH)`, falling back to `/proc/self/fd/N` when
/// the kernel lacks it; `ENOENT` from the fallback means `EBADF`).
/// Returns only on error, with errno set.
///
/// # Safety
///
/// `fd` must be open (executable); `argv`/`envp` follow [`execve`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fexecve(
    fd: c_int,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    unsafe {
        const AT_EMPTY_PATH: c_int = 0x1000; // musl include/fcntl.h:102
        let r = syscall5(
            SYS_EXECVEAT,
            fd as usize,
            EMPTY_PATH.as_ptr() as usize,
            argv as usize,
            envp as usize,
            AT_EMPTY_PATH as usize,
        );
        if r != -(ENOSYS as isize) {
            return syscall_ret(r) as c_int;
        }
        let mut buf = [0u8; 32];
        let prefix = b"/proc/self/fd/";
        let mut n = 0usize;
        while n < prefix.len() {
            buf[n] = prefix[n];
            n = n.wrapping_add(1);
        }
        let mag = if fd < 0 {
            buf[n] = b'-';
            n = n.wrapping_add(1);
            (fd as i64).wrapping_neg() as u64
        } else {
            fd as u64
        };
        let mut tmp = [0u8; 12];
        let mut nd = 0usize;
        let mut m = mag;
        loop {
            tmp[nd] = b'0'.wrapping_add((m % 10) as u8);
            nd = nd.wrapping_add(1);
            m /= 10;
            if m == 0 {
                break;
            }
        }
        while nd > 0 {
            nd = nd.wrapping_sub(1);
            buf[n] = tmp[nd];
            n = n.wrapping_add(1);
        }
        buf[n] = 0;
        execve(buf.as_ptr() as *const c_char, argv, envp);
        if errno_load(__errno_location()) == ENOENT {
            errno_store(__errno_location(), EBADF);
        }
        -1
    }
}

/// Wait for any child (musl `wait`: `waitpid(-1, status, 0)`).
///
/// # Safety
///
/// `status` must be null or writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wait(status: *mut c_int) -> c_int {
    unsafe { waitpid(-1, status, 0) }
}

/// Wait for a child (musl `waitpid`: one `SYS_wait4` trap with a NULL
/// `rusage`; no cancel point — cancellation does not exist here).
///
/// # Safety
///
/// `status` must be null or writable; `pid`/`options` are kernel-checked.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int {
    unsafe {
        syscall_ret(syscall4(
            SYS_WAIT4,
            pid as usize,
            status as usize,
            options as usize,
            0,
        )) as c_int
    }
}

/// Wait with resource usage (musl `wait4`, `src/linux/wait4.c` minus the
/// time64 shim: x86_64 `time_t` is 64-bit, so one `SYS_wait4` trap
/// writes [`RUsage`] directly).
///
/// # Safety
///
/// `status`/`ru` must each be null or writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wait4(
    pid: c_int,
    status: *mut c_int,
    options: c_int,
    ru: *mut RUsage,
) -> c_int {
    unsafe {
        syscall_ret(syscall4(
            SYS_WAIT4,
            pid as usize,
            status as usize,
            options as usize,
            ru as usize,
        )) as c_int
    }
}

/// Wait for any child with usage (musl `wait3`: `wait4(-1, ...)`).
///
/// # Safety
///
/// Same contract as [`wait4`] with `pid` fixed to -1.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wait3(status: *mut c_int, options: c_int, ru: *mut RUsage) -> c_int {
    unsafe { wait4(-1, status, options, ru) }
}

/// Extended wait status (musl `waitid`: one `SYS_waitid` trap, NULL
/// `rusage`; no cancel point).
///
/// # Safety
///
/// `infop` must be null or point to a writable [`Siginfo`];
/// `idtype`/`id`/`options` are kernel-checked (`id` is musl `id_t`).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn waitid(
    idtype: c_int,
    id: u32,
    infop: *mut Siginfo,
    options: c_int,
) -> c_int {
    unsafe {
        syscall_ret(syscall5(
            SYS_WAITID,
            idtype as usize,
            id as usize,
            infop as usize,
            options as usize,
            0,
        )) as c_int
    }
}

/// Diverging child exit without handlers (the `crate::exit::_Exit`
/// trap shape, local so tests can use it: `SYS_exit_group` then
/// `SYS_exit` forever; never touches errno or locks).
#[cfg(target_arch = "x86_64")]
unsafe fn child_halt(code: c_int) -> ! {
    unsafe {
        syscall1(SYS_EXIT_GROUP, code as usize);
        loop {
            syscall1(SYS_EXIT, code as usize);
        }
    }
}

/// Run a shell command (musl `system.c` shape with fork+exec in place
/// of `posix_spawn`, which is the next wave: `NULL` returns 1;
/// `SIGINT`/`SIGQUIT` ignored and `SIGCHLD` blocked around the fork;
/// the child restores the mask, resets non-ignored `INT`/`QUIT` to
/// default, and execs `/bin/sh -c` — an absolute path, so `execlp`
/// would take the same direct-`execve` path; the parent `waitpid`s
/// through `EINTR` and restores both dispositions and the mask).
///
/// # Safety
///
/// `cmd` must be null or a valid NUL-terminated string. Blocks until
/// the shell exits; returns its wait status (`-1` with errno on fork
/// failure).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn system(cmd: *const c_char) -> c_int {
    unsafe {
        if cmd.is_null() {
            return 1;
        }
        let ign = Sigaction {
            handler: SIG_IGN,
            mask: [0; 16],
            flags: 0,
            restorer: 0,
        };
        let mut oldint: Sigaction = core::mem::zeroed();
        let mut oldquit: Sigaction = core::mem::zeroed();
        let mut old: sigset_t = [0; 16];
        sigaction(SIGINT, &ign, &mut oldint);
        sigaction(SIGQUIT, &ign, &mut oldquit);
        let mut blk: sigset_t = [0; 16];
        sigemptyset(&mut blk);
        sigaddset(&mut blk, SIGCHLD);
        sigprocmask(SIG_BLOCK, &blk, &mut old);
        let mut reset: sigset_t = [0; 16];
        sigemptyset(&mut reset);
        if oldint.handler != SIG_IGN {
            sigaddset(&mut reset, SIGINT);
        }
        if oldquit.handler != SIG_IGN {
            sigaddset(&mut reset, SIGQUIT);
        }
        let pid = fork();
        let mut status = -1;
        if pid == 0 {
            sigprocmask(SIG_SETMASK, &old, null_mut());
            if oldint.handler != SIG_IGN {
                let dfl = Sigaction {
                    handler: SIG_DFL,
                    mask: [0; 16],
                    flags: 0,
                    restorer: 0,
                };
                sigaction(SIGINT, &dfl, null_mut());
            }
            if oldquit.handler != SIG_IGN {
                let dfl = Sigaction {
                    handler: SIG_DFL,
                    mask: [0; 16],
                    flags: 0,
                    restorer: 0,
                };
                sigaction(SIGQUIT, &dfl, null_mut());
            }
            let sh = c"/bin/sh".as_ptr();
            let argv = [
                c"sh".as_ptr() as *mut c_char,
                c"-c".as_ptr() as *mut c_char,
                cmd as *mut c_char,
                null_mut(),
            ];
            execve(sh, argv.as_ptr(), current_environ());
            child_halt(127);
        }
        if pid > 0 {
            while waitpid(pid, &mut status, 0) < 0 && errno_load(__errno_location()) == EINTR {}
        }
        sigaction(SIGINT, &oldint, null_mut());
        sigaction(SIGQUIT, &oldquit, null_mut());
        sigprocmask(SIG_SETMASK, &old, null_mut());
        status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::{c_char, c_int, c_void};

    use crate::fcntl::{open, O_RDONLY};
    use crate::syscall::syscall3;
    use crate::unistd::{close, pipe, read};

    /// musl `arch/generic/bits/errno.h:10` (waitpid reap proof).
    const ECHILD: c_int = 10;

    /// musl `arch/x86_64/bits/syscall.h.in` (vfork-child write).
    const SYS_WRITE: usize = 1;

    // musl include/sys/wait.h:48-53, values re-verified (see module docs).
    fn wifexited(s: c_int) -> bool {
        (s & 0x7f) == 0
    }
    fn wexitstatus(s: c_int) -> c_int {
        (s & 0xff00) >> 8
    }

    // Our own C-variadic symbols (naked trampolines): foreign `...`
    // declarations are stable to *call* (same pattern as stdio tests).
    extern "C" {
        fn execl(path: *const c_char, ...) -> c_int;
        fn execlp(file: *const c_char, ...) -> c_int;
        fn execle(path: *const c_char, ...) -> c_int;
    }

    #[test]
    fn fork_child_exit_waitpid_decode() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut status = 0;
            let pid = fork();
            assert!(pid >= 0);
            if pid == 0 {
                child_halt(7);
            }
            assert_eq!(waitpid(pid, &mut status, 0), pid);
            assert!(wifexited(status));
            assert_eq!(wexitstatus(status), 7);
            // Reaped: no zombie left behind.
            assert_eq!(waitpid(pid, &mut status, 0), -1);
            assert_eq!(errno_load(__errno_location()), ECHILD);
        }
    }

    #[test]
    fn execvp_true_exits_zero() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let pid = fork();
            assert!(pid >= 0);
            if pid == 0 {
                let argv = [c"true".as_ptr() as *mut c_char, null_mut()];
                execvp(c"true".as_ptr(), argv.as_ptr());
                child_halt(127);
            }
            let mut status = 0;
            assert_eq!(waitpid(pid, &mut status, 0), pid);
            assert!(wifexited(status));
            assert_eq!(wexitstatus(status), 0);
        }
    }

    #[test]
    fn execlp_trampoline_execs_true() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let pid = fork();
            assert!(pid >= 0);
            if pid == 0 {
                // Real variadic call through the naked trampoline
                // (register varargs: argv + NULL in rsi/rdx).
                execlp(
                    c"true".as_ptr(),
                    c"true".as_ptr(),
                    core::ptr::null::<c_char>(),
                );
                child_halt(99);
            }
            let mut status = 0;
            assert_eq!(waitpid(pid, &mut status, 0), pid);
            assert!(wifexited(status));
            assert_eq!(wexitstatus(status), 0);
        }
    }

    #[test]
    fn execl_bad_path_returns_enoent() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            // No fork: exec failure returns in-process.
            let r = execl(
                c"/nonexistent-zlibc-xyz".as_ptr(),
                c"x".as_ptr(),
                core::ptr::null::<c_char>(),
            );
            assert_eq!(r, -1);
            assert_eq!(errno_load(__errno_location()), ENOENT);
        }
    }

    #[test]
    fn vararg_walker_covers_overflow_and_envp() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            // Mixed tag: two pointers in registers (gp 16..32), two plus
            // NULL on the overflow stack — exercises both walker arms.
            let mut regs = [0u64; 6];
            regs[2] = c"b1".as_ptr() as u64;
            regs[3] = c"b2".as_ptr() as u64;
            let mut over = [c"b3".as_ptr() as u64, c"b4".as_ptr() as u64, 0u64];
            let mut tag = VaList {
                gp: 16,
                fp: 48,
                overflow: over.as_mut_ptr() as *mut u8,
                regsave: regs.as_mut_ptr() as *mut u8,
            };
            let r = execl_inner(
                c"/nonexistent-zlibc-xyz".as_ptr(),
                c"argv0".as_ptr(),
                &mut tag,
            );
            assert_eq!(r, -1);
            assert_eq!(errno_load(__errno_location()), ENOENT);
            // execle: envp sits past the NULL terminator.
            let env = [c"PATH=/bin:/usr/bin".as_ptr() as *mut c_char, null_mut()];
            let mut regs2 = [0u64; 6];
            regs2[2] = c"only".as_ptr() as u64;
            regs2[3] = 0;
            regs2[4] = env.as_ptr() as u64;
            let mut tag2 = VaList {
                gp: 16,
                fp: 48,
                overflow: core::ptr::null_mut(),
                regsave: regs2.as_mut_ptr() as *mut u8,
            };
            let r2 = execle_inner(
                c"/nonexistent-zlibc-xyz".as_ptr(),
                c"argv0".as_ptr(),
                &mut tag2,
            );
            assert_eq!(r2, -1);
            assert_eq!(errno_load(__errno_location()), ENOENT);
        }
    }

    #[test]
    fn execle_decl_links_and_fails_clean() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let env = [c"PATH=/bin:/usr/bin".as_ptr() as *mut c_char, null_mut()];
            let r = execle(
                c"/nonexistent-zlibc-xyz".as_ptr(),
                c"x".as_ptr(),
                core::ptr::null::<c_char>(),
                env.as_ptr() as *const c_char,
            );
            assert_eq!(r, -1);
            assert_eq!(errno_load(__errno_location()), ENOENT);
        }
    }

    #[test]
    fn fexecve_true_exits_zero() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut fd = open(c"/bin/true".as_ptr(), O_RDONLY, 0);
            if fd < 0 {
                fd = open(c"/usr/bin/true".as_ptr(), O_RDONLY, 0);
            }
            assert!(fd >= 0);
            let pid = fork();
            assert!(pid >= 0);
            if pid == 0 {
                let argv = [c"true".as_ptr() as *mut c_char, null_mut()];
                fexecve(fd, argv.as_ptr(), current_environ());
                child_halt(127);
            }
            assert_eq!(close(fd), 0);
            let mut status = 0;
            assert_eq!(waitpid(pid, &mut status, 0), pid);
            assert!(wifexited(status));
            assert_eq!(wexitstatus(status), 0);
        }
    }

    #[test]
    fn two_children_reaped_in_any_order() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let p1 = fork();
            assert!(p1 >= 0);
            if p1 == 0 {
                child_halt(11);
            }
            let p2 = fork();
            assert!(p2 >= 0);
            if p2 == 0 {
                child_halt(12);
            }
            // Specific-pid reaps only (a `-1` wait here could harvest a
            // sibling test's spawned child; see below).
            let mut s = 0;
            assert_eq!(waitpid(p1, &mut s, 0), p1);
            assert!(wifexited(s));
            let e1 = wexitstatus(s);
            assert_eq!(waitpid(p2, &mut s, 0), p2);
            assert!(wifexited(s));
            let e2 = wexitstatus(s);
            assert!((e1 == 11 && e2 == 12) || (e1 == 12 && e2 == 11));
            // Both reaped: specific probes report ECHILD, no zombies.
            assert_eq!(waitpid(p1, &mut s, WNOHANG), -1);
            assert_eq!(waitpid(p2, &mut s, WNOHANG), -1);
            assert_eq!(errno_load(__errno_location()), ECHILD);
        }
    }

    /// `wait`/`wait3` need a `-1` wait, which must never run where
    /// sibling tests spawn (it would harvest their children, and block
    /// until one exits when none of ours remain). So the real `-1`
    /// sequence runs in a spawned copy of this binary, whose child
    /// table holds only the two children forked below (same
    /// out-of-process pattern as the malloc death tests).
    #[test]
    fn wait_and_wait3_under_empty_table() {
        if std::env::var("ZLIBC_WAIT_SELF").is_ok() {
            unsafe {
                let p1 = fork();
                assert!(p1 >= 0);
                if p1 == 0 {
                    child_halt(11);
                }
                let p2 = fork();
                assert!(p2 >= 0);
                if p2 == 0 {
                    child_halt(12);
                }
                let mut s = 0;
                let q1 = wait(&mut s);
                assert!(q1 == p1 || q1 == p2);
                assert!(wifexited(s));
                let e1 = wexitstatus(s);
                let mut ru: RUsage = core::mem::zeroed();
                let q2 = wait3(&mut s, 0, &mut ru);
                assert!(q2 == p1 || q2 == p2);
                assert!(q2 != q1);
                assert!(wifexited(s));
                let e2 = wexitstatus(s);
                assert!((e1 == 11 && e2 == 12) || (e1 == 12 && e2 == 11));
                // Table provably empty: immediate -1/ECHILD, no block.
                assert_eq!(wait(&mut s), -1);
                assert_eq!(errno_load(__errno_location()), ECHILD);
            }
            return;
        }
        let me = std::env::current_exe().unwrap();
        let st = std::process::Command::new(me)
            .env("ZLIBC_WAIT_SELF", "1")
            .arg("--exact")
            .arg("process::tests::wait_and_wait3_under_empty_table")
            .arg("--test-threads=1")
            .status()
            .unwrap();
        assert!(st.success());
    }

    // NOTE: no direct wait3() test here by design. wait3() waits for ANY
    // child, so in a parallel forking suite it harvests siblings' children
    // (observed: reaped pid != ours; also starves std::process::Command's
    // internal waitpid with ECHILD). Coverage: wait4_targets_one_pid checks
    // rusage via specific-pid wait4, and wait_and_wait3_under_empty_table
    // exercises wait3() inside an isolated child binary with an empty table.
    #[test]
    fn wait4_targets_one_pid() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let pid = fork();
            assert!(pid >= 0);
            if pid == 0 {
                child_halt(4);
            }
            let mut status = 0;
            let mut ru: RUsage = core::mem::zeroed();
            assert_eq!(wait4(pid, &mut status, 0, &mut ru), pid);
            assert!(wifexited(status));
            assert_eq!(wexitstatus(status), 4);
            assert_eq!(waitpid(pid, &mut status, 0), -1);
            assert_eq!(errno_load(__errno_location()), ECHILD);
        }
    }

    #[test]
    fn waitid_reports_exit() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let pid = fork();
            assert!(pid >= 0);
            if pid == 0 {
                child_halt(5);
            }
            let mut si: Siginfo = core::mem::zeroed();
            assert_eq!(waitid(P_PID, pid as u32, &mut si, WEXITED), 0);
            assert_eq!(si.si_pid, pid);
            assert_eq!(si.si_code, CLD_EXITED);
            assert_eq!(si.si_value.sival_int, 5);
            // Reaped (no WNOWAIT): no zombie left behind.
            let mut status = 0;
            assert_eq!(waitpid(pid, &mut status, 0), -1);
            assert_eq!(errno_load(__errno_location()), ECHILD);
        }
    }

    #[test]
    fn vfork_child_writes_pipe_byte() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            static B: u8 = b'v';
            let mut fds = [0 as c_int; 2];
            assert_eq!(pipe(fds.as_mut_ptr()), 0);
            let pid = vfork();
            assert!(pid >= 0);
            if pid == 0 {
                // Shared stack: raw traps only, then out.
                syscall3(SYS_WRITE, fds[1] as usize, &B as *const u8 as usize, 1);
                child_halt(0);
            }
            let mut status = 0;
            assert_eq!(waitpid(pid, &mut status, 0), pid);
            assert!(wifexited(status));
            assert_eq!(wexitstatus(status), 0);
            let mut got = 0u8;
            assert_eq!(read(fds[0], &mut got as *mut u8 as *mut c_void, 1), 1);
            assert_eq!(got, b'v');
            assert_eq!(close(fds[0]), 0);
            assert_eq!(close(fds[1]), 0);
        }
    }

    #[test]
    fn system_exit_code_and_null() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            assert_eq!(system(core::ptr::null()), 1);
            assert_eq!(system(c"exit 3".as_ptr()), 3 << 8);
        }
    }

    #[test]
    fn waitpid_no_child_is_echild() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut status = 0;
            // No live children under the lock: immediate -1/ECHILD.
            assert_eq!(waitpid(c_int::MAX, &mut status, WNOHANG), -1);
            assert_eq!(errno_load(__errno_location()), ECHILD);
        }
    }
}
