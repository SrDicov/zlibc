//! Process entry, libc boot, and process exit (x86_64).
//!
//! Clean-room mirrors of musl `arch/x86_64/crt_arch.h` (`_start`),
//! `crt/crt1.c` (`_start_c`), `src/env/__libc_start_main.c`
//! (`__init_libc`, `__libc_start_main`), `src/env/__stack_chk_fail.c`
//! (`__stack_chk_guard`, `__init_ssp`), `src/internal/libc.h:20-31`
//! (`struct __libc`), and `src/exit/exit.c` + `src/exit/_Exit.c`
//! (`exit`, `_Exit`). Layouts are re-derived from the cited sources;
//! no musl code is copied.
//!
//! Boot/exit symbols are `#[cfg(not(test))]`: under `cargo test` the host
//! toolchain owns `_start`/`exit`, and redefining them here would hijack
//! the test harness itself. Tests therefore cover only the pure auxv-table
//! fill; `_start`/`exit` are never executed in tests.

#[cfg(not(test))]
use core::ffi::c_long;
use core::ffi::{c_char, c_int, c_schar, c_void};
#[cfg(not(test))]
use core::sync::atomic::{AtomicI32, Ordering};

/// musl `arch/x86_64/bits/syscall.h.in:61` (`__NR_exit`).
pub const SYS_EXIT: usize = 60; // TODO: generate from arch bits/syscall.h
/// musl `arch/x86_64/bits/syscall.h.in:232` (`__NR_exit_group`).
pub const SYS_EXIT_GROUP: usize = 231; // TODO: generate from arch bits/syscall.h

/// musl `src/env/__libc_start_main.c:18` (`AUX_CNT`).
pub const AUX_CNT: usize = 38;

// Auxv keys (musl `include/elf.h`, line cited per key).
pub const AT_NULL: usize = 0; // include/elf.h:1003
pub const AT_PAGESZ: usize = 6; // include/elf.h:1009
pub const AT_UID: usize = 11; // include/elf.h:1014
pub const AT_EUID: usize = 12; // include/elf.h:1015
pub const AT_GID: usize = 13; // include/elf.h:1016
pub const AT_EGID: usize = 14; // include/elf.h:1017
pub const AT_HWCAP: usize = 16; // include/elf.h:1022
pub const AT_EXECFN: usize = 31; // include/elf.h:1037
pub const AT_SECURE: usize = 23; // include/elf.h:1038
pub const AT_RANDOM: usize = 25; // include/elf.h:1042

/// musl `struct __libc` (src/internal/libc.h:20-31), re-derived layout.
#[repr(C)]
pub struct Libc {
    pub can_do_threads: c_char,
    pub threaded: c_char,
    pub secure: c_char,
    /// C `volatile signed char`: same size/offset; every access MUST go
    /// through `read_volatile`/`write_volatile` (same rule as
    /// `abi::IoFile.lock`).
    pub need_locks: c_schar,
    pub threads_minus_1: c_int,
    pub auxv: *mut usize,
    /// Opaque until B2 owns `struct tls_module` via `crate::ldso::dso`.
    pub tls_head: *mut c_void,
    pub tls_size: usize,
    pub tls_align: usize,
    pub tls_cnt: usize,
    pub page_size: usize,
    /// musl `struct __locale_struct` (`cat[6]`, libc.h:10-12): locale maps.
    pub global_locale: [*const c_void; 6],
}

/// musl `src/internal/libc.h:37` (`extern hidden struct __libc __libc`).
#[cfg(not(test))]
#[no_mangle]
pub static mut __libc: Libc = Libc {
    can_do_threads: 0,
    threaded: 0,
    secure: 0,
    need_locks: 0,
    threads_minus_1: 0,
    auxv: core::ptr::null_mut(),
    tls_head: core::ptr::null_mut(),
    tls_size: 0,
    tls_align: 0,
    tls_cnt: 0,
    page_size: 0,
    global_locale: [core::ptr::null(); 6],
};

/// musl `src/internal/libc.h:49` (`extern hidden size_t __hwcap`).
#[cfg(not(test))]
#[no_mangle]
pub static mut __hwcap: usize = 0;

/// musl `char *__progname/__progname_full` (`src/internal/libc.c:6`),
/// initialized from `argv[0]` in [`__init_libc`]. Initialized to the
/// empty string rather than null: a zero-initialized `static mut` is
/// emitted as a COMMON symbol, and the `.set` alias below requires a
/// strong definition ("changed binding to STB_GLOBAL" otherwise). musl
/// holds NULL until `__init_libc`; nothing can observe ours before
/// `__init_libc` overwrites it on the same path.
#[cfg(not(test))]
#[no_mangle]
pub static mut __progname: *mut c_char = c"".as_ptr() as *mut c_char;
/// musl `char *__progname_full` (`src/internal/libc.c:6`): `argv[0]` whole.
#[cfg(not(test))]
#[no_mangle]
pub static mut __progname_full: *mut c_char = c"".as_ptr() as *mut c_char;

// musl `src/internal/libc.c:8-9`: both pointers are also visible under
// their `program_invocation_*` names. `weak_alias!` is plain `.weak` +
// `.set`, so it aliases data exactly like functions. Note the argument
// order is `(new, old)` — the reverse of musl's `weak_alias(old, new)`
// — getting it backwards declares the real symbol weak and fails the
// build with "changed binding to STB_GLOBAL".
#[cfg(not(test))]
crate::weak_alias!(program_invocation_short_name, __progname);
#[cfg(not(test))]
crate::weak_alias!(program_invocation_name, __progname_full);

/// musl `src/env/__stack_chk_fail.c:5` (`uintptr_t __stack_chk_guard`).
#[cfg(not(test))]
#[no_mangle]
pub static mut __stack_chk_guard: usize = 0;

/// Process entry (x86_64). Replicates musl `arch/x86_64/crt_arch.h`:
/// clear `rbp`, pass the initial `rsp` as `_start_c`'s argument, take the
/// (weak, hidden) `_DYNAMIC` address in `rsi`, align `rsp` to 16, then
/// call `_start_c`. Rust emits the `.global`/`.type`; `#[naked]` emits no
/// prologue. Template is Intel syntax for the same instructions.
///
/// # Safety
///
/// The kernel jumps here once with `rsp` pointing at `argc`. Never returns
/// and never callable from Rust.
#[cfg(not(test))]
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "xor rbp, rbp",
        "mov rdi, rsp",
        ".weak _DYNAMIC",
        ".hidden _DYNAMIC",
        "lea rsi, [rip + _DYNAMIC]",
        "and rsp, -16",
        "call _start_c",
        "ud2",
    )
}

/// musl `_start_c` (crt/crt1.c:14-19): `argc = p[0]`, `argv = p+1`, then
/// `__libc_start_main(main, argc, argv, _init, _fini, 0)`. Diverges like
/// its only caller promises (`_start` traps on fallthrough anyway).
///
/// # Safety
///
/// `sp` must point at the kernel stack words (`argc`, then `argc` argument
/// pointers, then `envp`, then auxv). Called once, from `_start`.
#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "C" fn _start_c(sp: *const c_long) -> ! {
    let argc = unsafe { sp.read() } as c_int;
    let argv = sp.wrapping_add(1) as *mut *mut c_char;
    unsafe { __libc_start_main(main, argc, argv, _init, _fini, core::ptr::null_mut()) };
    loop {
        core::hint::spin_loop();
    }
}

/// musl `__libc_start_main` (src/env/__libc_start_main.c:72-87): derive
/// `envp` (`argv + argc + 1`), run `__init_libc`, then the stage-2 tail in
/// a `#[inline(never)]` helper so the init stack frame cannot persist for
/// the process lifetime (musl's asm-barrier intent, lines 82-86). The
/// `_init`/`_fini`/`_ldso` params are ignored exactly like musl ignores
/// them.
///
/// # Safety
///
/// `argv` must point at `argc` valid argument pointers followed by `envp`;
/// `main` must be the application entry. Called once, from `_start_c`.
#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "C" fn __libc_start_main(
    main: unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) -> c_int,
    argc: c_int,
    argv: *mut *mut c_char,
    _init: unsafe extern "C" fn(),
    _fini: unsafe extern "C" fn(),
    _ldso: *mut c_void,
) -> c_int {
    let envp = argv.wrapping_add(argc as usize + 1);
    unsafe { __init_libc(envp, argv.read() as *const c_char) };
    unsafe { libc_start_main_stage2(main, argc, argv) }
}

/// musl `libc_start_main_stage2` (__libc_start_main.c:89-97): run init
/// hooks, hand control to `main`, pass its status to `exit`.
///
/// # Safety
///
/// Same contract as `__libc_start_main`. Never returns (`exit` diverges).
#[cfg(not(test))]
#[inline(never)]
unsafe fn libc_start_main_stage2(
    main: unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) -> c_int,
    argc: c_int,
    argv: *mut *mut c_char,
) -> c_int {
    unsafe { __libc_start_init() };
    let envp = argv.wrapping_add(argc as usize + 1);
    unsafe { exit(main(argc, argv, envp)) }
}

/// Basename scan for [`__progname`] (musl `__libc_start_main.c:37`):
/// advance past every `/`, so `__progname` points just after the last
/// one. Pure over the string, which is what makes it unit-testable —
/// `__init_libc` itself writes process-global state and stays out of
/// tests, like the rest of this module's runtime half.
///
/// # Safety
///
/// `pn` must be a valid NUL-terminated string.
fn progname_short(pn: *const c_char) -> *const c_char {
    unsafe {
        let mut short = pn;
        let mut p = pn;
        while *p != 0 {
            if *p == b'/' as c_char {
                short = p.add(1);
            }
            p = p.add(1);
        }
        short
    }
}

/// musl `__init_libc` (src/env/__libc_start_main.c:23-57), reduced to the
/// Wave 2 contract: envp→auxv scan, `__hwcap`, page size, `__init_ssp`
/// from `AT_RANDOM`, `__progname`/`__progname_full` from `argv[0]`, and
/// the set-uid/set-gid/`AT_SECURE` early-return check (lines 42-43).
/// Deferred: `__environ` (needs no loader state, still unwired),
/// `__init_tls` (Wave 3 owns the TP), `__sysinfo` (vdso, with B2/B3).
///
/// # Safety
///
/// `envp` must point at a null-terminated array of valid string pointers
/// followed, past the terminator, by the auxv word pairs. `pn` (argv[0])
/// must be a valid string; it is currently unused.
#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "C" fn __init_libc(envp: *mut *mut c_char, pn: *const c_char) {
    let mut n = 0usize;
    while !(unsafe { envp.wrapping_add(n).read() }).is_null() {
        n += 1;
    }
    let auxv = envp.wrapping_add(n + 1) as *const usize;
    unsafe { (*core::ptr::addr_of_mut!(__libc)).auxv = auxv as *mut usize };
    let mut aux = [0usize; AUX_CNT];
    unsafe { auxv_fill(&mut aux, auxv) };
    // musl `__libc_start_main.c:32-37`: `argv[0]`, else `AT_EXECFN`,
    // else the empty string; `__progname` stops past the last `/`.
    let mut full = pn;
    if full.is_null() {
        full = aux[AT_EXECFN] as *const c_char;
    }
    if full.is_null() {
        full = c"".as_ptr();
    }
    unsafe {
        core::ptr::addr_of_mut!(__progname_full).write(full as *mut c_char);
        core::ptr::addr_of_mut!(__progname).write(progname_short(full) as *mut c_char);
    }
    unsafe { core::ptr::addr_of_mut!(__hwcap).write(aux[AT_HWCAP]) };
    unsafe { (*core::ptr::addr_of_mut!(__libc)).page_size = aux[AT_PAGESZ] };
    unsafe { __init_ssp(aux[AT_RANDOM] as *mut c_void) };
    if aux[AT_UID] == aux[AT_EUID] && aux[AT_GID] == aux[AT_EGID] && aux[AT_SECURE] == 0 {
        return;
    }
    // shortcut(fd-scrub): musl reopens fds 0-2 from /dev/null here
    // (__libc_start_main.c:45-56); needs open/poll, so deferred — but the
    // `secure` latch below still happens exactly when musl sets it.
    unsafe { (*core::ptr::addr_of_mut!(__libc)).secure = 1 };
}

/// Fill a musl-style `aux[AUX_CNT]` table from raw auxv pairs.
///
/// Mirrors the scan in musl `__init_libc` (__libc_start_main.c:29):
/// consecutive key/value words up to the `AT_NULL` terminator; keys
/// `>= AUX_CNT` are ignored.
///
/// # Safety
///
/// `auxv` must point at a valid `AT_NULL`-terminated sequence of
/// key/value `usize` words, readable for the whole scan.
pub unsafe fn auxv_fill(table: &mut [usize; AUX_CNT], auxv: *const usize) {
    let mut p = auxv;
    loop {
        let key = unsafe { p.read() };
        if key == AT_NULL {
            break;
        }
        let val = unsafe { p.wrapping_add(1).read() };
        if key < AUX_CNT {
            table[key] = val;
        }
        p = p.wrapping_add(2);
    }
}

/// musl `__init_ssp` (src/env/__stack_chk_fail.c:7-22): copy `AT_RANDOM`
/// entropy bytes into the guard, else hash the guard's own address with
/// the 1103515245 multiplier; then clear the second byte so the canary
/// cannot leak through string functions. The thread-canary store
/// (`__pthread_self()->canary`) is skipped: no thread pointer exists
/// until Wave 3 sets up TLS.
///
/// # Safety
///
/// `entropy` must be null or point at `size_of::<usize>()` readable bytes
/// that stay valid for the copy.
#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "C" fn __init_ssp(entropy: *mut c_void) {
    if entropy.is_null() {
        let addr = core::ptr::addr_of!(__stack_chk_guard) as usize;
        unsafe { core::ptr::addr_of_mut!(__stack_chk_guard).write(addr.wrapping_mul(1103515245)) };
    } else {
        let src = entropy as *const u8;
        let dst = core::ptr::addr_of_mut!(__stack_chk_guard) as *mut u8;
        for i in 0..core::mem::size_of::<usize>() {
            unsafe { dst.wrapping_add(i).write(src.wrapping_add(i).read()) };
        }
    }
    let second = (core::ptr::addr_of_mut!(__stack_chk_guard) as *mut u8).wrapping_add(1);
    unsafe { second.write(0) };
}

/// musl `exit` (src/exit/exit.c:30-47): single-shot gate, then
/// `__funcs_on_exit` (atexit), `__libc_exit_fini` (fini array),
/// `__stdio_exit` (stdio flush), `_Exit` — in exactly this order.
///
/// shortcut(single-threaded): musl keys the gate on
/// `__pthread_self()->tid`, trapping recursive calls and spinning on
/// `__sys_pause` when contended. With no threads/TID yet, any second
/// arrival is recursion, so it traps outright. Full per-thread lock when
/// pthreads land (Wave 3).
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn exit(code: c_int) -> ! {
    if EXIT_LOCK
        .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        // Trap: musl `a_crash()` equivalent for recursive `exit`.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("ud2", options(noreturn));
        }
        #[cfg(not(target_arch = "x86_64"))]
        loop {}
    }
    unsafe { __funcs_on_exit() };
    unsafe { __libc_exit_fini() };
    unsafe { __stdio_exit() };
    _Exit(code)
}

/// musl `exit.c:37` (`static volatile int exit_lock[1]`), as an atomic:
/// single-threaded use needs only the CAS, no TID keying yet.
#[cfg(not(test))]
static EXIT_LOCK: AtomicI32 = AtomicI32::new(0);

/// musl `_Exit` (src/exit/_Exit.c:4-7): `SYS_exit_group`, falling back to
/// `SYS_exit` forever. Raw dispatch, bypassing the errno wrappers:
/// neither call returns on success, so there is no status to translate.
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn _Exit(code: c_int) -> ! {
    unsafe { crate::syscall::syscall1(SYS_EXIT_GROUP, code as usize) };
    loop {
        unsafe { crate::syscall::syscall1(SYS_EXIT, code as usize) };
    }
}

// Application entry plus the hook symbols `_start_c`/`exit`/stage-2 call
// into. All but `main` are weak dummies (next block) until their owning
// waves define them: `__funcs_on_exit`/`__stdio_exit` (musl
// src/exit/exit.c:14-15), `__libc_exit_fini` (musl exit.c:28),
// `__libc_start_init` (musl __libc_start_main.c:67), `_init`/`_fini`
// (musl __libc_start_main.c:11, crt/crt1.c:18).
#[cfg(not(test))]
extern "C" {
    fn main(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char) -> c_int;
    fn _init();
    fn _fini();
    fn __funcs_on_exit();
    fn __stdio_exit();
    fn __libc_exit_fini();
    fn __libc_start_init();
}

/// Shared empty body for this file's weak dummies (musl's `static void
/// dummy`, src/exit/exit.c:8-10 and __libc_start_main.c:10). A later
/// strong definition overrides any alias below without link errors.
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn __start_dummy() {}

// Weak dummies via the existing `crate::weak_alias!` macro (x86_64 only,
// like the macro itself).
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(_init, __start_dummy);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(_fini, __start_dummy);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(__funcs_on_exit, __start_dummy);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(__stdio_exit, __start_dummy);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(__libc_exit_fini, __start_dummy);
#[cfg(all(not(test), target_arch = "x86_64"))]
crate::weak_alias!(__libc_start_init, __start_dummy);

#[cfg(test)]
mod tests {
    use super::{auxv_fill, progname_short, AT_HWCAP, AT_NULL, AT_PAGESZ, AUX_CNT};

    fn fill(words: &[usize]) -> [usize; AUX_CNT] {
        let mut table = [0usize; AUX_CNT];
        unsafe { auxv_fill(&mut table, words.as_ptr()) };
        table
    }

    #[test]
    fn auxv_fill_records_known_keys() {
        let table = fill(&[AT_HWCAP, 42, AT_PAGESZ, 4096, AT_NULL]);
        assert_eq!(table[AT_HWCAP], 42);
        assert_eq!(table[AT_PAGESZ], 4096);
        assert_eq!(table.iter().sum::<usize>(), 42 + 4096);
    }

    #[test]
    fn auxv_fill_stops_at_null_and_ignores_big_keys() {
        let table = fill(&[77, 9, AT_NULL, AT_HWCAP, 7, AT_NULL]);
        assert_eq!(table[AT_HWCAP], 0);
        assert!(table.iter().all(|&w| w == 0));
    }

    #[test]
    fn auxv_fill_empty_is_all_zero() {
        let table = fill(&[AT_NULL]);
        assert!(table.iter().all(|&w| w == 0));
    }

    /// `progname_short` stops past the last `/` (musl
    /// `__libc_start_main.c:37`); a bare name and the empty string come
    /// back untouched.
    #[test]
    fn progname_short_strips_directories() {
        let full = c"/usr/bin/foo";
        let short = progname_short(full.as_ptr());
        assert_eq!(short, full.as_ptr().wrapping_add(9));
        let bare = c"foo";
        assert_eq!(progname_short(bare.as_ptr()), bare.as_ptr());
        let empty = c"";
        assert_eq!(progname_short(empty.as_ptr()), empty.as_ptr());
    }
}
