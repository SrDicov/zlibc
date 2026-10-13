//! D1 packet 1: buffered stdio basics (fd-backed, C-conformant core).
//!
//! Semantics mirror musl `src/stdio` essentials (verified, reimplemented):
//! `stdin`/`stdout`/`stderr` statics (fd 0/1/2; stdout line-buffered,
//! stderr unbuffered), `puts = fputs + '\n'`, the write path joining
//! buffered + direct bytes, `fopen` mode mapping, clean `EOF`/`ERR`
//! sticky bits. `printf` covers `d i u x X o p s c % n` with flags,
//! width, precision and lengths (no floats yet — `%f e g a` consume the
//! `double` and emit nothing, `shortcut:` packet 2 adds `dtoa`; never
//! silent garbage, always documented).
//!
//! Deliberate deviations from musl, all documented: one global stdio
//! lock instead of per-stream locks (same exclusion, coarser); our own
//! compact `File` instead of the full `struct _IO_FILE` (orientation,
//! wide mode, unget, per-stream locks arrive in packet 2 — `IoFile`
//! stays the ABI witness in `crate::abi` until then); read/write mixing
//! without repositioning discards the opposite buffer deterministically.
//! Lock order is always stdio → heap, never the reverse (the allocator
//! never takes the stdio lock), so no deadlock cycle exists.

use core::ffi::{c_char, c_int, c_void};
use core::ptr::{addr_of_mut, null_mut};

use crate::errno::__errno_location;
use crate::malloc::{free, malloc};
use crate::sync::{pthread_mutex_lock, pthread_mutex_unlock, MutexT};
use crate::syscall::{syscall3, syscall4, syscall_ret};

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_READ: usize = 0; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_WRITE: usize = 1; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_CLOSE: usize = 3; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_OPENAT: usize = 257; // TODO: generate from arch bits/syscall.h
/// musl `arch/generic/bits/errno.h`.
const EINTR: c_int = 4;
const EINVAL: c_int = 22;
/// musl `include/fcntl.h` (generic subset used here).
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_RDWR: c_int = 2;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;
const O_APPEND: c_int = 0o2000;
const O_CLOEXEC: c_int = 0o2000000;
const AT_FDCWD: c_int = -100;
/// musl `include/stdio.h:21` (`BUFSIZ`).
const STDIO_BUF: usize = 1024;
/// `EOF` (musl `include/stdio.h:53`).
pub const EOF: c_int = -1;

const F_READ: u32 = 1;
const F_WRITE: u32 = 2;
const F_EOF: u32 = 4;
const F_ERR: u32 = 8;
const F_OWNBUF: u32 = 16;

/// Compact buffered stream (packet-1 repr; NOT `struct _IO_FILE` yet).
#[repr(C)]
pub struct File {
    fd: c_int,
    flags: u32,
    line_buf: bool,
    buf: *mut u8,
    cap: usize,
    wpos: usize,
    rpos: usize,
    rlen: usize,
    next: *mut File,
}

static mut STDIO_LOCK: MutexT = [0; 5];
static mut STDIN_FILE: File = File {
    fd: 0,
    flags: F_READ,
    line_buf: false,
    buf: null_mut(),
    cap: 0,
    wpos: 0,
    rpos: 0,
    rlen: 0,
    next: null_mut(),
};
static mut STDIN_BUF: [u8; STDIO_BUF] = [0; STDIO_BUF];
static mut STDOUT_FILE: File = File {
    fd: 1,
    flags: F_WRITE,
    line_buf: true,
    buf: null_mut(),
    cap: 0,
    wpos: 0,
    rpos: 0,
    rlen: 0,
    next: null_mut(),
};
static mut STDOUT_BUF: [u8; STDIO_BUF] = [0; STDIO_BUF];
static mut STDERR_FILE: File = File {
    fd: 2,
    flags: F_WRITE,
    line_buf: false,
    buf: null_mut(),
    cap: 0,
    wpos: 0,
    rpos: 0,
    rlen: 0,
    next: null_mut(),
};
/// musl `src/stdio/stdin.c:16`, `stdout.c:17`, `stderr.c:17` (`FILE *const`).
#[no_mangle]
pub static mut stdin: *mut File = addr_of_mut!(STDIN_FILE);
/// musl `src/stdio/stdout.c:17`.
#[no_mangle]
pub static mut stdout: *mut File = addr_of_mut!(STDOUT_FILE);
/// musl `src/stdio/stderr.c:17`.
#[no_mangle]
pub static mut stderr: *mut File = addr_of_mut!(STDERR_FILE);

static mut OPEN_LIST: *mut File = null_mut();
static mut STDIO_READY: bool = false;

fn slock() {
    unsafe {
        pthread_mutex_lock(addr_of_mut!(STDIO_LOCK));
    }
}

fn sunlock() {
    unsafe {
        pthread_mutex_unlock(addr_of_mut!(STDIO_LOCK));
    }
}

/// Wire static buffers + the open list once (lock held by the caller).
unsafe fn ensure_locked() {
    unsafe {
        if addr_of_mut!(STDIO_READY).read() {
            return;
        }
        (*addr_of_mut!(STDIN_FILE)).buf = addr_of_mut!(STDIN_BUF) as *mut u8;
        (*addr_of_mut!(STDIN_FILE)).cap = STDIO_BUF;
        (*addr_of_mut!(STDOUT_FILE)).buf = addr_of_mut!(STDOUT_BUF) as *mut u8;
        (*addr_of_mut!(STDOUT_FILE)).cap = STDIO_BUF;
        // stderr stays unbuffered (cap 0, null buf): every byte direct.
        (*addr_of_mut!(STDOUT_FILE)).next = addr_of_mut!(STDIN_FILE);
        (*addr_of_mut!(STDIN_FILE)).next = addr_of_mut!(STDERR_FILE);
        addr_of_mut!(OPEN_LIST).write(addr_of_mut!(STDOUT_FILE));
        addr_of_mut!(STDIO_READY).write(true);
    }
}

fn set_err(e: c_int) {
    unsafe {
        *__errno_location() = e;
    }
}

/// Raw `write` loop (lock held or private fd): partial writes continue,
/// `EINTR` retries, anything else latches `F_ERR` when `f` is given.
unsafe fn write_all(f: *mut File, mut p: *const u8, mut n: usize) -> bool {
    unsafe {
        while n > 0 {
            let r = syscall_ret(syscall3(SYS_WRITE, (*f).fd as usize, p as usize, n));
            if r == -1 {
                if *__errno_location() == EINTR {
                    continue;
                }
                if !f.is_null() {
                    (*f).flags |= F_ERR;
                }
                return false;
            }
            if r == 0 {
                if !f.is_null() {
                    (*f).flags |= F_ERR;
                }
                return false;
            }
            p = p.add(r as usize);
            n -= r as usize;
        }
        true
    }
}

/// Flush buffered output (lock held).
unsafe fn flush_locked(f: *mut File) -> bool {
    unsafe {
        if f.is_null() || ((*f).flags & F_WRITE) == 0 || (*f).wpos == 0 {
            return true;
        }
        let ok = write_all(f, (*f).buf, (*f).wpos);
        (*f).wpos = 0;
        ok
    }
}

/// Buffer one byte for output; flushes on full buffer (and on newline
/// when line-buffered). Unbuffered streams write through. (Lock held.)
unsafe fn put_byte_locked(f: *mut File, b: u8) -> bool {
    unsafe {
        if (*f).cap == 0 || (*f).buf.is_null() {
            return write_all(f, &b, 1);
        }
        if (*f).wpos >= (*f).cap && !flush_locked(f) {
            return false;
        }
        (*(*f).buf.add((*f).wpos)) = b;
        (*f).wpos += 1;
        if (*f).line_buf && b == b'\n' {
            return flush_locked(f);
        }
        if (*f).wpos >= (*f).cap {
            return flush_locked(f);
        }
        true
    }
}

/// Fill the read buffer (lock held). True when bytes are available.
unsafe fn fill_locked(f: *mut File) -> bool {
    unsafe {
        if ((*f).flags & F_READ) == 0 {
            (*f).flags |= F_ERR;
            return false;
        }
        if (*f).cap == 0 || (*f).buf.is_null() {
            return false;
        }
        // A pending write side is flushed before switching direction.
        if !flush_locked(f) {
            return false;
        }
        loop {
            let r = syscall_ret(syscall3(
                SYS_READ,
                (*f).fd as usize,
                (*f).buf as usize,
                (*f).cap,
            ));
            if r == -1 {
                if *__errno_location() == EINTR {
                    continue;
                }
                (*f).flags |= F_ERR;
                return false;
            }
            if r == 0 {
                (*f).flags |= F_EOF;
                return false;
            }
            (*f).rpos = 0;
            (*f).rlen = r as usize;
            return true;
        }
    }
}

/// Build a heap `File` over `fd` (lock held). Null on buffer OOM
/// (musl fails the open too — an unbuffered fallback would silently
/// break reads, which have nowhere to stage without a buffer).
unsafe fn make_file(fd: c_int, read: bool) -> *mut File {
    unsafe {
        let f = malloc(size_of::<File>()) as *mut File;
        if f.is_null() {
            return null_mut();
        }
        let buf = malloc(STDIO_BUF) as *mut u8;
        if buf.is_null() {
            free(f as *mut c_void);
            return null_mut();
        }
        (*f).fd = fd;
        (*f).flags = (if read { F_READ } else { F_WRITE }) | F_OWNBUF;
        (*f).line_buf = false;
        (*f).buf = buf;
        (*f).cap = STDIO_BUF;
        (*f).wpos = 0;
        (*f).rpos = 0;
        (*f).rlen = 0;
        (*f).next = addr_of_mut!(OPEN_LIST).read();
        addr_of_mut!(OPEN_LIST).write(f);
        f
    }
}

/// Unlink `f` from the open list (lock held).
unsafe fn unlink_locked(f: *mut File) {
    unsafe {
        let mut link = addr_of_mut!(OPEN_LIST);
        while !(*link).is_null() {
            if *link == f {
                *link = (*f).next;
                return;
            }
            link = addr_of_mut!((**link).next);
        }
    }
}

/// Flush a stream.
///
/// # Safety
///
/// `f` must be null or a live stream; null flushes every open stream.
#[no_mangle]
pub unsafe extern "C" fn fflush(f: *mut File) -> c_int {
    unsafe {
        slock();
        ensure_locked();
        let mut rc = 0;
        if f.is_null() {
            let mut cur = addr_of_mut!(OPEN_LIST).read();
            while !cur.is_null() {
                if !flush_locked(cur) {
                    rc = EOF;
                }
                cur = (*cur).next;
            }
        } else if !flush_locked(f) {
            rc = EOF;
        }
        sunlock();
        rc
    }
}

/// Open a file by path (musl `fopen`: mode mapping `r w a [+][e][b]`).
///
/// # Safety
///
/// Both pointers must be valid NUL-terminated strings.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fopen(path: *const c_char, mode: *const c_char) -> *mut File {
    unsafe {
        if path.is_null() || mode.is_null() {
            set_err(EINVAL);
            return null_mut();
        }
        let mut m = mode;
        let mut flags = match *m as u8 {
            b'r' => O_RDONLY,
            b'w' => O_WRONLY | O_CREAT | O_TRUNC,
            b'a' => O_WRONLY | O_CREAT | O_APPEND,
            _ => {
                set_err(EINVAL);
                return null_mut();
            }
        };
        m = m.add(1);
        let mut plus = false;
        let mut cloexec = false;
        while *m != 0 {
            match *m as u8 {
                b'+' => plus = true,
                b'e' => cloexec = true,
                b'b' => {}
                _ => {
                    set_err(EINVAL);
                    return null_mut();
                }
            }
            m = m.add(1);
        }
        if plus {
            flags = (flags & !O_WRONLY) | O_RDWR;
        }
        if cloexec {
            flags |= O_CLOEXEC;
        }
        let fd = syscall_ret(syscall4(
            SYS_OPENAT,
            (AT_FDCWD as isize) as usize,
            path as usize,
            flags as usize,
            0o666,
        ));
        if fd == -1 {
            return null_mut();
        }
        slock();
        ensure_locked();
        let read = (flags & O_WRONLY) == 0;
        let f = make_file(fd as c_int, read);
        if f.is_null() {
            let _ = syscall_ret(syscall3(SYS_CLOSE, fd as usize, 0, 0));
        }
        sunlock();
        f
    }
}

/// Wrap a live fd as a stream (musl `fdopen`, same mode mapping).
/// Append mode positions like write until `fseek` lands (packet 2).
///
/// # Safety
///
/// `fd` must be open; `mode` a valid string.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fdopen(fd: c_int, mode: *const c_char) -> *mut File {
    unsafe {
        if mode.is_null() || *mode == 0 {
            set_err(EINVAL);
            return null_mut();
        }
        let read = *mode == (b'r' as c_char);
        if !read && *mode != (b'w' as c_char) && *mode != (b'a' as c_char) {
            set_err(EINVAL);
            return null_mut();
        }
        slock();
        ensure_locked();
        let f = make_file(fd, read);
        sunlock();
        f
    }
}

/// Close a stream (flushes, closes the fd, frees everything).
/// Standard streams are flushed and their fd closed, but never freed
/// (static storage); later use fails clean with `F_ERR`, never dangles.
///
/// # Safety
///
/// `f` must be a live stream.
#[no_mangle]
pub unsafe extern "C" fn fclose(f: *mut File) -> c_int {
    unsafe {
        if f.is_null() {
            set_err(EINVAL);
            return EOF;
        }
        slock();
        ensure_locked();
        let ok = flush_locked(f);
        let fd = (*f).fd;
        (*f).fd = -1;
        let std = f == addr_of_mut!(STDIN_FILE)
            || f == addr_of_mut!(STDOUT_FILE)
            || f == addr_of_mut!(STDERR_FILE);
        let buf = (*f).buf;
        let own = ((*f).flags & F_OWNBUF) != 0;
        if !std {
            unlink_locked(f);
        }
        sunlock();
        let _ = syscall_ret(syscall3(SYS_CLOSE, fd as usize, 0, 0));
        if !std {
            if own && !buf.is_null() {
                free(buf as *mut c_void);
            }
            free(f as *mut c_void);
        }
        if ok {
            0
        } else {
            EOF
        }
    }
}

/// Write `n` items of `size` (musl `fwrite`: big writes go direct).
///
/// # Safety
///
/// `f` live, `p` readable for `size*n` bytes.
#[no_mangle]
pub unsafe extern "C" fn fwrite(p: *const c_void, size: usize, n: usize, f: *mut File) -> usize {
    unsafe {
        if f.is_null() || p.is_null() || size == 0 || n == 0 {
            return 0;
        }
        let total = match size.checked_mul(n) {
            Some(m) => m,
            None => {
                set_err(EINVAL);
                return 0;
            }
        };
        slock();
        ensure_locked();
        if ((*f).flags & F_WRITE) == 0 {
            (*f).flags |= F_ERR;
            sunlock();
            return 0;
        }
        // Switching from a read position discards it (documented).
        (*f).rpos = 0;
        (*f).rlen = 0;
        let mut done = 0usize;
        // Fast lane: empty buffer and more than a bufferful goes direct.
        if (*f).wpos == 0 && total >= (*f).cap && (*f).cap > 0 {
            if !write_all(f, p as *const u8, total) {
                sunlock();
                return 0;
            }
            sunlock();
            return n;
        }
        let mut src = p as *const u8;
        let mut left = total;
        let mut ok = true;
        while left > 0 && ok {
            if (*f).cap == 0 || (*f).buf.is_null() {
                ok = write_all(f, src, left);
                if ok {
                    done += left;
                }
                break;
            }
            let space = (*f).cap - (*f).wpos;
            if space == 0 {
                ok = flush_locked(f);
                continue;
            }
            let step = space.min(left);
            core::ptr::copy_nonoverlapping(src, (*f).buf.add((*f).wpos), step);
            (*f).wpos += step;
            src = src.add(step);
            left -= step;
            done += step;
            if (*f).line_buf {
                // Scan only the bytes just staged for a newline.
                let mut k = (*f).wpos - step;
                while k < (*f).wpos {
                    if *(*f).buf.add(k) == b'\n' {
                        ok = flush_locked(f);
                        break;
                    }
                    k += 1;
                }
            }
            if left > 0 && (*f).wpos >= (*f).cap {
                ok = flush_locked(f);
            }
        }
        sunlock();
        done / size
    }
}

/// Read `n` items of `size` (musl `fread`: short count on EOF/error).
///
/// # Safety
///
/// `f` live, `p` writable for `size*n` bytes.
#[no_mangle]
pub unsafe extern "C" fn fread(p: *mut c_void, size: usize, n: usize, f: *mut File) -> usize {
    unsafe {
        if f.is_null() || p.is_null() || size == 0 || n == 0 {
            return 0;
        }
        let total = match size.checked_mul(n) {
            Some(m) => m,
            None => {
                set_err(EINVAL);
                return 0;
            }
        };
        slock();
        ensure_locked();
        let mut dst = p as *mut u8;
        let mut left = total;
        while left > 0 {
            if (*f).rpos >= (*f).rlen && !fill_locked(f) {
                break;
            }
            let avail = (*f).rlen - (*f).rpos;
            let step = avail.min(left);
            core::ptr::copy_nonoverlapping((*f).buf.add((*f).rpos), dst, step);
            (*f).rpos += step;
            dst = dst.add(step);
            left -= step;
        }
        sunlock();
        (total - left) / size
    }
}

/// Get one byte or `EOF` (musl `fgetc`).
///
/// # Safety
///
/// `f` must be a live readable stream.
#[no_mangle]
pub unsafe extern "C" fn fgetc(f: *mut File) -> c_int {
    unsafe {
        if f.is_null() {
            set_err(EINVAL);
            return EOF;
        }
        slock();
        ensure_locked();
        if (*f).rpos >= (*f).rlen && !fill_locked(f) {
            sunlock();
            return EOF;
        }
        let b = *(*f).buf.add((*f).rpos) as c_int;
        (*f).rpos += 1;
        sunlock();
        b
    }
}

/// `fgetc(stdin)`.
///
/// # Safety
///
/// Reads fd 0 through the standard stream; same contract as [`fgetc`].
#[no_mangle]
pub unsafe extern "C" fn getchar() -> c_int {
    unsafe {
        slock();
        ensure_locked();
        let f = addr_of_mut!(STDIN_FILE);
        sunlock();
        fgetc(f)
    }
}

/// Write a string without its NUL (musl `fputs`).
///
/// # Safety
///
/// Both pointers live; `s` NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn fputs(s: *const c_char, f: *mut File) -> c_int {
    unsafe {
        if s.is_null() || f.is_null() {
            set_err(EINVAL);
            return EOF;
        }
        let mut n = 0usize;
        while *s.add(n) != 0 {
            n += 1;
        }
        if fwrite(s as *const c_void, 1, n, f) == n {
            0
        } else {
            EOF
        }
    }
}

/// `fputs(s, stdout)` plus `'\n'` (musl `puts`: 0 on success).
///
/// # Safety
///
/// `s` must be a live NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn puts(s: *const c_char) -> c_int {
    unsafe {
        slock();
        ensure_locked();
        let f = addr_of_mut!(STDOUT_FILE);
        sunlock();
        if fputs(s, f) != 0 {
            return EOF;
        }
        slock();
        let ok = put_byte_locked(f, b'\n') && flush_locked(f);
        sunlock();
        if ok {
            0
        } else {
            EOF
        }
    }
}

// ---- Minimal printf --------------------------------------------------------
// Covers `d i u x X o p s c % n` + flags `- + space 0 #`, width
// (number or `*`), `.precision`, lengths `hh h l ll j z t`. Floats consume
// their `double` and emit nothing (packet-2 `dtoa`); unknown specs echo
// the character (deterministic, documented). Unknown ≠ crash, ever.
//
// Stable Rust cannot `va_start` (nightly-only `c_variadic`), so varargs
// are read by walking the x86_64 SysV `va_list` by hand: it is a plain
// documented struct (GP slots below offset 48, XMM slots below 304,
// overflow stack above), and every type we pull is ≤ 8 bytes at ≤ 8
// alignment, which SysV always passes in plain slots. The `...` symbols
// build the tag in a naked trampoline (spilling the caller's register
// file exactly as compiler `va_start` would stage it); the `v*` family
// walks caller-initialized tags with the same code.

/// C `va_list` for x86_64 SysV, layout-compatible by construction
/// (`__va_list_tag`: two offsets + overflow area + register save area).
#[repr(C)]
pub struct VaList {
    gp: u32,
    fp: u32,
    overflow: *mut u8,
    regsave: *mut u8,
}

/// Cursor over a [`VaList`].
#[derive(Clone, Copy)]
struct Ap {
    t: *mut VaList,
}

impl Ap {
    /// Next general slot as raw bits (registers then overflow stack).
    unsafe fn gp(&mut self) -> u64 {
        unsafe {
            let t = &mut *self.t;
            if t.gp < 48 {
                let v = (t.regsave.add(t.gp as usize) as *const u64).read_unaligned();
                t.gp += 8;
                v
            } else {
                let v = (t.overflow as *const u64).read_unaligned();
                t.overflow = t.overflow.add(8);
                v
            }
        }
    }

    /// Skip one floating-point slot (floats ignored packet-wide).
    unsafe fn fp_skip(&mut self) {
        unsafe {
            let t = &mut *self.t;
            if t.fp < 304 {
                t.fp += 16;
            } else {
                t.overflow = t.overflow.add(8);
            }
        }
    }

    /// Skip one 16-byte stack slot (`%Lf`: SysV MEMORY class, 16-aligned).
    unsafe fn stk16(&mut self) {
        unsafe {
            let t = &mut *self.t;
            t.overflow = (((t.overflow as usize + 15) & !15) + 16) as *mut u8;
        }
    }
}

/// Build a SysV `VaList` on our own stack and tail-call `$inner`.
/// Spills the whole vararg register file (GP + XMM) into a private
/// 304-byte area, so the walker sees exactly what `va_start` would have
/// staged. `$gp` is 8 × named GP args; FP always starts at 48 (no named
/// FP args); overflow is the first stack arg above the return address.
/// Stack discipline: entry `rsp % 16 == 8`, minus 312 keeps `% 16 == 0`,
/// so the inner `call` lands SysV-clean.
///
/// C-variadic entry: spills the caller's register file and tail-calls
/// the inner formatter. Callers pass args per SysV as usual.
///
/// Contract (single source for all three instantiations; the lint
/// cannot see docs through the expansion, hence the allow below):
/// same safety contract as the inner function.
///
/// # Safety
///
/// Same contract as the inner function.
macro_rules! va_trampoline {
    ($name:ident, $inner:ident, $gp:expr, $tagsetup:literal) => {
        #[allow(clippy::missing_safety_doc)]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "mov rax, rsp",
                "sub rsp, 312",
                "mov [rsp], rsi",
                "mov [rsp+8], rdx",
                "mov [rsp+16], rcx",
                "mov [rsp+24], r8",
                "mov [rsp+32], r9",
                "movups [rsp+48], xmm0",
                "movups [rsp+64], xmm1",
                "movups [rsp+80], xmm2",
                "movups [rsp+96], xmm3",
                "movups [rsp+112], xmm4",
                "movups [rsp+128], xmm5",
                "movups [rsp+144], xmm6",
                "movups [rsp+160], xmm7",
                "mov dword ptr [rsp+176], {gp}",
                "mov dword ptr [rsp+180], 48",
                "lea rcx, [rax+8]",
                "mov [rsp+184], rcx",
                "mov [rsp+192], rsp",
                $tagsetup,
                "call {inner}",
                "add rsp, 312",
                "ret",
                gp = const $gp,
                inner = sym $inner,
            )
        }
    };
}

va_trampoline!(printf, printf_inner, 8, "lea rsi, [rsp+176]");
va_trampoline!(fprintf, fprintf_inner, 16, "lea rdx, [rsp+176]");
va_trampoline!(snprintf, snprintf_inner, 24, "lea rcx, [rsp+176]");

/// `printf` body: stdout + caller-built tag (see [`va_trampoline`]).
///
/// # Safety
///
/// `fmt` valid; `tag` a live tag whose remaining args match it.
unsafe fn printf_inner(fmt: *const c_char, tag: *mut VaList) -> c_int {
    unsafe {
        slock();
        ensure_locked();
        let f = addr_of_mut!(STDOUT_FILE);
        sunlock();
        vfprintf(f, fmt, tag)
    }
}

/// `fprintf` body.
///
/// # Safety
///
/// `f` live; otherwise like [`printf_inner`].
unsafe fn fprintf_inner(f: *mut File, fmt: *const c_char, tag: *mut VaList) -> c_int {
    unsafe { vfprintf(f, fmt, tag) }
}

/// `snprintf` body.
///
/// # Safety
///
/// `s` writable for `n` bytes; otherwise like [`printf_inner`].
unsafe fn snprintf_inner(s: *mut c_char, n: usize, fmt: *const c_char, tag: *mut VaList) -> c_int {
    unsafe { vsnprintf(s, n, fmt, tag) }
}

enum Sink {
    Fd(c_int),
    Buf {
        base: *mut u8,
        cap: usize,
        len: usize,
    },
}

struct Out<'a> {
    sink: &'a mut Sink,
    count: usize,
    failed: bool,
}

impl<'a> Out<'a> {
    fn emit(&mut self, bytes: &[u8]) {
        if self.failed {
            return;
        }
        match self.sink {
            Sink::Fd(fd) => {
                let fd = *fd;
                let mut p = bytes.as_ptr();
                let mut n = bytes.len();
                unsafe {
                    while n > 0 {
                        let r = syscall_ret(syscall3(SYS_WRITE, fd as usize, p as usize, n));
                        if r == -1 {
                            if *__errno_location() == EINTR {
                                continue;
                            }
                            self.failed = true;
                            return;
                        }
                        if r == 0 {
                            self.failed = true;
                            return;
                        }
                        p = p.add(r as usize);
                        n -= r as usize;
                        self.count += r as usize;
                    }
                }
            }
            Sink::Buf { base, cap, len } => {
                let room = (*cap).saturating_sub(*len);
                let step = room.min(bytes.len());
                unsafe {
                    if step > 0 {
                        core::ptr::copy_nonoverlapping(bytes.as_ptr(), (*base).add(*len), step);
                    }
                    *len += bytes.len();
                }
                self.count += bytes.len();
            }
        }
    }

    fn pad(&mut self, ch: u8, n: usize) {
        let mut k = 0;
        while k < n {
            let step = (n - k).min(32);
            self.emit(&[ch; 32][..step]);
            k += step;
        }
    }
}

fn parse_uint(fmt: *const u8, pos: &mut usize) -> usize {
    let mut v = 0usize;
    unsafe {
        while (*fmt.add(*pos)).is_ascii_digit() {
            // Saturate: hostile widths must never panic in debug builds.
            v = v
                .saturating_mul(10)
                .saturating_add(((*fmt.add(*pos)) - b'0') as usize);
            *pos += 1;
        }
    }
    v
}

/// One parsed conversion (driver → convert, single argument).
/// (`narrow` stays driver-local for `%n`; convert never needs it.)
struct Spec {
    spec: u8,
    flags: u8,
    width: usize,
    prec: isize,
    wide: u8,
}

/// Integer render request (convert → int_emit, single argument).
struct Num {
    base: u32,
    upper: bool,
    neg: bool,
    flags: u8,
    width: usize,
    prec: isize,
}

/// Format one conversion; pulls exactly the args it needs from the
/// walker. Returns through `out`.
unsafe fn convert(out: &mut Out, sp: &Spec, ap: &mut Ap) {
    // Flags: bit0 '-', bit1 '+', bit2 ' ', bit3 '0', bit4 '#'.
    unsafe {
        match sp.spec {
            b'd' | b'i' => {
                let (uval, neg) = if sp.wide == 1 {
                    let v = ap.gp() as i64;
                    (v as u64, v < 0)
                } else {
                    let v = ap.gp() as c_int;
                    (v as u64, v < 0)
                };
                let mag = if neg { (0u64).wrapping_sub(uval) } else { uval };
                int_emit(
                    out,
                    &Num {
                        base: 10,
                        upper: false,
                        neg,
                        flags: sp.flags,
                        width: sp.width,
                        prec: sp.prec,
                    },
                    mag,
                );
            }
            b'u' => {
                let uval = if sp.wide == 1 {
                    ap.gp()
                } else {
                    ap.gp() & 0xffff_ffff
                };
                int_emit(
                    out,
                    &Num {
                        base: 10,
                        upper: false,
                        neg: false,
                        flags: sp.flags,
                        width: sp.width,
                        prec: sp.prec,
                    },
                    uval,
                );
            }
            b'o' => {
                let uval = if sp.wide == 1 {
                    ap.gp()
                } else {
                    ap.gp() & 0xffff_ffff
                };
                int_emit(
                    out,
                    &Num {
                        base: 8,
                        upper: false,
                        neg: false,
                        flags: sp.flags,
                        width: sp.width,
                        prec: sp.prec,
                    },
                    uval,
                );
            }
            b'x' | b'X' | b'p' => {
                let upper = sp.spec == b'X';
                let mut fl = sp.flags;
                let v = if sp.spec == b'p' {
                    fl |= 0x30;
                    ap.gp()
                } else if sp.wide == 1 {
                    ap.gp()
                } else {
                    ap.gp() & 0xffff_ffff
                };
                int_emit(
                    out,
                    &Num {
                        base: 16,
                        upper,
                        neg: false,
                        flags: fl,
                        width: sp.width,
                        prec: sp.prec,
                    },
                    v,
                );
            }
            b's' => {
                let raw = ap.gp() as *const c_char as *const u8;
                let mut s = if raw.is_null() {
                    &b"(null)"[..]
                } else {
                    let mut len = 0usize;
                    while *raw.add(len) != 0 {
                        len += 1;
                    }
                    core::slice::from_raw_parts(raw, len)
                };
                if sp.prec >= 0 && (sp.prec as usize) < s.len() {
                    s = &s[..sp.prec as usize];
                }
                let pad = sp.width.saturating_sub(s.len());
                if sp.flags & 1 == 0 {
                    out.pad(b' ', pad);
                }
                out.emit(s);
                if sp.flags & 1 != 0 {
                    out.pad(b' ', pad);
                }
            }
            b'c' => {
                let b = ap.gp() as u8;
                if sp.flags & 1 == 0 {
                    out.pad(b' ', sp.width.saturating_sub(1));
                }
                out.emit(&[b]);
                if sp.flags & 1 != 0 {
                    out.pad(b' ', sp.width.saturating_sub(1));
                }
            }
            _ => {
                // Floats (`f e g a`, upper too): consume, emit nothing.
                // `L` is the 16-byte SysV MEMORY class, the rest XMM slots.
                if matches!(
                    sp.spec,
                    b'f' | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A'
                ) {
                    if sp.wide == 2 {
                        ap.stk16();
                    } else {
                        ap.fp_skip();
                    }
                } else {
                    // Unknown spec: echo deterministically, never crash.
                    out.emit(&[sp.spec]);
                }
            }
        }
    }
}

/// `%n` needs the destination pointer, which `convert` does not carry —
/// handled inline in the driver below.
fn int_emit(out: &mut Out, n: &Num, mut v: u64) {
    let digits = if n.upper {
        &b"0123456789ABCDEF"[..]
    } else {
        &b"0123456789abcdef"[..]
    };
    let mut tmp = [0u8; 64];
    let mut len = 0usize;
    if v == 0 && n.prec != 0 {
        tmp[63] = b'0';
        len = 1;
    } else {
        let mut k = 64usize;
        while v > 0 {
            k -= 1;
            tmp[k] = digits[(v % n.base as u64) as usize];
            v /= n.base as u64;
            len += 1;
        }
        debug_assert!(k + len == 64);
    }
    // Digits land backwards from the tail; `num` borrows them in place.
    let num = &tmp[64 - len..];
    let zero = len == 0 || (len == 1 && tmp[63] == b'0');
    let zeros = if n.prec > len as isize {
        (n.prec as usize) - len
    } else {
        0
    };
    let mut sign = 0u8;
    let mut signlen = 0usize;
    if n.neg {
        sign = b'-';
        signlen = 1;
    } else if n.base == 10 && n.flags & 2 != 0 {
        sign = b'+';
        signlen = 1;
    } else if n.base == 10 && n.flags & 4 != 0 {
        sign = b' ';
        signlen = 1;
    }
    let mut alt = 0usize;
    // `0x` only for nonzero values (`%p` forces it via bit 0x20); `%#o`
    // forces a single `0` exactly when the digits show none (musl rules).
    if n.flags & 0x10 != 0 && n.base == 16 && (!zero || n.flags & 0x20 != 0) {
        alt = 2; // `0x`
    }
    let force_zero = n.base == 8 && n.flags & 0x10 != 0 && zero;
    // `0` flag pads with zeros after sign/alt (ignored with precision or `-`).
    let zpad = n.flags & 8 != 0 && n.flags & 1 == 0 && n.prec < 0;
    let body = signlen + alt + zeros + len + if force_zero { 1 } else { 0 };
    let pad = n.width.saturating_sub(body);
    if !zpad && n.flags & 1 == 0 {
        out.pad(b' ', pad);
    }
    if signlen > 0 {
        out.emit(&[sign]);
    }
    if alt == 2 {
        out.emit(if n.upper { &b"0X"[..] } else { &b"0x"[..] });
    }
    if zpad {
        out.pad(b'0', pad);
    }
    if force_zero {
        out.emit(&b"0"[..]);
    }
    out.pad(b'0', zeros);
    out.emit(num);
    if n.flags & 1 != 0 {
        out.pad(b' ', pad);
    }
}

/// Core driver: walk `fmt`, pull args, emit through `sink`. Returns
/// bytes (or would-be bytes for buffers), or -1 on write error.
unsafe fn fmt_driver(sink: &mut Sink, fmt: *const c_char, mut ap: Ap) -> c_int {
    unsafe {
        let mut out = Out {
            sink,
            count: 0,
            failed: false,
        };
        let f = fmt as *const u8;
        let mut i = 0usize;
        while *f.add(i) != 0 {
            if *f.add(i) != b'%' {
                let mut j = i;
                while *f.add(j) != 0 && *f.add(j) != b'%' {
                    j += 1;
                }
                out.emit(core::slice::from_raw_parts(f.add(i), j - i));
                i = j;
                continue;
            }
            i += 1; // consume '%'
            if *f.add(i) == b'%' {
                out.emit(&b"%"[..]);
                i += 1;
                continue;
            }
            let mut flags = 0u8;
            loop {
                match *f.add(i) {
                    b'-' => flags |= 1,
                    b'+' => flags |= 2,
                    b' ' => flags |= 4,
                    b'0' => flags |= 8,
                    b'#' => flags |= 0x10,
                    _ => break,
                }
                i += 1;
            }
            let width: usize;
            if *f.add(i) == b'*' {
                let w = ap.gp() as c_int;
                if w < 0 {
                    flags |= 1;
                    width = (w as isize).wrapping_neg() as usize;
                } else {
                    width = w as usize;
                }
                i += 1;
            } else {
                width = parse_uint(f, &mut i);
            }
            let mut prec = -1isize;
            if *f.add(i) == b'.' {
                i += 1;
                if *f.add(i) == b'*' {
                    let p = ap.gp() as c_int;
                    prec = p as isize;
                    i += 1;
                } else {
                    prec = parse_uint(f, &mut i) as isize;
                }
            }
            // Lengths: hh h l ll j z t (only the read width matters;
            // `narrow` drives `%n`'s pointee below).
            let mut wide = 0u8; // 0 = int, 1 = 64-bit
            let mut narrow = 0u8; // 0 = none, 1 = h, 2 = hh
            match *f.add(i) {
                b'h' => {
                    i += 1;
                    narrow = 1;
                    if *f.add(i) == b'h' {
                        i += 1;
                        narrow = 2;
                    }
                }
                b'l' => {
                    i += 1;
                    wide = 1;
                    if *f.add(i) == b'l' {
                        i += 1;
                    }
                }
                b'L' => {
                    i += 1;
                    wide = 2;
                }
                b'j' | b'z' | b't' => {
                    i += 1;
                    wide = 1;
                }
                _ => {}
            }
            let spec = *f.add(i);
            if spec == 0 {
                break;
            }
            i += 1;
            // `%n`: store the count through the pointer arg; the length
            // picks the pointee (`hh`→i8, `h`→i16, none→int, `l*`→i64).
            if spec == b'n' {
                if wide == 1 {
                    let p = ap.gp() as *mut i64;
                    if !p.is_null() {
                        *p = out.count as i64;
                    }
                } else if narrow == 2 {
                    let p = ap.gp() as *mut i8;
                    if !p.is_null() {
                        *p = out.count as i8;
                    }
                } else if narrow == 1 {
                    let p = ap.gp() as *mut i16;
                    if !p.is_null() {
                        *p = out.count as i16;
                    }
                } else {
                    let p = ap.gp() as *mut c_int;
                    if !p.is_null() {
                        *p = out.count as c_int;
                    }
                }
                continue;
            }
            // Pull the value arg (strings/pointers read raw, never as int).
            let sp = Spec {
                spec,
                flags,
                width,
                prec,
                wide,
            };
            convert(&mut out, &sp, &mut ap);
            if out.failed {
                return -1;
            }
        }
        if out.failed {
            -1
        } else {
            out.count as c_int
        }
    }
}

/// Formatted output to a stream (musl `vfprintf`): flushes pending
/// bytes first so ordering stays exact, then emits direct.
///
/// # Safety
///
/// `f` live, `fmt` a valid format string, `ap` a live tag whose
/// remaining args match it.
#[no_mangle]
pub unsafe extern "C" fn vfprintf(f: *mut File, fmt: *const c_char, ap: *mut VaList) -> c_int {
    unsafe {
        if f.is_null() || fmt.is_null() || ap.is_null() {
            set_err(EINVAL);
            return EOF;
        }
        slock();
        ensure_locked();
        // Reads switch to write mode by discarding (documented).
        (*f).rpos = 0;
        (*f).rlen = 0;
        if !flush_locked(f) {
            sunlock();
            return EOF;
        }
        let mut sink = Sink::Fd((*f).fd);
        let rc = fmt_driver(&mut sink, fmt, Ap { t: ap });
        sunlock();
        rc
    }
}

/// Formatted output to `stdout` (musl `vprintf`).
///
/// # Safety
///
/// `fmt` valid, `ap` a live tag matching it.
#[no_mangle]
pub unsafe extern "C" fn vprintf(fmt: *const c_char, ap: *mut VaList) -> c_int {
    unsafe {
        slock();
        ensure_locked();
        let f = addr_of_mut!(STDOUT_FILE);
        sunlock();
        vfprintf(f, fmt, ap)
    }
}

/// Formatted output into a buffer (musl `vsnprintf`: C99 truncation +
/// NUL rules, returns the would-be length).
///
/// # Safety
///
/// `s` writable for `n` bytes (or null when `n` is 0), `fmt` valid,
/// `ap` a live tag matching it.
#[no_mangle]
pub unsafe extern "C" fn vsnprintf(
    s: *mut c_char,
    n: usize,
    fmt: *const c_char,
    ap: *mut VaList,
) -> c_int {
    unsafe {
        if fmt.is_null() || (s.is_null() && n != 0) || ap.is_null() {
            set_err(EINVAL);
            return EOF;
        }
        let mut sink = Sink::Buf {
            base: s as *mut u8,
            cap: n,
            len: 0,
        };
        let rc = fmt_driver(&mut sink, fmt, Ap { t: ap });
        if n > 0 {
            if let Sink::Buf { base, len, .. } = sink {
                *base.add(len.min(n - 1)) = 0;
            }
        }
        rc
    }
}

#[cfg(test)]
mod tests {
    use super::{fclose, fdopen, fgetc, fputs, fread, fwrite, Ap, VaList, EOF};
    use core::ffi::{c_char, c_int};
    use core::ptr::null_mut;

    use crate::syscall::{syscall2, syscall_ret};

    // Our own C-variadic symbols (naked trampolines): foreign `...`
    // declarations are stable to *call*; only *reading* needs nightly.
    extern "C" {
        fn printf(fmt: *const c_char, ...) -> c_int;
        fn fprintf(f: *mut super::File, fmt: *const c_char, ...) -> c_int;
        fn snprintf(s: *mut c_char, n: usize, fmt: *const c_char, ...) -> c_int;
    }

    /// musl `arch/x86_64/bits/syscall.h.in` (`SYS_pipe`, test plumbing).
    const SYS_PIPE: usize = 22;

    unsafe fn new_pipe() -> (c_int, c_int) {
        unsafe {
            let mut fds = [0 as c_int; 2];
            assert_eq!(
                syscall_ret(syscall2(SYS_PIPE, fds.as_mut_ptr() as usize, 0)),
                0
            );
            (fds[0], fds[1])
        }
    }

    #[test]
    fn pipe_write_read_roundtrip() {
        unsafe {
            let (r, w) = new_pipe();
            let wf = fdopen(w, c"w".as_ptr());
            assert!(!wf.is_null());
            let msg = b"hello stdio 12345";
            assert_eq!(
                fwrite(msg.as_ptr() as *const _, 1, msg.len(), wf),
                msg.len()
            );
            assert_eq!(fclose(wf), 0);
            let rf = fdopen(r, c"r".as_ptr());
            assert!(!rf.is_null());
            let mut back = [0u8; 64];
            let n = fread(back.as_mut_ptr() as *mut _, 1, back.len(), rf);
            assert_eq!(n, msg.len());
            assert_eq!(&back[..n], msg);
            // EOF after the writer closed: short count, then EOF bit.
            assert_eq!(fread(back.as_mut_ptr() as *mut _, 1, 1, rf), 0);
            assert_eq!(fclose(rf), 0);
        }
    }

    #[test]
    fn fputs_and_getc_loopback() {
        unsafe {
            let (r, w) = new_pipe();
            let wf = fdopen(w, c"w".as_ptr());
            let rf = fdopen(r, c"r".as_ptr());
            assert_eq!(fputs(c"abc".as_ptr(), wf), 0);
            // Null surface rejection on a live stream: no output, no crash.
            assert_eq!(fputs(null_mut(), wf), EOF);
            assert_eq!(fclose(wf), 0);
            assert_eq!(fgetc(rf), b'a' as c_int);
            assert_eq!(fgetc(rf), b'b' as c_int);
            assert_eq!(fgetc(rf), b'c' as c_int);
            assert_eq!(fgetc(rf), EOF);
            assert_eq!(fclose(rf), 0);
        }
    }

    #[test]
    fn printf_family_is_byte_exact() {
        unsafe {
            // snprintf incl. %n, truncation + NUL rules (C99).
            let mut buf = [0u8; 64];
            let mut n1 = 0 as c_int;
            let mut n2 = 0 as c_int;
            let rc = snprintf(
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                c"%d|%s|%x|%c|%%|%5d|%-5d|%.3s|%u|%o|%lld|%zd|ab%ncd%d%n".as_ptr(),
                -42 as c_int,
                c"hello".as_ptr(),
                255 as c_int,
                65 as c_int,
                7 as c_int,
                7 as c_int,
                c"hello".as_ptr(),
                42 as c_int,
                8 as c_int,
                9_i64,
                10_u64,
                &mut n1,
                11 as c_int,
                &mut n2,
            );
            let want: &[u8] = b"-42|hello|ff|A|%|    7|7    |hel|42|10|9|10|abcd11";
            assert_eq!(rc as usize, want.len());
            assert_eq!(&buf[..want.len()], want);
            assert_eq!(buf[want.len()], 0);
            assert_eq!((n1, n2), (46, 50));
            // Truncation: would-be length returned, buffer NUL-capped.
            let mut small = [0u8; 8];
            let rc = snprintf(
                small.as_mut_ptr() as *mut c_char,
                small.len(),
                c"0123456789abcdef".as_ptr(),
            );
            assert_eq!(rc, 16);
            assert_eq!(&small, b"0123456\0");
            // %p carries a 0x prefix; %#x too.
            let mut pbuf = [0u8; 32];
            let rc = snprintf(
                pbuf.as_mut_ptr() as *mut c_char,
                pbuf.len(),
                c"%p|%#x|%+d|% d|%08d|%.0d|%c".as_ptr(),
                0x1234usize,
                1 as c_int,
                1 as c_int,
                1 as c_int,
                42 as c_int,
                0 as c_int,
                66 as c_int,
            );
            let want: &[u8] = b"0x1234|0x1|+1| 1|00000042||B";
            assert_eq!(rc as usize, want.len());
            assert_eq!(&pbuf[..want.len()], want);
        }
    }

    #[test]
    fn trampolines_and_float_skip_hold() {
        unsafe {
            // fprintf through its trampoline, end to end over a pipe.
            let (r, w) = new_pipe();
            let wf = fdopen(w, c"w".as_ptr());
            assert_eq!(
                fprintf(wf, c"%s=%d\n".as_ptr(), c"k".as_ptr(), 7 as c_int),
                4
            );
            assert_eq!(fclose(wf), 0);
            let rf = fdopen(r, c"r".as_ptr());
            let mut back = [0u8; 8];
            assert_eq!(fread(back.as_mut_ptr() as *mut _, 1, back.len(), rf), 4);
            assert_eq!(&back[..4], b"k=7\n");
            assert_eq!(fclose(rf), 0);
            // printf returns the count (bytes land on fd 1, by design).
            assert_eq!(printf(c"%d".as_ptr(), 42 as c_int), 2);
            // A double in XMM is consumed and skipped; later args align.
            let mut fbuf = [0u8; 16];
            let rc = snprintf(
                fbuf.as_mut_ptr() as *mut c_char,
                fbuf.len(),
                c"%d|%f|%d".as_ptr(),
                1 as c_int,
                3.5f64,
                2 as c_int,
            );
            let want: &[u8] = b"1||2";
            assert_eq!(rc as usize, want.len());
            assert_eq!(&fbuf[..want.len()], want);
        }
    }

    #[test]
    fn walker_covers_registers_and_overflow() {
        // Synthetic SysV tag: GP slots then overflow, FP untouched.
        let mut regs = [0u64; 6];
        regs[1] = 0x1122_3344_5566_7788;
        regs[2] = 0x99aa;
        let mut over = [0u64; 2];
        over[0] = 0xdead;
        over[1] = 0xbeef;
        let mut tag = VaList {
            gp: 8,
            fp: 48,
            overflow: over.as_mut_ptr() as *mut u8,
            regsave: regs.as_mut_ptr() as *mut u8,
        };
        unsafe {
            let mut ap = Ap {
                t: &mut tag as *mut VaList,
            };
            assert_eq!(ap.gp(), 0x1122_3344_5566_7788);
            assert_eq!(ap.gp(), 0x99aa);
            // Exhaust GP: jump to the overflow area, order preserved.
            (*ap.t).gp = 48;
            assert_eq!(ap.gp(), 0xdead);
            assert_eq!(ap.gp(), 0xbeef);
            // Skips only move cursors (checked exactly, never dereferenced).
            let fp0 = (*ap.t).fp;
            ap.fp_skip();
            assert_eq!((*ap.t).fp, fp0 + 16);
            let ob = (*ap.t).overflow as usize;
            ap.stk16();
            assert_eq!((*ap.t).overflow as usize, ((ob + 15) & !15) + 16);
        }
    }
}
