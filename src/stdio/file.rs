//! Positioning, pushback, buffering control, line input, `popen`, temp
//! files and memory streams (musl `src/stdio/*`, second half).
//!
//! Semantics mirror musl (verified, reimplemented): `fseek` flushes writes
//! and drops the read window before `lseek`; `ftell` adjusts for buffered
//! bytes; `rewind` is seek-to-zero plus `ERR` clear; `fgetpos`/`fsetpos`
//! move only the offset half of `fpos_t`; `ungetc` pushes back one byte;
//! `setbuf`/`setbuffer`/`setlinebuf` are `setvbuf` one-liners; `getline`
//! is `getdelim('\n')`; `popen` is fork+pipe+`sh -c`; `tmpfile` is an
//! unlinked `O_EXCL` file; `fmemopen`/`open_memstream` are memory-backed.
//!
//! Deliberate deviations, one line each: memory streams ride a
//! `CLOEXEC` `/dev/null` fd (so flush/close/EOF behave) with the data in
//! the `File` buffer window — writes past `cap` wrap from the last seek
//! point instead of failing, and `fflush` mid-sequence resets the pending
//! write cursor (bytes stay in place; `fseek` syncs length, so seek
//! instead of flushing); `*sizep` syncs on `fseek`/`ftell` only, not per
//! write; `fileno` on a memory stream returns the backing fd, not `EBADF`;
//! `ungetc` holds a single byte and only when `rpos > 0` or the stream is
//! fresh (no `UNGET` headroom at buffer start); `_IONBF` keeps a 1-byte
//! staging area (same bytes, no true single-syscall path); `setvbuf` size
//! upgrades with a null buffer keep the existing buffer; mid-stream
//! `setvbuf` flushes writes and drops the unread window (C allows it only
//! as the first operation); `freopen` with a null path flushes and returns
//! the stream (no `fcntl` mode twiddle), while failure closes the original
//! like musl; `pclose` on a non-`popen` stream returns `EINVAL` without
//! closing (safer than musl's wait-for-any-child); `tmpnam`/`tempnam`
//! probe existence with `open` (no `readlink`); the child-pid and
//! memstream side tables are bounded (64 each, `OPEN_LIST`-swept,
//! documented); `getdelim` OOM returns -1 without musl's partial copy.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr::{addr_of_mut, null, null_mut};
use core::sync::atomic::{AtomicU32, Ordering};

use super::{
    ensure_locked, fclose, fdopen, fgetc, fill_locked, flush_locked, fopen, make_file,
    put_byte_locked, set_err, slock, sunlock, File, EINTR, EINVAL, EOF, F_EOF, F_ERR, F_OWNBUF,
    F_READ, F_WRITE, STDIO_BUF,
};
use crate::errno::{__errno_location, errno_load};
use crate::fcntl::{fcntl, open, F_SETFD, O_CLOEXEC, O_CREAT, O_EXCL, O_RDONLY, O_RDWR};
use crate::malloc::{free, malloc, realloc};
use crate::process::{fork, waitpid};
use crate::syscall::{syscall1, syscall3, syscall_ret};
use crate::unistd::{close, dup2, dup3, getpid, lseek, pipe2, SEEK_CUR, SEEK_END, SEEK_SET};

/// musl `include/stdio.h:46-48`.
#[cfg(target_arch = "x86_64")]
const _IOFBF: c_int = 0;
/// musl `include/stdio.h:47`.
#[cfg(target_arch = "x86_64")]
const _IOLBF: c_int = 1;
/// musl `include/stdio.h:48`.
#[cfg(target_arch = "x86_64")]
const _IONBF: c_int = 2;

/// musl `arch/generic/bits/errno.h`.
#[cfg(target_arch = "x86_64")]
const ENOMEM: c_int = 12;
/// musl `arch/generic/bits/errno.h`.
#[cfg(target_arch = "x86_64")]
const EBADF: c_int = 9;
/// musl `arch/generic/bits/errno.h`.
#[cfg(target_arch = "x86_64")]
const EOVERFLOW: c_int = 75;
/// musl `arch/generic/bits/errno.h`.
#[cfg(target_arch = "x86_64")]
const ENAMETOOLONG: c_int = 36;
/// musl `arch/generic/bits/errno.h`.
#[cfg(target_arch = "x86_64")]
const ECHILD: c_int = 10;

/// Our bit: memory-backed stream (`/dev/null` fd, data in the buffer).
#[cfg(target_arch = "x86_64")]
pub(crate) const F_MEM: u32 = 1 << 30;

/// musl `SYS_exit` / `SYS_exit_group` (x86_64).
#[cfg(target_arch = "x86_64")]
const SYS_EXIT: usize = 60;
#[cfg(target_arch = "x86_64")]
const SYS_EXIT_GROUP: usize = 231;
/// musl `SYS_unlinkat` (x86_64).
#[cfg(target_arch = "x86_64")]
const SYS_UNLINKAT: usize = 263;

/// Diverging child exit without handlers (same shape as the
/// `crate::exit::_Exit` trap, local so test builds — where `_Exit` is
/// configured out — can use it too: raw traps, never errno or locks).
#[cfg(target_arch = "x86_64")]
unsafe fn child_exit(code: c_int) -> ! {
    unsafe {
        syscall1(SYS_EXIT_GROUP, code as usize);
        loop {
            syscall1(SYS_EXIT, code as usize);
        }
    }
}
#[cfg(target_arch = "x86_64")]
const AT_FDCWD: c_int = -100;
/// musl `tmpfile.c`/`tmpnam.c` retry bound.
#[cfg(target_arch = "x86_64")]
const MAXTRIES: usize = 100;
/// musl `include/stdio.h:54` (`L_tmpnam`).
#[cfg(target_arch = "x86_64")]
const L_TMPNAM: usize = 20;
/// musl `PATH_MAX` corner for `tempnam`.
#[cfg(target_arch = "x86_64")]
const PATH_MAX: usize = 4096;
/// Side-table bounds (swept against the open list; see below).
#[cfg(target_arch = "x86_64")]
const TAB_MAX: usize = 64;

/// musl `include/stdio.h:56-60`: 16-byte `fpos_t`, offset first, the
/// multibyte state after it (opaque zeros until wide orientation lands).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct FposT {
    pub off: i64,
    pub state: [u8; 8],
}

#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<FposT>() == 16);

/// `popen` child registry: musl keeps `pipe_pid` in the `FILE`; our
/// `File` has no spare field, so a bounded table pairs stream to pid.
/// Slots are reclaimed at `pclose`; stale ones (stream `fclose`d
/// directly) are swept against the open list on every insert.
#[cfg(target_arch = "x86_64")]
static mut PIPE_TAB: [(*mut File, c_int); TAB_MAX] = [(null_mut(), 0); TAB_MAX];

/// `open_memstream` pointers: the buffer pointer and size cell live with
/// the caller, so a bounded table maps stream to both. Same sweep rule
/// as [`PIPE_TAB`]; entries are validated by stream address plus the
/// `F_MEM` bit on use.
#[cfg(target_arch = "x86_64")]
static mut MEMTAB: [(*mut File, *mut *mut c_char, *mut usize); TAB_MAX] =
    [(null_mut(), null_mut(), null_mut()); TAB_MAX];

/// 1-byte staging for `_IONBF` streams that own no buffer (transient use
/// only, always under the stdio lock).
#[cfg(target_arch = "x86_64")]
static mut IONBF_SCRATCH: u8 = 0;

/// `tmpnam(NULL)` round-trip box (musl-identical static).
#[cfg(target_arch = "x86_64")]
static mut TMPNAM_BUF: [c_char; L_TMPNAM] = [0; L_TMPNAM];

/// Name-mangling counter (template suffixes + test tags).
#[cfg(target_arch = "x86_64")]
static CTR: AtomicU32 = AtomicU32::new(0x243F_6A88);

/// musl `__randname` shape (alphanumeric suffix; `O_EXCL` retries make
/// collisions harmless, so a pid+counter LCG is enough).
#[cfg(target_arch = "x86_64")]
unsafe fn rand6(out: *mut u8) {
    unsafe {
        const ALNUM: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let pid = getpid() as u32;
        let c = CTR.fetch_add(0x9E37_79B1, Ordering::Relaxed);
        let mut x = pid.wrapping_mul(0x85EB_CA6B) ^ c.wrapping_add(0xC2B2_AE35);
        let mut i = 0usize;
        while i < 6 {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            *out.add(i) = ALNUM[(x >> 16) as usize % 62];
            i += 1;
        }
    }
}

/// NUL-terminated length (caller guarantees termination).
#[cfg(target_arch = "x86_64")]
unsafe fn cstrlen(p: *const c_char) -> usize {
    unsafe {
        let mut n = 0usize;
        while *p.add(n) != 0 {
            n = n.wrapping_add(1);
        }
        n
    }
}

/// Bounded length (never reads past `max`).
#[cfg(target_arch = "x86_64")]
unsafe fn memlen(p: *const u8, max: usize) -> usize {
    unsafe {
        let mut n = 0usize;
        while n < max && *p.add(n) != 0 {
            n = n.wrapping_add(1);
        }
        n
    }
}

/// True while `f` is on the open list (lock held).
#[cfg(target_arch = "x86_64")]
unsafe fn listed(f: *mut File) -> bool {
    unsafe {
        let mut cur = addr_of_mut!(super::OPEN_LIST).read();
        while !cur.is_null() {
            if cur == f {
                return true;
            }
            cur = (*cur).next;
        }
        false
    }
}

/// Drop table slots whose stream left the open list (lock held).
#[cfg(target_arch = "x86_64")]
unsafe fn sweep_pipes() {
    unsafe {
        let mut i = 0usize;
        while i < TAB_MAX {
            let e = PIPE_TAB[i];
            if !e.0.is_null() && !listed(e.0) {
                PIPE_TAB[i] = (null_mut(), 0);
            }
            i += 1;
        }
    }
}

/// Same sweep for the memstream table (lock held).
#[cfg(target_arch = "x86_64")]
unsafe fn sweep_mems() {
    unsafe {
        let mut i = 0usize;
        while i < TAB_MAX {
            let e = MEMTAB[i];
            if !e.0.is_null() && !listed(e.0) {
                MEMTAB[i] = (null_mut(), null_mut(), null_mut());
            }
            i += 1;
        }
    }
}

/// Look up a memstream's caller cells (nulls when absent; lock held).
#[cfg(target_arch = "x86_64")]
unsafe fn mem_slot(f: *mut File) -> (*mut *mut c_char, *mut usize) {
    unsafe {
        let mut i = 0usize;
        while i < TAB_MAX {
            if MEMTAB[i].0 == f {
                return (MEMTAB[i].1, MEMTAB[i].2);
            }
            i += 1;
        }
        (null_mut(), null_mut())
    }
}

/// Forget a memstream's cells without touching the buffer (lock held).
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn mem_forget(f: *mut File) {
    unsafe {
        let mut i = 0usize;
        while i < TAB_MAX {
            if MEMTAB[i].0 == f {
                MEMTAB[i] = (null_mut(), null_mut(), null_mut());
                return;
            }
            i += 1;
        }
    }
}

/// Fold pending writes into the readable length and keep musl's trailing
/// NUL (`buf[len] == 0` while it fits). Returns the length (lock held).
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn mem_fold(f: *mut File) -> usize {
    unsafe {
        let len = (*f).rlen.max((*f).wpos);
        if len < (*f).cap && !(*f).buf.is_null() {
            *(*f).buf.add(len) = 0;
        }
        len
    }
}

/// Refresh the caller's `*sizep` from the folded length (lock held).
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn mem_sync(f: *mut File) {
    unsafe {
        let (_, sp) = mem_slot(f);
        if !sp.is_null() {
            *sp = (*f).rlen.max((*f).wpos);
        }
    }
}

/// Grow a memstream's buffer past `need` (lock held). Zeroes the new
/// area like musl; updates the stream and the caller's `*bufp`.
#[cfg(target_arch = "x86_64")]
pub(crate) unsafe fn mem_grow(f: *mut File, need: usize) -> c_int {
    unsafe {
        let (bp, _) = mem_slot(f);
        if bp.is_null() {
            set_err(EINVAL);
            return -1;
        }
        let mut newcap = (*f).cap.max(1);
        while newcap <= need {
            newcap = match newcap.checked_mul(2) {
                Some(v) => v,
                None => {
                    set_err(ENOMEM);
                    return -1;
                }
            };
        }
        let nb = realloc((*f).buf as *mut c_void, newcap) as *mut u8;
        if nb.is_null() {
            set_err(ENOMEM);
            (*f).flags |= F_ERR;
            return -1;
        }
        let mut k = (*f).cap;
        while k < newcap {
            *nb.add(k) = 0;
            k = k.wrapping_add(1);
        }
        (*f).buf = nb;
        (*f).cap = newcap;
        *bp = nb as *mut c_char;
        0
    }
}

/// Positioning on a memory stream: fold, then place all three cursors
/// (`rpos`/`rlen` window plus `wpos`) at the target, growing memstreams
/// past the end. Fixed `fmemopen` areas refuse seeks past `cap`
/// (musl `mseek` fails past `size`). Returns 0 or -1 (lock held).
#[cfg(target_arch = "x86_64")]
unsafe fn mem_seek(f: *mut File, off: i64, whence: c_int) -> c_int {
    unsafe {
        let len = mem_fold(f);
        let base: i64 = match whence {
            SEEK_SET => 0,
            SEEK_CUR => (*f).rpos.max((*f).wpos) as i64,
            SEEK_END => len as i64,
            _ => {
                set_err(EINVAL);
                return -1;
            }
        };
        let np = match base.checked_add(off) {
            Some(v) => v,
            None => {
                set_err(EOVERFLOW);
                return -1;
            }
        };
        if np < 0 {
            set_err(EINVAL);
            return -1;
        }
        let npz = np as usize;
        if npz > (*f).cap {
            let (bp, _) = mem_slot(f);
            if bp.is_null() {
                set_err(EINVAL);
                return -1;
            }
            if mem_grow(f, npz) != 0 {
                return -1;
            }
        }
        (*f).rpos = npz;
        (*f).rlen = len.max(npz);
        (*f).wpos = npz;
        (*f).flags &= !F_EOF;
        mem_sync(f);
        0
    }
}

/// Positioning on an fd-backed stream: flush writes, drop the read
/// window (adjusting `SEEK_CUR` for buffered-but-unread bytes, musl
/// `__fseeko_unlocked`), then `lseek`. Returns 0 or -1 (lock held).
#[cfg(target_arch = "x86_64")]
unsafe fn real_seek(f: *mut File, off: i64, whence: c_int) -> c_int {
    unsafe {
        let mut o = off;
        if whence == SEEK_CUR {
            let buffered = (*f).rlen.saturating_sub((*f).rpos) as i64;
            o = match o.checked_sub(buffered) {
                Some(v) => v,
                None => {
                    set_err(EOVERFLOW);
                    return -1;
                }
            };
        }
        if !flush_locked(f) {
            return -1;
        }
        (*f).rpos = 0;
        (*f).rlen = 0;
        if lseek((*f).fd, o, whence) < 0 {
            return -1;
        }
        (*f).flags &= !F_EOF;
        0
    }
}

/// Build a memory stream over `buf`/`cap` (lock held). The fd is
/// `CLOEXEC` `/dev/null` so inherited flush/close/EOF paths behave;
/// the data area is never freed here (`F_OWNBUF` decides that).
#[cfg(target_arch = "x86_64")]
unsafe fn mem_file(read: bool, write: bool, buf: *mut u8, cap: usize, ownbuf: bool) -> *mut File {
    unsafe {
        let dn = open(c"/dev/null".as_ptr(), O_RDWR | O_CLOEXEC, 0);
        if dn < 0 {
            return null_mut();
        }
        let f = make_file(dn, read, write);
        if f.is_null() {
            close(dn);
            return null_mut();
        }
        free((*f).buf as *mut c_void);
        (*f).buf = buf;
        (*f).cap = cap;
        (*f).rpos = 0;
        (*f).rlen = 0;
        (*f).wpos = 0;
        if ownbuf {
            (*f).flags |= F_OWNBUF;
        } else {
            (*f).flags &= !F_OWNBUF;
        }
        (*f).flags |= F_MEM;
        if cap == 0 && !write {
            (*f).flags |= F_EOF;
        }
        f
    }
}

/// `open`-probe: true when the path opens (used for tmp name selection).
#[cfg(target_arch = "x86_64")]
unsafe fn exists_probe(path: *const c_char) -> bool {
    unsafe {
        let fd = open(path, O_RDONLY, 0);
        if fd < 0 {
            return false;
        }
        close(fd);
        true
    }
}

/// Reopen a stream on a new file (musl `freopen`: the new `FILE` is
/// hacked into the old one, then closed).
///
/// # Safety
///
/// `f` must be a live stream; `filename`/`mode` (when non-null) valid
/// NUL-terminated strings.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn freopen(
    filename: *const c_char,
    mode: *const c_char,
    f: *mut File,
) -> *mut File {
    unsafe {
        if f.is_null() || mode.is_null() {
            set_err(EINVAL);
            return null_mut();
        }
        slock();
        ensure_locked();
        let _ = flush_locked(f);
        sunlock();
        if filename.is_null() {
            return f;
        }
        let f2 = fopen(filename, mode);
        if f2.is_null() {
            fclose(f);
            return null_mut();
        }
        // Memory streams have no fd-backed state to carry over: demote
        // to a plain buffered stream first (caller-owned buffers are
        // orphaned back to the caller, ours are freed).
        if ((*f).flags & F_MEM) != 0 {
            let nb = malloc(STDIO_BUF) as *mut u8;
            if nb.is_null() {
                fclose(f2);
                set_err(ENOMEM);
                return null_mut();
            }
            slock();
            ensure_locked();
            mem_forget(f);
            if ((*f).flags & F_OWNBUF) != 0 && !(*f).buf.is_null() {
                free((*f).buf as *mut c_void);
            }
            (*f).buf = nb;
            (*f).cap = STDIO_BUF;
            (*f).flags = ((*f).flags & !(F_MEM | F_EOF | F_ERR)) | F_OWNBUF;
            (*f).wpos = 0;
            (*f).rpos = 0;
            (*f).rlen = 0;
            (*f).line_buf = false;
            sunlock();
        }
        // `e` requests close-on-exec on the transplanted fd.
        let mut cloexec = false;
        let mut m = mode;
        while *m != 0 {
            if *m as u8 == b'e' {
                cloexec = true;
                break;
            }
            m = m.add(1);
        }
        let src = (*f2).fd;
        let dst = (*f).fd;
        if src != dst {
            let r = if cloexec {
                dup3(src, dst, O_CLOEXEC)
            } else {
                dup2(src, dst)
            };
            if r < 0 {
                fclose(f2);
                fclose(f);
                return null_mut();
            }
        }
        slock();
        ensure_locked();
        (*f).flags = ((*f).flags & F_OWNBUF) | ((*f2).flags & (F_READ | F_WRITE));
        (*f).line_buf = (*f2).line_buf;
        (*f).wpos = 0;
        (*f).rpos = 0;
        (*f).rlen = 0;
        if src == dst {
            // Same fd (reopening the same file): keep it, stop `fclose`
            // from closing it out from under us.
            (*f2).fd = -1;
        }
        sunlock();
        fclose(f2);
        f
    }
}

/// `fgetc` alias (musl `getc` is a macro over it).
///
/// # Safety
///
/// `f` must be a live readable stream.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getc(f: *mut File) -> c_int {
    unsafe { fgetc(f) }
}

/// Write one byte (musl `fputc`: buffered, newline-flushed when
/// line-buffered).
///
/// # Safety
///
/// `f` must be a live writable stream.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fputc(c: c_int, f: *mut File) -> c_int {
    unsafe {
        if f.is_null() {
            set_err(EINVAL);
            return EOF;
        }
        let b = c as u8;
        slock();
        ensure_locked();
        let rc = if ((*f).flags & F_WRITE) == 0 {
            (*f).flags |= F_ERR;
            EOF
        } else {
            (*f).rpos = 0;
            (*f).rlen = 0;
            if put_byte_locked(f, b) {
                b as c_int
            } else {
                EOF
            }
        };
        sunlock();
        rc
    }
}

/// `fputc` alias (musl `putc` is a macro over it).
///
/// # Safety
///
/// Same contract as [`fputc`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn putc(c: c_int, f: *mut File) -> c_int {
    unsafe { fputc(c, f) }
}

/// `fputc` to `stdout`.
///
/// # Safety
///
/// Pure byte output; same contract as [`fputc`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn putchar(c: c_int) -> c_int {
    unsafe {
        slock();
        ensure_locked();
        let f = addr_of_mut!(super::stdout).read();
        sunlock();
        fputc(c, f)
    }
}

/// Read a line (musl `fgets`: up to `n-1` bytes, stops after `\n`,
/// always NUL-terminates; `NULL` on empty EOF or error).
///
/// # Safety
///
/// `f` live and readable; `s` writable for `n` bytes when `n > 0`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fgets(s: *mut c_char, n: c_int, f: *mut File) -> *mut c_char {
    unsafe {
        if s.is_null() || f.is_null() {
            set_err(EINVAL);
            return null_mut();
        }
        if n <= 1 {
            if n < 1 {
                return null_mut();
            }
            *s = 0;
            return s;
        }
        slock();
        ensure_locked();
        let mut p = s as *mut u8;
        let mut left = (n as usize).wrapping_sub(1);
        let start = p;
        loop {
            if (*f).rpos < (*f).rlen {
                // Fast lane: copy through the next newline (or the
                // window's end), capped by the room left.
                let avail = (*f).rlen - (*f).rpos;
                let mut k = 0usize;
                while k < avail && k < left {
                    if *(*f).buf.add((*f).rpos.wrapping_add(k)) == b'\n' {
                        k = k.wrapping_add(1);
                        break;
                    }
                    k = k.wrapping_add(1);
                }
                core::ptr::copy_nonoverlapping((*f).buf.add((*f).rpos), p, k);
                (*f).rpos = (*f).rpos.wrapping_add(k);
                p = p.add(k);
                left -= k;
                // Stopped at a newline or out of room: line done
                // (`k >= 1` here: the window and the room are both
                // non-empty on entry to this arm).
                if *p.sub(1) == b'\n' || left == 0 {
                    break;
                }
            } else {
                if !fill_locked(f) {
                    break;
                }
                let b = *(*f).buf.add((*f).rpos);
                (*f).rpos = (*f).rpos.wrapping_add(1);
                *p = b;
                p = p.add(1);
                left -= 1;
                if b == b'\n' || left == 0 {
                    break;
                }
            }
        }
        let rc = if p == start || ((*f).flags & F_ERR) != 0 {
            null_mut()
        } else {
            *p = 0;
            s
        };
        sunlock();
        rc
    }
}

/// Push one byte back (musl `ungetc`: single byte; needs `rpos > 0` or
/// a fresh stream since there is no `UNGET` headroom).
///
/// # Safety
///
/// `f` must be a live readable stream.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ungetc(c: c_int, f: *mut File) -> c_int {
    unsafe {
        if c == EOF {
            return EOF;
        }
        if f.is_null() {
            set_err(EINVAL);
            return EOF;
        }
        slock();
        ensure_locked();
        let mut rc = EOF;
        if ((*f).flags & F_READ) == 0 {
            (*f).flags |= F_ERR;
        } else {
            // Reads commit pending writes first (same rule as refill).
            if (*f).wpos == 0 || flush_locked(f) {
                let b = c as u8;
                if (*f).rpos > 0 {
                    (*f).rpos -= 1;
                    *(*f).buf.add((*f).rpos) = b;
                    (*f).flags &= !F_EOF;
                    rc = b as c_int;
                } else if (*f).rpos == 0 && (*f).rlen == 0 && (*f).cap > 0 && !(*f).buf.is_null() {
                    *(*f).buf = b;
                    (*f).rlen = 1;
                    (*f).flags &= !F_EOF;
                    rc = b as c_int;
                }
            }
        }
        sunlock();
        rc
    }
}

/// Reposition a stream (musl `fseek`).
///
/// # Safety
///
/// `f` must be a live seekable stream.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fseek(f: *mut File, off: c_long, whence: c_int) -> c_int {
    unsafe {
        if f.is_null() {
            set_err(EINVAL);
            return -1;
        }
        if whence != SEEK_SET && whence != SEEK_CUR && whence != SEEK_END {
            set_err(EINVAL);
            return -1;
        }
        slock();
        ensure_locked();
        let rc = if ((*f).flags & F_MEM) != 0 {
            mem_seek(f, off, whence)
        } else {
            real_seek(f, off, whence)
        };
        sunlock();
        rc
    }
}

/// Report the current position (musl `ftell`: underlying offset
/// adjusted for buffered bytes on either side).
///
/// # Safety
///
/// `f` must be a live seekable stream.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ftell(f: *mut File) -> c_long {
    unsafe {
        if f.is_null() {
            set_err(EINVAL);
            return -1;
        }
        slock();
        ensure_locked();
        let mut rc: c_long = -1;
        if ((*f).flags & F_MEM) != 0 {
            rc = (*f).rpos.max((*f).wpos) as c_long;
            mem_sync(f);
        } else {
            let pos = lseek((*f).fd, 0, SEEK_CUR);
            if pos >= 0 {
                if (*f).rlen > 0 {
                    let buffered = (*f).rlen.saturating_sub((*f).rpos) as i64;
                    if let Some(v) = pos.checked_sub(buffered) {
                        rc = v;
                    } else {
                        set_err(EOVERFLOW);
                    }
                } else if let Some(v) = pos.checked_add((*f).wpos as i64) {
                    rc = v;
                } else {
                    set_err(EOVERFLOW);
                }
            }
        }
        sunlock();
        rc
    }
}

/// Reset to the start and clear `ERR` (musl `rewind`: errors ignored).
///
/// # Safety
///
/// `f` must be a live seekable stream.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn rewind(f: *mut File) {
    unsafe {
        let _ = fseek(f, 0, SEEK_SET);
        if !f.is_null() {
            slock();
            ensure_locked();
            (*f).flags &= !F_ERR;
            sunlock();
        }
    }
}

/// Store the current position (musl `fgetpos`: offset half only, state
/// zeroed).
///
/// # Safety
///
/// `f` live and seekable; `pos` writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fgetpos(f: *mut File, pos: *mut FposT) -> c_int {
    unsafe {
        if f.is_null() || pos.is_null() {
            set_err(EINVAL);
            return -1;
        }
        let off = ftell(f);
        if off < 0 {
            return -1;
        }
        (*pos).off = off;
        (*pos).state = [0; 8];
        0
    }
}

/// Restore a saved position (musl `fsetpos`).
///
/// # Safety
///
/// `f` live and seekable; `pos` readable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fsetpos(f: *mut File, pos: *const FposT) -> c_int {
    unsafe {
        if f.is_null() || pos.is_null() {
            set_err(EINVAL);
            return -1;
        }
        fseek(f, (*pos).off, SEEK_SET)
    }
}

/// End-of-file sticky bit (musl `feof`).
///
/// # Safety
///
/// Null tolerated (reports false); otherwise `f` must be a live stream.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn feof(f: *mut File) -> c_int {
    unsafe {
        if f.is_null() {
            set_err(EINVAL);
            return 0;
        }
        slock();
        ensure_locked();
        let rc = (((*f).flags & F_EOF) != 0) as c_int;
        sunlock();
        rc
    }
}

/// Error sticky bit (musl `ferror`).
///
/// # Safety
///
/// Null tolerated (reports false); otherwise `f` must be a live stream.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ferror(f: *mut File) -> c_int {
    unsafe {
        if f.is_null() {
            set_err(EINVAL);
            return 0;
        }
        slock();
        ensure_locked();
        let rc = (((*f).flags & F_ERR) != 0) as c_int;
        sunlock();
        rc
    }
}

/// Clear both sticky bits (musl `clearerr`).
///
/// # Safety
///
/// Null tolerated; otherwise `f` must be a live stream.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn clearerr(f: *mut File) {
    unsafe {
        if f.is_null() {
            set_err(EINVAL);
            return;
        }
        slock();
        ensure_locked();
        (*f).flags &= !(F_EOF | F_ERR);
        sunlock();
    }
}

/// Underlying fd (musl `fileno`: -1 with `EBADF` when closed).
///
/// # Safety
///
/// `f` must be a live stream (memory streams report the backing fd).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fileno(f: *mut File) -> c_int {
    unsafe {
        if f.is_null() {
            set_err(EBADF);
            return -1;
        }
        slock();
        ensure_locked();
        let fd = (*f).fd;
        sunlock();
        if fd < 0 {
            set_err(EBADF);
            return -1;
        }
        fd
    }
}

/// Select buffering (musl `setvbuf`: no locking there since it must run
/// first; taking the lock here is the same exclusion, coarser).
///
/// # Safety
///
/// `f` must be a live stream; `buf` (when non-null) writable for `size`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setvbuf(
    f: *mut File,
    buf: *mut c_char,
    type_: c_int,
    size: usize,
) -> c_int {
    unsafe {
        if f.is_null() {
            set_err(EINVAL);
            return -1;
        }
        if type_ != _IOFBF && type_ != _IOLBF && type_ != _IONBF {
            return -1;
        }
        slock();
        ensure_locked();
        // Memory streams own their window; only the line mode applies.
        if ((*f).flags & F_MEM) != 0 {
            (*f).line_buf = type_ == _IOLBF;
            sunlock();
            return 0;
        }
        // Committed output stays valid across the switch; unread input
        // is indexed into the old buffer, so it goes with it.
        let _ = flush_locked(f);
        (*f).rpos = 0;
        (*f).rlen = 0;
        if type_ == _IONBF {
            (*f).line_buf = false;
            if ((*f).flags & F_READ) == 0 {
                // Write-only: direct, like our stock unbuffered stderr.
                (*f).cap = 0;
            } else if !buf.is_null() && size > 0 {
                if ((*f).flags & F_OWNBUF) != 0 && !(*f).buf.is_null() {
                    free((*f).buf as *mut c_void);
                }
                (*f).buf = buf as *mut u8;
                (*f).cap = 1;
                (*f).flags &= !F_OWNBUF;
            } else if (*f).cap > 0 && !(*f).buf.is_null() {
                (*f).cap = 1;
            } else {
                if ((*f).flags & F_OWNBUF) != 0 && !(*f).buf.is_null() {
                    free((*f).buf as *mut c_void);
                }
                (*f).buf = addr_of_mut!(IONBF_SCRATCH);
                (*f).cap = 1;
                (*f).flags &= !F_OWNBUF;
            }
        } else {
            (*f).line_buf = type_ == _IOLBF;
            if !buf.is_null() && size > 0 {
                if ((*f).flags & F_OWNBUF) != 0 && !(*f).buf.is_null() {
                    free((*f).buf as *mut c_void);
                }
                (*f).buf = buf as *mut u8;
                (*f).cap = size;
                (*f).flags &= !F_OWNBUF;
            } else if (*f).buf.is_null() || (*f).cap == 0 {
                let want = if size > 0 { size } else { STDIO_BUF };
                let nb = malloc(want) as *mut u8;
                if nb.is_null() {
                    sunlock();
                    set_err(ENOMEM);
                    return -1;
                }
                if ((*f).flags & F_OWNBUF) != 0 && !(*f).buf.is_null() {
                    free((*f).buf as *mut c_void);
                }
                (*f).buf = nb;
                (*f).cap = want;
                (*f).flags |= F_OWNBUF;
            }
        }
        sunlock();
        0
    }
}

/// Full buffering on `buf`, unbuffered on null (musl `setbuf`).
///
/// # Safety
///
/// Same contract as [`setvbuf`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setbuf(f: *mut File, buf: *mut c_char) {
    unsafe {
        setvbuf(
            f,
            buf,
            if buf.is_null() { _IONBF } else { _IOFBF },
            STDIO_BUF,
        );
    }
}

/// Sized `setbuf` (BSD `setbuffer`).
///
/// # Safety
///
/// Same contract as [`setvbuf`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setbuffer(f: *mut File, buf: *mut c_char, size: usize) {
    unsafe {
        setvbuf(f, buf, if buf.is_null() { _IONBF } else { _IOFBF }, size);
    }
}

/// Line buffering (BSD `setlinebuf`).
///
/// # Safety
///
/// `f` must be a live stream.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setlinebuf(f: *mut File) {
    unsafe {
        setvbuf(f, null_mut(), _IOLBF, 0);
    }
}

/// Read through a delimiter, growing `*s` (musl `getdelim`).
///
/// # Safety
///
/// `f` live and readable; `s`/`n` writable; `*s` null or malloc'd.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getdelim(
    s: *mut *mut c_char,
    n: *mut usize,
    delim: c_int,
    f: *mut File,
) -> isize {
    unsafe {
        if s.is_null() || n.is_null() || f.is_null() {
            if !f.is_null() {
                slock();
                ensure_locked();
                (*f).flags |= F_ERR;
                sunlock();
            }
            set_err(EINVAL);
            return -1;
        }
        let d = delim as u8;
        slock();
        ensure_locked();
        if (*s).is_null() {
            *n = 0;
        }
        let mut i = 0usize;
        let rc: isize = loop {
            // Window fast lane: copy through the delimiter (or the
            // window's end), growing first when it cannot fit.
            let mut k = 0usize;
            let mut found = false;
            while (*f).rpos.wrapping_add(k) < (*f).rlen {
                k = k.wrapping_add(1);
                if *(*f).buf.add((*f).rpos.wrapping_add(k).wrapping_sub(1)) == d {
                    found = true;
                    break;
                }
            }
            if i.wrapping_add(k) >= *n {
                let mut m = match i.checked_add(k.wrapping_add(2)) {
                    Some(v) => v,
                    None => {
                        (*f).flags |= F_ERR;
                        set_err(ENOMEM);
                        break -1;
                    }
                };
                if !found {
                    if let Some(grown) = m.checked_add(m / 2) {
                        m = grown;
                    }
                }
                let tmp = realloc(*s as *mut c_void, m) as *mut c_char;
                if tmp.is_null() {
                    (*f).flags |= F_ERR;
                    set_err(ENOMEM);
                    break -1;
                }
                *s = tmp;
                *n = m;
            }
            if k > 0 {
                core::ptr::copy_nonoverlapping((*f).buf.add((*f).rpos), (*s as *mut u8).add(i), k);
                (*f).rpos = (*f).rpos.wrapping_add(k);
                i = i.wrapping_add(k);
            }
            if found {
                break i as isize;
            }
            // One byte past the window (room guaranteed by the check).
            if (*f).rpos >= (*f).rlen && !fill_locked(f) {
                if i == 0 || ((*f).flags & F_ERR) != 0 {
                    break -1;
                }
                break i as isize;
            }
            if i.wrapping_add(1) >= *n {
                let m = match i.checked_add(2) {
                    Some(v) => v,
                    None => {
                        (*f).flags |= F_ERR;
                        set_err(ENOMEM);
                        break -1;
                    }
                };
                let tmp = realloc(*s as *mut c_void, m) as *mut c_char;
                if tmp.is_null() {
                    (*f).flags |= F_ERR;
                    set_err(ENOMEM);
                    break -1;
                }
                *s = tmp;
                *n = m;
            }
            let b = *(*f).buf.add((*f).rpos);
            (*f).rpos = (*f).rpos.wrapping_add(1);
            *(*s as *mut u8).add(i) = b;
            i = i.wrapping_add(1);
            if b == d {
                break i as isize;
            }
        };
        if rc >= 0 {
            *(*s as *mut u8).add(i) = 0;
        }
        sunlock();
        rc
    }
}

/// Read a line, growing `*s` (musl `getline` is `getdelim('\n')`).
///
/// # Safety
///
/// Same contract as [`getdelim`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getline(s: *mut *mut c_char, n: *mut usize, f: *mut File) -> isize {
    unsafe { getdelim(s, n, b'\n' as c_int, f) }
}

/// Open a pipe to a shell command (musl `popen`: fork+pipe+`sh -c`;
/// the child closes our pipe ends and the registered popen fds so EOF
/// still propagates).
///
/// # Safety
///
/// `cmd`/`mode` valid strings; `mode` starts with `r` or `w`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn popen(cmd: *const c_char, mode: *const c_char) -> *mut File {
    unsafe {
        if cmd.is_null() || mode.is_null() {
            set_err(EINVAL);
            return null_mut();
        }
        let op: usize = match *mode as u8 {
            b'r' => 0,
            b'w' => 1,
            _ => {
                set_err(EINVAL);
                return null_mut();
            }
        };
        let mut p = [0 as c_int; 2];
        if pipe2(p.as_mut_ptr(), O_CLOEXEC) != 0 {
            return null_mut();
        }
        let f = fdopen(p[op], mode);
        if f.is_null() {
            close(p[0]);
            close(p[1]);
            return null_mut();
        }
        let pid = fork();
        if pid < 0 {
            fclose(f);
            close(p[1 - op]);
            return null_mut();
        }
        if pid == 0 {
            close(p[op]);
            if dup2(p[1 - op], (1 - op) as c_int) < 0 {
                child_exit(127);
            }
            if p[1 - op] != (1 - op) as c_int {
                close(p[1 - op]);
            }
            // Snapshot read (no locks past `fork`): shut sibling popen
            // ends, never our own pipe.
            let mut i = 0usize;
            while i < TAB_MAX {
                let e = PIPE_TAB[i];
                if !e.0.is_null() {
                    let cfd = (*e.0).fd;
                    if cfd != p[0] && cfd != p[1] {
                        close(cfd);
                    }
                }
                i += 1;
            }
            execlp(
                c"sh".as_ptr(),
                c"sh".as_ptr(),
                c"-c".as_ptr(),
                cmd,
                null::<c_char>(),
            );
            child_exit(127);
        }
        close(p[1 - op]);
        // Keep close-on-exec only under `e` (musl `popen` rule).
        let mut e = false;
        let mut m = mode.add(1);
        while *m != 0 {
            if *m as u8 == b'e' {
                e = true;
                break;
            }
            m = m.add(1);
        }
        if !e {
            fcntl(p[op], F_SETFD, 0);
        }
        slock();
        ensure_locked();
        sweep_pipes();
        let mut placed = false;
        let mut i = 0usize;
        while i < TAB_MAX {
            if PIPE_TAB[i].0.is_null() {
                PIPE_TAB[i] = (f, pid);
                placed = true;
                break;
            }
            i += 1;
        }
        sunlock();
        if !placed {
            fclose(f);
            set_err(ENOMEM);
            return null_mut();
        }
        f
    }
}

/// Close a `popen` stream and report the child's raw status (musl
/// `pclose`: close first, then reap with `EINTR` retries).
///
/// # Safety
///
/// `f` must be a live `popen` stream; anything else is `EINVAL`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn pclose(f: *mut File) -> c_int {
    unsafe {
        if f.is_null() {
            set_err(EINVAL);
            return -1;
        }
        slock();
        ensure_locked();
        let mut pid = 0 as c_int;
        let mut ok = false;
        if listed(f) {
            let mut i = 0usize;
            while i < TAB_MAX {
                if PIPE_TAB[i].0 == f {
                    pid = PIPE_TAB[i].1;
                    PIPE_TAB[i] = (null_mut(), 0);
                    ok = true;
                    break;
                }
                i += 1;
            }
        }
        sunlock();
        if !ok {
            set_err(EINVAL);
            return -1;
        }
        fclose(f);
        let mut st = 0 as c_int;
        loop {
            let r = waitpid(pid, &mut st, 0);
            if r == pid {
                return st;
            }
            if r < 0 {
                if errno_load(__errno_location()) == EINTR {
                    continue;
                }
                if errno_load(__errno_location()) == ECHILD {
                    set_err(ECHILD);
                }
                return -1;
            }
        }
    }
}

/// Anonymous read/write scratch file (musl `tmpfile`: `O_EXCL` create
/// in `/tmp`, unlinked at once).
#[cfg(target_arch = "x86_64")]
/// Open an anonymous temporary file (musl `tmpfile`).
///
/// # Safety
///
/// Pure constructor; the returned `File` must be `fclose`d.
#[no_mangle]
pub unsafe extern "C" fn tmpfile() -> *mut File {
    unsafe {
        let mut try_ = 0usize;
        while try_ < MAXTRIES {
            try_ = try_.wrapping_add(1);
            let mut t = *b"/tmp/tmpfile_XXXXXX\0";
            rand6(t.as_mut_ptr().add(13));
            let fd = open(
                t.as_ptr() as *const c_char,
                O_RDWR | O_CREAT | O_EXCL,
                0o600,
            );
            if fd < 0 {
                continue;
            }
            let _ = syscall_ret(syscall3(
                SYS_UNLINKAT,
                (AT_FDCWD as isize) as usize,
                t.as_ptr() as usize,
                0,
            ));
            let f = fdopen(fd, c"w+".as_ptr());
            if f.is_null() {
                close(fd);
                return null_mut();
            }
            return f;
        }
        null_mut()
    }
}

/// Unique `/tmp` name (musl `tmpnam`, `open`-probed, static box on null).
///
/// # Safety
///
/// `buf` null or writable for `L_tmpnam` (20) bytes.
#[cfg(target_arch = "x86_64")]
/// Generate a unique temporary file name (musl `tmpnam`).
///
/// # Safety
///
/// `buf` must be null or point at `L_tmpnam` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn tmpnam(buf: *mut c_char) -> *mut c_char {
    unsafe {
        let mut try_ = 0usize;
        while try_ < MAXTRIES {
            try_ = try_.wrapping_add(1);
            let mut t = *b"/tmp/tmpnam_XXXXXX\0";
            rand6(t.as_mut_ptr().add(12));
            if exists_probe(t.as_ptr() as *const c_char) {
                continue;
            }
            let dst = if buf.is_null() {
                addr_of_mut!(TMPNAM_BUF) as *mut c_char
            } else {
                buf
            };
            let mut i = 0usize;
            while i < t.len() {
                *dst.add(i) = t[i] as c_char;
                i = i.wrapping_add(1);
            }
            return dst;
        }
        null_mut()
    }
}

/// Unique malloc'd path under `dir` with prefix `pfx` (BSD `tempnam`,
/// `open`-probed; caller frees).
///
/// # Safety
///
/// `dir`/`pfx` null or valid strings.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn tempnam(dir: *const c_char, pfx: *const c_char) -> *mut c_char {
    unsafe {
        let d = if dir.is_null() { c"/tmp".as_ptr() } else { dir };
        let p = if pfx.is_null() { c"temp".as_ptr() } else { pfx };
        let dl = cstrlen(d);
        let pl = cstrlen(p);
        let l = match dl
            .checked_add(1)
            .and_then(|v| v.checked_add(pl))
            .and_then(|v| v.checked_add(1))
            .and_then(|v| v.checked_add(6))
        {
            Some(v) => v,
            None => {
                set_err(ENAMETOOLONG);
                return null_mut();
            }
        };
        if l >= PATH_MAX {
            set_err(ENAMETOOLONG);
            return null_mut();
        }
        let s = malloc(l.wrapping_add(1)) as *mut u8;
        if s.is_null() {
            set_err(ENOMEM);
            return null_mut();
        }
        let mut try_ = 0usize;
        while try_ < MAXTRIES {
            try_ = try_.wrapping_add(1);
            core::ptr::copy_nonoverlapping(d as *const u8, s, dl);
            *s.add(dl) = b'/';
            core::ptr::copy_nonoverlapping(p as *const u8, s.add(dl.wrapping_add(1)), pl);
            let q = dl.wrapping_add(1).wrapping_add(pl);
            *s.add(q) = b'_';
            rand6(s.add(q.wrapping_add(1)));
            *s.add(l) = 0;
            if exists_probe(s as *const c_char) {
                continue;
            }
            return s as *mut c_char;
        }
        free(s as *mut c_void);
        null_mut()
    }
}

/// Fixed-size memory stream (musl `fmemopen`, cookie-free: the data
/// area is the buffer window over a `/dev/null` fd; positions live in
/// `rpos`/`rlen`/`wpos` and sync on `fseek`).
///
/// # Safety
///
/// `buf` null (buffer malloc'd) or writable for `size`; `mode` starts
/// with `r`, `w` or `a` with an optional `+`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fmemopen(buf: *mut c_void, size: usize, mode: *const c_char) -> *mut File {
    unsafe {
        if mode.is_null() {
            set_err(EINVAL);
            return null_mut();
        }
        let m0 = *mode as u8;
        if m0 != b'r' && m0 != b'w' && m0 != b'a' {
            set_err(EINVAL);
            return null_mut();
        }
        let mut plus = false;
        let mut m = mode;
        while *m != 0 {
            if *m as u8 == b'+' {
                plus = true;
                break;
            }
            m = m.add(1);
        }
        let read = m0 == b'r' || plus;
        let write = m0 != b'r' || plus;
        let (area, cap, own) = if buf.is_null() {
            if size == 0 {
                (null_mut(), 0, true)
            } else {
                let q = malloc(size) as *mut u8;
                if q.is_null() {
                    set_err(ENOMEM);
                    return null_mut();
                }
                let mut k = 0usize;
                while k < size {
                    *q.add(k) = 0;
                    k = k.wrapping_add(1);
                }
                (q, size, true)
            }
        } else {
            (buf as *mut u8, size, false)
        };
        slock();
        ensure_locked();
        let f = mem_file(read, write, area, cap, own);
        if f.is_null() {
            if own && !area.is_null() {
                free(area as *mut c_void);
            }
            sunlock();
            set_err(ENOMEM);
            return null_mut();
        }
        if m0 == b'r' {
            (*f).rlen = cap;
        } else if m0 == b'a' && !area.is_null() {
            let pos = memlen(area, cap);
            (*f).rpos = 0;
            (*f).rlen = pos;
            (*f).wpos = pos;
        }
        sunlock();
        f
    }
}

/// Growable memory stream (musl `open_memstream`, cookie-free: malloc'd
/// buffer, length folded on `fseek`/`ftell`; the buffer outlives the
/// stream for the caller to free).
///
/// # Safety
///
/// `bufp`/`sizep` writable; `*bufp`/`*sizep` set on success.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn open_memstream(bufp: *mut *mut c_char, sizep: *mut usize) -> *mut File {
    unsafe {
        if bufp.is_null() || sizep.is_null() {
            set_err(EINVAL);
            return null_mut();
        }
        let q = malloc(STDIO_BUF) as *mut u8;
        if q.is_null() {
            set_err(ENOMEM);
            return null_mut();
        }
        *q = 0;
        slock();
        ensure_locked();
        let f = mem_file(true, true, q, STDIO_BUF, false);
        if f.is_null() {
            sunlock();
            free(q as *mut c_void);
            set_err(ENOMEM);
            return null_mut();
        }
        sweep_mems();
        let mut placed = false;
        let mut i = 0usize;
        while i < TAB_MAX {
            if MEMTAB[i].0.is_null() {
                MEMTAB[i] = (f, bufp, sizep);
                placed = true;
                break;
            }
            i += 1;
        }
        if !placed {
            sunlock();
            fclose(f);
            free(q as *mut c_void);
            set_err(ENOMEM);
            return null_mut();
        }
        *bufp = q as *mut c_char;
        *sizep = 0;
        sunlock();
        f
    }
}

extern "C" {
    fn execlp(file: *const c_char, ...) -> c_int;
}

#[cfg(test)]
mod tests {
    use core::ffi::{c_char, c_int};
    use core::ptr::{addr_of_mut, null_mut};
    use core::sync::atomic::Ordering;

    use super::super::{fclose, fdopen, fopen, fread, fwrite};
    use super::{FposT, CTR};
    use crate::malloc::free;
    use crate::unistd::getpid;

    unsafe fn push_decimal(mut v: u32, b: *mut u8, k: &mut usize) {
        unsafe {
            let mut tmp = [0u8; 10];
            let mut n = 0usize;
            if v == 0 {
                tmp[0] = b'0';
                n = 1;
            } else {
                while v > 0 {
                    tmp[n] = b'0'.wrapping_add((v % 10) as u8);
                    n = n.wrapping_add(1);
                    v /= 10;
                }
            }
            while n > 0 {
                n -= 1;
                *b.add(*k) = tmp[n];
                *k = k.wrapping_add(1);
            }
        }
    }

    /// `/tmp/z8c1-<tag>-<pid>-<n>\0` (unique per test: pid+tag+counter).
    unsafe fn tpath(tag: &[u8]) -> [u8; 64] {
        unsafe {
            let mut b = [0u8; 64];
            let mut k = 0usize;
            let head = b"/tmp/z8c1-";
            let mut i = 0usize;
            while i < head.len() {
                b[k] = head[i];
                k = k.wrapping_add(1);
                i += 1;
            }
            i = 0;
            while i < tag.len() {
                b[k] = tag[i];
                k = k.wrapping_add(1);
                i += 1;
            }
            b[k] = b'-';
            k = k.wrapping_add(1);
            push_decimal(getpid() as u32, b.as_mut_ptr(), &mut k);
            b[k] = b'-';
            k = k.wrapping_add(1);
            push_decimal(CTR.fetch_add(1, Ordering::Relaxed), b.as_mut_ptr(), &mut k);
            b[k] = 0;
            b
        }
    }

    unsafe fn slen(p: *const c_char) -> usize {
        unsafe {
            let mut n = 0usize;
            while *p.add(n) != 0 {
                n = n.wrapping_add(1);
            }
            n
        }
    }

    #[test]
    fn fgets_roundtrip_and_edges() {
        unsafe {
            let tp = tpath(b"fgets");
            let f = fopen(tp.as_ptr() as *const c_char, c"w".as_ptr());
            assert!(!f.is_null());
            let msg = b"ab\nc\ndef";
            assert_eq!(fwrite(msg.as_ptr() as *const _, 1, msg.len(), f), msg.len());
            assert_eq!(fclose(f), 0);
            let f = fopen(tp.as_ptr() as *const c_char, c"r".as_ptr());
            assert!(!f.is_null());
            let mut b = [0u8; 16];
            assert_eq!(
                super::fgets(b.as_mut_ptr() as *mut c_char, 16, f),
                b.as_mut_ptr() as *mut c_char
            );
            assert_eq!(&b[..3], b"ab\n");
            assert_eq!(
                super::fgets(b.as_mut_ptr() as *mut c_char, 16, f),
                b.as_mut_ptr() as *mut c_char
            );
            assert_eq!(&b[..2], b"c\n");
            assert_eq!(
                super::fgets(b.as_mut_ptr() as *mut c_char, 16, f),
                b.as_mut_ptr() as *mut c_char
            );
            assert_eq!(&b[..3], b"def");
            assert_eq!(
                super::fgets(b.as_mut_ptr() as *mut c_char, 16, f),
                null_mut()
            );
            assert_ne!(super::feof(f), 0);
            // n == 1 yields empty string; n == 0 yields null.
            super::rewind(f);
            assert_eq!(
                super::fgets(b.as_mut_ptr() as *mut c_char, 1, f),
                b.as_mut_ptr() as *mut c_char
            );
            assert_eq!(b[0], 0);
            assert_eq!(
                super::fgets(b.as_mut_ptr() as *mut c_char, 0, f),
                null_mut()
            );
            assert_eq!(fclose(f), 0);
        }
    }

    #[test]
    fn char_wrappers_roundtrip() {
        unsafe {
            let tp = tpath(b"chars");
            let f = fopen(tp.as_ptr() as *const c_char, c"w".as_ptr());
            assert!(!f.is_null());
            assert_eq!(super::fputc(b'A' as c_int, f), b'A' as c_int);
            assert_eq!(super::putc(b'B' as c_int, f), b'B' as c_int);
            assert_eq!(fclose(f), 0);
            let f = fopen(tp.as_ptr() as *const c_char, c"r".as_ptr());
            assert!(!f.is_null());
            assert_eq!(super::getc(f), b'A' as c_int);
            assert_eq!(super::getc(f), b'B' as c_int);
            assert_eq!(fclose(f), 0);
            assert_eq!(super::putchar(b'Z' as c_int), b'Z' as c_int);
        }
    }

    #[test]
    fn ungetc_pushback_paths() {
        unsafe {
            let tp = tpath(b"ungetc");
            let f = fopen(tp.as_ptr() as *const c_char, c"w+".as_ptr());
            assert!(!f.is_null());
            assert_eq!(fwrite(b"XY".as_ptr() as *const _, 1, 2, f), 2);
            super::rewind(f);
            // Fresh-stream slot first (nothing consumed yet).
            assert_eq!(super::ungetc(b'Q' as c_int, f), b'Q' as c_int);
            assert_eq!(super::getc(f), b'Q' as c_int);
            // Normal path: rpos > 0 after a read.
            assert_eq!(super::getc(f), b'X' as c_int);
            assert_eq!(super::ungetc(b'Z' as c_int, f), b'Z' as c_int);
            assert_eq!(super::getc(f), b'Z' as c_int);
            assert_eq!(super::getc(f), b'Y' as c_int);
            // EOF pushback is a no-op returning EOF.
            assert_eq!(super::ungetc(-1, f), -1);
            assert_eq!(fclose(f), 0);
        }
    }

    #[test]
    fn seek_tell_rewind_positions() {
        unsafe {
            let tp = tpath(b"seek");
            let f = fopen(tp.as_ptr() as *const c_char, c"w+".as_ptr());
            assert!(!f.is_null());
            assert_eq!(fwrite(b"0123456789".as_ptr() as *const _, 1, 10, f), 10);
            assert_eq!(super::fseek(f, 5, crate::unistd::SEEK_SET), 0);
            assert_eq!(super::ftell(f), 5);
            assert_eq!(super::getc(f), b'5' as c_int);
            assert_eq!(super::fseek(f, 2, crate::unistd::SEEK_CUR), 0);
            assert_eq!(super::ftell(f), 8);
            assert_eq!(super::fseek(f, -3, crate::unistd::SEEK_END), 0);
            assert_eq!(super::ftell(f), 7);
            assert_eq!(super::fseek(f, 0, 99), -1);
            super::rewind(f);
            assert_eq!(super::ftell(f), 0);
            assert_eq!(fclose(f), 0);
        }
    }

    #[test]
    fn pos_roundtrip() {
        unsafe {
            assert_eq!(core::mem::size_of::<FposT>(), 16);
            let tp = tpath(b"pos");
            let f = fopen(tp.as_ptr() as *const c_char, c"w+".as_ptr());
            assert!(!f.is_null());
            assert_eq!(fwrite(b"hello".as_ptr() as *const _, 1, 5, f), 5);
            super::rewind(f);
            assert_eq!(super::getc(f), b'h' as c_int);
            let mut pos = FposT {
                off: 0,
                state: [0xAA; 8],
            };
            assert_eq!(super::fgetpos(f, addr_of_mut!(pos)), 0);
            assert_eq!(pos.off, 1);
            assert_eq!(pos.state, [0; 8]);
            assert_eq!(super::getc(f), b'e' as c_int);
            assert_eq!(super::fsetpos(f, &pos), 0);
            assert_eq!(super::getc(f), b'e' as c_int);
            assert_eq!(super::fsetpos(f, null_mut()), -1);
            assert_eq!(super::fgetpos(f, null_mut()), -1);
            assert_eq!(fclose(f), 0);
        }
    }

    #[test]
    fn err_bits_transition() {
        unsafe {
            let tp = tpath(b"errbits");
            let f = fopen(tp.as_ptr() as *const c_char, c"w".as_ptr());
            assert!(!f.is_null());
            assert_eq!(fwrite(b"zz".as_ptr() as *const _, 1, 2, f), 2);
            assert_eq!(fclose(f), 0);
            let f = fopen(tp.as_ptr() as *const c_char, c"r".as_ptr());
            assert!(!f.is_null());
            assert!(super::fileno(f) >= 0);
            assert_eq!(super::feof(f), 0);
            assert_eq!(super::ferror(f), 0);
            // Write to a read-only stream latches ERR.
            assert_eq!(fwrite(b"q".as_ptr() as *const _, 1, 1, f), 0);
            assert_ne!(super::ferror(f), 0);
            assert_eq!(super::feof(f), 0);
            super::clearerr(f);
            assert_eq!(super::ferror(f), 0);
            // Drain to EOF, then rewind clears it.
            let mut b = [0u8; 8];
            assert_eq!(fread(b.as_mut_ptr() as *mut _, 1, 8, f), 2);
            assert_eq!(fread(b.as_mut_ptr() as *mut _, 1, 1, f), 0);
            assert_ne!(super::feof(f), 0);
            super::rewind(f);
            assert_eq!(super::feof(f), 0);
            assert_eq!(super::fileno(null_mut()), -1);
            assert_eq!(fclose(f), 0);
        }
    }

    #[test]
    fn buffering_modes_hold() {
        unsafe {
            // Null buffer + explicit sizes across all three modes.
            let tp = tpath(b"setvbuf");
            let f = fopen(tp.as_ptr() as *const c_char, c"w+".as_ptr());
            assert!(!f.is_null());
            assert_eq!(super::setvbuf(f, null_mut(), 0, 0), 0);
            assert_eq!(fwrite(b"ab".as_ptr() as *const _, 1, 2, f), 2);
            assert_eq!(super::setvbuf(f, null_mut(), 1, 0), 0);
            assert_eq!(fwrite(b"\n".as_ptr() as *const _, 1, 1, f), 1);
            assert_eq!(super::setvbuf(f, null_mut(), 2, 0), 0);
            assert_eq!(fwrite(b"cd".as_ptr() as *const _, 1, 2, f), 2);
            assert_eq!(super::setvbuf(f, null_mut(), 99, 0), -1);
            super::rewind(f);
            let mut b = [0u8; 8];
            assert_eq!(fread(b.as_mut_ptr() as *mut _, 1, 5, f), 5);
            assert_eq!(&b[..5], b"ab\ncd");
            assert_eq!(fclose(f), 0);
            // Caller buffer + setbuf/setbuffer/setlinebuf spellings.
            let f = fopen(tp.as_ptr() as *const c_char, c"w".as_ptr());
            assert!(!f.is_null());
            let mut ub = [0u8; 512];
            assert_eq!(
                super::setvbuf(f, ub.as_mut_ptr() as *mut c_char, 0, ub.len()),
                0
            );
            assert_eq!(fwrite(b"ok".as_ptr() as *const _, 1, 2, f), 2);
            super::setbuf(f, ub.as_mut_ptr() as *mut c_char);
            super::setbuffer(f, ub.as_mut_ptr() as *mut c_char, ub.len());
            super::setlinebuf(f);
            super::setbuf(f, null_mut());
            assert_eq!(fclose(f), 0);
            // Unbuffered reads still stage single bytes.
            let f = fopen(tp.as_ptr() as *const c_char, c"r".as_ptr());
            assert!(!f.is_null());
            assert_eq!(super::setvbuf(f, null_mut(), 2, 0), 0);
            let mut b2 = [0u8; 8];
            assert_eq!(
                super::fgets(b2.as_mut_ptr() as *mut c_char, 8, f),
                b2.as_mut_ptr() as *mut c_char
            );
            assert_eq!(&b2[..2], b"ok");
            assert_eq!(fclose(f), 0);
        }
    }

    #[test]
    fn delim_getline_on_pipes() {
        unsafe {
            let mut p = [0 as c_int; 2];
            assert_eq!(crate::unistd::pipe(p.as_mut_ptr()), 0);
            let wf = fdopen(p[1], c"w".as_ptr());
            assert!(!wf.is_null());
            let msg = b"a;b;cd";
            assert_eq!(
                fwrite(msg.as_ptr() as *const _, 1, msg.len(), wf),
                msg.len()
            );
            assert_eq!(fclose(wf), 0);
            let rf = fdopen(p[0], c"r".as_ptr());
            assert!(!rf.is_null());
            let mut line: *mut c_char = null_mut();
            let mut cap = 0usize;
            assert_eq!(
                super::getdelim(addr_of_mut!(line), addr_of_mut!(cap), b';' as c_int, rf),
                2
            );
            assert_eq!(slen(line), 2);
            assert_eq!(
                super::getdelim(addr_of_mut!(line), addr_of_mut!(cap), b';' as c_int, rf),
                2
            );
            // No trailing delimiter: short final item, then -1.
            assert_eq!(
                super::getdelim(addr_of_mut!(line), addr_of_mut!(cap), b';' as c_int, rf),
                2
            );
            assert_eq!(slen(line), 2);
            assert_eq!(
                super::getdelim(addr_of_mut!(line), addr_of_mut!(cap), b';' as c_int, rf),
                -1
            );
            assert_eq!(
                super::getdelim(null_mut(), addr_of_mut!(cap), b';' as c_int, rf),
                -1
            );
            free(line as *mut core::ffi::c_void);
            assert_eq!(fclose(rf), 0);
            // getline over newline-terminated lines.
            assert_eq!(crate::unistd::pipe(p.as_mut_ptr()), 0);
            let wf = fdopen(p[1], c"w".as_ptr());
            let msg = b"l1\nl2\nlast";
            assert_eq!(
                fwrite(msg.as_ptr() as *const _, 1, msg.len(), wf),
                msg.len()
            );
            assert_eq!(fclose(wf), 0);
            let rf = fdopen(p[0], c"r".as_ptr());
            let mut l2: *mut c_char = null_mut();
            let mut c2 = 0usize;
            assert_eq!(super::getline(addr_of_mut!(l2), addr_of_mut!(c2), rf), 3);
            assert_eq!(super::getline(addr_of_mut!(l2), addr_of_mut!(c2), rf), 3);
            assert_eq!(super::getline(addr_of_mut!(l2), addr_of_mut!(c2), rf), 4);
            assert_eq!(super::getline(addr_of_mut!(l2), addr_of_mut!(c2), rf), -1);
            free(l2 as *mut core::ffi::c_void);
            assert_eq!(fclose(rf), 0);
        }
    }

    #[test]
    fn popen_echo_and_status() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let f = super::popen(c"echo popen-hi".as_ptr(), c"r".as_ptr());
            assert!(!f.is_null());
            let mut b = [0u8; 32];
            assert_eq!(
                super::fgets(b.as_mut_ptr() as *mut c_char, 32, f),
                b.as_mut_ptr() as *mut c_char
            );
            assert_eq!(&b[..9], b"popen-hi\n");
            assert_eq!(super::pclose(f), 0);
            // Exit-code decoding through the raw status word.
            let g = super::popen(c"exit 41".as_ptr(), c"r".as_ptr());
            assert!(!g.is_null());
            assert_eq!(super::pclose(g), 41 << 8);
            // Write-mode pipe to a sink that exits zero.
            let h = super::popen(c"cat > /dev/null".as_ptr(), c"w".as_ptr());
            assert!(!h.is_null());
            assert_eq!(super::pclose(h), 0);
            assert!(super::popen(c"echo x".as_ptr(), c"q".as_ptr()).is_null());
            // A plain file is not a popen stream: EINVAL, left open.
            let tp = tpath(b"pclose");
            let f = fopen(tp.as_ptr() as *const c_char, c"w".as_ptr());
            assert!(!f.is_null());
            assert_eq!(super::pclose(f), -1);
            assert_eq!(fclose(f), 0);
        }
    }

    #[test]
    fn tmpfile_scratch_works() {
        unsafe {
            let f = super::tmpfile();
            assert!(!f.is_null());
            assert!(super::fileno(f) >= 0);
            assert_eq!(fwrite(b"tmp-data".as_ptr() as *const _, 1, 8, f), 8);
            super::rewind(f);
            let mut b = [0u8; 8];
            assert_eq!(fread(b.as_mut_ptr() as *mut _, 1, 8, f), 8);
            assert_eq!(&b, b"tmp-data");
            assert_eq!(fclose(f), 0);
        }
    }

    #[test]
    fn tmp_names_are_unique_paths() {
        // tmpnam/tempnam probe nonexistent paths (ENOENT writes): serialize.
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let a = super::tmpnam(null_mut());
            assert!(!a.is_null());
            assert_eq!(slen(a), 18);
            let mut sb = [0 as c_char; 20];
            let b = super::tmpnam(sb.as_mut_ptr());
            assert_eq!(b, sb.as_mut_ptr());
            assert_ne!(slen(b), 0);
            // Distinct calls mint distinct names.
            let mut i = 0usize;
            let mut same = true;
            while i < slen(a) {
                if *a.add(i) != *b.add(i) {
                    same = false;
                    break;
                }
                i = i.wrapping_add(1);
            }
            assert!(!same);
            let p = super::tempnam(c"/tmp".as_ptr(), c"zt".as_ptr());
            assert!(!p.is_null());
            assert_eq!(*p, b'/' as c_char);
            assert!(slen(p) > 8);
            free(p as *mut core::ffi::c_void);
            let q = super::tempnam(null_mut(), null_mut());
            assert!(!q.is_null());
            free(q as *mut core::ffi::c_void);
        }
    }

    #[test]
    fn fmemopen_modes() {
        unsafe {
            // "w": write, seek, read back; trailing NUL kept.
            let mut area = [0u8; 32];
            let f = super::fmemopen(
                area.as_mut_ptr() as *mut core::ffi::c_void,
                area.len(),
                c"w".as_ptr(),
            );
            assert!(!f.is_null());
            assert_eq!(fwrite(b"hello".as_ptr() as *const _, 1, 5, f), 5);
            assert_eq!(super::fseek(f, 0, crate::unistd::SEEK_SET), 0);
            assert_eq!(super::ftell(f), 0);
            let mut b = [0u8; 8];
            assert_eq!(fread(b.as_mut_ptr() as *mut _, 1, 5, f), 5);
            assert_eq!(&b[..5], b"hello");
            assert_eq!(area[5], 0);
            assert_eq!(fclose(f), 0);
            // "r": read-only view over caller memory.
            let src = b"world!";
            let f = super::fmemopen(
                src.as_ptr() as *mut core::ffi::c_void,
                src.len(),
                c"r".as_ptr(),
            );
            assert!(!f.is_null());
            let mut lb = [0u8; 8];
            assert_eq!(
                super::fgets(lb.as_mut_ptr() as *mut c_char, 8, f),
                lb.as_mut_ptr() as *mut c_char
            );
            assert_eq!(&lb[..6], b"world!");
            // Read-only: writes fail clean.
            assert_eq!(fwrite(b"q".as_ptr() as *const _, 1, 1, f), 0);
            assert_eq!(fclose(f), 0);
            // "a": appends land past the existing string.
            let mut ab = [b'a', b'b', 0, 0, 0, 0, 0, 0];
            let f = super::fmemopen(
                ab.as_mut_ptr() as *mut core::ffi::c_void,
                ab.len(),
                c"a".as_ptr(),
            );
            assert!(!f.is_null());
            assert_eq!(fwrite(b"cd".as_ptr() as *const _, 1, 2, f), 2);
            assert_eq!(super::fseek(f, 0, crate::unistd::SEEK_SET), 0);
            let mut rb = [0u8; 4];
            assert_eq!(fread(rb.as_mut_ptr() as *mut _, 1, 4, f), 4);
            assert_eq!(&rb, b"abcd");
            assert_eq!(fclose(f), 0);
            // Null buffer: libc-owned area, update mode.
            let f = super::fmemopen(null_mut(), 16, c"w+".as_ptr());
            assert!(!f.is_null());
            assert_eq!(fwrite(b"nm".as_ptr() as *const _, 1, 2, f), 2);
            assert_eq!(super::fseek(f, 0, crate::unistd::SEEK_SET), 0);
            let mut nb = [0u8; 2];
            assert_eq!(fread(nb.as_mut_ptr() as *mut _, 1, 2, f), 2);
            assert_eq!(&nb, b"nm");
            assert_eq!(fclose(f), 0);
            assert!(super::fmemopen(
                area.as_mut_ptr() as *mut core::ffi::c_void,
                area.len(),
                c"x".as_ptr()
            )
            .is_null());
        }
    }

    #[test]
    fn memstream_collects_and_grows() {
        unsafe {
            let mut bp: *mut c_char = null_mut();
            let mut sz = 0usize;
            let ms = super::open_memstream(addr_of_mut!(bp), addr_of_mut!(sz));
            assert!(!ms.is_null());
            assert_eq!(sz, 0);
            assert_eq!(*bp, 0);
            assert_eq!(fwrite(b"hey".as_ptr() as *const _, 1, 3, ms), 3);
            // Seek syncs length (implies flush: bytes are in place).
            assert_eq!(super::fseek(ms, 0, crate::unistd::SEEK_END), 0);
            assert_eq!(sz, 3);
            assert_eq!(super::ftell(ms), 3);
            assert_eq!(*bp.add(0) as u8, b'h');
            assert_eq!(*bp.add(2) as u8, b'y');
            // Growth past the initial buffer via seek + write.
            assert_eq!(super::fseek(ms, 2000, crate::unistd::SEEK_SET), 0);
            assert_eq!(super::ftell(ms), 2000);
            assert_eq!(fwrite(b"Z".as_ptr() as *const _, 1, 1, ms), 1);
            assert_eq!(super::fseek(ms, 0, crate::unistd::SEEK_END), 0);
            assert_eq!(sz, 2001);
            assert_eq!(*bp.add(2000) as u8, b'Z');
            assert_eq!(super::fseek(ms, 0, crate::unistd::SEEK_SET), 0);
            let mut rb = [0u8; 3];
            assert_eq!(fread(rb.as_mut_ptr() as *mut _, 1, 3, ms), 3);
            assert_eq!(&rb, b"hey");
            assert_eq!(fclose(ms), 0);
            free(bp as *mut core::ffi::c_void);
            assert!(super::open_memstream(null_mut(), addr_of_mut!(sz)).is_null());
        }
    }

    #[test]
    fn freopen_transplants() {
        unsafe {
            let tp = tpath(b"freopen");
            let f = fopen(tp.as_ptr() as *const c_char, c"w".as_ptr());
            assert!(!f.is_null());
            assert_eq!(fwrite(b"data".as_ptr() as *const _, 1, 4, f), 4);
            let g = super::freopen(tp.as_ptr() as *const c_char, c"r".as_ptr(), f);
            assert_eq!(g, f);
            let mut b = [0u8; 4];
            assert_eq!(fread(b.as_mut_ptr() as *mut _, 1, 4, g), 4);
            assert_eq!(&b, b"data");
            // Null path is a flush-preserving no-op returning the stream.
            assert_eq!(super::freopen(null_mut(), c"r".as_ptr(), g), g);
            assert_eq!(fclose(g), 0);
            assert!(
                super::freopen(tp.as_ptr() as *const c_char, c"r".as_ptr(), null_mut()).is_null()
            );
        }
    }
}
