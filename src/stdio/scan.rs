//! scanf family (musl `scanf.c`, `fscanf.c`, `sscanf.c`, `vscanf.c`,
//! `vsscanf.c`, `vfscanf.c`, internal `shgetc.c`, `intscan.c`, `floatscan.c`).
//!
//! One `vfscanf`-shaped driver over two inputs: the parent [`File`] (via
//! `super::`, lock held for the whole scan like musl's `FLOCK`) and a
//! NUL-terminated string (`sscanf`, musl's `sh_fromstring` cookie trick
//! without the fake `FILE`). `scanf` reads fd 0 through the `stdin`
//! stream. The driver keeps musl's field-width limiter (`shlim`/
//! `shgetc`/`shunget`/`shcnt`) as a small cursor: limit `-1` frozen
//! (width hit or real EOF, `shunget` a no-op exactly like musl),
//! `0` unlimited, positive for the width.
//!
//! Integer conversions port `intscan.c` line-faithfully (`lim` is always
//! `ULLONG_MAX` from this driver, so huge inputs yield `ULLONG_MAX` and
//! truncate into the destination exactly like musl — e.g. `%d` of a
//! 30-digit number stores `-1`). Float conversions port `floatscan.c`'s
//! shape (`inf`/`infinity`/`nan(...)`, decimal and `0x` hex with `p`
//! exponents) but the binary assembly is integer limbs (`Big` below):
//! the decimal value `M * 10^E` (up to 1100 significant digits, sticky
//! past that — past any testable rounding boundary) is divided down to
//! `N+3` bits and rounded half-to-even, so `%lf` of `0.1` lands on
//! `0x3FB999999999999A`. Hex mantissas are exact (16 digits + sticky).
//! `%Lf` writes the 10 LE bytes of 80-bit extended (explicit integer bit,
//! same layout as `dtoa::fmt_f80_bits` reads).
//!
//! Deliberate deviations, one line each:
//! - `%m` (allocating strings) is a format failure; musl would `malloc`.
//! - `%n$` positional args ARE supported (all destinations are pointers,
//!   so the tag snapshot walk is exact).
//! - Wide `%ls`/`%lc`/`%S`/`%C` read single bytes (no multibyte until
//!   Ola 9); C-locale bytes stay exact.
//! - `errno` (`ERANGE`/`EINVAL`) follows musl, observable only through
//!   `__errno_location`.
//! - Width saturates instead of wrapping on hostile 20-digit widths.
//!
//! # Safety
//!
//! The `...` symbols only spill GP registers (documented on the macro);
//! the `v*` contracts match musl (`f` live, strings NUL-terminated, tag
//! args matching `fmt`).

use core::cmp::Ordering;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;

use super::{Ap, File, VaList, EOF};

/// musl `arch/generic/bits/errno.h`.
const EINVAL: c_int = 22;
const ERANGE: c_int = 34;

/// `log2(10)` for the decimal→binary exponent estimate.
const LOG2_10: f64 = 3.3219280948873626;

// ---- C-variadic trampolines -------------------------------------------------
// scanf args are ALL pointers (conversion outputs), i.e. SysV GP class,
// so spilling just the 6 GP regs plus the overflow area suffices: no XMM
// staging is needed (floats travel out through pointers, never by value).
// The tag's FP cursor is still initialised to 48 (first XMM slot, unused)
// to keep the tag well-formed. Frame is 72 bytes (`72 % 16 == 8`, so the
// inner `call` lands SysV-clean): 48 bytes of saved regs + 24 tag bytes.
// $gp is 8 x named GP args; the tag register carries the tag pointer while
// the named registers still hold the caller's values for the inner call.
//
// Contract (single source for all three; the lint cannot see docs through
// the expansion, hence the allow below): same safety contract as inner.
//
/// # Safety
///
/// Same contract as the inner function.
macro_rules! scan_trampoline {
    ($name:ident, $inner:ident, $gp:expr, $tagreg:literal) => {
        #[allow(clippy::missing_safety_doc)]
        #[no_mangle]
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "mov rax, rsp",
                "sub rsp, 72",
                "mov [rsp], rdi",
                "mov [rsp+8], rsi",
                "mov [rsp+16], rdx",
                "mov [rsp+24], rcx",
                "mov [rsp+32], r8",
                "mov [rsp+40], r9",
                "mov dword ptr [rsp+48], {gp}",
                "mov dword ptr [rsp+52], 48",
                "lea rcx, [rax+8]",
                "mov [rsp+56], rcx",
                "mov [rsp+64], rsp",
                $tagreg,
                "call {inner}",
                "add rsp, 72",
                "ret",
                gp = const $gp,
                inner = sym $inner,
            )
        }
    };
}

scan_trampoline!(scanf, scanf_inner, 8, "lea rsi, [rsp+48]");
scan_trampoline!(fscanf, fscanf_inner, 16, "lea rdx, [rsp+48]");
scan_trampoline!(sscanf, sscanf_inner, 16, "lea rdx, [rsp+48]");

/// `scanf` body: stdin + caller-built tag (see [`scan_trampoline`]).
///
/// # Safety
///
/// `fmt` valid; `tag` a live tag whose remaining args match it.
unsafe fn scanf_inner(fmt: *const c_char, tag: *mut VaList) -> c_int {
    unsafe {
        if fmt.is_null() || tag.is_null() {
            super::set_err(EINVAL);
            return EOF;
        }
        body_file(super::stdin, fmt, tag)
    }
}

/// `fscanf` body.
///
/// # Safety
///
/// `f` live; otherwise like [`scanf_inner`].
unsafe fn fscanf_inner(f: *mut File, fmt: *const c_char, tag: *mut VaList) -> c_int {
    unsafe {
        if f.is_null() || fmt.is_null() || tag.is_null() {
            super::set_err(EINVAL);
            return EOF;
        }
        body_file(f, fmt, tag)
    }
}

/// `sscanf` body.
///
/// # Safety
///
/// `s`/`fmt` valid NUL-terminated strings; `tag` live and matching.
unsafe fn sscanf_inner(s: *const c_char, fmt: *const c_char, tag: *mut VaList) -> c_int {
    unsafe {
        if s.is_null() || fmt.is_null() || tag.is_null() {
            super::set_err(EINVAL);
            return EOF;
        }
        body_mem(s, fmt, tag)
    }
}

/// Shared `FILE` path: lock, snapshot the tag (for `%n$`), prime, drive.
///
/// # Safety
///
/// `f` live, `fmt` valid, `ap` a live tag. Lock is taken here.
unsafe fn body_file(f: *mut File, fmt: *const c_char, ap: *mut VaList) -> c_int {
    unsafe {
        super::slock();
        super::ensure_locked();
        let snap = VaList {
            gp: (*ap).gp,
            fp: (*ap).fp,
            overflow: (*ap).overflow,
            regsave: (*ap).regsave,
        };
        let mut input = In::file(f);
        if !input.prime() {
            super::sunlock();
            return EOF;
        }
        let r = driver(&mut input, fmt as *const u8, ap, &snap);
        super::sunlock();
        r
    }
}

/// Shared string path (no lock: private memory).
///
/// # Safety
///
/// Like [`body_file`] but `s` is a valid NUL-terminated string.
unsafe fn body_mem(s: *const c_char, fmt: *const c_char, ap: *mut VaList) -> c_int {
    unsafe {
        let snap = VaList {
            gp: (*ap).gp,
            fp: (*ap).fp,
            overflow: (*ap).overflow,
            regsave: (*ap).regsave,
        };
        let mut input = In::mem(s);
        if !input.prime() {
            return EOF;
        }
        driver(&mut input, fmt as *const u8, ap, &snap)
    }
}

/// Formatted input from a stream (musl `vfscanf`).
///
/// # Safety
///
/// `f` live, `fmt` valid, `ap` a live tag whose remaining args match it.
#[no_mangle]
pub unsafe extern "C" fn vfscanf(f: *mut File, fmt: *const c_char, ap: *mut VaList) -> c_int {
    unsafe {
        if f.is_null() || fmt.is_null() || ap.is_null() {
            super::set_err(EINVAL);
            return EOF;
        }
        body_file(f, fmt, ap)
    }
}

/// Formatted input from `stdin` (musl `vscanf`).
///
/// # Safety
///
/// `fmt` valid, `ap` a live tag matching it.
#[no_mangle]
pub unsafe extern "C" fn vscanf(fmt: *const c_char, ap: *mut VaList) -> c_int {
    unsafe {
        if fmt.is_null() || ap.is_null() {
            super::set_err(EINVAL);
            return EOF;
        }
        body_file(super::stdin, fmt, ap)
    }
}

/// Formatted input from a string (musl `vsscanf`).
///
/// # Safety
///
/// `s`/`fmt` valid NUL-terminated strings, `ap` a live tag matching it.
#[no_mangle]
pub unsafe extern "C" fn vsscanf(s: *const c_char, fmt: *const c_char, ap: *mut VaList) -> c_int {
    unsafe {
        if s.is_null() || fmt.is_null() || ap.is_null() {
            super::set_err(EINVAL);
            return EOF;
        }
        body_mem(s, fmt, ap)
    }
}

// ---- input cursor (musl shgetc.h) --------------------------------------------

/// Width-limited reader: `lim` `-1` frozen (width hit or real EOF, and
/// `unget` is then a no-op, exactly like musl), `0` unlimited.
/// `cnt` is the musl `shcnt` (consumed since the last `set_lim`).
struct In {
    f: *mut File,
    cur: *const u8,
    base: *const u8,
    lim: i64,
    cnt: i64,
}

impl In {
    fn file(f: *mut File) -> In {
        In {
            f,
            cur: null_mut(),
            base: null_mut(),
            lim: 0,
            cnt: 0,
        }
    }

    fn mem(s: *const c_char) -> In {
        In {
            f: null_mut(),
            cur: s as *const u8,
            base: s as *const u8,
            lim: 0,
            cnt: 0,
        }
    }

    /// musl `shlim`: set the width, reset the count.
    fn set_lim(&mut self, n: i64) {
        self.lim = n;
        self.cnt = 0;
    }

    /// musl `shcnt`.
    fn count(&self) -> i64 {
        self.cnt
    }

    /// musl `shgetc` (lock must be held for `File` sources).
    unsafe fn getc(&mut self) -> c_int {
        unsafe {
            if self.lim < 0 {
                return EOF;
            }
            if self.lim > 0 && self.cnt >= self.lim {
                self.lim = -1;
                return EOF;
            }
            let c = if self.f.is_null() {
                let b = *self.cur;
                if b == 0 {
                    EOF
                } else {
                    self.cur = self.cur.add(1);
                    b as c_int
                }
            } else {
                let f = self.f;
                if (*f).rpos < (*f).rlen {
                    let b = *(*f).buf.add((*f).rpos);
                    (*f).rpos += 1;
                    b as c_int
                } else if super::fill_locked(f) {
                    let b = *(*f).buf.add(0);
                    (*f).rpos = 1;
                    b as c_int
                } else {
                    EOF
                }
            };
            if c < 0 {
                self.lim = -1;
                return EOF;
            }
            self.cnt = self.cnt.wrapping_add(1);
            c
        }
    }

    /// musl `shunget`: backs up one byte unless frozen.
    unsafe fn unget(&mut self) {
        unsafe {
            if self.lim < 0 {
                return;
            }
            if self.f.is_null() {
                if self.cur > self.base {
                    self.cur = self.cur.sub(1);
                } else {
                    return;
                }
            } else {
                let f = self.f;
                if (*f).rpos > 0 {
                    (*f).rpos -= 1;
                } else {
                    return;
                }
            }
            self.cnt = self.cnt.wrapping_sub(1);
        }
    }

    /// Entry check (musl's `if (!f->rpos) __toread(f)`): any input at all?
    unsafe fn prime(&mut self) -> bool {
        unsafe {
            if self.f.is_null() {
                *self.cur != 0
            } else {
                let f = self.f;
                if (*f).rpos < (*f).rlen {
                    return true;
                }
                super::fill_locked(f)
            }
        }
    }
}

// ---- small classifiers ---------------------------------------------------------

fn is_sp(c: c_int) -> bool {
    matches!(c, 9..=13 | 32)
}

fn is_dg(c: c_int) -> bool {
    ((c - b'0' as c_int) as u32) < 10
}

fn dv(c: c_int) -> u32 {
    if c >= b'0' as c_int && c <= b'9' as c_int {
        (c - b'0' as c_int) as u32
    } else if c >= b'A' as c_int && c <= b'Z' as c_int {
        (c - b'A' as c_int) as u32 + 10
    } else if c >= b'a' as c_int && c <= b'z' as c_int {
        (c - b'a' as c_int) as u32 + 10
    } else {
        255
    }
}

fn hexdv(c: c_int) -> u32 {
    if c >= b'0' as c_int && c <= b'9' as c_int {
        (c - b'0' as c_int) as u32
    } else if c >= b'A' as c_int && c <= b'F' as c_int {
        (c - b'A' as c_int) as u32 + 10
    } else if c >= b'a' as c_int && c <= b'f' as c_int {
        (c - b'a' as c_int) as u32 + 10
    } else {
        255
    }
}

/// musl sizes: `hh` -2, `h` -1, none 0, `l` 1, `L` 2, `ll` 3 (`j`→3, `z`/`t`→1).
unsafe fn store_int(dest: *mut c_void, size: i32, v: u64) {
    unsafe {
        if dest.is_null() {
            return;
        }
        match size {
            -2 => *(dest as *mut i8) = v as i8,
            -1 => *(dest as *mut i16) = v as i16,
            0 => *(dest as *mut i32) = v as i32,
            1 | 3 => *(dest as *mut i64) = v as i64,
            _ => {}
        }
    }
}

/// musl `arg_n`: the nth vararg (all scanf args are pointers, one GP slot).
unsafe fn arg_n(snap: &VaList, n: u32) -> *mut c_void {
    unsafe {
        let mut tmp = VaList {
            gp: snap.gp,
            fp: snap.fp,
            overflow: snap.overflow,
            regsave: snap.regsave,
        };
        let mut a = Ap { t: &mut tmp };
        let mut k = n;
        while k > 1 {
            a.gp();
            k -= 1;
        }
        a.gp() as *mut c_void
    }
}

// ---- driver (musl vfscanf) --------------------------------------------------------
// Returns the assigned count, or EOF(-1) on input failure before any
// conversion; match/format failure returns the count so far (musl rules).

/// Core format walker over an [`In`] source.
///
/// # Safety
///
/// `f` valid NUL-terminated format; `tag` a live tag; `snap` its entry
/// copy for `%n$`. Lock held for `File` sources.
unsafe fn driver(in_: &mut In, f: *const u8, tag: *mut VaList, snap: &VaList) -> c_int {
    unsafe {
        let mut ap = Ap { t: tag };
        let mut i = 0usize;
        let mut matches: c_int = 0;
        let mut pos: i64 = 0;
        // musl's shared fail tail: input/format failure yields EOF only
        // when nothing was assigned yet.
        let fail = |matches: c_int| -> c_int {
            if matches == 0 {
                -1
            } else {
                matches
            }
        };
        loop {
            let p0 = *f.add(i);
            if p0 == 0 {
                return matches;
            }
            if is_sp(p0 as c_int) {
                while is_sp(*f.add(i + 1) as c_int) {
                    i += 1;
                }
                in_.set_lim(0);
                loop {
                    if !is_sp(in_.getc()) {
                        break;
                    }
                }
                in_.unget();
                pos = pos.wrapping_add(in_.count());
                i += 1;
                continue;
            }
            if p0 != b'%' || *f.add(i + 1) == b'%' {
                in_.set_lim(0);
                let c: c_int;
                if p0 == b'%' {
                    // `%%`: musl skips input whitespace, then wants '%'.
                    i += 1;
                    loop {
                        let cc = in_.getc();
                        if !is_sp(cc) {
                            c = cc;
                            break;
                        }
                    }
                } else {
                    c = in_.getc();
                }
                if c != *f.add(i) as c_int {
                    in_.unget();
                    if c < 0 {
                        return fail(matches);
                    }
                    return matches;
                }
                pos = pos.wrapping_add(in_.count());
                i += 1;
                continue;
            }
            // Conversion.
            i += 1;
            let dest: *mut c_void;
            if *f.add(i) == b'*' {
                dest = null_mut();
                i += 1;
            } else if is_dg(*f.add(i) as c_int) && *f.add(i + 1) == b'$' {
                dest = arg_n(snap, (*f.add(i) - b'0') as u32);
                i += 2;
            } else {
                dest = ap.gp() as *mut c_void;
            }
            let mut width: i64 = 0;
            while is_dg(*f.add(i) as c_int) {
                width = width
                    .saturating_mul(10)
                    .saturating_add((*f.add(i) - b'0') as i64);
                i += 1;
            }
            // Deviation: no `%m` (would malloc); a format failure.
            if *f.add(i) == b'm' {
                return fail(matches);
            }
            let mut size: i32 = 0;
            match *f.add(i) {
                b'h' => {
                    i += 1;
                    if *f.add(i) == b'h' {
                        i += 1;
                        size = -2;
                    } else {
                        size = -1;
                    }
                }
                b'l' => {
                    i += 1;
                    if *f.add(i) == b'l' {
                        i += 1;
                        size = 3;
                    } else {
                        size = 1;
                    }
                }
                b'j' => {
                    i += 1;
                    size = 3;
                }
                b'z' | b't' => {
                    i += 1;
                    size = 1;
                }
                b'L' => {
                    i += 1;
                    size = 2;
                }
                b'd' | b'i' | b'o' | b'u' | b'x' | b'X' | b'a' | b'e' | b'f' | b'g' | b'A'
                | b'E' | b'F' | b'G' | b's' | b'c' | b'[' | b'S' | b'C' | b'p' | b'n' => {}
                _ => {
                    return fail(matches);
                }
            }
            let mut t = *f.add(i);
            i += 1;
            // `C`/`S`: wide in musl; single bytes here (documented).
            if (t & 0x2f) == 3 {
                t |= 32;
                size = 1;
            }
            match t {
                b'c' => {
                    if width < 1 {
                        width = 1;
                    }
                }
                b'[' => {}
                b'n' => {
                    // `%n` stores without assigning (even when it is the
                    // only directive, the count stays 0).
                    store_int(dest, size, pos as u64);
                    continue;
                }
                _ => {
                    in_.set_lim(0);
                    loop {
                        if !is_sp(in_.getc()) {
                            break;
                        }
                    }
                    in_.unget();
                    pos = pos.wrapping_add(in_.count());
                }
            }
            in_.set_lim(width);
            if in_.getc() < 0 {
                return fail(matches);
            }
            in_.unget();
            match t {
                b's' | b'c' | b'[' => {
                    let mut set = [255u8; 257];
                    if t == b'[' {
                        let mut inv = false;
                        if *f.add(i) == b'^' {
                            inv = true;
                            i += 1;
                        }
                        if inv {
                            set = [1u8; 257];
                        } else {
                            set = [0u8; 257];
                        }
                        let on: u8 = if inv { 0 } else { 1 };
                        set[0] = 0;
                        if *f.add(i) == b'-' {
                            i += 1;
                            set[1 + b'-' as usize] = on;
                        } else if *f.add(i) == b']' {
                            i += 1;
                            set[1 + b']' as usize] = on;
                        }
                        loop {
                            let q = *f.add(i);
                            if q == 0 {
                                return fail(matches);
                            }
                            if q == b']' {
                                i += 1;
                                break;
                            }
                            if q == b'-' && *f.add(i + 1) != 0 && *f.add(i + 1) != b']' {
                                let prev = *f.add(i - 1) as i32;
                                let end = *f.add(i + 1);
                                let mut cc = prev;
                                while cc < end as i32 {
                                    set[(1 + cc) as usize] = on;
                                    cc += 1;
                                }
                                set[(1 + end) as usize] = on;
                                i += 2;
                            } else {
                                set[(1 + q) as usize] = on;
                                i += 1;
                            }
                        }
                    } else {
                        set[0] = 0;
                        if t == b's' {
                            set[1 + b'\t' as usize] = 0;
                            set[1 + b'\n' as usize] = 0;
                            set[1 + 11usize] = 0;
                            set[1 + 12usize] = 0;
                            set[1 + b'\r' as usize] = 0;
                            set[1 + b' ' as usize] = 0;
                        }
                    }
                    let dst = dest as *mut u8;
                    let mut k: usize = 0;
                    loop {
                        let c = in_.getc();
                        if c < 0 || set[(c + 1) as usize] == 0 {
                            break;
                        }
                        if !dest.is_null() {
                            *dst.add(k) = c as u8;
                        }
                        k = k.wrapping_add(1);
                    }
                    in_.unget();
                    if in_.count() == 0 {
                        return matches;
                    }
                    if t == b'c' && in_.count() != width {
                        return matches;
                    }
                    if t != b'c' && !dest.is_null() {
                        *dst.add(k) = 0;
                    }
                }
                b'p' | b'X' | b'x' | b'o' | b'd' | b'u' | b'i' => {
                    let base = match t {
                        b'p' | b'X' | b'x' => 16,
                        b'o' => 8,
                        b'i' => 0,
                        _ => 10,
                    };
                    let x = intscan(in_, base);
                    if in_.count() == 0 {
                        return matches;
                    }
                    if !dest.is_null() {
                        if t == b'p' {
                            *(dest as *mut *mut c_void) = x as *mut c_void;
                        } else {
                            store_int(dest, size, x);
                        }
                    }
                }
                _ => {
                    let fprec = match size {
                        0 => 0,
                        1 => 1,
                        2 => 2,
                        _ => {
                            return matches;
                        }
                    };
                    let v = match floatscan(in_, fprec) {
                        Some(v) => v,
                        None => {
                            return matches;
                        }
                    };
                    if in_.count() == 0 {
                        return matches;
                    }
                    if !dest.is_null() {
                        match v {
                            FVal::F32(b) => *(dest as *mut u32) = b,
                            FVal::F64(b) => *(dest as *mut u64) = b,
                            FVal::F80(b) => {
                                let d = dest as *mut u8;
                                let mut j = 0;
                                while j < 10 {
                                    *d.add(j) = b[j];
                                    j += 1;
                                }
                            }
                        }
                    }
                }
            }
            pos = pos.wrapping_add(in_.count());
            if !dest.is_null() {
                matches += 1;
            }
        }
    }
}

// ---- intscan (musl internal/intscan.c, pok=0 path) -------------------------------
// `lim` is always ULLONG_MAX here (this driver's only call), so the
// tail clamps collapse to returning ULLONG_MAX (truncated by store_int).

/// Tail of `intscan`: exact values return masked (`(y^neg)-neg`); the
/// consuming-loop overflow path returns `ULLONG_MAX` with `ERANGE`.
fn finish_int(y: u64, neg: u64) -> u64 {
    (y ^ neg).wrapping_sub(neg)
}

/// Unsigned scan with musl's two-stage (`u32` then `u64`) accumulation.
///
/// # Safety
///
/// Reads through `in_`; lock held for `File` sources.
unsafe fn intscan(in_: &mut In, mut base: u32) -> u64 {
    unsafe {
        if base > 36 || base == 1 {
            super::set_err(EINVAL);
            return 0;
        }
        let mut c: c_int;
        loop {
            c = in_.getc();
            if !is_sp(c) {
                break;
            }
        }
        let mut neg: u64 = 0;
        if c == b'+' as c_int || c == b'-' as c_int {
            if c == b'-' as c_int {
                neg = u64::MAX;
            }
            c = in_.getc();
        }
        if (base == 0 || base == 16) && c == b'0' as c_int {
            c = in_.getc();
            if (c | 32) == b'x' as c_int {
                c = in_.getc();
                if dv(c) >= 16 {
                    in_.unget();
                    in_.set_lim(0);
                    return 0;
                }
                base = 16;
            } else if base == 0 {
                base = 8;
            }
        } else {
            if base == 0 {
                base = 10;
            }
            if dv(c) >= base {
                in_.unget();
                in_.set_lim(0);
                super::set_err(EINVAL);
                return 0;
            }
        }
        let y: u64;
        if base == 10 {
            let mut x: u32 = 0;
            while is_dg(c) && x < u32::MAX / 10 {
                x = x.wrapping_mul(10).wrapping_add((c - b'0' as c_int) as u32);
                c = in_.getc();
            }
            y = x as u64;
            let mut yy = y;
            while is_dg(c)
                && yy <= u64::MAX / 10
                && 10u64.wrapping_mul(yy) <= u64::MAX - (c - b'0' as c_int) as u64
            {
                yy = yy.wrapping_mul(10).wrapping_add((c - b'0' as c_int) as u64);
                c = in_.getc();
            }
            if !is_dg(c) {
                in_.unget();
                return finish_int(yy, neg);
            }
            // Overflow: swallow the rest, ERANGE, ULLONG_MAX.
            while is_dg(c) {
                c = in_.getc();
            }
            super::set_err(ERANGE);
            in_.unget();
            return u64::MAX;
        } else if base == 8 || base == 16 {
            let bs: u32 = if base == 8 { 3 } else { 4 };
            let mut x: u32 = 0;
            while dv(c) < base && x <= u32::MAX / 32 {
                x = (x << bs) | dv(c);
                c = in_.getc();
            }
            let mut yy = x as u64;
            let ymax = u64::MAX >> bs;
            while dv(c) < base && yy <= ymax {
                yy = (yy << bs) | dv(c) as u64;
                c = in_.getc();
            }
            if dv(c) >= base {
                in_.unget();
                return finish_int(yy, neg);
            }
            while dv(c) < base {
                c = in_.getc();
            }
            super::set_err(ERANGE);
            in_.unget();
            return u64::MAX;
        }
        // Generic base (unreachable from this driver; musl's shape kept).
        let mut x: u32 = 0;
        while dv(c) < base && x < u32::MAX / 36 {
            x = x.wrapping_mul(base).wrapping_add(dv(c));
            c = in_.getc();
        }
        y = x as u64;
        let mut yy = y;
        while dv(c) < base
            && yy <= u64::MAX / base as u64
            && (base as u64).wrapping_mul(yy) <= u64::MAX - dv(c) as u64
        {
            yy = yy.wrapping_mul(base as u64).wrapping_add(dv(c) as u64);
            c = in_.getc();
        }
        if dv(c) >= base {
            in_.unget();
            return finish_int(yy, neg);
        }
        while dv(c) < base {
            c = in_.getc();
        }
        super::set_err(ERANGE);
        in_.unget();
        u64::MAX
    }
}

// ---- floatscan (musl internal/floatscan.c, pok=0 path) ------------------------------
// Parsing follows musl; the decimal→binary assembly is integer limbs
// (`Big`): value `M * 10^E` is scaled to `N+3` bits and rounded
// half-to-even, giving correctly-rounded `f32`/`f64`/80-bit results.
// Significant decimal digits cap at 1100 (sticky past that — past any
// testable rounding boundary); hex keeps 16 digits + sticky (exact for
// every `%a` round trip).

/// Big unsigned integer, base 2^32 LE. Scratch only; sizes stay tiny
/// (early estimate outs bound exponents before any limb is built).
const NLIMB: usize = 2048;

struct Big {
    l: [u32; NLIMB],
    n: usize,
}

impl Big {
    fn zero() -> Big {
        Big {
            l: [0; NLIMB],
            n: 0,
        }
    }

    fn one() -> Big {
        let mut b = Big::zero();
        b.l[0] = 1;
        b.n = 1;
        b
    }

    fn is_zero(&self) -> bool {
        self.n == 0
    }

    fn copy_from(&mut self, o: &Big) {
        let mut i = 0;
        while i < o.n {
            self.l[i] = o.l[i];
            i += 1;
        }
        self.n = o.n;
    }

    fn trim(&mut self) {
        while self.n > 0 && self.l[self.n - 1] == 0 {
            self.n -= 1;
        }
    }

    fn add_small(&mut self, a: u32) -> bool {
        if a == 0 {
            return true;
        }
        if self.n == 0 {
            self.l[0] = a;
            self.n = 1;
            return true;
        }
        let mut c = a as u64;
        let mut i = 0;
        while i < self.n && c != 0 {
            let t = self.l[i] as u64 + c;
            self.l[i] = t as u32;
            c = t >> 32;
            i += 1;
        }
        if c != 0 {
            if self.n >= NLIMB {
                return false;
            }
            self.l[self.n] = c as u32;
            self.n += 1;
        }
        true
    }

    fn mul_small(&mut self, m: u32) -> bool {
        if m == 0 {
            self.n = 0;
            return true;
        }
        if self.n == 0 {
            return true;
        }
        let mut c: u64 = 0;
        let mut i = 0;
        while i < self.n {
            let t = self.l[i] as u64 * m as u64 + c;
            self.l[i] = t as u32;
            c = t >> 32;
            i += 1;
        }
        while c != 0 {
            if self.n >= NLIMB {
                return false;
            }
            self.l[self.n] = c as u32;
            c >>= 32;
            self.n += 1;
        }
        true
    }

    fn bitlen(&self) -> usize {
        if self.n == 0 {
            return 0;
        }
        (self.n - 1) * 32 + (32 - self.l[self.n - 1].leading_zeros() as usize)
    }

    fn cmp(&self, o: &Big) -> Ordering {
        if self.n != o.n {
            return self.n.cmp(&o.n);
        }
        let mut i = self.n;
        while i > 0 {
            i -= 1;
            if self.l[i] != o.l[i] {
                return self.l[i].cmp(&o.l[i]);
            }
        }
        Ordering::Equal
    }

    fn shl(&mut self, k: usize) -> bool {
        if self.n == 0 || k == 0 {
            return true;
        }
        let w = k / 32;
        let b = (k % 32) as u32;
        if self.n + w + 1 > NLIMB {
            return false;
        }
        let mut i = self.n;
        while i > 0 {
            i -= 1;
            self.l[i + w] = self.l[i];
        }
        let mut j = 0;
        while j < w {
            self.l[j] = 0;
            j += 1;
        }
        self.n += w;
        if b != 0 {
            let mut c: u32 = 0;
            let mut t = w;
            while t < self.n {
                let nt = self.l[t] >> (32 - b);
                self.l[t] = (self.l[t] << b) | c;
                c = nt;
                t += 1;
            }
            if c != 0 {
                if self.n >= NLIMB {
                    return false;
                }
                self.l[self.n] = c;
                self.n += 1;
            }
        }
        true
    }

    fn shr1(&mut self) {
        if self.n == 0 {
            return;
        }
        let mut c: u32 = 0;
        let mut i = self.n;
        while i > 0 {
            i -= 1;
            let nt = (self.l[i] & 1) << 31;
            self.l[i] = (self.l[i] >> 1) | c;
            c = nt;
        }
        self.trim();
    }

    /// `self -= o`; caller guarantees `self >= o`.
    fn sub(&mut self, o: &Big) {
        let mut b: i64 = 0;
        let mut i = 0;
        while i < self.n {
            let ov = if i < o.n { o.l[i] as i64 } else { 0 };
            let t = self.l[i] as i64 - ov - b;
            if t < 0 {
                self.l[i] = (t + 0x1_0000_0000) as u32;
                b = 1;
            } else {
                self.l[i] = t as u32;
                b = 0;
            }
            i += 1;
        }
        self.trim();
    }
}

/// Binary long division; the quotient here is always `< 2^67` by
/// construction (value/`2^D` with `D` chosen off the exact exponent).
fn divmod(num: &Big, den: &Big) -> (u128, Big) {
    if num.cmp(den) == Ordering::Less {
        let mut r = Big::zero();
        r.copy_from(num);
        return (0, r);
    }
    let sh = num.bitlen() - den.bitlen();
    if sh > 120 {
        return (u128::MAX, Big::zero());
    }
    let mut d = Big::zero();
    d.copy_from(den);
    d.shl(sh);
    let mut r = Big::zero();
    r.copy_from(num);
    let mut q: u128 = 0;
    let mut i = sh;
    loop {
        if r.cmp(&d) != Ordering::Less {
            r.sub(&d);
            q |= 1u128 << i;
        }
        if i == 0 {
            break;
        }
        i -= 1;
        d.shr1();
    }
    (q, r)
}

/// Compare `num/den` against `2^e` without building the full powers.
fn cmp_pow2(num: &Big, den: &Big, e: i64) -> Ordering {
    if e >= 0 {
        let mut t = Big::zero();
        t.copy_from(den);
        if !t.shl(e as usize) {
            return Ordering::Less;
        }
        num.cmp(&t)
    } else {
        let mut t = Big::zero();
        t.copy_from(num);
        if !t.shl((-e) as usize) {
            return Ordering::Greater;
        }
        t.cmp(den)
    }
}

/// Rounding outcome: normal (top bit set), denormal, zero, or infinity.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FKind {
    Normal,
    Denormal,
    Zero,
    Inf,
}

/// Round `Q` (value/`2^D`, holding `N+3` significant bits) plus the
/// sticky flag to `N` bits, half-to-even. `den` selects the denormal
/// grid; returns `(sig, e2, kind, inexact)`.
fn finish(
    q: u128,
    st: bool,
    e2: i64,
    den: bool,
    n: u32,
    emax_n: i64,
    enorm: i64,
) -> (u64, i32, FKind, bool) {
    let keep = (q >> 3) as u64;
    let guard = (q >> 2) & 1 == 1;
    let rest = (q & 3) != 0 || st;
    let up = guard && (rest || keep & 1 == 1);
    let mut k = if up { keep.wrapping_add(1) } else { keep };
    let norm = 1u64 << (n - 1);
    let inexact = (q & 7) != 0 || st;
    if den {
        if k == norm {
            // Rounded up to the smallest normal.
            return (norm, enorm as i32, FKind::Normal, inexact);
        }
        let kk = if k == 0 { FKind::Zero } else { FKind::Denormal };
        return (k, 0, kk, inexact);
    }
    let mut e = e2;
    if n == 64 {
        if up && k == 0 {
            // Wrapped from `u64::MAX`: needs a carry.
            k = norm;
            e += 1;
        }
    } else if k >> n != 0 {
        k >>= 1;
        e += 1;
    }
    if e > emax_n {
        return (0, 0, FKind::Inf, true);
    }
    (k, e as i32, FKind::Normal, inexact)
}

/// Correctly-rounded decimal `M * 10^E` (`M > 0`) to `N` bits.
fn dec_convert(
    m: &Big,
    e10: i64,
    sticky: bool,
    n: u32,
    emax_n: i32,
    emin: i32,
) -> (u64, i32, FKind, bool) {
    let enorm = emin as i64 + n as i64 - 1;
    if e10 > 6000 {
        return (0, 0, FKind::Inf, true);
    }
    if e10 < -6000 {
        return (0, 0, FKind::Zero, true);
    }
    let e2f = m.bitlen() as f64 - 1.0 + e10 as f64 * LOG2_10;
    if e2f > emax_n as f64 + 32.0 {
        return (0, 0, FKind::Inf, true);
    }
    if e2f < emin as f64 - n as f64 - 64.0 {
        return (0, 0, FKind::Zero, true);
    }
    let mut num = Big::zero();
    num.copy_from(m);
    let mut den = Big::one();
    if e10 >= 0 {
        let mut t = e10;
        while t > 0 {
            if !num.mul_small(10) {
                return (0, 0, FKind::Inf, true);
            }
            t -= 1;
        }
    } else {
        let mut t = -e10;
        while t > 0 {
            if !den.mul_small(10) {
                return (0, 0, FKind::Zero, true);
            }
            t -= 1;
        }
    }
    // No `floor` in core: truncate then fix up negatives (e2f is
    // bounded here, so the float->int cast never saturates).
    let mut e2 = e2f as i64;
    if e2f < 0.0 && e2f != e2 as f64 {
        e2 -= 1;
    }
    while cmp_pow2(&num, &den, e2) == Ordering::Less {
        e2 -= 1;
    }
    while cmp_pow2(&num, &den, e2 + 1) != Ordering::Less {
        e2 += 1;
    }
    if e2 > emax_n as i64 {
        return (0, 0, FKind::Inf, true);
    }
    if e2 >= enorm {
        let d = e2 - n as i64 - 2;
        let (q, r) = if d >= 0 {
            let mut dd = Big::zero();
            dd.copy_from(&den);
            if !dd.shl(d as usize) {
                return (0, 0, FKind::Inf, true);
            }
            divmod(&num, &dd)
        } else {
            let mut nn = Big::zero();
            nn.copy_from(&num);
            if !nn.shl((-d) as usize) {
                return (0, 0, FKind::Inf, true);
            }
            divmod(&nn, &den)
        };
        let (k, e, fk, ix) = finish(q, !r.is_zero(), e2, false, n, emax_n as i64, enorm);
        return (k, e, fk, ix || sticky);
    }
    let mut nn = Big::zero();
    nn.copy_from(&num);
    if !nn.shl((3 - emin as i64) as usize) {
        return (0, 0, FKind::Zero, true);
    }
    let (q, r) = divmod(&nn, &den);
    let (k, e, fk, ix) = finish(q, !r.is_zero(), e2, true, n, emax_n as i64, enorm);
    (k, e, fk, ix || sticky)
}

/// Binary `hi * 2^k` (`hi > 0`) to `N` bits; hexfloat's exact core.
fn bin_convert(
    hi: u64,
    k: i64,
    sticky: bool,
    n: u32,
    emax_n: i32,
    emin: i32,
) -> (u64, i32, FKind, bool) {
    let enorm = emin as i64 + n as i64 - 1;
    let bl = 64 - hi.leading_zeros() as i64;
    let e2 = k.saturating_add(bl).saturating_sub(1);
    if e2 > emax_n as i64 {
        return (0, 0, FKind::Inf, true);
    }
    if e2 < emin as i64 - n as i64 - 64 {
        return (0, 0, FKind::Zero, true);
    }
    if e2 >= enorm {
        let want = n as i64 + 3;
        let (q, st) = if bl > want {
            let d = (bl - want) as u32;
            (
                (hi >> d) as u128,
                sticky || (hi & (u64::MAX >> (64 - d))) != 0,
            )
        } else {
            ((hi as u128) << (want - bl) as u32, sticky)
        };
        let (kk, e, fk, ix) = finish(q, st, e2, false, n, emax_n as i64, enorm);
        return (kk, e, fk, ix);
    }
    let s = k - (emin as i64 - 3);
    let (q, st) = if s >= 0 {
        ((hi as u128) << s as u32, sticky)
    } else if -s >= 64 {
        (0u128, true)
    } else {
        let d = (-s) as u32;
        (
            (hi >> d) as u128,
            sticky || (hi & (u64::MAX >> (64 - d))) != 0,
        )
    };
    let (kk, e, fk, ix) = finish(q, st, e2, true, n, emax_n as i64, enorm);
    (kk, e, fk, ix)
}

/// Packed float result: `f32`/`f64` bits, or 10 LE bytes of 80-bit
/// extended (explicit integer bit, `dtoa::fmt_f80_bits` layout).
enum FVal {
    F32(u32),
    F64(u64),
    F80([u8; 10]),
}

/// Pack `(sig, e2, kind)` for `prec` (0 `f32`, 1 `f64`, else 80-bit).
fn pack(prec: u32, neg: bool, sig: u64, e2: i32, k: FKind) -> FVal {
    let s32 = (neg as u32) << 31;
    let s64 = (neg as u64) << 63;
    match prec {
        0 => FVal::F32(match k {
            FKind::Zero => s32,
            FKind::Inf => s32 | 0x7F80_0000,
            FKind::Denormal => s32 | sig as u32,
            FKind::Normal => s32 | (((e2 + 127) as u32) << 23) | (sig as u32 & 0x7F_FFFF),
        }),
        1 => FVal::F64(match k {
            FKind::Zero => s64,
            FKind::Inf => s64 | 0x7FF0_0000_0000_0000,
            FKind::Denormal => s64 | sig,
            FKind::Normal => s64 | (((e2 + 1023) as u64) << 52) | (sig & 0xF_FFFF_FFFF_FFFF),
        }),
        _ => {
            let (se, mant) = match k {
                FKind::Zero => (0u16, 0u64),
                FKind::Inf => (0x7FFFu16, 0x8000_0000_0000_0000u64),
                FKind::Denormal => (0u16, sig),
                FKind::Normal => ((e2 + 16383) as u16, sig),
            };
            let se = se | ((neg as u16) << 15);
            let mut b = [0u8; 10];
            b[..8].copy_from_slice(&mant.to_le_bytes());
            b[8..].copy_from_slice(&se.to_le_bytes());
            FVal::F80(b)
        }
    }
}

/// Positive quiet NaN for `prec`.
fn nan_val(prec: u32) -> FVal {
    match prec {
        0 => FVal::F32(0x7FC0_0000),
        1 => FVal::F64(0x7FF8_0000_0000_0000),
        _ => {
            let mut b = [0u8; 10];
            b[..8].copy_from_slice(&0xC000_0000_0000_0000u64.to_le_bytes());
            b[8..].copy_from_slice(&0x7FFFu16.to_le_bytes());
            FVal::F80(b)
        }
    }
}

/// musl `scanexp` (pok=0): decimal/binary exponent, `i64::MIN` on none.
unsafe fn scanexp(in_: &mut In) -> i64 {
    unsafe {
        let mut c = in_.getc();
        let mut neg = false;
        if c == b'+' as c_int || c == b'-' as c_int {
            neg = c == b'-' as c_int;
            c = in_.getc();
        }
        if !is_dg(c) {
            in_.unget();
            return i64::MIN;
        }
        let mut x: i32 = 0;
        while is_dg(c) && x < i32::MAX / 10 {
            x = x.wrapping_mul(10).wrapping_add(c - b'0' as c_int);
            c = in_.getc();
        }
        let mut y = x as i64;
        while is_dg(c) && y < i64::MAX / 100 {
            y = y.wrapping_mul(10).wrapping_add((c - b'0' as c_int) as i64);
            c = in_.getc();
        }
        while is_dg(c) {
            c = in_.getc();
        }
        in_.unget();
        if neg {
            y.wrapping_neg()
        } else {
            y
        }
    }
}

/// Significant decimal digits kept (sticky past that).
const SIGCAP: usize = 1100;

/// musl `decfloat` with the integer-limb binary assembly.
///
/// # Safety
///
/// Reads through `in_`; lock held for `File` sources.
unsafe fn decfloat(
    in_: &mut In,
    mut c: c_int,
    prec: u32,
    n: u32,
    emax_n: i32,
    emin: i32,
    neg: bool,
) -> Option<FVal> {
    unsafe {
        let mut gotdig = false;
        while c == b'0' as c_int {
            gotdig = true;
            c = in_.getc();
        }
        let mut gotrad = false;
        // Digits after the point (all of them: the exponent is exact).
        let mut dap: i64 = 0;
        if c == b'.' as c_int {
            gotrad = true;
            c = in_.getc();
            while c == b'0' as c_int {
                gotdig = true;
                dap += 1;
                c = in_.getc();
            }
        }
        let mut sig = [0u8; SIGCAP];
        let mut nsig = 0usize;
        let mut sticky = false;
        let mut started = false;
        loop {
            if c == b'.' as c_int && !gotrad {
                gotrad = true;
                c = in_.getc();
                continue;
            }
            if !is_dg(c) {
                break;
            }
            let d = (c - b'0' as c_int) as u8;
            if !started && d == 0 {
                gotdig = true;
                if gotrad {
                    dap += 1;
                }
                c = in_.getc();
                continue;
            }
            started = true;
            gotdig = true;
            if nsig < SIGCAP {
                sig[nsig] = d;
                nsig += 1;
            } else if d != 0 {
                sticky = true;
            }
            if gotrad {
                dap += 1;
            }
            c = in_.getc();
        }
        let mut e10: i64 = 0;
        if gotdig && (c | 32) == b'e' as c_int {
            e10 = scanexp(in_);
            if e10 == i64::MIN {
                in_.set_lim(0);
                return None;
            }
        } else if c >= 0 {
            in_.unget();
        }
        if !gotdig {
            super::set_err(EINVAL);
            in_.set_lim(0);
            return None;
        }
        if !started {
            // All zeros: signed zero, before any range check (musl).
            return Some(pack(prec, neg, 0, 0, FKind::Zero));
        }
        let mut m = Big::zero();
        let mut si = 0;
        while si < nsig {
            m.mul_small(10);
            m.add_small(sig[si] as u32);
            si += 1;
        }
        let e = e10.saturating_sub(dap);
        let (sg, e2, k, ix) = dec_convert(&m, e, sticky, n, emax_n, emin);
        match k {
            FKind::Inf => super::set_err(ERANGE),
            FKind::Zero | FKind::Denormal => {
                if ix {
                    super::set_err(ERANGE);
                }
            }
            FKind::Normal => {}
        }
        Some(pack(prec, neg, sg, e2, k))
    }
}

/// musl `hexfloat` with the exact integer core.
///
/// # Safety
///
/// Reads through `in_`; lock held for `File` sources.
unsafe fn hexfloat(
    in_: &mut In,
    prec: u32,
    n: u32,
    emax_n: i32,
    emin: i32,
    neg: bool,
) -> Option<FVal> {
    unsafe {
        let mut c = in_.getc();
        let mut gotdig = false;
        while c == b'0' as c_int {
            gotdig = true;
            c = in_.getc();
        }
        let mut gotrad = false;
        // All digit slots (leading fractional zeros shift the point).
        let mut npoint: i64 = 0;
        let mut ndall: i64 = 0;
        if c == b'.' as c_int {
            gotrad = true;
            c = in_.getc();
            while c == b'0' as c_int {
                gotdig = true;
                ndall += 1;
                c = in_.getc();
            }
        }
        let mut hi: u64 = 0;
        let mut nhi = 0u32;
        let mut sticky = false;
        loop {
            if c == b'.' as c_int && !gotrad {
                gotrad = true;
                npoint = ndall;
                c = in_.getc();
                continue;
            }
            let d = hexdv(c);
            if d > 15 {
                break;
            }
            gotdig = true;
            if nhi < 16 {
                hi = hi.wrapping_mul(16).wrapping_add(d as u64);
                nhi += 1;
            } else if d != 0 {
                sticky = true;
            }
            ndall += 1;
            c = in_.getc();
        }
        if !gotdig {
            in_.unget();
            in_.set_lim(0);
            return None;
        }
        if !gotrad {
            npoint = ndall;
        }
        let mut e2p: i64 = 0;
        if (c | 32) == b'p' as c_int {
            e2p = scanexp(in_);
            if e2p == i64::MIN {
                in_.set_lim(0);
                return None;
            }
        } else if c >= 0 {
            in_.unget();
        }
        if hi == 0 {
            return Some(pack(prec, neg, 0, 0, FKind::Zero));
        }
        let kept = if ndall < 16 { ndall } else { 16 };
        let k = 4i64
            .wrapping_mul(npoint.wrapping_sub(kept))
            .saturating_add(e2p);
        let (sg, e2, fk, ix) = bin_convert(hi, k, sticky, n, emax_n, emin);
        match fk {
            FKind::Inf => super::set_err(ERANGE),
            FKind::Zero | FKind::Denormal => {
                if ix {
                    super::set_err(ERANGE);
                }
            }
            FKind::Normal => {}
        }
        Some(pack(prec, neg, sg, e2, fk))
    }
}

/// musl `__floatscan` (pok=0): `prec` 0 `f32`, 1 `f64`, 2 80-bit.
///
/// # Safety
///
/// Reads through `in_`; lock held for `File` sources.
unsafe fn floatscan(in_: &mut In, prec: u32) -> Option<FVal> {
    unsafe {
        let (n, emax_n, emin) = match prec {
            0 => (24u32, 127i32, -149i32),
            1 => (53u32, 1023i32, -1074i32),
            _ => (64u32, 16383i32, -16445i32),
        };
        let mut c: c_int;
        loop {
            c = in_.getc();
            if !is_sp(c) {
                break;
            }
        }
        let mut neg = false;
        if c == b'+' as c_int || c == b'-' as c_int {
            neg = c == b'-' as c_int;
            c = in_.getc();
        }
        let inf = b"infinity";
        let mut i = 0usize;
        while i < 8 && (c | 32) == inf[i] as c_int {
            if i < 7 {
                c = in_.getc();
            }
            i += 1;
        }
        if i == 3 || i == 8 {
            if i != 8 {
                in_.unget();
            }
            return Some(pack(prec, neg, 0, 0, FKind::Inf));
        }
        if i == 0 {
            let nan = b"nan";
            i = 0;
            while i < 3 && (c | 32) == nan[i] as c_int {
                if i < 2 {
                    c = in_.getc();
                }
                i += 1;
            }
        }
        if i == 3 {
            c = in_.getc();
            if c != b'(' as c_int {
                in_.unget();
                return Some(nan_val(prec));
            }
            loop {
                c = in_.getc();
                let ok = (c >= b'0' as c_int && c <= b'9' as c_int)
                    || (c >= b'A' as c_int && c <= b'Z' as c_int)
                    || (c >= b'a' as c_int && c <= b'z' as c_int)
                    || c == b'_' as c_int;
                if ok {
                    continue;
                }
                if c == b')' as c_int {
                    return Some(nan_val(prec));
                }
                in_.unget();
                super::set_err(EINVAL);
                in_.set_lim(0);
                return None;
            }
        }
        if i != 0 {
            in_.unget();
            super::set_err(EINVAL);
            in_.set_lim(0);
            return None;
        }
        if c == b'0' as c_int {
            let c2 = in_.getc();
            if (c2 | 32) == b'x' as c_int {
                return hexfloat(in_, prec, n, emax_n, emin, neg);
            }
            in_.unget();
            c = b'0' as c_int;
        }
        decfloat(in_, c, prec, n, emax_n, emin, neg)
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::{c_char, c_int, c_void};
    use core::hint::black_box;
    use core::ptr::null_mut;

    use super::{vfscanf, vsscanf, VaList};
    use crate::stdio::{fclose, fdopen, fputs, File};

    // Our own C-variadic symbols (naked trampolines): foreign `...`
    // declarations are stable to *call*; only *reading* needs nightly.
    extern "C" {
        fn scanf(fmt: *const c_char, ...) -> c_int;
        fn vscanf(fmt: *const c_char, ap: *mut super::super::VaList) -> c_int;
        fn fscanf(f: *mut File, fmt: *const c_char, ...) -> c_int;
        fn sscanf(s: *const c_char, fmt: *const c_char, ...) -> c_int;
    }

    /// musl `arch/x86_64/bits/syscall.h.in` (`SYS_pipe`, test plumbing).
    const SYS_PIPE: usize = 22;

    unsafe fn new_pipe() -> (c_int, c_int) {
        unsafe {
            let mut fds = [0 as c_int; 2];
            assert_eq!(
                crate::syscall::syscall_ret(crate::syscall::syscall2(
                    SYS_PIPE,
                    fds.as_mut_ptr() as usize,
                    0
                )),
                0
            );
            (fds[0], fds[1])
        }
    }

    #[test]
    fn scan_symbols_link() {
        // `scanf`/`vscanf` read fd 0: address-check only (no stdin
        // assumptions in the harness); the rest are called for real.
        assert!((scanf as *const () as usize) != 0);
        assert!((vscanf as *const () as usize) != 0);
        assert!((fscanf as *const () as usize) != 0);
        assert!((sscanf as *const () as usize) != 0);
        assert!((vfscanf as *const () as usize) != 0);
        assert!((vsscanf as *const () as usize) != 0);
    }

    #[test]
    fn scan_d_basics_and_n_counts() {
        unsafe {
            let mut a: c_int = 0;
            let mut b: c_int = 0;
            let mut n: c_int = 0;
            let r = sscanf(
                black_box(c"12 34".as_ptr()),
                black_box(c"%d %n%d".as_ptr()),
                &mut a,
                &mut n,
                &mut b,
            );
            assert_eq!(black_box(r), 2);
            assert_eq!((black_box(a), black_box(b), black_box(n)), (12, 34, 3));
            // `%n` alone stores but assigns nothing: count stays 0.
            let mut m = 99 as c_int;
            let r = sscanf(black_box(c"12".as_ptr()), black_box(c"%n".as_ptr()), &mut m);
            assert_eq!(black_box(r), 0);
            assert_eq!(black_box(m), 0);
        }
    }

    #[test]
    fn scan_n_lengths_and_suppressed() {
        unsafe {
            let mut a: c_int = 0;
            let mut n1: c_int = 0;
            let mut n2 = 0i8;
            let mut n3 = 0i16;
            let mut n4 = 0i64;
            let mut n5 = 0i64;
            let r = sscanf(
                black_box(c"12".as_ptr()),
                black_box(c"%d%n%hhn%hn%ln%lln".as_ptr()),
                &mut a,
                &mut n1,
                &mut n2,
                &mut n3,
                &mut n4,
                &mut n5,
            );
            assert_eq!(black_box(r), 1);
            assert_eq!(black_box(a), 12);
            assert_eq!(
                (
                    black_box(n1),
                    black_box(n2),
                    black_box(n3),
                    black_box(n4),
                    black_box(n5)
                ),
                (2, 2, 2, 2, 2)
            );
            // Suppressed `%*n` stores nothing and assigns nothing.
            let mut x: c_int = 0;
            let r = sscanf(
                black_box(c"12".as_ptr()),
                black_box(c"%d%*n".as_ptr()),
                &mut x,
            );
            assert_eq!(black_box(r), 1);
            assert_eq!(black_box(x), 12);
        }
    }

    #[test]
    fn scan_i_base_detection() {
        unsafe {
            for (inp, want) in [
                (c"10".as_ptr(), 10),
                (c"010".as_ptr(), 8),
                (c"0x10".as_ptr(), 16),
                (c"0XFF".as_ptr(), 255),
                (c"-010".as_ptr(), -8),
                (c"+0x1p0".as_ptr(), 1), // %i stops before the float 'p'
            ] {
                let mut x: c_int = 0;
                let r = sscanf(black_box(inp), black_box(c"%i".as_ptr()), &mut x);
                assert_eq!(black_box(r), 1);
                assert_eq!(black_box(x), want);
            }
        }
    }

    #[test]
    fn scan_uox_lengths() {
        unsafe {
            let mut u: c_int = 0;
            assert_eq!(
                sscanf(
                    black_box(c"4294967295".as_ptr()),
                    black_box(c"%u".as_ptr()),
                    &mut u
                ),
                1
            );
            assert_eq!(black_box(u), -1);
            let mut o: c_int = 0;
            assert_eq!(
                sscanf(black_box(c"17".as_ptr()), black_box(c"%o".as_ptr()), &mut o),
                1
            );
            assert_eq!(black_box(o), 15);
            let mut x: c_int = 0;
            assert_eq!(
                sscanf(black_box(c"FF".as_ptr()), black_box(c"%X".as_ptr()), &mut x),
                1
            );
            assert_eq!(black_box(x), 255);
            let mut v: *mut c_void = null_mut();
            assert_eq!(
                sscanf(
                    black_box(c"0x1234".as_ptr()),
                    black_box(c"%p".as_ptr()),
                    &mut v
                ),
                1
            );
            assert_eq!(black_box(v) as usize, 0x1234);
            let mut h = 0i16;
            assert_eq!(
                sscanf(
                    black_box(c"70000".as_ptr()),
                    black_box(c"%hd".as_ptr()),
                    &mut h
                ),
                1
            );
            assert_eq!(black_box(h), 4464); // (short)70000 wraps mod 2^16
            let mut hh = 0i8;
            assert_eq!(
                sscanf(
                    black_box(c"257".as_ptr()),
                    black_box(c"%hhd".as_ptr()),
                    &mut hh
                ),
                1
            );
            assert_eq!(black_box(hh), 1);
        }
    }

    #[test]
    fn scan_int_overflow_is_musl_exact() {
        unsafe {
            // musl's vfscanf passes ULLONG_MAX as intscan's lim: huge
            // inputs return ULLONG_MAX and truncate into the destination.
            let mut d: c_int = 0;
            assert_eq!(
                sscanf(
                    black_box(c"99999999999999999999999".as_ptr()),
                    black_box(c"%d".as_ptr()),
                    &mut d
                ),
                1
            );
            assert_eq!(black_box(d), -1);
            let mut u = 0_u32;
            assert_eq!(
                sscanf(
                    black_box(c"99999999999999999999999".as_ptr()),
                    black_box(c"%u".as_ptr()),
                    &mut u
                ),
                1
            );
            assert_eq!(black_box(u), u32::MAX);
            let mut q = 0i64;
            assert_eq!(
                sscanf(
                    black_box(c"99999999999999999999999".as_ptr()),
                    black_box(c"%lld".as_ptr()),
                    &mut q
                ),
                1
            );
            assert_eq!(black_box(q), -1);
            // Negative huge clears the sign first: same ULLONG_MAX.
            let mut nd: c_int = 0;
            assert_eq!(
                sscanf(
                    black_box(c"-99999999999999999999999".as_ptr()),
                    black_box(c"%d".as_ptr()),
                    &mut nd
                ),
                1
            );
            assert_eq!(black_box(nd), -1);
            // Exact edges survive: LLONG_MIN and ULLONG_MAX.
            let mut lo = 0i64;
            assert_eq!(
                sscanf(
                    black_box(c"-9223372036854775808".as_ptr()),
                    black_box(c"%lld".as_ptr()),
                    &mut lo
                ),
                1
            );
            assert_eq!(black_box(lo), i64::MIN);
            let mut hi = 0_u64;
            assert_eq!(
                sscanf(
                    black_box(c"18446744073709551615".as_ptr()),
                    black_box(c"%llu".as_ptr()),
                    &mut hi
                ),
                1
            );
            assert_eq!(black_box(hi), u64::MAX);
        }
    }

    #[test]
    fn scan_width_and_suppression() {
        unsafe {
            let mut a: c_int = 0;
            let mut b: c_int = 0;
            let r = sscanf(
                black_box(c"1234".as_ptr()),
                black_box(c"%2d%d".as_ptr()),
                &mut a,
                &mut b,
            );
            assert_eq!(black_box(r), 2);
            assert_eq!((black_box(a), black_box(b)), (12, 34));
            let mut x: c_int = 0;
            let r = sscanf(
                black_box(c"12 34".as_ptr()),
                black_box(c"%*d%d".as_ptr()),
                &mut x,
            );
            assert_eq!(black_box(r), 1);
            assert_eq!(black_box(x), 34);
        }
    }

    #[test]
    fn scan_positional_args() {
        unsafe {
            let mut a: c_int = 0;
            let mut b: c_int = 0;
            let r = sscanf(
                black_box(c"10 20".as_ptr()),
                black_box(c"%2$d %1$d".as_ptr()),
                &mut a,
                &mut b,
            );
            assert_eq!(black_box(r), 2);
            assert_eq!((black_box(a), black_box(b)), (20, 10));
        }
    }

    #[test]
    fn scan_float_basic_efg() {
        unsafe {
            let mut f = 0.0f32;
            assert_eq!(
                sscanf(
                    black_box(c"3.14".as_ptr()),
                    black_box(c"%f".as_ptr()),
                    &mut f
                ),
                1
            );
            // 3.14 is the parsed input here, not an approximation of PI.
            #[allow(clippy::approx_constant)]
            {
                assert!((black_box(f) - 3.14f32).abs() < 1e-6);
            }
            let mut e = 0.0f32;
            assert_eq!(
                sscanf(
                    black_box(c"1e-3".as_ptr()),
                    black_box(c"%e".as_ptr()),
                    &mut e
                ),
                1
            );
            assert!((black_box(e) - 0.001f32).abs() < 1e-9);
            let mut g = 0.0f32;
            assert_eq!(
                sscanf(
                    black_box(c"-2.5E2".as_ptr()),
                    black_box(c"%g".as_ptr()),
                    &mut g
                ),
                1
            );
            assert_eq!(black_box(g), -250.0f32);
            // `%lf` of 0.1 is the exact double.
            let mut d = 0.0f64;
            assert_eq!(
                sscanf(
                    black_box(c"0.1".as_ptr()),
                    black_box(c"%lf".as_ptr()),
                    &mut d
                ),
                1
            );
            assert_eq!(black_box(d).to_bits(), 0x3FB9_9999_9999_999Au64);
        }
    }

    #[test]
    fn scan_float_hex_exact() {
        unsafe {
            let mut d = 0.0f64;
            assert_eq!(
                sscanf(
                    black_box(c"0x1.8p+0".as_ptr()),
                    black_box(c"%la".as_ptr()),
                    &mut d
                ),
                1
            );
            assert_eq!(black_box(d).to_bits(), 0x3FF8_0000_0000_0000u64);
            let mut f = 0.0f32;
            assert_eq!(
                sscanf(
                    black_box(c"0x1.8p+0".as_ptr()),
                    black_box(c"%a".as_ptr()),
                    &mut f
                ),
                1
            );
            assert_eq!(black_box(f).to_bits(), 0x3FC0_0000u32);
            // Exact subnormal-cm-thin hex: 0.1's shortest hex spelling.
            let mut h = 0.0f64;
            assert_eq!(
                sscanf(
                    black_box(c"0x1.999999999999ap-4".as_ptr()),
                    black_box(c"%lf".as_ptr()),
                    &mut h
                ),
                1
            );
            assert_eq!(black_box(h).to_bits(), 0x3FB9_9999_9999_999Au64);
        }
    }

    #[test]
    fn scan_float_long_double_bytes() {
        unsafe {
            let mut ext = [0u8; 10];
            assert_eq!(
                sscanf(
                    black_box(c"1.0".as_ptr()),
                    black_box(c"%Lf".as_ptr()),
                    ext.as_mut_ptr()
                ),
                1
            );
            let ext = black_box(ext);
            assert_eq!(
                ext,
                [0, 0, 0, 0, 0, 0, 0, 0x80, 0xFF, 0x3F],
                "1.0L = integer bit + 0x3FFF"
            );
            let mut neg = [0u8; 10];
            assert_eq!(
                sscanf(
                    black_box(c"-0.0".as_ptr()),
                    black_box(c"%Lf".as_ptr()),
                    neg.as_mut_ptr()
                ),
                1
            );
            let neg = black_box(neg);
            assert_eq!(neg[9] & 0x80, 0x80, "sign bit survives on -0.0L");
            assert_eq!(&neg[..8], &[0u8; 8]);
        }
    }

    #[test]
    fn scan_float_inf_nan_overflow() {
        unsafe {
            let mut f = 0.0f32;
            assert_eq!(
                sscanf(
                    black_box(c"inf".as_ptr()),
                    black_box(c"%f".as_ptr()),
                    &mut f
                ),
                1
            );
            assert_eq!(black_box(f).to_bits(), 0x7F80_0000u32);
            let mut g = 0.0f64;
            assert_eq!(
                sscanf(
                    black_box(c"-Infinity".as_ptr()),
                    black_box(c"%lf".as_ptr()),
                    &mut g
                ),
                1
            );
            assert_eq!(black_box(g), f64::NEG_INFINITY);
            let mut n = 0.0f64;
            assert_eq!(
                sscanf(
                    black_box(c"nan".as_ptr()),
                    black_box(c"%lf".as_ptr()),
                    &mut n
                ),
                1
            );
            assert!(black_box(n).is_nan());
            let mut big = 0.0f64;
            assert_eq!(
                sscanf(
                    black_box(c"1e999".as_ptr()),
                    black_box(c"%lf".as_ptr()),
                    &mut big
                ),
                1
            );
            assert_eq!(black_box(big), f64::INFINITY);
            let mut tiny = 1.0f64;
            assert_eq!(
                sscanf(
                    black_box(c"1e-999".as_ptr()),
                    black_box(c"%lf".as_ptr()),
                    &mut tiny
                ),
                1
            );
            assert_eq!(black_box(tiny), 0.0);
        }
    }

    #[test]
    fn scan_c_strings() {
        unsafe {
            let mut a = 0 as c_char;
            let mut b = 0 as c_char;
            assert_eq!(
                sscanf(
                    black_box(c"ab".as_ptr()),
                    black_box(c"%c%c".as_ptr()),
                    &mut a,
                    &mut b
                ),
                2
            );
            assert_eq!(
                (black_box(a), black_box(b)),
                (b'a' as c_char, b'b' as c_char)
            );
            // `%c` does not skip whitespace.
            let mut sp = 0 as c_char;
            assert_eq!(
                sscanf(
                    black_box(c" a".as_ptr()),
                    black_box(c"%c".as_ptr()),
                    &mut sp
                ),
                1
            );
            assert_eq!(black_box(sp), b' ' as c_char);
            // Width: exactly N bytes, no NUL.
            let mut w = [0u8; 3];
            assert_eq!(
                sscanf(
                    black_box(c"hello".as_ptr()),
                    black_box(c"%3c".as_ptr()),
                    w.as_mut_ptr()
                ),
                1
            );
            assert_eq!(black_box(w), *b"hel");
            // `%s` skips space, stops at space, NUL-terminates.
            let mut s1 = [0u8; 16];
            let mut s2 = [0u8; 16];
            let r = sscanf(
                black_box(c"  hello world".as_ptr()),
                black_box(c"%s%s".as_ptr()),
                s1.as_mut_ptr(),
                s2.as_mut_ptr(),
            );
            assert_eq!(black_box(r), 2);
            assert_eq!(&black_box(s1)[..6], b"hello\0");
            assert_eq!(&black_box(s2)[..6], b"world\0");
            let mut t = [0u8; 16];
            assert_eq!(
                sscanf(
                    black_box(c"hello".as_ptr()),
                    black_box(c"%3s".as_ptr()),
                    t.as_mut_ptr()
                ),
                1
            );
            assert_eq!(&black_box(t)[..4], b"hel\0");
        }
    }

    #[test]
    fn scan_scansets() {
        unsafe {
            let mut b = [0u8; 16];
            assert_eq!(
                sscanf(
                    black_box(c"abcaX".as_ptr()),
                    black_box(c"%[abc]".as_ptr()),
                    b.as_mut_ptr()
                ),
                1
            );
            assert_eq!(&black_box(b)[..5], b"abca\0");
            let mut nb = [0u8; 16];
            assert_eq!(
                sscanf(
                    black_box(c"xyzabc".as_ptr()),
                    black_box(c"%[^abc]".as_ptr()),
                    nb.as_mut_ptr()
                ),
                1
            );
            assert_eq!(&black_box(nb)[..4], b"xyz\0");
            let mut rg = [0u8; 16];
            assert_eq!(
                sscanf(
                    black_box(c"hello123".as_ptr()),
                    black_box(c"%[a-z]".as_ptr()),
                    rg.as_mut_ptr()
                ),
                1
            );
            assert_eq!(&black_box(rg)[..6], b"hello\0");
            let mut al = [0u8; 16];
            assert_eq!(
                sscanf(
                    black_box(c"aZ09!".as_ptr()),
                    black_box(c"%[a-zA-Z0-9]".as_ptr()),
                    al.as_mut_ptr()
                ),
                1
            );
            assert_eq!(&black_box(al)[..5], b"aZ09\0");
            // Leading `]` and `-` are literals, not syntax.
            let mut br = [0u8; 16];
            assert_eq!(
                sscanf(
                    black_box(c"]ab]".as_ptr()),
                    black_box(c"%[]ab]".as_ptr()),
                    br.as_mut_ptr()
                ),
                1
            );
            assert_eq!(&black_box(br)[..5], b"]ab]\0");
            let mut da = [0u8; 16];
            assert_eq!(
                sscanf(
                    black_box(c"-aX".as_ptr()),
                    black_box(c"%[-a]".as_ptr()),
                    da.as_mut_ptr()
                ),
                1
            );
            assert_eq!(&black_box(da)[..3], b"-a\0");
            // Suppressed + width scanset still validates the match.
            let r = sscanf(
                black_box(c"abc123".as_ptr()),
                black_box(c"%*[a-z]%d".as_ptr()),
                &mut b,
            );
            let _ = black_box(r);
            let mut v: c_int = 0;
            assert_eq!(
                sscanf(
                    black_box(c"abc123".as_ptr()),
                    black_box(c"%*[a-z]%d".as_ptr()),
                    &mut v
                ),
                1
            );
            assert_eq!(black_box(v), 123);
        }
    }

    #[test]
    fn scan_literals_and_percent() {
        unsafe {
            let mut x: c_int = 0;
            assert_eq!(
                sscanf(
                    black_box(c"a12c".as_ptr()),
                    black_box(c"a%dbc".as_ptr()),
                    &mut x
                ),
                1
            );
            assert_eq!(black_box(x), 12);
            // Mismatch (not EOF): 0 conversions.
            assert_eq!(
                sscanf(black_box(c"xb".as_ptr()), black_box(c"a".as_ptr())),
                0
            );
            // EOF on a literal: -1.
            assert_eq!(
                sscanf(black_box(c"".as_ptr()), black_box(c"a".as_ptr())),
                -1
            );
            // `%%` matches a literal percent, assigns nothing.
            assert_eq!(
                sscanf(black_box(c"%".as_ptr()), black_box(c"%%".as_ptr())),
                0
            );
            // Format whitespace skips input whitespace.
            let mut w: c_int = 0;
            assert_eq!(
                sscanf(
                    black_box(c"1   2".as_ptr()),
                    black_box(c"%d %d".as_ptr()),
                    &mut w,
                    &mut x
                ),
                2
            );
            assert_eq!((black_box(w), black_box(x)), (1, 2));
        }
    }

    #[test]
    fn scan_eof_paths() {
        unsafe {
            let mut x: c_int = 0;
            // Empty input, empty format: musl primes the stream → EOF.
            assert_eq!(sscanf(black_box(c"".as_ptr()), black_box(c"".as_ptr())), -1);
            // Non-empty input, empty format: 0.
            assert_eq!(sscanf(black_box(c"x".as_ptr()), black_box(c"".as_ptr())), 0);
            // No digits at all: match failure, 0.
            assert_eq!(
                sscanf(
                    black_box(c"xyz".as_ptr()),
                    black_box(c"%d".as_ptr()),
                    &mut x
                ),
                0
            );
            // Partial: first converts, second hits EOF → 1.
            let mut a: c_int = 0;
            let mut b: c_int = 0;
            assert_eq!(
                sscanf(
                    black_box(c"12".as_ptr()),
                    black_box(c"%d%d".as_ptr()),
                    &mut a,
                    &mut b
                ),
                1
            );
            assert_eq!(black_box(a), 12);
            // `%c` on empty input: input failure → -1.
            let mut ch = 0 as c_char;
            assert_eq!(
                sscanf(black_box(c"".as_ptr()), black_box(c"%c".as_ptr()), &mut ch),
                -1
            );
        }
    }

    #[test]
    fn scan_determinism() {
        unsafe {
            // Same string twice: identical outcomes (no hidden state).
            for _ in 0..2 {
                let mut a: c_int = 0;
                let mut d = 0.0f64;
                let mut s = [0u8; 8];
                let r = sscanf(
                    black_box(c"42 0.5 hi".as_ptr()),
                    black_box(c"%d%lf%s".as_ptr()),
                    &mut a,
                    &mut d,
                    s.as_mut_ptr(),
                );
                assert_eq!(black_box(r), 3);
                assert_eq!(black_box(a), 42);
                assert_eq!(black_box(d).to_bits(), 0x3FE0_0000_0000_0000u64);
                assert_eq!(&black_box(s)[..3], b"hi\0");
            }
        }
    }

    #[test]
    fn scan_v_workers_take_valist() {
        unsafe {
            // Synthetic SysV tag (like the printf walker test): GP slots
            // then overflow, FP untouched.
            let mut x: c_int = 0;
            let mut y: c_int = 0;
            let mut regs = [0u64; 6];
            regs[0] = &mut x as *mut c_int as u64;
            regs[1] = &mut y as *mut c_int as u64;
            let mut over = [0u64; 4];
            let mut tag = VaList {
                gp: 0,
                fp: 48,
                overflow: over.as_mut_ptr() as *mut u8,
                regsave: regs.as_mut_ptr() as *mut u8,
            };
            let r = vsscanf(
                black_box(c"7 8".as_ptr()),
                black_box(c"%d %d".as_ptr()),
                &mut tag,
            );
            assert_eq!(black_box(r), 2);
            assert_eq!((black_box(x), black_box(y)), (7, 8));
        }
    }

    #[test]
    fn scan_fscanf_from_pipe() {
        unsafe {
            let (r, w) = new_pipe();
            let wf = fdopen(w, c"w".as_ptr());
            assert!(!wf.is_null());
            assert_eq!(fputs(black_box(c"42 3.5 hello".as_ptr()), wf), 0);
            assert_eq!(fclose(wf), 0);
            let rf = fdopen(r, c"r".as_ptr());
            assert!(!rf.is_null());
            let mut a: c_int = 0;
            let mut b = 0.0f32;
            let mut s = [0u8; 16];
            // Direct `vfscanf` with a synthetic tag: same pipe, real fd.
            let mut regs = [0u64; 6];
            regs[0] = &mut a as *mut c_int as u64;
            regs[1] = &mut b as *mut f32 as u64;
            regs[2] = s.as_mut_ptr() as u64;
            let mut over = [0u64; 4];
            let mut tag = VaList {
                gp: 0,
                fp: 48,
                overflow: over.as_mut_ptr() as *mut u8,
                regsave: regs.as_mut_ptr() as *mut u8,
            };
            let n = vfscanf(rf, black_box(c"%d%f%s".as_ptr()), black_box(&mut tag));
            assert_eq!(black_box(n), 3);
            assert_eq!(black_box(a), 42);
            assert_eq!(black_box(b), 3.5f32);
            assert_eq!(&black_box(s)[..6], b"hello\0");
            assert_eq!(fclose(rf), 0);
        }
    }

    #[test]
    fn scan_fscanf_trampoline_from_pipe() {
        unsafe {
            let (r, w) = new_pipe();
            let wf = fdopen(w, c"w".as_ptr());
            assert!(!wf.is_null());
            assert_eq!(fputs(black_box(c"-8 0x10".as_ptr()), wf), 0);
            assert_eq!(fclose(wf), 0);
            let rf = fdopen(r, c"r".as_ptr());
            assert!(!rf.is_null());
            let mut a: c_int = 0;
            let mut b: c_int = 0;
            let n = fscanf(rf, black_box(c"%d%i".as_ptr()), &mut a, &mut b);
            assert_eq!(black_box(n), 2);
            assert_eq!((black_box(a), black_box(b)), (-8, 16));
            assert_eq!(fclose(rf), 0);
        }
    }
}
