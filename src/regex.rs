//! POSIX regex, globbing, word expansion, file-tree walk, path splitting.
//!
//! musl sources: `src/regex/regcomp.c`, `regexec.c`, `regerror.c`
//! (TRE NFA engine), `src/regex/glob.c`, `src/regex/fnmatch.c`,
//! `src/misc/wordexp.c`, `src/misc/nftw.c`, `src/legacy/ftw.c`,
//! `src/misc/basename.c`, `src/misc/dirname.c`.
//!
//! Shape: `glob`/`nftw`/`ftw`/`basename`/`dirname` follow musl's
//! structure line for line (same traversal, same edge semantics, same
//! `GLOB_*`/`FTW_*` values); `fnmatch` keeps musl's segment split and
//! `FNM_PERIOD` rule but compares bytes, not `wchar_t`. The regex side
//! keeps musl's grammar (BRE/ERE atoms, `[...]` classes incl.
//! `[:class:]`, `{m,n}` intervals, `\(...\)` groups, `\1` backrefs,
//! musl's error codes and `regerror` strings verbatim) but compiles to
//! a small Thompson bytecode run by a backtracking VM instead of the
//! full TRE TNFA/tag engine.
//!
//! Deliberate deviations (each cheaper than the musl original, same
//! observable contract on the tested surface):
//! - leftmost-greedy (Perl-like) match, not POSIX leftmost-longest.
//! - byte-oriented: no multibyte; `REG_ICASE` folds ASCII only.
//! - GNU `\b \< \> \B \xHH` escapes are plain literals.
//! - `~user` globs fail with `GLOB_NOMATCH` (no passwd db); bare `~`
//!   uses `$HOME` via `getenv`.
//! - `wordexp` never forks: command substitution always returns
//!   `WRDE_CMDSUB`, no pathname expansion, expansions do not
//!   field-split, shell-only `$`-forms stay literal.
//! - the matcher carries finite fuel (`1<<22` steps); adversarial
//!   backtracking degrades to `REG_NOMATCH` instead of hanging.
//! - no `__xpg_basename` alias (no `weak_alias!` per work order).
//! - `nftw` skips `pthread_setcancelstate` (the crate has no
//!   cancellation); `FTW_CHDIR` is accepted and ignored, as in musl.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::mem::{offset_of, size_of};
use core::ptr::null_mut;

use crate::errno::__errno_location;
use crate::malloc::{free, malloc, realloc};
use crate::mem::{memcpy, strlen};

extern "C" {
    fn getenv(name: *const c_char) -> *mut c_char;
}

// ---- Types (musl include/regex.h, glob.h, wordexp.h, ftw.h) ---------------

/// musl `regoff_t` (`_Addr` = `long` on x86_64).
#[allow(non_camel_case_types)]
#[cfg(target_arch = "x86_64")]
pub type regoff_t = c_long;

/// musl `regex_t` (`include/regex.h:15-20`), field for field.
#[allow(non_camel_case_types)]
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct regex_t {
    pub re_nsub: usize,
    pub __opaque: *mut c_void,
    pub __padding: [*mut c_void; 4],
    pub __nsub2: usize,
    pub __padding2: c_char,
}

/// musl `regmatch_t` (`include/regex.h:22-25`).
#[allow(non_camel_case_types)]
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct regmatch_t {
    pub rm_so: regoff_t,
    pub rm_eo: regoff_t,
}

/// musl `glob_t` (`include/glob.h:14-20`), field for field.
#[allow(non_camel_case_types)]
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct glob_t {
    pub gl_pathc: usize,
    pub gl_pathv: *mut *mut c_char,
    pub gl_offs: usize,
    pub __dummy1: c_int,
    pub __dummy2: [*mut c_void; 5],
}

/// musl `wordexp_t` (`include/wordexp.h:21-25`), field for field.
#[allow(non_camel_case_types)]
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct wordexp_t {
    pub we_wordc: usize,
    pub we_wordv: *mut *mut c_char,
    pub we_offs: usize,
}

/// musl `struct FTW` (`include/ftw.h:23-26`), field for field.
#[allow(non_camel_case_types)]
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct FTW {
    pub base: c_int,
    pub level: c_int,
}

#[cfg(target_arch = "x86_64")]
const _: () = assert!(size_of::<regex_t>() == 64);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(offset_of!(regex_t, re_nsub) == 0);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(offset_of!(regex_t, __opaque) == 8);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(offset_of!(regex_t, __padding) == 16);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(offset_of!(regex_t, __nsub2) == 48);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(offset_of!(regex_t, __padding2) == 56);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(size_of::<regmatch_t>() == 16);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(size_of::<glob_t>() == 72);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(size_of::<wordexp_t>() == 24);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(size_of::<FTW>() == 8);

// ---- Consts (musl values, verified against the headers) --------------------

#[cfg(target_arch = "x86_64")]
pub const REG_EXTENDED: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const REG_ICASE: c_int = 2;
#[cfg(target_arch = "x86_64")]
pub const REG_NEWLINE: c_int = 4;
#[cfg(target_arch = "x86_64")]
pub const REG_NOSUB: c_int = 8;
#[cfg(target_arch = "x86_64")]
pub const REG_NOTBOL: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const REG_NOTEOL: c_int = 2;
#[cfg(target_arch = "x86_64")]
pub const REG_OK: c_int = 0;
#[cfg(target_arch = "x86_64")]
pub const REG_NOMATCH: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const REG_BADPAT: c_int = 2;
#[cfg(target_arch = "x86_64")]
pub const REG_ECOLLATE: c_int = 3;
#[cfg(target_arch = "x86_64")]
pub const REG_ECTYPE: c_int = 4;
#[cfg(target_arch = "x86_64")]
pub const REG_EESCAPE: c_int = 5;
#[cfg(target_arch = "x86_64")]
pub const REG_ESUBREG: c_int = 6;
#[cfg(target_arch = "x86_64")]
pub const REG_EBRACK: c_int = 7;
#[cfg(target_arch = "x86_64")]
pub const REG_EPAREN: c_int = 8;
#[cfg(target_arch = "x86_64")]
pub const REG_EBRACE: c_int = 9;
#[cfg(target_arch = "x86_64")]
pub const REG_BADBR: c_int = 10;
#[cfg(target_arch = "x86_64")]
pub const REG_ERANGE: c_int = 11;
#[cfg(target_arch = "x86_64")]
pub const REG_ESPACE: c_int = 12;
#[cfg(target_arch = "x86_64")]
pub const REG_BADRPT: c_int = 13;
#[cfg(target_arch = "x86_64")]
pub const REG_ENOSYS: c_int = -1;

#[cfg(target_arch = "x86_64")]
pub const GLOB_ERR: c_int = 0x01;
#[cfg(target_arch = "x86_64")]
pub const GLOB_MARK: c_int = 0x02;
#[cfg(target_arch = "x86_64")]
pub const GLOB_NOSORT: c_int = 0x04;
#[cfg(target_arch = "x86_64")]
pub const GLOB_DOOFFS: c_int = 0x08;
#[cfg(target_arch = "x86_64")]
pub const GLOB_NOCHECK: c_int = 0x10;
#[cfg(target_arch = "x86_64")]
pub const GLOB_APPEND: c_int = 0x20;
#[cfg(target_arch = "x86_64")]
pub const GLOB_NOESCAPE: c_int = 0x40;
#[cfg(target_arch = "x86_64")]
pub const GLOB_PERIOD: c_int = 0x80;
#[cfg(target_arch = "x86_64")]
pub const GLOB_TILDE: c_int = 0x1000;
#[cfg(target_arch = "x86_64")]
pub const GLOB_TILDE_CHECK: c_int = 0x4000;
#[cfg(target_arch = "x86_64")]
pub const GLOB_NOSPACE: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const GLOB_ABORTED: c_int = 2;
#[cfg(target_arch = "x86_64")]
pub const GLOB_NOMATCH: c_int = 3;
#[cfg(target_arch = "x86_64")]
pub const GLOB_NOSYS: c_int = 4;

#[cfg(target_arch = "x86_64")]
pub const FNM_PATHNAME: c_int = 0x1;
#[cfg(target_arch = "x86_64")]
pub const FNM_NOESCAPE: c_int = 0x2;
#[cfg(target_arch = "x86_64")]
pub const FNM_PERIOD: c_int = 0x4;
#[cfg(target_arch = "x86_64")]
pub const FNM_LEADING_DIR: c_int = 0x8;
#[cfg(target_arch = "x86_64")]
pub const FNM_CASEFOLD: c_int = 0x10;
#[cfg(target_arch = "x86_64")]
pub const FNM_NOCASE: c_int = 0x10;
#[cfg(target_arch = "x86_64")]
pub const FNM_FILE_NAME: c_int = 0x1;
#[cfg(target_arch = "x86_64")]
pub const FNM_NOMATCH: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const FNM_NOSYS: c_int = -1;

#[cfg(target_arch = "x86_64")]
pub const WRDE_DOOFFS: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const WRDE_APPEND: c_int = 2;
#[cfg(target_arch = "x86_64")]
pub const WRDE_NOCMD: c_int = 4;
#[cfg(target_arch = "x86_64")]
pub const WRDE_REUSE: c_int = 8;
#[cfg(target_arch = "x86_64")]
pub const WRDE_SHOWERR: c_int = 16;
#[cfg(target_arch = "x86_64")]
pub const WRDE_UNDEF: c_int = 32;
#[cfg(target_arch = "x86_64")]
pub const WRDE_NOSPACE: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const WRDE_BADCHAR: c_int = 2;
#[cfg(target_arch = "x86_64")]
pub const WRDE_BADVAL: c_int = 3;
#[cfg(target_arch = "x86_64")]
pub const WRDE_CMDSUB: c_int = 4;
#[cfg(target_arch = "x86_64")]
pub const WRDE_SYNTAX: c_int = 5;
#[cfg(target_arch = "x86_64")]
pub const WRDE_NOSYS: c_int = -1;

#[cfg(target_arch = "x86_64")]
pub const FTW_F: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const FTW_D: c_int = 2;
#[cfg(target_arch = "x86_64")]
pub const FTW_DNR: c_int = 3;
#[cfg(target_arch = "x86_64")]
pub const FTW_NS: c_int = 4;
#[cfg(target_arch = "x86_64")]
pub const FTW_SL: c_int = 5;
#[cfg(target_arch = "x86_64")]
pub const FTW_DP: c_int = 6;
#[cfg(target_arch = "x86_64")]
pub const FTW_SLN: c_int = 7;
#[cfg(target_arch = "x86_64")]
pub const FTW_PHYS: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const FTW_MOUNT: c_int = 2;
#[cfg(target_arch = "x86_64")]
pub const FTW_CHDIR: c_int = 4;
#[cfg(target_arch = "x86_64")]
pub const FTW_DEPTH: c_int = 8;

// ---- Shared bits ------------------------------------------------------------

/// musl `include/limits.h:85`.
#[cfg(target_arch = "x86_64")]
const RE_DUP_MAX: u32 = 255;
/// musl `include/limits.h` (`PATH_MAX`).
#[cfg(target_arch = "x86_64")]
const PATH_MAX: usize = 4096;
/// musl `arch/generic/bits/errno.h` values used here.
#[cfg(target_arch = "x86_64")]
const ENOENT: c_int = 2;
#[cfg(target_arch = "x86_64")]
const EACCES: c_int = 13;
#[cfg(target_arch = "x86_64")]
const ENAMETOOLONG: c_int = 36;
#[cfg(target_arch = "x86_64")]
const ENOMEM: c_int = 12;

/// Read `errno`.
#[cfg(target_arch = "x86_64")]
unsafe fn e_get() -> c_int {
    unsafe { *__errno_location() }
}

/// Write `errno`.
#[cfg(target_arch = "x86_64")]
unsafe fn e_set(v: c_int) {
    unsafe {
        crate::errno::errno_store(__errno_location(), v);
    }
}

/// ASCII case fold (the `REG_ICASE`/`FNM_CASEFOLD` domain is bytes).
#[cfg(target_arch = "x86_64")]
fn fold_byte(b: u8) -> u8 {
    if b.is_ascii_uppercase() {
        b.wrapping_add(32)
    } else {
        b
    }
}

#[cfg(target_arch = "x86_64")]
fn byte_eq(a: u8, b: u8, icase: bool) -> bool {
    a == b || (icase && fold_byte(a) == fold_byte(b))
}

// ---- Regex bytecode ---------------------------------------------------------

#[cfg(target_arch = "x86_64")]
const OP_BYTE: u8 = 0;
#[cfg(target_arch = "x86_64")]
const OP_ANY: u8 = 1;
#[cfg(target_arch = "x86_64")]
const OP_CLS: u8 = 2;
#[cfg(target_arch = "x86_64")]
const OP_BOL: u8 = 3;
#[cfg(target_arch = "x86_64")]
const OP_EOL: u8 = 4;
#[cfg(target_arch = "x86_64")]
const OP_SPLIT: u8 = 5;
#[cfg(target_arch = "x86_64")]
const OP_SAVE: u8 = 6;
#[cfg(target_arch = "x86_64")]
const OP_BREF: u8 = 7;
#[cfg(target_arch = "x86_64")]
const OP_MATCH: u8 = 8;
#[cfg(target_arch = "x86_64")]
const OP_JMP: u8 = 9;

#[cfg(target_arch = "x86_64")]
const HOLE: u32 = u32::MAX;
#[cfg(target_arch = "x86_64")]
const ARM_X: u8 = 0;
#[cfg(target_arch = "x86_64")]
const ARM_Y: u8 = 1;

/// One Thompson instruction. `x`/`y` are jump targets for
/// `SPLIT`/`BOL`/`EOL`/`JMP`; `b` is the literal for `BYTE`; `x`/`y`
/// are class-pool index/count for `CLS`; `x` is the slot for `SAVE`
/// and the group number for `BREF`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
struct Ins {
    op: u8,
    b: u8,
    neg: u8,
    _z: u8,
    x: u32,
    y: u32,
}

/// Patch-list link: instruction `pos`, arm `arm` (`x`/`y`), next link.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
struct PNode {
    pos: u32,
    arm: u8,
    _p: [u8; 3],
    next: u32,
}

/// Compiled program owned by `regex_t.__opaque`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct Prog {
    nsub: u32,
    cflags: c_int,
    nins: u32,
    start: u32,
    ins: *mut Ins,
    cls: *mut u8,
    ncls: u32,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
struct Frag {
    start: u32,
    out: u32,
}

#[cfg(target_arch = "x86_64")]
const FRAG_EMPTY: Frag = Frag {
    start: HOLE,
    out: HOLE,
};

/// Parser + emitter state. Buffers grow with `realloc`; any failure
/// sets `err = REG_ESPACE` and every emitter becomes a no-op.
#[cfg(target_arch = "x86_64")]
struct Comp {
    pat: *const u8,
    pos: usize,
    plen: usize,
    ere: bool,
    icase: bool,
    newline: bool,
    at_start: bool,
    err: c_int,
    ins: *mut Ins,
    nins: u32,
    cins: u32,
    pool: *mut PNode,
    npool: u32,
    cpool: u32,
    cls: *mut u8,
    ncls: u32,
    ccls: u32,
    nsub: u32,
    closed: [bool; 10],
}

#[cfg(target_arch = "x86_64")]
unsafe fn c_emit(c: &mut Comp, op: u8, b: u8, neg: u8, x: u32, y: u32) -> u32 {
    unsafe {
        if c.err != 0 {
            return HOLE;
        }
        if c.nins == c.cins {
            let ncap = if c.cins == 0 {
                64u32
            } else {
                c.cins.wrapping_mul(2)
            };
            if ncap > 1_000_000 {
                c.err = REG_ESPACE;
                return HOLE;
            }
            let nb = realloc(
                c.ins as *mut c_void,
                (ncap as usize).wrapping_mul(size_of::<Ins>()),
            ) as *mut Ins;
            if nb.is_null() {
                c.err = REG_ESPACE;
                return HOLE;
            }
            c.ins = nb;
            c.cins = ncap;
        }
        let i = c.nins;
        c.ins.add(i as usize).write(Ins {
            op,
            b,
            neg,
            _z: 0,
            x,
            y,
        });
        c.nins = i.wrapping_add(1);
        i
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn c_list(c: &mut Comp, pos: u32, arm: u8) -> u32 {
    unsafe {
        if c.err != 0 {
            return HOLE;
        }
        if c.npool == c.cpool {
            let ncap = if c.cpool == 0 {
                64u32
            } else {
                c.cpool.wrapping_mul(2)
            };
            if ncap > 4_000_000 {
                c.err = REG_ESPACE;
                return HOLE;
            }
            let nb = realloc(
                c.pool as *mut c_void,
                (ncap as usize).wrapping_mul(size_of::<PNode>()),
            ) as *mut PNode;
            if nb.is_null() {
                c.err = REG_ESPACE;
                return HOLE;
            }
            c.pool = nb;
            c.cpool = ncap;
        }
        let i = c.npool;
        c.pool.add(i as usize).write(PNode {
            pos,
            arm,
            _p: [0; 3],
            next: HOLE,
        });
        c.npool = i.wrapping_add(1);
        i
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn c_append(c: &mut Comp, l1: u32, l2: u32) -> u32 {
    unsafe {
        if l1 == HOLE {
            return l2;
        }
        if l2 == HOLE {
            return l1;
        }
        let mut h = l1;
        loop {
            let nx = (*c.pool.add(h as usize)).next;
            if nx == HOLE {
                (*c.pool.add(h as usize)).next = l2;
                break;
            }
            h = nx;
        }
        l1
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn c_patch(c: &mut Comp, mut l: u32, target: u32) {
    unsafe {
        while l != HOLE {
            let n = c.pool.add(l as usize).read();
            l = n.next;
            let ins = c.ins.add(n.pos as usize);
            if n.arm == ARM_X {
                (*ins).x = target;
            } else {
                (*ins).y = target;
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn c_cls_push(c: &mut Comp, b: u8) {
    unsafe {
        if c.err != 0 {
            return;
        }
        if c.ncls == c.ccls {
            let ncap = if c.ccls == 0 {
                64u32
            } else {
                c.ccls.wrapping_mul(2)
            };
            if ncap > 1_000_000 {
                c.err = REG_ESPACE;
                return;
            }
            let nb = realloc(c.cls as *mut c_void, ncap as usize) as *mut u8;
            if nb.is_null() {
                c.err = REG_ESPACE;
                return;
            }
            c.cls = nb;
            c.ccls = ncap;
        }
        c.cls.add(c.ncls as usize).write(b);
        c.ncls = c.ncls.wrapping_add(1);
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn c_peek(c: &Comp, off: usize) -> u8 {
    unsafe {
        let i = c.pos.wrapping_add(off);
        if i >= c.plen {
            0
        } else {
            *c.pat.add(i)
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn c_isdigit(b: u8) -> bool {
    b.is_ascii_digit()
}

#[cfg(target_arch = "x86_64")]
unsafe fn mk_cat(c: &mut Comp, a: Frag, b: Frag) -> Frag {
    unsafe {
        if a.start == HOLE {
            return b;
        }
        if b.start == HOLE {
            return a;
        }
        c_patch(c, a.out, b.start);
        Frag {
            start: a.start,
            out: b.out,
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn mk_alt(c: &mut Comp, a: Frag, b: Frag) -> Frag {
    unsafe {
        // An empty branch matches the empty string (musl accepts
        // `()`, `(a|)`, `(|a)` as empty-matching): one-sided choice
        // is just an optional.
        if a.start == HOLE && b.start == HOLE {
            return FRAG_EMPTY;
        }
        if a.start == HOLE {
            return mk_quest(c, b);
        }
        if b.start == HOLE {
            return mk_quest(c, a);
        }
        // Textbook layout `[SPLIT, a, JMP, b]`: the split must lead
        // the branches so neither falls into the other. Both
        // branches already sit contiguously as `[a, b]`, so open the
        // two gaps with `c_insert` (targets/pool positions at or
        // past each gap move along; nothing else can reference the
        // shifted region while the alternation is open).
        c_insert(
            c,
            b.start,
            Ins {
                op: OP_JMP,
                b: 0,
                neg: 0,
                _z: 0,
                x: HOLE,
                y: 0,
            },
        );
        if c.err != 0 {
            return FRAG_EMPTY;
        }
        let j = b.start;
        let b2 = b.start.wrapping_add(1);
        c_insert(
            c,
            a.start,
            Ins {
                op: OP_SPLIT,
                b: 0,
                neg: 0,
                _z: 0,
                x: a.start.wrapping_add(1),
                y: b2.wrapping_add(1),
            },
        );
        if c.err != 0 {
            return FRAG_EMPTY;
        }
        let s = a.start;
        // `a` now starts one slot later; the join sits at `j + 1`.
        let out = c_append(c, a.out, b.out);
        let hole = c_list(c, j.wrapping_add(1), ARM_X);
        Frag {
            start: s,
            out: c_append(c, out, hole),
        }
    }
}

/// Insert one instruction at `at`, shifting `[at..nins)` right and
/// moving every jump target and patch position at or past the gap
/// along. (`SAVE`/`BREF`/`CLS`/`BYTE` operands are slots, groups,
/// pool indices and literals — never code targets — so only
/// `SPLIT`/`BOL`/`EOL`/`JMP` arms move.)
#[cfg(target_arch = "x86_64")]
/// Bump a bytecode jump slot past an insertion point (musl `c_insert`
/// inner arms): skip holes, shift targets at/after `at`.
#[cfg(target_arch = "x86_64")]
unsafe fn shift_ge(slot: *mut u32, at: u32, delta: u32) {
    unsafe {
        if *slot != HOLE && *slot >= at {
            *slot = (*slot).wrapping_add(delta);
        }
    }
}

/// Bump a slot inside `[start, end)` (second `c_insert`-style walk).
#[cfg(target_arch = "x86_64")]
unsafe fn shift_range(slot: *mut u32, start: u32, end: u32, delta: u32) {
    unsafe {
        if *slot != HOLE && *slot >= start && *slot < end {
            *slot = (*slot).wrapping_add(delta);
        }
    }
}

unsafe fn c_insert(c: &mut Comp, at: u32, ins: Ins) {
    unsafe {
        if c.err != 0 {
            return;
        }
        let end = c.nins;
        c_emit(c, 0, 0, 0, 0, 0);
        if c.err != 0 {
            return;
        }
        // Fix up real insns only (the placeholder at the end is
        // shifted over, never retargeted).
        let mut k = 0u32;
        while k < end {
            let p = c.ins.add(k as usize);
            match (*p).op {
                OP_SPLIT => {
                    shift_ge(core::ptr::addr_of_mut!((*p).x), at, 1);
                    shift_ge(core::ptr::addr_of_mut!((*p).y), at, 1);
                }
                OP_BOL | OP_EOL | OP_JMP => {
                    shift_ge(core::ptr::addr_of_mut!((*p).x), at, 1);
                }
                _ => {}
            }
            k = k.wrapping_add(1);
        }
        let mut l = 0u32;
        while l < c.npool {
            let n = c.pool.add(l as usize);
            if (*n).pos >= at {
                (*n).pos = (*n).pos.wrapping_add(1);
            }
            l = l.wrapping_add(1);
        }
        let mut k = c.nins.wrapping_sub(1);
        while k > at {
            let v = c.ins.add(k.wrapping_sub(1) as usize).read();
            c.ins.add(k as usize).write(v);
            k = k.wrapping_sub(1);
        }
        c.ins.add(at as usize).write(ins);
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn mk_star(c: &mut Comp, f: Frag) -> Frag {
    unsafe {
        if f.start == HOLE {
            return f;
        }
        let s = c_emit(c, OP_SPLIT, 0, 0, f.start, HOLE);
        c_patch(c, f.out, s);
        Frag {
            start: s,
            out: c_list(c, s, ARM_Y),
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn mk_plus(c: &mut Comp, f: Frag) -> Frag {
    unsafe {
        if f.start == HOLE {
            return f;
        }
        let s = c_emit(c, OP_SPLIT, 0, 0, f.start, HOLE);
        c_patch(c, f.out, s);
        Frag {
            start: f.start,
            out: c_list(c, s, ARM_Y),
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn mk_quest(c: &mut Comp, f: Frag) -> Frag {
    unsafe {
        if f.start == HOLE {
            return f;
        }
        // Textbook `[SPLIT, body]`: the split must lead so
        // fall-through from the preceding fragment offers the skip.
        // (A trailing split would be bypassed straight into the
        // body.)
        let s = f.start;
        c_insert(
            c,
            s,
            Ins {
                op: OP_SPLIT,
                b: 0,
                neg: 0,
                _z: 0,
                x: s.wrapping_add(1),
                y: HOLE,
            },
        );
        if c.err != 0 {
            return FRAG_EMPTY;
        }
        let hole = c_list(c, s, ARM_Y);
        Frag {
            start: s,
            out: c_append(c, hole, f.out),
        }
    }
}

/// Duplicate the insns of `f` (emitted in `[f.start, f_end)`);
/// internal jump targets move along. Used to unroll `{m,n}`.
#[cfg(target_arch = "x86_64")]
unsafe fn clone_frag(c: &mut Comp, f: Frag, f_end: u32) -> Frag {
    unsafe {
        if f.start == HOLE {
            return f;
        }
        let base = c.nins;
        let delta = base.wrapping_sub(f.start);
        let mut i = f.start;
        while i < f_end {
            let ins = c.ins.add(i as usize).read();
            c_emit(c, ins.op, ins.b, ins.neg, ins.x, ins.y);
            i = i.wrapping_add(1);
        }
        if c.err != 0 {
            return FRAG_EMPTY;
        }
        let mut k = base;
        while k < c.nins {
            let p = c.ins.add(k as usize);
            match (*p).op {
                OP_SPLIT => {
                    shift_range(core::ptr::addr_of_mut!((*p).x), f.start, f_end, delta);
                    shift_range(core::ptr::addr_of_mut!((*p).y), f.start, f_end, delta);
                }
                OP_BOL | OP_EOL | OP_JMP => {
                    shift_range(core::ptr::addr_of_mut!((*p).x), f.start, f_end, delta);
                }
                _ => {}
            }
            k = k.wrapping_add(1);
        }
        let mut nh = HOLE;
        let mut l = f.out;
        while l != HOLE {
            let n = c.pool.add(l as usize).read();
            l = n.next;
            let nn = c_list(c, n.pos.wrapping_add(delta), n.arm);
            nh = c_append(c, nh, nn);
        }
        Frag {
            start: base,
            out: nh,
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn mk_rep(c: &mut Comp, f: Frag, f_end: u32, min: u32, max: i32) -> Frag {
    unsafe {
        if min == 0 && max == 0 {
            return FRAG_EMPTY;
        }
        let mut r = f;
        let mut i = 1u32;
        while i < min {
            let g = clone_frag(c, f, f_end);
            r = mk_cat(c, r, g);
            if c.err != 0 {
                return FRAG_EMPTY;
            }
            i = i.wrapping_add(1);
        }
        if max < 0 {
            let g = clone_frag(c, f, f_end);
            let s = mk_star(c, g);
            r = mk_cat(c, r, s);
        } else {
            let mut k = min;
            while k < max as u32 {
                let g = clone_frag(c, f, f_end);
                let o = mk_quest(c, g);
                r = mk_cat(c, r, o);
                if c.err != 0 {
                    return FRAG_EMPTY;
                }
                k = k.wrapping_add(1);
            }
        }
        r
    }
}

// ---- Regex parser (musl tre-parse.c grammar) -------------------------------

/// `[:name:]` classes, ASCII edition. Returns the ranges to add, or
/// `None` for an unknown name (musl `REG_ECTYPE`).
#[cfg(target_arch = "x86_64")]
fn cls_named(name: &[u8]) -> Option<&'static [(u8, u8)]> {
    match name {
        b"alnum" => Some(&[(b'0', b'9'), (b'A', b'Z'), (b'a', b'z')]),
        b"alpha" => Some(&[(b'A', b'Z'), (b'a', b'z')]),
        b"blank" => Some(&[(b' ', b' '), (b'\t', b'\t')]),
        b"cntrl" => Some(&[(0, 31), (127, 127)]),
        b"digit" => Some(&[(b'0', b'9')]),
        b"graph" => Some(&[(33, 126)]),
        b"lower" => Some(&[(b'a', b'z')]),
        b"print" => Some(&[(32, 126)]),
        b"punct" => Some(&[(33, 47), (58, 64), (91, 96), (123, 126)]),
        b"space" => Some(&[(9, 13), (b' ', b' ')]),
        b"upper" => Some(&[(b'A', b'Z')]),
        b"xdigit" => Some(&[(b'0', b'9'), (b'A', b'F'), (b'a', b'f')]),
        _ => None,
    }
}

/// Push one range plus its ASCII opposite-case parts when `icase`
/// (musl's `add_icase_literals`, byte edition).
#[cfg(target_arch = "x86_64")]
unsafe fn cls_range(c: &mut Comp, lo: u8, hi: u8) {
    unsafe {
        c_cls_push(c, lo);
        c_cls_push(c, hi);
        if c.icase {
            let a0 = lo.max(b'A');
            let a1 = hi.min(b'Z');
            if a0 <= a1 {
                c_cls_push(c, a0.wrapping_add(32));
                c_cls_push(c, a1.wrapping_add(32));
            }
            let b0 = lo.max(b'a');
            let b1 = hi.min(b'z');
            if b0 <= b1 {
                c_cls_push(c, b0.wrapping_sub(32));
                c_cls_push(c, b1.wrapping_sub(32));
            }
        }
    }
}

/// Parse `[...]`. `c.pos` is past the `[`.
#[cfg(target_arch = "x86_64")]
unsafe fn p_class(c: &mut Comp) -> Frag {
    unsafe {
        let pair0 = c.ncls / 2;
        let mut neg = false;
        if c_peek(c, 0) == b'^' {
            neg = true;
            c.pos = c.pos.wrapping_add(1);
        }
        let mut first = true;
        loop {
            let ch = c_peek(c, 0);
            if ch == 0 {
                c.err = REG_EBRACK;
                return FRAG_EMPTY;
            }
            if ch == b']' && !first {
                c.pos = c.pos.wrapping_add(1);
                break;
            }
            // musl rejects `[a-b-c]` (REG_ERANGE) but accepts a `-`
            // next to `]` or another `-` as a literal.
            if ch == b'-' && !first {
                let n1 = c_peek(c, 1);
                if n1 != b']' && n1 != 0 && n1 != b'-' {
                    c.err = REG_ERANGE;
                    return FRAG_EMPTY;
                }
            }
            if ch == b'[' && (c_peek(c, 1) == b':' || c_peek(c, 1) == b'.' || c_peek(c, 1) == b'=')
            {
                if c_peek(c, 1) != b':' {
                    c.err = REG_ECOLLATE;
                    return FRAG_EMPTY;
                }
                let mut nl = 0usize;
                while c_peek(c, 2 + nl) != 0
                    && !(c_peek(c, 2 + nl) == b':' && c_peek(c, 3 + nl) == b']')
                {
                    nl = nl.wrapping_add(1);
                    if nl > 32 {
                        break;
                    }
                }
                if c_peek(c, 2 + nl) != b':' || c_peek(c, 3 + nl) != b']' {
                    c.err = REG_ECTYPE;
                    return FRAG_EMPTY;
                }
                let mut nm = [0u8; 32];
                let mut k = 0usize;
                while k < nl && k < 32 {
                    nm[k] = c_peek(c, 2 + k);
                    k = k.wrapping_add(1);
                }
                let rs = match cls_named(&nm[..nl.min(32)]) {
                    Some(r) => r,
                    None => {
                        c.err = REG_ECTYPE;
                        return FRAG_EMPTY;
                    }
                };
                let mut k = 0usize;
                while k < rs.len() {
                    cls_range(c, rs[k].0, rs[k].1);
                    k = k.wrapping_add(1);
                }
                c.pos = c.pos.wrapping_add(4 + nl);
                first = false;
                continue;
            }
            // Literal byte (a backslash is literal here, as in musl).
            let lo = ch;
            c.pos = c.pos.wrapping_add(1);
            first = false;
            let mut hi = lo;
            if c_peek(c, 0) == b'-' && c_peek(c, 1) != b']' && c_peek(c, 1) != 0 {
                c.pos = c.pos.wrapping_add(1);
                hi = c_peek(c, 0);
                c.pos = c.pos.wrapping_add(1);
                if hi < lo {
                    c.err = REG_ERANGE;
                    return FRAG_EMPTY;
                }
            }
            cls_range(c, lo, hi);
            if c.err != 0 {
                return FRAG_EMPTY;
            }
        }
        // POSIX via musl: with REG_NEWLINE a negated bracket also
        // excludes `\n`.
        if neg && c.newline {
            c_cls_push(c, b'\n');
            c_cls_push(c, b'\n');
        }
        let count = (c.ncls / 2).wrapping_sub(pair0);
        let s = c_emit(c, OP_CLS, 0, neg as u8, pair0, count);
        Frag {
            start: s,
            out: HOLE,
        }
    }
}

/// Parse an ERE `{m,n}` / `{m,}` / `{m}` at `c.pos` (on the `{`).
#[cfg(target_arch = "x86_64")]
unsafe fn p_interval_ere(c: &mut Comp) -> (u32, i32, bool) {
    unsafe {
        let mut i = c.pos.wrapping_add(1);
        let plen = c.plen;
        let pat = c.pat;
        let at = move |o: usize| {
            if o >= plen {
                0
            } else {
                *pat.add(o)
            }
        };
        if !c_isdigit(at(i)) {
            c.err = REG_BADBR;
            return (0, 0, false);
        }
        let mut min: u32 = 0;
        while c_isdigit(at(i)) {
            min = min
                .wrapping_mul(10)
                .wrapping_add((at(i).wrapping_sub(b'0')) as u32);
            if min > RE_DUP_MAX {
                c.err = REG_BADBR;
                return (0, 0, false);
            }
            i = i.wrapping_add(1);
        }
        let mut max = min as i32;
        if at(i) == b',' {
            i = i.wrapping_add(1);
            max = -1;
            if c_isdigit(at(i)) {
                max = 0;
                while c_isdigit(at(i)) {
                    max = max
                        .wrapping_mul(10)
                        .wrapping_add((at(i).wrapping_sub(b'0')) as i32);
                    if max > RE_DUP_MAX as i32 {
                        c.err = REG_BADBR;
                        return (0, 0, false);
                    }
                    i = i.wrapping_add(1);
                }
            }
        }
        if at(i) != b'}' || (max >= 0 && max < min as i32) {
            c.err = REG_BADBR;
            return (0, 0, false);
        }
        c.pos = i.wrapping_add(1);
        (min, max, true)
    }
}

/// Parse a BRE `\{m,n\}` at `c.pos` (on the `\`).
#[cfg(target_arch = "x86_64")]
unsafe fn p_interval_bre(c: &mut Comp) -> (u32, i32, bool) {
    unsafe {
        let mut i = c.pos.wrapping_add(2);
        let plen = c.plen;
        let pat = c.pat;
        let at = move |o: usize| {
            if o >= plen {
                0
            } else {
                *pat.add(o)
            }
        };
        if !c_isdigit(at(i)) {
            c.err = REG_BADBR;
            return (0, 0, false);
        }
        let mut min: u32 = 0;
        while c_isdigit(at(i)) {
            min = min
                .wrapping_mul(10)
                .wrapping_add((at(i).wrapping_sub(b'0')) as u32);
            if min > RE_DUP_MAX {
                c.err = REG_BADBR;
                return (0, 0, false);
            }
            i = i.wrapping_add(1);
        }
        let mut max = min as i32;
        if at(i) == b',' {
            i = i.wrapping_add(1);
            max = -1;
            if c_isdigit(at(i)) {
                max = 0;
                while c_isdigit(at(i)) {
                    max = max
                        .wrapping_mul(10)
                        .wrapping_add((at(i).wrapping_sub(b'0')) as i32);
                    if max > RE_DUP_MAX as i32 {
                        c.err = REG_BADBR;
                        return (0, 0, false);
                    }
                    i = i.wrapping_add(1);
                }
            }
        }
        if at(i) != b'\\' || at(i.wrapping_add(1)) != b'}' || (max >= 0 && max < min as i32) {
            c.err = REG_BADBR;
            return (0, 0, false);
        }
        c.pos = i.wrapping_add(2);
        (min, max, true)
    }
}

/// One atom. Returns the fragment plus whether it was a BRE `^`
/// anchor (musl treats a following `*` as a literal then).
#[cfg(target_arch = "x86_64")]
unsafe fn p_atom(c: &mut Comp) -> (Frag, bool) {
    unsafe {
        let e = c_peek(c, 0);
        if c.ere {
            match e {
                b'(' => {
                    c.pos = c.pos.wrapping_add(1);
                    c.at_start = true;
                    c.nsub = c.nsub.wrapping_add(1);
                    let g = c.nsub;
                    let s1 = c_emit(c, OP_SAVE, 0, 0, g.wrapping_mul(2), 0);
                    let inner = p_union(c);
                    if c.err != 0 {
                        return (FRAG_EMPTY, false);
                    }
                    if c_peek(c, 0) != b')' {
                        c.err = REG_EPAREN;
                        return (FRAG_EMPTY, false);
                    }
                    c.pos = c.pos.wrapping_add(1);
                    if g <= 9 {
                        c.closed[g as usize] = true;
                    }
                    let s2 = c_emit(c, OP_SAVE, 0, 0, g.wrapping_mul(2).wrapping_add(1), 0);
                    let tail = mk_cat(
                        c,
                        inner,
                        Frag {
                            start: s2,
                            out: HOLE,
                        },
                    );
                    let r = mk_cat(
                        c,
                        Frag {
                            start: s1,
                            out: HOLE,
                        },
                        tail,
                    );
                    (r, false)
                }
                b'[' => {
                    c.pos = c.pos.wrapping_add(1);
                    (p_class(c), false)
                }
                b'.' => {
                    c.pos = c.pos.wrapping_add(1);
                    let s = c_emit(c, OP_ANY, 0, 0, 0, 0);
                    (
                        Frag {
                            start: s,
                            out: HOLE,
                        },
                        false,
                    )
                }
                b'^' => {
                    c.pos = c.pos.wrapping_add(1);
                    let s = c_emit(c, OP_BOL, 0, 0, HOLE, 0);
                    (
                        Frag {
                            start: s,
                            out: c_list(c, s, ARM_X),
                        },
                        false,
                    )
                }
                b'$' => {
                    c.pos = c.pos.wrapping_add(1);
                    let s = c_emit(c, OP_EOL, 0, 0, HOLE, 0);
                    (
                        Frag {
                            start: s,
                            out: c_list(c, s, ARM_X),
                        },
                        false,
                    )
                }
                b'*' | b'+' | b'?' | b'{' => {
                    c.err = REG_BADRPT;
                    (FRAG_EMPTY, false)
                }
                b'\\' => {
                    c.pos = c.pos.wrapping_add(1);
                    let c2 = c_peek(c, 0);
                    if c2 == 0 {
                        c.err = REG_EESCAPE;
                        return (FRAG_EMPTY, false);
                    }
                    c.pos = c.pos.wrapping_add(1);
                    let s = c_emit(c, OP_BYTE, c2, 0, 0, 0);
                    (
                        Frag {
                            start: s,
                            out: HOLE,
                        },
                        false,
                    )
                }
                0 => (FRAG_EMPTY, false),
                _ => {
                    c.pos = c.pos.wrapping_add(1);
                    let s = c_emit(c, OP_BYTE, e, 0, 0, 0);
                    (
                        Frag {
                            start: s,
                            out: HOLE,
                        },
                        false,
                    )
                }
            }
        } else {
            match e {
                b'\\' => {
                    let c2 = c_peek(c, 1);
                    if c2 == 0 {
                        c.err = REG_EESCAPE;
                        return (FRAG_EMPTY, false);
                    }
                    if c2 == b'(' {
                        c.pos = c.pos.wrapping_add(2);
                        c.at_start = true;
                        c.nsub = c.nsub.wrapping_add(1);
                        let g = c.nsub;
                        let s1 = c_emit(c, OP_SAVE, 0, 0, g.wrapping_mul(2), 0);
                        let inner = p_union(c);
                        if c.err != 0 {
                            return (FRAG_EMPTY, false);
                        }
                        if c_peek(c, 0) != b'\\' || c_peek(c, 1) != b')' {
                            c.err = REG_EPAREN;
                            return (FRAG_EMPTY, false);
                        }
                        c.pos = c.pos.wrapping_add(2);
                        if g <= 9 {
                            c.closed[g as usize] = true;
                        }
                        let s2 = c_emit(c, OP_SAVE, 0, 0, g.wrapping_mul(2).wrapping_add(1), 0);
                        let tail = mk_cat(
                            c,
                            inner,
                            Frag {
                                start: s2,
                                out: HOLE,
                            },
                        );
                        let r = mk_cat(
                            c,
                            Frag {
                                start: s1,
                                out: HOLE,
                            },
                            tail,
                        );
                        (r, false)
                    } else if (b'1'..=b'9').contains(&c2) {
                        let v = (c2.wrapping_sub(b'0')) as usize;
                        if v as u32 > c.nsub || !c.closed[v] {
                            c.err = REG_ESUBREG;
                            return (FRAG_EMPTY, false);
                        }
                        c.pos = c.pos.wrapping_add(2);
                        let s = c_emit(c, OP_BREF, 0, 0, v as u32, 0);
                        (
                            Frag {
                                start: s,
                                out: HOLE,
                            },
                            false,
                        )
                    } else if c2 == b'+' || c2 == b'?' || c2 == b'{' {
                        // musl: repetition with no preceding atom.
                        c.err = REG_BADRPT;
                        (FRAG_EMPTY, false)
                    } else {
                        c.pos = c.pos.wrapping_add(2);
                        let s = c_emit(c, OP_BYTE, c2, 0, 0, 0);
                        (
                            Frag {
                                start: s,
                                out: HOLE,
                            },
                            false,
                        )
                    }
                }
                b'[' => {
                    c.pos = c.pos.wrapping_add(1);
                    (p_class(c), false)
                }
                b'.' => {
                    c.pos = c.pos.wrapping_add(1);
                    let s = c_emit(c, OP_ANY, 0, 0, 0, 0);
                    (
                        Frag {
                            start: s,
                            out: HOLE,
                        },
                        false,
                    )
                }
                b'^' if c.at_start => {
                    c.pos = c.pos.wrapping_add(1);
                    let s = c_emit(c, OP_BOL, 0, 0, HOLE, 0);
                    (
                        Frag {
                            start: s,
                            out: c_list(c, s, ARM_X),
                        },
                        true,
                    )
                }
                b'$' => {
                    let n1 = c_peek(c, 1);
                    let n2 = c_peek(c, 2);
                    if n1 == 0 || (n1 == b'\\' && (n2 == b')' || n2 == b'|')) {
                        c.pos = c.pos.wrapping_add(1);
                        let s = c_emit(c, OP_EOL, 0, 0, HOLE, 0);
                        (
                            Frag {
                                start: s,
                                out: c_list(c, s, ARM_X),
                            },
                            false,
                        )
                    } else {
                        c.pos = c.pos.wrapping_add(1);
                        let s = c_emit(c, OP_BYTE, e, 0, 0, 0);
                        (
                            Frag {
                                start: s,
                                out: HOLE,
                            },
                            false,
                        )
                    }
                }
                0 => (FRAG_EMPTY, false),
                _ => {
                    // BRE: `*` `+` `?` `{` `|` and mid-pattern `^`
                    // are literals here.
                    c.pos = c.pos.wrapping_add(1);
                    let s = c_emit(c, OP_BYTE, e, 0, 0, 0);
                    (
                        Frag {
                            start: s,
                            out: HOLE,
                        },
                        false,
                    )
                }
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn p_piece(c: &mut Comp) -> Frag {
    unsafe {
        let (mut f, caret) = p_atom(c);
        if c.err != 0 {
            return FRAG_EMPTY;
        }
        loop {
            if c.ere {
                match c_peek(c, 0) {
                    b'*' => {
                        c.pos = c.pos.wrapping_add(1);
                        f = mk_star(c, f);
                    }
                    b'+' => {
                        c.pos = c.pos.wrapping_add(1);
                        f = mk_plus(c, f);
                    }
                    b'?' => {
                        c.pos = c.pos.wrapping_add(1);
                        f = mk_quest(c, f);
                    }
                    b'{' => {
                        let f_end = c.nins;
                        let (min, max, ok) = p_interval_ere(c);
                        if !ok {
                            return FRAG_EMPTY;
                        }
                        f = mk_rep(c, f, f_end, min, max);
                    }
                    _ => break,
                }
            } else if c_peek(c, 0) == b'*' {
                // musl: `^*` at the start of a BRE keeps a
                // literal `*`.
                if caret {
                    break;
                }
                c.pos = c.pos.wrapping_add(1);
                f = mk_star(c, f);
            } else if c_peek(c, 0) == b'\\' && (c_peek(c, 1) == b'+' || c_peek(c, 1) == b'?') {
                let plus = c_peek(c, 1) == b'+';
                c.pos = c.pos.wrapping_add(2);
                f = if plus { mk_plus(c, f) } else { mk_quest(c, f) };
            } else if c_peek(c, 0) == b'\\' && c_peek(c, 1) == b'{' {
                let f_end = c.nins;
                let (min, max, ok) = p_interval_bre(c);
                if !ok {
                    return FRAG_EMPTY;
                }
                f = mk_rep(c, f, f_end, min, max);
            } else {
                break;
            }
            if c.err != 0 {
                return FRAG_EMPTY;
            }
        }
        c.at_start = false;
        f
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn p_concat(c: &mut Comp) -> Frag {
    unsafe {
        let mut f = FRAG_EMPTY;
        loop {
            if c.err != 0 {
                return FRAG_EMPTY;
            }
            let a = c_peek(c, 0);
            let term = if c.ere {
                a == 0 || a == b'|' || a == b')'
            } else {
                a == 0 || (a == b'\\' && (c_peek(c, 1) == b')' || c_peek(c, 1) == b'|'))
            };
            if term {
                break;
            }
            let g = p_piece(c);
            f = mk_cat(c, f, g);
        }
        f
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn p_union(c: &mut Comp) -> Frag {
    unsafe {
        let mut f = p_concat(c);
        loop {
            if c.err != 0 {
                return FRAG_EMPTY;
            }
            let is_alt = if c.ere {
                c_peek(c, 0) == b'|'
            } else {
                c_peek(c, 0) == b'\\' && c_peek(c, 1) == b'|'
            };
            if !is_alt {
                break;
            }
            c.pos = c.pos.wrapping_add(if c.ere { 1 } else { 2 });
            c.at_start = false;
            let g = p_concat(c);
            f = mk_alt(c, f, g);
        }
        f
    }
}

// ---- Regex VM (backtracking over the bytecode) ------------------------------

#[cfg(target_arch = "x86_64")]
const SAVE_NONE: usize = usize::MAX;
/// Fuel cap: catastrophic backtracking degrades to `REG_NOMATCH`.
#[cfg(target_arch = "x86_64")]
const VM_FUEL: usize = 1 << 22;

/// Try to match at `pos`; `Some(end)` on success. `saves` holds
/// `2*(nsub+1)` group-boundary offsets (`SAVE_NONE` = unset).
#[cfg(target_arch = "x86_64")]
#[allow(clippy::too_many_arguments)]
unsafe fn vm_run(
    ins: *const Ins,
    cls: *const u8,
    input: *const u8,
    len: usize,
    icase: bool,
    newline: bool,
    notbol: bool,
    noteol: bool,
    saves: *mut usize,
    fuel: &mut usize,
    pc: u32,
    pos: usize,
) -> Option<usize> {
    unsafe {
        *fuel = fuel.wrapping_sub(1);
        if *fuel == 0 {
            return None;
        }
        let cur = ins.add(pc as usize).read();
        match cur.op {
            OP_BYTE => {
                if pos < len && byte_eq(input.add(pos).read(), cur.b, icase) {
                    return vm_run(
                        ins,
                        cls,
                        input,
                        len,
                        icase,
                        newline,
                        notbol,
                        noteol,
                        saves,
                        fuel,
                        pc.wrapping_add(1),
                        pos.wrapping_add(1),
                    );
                }
                None
            }
            OP_ANY => {
                if pos < len && (!newline || input.add(pos).read() != b'\n') {
                    return vm_run(
                        ins,
                        cls,
                        input,
                        len,
                        icase,
                        newline,
                        notbol,
                        noteol,
                        saves,
                        fuel,
                        pc.wrapping_add(1),
                        pos.wrapping_add(1),
                    );
                }
                None
            }
            OP_CLS => {
                if pos < len {
                    let b = input.add(pos).read();
                    let mut hit = false;
                    let mut k = 0u32;
                    while k < cur.y {
                        let lo = cls
                            .add((cur.x.wrapping_add(k) as usize).wrapping_mul(2))
                            .read();
                        let hi = cls
                            .add(
                                (cur.x.wrapping_add(k) as usize)
                                    .wrapping_mul(2)
                                    .wrapping_add(1),
                            )
                            .read();
                        if (b >= lo && b <= hi) || (fold_byte(b) >= lo && fold_byte(b) <= hi) {
                            hit = true;
                            break;
                        }
                        k = k.wrapping_add(1);
                    }
                    if cur.neg != 0 {
                        hit = !hit;
                    }
                    if hit {
                        return vm_run(
                            ins,
                            cls,
                            input,
                            len,
                            icase,
                            newline,
                            notbol,
                            noteol,
                            saves,
                            fuel,
                            pc.wrapping_add(1),
                            pos.wrapping_add(1),
                        );
                    }
                }
                None
            }
            OP_BOL => {
                let at = (pos == 0 && !notbol)
                    || (newline && pos > 0 && input.add(pos.wrapping_sub(1)).read() == b'\n');
                if at {
                    return vm_run(
                        ins, cls, input, len, icase, newline, notbol, noteol, saves, fuel, cur.x,
                        pos,
                    );
                }
                None
            }
            OP_EOL => {
                let at = (pos == len && !noteol)
                    || (newline && pos < len && input.add(pos).read() == b'\n');
                if at {
                    return vm_run(
                        ins, cls, input, len, icase, newline, notbol, noteol, saves, fuel, cur.x,
                        pos,
                    );
                }
                None
            }
            OP_SPLIT => {
                if let Some(e) = vm_run(
                    ins, cls, input, len, icase, newline, notbol, noteol, saves, fuel, cur.x, pos,
                ) {
                    Some(e)
                } else {
                    vm_run(
                        ins, cls, input, len, icase, newline, notbol, noteol, saves, fuel, cur.y,
                        pos,
                    )
                }
            }
            OP_JMP => vm_run(
                ins, cls, input, len, icase, newline, notbol, noteol, saves, fuel, cur.x, pos,
            ),
            OP_SAVE => {
                let s = cur.x as usize;
                let old = saves.add(s).read();
                saves.add(s).write(pos);
                let r = vm_run(
                    ins,
                    cls,
                    input,
                    len,
                    icase,
                    newline,
                    notbol,
                    noteol,
                    saves,
                    fuel,
                    pc.wrapping_add(1),
                    pos,
                );
                if r.is_none() {
                    saves.add(s).write(old);
                }
                r
            }
            OP_BREF => {
                let g = (cur.x as usize).wrapping_mul(2);
                let s0 = saves.add(g).read();
                let s1 = saves.add(g.wrapping_add(1)).read();
                if s0 == SAVE_NONE || s1 == SAVE_NONE || s1 < s0 {
                    return None;
                }
                let blen = s1.wrapping_sub(s0);
                let end = pos.wrapping_add(blen);
                if end > len {
                    return None;
                }
                let mut k = 0usize;
                while k < blen {
                    if input.add(pos.wrapping_add(k)).read() != input.add(s0.wrapping_add(k)).read()
                    {
                        return None;
                    }
                    k = k.wrapping_add(1);
                }
                vm_run(
                    ins,
                    cls,
                    input,
                    len,
                    icase,
                    newline,
                    notbol,
                    noteol,
                    saves,
                    fuel,
                    pc.wrapping_add(1),
                    end,
                )
            }
            OP_MATCH => Some(pos),
            _ => None,
        }
    }
}

// ---- regcomp / regexec / regerror / regfree ---------------------------------

/// Compile `pattern` (musl `regcomp`: BRE by default, ERE with
/// `REG_EXTENDED`).
///
/// # Safety
///
/// `preg` must point to writable `regex_t` storage and `pattern` to a
/// NUL-terminated string.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn regcomp(
    preg: *mut regex_t,
    pattern: *const c_char,
    cflags: c_int,
) -> c_int {
    unsafe {
        if preg.is_null() || pattern.is_null() {
            return REG_BADPAT;
        }
        (*preg).__opaque = null_mut();
        let mut c = Comp {
            pat: pattern as *const u8,
            pos: 0,
            plen: strlen(pattern),
            ere: (cflags & REG_EXTENDED) != 0,
            icase: (cflags & REG_ICASE) != 0,
            newline: (cflags & REG_NEWLINE) != 0,
            at_start: true,
            err: 0,
            ins: null_mut(),
            nins: 0,
            cins: 0,
            pool: null_mut(),
            npool: 0,
            cpool: 0,
            cls: null_mut(),
            ncls: 0,
            ccls: 0,
            nsub: 0,
            closed: [false; 10],
        };
        let f = p_union(&mut c);
        if c.err == 0 && c.pos != c.plen {
            c.err = REG_EPAREN;
        }
        if c.err != 0 {
            let e = c.err;
            if !c.ins.is_null() {
                free(c.ins as *mut c_void);
            }
            if !c.pool.is_null() {
                free(c.pool as *mut c_void);
            }
            if !c.cls.is_null() {
                free(c.cls as *mut c_void);
            }
            return e;
        }
        let m = c_emit(&mut c, OP_MATCH, 0, 0, 0, 0);
        c_patch(&mut c, f.out, m);
        let start = if f.start == HOLE { m } else { f.start };
        if !c.pool.is_null() {
            free(c.pool as *mut c_void);
        }
        if c.err != 0 || c.ins.is_null() {
            if !c.ins.is_null() {
                free(c.ins as *mut c_void);
            }
            if !c.cls.is_null() {
                free(c.cls as *mut c_void);
            }
            (*preg).__opaque = null_mut();
            return REG_ESPACE;
        }
        let p = malloc(size_of::<Prog>()) as *mut Prog;
        if p.is_null() {
            free(c.ins as *mut c_void);
            free(c.cls as *mut c_void);
            e_set(ENOMEM);
            return REG_ESPACE;
        }
        (*p).nsub = c.nsub;
        (*p).cflags = cflags;
        (*p).nins = c.nins;
        (*p).start = start;
        (*p).ins = c.ins;
        (*p).cls = c.cls;
        (*p).ncls = c.ncls;
        (*preg).re_nsub = c.nsub as usize;
        (*preg).__opaque = p as *mut c_void;
        (*preg).__padding = [null_mut(); 4];
        (*preg).__nsub2 = c.nsub as usize;
        (*preg).__padding2 = 0;
        REG_OK
    }
}

/// Match a compiled pattern anywhere in `string` (musl `regexec`:
/// leftmost search, `rm_so`/`rm_eo` byte offsets, `-1` when unset).
///
/// # Safety
///
/// `preg` must point to a successfully compiled `regex_t`; `string`
/// to a NUL-terminated string; `pmatch` to `nmatch` writable
/// `regmatch_t`s unless `nmatch` is 0 or `REG_NOSUB` was given.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn regexec(
    preg: *const regex_t,
    string: *const c_char,
    nmatch: usize,
    pmatch: *mut regmatch_t,
    eflags: c_int,
) -> c_int {
    unsafe {
        if preg.is_null() || string.is_null() {
            return REG_BADPAT;
        }
        let p = (*preg).__opaque as *const Prog;
        if p.is_null() {
            return REG_BADPAT;
        }
        let nsub = (*p).nsub as usize;
        let len = strlen(string);
        let nslots = nsub.wrapping_add(1).wrapping_mul(2);
        let saves = malloc(nslots.wrapping_mul(size_of::<usize>())) as *mut usize;
        if saves.is_null() {
            e_set(ENOMEM);
            return REG_ESPACE;
        }
        let icase = ((*p).cflags & REG_ICASE) != 0;
        let newline = ((*p).cflags & REG_NEWLINE) != 0;
        let notbol = (eflags & REG_NOTBOL) != 0;
        let noteol = (eflags & REG_NOTEOL) != 0;
        let mut fuel = VM_FUEL;
        let mut st = 0usize;
        let found = loop {
            let mut k = 0usize;
            while k < nslots {
                saves.add(k).write(SAVE_NONE);
                k = k.wrapping_add(1);
            }
            if let Some(end) = vm_run(
                (*p).ins,
                (*p).cls,
                string as *const u8,
                len,
                icase,
                newline,
                notbol,
                noteol,
                saves,
                &mut fuel,
                (*p).start,
                st,
            ) {
                break Some((st, end));
            }
            if st == len {
                break None;
            }
            st = st.wrapping_add(1);
        };
        free(saves as *mut c_void);
        match found {
            None => REG_NOMATCH,
            Some((so, eo)) => {
                if ((*p).cflags & REG_NOSUB) == 0 && nmatch > 0 && !pmatch.is_null() {
                    // Re-run saves are gone (freed); re-derive group
                    // offsets with a fresh pass. Cheap and simple:
                    // re-match from `so` to recover them.
                    let s2 = malloc(nslots.wrapping_mul(size_of::<usize>())) as *mut usize;
                    if !s2.is_null() {
                        let mut k = 0usize;
                        while k < nslots {
                            s2.add(k).write(SAVE_NONE);
                            k = k.wrapping_add(1);
                        }
                        let mut f2 = VM_FUEL;
                        let ok = vm_run(
                            (*p).ins,
                            (*p).cls,
                            string as *const u8,
                            len,
                            icase,
                            newline,
                            notbol,
                            noteol,
                            s2,
                            &mut f2,
                            (*p).start,
                            so,
                        );
                        let ng = nmatch.min(nsub.wrapping_add(1));
                        if ok.is_some() {
                            (*pmatch.add(0)).rm_so = so as regoff_t;
                            (*pmatch.add(0)).rm_eo = eo as regoff_t;
                            let mut g = 1usize;
                            while g < ng {
                                let a = s2.add(g.wrapping_mul(2)).read();
                                let b = s2.add(g.wrapping_mul(2).wrapping_add(1)).read();
                                if a == SAVE_NONE || b == SAVE_NONE {
                                    (*pmatch.add(g)).rm_so = -1;
                                    (*pmatch.add(g)).rm_eo = -1;
                                } else {
                                    (*pmatch.add(g)).rm_so = a as regoff_t;
                                    (*pmatch.add(g)).rm_eo = b as regoff_t;
                                }
                                g = g.wrapping_add(1);
                            }
                        }
                        let mut g = ng;
                        while g < nmatch {
                            (*pmatch.add(g)).rm_so = -1;
                            (*pmatch.add(g)).rm_eo = -1;
                            g = g.wrapping_add(1);
                        }
                        free(s2 as *mut c_void);
                    }
                }
                REG_OK
            }
        }
    }
}

/// Error strings, musl `regerror.c` verbatim (`preg` is ignored, as
/// in musl; returns the full length + 1 regardless of truncation).
///
/// # Safety
///
/// `errbuf` must be writable for `errbuf_size` bytes when
/// `errbuf_size > 0`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn regerror(
    errcode: c_int,
    _preg: *const regex_t,
    errbuf: *mut c_char,
    errbuf_size: usize,
) -> usize {
    unsafe {
        const MSGS: [&[u8]; 14] = [
            b"No error",
            b"No match",
            b"Invalid regexp",
            b"Unknown collating element",
            b"Unknown character class name",
            b"Trailing backslash",
            b"Invalid back reference",
            b"Missing ']'",
            b"Missing ')'",
            b"Missing '}'",
            b"Invalid contents of {}",
            b"Invalid character range",
            b"Out of memory",
            b"Repetition not preceded by valid expression",
        ];
        let msg: &[u8] = if errcode >= 0 && (errcode as usize) < MSGS.len() {
            MSGS[errcode as usize]
        } else {
            b"Unknown error"
        };
        if errbuf_size > 0 && !errbuf.is_null() {
            let n = (errbuf_size.wrapping_sub(1)).min(msg.len());
            let mut k = 0usize;
            while k < n {
                errbuf.add(k).write(msg[k] as c_char);
                k = k.wrapping_add(1);
            }
            errbuf.add(n).write(0);
        }
        msg.len().wrapping_add(1)
    }
}

/// Release a compiled pattern (musl `regexec.c:regfree` shape:
/// freeing twice is safe — the second is a no-op).
///
/// # Safety
///
/// `preg` must point to a `regex_t` from [`regcomp`] (or a
/// zero-filled one).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn regfree(preg: *mut regex_t) {
    unsafe {
        if preg.is_null() {
            return;
        }
        let p = (*preg).__opaque as *mut Prog;
        if !p.is_null() {
            if !(*p).ins.is_null() {
                free((*p).ins as *mut c_void);
            }
            if !(*p).cls.is_null() {
                free((*p).cls as *mut c_void);
            }
            free(p as *mut c_void);
        }
        (*preg).__opaque = null_mut();
        (*preg).__padding = [null_mut(); 4];
        (*preg).re_nsub = 0;
        (*preg).__nsub2 = 0;
        (*preg).__padding2 = 0;
    }
}

// ---- fnmatch (musl src/regex/fnmatch.c shape, bytes not wchar) --------------

/// Match one `[...]` class at `p` (length `plen`) against byte `b`.
/// Returns the pattern bytes consumed, or 0 when unterminated (musl
/// treats a lone `[` as a literal).
#[cfg(target_arch = "x86_64")]
unsafe fn fm_bracket(p: *const u8, plen: usize, b: u8, bfold: u8) -> (usize, bool) {
    unsafe {
        let at = |o: usize| {
            if o < plen {
                *p.add(o)
            } else {
                0
            }
        };
        if at(0) != b'[' {
            return (0, false);
        }
        // Find the closing `]`, honouring `]`/`-` in first position
        // and skipping `[:...:]` `[....]` `[=...=]` spans.
        let mut k = 1usize;
        if k < plen && (at(k) == b'!' || at(k) == b'^') {
            k = k.wrapping_add(1);
        }
        if k < plen && (at(k) == b']' || at(k) == b'-') {
            k = k.wrapping_add(1);
        }
        while k < plen && at(k) != b']' {
            if at(k) == b'['
                && k.wrapping_add(1) < plen
                && (at(k.wrapping_add(1)) == b':'
                    || at(k.wrapping_add(1)) == b'.'
                    || at(k.wrapping_add(1)) == b'=')
            {
                let z = at(k.wrapping_add(1));
                k = k.wrapping_add(2);
                if k < plen {
                    k = k.wrapping_add(1);
                }
                while k < plen && !(at(k.wrapping_sub(1)) == z && at(k) == b']') {
                    k = k.wrapping_add(1);
                }
                if k >= plen {
                    break;
                }
            }
            k = k.wrapping_add(1);
        }
        if k >= plen || at(k) != b']' {
            return (0, false);
        }
        let end = k;
        // Evaluate.
        let mut j = 1usize;
        let mut inv = false;
        if at(j) == b'!' || at(j) == b'^' {
            inv = true;
            j = j.wrapping_add(1);
        }
        let mut prev: Option<u8> = None;
        // A `]`/`-` first is a literal member.
        if j < end && (at(j) == b']' || at(j) == b'-') {
            if at(j) == b || at(j) == bfold {
                return (end.wrapping_add(1), !inv);
            }
            prev = Some(at(j));
            j = j.wrapping_add(1);
        }
        while j < end {
            if at(j) == b'['
                && j.wrapping_add(1) < end
                && (at(j.wrapping_add(1)) == b':'
                    || at(j.wrapping_add(1)) == b'.'
                    || at(j.wrapping_add(1)) == b'=')
            {
                let z = at(j.wrapping_add(1));
                let n0 = j.wrapping_add(2);
                let mut q = j.wrapping_add(3);
                while q < end && !(at(q.wrapping_sub(1)) == z && at(q) == b']') {
                    q = q.wrapping_add(1);
                }
                if z == b':' && q.wrapping_sub(n0).wrapping_sub(1) < 16 {
                    let mut nm = [0u8; 16];
                    let mut t = 0usize;
                    while n0.wrapping_add(t) < q.wrapping_sub(1) && t < 16 {
                        nm[t] = at(n0.wrapping_add(t));
                        t = t.wrapping_add(1);
                    }
                    let hit = match cls_named(&nm[..t]) {
                        Some(rs) => {
                            let mut h = false;
                            let mut r = 0usize;
                            while r < rs.len() {
                                if (b >= rs[r].0 && b <= rs[r].1)
                                    || (bfold >= rs[r].0 && bfold <= rs[r].1)
                                {
                                    h = true;
                                    break;
                                }
                                r = r.wrapping_add(1);
                            }
                            h
                        }
                        None => false,
                    };
                    if hit {
                        return (end.wrapping_add(1), !inv);
                    }
                }
                j = q.wrapping_add(1);
                prev = None;
                continue;
            }
            if at(j) == b'-' && prev.is_some() && j.wrapping_add(1) < end {
                let lo = prev.unwrap_or(0);
                let hi = at(j.wrapping_add(1));
                if lo <= hi
                    && ((b.wrapping_sub(lo)) <= hi.wrapping_sub(lo)
                        || (bfold.wrapping_sub(lo)) <= hi.wrapping_sub(lo))
                {
                    return (end.wrapping_add(1), !inv);
                }
                prev = None;
                j = j.wrapping_add(2);
                continue;
            }
            let ch = at(j);
            if ch == b || ch == bfold {
                // A trailing `-x` is a range, handled above on the
                // next pass; a lone repeat still matches here unless
                // it starts a range.
                if !(j.wrapping_add(2) < end
                    && at(j.wrapping_add(1)) == b'-'
                    && at(j.wrapping_add(2)) != b']')
                {
                    return (end.wrapping_add(1), !inv);
                }
            }
            prev = Some(ch);
            j = j.wrapping_add(1);
        }
        (end.wrapping_add(1), inv)
    }
}

/// One path segment (no `/` handling): musl `fnmatch_internal`,
/// byte edition, recursive.
#[cfg(target_arch = "x86_64")]
unsafe fn fm_seg(
    p: *const u8,
    plen: usize,
    s: *const u8,
    slen: usize,
    flags: c_int,
    seg_start: bool,
) -> bool {
    unsafe {
        let at = |o: usize| {
            if o < plen {
                *p.add(o)
            } else {
                0
            }
        };
        let sat = |o: usize| {
            if o < slen {
                *s.add(o)
            } else {
                0
            }
        };
        if plen == 0 {
            if (flags & FNM_LEADING_DIR) != 0 && slen > 0 && sat(0) == b'/' {
                return true;
            }
            return slen == 0;
        }
        // musl's FNM_PERIOD rule: a leading `.` must be matched by a
        // literal `.` (or an escaped one).
        if seg_start && (flags & FNM_PERIOD) != 0 && slen > 0 && sat(0) == b'.' {
            let p0 = at(0);
            if p0 != b'.'
                && !(p0 == b'\\' && (flags & FNM_NOESCAPE) == 0 && plen > 1 && at(1) == b'.')
            {
                return false;
            }
        }
        let p0 = at(0);
        if p0 == b'*' {
            let mut q = 1usize;
            while q < plen && at(q) == b'*' {
                q = q.wrapping_add(1);
            }
            if q == plen {
                // Trailing stars: without PATHNAME everything
                // matches; with it, `/` must not be crossed (but a
                // LEADING_DIR tail is always satisfiable past the
                // already-matched prefix).
                if (flags & FNM_PATHNAME) == 0 {
                    return true;
                }
                if (flags & FNM_LEADING_DIR) != 0 {
                    return true;
                }
                let mut k = 0usize;
                while k < slen {
                    if sat(k) == b'/' {
                        return false;
                    }
                    k = k.wrapping_add(1);
                }
                return true;
            }
            let mut k = 0usize;
            loop {
                if fm_seg(
                    p.add(q),
                    plen.wrapping_sub(q),
                    s.add(k),
                    slen.wrapping_sub(k),
                    flags,
                    seg_start && k == 0,
                ) {
                    return true;
                }
                if k == slen {
                    break;
                }
                if (flags & FNM_PATHNAME) != 0 && sat(k) == b'/' {
                    break;
                }
                k = k.wrapping_add(1);
            }
            return false;
        }
        if slen == 0 {
            return false;
        }
        let s0 = sat(0);
        if p0 == b'?' {
            if (flags & FNM_PATHNAME) != 0 && s0 == b'/' {
                return false;
            }
            return fm_seg(
                p.add(1),
                plen.wrapping_sub(1),
                s.add(1),
                slen.wrapping_sub(1),
                flags,
                false,
            );
        }
        if p0 == b'[' {
            let bfold = if (flags & FNM_CASEFOLD) != 0 {
                fold_byte(s0)
            } else {
                s0
            };
            let (used, hit) = fm_bracket(p, plen, s0, bfold);
            if used == 0 {
                // Unterminated: literal `[` (musl `pat_next`).
                if !byte_eq(s0, b'[', (flags & FNM_CASEFOLD) != 0) {
                    return false;
                }
                return fm_seg(
                    p.add(1),
                    plen.wrapping_sub(1),
                    s.add(1),
                    slen.wrapping_sub(1),
                    flags,
                    false,
                );
            }
            if !hit {
                return false;
            }
            if (flags & FNM_PATHNAME) != 0 && s0 == b'/' {
                return false;
            }
            return fm_seg(
                p.add(used),
                plen.wrapping_sub(used),
                s.add(1),
                slen.wrapping_sub(1),
                flags,
                false,
            );
        }
        if p0 == b'\\' && (flags & FNM_NOESCAPE) == 0 && plen > 1 {
            let lit = at(1);
            if !byte_eq(s0, lit, (flags & FNM_CASEFOLD) != 0) {
                return false;
            }
            return fm_seg(
                p.add(2),
                plen.wrapping_sub(2),
                s.add(1),
                slen.wrapping_sub(1),
                flags,
                false,
            );
        }
        if !byte_eq(s0, p0, (flags & FNM_CASEFOLD) != 0) {
            return false;
        }
        fm_seg(
            p.add(1),
            plen.wrapping_sub(1),
            s.add(1),
            slen.wrapping_sub(1),
            flags,
            p0 == b'/' && (flags & FNM_PATHNAME) != 0,
        )
    }
}

/// Filename matching (musl `fnmatch.c`: `FNM_PATHNAME` splits on
/// `/`, `FNM_PERIOD` pins leading dots, `FNM_LEADING_DIR` allows a
/// `/...` tail).
///
/// # Safety
///
/// `pattern` and `string` must point to NUL-terminated strings.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fnmatch(
    pattern: *const c_char,
    string: *const c_char,
    flags: c_int,
) -> c_int {
    unsafe {
        if pattern.is_null() || string.is_null() {
            return FNM_NOMATCH;
        }
        let p = pattern as *const u8;
        let s = string as *const u8;
        let plen = strlen(pattern);
        let slen = strlen(string);
        if (flags & FNM_PATHNAME) != 0 {
            if fm_seg(p, plen, s, slen, flags, true) {
                0
            } else {
                FNM_NOMATCH
            }
        } else if (flags & FNM_LEADING_DIR) != 0 {
            // musl: try every `/`-terminated prefix, then the whole.
            let mut i = 0usize;
            while i < slen {
                if *s.add(i) == b'/' && fm_seg(p, plen, s, i, flags, true) {
                    return 0;
                }
                i = i.wrapping_add(1);
            }
            if fm_seg(p, plen, s, slen, flags, true) {
                0
            } else {
                FNM_NOMATCH
            }
        } else if fm_seg(p, plen, s, slen, flags, true) {
            0
        } else {
            FNM_NOMATCH
        }
    }
}

// ---- glob (musl src/regex/glob.c, line-for-line shape) ----------------------

/// One result node; the name bytes follow the header in the same
/// allocation (musl `struct match`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct GMatch {
    next: *mut GMatch,
}

#[cfg(target_arch = "x86_64")]
const GMATCH_OFF: usize = 8;

#[cfg(target_arch = "x86_64")]
unsafe fn g_name(m: *mut GMatch) -> *mut c_char {
    unsafe { (m as *mut u8).add(GMATCH_OFF) as *mut c_char }
}

#[cfg(target_arch = "x86_64")]
static GDOT: [c_char; 2] = [b'.' as c_char, 0];
#[cfg(target_arch = "x86_64")]
static GEMPTY: [c_char; 1] = [0];
#[cfg(target_arch = "x86_64")]
static GHOME: [c_char; 5] = [
    b'H' as c_char,
    b'O' as c_char,
    b'M' as c_char,
    b'E' as c_char,
    0,
];

#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn g_ignore(_path: *const c_char, _err: c_int) -> c_int {
    0
}

#[cfg(target_arch = "x86_64")]
unsafe extern "C" fn g_sort(a: *const c_void, b: *const c_void) -> c_int {
    unsafe { crate::string::strcmp(*(a as *const *const c_char), *(b as *const *const c_char)) }
}

#[cfg(target_arch = "x86_64")]
unsafe fn g_err(
    f: Option<unsafe extern "C" fn(*const c_char, c_int) -> c_int>,
    path: *const c_char,
    e: c_int,
) -> c_int {
    unsafe {
        match f {
            Some(g) => g(path, e),
            None => 0,
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn g_append(tail: *mut *mut GMatch, name: *const c_char, len: usize, mark: bool) -> c_int {
    unsafe {
        let m = malloc(GMATCH_OFF.wrapping_add(len).wrapping_add(2)) as *mut GMatch;
        if m.is_null() {
            e_set(ENOMEM);
            return -1;
        }
        (*m).next = null_mut();
        let np = g_name(m);
        memcpy(
            np as *mut c_void,
            name as *const c_void,
            len.wrapping_add(1),
        );
        if mark && len > 0 && *name.add(len.wrapping_sub(1)) != b'/' as c_char {
            *np.add(len) = b'/' as c_char;
            *np.add(len.wrapping_add(1)) = 0;
        }
        (**tail).next = m;
        *tail = m;
        0
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn g_freelist(head: *mut GMatch) {
    unsafe {
        let mut m = (*head).next;
        while !m.is_null() {
            let nx = (*m).next;
            free(m as *mut c_void);
            m = nx;
        }
        (*head).next = null_mut();
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(clippy::too_many_arguments)]
unsafe fn g_do(
    buf: *mut c_char,
    pos: usize,
    mut typ: c_int,
    pat: *mut c_char,
    flags: c_int,
    errfunc: Option<unsafe extern "C" fn(*const c_char, c_int) -> c_int>,
    tail: *mut *mut GMatch,
) -> c_int {
    unsafe {
        use crate::dirent::{DT_DIR, DT_LNK, DT_REG};
        let dtdir = DT_DIR as c_int;
        let dtlnk = DT_LNK as c_int;
        let dtreg = DT_REG as c_int;
        if typ == 0 && (flags & GLOB_MARK) == 0 {
            typ = dtreg;
        }
        let mut pp = pat;
        let mut ppos = pos;
        if *pp != 0 && typ != dtdir {
            typ = 0;
        }
        while ppos.wrapping_add(1) < PATH_MAX && *pp == b'/' as c_char {
            *buf.add(ppos) = *pp;
            ppos = ppos.wrapping_add(1);
            pp = pp.add(1);
        }
        // Consume the maximal literal prefix, un-escaping into `buf`.
        let mut i: isize = 0;
        let mut j: isize = 0;
        let mut in_bracket = false;
        let mut overflow = false;
        loop {
            let ch = *pp.offset(i);
            if ch == b'*' as c_char || ch == b'?' as c_char || (in_bracket && ch == b']' as c_char)
            {
                break;
            }
            if ch == 0 {
                if overflow {
                    return 0;
                }
                pp = pp.offset(i);
                ppos = ppos.wrapping_add(j as usize);
                break;
            } else if ch == b'[' as c_char {
                in_bracket = true;
            } else if ch == b'\\' as c_char && (flags & GLOB_NOESCAPE) == 0 {
                if in_bracket && *pp.offset(i.wrapping_add(1)) == b']' as c_char {
                    break;
                }
                if *pp.offset(i.wrapping_add(1)) == 0 {
                    return 0;
                }
                i = i.wrapping_add(1);
            }
            if *pp.offset(i) == b'/' as c_char {
                if overflow {
                    return 0;
                }
                in_bracket = false;
                pp = pp.offset(i.wrapping_add(1));
                i = -1;
                ppos = ppos.wrapping_add(j.wrapping_add(1) as usize);
                j = -1;
            }
            if (ppos as isize).wrapping_add(j.wrapping_add(1)) < PATH_MAX as isize {
                *buf.add(ppos.wrapping_add(j as usize)) = *pp.offset(i);
                j = j.wrapping_add(1);
            } else if in_bracket {
                overflow = true;
            } else {
                return 0;
            }
            typ = 0;
            i = i.wrapping_add(1);
        }
        *buf.add(ppos) = 0;
        if *pp == 0 {
            if (flags & GLOB_MARK) != 0 && (typ == 0 || typ == dtlnk) {
                let mut st: crate::stat::Stat = core::mem::zeroed();
                if crate::stat::stat(buf, &mut st) == 0 {
                    typ = if crate::stat::S_ISDIR(st.st_mode) {
                        dtdir
                    } else {
                        dtreg
                    };
                }
            }
            if typ == 0 {
                let mut st: crate::stat::Stat = core::mem::zeroed();
                if crate::stat::lstat(buf, &mut st) != 0 {
                    let e = e_get();
                    if e != ENOENT && (g_err(errfunc, buf, e) != 0 || (flags & GLOB_ERR) != 0) {
                        return GLOB_ABORTED;
                    }
                    return 0;
                }
            }
            if g_append(
                tail,
                buf,
                strlen(buf),
                (flags & GLOB_MARK) != 0 && typ == dtdir,
            ) != 0
            {
                return GLOB_NOSPACE;
            }
            return 0;
        }
        // Split off the next component at an (unescaped) `/`.
        let mut p2 = crate::string::strchr(pp, b'/' as c_int);
        let mut saved = b'/' as c_char;
        if !p2.is_null() && (flags & GLOB_NOESCAPE) == 0 {
            let mut q = p2;
            while q != pp && *q.sub(1) == b'\\' as c_char {
                q = q.sub(1);
            }
            if (p2 as usize).wrapping_sub(q as usize) % 2 == 1 {
                p2 = p2.sub(1);
                saved = b'\\' as c_char;
            }
        }
        let dir = if ppos > 0 {
            crate::dirent::opendir(buf)
        } else {
            crate::dirent::opendir(GDOT.as_ptr())
        };
        if dir.is_null() {
            let e = e_get();
            if g_err(errfunc, buf, e) != 0 || (flags & GLOB_ERR) != 0 {
                return GLOB_ABORTED;
            }
            return 0;
        }
        let old = e_get();
        loop {
            e_set(0);
            let de = crate::dirent::readdir(dir);
            if de.is_null() {
                break;
            }
            let dtype = (*de).d_type as c_int;
            if !p2.is_null() && dtype != 0 && dtype != dtdir && dtype != dtlnk {
                continue;
            }
            let dn = (*de).d_name.as_ptr();
            let l = strlen(dn);
            if l >= PATH_MAX.wrapping_sub(ppos) {
                continue;
            }
            if !p2.is_null() {
                *p2 = 0;
            }
            let fnm = (if (flags & GLOB_NOESCAPE) != 0 {
                FNM_NOESCAPE
            } else {
                0
            }) | (if (flags & GLOB_PERIOD) == 0 {
                FNM_PERIOD
            } else {
                0
            });
            let mut skip = fnmatch(pp, dn, fnm) != 0;
            if !skip
                && !p2.is_null()
                && (flags & GLOB_PERIOD) != 0
                && *dn == b'.' as c_char
                && (*dn.add(1) == 0 || (*dn.add(1) == b'.' as c_char && *dn.add(2) == 0))
                && fnmatch(pp, dn, fnm | FNM_PERIOD) != 0
            {
                skip = true;
            }
            if !p2.is_null() {
                *p2 = saved;
            }
            if skip {
                continue;
            }
            memcpy(
                buf.add(ppos) as *mut c_void,
                dn as *const c_void,
                l.wrapping_add(1),
            );
            let next = if p2.is_null() {
                GEMPTY.as_ptr() as *mut c_char
            } else {
                p2
            };
            let r = g_do(buf, ppos.wrapping_add(l), dtype, next, flags, errfunc, tail);
            if r != 0 {
                crate::dirent::closedir(dir);
                return r;
            }
        }
        let readerr = e_get();
        crate::dirent::closedir(dir);
        if readerr != 0 && (g_err(errfunc, buf, readerr) != 0 || (flags & GLOB_ERR) != 0) {
            return GLOB_ABORTED;
        }
        e_set(old);
        0
    }
}

/// Expand a leading `~` (`*pat` on entry). Only bare `~` (via
/// `$HOME`) is supported; `~user` needs the passwd db this crate
/// does not have, and fails with `GLOB_NOMATCH` like an unknown user
/// does in musl.
#[cfg(target_arch = "x86_64")]
unsafe fn g_tilde(pat: *mut *mut c_char, buf: *mut c_char, pos: *mut usize) -> c_int {
    unsafe {
        let p = (*pat).add(1);
        let mut elen: usize = 0;
        while *p.add(elen) != 0 && *p.add(elen) != b'/' as c_char {
            elen = elen.wrapping_add(1);
        }
        let delim = *p.add(elen);
        *pat = if delim != 0 {
            p.add(elen).add(1)
        } else {
            p.add(elen)
        };
        if elen != 0 {
            return GLOB_NOMATCH;
        }
        let h = getenv(GHOME.as_ptr());
        if h.is_null() {
            return GLOB_NOMATCH;
        }
        let hlen = strlen(h);
        let mut i: usize = 0;
        while i < hlen {
            if i >= PATH_MAX.wrapping_sub(2) {
                return GLOB_NOMATCH;
            }
            *buf.add(i) = *h.add(i);
            i = i.wrapping_add(1);
        }
        if delim != 0 {
            *buf.add(i) = delim;
            i = i.wrapping_add(1);
        }
        *buf.add(i) = 0;
        *pos = i;
        0
    }
}

/// Filename globbing (musl `glob.c`).
///
/// # Safety
///
/// `pattern` must point to a NUL-terminated string; `pglob` to
/// writable `glob_t` storage (zeroed unless `GLOB_APPEND` reuses a
/// previous result); `errfunc` may be null.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn glob(
    pattern: *const c_char,
    flags: c_int,
    errfunc: Option<unsafe extern "C" fn(*const c_char, c_int) -> c_int>,
    pglob: *mut glob_t,
) -> c_int {
    unsafe {
        if pattern.is_null() || pglob.is_null() {
            return GLOB_NOSPACE;
        }
        let ef = match errfunc {
            Some(_) => errfunc,
            None => Some(g_ignore as unsafe extern "C" fn(*const c_char, c_int) -> c_int),
        };
        let mut offs: usize = if (flags & GLOB_DOOFFS) != 0 {
            (*pglob).gl_offs
        } else {
            0
        };
        if (flags & GLOB_APPEND) == 0 {
            (*pglob).gl_offs = offs;
            (*pglob).gl_pathc = 0;
            (*pglob).gl_pathv = null_mut();
        }
        let mut head = GMatch { next: null_mut() };
        let mut t: *mut GMatch = &mut head as *mut GMatch;
        let mut error: c_int = 0;
        let mut buf = [0 as c_char; PATH_MAX];
        if *pattern != 0 {
            let plen = strlen(pattern);
            let pc = malloc(plen.wrapping_add(1)) as *mut c_char;
            if pc.is_null() {
                return GLOB_NOSPACE;
            }
            memcpy(
                pc as *mut c_void,
                pattern as *const c_void,
                plen.wrapping_add(1),
            );
            let mut ppos: usize = 0;
            let mut s = pc;
            if ((flags & (GLOB_TILDE | GLOB_TILDE_CHECK)) != 0) && *pc == b'~' as c_char {
                error = g_tilde(&mut s as *mut *mut c_char, buf.as_mut_ptr(), &mut ppos);
            }
            if error == 0 {
                error = g_do(
                    buf.as_mut_ptr(),
                    ppos,
                    0,
                    s,
                    flags,
                    ef,
                    &mut t as *mut *mut GMatch,
                );
            }
            free(pc as *mut c_void);
        }
        if error == GLOB_NOSPACE {
            g_freelist(&mut head as *mut GMatch);
            return error;
        }
        let mut cnt: usize = 0;
        let mut m = head.next;
        while !m.is_null() {
            cnt = cnt.wrapping_add(1);
            m = (*m).next;
        }
        if cnt == 0 {
            if (flags & GLOB_NOCHECK) != 0 {
                if g_append(&mut t as *mut *mut GMatch, pattern, strlen(pattern), false) != 0 {
                    return GLOB_NOSPACE;
                }
                cnt = 1;
            } else if error == 0 {
                return GLOB_NOMATCH;
            }
        }
        if (flags & GLOB_APPEND) != 0 {
            let cur = (*pglob).gl_pathc;
            let nv = realloc(
                (*pglob).gl_pathv as *mut c_void,
                offs.wrapping_add(cur)
                    .wrapping_add(cnt)
                    .wrapping_add(1)
                    .wrapping_mul(size_of::<*mut c_char>()),
            ) as *mut *mut c_char;
            if nv.is_null() {
                g_freelist(&mut head as *mut GMatch);
                return GLOB_NOSPACE;
            }
            (*pglob).gl_pathv = nv;
            offs = offs.wrapping_add(cur);
        } else {
            let nv = malloc(
                offs.wrapping_add(cnt)
                    .wrapping_add(1)
                    .wrapping_mul(size_of::<*mut c_char>()),
            ) as *mut *mut c_char;
            if nv.is_null() {
                g_freelist(&mut head as *mut GMatch);
                return GLOB_NOSPACE;
            }
            (*pglob).gl_pathv = nv;
            let mut k = 0usize;
            while k < offs {
                *nv.add(k) = null_mut();
                k = k.wrapping_add(1);
            }
        }
        let mut k = 0usize;
        let mut mm = head.next;
        while k < cnt {
            *(*pglob).gl_pathv.add(offs.wrapping_add(k)) = g_name(mm);
            mm = (*mm).next;
            k = k.wrapping_add(1);
        }
        *(*pglob).gl_pathv.add(offs.wrapping_add(cnt)) = null_mut();
        (*pglob).gl_pathc = (*pglob).gl_pathc.wrapping_add(cnt);
        if (flags & GLOB_NOSORT) == 0 {
            crate::stdlib::qsort(
                (*pglob).gl_pathv.add(offs) as *mut c_void,
                cnt,
                size_of::<*mut c_char>(),
                Some(g_sort),
            );
        }
        error
    }
}

/// Release a `glob` result (musl `globfree`).
///
/// # Safety
///
/// `pglob` must point to a `glob_t` from [`glob`] (or a zeroed one).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn globfree(pglob: *mut glob_t) {
    unsafe {
        if pglob.is_null() {
            return;
        }
        let mut k = 0usize;
        while k < (*pglob).gl_pathc {
            let p = *(*pglob).gl_pathv.add((*pglob).gl_offs.wrapping_add(k));
            if !p.is_null() {
                free((p as *mut u8).sub(GMATCH_OFF) as *mut c_void);
            }
            k = k.wrapping_add(1);
        }
        if !(*pglob).gl_pathv.is_null() {
            free((*pglob).gl_pathv as *mut c_void);
        }
        (*pglob).gl_pathc = 0;
        (*pglob).gl_pathv = null_mut();
    }
}

// ---- wordexp (shell-less subset of musl src/misc/wordexp.c) ------------------

/// Growable byte scratch for one word / the word list.
#[cfg(target_arch = "x86_64")]
struct Wrd {
    p: *mut u8,
    len: usize,
    cap: usize,
    fail: bool,
}

#[cfg(target_arch = "x86_64")]
unsafe fn w_push(w: &mut Wrd, b: u8) {
    unsafe {
        if w.fail {
            return;
        }
        if w.len == w.cap {
            let ncap = if w.cap == 0 {
                32
            } else {
                w.cap.wrapping_mul(2)
            };
            if ncap > 1_000_000 {
                w.fail = true;
                return;
            }
            let nb = realloc(w.p as *mut c_void, ncap) as *mut u8;
            if nb.is_null() {
                w.fail = true;
                return;
            }
            w.p = nb;
            w.cap = ncap;
        }
        w.p.add(w.len).write(b);
        w.len = w.len.wrapping_add(1);
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn w_push_str(w: &mut Wrd, s: *const c_char) {
    unsafe {
        let mut k = 0usize;
        while *s.add(k) != 0 {
            w_push(w, *s.add(k) as u8);
            k = k.wrapping_add(1);
        }
    }
}

/// Parser state shared by the helpers below.
#[cfg(target_arch = "x86_64")]
struct WState {
    words: *mut *mut c_char,
    nwords: usize,
    cwords: usize,
    scratch: Wrd,
    started: bool,
    content: bool,
    quoted: bool,
    fail: bool,
    code: c_int,
}

#[cfg(target_arch = "x86_64")]
unsafe fn w_flush(st: &mut WState) {
    unsafe {
        if !st.started || (!st.content && !st.quoted) {
            st.started = false;
            st.content = false;
            st.quoted = false;
            st.scratch.len = 0;
            return;
        }
        if st.fail {
            return;
        }
        if st.nwords == st.cwords {
            let ncap = if st.cwords == 0 {
                16
            } else {
                st.cwords.wrapping_mul(2)
            };
            if ncap > 1_000_000 {
                st.fail = true;
                st.code = WRDE_NOSPACE;
                return;
            }
            let nb = realloc(
                st.words as *mut c_void,
                ncap.wrapping_mul(size_of::<*mut c_char>()),
            ) as *mut *mut c_char;
            if nb.is_null() {
                st.fail = true;
                st.code = WRDE_NOSPACE;
                return;
            }
            st.words = nb;
            st.cwords = ncap;
        }
        let s = malloc(st.scratch.len.wrapping_add(1)) as *mut c_char;
        if s.is_null() {
            st.fail = true;
            st.code = WRDE_NOSPACE;
            return;
        }
        let mut k = 0usize;
        while k < st.scratch.len {
            *s.add(k) = st.scratch.p.add(k).read() as c_char;
            k = k.wrapping_add(1);
        }
        *s.add(st.scratch.len) = 0;
        *st.words.add(st.nwords) = s;
        st.nwords = st.nwords.wrapping_add(1);
        st.started = false;
        st.content = false;
        st.quoted = false;
        st.scratch.len = 0;
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn w_free_all(st: &mut WState) {
    unsafe {
        let mut k = 0usize;
        while k < st.nwords {
            free(*st.words.add(k) as *mut c_void);
            k = k.wrapping_add(1);
        }
        if !st.words.is_null() {
            free(st.words as *mut c_void);
            st.words = null_mut();
        }
        if !st.scratch.p.is_null() {
            free(st.scratch.p as *mut c_void);
            st.scratch.p = null_mut();
        }
        st.nwords = 0;
        st.cwords = 0;
    }
}

/// Expand `$`-forms at `*pp` (past the `$`); advances `*pp`.
/// Returns `true` when the caller must abort with `st.code`.
#[cfg(target_arch = "x86_64")]
unsafe fn w_dollar(st: &mut WState, pp: &mut *const u8, flags: c_int) -> bool {
    unsafe {
        let base = *pp;
        let at = move |o: usize| *base.add(o);
        let c1 = at(0);
        if c1 == b'(' {
            st.code = WRDE_CMDSUB;
            return true;
        }
        if c1 == b'{' {
            let mut k = 1usize;
            while at(k) != 0 && at(k) != b'}' {
                k = k.wrapping_add(1);
            }
            if at(k) != b'}' {
                st.code = WRDE_SYNTAX;
                return true;
            }
            if k == 1 {
                st.code = WRDE_SYNTAX;
                return true;
            }
            let mut ok = true;
            let mut j = 1usize;
            while j < k {
                let ch = at(j);
                if !(ch == b'_'
                    || ch.is_ascii_uppercase()
                    || ch.is_ascii_lowercase()
                    || ch.is_ascii_digit())
                {
                    ok = false;
                    break;
                }
                j = j.wrapping_add(1);
            }
            if !ok {
                st.code = WRDE_SYNTAX;
                return true;
            }
            let mut nm = [0 as c_char; 256];
            let nl = (k.wrapping_sub(1)).min(255);
            let mut j = 0usize;
            while j < nl {
                nm[j] = at(j.wrapping_add(1)) as c_char;
                j = j.wrapping_add(1);
            }
            nm[nl] = 0;
            let v = getenv(nm.as_ptr());
            if v.is_null() {
                if (flags & WRDE_UNDEF) != 0 {
                    st.code = WRDE_BADVAL;
                    return true;
                }
            } else {
                w_push_str(&mut st.scratch, v);
                if strlen(v) > 0 {
                    st.content = true;
                }
            }
            st.started = true;
            *pp = (*pp).add(k.wrapping_add(1));
            return false;
        }
        let is_start = c1 == b'_' || c1.is_ascii_uppercase() || c1.is_ascii_lowercase();
        if is_start {
            let mut k = 0usize;
            while {
                let ch = at(k);
                ch == b'_'
                    || ch.is_ascii_uppercase()
                    || ch.is_ascii_lowercase()
                    || ch.is_ascii_digit()
            } {
                k = k.wrapping_add(1);
            }
            let mut nm = [0 as c_char; 256];
            let nl = k.min(255);
            let mut j = 0usize;
            while j < nl {
                nm[j] = at(j) as c_char;
                j = j.wrapping_add(1);
            }
            nm[nl] = 0;
            let v = getenv(nm.as_ptr());
            if v.is_null() {
                if (flags & WRDE_UNDEF) != 0 {
                    st.code = WRDE_BADVAL;
                    return true;
                }
            } else {
                w_push_str(&mut st.scratch, v);
                if strlen(v) > 0 {
                    st.content = true;
                }
            }
            st.started = true;
            *pp = (*pp).add(k);
            return false;
        }
        if c1 == b'$' {
            // `$$`: the caller's pid, decimal.
            let mut pid = crate::unistd::getpid() as u32;
            let mut tmp = [0u8; 12];
            let mut n = 0usize;
            if pid == 0 {
                tmp[0] = b'0';
                n = 1;
            } else {
                while pid > 0 {
                    tmp[n] = b'0'.wrapping_add((pid % 10) as u8);
                    n = n.wrapping_add(1);
                    pid /= 10;
                }
            }
            while n > 0 {
                n = n.wrapping_sub(1);
                w_push(&mut st.scratch, tmp[n]);
            }
            st.started = true;
            st.content = true;
            *pp = (*pp).add(2);
            return false;
        }
        // Anything else: a literal `$`, reprocess the next char.
        w_push(&mut st.scratch, b'$');
        st.started = true;
        st.content = true;
        *pp = (*pp).add(1);
        false
    }
}

/// Shell word expansion without a shell (see module docs for the
/// exact subset).
///
/// # Safety
///
/// `s` must point to a NUL-terminated string; `we` to writable
/// `wordexp_t` storage (zeroed unless `WRDE_APPEND`/`WRDE_REUSE`
/// apply).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wordexp(s: *const c_char, we: *mut wordexp_t, flags: c_int) -> c_int {
    unsafe {
        if s.is_null() || we.is_null() {
            return WRDE_NOSPACE;
        }
        if (flags & WRDE_REUSE) != 0 {
            wordfree(we);
        }
        let mut st = WState {
            words: null_mut(),
            nwords: 0,
            cwords: 0,
            scratch: Wrd {
                p: null_mut(),
                len: 0,
                cap: 0,
                fail: false,
            },
            started: false,
            content: false,
            quoted: false,
            fail: false,
            code: 0,
        };
        let mut p = s as *const u8;
        let mut sq = false;
        let mut dq = false;
        let mut rc = 0;
        loop {
            let ch = *p;
            if ch == 0 {
                break;
            }
            if ch == b'\\' && !sq {
                // `at(1)` needs the raw byte past `p`.
                let nx = *p.add(1);
                if nx == 0 {
                    rc = WRDE_SYNTAX;
                    break;
                }
                w_push(&mut st.scratch, nx);
                st.started = true;
                st.content = true;
                p = p.add(2);
                continue;
            }
            if ch == b'\'' && !dq {
                sq = !sq;
                st.started = true;
                st.quoted = true;
                p = p.add(1);
                continue;
            }
            if ch == b'"' && !sq {
                dq = !dq;
                st.started = true;
                st.quoted = true;
                p = p.add(1);
                continue;
            }
            if (ch == b' ' || ch == b'\t' || ch == b'\n') && !sq && !dq {
                if ch == b'\n' && (flags & WRDE_NOCMD) != 0 {
                    rc = WRDE_BADCHAR;
                    break;
                }
                w_flush(&mut st);
                if st.fail {
                    rc = st.code;
                    break;
                }
                p = p.add(1);
                continue;
            }
            if ch == b'`' && !sq {
                rc = WRDE_CMDSUB;
                break;
            }
            if ch == b'$' && !sq {
                let mut q = p.add(1);
                if w_dollar(&mut st, &mut q, flags) {
                    rc = st.code;
                    break;
                }
                if st.scratch.fail {
                    rc = WRDE_NOSPACE;
                    break;
                }
                p = q;
                continue;
            }
            if ch == b'~' && !sq && !dq && !st.started {
                let h = getenv(GHOME.as_ptr());
                if !h.is_null() {
                    w_push_str(&mut st.scratch, h);
                    if strlen(h) > 0 {
                        st.content = true;
                    }
                    st.started = true;
                } else {
                    w_push(&mut st.scratch, b'~');
                    st.started = true;
                    st.content = true;
                }
                p = p.add(1);
                continue;
            }
            let special = ch == b'|'
                || ch == b'&'
                || ch == b';'
                || ch == b'<'
                || ch == b'>'
                || ch == b'('
                || ch == b')'
                || ch == b'{'
                || ch == b'}';
            if special && !sq && !dq {
                if (flags & WRDE_NOCMD) != 0 {
                    rc = WRDE_BADCHAR;
                    break;
                }
                w_push(&mut st.scratch, ch);
                st.started = true;
                st.content = true;
                p = p.add(1);
                continue;
            }
            w_push(&mut st.scratch, ch);
            st.started = true;
            st.content = true;
            p = p.add(1);
        }
        if rc == 0 && (sq || dq) {
            rc = WRDE_SYNTAX;
        }
        if rc == 0 && (st.fail || st.scratch.fail) {
            rc = WRDE_NOSPACE;
        }
        if rc == 0 {
            w_flush(&mut st);
            if st.fail {
                rc = st.code;
            }
        }
        if rc != 0 {
            w_free_all(&mut st);
            if (flags & WRDE_APPEND) == 0 {
                (*we).we_wordc = 0;
                (*we).we_wordv = null_mut();
            }
            return rc;
        }
        // Merge: [offs nulls][kept words][new words][null].
        let offs: usize = if (flags & WRDE_DOOFFS) != 0 {
            (*we).we_offs
        } else {
            0
        };
        let kept: usize = if (flags & WRDE_APPEND) != 0 {
            (*we).we_wordc
        } else {
            0
        };
        let total = offs.wrapping_add(kept).wrapping_add(st.nwords);
        let nv = malloc(total.wrapping_add(1).wrapping_mul(size_of::<*mut c_char>()))
            as *mut *mut c_char;
        if nv.is_null() {
            w_free_all(&mut st);
            if (flags & WRDE_APPEND) == 0 {
                (*we).we_wordc = 0;
                (*we).we_wordv = null_mut();
            }
            return WRDE_NOSPACE;
        }
        let mut k = 0usize;
        while k < offs {
            *nv.add(k) = null_mut();
            k = k.wrapping_add(1);
        }
        let mut k = 0usize;
        while k < kept {
            *nv.add(offs.wrapping_add(k)) = *(*we).we_wordv.add((*we).we_offs.wrapping_add(k));
            k = k.wrapping_add(1);
        }
        let mut k = 0usize;
        while k < st.nwords {
            *nv.add(offs.wrapping_add(kept).wrapping_add(k)) = *st.words.add(k);
            k = k.wrapping_add(1);
        }
        *nv.add(total) = null_mut();
        if (flags & WRDE_APPEND) != 0 && !(*we).we_wordv.is_null() {
            free((*we).we_wordv as *mut c_void);
        }
        if !st.words.is_null() {
            free(st.words as *mut c_void);
        }
        if !st.scratch.p.is_null() {
            free(st.scratch.p as *mut c_void);
        }
        (*we).we_wordv = nv;
        (*we).we_wordc = kept.wrapping_add(st.nwords);
        (*we).we_offs = offs;
        0
    }
}

/// Release a `wordexp` result (musl `wordfree`).
///
/// # Safety
///
/// `we` must point to a `wordexp_t` from [`wordexp`] (or a zeroed
/// one).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn wordfree(we: *mut wordexp_t) {
    unsafe {
        if we.is_null() || (*we).we_wordv.is_null() {
            return;
        }
        let mut k = 0usize;
        while k < (*we).we_wordc {
            free(*(*we).we_wordv.add((*we).we_offs.wrapping_add(k)) as *mut c_void);
            k = k.wrapping_add(1);
        }
        free((*we).we_wordv as *mut c_void);
        (*we).we_wordv = null_mut();
        (*we).we_wordc = 0;
    }
}

// ---- ftw / nftw (musl src/misc/nftw.c shape) ---------------------------------

/// musl `S_IFLNK` (`include/sys/stat.h`); the crate only keeps
/// `IFMT`/`IFREG`/`IFDIR`.
#[cfg(target_arch = "x86_64")]
const S_IFLNK: u32 = 0o120000;
/// musl `S_IFDIR` value (kept local so matching never depends on
/// which `stat` helpers are in scope).
#[cfg(target_arch = "x86_64")]
const S_IFDIR: u32 = 0o040000;

/// Ancestor chain for cycle detection (musl `struct history`).
#[cfg(target_arch = "x86_64")]
struct Hist {
    chain: *mut Hist,
    dev: u64,
    ino: u64,
    level: c_int,
    base: c_int,
}

#[cfg(target_arch = "x86_64")]
unsafe fn ftw_call(
    f3: Option<unsafe extern "C" fn(*const c_char, *const crate::stat::Stat, c_int) -> c_int>,
    f4: Option<
        unsafe extern "C" fn(*const c_char, *const crate::stat::Stat, c_int, *mut FTW) -> c_int,
    >,
    path: *const c_char,
    st: *const crate::stat::Stat,
    typ: c_int,
    lev: *mut FTW,
) -> c_int {
    unsafe {
        match f4 {
            Some(g) => g(path, st, typ, lev),
            None => match f3 {
                Some(g) => g(path, st, typ),
                None => 0,
            },
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(clippy::too_many_arguments)]
unsafe fn ftw_walk(
    path: *mut c_char,
    f3: Option<unsafe extern "C" fn(*const c_char, *const crate::stat::Stat, c_int) -> c_int>,
    f4: Option<
        unsafe extern "C" fn(*const c_char, *const crate::stat::Stat, c_int, *mut FTW) -> c_int,
    >,
    fd_limit: c_int,
    flags: c_int,
    h: *mut Hist,
) -> c_int {
    unsafe {
        let l = strlen(path);
        let mut j = l;
        if j > 0 && *path.add(j.wrapping_sub(1)) == b'/' as c_char {
            j = j.wrapping_sub(1);
        }
        let mut st: crate::stat::Stat = core::mem::zeroed();
        st.st_dev = 0;
        st.st_ino = 0;
        let mut typ: c_int;
        if (flags & FTW_PHYS) != 0 {
            if crate::stat::lstat(path, &mut st) != 0 {
                if e_get() != EACCES {
                    return -1;
                }
                typ = FTW_NS;
            } else if (st.st_mode & crate::stat::S_IFMT) == S_IFDIR {
                typ = if (flags & FTW_DEPTH) != 0 {
                    FTW_DP
                } else {
                    FTW_D
                };
            } else if (st.st_mode & crate::stat::S_IFMT) == S_IFLNK {
                typ = FTW_SL;
            } else {
                typ = FTW_F;
            }
        } else if crate::stat::stat(path, &mut st) != 0 {
            let e = e_get();
            if e == ENOENT && crate::stat::lstat(path, &mut st) == 0 {
                typ = FTW_SLN;
            } else if e != EACCES {
                return -1;
            } else {
                typ = FTW_NS;
            }
        } else if (st.st_mode & crate::stat::S_IFMT) == S_IFDIR {
            typ = if (flags & FTW_DEPTH) != 0 {
                FTW_DP
            } else {
                FTW_D
            };
        } else if (st.st_mode & crate::stat::S_IFMT) == S_IFLNK {
            typ = FTW_SLN;
        } else {
            typ = FTW_F;
        }

        if (flags & FTW_MOUNT) != 0 && !h.is_null() && typ != FTW_NS && st.st_dev != (*h).dev {
            return 0;
        }

        let mut newh = Hist {
            chain: h,
            dev: st.st_dev,
            ino: st.st_ino,
            level: if h.is_null() {
                0
            } else {
                (*h).level.wrapping_add(1)
            },
            base: j.wrapping_add(1) as c_int,
        };
        let mut lev = FTW {
            level: newh.level,
            base: if h.is_null() {
                let mut k = j;
                while k > 0 && *path.add(k) == b'/' as c_char {
                    k = k.wrapping_sub(1);
                }
                while k > 0 && *path.add(k.wrapping_sub(1)) != b'/' as c_char {
                    k = k.wrapping_sub(1);
                }
                k as c_int
            } else {
                (*h).base
            },
        };

        let mut dfd: c_int = -1;
        let mut err = 0;
        if typ == FTW_D || typ == FTW_DP {
            dfd = crate::fcntl::open(path, crate::fcntl::O_RDONLY, 0);
            err = e_get();
            if dfd < 0 && err == EACCES {
                typ = FTW_DNR;
            }
            if fd_limit == 0 && dfd >= 0 {
                crate::unistd::close(dfd);
                dfd = -1;
            }
        }

        if (flags & FTW_DEPTH) == 0 {
            let r = ftw_call(f3, f4, path, &st, typ, &mut lev as *mut FTW);
            if r != 0 {
                return r;
            }
        }

        let mut hh = h;
        while !hh.is_null() {
            if (*hh).dev == st.st_dev && (*hh).ino == st.st_ino {
                return 0;
            }
            hh = (*hh).chain;
        }

        if (typ == FTW_D || typ == FTW_DP) && fd_limit != 0 {
            if dfd < 0 {
                e_set(err);
                return -1;
            }
            let d = crate::dirent::fdopendir(dfd);
            if !d.is_null() {
                loop {
                    let de = crate::dirent::readdir(d);
                    if de.is_null() {
                        break;
                    }
                    let dn = (*de).d_name.as_ptr();
                    if *dn == b'.' as c_char
                        && (*dn.add(1) == 0 || (*dn.add(1) == b'.' as c_char && *dn.add(2) == 0))
                    {
                        continue;
                    }
                    if strlen(dn) >= PATH_MAX.wrapping_sub(l) {
                        e_set(ENAMETOOLONG);
                        crate::dirent::closedir(d);
                        return -1;
                    }
                    *path.add(j) = b'/' as c_char;
                    crate::string::strcpy(path.add(j.wrapping_add(1)), dn);
                    let r = ftw_walk(
                        path,
                        f3,
                        f4,
                        fd_limit.wrapping_sub(1),
                        flags,
                        &mut newh as *mut Hist,
                    );
                    if r != 0 {
                        crate::dirent::closedir(d);
                        return r;
                    }
                }
                crate::dirent::closedir(d);
            } else {
                crate::unistd::close(dfd);
                return -1;
            }
        }

        *path.add(l) = 0;
        if (flags & FTW_DEPTH) != 0 {
            let r = ftw_call(f3, f4, path, &st, typ, &mut lev as *mut FTW);
            if r != 0 {
                return r;
            }
        }
        0
    }
}

/// File-tree walk, three-argument form (musl `src/legacy/ftw.c`:
/// `nftw` with `FTW_PHYS`).
///
/// # Safety
///
/// `path` must point to a NUL-terminated string; `fn_` a valid
/// callback (or null, which visits nothing and returns 0).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ftw(
    path: *const c_char,
    fn_: Option<unsafe extern "C" fn(*const c_char, *const crate::stat::Stat, c_int) -> c_int>,
    nopenfd: c_int,
) -> c_int {
    unsafe {
        if path.is_null() {
            return -1;
        }
        if nopenfd <= 0 {
            return 0;
        }
        let l = strlen(path);
        if l > PATH_MAX {
            e_set(ENAMETOOLONG);
            return -1;
        }
        let mut buf = [0 as c_char; 4097];
        memcpy(
            buf.as_mut_ptr() as *mut c_void,
            path as *const c_void,
            l.wrapping_add(1),
        );
        ftw_walk(buf.as_mut_ptr(), fn_, None, nopenfd, FTW_PHYS, null_mut())
    }
}

/// File-tree walk (musl `nftw.c`). `FTW_CHDIR` is accepted and
/// ignored, exactly as in musl.
///
/// # Safety
///
/// `path` must point to a NUL-terminated string; `fn_` a valid
/// callback (or null).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn nftw(
    path: *const c_char,
    fn_: Option<
        unsafe extern "C" fn(*const c_char, *const crate::stat::Stat, c_int, *mut FTW) -> c_int,
    >,
    nopenfd: c_int,
    flags: c_int,
) -> c_int {
    unsafe {
        if path.is_null() {
            return -1;
        }
        if nopenfd <= 0 {
            return 0;
        }
        let l = strlen(path);
        if l > PATH_MAX {
            e_set(ENAMETOOLONG);
            return -1;
        }
        let mut buf = [0 as c_char; 4097];
        memcpy(
            buf.as_mut_ptr() as *mut c_void,
            path as *const c_void,
            l.wrapping_add(1),
        );
        ftw_walk(buf.as_mut_ptr(), None, fn_, nopenfd, flags, null_mut())
    }
}

// ---- basename / dirname (musl src/misc/basename.c, dirname.c) ---------------

#[cfg(target_arch = "x86_64")]
static DOT2: [c_char; 2] = [b'.' as c_char, 0];
#[cfg(target_arch = "x86_64")]
static SLASH2: [c_char; 2] = [b'/' as c_char, 0];

/// Last component of `s` (musl `basename`: strips trailing slashes
/// in place; `NULL`/empty gives `"."`).
///
/// # Safety
///
/// `s` must be null or point to a writable NUL-terminated string;
/// the result borrows it (or a static `"."`).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn basename(s: *mut c_char) -> *mut c_char {
    unsafe {
        if s.is_null() || *s == 0 {
            return DOT2.as_ptr() as *mut c_char;
        }
        let mut i = strlen(s).wrapping_sub(1);
        while i != 0 && *s.add(i) == b'/' as c_char {
            *s.add(i) = 0;
            i = i.wrapping_sub(1);
        }
        while i != 0 && *s.add(i.wrapping_sub(1)) != b'/' as c_char {
            i = i.wrapping_sub(1);
        }
        s.add(i)
    }
}

/// Directory component of `s` (musl `dirname`: mutates in place;
/// `NULL`/empty/bare name gives `"."`, all-slashes gives `"/"`).
///
/// # Safety
///
/// `s` must be null or point to a writable NUL-terminated string;
/// the result borrows it (or a static `"."`/`"/"`).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn dirname(s: *mut c_char) -> *mut c_char {
    unsafe {
        if s.is_null() || *s == 0 {
            return DOT2.as_ptr() as *mut c_char;
        }
        let mut i = strlen(s).wrapping_sub(1);
        loop {
            if *s.add(i) != b'/' as c_char {
                break;
            }
            if i == 0 {
                return SLASH2.as_ptr() as *mut c_char;
            }
            i = i.wrapping_sub(1);
        }
        loop {
            if *s.add(i) == b'/' as c_char {
                break;
            }
            if i == 0 {
                return DOT2.as_ptr() as *mut c_char;
            }
            i = i.wrapping_sub(1);
        }
        loop {
            if *s.add(i) != b'/' as c_char {
                break;
            }
            if i == 0 {
                return SLASH2.as_ptr() as *mut c_char;
            }
            i = i.wrapping_sub(1);
        }
        *s.add(i.wrapping_add(1)) = 0;
        s
    }
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::format;
    use std::string::String;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::vec::Vec;

    static TNUM: AtomicU32 = AtomicU32::new(0);

    fn uniq(tag: &str) -> std::path::PathBuf {
        let n = TNUM.fetch_add(1, Ordering::SeqCst);
        let p = std::path::PathBuf::from(format!(
            "/tmp/zlibc-rx9c4-{}-{}-{}",
            std::process::id(),
            tag,
            n
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn cs(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    /// Compile `pat`, match `s`, return `(code, offsets[..nm])`.
    unsafe fn do_match(
        pat: &str,
        s: &str,
        cflags: c_int,
        eflags: c_int,
        nm: usize,
    ) -> (c_int, [(regoff_t, regoff_t); 10]) {
        unsafe {
            let mut re: regex_t = core::mem::zeroed();
            let p = cs(pat);
            let rc = regcomp(&mut re, p.as_ptr(), cflags);
            assert_eq!(rc, 0, "regcomp({pat:?}) failed: {rc}");
            let t = cs(s);
            let mut pm: [regmatch_t; 10] = core::mem::zeroed();
            let n = nm.min(10);
            let r = regexec(&re, t.as_ptr(), n, pm.as_mut_ptr(), eflags);
            let mut out = [(-1 as regoff_t, -1 as regoff_t); 10];
            let mut k = 0;
            while k < n {
                out[k] = (pm[k].rm_so, pm[k].rm_eo);
                k += 1;
            }
            regfree(&mut re);
            (r, out)
        }
    }

    #[test]
    fn regcomp_basic_bre() {
        unsafe {
            let (r, o) = do_match("a*b", "aaab", 0, 0, 1);
            assert_eq!((r, o[0]), (0, (0, 4)));
            let (r, _) = do_match("a*b", "c", 0, 0, 1);
            assert_eq!(r, REG_NOMATCH);
            // BRE parens are literal; `\(..\)` groups.
            let (r, o) = do_match("\\(a\\)\\1", "aa", 0, 0, 2);
            assert_eq!((r, o[0], o[1]), (0, (0, 2), (0, 1)));
            let (r, o) = do_match("a\\{2\\}", "aaa", 0, 0, 1);
            assert_eq!((r, o[0]), (0, (0, 2)));
            // BRE alternation and one-or-more extensions.
            let (r, o) = do_match("a\\|b", "b", 0, 0, 1);
            assert_eq!((r, o[0]), (0, (0, 1)));
            let (r, o) = do_match("a\\+", "aaa", 0, 0, 1);
            assert_eq!((r, o[0]), (0, (0, 3)));
        }
    }

    #[test]
    fn regcomp_extended() {
        unsafe {
            let (r, o) = do_match("(a|b)+c", "abac", REG_EXTENDED, 0, 2);
            assert_eq!((r, o[0], o[1]), (0, (0, 4), (2, 3)));
            let (r, o) = do_match("colou?r", "color", REG_EXTENDED, 0, 1);
            assert_eq!((r, o[0]), (0, (0, 5)));
            let (r, o) = do_match("a{2,3}", "aaaa", REG_EXTENDED, 0, 1);
            assert_eq!((r, o[0]), (0, (0, 3)));
            let (r, o) = do_match("[a-z]+x", "abcx", REG_EXTENDED, 0, 1);
            assert_eq!((r, o[0]), (0, (0, 4)));
            let (r, o) = do_match("[^0-9]+", "ab1", REG_EXTENDED, 0, 1);
            assert_eq!((r, o[0]), (0, (0, 2)));
            // Empty branches match empty; star over alternation loops.
            let (r, o) = do_match("(a|)", "", REG_EXTENDED, 0, 1);
            assert_eq!((r, o[0]), (0, (0, 0)));
            let (r, o) = do_match("(a|b)*c", "ababac", REG_EXTENDED, 0, 1);
            assert_eq!((r, o[0]), (0, (0, 6)));
            let (r, o) = do_match("a{0}", "aaa", REG_EXTENDED, 0, 1);
            assert_eq!((r, o[0]), (0, (0, 0)));
            let (r, o) = do_match("", "", 0, 0, 1);
            assert_eq!((r, o[0]), (0, (0, 0)));
        }
    }

    #[test]
    fn regcomp_icase_nosub() {
        unsafe {
            let (r, o) = do_match("hello", "HeLLo", REG_ICASE, 0, 1);
            assert_eq!((r, o[0]), (0, (0, 5)));
            let (r, o) = do_match("[abc]+", "ABCa", REG_EXTENDED | REG_ICASE, 0, 1);
            assert_eq!((r, o[0]), (0, (0, 4)));
            // REG_NOSUB with nmatch 0 still reports match/no-match.
            let (r, _) = do_match("(a+)(b+)", "aabb", REG_EXTENDED | REG_NOSUB, 0, 0);
            assert_eq!(r, 0);
            let mut re: regex_t = core::mem::zeroed();
            let p = cs("(a+)(b+)");
            assert_eq!(regcomp(&mut re, p.as_ptr(), REG_EXTENDED | REG_NOSUB), 0);
            assert_eq!(re.re_nsub, 2);
            regfree(&mut re);
        }
    }

    #[test]
    fn regexec_offsets_search_and_anchors() {
        unsafe {
            let (r, o) = do_match("(a+)(b+)", "xxaaabbyy", REG_EXTENDED, 0, 3);
            assert_eq!((r, o[0], o[1], o[2]), (0, (2, 7), (2, 5), (5, 7)));
            // Unset groups read back as -1.
            let (r, o) = do_match("(a)|(b)", "b", REG_EXTENDED, 0, 3);
            assert_eq!((r, o[0], o[1], o[2]), (0, (0, 1), (-1, -1), (0, 1)));
            // Anchors and eflags.
            let (r, _) = do_match("^b", "ab", REG_EXTENDED, 0, 1);
            assert_eq!(r, REG_NOMATCH);
            let (r, o) = do_match("b$", "ab", REG_EXTENDED, 0, 1);
            assert_eq!((r, o[0]), (0, (1, 2)));
            let (r, _) = do_match("^a", "a", REG_EXTENDED, REG_NOTBOL, 0);
            assert_eq!(r, REG_NOMATCH);
            let (r, _) = do_match("a$", "a", REG_EXTENDED, REG_NOTEOL, 0);
            assert_eq!(r, REG_NOMATCH);
            // REG_NEWLINE: `.` skips `\n`, `^` matches after it.
            let (r, _) = do_match(".", "\n", REG_NEWLINE, 0, 0);
            assert_eq!(r, REG_NOMATCH);
            let (r, o) = do_match("^b", "a\nb", REG_NEWLINE, 0, 1);
            assert_eq!((r, o[0]), (0, (2, 3)));
        }
    }

    #[test]
    fn regcomp_bad_patterns() {
        unsafe {
            let bad: &[(&str, c_int, c_int)] = &[
                ("(", REG_EXTENDED, REG_EPAREN),
                ("[", REG_EXTENDED, REG_EBRACK),
                ("*a", REG_EXTENDED, REG_BADRPT),
                ("\\", REG_EXTENDED, REG_EESCAPE),
                ("a{2,1}", REG_EXTENDED, REG_BADBR),
                ("a{b", REG_EXTENDED, REG_BADBR),
                ("\\1", 0, REG_ESUBREG),
                ("\\)", 0, REG_EPAREN),
                ("[z-a]", REG_EXTENDED, REG_ERANGE),
                ("[[:nope:]]", REG_EXTENDED, REG_ECTYPE),
            ];
            for (pat, cf, want) in bad {
                let mut re: regex_t = core::mem::zeroed();
                let p = cs(pat);
                let rc = regcomp(&mut re, p.as_ptr(), *cf);
                assert_eq!(rc, *want, "regcomp({pat:?}) = {rc}, want {want}");
                regfree(&mut re);
            }
        }
    }

    #[test]
    fn regerror_text() {
        unsafe {
            let mut buf = [0 as c_char; 64];
            let r = regerror(REG_NOMATCH, core::ptr::null(), buf.as_mut_ptr(), 64);
            assert_eq!(r, 9);
            assert_eq!(CStr::from_ptr(buf.as_ptr()).to_bytes(), b"No match");
            let r = regerror(REG_BADPAT, core::ptr::null(), buf.as_mut_ptr(), 64);
            assert_eq!(r, 15);
            assert_eq!(CStr::from_ptr(buf.as_ptr()).to_bytes(), b"Invalid regexp");
            let r = regerror(99, core::ptr::null(), buf.as_mut_ptr(), 64);
            assert_eq!(r, 14);
            assert_eq!(CStr::from_ptr(buf.as_ptr()).to_bytes(), b"Unknown error");
            // Truncation still returns the full length.
            let r = regerror(REG_NOMATCH, core::ptr::null(), buf.as_mut_ptr(), 4);
            assert_eq!(r, 9);
            assert_eq!(CStr::from_ptr(buf.as_ptr()).to_bytes(), b"No ");
        }
    }

    #[test]
    fn fnmatch_vectors() {
        unsafe {
            let v: &[(&str, &str, c_int, c_int)] = &[
                ("*.txt", "a.txt", 0, 0),
                ("*.txt", "a.txtx", 0, FNM_NOMATCH),
                ("a?c", "abc", 0, 0),
                ("[a-z]", "m", 0, 0),
                ("[^a-z]", "m", 0, FNM_NOMATCH),
                ("[!a-z]", "5", 0, 0),
                ("*.txt", "d/a.txt", FNM_PATHNAME, FNM_NOMATCH),
                ("d/*.txt", "d/a.txt", FNM_PATHNAME, 0),
                ("*", ".hidden", FNM_PERIOD, FNM_NOMATCH),
                (".*", ".hidden", FNM_PERIOD, 0),
                ("a*c", "ABC", FNM_CASEFOLD, 0),
                ("a*c", "ABC", FNM_NOCASE, 0),
                ("a\\*b", "a*b", 0, 0),
                ("a\\*b", "axb", 0, FNM_NOMATCH),
                ("foo", "foobar", FNM_LEADING_DIR, FNM_NOMATCH),
                ("foo", "foo/bar", FNM_LEADING_DIR, 0),
                ("foo", "foobar", 0, FNM_NOMATCH),
                ("foo", "foo/bar", FNM_PATHNAME | FNM_LEADING_DIR, 0),
            ];
            for (pat, s, fl, want) in v {
                let p = cs(pat);
                let t = cs(s);
                let r = fnmatch(p.as_ptr(), t.as_ptr(), *fl);
                assert_eq!(r, *want, "fnmatch({pat:?}, {s:?}, {fl}) = {r}");
            }
        }
    }

    /// Explicit per-file cleanup: `std::fs::remove_dir_all` lists
    /// directories through `readdir`, which this test binary
    /// interposes with the crate's own `readdir` (built for the
    /// crate's `DIR` layout, not the host's) — traversal would miss
    /// entries. Unlinking known files needs no listing.
    fn rm_file(d: &std::path::Path, name: &str) {
        std::fs::remove_file(d.join(name)).unwrap();
    }

    fn rm_dir(p: &std::path::Path) {
        std::fs::remove_dir(p).unwrap();
    }

    fn glob_tree(tag: &str) -> std::path::PathBuf {
        let d = uniq(tag);
        for f in ["alpha.txt", "beta.txt", "gamma.log"] {
            std::fs::write(d.join(f), b"x").unwrap();
        }
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("sub").join("delta.txt"), b"x").unwrap();
        d
    }

    unsafe fn glob_paths(pat: &str, flags: c_int) -> (c_int, Vec<String>) {
        unsafe {
            let mut g: glob_t = core::mem::zeroed();
            let p = cs(pat);
            let r = glob(p.as_ptr(), flags, None, &mut g);
            let mut out = Vec::new();
            if r == 0 {
                let mut k = 0;
                while k < g.gl_pathc {
                    let s = *g.gl_pathv.add(g.gl_offs.wrapping_add(k));
                    out.push(CStr::from_ptr(s).to_string_lossy().into_owned());
                    k += 1;
                }
            }
            globfree(&mut g);
            (r, out)
        }
    }

    #[test]
    fn glob_literal_star_qmark_class() {
        unsafe {
            let d = glob_tree("glob1");
            let ds = d.to_string_lossy().into_owned();
            let (r, o) = glob_paths(&format!("{ds}/alpha.txt"), 0);
            assert_eq!(
                (r, o.as_slice()),
                (0, [format!("{ds}/alpha.txt")].as_slice())
            );
            let (r, mut o) = glob_paths(&format!("{ds}/*.txt"), 0);
            assert_eq!(r, 0);
            o.sort();
            assert_eq!(
                o.as_slice(),
                [format!("{ds}/alpha.txt"), format!("{ds}/beta.txt")].as_slice()
            );
            let (r, o) = glob_paths(&format!("{ds}/?????.*"), 0);
            assert_eq!((r, o.len()), (0, 2));
            let (r, o) = glob_paths(&format!("{ds}/[a-b]*.txt"), 0);
            assert_eq!((r, o.len()), (0, 2));
            let (r, o) = glob_paths(&format!("{ds}/sub/*.txt"), 0);
            assert_eq!(
                (r, o.as_slice()),
                (0, [format!("{ds}/sub/delta.txt")].as_slice())
            );
            rm_file(&d, "alpha.txt");
            rm_file(&d, "beta.txt");
            rm_file(&d, "gamma.log");
            rm_file(&d.join("sub"), "delta.txt");
            rm_dir(&d.join("sub"));
            rm_dir(&d);
        }
    }

    #[test]
    fn glob_nocheck_mark_append_doffs() {
        unsafe {
            let d = glob_tree("glob2");
            let ds = d.to_string_lossy().into_owned();
            // NOCHECK echoes the pattern; without it, GLOB_NOMATCH.
            let pat = format!("{ds}/nomatch-*");
            let (r, o) = glob_paths(&pat, GLOB_NOCHECK);
            assert_eq!((r, o.as_slice()), (0, [pat.clone()].as_slice()));
            let (r, _) = glob_paths(&pat, 0);
            assert_eq!(r, GLOB_NOMATCH);
            // MARK slashes directories.
            let (r, o) = glob_paths(&format!("{ds}/sub*"), GLOB_MARK);
            assert_eq!((r, o.as_slice()), (0, [format!("{ds}/sub/")].as_slice()));
            let (r, o) = glob_paths(&format!("{ds}/sub*"), 0);
            assert_eq!((r, o.as_slice()), (0, [format!("{ds}/sub")].as_slice()));
            // APPEND accumulates; DOOFFS reserves null slots.
            let mut g: glob_t = core::mem::zeroed();
            let p1 = cs(&format!("{ds}/alpha.txt"));
            assert_eq!(glob(p1.as_ptr(), 0, None, &mut g), 0);
            assert_eq!(g.gl_pathc, 1);
            let p2 = cs(&format!("{ds}/beta.txt"));
            assert_eq!(glob(p2.as_ptr(), GLOB_APPEND, None, &mut g), 0);
            assert_eq!(g.gl_pathc, 2);
            globfree(&mut g);
            let mut g2: glob_t = core::mem::zeroed();
            g2.gl_offs = 2;
            let p3 = cs(&format!("{ds}/alpha.txt"));
            assert_eq!(glob(p3.as_ptr(), GLOB_DOOFFS, None, &mut g2), 0);
            assert_eq!(g2.gl_pathc, 1);
            assert!((*g2.gl_pathv.add(0)).is_null());
            assert!((*g2.gl_pathv.add(1)).is_null());
            assert!(!(*g2.gl_pathv.add(2)).is_null());
            globfree(&mut g2);
            rm_file(&d, "alpha.txt");
            rm_file(&d, "beta.txt");
            rm_file(&d, "gamma.log");
            rm_file(&d.join("sub"), "delta.txt");
            rm_dir(&d.join("sub"));
            rm_dir(&d);
        }
    }

    #[test]
    fn glob_tilde_and_errfunc() {
        unsafe {
            let home = std::env::var("HOME").unwrap();
            let (r, o) = glob_paths("~", GLOB_TILDE);
            assert_eq!((r, o.as_slice()), (0, [home].as_slice()));
            // errfunc fires on an unreadable intermediate directory.
            static ECALLS: AtomicU32 = AtomicU32::new(0);
            unsafe extern "C" fn ecb(_p: *const c_char, _e: c_int) -> c_int {
                ECALLS.fetch_add(1, Ordering::SeqCst);
                0
            }
            ECALLS.store(0, Ordering::SeqCst);
            let mut g: glob_t = core::mem::zeroed();
            let p = cs("/tmp/zlibc-rx9c4-no-such-dir-xyz/*");
            let r = glob(p.as_ptr(), GLOB_ERR, Some(ecb), &mut g);
            assert_eq!(r, GLOB_ABORTED);
            assert_eq!(ECALLS.load(Ordering::SeqCst), 1);
            globfree(&mut g);
        }
    }

    unsafe fn word_list(s: &str, flags: c_int) -> (c_int, Vec<String>) {
        unsafe {
            let mut we: wordexp_t = core::mem::zeroed();
            let p = cs(s);
            let r = wordexp(p.as_ptr(), &mut we, flags);
            let mut out = Vec::new();
            if r == 0 {
                let mut k = 0;
                while k < we.we_wordc {
                    let w = *we.we_wordv.add(we.we_offs.wrapping_add(k));
                    out.push(CStr::from_ptr(w).to_string_lossy().into_owned());
                    k += 1;
                }
            }
            wordfree(&mut we);
            (r, out)
        }
    }

    #[test]
    fn wordexp_tilde_vars_quotes() {
        unsafe {
            let (r, o) = word_list("alpha beta", 0);
            assert_eq!(
                (r, o.as_slice()),
                (0, [String::from("alpha"), String::from("beta")].as_slice())
            );
            let (r, o) = word_list("a'b c'd \"e f\" g", 0);
            assert_eq!(
                (r, o.as_slice()),
                (
                    0,
                    [
                        String::from("ab cd"),
                        String::from("e f"),
                        String::from("g")
                    ]
                    .as_slice()
                )
            );
            let home = std::env::var("HOME").unwrap();
            let (r, o) = word_list("~/x", 0);
            assert_eq!((r, o.as_slice()), (0, [format!("{home}/x")].as_slice()));
            let (r, o) = word_list("$HOME", 0);
            assert_eq!((r, o.as_slice()), (0, [home].as_slice()));
            let (r, _) = word_list("$ZLIC_RX_NOPE_9C4", WRDE_UNDEF);
            assert_eq!(r, WRDE_BADVAL);
            let (r, o) = word_list("$ZLIC_RX_NOPE_9C4", 0);
            assert_eq!((r, o.len()), (0, 0));
            let (r, _) = word_list("'abc", 0);
            assert_eq!(r, WRDE_SYNTAX);
        }
    }

    #[test]
    fn wordexp_nocmd_rejection() {
        unsafe {
            let (r, _) = word_list("$(echo hi)", WRDE_NOCMD);
            assert_eq!(r, WRDE_CMDSUB);
            let (r, _) = word_list("`echo hi`", WRDE_NOCMD);
            assert_eq!(r, WRDE_CMDSUB);
            let (r, _) = word_list("a|b", WRDE_NOCMD);
            assert_eq!(r, WRDE_BADCHAR);
            // APPEND accumulates across calls.
            let mut we: wordexp_t = core::mem::zeroed();
            let a = cs("one");
            let b = cs("two");
            assert_eq!(wordexp(a.as_ptr(), &mut we, 0), 0);
            assert_eq!(wordexp(b.as_ptr(), &mut we, WRDE_APPEND), 0);
            assert_eq!(we.we_wordc, 2);
            wordfree(&mut we);
        }
    }

    static FHITS: std::sync::Mutex<Vec<(String, c_int, c_int, c_int)>> =
        std::sync::Mutex::new(Vec::new());

    unsafe extern "C" fn fcb(
        path: *const c_char,
        _st: *const crate::stat::Stat,
        typ: c_int,
        f: *mut FTW,
    ) -> c_int {
        unsafe {
            let p = CStr::from_ptr(path).to_string_lossy().into_owned();
            FHITS.lock().unwrap().push((p, typ, (*f).base, (*f).level));
            0
        }
    }

    fn ftw_tree(tag: &str) -> std::path::PathBuf {
        let d = uniq(tag);
        std::fs::write(d.join("a.txt"), b"x").unwrap();
        let s1 = d.join("sub1");
        std::fs::create_dir_all(&s1).unwrap();
        std::fs::write(s1.join("b.txt"), b"x").unwrap();
        let s2 = s1.join("sub2");
        std::fs::create_dir_all(&s2).unwrap();
        std::fs::write(s2.join("c.txt"), b"x").unwrap();
        d
    }

    #[test]
    fn ftw_counts_three_level_tree() {
        unsafe {
            let d = ftw_tree("ftw1");
            let root = cs(d.to_string_lossy().as_ref());
            FHITS.lock().unwrap().clear();
            let r = nftw(root.as_ptr(), Some(fcb), 16, FTW_PHYS);
            assert_eq!(r, 0);
            let hits = FHITS.lock().unwrap().clone();
            assert_eq!(hits.len(), 6);
            // Every entry: base points at its basename, levels 0..3.
            for (p, _, base, level) in &hits {
                let b = p.rsplit('/').next().unwrap();
                assert_eq!(&p[*base as usize..], b, "base for {p}");
                assert!((0..4).contains(level), "level for {p}");
            }
            let n_d = hits.iter().filter(|h| h.1 == FTW_D).count();
            let n_f = hits.iter().filter(|h| h.1 == FTW_F).count();
            assert_eq!((n_d, n_f), (3, 3));
            // ftw() wrapper agrees.
            FHITS.lock().unwrap().clear();
            let r = ftw(root.as_ptr(), None, 16);
            assert_eq!(r, 0);
            // nopenfd caps the descent depth (musl shape).
            FHITS.lock().unwrap().clear();
            let r = nftw(root.as_ptr(), Some(fcb), 1, FTW_PHYS);
            assert_eq!(r, 0);
            assert_eq!(FHITS.lock().unwrap().len(), 3);
            // FTW_DEPTH visits the root last.
            FHITS.lock().unwrap().clear();
            let r = nftw(root.as_ptr(), Some(fcb), 16, FTW_PHYS | FTW_DEPTH);
            assert_eq!(r, 0);
            let hits = FHITS.lock().unwrap().clone();
            assert_eq!(hits.len(), 6);
            assert_eq!(hits[5].1, FTW_DP);
            assert!(hits[5]
                .0
                .ends_with(d.file_name().unwrap().to_str().unwrap()));
            rm_file(&d, "a.txt");
            rm_file(&d.join("sub1"), "b.txt");
            rm_file(&d.join("sub1").join("sub2"), "c.txt");
            rm_dir(&d.join("sub1").join("sub2"));
            rm_dir(&d.join("sub1"));
            rm_dir(&d);
        }
    }

    #[test]
    fn basename_dirname_edges() {
        unsafe {
            let bn: &[(&str, &str)] = &[
                ("/usr/lib/", "lib"),
                ("/usr/lib", "lib"),
                ("/", "/"),
                ("a", "a"),
                ("a/b/c", "c"),
                ("", "."),
            ];
            for (inp, want) in bn {
                let mut v = Vec::from(inp.as_bytes());
                v.push(0);
                let r = basename(v.as_mut_ptr() as *mut c_char);
                let got = CStr::from_ptr(r).to_bytes();
                assert_eq!(got, want.as_bytes(), "basename({inp:?})");
            }
            let r = basename(core::ptr::null_mut());
            assert_eq!(CStr::from_ptr(r).to_bytes(), b".");
            let dn: &[(&str, &str)] = &[
                ("/usr/lib", "/usr"),
                ("/usr/", "/"),
                ("/", "/"),
                ("a", "."),
                ("a/", "."),
                ("a/b", "a"),
                ("a/b/", "a"),
                ("", "."),
            ];
            for (inp, want) in dn {
                let mut v = Vec::from(inp.as_bytes());
                v.push(0);
                let r = dirname(v.as_mut_ptr() as *mut c_char);
                let got = CStr::from_ptr(r).to_bytes();
                assert_eq!(got, want.as_bytes(), "dirname({inp:?})");
            }
            let r = dirname(core::ptr::null_mut());
            assert_eq!(CStr::from_ptr(r).to_bytes(), b".");
        }
    }
}
