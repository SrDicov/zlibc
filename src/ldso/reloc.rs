//! x86_64 relocation application (`do_relocs`).
//!
//! Clean reimplementation of musl `do_relocs` (`ldso/dynlink.c:383-530`)
//! with the lookup half it depends on (`sysv_lookup`, `gnu_lookup`,
//! `gnu_lookup_filtered`, `find_sym2`/`find_sym`, `dynlink.c:265-351`).
//! Zero musl code is copied; every non-obvious rule cites its `file:line`.
//!
//! x86_64 type mapping from `arch/x86_64/reloc.h:3-13` (numbers in
//! `include/elf.h:3004-3047`); `R_TYPE`/`R_SYM` are the 64-bit arms of
//! `src/internal/dynlink.h:21-22`, `laddr` is `ldso/dynlink.c:217`
//! (non-FDPIC). Stores are plain writes like musl's, NOT volatile —
//! musl's barriers suffice on real hardware (`docs/plan.md`, Wave 2).
//!
//! Divergences from musl, each marked `shortcut:` at the site:
//! - Lookup starts at `dso`: musl threads the app `head` and starts
//!   `COPY` at `head->syms_next`; no loader-global chain exists yet.
//! - `REL` (stride 2) addends are re-read from the slot; musl's
//!   save/reuse dance is ldso-self-only (`dynlink.c:402-407`).
//! - `static_tls_cnt` (`dynlink.c:154`) lives here until the loader owns
//!   it. x86_64 defines neither `TLS_ABOVE_TP` nor `DTP_OFFSET` (default
//!   0, `src/internal/pthread_impl.h:113-114`).
//! - `IRELATIVE` has no musl arm (it would hit musl's default-fatal);
//!   resolved glibc-style per the Wave 2 contract.
//! - `get_lfs64` (`dynlink.c:354-381`) is a not-found stub until the
//!   loader owns the namespace head.
//! - Fatal paths write to fd 2 then `exit_group`; musl reports via
//!   `error()` and `longjmp`s (no `setjmp` yet).
//! - Dynamic-DTV `TLSDESC` dies the same fatal way (musl `malloc`s a
//!   `td_index`; no allocator until Wave 4). Static-TLS `TLSDESC`
//!   stores a placeholder resolver until C1 provides `__tlsdesc_static`.
//! - No `FUNCDESC` arms: `DL_FDPIC` is 0 on x86_64, so musl's are
//!   unreachable here; such types hit the unsupported-type fatal.

use core::ffi::{c_char, c_void};

use core::mem::{size_of, transmute};

use core::sync::atomic::{AtomicUsize, Ordering};

use super::dso::{gnu_hash, sysv_hash};

use super::dso::Dso;

use super::Elf64Sym;

// ---- Raw numbers (musl arch/x86_64/bits/syscall.h.in) ----------------------

// TODO: generate from arch bits/syscall.h, same as the ldso/mod.rs copies.
const SYS_WRITE: usize = 1;
const SYS_EXIT_GROUP: usize = 231;

// ---- x86_64 relocation types (musl arch/x86_64/reloc.h:3-13) ---------------

const REL_NONE: u32 = 0; // R_X86_64_NONE (elf.h:3004)
const REL_SYMBOLIC: u32 = 1; // R_X86_64_64
const REL_OFFSET32: u32 = 2; // R_X86_64_PC32
const REL_COPY: u32 = 5; // R_X86_64_COPY
const REL_GOT: u32 = 6; // R_X86_64_GLOB_DAT
const REL_PLT: u32 = 7; // R_X86_64_JUMP_SLOT
const REL_RELATIVE: u32 = 8; // R_X86_64_RELATIVE
const REL_DTPMOD: u32 = 16; // R_X86_64_DTPMOD64
const REL_DTPOFF: u32 = 17; // R_X86_64_DTPOFF64
const REL_TPOFF: u32 = 18; // R_X86_64_TPOFF64
const REL_TLSDESC: u32 = 36; // R_X86_64_TLSDESC

// Contract extension, NOT musl: R_X86_64_IRELATIVE (elf.h:3047). musl has
// no arm for it (default-fatal); we call the resolver glibc-style.
const REL_IRELATIVE: u32 = 37;

// Unmatchable defaults, mirroring musl's negative-enum trick
// (src/internal/dynlink.h:28-46): no x86_64 type maps to these, but the
// arms keep the switch a line-for-line mirror of musl's.
const REL_OFFSET: u32 = u32::MAX;
const REL_USYMBOLIC: u32 = u32::MAX - 1;
const REL_SYM_OR_REL: u32 = u32::MAX - 2;
const REL_TPOFF_NEG: u32 = u32::MAX - 3;

// ---- ELF symbol bits (musl include/elf.h) ----------------------------------

const STB_LOCAL: u8 = 0; // elf.h:499
const STB_WEAK: u8 = 2; // elf.h:501
const STT_TLS: u8 = 6; // elf.h:515
const SHN_UNDEF: u16 = 0; // elf.h:355
                          // musl OK_TYPES / OK_BINDS (ldso/dynlink.c:308-309).
const OK_TYPES: u32 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 5) | (1 << 6);
const OK_BINDS: u32 = (1 << 1) | (1 << 2) | (1 << 10);
// x86_64 defines no DTP_OFFSET: default 0 (pthread_impl.h:113-114).
const DTP_OFFSET: usize = 0;
// x86_64 defines no TLSDESC_BACKWARDS: default 0 (dynlink.h:76-78).
const TLSDESC_BACKWARDS: usize = 0;

// ---- Loader state owned here until reloc_all lands -------------------------

// musl `static_tls_cnt` (ldso/dynlink.c:154): modules with
// `tls_id <= cnt` are statically placed at boot. Atomic only to avoid
// `static mut` aliasing rules; relaxed ops compile to plain loads.
static STATIC_TLS_CNT: AtomicUsize = AtomicUsize::new(0);

/// Publish the static-TLS module count. The loader/C1 calls this during
/// single-threaded boot, before any relocated code can run concurrently.
pub fn set_static_tls_cnt(n: usize) {
    STATIC_TLS_CNT.store(n, Ordering::Relaxed);
}

// ---- r_info field extraction (musl dynlink.h:21-22, 64-bit arms) -----------

pub(crate) fn r_type(info: usize) -> u32 {
    (info & 0xffff_ffff) as u32
}

fn r_sym(info: usize) -> u32 {
    (info >> 32) as u32
}

// ---- Tiny libc-free helpers -------------------------------------------------

/// Byte-wise NUL-terminated equality (core-only `strcmp`).
///
/// # Safety
///
/// Both pointers must address valid NUL-terminated strings.
unsafe fn streq(a: *const c_char, b: *const c_char) -> bool {
    unsafe {
        let mut i = 0usize;
        loop {
            let x = *(a as *const u8).add(i);
            let y = *(b as *const u8).add(i);
            if x != y {
                return false;
            }
            if x == 0 {
                return true;
            }
            i += 1;
        }
    }
}

/// NUL-terminated length.
///
/// # Safety
///
/// `s` must address a valid NUL-terminated string.
unsafe fn c_strlen(s: *const c_char) -> usize {
    unsafe {
        let mut n = 0usize;
        while *(s as *const u8).add(n) != 0 {
            n += 1;
        }
        n
    }
}

/// Best-effort write of `len` bytes to `fd` via raw `SYS_write`.
///
/// # Safety
///
/// `p` must be valid for `len` byte reads.
unsafe fn write_all(fd: usize, p: *const u8, len: usize) {
    let mut off = 0usize;
    while off < len {
        let r = crate::__syscall!(SYS_WRITE, fd, p.wrapping_add(off), len - off);
        if r <= 0 {
            break;
        }
        off += r as usize;
    }
}

const FATAL_PREFIX: &[u8] = b"zlibc: reloc ";
const FATAL_SEP: &[u8] = b": ";
const FATAL_NL: &[u8] = b"\n";

/// Diagnostic to fd 2 (`dso: detail[: sym]`) then `exit_group(127)`.
/// Mirrors the outcome of musl's `error()` + `longjmp(*rtld_fail, 1)`.
/// shortcut: no setjmp/longjmp yet, so the process dies instead of
/// unwinding to the loader.
///
/// # Safety
///
/// Both pointers must be null or address valid NUL-terminated strings.
/// Never returns.
unsafe fn fatal(dso: *const c_char, sym: *const c_char, detail: &[u8]) -> ! {
    unsafe {
        write_all(2, FATAL_PREFIX.as_ptr(), FATAL_PREFIX.len());
        if !dso.is_null() {
            write_all(2, dso as *const u8, c_strlen(dso));
        }
        write_all(2, FATAL_SEP.as_ptr(), FATAL_SEP.len());
        write_all(2, detail.as_ptr(), detail.len());
        if !sym.is_null() {
            write_all(2, FATAL_SEP.as_ptr(), FATAL_SEP.len());
            write_all(2, sym as *const u8, c_strlen(sym));
        }
        write_all(2, FATAL_NL.as_ptr(), FATAL_NL.len());
        // Direct calls, not the macro: the macro wraps itself in `unsafe`,
        // which would be redundant inside this block (unused_unsafe).
        crate::syscall::syscall_ret(crate::syscall::syscall1(SYS_EXIT_GROUP, 127));
        core::hint::unreachable_unchecked()
    }
}

// ---- TLSDESC placeholder ----------------------------------------------------

/// Loud abort for static-TLS `TLSDESC` slot 0 (musl resolves
/// `__tlsdesc_static` from `src/ldso/x86_64/tlsdesc.s`): the old code
/// stored a placeholder returning 0 into live slots, silently corrupting
/// thread addresses. Any call reaching here traps instead of computing
/// garbage; a real resolver replaces this when dynamic TLS grows one.
extern "C" fn tlsdesc_static() -> isize {
    unsafe {
        core::arch::asm!("ud2", options(noreturn));
    }
}

// ---- Symbol lookup (musl ldso/dynlink.c:265-351) ----------------------------

/// musl `sysv_lookup` (`dynlink.c:265-277`), reimplemented.
///
/// # Safety
///
/// `dso` must be valid with mapped `syms`/`strings`/`hashtab` (and
/// `versym`, unless null); `s` must be NUL-terminated.
unsafe fn sysv_lookup(s: *const c_char, h: u32, dso: *const Dso) -> *mut Elf64Sym {
    unsafe {
        let syms = (*dso).syms;
        let hashtab = (*dso).hashtab;
        let strings = (*dso).strings;
        let nbucket = *hashtab;
        let mut i = *hashtab.add(2 + (h % nbucket) as usize);
        while i != 0 {
            let sym = syms.add(i as usize);
            if ((*dso).versym.is_null() || *(*dso).versym.add(i as usize) >= 0)
                && streq(s, strings.add((*sym).st_name as usize))
            {
                return sym;
            }
            i = *hashtab.add(2 + nbucket as usize + i as usize);
        }
        core::ptr::null_mut()
    }
}

/// musl `gnu_lookup` (`dynlink.c:279-299`), reimplemented. `hashtab[1]`
/// is the symbol offset, `[2]` the bloom size in words, `[3]` the shift.
///
/// # Safety
///
/// Same table validity as [`sysv_lookup`].
unsafe fn gnu_lookup(
    h1: u32,
    hashtab: *const u32,
    dso: *const Dso,
    s: *const c_char,
) -> *mut Elf64Sym {
    unsafe {
        let nbuckets = *hashtab;
        let symoff = *hashtab.add(1);
        let bloom_words = *hashtab.add(2) as usize * (size_of::<usize>() / 4);
        let buckets = hashtab.add(4 + bloom_words);
        let mut i = *buckets.add((h1 % nbuckets) as usize);
        if i == 0 {
            return core::ptr::null_mut();
        }
        let mut hashval = buckets.add(nbuckets as usize + (i - symoff) as usize);
        let want = h1 | 1;
        loop {
            let h2 = *hashval;
            hashval = hashval.add(1);
            let sym = (*dso).syms.add(i as usize);
            if want == (h2 | 1)
                && ((*dso).versym.is_null() || *(*dso).versym.add(i as usize) >= 0)
                && streq(s, (*dso).strings.add((*sym).st_name as usize))
            {
                return sym;
            }
            if (h2 & 1) != 0 {
                break;
            }
            i += 1;
        }
        core::ptr::null_mut()
    }
}

/// musl `gnu_lookup_filtered` (`dynlink.c:301-306`), reimplemented.
///
/// # Safety
///
/// Same table validity as [`sysv_lookup`].
unsafe fn gnu_lookup_filtered(
    h1: u32,
    hashtab: *const u32,
    dso: *const Dso,
    s: *const c_char,
    fofs: usize,
    fmask: usize,
) -> *mut Elf64Sym {
    unsafe {
        let bloom_size = *hashtab.add(2) as usize;
        let shift = *hashtab.add(3);
        let words = hashtab.add(4) as *const usize;
        let f = *words.add(fofs & (bloom_size - 1));
        if (f & fmask) == 0 {
            return core::ptr::null_mut();
        }
        if ((f >> ((h1 >> shift) % usize::BITS)) & 1) == 0 {
            return core::ptr::null_mut();
        }
        gnu_lookup(h1, hashtab, dso, s)
    }
}

/// Minimal mirror of musl `find_sym2`/`find_sym` (`dynlink.c:312-351`,
/// `use_deps = 0`): walk `syms_next` from `head`, GNU-hash first else
/// sysv, with the same need_def / `SHN_UNDEF` / null-value / type / bind
/// filters (`ARCH_SYM_REJECT_UND` is 0 on x86_64).
///
/// # Safety
///
/// Every `Dso` in the chain must satisfy the table validity of
/// [`sysv_lookup`]; `s` must be NUL-terminated.
unsafe fn find_sym(head: *mut Dso, s: *const c_char, need_def: bool) -> (*mut Dso, *mut Elf64Sym) {
    unsafe {
        let gh = gnu_hash(s);
        let mut h: u32 = 0;
        let mut hashed = false;
        let mut p = head;
        while !p.is_null() {
            let sym = if !(*p).ghashtab.is_null() {
                let fofs = (gh as usize) / (usize::BITS as usize);
                let fmask = 1usize << ((gh as usize) % (usize::BITS as usize));
                gnu_lookup_filtered(gh, (*p).ghashtab, p, s, fofs, fmask)
            } else {
                if !hashed {
                    h = sysv_hash(s);
                    hashed = true;
                }
                sysv_lookup(s, h, p)
            };
            if !sym.is_null() {
                let ty = (*sym).st_info & 0xf;
                let bind = (*sym).st_info >> 4;
                let undef_no_def = (*sym).st_shndx == SHN_UNDEF && (need_def || ty == STT_TLS);
                let null_no_tls = (*sym).st_value == 0 && ty != STT_TLS;
                if !undef_no_def
                    && !null_no_tls
                    && ((1u32 << (ty as u32)) & OK_TYPES) != 0
                    && ((1u32 << (bind as u32)) & OK_BINDS) != 0
                {
                    return (p, sym);
                }
            }
            p = (*p).syms_next;
        }
        (core::ptr::null_mut(), core::ptr::null_mut())
    }
}

/// musl `get_lfs64` (`dynlink.c:354-381`) maps `foo64` names to `foo`.
/// shortcut: always "not found"; the table + ldso lookup land with the
/// loader follow-up that owns the namespace head.
fn get_lfs64(_name: *const c_char) -> (*mut Dso, *mut Elf64Sym) {
    (core::ptr::null_mut(), core::ptr::null_mut())
}

// ---- Relocation application (musl ldso/dynlink.c:383-530) ------------------

/// Apply one REL (`stride` 2) or RELA (`stride` 3) table to `dso`.
///
/// Addends: RELA takes `rel[2]`; REL `GOT`/`PLT`/`COPY` use 0, anything
/// else re-reads `*reloc_addr`. `sym_index == 0` means "no symbol"
/// (`RELATIVE`/`SYM_OR_REL` fall back to `base + addend`). `STB_LOCAL`
/// resolves in place; otherwise [`find_sym`] runs from `head` (the
/// namespace start, so the executable interposes like musl — never from
/// `dso` itself), then [`get_lfs64`]. `skip_relative` skips RELATIVE
/// entries (6B self-image: `_dlstart` already applied them; musl skips
/// `IS_RELATIVE` for `&ldso`, dynlink.c:400-408). Unresolved `PLT`/`GOT`
/// with `dso->lazy` set are saved as `(off, info, addend)` triples for
/// `redo_lazy_relocs` (`dynlink.c:439-446`, sized at `:2090-2105`).
/// Anything else unresolved-and-not-weak-undef is fatal, as are
/// initial-exec TLS resolving to a dynamic module and dynamic-DTV
/// `TLSDESC`.
///
/// # Safety
///
/// `head` must start a valid `syms_next` chain; `dso` must be valid with
/// a mapped image at `base`; `rel` must hold `rel_size` bytes (an exact
/// multiple of `stride` words — debug-asserted, musl trusts the linker);
/// `dso->lazy` (when set) must hold `lazy_cnt` triples plus whatever
/// this call appends; `COPY` entries must reference a symbol; TLS
/// entries must resolve (weak-undef TLS is a link error musl rejects
/// too). Never call the fatal paths from tests: they exit the process.
pub unsafe fn do_relocs(
    head: *mut Dso,
    dso: *mut Dso,
    rel: *mut usize,
    rel_size: usize,
    stride: usize,
    skip_relative: bool,
) {
    unsafe {
        let base = (*dso).base;
        let syms = (*dso).syms;
        let strings = (*dso).strings;
        let step = stride.wrapping_mul(size_of::<usize>());
        debug_assert!(
            rel_size.is_multiple_of(step),
            "relocation table size must be a stride multiple"
        );
        let mut p = rel;
        let mut left = rel_size;
        while left != 0 {
            let r_off = *p.add(0);
            let r_info = *p.add(1);
            let ty = r_type(r_info);
            if ty == REL_NONE {
                // musl dynlink.c:410: skip before touching the slot.
                p = p.add(stride);
                left -= step;
                continue;
            }
            if skip_relative && ty == REL_RELATIVE {
                // 6B self-image (see fn docs): already applied.
                p = p.add(stride);
                left -= step;
                continue;
            }
            let addr = base.wrapping_add(r_off) as *mut usize;
            let addend = if stride > 2 {
                *p.add(2)
            } else if ty == REL_GOT || ty == REL_PLT || ty == REL_COPY {
                0
            } else {
                // shortcut: plain re-read; musl's save/reuse is
                // ldso-self-only (dynlink.c:402-407).
                *addr
            };

            let sym_idx = r_sym(r_info);
            let mut def_dso: *mut Dso;
            let mut def_sym: *mut Elf64Sym;
            let mut ref_sym: *mut Elf64Sym = core::ptr::null_mut();
            let mut name: *const c_char = core::ptr::null();
            if sym_idx != 0 {
                let s = syms.add(sym_idx as usize);
                ref_sym = s;
                name = strings.add((*s).st_name as usize);
                if (*s).st_info >> 4 == STB_LOCAL {
                    def_dso = dso;
                    def_sym = s;
                } else {
                    // Namespace head first (musl interposition): an
                    // executable definition wins over the DSO's own.
                    (def_dso, def_sym) = find_sym(head, name, ty == REL_PLT);
                    if def_sym.is_null() {
                        (def_dso, def_sym) = get_lfs64(name);
                    }
                    if def_sym.is_null()
                        && ((*s).st_shndx != SHN_UNDEF || (*s).st_info >> 4 != STB_WEAK)
                    {
                        if !(*dso).lazy.is_null() && (ty == REL_PLT || ty == REL_GOT) {
                            let slot = (*dso).lazy.add((*dso).lazy_cnt * 3);
                            *slot.add(0) = r_off;
                            *slot.add(1) = r_info;
                            *slot.add(2) = addend;
                            (*dso).lazy_cnt += 1;
                            p = p.add(stride);
                            left -= step;
                            continue;
                        }
                        fatal((*dso).name, name, b"symbol not found");
                    }
                }
            } else {
                def_dso = dso;
                def_sym = core::ptr::null_mut();
            }

            // Weak-undef TLS with no definition is a link error (musl
            // rejects it too): fail loud instead of null-dereferencing
            // the arms below.
            if def_sym.is_null()
                && matches!(
                    ty,
                    REL_DTPMOD | REL_DTPOFF | REL_TPOFF | REL_TPOFF_NEG | REL_TLSDESC
                )
            {
                fatal((*dso).name, name, b"tls symbol not found");
            }

            let sym_val = if def_sym.is_null() {
                0
            } else {
                (*def_dso).base.wrapping_add((*def_sym).st_value as usize) as usize
            };
            let tls_val = if def_sym.is_null() {
                0
            } else {
                (*def_sym).st_value as usize
            };

            // musl dynlink.c:461-465 (null-guard added: failed weak-undef
            // lookups leave def_dso null, where musl would crash).
            if (ty == REL_TPOFF || ty == REL_TPOFF_NEG)
                && !def_dso.is_null()
                && (*def_dso).tls_id > STATIC_TLS_CNT.load(Ordering::Relaxed)
            {
                fatal((*dso).name, name, b"initial-exec TLS in dynamic module");
            }

            match ty {
                REL_OFFSET => {
                    // musl fallthrough: addend -= reloc_addr, then the
                    // symbolic store below (dynlink.c:469-475).
                    *addr = sym_val.wrapping_add(addend.wrapping_sub(addr as usize));
                }
                REL_SYMBOLIC | REL_GOT | REL_PLT => {
                    *addr = sym_val.wrapping_add(addend);
                }
                REL_USYMBOLIC => {
                    let v = sym_val.wrapping_add(addend);
                    crate::mem::memcpy(
                        addr as *mut c_void,
                        (&v as *const usize) as *const c_void,
                        size_of::<usize>(),
                    );
                }
                REL_RELATIVE => {
                    *addr = (base as usize).wrapping_add(addend);
                }
                REL_SYM_OR_REL => {
                    *addr = if !ref_sym.is_null() {
                        sym_val.wrapping_add(addend)
                    } else {
                        (base as usize).wrapping_add(addend)
                    };
                }
                REL_COPY => {
                    crate::mem::memcpy(
                        addr as *mut c_void,
                        sym_val as *const c_void,
                        (*ref_sym).st_size as usize,
                    );
                }
                REL_OFFSET32 => {
                    *(addr as *mut u32) =
                        (sym_val.wrapping_add(addend).wrapping_sub(addr as usize)) as u32;
                }
                REL_DTPMOD => {
                    *addr = (*def_dso).tls_id;
                }
                REL_DTPOFF => {
                    // musl dynlink.c:506 (DTP_OFFSET is 0 on x86_64).
                    *addr = tls_val.wrapping_add(addend).wrapping_sub(DTP_OFFSET);
                }
                REL_TPOFF => {
                    // No TLS_ABOVE_TP on x86_64 (dynlink.c:512-514).
                    *addr = tls_val
                        .wrapping_sub((*def_dso).tls.offset)
                        .wrapping_add(addend);
                }
                REL_TPOFF_NEG => {
                    *addr = (*def_dso)
                        .tls
                        .offset
                        .wrapping_sub(tls_val)
                        .wrapping_add(addend);
                }
                REL_IRELATIVE => {
                    // Contract-only (musl would fatal): resolve like glibc,
                    // `((addr)(base + addend))()`.
                    let r = (base as usize).wrapping_add(addend);
                    let f = transmute::<usize, extern "C" fn() -> usize>(r);
                    *addr = f();
                }
                REL_TLSDESC => {
                    // musl dynlink.c:521 (`!TLSDESC_BACKWARDS` is 1 here).
                    let a = if stride < 3 {
                        *addr.add(1 - TLSDESC_BACKWARDS)
                    } else {
                        addend
                    };
                    if (*def_dso).tls_id > STATIC_TLS_CNT.load(Ordering::Relaxed) {
                        // shortcut: musl mallocs td_index (dynlink.c:522-536);
                        // no allocator until Wave 4.
                        fatal((*dso).name, name, b"dynamic TLSDESC needs allocator");
                    }
                    let desc: usize = tlsdesc_static as *const () as usize;
                    *addr.add(0) = desc;
                    *addr.add(1) = tls_val.wrapping_sub((*def_dso).tls.offset).wrapping_add(a);
                }
                _ => {
                    fatal((*dso).name, name, b"unsupported relocation type");
                }
            }
            p = p.add(stride);
            left -= step;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::eprintln;

    /// `r_info` word: musl `ELF64_R_INFO` (include/elf.h:573).
    fn info(sym: usize, ty: u32) -> usize {
        (sym << 32) | (ty as usize)
    }

    /// One `Elf64Sym` literal (`bind_ty` packs bind + type, e.g.
    /// `0x12` = GLOBAL + FUNC).
    fn sym(name: u32, bind_ty: u8, shndx: u16, val: u64, size: u64) -> Elf64Sym {
        Elf64Sym {
            st_name: name,
            st_info: bind_ty,
            st_other: 0,
            st_shndx: shndx,
            st_value: val,
            st_size: size,
        }
    }

    /// Slot address `base + off`.
    fn at(base: *mut u8, off: usize) -> *mut usize {
        base.wrapping_add(off) as *mut usize
    }

    /// Point a zeroed `Dso` at `base` plus caller-owned tables.
    ///
    /// # Safety
    ///
    /// All pointers must stay valid for the caller's test body.
    unsafe fn wire(
        dso: *mut Dso,
        base: *mut u8,
        symtbl: *mut Elf64Sym,
        strs: *mut c_char,
        ht: *mut u32,
    ) {
        unsafe {
            (*dso).base = base;
            (*dso).syms = symtbl;
            (*dso).strings = strs;
            (*dso).hashtab = ht;
        }
    }

    /// Single-bucket sysv table chaining `syms[1..=n]`; `ht` needs
    /// `4 + n` words (`[nbucket, nchain, bucket, chains...]`).
    ///
    /// # Safety
    ///
    /// `ht` must be valid for `4 + n` word writes.
    unsafe fn sysv_chain(ht: *mut u32, n: u32) {
        unsafe {
            *ht.add(0) = 1;
            *ht.add(1) = n + 1;
            *ht.add(2) = if n == 0 { 0 } else { 1 };
            let mut i = 1u32;
            while i <= n {
                *ht.add(3 + i as usize) = if i == n { 0 } else { i + 1 };
                i += 1;
            }
        }
    }

    #[test]
    fn relative_applies_base_plus_addend() {
        let mut mem = [0u8; 64];
        let base = mem.as_mut_ptr();
        let mut dso: Dso = unsafe { core::mem::zeroed() };
        dso.base = base;
        let mut rela = [0x10usize, info(0, REL_RELATIVE), 0x20];
        unsafe {
            do_relocs(
                &mut dso as *mut Dso,
                &mut dso as *mut Dso,
                rela.as_mut_ptr(),
                3 * size_of::<usize>(),
                3,
                false,
            )
        };
        assert_eq!(unsafe { *at(base, 0x10) }, base as usize + 0x20);
    }

    #[test]
    fn symbolic_self_def_adds_sym_and_addend() {
        let mut mem = [0u8; 64];
        let base = mem.as_mut_ptr();
        unsafe {
            *at(base, 0x08) = 0xdead;
        }
        let mut syms = [sym(0, 0, 0, 0, 0), sym(0, 0x12, 1, 0x20, 0)];
        let mut strs = *b"foo\0";
        let mut ht = [0u32; 5];
        let mut dso: Dso = unsafe { core::mem::zeroed() };
        unsafe {
            sysv_chain(ht.as_mut_ptr(), 1);
            wire(
                &mut dso as *mut Dso,
                base,
                syms.as_mut_ptr(),
                strs.as_mut_ptr() as *mut c_char,
                ht.as_mut_ptr(),
            );
        }
        let mut rela = [0x08usize, info(1, REL_SYMBOLIC), 5];
        unsafe {
            do_relocs(
                &mut dso as *mut Dso,
                &mut dso as *mut Dso,
                rela.as_mut_ptr(),
                3 * size_of::<usize>(),
                3,
                false,
            )
        };
        assert_eq!(unsafe { *at(base, 0x08) }, base as usize + 0x20 + 5);
    }

    #[test]
    fn got_and_plt_store_sym_plus_addend() {
        let mut mem = [0u8; 64];
        let base = mem.as_mut_ptr();
        // sym 1 "foo": GLOBAL FUNC @0x20; sym 2 "bar": GLOBAL OBJECT @0x30.
        let mut syms = [
            sym(0, 0, 0, 0, 0),
            sym(0, 0x12, 1, 0x20, 0),
            sym(4, 0x11, 1, 0x30, 8),
        ];
        let mut strs = *b"foo\0bar\0";
        let mut ht = [0u32; 6];
        let mut dso: Dso = unsafe { core::mem::zeroed() };
        unsafe {
            sysv_chain(ht.as_mut_ptr(), 2);
            wire(
                &mut dso as *mut Dso,
                base,
                syms.as_mut_ptr(),
                strs.as_mut_ptr() as *mut c_char,
                ht.as_mut_ptr(),
            );
        }
        let mut rela = [
            0x08usize,
            info(1, REL_GOT),
            7,
            0x10usize,
            info(2, REL_PLT),
            0,
        ];
        unsafe {
            do_relocs(
                &mut dso as *mut Dso,
                &mut dso as *mut Dso,
                rela.as_mut_ptr(),
                6 * size_of::<usize>(),
                3,
                false,
            )
        };
        assert_eq!(unsafe { *at(base, 0x08) }, base as usize + 0x20 + 7);
        assert_eq!(unsafe { *at(base, 0x10) }, base as usize + 0x30);
    }

    #[test]
    fn dtpmod_dtpoff_tpoff_use_static_module() {
        // Static-TLS modules (tls_id <= cnt) take the arithmetic paths;
        // the count is left at 1 (no test depends on 0; resetting would
        // race a parallel TLS test into the fatal path).
        set_static_tls_cnt(1);
        let mut mem = [0u8; 64];
        let base = mem.as_mut_ptr();
        // "tlsv": GLOBAL TLS @0x10.
        let mut syms = [sym(0, 0, 0, 0, 0), sym(0, 0x16, 1, 0x10, 4)];
        let mut strs = *b"tlsv\0";
        let mut ht = [0u32; 5];
        let mut dso: Dso = unsafe { core::mem::zeroed() };
        dso.tls.offset = 0x40;
        dso.tls_id = 1;
        unsafe {
            sysv_chain(ht.as_mut_ptr(), 1);
            wire(
                &mut dso as *mut Dso,
                base,
                syms.as_mut_ptr(),
                strs.as_mut_ptr() as *mut c_char,
                ht.as_mut_ptr(),
            );
        }
        let mut rela = [
            0x08usize,
            info(1, REL_DTPMOD),
            0,
            0x10usize,
            info(1, REL_DTPOFF),
            3,
            0x18usize,
            info(1, REL_TPOFF),
            4,
        ];
        unsafe {
            do_relocs(
                &mut dso as *mut Dso,
                &mut dso as *mut Dso,
                rela.as_mut_ptr(),
                9 * size_of::<usize>(),
                3,
                false,
            )
        };
        assert_eq!(unsafe { *at(base, 0x08) }, 1);
        assert_eq!(unsafe { *at(base, 0x10) }, 0x10 + 3);
        assert_eq!(
            unsafe { *at(base, 0x18) },
            0x10usize.wrapping_sub(0x40).wrapping_add(4)
        );
    }

    #[test]
    fn tlsdesc_static_stores_fn_and_offset() {
        set_static_tls_cnt(1);
        let mut mem = [0u8; 64];
        let base = mem.as_mut_ptr();
        let mut syms = [sym(0, 0, 0, 0, 0), sym(0, 0x16, 1, 0x10, 4)];
        let mut strs = *b"tlsv\0";
        let mut ht = [0u32; 5];
        let mut dso: Dso = unsafe { core::mem::zeroed() };
        dso.tls.offset = 0x40;
        dso.tls_id = 1;
        unsafe {
            sysv_chain(ht.as_mut_ptr(), 1);
            wire(
                &mut dso as *mut Dso,
                base,
                syms.as_mut_ptr(),
                strs.as_mut_ptr() as *mut c_char,
                ht.as_mut_ptr(),
            );
        }
        let mut rela = [0x08usize, info(1, REL_TLSDESC), 6];
        unsafe {
            do_relocs(
                &mut dso as *mut Dso,
                &mut dso as *mut Dso,
                rela.as_mut_ptr(),
                3 * size_of::<usize>(),
                3,
                false,
            )
        };
        let want_fn: usize = tlsdesc_static as *const () as usize;
        eprintln!(
            "TLSDESC slot={:x} want_fn={:x} syms={:x} fatal={:x} rtype={}",
            unsafe { *at(base, 0x08) },
            want_fn,
            find_sym as *const () as usize,
            fatal as *const () as usize,
            r_type(rela[1])
        );
        assert_eq!(
            unsafe { *at(base, 0x08) },
            want_fn,
            "tlsdesc slot = {:x}, want_fn = {:x}",
            unsafe { *at(base, 0x08) },
            want_fn
        );
        assert_eq!(
            unsafe { *at(base, 0x10) },
            0x10usize.wrapping_sub(0x40).wrapping_add(6)
        );
    }

    extern "C" fn probe_resolver() -> usize {
        0x1234_5678
    }

    #[test]
    fn irelative_calls_resolver() {
        let mut mem = [0u8; 64];
        let base = mem.as_mut_ptr();
        let mut dso: Dso = unsafe { core::mem::zeroed() };
        dso.base = base;
        let target: usize = probe_resolver as *const () as usize;
        let mut rela = [
            0x18usize,
            info(0, REL_IRELATIVE),
            target.wrapping_sub(base as usize),
        ];
        unsafe {
            do_relocs(
                &mut dso as *mut Dso,
                &mut dso as *mut Dso,
                rela.as_mut_ptr(),
                3 * size_of::<usize>(),
                3,
                false,
            )
        };
        assert_eq!(unsafe { *at(base, 0x18) }, 0x1234_5678);
    }

    #[test]
    fn copy_moves_sized_def() {
        let mut mem = [0u8; 96];
        let base = mem.as_mut_ptr();
        unsafe {
            *at(base, 0x40) = 0x1122_3344_5566_7788;
        }
        // "obj": GLOBAL OBJECT @0x40, 8 bytes.
        let mut syms = [sym(0, 0, 0, 0, 0), sym(0, 0x11, 1, 0x40, 8)];
        let mut strs = *b"obj\0";
        let mut ht = [0u32; 5];
        let mut dso: Dso = unsafe { core::mem::zeroed() };
        unsafe {
            sysv_chain(ht.as_mut_ptr(), 1);
            wire(
                &mut dso as *mut Dso,
                base,
                syms.as_mut_ptr(),
                strs.as_mut_ptr() as *mut c_char,
                ht.as_mut_ptr(),
            );
        }
        let mut rela = [0x08usize, info(1, REL_COPY), 0];
        unsafe {
            do_relocs(
                &mut dso as *mut Dso,
                &mut dso as *mut Dso,
                rela.as_mut_ptr(),
                3 * size_of::<usize>(),
                3,
                false,
            )
        };
        assert_eq!(unsafe { *at(base, 0x08) }, 0x1122_3344_5566_7788);
    }

    #[test]
    fn offset32_stores_truncated_pc_delta() {
        let mut mem = [0u8; 64];
        let base = mem.as_mut_ptr();
        let mut syms = [sym(0, 0, 0, 0, 0), sym(0, 0x12, 1, 0x20, 0)];
        let mut strs = *b"foo\0";
        let mut ht = [0u32; 5];
        let mut dso: Dso = unsafe { core::mem::zeroed() };
        unsafe {
            sysv_chain(ht.as_mut_ptr(), 1);
            wire(
                &mut dso as *mut Dso,
                base,
                syms.as_mut_ptr(),
                strs.as_mut_ptr() as *mut c_char,
                ht.as_mut_ptr(),
            );
        }
        let mut rela = [0x08usize, info(1, REL_OFFSET32), 0x100];
        unsafe {
            do_relocs(
                &mut dso as *mut Dso,
                &mut dso as *mut Dso,
                rela.as_mut_ptr(),
                3 * size_of::<usize>(),
                3,
                false,
            )
        };
        let addr = base as usize + 0x08;
        let want = (base as usize + 0x20 + 0x100 - addr) as u32;
        assert_eq!(unsafe { *(base.wrapping_add(0x08) as *const u32) }, want);
    }

    #[test]
    fn lazy_unresolved_plt_got_saved() {
        let mut mem = [0u8; 64];
        let base = mem.as_mut_ptr();
        unsafe {
            *at(base, 0x08) = 0xaaaa;
            *at(base, 0x10) = 0xbbbb;
        }
        // "missing": GLOBAL FUNC but SHN_UNDEF, and the bucket is empty,
        // so lookup misses while the weak check still demands a definition.
        let mut syms = [sym(0, 0, 0, 0, 0), sym(0, 0x12, 0, 0, 0)];
        let mut strs = *b"missing\0";
        let mut ht = [1u32, 1, 0, 0];
        let mut lazy = [0usize; 8];
        let mut dso: Dso = unsafe { core::mem::zeroed() };
        unsafe {
            wire(
                &mut dso as *mut Dso,
                base,
                syms.as_mut_ptr(),
                strs.as_mut_ptr() as *mut c_char,
                ht.as_mut_ptr(),
            );
        }
        dso.lazy = lazy.as_mut_ptr();
        let i1 = info(1, REL_PLT);
        let i2 = info(1, REL_GOT);
        let mut rela = [0x08usize, i1, 9, 0x10usize, i2, 10];
        unsafe {
            do_relocs(
                &mut dso as *mut Dso,
                &mut dso as *mut Dso,
                rela.as_mut_ptr(),
                6 * size_of::<usize>(),
                3,
                false,
            )
        };
        assert_eq!(dso.lazy_cnt, 2);
        assert_eq!(lazy, [0x08, i1, 9, 0x10, i2, 10, 0, 0]);
        assert_eq!(unsafe { *at(base, 0x08) }, 0xaaaa);
        assert_eq!(unsafe { *at(base, 0x10) }, 0xbbbb);
    }

    /// Lookup starts at the namespace head: an executable definition
    /// interposes over the DSO's own (musl binding order).
    #[test]
    fn head_definition_interposes_over_dso_own() {
        let mut exe_mem = [0u8; 64];
        let mut lib_mem = [0u8; 64];
        let exe_base = exe_mem.as_mut_ptr();
        let lib_base = lib_mem.as_mut_ptr();
        // exe defines "foo" @0x20; lib references it (undef) via GOT.
        let mut exe_syms = [sym(0, 0, 0, 0, 0), sym(0, 0x12, 1, 0x20, 0)];
        let mut exe_strs = *b"foo\0";
        let mut exe_ht = [0u32; 5];
        let mut lib_syms = [sym(0, 0, 0, 0, 0), sym(0, 0x12, 0, 0, 0)];
        let mut lib_strs = *b"foo\0";
        let mut lib_ht = [0u32; 5];
        let mut exe: Dso = unsafe { core::mem::zeroed() };
        let mut lib: Dso = unsafe { core::mem::zeroed() };
        unsafe {
            sysv_chain(exe_ht.as_mut_ptr(), 1);
            sysv_chain(lib_ht.as_mut_ptr(), 1);
            wire(
                &mut exe as *mut Dso,
                exe_base,
                exe_syms.as_mut_ptr(),
                exe_strs.as_mut_ptr() as *mut c_char,
                exe_ht.as_mut_ptr(),
            );
            wire(
                &mut lib as *mut Dso,
                lib_base,
                lib_syms.as_mut_ptr(),
                lib_strs.as_mut_ptr() as *mut c_char,
                lib_ht.as_mut_ptr(),
            );
            // Namespace: exe -> lib.
            exe.syms_next = &mut lib as *mut Dso;
            lib.syms_next = core::ptr::null_mut();
        }
        // lib's GOT reloc for "foo" binds exe's def, not lib's undef.
        let mut rela = [0x08usize, info(1, REL_GOT), 7];
        unsafe {
            do_relocs(
                &mut exe as *mut Dso,
                &mut lib as *mut Dso,
                rela.as_mut_ptr(),
                3 * size_of::<usize>(),
                3,
                false,
            )
        };
        assert_eq!(unsafe { *at(lib_base, 0x08) }, exe_base as usize + 0x20 + 7);
    }

    /// `skip_relative` leaves RELATIVE slots alone (6B self-image, which
    /// `_dlstart` already relocated).
    #[test]
    fn skip_relative_leaves_relative_slots() {
        let mut mem = [0u8; 64];
        let base = mem.as_mut_ptr();
        unsafe {
            *at(base, 0x08) = 0xdead;
        }
        let mut dso: Dso = unsafe { core::mem::zeroed() };
        dso.base = base;
        let mut rela = [0x08usize, info(0, REL_RELATIVE), 0x20];
        unsafe {
            do_relocs(
                &mut dso as *mut Dso,
                &mut dso as *mut Dso,
                rela.as_mut_ptr(),
                3 * size_of::<usize>(),
                3,
                true,
            )
        };
        assert_eq!(unsafe { *at(base, 0x08) }, 0xdead);
    }

    /// Corrupt table sizes fail loud in debug (musl trusts the linker;
    /// release would wrap `left` and walk OOB instead). Debug-only: the
    /// guard is a `debug_assert!`, so in release there is nothing to panic
    /// and the test would report a false failure.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic]
    fn rel_size_must_be_stride_multiple() {
        let mut dso: Dso = unsafe { core::mem::zeroed() };
        let mut rela = [0usize; 4];
        unsafe {
            do_relocs(
                &mut dso as *mut Dso,
                &mut dso as *mut Dso,
                rela.as_mut_ptr(),
                4 * size_of::<usize>(),
                3,
                false,
            )
        };
    }
}
