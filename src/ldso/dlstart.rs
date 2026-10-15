//! `_dlstart` bootstrap (x86_64): find auxv, compute our load bias,
//! self-relocate RELATIVE-only, hand facts to the 6B stage.
//!
//! Clean-room mirror of musl `ldso/dlstart.c:21-162` (entry asm from
//! `arch/x86_64/crt_arch.h:1-13`, REL arm from `dynlink.h:81-83`).
//! Only RELATIVE relocs run here — no symbol exists yet, exactly like
//! musl, which skips every other type in `_dlstart`. The full engine
//! (`do_relocs`) takes over from 6B; `GETFUNCSYM`/`__dls2` are OUT (this
//! stage RETURNS its facts instead of chaining into `dls2`).
//!
//! Stays clear of the loader's own state on purpose: no `Dso`, no TLS,
//! no allocation, no libc calls — only raw pointer walks, so it also
//! runs before any of that exists. The `R_RELATIVE` number mirrors
//! `super::reloc` (same stable ABI value, not shared: this file must
//! not depend on loader state that does not exist yet).
//!
//! `.weak _DYNAMIC` (crt_arch.h:8-9) arrives with the real ldso link in
//! 6B; today the entry is `cfg(not(test))` so test binaries never need
//! the symbol.

use super::{
    Elf64Phdr, AT_BASE, AT_NULL, AT_PHDR, AT_PHENT, AT_PHNUM, AUX_CNT, DT_NULL, DT_REL, DT_RELA,
    DT_RELASZ, DT_RELR, DT_RELRSZ, DT_RELSZ, DYN_CNT, PT_DYNAMIC,
};
use core::mem::size_of;

/// `R_X86_64_RELATIVE` (musl `arch/x86_64/reloc.h:7`; mirrors the
/// canonical `super::reloc` copy, see module docs for why).
const R_RELATIVE: u32 = 8;

/// Boot facts for the 6B stage: our load bias plus the raw vectors it
/// re-derives everything else from (mirrors musl's `dls2(base, sp)`
/// tail, minus the chaining call).
pub struct BootInfo {
    /// Our load bias (`AT_BASE`, else `_DYNAMIC` minus `PT_DYNAMIC`
    /// `p_vaddr` — dlstart.c:104-115).
    pub base: usize,
    /// The kernel stack as received (argc first).
    pub sp: usize,
}

/// Skip `argv`/`envp` to the auxv (musl `dlstart.c:29-30`).
///
/// # Safety
///
/// `sp` must be the kernel stack (`argc`, `argc` pointers, NULL, env
/// strings, NULL, auxv pairs).
/// `envp` from the kernel stack: `argv` is `sp+1`, `envp` follows the
/// `argc` pointers plus their terminator (mirrors [`find_auxv`], which
/// walks one step further to the auxv).
///
/// # Safety
///
/// `sp` must be the kernel stack.
pub(crate) unsafe fn envp_from_sp(sp: *const usize) -> *mut *mut core::ffi::c_char {
    unsafe {
        let argc = sp.read();
        sp.add(1 + argc + 1) as *mut *mut core::ffi::c_char
    }
}

pub(crate) unsafe fn find_auxv(sp: *const usize) -> *const usize {
    unsafe {
        let argc = sp.read();
        let argv = sp.add(1) as *const *const u8;
        let mut i = argc + 1;
        while !(*argv.add(i)).is_null() {
            i += 1;
        }
        argv.add(i + 1) as *const usize
    }
}

/// Apply RELATIVE-only self-relocation (musl `dlstart.c:128-157`):
/// REL slots re-read their addend, RELA slots take `base + addend`,
/// RELR bitmap words decode exactly per musl's loop. Anything else is
/// skipped (no symbols exist yet). `wrapping_add`: identical on real
/// addresses, panic-free in debug builds.
///
/// # Safety
///
/// `base` must be our load bias; `dynt` the parsed `_DYNAMIC` table
/// whose REL/RELA/RELR addresses are `base`-relative link-time values
/// over writable mappings of the stated sizes.
pub(crate) unsafe fn relocate_self(base: usize, dynt: &[usize; DYN_CNT]) {
    unsafe {
        debug_assert!(
            dynt[DT_RELSZ].is_multiple_of(2 * size_of::<usize>()),
            "REL table size must be a stride multiple"
        );
        debug_assert!(
            dynt[DT_RELASZ].is_multiple_of(3 * size_of::<usize>()),
            "RELA table size must be a stride multiple"
        );
        debug_assert!(
            dynt[DT_RELRSZ].is_multiple_of(size_of::<usize>()),
            "RELR table size must be a word multiple"
        );
        // REL, stride 2 (dlstart.c:128-134).
        let mut p = base.wrapping_add(dynt[DT_REL]) as *mut usize;
        let mut left = dynt[DT_RELSZ];
        while left > 0 {
            if super::reloc::r_type(*p.add(1)) == R_RELATIVE {
                let slot = base.wrapping_add(*p) as *mut usize;
                *slot = (*slot).wrapping_add(base);
            }
            p = p.add(2);
            left -= 2 * size_of::<usize>();
        }
        // RELA, stride 3 (dlstart.c:136-142).
        let mut p = base.wrapping_add(dynt[DT_RELA]) as *mut usize;
        let mut left = dynt[DT_RELASZ];
        while left > 0 {
            if super::reloc::r_type(*p.add(1)) == R_RELATIVE {
                let slot = base.wrapping_add(*p) as *mut usize;
                *slot = base.wrapping_add(*p.add(2));
            }
            p = p.add(3);
            left -= 3 * size_of::<usize>();
        }
        // RELR bitmap (dlstart.c:144-157): even words relocate one slot,
        // odd words are 63-slot bitmaps (bit 0 is the flag).
        let mut p = base.wrapping_add(dynt[DT_RELR]) as *mut usize;
        let mut left = dynt[DT_RELRSZ];
        let mut slot = core::ptr::null_mut::<usize>();
        while left > 0 {
            let e = *p;
            p = p.add(1);
            left -= size_of::<usize>();
            if e & 1 == 0 {
                slot = (base.wrapping_add(e)) as *mut usize;
                *slot = (*slot).wrapping_add(base);
                slot = slot.add(1);
            } else {
                let mut bitmap = e;
                let mut i = 0usize;
                loop {
                    bitmap >>= 1;
                    if bitmap == 0 {
                        break;
                    }
                    if bitmap & 1 != 0 {
                        let s = slot.add(i);
                        *s = (*s).wrapping_add(base);
                    }
                    i += 1;
                }
                slot = slot.add(usize::BITS as usize - 1);
            }
        }
    }
}

/// Entry for the kernel/`PT_INTERP` (musl `arch/x86_64/crt_arch.h:1-13`,
/// translated to Intel asm like the rest of this codebase): `rdi` = the
/// kernel stack, `rsi` = `_DYNAMIC`, align, call [`_dlstart_boot`], then
/// restore the original stack and jump to the entry it returns (musl's
/// `CRTJMP`). `rbx` carries `sp` across the call: it is callee-saved, so
/// the C function cannot clobber it.
///
/// # Safety
///
/// Entered once by the kernel/loader with a valid stack and `_DYNAMIC`;
/// never call, never return (a returned entry that faults is the only
/// way out other than the jump).
#[cfg(all(not(test), target_arch = "x86_64"))]
#[unsafe(naked)]
pub unsafe extern "C" fn _dlstart() {
    core::arch::naked_asm!(
        "xor rbp, rbp",
        "mov rdi, rsp",
        "lea rsi, [rip + _DYNAMIC]",
        "and rsp, -16",
        "mov rbx, rdi",
        "call _dlstart_boot",
        "mov rsp, rbx",
        "jmp rax",
    )
}

/// Bootstrap body (musl `dlstart.c:21-62,66-68,99-157`): parse auxv +
/// `_DYNAMIC`, compute the bias, self-relocate, return the bias. The
/// `dls2` tail (dlstart.c:160-162) is 6B, which also reworks this
/// function's naked caller from return to chain.
///
/// # Safety
///
/// `sp` must be the kernel stack (see [`find_auxv`]); `dynv` the
/// `_DYNAMIC` word vector (`tag, val` pairs to `DT_NULL`).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn _dlstart_c(sp: *const usize, dynv: *const usize) -> usize {
    unsafe {
        let auxv = find_auxv(sp);
        let mut aux = [0usize; AUX_CNT];
        let mut i = 0usize;
        while *auxv.add(i) != AT_NULL {
            if *auxv.add(i) < AUX_CNT {
                aux[*auxv.add(i)] = *auxv.add(i + 1);
            }
            i += 2;
        }
        let mut dynt = [0usize; DYN_CNT];
        let mut j = 0usize;
        while *dynv.add(j) != DT_NULL {
            if *dynv.add(j) < DYN_CNT {
                dynt[*dynv.add(j)] = *dynv.add(j + 1);
            }
            j += 2;
        }
        // Bias (dlstart.c:104-115): `AT_BASE`, else `_DYNAMIC` minus the
        // `PT_DYNAMIC` virtual address, scanning backward like musl
        // (dlstart.c:109) so the LAST `PT_DYNAMIC` wins.
        let mut base = aux[AT_BASE];
        if base == 0 {
            let mut k = aux[AT_PHNUM];
            let phent = aux[AT_PHENT];
            while k > 0 {
                k -= 1;
                let ph = (aux[AT_PHDR] as *const u8).add(k * phent) as *const Elf64Phdr;
                if (*ph).p_type == PT_DYNAMIC {
                    base = (dynv as usize).wrapping_sub((*ph).p_vaddr as usize);
                    break;
                }
            }
        }
        relocate_self(base, &dynt);
        base
    }
}

/// Full interpreter entry: self-relocate, decode our own `Dso`, build
/// the program's, run [`super::boot::dynlink_boot`], return the entry
/// point for the naked [`_dlstart`] to jump to. This is the
/// `__dls2`+`__dls3` shape in one function: musl splits them because
/// stage 2 runs before any `Dso` exists; ours can share `_dlstart_c`
/// since the base computation is already factored.
///
/// Order inside is the load-bearing part (musl `dynlink.c:1802-2081`):
/// our `Dso` is decoded *before* `dynlink_boot` so a `DT_NEEDED:
/// libc.so` resolves to a node with real symbol tables, not the empty
/// shell. Our GOT is relocated in two passes like musl's (`__dls2` at
/// `dynlink.c:1760` plus the `relocated = 0` reset at `:1763` and the
/// step-12 pass): pass 1 against ourselves (a cdylib emits `GLOB_DAT`
/// for exported statics — ELF interposition forbids `RELATIVE` there —
/// so without it the first GOT load faults), pass 2 against the full
/// namespace after the program's `COPY` relocs so interposed copies
/// win. `RELATIVE` is applied exactly once, by `relocate_self`; both
/// passes skip it.
///
/// FS discipline for the cold-boot path (kernel enters with `FS_BASE`
/// 0): nothing called from here may execute `%fs` reads. It holds:
/// `errno` falls back to its global cell when the base is 0,
/// `self_tp` never dereferences, `malloc`'s lock is a plain futex, and
/// the only `%fs` users (`__tlsdesc_dynamic`, `__tls_get_addr`) run
/// solely on program execution, after the jump below.
///
/// # Safety
///
/// `sp` must be the kernel stack; `dynv` the `_DYNAMIC` word vector.
/// Runs once, before any thread exists.
#[cfg(all(not(test), target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn _dlstart_boot(sp: *const usize, dynv: *const usize) -> usize {
    unsafe {
        let base = _dlstart_c(sp, dynv);
        let ldso = core::ptr::addr_of_mut!(super::boot::LDSO);
        (*ldso).base = base as *mut u8;
        (*ldso).dynv = dynv as *mut usize;
        super::dso::decode_dyn(ldso);
        // Pass 1 (musl `__dls2`, `dynlink.c:1760-1761`): our
        // non-`RELATIVE` relocations against ourselves. `relocate_self`
        // already applied `RELATIVE`, hence `skip_relative` — together
        // they are the full self-relocation. Without this pass the GOT
        // slots of our exported statics (`__environ`, `stdout`, …) stay
        // zero: a cdylib emits `GLOB_DAT` for them because ELF
        // interposition forbids `RELATIVE` there, and the first GOT load
        // faults. `head == ldso` with an empty `syms_next`, so only our
        // own definitions can satisfy it; anything else is fatal, which
        // is correct — our image links nothing external.
        super::boot::reloc_all(ldso, ldso, true);
        let auxv = find_auxv(sp);
        let mut aux = [0usize; AUX_CNT];
        let mut i = 0usize;
        while *auxv.add(i) != DT_NULL {
            if *auxv.add(i) < AUX_CNT {
                aux[*auxv.add(i)] = *auxv.add(i + 1);
            }
            i += 2;
        }
        let app = core::ptr::addr_of_mut!(super::boot::APP);
        *app = super::boot::app_dso_from_aux(&aux);
        let entry =
            super::boot::dynlink_boot(envp_from_sp(sp), &aux, app, super::boot::load_library);
        // Pass 2 (musl's `ldso.relocated = 0` + the step-12 pass,
        // `dynlink.c:1763,2032-2033`): re-resolve our GOT against the
        // full namespace, searching from `head`. By now the program ran
        // its `COPY` relocs, so an interposed `stdout`/`optind`/`environ`
        // resolves to the executable's `.bss` copy and our GOT follows
        // it there — otherwise libc would keep reading its private copy
        // while the program uses its own (split-brain). `RELATIVE`
        // stays skipped: pass 1 plus `relocate_self` already applied it,
        // and re-adding the base would corrupt every slot.
        (*ldso).relocated = 0;
        super::boot::reloc_all(super::linkmap::head(), ldso, true);
        entry
    }
}

#[cfg(test)]
mod tests {
    use super::{find_auxv, relocate_self, AT_BASE, AT_NULL, AT_PHDR, AT_PHENT, AT_PHNUM, DT_NULL};
    use super::{DT_REL, DT_RELA, DT_RELASZ, DT_RELR, DT_RELRSZ, DT_RELSZ, DYN_CNT};
    use core::mem::size_of;

    /// Fake kernel stack: argc, argv, NULL, env, NULL, auxv pairs.
    fn fake_stack(aux_pairs: &[usize]) -> [usize; 16] {
        let mut sp = [0usize; 16];
        sp[0] = 2; // argc
        sp[1] = 0x1000; // argv[0]
        sp[2] = 0x2000; // argv[1]
        sp[3] = 0; // argv NULL
        sp[4] = 0x3000; // envp[0]
        sp[5] = 0; // envp NULL
        let mut k = 0;
        while k < aux_pairs.len() {
            sp[6 + k] = aux_pairs[k];
            k += 1;
        }
        sp
    }

    #[test]
    fn auxv_skip_finds_table() {
        let sp = fake_stack(&[AT_PHDR, 0x4000, AT_NULL, 0]);
        let auxv = unsafe { find_auxv(sp.as_ptr()) };
        assert_eq!(auxv as usize, sp.as_ptr() as usize + 6 * size_of::<usize>());
        assert_eq!(unsafe { *auxv }, AT_PHDR);
    }

    /// `envp` sits past `argv` and its terminator: `sp[0]` is argc,
    /// `sp[1..1+argc]` the pointers, `sp[1+argc]` NULL, `sp[2+argc]`
    /// the first environment string.
    #[test]
    fn envp_from_sp_skips_argv() {
        let a0 = c"prog";
        let a1 = c"--flag";
        let e0 = c"HOME=/root";
        let e1 = c"PATH=/bin";
        let stack: [usize; 8] = [
            2,
            a0.as_ptr() as usize,
            a1.as_ptr() as usize,
            0,
            e0.as_ptr() as usize,
            e1.as_ptr() as usize,
            0,
            AT_NULL,
        ];
        let envp = unsafe { super::envp_from_sp(stack.as_ptr()) };
        assert_eq!(
            envp as usize,
            stack.as_ptr() as usize + 4 * size_of::<usize>()
        );
        assert_eq!(unsafe { *envp } as usize, e0.as_ptr() as usize);
        assert_eq!(unsafe { *envp.add(1) } as usize, e1.as_ptr() as usize);
        assert!(unsafe { (*envp.add(2)).is_null() });
    }

    /// Bias from `AT_BASE` (the normal exec path, dlstart.c:104).
    #[test]
    fn bias_from_at_base() {
        let sp = fake_stack(&[AT_BASE, 0x7f00_0000, AT_NULL, 0]);
        let dynv = [DT_NULL, 0];
        let base = unsafe { super::_dlstart_c(sp.as_ptr(), dynv.as_ptr()) };
        assert_eq!(base, 0x7f00_0000);
    }

    /// Bias from the `AT_PHDR` scan (ldso-as-command, dlstart.c:105-115):
    /// musl scans backward and takes the LAST `PT_DYNAMIC`. Synthetic
    /// stride 80 (musl follows `AT_PHENT` blindly, so does the code —
    /// consistency, not the real 56, is what matters).
    #[test]
    fn bias_from_phdr_scan() {
        // Two PT_DYNAMICs: the LAST one wins (musl walks backward).
        let mut phdrs = [0u64; 20];
        phdrs[0] = 2; // p_type PT_DYNAMIC
        phdrs[2] = 0x1000; // p_vaddr (first, ignored)
        phdrs[10] = 2; // p_type PT_DYNAMIC
        phdrs[12] = 0x2000; // p_vaddr (last, wins)
        let dynv = [DT_NULL, 0];
        let sp = fake_stack(&[
            AT_PHDR,
            phdrs.as_ptr() as usize,
            AT_PHENT,
            80,
            AT_PHNUM,
            2,
            AT_NULL,
            0,
        ]);
        // Point dynv at a real array; base must equal dynv - 0x2000.
        let base = unsafe { super::_dlstart_c(sp.as_ptr(), dynv.as_ptr()) };
        assert_eq!(base, dynv.as_ptr() as usize - 0x2000);
    }

    /// Corrupt table sizes fail loud in debug (musl trusts the linker).
    /// Debug-only by construction: the guard is a `debug_assert!`, gone in
    /// release — so this test must not run there or it would "pass" the
    /// wrong way (no panic, exit 0 is a failure, not a verdict).
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic]
    fn reloc_table_size_must_be_stride_multiple() {
        let mut dynt = [0usize; DYN_CNT];
        dynt[DT_RELASZ] = 1;
        unsafe { relocate_self(0x10000, &dynt) };
    }

    /// REL/RELA/RELR RELATIVE-only application; other types skipped.
    /// Each mechanism gets fresh slots so the asserts stay independent.
    #[test]
    fn self_reloc_applies_relative_only() {
        const BASE: usize = 0x10000;
        let mut slots = [0usize; 8];
        let at = |s: &mut [usize], k: usize| &mut s[k] as *mut usize as usize - BASE;
        // RELA image: [off, info, addend] ×2 (RELATIVE then GLOB_DAT=6).
        let mut rela = [0usize; 6];
        rela[0] = at(&mut slots, 0);
        rela[1] = 8;
        rela[2] = 0x10;
        rela[3] = at(&mut slots, 1);
        rela[4] = 6;
        rela[5] = 0x20;
        // REL image: [off, info] ×2 (RELATIVE then NONE=0).
        let mut rel = [0usize; 4];
        rel[0] = at(&mut slots, 2);
        rel[1] = 8;
        rel[2] = at(&mut slots, 3);
        rel[3] = 0;
        // RELR image: one direct word (even) then a bitmap (odd: bit 2
        // set relocates the second slot of the run).
        let mut relr = [0usize; 2];
        relr[0] = at(&mut slots, 4);
        relr[1] = 0b101;
        let mut dynt = [0usize; DYN_CNT];
        dynt[DT_RELA] = &mut rela as *mut usize as usize - BASE;
        dynt[DT_RELASZ] = 6 * size_of::<usize>();
        dynt[DT_REL] = &mut rel as *mut usize as usize - BASE;
        dynt[DT_RELSZ] = 4 * size_of::<usize>();
        dynt[DT_RELR] = &mut relr as *mut usize as usize - BASE;
        dynt[DT_RELRSZ] = 2 * size_of::<usize>();
        // Rig contract: link-time offsets recover real addresses via BASE.
        assert_eq!(BASE.wrapping_add(rela[0]), slots.as_mut_ptr() as usize);
        unsafe { relocate_self(BASE, &dynt) };
        // RELA RELATIVE: base + addend; GLOB_DAT skipped.
        assert_eq!(slots[0], BASE + 0x10);
        assert_eq!(slots[1], 0);
        // REL RELATIVE: re-read (0) + base; NONE skipped.
        assert_eq!(slots[2], BASE);
        assert_eq!(slots[3], 0);
        // RELR direct word relocates its slot; the bitmap word relocates
        // the run's second slot (slots[6]), leaving slots[5] alone.
        assert_eq!(slots[4], BASE);
        assert_eq!(slots[5], 0);
        assert_eq!(slots[6], BASE);
        assert_eq!(slots[7], 0);
    }
}
