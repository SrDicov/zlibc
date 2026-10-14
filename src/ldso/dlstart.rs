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
        // REL, stride 2 (dlstart.c:128-134).
        let mut p = base.wrapping_add(dynt[DT_REL]) as *mut usize;
        let mut left = dynt[DT_RELSZ];
        while left > 0 {
            if (*p.add(1) & 0xffff_ffff) as u32 == R_RELATIVE {
                *p = (*p).wrapping_add(base);
            }
            p = p.add(2);
            left -= 2 * size_of::<usize>();
        }
        // RELA, stride 3 (dlstart.c:136-142).
        let mut p = base.wrapping_add(dynt[DT_RELA]) as *mut usize;
        let mut left = dynt[DT_RELASZ];
        while left > 0 {
            if (*p.add(1) & 0xffff_ffff) as u32 == R_RELATIVE {
                *p = base.wrapping_add(*p.add(2));
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
                slot = slot.add(8 * size_of::<usize>() - 1);
            }
        }
    }
}

/// Entry for the kernel/`PT_INTERP` (musl `arch/x86_64/crt_arch.h:1-13`,
/// translated to Intel asm like the rest of this codebase): `rdi` = the
/// kernel stack, `rsi` = `_DYNAMIC`, align, call [`_dlstart_c`].
#[cfg(all(not(test), target_arch = "x86_64"))]
#[unsafe(naked)]
pub unsafe extern "C" fn _dlstart() {
    core::arch::naked_asm!(
        "xor rbp, rbp",
        "mov rdi, rsp",
        "lea rsi, [rip + _DYNAMIC]",
        "and rsp, -16",
        "call _dlstart_c",
        "ud2",
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
        // `PT_DYNAMIC` virtual address found by scanning `AT_PHDR`.
        let mut base = aux[AT_BASE];
        if base == 0 {
            let mut ph = aux[AT_PHDR] as *const Elf64Phdr;
            let mut k = aux[AT_PHNUM];
            let phent = aux[AT_PHENT];
            while k > 0 {
                if (*ph).p_type == PT_DYNAMIC {
                    base = (dynv as usize).wrapping_sub((*ph).p_vaddr as usize);
                    break;
                }
                ph = (ph as *const u8).add(phent) as *const Elf64Phdr;
                k -= 1;
            }
        }
        relocate_self(base, &dynt);
        base
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

    /// Bias from `AT_BASE` (the normal exec path, dlstart.c:104).
    #[test]
    fn bias_from_at_base() {
        let sp = fake_stack(&[AT_BASE, 0x7f00_0000, AT_NULL, 0]);
        let dynv = [DT_NULL, 0];
        let base = unsafe { super::_dlstart_c(sp.as_ptr(), dynv.as_ptr()) };
        assert_eq!(base, 0x7f00_0000);
    }

    /// Bias from the `AT_PHDR` scan (ldso-as-command, dlstart.c:105-115).
    /// Synthetic stride 80 (musl follows `AT_PHENT` blindly, so does the
    /// code under test — consistency, not the real 56, is what matters).
    #[test]
    fn bias_from_phdr_scan() {
        // Two fake phdrs: PT_LOAD then PT_DYNAMIC with p_vaddr 0x2000.
        let mut phdrs = [0u64; 20];
        phdrs[0] = 1; // p_type PT_LOAD
        phdrs[10] = 2; // p_type PT_DYNAMIC
        phdrs[12] = 0x2000; // p_vaddr
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
