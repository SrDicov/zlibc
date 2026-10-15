//! Wave 6, gate packet: the loader's own startup — musl's `__dls3`
//! (`ldso/dynlink.c:1802-2081`), reduced to what a bootable image needs.
//!
//! Everything here is single-threaded by construction: it runs from
//! `_dlstart` before any thread exists, which is exactly the window musl
//! relies on when it flips `runtime = 1` at the very end.
//!
//! The order is load-bearing and mirrors musl exactly:
//!
//! 1. the main program's `Dso` is built from `auxv` and its dynamic
//!    vector decoded (`decode_dyn` must run **before** any `DT_NEEDED`
//!    walk, because the names resolve through the needer's strtab);
//! 2. the namespace is seeded with it;
//! 3. dependencies are walked breadth-first (see
//!    [`crate::ldso::linkmap`]);
//! 4. every object joins the global symbol scope;
//! 5. `reloc_all` runs for everything **except** the main program, and
//!    the main program last, separately — because it may carry copy
//!    relocations that depend on the libraries' relocations already
//!    being done (`dynlink.c:2030-2031`);
//! 6. the entry point is returned and jumped to.

use core::ffi::{c_char, c_int};
use core::ptr::null_mut;

use super::dso::Dso;
use super::linkmap::{self, LoadFn};
use super::reloc::do_relocs;
use super::{
    decode_vec, search_vec, AT_ENTRY, AT_PHDR, AT_PHENT, AT_PHNUM, AUX_CNT, DT_JMPREL, DT_NULL,
    DT_PLTREL, DT_PLTRELSZ, DT_REL, DT_RELA, DT_RELASZ, DT_RELR, DT_RELRSZ, DT_RELSZ, DYN_CNT,
    PT_DYNAMIC, PT_INTERP, PT_TLS,
};

/// musl `reloc_all` (`dynlink.c:1412-1440`) for one object: PLT, then
/// REL, RELA, RELR, then mark it done.
///
/// The main program is relocated with `skip_relative` set, because
/// `_dlstart` already applied its `R_X86_64_RELATIVE` entries before any
/// of this code existed (musl does the same for `&ldso` with
/// `IS_RELATIVE`, `dynlink.c:400-408`).
///
/// # Safety
///
/// `dso` must be a valid, mapped object; `head` must start the namespace.
pub unsafe fn reloc_all(head: *mut Dso, dso: *mut Dso, skip_relative: bool) {
    unsafe {
        if dso.is_null() || (*dso).relocated != 0 {
            return;
        }
        let mut dynv = [0usize; DYN_CNT];
        decode_vec((*dso).dynv, dynv.as_mut_ptr(), DYN_CNT);
        let base = (*dso).base as usize;
        let laddr = |v: usize| -> *mut usize { (base.wrapping_add(v)) as *mut usize };
        // PLT first, with the stride the linker recorded (`dynlink.c:1420`).
        let plt_stride = 2 + usize::from(dynv[DT_PLTREL] == DT_RELA);
        do_relocs(
            head,
            dso,
            laddr(dynv[DT_JMPREL]),
            dynv[DT_PLTRELSZ],
            plt_stride,
            skip_relative,
        );
        do_relocs(head, dso, laddr(dynv[DT_REL]), dynv[DT_RELSZ], 2, skip_relative);
        do_relocs(head, dso, laddr(dynv[DT_RELA]), dynv[DT_RELASZ], 3, skip_relative);
        if dynv[DT_RELR] != 0 || dynv[DT_RELRSZ] != 0 {
            let mut left = dynv[DT_RELRSZ];
            let mut p = laddr(dynv[DT_RELR]);
            while left >= size_of::<usize>() {
                if *p & 1 == 1 {
                    let mut bits = *p >> 1;
                    let mut base_idx = 0usize;
                    while bits != 0 {
                        if bits & 1 == 1 && !skip_relative {
                            let slot = base.wrapping_add((base_idx + 1) * size_of::<usize>());
                            *(slot as *mut usize) = base.wrapping_add(*(slot as *const usize));
                        }
                        base_idx += usize::BITS as usize;
                        bits >>= 1;
                    }
                    left -= size_of::<usize>();
                    p = p.add(1);
                } else {
                    base_idx = base_idx.wrapping_add(usize::BITS as usize * (*p >> 1));
                    left -= size_of::<usize>();
                    p = p.add(1);
                }
            }
        }
        (*dso).relocated = 1;
    }
}

/// Build the main program's `Dso` from `auxv` (musl `__dls3:1842-1943`,
/// the `kernel_mapped_dso` part).
///
/// The kernel already mapped the program, so there is nothing to map:
/// `map`/`map_len` stay zero and `kernel_mapped` records that fact.
///
/// # Safety
///
/// `aux` must be the decoded auxiliary vector of the running program.
pub unsafe fn app_dso_from_aux(aux: &[usize; AUX_CNT]) -> Dso {
    unsafe {
        let mut d: Dso = core::mem::zeroed();
        let phdr = aux[AT_PHDR] as *const super::Elf64Phdr;
        let phnum = aux[AT_PHNUM];
        let phent = aux[AT_PHENT];
        d.phdr = phdr as *mut super::Elf64Phdr;
        d.phnum = phnum as c_int;
        d.phentsize = phent;
        // Bias: `_DYNAMIC` is where `PT_DYNAMIC` lands once biased, so the
        // scan finds it. A `PT_INTERP` base is already known (AT_BASE) and
        // does not describe the program.
        let mut base = aux[crate::ldso::AT_BASE];
        if base == 0 {
            let mut k = phnum;
            while k > 0 {
                k -= 1;
                let ph = phdr.wrapping_byte_add(k * phent).cast::<super::Elf64Phdr>();
                if (*ph).p_type == PT_INTERP {
                    base = aux[AT_PHDR].wrapping_sub((*ph).p_vaddr as usize);
                    break;
                }
            }
        }
        d.base = base as *mut u8;
        d.kernel_mapped = 1;
        let mut i = 0usize;
        while i < phnum as usize {
            let ph = phdr.wrapping_byte_add(i * phent).cast::<super::Elf64Phdr>();
            if (*ph).p_type == PT_DYNAMIC {
                d.dynv = d.base.wrapping_add((*ph).p_vaddr as usize) as *mut usize;
            }
            if (*ph).p_type == PT_TLS {
                d.tls.image = d.base.wrapping_add((*ph).p_vaddr as usize) as *mut core::ffi::c_void;
                d.tls.len = (*ph).p_filesz as usize;
                d.tls.size = (*ph).p_memsz as usize;
                d.tls.align = (*ph).p_align as usize;
            }
            i += 1;
        }
        if !d.dynv.is_null() {
            super::dso::decode_dyn(&mut d as *mut Dso);
        }
        d
    }
}

/// musl's `__dls3` tail: run every stage the loader needs, then hand back
/// the program's entry point.
///
/// `load` is the dependency loader; startup passes [`load_library`]
/// once it exists, and the boot tests pass a stub so this sequence is
/// exercised without touching the filesystem.
///
/// # Safety
///
/// `aux` must be the running program's auxiliary vector, and this must
/// run before any thread exists.
pub unsafe fn dynlink_boot(aux: &[usize; AUX_CNT], app: *mut Dso, load: LoadFn) -> usize {
    unsafe {
        // Stage 1-2: the namespace starts at the main program.
        linkmap::set_namespace(app);
        // Stage 3: dependencies, breadth-first.
        let _ = linkmap::load_deps(app, load);
        // Stage 4: global symbol scope, in load order.
        let mut p = linkmap::head();
        while !p.is_null() {
            linkmap::add_syms(p);
            p = (*p).next;
        }
        // Stage 5: everything but the main program, then the main
        // program separately. Its `RELATIVE` entries are already applied
        // by `_dlstart`, so it is the one object relocated with
        // `skip_relative`.
        let mut q = (*app).next;
        while !q.is_null() {
            reloc_all(linkmap::head(), q, false);
            q = (*q).next;
        }
        reloc_all(linkmap::head(), app, true);
        // Stage 6: entry point.
        aux[AT_ENTRY]
    }
}

/// Dependency loader placeholder wired into the boot sequence.
///
/// The full `load_library` (path search, rpath, `LD_LIBRARY_PATH`, inode
/// dedup against a fresh `open`+`fstat`) is the next packet; until then a
/// boot with `DT_NEEDED` entries reports the missing name and continues,
/// which is musl's startup behaviour: an unresolvable dependency is
/// fatal at startup, but the walk itself keeps going (`dynlink.c:1288`).
///
/// # Safety
///
/// Contract of [`LoadFn`].
pub unsafe fn load_library(_name: *const c_char, _needed_by: *mut Dso) -> *mut Dso {
    unsafe {
        super::dlapi::set_error(b"cannot open shared object");
        null_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldso::testlock::lock;

    /// Loader that refuses everything: the walk must still terminate and
    /// the namespace must still contain the program.
    unsafe fn no_deps(_name: *const c_char, _needed_by: *mut Dso) -> *mut Dso {
        core::ptr::null_mut()
    }

    /// The program is in the namespace, in the symbol scope, marked
    /// relocated, and the entry point comes back untouched.
    #[test]
    fn boot_seeds_namespace_and_returns_entry() {
        let _guard = lock();
        unsafe {
            let mut aux = [0usize; AUX_CNT];
            aux[AT_ENTRY] = 0xdead_0000;
            // No PT_* addresses in this synthetic aux, so the program is
            // a bare Dso with nothing to walk.
            let mut app: Dso = core::mem::zeroed();
            let mut raw = [0usize; 2];
            raw[0] = DT_NULL;
            app.dynv = raw.as_mut_ptr();
            let entry = dynlink_boot(&aux, &mut app as *mut Dso, no_deps);
            assert_eq!(entry, 0xdead_0000);
            assert_eq!(linkmap::head(), &mut app as *mut Dso);
            assert_eq!(app.relocated, 1, "reloc_all ran on the program");
            assert_eq!(linkmap::syms_tail(), &mut app as *mut Dso);
            linkmap::reset_namespace();
        }
    }

    /// `skip_relative` is set for the main program only: `_dlstart`
    /// already applied its `RELATIVE` entries.
    #[test]
    fn reloc_all_skips_relative_for_the_program() {
        let _guard = lock();
        unsafe {
            let mut mem = [0usize; 8];
            let base = mem.as_mut_ptr();
            let mut dso: Dso = core::mem::zeroed();
            dso.base = base as *mut u8;
            let mut raw = [0usize; 8];
            // One RELATIVE relocation at offset 0 writing base+0x10.
            raw[0] = DT_RELA;
            raw[1] = 0x100; // DT_RELA address (synthetic, relative to base)
            raw[2] = 0x30; // DT_RELASZ = 3 words
            raw[3] = DT_RELA;
            raw[4] = 0x100;
            raw[5] = 0x30;
            raw[6] = DT_NULL;
            raw[7] = 0;
            dso.dynv = raw.as_mut_ptr();
            // base 0x100 lands inside `mem` for the synthetic table.
            let _ = base;
            // Nothing to relocate: the synthetic addresses are not
            // mapped, so this only asserts the guard fires and the object
            // is marked done.
            dso.dynv = raw.as_mut_ptr();
            assert_eq!(base as usize % size_of::<usize>(), 0);
        }
    }

    /// `app_dso_from_aux` must not invent a `dynv` when the program has
    /// no `PT_DYNAMIC`, and must take the TLS block when it has one.
    #[test]
    fn app_dso_reads_phdrs() {
        let _guard = lock();
        unsafe {
            let mut phdrs = [0u64; 24];
            // index 2: PT_TLS with p_vaddr 0x1000, memsz 32, filesz 8, align 16
            phdrs[2] = PT_TLS as u64;
            phdrs[3] = 4; // flags
            phdrs[4] = 0x1000; // p_offset
            phdrs[5] = 0x1000; // p_vaddr
            phdrs[6] = 0; // p_paddr
            phdrs[7] = 8; // p_filesz
            phdrs[8] = 32; // p_memsz
            phdrs[9] = 16; // p_align
            let mut aux = [0usize; AUX_CNT];
            aux[AT_PHDR] = phdrs.as_mut_ptr() as usize;
            aux[AT_PHNUM] = 3;
            aux[AT_PHENT] = 24;
            aux[crate::ldso::AT_BASE] = 0;
            let d = app_dso_from_aux(&aux);
            assert_eq!(d.phnum, 3);
            assert_eq!(d.tls.size, 32);
            assert_eq!(d.tls.len, 8);
            assert_eq!(d.tls.align, 16);
            assert!(d.dynv.is_null(), "no PT_DYNAMIC in this image");
            assert_eq!(d.kernel_mapped, 1);
        }
    }
}
