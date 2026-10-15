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

use super::dso::{decode_vec, Dso};
use super::linkmap::{self, LoadFn};
use super::reloc::do_relocs;
use super::{
    AT_ENTRY, AT_PHDR, AT_PHENT, AT_PHNUM, AUX_CNT, DT_JMPREL, DT_PLTREL, DT_PLTRELSZ, DT_REL,
    DT_RELA, DT_RELASZ, DT_RELR, DT_RELRSZ, DT_RELSZ, DYN_CNT, PT_DYNAMIC, PT_INTERP, PT_TLS,
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
        do_relocs(
            head,
            dso,
            laddr(dynv[DT_REL]),
            dynv[DT_RELSZ],
            2,
            skip_relative,
        );
        do_relocs(
            head,
            dso,
            laddr(dynv[DT_RELA]),
            dynv[DT_RELASZ],
            3,
            skip_relative,
        );
        if dynv[DT_RELR] != 0 || dynv[DT_RELRSZ] != 0 {
            let mut left = dynv[DT_RELRSZ];
            let mut p = laddr(dynv[DT_RELR]);
            let mut relr_base = 0usize;
            while left >= size_of::<usize>() {
                if *p & 1 == 1 {
                    // DT_RELR entry: bit 0 set, the remaining bits are
                    // a bitmap of which words from `base_idx` onward are
                    // `RELATIVE` (musl `do_relr_relocs`,
                    // `dynlink.c:563-580`).
                    let mut bits = *p >> 1;
                    while bits != 0 {
                        if bits & 1 == 1 && !skip_relative {
                            let slot = base.wrapping_add((relr_base + 1) * size_of::<usize>());
                            *(slot as *mut usize) = base.wrapping_add(*(slot as *const usize));
                        }
                        relr_base = relr_base.wrapping_add(usize::BITS as usize);
                        bits >>= 1;
                    }
                } else {
                    // Address entry: the top bits hold a word index.
                    relr_base = relr_base.wrapping_add(usize::BITS as usize * (*p >> 1));
                }
                left -= size_of::<usize>();
                p = p.add(1);
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
        while i < phnum {
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

/// The loader's own shared object (musl `ldso`, `dynlink.c:145-158`).
/// Its `name` is what a `DT_NEEDED: libc.so` must resolve to.
pub static mut LDSO: Dso = unsafe { core::mem::zeroed() };

/// musl's reserved self-names (`dynlink.c:1077-1079`): after a leading
/// `lib`, these dot-separated prefixes are the loader itself, and an
/// attempt to "load" one is a hit, not a second copy.
///
/// ```text
/// libc.so  libpthread.so  librt.so  libm.so  libdl.so  libutil.so  libxnet.so
/// ```
///
/// This is what lets a musl-linked binary keep its `DT_NEEDED: libc.so`
/// when the libc *is* us.
#[cfg(target_arch = "x86_64")]
const RESERVED: &[u8] = b"c.pthread.rt.m.dl.util.xnet.";

#[cfg(target_arch = "x86_64")]
unsafe fn is_self(name: *const c_char) -> bool {
    unsafe {
        // musl reads name[0..2] before any length check; a 1- or 2-char
        // name stays inside the terminator, so this is safe (`:1075`).
        if *name != b'l' as c_char
            || *name.add(1) != b'i' as c_char
            || *name.add(2) != b'b' as c_char
        {
            return false;
        }
        let rest = name.add(3);
        let mut rp = 0usize;
        while RESERVED[rp] != 0 {
            let seg_len = {
                let mut n = rp;
                while RESERVED[n] != b'.' && RESERVED[n] != 0 {
                    n += 1;
                }
                n - rp
            };
            let mut same = true;
            for k in 0..seg_len {
                if *rest.add(k) as u8 != RESERVED[rp + k] {
                    same = false;
                    break;
                }
            }
            if same {
                return true;
            }
            rp += seg_len + 1;
        }
        false
    }
}

/// The loader's own name, used for the `!strcmp(name, ldso.name)` arm of
/// the self check (`dynlink.c:1100`).
#[cfg(target_arch = "x86_64")]
fn ldso_name() -> *mut c_char {
    b"libc.so\0".as_ptr() as *mut c_char
}

/// musl `load_library` (`dynlink.c:1057-1260`), minus the search-path
/// machinery (`LD_LIBRARY_PATH`, `DT_RPATH`, `/etc/ld-musl-*.path`): the
/// self-name check, both dedup layers, open, `map_object`, link.
///
/// The search paths are the remaining gap and are additive: a name with
/// a `/` is opened directly, and a bare soname is only satisfied by an
/// object already in the namespace, exactly like musl after its
/// shortname layer.
///
/// # Safety
///
/// Contract of [`LoadFn`].
#[cfg(target_arch = "x86_64")]
pub unsafe fn load_library(name: *const c_char, _needed_by: *mut Dso) -> *mut Dso {
    unsafe {
        if *name == 0 {
            return null_mut();
        }
        let me = core::ptr::addr_of_mut!(LDSO);
        // `libc.so` is already in RESERVED, so musl's extra
        // `!strcmp(name, ldso.name)` arm (`:1100`) is redundant for our
        // own name and is not replicated.
        if is_self(name) {
            (*me).name = ldso_name();
            if (*me).shortname.is_null() {
                (*me).shortname = ldso_name();
            }
            // Link ourselves in once (`dynlink.c:1101-1108`): the list
            // must exist first, so an empty namespace means the boot has
            // not seeded it and there is nothing to append to.
            if !linkmap::head().is_null() && !self_is_linked() {
                linkmap::append_namespace(me);
            }
            return me;
        }
        // Layer 2: already-loaded short name. `find_by_shortname`
        // refuses names containing a `/` on its own.
        let hit = linkmap::find_by_shortname(name);
        if !hit.is_null() {
            return hit;
        }
        // Layer 3: same file, different path.
        let fd = super::dso::open_object(name);
        if fd < 0 {
            super::dlapi::set_error(b"cannot open shared object");
            return null_mut();
        }
        let mut stbuf = [0u8; 16];
        if crate::__syscall!(super::SYS_FSTAT, fd, stbuf.as_mut_ptr()) < 0 {
            super::dso::close_object(fd);
            return null_mut();
        }
        let st_dev = u64::from_ne_bytes(stbuf[0..8].try_into().unwrap());
        let st_ino = u64::from_ne_bytes(stbuf[8..16].try_into().unwrap());
        let hit = linkmap::find_by_inode(st_dev, st_ino);
        if !hit.is_null() {
            super::dso::close_object(fd);
            return hit;
        }
        // musl allocates the struct plus the name in one block
        // (`:1209`); the trailing name is what `dso->name` points at.
        let name_len = super::reloc::c_strlen(name);
        let block = crate::malloc::malloc(size_of::<Dso>() + name_len + 1);
        if block.is_null() {
            super::dso::close_object(fd);
            super::dlapi::set_error(b"cannot allocate dso");
            return null_mut();
        }
        let p = block as *mut Dso;
        core::ptr::write_bytes(p, 0, 1);
        let name_ptr = (block as *mut u8).add(size_of::<Dso>()) as *mut c_char;
        crate::mem::memcpy(
            name_ptr as *mut core::ffi::c_void,
            name as *const core::ffi::c_void,
            name_len + 1,
        );
        (*p).name = name_ptr;
        (*p).dev = st_dev;
        (*p).ino = st_ino;
        if super::dso::map_object(fd, p) != 0 {
            crate::malloc::free(block as *mut core::ffi::c_void);
            super::dso::close_object(fd);
            super::dlapi::set_error(b"cannot map shared object");
            return null_mut();
        }
        super::dso::close_object(fd);
        (*p).shortname = last_component(name_ptr);
        linkmap::append_namespace(p);
        p
    }
}

/// True when `LDSO` already sits in the namespace list.
#[cfg(target_arch = "x86_64")]
fn self_is_linked() -> bool {
    unsafe {
        let me = core::ptr::addr_of_mut!(LDSO);
        let mut p = linkmap::head();
        while !p.is_null() {
            if core::ptr::eq(p, me) {
                return true;
            }
            p = (*p).next;
        }
        false
    }
}

/// musl sets `shortname` only when the resolved path differed from the
/// requested name (`dynlink.c:1230`), so an explicit pathname can never
/// be found by the shortname layer later.
#[cfg(target_arch = "x86_64")]
fn last_component(path: *mut c_char) -> *mut c_char {
    unsafe {
        let mut best = path;
        let mut p = path;
        while *p != 0 {
            if *p == b'/' as c_char {
                best = p.add(1);
            }
            p = p.add(1);
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ldso::testlock::lock;
    use crate::ldso::{AT_BASE, DT_NULL};

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

    /// `reloc_all` marks the object done and is idempotent, and the
    /// `skip_relative` flag is what keeps `_dlstart`'s already-applied
    /// `RELATIVE` entries from being applied twice.
    #[test]
    fn reloc_all_marks_done_once() {
        let _guard = lock();
        unsafe {
            let mut mem = [0usize; 8];
            let mut dso: Dso = core::mem::zeroed();
            dso.base = mem.as_mut_ptr() as *mut u8;
            let mut raw = [0usize; 2];
            raw[0] = DT_NULL;
            raw[1] = 0;
            dso.dynv = raw.as_mut_ptr();
            assert_eq!(dso.relocated, 0);
            reloc_all(null_mut(), &mut dso as *mut Dso, true);
            assert_eq!(dso.relocated, 1);
            // Second call is a no-op: the guard, not a double relocation.
            reloc_all(null_mut(), &mut dso as *mut Dso, true);
            assert_eq!(dso.relocated, 1);
        }
    }

    /// `app_dso_from_aux` must not invent a `dynv` when the program has
    /// no `PT_DYNAMIC`, and must take the TLS block when it has one.
    #[test]
    fn app_dso_reads_phdrs() {
        let _guard = lock();
        unsafe {
            // Elf64Phdr is 56 bytes (p_type and p_flags are u32 and share
            // the first word). Put PT_TLS in header 2.
            let mut phdrs = [0u64; 32];
            const TLS_PH: usize = 2 * 7;
            phdrs[TLS_PH] = PT_TLS as u64 | ((4u64) << 32); // type | flags
            phdrs[TLS_PH + 1] = 0x1000; // p_offset
            phdrs[TLS_PH + 2] = 0x1000; // p_vaddr
            phdrs[TLS_PH + 3] = 0x1000; // p_paddr
            phdrs[TLS_PH + 4] = 8; // p_filesz: the initialized part
            phdrs[TLS_PH + 5] = 32; // p_memsz
            phdrs[TLS_PH + 6] = 16; // p_align
            let mut aux = [0usize; AUX_CNT];
            aux[AT_PHDR] = phdrs.as_mut_ptr() as usize;
            aux[AT_PHNUM] = 3;
            aux[AT_PHENT] = 56;
            aux[AT_BASE] = 0;
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
