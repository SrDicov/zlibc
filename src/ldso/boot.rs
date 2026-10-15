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

use core::ffi::{c_char, c_int, c_void};
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
/// musl's is a C string literal, so it carries the implicit NUL the
/// loop below terminates on; a Rust byte literal does not.
const RESERVED: &[u8] = b"c.pthread.rt.m.dl.util.xnet.\0";

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
            // musl's `next = strchr(rp,'.') + 1` makes the compared
            // segment include its trailing dot, so `c.` is the unit and
            // `libc` (no dot) does not match it.
            let seg_len = {
                let mut n = rp;
                while RESERVED[n] != b'.' && RESERVED[n] != 0 {
                    n += 1;
                }
                n + 1 - rp
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
            // `seg_len` already covers the dot, so this lands on the
            // next segment — and on the NUL for the last one.
            rp += seg_len;
        }
        false
    }
}

/// The loader's own name, used for the `!strcmp(name, ldso.name)` arm of
/// the self check (`dynlink.c:1100`).
#[cfg(target_arch = "x86_64")]
fn ldso_name() -> *mut c_char {
    c"libc.so".as_ptr() as *mut c_char
}

/// musl errno values the path search distinguishes
/// (`arch/generic/bits/errno.h`): `path_open` keeps searching on these
/// and inhibits the whole search on anything else.
#[cfg(target_arch = "x86_64")]
const ENOENT: c_int = 2;
#[cfg(target_arch = "x86_64")]
const ENOTDIR: c_int = 20;
#[cfg(target_arch = "x86_64")]
const EACCES: c_int = 13;
#[cfg(target_arch = "x86_64")]
const ENAMETOOLONG: c_int = 36;

/// System default search path, used when nothing else matched (musl
/// `dynlink.c:1164`).
#[cfg(target_arch = "x86_64")]
const DEFAULT_PATHS: &[u8] = b"/lib:/usr/local/lib:/usr/lib\0";

/// Whether the loader must distrust the environment (musl `libc.secure`,
/// `dynlink.c:1821-1829`). Split by cfg because `__libc` does not exist
/// in test builds; tests drive `search_bare` with an explicit `secure`.
#[cfg(all(not(test), target_arch = "x86_64"))]
fn loader_secure() -> bool {
    unsafe { (*core::ptr::addr_of_mut!(crate::start::__libc)).secure != 0 }
}
#[cfg(test)]
fn loader_secure() -> bool {
    false
}

/// `LD_LIBRARY_PATH` as the loader sees it: nothing when secure, the
/// live value otherwise. musl snapshots it once at startup
/// (`dynlink.c:1827`); reading it per call is simpler and differs only
/// if the environment changes mid-run, which the loader never does on
/// purpose. Split by cfg for the same reason as [`loader_secure`].
#[cfg(all(not(test), target_arch = "x86_64"))]
fn live_env_path() -> *const c_char {
    if loader_secure() {
        core::ptr::null()
    } else {
        unsafe { crate::start::getenv(c"LD_LIBRARY_PATH".as_ptr()) }
    }
}
#[cfg(test)]
fn live_env_path() -> *const c_char {
    core::ptr::null()
}

/// Does `name` contain a `/`? Only bare sonames go through the
/// search paths; an explicit pathname opens directly (musl
/// `dynlink.c:1111`).
fn has_slash(name: *const c_char) -> bool {
    unsafe {
        let mut k = 0usize;
        while *name.add(k) != 0 {
            if *name.add(k) == b'/' as c_char {
                return true;
            }
            k += 1;
        }
        false
    }
}

/// musl `path_open` (`dynlink.c:875-899`): try `name` under every
/// colon/newline-separated directory in `list`, writing each candidate
/// into `buf`.
///
/// Returns the fd, -1 when nothing matched (keep searching), or -2 when
/// an open failed with an errno outside
/// `ENOENT`/`ENOTDIR`/`EACCES`/`ENAMETOOLONG` (inhibit the whole
/// search, musl `:890-896`). An over-long candidate is skipped without
/// opening, same as musl's failed `snprintf` bounds check.
#[cfg(target_arch = "x86_64")]
unsafe fn path_open(
    name: *const c_char,
    list: *const c_char,
    buf: *mut u8,
    buf_size: usize,
) -> c_int {
    unsafe {
        let mut nl = 0usize;
        while *name.add(nl) != 0 {
            nl += 1;
        }
        let mut s = list;
        loop {
            while *s == b':' as c_char || *s == b'\n' as c_char {
                s = s.add(1);
            }
            if *s == 0 {
                return -1;
            }
            let mut l = 0usize;
            while *s.add(l) != 0 && *s.add(l) != b':' as c_char && *s.add(l) != b'\n' as c_char {
                l += 1;
            }
            if l + 1 + nl < buf_size {
                crate::mem::memcpy(buf as *mut c_void, s as *const c_void, l);
                *buf.add(l) = b'/';
                crate::mem::memcpy(buf.add(l + 1) as *mut c_void, name as *const c_void, nl + 1);
                let fd = super::dso::open_object(buf as *const c_char);
                if fd >= 0 {
                    return fd;
                }
                match crate::errno::errno_load(crate::errno::__errno_location()) {
                    ENOENT | ENOTDIR | EACCES | ENAMETOOLONG => {}
                    _ => return -2,
                }
            }
            s = s.add(l);
        }
    }
}

/// Length of the `$ORIGIN` word at `s`: 7 for `$ORIGIN`, 9 for
/// `${ORIGIN}`, 0 for anything else (musl `dynlink.c:913-918` accepts
/// exactly these two spellings).
fn origin_word_len(s: *const c_char) -> usize {
    unsafe {
        if *s.add(1) == b'{' as c_char {
            for (i, b) in b"{ORIGIN}".iter().enumerate() {
                if *s.add(1 + i) as u8 != *b {
                    return 0;
                }
            }
            9
        } else {
            for (i, b) in b"ORIGIN".iter().enumerate() {
                if *s.add(1 + i) as u8 != *b {
                    return 0;
                }
            }
            7
        }
    }
}

/// musl `fixup_rpath` (`dynlink.c:901-976`): expand `$ORIGIN` in
/// `p->rpath_orig` into `p->rpath`, or share the string when there is
/// nothing to expand.
///
/// Returns 0, or -1 when the expansion cannot be built (inhibits the
/// search, musl `:948-958`). A `$` that is not `$ORIGIN`/`${ORIGIN}`
/// leaves `rpath` null — the entry is skipped, not failed (musl
/// `:917-920`).
///
/// # Safety
///
/// `p` must be a valid `Dso`; `buf` must be writable for `buf_size`
/// bytes (scratch for the `/proc/self/exe` read).
#[cfg(target_arch = "x86_64")]
unsafe fn fixup_rpath(p: *mut Dso, buf: *mut u8, buf_size: usize) -> c_int {
    unsafe {
        if !(*p).rpath.is_null() || (*p).rpath_orig.is_null() {
            return 0;
        }
        let orig = (*p).rpath_orig;
        // Fast path and validation in one scan: share the string when
        // there is no `$`, count the words, reject any other `$` use.
        let mut n = 0usize;
        let mut k = 0usize;
        let mut has_dollar = false;
        while *orig.add(k) != 0 {
            if *orig.add(k) == b'$' as c_char {
                has_dollar = true;
                if origin_word_len(orig.add(k)) == 0 {
                    return 0;
                }
                n += 1;
            }
            k += 1;
        }
        if !has_dollar {
            (*p).rpath = (*p).rpath_orig;
            return 0;
        }
        if n > isize::MAX as usize / 4096 {
            return 0;
        }
        // Origin: dirname of `/proc/self/exe` for the main program, of
        // the object's own path for a library (musl `:943-971`).
        let origin: *const c_char = if (*p).kernel_mapped != 0 {
            if loader_secure() {
                return 0;
            }
            let r = super::dso::readlink(c"/proc/self/exe".as_ptr(), buf as *mut c_char, buf_size);
            if r < 0 {
                match crate::errno::errno_load(crate::errno::__errno_location()) {
                    ENOENT | ENOTDIR | EACCES => return 0,
                    _ => return -1,
                }
            }
            if r as usize >= buf_size {
                return 0;
            }
            *buf.add(r as usize) = 0;
            buf as *const c_char
        } else {
            (*p).name
        };
        let mut last = origin;
        let mut t = origin;
        while *t != 0 {
            if *t == b'/' as c_char {
                last = t;
            }
            t = t.add(1);
        }
        let (origin, l): (*const c_char, usize) = if last == origin && *origin != b'/' as c_char {
            // No `/` at all (musl `:964-971`): relative to `.`.
            (b".".as_ptr() as *const c_char, 1)
        } else {
            (origin, last.wrapping_sub(origin) as usize)
        };
        if loader_secure() && *origin != b'/' as c_char {
            return 0;
        }
        let mem = crate::malloc::malloc(k + n * l + 1) as *mut u8;
        if mem.is_null() {
            return -1;
        }
        let mut d = mem;
        let mut s = orig;
        while *s != 0 {
            if *s == b'$' as c_char {
                crate::mem::memcpy(d as *mut c_void, origin as *const c_void, l);
                d = d.add(l);
                s = s.add(origin_word_len(s));
            } else {
                *d = *s as u8;
                d = d.add(1);
                s = s.add(1);
            }
        }
        *d = 0;
        (*p).rpath = mem as *mut c_char;
        0
    }
}

/// Bare-soname search (musl `dynlink.c:1120-1165` minus the
/// `/etc/ld-musl-*.path` config file): `LD_LIBRARY_PATH` unless secure,
/// then each `needed_by` ancestor's `RPATH`/`RUNPATH` with `$ORIGIN`
/// expansion, then the system defaults.
///
/// `env_path` arrives resolved by the caller so tests can drive every
/// branch without process state. Returns the fd, -1 when nothing
/// matched, -2 when a failure inhibited the whole search.
///
/// shortcut(/etc/ld-musl-arch.path): musl reads an admin opt-in config
/// file before falling back to the defaults (`dynlink.c:1129-1163`).
/// No container ships it, and when absent musl behaves exactly like
/// this function. Adopt it when a real image needs it.
///
/// # Safety
///
/// `name` must be a bare soname (no `/`); `buf` writable for `buf_size`.
#[cfg(target_arch = "x86_64")]
unsafe fn search_bare(
    name: *const c_char,
    needed_by: *mut Dso,
    env_path: *const c_char,
    buf: *mut u8,
    buf_size: usize,
) -> c_int {
    unsafe {
        let mut fd = -1;
        if !env_path.is_null() {
            fd = path_open(name, env_path, buf, buf_size);
        }
        let mut p = needed_by;
        while fd == -1 && !p.is_null() {
            if fixup_rpath(p, buf, buf_size) < 0 {
                fd = -2;
            }
            if !(*p).rpath.is_null() {
                fd = path_open(name, (*p).rpath, buf, buf_size);
            }
            p = (*p).needed_by;
        }
        if fd == -1 {
            fd = path_open(name, DEFAULT_PATHS.as_ptr() as *const c_char, buf, buf_size);
        }
        fd
    }
}

/// musl `load_library` (`dynlink.c:1057-1260`): the self-name check,
/// both dedup layers, search paths, open, `map_object`, link. The only
/// deliberately missing search step is `/etc/ld-musl-*.path` (see
/// [`search_bare`]).
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
pub unsafe fn load_library(name: *const c_char, needed_by: *mut Dso) -> *mut Dso {
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
        // Open: explicit pathnames directly, bare sonames through the
        // search order (musl `dynlink.c:1111-1165`). Over-long bare
        // names are refused before any I/O (musl `:1119`).
        let mut pathbuf = [0u8; 4096];
        let (fd, pathname): (c_int, *const c_char) = if has_slash(name) {
            (super::dso::open_object(name), name)
        } else {
            if super::reloc::c_strlen(name) > 255 {
                return null_mut();
            }
            let fd = search_bare(
                name,
                needed_by,
                live_env_path(),
                pathbuf.as_mut_ptr(),
                pathbuf.len(),
            );
            if fd < 0 {
                super::dlapi::set_error(b"cannot open shared object");
                return null_mut();
            }
            (fd, pathbuf.as_ptr() as *const c_char)
        };
        if fd < 0 {
            super::dlapi::set_error(b"cannot open shared object");
            return null_mut();
        }
        let Some((st_dev, st_ino)) = stat_key(fd) else {
            super::dso::close_object(fd);
            return null_mut();
        };
        let hit = linkmap::find_by_inode(st_dev, st_ino);
        if !hit.is_null() {
            super::dso::close_object(fd);
            return hit;
        }
        // musl allocates the struct plus the name in one block
        // (`:1209`); the trailing name is what `dso->name` points at.
        // Stored is the *resolved* pathname, not the request.
        let name_len = super::reloc::c_strlen(pathname);
        let block = crate::malloc::malloc(size_of::<Dso>() + name_len + 1);
        if block.is_null() {
            super::dso::close_object(fd);
            super::dlapi::set_error(b"cannot allocate dso");
            return null_mut();
        }
        let p = block as *mut Dso;
        let name_ptr = (block as *mut u8).add(size_of::<Dso>()).cast::<c_char>();
        crate::mem::memcpy(
            name_ptr.cast::<core::ffi::c_void>(),
            pathname.cast::<core::ffi::c_void>(),
            name_len + 1,
        );
        (*p).name = name_ptr;
        (*p).needed_by = needed_by;
        (*p).dev = st_dev;
        (*p).ino = st_ino;
        if super::dso::map_object(fd, p) != 0 {
            crate::malloc::free(block);
            super::dso::close_object(fd);
            super::dlapi::set_error(b"cannot map shared object");
            return null_mut();
        }
        super::dso::close_object(fd);
        // musl only assigns a shortname when the resolved path differed
        // from the request (`dynlink.c:1230`): an explicit pathname
        // passed through untouched is never findable by this layer.
        if pathname != name {
            (*p).shortname = last_component(name_ptr);
        }
        linkmap::append_namespace(p);
        p
    }
}

/// `fstat`'s `(st_dev, st_ino)`: the only two `struct stat` fields the
/// loader's dedup key reads (`dynlink.c:1174`). Read through
/// [`crate::abi::StatKey`], whose offsets the probe asserts against the
/// real musl headers — no hardcoded 0/8 anywhere.
///
/// # Safety
///
/// `fd` must be an open descriptor.
#[cfg(target_arch = "x86_64")]
unsafe fn stat_key(fd: c_int) -> Option<(u64, u64)> {
    let mut buf = [0u8; size_of::<crate::abi::StatKey>()];
    if crate::__syscall!(super::SYS_FSTAT, fd, buf.as_mut_ptr()) < 0 {
        return None;
    }
    let st = buf.as_ptr() as *const crate::abi::StatKey;
    Some(unsafe { ((*st).st_dev, (*st).st_ino) })
}

/// True when `LDSO` already sits in the namespace list.
#[cfg(target_arch = "x86_64")]
fn self_is_linked() -> bool {
    let me = core::ptr::addr_of_mut!(LDSO);
    unsafe {
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

    /// NUL-terminated copy of a Rust string, for the `*const c_char`
    /// entry points.
    fn c_str(s: &str) -> std::ffi::CString {
        std::ffi::CString::new(s).unwrap()
    }

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

    /// The reserved-name table is the whole reason a musl-linked
    /// binary keeps working: its `DT_NEEDED: libc.so` must resolve to
    /// *us*, not to a second copy of ourselves. musl matches the
    /// dot-separated segments of `c.pthread.rt.m.dl.util.xnet.` after a
    /// leading `lib` (`dynlink.c:1075-1097`), so `libm.so` hits and
    /// `libfoo.so` must not.
    #[test]
    fn reserved_names_resolve_to_the_loader_itself() {
        // musl's check is a segment *prefix* match, not equality: it
        // compares `name+3` against `"c."` and so also claims
        // `libc.so.1`. Reproduced rather than corrected — a program that
        // depends on `libc.so.1` wants us anyway.
        for yes in [
            "libc.so",
            "libc.so.1",
            "libpthread.so",
            "librt.so",
            "libm.so",
            "libdl.so",
            "libutil.so",
            "libxnet.so",
        ] {
            assert!(unsafe { is_self(c_str(yes).as_ptr()) }, "{yes} is us");
        }
        for no in ["libfoo.so", "libz.so", "lib", "li", "l", "", "libc"] {
            assert!(!unsafe { is_self(c_str(no).as_ptr()) }, "{no} is not us");
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
