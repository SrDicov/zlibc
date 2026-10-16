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
    AT_EGID, AT_ENTRY, AT_EUID, AT_GID, AT_PHDR, AT_PHENT, AT_PHNUM, AT_SECURE, AT_UID, AUX_CNT,
    DT_JMPREL, DT_PLTREL, DT_PLTRELSZ, DT_REL, DT_RELA, DT_RELASZ, DT_RELR, DT_RELRSZ, DT_RELSZ,
    DYN_CNT, PT_DYNAMIC, PT_PHDR, PT_TLS,
};

/// musl `reloc_all` (`dynlink.c:1412-1440`) for one object: PLT, then
/// REL, RELA, RELR, then mark it done.
///
/// The main program is relocated with `skip_relative` clear: unlike
/// `LDSO` (whose `RELATIVE` entries `_dlstart`/`relocate_self` already
/// applied before any of this code existed), nothing has touched the
/// program's `RELATIVE` slots yet — the kernel maps but never
/// relocates. Skipping them here used to go unnoticed (calls run
/// through the eagerly-resolved PLT), until constructor dispatch read
/// an unrelocated `.init_array` entry and jumped to a bare file
/// offset. musl applies them in `__dls3` the same way
/// (`dynlink.c:1995-2000`).
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
        let phdr = aux[AT_PHDR] as *const crate::ldso::Elf64Phdr;
        let phnum = aux[AT_PHNUM];
        let phent = aux[AT_PHENT];
        d.phdr = phdr as *mut crate::ldso::Elf64Phdr;
        d.phnum = phnum as c_int;
        d.phentsize = phent;
        // musl `dynlink.c:1847`: the app's load base comes from the
        // PT_PHDR entry (`AT_PHDR - p_vaddr`). `AT_BASE` is the
        // *loader's* base and never the program's: using it here made
        // `app.dynv` point into our own `.text`, so `decode_dyn`
        // harvested garbage tags and `do_relocs` dereferenced junk. The
        // interpreted-ldso-as-main path reuses `ldso.phdr` (musl
        // `__dls2`) and never reaches here looking for a base.
        let mut base = 0usize;
        let mut tls_image = 0usize;
        let mut i = 0usize;
        while i < phnum {
            let ph = phdr
                .wrapping_byte_add(i * phent)
                .cast::<crate::ldso::Elf64Phdr>();
            match (*ph).p_type {
                PT_PHDR => {
                    base = aux[AT_PHDR].wrapping_sub((*ph).p_vaddr as usize);
                }
                PT_TLS => {
                    tls_image = (*ph).p_vaddr as usize;
                    d.tls.len = (*ph).p_filesz as usize;
                    d.tls.size = (*ph).p_memsz as usize;
                    d.tls.align = (*ph).p_align as usize;
                }
                _ => {}
            }
            i += 1;
        }
        d.base = base as *mut u8;
        if d.tls.size != 0 {
            d.tls.image = d.base.wrapping_add(tls_image) as *mut core::ffi::c_void;
        }
        d.kernel_mapped = 1;
        i = 0;
        while i < phnum {
            let ph = phdr
                .wrapping_byte_add(i * phent)
                .cast::<crate::ldso::Elf64Phdr>();
            if (*ph).p_type == PT_DYNAMIC {
                d.dynv = d.base.wrapping_add((*ph).p_vaddr as usize) as *mut usize;
            }
            i += 1;
        }
        if !d.dynv.is_null() {
            super::dso::decode_dyn(&mut d as *mut Dso);
        }
        d
    }
}

/// Whether the loader must distrust the environment, from the decoded
/// aux table (musl `__dls3`, `dynlink.c:1822-1824`).
///
/// `aux[0]` is NOT the `AT_NULL` value: `decode_vec` sets bit `v[0]` in
/// `a[0]` for every low key it sees (`dynlink.c:227-228`, replicated in
/// ours), so `aux[0]` is a presence bitmap and `0x7800` tests that the
/// kernel provided `AT_UID`..`AT_EGID` (keys 11-14) at all. Reading it
/// as a value would conclude `secure` unconditionally — the exact
/// misreading this function exists to prevent.
pub(crate) fn secure_from_aux(aux: &[usize; AUX_CNT]) -> bool {
    (aux[0] & 0x7800) != 0x7800
        || aux[AT_UID] != aux[AT_EUID]
        || aux[AT_GID] != aux[AT_EGID]
        || aux[AT_SECURE] != 0
}

/// Publish `__environ` and `secure` before any dependency is loaded
/// (musl `__dls3`, `dynlink.c:1817-1824`). `LD_LIBRARY_PATH` and the
/// `$ORIGIN`/secure filters in the search paths read both, so doing it
/// here — not in `__init_libc`, which runs after the loader jumps to
/// the program — is what makes boot-time `DT_NEEDED` resolution see the
/// real environment. Split by cfg because the globals do not exist in
/// test builds; tests drive the loader with explicit state instead.
#[cfg(all(not(test), target_arch = "x86_64"))]
unsafe fn init_loader_state(envp: *mut *mut c_char, aux: &[usize; AUX_CNT]) {
    unsafe {
        core::ptr::addr_of_mut!(crate::start::__environ).write(envp);
        (*core::ptr::addr_of_mut!(crate::start::__libc)).secure =
            if secure_from_aux(aux) { 1 } else { 0 };
    }
}
#[cfg(test)]
unsafe fn init_loader_state(_envp: *mut *mut c_char, _aux: &[usize; AUX_CNT]) {}

/// The main program's `Dso` for the live boot path. Unit tests keep
/// theirs on the stack; the real `_dlstart` chain has no caller frame to
/// borrow, so the object lives here (musl keeps its `app` the same way:
/// a function-static `struct dso` in `__dls3`, `dynlink.c:1804`).
pub static mut APP: Dso = unsafe { core::mem::zeroed() };

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
pub unsafe fn dynlink_boot(
    envp: *mut *mut c_char,
    aux: &[usize; AUX_CNT],
    app: *mut Dso,
    load: LoadFn,
) -> usize {
    unsafe {
        // Stage 0: environment and trust level, before anything loads.
        init_loader_state(envp, aux);
        diag_boot(b"boot: env+secure published\n");
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
        diag_boot(b"boot: deps loaded, scope linked\n");
        // Stage 5: everything but the main program, then the main
        // program with RELATIVE included (nothing applied them yet).
        let mut q = (*app).next;
        while !q.is_null() {
            diag_boot(b"boot: reloc dep ");
            diag_hex(b"q", q as usize);
            reloc_all(linkmap::head(), q, false);
            q = (*q).next;
        }
        diag_boot(b"boot: reloc app\n");
        reloc_all(linkmap::head(), app, false);
        diag_boot(b"boot: relocated, jumping\n");
        // Stage 6: constructors, dependency-first (musl `main_ctor_queue`
        // + `do_init_fini`, `dynlink.c:1624/2014`). A null queue (calloc
        // failure) runs nothing — musl's pre-runtime outcome as well.
        let queue = linkmap::queue_ctors(app);
        if !queue.is_null() {
            linkmap::do_init_fini(queue);
            crate::malloc::free(queue as *mut core::ffi::c_void);
        }
        // Stage 7: entry point.
        aux[AT_ENTRY]
    }
}

/// The loader's own shared object (musl `ldso`, `dynlink.c:145-158`).
/// Its `name` is what a `DT_NEEDED: libc.so` must resolve to.
#[no_mangle]
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
            (origin, (last as usize).wrapping_sub(origin as usize))
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

/// Bare-soname search (musl `dynlink.c:1120-1165`): `LD_LIBRARY_PATH`
/// unless secure, then each `needed_by` ancestor's `RPATH`/`RUNPATH`
/// with `$ORIGIN` expansion, then the `/etc/ld-musl-<arch>.path`
/// admin config, then the system defaults.
///
/// `env_path` arrives resolved by the caller so tests can drive every
/// branch without process state. Returns the fd, -1 when nothing
/// matched, -2 when a failure inhibited the whole search.
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
        // Tests stay hermetic: no filesystem config there (a stray
        // /etc file on the dev host must not change unit results).
        #[cfg(not(test))]
        if fd == -1 {
            let sys = etc_sys_path();
            if !sys.is_null() {
                fd = path_open(name, sys, buf, buf_size);
            }
        }
        if fd == -1 {
            fd = path_open(name, DEFAULT_PATHS.as_ptr() as *const c_char, buf, buf_size);
        }
        fd
    }
}

/// musl `/etc/ld-musl-$ARCH.path` (`dynlink.c:1129-1163`): admin opt-in
/// system path, read once and cached. Directory prefix comes from our
/// own path (`ldso.name` up to the last `/`); with no usable prefix the
/// bare `/etc/...` is tried, exactly like musl's empty-prefix arm.
/// Returns null when the file is absent or unreadable (musl falls back
/// to the defaults then too), else the NUL-terminated path list.
/// Content is capped at the static buffer; a longer file is truncated
/// (musl has no cap — ponytail: full-size read when a real config
/// exceeds 4K).
///
/// # Safety
///
/// Single-threaded boot / `dlopen`-lock context only (plain statics).
#[cfg(all(not(test), target_arch = "x86_64"))]
unsafe fn etc_sys_path() -> *const c_char {
    const CAP: usize = 4096;
    static mut BUF: [u8; CAP] = [0; CAP];
    static mut DONE: bool = false;
    // Raw pointers throughout (`addr_of_mut!`): edition-2024 forbids
    // shared/mut references to `static mut`, and `__syscall!` carries
    // its own `unsafe`.
    let b = core::ptr::addr_of_mut!(BUF).cast::<u8>();
    let done = core::ptr::addr_of_mut!(DONE);
    if unsafe { *done } {
        return unsafe {
            if *b == 0 {
                core::ptr::null()
            } else {
                b as *const c_char
            }
        };
    }
    unsafe { *done = true };
    // "<dir>/etc/ld-musl-x86_64.path".
    let mut path = [0u8; 256];
    let mut dir_len = 0usize;
    let me = core::ptr::addr_of_mut!(LDSO);
    if unsafe { !(*me).name.is_null() } {
        let mut n = 0usize;
        while unsafe { *(*me).name.add(n) } != 0 {
            n += 1;
        }
        let mut last = 0usize;
        let mut k = 0usize;
        while k < n {
            if unsafe { *(*me).name.add(k) } == b'/' as c_char {
                last = k + 1;
            }
            k += 1;
        }
        dir_len = last;
    }
    let tail = b"/etc/ld-musl-";
    let mut w = 0usize;
    while w < dir_len && w + tail.len() + super::LDSO_ARCH.len() + 6 < path.len() {
        path[w] = unsafe { *(*me).name.add(w) } as u8;
        w += 1;
    }
    if w != dir_len {
        return core::ptr::null();
    }
    for x in tail
        .iter()
        .chain(super::LDSO_ARCH.iter())
        .chain(b".path\0".iter())
    {
        path[w] = *x;
        w += 1;
    }
    let fd = crate::__syscall!(
        super::SYS_OPENAT,
        super::AT_FDCWD,
        path.as_ptr(),
        super::O_RDONLY | super::O_CLOEXEC,
        0
    ) as c_int;
    if fd < 0 {
        return core::ptr::null();
    }
    let n = crate::__syscall!(super::SYS_READ, fd, b, CAP - 1);
    crate::__syscall!(super::SYS_CLOSE, fd);
    if n <= 0 {
        return core::ptr::null();
    }
    unsafe {
        b.add(n as usize).write(0);
        b as *const c_char
    }
}

/// DIAG (transient, 6E bring-up): raw `write(2)` marker. Uses the raw
/// syscall, not `__syscall!`, so it works with `FS_BASE` 0, without
/// errno, without malloc, without TLS — callable from any boot stage.
/// libtest captures fd 2 per test, so unit tests stay quiet.
pub(crate) fn diag_boot(msg: &[u8]) {
    diag_raw(msg);
}

/// DIAG (transient, 6E bring-up): `label=value` in hex, raw bytes.
pub(crate) fn diag_hex(label: &[u8], v: usize) {
    diag_raw(label);
    let mut digits = [0u8; 16];
    let mut i = 0usize;
    let mut x = v;
    loop {
        let d = (x & 0xf) as u8;
        digits[i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        i += 1;
        x >>= 4;
        if x == 0 {
            break;
        }
    }
    while i > 0 {
        i -= 1;
        diag_raw(&digits[i..i + 1]);
    }
    diag_raw(b"\n");
}

fn diag_raw(msg: &[u8]) {
    unsafe {
        crate::syscall::syscall3(
            crate::syscall::SYS_WRITE,
            2,
            msg.as_ptr() as usize,
            msg.len(),
        );
    }
}

/// musl `load_library` (`dynlink.c:1057-1260`): the self-name check,
/// both dedup layers, search paths, open, `map_object`, link.
///
/// A name with a `/` is opened directly; a bare soname goes through
/// `LD_LIBRARY_PATH`, ancestor `RPATH`/`RUNPATH`, the
/// `/etc/ld-musl-<arch>.path` config, then the system defaults —
/// the full musl order.
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

    /// `path_open` tries every directory in order and stops at the
    /// first hit; a missing name exhausts the list. Uses the real
    /// filesystem (`/bin/sh` exists on any Linux CI/dev machine, same
    /// assumption the `/proc` tests elsewhere already make).
    #[test]
    fn path_open_finds_first_hit() {
        let _guard = lock();
        unsafe {
            let mut buf = [0u8; 4096];
            let fd = path_open(
                c"sh".as_ptr(),
                c"/nope-zzz:/bin:/usr/bin".as_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
            );
            assert!(fd >= 0, "sh must be found under /bin or /usr/bin");
            super::super::dso::close_object(fd);
            let missing = path_open(
                c"definitely-not-here-zzz".as_ptr(),
                c"/bin:/usr/bin".as_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
            );
            assert_eq!(missing, -1);
        }
    }

    /// `fixup_rpath` shares the string when there is no `$`, rejects a
    /// `$` that is not `$ORIGIN`, and expands `$ORIGIN` against the
    /// dirname of a library's own path.
    #[test]
    fn fixup_rpath_expands_origin_for_libraries() {
        let _guard = lock();
        unsafe {
            let mut plain: Dso = core::mem::zeroed();
            let rpath = c"/a:/b".as_ptr() as *mut c_char;
            plain.rpath_orig = rpath;
            let mut buf = [0u8; 4096];
            assert_eq!(
                fixup_rpath(&mut plain as *mut Dso, buf.as_mut_ptr(), buf.len()),
                0
            );
            assert_eq!(plain.rpath, rpath, "shared, not copied");

            let mut bad: Dso = core::mem::zeroed();
            bad.rpath_orig = c"/a/$FOO/b".as_ptr() as *mut c_char;
            assert_eq!(
                fixup_rpath(&mut bad as *mut Dso, buf.as_mut_ptr(), buf.len()),
                0
            );
            assert!(bad.rpath.is_null(), "unexpandable entry is skipped");

            let mut lib: Dso = core::mem::zeroed();
            lib.name = c"/x/y/libz.so".as_ptr() as *mut c_char;
            lib.rpath_orig = c"$ORIGIN/lib:${ORIGIN}/extra".as_ptr() as *mut c_char;
            assert_eq!(
                fixup_rpath(&mut lib as *mut Dso, buf.as_mut_ptr(), buf.len()),
                0
            );
            assert!(!lib.rpath.is_null());
            let got = core::slice::from_raw_parts(lib.rpath as *const u8, 17);
            assert_eq!(
                got, b"/x/y/lib:/x/y/ext",
                "both spellings expand to the dirname"
            );
            crate::malloc::free(lib.rpath as *mut core::ffi::c_void);
        }
    }

    /// `search_bare` honors `LD_LIBRARY_PATH` unless secure: `/proc`
    /// is in no default path, so `version` is found only through the
    /// environment. This is the exact gate `libc.secure` closes.
    #[test]
    fn search_bare_gates_env_on_secure() {
        let _guard = lock();
        unsafe {
            let mut buf = [0u8; 4096];
            let env = c"/proc".as_ptr();
            let found = search_bare(
                c"version".as_ptr(),
                core::ptr::null_mut(),
                env,
                buf.as_mut_ptr(),
                buf.len(),
            );
            assert!(found >= 0, "insecure search reads LD_LIBRARY_PATH");
            super::super::dso::close_object(found);
            // Secure: env skipped, needed_by empty, defaults lack
            // /proc — nothing to find. `secure` is not passed here;
            // the null env models what `live_env_path` hands out when
            // `loader_secure()` is true.
            let missing = search_bare(
                c"version".as_ptr(),
                core::ptr::null_mut(),
                core::ptr::null(),
                buf.as_mut_ptr(),
                buf.len(),
            );
            assert_eq!(missing, -1);
        }
    }

    /// A `needed_by` ancestor's `RUNPATH` is searched after the
    /// environment (musl `dynlink.c:1122-1128`).
    #[test]
    fn search_bare_walks_needed_by_rpath() {
        let _guard = lock();
        unsafe {
            let mut buf = [0u8; 4096];
            let mut app: Dso = core::mem::zeroed();
            app.rpath_orig = c"/bin".as_ptr() as *mut c_char;
            assert_eq!(
                fixup_rpath(&mut app as *mut Dso, buf.as_mut_ptr(), buf.len()),
                0
            );
            let found = search_bare(
                c"sh".as_ptr(),
                &mut app as *mut Dso,
                core::ptr::null(),
                buf.as_mut_ptr(),
                buf.len(),
            );
            assert!(found >= 0, "ancestor RPATH is searched");
            super::super::dso::close_object(found);
        }
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
            let entry = dynlink_boot(core::ptr::null_mut(), &aux, &mut app as *mut Dso, no_deps);
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

    /// `secure_from_aux` reads musl's exact condition: the bitmap in
    /// `aux[0]` must show keys 11-14 present, the uid/gid pairs must
    /// match, and `AT_SECURE` must be zero — otherwise the loader
    /// distrusts the environment.
    #[test]
    fn secure_from_aux_matches_musl_conditions() {
        let _guard = lock();
        let mut aux = [0usize; AUX_CNT];
        aux[0] = 0x7800;
        aux[AT_UID] = 1000;
        aux[AT_EUID] = 1000;
        aux[AT_GID] = 1000;
        aux[AT_EGID] = 1000;
        aux[AT_SECURE] = 0;
        assert!(!secure_from_aux(&aux), "normal process is not secure");
        aux[AT_EUID] = 0;
        assert!(secure_from_aux(&aux), "setuid trusts nothing");
        aux[AT_EUID] = 1000;
        aux[AT_SECURE] = 1;
        assert!(secure_from_aux(&aux), "AT_SECURE trusts nothing");
        aux[AT_SECURE] = 0;
        aux[0] = 0x0800;
        assert!(
            secure_from_aux(&aux),
            "missing uid/gid keys means secure, even with matching ids"
        );
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

    /// Regression guard for the 6E cold-boot family: `app.base` comes
    /// from the **PT_PHDR** entry (`AT_PHDR - phdr->p_vaddr`, musl
    /// `dynlink.c:1847`), never from `AT_BASE` — that register holds the
    /// *interpreter's* base. A base taken from `AT_BASE` pointed `dynv`
    /// at our own `.text` and let `do_relocs` dereference garbage
    /// (observed: the first non-RELATIVE entry read
    /// `r_off = 0x8000f8369003`).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn app_base_comes_from_pt_phdr_not_at_base() {
        let _guard = lock();
        unsafe {
            // Array of three phdrs lands at mem+0x40; the PT_PHDR entry
            // carries its own p_vaddr so `base = AT_PHDR - p_vaddr`
            // recovers `mem`. PT_DYNAMIC's p_vaddr points back inside
            // the buffer so `decode_dyn` reads real memory.
            let mut mem = [0u8; 320];
            let base = mem.as_mut_ptr();
            let phdrs = [
                crate::ldso::Elf64Phdr {
                    p_type: PT_PHDR,
                    p_flags: 4,
                    p_offset: 0x10,
                    p_vaddr: 0x40,
                    p_paddr: 0x40,
                    p_filesz: 3 * size_of::<crate::ldso::Elf64Phdr>() as u64,
                    p_memsz: 3 * size_of::<crate::ldso::Elf64Phdr>() as u64,
                    p_align: 8,
                },
                crate::ldso::Elf64Phdr {
                    p_type: PT_DYNAMIC,
                    p_flags: 6,
                    p_offset: 0x80,
                    p_vaddr: 0x100,
                    p_paddr: 0x100,
                    p_filesz: 16,
                    p_memsz: 16,
                    p_align: 8,
                },
                crate::ldso::Elf64Phdr {
                    p_type: 0,
                    p_flags: 0,
                    p_offset: 0,
                    p_vaddr: 0,
                    p_paddr: 0,
                    p_filesz: 0,
                    p_memsz: 0,
                    p_align: 0,
                },
            ];
            base.add(0x40)
                .cast::<crate::ldso::Elf64Phdr>()
                .copy_from_nonoverlapping(phdrs.as_ptr(), 3);
            // A DT_NULL dynamic vector at mem+0x100 keeps decode_dyn on
            // real memory while proving `dynv` was resolved by PT_DYNAMIC.
            let dynv = base.add(0x100) as *mut usize;
            dynv.add(0).write(DT_NULL);
            dynv.add(1).write(0);
            let mut aux = [0usize; AUX_CNT];
            aux[AT_PHDR] = base.wrapping_add(0x40) as usize;
            aux[AT_PHNUM] = 3;
            aux[AT_PHENT] = size_of::<crate::ldso::Elf64Phdr>();
            aux[crate::ldso::AT_BASE] = 0x5d00_usize; // loader's base: must NOT be used
            let d = app_dso_from_aux(&aux);
            assert_eq!(d.base, base, "base from PT_PHDR, not AT_BASE");
            assert_eq!(d.dynv as *mut u8, base.add(0x100));
            assert!(d.tls.image.is_null(), "no PT_TLS in this image");
        }
    }
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(".hidden LDSO");
