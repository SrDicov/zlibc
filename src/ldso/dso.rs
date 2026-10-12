//! `Dso` descriptor + ELF load/parse helpers (x86_64).
//!
//! Mirrors musl `struct dso` (`ldso/dynlink.c:67-121`, DL_FDPIC=0 on
//! x86_64: `base` first, `loadmap` a pointer at the tail) and the
//! `decode_dyn` walk (`ldso/dynlink.c:978-996`). Layouts are
//! re-expressed and algorithms reimplemented; zero musl code is copied.
//!
//! Stops at loaded + parsed: applying relocations is B3's job.

use core::ffi::{c_char, c_int, c_void};
use core::mem::size_of;

use super::Elf64Ehdr;
use super::Elf64Phdr;
use super::AT_FDCWD;
use super::DT_GNU_HASH;
use super::DT_HASH;
use super::DT_NULL;
use super::DT_PLTGOT;
use super::DT_RPATH;
use super::DT_RUNPATH;
use super::DT_STRTAB;
use super::DT_SYMTAB;
use super::DT_VERSYM;
use super::EI_CLASS;
use super::EI_DATA;
use super::EI_MAG0;
use super::EI_MAG1;
use super::EI_MAG2;
use super::EI_MAG3;
use super::EI_VERSION;
use super::ELFCLASS64;
use super::ELFDATA2LSB;
use super::ELFMAG0;
use super::ELFMAG1;
use super::ELFMAG2;
use super::ELFMAG3;
use super::EM_X86_64;
use super::ET_DYN;
use super::ET_EXEC;
use super::EV_CURRENT;
use super::MAP_ANONYMOUS;
use super::MAP_FIXED;
use super::MAP_PRIVATE;
use super::O_RDONLY;
use super::PAGE_SIZE;
use super::PF_R;
use super::PF_W;
use super::PF_X;
use super::PN_XNUM;
use super::PROT_EXEC;
use super::PROT_NONE;
use super::PROT_READ;
use super::PROT_WRITE;
use super::PT_DYNAMIC;
use super::PT_LOAD;
use super::SYS_CLOSE;
use super::SYS_MMAP;
use super::SYS_MPROTECT;
use super::SYS_MUNMAP;
use super::SYS_OPENAT;
use super::SYS_PREAD64;

use crate::abi::PthreadT;

/// musl `DYN_CNT` (`src/internal/dynlink.h:104`): dense dynamic range.
pub const DYN_CNT: usize = 37;

/// musl `struct tls_module` (`src/internal/libc.h:14-18`).
///
/// Binding path: B1 uses this type only as `crate::ldso::dso::TlsModule`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct TlsModule {
    pub next: *mut TlsModule,
    pub image: *mut c_void,
    pub len: usize,
    pub size: usize,
    pub align: usize,
    pub offset: usize,
}

/// musl `struct dso`'s `funcdesc` (`ldso/dynlink.c:115-118`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Funcdesc {
    pub addr: *mut c_void,
    pub got: *mut usize,
}

/// musl `struct td_index` (`ldso/dynlink.c:62-65`): opaque here, only
/// ever pointed at (x86_64 has no `DL_FDPIC` function descriptors).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct TdIndex {
    _opaque: [u8; 0],
}

/// musl `struct fdpic_loadmap` (`src/internal/dynlink.h:52-55`): opaque
/// here; on x86_64 `Dso::loadmap` stays null (no FDPIC).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct FdpicLoadmap {
    _opaque: [u8; 0],
}

/// musl `struct dso` (`ldso/dynlink.c:67-121`, x86_64: no `DL_FDPIC`).
///
/// `char` flags stay `c_char` (signed, 1 byte on x86_64); counts stay
/// `usize`; every address stays a raw pointer. The C `buf[]` flex tail
/// is omitted: it contributes 0 to `sizeof`, so the size assert still
/// holds without it.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Dso {
    pub base: *mut u8,
    pub name: *mut c_char,
    pub dynv: *mut usize,
    pub next: *mut Dso,
    pub prev: *mut Dso,
    pub phdr: *mut Elf64Phdr,
    pub phnum: c_int,
    pub phentsize: usize,
    pub syms: *mut super::Elf64Sym,
    pub hashtab: *mut u32, // musl `Elf_Symndx` is `uint32_t` (see below)
    pub ghashtab: *mut u32,
    pub versym: *mut i16,
    pub strings: *mut c_char,
    pub syms_next: *mut Dso,
    pub lazy_next: *mut Dso,
    pub lazy: *mut usize,
    pub lazy_cnt: usize,
    pub map: *mut u8,
    pub map_len: usize,
    pub dev: u64, // musl `dev_t`: `unsigned _Int64` (`alltypes.h.in:31`)
    pub ino: u64, // musl `ino_t`: `unsigned _Int64` (`alltypes.h.in:30`)
    pub relocated: c_char,
    pub constructed: c_char,
    pub kernel_mapped: c_char,
    pub mark: c_char,
    pub bfs_built: c_char,
    pub runtime_loaded: c_char,
    pub deps: *mut *mut Dso,
    pub needed_by: *mut Dso,
    pub ndeps_direct: usize,
    pub next_dep: usize,
    pub ctor_visitor: PthreadT, // musl `pthread_t` (8-byte pointer here)
    pub rpath_orig: *mut c_char,
    pub rpath: *mut c_char,
    pub tls: TlsModule,
    pub tls_id: usize,
    pub relro_start: usize,
    pub relro_end: usize,
    pub new_dtv: *mut usize,
    pub new_tls: *mut u8,
    pub td_index: *mut TdIndex,
    pub fini_next: *mut Dso,
    pub shortname: *mut c_char,
    pub loadmap: *mut FdpicLoadmap,
    pub funcdescs: *mut Funcdesc,
    pub got: *mut usize,
}

// musl `Elf_Symndx` is `uint32_t` (`arch/generic/bits/link.h:1`;
// x86_64 provides no override), hence `Dso::hashtab: *mut u32`.

/// musl `sysv_hash` (`ldso/dynlink.c:241-250`), reimplemented from the
/// algorithm: `h = 16*h + c; h ^= (h >> 24) & 0xf0` per byte, result
/// masked to 28 bits. Wrapping `u32` math keeps the same low 28 bits
/// musl's `uint_fast32_t` (64-bit) truncated by its `uint32_t` return.
///
/// # Safety
///
/// `s` must point to a valid NUL-terminated string.
pub unsafe fn sysv_hash(s: *const c_char) -> u32 {
    let mut h: u32 = 0;
    let mut p = s as *const u8;
    loop {
        let c = unsafe { p.read() };
        if c == 0 {
            break;
        }
        h = h.wrapping_mul(16).wrapping_add(c as u32);
        h ^= (h >> 24) & 0xf0;
        p = unsafe { p.add(1) };
    }
    h & 0x0fff_ffff
}

/// musl `gnu_hash` (`ldso/dynlink.c:252-259`), reimplemented (djb2:
/// `h = 33*h + c` from 5381). Same truncation note as [`sysv_hash`].
///
/// # Safety
///
/// `s` must point to a valid NUL-terminated string.
pub unsafe fn gnu_hash(s: *const c_char) -> u32 {
    let mut h: u32 = 5381;
    let mut p = s as *const u8;
    loop {
        let c = unsafe { p.read() };
        if c == 0 {
            break;
        }
        h = h.wrapping_mul(33).wrapping_add(c as u32);
        p = unsafe { p.add(1) };
    }
    h
}

/// musl `laddr(p, v)` (`ldso/dynlink.c:217`, non-FDPIC arm): address of
/// file offset `v` at load bias `base`.
fn laddr(base: *mut u8, v: usize) -> *mut u8 {
    base.wrapping_add(v)
}

/// musl `decode_vec` (`ldso/dynlink.c:222-231`), reimplemented: clear
/// `a[..cnt]`, then fold the `DT_NULL`-terminated tag/value pairs in.
/// musl's `v[0]-1 < cnt-1` guard with nonzero tags is just `tag < cnt`;
/// tags below `usize::BITS` also set their bit in `a[0]`.
///
/// # Safety
///
/// `v` must point to a `DT_NULL`-terminated tag/value array, `a` to
/// `cnt` writable words.
pub unsafe fn decode_vec(v: *const usize, a: *mut usize, cnt: usize) {
    for i in 0..cnt {
        unsafe { a.add(i).write(0) };
    }
    let mut o = 0usize;
    loop {
        let tag = unsafe { *v.add(o) };
        if tag == DT_NULL {
            break;
        }
        let val = unsafe { *v.add(o + 1) };
        if tag < cnt {
            if tag < usize::BITS as usize {
                let b = unsafe { a.read() };
                unsafe { a.write(b | (1usize << tag)) };
            }
            unsafe { a.add(tag).write(val) };
        }
        o += 2;
    }
}

/// musl `search_vec` (`ldso/dynlink.c:233-239`), reimplemented: linear
/// scan for `key`, storing the value in `r`. Used for tags past the
/// dense `DYN_CNT` range (`DT_GNU_HASH`, `DT_VERSYM`).
///
/// # Safety
///
/// `v` must point to a `DT_NULL`-terminated tag/value array, `r` to
/// one writable word.
pub unsafe fn search_vec(v: *const usize, r: *mut usize, key: usize) -> bool {
    let mut o = 0usize;
    loop {
        let tag = unsafe { *v.add(o) };
        if tag == key {
            unsafe { r.write(*v.add(o + 1)) };
            return true;
        }
        if tag == DT_NULL {
            return false;
        }
        o += 2;
    }
}

/// Zero a caller-provided `Dso`. We own no allocator yet, so the caller
/// lends the storage (typically one `static mut` slot per object).
///
/// # Safety
///
/// `p` must be valid for writes and unaliased for the call.
#[cfg(target_arch = "x86_64")]
pub unsafe fn dso_init(p: *mut Dso) {
    unsafe { p.write_bytes(0, 1) };
}

/// Prepend `p` to the `*head` list, wiring `next`/`prev`. (musl
/// appends at the tail; order policy moves to the full loader — this
/// only guarantees a well-formed doubly-linked list.)
///
/// # Safety
///
/// `head` must hold a valid list (or null); `p` must be zeroed (see
/// [`dso_init`]) and not already linked.
#[cfg(target_arch = "x86_64")]
pub unsafe fn dso_link(head: *mut *mut Dso, p: *mut Dso) {
    let first = unsafe { head.read() };
    unsafe {
        (*p).next = first;
        (*p).prev = core::ptr::null_mut();
        if !first.is_null() {
            (*first).prev = p;
        }
        head.write(p);
    }
}

/// musl `decode_dyn` (`ldso/dynlink.c:978-996`), reimplemented: resolve
/// `dynv` against `base` into `syms`/`strings`/`hashtab`/`ghashtab`/
/// `versym`/`got`/`rpath_orig`. `DT_HASH`/`DT_RPATH`/`DT_RUNPATH`/
/// `DT_PLTGOT` ride the decoded vector; `DT_GNU_HASH`/`DT_VERSYM` sit
/// past the dense range and need the raw [`search_vec`] scan.
///
/// # Safety
///
/// `p` must point to a valid `Dso` whose `base`/`dynv` address a
/// mapped image (see [`map_object`]).
#[cfg(target_arch = "x86_64")]
pub unsafe fn decode_dyn(p: *mut Dso) {
    let d = unsafe { &mut *p };
    let mut dynv = [0usize; DYN_CNT];
    unsafe { decode_vec(d.dynv, dynv.as_mut_ptr(), DYN_CNT) };
    let base = d.base;
    d.syms = laddr(base, dynv[DT_SYMTAB]) as *mut super::Elf64Sym;
    d.strings = laddr(base, dynv[DT_STRTAB]) as *mut c_char;
    if dynv[0] & (1usize << DT_HASH) != 0 {
        d.hashtab = laddr(base, dynv[DT_HASH]) as *mut u32;
    }
    if dynv[0] & (1usize << DT_RPATH) != 0 {
        d.rpath_orig = d.strings.wrapping_add(dynv[DT_RPATH]);
    }
    if dynv[0] & (1usize << DT_RUNPATH) != 0 {
        d.rpath_orig = d.strings.wrapping_add(dynv[DT_RUNPATH]);
    }
    if dynv[0] & (1usize << DT_PLTGOT) != 0 {
        d.got = laddr(base, dynv[DT_PLTGOT]) as *mut usize;
    }
    let mut v = 0usize;
    if unsafe { search_vec(d.dynv, &mut v as *mut usize, DT_GNU_HASH) } {
        d.ghashtab = laddr(base, v) as *mut u32;
    }
    v = 0;
    if unsafe { search_vec(d.dynv, &mut v as *mut usize, DT_VERSYM) } {
        d.versym = laddr(base, v) as *mut i16;
    }
}

/// Point `p` at an already-mapped image: record `base`/program
/// headers, take `dynv` from `PT_DYNAMIC`, then [`decode_dyn`].
/// Returns 0, or -1 when no `PT_DYNAMIC` is present.
///
/// # Safety
///
/// `p` must be writable; `phdr` must point to `phnum` headers of
/// `phentsize` bytes; `base + vaddr` must address the mapping.
#[cfg(target_arch = "x86_64")]
pub unsafe fn dso_from_phdr(
    p: *mut Dso,
    base: *mut u8,
    phdr: *const Elf64Phdr,
    phnum: usize,
    phentsize: usize,
) -> c_int {
    let d = unsafe { &mut *p };
    d.base = base;
    d.phdr = phdr as *mut Elf64Phdr;
    d.phnum = phnum as c_int;
    d.phentsize = phentsize;
    let mut i = 0usize;
    while i < phnum {
        let ph = unsafe { &*phdr.wrapping_byte_add(i * phentsize) };
        if ph.p_type == PT_DYNAMIC {
            d.dynv = laddr(base, ph.p_vaddr as usize) as *mut usize;
            unsafe { decode_dyn(p) };
            return 0;
        }
        i += 1;
    }
    -1
}

/// Open `path` read-only via `openat(AT_FDCWD)`. Returns the fd or -1.
///
/// # Safety
///
/// `path` must point to a valid NUL-terminated string.
#[cfg(target_arch = "x86_64")]
pub unsafe fn open_object(path: *const c_char) -> c_int {
    crate::__syscall!(SYS_OPENAT, AT_FDCWD, path, O_RDONLY, 0) as c_int
}

/// Close an `fd` from [`open_object`]. Returns 0 or -1.
///
/// # Safety
///
/// `fd` must be an open file descriptor owned by the caller.
#[cfg(target_arch = "x86_64")]
pub unsafe fn close_object(fd: c_int) -> c_int {
    crate::__syscall!(SYS_CLOSE, fd) as c_int
}

/// `p_flags` → `mmap` prot (`PF_R/W/X` → `PROT_READ/WRITE/EXEC`;
/// musl spreads the same mapping across `map_library`).
fn prot_from_flags(flags: u32) -> c_int {
    let mut prot = 0;
    if flags & PF_R != 0 {
        prot |= PROT_READ;
    }
    if flags & PF_W != 0 {
        prot |= PROT_WRITE;
    }
    if flags & PF_X != 0 {
        prot |= PROT_EXEC;
    }
    prot
}

/// Zero `n` bytes at `p` (open-coded; `memset` itself belongs to B4).
///
/// # Safety
///
/// `p` must be valid for `n` byte writes.
unsafe fn zero_range(p: *mut u8, n: usize) {
    let mut i = 0usize;
    while i < n {
        unsafe { p.wrapping_add(i).write(0) };
        i += 1;
    }
}

/// Read one program header via `pread64` (leaves `fd`'s offset alone).
///
/// # Safety
///
/// `fd` must be readable; `ph` must be writable.
#[cfg(target_arch = "x86_64")]
unsafe fn read_phdr(fd: c_int, off: u64, ph: *mut Elf64Phdr) -> bool {
    let n = crate::__syscall!(SYS_PREAD64, fd, ph, size_of::<Elf64Phdr>(), off);
    n == size_of::<Elf64Phdr>() as isize
}

/// Map the ELF object behind `fd` and fill in `p`: `base`,
/// `map`/`map_len`, program headers, then [`decode_dyn`] through
/// [`dso_from_phdr`]. Reads use `pread64`, so `fd`'s file position is
/// untouched; `fd` stays open for the caller to close. Segment
/// protections follow `p_flags`; `bss` tails are zeroed. Relocations
/// are NOT applied (B3's job). Returns 0, or -1 with nothing mapped.
///
/// Page size is assumed 4096 (true on x86_64; musl reads AT_PAGESZ).
/// `e_phnum == PN_XNUM` (extended numbering) is refused.
/// shortcut: single-`PT_DYNAMIC`, no `PT_TLS`/`PT_GNU_RELRO`
/// bookkeeping; add when B3/the TLS work needs them.
///
/// # Safety
///
/// `fd` must be an open, readable ELF file; `p` must be writable and
/// unlinked (see [`dso_init`]).
#[cfg(target_arch = "x86_64")]
pub unsafe fn map_object(fd: c_int, p: *mut Dso) -> c_int {
    let mut ehdr: Elf64Ehdr = unsafe { core::mem::zeroed() };
    let n = crate::__syscall!(
        SYS_PREAD64,
        fd,
        (&mut ehdr as *mut Elf64Ehdr),
        size_of::<Elf64Ehdr>(),
        0
    );
    if n != size_of::<Elf64Ehdr>() as isize {
        return -1;
    }
    if ehdr.e_ident[EI_MAG0] != ELFMAG0
        || ehdr.e_ident[EI_MAG1] != ELFMAG1
        || ehdr.e_ident[EI_MAG2] != ELFMAG2
        || ehdr.e_ident[EI_MAG3] != ELFMAG3
        || ehdr.e_ident[EI_CLASS] != ELFCLASS64
        || ehdr.e_ident[EI_DATA] != ELFDATA2LSB
        || ehdr.e_ident[EI_VERSION] != EV_CURRENT
    {
        return -1;
    }
    if ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN {
        return -1;
    }
    if ehdr.e_machine != EM_X86_64 {
        return -1;
    }
    if ehdr.e_phentsize as usize != size_of::<Elf64Phdr>() || ehdr.e_phnum == 0 {
        return -1;
    }
    if ehdr.e_phnum == PN_XNUM {
        return -1;
    }
    let phnum = ehdr.e_phnum as usize;
    let phentsize = ehdr.e_phentsize as usize;

    // Pass 1: span of PT_LOADs; fail when there is nothing to map.
    let mut lo = usize::MAX;
    let mut hi = 0usize;
    let mut loads = 0usize;
    for i in 0..phnum {
        let mut ph: Elf64Phdr = unsafe { core::mem::zeroed() };
        let off = ehdr.e_phoff.wrapping_add((i * phentsize) as u64);
        if !unsafe { read_phdr(fd, off, &mut ph as *mut Elf64Phdr) } {
            return -1;
        }
        if ph.p_type == PT_LOAD && ph.p_memsz != 0 {
            let s = (ph.p_vaddr as usize) & !(PAGE_SIZE - 1);
            let e = (ph.p_vaddr as usize)
                .wrapping_add(ph.p_memsz as usize)
                .wrapping_add(PAGE_SIZE - 1)
                & !(PAGE_SIZE - 1);
            if s < lo {
                lo = s;
            }
            if e > hi {
                hi = e;
            }
            loads += 1;
        }
    }
    if loads == 0 || hi <= lo {
        return -1;
    }

    // Reserve the span, then overlay each LOAD with MAP_FIXED.
    let span = hi - lo;
    let map = crate::__syscall!(
        SYS_MMAP,
        0,
        span,
        PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        // -1 fd for MAP_ANONYMOUS, spelled as usize::MAX: `-1 as usize`
        // parses as `-(1 as usize)` and does not compile.
        usize::MAX,
        0
    );
    if map == -1 {
        return -1;
    }
    let bias = (map as usize).wrapping_sub(lo);
    let table = (phnum * phentsize) as u64;
    let mut have_dyn = false;
    let mut phdr_ok = false;
    let mut failed = false;
    for i in 0..phnum {
        let mut ph: Elf64Phdr = unsafe { core::mem::zeroed() };
        let off = ehdr.e_phoff.wrapping_add((i * phentsize) as u64);
        if !unsafe { read_phdr(fd, off, &mut ph as *mut Elf64Phdr) } {
            failed = true;
            break;
        }
        if ph.p_type == PT_LOAD && ph.p_memsz != 0 {
            let prot = prot_from_flags(ph.p_flags);
            let s = bias.wrapping_add((ph.p_vaddr as usize) & !(PAGE_SIZE - 1));
            let e = bias.wrapping_add(
                (ph.p_vaddr as usize)
                    .wrapping_add(ph.p_memsz as usize)
                    .wrapping_add(PAGE_SIZE - 1)
                    & !(PAGE_SIZE - 1),
            );
            // Widen first: pure-bss segments have no file slice, and
            // the reserve is PROT_NONE, so nothing is writable yet.
            if crate::__syscall!(SYS_MPROTECT, s, e - s, prot | PROT_WRITE) == -1 {
                failed = true;
                break;
            }
            // Standard file-backed overlay: page-align the file slice.
            let page_off = (ph.p_offset as usize) & (PAGE_SIZE - 1);
            let file_start = (ph.p_offset as usize) - page_off;
            let dest = bias
                .wrapping_add(ph.p_vaddr as usize)
                .wrapping_sub(page_off);
            let len = page_off.wrapping_add(ph.p_filesz as usize);
            if len != 0 {
                let m = crate::__syscall!(
                    SYS_MMAP,
                    dest,
                    len,
                    prot | PROT_WRITE,
                    MAP_PRIVATE | MAP_FIXED,
                    fd,
                    file_start
                );
                if m == -1 {
                    failed = true;
                    break;
                }
            }
            // Zero bss, then drop the temporary PROT_WRITE.
            if (ph.p_memsz as usize) > (ph.p_filesz as usize) {
                let zb = bias
                    .wrapping_add(ph.p_vaddr as usize)
                    .wrapping_add(ph.p_filesz as usize);
                let zn = (ph.p_memsz as usize) - (ph.p_filesz as usize);
                unsafe { zero_range(zb as *mut u8, zn) };
            }
            if crate::__syscall!(SYS_MPROTECT, s, e - s, prot) == -1 {
                failed = true;
                break;
            }
            // The phdr table normally ships inside a LOAD at offset 0.
            if ph.p_offset <= ehdr.e_phoff
                && ehdr.e_phoff.wrapping_add(table) <= ph.p_offset.wrapping_add(ph.p_filesz)
            {
                phdr_ok = true;
            }
        } else if ph.p_type == PT_DYNAMIC && !have_dyn {
            have_dyn = true;
        }
    }
    if failed || !have_dyn || !phdr_ok {
        crate::__syscall!(SYS_MUNMAP, map, span);
        return -1;
    }
    {
        let d = unsafe { &mut *p };
        d.map = map as *mut u8;
        d.map_len = span;
    }
    let ph_addr = (bias as *mut u8).wrapping_add(ehdr.e_phoff as usize);
    if unsafe {
        dso_from_phdr(
            p,
            bias as *mut u8,
            ph_addr as *const Elf64Phdr,
            phnum,
            phentsize,
        )
    } != 0
    {
        crate::__syscall!(SYS_MUNMAP, map, span);
        return -1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::super::Elf64Dyn;
    use super::super::Elf64Ehdr;
    use super::super::Elf64Phdr;
    use super::super::DT_GNU_HASH;
    use super::super::DT_HASH;
    use super::super::DT_NULL;
    use super::super::DT_STRTAB;
    use super::super::DT_SYMTAB;
    use super::super::DT_VERSYM;
    use super::super::PT_DYNAMIC;
    use super::super::PT_LOAD;
    use super::decode_dyn;
    use super::decode_vec;
    use super::dso_from_phdr;
    use super::dso_link;
    use super::gnu_hash;
    use super::search_vec;
    use super::sysv_hash;
    use super::Dso;
    use super::TlsModule;
    use super::DYN_CNT;

    use core::mem::offset_of;
    use core::mem::size_of;

    // Hand-derived hash vectors: each traced through the loop by hand
    // (see the fn docs for the step rule), CI replays them as asserts.

    #[test]
    fn sysv_hash_vectors() {
        unsafe {
            // "" never enters the loop: 0 masked to 28 bits is 0.
            assert_eq!(sysv_hash(c"".as_ptr()), 0);
            // "a": h = 16*0+0x61 = 0x61, no fold, mask keeps it: 97.
            assert_eq!(sysv_hash(c"a".as_ptr()), 97);
            // "ab": h = 16*0x61+0x62 = 0x672, no fold: 1650.
            assert_eq!(sysv_hash(c"ab".as_ptr()), 0x672);
            // "abcdefg" traced byte by byte (hex h after each step):
            // 0x61, 0x672, 0x6783, 0x67894, 0x6789a5, 0x6789ab6
            // (0x6789ab6>>24 = 0x06, &0xf0 = 0: fold is a no-op),
            // then 16*0x6789ab6+0x67 = 0x6789abc7; fold:
            // (0x6789abc7>>24)&0xf0 = 0x60, h^=0x60 -> 0x6789aba7;
            // &0x0fffffff -> 0x0789aba7 = 126462887.
            assert_eq!(sysv_hash(c"abcdefg".as_ptr()), 126462887);
        }
    }

    #[test]
    fn gnu_hash_vectors() {
        unsafe {
            // "": loop skipped, seed survives: 5381.
            assert_eq!(gnu_hash(c"".as_ptr()), 5381);
            // "a": 5381*33+97 = 177573+97 = 177670.
            assert_eq!(gnu_hash(c"a".as_ptr()), 177670);
            // "ab": 177670*33+98 = 5863110+98 = 5863208.
            assert_eq!(gnu_hash(c"ab".as_ptr()), 5863208);
            // "hello" traced in u32 (wraps once, at the 4th byte):
            // 177677, 5863442, 193493694,
            // 4th: 193493694*33+108 = 6385292010 mod 2^32
            // = 2090324714 = 0x7c97d2ea,
            // 5th: 2090324714*33+111 = 68980715673 mod 2^32
            // = 68980715673-16*4294967296 = 261238937.
            assert_eq!(gnu_hash(c"hello".as_ptr()), 261238937);
        }
    }

    #[test]
    fn decode_vec_folds_pairs() {
        let v = [DT_SYMTAB, 0x1000usize, DT_NULL, 0];
        let mut a = [0usize; DYN_CNT];
        unsafe { decode_vec(v.as_ptr(), a.as_mut_ptr(), DYN_CNT) };
        assert_eq!(a[DT_SYMTAB], 0x1000);
        assert_eq!(a[0], 1usize << DT_SYMTAB);
        // Out-of-range tags are ignored, presence bits only below 64.
        let v = [DYN_CNT + 5, 7usize, DT_NULL, 0];
        let mut a = [0usize; DYN_CNT];
        unsafe { decode_vec(v.as_ptr(), a.as_mut_ptr(), DYN_CNT) };
        assert_eq!(a[0], 0);
    }

    #[test]
    fn search_vec_finds_and_misses() {
        let v = [DT_SYMTAB, 9usize, DT_GNU_HASH, 11, DT_NULL, 0];
        let mut r = 0usize;
        assert!(unsafe { search_vec(v.as_ptr(), &mut r as *mut usize, DT_GNU_HASH) });
        assert_eq!(r, 11);
        assert!(!unsafe { search_vec(v.as_ptr(), &mut r as *mut usize, DT_VERSYM) });
    }

    #[test]
    fn decode_dyn_resolves_against_base() {
        // Fake image: dynv at +0, symtab +64, strtab +128, hash +192.
        let mut mem = [0u8; 256];
        let base = mem.as_mut_ptr();
        let dynv = base as *mut usize;
        unsafe {
            *dynv.add(0) = DT_SYMTAB;
            *dynv.add(1) = 64;
            *dynv.add(2) = DT_STRTAB;
            *dynv.add(3) = 128;
            *dynv.add(4) = DT_HASH;
            *dynv.add(5) = 192;
            *dynv.add(6) = DT_GNU_HASH;
            *dynv.add(7) = 200;
            *dynv.add(8) = DT_NULL;
            *dynv.add(9) = 0;
        }
        let mut dso: Dso = unsafe { core::mem::zeroed() };
        dso.base = base;
        dso.dynv = dynv;
        unsafe { decode_dyn(&mut dso as *mut Dso) };
        assert_eq!(dso.syms as *mut u8, unsafe { base.add(64) });
        assert_eq!(dso.strings as *mut u8, unsafe { base.add(128) });
        assert_eq!(dso.hashtab as *mut u8, unsafe { base.add(192) });
        assert_eq!(dso.ghashtab as *mut u8, unsafe { base.add(200) });
        assert!(dso.versym.is_null());
        assert!(dso.got.is_null());
    }

    #[test]
    fn dso_from_phdr_finds_dynamic() {
        // Two fake headers: LOAD then DYNAMIC pointing at offset 32.
        let ph = [
            Elf64Phdr {
                p_type: PT_LOAD,
                p_flags: 5,
                p_offset: 0,
                p_vaddr: 0,
                p_paddr: 0,
                p_filesz: 64,
                p_memsz: 64,
                p_align: 4096,
            },
            Elf64Phdr {
                p_type: PT_DYNAMIC,
                p_flags: 3,
                p_offset: 32,
                p_vaddr: 32,
                p_paddr: 32,
                p_filesz: 32,
                p_memsz: 32,
                p_align: 8,
            },
        ];
        let mut mem = [0u8; 128];
        let base = mem.as_mut_ptr();
        unsafe {
            let dynv = base.add(32) as *mut usize;
            *dynv.add(0) = DT_SYMTAB;
            *dynv.add(1) = 64;
            *dynv.add(2) = DT_STRTAB;
            *dynv.add(3) = 96;
            *dynv.add(4) = DT_NULL;
            *dynv.add(5) = 0;
        }
        let mut dso: Dso = unsafe { core::mem::zeroed() };
        let r = unsafe {
            dso_from_phdr(
                &mut dso as *mut Dso,
                base,
                ph.as_ptr(),
                2,
                size_of::<Elf64Phdr>(),
            )
        };
        assert_eq!(r, 0);
        assert_eq!(dso.base, base);
        assert_eq!(dso.dynv as *mut u8, unsafe { base.add(32) });
        assert_eq!(dso.syms as *mut u8, unsafe { base.add(64) });
        assert_eq!(dso.strings as *mut u8, unsafe { base.add(96) });
        // No PT_DYNAMIC at all: -1, fields still recorded.
        let r = unsafe {
            dso_from_phdr(
                &mut dso as *mut Dso,
                base,
                ph.as_ptr(),
                1,
                size_of::<Elf64Phdr>(),
            )
        };
        assert_eq!(r, -1);
    }

    #[test]
    fn dso_link_wires_next_prev() {
        let mut a: Dso = unsafe { core::mem::zeroed() };
        let mut b: Dso = unsafe { core::mem::zeroed() };
        let mut head: *mut Dso = core::ptr::null_mut();
        unsafe {
            dso_link(&mut head as *mut *mut Dso, &mut a as *mut Dso);
            dso_link(&mut head as *mut *mut Dso, &mut b as *mut Dso);
        }
        assert_eq!(head, &mut b as *mut Dso);
        assert_eq!(b.next, &mut a as *mut Dso);
        assert!(b.prev.is_null());
        assert_eq!(a.prev, &mut b as *mut Dso);
        assert!(a.next.is_null());
    }

    // Hand-computed x86_64 layout (musl ldso/dynlink.c:67-121 order):
    // base 0, name 8, dynv 16, next 24, prev 32, phdr 40, phnum 48,
    // phentsize 56, syms 64, hashtab 72, ghashtab 80, versym 88,
    // strings 96, syms_next 104, lazy_next 112, lazy 120, lazy_cnt 128,
    // map 136, map_len 144, dev 152, ino 160, six chars 168..174,
    // deps 176, needed_by 184, ndeps_direct 192, next_dep 200,
    // ctor_visitor 208, rpath_orig 216, rpath 224, tls 232..280,
    // tls_id 280, relro_start 288, relro_end 296, new_dtv 304,
    // new_tls 312, td_index 320, fini_next 328, shortname 336,
    // loadmap 344, funcdescs 352, got 360; size 368, align 8.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn dso_layout_matches_hand_computation() {
        assert_eq!(size_of::<Dso>(), 368);
        assert_eq!(offset_of!(Dso, tls), 232);
        assert_eq!(offset_of!(Dso, got), 360);
        assert_eq!(size_of::<TlsModule>(), 48);
        assert_eq!(offset_of!(TlsModule, offset), 40);
        assert_eq!(size_of::<super::super::Elf64Sym>(), 24);
        assert_eq!(offset_of!(super::super::Elf64Sym, st_value), 8);
        assert_eq!(size_of::<Elf64Ehdr>(), 64);
        assert_eq!(size_of::<Elf64Phdr>(), 56);
        assert_eq!(size_of::<Elf64Dyn>(), 16);
    }
}
