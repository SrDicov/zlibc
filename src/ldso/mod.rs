//! Dynamic linker front end (x86_64): ELF64 types and raw numbers.
//!
//! Reimplements what musl's loader needs before relocation: the ELF64
//! file structures (musl `include/elf.h`), the `Dso` descriptor (musl
//! `ldso/dynlink.c:67-121`, see [`dso`]) and the file-mapping numbers.
//! Relocation application is B3's job; this module stops at parsed.
//!
//! Syscall/file constants are hardcoded with the same TODO as
//! `crate::syscall::SYS_WRITE` until they are generated from
//! `arch/x86_64/bits/`.

pub mod dso;

use core::ffi::c_int;

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) ------------------------
#[cfg(target_arch = "x86_64")]
pub const SYS_CLOSE: usize = 3; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
pub const SYS_MMAP: usize = 9; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
pub const SYS_MPROTECT: usize = 10; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
pub const SYS_MUNMAP: usize = 11; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
pub const SYS_PREAD64: usize = 17; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
pub const SYS_OPENAT: usize = 257; // TODO: generate from arch bits/syscall.h

// ---- open/mmap plumbing ----------------------------------------------------
/// musl `AT_FDCWD` (musl `include/fcntl.h:60`): open relative to cwd.
pub const AT_FDCWD: c_int = -100;
/// musl `O_RDONLY` (musl `include/fcntl.h:44`): zero, no flags.
pub const O_RDONLY: c_int = 0;
/// Page size, assumed 4096: true on x86_64 (musl reads AT_PAGESZ).
pub const PAGE_SIZE: usize = 4096;
/// musl `PROT_*` (musl `include/sys/mman.h:57-60`).
pub const PROT_NONE: c_int = 0;
/// musl `PROT_READ` (musl `include/sys/mman.h:58`).
pub const PROT_READ: c_int = 1;
/// musl `PROT_WRITE` (musl `include/sys/mman.h:59`).
pub const PROT_WRITE: c_int = 2;
/// musl `PROT_EXEC` (musl `include/sys/mman.h:60`).
pub const PROT_EXEC: c_int = 4;
/// musl `MAP_PRIVATE` (musl `include/sys/mman.h:22`).
pub const MAP_PRIVATE: c_int = 0x02;
/// musl `MAP_FIXED` (musl `include/sys/mman.h:25`).
pub const MAP_FIXED: c_int = 0x10;
/// musl `MAP_ANONYMOUS` (musl `include/sys/mman.h:27`).
pub const MAP_ANONYMOUS: c_int = 0x20;

// ---- ELF64 file structures (musl include/elf.h) ----------------------------

/// musl `EI_MAG0..3` (musl `include/elf.h:71-81`): `e_ident` indices.
pub const EI_MAG0: usize = 0;
/// musl `EI_MAG1` (musl `include/elf.h:74`): `e_ident` index.
pub const EI_MAG1: usize = 1;
/// musl `EI_MAG2` (musl `include/elf.h:77`): `e_ident` index.
pub const EI_MAG2: usize = 2;
/// musl `EI_MAG3` (musl `include/elf.h:80`): `e_ident` index.
pub const EI_MAG3: usize = 3;
/// musl `ELFMAG0` (musl `include/elf.h:72`): `0x7f`.
pub const ELFMAG0: u8 = 0x7f;
/// musl `ELFMAG1` (musl `include/elf.h:75`): `E`.
pub const ELFMAG1: u8 = b'E';
/// musl `ELFMAG2` (musl `include/elf.h:78`): `L`.
pub const ELFMAG2: u8 = b'L';
/// musl `ELFMAG3` (musl `include/elf.h:81`): `F`.
pub const ELFMAG3: u8 = b'F';
/// musl `EI_CLASS` (musl `include/elf.h:87`): `e_ident` index.
pub const EI_CLASS: usize = 4;
/// musl `ELFCLASS64` (musl `include/elf.h:90`).
pub const ELFCLASS64: u8 = 2;
/// musl `EI_DATA` (musl `include/elf.h:93`): `e_ident` index.
pub const EI_DATA: usize = 5;
/// musl `ELFDATA2LSB` (musl `include/elf.h:95`).
pub const ELFDATA2LSB: u8 = 1;
/// musl `EI_VERSION` (musl `include/elf.h:99`): `e_ident` index.
pub const EI_VERSION: usize = 6;
/// musl `EV_CURRENT` (musl `include/elf.h:324`).
pub const EV_CURRENT: u8 = 1;
/// musl `ET_EXEC` (musl `include/elf.h:127`).
#[cfg(target_arch = "x86_64")]
pub const ET_EXEC: u16 = 2;
/// musl `ET_DYN` (musl `include/elf.h:128`).
#[cfg(target_arch = "x86_64")]
pub const ET_DYN: u16 = 3;
/// musl `EM_X86_64` (musl `include/elf.h:183`).
#[cfg(target_arch = "x86_64")]
pub const EM_X86_64: u16 = 62;
/// musl `PN_XNUM` (musl `include/elf.h:624`): extended numbering, refused.
#[cfg(target_arch = "x86_64")]
pub const PN_XNUM: u16 = 0xffff;
/// musl `PT_LOAD` (musl `include/elf.h:602`).
#[cfg(target_arch = "x86_64")]
pub const PT_LOAD: u32 = 1;
/// musl `PT_DYNAMIC` (musl `include/elf.h:603`).
#[cfg(target_arch = "x86_64")]
pub const PT_DYNAMIC: u32 = 2;
/// musl `PF_X/W/R` (musl `include/elf.h:627-629`).
#[cfg(target_arch = "x86_64")]
pub const PF_X: u32 = 1 << 0;
/// musl `PF_W` (musl `include/elf.h:628`).
#[cfg(target_arch = "x86_64")]
pub const PF_W: u32 = 1 << 1;
/// musl `PF_R` (musl `include/elf.h:629`).
#[cfg(target_arch = "x86_64")]
pub const PF_R: u32 = 1 << 2;
/// musl `DT_*` tags read by `decode_dyn` (musl `include/elf.h:739-831`).
#[cfg(target_arch = "x86_64")]
pub const DT_NULL: usize = 0;
/// musl `DT_PLTGOT` (musl `include/elf.h:743`).
#[cfg(target_arch = "x86_64")]
pub const DT_PLTGOT: usize = 3;
/// musl `DT_HASH` (musl `include/elf.h:744`).
#[cfg(target_arch = "x86_64")]
pub const DT_HASH: usize = 4;
/// musl `DT_STRTAB` (musl `include/elf.h:745`).
#[cfg(target_arch = "x86_64")]
pub const DT_STRTAB: usize = 5;
/// musl `DT_SYMTAB` (musl `include/elf.h:746`).
#[cfg(target_arch = "x86_64")]
pub const DT_SYMTAB: usize = 6;
/// musl `DT_RPATH` (musl `include/elf.h:754`).
#[cfg(target_arch = "x86_64")]
pub const DT_RPATH: usize = 15;
/// musl `DT_RUNPATH` (musl `include/elf.h:768`).
#[cfg(target_arch = "x86_64")]
pub const DT_RUNPATH: usize = 29;
/// musl `DT_VERSYM` (musl `include/elf.h:819`).
#[cfg(target_arch = "x86_64")]
pub const DT_VERSYM: usize = 0x6ffffff0;
/// musl `DT_GNU_HASH` (musl `include/elf.h:802`).
#[cfg(target_arch = "x86_64")]
pub const DT_GNU_HASH: usize = 0x6ffffef5;

/// musl `Elf64_Ehdr` (musl `include/elf.h:54-69`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Elf64Ehdr {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// musl `Elf64_Phdr` (musl `include/elf.h:588-597`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Elf64Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/// musl `Elf64_Dyn` (musl `include/elf.h:729-735`).
///
/// The C `d_un` union (`d_val`/`d_ptr`) collapses to one `u64`: both
/// arms are 8 bytes and `decode_dyn` only moves the word.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Elf64Dyn {
    pub d_tag: i64,
    pub d_val: u64,
}

/// musl `Elf64_Sym` (musl `include/elf.h:459-466`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Elf64Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}
