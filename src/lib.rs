#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

// Tests link the harness (std); the `no_std` attribute above hides the
// implicit `std` extern crate, so re-add it for test builds only.
#[cfg(test)]
extern crate std;

pub mod abi;
pub mod errno;
pub mod futex;
pub mod ldso;
pub mod libm;
pub mod locale;
pub mod malloc;
pub mod mem;
pub mod net;
pub mod panic;
pub mod start;
pub mod stdio;
pub mod symbols;
pub mod sync;
pub mod syscall;
#[cfg(target_arch = "x86_64")]
pub mod thread;
#[cfg(target_arch = "x86_64")]
pub mod validation;

// OUT_DIR/abi_probed.rs is emitted by build.rs with sizes/offsets
// measured from the real musl headers (see probe/probe.c).
include!(concat!(env!("OUT_DIR"), "/abi_probed.rs"));

// ---- Compile-time ABI contract -------------------------------------------
// Each assert compares a Rust #[repr(C)] type against the value probed
// from musl at build time. A mismatch fails the build here, never
// silently. When adding a field, update src/abi.rs AND probe/probe.c.
use core::mem::{offset_of, size_of};

const _: () = assert!(PROBE_SIZE_IOFILE == size_of::<abi::IoFile>());
const _: () = assert!(PROBE_OFF_IOFILE_FLAGS == offset_of!(abi::IoFile, flags));
const _: () = assert!(PROBE_OFF_IOFILE_RPOS == offset_of!(abi::IoFile, rpos));
const _: () = assert!(PROBE_OFF_IOFILE_REND == offset_of!(abi::IoFile, rend));
const _: () = assert!(PROBE_OFF_IOFILE_CLOSE == offset_of!(abi::IoFile, close));
const _: () = assert!(PROBE_OFF_IOFILE_WEND == offset_of!(abi::IoFile, wend));
const _: () = assert!(PROBE_OFF_IOFILE_WPOS == offset_of!(abi::IoFile, wpos));
const _: () = assert!(PROBE_OFF_IOFILE_MUSTBEZERO_1 == offset_of!(abi::IoFile, mustbezero_1));
const _: () = assert!(PROBE_OFF_IOFILE_WBASE == offset_of!(abi::IoFile, wbase));
const _: () = assert!(PROBE_OFF_IOFILE_READ == offset_of!(abi::IoFile, read));
const _: () = assert!(PROBE_OFF_IOFILE_WRITE == offset_of!(abi::IoFile, write));
const _: () = assert!(PROBE_OFF_IOFILE_SEEK == offset_of!(abi::IoFile, seek));
const _: () = assert!(PROBE_OFF_IOFILE_BUF == offset_of!(abi::IoFile, buf));
const _: () = assert!(PROBE_OFF_IOFILE_BUF_SIZE == offset_of!(abi::IoFile, buf_size));
const _: () = assert!(PROBE_OFF_IOFILE_PREV == offset_of!(abi::IoFile, prev));
const _: () = assert!(PROBE_OFF_IOFILE_NEXT == offset_of!(abi::IoFile, next));
const _: () = assert!(PROBE_OFF_IOFILE_FD == offset_of!(abi::IoFile, fd));
const _: () = assert!(PROBE_OFF_IOFILE_PIPE_PID == offset_of!(abi::IoFile, pipe_pid));
const _: () = assert!(PROBE_OFF_IOFILE_LOCKCOUNT == offset_of!(abi::IoFile, lockcount));
const _: () = assert!(PROBE_OFF_IOFILE_MODE == offset_of!(abi::IoFile, mode));
const _: () = assert!(PROBE_OFF_IOFILE_LOCK == offset_of!(abi::IoFile, lock));
const _: () = assert!(PROBE_OFF_IOFILE_LBF == offset_of!(abi::IoFile, lbf));
const _: () = assert!(PROBE_OFF_IOFILE_COOKIE == offset_of!(abi::IoFile, cookie));
const _: () = assert!(PROBE_OFF_IOFILE_OFF == offset_of!(abi::IoFile, off));
const _: () = assert!(PROBE_OFF_IOFILE_GETLN_BUF == offset_of!(abi::IoFile, getln_buf));
const _: () = assert!(PROBE_OFF_IOFILE_MUSTBEZERO_2 == offset_of!(abi::IoFile, mustbezero_2));
const _: () = assert!(PROBE_OFF_IOFILE_SHEND == offset_of!(abi::IoFile, shend));
const _: () = assert!(PROBE_OFF_IOFILE_SHLIM == offset_of!(abi::IoFile, shlim));
const _: () = assert!(PROBE_OFF_IOFILE_SHCNT == offset_of!(abi::IoFile, shcnt));
const _: () = assert!(PROBE_OFF_IOFILE_PREV_LOCKED == offset_of!(abi::IoFile, prev_locked));
const _: () = assert!(PROBE_OFF_IOFILE_NEXT_LOCKED == offset_of!(abi::IoFile, next_locked));
const _: () = assert!(PROBE_OFF_IOFILE_LOCALE == offset_of!(abi::IoFile, locale));

#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_SIZE_PTHREAD_P1 == size_of::<abi::PthreadHead>());
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_PTHREAD_SELF == offset_of!(abi::PthreadHead, this));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_PTHREAD_DTV == offset_of!(abi::PthreadHead, dtv));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_PTHREAD_SYSINFO == offset_of!(abi::PthreadHead, sysinfo));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_PTHREAD_CANARY == offset_of!(abi::PthreadHead, canary));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_SIZE_PTHREAD_T == size_of::<abi::PthreadT>());
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_SIZE_MUTEX == 40);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_M_TYPE == 0);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_M_LOCK == 4);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_M_WAITERS == 8);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_M_COUNT == 20);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_SIZE_COND == 48);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_C_SEQ == 8);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_C_WAITERS == 12);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_C_CLOCK == 16);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_C_LOCK == 32);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_SIZE_ELF64_EHDR == size_of::<ldso::Elf64Ehdr>());
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_SIZE_ELF64_PHDR == size_of::<ldso::Elf64Phdr>());
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_SIZE_ELF64_DYN == size_of::<ldso::Elf64Dyn>());
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_SIZE_ELF64_SYM == size_of::<ldso::Elf64Sym>());
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_ELF64_SYM_ST_NAME == offset_of!(ldso::Elf64Sym, st_name));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_ELF64_SYM_ST_INFO == offset_of!(ldso::Elf64Sym, st_info));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_ELF64_SYM_ST_OTHER == offset_of!(ldso::Elf64Sym, st_other));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_ELF64_SYM_ST_SHNDX == offset_of!(ldso::Elf64Sym, st_shndx));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_ELF64_SYM_ST_VALUE == offset_of!(ldso::Elf64Sym, st_value));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_ELF64_SYM_ST_SIZE == offset_of!(ldso::Elf64Sym, st_size));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_SIZE_TLS_MODULE == size_of::<ldso::dso::TlsModule>());
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_TLS_MODULE_NEXT == offset_of!(ldso::dso::TlsModule, next));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_TLS_MODULE_IMAGE == offset_of!(ldso::dso::TlsModule, image));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_TLS_MODULE_LEN == offset_of!(ldso::dso::TlsModule, len));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_TLS_MODULE_SIZE == offset_of!(ldso::dso::TlsModule, size));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_TLS_MODULE_ALIGN == offset_of!(ldso::dso::TlsModule, align));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_TLS_MODULE_OFFSET == offset_of!(ldso::dso::TlsModule, offset));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_SIZE_DSO == size_of::<ldso::dso::Dso>());
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_BASE == offset_of!(ldso::dso::Dso, base));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_NAME == offset_of!(ldso::dso::Dso, name));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_DYNV == offset_of!(ldso::dso::Dso, dynv));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_NEXT == offset_of!(ldso::dso::Dso, next));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_PREV == offset_of!(ldso::dso::Dso, prev));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_PHDR == offset_of!(ldso::dso::Dso, phdr));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_PHNUM == offset_of!(ldso::dso::Dso, phnum));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_PHENTSIZE == offset_of!(ldso::dso::Dso, phentsize));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_SYMS == offset_of!(ldso::dso::Dso, syms));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_HASHTAB == offset_of!(ldso::dso::Dso, hashtab));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_GHASHTAB == offset_of!(ldso::dso::Dso, ghashtab));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_VERSYM == offset_of!(ldso::dso::Dso, versym));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_STRINGS == offset_of!(ldso::dso::Dso, strings));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_SYMS_NEXT == offset_of!(ldso::dso::Dso, syms_next));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_LAZY_NEXT == offset_of!(ldso::dso::Dso, lazy_next));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_LAZY == offset_of!(ldso::dso::Dso, lazy));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_LAZY_CNT == offset_of!(ldso::dso::Dso, lazy_cnt));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_MAP == offset_of!(ldso::dso::Dso, map));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_MAP_LEN == offset_of!(ldso::dso::Dso, map_len));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_DEV == offset_of!(ldso::dso::Dso, dev));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_INO == offset_of!(ldso::dso::Dso, ino));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_RELOCATED == offset_of!(ldso::dso::Dso, relocated));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_CONSTRUCTED == offset_of!(ldso::dso::Dso, constructed));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_KERNEL_MAPPED == offset_of!(ldso::dso::Dso, kernel_mapped));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_MARK == offset_of!(ldso::dso::Dso, mark));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_BFS_BUILT == offset_of!(ldso::dso::Dso, bfs_built));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_RUNTIME_LOADED == offset_of!(ldso::dso::Dso, runtime_loaded));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_DEPS == offset_of!(ldso::dso::Dso, deps));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_NEEDED_BY == offset_of!(ldso::dso::Dso, needed_by));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_NDEPS_DIRECT == offset_of!(ldso::dso::Dso, ndeps_direct));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_NEXT_DEP == offset_of!(ldso::dso::Dso, next_dep));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_CTOR_VISITOR == offset_of!(ldso::dso::Dso, ctor_visitor));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_RPATH_ORIG == offset_of!(ldso::dso::Dso, rpath_orig));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_RPATH == offset_of!(ldso::dso::Dso, rpath));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_TLS == offset_of!(ldso::dso::Dso, tls));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_TLS_ID == offset_of!(ldso::dso::Dso, tls_id));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_RELRO_START == offset_of!(ldso::dso::Dso, relro_start));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_RELRO_END == offset_of!(ldso::dso::Dso, relro_end));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_NEW_DTV == offset_of!(ldso::dso::Dso, new_dtv));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_NEW_TLS == offset_of!(ldso::dso::Dso, new_tls));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_TD_INDEX == offset_of!(ldso::dso::Dso, td_index));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_FINI_NEXT == offset_of!(ldso::dso::Dso, fini_next));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_SHORTNAME == offset_of!(ldso::dso::Dso, shortname));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_LOADMAP == offset_of!(ldso::dso::Dso, loadmap));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_FUNCDESCS == offset_of!(ldso::dso::Dso, funcdescs));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_DSO_GOT == offset_of!(ldso::dso::Dso, got));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_STAT_DEV == offset_of!(abi::StatKey, st_dev));
#[cfg(target_arch = "x86_64")]
const _: () = assert!(PROBE_OFF_STAT_INO == offset_of!(abi::StatKey, st_ino));
