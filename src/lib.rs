#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod abi;
pub mod futex;
pub mod mem;
pub mod panic;
pub mod start;
pub mod symbols;
pub mod sync;
pub mod syscall;

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
