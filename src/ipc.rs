//! SysV/POSIX IPC: msg/sem/shm/mq plus a synchronous `aio`
//! (musl `src/ipc/*`, `src/mq/*`, `src/mman/shm_open.c`, `src/aio/*`).
//!
//! SysV and mq entries are one raw syscall each returning through
//! `syscall_ret`, exactly musl's ABI-boundary contract. `ftok` hashes
//! `stat` output like musl's `ftok.c`; `shm_open`/`shm_unlink` map
//! names onto `/dev/shm/` like musl's `shm_open.c`.
//!
//! Deliberate deviations from musl (all cheaper, all documented):
//! - `semctl`/`mq_open` are C-variadic in musl; stable Rust has no C
//!   variadics, so both take a fixed 4-arg shape (same definedness
//!   boundary as this crate's `fcntl` `open`: words the command does
//!   not read are ignored). For `semctl`, `SETVAL` takes the value,
//!   buffer commands take the pointer.
//! - `aio` is synchronous, not musl's thread pool: each op finishes
//!   before it returns, so `__err`/`__ret` are always settled,
//!   `aio_cancel` has nothing to cancel (`AIO_ALLDONE`),
//!   `aio_suspend` degrades to a poll (`0` if anything settled,
//!   `EAGAIN` otherwise — musl's timeout shape, without the wait), and
//!   `lio_listio` runs `LIO_WAIT` inline. `LIO_NOWAIT` with a live
//!   notification request fails with `EAGAIN`: there is no worker
//!   thread to deliver it.
//! - `mq_notify` with `SIGEV_THREAD` fails with `ENOSYS`: musl emulates
//!   it with a netlink socket plus a helper thread; `NULL`/`NONE`/
//!   `SIGNAL` go straight to the kernel like musl's fast path.
//! - `msgsnd`/`msgrcv`/timed-mq are plain traps, not cancellation
//!   points (this crate has no cancellation).

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};

use crate::errno::{__errno_location, errno_load, errno_store};
use crate::signal::Sigval;
use crate::syscall::{syscall1, syscall2, syscall3, syscall4, syscall5, syscall_ret};
use crate::time::Timespec;

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_CLOSE: usize = 3; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_PREAD: usize = 17; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_PWRITE: usize = 18; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_SHMGET: usize = 29; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_SHMAT: usize = 30; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_SHMCTL: usize = 31; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_SEMGET: usize = 64; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_SEMOP: usize = 65; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_SEMCTL: usize = 66; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_SHMDT: usize = 67; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_MSGGET: usize = 68; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_MSGSND: usize = 69; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_MSGRCV: usize = 70; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_MSGCTL: usize = 71; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_FSYNC: usize = 74; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_FDATASYNC: usize = 75; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_SEMTIMEDOP: usize = 220; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_MQ_OPEN: usize = 240; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_MQ_UNLINK: usize = 241; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_MQ_TIMEDSEND: usize = 242; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_MQ_TIMEDRECEIVE: usize = 243; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_MQ_NOTIFY: usize = 244; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_MQ_GETSETATTR: usize = 245; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_OPENAT: usize = 257; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_UNLINKAT: usize = 263; // TODO: generate from arch bits/syscall.h

// ---- Errnos (musl arch/generic/bits/errno.h, local: only ipc needs these) --
#[cfg(target_arch = "x86_64")]
const EPERM: c_int = 1;
#[cfg(target_arch = "x86_64")]
const EINVAL: c_int = 22;
#[cfg(target_arch = "x86_64")]
const EACCES: c_int = 13;
#[cfg(target_arch = "x86_64")]
const EAGAIN: c_int = 11;
#[cfg(target_arch = "x86_64")]
const EIO: c_int = 5;
#[cfg(target_arch = "x86_64")]
const ENOSYS: c_int = 38;
#[cfg(target_arch = "x86_64")]
const EINPROGRESS: c_int = 115;
#[cfg(target_arch = "x86_64")]
const ENAMETOOLONG: c_int = 36;
#[cfg(target_arch = "x86_64")]
const ECANCELED: c_int = 125;

// ---- Types ------------------------------------------------------------------
// musl `include/alltypes.h.in` (`key_t` is `int`).
#[cfg(target_arch = "x86_64")]
#[allow(non_camel_case_types)]
pub type key_t = c_int;
/// musl `include/mqueue.h` (`mqd_t` is `int`).
#[cfg(target_arch = "x86_64")]
#[allow(non_camel_case_types)]
pub type mqd_t = c_int;

/// musl `arch/generic/bits/ipc.h` (`struct ipc_perm`), field for field.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct IpcPerm {
    pub key: key_t,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    pub mode: u32,
    pub seq: c_int,
    pub __pad1: c_long,
    pub __pad2: c_long,
}

/// musl `arch/generic/bits/msg.h` (`struct msqid_ds`), field for field.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct MsqidDs {
    pub msg_perm: IpcPerm,
    pub msg_stime: i64,
    pub msg_rtime: i64,
    pub msg_ctime: i64,
    pub msg_cbytes: u64,
    pub msg_qnum: u64,
    pub msg_qbytes: u64,
    pub msg_lspid: c_int,
    pub msg_lrpid: c_int,
    pub __unused: [u64; 2],
}

/// musl `include/sys/msg.h` (`struct msgbuf`); `mtext` is flexible in C.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Msgbuf {
    pub mtype: c_long,
    pub mtext: [c_char; 1],
}

/// musl `arch/x86_64/bits/sem.h` (`struct semid_ds`), field for field.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct SemidDs {
    pub sem_perm: IpcPerm,
    pub sem_otime: i64,
    pub __unused1: c_long,
    pub sem_ctime: i64,
    pub __unused2: c_long,
    pub sem_nsems: u16,
    pub __sem_nsems_pad: [u8; 6],
    pub __unused3: c_long,
    pub __unused4: c_long,
}

/// musl `include/sys/sem.h` (`struct sembuf`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Sembuf {
    pub sem_num: u16,
    pub sem_op: i16,
    pub sem_flg: i16,
}

/// musl `src/ipc/semctl.c` (`union semun`, undefined in musl's public
/// headers): builds the word [`semctl`] takes as `arg`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Copy, Clone)]
pub union Semun {
    pub val: c_int,
    pub buf: *mut SemidDs,
    pub array: *mut u16,
}

/// musl `arch/generic/bits/shm.h` (`struct shmid_ds`), field for field.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct ShmidDs {
    pub shm_perm: IpcPerm,
    pub shm_segsz: usize,
    pub shm_atime: i64,
    pub shm_dtime: i64,
    pub shm_ctime: i64,
    pub shm_cpid: c_int,
    pub shm_lpid: c_int,
    pub shm_nattch: u64,
    pub __pad1: u64,
    pub __pad2: u64,
}

/// musl `include/mqueue.h` (`struct mq_attr`), field for field.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct MqAttr {
    pub mq_flags: c_long,
    pub mq_maxmsg: c_long,
    pub mq_msgsize: c_long,
    pub mq_curmsgs: c_long,
    pub __unused: [c_long; 4],
}

/// musl `include/signal.h:184-196` (`struct sigevent`), minimal and field
/// for field: value, signal, notify kind, then a 48-byte arm holding the
/// thread id or the thread-callback pair.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Sigevent {
    pub sigev_value: Sigval,
    pub sigev_signo: c_int,
    pub sigev_notify: c_int,
    pub sigev_un: SigevUn,
}

/// Thread-callback arm of [`Sigevent`] (attributes stay an opaque pointer;
/// its layout belongs to the threads wave).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SigevThread {
    pub function: Option<unsafe extern "C" fn(Sigval)>,
    pub attributes: *mut c_void,
}

/// Trailing arm of [`Sigevent`].
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Copy, Clone)]
pub union SigevUn {
    pub pad: [u8; 48],
    pub thread_id: c_int,
    pub thread: SigevThread,
}

/// musl `include/aio.h` (`struct aiocb`), field for field. `aio_buf` is
/// `volatile void *` in C; volatility is not modeled (completion here is
/// synchronous, so no other thread observes the control block mid-flight).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Aiocb {
    pub aio_fildes: c_int,
    pub aio_lio_opcode: c_int,
    pub aio_reqprio: c_int,
    pub aio_buf: *mut c_void,
    pub aio_nbytes: usize,
    pub aio_sigevent: Sigevent,
    pub __td: *mut c_void,
    pub __lock: [c_int; 2],
    pub __err: c_int,
    pub __ret: isize,
    pub aio_offset: i64,
    pub __next: *mut c_void,
    pub __prev: *mut c_void,
    pub __dummy4: [u8; 16],
}

#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<IpcPerm>() == 48);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<MsqidDs>() == 120);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<SemidDs>() == 104);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<Sembuf>() == 6);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<Semun>() == 8);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<ShmidDs>() == 112);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<MqAttr>() == 64);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<Sigevent>() == 64);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<Aiocb>() == 168);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(Aiocb, aio_buf) == 16);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(Aiocb, aio_nbytes) == 24);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(Aiocb, aio_sigevent) == 32);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(Aiocb, __err) == 112);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(Aiocb, __ret) == 120);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(Aiocb, aio_offset) == 128);

// ---- Constants ---------------------------------------------------------------
// musl `include/sys/ipc.h`.
#[cfg(target_arch = "x86_64")]
pub const IPC_CREAT: c_int = 0o1000;
#[cfg(target_arch = "x86_64")]
pub const IPC_EXCL: c_int = 0o2000;
#[cfg(target_arch = "x86_64")]
pub const IPC_NOWAIT: c_int = 0o4000;
#[cfg(target_arch = "x86_64")]
pub const IPC_PRIVATE: key_t = 0;
#[cfg(target_arch = "x86_64")]
pub const IPC_RMID: c_int = 0;
#[cfg(target_arch = "x86_64")]
pub const IPC_SET: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const IPC_STAT: c_int = 2;
#[cfg(target_arch = "x86_64")]
pub const IPC_INFO: c_int = 3;
// musl `src/ipc/ipc.h` (kernel ABI selector, ORed into ctl commands).

// musl `include/sys/msg.h`.
#[cfg(target_arch = "x86_64")]
pub const MSG_NOERROR: c_int = 0o10000;
#[cfg(target_arch = "x86_64")]
pub const MSG_EXCEPT: c_int = 0o20000;
#[cfg(target_arch = "x86_64")]
pub const MSG_STAT: c_int = 11 | 0x100;
#[cfg(target_arch = "x86_64")]
pub const MSG_INFO: c_int = 12;
#[cfg(target_arch = "x86_64")]
pub const MSG_STAT_ANY: c_int = 13 | 0x100;

// musl `include/sys/sem.h`.
#[cfg(target_arch = "x86_64")]
pub const SEM_UNDO: c_int = 0x1000;
#[cfg(target_arch = "x86_64")]
pub const GETPID: c_int = 11;
#[cfg(target_arch = "x86_64")]
pub const GETVAL: c_int = 12;
#[cfg(target_arch = "x86_64")]
pub const GETALL: c_int = 13;
#[cfg(target_arch = "x86_64")]
pub const GETNCNT: c_int = 14;
#[cfg(target_arch = "x86_64")]
pub const GETZCNT: c_int = 15;
#[cfg(target_arch = "x86_64")]
pub const SETVAL: c_int = 16;
#[cfg(target_arch = "x86_64")]
pub const SETALL: c_int = 17;
#[cfg(target_arch = "x86_64")]
pub const SEM_STAT: c_int = 18 | 0x100;
#[cfg(target_arch = "x86_64")]
pub const SEM_INFO: c_int = 19;
#[cfg(target_arch = "x86_64")]
pub const SEM_STAT_ANY: c_int = 20 | 0x100;

// musl `include/sys/shm.h` + `arch/generic/bits/shm.h`.
#[cfg(target_arch = "x86_64")]
pub const SHM_R: c_int = 0o400;
#[cfg(target_arch = "x86_64")]
pub const SHM_W: c_int = 0o200;
#[cfg(target_arch = "x86_64")]
pub const SHM_RDONLY: c_int = 0o10000;
#[cfg(target_arch = "x86_64")]
pub const SHM_RND: c_int = 0o20000;
#[cfg(target_arch = "x86_64")]
pub const SHM_REMAP: c_int = 0o40000;
#[cfg(target_arch = "x86_64")]
pub const SHM_EXEC: c_int = 0o100000;
#[cfg(target_arch = "x86_64")]
pub const SHM_LOCK: c_int = 11;
#[cfg(target_arch = "x86_64")]
pub const SHM_UNLOCK: c_int = 12;
#[cfg(target_arch = "x86_64")]
pub const SHM_STAT: c_int = 13 | 0x100;
#[cfg(target_arch = "x86_64")]
pub const SHM_INFO: c_int = 14;
#[cfg(target_arch = "x86_64")]
pub const SHM_STAT_ANY: c_int = 15 | 0x100;
#[cfg(target_arch = "x86_64")]
pub const SHM_DEST: c_int = 0o1000;
#[cfg(target_arch = "x86_64")]
pub const SHM_LOCKED: c_int = 0o2000;
#[cfg(target_arch = "x86_64")]
pub const SHM_HUGETLB: c_int = 0o4000;
#[cfg(target_arch = "x86_64")]
pub const SHM_NORESERVE: c_int = 0o10000;
#[cfg(target_arch = "x86_64")]
pub const SHMLBA: usize = 4096;

// `O_*`/`AT_*` the mq/shm/aio entries need beyond `crate::fcntl`
// (musl `arch/generic/bits/fcntl.h` + `include/fcntl.h`).
#[cfg(target_arch = "x86_64")]
pub const O_NOFOLLOW: c_int = 0o400000;
#[cfg(target_arch = "x86_64")]
pub const O_DSYNC: c_int = 0o10000;
#[cfg(target_arch = "x86_64")]
pub const O_SYNC: c_int = 0o4010000;
#[cfg(target_arch = "x86_64")]
pub const O_RDONLY: c_int = 0;
#[cfg(target_arch = "x86_64")]
pub const O_RDWR: c_int = 2;
#[cfg(target_arch = "x86_64")]
const AT_FDCWD: c_int = -100;

// musl `include/signal.h:202-204`.
#[cfg(target_arch = "x86_64")]
pub const SIGEV_SIGNAL: c_int = 0;
#[cfg(target_arch = "x86_64")]
pub const SIGEV_NONE: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const SIGEV_THREAD: c_int = 2;

// musl `include/aio.h`.
#[cfg(target_arch = "x86_64")]
pub const AIO_CANCELED: c_int = 0;
#[cfg(target_arch = "x86_64")]
pub const AIO_NOTCANCELED: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const AIO_ALLDONE: c_int = 2;
#[cfg(target_arch = "x86_64")]
pub const LIO_READ: c_int = 0;
#[cfg(target_arch = "x86_64")]
pub const LIO_WRITE: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const LIO_NOP: c_int = 2;
#[cfg(target_arch = "x86_64")]
pub const LIO_WAIT: c_int = 0;
#[cfg(target_arch = "x86_64")]
pub const LIO_NOWAIT: c_int = 1;

// Command word for the direct `*ctl` syscalls (musl `src/ipc/ipc.h`
// `IPC_CMD` would OR `IPC_64` here, but measured kernels reject the
// flag on control ops (`msgctl(q, 0x100, _)` → EINVAL while plain `0`
// succeeds; glibc and musl binaries both pass verbatim). The `STAT`
// selectors already carry their bit (`IPC_STAT` is `0x102`), so
// verbatim is exact on x86_64.
#[cfg(target_arch = "x86_64")]
fn ipc_cmd(cmd: c_int) -> c_int {
    cmd
}

// ---- SysV IPC ---------------------------------------------------------------

/// Make a key from a path and an id (musl `ftok`: `stat` + inode/dev/id
/// hash; `-1` when the path does not stat, `errno` from `stat`).
///
/// # Safety
///
/// `path` must point to a NUL-terminated string.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ftok(path: *const c_char, id: c_int) -> key_t {
    unsafe {
        let mut st: crate::stat::Stat = core::mem::zeroed();
        if crate::stat::stat(path, &mut st) < 0 {
            return -1;
        }
        ((st.st_ino & 0xffff) | ((st.st_dev & 0xff) << 16) | (((id as u32) & 0xff) as u64) << 24)
            as key_t
    }
}

/// Get/create a message queue (musl `msgget`: direct `SYS_msgget`).
///
/// # Safety
///
/// Pure syscall wrapper; no pointers involved.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn msgget(key: key_t, flag: c_int) -> c_int {
    unsafe { syscall_ret(syscall2(SYS_MSGGET, key as usize, flag as usize)) as c_int }
}

/// Control a message queue (musl `msgctl`, 64-bit path: `IPC_64` ORed
/// into the command, no time/BROKEN_MODE translation on x86_64).
///
/// # Safety
///
/// `buf` must point to a readable/writable [`MsqidDs`] for the commands
/// that use it (`IPC_STAT`, `IPC_SET`, ...); null/`0` otherwise.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn msgctl(q: c_int, cmd: c_int, buf: *mut MsqidDs) -> c_int {
    unsafe {
        syscall_ret(syscall3(
            SYS_MSGCTL,
            q as usize,
            ipc_cmd(cmd) as usize,
            buf as usize,
        )) as c_int
    }
}

/// Send a message (musl `msgsnd`: direct `SYS_msgsnd`).
///
/// # Safety
///
/// `m` must point to a `len`-byte payload preceded by a `long` type.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn msgsnd(q: c_int, m: *const c_void, len: usize, flag: c_int) -> c_int {
    unsafe {
        syscall_ret(syscall4(
            SYS_MSGSND,
            q as usize,
            m as usize,
            len,
            flag as usize,
        )) as c_int
    }
}

/// Receive a message (musl `msgrcv`: direct `SYS_msgrcv`).
///
/// # Safety
///
/// `m` must be writable for `len` bytes plus the leading `long` type.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn msgrcv(
    q: c_int,
    m: *mut c_void,
    len: usize,
    typ: c_long,
    flag: c_int,
) -> isize {
    unsafe {
        syscall_ret(syscall5(
            SYS_MSGRCV,
            q as usize,
            m as usize,
            len,
            typ as usize,
            flag as usize,
        ))
    }
}

/// Get/create a semaphore set (musl `semget`, including its userspace
/// `n > USHRT_MAX` guard: the kernel's `sem_nsems` is the wrong width
/// to check it).
///
/// # Safety
///
/// Pure syscall wrapper; no pointers involved.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn semget(key: key_t, n: c_int, flag: c_int) -> c_int {
    unsafe {
        if n > 0xffff {
            errno_store(__errno_location(), EINVAL);
            return -1;
        }
        syscall_ret(syscall3(
            SYS_SEMGET,
            key as usize,
            n as usize,
            flag as usize,
        )) as c_int
    }
}

/// Control a semaphore (musl `semctl`, 64-bit path; fixed 4-arg shape —
/// see module docs: `SETVAL` takes the value, buffer commands take the
/// pointer, other commands ignore `arg`).
///
/// # Safety
///
/// `arg` must be the command's value (`SETVAL`) or a valid pointer of
/// the command's kind (`IPC_STAT`/`IPC_SET`/`GETALL`/`SETALL`); it is
/// never dereferenced here, only handed to the kernel.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn semctl(id: c_int, num: c_int, cmd: c_int, arg: usize) -> c_int {
    unsafe {
        syscall_ret(syscall4(
            SYS_SEMCTL,
            id as usize,
            num as usize,
            ipc_cmd(cmd) as usize,
            arg,
        )) as c_int
    }
}

/// Operate on semaphores (musl `semop`: direct `SYS_semop`).
///
/// # Safety
///
/// `buf` must point to `n` readable [`Sembuf`]s.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn semop(id: c_int, buf: *mut Sembuf, n: usize) -> c_int {
    unsafe { syscall_ret(syscall3(SYS_SEMOP, id as usize, buf as usize, n)) as c_int }
}

/// Timed semaphore operation (musl `semtimedop`, 64-bit path: direct
/// `SYS_semtimedop`; no time32/time64 dance on x86_64).
///
/// # Safety
///
/// `buf` must point to `n` readable [`Sembuf`]s; `ts` must be null or
/// point to a readable timeout.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn semtimedop(
    id: c_int,
    buf: *mut Sembuf,
    n: usize,
    ts: *const Timespec,
) -> c_int {
    unsafe {
        syscall_ret(syscall4(
            SYS_SEMTIMEDOP,
            id as usize,
            buf as usize,
            n,
            ts as usize,
        )) as c_int
    }
}

/// Get/create shared memory (musl `shmget`, including the `size >
/// PTRDIFF_MAX` clamp).
///
/// # Safety
///
/// Pure syscall wrapper; no pointers involved.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn shmget(key: key_t, size: usize, flag: c_int) -> c_int {
    unsafe {
        let size = if size > i64::MAX as usize {
            usize::MAX
        } else {
            size
        };
        syscall_ret(syscall3(SYS_SHMGET, key as usize, size, flag as usize)) as c_int
    }
}

/// Control shared memory (musl `shmctl`, 64-bit path: `IPC_64` ORed
/// into the command).
///
/// # Safety
///
/// `buf` must point to a readable/writable [`ShmidDs`] for the commands
/// that use it; null/`0` otherwise.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn shmctl(id: c_int, cmd: c_int, buf: *mut ShmidDs) -> c_int {
    unsafe {
        syscall_ret(syscall3(
            SYS_SHMCTL,
            id as usize,
            ipc_cmd(cmd) as usize,
            buf as usize,
        )) as c_int
    }
}

/// Attach shared memory (musl `shmat`: the raw trap value is the
/// address; any `-4095..-1` result sets `errno` and comes back as
/// `(void *)-1`, never null).
///
/// # Safety
///
/// `addr` must be null or a valid attach address for `flag`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn shmat(id: c_int, addr: *const c_void, flag: c_int) -> *mut c_void {
    unsafe {
        let r = syscall3(SYS_SHMAT, id as usize, addr as usize, flag as usize);
        if (-4095..=-1).contains(&r) {
            let _ = syscall_ret(r);
            (-1isize) as *mut c_void
        } else {
            r as *mut c_void
        }
    }
}

/// Detach shared memory (musl `shmdt`: direct `SYS_shmdt`).
///
/// # Safety
///
/// `addr` must be an attached address.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn shmdt(addr: *const c_void) -> c_int {
    unsafe { syscall_ret(syscall1(SYS_SHMDT, addr as usize)) as c_int }
}

// ---- POSIX message queues ----------------------------------------------------

/// Open a message queue (musl `mq_open`: one leading `/` stripped, fixed
/// 4-arg shape — `mode`/`attr` are only read with `O_CREAT`, same
/// boundary as this crate's `fcntl` `open`).
///
/// # Safety
///
/// `name` must point to a NUL-terminated string; `attr` must be null or
/// point to a readable [`MqAttr`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mq_open(
    name: *const c_char,
    flags: c_int,
    mode: c_uint,
    attr: *const MqAttr,
) -> mqd_t {
    unsafe {
        let mut p = name;
        if *p == b'/' as c_char {
            p = p.add(1);
        }
        syscall_ret(syscall4(
            SYS_MQ_OPEN,
            p as usize,
            flags as usize,
            mode as usize,
            attr as usize,
        )) as mqd_t
    }
}

/// Close a queue (musl `mq_close`: `close`).
///
/// # Safety
///
/// `mqd` must be an open queue descriptor.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mq_close(mqd: mqd_t) -> c_int {
    unsafe { syscall_ret(syscall1(SYS_CLOSE, mqd as usize)) as c_int }
}

/// Unlink a queue (musl `mq_unlink`: one leading `/` stripped,
/// kernel `EPERM` reported as `EACCES`).
///
/// # Safety
///
/// `name` must point to a NUL-terminated string.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mq_unlink(name: *const c_char) -> c_int {
    unsafe {
        let mut p = name;
        if *p == b'/' as c_char {
            p = p.add(1);
        }
        let r = syscall1(SYS_MQ_UNLINK, p as usize);
        if r < 0 {
            let e = if r == -(EPERM as isize) {
                EACCES
            } else {
                (-r) as c_int
            };
            errno_store(__errno_location(), e);
            return -1;
        }
        r as c_int
    }
}

/// Get queue attributes (musl `mq_getattr`: `mq_setattr` with null new).
///
/// # Safety
///
/// `attr` must point to a writable [`MqAttr`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mq_getattr(mqd: mqd_t, attr: *mut MqAttr) -> c_int {
    unsafe { mq_setattr(mqd, core::ptr::null(), attr) }
}

/// Set/get queue attributes (musl `mq_setattr`: `SYS_mq_getsetattr`).
///
/// # Safety
///
/// `new`/`old` must each be null or point to a readable/writable
/// [`MqAttr`] respectively.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mq_setattr(mqd: mqd_t, new: *const MqAttr, old: *mut MqAttr) -> c_int {
    unsafe {
        syscall_ret(syscall3(
            SYS_MQ_GETSETATTR,
            mqd as usize,
            new as usize,
            old as usize,
        )) as c_int
    }
}

/// Register for queue notification (musl `mq_notify` fast path: null,
/// `SIGEV_NONE` and `SIGEV_SIGNAL` go to the kernel; `SIGEV_THREAD`
/// needs musl's netlink helper thread and fails here with `ENOSYS`).
///
/// # Safety
///
/// `sev` must be null or point to a readable [`Sigevent`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mq_notify(mqd: mqd_t, sev: *const Sigevent) -> c_int {
    unsafe {
        if !sev.is_null() && (*sev).sigev_notify == SIGEV_THREAD {
            errno_store(__errno_location(), ENOSYS);
            return -1;
        }
        syscall_ret(syscall2(SYS_MQ_NOTIFY, mqd as usize, sev as usize)) as c_int
    }
}

/// Send a message (musl `mq_send`: `mq_timedsend` with a null timeout).
///
/// # Safety
///
/// `msg` must be readable for `len` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mq_send(
    mqd: mqd_t,
    msg: *const c_char,
    len: usize,
    prio: c_uint,
) -> c_int {
    unsafe { mq_timedsend(mqd, msg, len, prio, core::ptr::null()) }
}

/// Receive a message (musl `mq_receive`: `mq_timedreceive` with null).
///
/// # Safety
///
/// `msg` must be writable for `len` bytes; `prio` must be null or point
/// to a writable `unsigned`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mq_receive(
    mqd: mqd_t,
    msg: *mut c_char,
    len: usize,
    prio: *mut c_uint,
) -> isize {
    unsafe { mq_timedreceive(mqd, msg, len, prio, core::ptr::null()) }
}

/// Timed send (musl `mq_timedsend`, 64-bit path: direct trap).
///
/// # Safety
///
/// Like [`mq_send`], plus `at` must be null or point to a readable
/// absolute timeout.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mq_timedsend(
    mqd: mqd_t,
    msg: *const c_char,
    len: usize,
    prio: c_uint,
    at: *const Timespec,
) -> c_int {
    unsafe {
        syscall_ret(syscall5(
            SYS_MQ_TIMEDSEND,
            mqd as usize,
            msg as usize,
            len,
            prio as usize,
            at as usize,
        )) as c_int
    }
}

/// Timed receive (musl `mq_timedreceive`, 64-bit path: direct trap).
///
/// # Safety
///
/// Like [`mq_receive`], plus `at` must be null or point to a readable
/// absolute timeout.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mq_timedreceive(
    mqd: mqd_t,
    msg: *mut c_char,
    len: usize,
    prio: *mut c_uint,
    at: *const Timespec,
) -> isize {
    unsafe {
        syscall_ret(syscall5(
            SYS_MQ_TIMEDRECEIVE,
            mqd as usize,
            msg as usize,
            len,
            prio as usize,
            at as usize,
        ))
    }
}

// ---- POSIX shared memory ------------------------------------------------------
// musl `src/mman/shm_open.c:__shm_mapname`: at most one name segment,
// no `.`/`..`, `NAME_MAX` cap, rooted at `/dev/shm/`.

/// Longest single name segment (musl `NAME_MAX`).
#[cfg(target_arch = "x86_64")]
const NAME_MAX: usize = 255;

/// Map `name` onto `/dev/shm/<name>` in `buf` (musl `__shm_mapname`).
/// Returns null with `errno` set for a bad name.
///
/// # Safety
///
/// `name` must point to a NUL-terminated string; `buf` must hold 265
/// writable bytes (`"/dev/shm/"` + `NAME_MAX` + NUL).
#[cfg(target_arch = "x86_64")]
unsafe fn shm_mapname(name: *const c_char, buf: *mut c_char) -> *const c_char {
    unsafe {
        let fail = |e: c_int| {
            errno_store(__errno_location(), e);
            core::ptr::null()
        };
        let mut p = name;
        while *p == b'/' as c_char {
            p = p.add(1);
        }
        let mut len = 0usize;
        while *p.add(len) != 0 {
            if *p.add(len) == b'/' as c_char {
                return fail(EINVAL);
            }
            len += 1;
        }
        if len == 0
            || (len <= 2 && *p == b'.' as c_char && (len == 1 || *p.add(1) == b'.' as c_char))
            || len > NAME_MAX
        {
            return fail(if len > NAME_MAX { ENAMETOOLONG } else { EINVAL });
        }
        const PREFIX: &[u8; 9] = b"/dev/shm/";
        let mut i = 0usize;
        while i < 9 {
            *buf.add(i) = PREFIX[i] as c_char;
            i += 1;
        }
        let mut j = 0usize;
        while j <= len {
            *buf.add(9 + j) = *p.add(j);
            j += 1;
        }
        buf as *const c_char
    }
}

/// Open shared memory (musl `shm_open`: mapped path opened with
/// `O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK` added, like musl).
///
/// # Safety
///
/// `name` must point to a NUL-terminated string; `mode` is only read
/// with `O_CREAT`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn shm_open(name: *const c_char, flags: c_int, mode: c_uint) -> c_int {
    unsafe {
        let mut buf = [0 as c_char; 265];
        let mapped = shm_mapname(name, buf.as_mut_ptr());
        if mapped.is_null() {
            return -1;
        }
        syscall_ret(syscall4(
            SYS_OPENAT,
            AT_FDCWD as usize,
            mapped as usize,
            (flags | O_NOFOLLOW | crate::fcntl::O_CLOEXEC | crate::fcntl::O_NONBLOCK) as usize,
            mode as usize,
        )) as c_int
    }
}

/// Unlink shared memory (musl `shm_unlink`: mapped path unlinked).
///
/// # Safety
///
/// `name` must point to a NUL-terminated string.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn shm_unlink(name: *const c_char) -> c_int {
    unsafe {
        let mut buf = [0 as c_char; 265];
        let mapped = shm_mapname(name, buf.as_mut_ptr());
        if mapped.is_null() {
            return -1;
        }
        syscall_ret(syscall3(
            SYS_UNLINKAT,
            AT_FDCWD as usize,
            mapped as usize,
            0,
        )) as c_int
    }
}

// ---- Synchronous aio ----------------------------------------------------------
// musl `src/aio/*` runs a per-fd thread pool; this backend runs each op
// inline (see module docs). One shared settler keeps the error/return
// bookkeeping identical for read, write and fsync.

/// Run `op` inline and settle `cb` (shared by read/write/fsync).
///
/// # Safety
///
/// `cb` fields must describe a valid fd/buffer/offset; `run` performs
/// the raw trap and returns the kernel result.
#[cfg(target_arch = "x86_64")]
unsafe fn aio_settle(cb: *mut Aiocb, run: isize) -> c_int {
    unsafe {
        if run < 0 {
            (*cb).__ret = -1;
            (*cb).__err = errno_load(__errno_location());
            -1
        } else {
            (*cb).__ret = run;
            (*cb).__err = 0;
            0
        }
    }
}

/// Queue a read (synchronous: `pread` runs before return).
///
/// # Safety
///
/// `cb` must point to a writable [`Aiocb`] whose buffer is writable for
/// `aio_nbytes` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn aio_read(cb: *mut Aiocb) -> c_int {
    unsafe {
        let r = syscall_ret(syscall4(
            SYS_PREAD,
            (*cb).aio_fildes as usize,
            (*cb).aio_buf as usize,
            (*cb).aio_nbytes,
            (*cb).aio_offset as usize,
        ));
        aio_settle(cb, r)
    }
}

/// Queue a write (synchronous: `pwrite` runs before return).
///
/// # Safety
///
/// `cb` must point to a writable [`Aiocb`] whose buffer is readable for
/// `aio_nbytes` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn aio_write(cb: *mut Aiocb) -> c_int {
    unsafe {
        let r = syscall_ret(syscall4(
            SYS_PWRITE,
            (*cb).aio_fildes as usize,
            (*cb).aio_buf as usize,
            (*cb).aio_nbytes,
            (*cb).aio_offset as usize,
        ));
        aio_settle(cb, r)
    }
}

/// Queue a sync (synchronous: `fsync`/`fdatasync` runs before return;
/// any other `op` is `EINVAL`, like musl).
///
/// # Safety
///
/// `cb` must point to a writable [`Aiocb`] for an open fd.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn aio_fsync(op: c_int, cb: *mut Aiocb) -> c_int {
    unsafe {
        let sys = if op == O_SYNC {
            SYS_FSYNC
        } else if op == O_DSYNC {
            SYS_FDATASYNC
        } else {
            errno_store(__errno_location(), EINVAL);
            return -1;
        };
        let r = syscall_ret(syscall1(sys, (*cb).aio_fildes as usize));
        aio_settle(cb, if r < 0 { r } else { 0 })
    }
}

/// Last error of the op (musl `aio_error`: the settled `__err`, masked
/// like musl's waiter-bit mask).
///
/// # Safety
///
/// `cb` must point to a readable [`Aiocb`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn aio_error(cb: *const Aiocb) -> c_int {
    unsafe { (*cb).__err & 0x7fffffff }
}

/// Return value of a finished op (musl `aio_return`).
///
/// # Safety
///
/// `cb` must point to a readable [`Aiocb`] whose op already finished
/// (always true here: completion is synchronous).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn aio_return(cb: *mut Aiocb) -> isize {
    unsafe { (*cb).__ret }
}

/// Cancel ops (synchronous backend: nothing is ever in flight, so every
/// consistent request is already done; a mismatched `cb` is `EINVAL`,
/// like musl's unspecified-behavior guard).
///
/// # Safety
///
/// `cb` must be null or point to a readable [`Aiocb`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn aio_cancel(fd: c_int, cb: *mut Aiocb) -> c_int {
    unsafe {
        if !cb.is_null() && fd != (*cb).aio_fildes {
            errno_store(__errno_location(), EINVAL);
            return -1;
        }
        let _ = ECANCELED;
        AIO_ALLDONE
    }
}

/// Wait for ops (synchronous backend: a settled op returns `0` at once;
/// with nothing settled this reports `EAGAIN`, musl's timeout shape,
/// instead of blocking).
///
/// # Safety
///
/// `cbs` must point to `cnt` readable nullable pointers; `ts` is
/// ignored (nothing can still be pending).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn aio_suspend(
    cbs: *const *const Aiocb,
    cnt: c_int,
    ts: *const Timespec,
) -> c_int {
    unsafe {
        let _ = ts;
        if cnt < 0 {
            errno_store(__errno_location(), EINVAL);
            return -1;
        }
        let mut i = 0;
        while i < cnt {
            let cb = *cbs.add(i as usize);
            if !cb.is_null() && ((*cb).__err & 0x7fffffff) != EINPROGRESS {
                return 0;
            }
            i += 1;
        }
        errno_store(__errno_location(), EAGAIN);
        -1
    }
}

/// List I/O (musl `lio_listio`, synchronous: each op runs inline;
/// `LIO_WAIT` collects `EIO` on any failure; `LIO_NOWAIT` with a live
/// notification fails with `EAGAIN` — no worker exists to deliver it).
///
/// # Safety
///
/// `cbs` must point to `cnt` nullable writable [`Aiocb`] pointers with
/// valid `aio_lio_opcode`s; `sev` must be null or readable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn lio_listio(
    mode: c_int,
    cbs: *const *mut Aiocb,
    cnt: c_int,
    sev: *mut Sigevent,
) -> c_int {
    unsafe {
        if cnt < 0 {
            errno_store(__errno_location(), EINVAL);
            return -1;
        }
        let mut i = 0;
        while i < cnt {
            let cb = *cbs.add(i as usize);
            if !cb.is_null() {
                let r = match (*cb).aio_lio_opcode {
                    LIO_READ => aio_read(cb),
                    LIO_WRITE => aio_write(cb),
                    _ => 0,
                };
                if r != 0 {
                    errno_store(__errno_location(), EAGAIN);
                    return -1;
                }
            }
            i += 1;
        }
        if mode == LIO_WAIT {
            let mut j = 0;
            while j < cnt {
                let cb = *cbs.add(j as usize);
                if !cb.is_null() && ((*cb).__err & 0x7fffffff) != 0 {
                    errno_store(__errno_location(), EIO);
                    return -1;
                }
                j += 1;
            }
            return 0;
        }
        if !sev.is_null() && (*sev).sigev_notify != SIGEV_NONE {
            errno_store(__errno_location(), EAGAIN);
            return -1;
        }
        0
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::{
        aio_cancel, aio_error, aio_fsync, aio_read, aio_return, aio_suspend, aio_write, ftok,
        lio_listio, mq_close, mq_getattr, mq_open, mq_receive, mq_send, mq_unlink, msgctl, msgget,
        msgrcv, msgsnd, semctl, semget, semop, shm_open, shm_unlink, shmat, shmctl, shmdt, shmget,
        Aiocb, MqAttr, Sigevent, AIO_ALLDONE, GETVAL, IPC_CREAT, IPC_PRIVATE, IPC_RMID, LIO_WAIT,
        LIO_WRITE, O_RDWR, SETVAL,
    };
    use core::ffi::{c_char, c_int, c_long, c_void};

    use crate::fcntl::{O_CREAT, O_NONBLOCK};
    use crate::syscall::{syscall3, syscall_ret};

    /// musl `arch/x86_64/bits/syscall.h.in` (test I/O + cleanup only).
    const SYS_READ: usize = 0; // TODO: generate from arch bits/syscall.h
    const SYS_WRITE: usize = 1; // TODO: generate from arch bits/syscall.h
    const SYS_CLOSE: usize = 3; // TODO: generate from arch bits/syscall.h
    const SYS_UNLINK: usize = 87; // TODO: generate from arch bits/syscall.h

    unsafe fn close(fd: c_int) {
        unsafe {
            let _ = syscall_ret(syscall3(SYS_CLOSE, fd as usize, 0, 0));
        }
    }

    fn tmp_cstr(tag: &str) -> std::ffi::CString {
        std::ffi::CString::new(std::format!("/tmp/zlibc-10d-{tag}-{}", std::process::id())).unwrap()
    }

    fn zero_aiocb() -> Aiocb {
        // `Sigevent`/`Aiocb` have no padding surprises; zero-init is the
        // settled-idle state (`__err == 0` reads "done", like musl's
        // never-submitted block, so tests submit before suspending).
        unsafe { core::mem::zeroed() }
    }

    #[test]
    fn struct_layouts_match_musl() {
        assert_eq!(core::mem::size_of::<super::IpcPerm>(), 48);
        assert_eq!(core::mem::size_of::<super::MsqidDs>(), 120);
        assert_eq!(core::mem::offset_of!(super::MsqidDs, msg_qnum), 80);
        assert_eq!(core::mem::size_of::<super::SemidDs>(), 104);
        assert_eq!(core::mem::offset_of!(super::SemidDs, sem_nsems), 80);
        assert_eq!(core::mem::size_of::<super::Sembuf>(), 6);
        assert_eq!(core::mem::size_of::<super::ShmidDs>(), 112);
        assert_eq!(core::mem::offset_of!(super::ShmidDs, shm_nattch), 88);
        assert_eq!(core::mem::size_of::<super::MqAttr>(), 64);
        assert_eq!(core::mem::size_of::<Sigevent>(), 64);
        assert_eq!(core::mem::size_of::<Aiocb>(), 168);
        assert_eq!(core::mem::offset_of!(Aiocb, aio_offset), 128);
    }

    #[test]
    fn ftok_hashes_stable() {
        let path = tmp_cstr("ftok");
        std::fs::write(path.to_str().unwrap(), b"k").unwrap();
        unsafe {
            let a = ftok(path.as_ptr(), 7);
            assert!(a != -1);
            assert_eq!(ftok(path.as_ptr(), 7), a);
            assert_ne!(ftok(path.as_ptr(), 8), a);
            let missing = std::ffi::CString::new(std::format!(
                "/tmp/zlibc-10d-missing-{}",
                std::process::id()
            ))
            .unwrap();
            assert_eq!(ftok(missing.as_ptr(), 7), -1);
            assert_eq!(
                syscall_ret(syscall3(SYS_UNLINK, path.as_ptr() as usize, 0, 0)),
                0
            );
        }
    }

    #[repr(C)]
    struct TestMsg {
        mtype: i64,
        mtext: [u8; 32],
    }

    #[test]
    fn msg_roundtrip_and_remove() {
        let _guard = crate::ldso::testlock::lock();
        let path = tmp_cstr("msg");
        std::fs::write(path.to_str().unwrap(), b"k").unwrap();
        unsafe {
            let key = ftok(path.as_ptr(), 11);
            assert!(key != -1);
            let q = msgget(key, IPC_CREAT | 0o600);
            assert!(q >= 0);
            let out = TestMsg {
                mtype: 3,
                mtext: *b"hello sysv                      ",
            };
            assert_eq!(msgsnd(q, &out as *const TestMsg as *const c_void, 32, 0), 0);
            let mut back: TestMsg = core::mem::zeroed();
            let r = msgrcv(q, &mut back as *mut TestMsg as *mut c_void, 32, 0, 0);
            assert_eq!(r, 32);
            assert_eq!(back.mtype, 3);
            assert_eq!(&back.mtext, &out.mtext);
            assert_eq!(msgctl(q, IPC_RMID, core::ptr::null_mut()), 0);
            assert_eq!(
                syscall_ret(syscall3(SYS_UNLINK, path.as_ptr() as usize, 0, 0)),
                0
            );
        }
    }

    #[test]
    fn sem_setval_getval_and_remove() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let id = semget(IPC_PRIVATE, 1, IPC_CREAT | 0o600);
            assert!(id >= 0);
            assert_eq!(semctl(id, 0, SETVAL, 42), 0);
            assert_eq!(semctl(id, 0, GETVAL, 0), 42);
            // A zero-op waits on a zero-valued sem and returns at once.
            let mut op = super::Sembuf {
                sem_num: 0,
                sem_op: 0,
                sem_flg: 0,
            };
            // Value is 42, not 0: use IPC_NOWAIT so this fails cleanly
            // instead of blocking, proving the op path reaches the kernel.
            op.sem_flg = super::IPC_NOWAIT as i16;
            assert_eq!(semop(id, &mut op, 1), -1);
            op.sem_op = -42;
            op.sem_flg = 0;
            assert_eq!(semop(id, &mut op, 1), 0);
            assert_eq!(semctl(id, 0, GETVAL, 0), 0);
            assert_eq!(semctl(id, 0, IPC_RMID, 0), 0);
        }
    }

    #[test]
    fn shm_attach_write_detach_remove() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0o600);
            assert!(id >= 0);
            let p = shmat(id, core::ptr::null(), 0);
            assert!(!p.is_null() && p != (-1isize) as *mut c_void);
            let slot = p as *mut u64;
            *slot = 0x12345678_9abcdef0;
            assert_eq!(*slot, 0x12345678_9abcdef0);
            assert_eq!(shmdt(p as *const c_void), 0);
            assert_eq!(shmctl(id, IPC_RMID, core::ptr::null_mut()), 0);
        }
    }

    #[test]
    fn mq_send_receive_close_unlink() {
        let _guard = crate::ldso::testlock::lock();
        let name =
            std::ffi::CString::new(std::format!("/zlibc-10d-mq-{}", std::process::id())).unwrap();
        unsafe {
            let q = mq_open(name.as_ptr(), O_RDWR | O_CREAT, 0o600, core::ptr::null());
            assert!(q >= 0, "mq_open failed");
            let msg = b"ping";
            assert_eq!(mq_send(q, msg.as_ptr() as *const c_char, msg.len(), 0), 0);
            // Receive buffer must hold mq_msgsize (queue max), not just
            // the message: query it first (also covers mq_getattr).
            let mut attr: MqAttr = core::mem::zeroed();
            assert_eq!(mq_getattr(q, &mut attr), 0);
            assert!(attr.mq_msgsize >= msg.len() as c_long);
            let mut back = [0u8; 8192];
            assert!((attr.mq_msgsize as usize) <= back.len());
            let r = mq_receive(
                q,
                back.as_mut_ptr() as *mut c_char,
                back.len(),
                core::ptr::null_mut(),
            );
            assert_eq!(r, msg.len() as isize);
            assert_eq!(&back[..msg.len()], msg);
            assert_eq!(mq_close(q), 0);
            assert_eq!(mq_unlink(name.as_ptr()), 0);
        }
    }

    #[test]
    fn shm_open_write_unlink() {
        let _guard = crate::ldso::testlock::lock();
        let name =
            std::ffi::CString::new(std::format!("zlibc-10d-shm-{}", std::process::id())).unwrap();
        unsafe {
            let fd = shm_open(name.as_ptr(), O_RDWR | O_CREAT, 0o600);
            assert!(fd >= 0);
            let msg = b"shared";
            assert_eq!(
                syscall_ret(syscall3(
                    SYS_WRITE,
                    fd as usize,
                    msg.as_ptr() as usize,
                    msg.len()
                )),
                msg.len() as isize
            );
            close(fd);
            let fd = shm_open(name.as_ptr(), O_RDWR, 0);
            assert!(fd >= 0);
            let mut back = [0u8; 8];
            assert_eq!(
                syscall_ret(syscall3(
                    SYS_READ,
                    fd as usize,
                    back.as_mut_ptr() as usize,
                    msg.len()
                )),
                msg.len() as isize
            );
            assert_eq!(&back[..msg.len()], msg);
            close(fd);
            assert_eq!(shm_unlink(name.as_ptr()), 0);
        }
    }

    #[test]
    fn aio_write_read_fsync_inline() {
        let _guard = crate::ldso::testlock::lock();
        let path = tmp_cstr("aio");
        unsafe {
            let fd = crate::fcntl::open(path.as_ptr(), O_RDWR | O_CREAT, 0o644);
            assert!(fd >= 0);
            let msg = b"async-ish";
            let mut wcb = zero_aiocb();
            wcb.aio_fildes = fd;
            wcb.aio_buf = msg.as_ptr() as *mut c_void;
            wcb.aio_nbytes = msg.len();
            wcb.aio_offset = 0;
            assert_eq!(aio_write(&mut wcb), 0);
            assert_eq!(aio_error(&wcb), 0);
            assert_eq!(aio_return(&mut wcb), msg.len() as isize);
            assert_eq!(aio_fsync(super::O_SYNC, &mut wcb), 0);
            let mut back = [0u8; 16];
            let mut rcb = zero_aiocb();
            rcb.aio_fildes = fd;
            rcb.aio_buf = back.as_mut_ptr() as *mut c_void;
            rcb.aio_nbytes = msg.len();
            rcb.aio_offset = 0;
            assert_eq!(aio_read(&mut rcb), 0);
            assert_eq!(aio_error(&rcb), 0);
            assert_eq!(aio_return(&mut rcb), msg.len() as isize);
            assert_eq!(&back[..msg.len()], msg);
            // Nothing pends: cancel is ALL DONE, suspend sees `wcb` done.
            assert_eq!(aio_cancel(fd, core::ptr::null_mut()), AIO_ALLDONE);
            let list = [&wcb as *const Aiocb];
            assert_eq!(aio_suspend(list.as_ptr(), 1, core::ptr::null()), 0);
            // lio_listio WAIT over a rewrite + reread pair.
            let mut lcb = zero_aiocb();
            lcb.aio_fildes = fd;
            lcb.aio_lio_opcode = LIO_WRITE;
            lcb.aio_buf = msg.as_ptr() as *mut c_void;
            lcb.aio_nbytes = msg.len();
            lcb.aio_offset = 0;
            let plist = [&mut lcb as *mut Aiocb];
            assert_eq!(
                lio_listio(LIO_WAIT, plist.as_ptr(), 1, core::ptr::null_mut()),
                0
            );
            assert_eq!(aio_return(&mut lcb), msg.len() as isize);
            close(fd);
            assert_eq!(
                syscall_ret(syscall3(SYS_UNLINK, path.as_ptr() as usize, 0, 0)),
                0
            );
        }
    }

    #[test]
    fn aio_rejects_bad_inputs() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut cb = zero_aiocb();
            cb.aio_fildes = -1;
            cb.aio_buf = core::ptr::null_mut();
            cb.aio_nbytes = 1;
            assert_eq!(aio_write(&mut cb), -1);
            assert!(aio_error(&cb) != 0);
            // fd/cb mismatch: EINVAL, like musl's guard.
            cb.aio_fildes = 7;
            assert_eq!(aio_cancel(8, &mut cb), -1);
            // Negative count: EINVAL, no wait attempted.
            assert_eq!(aio_suspend(core::ptr::null(), -1, core::ptr::null()), -1);
            let _ = O_NONBLOCK;
        }
    }
}
