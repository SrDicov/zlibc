//! fd multiplexing: epoll, inotify, eventfd, signalfd, timerfd.
//!
//! Thin wrappers over the raw traps, exactly musl's ABI boundary
//! (`src/linux/epoll.c`, `inotify.c`, `eventfd.c`, `signalfd.c`,
//! `timerfd.c`): one syscall per entry, errno through `syscall_ret`,
//! no cancellation-point handling. `epoll_create` rejects `size <= 0`
//! with `EINVAL`, `inotify_init` is `inotify_init1(0)`, `epoll_wait` is
//! `epoll_pwait` with a null mask, and `eventfd_read`/`write` are a
//! single 8-byte `read`/`write` (musl loops nothing: a short count
//! fails with `-1`), all exactly like musl.
//!
//! `sigset_t` is reused from [`crate::signal`]; the kernel only reads
//! its first 8 bytes (`_NSIG/8`). `Timespec`/`Itimerspec` are local:
//! the clocks wave owns the public ones, merge on contact.

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};

use crate::syscall::{syscall1, syscall2, syscall3, syscall4, syscall6, syscall_ret};

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_EPOLL_CREATE: usize = 213; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_EPOLL_CTL: usize = 233; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_EPOLL_WAIT: usize = 232; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_EPOLL_PWAIT: usize = 281; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_EPOLL_CREATE1: usize = 291; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_INOTIFY_INIT: usize = 253; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_INOTIFY_ADD_WATCH: usize = 254; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_INOTIFY_RM_WATCH: usize = 255; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_SIGNALFD: usize = 282; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_TIMERFD_CREATE: usize = 283; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_TIMERFD_SETTIME: usize = 286; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_TIMERFD_GETTIME: usize = 287; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_SIGNALFD4: usize = 289; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_EVENTFD2: usize = 290; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_INOTIFY_INIT1: usize = 294; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_EVENTFD: usize = 284; // TODO: generate from arch bits/syscall.h

/// musl `EINVAL` (`include/errno.h`).
#[cfg(target_arch = "x86_64")]
const EINVAL: c_int = 22;
/// musl `ENOSYS` (`include/errno.h`): drives the legacy-trap fallbacks.
#[cfg(target_arch = "x86_64")]
const ENOSYS: c_int = 38;
/// musl `SYS_fcntl` + commands for the `signalfd` fallback below.
#[cfg(target_arch = "x86_64")]
const SYS_FCNTL: usize = 72; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const F_SETFD: c_int = 2;
#[cfg(target_arch = "x86_64")]
const F_SETFL: c_int = 4;
#[cfg(target_arch = "x86_64")]
const FD_CLOEXEC: c_int = 1;
#[cfg(target_arch = "x86_64")]
const O_NONBLOCK: c_int = 0o4000;
#[cfg(target_arch = "x86_64")]
const SFD_CLOEXEC: c_int = crate::fcntl::O_CLOEXEC;
#[cfg(target_arch = "x86_64")]
const SFD_NONBLOCK: c_int = crate::fcntl::O_NONBLOCK;

/// Kernel signal-mask length (`_NSIG/8`, `_NSIG` is 65 on x86_64 per
/// `arch/x86_64/bits/signal.h:152`; `65/8` truncates to 8).
#[cfg(target_arch = "x86_64")]
const K_SIGSET_LEN: usize = 8;

/// musl `struct epoll_event` (`include/sys/epoll.h`): packed on x86_64,
/// so 12 bytes, not 16. `data` overlays musl's `epoll_data_t` union as
/// its widest member (`u64`).
#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

/// musl `struct inotify_event` (`include/sys/inotify.h:16-19`): the
/// trailing `name` is a C flexible array; model it as zero-length and
/// read the `len` name bytes following the header.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct InotifyEvent {
    pub wd: c_int,
    pub mask: u32,
    pub cookie: u32,
    pub len: u32,
    pub name: [c_char; 0],
}

/// musl `eventfd_t` (`include/sys/eventfd.h:11`).
#[cfg(target_arch = "x86_64")]
#[allow(non_camel_case_types)]
pub type eventfd_t = u64;

/// Local `struct timespec` (clocks wave owns the public one; note the
/// future merge). Field order matches musl: seconds, nanoseconds.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Timespec {
    pub tv_sec: c_long,
    pub tv_nsec: c_long,
}

/// Local `struct itimerspec` (same merge note as [`Timespec`]).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Itimerspec {
    pub it_interval: Timespec,
    pub it_value: Timespec,
}

// musl `include/sys/epoll.h:18-36`.
#[cfg(target_arch = "x86_64")]
pub const EPOLLIN: u32 = 0x001;
#[cfg(target_arch = "x86_64")]
pub const EPOLLPRI: u32 = 0x002;
#[cfg(target_arch = "x86_64")]
pub const EPOLLOUT: u32 = 0x004;
#[cfg(target_arch = "x86_64")]
pub const EPOLLERR: u32 = 0x008;
#[cfg(target_arch = "x86_64")]
pub const EPOLLHUP: u32 = 0x010;
#[cfg(target_arch = "x86_64")]
pub const EPOLLNVAL: u32 = 0x020;
#[cfg(target_arch = "x86_64")]
pub const EPOLLRDNORM: u32 = 0x040;
#[cfg(target_arch = "x86_64")]
pub const EPOLLRDBAND: u32 = 0x080;
#[cfg(target_arch = "x86_64")]
pub const EPOLLWRNORM: u32 = 0x100;
#[cfg(target_arch = "x86_64")]
pub const EPOLLWRBAND: u32 = 0x200;
#[cfg(target_arch = "x86_64")]
pub const EPOLLMSG: u32 = 0x400;
#[cfg(target_arch = "x86_64")]
pub const EPOLLRDHUP: u32 = 0x2000;
#[cfg(target_arch = "x86_64")]
pub const EPOLLEXCLUSIVE: u32 = 1u32 << 28;
#[cfg(target_arch = "x86_64")]
pub const EPOLLWAKEUP: u32 = 1u32 << 29;
#[cfg(target_arch = "x86_64")]
pub const EPOLLONESHOT: u32 = 1u32 << 30;
#[cfg(target_arch = "x86_64")]
pub const EPOLLET: u32 = 1u32 << 31;
#[cfg(target_arch = "x86_64")]
pub const EPOLL_CTL_ADD: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const EPOLL_CTL_DEL: c_int = 2;
#[cfg(target_arch = "x86_64")]
pub const EPOLL_CTL_MOD: c_int = 3;
#[cfg(target_arch = "x86_64")]
pub const EPOLL_CLOEXEC: c_int = crate::fcntl::O_CLOEXEC;
#[cfg(target_arch = "x86_64")]
pub const EPOLL_NONBLOCK: c_int = crate::fcntl::O_NONBLOCK;

// musl `include/sys/inotify.h:21-53`.
#[cfg(target_arch = "x86_64")]
pub const IN_ACCESS: u32 = 0x00000001;
#[cfg(target_arch = "x86_64")]
pub const IN_MODIFY: u32 = 0x00000002;
#[cfg(target_arch = "x86_64")]
pub const IN_ATTRIB: u32 = 0x00000004;
#[cfg(target_arch = "x86_64")]
pub const IN_CLOSE_WRITE: u32 = 0x00000008;
#[cfg(target_arch = "x86_64")]
pub const IN_CLOSE_NOWRITE: u32 = 0x00000010;
#[cfg(target_arch = "x86_64")]
pub const IN_CLOSE: u32 = IN_CLOSE_WRITE | IN_CLOSE_NOWRITE;
#[cfg(target_arch = "x86_64")]
pub const IN_OPEN: u32 = 0x00000020;
#[cfg(target_arch = "x86_64")]
pub const IN_MOVED_FROM: u32 = 0x00000040;
#[cfg(target_arch = "x86_64")]
pub const IN_MOVED_TO: u32 = 0x00000080;
#[cfg(target_arch = "x86_64")]
pub const IN_MOVE: u32 = IN_MOVED_FROM | IN_MOVED_TO;
#[cfg(target_arch = "x86_64")]
pub const IN_CREATE: u32 = 0x00000100;
#[cfg(target_arch = "x86_64")]
pub const IN_DELETE: u32 = 0x00000200;
#[cfg(target_arch = "x86_64")]
pub const IN_DELETE_SELF: u32 = 0x00000400;
#[cfg(target_arch = "x86_64")]
pub const IN_MOVE_SELF: u32 = 0x00000800;
#[cfg(target_arch = "x86_64")]
pub const IN_ALL_EVENTS: u32 = 0x00000fff;
#[cfg(target_arch = "x86_64")]
pub const IN_UNMOUNT: u32 = 0x00002000;
#[cfg(target_arch = "x86_64")]
pub const IN_Q_OVERFLOW: u32 = 0x00004000;
#[cfg(target_arch = "x86_64")]
pub const IN_IGNORED: u32 = 0x00008000;
#[cfg(target_arch = "x86_64")]
pub const IN_ONLYDIR: u32 = 0x01000000;
#[cfg(target_arch = "x86_64")]
pub const IN_DONT_FOLLOW: u32 = 0x02000000;
#[cfg(target_arch = "x86_64")]
pub const IN_EXCL_UNLINK: u32 = 0x04000000;
#[cfg(target_arch = "x86_64")]
pub const IN_MASK_CREATE: u32 = 0x10000000;
#[cfg(target_arch = "x86_64")]
pub const IN_MASK_ADD: u32 = 0x20000000;
#[cfg(target_arch = "x86_64")]
pub const IN_ISDIR: u32 = 0x40000000;
#[cfg(target_arch = "x86_64")]
pub const IN_ONESHOT: u32 = 0x80000000;
#[cfg(target_arch = "x86_64")]
pub const IN_CLOEXEC: c_int = crate::fcntl::O_CLOEXEC;
#[cfg(target_arch = "x86_64")]
pub const IN_NONBLOCK: c_int = crate::fcntl::O_NONBLOCK;

#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<EpollEvent>() == 12);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<InotifyEvent>() == 16);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<Timespec>() == 16);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<Itimerspec>() == 32);

/// Create an epoll instance (musl `epoll.c:6-10`): `size <= 0` fails
/// with `EINVAL` before any trap; the size itself is ignored.
///
/// # Safety
///
/// Pure syscall wrapper; `size` is kernel-checked.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn epoll_create(size: c_int) -> c_int {
    unsafe {
        if size <= 0 {
            return syscall_ret(-(EINVAL as isize)) as c_int;
        }
        epoll_create1(0)
    }
}

/// Create an epoll instance with flags (musl `epoll.c:12-19`): one
/// `SYS_epoll_create1` trap, falling back to legacy `SYS_epoll_create`
/// when the kernel lacks it and no flags were asked.
///
/// # Safety
///
/// Pure syscall wrapper; `flags` is kernel-checked.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn epoll_create1(flags: c_int) -> c_int {
    unsafe {
        let mut r = syscall1(SYS_EPOLL_CREATE1, flags as usize);
        if r == -(ENOSYS as isize) && flags == 0 {
            r = syscall1(SYS_EPOLL_CREATE, 1);
        }
        syscall_ret(r) as c_int
    }
}

/// Control an epoll set (musl `epoll.c:21-24`): one `SYS_epoll_ctl`
/// trap.
///
/// # Safety
///
/// `ev`, when non-null, must point to a readable [`EpollEvent`]
/// (`EPOLL_CTL_DEL` allows null).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn epoll_ctl(fd: c_int, op: c_int, fd2: c_int, ev: *mut EpollEvent) -> c_int {
    unsafe {
        syscall_ret(syscall4(
            SYS_EPOLL_CTL,
            fd as usize,
            op as usize,
            fd2 as usize,
            ev as usize,
        )) as c_int
    }
}

/// Wait on an epoll set (musl `epoll.c:35-38`): `epoll_pwait` with a
/// null mask.
///
/// # Safety
///
/// `ev` must point to `cnt` writable [`EpollEvent`]s.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn epoll_wait(
    fd: c_int,
    ev: *mut EpollEvent,
    cnt: c_int,
    timeout: c_int,
) -> c_int {
    unsafe { epoll_pwait(fd, ev, cnt, timeout, core::ptr::null()) }
}

/// Wait on an epoll set with a signal mask (musl `epoll.c:26-33`): one
/// `SYS_epoll_pwait` trap with the kernel mask length 8, falling back
/// to legacy `SYS_epoll_wait` when the kernel lacks it and the mask is
/// null. A null mask leaves the signal mask alone; the kernel only
/// reads the first 8 bytes of a non-null one.
///
/// # Safety
///
/// `ev` must point to `cnt` writable [`EpollEvent`]s; `sigs`, when
/// non-null, must point to a readable [`crate::signal::sigset_t`]
/// (only the first 8 bytes are read, like musl).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn epoll_pwait(
    fd: c_int,
    ev: *mut EpollEvent,
    cnt: c_int,
    timeout: c_int,
    sigs: *const crate::signal::sigset_t,
) -> c_int {
    unsafe {
        let mut r = syscall6(
            SYS_EPOLL_PWAIT,
            fd as usize,
            ev as usize,
            cnt as usize,
            timeout as usize,
            sigs as usize,
            K_SIGSET_LEN,
        );
        if r == -(ENOSYS as isize) && sigs.is_null() {
            r = syscall4(
                SYS_EPOLL_WAIT,
                fd as usize,
                ev as usize,
                cnt as usize,
                timeout as usize,
            );
        }
        syscall_ret(r) as c_int
    }
}

/// Create or reconfigure a signalfd (musl `signalfd.c:7-21`): one
/// `SYS_signalfd4` trap, falling back to legacy `SYS_signalfd` plus
/// raw-`fcntl` flag emulation when the kernel lacks it.
///
/// # Safety
///
/// `sigs` must point to a readable [`crate::signal::sigset_t`] (only
/// the first 8 bytes are read, like musl); `fd` is -1 to create.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn signalfd(
    fd: c_int,
    sigs: *const crate::signal::sigset_t,
    flags: c_int,
) -> c_int {
    unsafe {
        let mut ret = syscall4(
            SYS_SIGNALFD4,
            fd as usize,
            sigs as usize,
            K_SIGSET_LEN,
            flags as usize,
        );
        if ret != -(ENOSYS as isize) {
            return syscall_ret(ret) as c_int;
        }
        ret = syscall3(SYS_SIGNALFD, fd as usize, sigs as usize, K_SIGSET_LEN);
        if ret >= 0 {
            if flags & SFD_CLOEXEC != 0 {
                syscall3(
                    SYS_FCNTL,
                    ret as usize,
                    F_SETFD as usize,
                    FD_CLOEXEC as usize,
                );
            }
            if flags & SFD_NONBLOCK != 0 {
                syscall3(
                    SYS_FCNTL,
                    ret as usize,
                    F_SETFL as usize,
                    O_NONBLOCK as usize,
                );
            }
        }
        syscall_ret(ret) as c_int
    }
}

/// Create a timerfd (musl `timerfd.c:7-10`): one `SYS_timerfd_create`
/// trap.
///
/// # Safety
///
/// Pure syscall wrapper; both arguments are kernel-checked.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn timerfd_create(clockid: c_int, flags: c_int) -> c_int {
    unsafe {
        syscall_ret(syscall2(
            SYS_TIMERFD_CREATE,
            clockid as usize,
            flags as usize,
        )) as c_int
    }
}

/// Arm or disarm a timerfd (musl `timerfd.c:12-38`; on 64-bit there is
/// no time64 split, so one `SYS_timerfd_settime` trap).
///
/// # Safety
///
/// `new` must point to a readable [`Itimerspec`]; `old`, when
/// non-null, must point to a writable one.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn timerfd_settime(
    fd: c_int,
    flags: c_int,
    new: *const Itimerspec,
    old: *mut Itimerspec,
) -> c_int {
    unsafe {
        syscall_ret(syscall4(
            SYS_TIMERFD_SETTIME,
            fd as usize,
            flags as usize,
            new as usize,
            old as usize,
        )) as c_int
    }
}

/// Read a timerfd's current setting (musl `timerfd.c:40-59`; same
/// no-split note as [`timerfd_settime`]).
///
/// # Safety
///
/// `cur` must point to a writable [`Itimerspec`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn timerfd_gettime(fd: c_int, cur: *mut Itimerspec) -> c_int {
    unsafe { syscall_ret(syscall2(SYS_TIMERFD_GETTIME, fd as usize, cur as usize)) as c_int }
}

/// Create an inotify instance (musl `inotify.c:5-8`):
/// `inotify_init1(0)`.
///
/// # Safety
///
/// Pure syscall wrapper.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn inotify_init() -> c_int {
    unsafe { inotify_init1(0) }
}

/// Create an inotify instance with flags (musl `inotify.c:9-16`): one
/// `SYS_inotify_init1` trap, falling back to legacy `SYS_inotify_init`
/// when the kernel lacks it and no flags were asked.
///
/// # Safety
///
/// Pure syscall wrapper; `flags` is kernel-checked.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn inotify_init1(flags: c_int) -> c_int {
    unsafe {
        let mut r = syscall1(SYS_INOTIFY_INIT1, flags as usize);
        if r == -(ENOSYS as isize) && flags == 0 {
            r = syscall1(SYS_INOTIFY_INIT, 0);
        }
        syscall_ret(r) as c_int
    }
}

/// Watch a path (musl `inotify.c:18-21`): one `SYS_inotify_add_watch`
/// trap.
///
/// # Safety
///
/// `pathname` must point to a readable NUL-terminated path.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn inotify_add_watch(fd: c_int, pathname: *const c_char, mask: u32) -> c_int {
    unsafe {
        syscall_ret(syscall3(
            SYS_INOTIFY_ADD_WATCH,
            fd as usize,
            pathname as usize,
            mask as usize,
        )) as c_int
    }
}

/// Drop a watch (musl `inotify.c:23-26`): one `SYS_inotify_rm_watch`
/// trap.
///
/// # Safety
///
/// Pure syscall wrapper; `fd`/`wd` are kernel-checked.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn inotify_rm_watch(fd: c_int, wd: c_int) -> c_int {
    unsafe { syscall_ret(syscall2(SYS_INOTIFY_RM_WATCH, fd as usize, wd as usize)) as c_int }
}

/// Create an eventfd counter (musl `eventfd.c:6-13`): one
/// `SYS_eventfd2` trap, falling back to legacy `SYS_eventfd` when the
/// kernel lacks it and no flags were asked.
///
/// # Safety
///
/// Pure syscall wrapper; both arguments are kernel-checked.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn eventfd(count: c_uint, flags: c_int) -> c_int {
    unsafe {
        let mut r = syscall2(SYS_EVENTFD2, count as usize, flags as usize);
        if r == -(ENOSYS as isize) && flags == 0 {
            r = syscall1(SYS_EVENTFD, count as usize);
        }
        syscall_ret(r) as c_int
    }
}

/// Read an eventfd counter (musl `eventfd.c:15-18`): a single 8-byte
/// `read`; `0` on a full read, `-1` otherwise.
///
/// # Safety
///
/// `value` must point to a writable [`eventfd_t`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn eventfd_read(fd: c_int, value: *mut eventfd_t) -> c_int {
    unsafe {
        if crate::unistd::read(fd, value as *mut c_void, 8) == 8 {
            0
        } else {
            -1
        }
    }
}

/// Write an eventfd counter (musl `eventfd.c:20-23`): a single 8-byte
/// `write`; `0` on a full write, `-1` otherwise.
///
/// # Safety
///
/// Pure syscall wrapper around the counter value.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn eventfd_write(fd: c_int, value: eventfd_t) -> c_int {
    unsafe {
        if crate::unistd::write(fd, &value as *const eventfd_t as *const c_void, 8) == 8 {
            0
        } else {
            -1
        }
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use core::ffi::{c_char, c_int, c_void};

    use super::{
        epoll_create, epoll_create1, epoll_ctl, epoll_pwait, epoll_wait, eventfd, eventfd_read,
        eventfd_write, inotify_add_watch, inotify_init1, inotify_rm_watch, signalfd,
        timerfd_create, timerfd_gettime, timerfd_settime, EpollEvent, Itimerspec, Timespec,
        EPOLLIN, EPOLL_CTL_ADD, IN_CREATE, IN_DELETE, IN_MODIFY, IN_NONBLOCK,
    };
    use crate::errno::{__errno_location, errno_load};
    use crate::fcntl::{open, AT_FDCWD, O_CREAT, O_WRONLY};
    use crate::signal::{raise, sigaddset, sigemptyset, sigprocmask, SIG_BLOCK, SIG_SETMASK};
    use crate::syscall::{syscall3, syscall_ret};
    use crate::unistd::{close, getpid, pipe, read, write};

    /// musl `SYS_unlinkat` (`arch/x86_64/bits/syscall.h.in`).
    const SYS_UNLINKAT: usize = 263;
    /// musl `CLOCK_MONOTONIC` (`include/time.h`).
    const CLOCK_MONOTONIC: c_int = 1;
    /// Real-time probe signal: valid per `sigaddset` (1..=64 except
    /// 32-34), clear of the libc-reserved low RT slots.
    const PROBE_RT: c_int = 40;

    unsafe fn unlink(path: *const c_char) -> c_int {
        unsafe { syscall_ret(syscall3(SYS_UNLINKAT, AT_FDCWD as usize, path as usize, 0)) as c_int }
    }

    /// Fill `out` with `/tmp/zlibc8e1-<pid>-<tag>\0`; returns the
    /// length without NUL (paths stay unique per test via pid+tag).
    unsafe fn tmp_path(tag: &[u8], out: &mut [u8; 64]) -> usize {
        let mut n = 0;
        let put = |out: &mut [u8; 64], n: &mut usize, b: u8| {
            out[*n] = b;
            *n = (*n).wrapping_add(1);
        };
        for &b in b"/tmp/zlibc8e1-".iter() {
            put(out, &mut n, b);
        }
        let mut v = unsafe { getpid() } as u32;
        let mut digits = [0u8; 10];
        let mut nd = 0;
        loop {
            digits[nd] = b'0'.wrapping_add((v.wrapping_rem(10)) as u8);
            nd = nd.wrapping_add(1);
            v = v.wrapping_div(10);
            if v == 0 {
                break;
            }
        }
        while nd > 0 {
            nd = nd.wrapping_sub(1);
            put(out, &mut n, digits[nd]);
        }
        put(out, &mut n, b'-');
        for &b in tag.iter() {
            put(out, &mut n, b);
        }
        out[n] = 0;
        n
    }

    #[test]
    fn epoll_create_rejects_nonpositive_size() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            assert_eq!(epoll_create(0), -1);
            assert_eq!(errno_load(__errno_location()), 22);
            assert_eq!(epoll_create(-5), -1);
            assert_eq!(errno_load(__errno_location()), 22);
        }
    }

    #[test]
    fn epoll_pipe_write_reports_readable() {
        unsafe {
            // `size` is ignored when positive, like musl.
            let efd = epoll_create(1);
            assert!(efd >= 0);
            let mut fds = [0 as c_int; 2];
            assert_eq!(pipe(fds.as_mut_ptr()), 0);
            let mut ev = EpollEvent {
                events: EPOLLIN,
                data: 7,
            };
            assert_eq!(epoll_ctl(efd, EPOLL_CTL_ADD, fds[0], &mut ev as *mut _), 0);
            // Empty pipe: nothing ready.
            let mut out = EpollEvent { events: 0, data: 0 };
            assert_eq!(epoll_wait(efd, &mut out as *mut _, 1, 0), 0);
            let msg = b"x";
            assert_eq!(write(fds[1], msg.as_ptr() as *const c_void, 1), 1);
            assert_eq!(epoll_wait(efd, &mut out as *mut _, 1, 1000), 1);
            assert!(out.events & EPOLLIN != 0);
            // `data` round-trips through the kernel untouched.
            let data = out.data;
            assert_eq!(data, 7);
            // Null-mask pwait is the same wait.
            assert_eq!(
                epoll_pwait(efd, &mut out as *mut _, 1, 0, core::ptr::null()),
                1
            );
            let mut back = [0u8; 1];
            assert_eq!(read(fds[0], back.as_mut_ptr() as *mut c_void, 1), 1);
            assert_eq!(close(fds[0]), 0);
            assert_eq!(close(fds[1]), 0);
            assert_eq!(close(efd), 0);
            assert!(epoll_create1(0) >= 0);
            assert_eq!(close(epoll_create1(0)), 0);
        }
    }

    #[test]
    fn eventfd_counter_accumulates() {
        unsafe {
            let fd = eventfd(0, 0);
            assert!(fd >= 0);
            assert_eq!(eventfd_write(fd, 5), 0);
            assert_eq!(eventfd_write(fd, 3), 0);
            let mut v: super::eventfd_t = 0;
            assert_eq!(eventfd_read(fd, &mut v as *mut _), 0);
            assert_eq!(v, 8);
            assert_eq!(close(fd), 0);
        }
    }

    #[test]
    fn timerfd_fires_after_10ms() {
        unsafe {
            let fd = timerfd_create(CLOCK_MONOTONIC, 0);
            assert!(fd >= 0);
            let new = Itimerspec {
                it_interval: Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: Timespec {
                    tv_sec: 0,
                    tv_nsec: 10_000_000,
                },
            };
            assert_eq!(
                timerfd_settime(fd, 0, &new as *const _, core::ptr::null_mut()),
                0
            );
            // Setting with a readable `old` slot works too.
            let mut old = Itimerspec {
                it_interval: Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
            };
            assert_eq!(timerfd_gettime(fd, &mut old as *mut _), 0);
            // Blocking read: the only sleep in this module's tests.
            let mut expiries: u64 = 0;
            assert_eq!(read(fd, &mut expiries as *mut u64 as *mut c_void, 8), 8);
            assert!(expiries >= 1);
            assert_eq!(close(fd), 0);
        }
    }

    #[test]
    fn inotify_sees_tmp_file_lifecycle() {
        unsafe {
            let fd = inotify_init1(IN_NONBLOCK);
            assert!(fd >= 0);
            let wd = inotify_add_watch(fd, c"/tmp".as_ptr(), IN_CREATE | IN_MODIFY | IN_DELETE);
            assert!(wd >= 0);
            let mut path = [0u8; 64];
            let plen = tmp_path(b"inotify", &mut path);
            let base = &path[b"/tmp/".len()..plen]; // watched-dir basename
            let wfd = open(path.as_ptr() as *const c_char, O_WRONLY | O_CREAT, 0o644);
            assert!(wfd >= 0);
            let msg = b"z";
            assert_eq!(write(wfd, msg.as_ptr() as *const c_void, 1), 1);
            assert_eq!(close(wfd), 0);
            assert_eq!(unlink(path.as_ptr() as *const c_char), 0);
            // Events are queued synchronously by our own syscalls, so a
            // bounded nonblocking drain sees them with no sleeps.
            let mut seen: u32 = 0;
            let mut buf = [0u8; 1024];
            for _ in 0..100 {
                let n = read(fd, buf.as_mut_ptr() as *mut c_void, buf.len());
                if n <= 0 {
                    break;
                }
                let mut off = 0usize;
                while off.wrapping_add(16) <= n as usize {
                    let mask = u32::from_ne_bytes([
                        buf[off.wrapping_add(4)],
                        buf[off.wrapping_add(5)],
                        buf[off.wrapping_add(6)],
                        buf[off.wrapping_add(7)],
                    ]);
                    let len = u32::from_ne_bytes([
                        buf[off.wrapping_add(12)],
                        buf[off.wrapping_add(13)],
                        buf[off.wrapping_add(14)],
                        buf[off.wrapping_add(15)],
                    ]) as usize;
                    let end = off.wrapping_add(16).wrapping_add(len);
                    if end > n as usize || end > buf.len() {
                        break;
                    }
                    // `len` covers NUL padding, so match the basename
                    // plus its terminator instead of the length.
                    if len >= base.len().wrapping_add(1)
                        && buf[off.wrapping_add(16)..off.wrapping_add(16).wrapping_add(base.len())]
                            == *base
                        && buf[off.wrapping_add(16).wrapping_add(base.len())] == 0
                    {
                        seen |= mask & (IN_CREATE | IN_MODIFY | IN_DELETE);
                    }
                    off = end;
                    if seen == (IN_CREATE | IN_MODIFY | IN_DELETE) {
                        break;
                    }
                }
                if seen == (IN_CREATE | IN_MODIFY | IN_DELETE) {
                    break;
                }
            }
            assert_eq!(seen, IN_CREATE | IN_MODIFY | IN_DELETE);
            assert_eq!(inotify_rm_watch(fd, wd), 0);
            assert_eq!(close(fd), 0);
        }
    }

    #[test]
    fn signalfd_delivers_blocked_rt_signal() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut set: crate::signal::sigset_t = [0; 16];
            let mut old: crate::signal::sigset_t = [0; 16];
            assert_eq!(sigemptyset(&mut set as *mut _), 0);
            assert_eq!(sigaddset(&mut set as *mut _, PROBE_RT), 0);
            assert_eq!(
                sigprocmask(SIG_BLOCK, &set as *const _, &mut old as *mut _),
                0
            );
            let sfd = signalfd(-1, &set as *const _, 0);
            assert!(sfd >= 0);
            assert_eq!(raise(PROBE_RT), 0);
            let mut info = [0u8; 128];
            assert_eq!(read(sfd, info.as_mut_ptr() as *mut c_void, info.len()), 128);
            assert_eq!(
                u32::from_ne_bytes([info[0], info[1], info[2], info[3]]),
                PROBE_RT as u32
            );
            assert_eq!(close(sfd), 0);
            assert_eq!(
                sigprocmask(SIG_SETMASK, &old as *const _, core::ptr::null_mut()),
                0
            );
        }
    }
}
