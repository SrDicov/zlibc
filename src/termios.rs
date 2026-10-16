//! Terminal control + `ioctl` (musl `src/termios/*`, `src/unistd/isatty.c`,
//! `ttyname.c`, `ttyname_r.c`, `tcgetpgrp.c`, `tcsetpgrp.c`, and the
//! `SYS_ioctl` path of `src/misc/ioctl.c`).
//!
//! Every fd-taking entry is one raw `SYS_ioctl` trap returning through
//! `syscall_ret`, so `errno` follows musl's contract. musl's compat map
//! (`ioctl.c`) only translates legacy 32-bit-timeval requests — dead on
//! x86_64, where the new numbers are native — so it is skipped and every
//! request goes straight to the kernel. Stable Rust has no C variadics,
//! so `ioctl` takes a fixed `arg` word: the same definedness boundary as
//! `open`/`openat`'s fixed `mode` in `crate::fcntl` (a two-argument
//! caller leaves whatever was in `rdx` as `arg`).

use core::ffi::{c_char, c_int, c_ulong, c_void};

use crate::errno::{__errno_location, errno_load, errno_store};
use crate::syscall::{syscall3, syscall_ret};

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_IOCTL: usize = 16; // TODO: generate from arch bits/syscall.h

/// musl `include/errno.h` via `arch/generic/bits/errno.h` (local: only
/// this module needs these three; `EINVAL` rides on `syscall_ret`).
const ENODEV: c_int = 19;
const EINVAL: c_int = 22;
const ERANGE: c_int = 34;

/// musl `include/limits.h:55`.
pub const TTY_NAME_MAX: usize = 32;

// ---- Requests (musl arch/generic/bits/ioctl.h) ------------------------------
pub const TCGETS: c_ulong = 0x5401;
pub const TCSETS: c_ulong = 0x5402;
pub const TCSBRK: c_ulong = 0x5409;
pub const TCXONC: c_ulong = 0x540A;
pub const TCFLSH: c_ulong = 0x540B;
pub const TIOCGPGRP: c_ulong = 0x540F;
pub const TIOCSPGRP: c_ulong = 0x5410;
pub const TIOCGWINSZ: c_ulong = 0x5413;
pub const TIOCSWINSZ: c_ulong = 0x5414;
pub const TIOCGSID: c_ulong = 0x5429;

// ---- Actions (musl arch/generic/bits/termios.h) -----------------------------
pub const TCSANOW: c_int = 0;
pub const TCSADRAIN: c_int = 1;
pub const TCSAFLUSH: c_int = 2;
pub const TCIFLUSH: c_int = 0;
pub const TCOFLUSH: c_int = 1;
pub const TCIOFLUSH: c_int = 2;
pub const TCOOFF: c_int = 0;
pub const TCOON: c_int = 1;
pub const TCIOFF: c_int = 2;
pub const TCION: c_int = 3;

// ---- Control chars (musl arch/generic/bits/termios.h) -----------------------
pub const NCCS: usize = 32;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;

// ---- Input flags used by cfmakeraw (musl arch/generic/bits/termios.h) -------
const IGNBRK: u32 = 0o1;
const BRKINT: u32 = 0o2;
const PARMRK: u32 = 0o10;
const ISTRIP: u32 = 0o40;
const INLCR: u32 = 0o100;
const IGNCR: u32 = 0o200;
const ICRNL: u32 = 0o400;
const IXON: u32 = 0o2000;

// ---- Output flags used by cfmakeraw ------------------------------------------
const OPOST: u32 = 0o1;

// ---- Control flags used by cfmakeraw / cf*speed ------------------------------
const CSIZE: u32 = 0o60;
const CS8: u32 = 0o60;
const PARENB: u32 = 0o400;
pub const CBAUD: u32 = 0o10017;
const CIBAUD: u32 = 0o2003600000;

// ---- Local flags used by cfmakeraw -------------------------------------------
const ISIG: u32 = 0o1;
const ICANON: u32 = 0o2;
const ECHO: u32 = 0o10;
const ECHONL: u32 = 0o100;
const IEXTEN: u32 = 0o100000;

// ---- Baud rates (musl arch/generic/bits/termios.h, octal verbatim) ------------
pub const B0: u32 = 0o0;
pub const B50: u32 = 0o1;
pub const B75: u32 = 0o2;
pub const B110: u32 = 0o3;
pub const B134: u32 = 0o4;
pub const B150: u32 = 0o5;
pub const B200: u32 = 0o6;
pub const B300: u32 = 0o7;
pub const B600: u32 = 0o10;
pub const B1200: u32 = 0o11;
pub const B1800: u32 = 0o12;
pub const B2400: u32 = 0o13;
pub const B4800: u32 = 0o14;
pub const B9600: u32 = 0o15;
pub const B19200: u32 = 0o16;
pub const B38400: u32 = 0o17;
pub const B57600: u32 = 0o10001;
pub const B115200: u32 = 0o10002;
pub const B230400: u32 = 0o10003;
pub const B460800: u32 = 0o10004;
pub const B500000: u32 = 0o10005;
pub const B576000: u32 = 0o10006;
pub const B921600: u32 = 0o10007;
pub const B1000000: u32 = 0o10010;
pub const B1152000: u32 = 0o10011;
pub const B1500000: u32 = 0o10012;
pub const B2000000: u32 = 0o10013;
pub const B2500000: u32 = 0o10014;
pub const B3000000: u32 = 0o10015;
pub const B3500000: u32 = 0o10016;
pub const B4000000: u32 = 0o10017;

/// musl `speed_t` (`include/termios.h`: `unsigned int`).
#[allow(non_camel_case_types)]
pub type speed_t = u32;

/// musl `struct termios` (`arch/generic/bits/termios.h`), field for
/// field: four `tcflag_t`, `c_line`, `c_cc[NCCS]`, then the two speeds.
/// musl spells the last two `__c_ispeed`/`__c_ospeed`; the shorter
/// glibc-style names are used here (offsets identical either way).
#[repr(C)]
pub struct Termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; 32],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

/// musl `struct winsize` (`obj/include/bits/alltypes.h`: four
/// `unsigned short`).
#[repr(C)]
pub struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

/// Device control (musl `ioctl`: one `SYS_ioctl` trap; the compat map is
/// x86_64-dead, see module docs).
///
/// # Safety
///
/// `arg` is passed to the kernel untouched; it must match whatever the
/// request expects (usually a pointer or a word).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ioctl(fd: c_int, req: c_ulong, arg: *mut c_void) -> c_int {
    unsafe { syscall_ret(syscall3(SYS_IOCTL, fd as usize, req as usize, arg as usize)) as c_int }
}

/// Get terminal attributes (musl `tcgetattr`: `TCGETS`).
///
/// # Safety
///
/// `tio` must point to a writable [`Termios`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn tcgetattr(fd: c_int, tio: *mut Termios) -> c_int {
    unsafe { ioctl(fd, TCGETS, tio as *mut c_void) }
}

/// Set terminal attributes (musl `tcsetattr`: `TCSETS+act`, `act` in
/// `0..=2`, else `EINVAL`).
///
/// # Safety
///
/// `tio` must point to a readable [`Termios`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn tcsetattr(fd: c_int, act: c_int, tio: *const Termios) -> c_int {
    unsafe {
        if !(TCSANOW..=TCSAFLUSH).contains(&act) {
            errno_store(__errno_location(), EINVAL);
            return -1;
        }
        ioctl(fd, TCSETS.wrapping_add(act as c_ulong), tio as *mut c_void)
    }
}

/// Send a break (musl `tcsendbreak`: nonzero duration is
/// implementation-defined, so it is ignored — `TCSBRK` with 0).
///
/// # Safety
///
/// `fd` must be open.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn tcsendbreak(fd: c_int, _dur: c_int) -> c_int {
    // Small-int ioctl args ride as pointer words (never dereferenced).
    #[allow(clippy::zero_ptr)]
    unsafe {
        ioctl(fd, TCSBRK, core::ptr::null_mut())
    }
}

/// Wait until output is transmitted (musl `tcdrain`: `TCSBRK` with 1).
///
/// # Safety
///
/// `fd` must be open.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn tcdrain(fd: c_int) -> c_int {
    // Address 1, never dereferenced: the kernel reads the word value.
    unsafe { ioctl(fd, TCSBRK, core::ptr::dangling_mut::<c_void>()) }
}

/// Discard queued data (musl `tcflush`: `TCFLSH`).
///
/// # Safety
///
/// `fd` must be open.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn tcflush(fd: c_int, queue: c_int) -> c_int {
    unsafe { ioctl(fd, TCFLSH, queue as *mut c_void) }
}

/// Suspend/resume transmission (musl `tcflow`: `TCXONC`).
///
/// # Safety
///
/// `fd` must be open.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn tcflow(fd: c_int, action: c_int) -> c_int {
    unsafe { ioctl(fd, TCXONC, action as *mut c_void) }
}

/// Put a termios in raw mode (musl `cfmakeraw`).
///
/// # Safety
///
/// `t` must point to a writable [`Termios`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn cfmakeraw(t: *mut Termios) {
    unsafe {
        (*t).c_iflag &= !(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
        (*t).c_oflag &= !OPOST;
        (*t).c_lflag &= !(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
        (*t).c_cflag &= !(CSIZE | PARENB);
        (*t).c_cflag |= CS8;
        (*t).c_cc[VMIN] = 1;
        (*t).c_cc[VTIME] = 0;
    }
}

/// Output baud rate (musl `cfgetospeed`: `c_cflag & CBAUD`).
///
/// # Safety
///
/// `tio` must point to a readable [`Termios`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn cfgetospeed(tio: *const Termios) -> speed_t {
    unsafe { (*tio).c_cflag & CBAUD }
}

/// Input baud rate (musl `cfgetispeed`, scaled down from `CIBAUD`).
///
/// # Safety
///
/// `tio` must point to a readable [`Termios`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn cfgetispeed(tio: *const Termios) -> speed_t {
    unsafe { ((*tio).c_cflag & CIBAUD).wrapping_div(CIBAUD.wrapping_div(CBAUD)) }
}

/// Set output baud rate (musl `cfsetospeed`; unknown bits are `EINVAL`).
///
/// # Safety
///
/// `tio` must point to a writable [`Termios`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn cfsetospeed(tio: *mut Termios, speed: speed_t) -> c_int {
    unsafe {
        if speed & !CBAUD != 0 {
            errno_store(__errno_location(), EINVAL);
            return -1;
        }
        (*tio).c_cflag &= !CBAUD;
        (*tio).c_cflag |= speed;
        0
    }
}

/// Set input baud rate (musl `cfsetispeed`, scaled up into `CIBAUD`).
///
/// # Safety
///
/// `tio` must point to a writable [`Termios`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn cfsetispeed(tio: *mut Termios, speed: speed_t) -> c_int {
    unsafe {
        if speed & !CBAUD != 0 {
            errno_store(__errno_location(), EINVAL);
            return -1;
        }
        (*tio).c_cflag &= !CIBAUD;
        (*tio).c_cflag |= speed.wrapping_mul(CIBAUD.wrapping_div(CBAUD));
        0
    }
}

/// Set both baud rates (musl `cfsetspeed`: output to `speed`, input to
/// 0 — which reads back as the output rate).
///
/// # Safety
///
/// `tio` must point to a writable [`Termios`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn cfsetspeed(tio: *mut Termios, speed: speed_t) -> c_int {
    unsafe {
        let r = cfsetospeed(tio, speed);
        if r == 0 {
            cfsetispeed(tio, 0);
        }
        r
    }
}

/// Foreground process group (musl `tcgetpgrp`: `TIOCGPGRP`).
///
/// # Safety
///
/// `fd` must be open.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn tcgetpgrp(fd: c_int) -> c_int {
    unsafe {
        let mut pgrp: c_int = 0;
        if ioctl(fd, TIOCGPGRP, core::ptr::addr_of_mut!(pgrp) as *mut c_void) < 0 {
            return -1;
        }
        pgrp
    }
}

/// Set foreground process group (musl `tcsetpgrp`: `TIOCSPGRP`).
///
/// # Safety
///
/// `fd` must be open.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn tcsetpgrp(fd: c_int, pgrp: c_int) -> c_int {
    unsafe {
        let mut p = pgrp;
        ioctl(fd, TIOCSPGRP, core::ptr::addr_of_mut!(p) as *mut c_void)
    }
}

/// Session id of a terminal's foreground session (musl `tcgetsid`:
/// `TIOCGSID`).
///
/// # Safety
///
/// `fd` must be open.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn tcgetsid(fd: c_int) -> c_int {
    unsafe {
        let mut sid: c_int = 0;
        if ioctl(fd, TIOCGSID, core::ptr::addr_of_mut!(sid) as *mut c_void) < 0 {
            return -1;
        }
        sid
    }
}

/// Window size (musl `tcgetwinsize`: `TIOCGWINSZ`).
///
/// # Safety
///
/// `wsz` must point to a writable [`Winsize`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn tcgetwinsize(fd: c_int, wsz: *mut Winsize) -> c_int {
    unsafe { ioctl(fd, TIOCGWINSZ, wsz as *mut c_void) }
}

/// Set window size (musl `tcsetwinsize`: `TIOCSWINSZ`).
///
/// # Safety
///
/// `wsz` must point to a readable [`Winsize`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn tcsetwinsize(fd: c_int, wsz: *const Winsize) -> c_int {
    unsafe { ioctl(fd, TIOCSWINSZ, wsz as *mut c_void) }
}

/// Test whether a fd is a terminal (musl `isatty`: `TIOCGWINSZ` probe;
/// success `0+1=1`, error `-1+1=0`, errno left from the failed trap).
///
/// # Safety
///
/// `fd` must be open (or detectably not).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn isatty(fd: c_int) -> c_int {
    unsafe {
        let mut wsz = core::mem::MaybeUninit::<Winsize>::uninit();
        ioctl(fd, TIOCGWINSZ, wsz.as_mut_ptr() as *mut c_void).wrapping_add(1)
    }
}

/// Terminal pathname (musl `ttyname`: `ttyname_r` into a shared static
/// buffer — one line on threads: the buffer is process-global like
/// musl's own, so concurrent callers race).
///
/// # Safety
///
/// `fd` must be open. The returned pointer is valid until the next
/// `ttyname` call in the process; do not free it.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ttyname(fd: c_int) -> *mut c_char {
    static mut BUF: [c_char; 32] = [0; 32];
    unsafe {
        let r = ttyname_r(
            fd,
            core::ptr::addr_of_mut!(BUF) as *mut c_char,
            TTY_NAME_MAX,
        );
        if r != 0 {
            errno_store(__errno_location(), r);
            return core::ptr::null_mut();
        }
        core::ptr::addr_of_mut!(BUF) as *mut c_char
    }
}

/// Terminal pathname into a caller buffer (musl `ttyname_r`: `isatty`
/// probe, `/proc/self/fd/N` readlink, then dev/ino match against
/// `stat`; `ERANGE` when the link fills the buffer, `ENODEV` on
/// mismatch).
///
/// # Safety
///
/// `name` must be writable for `size` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ttyname_r(fd: c_int, name: *mut c_char, size: usize) -> c_int {
    unsafe {
        if isatty(fd) == 0 {
            return errno_load(__errno_location());
        }
        // musl `__procfdname` (`src/internal/procfdname.c`): NUL-terminated
        // "/proc/self/fd/<fd>". `fd` passed `isatty`, so it is non-negative.
        let mut proc = [0 as c_char; 15 + 3 * 4 + 2];
        let prefix = b"/proc/self/fd/";
        let mut i = 0;
        while i < prefix.len() {
            proc[i] = prefix[i] as c_char;
            i = i.wrapping_add(1);
        }
        let mut u = fd as u32;
        let mut digits: usize = 0;
        if u == 0 {
            digits = 1;
        } else {
            let mut v = u;
            while v != 0 {
                digits = digits.wrapping_add(1);
                v = v.wrapping_div(10);
            }
        }
        let mut j = i.wrapping_add(digits);
        proc[j] = 0;
        if u == 0 {
            proc[i] = b'0' as c_char;
        } else {
            while u != 0 {
                j = j.wrapping_sub(1);
                proc[j] = b'0'.wrapping_add((u.wrapping_rem(10)) as u8) as c_char;
                u = u.wrapping_div(10);
            }
        }
        let l = syscall_ret(syscall3(
            crate::ldso::SYS_READLINK,
            proc.as_ptr() as usize,
            name as usize,
            size,
        ));
        if l < 0 {
            return errno_load(__errno_location());
        }
        if l as usize == size {
            return ERANGE;
        }
        *name.add(l as usize) = 0;
        let mut st1 = core::mem::MaybeUninit::<crate::stat::Stat>::uninit();
        let mut st2 = core::mem::MaybeUninit::<crate::stat::Stat>::uninit();
        if crate::stat::stat(name as *const c_char, st1.as_mut_ptr()) != 0
            || crate::stat::fstat(fd, st2.as_mut_ptr()) != 0
        {
            return errno_load(__errno_location());
        }
        let st1 = st1.assume_init();
        let st2 = st2.assume_init();
        if st1.st_dev != st2.st_dev || st1.st_ino != st2.st_ino {
            return ENODEV;
        }
        0
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::{
        cfgetispeed, cfgetospeed, cfmakeraw, cfsetispeed, cfsetospeed, cfsetspeed, isatty,
        tcgetattr, tcsetattr, Termios, Winsize, B115200, B9600, TCSAFLUSH, TCSANOW,
    };
    use core::ffi::c_int;
    use core::mem::{offset_of, size_of};

    use crate::errno::{__errno_location, errno_load};
    use crate::syscall::{syscall3, syscall_ret};

    /// musl `arch/x86_64/bits/syscall.h.in` (test I/O + cleanup only).
    const SYS_CLOSE: usize = 3; // TODO: generate from arch bits/syscall.h

    unsafe fn close(fd: c_int) {
        unsafe {
            let _ = syscall_ret(syscall3(SYS_CLOSE, fd as usize, 0, 0));
        }
    }

    #[test]
    fn layouts_match_musl() {
        assert_eq!(size_of::<Termios>(), 60);
        assert_eq!(offset_of!(Termios, c_iflag), 0);
        assert_eq!(offset_of!(Termios, c_oflag), 4);
        assert_eq!(offset_of!(Termios, c_cflag), 8);
        assert_eq!(offset_of!(Termios, c_lflag), 12);
        assert_eq!(offset_of!(Termios, c_line), 16);
        assert_eq!(offset_of!(Termios, c_cc), 17);
        assert_eq!(offset_of!(Termios, c_ispeed), 52);
        assert_eq!(offset_of!(Termios, c_ospeed), 56);
        assert_eq!(size_of::<Winsize>(), 8);
        assert_eq!(offset_of!(Winsize, ws_col), 2);
        assert_eq!(offset_of!(Winsize, ws_ypixel), 6);
    }

    #[test]
    fn cfmakeraw_clears_exactly_musl_masks() {
        unsafe {
            let mut t = Termios {
                c_iflag: u32::MAX,
                c_oflag: u32::MAX,
                c_cflag: u32::MAX,
                c_lflag: u32::MAX,
                c_line: 0,
                c_cc: [0xFF; 32],
                c_ispeed: 0,
                c_ospeed: 0,
            };
            cfmakeraw(core::ptr::addr_of_mut!(t));
            assert_eq!(t.c_iflag | 0o2753, u32::MAX);
            assert_eq!(t.c_iflag & 0o2753, 0);
            assert_eq!(t.c_oflag | 0o1, u32::MAX);
            assert_eq!(t.c_lflag | 0o100113, u32::MAX);
            assert_eq!(t.c_lflag & 0o100113, 0);
            // CSIZE|PARENB cleared, CS8 set: only those bits change.
            assert_eq!(t.c_cflag, !0o460 | 0o60);
            assert_eq!(t.c_cc[super::VMIN], 1);
            assert_eq!(t.c_cc[super::VTIME], 0);
            assert_eq!(t.c_cc[0], 0xFF);
        }
    }

    #[test]
    fn speed_roundtrip() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut t = core::mem::zeroed::<Termios>();
            assert_eq!(cfsetospeed(core::ptr::addr_of_mut!(t), B9600), 0);
            assert_eq!(cfgetospeed(core::ptr::addr_of!(t)), B9600);
            assert_eq!(cfsetispeed(core::ptr::addr_of_mut!(t), B9600), 0);
            assert_eq!(cfgetispeed(core::ptr::addr_of!(t)), B9600);
            assert_eq!(cfsetspeed(core::ptr::addr_of_mut!(t), B115200), 0);
            assert_eq!(cfgetospeed(core::ptr::addr_of!(t)), B115200);
            assert_eq!(cfgetispeed(core::ptr::addr_of!(t)), 0);
            // Unknown bits: EINVAL, value untouched.
            assert_eq!(cfsetospeed(core::ptr::addr_of_mut!(t), u32::MAX), -1);
            assert_eq!(errno_load(__errno_location()), 22);
            assert_eq!(cfgetospeed(core::ptr::addr_of!(t)), B115200);
        }
    }

    #[test]
    fn pipe_is_not_a_tty() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let mut fds = [0 as c_int; 2];
            assert_eq!(crate::unistd::pipe(fds.as_mut_ptr()), 0);
            assert_eq!(isatty(fds[0]), 0);
            assert_eq!(errno_load(__errno_location()), 25);
            let mut t = core::mem::MaybeUninit::<Termios>::uninit();
            assert_eq!(tcgetattr(fds[0], t.as_mut_ptr()), -1);
            assert_eq!(errno_load(__errno_location()), 25);
            assert_eq!(tcsetattr(fds[1], TCSANOW, t.as_ptr()), -1);
            assert_eq!(tcsetattr(fds[1], 99, t.as_ptr()), -1);
            assert_eq!(errno_load(__errno_location()), 22);
            let _ = TCSAFLUSH;
            close(fds[0]);
            close(fds[1]);
        }
    }

    #[test]
    fn pty_master_if_present() {
        // A missing pty fails open (errno write): serialize (see testlock docs).
        let _guard = crate::ldso::testlock::lock();
        // No grantpt/unlockpt in this wave: open the master side only.
        // Absent pty support skips, never fails.
        unsafe {
            let fd = crate::fcntl::open(c"/dev/ptmx".as_ptr(), crate::fcntl::O_RDWR, 0);
            if fd < 0 {
                return;
            }
            assert_eq!(isatty(fd), 1);
            let mut t = core::mem::MaybeUninit::<Termios>::uninit();
            assert_eq!(tcgetattr(fd, t.as_mut_ptr()), 0);
            close(fd);
        }
    }
}
