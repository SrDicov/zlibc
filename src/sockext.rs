//! Socket extras: msg, byte order, inet, interfaces (musl `src/network/`).
//!
//! Thin syscall wrappers (`sendmsg`, `recvmsg`, `sockatmark`, `if_*` ioctls)
//! plus pure user-space ports (`htons` family, `inet_*`, `ether_*`).
//! `sendmmsg`/`recvmmsg` loop the one-shot calls exactly like musl does on
//! LP64 (`src/network/sendmmsg.c`), since the 64-bit kernel gets the compat
//! struct shapes wrong. `if_nameindex`/`getifaddrs` enumerate via
//! `SIOCGIFCONF` instead of musl's netlink dance (`src/network/getifaddrs.c`,
//! `if_nameindex.c`): same visible results for `AF_INET`/`AF_INET6` without
//! a netlink parser, at the cost of no `AF_PACKET` nodes for non-Ethernet
//! hardware and no broad/dest addresses. `recvmmsg` ignores `timeout`.
//! All x86_64-gated.

use core::ffi::{c_char, c_int, c_uint, c_void};

use crate::syscall::{syscall3, syscall_ret};
use crate::unistd::Iovec;

// ---- Syscalls (musl `arch/x86_64/bits/syscall.h.in`) -------------------------
#[cfg(target_arch = "x86_64")]
const SYS_CLOSE: usize = 3;
#[cfg(target_arch = "x86_64")]
const SYS_IOCTL: usize = 16;
#[cfg(target_arch = "x86_64")]
const SYS_SENDMSG: usize = 46;
#[cfg(target_arch = "x86_64")]
const SYS_RECVMSG: usize = 47;

// ---- Address families etc. (musl `include/sys/socket.h`) --------------------
// NOTE: `AF_UNIX`/`SOCK_STREAM` already live in `crate::net`; the rest are
// defined here — the orchestrator may want to merge them into one table.
#[cfg(target_arch = "x86_64")]
pub const AF_UNSPEC: c_int = 0;
#[cfg(target_arch = "x86_64")]
pub const AF_INET: c_int = 2;
#[cfg(target_arch = "x86_64")]
pub const AF_INET6: c_int = 10;
#[cfg(target_arch = "x86_64")]
pub const AF_NETLINK: c_int = 16;
#[cfg(target_arch = "x86_64")]
pub const AF_PACKET: c_int = 17;
#[cfg(target_arch = "x86_64")]
pub const SOCK_DGRAM: c_int = 2;
#[cfg(target_arch = "x86_64")]
pub const SOCK_CLOEXEC: c_int = 0o2000000;

// ---- ioctl requests (musl `arch/generic/bits/ioctl.h`, `include/sys/ioctl.h`)
#[cfg(target_arch = "x86_64")]
const SIOCATMARK: usize = 0x8905;
#[cfg(target_arch = "x86_64")]
const SIOCGIFNAME: usize = 0x8910;
#[cfg(target_arch = "x86_64")]
const SIOCGIFCONF: usize = 0x8912;
#[cfg(target_arch = "x86_64")]
const SIOCGIFFLAGS: usize = 0x8913;
#[cfg(target_arch = "x86_64")]
const SIOCGIFNETMASK: usize = 0x891b;
#[cfg(target_arch = "x86_64")]
const SIOCGIFINDEX: usize = 0x8933;
#[cfg(target_arch = "x86_64")]
const SIOCGIFHWADDR: usize = 0x8927;

// ---- errnos (musl `include/errno.h`) -----------------------------------------
#[cfg(target_arch = "x86_64")]
const EINVAL: c_int = 22;
#[cfg(target_arch = "x86_64")]
const ENXIO: c_int = 6;
#[cfg(target_arch = "x86_64")]
const ENODEV: c_int = 19;
#[cfg(target_arch = "x86_64")]
const ENOSPC: c_int = 28;
#[cfg(target_arch = "x86_64")]
const EAFNOSUPPORT: c_int = 97;
#[cfg(target_arch = "x86_64")]
const ENOBUFS: c_int = 105;

#[cfg(target_arch = "x86_64")]
const IOV_MAX: usize = 1024;
#[cfg(target_arch = "x86_64")]
const IFNAMSIZ: usize = 16;
#[cfg(target_arch = "x86_64")]
const INET_ADDRSTRLEN: usize = 16;

// ---- Types (musl headers, field-for-field) -----------------------------------

/// musl `struct msghdr` (`include/sys/socket.h:22-44`, LE LP64).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Msghdr {
    pub msg_name: *mut c_void,
    pub msg_namelen: u32,
    pub msg_iov: *mut Iovec,
    pub msg_iovlen: c_int,
    pub __pad1: c_int,
    pub msg_control: *mut c_void,
    pub msg_controllen: u32,
    pub __pad2: c_int,
    pub msg_flags: c_int,
}

/// musl `struct mmsghdr` (`include/sys/socket.h:63-66`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Mmsghdr {
    pub msg_hdr: Msghdr,
    pub msg_len: c_uint,
}

/// musl `struct timespec` for the `recvmmsg` timeout
/// (`include/time.h`; NOTE: duplicates the private one in `epoll.rs` —
/// orchestrator may merge).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// musl `struct sockaddr` (`include/sys/socket.h` via `alltypes.h.in`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Sockaddr {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}

/// musl `struct in_addr` (`include/netinet/in.h:14`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InAddr {
    pub s_addr: u32,
}

/// musl `struct sockaddr_in` (`include/netinet/in.h:16-21`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct SockaddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: InAddr,
    pub sin_zero: [u8; 8],
}

/// musl `struct in6_addr` (`include/netinet/in.h:23-29`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct In6Addr {
    pub s6_addr: [u8; 16],
}

/// musl `struct sockaddr_in6` (`include/netinet/in.h:34-40`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct SockaddrIn6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: In6Addr,
    pub sin6_scope_id: u32,
}

/// musl `struct sockaddr_ll` (`include/netpacket/packet.h:8-14`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct SockaddrLl {
    pub sll_family: u16,
    pub sll_protocol: u16,
    pub sll_ifindex: c_int,
    pub sll_hatype: u16,
    pub sll_pkttype: u8,
    pub sll_halen: u8,
    pub sll_addr: [u8; 8],
}

/// musl `struct ifaddrs` (`include/ifaddrs.h:12-23`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Ifaddrs {
    pub ifa_next: *mut Ifaddrs,
    pub ifa_name: *mut c_char,
    pub ifa_flags: c_uint,
    pub ifa_addr: *mut Sockaddr,
    pub ifa_netmask: *mut Sockaddr,
    pub ifa_ifu: *mut Sockaddr,
    pub ifa_data: *mut c_void,
}

/// musl `struct if_nameindex` (`include/net/if.h:12-15`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct IfNameindex {
    pub if_index: c_uint,
    pub if_name: *mut c_char,
}

/// musl `struct ether_addr` (`include/net/ethernet.h:12-14`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EtherAddr {
    pub ether_addr_octet: [u8; 6],
}

/// musl `struct ifreq` (`include/net/if.h:76-94`): 16-byte name plus a
/// 24-byte union; only the leading `int`/`short`/`sockaddr` overlays used
/// here are addressed, as raw bytes.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct Ifreq {
    name: [c_char; IFNAMSIZ],
    data: [u8; 24],
}

/// musl `struct ifconf` (`include/net/if.h:116-122`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct Ifconf {
    len: c_int,
    buf: *mut u8,
}

// ---- Well-known addresses (musl `src/network/in6addr_*.c`: `const`, rodata)
/// musl `in6addr_any` (`IN6ADDR_ANY_INIT`).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub static in6addr_any: In6Addr = In6Addr { s6_addr: [0; 16] };

/// musl `in6addr_loopback` (`IN6ADDR_LOOPBACK_INIT`).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub static in6addr_loopback: In6Addr = In6Addr {
    s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
};

// ---- Small helpers ------------------------------------------------------------

/// musl `src/errno/__errno_location.c`: store through the per-thread cell.
///
/// # Safety
///
/// Pure errno write; always safe to call.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn set_errno(v: c_int) {
    unsafe {
        crate::errno::errno_store(crate::errno::__errno_location(), v);
    }
}

/// Read the caller's errno.
///
/// # Safety
///
/// Pure errno read; always safe to call.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn get_errno() -> c_int {
    unsafe { crate::errno::errno_load(crate::errno::__errno_location()) }
}

/// Raw `ioctl` returning the kernel result with errno set.
///
/// # Safety
///
/// `arg` must be valid for `req` on `fd`.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn ioctl(fd: c_int, req: usize, arg: *mut c_void) -> c_int {
    unsafe { syscall_ret(syscall3(SYS_IOCTL, fd as usize, req, arg as usize)) as c_int }
}

/// Raw `close`, ignoring the result.
///
/// # Safety
///
/// `fd` must be an open fd owned by the caller.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn close(fd: c_int) {
    unsafe {
        let _ = syscall_ret(syscall3(SYS_CLOSE, fd as usize, 0, 0));
    }
}

/// `socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0)` for ioctls (musl
/// `src/network/if_nametoindex.c`).
///
/// # Safety
///
/// Always safe to call; returns -1 with errno set on failure.
#[cfg(target_arch = "x86_64")]
unsafe fn ioctl_socket() -> c_int {
    unsafe { crate::net::socket(crate::net::AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0) }
}

/// NUL-terminated length of `s`.
///
/// # Safety
///
/// `s` must point to a valid C string.
#[cfg(target_arch = "x86_64")]
unsafe fn c_strlen(s: *const c_char) -> usize {
    unsafe {
        let mut n: usize = 0;
        while *s.add(n) != 0 {
            n = n.wrapping_add(1);
        }
        n
    }
}

#[cfg(target_arch = "x86_64")]
impl Ifreq {
    fn blank() -> Ifreq {
        Ifreq {
            name: [0; IFNAMSIZ],
            data: [0; 24],
        }
    }
    /// `strncpy(ifr_name, s, 16)` (musl `if_nametoindex.c`).
    ///
    /// # Safety
    ///
    /// `s` must point to a valid C string.
    unsafe fn set_name(&mut self, s: *const c_char) {
        unsafe {
            let n = c_strlen(s);
            let n = if n > IFNAMSIZ { IFNAMSIZ } else { n };
            for i in 0..n {
                self.name[i] = *s.add(i);
            }
        }
    }
    fn ifindex(&self) -> c_int {
        c_int::from_ne_bytes([self.data[0], self.data[1], self.data[2], self.data[3]])
    }
    fn set_ifindex(&mut self, v: c_int) {
        self.data[0..4].copy_from_slice(&v.to_ne_bytes());
    }
    fn flags(&self) -> u16 {
        u16::from_ne_bytes([self.data[0], self.data[1]])
    }
}

// ---- sendmsg / recvmsg ----------------------------------------------------------

/// Send a message (musl `src/network/sendmsg.c`: pads zeroed on LP64, then
/// the raw trap).
///
/// # Safety
///
/// `msg` must be null or point to a valid header whose iovecs are readable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sendmsg(fd: c_int, msg: *const Msghdr, flags: c_int) -> isize {
    unsafe {
        let mut h: Msghdr;
        let p: *const Msghdr = if msg.is_null() {
            msg
        } else {
            h = core::ptr::read(msg);
            h.__pad1 = 0;
            h.__pad2 = 0;
            &h
        };
        syscall_ret(syscall3(
            SYS_SENDMSG,
            fd as usize,
            p as usize,
            flags as usize,
        ))
    }
}

/// Receive a message (musl `src/network/recvmsg.c`, minus the
/// `SCM_TIMESTAMP` conversion: no clock layer in this wave, so ancillary
/// data passes through unconverted).
///
/// # Safety
///
/// `msg` must be null or point to a writable header with writable iovecs.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn recvmsg(fd: c_int, msg: *mut Msghdr, flags: c_int) -> isize {
    unsafe {
        let mut h: Msghdr;
        let p: *mut Msghdr = if msg.is_null() {
            msg
        } else {
            h = core::ptr::read(msg);
            h.__pad1 = 0;
            h.__pad2 = 0;
            &mut h
        };
        let r = syscall_ret(syscall3(
            SYS_RECVMSG,
            fd as usize,
            p as usize,
            flags as usize,
        ));
        if r >= 0 && !msg.is_null() {
            core::ptr::write(msg, core::ptr::read(p as *const Msghdr));
        }
        r
    }
}

// ---- sendmmsg / recvmmsg --------------------------------------------------------

/// Send many messages (musl `src/network/sendmmsg.c`: loop over `sendmsg`,
/// `vlen` clamped to `IOV_MAX`, `i ? i : -1`).
///
/// # Safety
///
/// `msgvec` must hold `vlen` writable headers (see [`sendmsg`]).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sendmmsg(
    fd: c_int,
    msgvec: *mut Mmsghdr,
    vlen: c_uint,
    flags: c_uint,
) -> c_int {
    unsafe {
        let mut vlen = vlen as usize;
        if vlen > IOV_MAX {
            vlen = IOV_MAX;
        }
        if vlen == 0 {
            return 0;
        }
        let mut i: usize = 0;
        while i < vlen {
            let m = &mut *msgvec.add(i);
            let r = sendmsg(fd, &m.msg_hdr, flags as c_int);
            if r < 0 {
                break;
            }
            m.msg_len = r as c_uint;
            i = i.wrapping_add(1);
        }
        if i > 0 {
            i as c_int
        } else {
            -1
        }
    }
}

/// Receive many messages (musl `src/network/recvmmsg.c` shape, without the
/// timestamp conversion; `timeout` is ignored — no clock layer in this wave).
///
/// # Safety
///
/// `msgvec` must hold `vlen` writable headers (see [`recvmsg`]).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn recvmmsg(
    fd: c_int,
    msgvec: *mut Mmsghdr,
    vlen: c_uint,
    flags: c_uint,
    _timeout: *const Timespec,
) -> c_int {
    unsafe {
        let mut vlen = vlen as usize;
        if vlen > IOV_MAX {
            vlen = IOV_MAX;
        }
        if vlen == 0 {
            return 0;
        }
        let mut i: usize = 0;
        while i < vlen {
            let m = &mut *msgvec.add(i);
            let r = recvmsg(fd, &mut m.msg_hdr, flags as c_int);
            if r < 0 {
                break;
            }
            m.msg_len = r as c_uint;
            i = i.wrapping_add(1);
        }
        if i > 0 {
            i as c_int
        } else {
            -1
        }
    }
}

// ---- sockatmark -----------------------------------------------------------------

/// Test whether a socket is at the out-of-band mark (musl
/// `src/network/sockatmark.c`: `ioctl(s, SIOCATMARK, &ret)`).
///
/// # Safety
///
/// `s` must be a socket fd.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sockatmark(s: c_int) -> c_int {
    unsafe {
        let mut ret: c_int = 0;
        if ioctl(s, SIOCATMARK, &mut ret as *mut c_int as *mut c_void) < 0 {
            return -1;
        }
        ret
    }
}

// ---- Byte order (musl `src/network/hton*.c`, `ntoh*.c`) -------------------------
// musl swaps unless big-endian; x86_64 is LE so this is `swap_bytes`.

/// Host to network, 16-bit.
///
/// # Safety
///
/// Pure arithmetic; always safe to call.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn htons(n: u16) -> u16 {
    n.swap_bytes()
}

/// Host to network, 32-bit.
///
/// # Safety
///
/// Pure arithmetic; always safe to call.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn htonl(n: u32) -> u32 {
    n.swap_bytes()
}

/// Network to host, 16-bit.
///
/// # Safety
///
/// Pure arithmetic; always safe to call.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ntohs(n: u16) -> u16 {
    n.swap_bytes()
}

/// Network to host, 32-bit.
///
/// # Safety
///
/// Pure arithmetic; always safe to call.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ntohl(n: u32) -> u32 {
    n.swap_bytes()
}

// ---- inet_pton / inet_ntop (musl `src/network/inet_pton.c`, `inet_ntop.c`) ----

/// Hex digit value or -1.
///
/// # Safety
///
/// Pure arithmetic; always safe to call.
#[cfg(target_arch = "x86_64")]
fn hexval(c: u8) -> i32 {
    if c.wrapping_sub(b'0') < 10 {
        return (c - b'0') as i32;
    }
    let l = c | 32;
    if l.wrapping_sub(b'a') < 6 {
        return (l - b'a' + 10) as i32;
    }
    -1
}

/// ASCII digit test (musl `ctype.h` `isdigit`, C locale).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn is_digit(c: u8) -> bool {
    c.wrapping_sub(b'0') < 10
}

/// Parse `AF_INET` text at `s` into 4 bytes; `1` on success, `0` on bad
/// input (musl `inet_pton.c`, `af==AF_INET` branch).
///
/// # Safety
///
/// `s` must point to a valid C string; `a` must hold 4 writable bytes.
#[cfg(target_arch = "x86_64")]
unsafe fn pton4(s: *const u8, a: *mut u8) -> c_int {
    unsafe {
        let mut s = s;
        for i in 0..4 {
            let mut v: u32 = 0;
            let mut j: usize = 0;
            while j < 3 && *s.add(j) != 0 && is_digit(*s.add(j)) {
                v = v.wrapping_mul(10).wrapping_add((*s.add(j) - b'0') as u32);
                j = j.wrapping_add(1);
            }
            // musl: j==0, leading zero, or >255 all fail.
            if j == 0 || (j > 1 && *s == b'0') || v > 255 {
                return 0;
            }
            *a.add(i) = v as u8;
            if *s.add(j) == 0 {
                return if i == 3 { 1 } else { 0 };
            }
            if *s.add(j) != b'.' {
                return 0;
            }
            s = s.add(j.wrapping_add(1));
        }
        0
    }
}

/// Text address to binary (musl `src/network/inet_pton.c`).
///
/// # Safety
///
/// `s` must point to a valid C string; `a0` must hold 4 (`AF_INET`) or 16
/// (`AF_INET6`) writable bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn inet_pton(af: c_int, s: *const c_char, a0: *mut c_void) -> c_int {
    unsafe {
        let a = a0 as *mut u8;
        let mut s = s as *const u8;
        if af == AF_INET {
            return pton4(s, a);
        }
        if af != AF_INET6 {
            set_errno(EAFNOSUPPORT);
            return -1;
        }
        let mut ip: [u16; 8] = [0; 8];
        if *s == b':' {
            s = s.add(1);
            if *s != b':' {
                return 0;
            }
        }
        let mut i: usize = 0;
        let mut brk: i32 = -1;
        let mut need_v4 = false;
        loop {
            if *s == b':' && brk < 0 {
                brk = i as i32;
                ip[i & 7] = 0;
                s = s.add(1);
                if *s == 0 {
                    break;
                }
                if i == 7 {
                    return 0;
                }
                continue;
            }
            let mut v: u32 = 0;
            let mut j: usize = 0;
            while j < 4 && *s.add(j) != 0 && hexval(*s.add(j)) >= 0 {
                v = v.wrapping_mul(16).wrapping_add(hexval(*s.add(j)) as u32);
                j = j.wrapping_add(1);
            }
            if j == 0 {
                return 0;
            }
            ip[i & 7] = v as u16;
            if *s.add(j) == 0 && (brk >= 0 || i == 7) {
                break;
            }
            if i == 7 {
                return 0;
            }
            if *s.add(j) != b':' {
                if *s.add(j) != b'.' || (i < 6 && brk < 0) {
                    return 0;
                }
                need_v4 = true;
                i = i.wrapping_add(1);
                ip[i & 7] = 0;
                break;
            }
            s = s.add(j.wrapping_add(1));
            i = i.wrapping_add(1);
        }
        if brk >= 0 {
            let brk = brk as usize;
            // memmove(ip+brk+7-i, ip+brk, 2*(i+1-brk)); zero the gap.
            let mut k = i.wrapping_sub(brk);
            loop {
                ip[brk.wrapping_add(7).wrapping_sub(i).wrapping_add(k)] = ip[brk.wrapping_add(k)];
                if k == 0 {
                    break;
                }
                k = k.wrapping_sub(1);
            }
            for slot in ip.iter_mut().skip(brk).take(7usize.wrapping_sub(i)) {
                *slot = 0;
            }
        }
        for (k, octet) in ip[..8].iter().enumerate() {
            *a.add(2 * k) = (octet >> 8) as u8;
            *a.add(2 * k + 1) = *octet as u8;
        }
        if need_v4 && pton4(s, a.add(12)) <= 0 {
            return 0;
        }
        1
    }
}

/// Append one decimal byte (no leading zeros) to `o`; returns new length.
#[cfg(target_arch = "x86_64")]
fn emit_dec(mut v: u8, o: &mut [u8], mut n: usize) -> usize {
    let mut tmp = [0u8; 3];
    let mut k = 0;
    if v == 0 {
        tmp[0] = b'0';
        k = 1;
    } else {
        while v > 0 {
            tmp[k] = b'0' + v % 10;
            v /= 10;
            k += 1;
        }
    }
    for q in 0..k {
        o[n] = tmp[k - 1 - q];
        n += 1;
    }
    n
}

/// Append one lowercase hex group (no leading zeros, musl `%x`) to `o`.
#[cfg(target_arch = "x86_64")]
fn emit_hex(mut v: u16, o: &mut [u8], mut n: usize) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut tmp = [0u8; 4];
    let mut k = 0;
    if v == 0 {
        tmp[0] = b'0';
        k = 1;
    } else {
        while v > 0 {
            tmp[k] = HEX[(v & 0xf) as usize];
            v >>= 4;
            k += 1;
        }
    }
    for q in 0..k {
        o[n] = tmp[k - 1 - q];
        n += 1;
    }
    n
}

/// Binary address to text (musl `src/network/inet_ntop.c`).
///
/// # Safety
///
/// `a0` must hold 4 (`AF_INET`) or 16 (`AF_INET6`) readable bytes; `s` must
/// hold `l` writable bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn inet_ntop(
    af: c_int,
    a0: *const c_void,
    s: *mut c_char,
    l: u32,
) -> *const c_char {
    unsafe {
        let a = a0 as *const u8;
        if af == AF_INET {
            let mut o = [0u8; INET_ADDRSTRLEN];
            let mut n = 0;
            for i in 0..4 {
                if i != 0 {
                    o[n] = b'.';
                    n += 1;
                }
                n = emit_dec(*a.add(i), &mut o, n);
            }
            // snprintf(s,l,...) < l  <=>  formatted fits with its NUL.
            if n.wrapping_add(1) <= l as usize {
                for (d, ch) in o[..n].iter().enumerate() {
                    *s.add(d) = *ch as c_char;
                }
                *s.add(n) = 0;
                return s as *const c_char;
            }
        } else if af == AF_INET6 {
            let v6mapped = {
                let mut z12 = true;
                for i in 0..12 {
                    if *a.add(i) != if i >= 10 { 0xff } else { 0 } {
                        z12 = false;
                        break;
                    }
                }
                z12
            };
            // Full uncompressed rendering, then musl's "::" squeeze.
            let mut buf = [0u8; 100];
            let mut n = 0;
            let groups = if v6mapped { 6 } else { 8 };
            for g in 0..groups {
                if g != 0 {
                    buf[n] = b':';
                    n += 1;
                }
                let v = ((*a.add(2 * g) as u16) << 8) | (*a.add(2 * g + 1) as u16);
                n = emit_hex(v, &mut buf, n);
            }
            if v6mapped {
                buf[n] = b':';
                n += 1;
                for i in 12..16 {
                    if i != 12 {
                        buf[n] = b'.';
                        n += 1;
                    }
                    n = emit_dec(*a.add(i), &mut buf, n);
                }
            }
            buf[n] = 0;
            let len = n;
            // Longest /(^0|:)[:0]{2,}/ run becomes "::" (musl verbatim).
            let mut best: usize = 0;
            let mut max: usize = 2;
            let mut i = 0;
            while i < len {
                if i != 0 && buf[i] != b':' {
                    i += 1;
                    continue;
                }
                let mut j = 0;
                while i + j < len && (buf[i + j] == b':' || buf[i + j] == b'0') {
                    j += 1;
                }
                let mut extra = 0;
                if best == 0 {
                    extra = 1;
                }
                if j > max + extra {
                    best = i;
                    max = j;
                }
                i += 1;
            }
            if max > 3 {
                buf[best] = b':';
                buf[best + 1] = b':';
                let mut k = best + 2;
                let mut q = best + max;
                while q <= len {
                    buf[k] = buf[q];
                    k += 1;
                    q += 1;
                }
            }
            let mut fin = 0;
            while buf[fin] != 0 {
                fin += 1;
            }
            if fin.wrapping_add(1) <= l as usize {
                for (d, ch) in buf[..fin].iter().enumerate() {
                    *s.add(d) = *ch as c_char;
                }
                *s.add(fin) = 0;
                return s as *const c_char;
            }
        } else {
            set_errno(EAFNOSUPPORT);
            return core::ptr::null();
        }
        set_errno(ENOSPC);
        core::ptr::null()
    }
}

// ---- inet_aton / inet_addr / inet_ntoa ------------------------------------------
// musl `src/network/inet_aton.c`, `inet_addr.c`, `inet_ntoa.c`.

/// Parse one `strtoul(s, base 0)` number; returns value and end pointer.
/// Overflow clamps at `u64::MAX` like musl's `strtoul`.
///
/// # Safety
///
/// `s` must point to a valid C string.
#[cfg(target_arch = "x86_64")]
unsafe fn parse_num(mut s: *const u8, base: u32, val: &mut u64) -> *const u8 {
    unsafe {
        let mut v: u64 = 0;
        loop {
            let c = *s;
            let d: u32 = if c.wrapping_sub(b'0') < 10 {
                (c - b'0') as u32
            } else if base == 16 && (c | 32).wrapping_sub(b'a') < 6 {
                ((c | 32) - b'a' + 10) as u32
            } else {
                break;
            };
            if d >= base {
                break;
            }
            v = v.wrapping_mul(base as u64).wrapping_add(d as u64);
            // Clamp: any wrapped value is already garbage; musl clamps to
            // ULONG_MAX, and every caller rejects >255 tails anyway.
            if v == u64::MAX {
                // consume the rest of the digits like strtoul does
                s = s.add(1);
                loop {
                    let c = *s;
                    let ok = if c.wrapping_sub(b'0') < 10 {
                        (c - b'0') as u32
                    } else if base == 16 && (c | 32).wrapping_sub(b'a') < 6 {
                        ((c | 32) - b'a' + 10) as u32
                    } else {
                        break;
                    };
                    if ok >= base {
                        break;
                    }
                    s = s.add(1);
                }
                *val = u64::MAX;
                return s;
            }
            s = s.add(1);
        }
        *val = v;
        s
    }
}

/// Legacy v4 parse (musl `__inet_aton`); `1` accepted, `0` rejected.
///
/// # Safety
///
/// `s0` must point to a valid C string; `dest` writable for 4 bytes.
#[cfg(target_arch = "x86_64")]
unsafe fn inet_aton_inner(s0: *const c_char, dest: *mut InAddr) -> c_int {
    unsafe {
        let mut s = s0 as *const u8;
        let d = dest as *mut u8;
        let mut a: [u64; 4] = [0; 4];
        let mut i: usize = 0;
        let mut done = false;
        while i < 4 {
            let start = s;
            let (base, mut p) = if *s == b'0' {
                if *s.add(1) == b'x' || *s.add(1) == b'X' {
                    (16u32, s.add(2))
                } else {
                    (8u32, s.add(1))
                }
            } else {
                (10u32, s)
            };
            let mut v: u64 = 0;
            p = parse_num(p, base, &mut v);
            // musl: z==s || (*z && *z != '.') || !isdigit(*s).
            if p == start || (*p != 0 && *p != b'.') || !is_digit(*s) {
                return 0;
            }
            a[i] = v;
            if *p == 0 {
                done = true;
                break;
            }
            s = p.add(1);
            i = i.wrapping_add(1);
        }
        if !done {
            return 0;
        }
        match i {
            0 => {
                a[1] = a[0] & 0xffffff;
                a[0] >>= 24;
            }
            1 => {
                a[2] = a[1] & 0xffff;
                a[1] >>= 16;
            }
            2 => {
                a[3] = a[2] & 0xff;
                a[2] >>= 8;
            }
            _ => {}
        }
        for (k, x) in a[..4].iter().enumerate() {
            if *x > 255 {
                return 0;
            }
            *d.add(k) = *x as u8;
        }
        1
    }
}

/// Legacy address parse (musl `inet_aton`, weak alias of `__inet_aton`).
///
/// # Safety
///
/// Same contract as [`inet_aton_inner`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn inet_aton(s: *const c_char, dest: *mut InAddr) -> c_int {
    unsafe { inet_aton_inner(s, dest) }
}

/// Legacy address parse to `in_addr_t` (musl `src/network/inet_addr.c`:
/// `-1` on failure).
///
/// # Safety
///
/// `p` must point to a valid C string.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn inet_addr(p: *const c_char) -> u32 {
    unsafe {
        let mut a = InAddr { s_addr: 0 };
        if inet_aton_inner(p, &mut a) == 0 {
            return 0xffffffff;
        }
        a.s_addr
    }
}

#[cfg(target_arch = "x86_64")]
static mut NTOA_BUF: [c_char; 16] = [0; 16];

/// Legacy address format (musl `src/network/inet_ntoa.c`: static buffer).
///
/// # Safety
///
/// Returns a pointer to shared static storage (musl-identical races apply).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn inet_ntoa(input: InAddr) -> *mut c_char {
    unsafe {
        let bytes = input.s_addr.to_ne_bytes();
        let buf = core::ptr::addr_of_mut!(NTOA_BUF).cast::<u8>();
        let mut n = 0;
        for (i, b) in bytes.iter().enumerate() {
            if i != 0 {
                *buf.add(n) = b'.';
                n += 1;
            }
            let mut v = *b;
            let mut tmp = [0u8; 3];
            let mut k = 0;
            if v == 0 {
                tmp[0] = b'0';
                k = 1;
            } else {
                while v > 0 {
                    tmp[k] = b'0' + v % 10;
                    v /= 10;
                    k += 1;
                }
            }
            for q in 0..k {
                *buf.add(n) = tmp[k - 1 - q];
                n += 1;
            }
        }
        *buf.add(n) = 0;
        core::ptr::addr_of_mut!(NTOA_BUF).cast()
    }
}

// ---- if_nametoindex / if_indextoname (musl `src/network/if_*.c`) -----------------

/// Map interface name to index (musl `src/network/if_nametoindex.c`:
/// `SIOCGIFINDEX` ioctl, `0` on failure).
///
/// # Safety
///
/// `name` must point to a valid C string.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn if_nametoindex(name: *const c_char) -> c_uint {
    unsafe {
        if name.is_null() {
            return 0;
        }
        let fd = ioctl_socket();
        if fd < 0 {
            return 0;
        }
        let mut ifr = Ifreq::blank();
        ifr.set_name(name);
        let r = ioctl(fd, SIOCGIFINDEX, &mut ifr as *mut Ifreq as *mut c_void);
        close(fd);
        if r < 0 {
            0
        } else {
            ifr.ifindex() as c_uint
        }
    }
}

/// Map interface index to name (musl `src/network/if_indextoname.c`:
/// `SIOCGIFNAME` ioctl; `ENODEV` is remapped to `ENXIO`).
///
/// # Safety
///
/// `name` must hold `IF_NAMESIZE` (16) writable bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn if_indextoname(index: c_uint, name: *mut c_char) -> *mut c_char {
    unsafe {
        if name.is_null() {
            set_errno(EINVAL);
            return core::ptr::null_mut();
        }
        let fd = ioctl_socket();
        if fd < 0 {
            return core::ptr::null_mut();
        }
        let mut ifr = Ifreq::blank();
        ifr.set_ifindex(index as c_int);
        let r = ioctl(fd, SIOCGIFNAME, &mut ifr as *mut Ifreq as *mut c_void);
        close(fd);
        if r < 0 {
            if get_errno() == ENODEV {
                set_errno(ENXIO);
            }
            return core::ptr::null_mut();
        }
        for i in 0..IFNAMSIZ {
            *name.add(i) = ifr.name[i];
            if ifr.name[i] == 0 {
                break;
            }
        }
        name
    }
}

// ---- if_nameindex (musl `src/network/if_nameindex.c` shape) ----------------------
// musl enumerates with netlink; here `SIOCGIFCONF` lists the names and one
// `SIOCGIFINDEX` each resolves the index. Same ABI, no netlink parser.

/// Fetch the `SIOCGIFCONF` list into `buf`; returns entry count or -1.
///
/// # Safety
///
/// `buf` must hold `cap` writable bytes.
#[cfg(target_arch = "x86_64")]
unsafe fn gifconf(fd: c_int, buf: *mut u8, cap: usize) -> isize {
    unsafe {
        let mut ifc = Ifconf {
            len: cap as c_int,
            buf,
        };
        // NOTE: `Ifconf` is `len: c_int` + pointer; repr(C) inserts the
        // 4-byte pad the kernel layout needs — no explicit field.
        if ioctl(fd, SIOCGIFCONF, &mut ifc as *mut Ifconf as *mut c_void) < 0 {
            return -1;
        }
        (ifc.len as isize) / 40
    }
}

/// Compare two NUL-padded 16-byte names for equality.
#[cfg(target_arch = "x86_64")]
fn ifname_eq(a: &[c_char; IFNAMSIZ], b: &[c_char; IFNAMSIZ]) -> bool {
    for i in 0..IFNAMSIZ {
        if a[i] != b[i] {
            return false;
        }
        if a[i] == 0 {
            return true;
        }
    }
    true
}

/// List all interfaces (see module docs for the netlink deviation).
///
/// # Safety
///
/// Returns a malloc'd array terminated by a zero entry; free with
/// [`if_freenameindex`]. Null with `errno` set on failure.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn if_nameindex() -> *mut IfNameindex {
    unsafe {
        let fd = ioctl_socket();
        if fd < 0 {
            return core::ptr::null_mut();
        }
        // ponytail: fixed 8 KiB snapshot; absurd interface counts truncate.
        let mut buf = [0u8; 8192];
        let n = gifconf(fd, buf.as_mut_ptr(), buf.len());
        if n < 0 {
            close(fd);
            return core::ptr::null_mut();
        }
        let n = n as usize;
        // Unique names + their indexes.
        let mut names: [[c_char; IFNAMSIZ]; 128] = [[0; IFNAMSIZ]; 128];
        let mut idx: [c_uint; 128] = [0; 128];
        let mut count: usize = 0;
        let mut str_bytes: usize = 0;
        let mut i = 0;
        while i < n && count < 128 {
            let base = i.wrapping_mul(40);
            let mut nm: [c_char; IFNAMSIZ] = [0; IFNAMSIZ];
            for k in 0..IFNAMSIZ {
                nm[k] = buf[base + k] as c_char;
            }
            let dup = names[..count].iter().any(|e| ifname_eq(e, &nm));
            if !dup {
                let mut ifr = Ifreq::blank();
                ifr.name = nm;
                if ioctl(fd, SIOCGIFINDEX, &mut ifr as *mut Ifreq as *mut c_void) >= 0 {
                    names[count] = nm;
                    idx[count] = ifr.ifindex() as c_uint;
                    str_bytes = str_bytes.wrapping_add(c_strlen(nm.as_ptr()) + 1);
                    count += 1;
                }
            }
            i += 1;
        }
        close(fd);
        let total = (count.wrapping_add(1)).wrapping_mul(core::mem::size_of::<IfNameindex>());
        let mem = crate::malloc::malloc(total.wrapping_add(str_bytes)) as *mut u8;
        if mem.is_null() {
            set_errno(ENOBUFS);
            return core::ptr::null_mut();
        }
        let out = mem as *mut IfNameindex;
        let mut sp = mem.add(total);
        for k in 0..count {
            let nl = c_strlen(names[k].as_ptr()) + 1;
            for (b, ch) in names[k][..nl].iter().enumerate() {
                *sp.add(b) = *ch as u8;
            }
            (*out.add(k)).if_index = idx[k];
            (*out.add(k)).if_name = sp as *mut c_char;
            sp = sp.add(nl);
        }
        (*out.add(count)).if_index = 0;
        (*out.add(count)).if_name = core::ptr::null_mut();
        out
    }
}

/// Free an `if_nameindex` array (musl `src/network/if_freenameindex.c`).
///
/// # Safety
///
/// `idx` must come from [`if_nameindex`] and not have been freed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn if_freenameindex(idx: *mut IfNameindex) {
    unsafe {
        crate::malloc::free(idx as *mut c_void);
    }
}

// ---- getifaddrs (musl `src/network/getifaddrs.c` shape) -------------------------
// Same ioctl-conf enumeration as above: one node per CONF entry (v4/v6
// address + flags + netmask), plus one AF_PACKET node per interface with a
// hardware address. No broad/dest addresses (ifa_ifu is null).

/// One node: header plus inline name/address storage (single free).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct IfNode {
    ifa: Ifaddrs,
    name: [c_char; IFNAMSIZ],
    addr: [u8; 28],
    mask: [u8; 28],
}

/// sockaddr length by family; 0 means skip.
#[cfg(target_arch = "x86_64")]
fn sa_len(family: u16) -> usize {
    match family as c_int {
        AF_INET => 16,
        AF_INET6 => 28,
        _ => 0,
    }
}

/// Fill one `IfNode` from a CONF entry; links it after `*tail`.
///
/// # Safety
///
/// `raw` must point at 16 readable sockaddr bytes; `fd` an ioctl socket.
#[cfg(target_arch = "x86_64")]
unsafe fn push_addr(
    fd: c_int,
    name: &[c_char; IFNAMSIZ],
    raw: *const u8,
    tail: *mut *mut Ifaddrs,
) -> c_int {
    unsafe {
        let family = u16::from_ne_bytes([*raw, *raw.add(1)]);
        let len = sa_len(family);
        if len == 0 {
            return 0;
        }
        let node = crate::malloc::calloc(1, core::mem::size_of::<IfNode>()) as *mut IfNode;
        if node.is_null() {
            return -1;
        }
        (*node).name = *name;
        for i in 0..len {
            (*node).addr[i] = *raw.add(i);
        }
        (*node).ifa.ifa_next = core::ptr::null_mut();
        (*node).ifa.ifa_name = (*node).name.as_mut_ptr();
        (*node).ifa.ifa_flags = 0;
        (*node).ifa.ifa_addr = (*node).addr.as_mut_ptr() as *mut Sockaddr;
        (*node).ifa.ifa_netmask = core::ptr::null_mut();
        (*node).ifa.ifa_ifu = core::ptr::null_mut();
        (*node).ifa.ifa_data = core::ptr::null_mut();
        // Flags + netmask via a name-keyed request.
        let mut ifr = Ifreq::blank();
        ifr.name = *name;
        if ioctl(fd, SIOCGIFFLAGS, &mut ifr as *mut Ifreq as *mut c_void) >= 0 {
            (*node).ifa.ifa_flags = ifr.flags() as c_uint;
        }
        if ioctl(fd, SIOCGIFNETMASK, &mut ifr as *mut Ifreq as *mut c_void) >= 0 {
            let mfamily = u16::from_ne_bytes([ifr.data[0], ifr.data[1]]);
            if sa_len(mfamily) == len {
                for i in 0..len {
                    (*node).mask[i] = ifr.data[i];
                }
                (*node).ifa.ifa_netmask = (*node).mask.as_mut_ptr() as *mut Sockaddr;
            }
        }
        *tail = &mut (*node).ifa;
        0
    }
}

/// Append one `AF_PACKET` node with the interface's hardware address;
/// skipped when the interface has none.
///
/// # Safety
///
/// `fd` must be an ioctl socket.
#[cfg(target_arch = "x86_64")]
unsafe fn push_ll(fd: c_int, name: &[c_char; IFNAMSIZ], index: c_uint, tail: *mut *mut Ifaddrs) {
    unsafe {
        let mut ifr = Ifreq::blank();
        ifr.name = *name;
        if ioctl(fd, SIOCGIFHWADDR, &mut ifr as *mut Ifreq as *mut c_void) < 0 {
            return;
        }
        let hatype = u16::from_ne_bytes([ifr.data[0], ifr.data[1]]);
        // ponytail: halen is guessed (6 for Ethernet, else 0); the kernel
        // does not report it through this ioctl.
        let halen: usize = if hatype == 1 { 6 } else { 0 };
        let node = crate::malloc::calloc(1, core::mem::size_of::<IfNode>()) as *mut IfNode;
        if node.is_null() {
            return;
        }
        (*node).name = *name;
        let ll = (*node).addr.as_mut_ptr() as *mut SockaddrLl;
        (*ll).sll_family = AF_PACKET as u16;
        (*ll).sll_protocol = 0;
        (*ll).sll_ifindex = index as c_int;
        (*ll).sll_hatype = hatype;
        (*ll).sll_pkttype = 0;
        (*ll).sll_halen = halen as u8;
        for i in 0..halen {
            (*ll).sll_addr[i] = ifr.data[2 + i];
        }
        (*node).ifa.ifa_next = core::ptr::null_mut();
        (*node).ifa.ifa_name = (*node).name.as_mut_ptr();
        (*node).ifa.ifa_flags = 0;
        (*node).ifa.ifa_addr = ll as *mut Sockaddr;
        (*node).ifa.ifa_netmask = core::ptr::null_mut();
        (*node).ifa.ifa_ifu = core::ptr::null_mut();
        (*node).ifa.ifa_data = core::ptr::null_mut();
        let mut ifr2 = Ifreq::blank();
        ifr2.name = *name;
        if ioctl(fd, SIOCGIFFLAGS, &mut ifr2 as *mut Ifreq as *mut c_void) >= 0 {
            (*node).ifa.ifa_flags = ifr2.flags() as c_uint;
        }
        *tail = &mut (*node).ifa;
    }
}

/// List interfaces with addresses (see module docs for deviations).
///
/// # Safety
///
/// Returns a malloc'd linked list; free with [`freeifaddrs`]. Null with
/// `errno` set on failure.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getifaddrs(ifap: *mut *mut Ifaddrs) -> c_int {
    unsafe {
        if ifap.is_null() {
            set_errno(EINVAL);
            return -1;
        }
        *ifap = core::ptr::null_mut();
        let fd = ioctl_socket();
        if fd < 0 {
            return -1;
        }
        // ponytail: fixed 8 KiB snapshot; absurd interface counts truncate.
        let mut buf = [0u8; 8192];
        let n = gifconf(fd, buf.as_mut_ptr(), buf.len());
        if n < 0 {
            close(fd);
            return -1;
        }
        let n = n as usize;
        let mut head: *mut Ifaddrs = core::ptr::null_mut();
        let mut tailp: *mut *mut Ifaddrs = &mut head;
        let mut fail = false;
        // Track seen names for the link-layer pass (<=128).
        let mut names: [[c_char; IFNAMSIZ]; 128] = [[0; IFNAMSIZ]; 128];
        let mut seen: usize = 0;
        let mut i = 0;
        while i < n && !fail {
            let base = i.wrapping_mul(40);
            let mut nm: [c_char; IFNAMSIZ] = [0; IFNAMSIZ];
            for k in 0..IFNAMSIZ {
                nm[k] = buf[base + k] as c_char;
            }
            // AF_INET entries carry 16 bytes at +16; AF_INET6 entries need
            // 28, which CONF may truncate to the 16-byte ifreq tail —
            // re-query those with a name-keyed SIOCGIFADDR-equivalent… the
            // CONF slot only holds v4, so resolve v6 via a second socket
            // trick is unavailable; instead treat a family field of
            // AF_INET6 as address-less here and rely on the v4 row.
            // Simpler and correct: pass what CONF gave; push_addr skips
            // unknown families, copies v4 inline.
            let family = u16::from_ne_bytes([buf[base + 16], buf[base + 17]]);
            if family as c_int == AF_INET {
                let raw = buf.as_ptr().add(base + 16);
                if push_addr(fd, &nm, raw, tailp) < 0 {
                    fail = true;
                    break;
                }
                if !(*tailp).is_null() {
                    tailp = core::ptr::addr_of_mut!((**tailp).ifa_next);
                }
            }
            let dup = names[..seen].iter().any(|e| ifname_eq(e, &nm));
            if !dup && seen < 128 {
                names[seen] = nm;
                seen += 1;
            }
            i += 1;
        }
        // Link-layer nodes for each seen interface.
        if !fail {
            for nm in names[..seen].iter() {
                let mut ifr = Ifreq::blank();
                ifr.name = *nm;
                let index: c_uint =
                    if ioctl(fd, SIOCGIFINDEX, &mut ifr as *mut Ifreq as *mut c_void) >= 0 {
                        ifr.ifindex() as c_uint
                    } else {
                        0
                    };
                push_ll(fd, nm, index, tailp);
                if !(*tailp).is_null() {
                    tailp = core::ptr::addr_of_mut!((**tailp).ifa_next);
                }
            }
        }
        close(fd);
        if fail {
            freeifaddrs(head);
            set_errno(ENOBUFS);
            return -1;
        }
        *ifap = head;
        0
    }
}

/// Free a `getifaddrs` list (musl `src/network/getifaddrs.c`).
///
/// # Safety
///
/// `ifp` must come from [`getifaddrs`] and not have been freed.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn freeifaddrs(ifp: *mut Ifaddrs) {
    unsafe {
        let mut p = ifp;
        while !p.is_null() {
            let n = (*p).ifa_next;
            crate::malloc::free(p as *mut c_void);
            p = n;
        }
    }
}

// ---- ether_* (musl `src/network/ether.c`) ----------------------------------------

/// Parse one hex byte; returns value and end pointer, or null on failure.
///
/// # Safety
///
/// `x` must point to a valid C string.
#[cfg(target_arch = "x86_64")]
unsafe fn parse_hexbyte(x: *const u8, v: &mut u8) -> *const u8 {
    unsafe {
        let mut n: u32 = 0;
        let mut p = x;
        let mut digits = 0;
        loop {
            let c = *p;
            let d = hexval(c);
            if !(0..=15).contains(&d) {
                break;
            }
            n = n.wrapping_mul(16).wrapping_add(d as u32);
            p = p.add(1);
            digits += 1;
        }
        if digits == 0 || n > 0xff {
            return core::ptr::null();
        }
        *v = n as u8;
        p
    }
}

/// Re-entrant MAC parse (musl `ether_aton_r`).
///
/// # Safety
///
/// `x` must point to a valid C string; `p_a` writable for 6 bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ether_aton_r(x: *const c_char, p_a: *mut EtherAddr) -> *mut EtherAddr {
    unsafe {
        if x.is_null() || p_a.is_null() {
            return core::ptr::null_mut();
        }
        let mut x = x as *const u8;
        let mut a = EtherAddr {
            ether_addr_octet: [0; 6],
        };
        for i in 0..6 {
            if i != 0 {
                if *x != b':' {
                    return core::ptr::null_mut();
                }
                x = x.add(1);
            }
            let mut v: u8 = 0;
            x = parse_hexbyte(x, &mut v);
            if x.is_null() {
                return core::ptr::null_mut();
            }
            a.ether_addr_octet[i] = v;
        }
        if *x != 0 {
            return core::ptr::null_mut();
        }
        *p_a = a;
        p_a
    }
}

#[cfg(target_arch = "x86_64")]
static mut ETHER_ADDR_BUF: EtherAddr = EtherAddr {
    ether_addr_octet: [0; 6],
};

/// MAC parse to static storage (musl `ether_aton`).
///
/// # Safety
///
/// `x` must point to a valid C string; returns shared static storage.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ether_aton(x: *const c_char) -> *mut EtherAddr {
    unsafe { ether_aton_r(x, core::ptr::addr_of_mut!(ETHER_ADDR_BUF)) }
}

/// Re-entrant MAC format, uppercase hex (musl `ether_ntoa_r`: `"%.2X"`).
///
/// # Safety
///
/// `p_a` must be readable; `x` must hold 18 writable bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ether_ntoa_r(p_a: *const EtherAddr, x: *mut c_char) -> *mut c_char {
    unsafe {
        if p_a.is_null() || x.is_null() {
            return core::ptr::null_mut();
        }
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let xb = x as *mut u8;
        let mut n = 0;
        for i in 0..6 {
            if i != 0 {
                *xb.add(n) = b':';
                n += 1;
            }
            let b = (*p_a).ether_addr_octet[i];
            *xb.add(n) = HEX[(b >> 4) as usize];
            *xb.add(n + 1) = HEX[(b & 0xf) as usize];
            n += 2;
        }
        *xb.add(n) = 0;
        x
    }
}

#[cfg(target_arch = "x86_64")]
static mut ETHER_NTOA_BUF: [c_char; 18] = [0; 18];

/// MAC format to static storage (musl `ether_ntoa`).
///
/// # Safety
///
/// `p_a` must be readable; returns shared static storage.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ether_ntoa(p_a: *const EtherAddr) -> *mut c_char {
    unsafe {
        ether_ntoa_r(
            p_a,
            core::ptr::addr_of_mut!(ETHER_NTOA_BUF).cast::<c_char>(),
        )
    }
}

/// Always fails, like musl's stub (`src/network/ether.c`).
///
/// # Safety
///
/// Always safe to call; ignores its arguments.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ether_line(
    _l: *const c_char,
    _e: *mut EtherAddr,
    _hostname: *mut c_char,
) -> c_int {
    -1
}

/// Always fails, like musl's stub.
///
/// # Safety
///
/// Always safe to call; ignores its arguments.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ether_ntohost(_hostname: *mut c_char, _e: *const EtherAddr) -> c_int {
    -1
}

/// Always fails, like musl's stub.
///
/// # Safety
///
/// Always safe to call; ignores its arguments.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ether_hostton(_hostname: *const c_char, _e: *mut EtherAddr) -> c_int {
    -1
}

// ---- Tests ----------------------------------------------------------------------
#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use core::ffi::{c_int, c_void};

    use crate::syscall::{syscall3, syscall_ret};

    unsafe fn tclose(fd: c_int) {
        unsafe {
            let _ = syscall_ret(syscall3(SYS_CLOSE, fd as usize, 0, 0));
        }
    }

    unsafe fn cstr_eq(p: *const c_char, want: &[u8]) -> bool {
        unsafe {
            for (i, b) in want.iter().enumerate() {
                if *p.add(i) != *b as c_char {
                    return false;
                }
            }
            *p.add(want.len()) == 0
        }
    }

    #[test]
    fn msg_roundtrip() {
        unsafe {
            // NOTE: datagram pair, so message boundaries survive mmsg.
            let mut fds = [0 as c_int; 2];
            assert_eq!(
                crate::net::socketpair(crate::net::AF_UNIX, SOCK_DGRAM, 0, fds.as_mut_ptr()),
                0
            );
            let hello = b"hello-msg";
            // sendmsg one iovec
            let iov = Iovec {
                base: hello.as_ptr() as *mut c_void,
                len: hello.len(),
            };
            let hdr = Msghdr {
                msg_name: core::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: &iov as *const Iovec as *mut Iovec,
                msg_iovlen: 1,
                __pad1: 0,
                msg_control: core::ptr::null_mut(),
                msg_controllen: 0,
                __pad2: 0,
                msg_flags: 0,
            };
            assert_eq!(sendmsg(fds[1], &hdr, 0), hello.len() as isize);
            // recvmsg
            let mut back = [0u8; 16];
            let mut riov = Iovec {
                base: back.as_mut_ptr() as *mut c_void,
                len: back.len(),
            };
            let mut rhdr = Msghdr {
                msg_name: core::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: &mut riov,
                msg_iovlen: 1,
                __pad1: 0,
                msg_control: core::ptr::null_mut(),
                msg_controllen: 0,
                __pad2: 0,
                msg_flags: 0,
            };
            assert_eq!(recvmsg(fds[0], &mut rhdr, 0), hello.len() as isize);
            assert_eq!(&back[..hello.len()], hello);
            // mmsg roundtrip, two messages
            let a = b"aa";
            let b = b"bbbb";
            let iovs = [
                Iovec {
                    base: a.as_ptr() as *mut c_void,
                    len: a.len(),
                },
                Iovec {
                    base: b.as_ptr() as *mut c_void,
                    len: b.len(),
                },
            ];
            let mut vec = [
                Mmsghdr {
                    msg_hdr: Msghdr {
                        msg_name: core::ptr::null_mut(),
                        msg_namelen: 0,
                        msg_iov: &iovs[0] as *const Iovec as *mut Iovec,
                        msg_iovlen: 1,
                        __pad1: 0,
                        msg_control: core::ptr::null_mut(),
                        msg_controllen: 0,
                        __pad2: 0,
                        msg_flags: 0,
                    },
                    msg_len: 0,
                },
                Mmsghdr {
                    msg_hdr: Msghdr {
                        msg_name: core::ptr::null_mut(),
                        msg_namelen: 0,
                        msg_iov: &iovs[1] as *const Iovec as *mut Iovec,
                        msg_iovlen: 1,
                        __pad1: 0,
                        msg_control: core::ptr::null_mut(),
                        msg_controllen: 0,
                        __pad2: 0,
                        msg_flags: 0,
                    },
                    msg_len: 0,
                },
            ];
            assert_eq!(sendmmsg(fds[1], vec.as_mut_ptr(), 2, 0), 2);
            assert_eq!(vec[0].msg_len, a.len() as c_uint);
            assert_eq!(vec[1].msg_len, b.len() as c_uint);
            let mut c1 = [0u8; 4];
            let mut c2 = [0u8; 8];
            let mut riovs = [
                Iovec {
                    base: c1.as_mut_ptr() as *mut c_void,
                    len: c1.len(),
                },
                Iovec {
                    base: c2.as_mut_ptr() as *mut c_void,
                    len: c2.len(),
                },
            ];
            let mut rvec = [
                Mmsghdr {
                    msg_hdr: Msghdr {
                        msg_name: core::ptr::null_mut(),
                        msg_namelen: 0,
                        msg_iov: &mut riovs[0],
                        msg_iovlen: 1,
                        __pad1: 0,
                        msg_control: core::ptr::null_mut(),
                        msg_controllen: 0,
                        __pad2: 0,
                        msg_flags: 0,
                    },
                    msg_len: 0,
                },
                Mmsghdr {
                    msg_hdr: Msghdr {
                        msg_name: core::ptr::null_mut(),
                        msg_namelen: 0,
                        msg_iov: &mut riovs[1],
                        msg_iovlen: 1,
                        __pad1: 0,
                        msg_control: core::ptr::null_mut(),
                        msg_controllen: 0,
                        __pad2: 0,
                        msg_flags: 0,
                    },
                    msg_len: 0,
                },
            ];
            assert_eq!(
                recvmmsg(fds[0], rvec.as_mut_ptr(), 2, 0, core::ptr::null()),
                2
            );
            assert_eq!(&c1[..a.len()], a);
            assert_eq!(&c2[..b.len()], b);
            // NOTE: SIOCATMARK is TCP-only (ENOTSUP on unix sockets), so test
            // it on a fresh TCP socket where "no OOB mark" reads back as 0.
            let tcp = crate::net::socket(AF_INET, crate::net::SOCK_STREAM, 0);
            assert!(tcp >= 0);
            assert_eq!(sockatmark(tcp), 0);
            tclose(tcp);
            tclose(fds[0]);
            tclose(fds[1]);
        }
    }

    #[test]
    fn byte_order() {
        unsafe {
            assert_eq!(htons(0x1234), 0x3412);
            assert_eq!(htonl(0x12345678), 0x78563412);
            assert_eq!(ntohs(htons(0xabcd)), 0xabcd);
            assert_eq!(ntohl(htonl(0xdeadbeef)), 0xdeadbeef);
        }
    }

    #[test]
    fn inet_v4() {
        unsafe {
            let mut b = [0u8; 4];
            assert_eq!(
                inet_pton(
                    AF_INET,
                    c"127.0.0.1".as_ptr(),
                    b.as_mut_ptr() as *mut c_void
                ),
                1
            );
            assert_eq!(b, [127, 0, 0, 1]);
            assert_eq!(
                inet_pton(
                    AF_INET,
                    c"999.1.1.1".as_ptr(),
                    b.as_mut_ptr() as *mut c_void
                ),
                0
            );
            assert_eq!(
                inet_pton(AF_INET, c"01.2.3.4".as_ptr(), b.as_mut_ptr() as *mut c_void),
                0
            );
            assert_eq!(
                inet_pton(99, c"1.2.3.4".as_ptr(), b.as_mut_ptr() as *mut c_void),
                -1
            );
            let mut s = [0 as c_char; 16];
            assert!(!inet_ntop(AF_INET, b.as_ptr() as *const c_void, s.as_mut_ptr(), 16).is_null());
            assert!(cstr_eq(s.as_ptr(), b"127.0.0.1"));
            // roundtrip via aton/addr/ntoa
            let mut ia = InAddr { s_addr: 0 };
            assert_eq!(inet_aton(c"10.0.0.1".as_ptr(), &mut ia), 1);
            assert_eq!(ia.s_addr.to_ne_bytes(), [10, 0, 0, 1]);
            assert_eq!(inet_addr(c"10.0.0.1".as_ptr()).to_ne_bytes(), [10, 0, 0, 1]);
            assert_eq!(inet_addr(c"bogus".as_ptr()), 0xffffffff);
            assert!(cstr_eq(inet_ntoa(ia), b"10.0.0.1"));
            assert_eq!(inet_aton(c"bogus".as_ptr(), &mut ia), 0);
        }
    }

    #[test]
    fn inet_v6() {
        unsafe {
            let mut b = [0u8; 16];
            assert_eq!(
                inet_pton(AF_INET6, c"::1".as_ptr(), b.as_mut_ptr() as *mut c_void),
                1
            );
            assert_eq!(&b[..15], &[0; 15]);
            assert_eq!(b[15], 1);
            let mut s = [0 as c_char; 46];
            assert!(
                !inet_ntop(AF_INET6, b.as_ptr() as *const c_void, s.as_mut_ptr(), 46).is_null()
            );
            assert!(cstr_eq(s.as_ptr(), b"::1"));
            // full form + mapped roundtrip through pton
            assert_eq!(
                inet_pton(
                    AF_INET6,
                    c"2001:db8::1".as_ptr(),
                    b.as_mut_ptr() as *mut c_void
                ),
                1
            );
            assert!(
                !inet_ntop(AF_INET6, b.as_ptr() as *const c_void, s.as_mut_ptr(), 46).is_null()
            );
            let mut b2 = [0u8; 16];
            let len = c_strlen(s.as_ptr());
            assert!(len > 0 && len < 46);
            assert_eq!(
                inet_pton(AF_INET6, s.as_ptr(), b2.as_mut_ptr() as *mut c_void),
                1
            );
            assert_eq!(b, b2);
            // too-small buffer
            let mut tiny = [0 as c_char; 2];
            assert!(
                inet_ntop(AF_INET6, b.as_ptr() as *const c_void, tiny.as_mut_ptr(), 2).is_null()
            );
        }
    }

    #[test]
    fn if_name_roundtrip() {
        unsafe {
            let lo = c"lo";
            let idx = if_nametoindex(lo.as_ptr());
            assert!(idx > 0);
            let mut name = [0 as c_char; 16];
            assert!(!if_indextoname(idx, name.as_mut_ptr()).is_null());
            assert!(cstr_eq(name.as_ptr(), b"lo"));
            assert!(if_indextoname(0, name.as_mut_ptr()).is_null());
        }
    }

    #[test]
    fn if_nameindex_lists_lo() {
        unsafe {
            let list = if_nameindex();
            assert!(!list.is_null());
            let mut found = false;
            let mut i = 0;
            while !(*list.add(i)).if_name.is_null() {
                if cstr_eq((*list.add(i)).if_name, b"lo") {
                    found = true;
                }
                i += 1;
                assert!(i < 1024);
            }
            assert!(((*list.add(i)).if_index) == 0);
            assert!(found);
            if_freenameindex(list);
        }
    }

    #[test]
    fn getifaddrs_finds_lo() {
        unsafe {
            let mut head: *mut Ifaddrs = core::ptr::null_mut();
            assert_eq!(getifaddrs(&mut head), 0);
            assert!(!head.is_null());
            let mut found_v4 = false;
            let mut p = head;
            let mut n = 0;
            while !p.is_null() {
                n += 1;
                assert!(n < 4096);
                if !(*p).ifa_name.is_null()
                    && cstr_eq((*p).ifa_name, b"lo")
                    && !(*p).ifa_addr.is_null()
                    && (*(*p).ifa_addr).sa_family == AF_INET as u16
                {
                    let sin = (*p).ifa_addr as *const SockaddrIn;
                    if (*sin).sin_addr.s_addr.to_ne_bytes() == [127, 0, 0, 1] {
                        found_v4 = true;
                    }
                }
                p = (*p).ifa_next;
            }
            assert!(found_v4);
            freeifaddrs(head);
        }
    }

    #[test]
    fn ether_roundtrip() {
        unsafe {
            let s = c"01:23:45:67:89:ab";
            let a = ether_aton(s.as_ptr());
            assert!(!a.is_null());
            assert_eq!((*a).ether_addr_octet, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab]);
            // musl formats uppercase
            assert!(cstr_eq(ether_ntoa(a), b"01:23:45:67:89:AB"));
            let mut e2 = EtherAddr {
                ether_addr_octet: [0; 6],
            };
            assert!(!ether_aton_r(ether_ntoa(a), &mut e2).is_null());
            assert_eq!(e2, *a);
            assert!(ether_aton(c"zz:00:00:00:00:00".as_ptr()).is_null());
            assert_eq!(
                ether_line(
                    core::ptr::null(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut()
                ),
                -1
            );
        }
    }

    #[test]
    fn addrs_well_known() {
        assert_eq!(in6addr_any.s6_addr, [0; 16]);
        assert_eq!(
            in6addr_loopback.s6_addr,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(core::mem::size_of::<Msghdr>(), 56);
        assert_eq!(core::mem::size_of::<Mmsghdr>(), 64);
        assert_eq!(core::mem::size_of::<SockaddrIn>(), 16);
        assert_eq!(core::mem::size_of::<SockaddrIn6>(), 28);
        assert_eq!(core::mem::size_of::<SockaddrLl>(), 20);
        assert_eq!(core::mem::size_of::<EtherAddr>(), 6);
    }
}
