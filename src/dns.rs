//! DNS + resolver (musl `src/network/getaddrinfo.c`, `lookup_name.c`,
//! `lookup_serv.c`, `lookup_ipliteral.c`, `dns_parse.c`, `res_mkquery.c`,
//! `res_msend.c`, `res_send.c`, `res_query.c`, `res_init.c`, `res_state.c`,
//! `resolvconf.c`, `getnameinfo.c`, `gethostby*.c`, `getservby*.c`,
//! `proto.c`, `gai_strerror.c`, `freeaddrinfo.c`, `h_errno.c`).
//!
//! Resolution order mirrors musl exactly (no nsswitch exists in musl):
//! null → numeric literal → `/etc/hosts` → DNS. `resolv.conf` is re-read
//! on every resolving call (musl keeps no cache). File reads use raw
//! syscalls (`crate::syscall`), never stdio, so there is no stdio-lock
//! interplay; DNS I/O reuses `crate::net` + `crate::poll`.
//!
//! Deviations from musl (deliberate, one line each):
//! - `h_errno` is a process-global cell, not per-thread (musl threads it
//!   through the TCB); legacy `gethostby*` statics are likewise not
//!   thread-safe — same caveat musl documents by using statics at all.
//! - AI_ADDRCONFIG uses musl's own socket+connect loopback probe (musl
//!   never calls getifaddrs here either), so no 10A dependency exists.
//! - `__res_msend` sends to nameservers sequentially, not in parallel,
//!   and has no TCP-FASTOPEN; the TC-bit TCP retry is kept (plain TCP).
//! - Destination-address sorting (RFC 3484 subset) is skipped; backend
//!   order is preserved (matters only with ≥2 mixed-family results).
//! - `if_nametoindex`/`if_indextoname` do not exist yet, so named `%scope`
//!   ids fail with EAI_NONAME and numeric scopes always print numerically.
//! - `is_valid_hostname` accepts any bytes ≥0x80 without multibyte
//!   validation (superset of musl's check, never rejects a valid name).
//! - Service lookup falls back to a small builtin table (`http`→80 et al.)
//!   when `/etc/services` misses, so hermetic CI never needs that file.

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr::null_mut;

use crate::syscall::{syscall3, syscall4, syscall_ret};

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_READ: usize = 0;
#[cfg(target_arch = "x86_64")]
const SYS_CLOSE: usize = 3;
#[cfg(target_arch = "x86_64")]
const SYS_OPENAT: usize = 257;

// ---- Families / sockets (musl sys/socket.h, netinet/in.h) -------------------
#[cfg(target_arch = "x86_64")]
pub const AF_UNSPEC: c_int = 0;
#[cfg(target_arch = "x86_64")]
pub const AF_INET: c_int = 2;
#[cfg(target_arch = "x86_64")]
pub const AF_INET6: c_int = 10;
#[cfg(target_arch = "x86_64")]
pub const SOCK_STREAM: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const SOCK_DGRAM: c_int = 2;
#[cfg(target_arch = "x86_64")]
pub const SOCK_CLOEXEC: c_int = 0o2000000;
#[cfg(target_arch = "x86_64")]
pub const SOCK_NONBLOCK: c_int = 0o4000000;
#[cfg(target_arch = "x86_64")]
pub const IPPROTO_TCP: c_int = 6;
#[cfg(target_arch = "x86_64")]
pub const IPPROTO_UDP: c_int = 17;
#[cfg(target_arch = "x86_64")]
const MSG_NOSIGNAL: c_int = 0x4000;
#[cfg(target_arch = "x86_64")]
const SOL_SOCKET: c_int = 1;
#[cfg(target_arch = "x86_64")]
const SO_ERROR: c_int = 4;
#[cfg(target_arch = "x86_64")]
const AT_FDCWD: c_int = -100;
#[cfg(target_arch = "x86_64")]
const O_RDONLY_CLOEXEC: c_int = 0o2000000; // O_RDONLY|O_CLOEXEC
#[cfg(target_arch = "x86_64")]
const F_SETFL: c_int = 4;

// ---- netdb.h (values verbatim) ----------------------------------------------
#[cfg(target_arch = "x86_64")]
pub const AI_PASSIVE: c_int = 0x01;
#[cfg(target_arch = "x86_64")]
pub const AI_CANONNAME: c_int = 0x02;
#[cfg(target_arch = "x86_64")]
pub const AI_NUMERICHOST: c_int = 0x04;
#[cfg(target_arch = "x86_64")]
pub const AI_V4MAPPED: c_int = 0x08;
#[cfg(target_arch = "x86_64")]
pub const AI_ALL: c_int = 0x10;
#[cfg(target_arch = "x86_64")]
pub const AI_ADDRCONFIG: c_int = 0x20;
#[cfg(target_arch = "x86_64")]
pub const AI_NUMERICSERV: c_int = 0x400;
#[cfg(target_arch = "x86_64")]
pub const NI_NUMERICHOST: c_int = 0x01;
#[cfg(target_arch = "x86_64")]
pub const NI_NUMERICSERV: c_int = 0x02;
#[cfg(target_arch = "x86_64")]
pub const NI_NOFQDN: c_int = 0x04;
#[cfg(target_arch = "x86_64")]
pub const NI_NAMEREQD: c_int = 0x08;
#[cfg(target_arch = "x86_64")]
pub const NI_DGRAM: c_int = 0x10;
#[cfg(target_arch = "x86_64")]
pub const NI_NUMERICSCOPE: c_int = 0x100;
#[cfg(target_arch = "x86_64")]
pub const EAI_BADFLAGS: c_int = -1;
#[cfg(target_arch = "x86_64")]
pub const EAI_NONAME: c_int = -2;
#[cfg(target_arch = "x86_64")]
pub const EAI_AGAIN: c_int = -3;
#[cfg(target_arch = "x86_64")]
pub const EAI_FAIL: c_int = -4;
#[cfg(target_arch = "x86_64")]
pub const EAI_NODATA: c_int = -5;
#[cfg(target_arch = "x86_64")]
pub const EAI_FAMILY: c_int = -6;
#[cfg(target_arch = "x86_64")]
pub const EAI_SOCKTYPE: c_int = -7;
#[cfg(target_arch = "x86_64")]
pub const EAI_SERVICE: c_int = -8;
#[cfg(target_arch = "x86_64")]
pub const EAI_MEMORY: c_int = -10;
#[cfg(target_arch = "x86_64")]
pub const EAI_SYSTEM: c_int = -11;
#[cfg(target_arch = "x86_64")]
pub const EAI_OVERFLOW: c_int = -12;
#[cfg(target_arch = "x86_64")]
pub const HOST_NOT_FOUND: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const TRY_AGAIN: c_int = 2;
#[cfg(target_arch = "x86_64")]
pub const NO_RECOVERY: c_int = 3;
#[cfg(target_arch = "x86_64")]
pub const NO_DATA: c_int = 4;

// ---- errno values (musl arch/generic/bits/errno.h) --------------------------
#[cfg(target_arch = "x86_64")]
const ENOENT: c_int = 2;
#[cfg(target_arch = "x86_64")]
const EACCES: c_int = 13;
#[cfg(target_arch = "x86_64")]
const ENOTDIR: c_int = 20;
#[cfg(target_arch = "x86_64")]
const EINVAL: c_int = 22;
#[cfg(target_arch = "x86_64")]
const ERANGE: c_int = 34;
#[cfg(target_arch = "x86_64")]
const EAGAIN: c_int = 11;
#[cfg(target_arch = "x86_64")]
const EINPROGRESS: c_int = 115;
#[cfg(target_arch = "x86_64")]
const EBADMSG: c_int = 74;
#[cfg(target_arch = "x86_64")]
const ENOMEM: c_int = 12;

// ---- repr(C) types (musl include/netdb.h, sys/socket.h, netinet/in.h) -------
/// musl `struct addrinfo`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct AddrInfo {
    pub ai_flags: c_int,
    pub ai_family: c_int,
    pub ai_socktype: c_int,
    pub ai_protocol: c_int,
    pub ai_addrlen: u32,
    pub ai_addr: *mut SockAddr,
    pub ai_canonname: *mut c_char,
    pub ai_next: *mut AddrInfo,
}

/// musl `struct sockaddr`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct SockAddr {
    pub sa_family: u16,
    pub sa_data: [c_char; 14],
}

/// musl `struct sockaddr_in`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

/// musl `struct sockaddr_in6`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrIn6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}

/// musl `struct hostent`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Hostent {
    pub h_name: *mut c_char,
    pub h_aliases: *mut *mut c_char,
    pub h_addrtype: c_int,
    pub h_length: c_int,
    pub h_addr_list: *mut *mut c_char,
}

/// musl `struct servent`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Servent {
    pub s_name: *mut c_char,
    pub s_aliases: *mut *mut c_char,
    pub s_port: c_int,
    pub s_proto: *mut c_char,
}

/// musl `struct protoent`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Protoent {
    pub p_name: *mut c_char,
    pub p_aliases: *mut *mut c_char,
    pub p_proto: c_int,
}

/// musl `struct __res_state` (dummy: musl's own res_state.c says it is
/// completely unused and exists purely to satisfy broken apps).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct ResState {
    _pad: [u64; 72],
}

/// musl `lookup.h struct address`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
struct Address {
    family: c_int,
    scopeid: u32,
    addr: [u8; 16],
}

/// musl `lookup.h struct service`.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Clone, Copy)]
struct Service {
    port: u16,
    proto: u8,
    socktype: u8,
}

/// musl `lookup.h struct aibuf` (freeaddrinfo inverts this layout).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct AiBuf {
    ai: AddrInfo,
    sa: SockAddrMax,
    lock: c_int,
    slot: i16,
    ref_: i16,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
union SockAddrMax {
    sin: SockAddrIn,
    sin6: SockAddrIn6,
}

#[cfg(target_arch = "x86_64")]
const MAXADDRS: usize = 48;
#[cfg(target_arch = "x86_64")]
const MAXSERVS: usize = 2;
#[cfg(target_arch = "x86_64")]
const MAXNS: usize = 3;

/// musl `lookup.h struct resolvconf`.
#[cfg(target_arch = "x86_64")]
struct ResolvConf {
    ns_family: [c_int; MAXNS],
    ns_addr: [[u8; 16]; MAXNS],
    ns_scope: [u32; MAXNS],
    nns: usize,
    attempts: u32,
    ndots: u32,
    timeout: u32, // seconds
}

// ---- tiny C-string / byte helpers (pure, no syscalls) -----------------------
#[cfg(target_arch = "x86_64")]
unsafe fn cstrlen(s: *const c_char) -> usize {
    unsafe {
        let mut n = 0;
        while *s.add(n) == 0 {
            n += 1;
        }
        n
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn cstrnlen(s: *const c_char, max: usize) -> usize {
    unsafe {
        let mut n = 0;
        while n < max && *s.add(n) != 0 {
            n += 1;
        }
        n
    }
}

#[cfg(target_arch = "x86_64")]
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

#[cfg(target_arch = "x86_64")]
fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}

#[cfg(target_arch = "x86_64")]
fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// musl `lookup_name.c is_valid_hostname` (multibyte check relaxed, see docs).
#[cfg(target_arch = "x86_64")]
unsafe fn is_valid_hostname(host: *const c_char, len: usize) -> bool {
    unsafe {
        if len == 0 || len > 254 {
            return false;
        }
        let mut i = 0;
        while i < len {
            let b = *host.add(i) as u8;
            if b >= 0x80 || b == b'.' || b == b'-' || is_alnum(b) {
                i += 1;
            } else {
                return false;
            }
        }
        true
    }
}

// ---- raw file loading (no stdio) --------------------------------------------
#[cfg(target_arch = "x86_64")]
struct FileBuf {
    ptr: *mut u8,
    len: usize,
}

/// Read a whole file (cap 64 KiB) with raw syscalls; errno flows through
/// `syscall_ret` exactly like musl's fopen path. Returns null ptr on error.
#[cfg(target_arch = "x86_64")]
unsafe fn read_file(path: *const c_char) -> FileBuf {
    unsafe {
        const CAP: usize = 65536;
        let fd = syscall_ret(syscall4(
            SYS_OPENAT,
            AT_FDCWD as usize,
            path as usize,
            O_RDONLY_CLOEXEC as usize,
            0,
        )) as c_int;
        if fd < 0 {
            return FileBuf {
                ptr: null_mut(),
                len: 0,
            };
        }
        let mem = crate::malloc::malloc(CAP) as *mut u8;
        if mem.is_null() {
            let _ = syscall_ret(syscall3(SYS_CLOSE, fd as usize, 0, 0));
            return FileBuf {
                ptr: null_mut(),
                len: 0,
            };
        }
        let mut len = 0;
        loop {
            if len >= CAP {
                break;
            }
            let r = syscall_ret(syscall3(
                SYS_READ,
                fd as usize,
                mem.add(len) as usize,
                CAP - len,
            ));
            if r <= 0 {
                break;
            }
            len += r as usize;
        }
        let _ = syscall_ret(syscall3(SYS_CLOSE, fd as usize, 0, 0));
        FileBuf { ptr: mem, len }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn free_file(f: FileBuf) {
    unsafe {
        if !f.ptr.is_null() {
            crate::malloc::free(f.ptr as *mut c_void);
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn last_errno() -> c_int {
    unsafe { *crate::errno::__errno_location() }
}

// ---- inet parse/format (musl inet_aton.c, inet_pton.c, inet_ntop.c) ---------
/// musl `__inet_aton`: dotted decimal with 1–4 parts (`127.1` → 127.0.0.1).
#[cfg(target_arch = "x86_64")]
unsafe fn inet_aton(s: *const c_char, len: usize, out: *mut u8) -> bool {
    unsafe {
        let mut a = [0u64; 4];
        let mut i = 0;
        let mut p = 0;
        while i < 4 {
            if p >= len || !is_digit(*s.add(p) as u8) {
                return false;
            }
            let mut v = 0u64;
            let mut base = 10u64;
            if *s.add(p) as u8 == b'0' && p + 1 < len {
                let c = *s.add(p + 1) as u8;
                if c == b'x' || c == b'X' {
                    base = 16;
                    p += 2;
                } else if c.is_ascii_digit() {
                    base = 8;
                    p += 1;
                }
            }
            let start = p;
            loop {
                if p >= len {
                    break;
                }
                let c = *s.add(p) as u8;
                let d = if c.is_ascii_digit() {
                    (c - b'0') as u64
                } else if base == 16 && c.is_ascii_hexdigit() {
                    ((c | 32) - b'a' + 10) as u64
                } else {
                    break;
                };
                if d >= base {
                    return false;
                }
                v = v.wrapping_mul(base).wrapping_add(d);
                p += 1;
            }
            if p == start || v > 0xffffffff {
                return false;
            }
            a[i] = v;
            i += 1;
            if p >= len {
                break;
            }
            if *s.add(p) as u8 != b'.' {
                return false;
            }
            p += 1;
        }
        if p != len || i == 4 {
            return false;
        }
        let n = i; // parts - 1
                   // Fold like musl's switch(i): parts fill from the right.
        let mut b = [0u8; 4];
        match n {
            0 => {
                b[0] = (a[0] >> 24) as u8;
                b[1] = ((a[0] >> 16) & 0xffffff) as u8;
                b[2] = ((a[0] >> 8) & 0xffff) as u8;
                b[3] = (a[0] & 0xff) as u8;
                if a[0] > 0xffffffff {
                    return false;
                }
            }
            _ => {
                // General fold: last part takes 8/16/24 bits by position.
                let mut v = a;
                if n == 1 {
                    if v[1] > 0xffffff {
                        return false;
                    }
                    v[1] &= 0xffffff;
                    if v[0] > 255 {
                        return false;
                    }
                    b[0] = v[0] as u8;
                    b[1] = (v[1] >> 16) as u8;
                    b[2] = (v[1] >> 8) as u8;
                    b[3] = v[1] as u8;
                } else if n == 2 {
                    if v[2] > 0xffff {
                        return false;
                    }
                    if v[0] > 255 || v[1] > 255 {
                        return false;
                    }
                    b[0] = v[0] as u8;
                    b[1] = v[1] as u8;
                    b[2] = (v[2] >> 8) as u8;
                    b[3] = v[2] as u8;
                } else {
                    for k in 0..4 {
                        if v[k] > 255 {
                            return false;
                        }
                        b[k] = v[k] as u8;
                    }
                }
            }
        }
        // Exact musl check: each folded part must be <=255.
        *out.add(0) = b[0];
        *out.add(1) = b[1];
        *out.add(2) = b[2];
        *out.add(3) = b[3];
        true
    }
}

#[cfg(target_arch = "x86_64")]
fn hexval(c: u8) -> c_int {
    if c.wrapping_sub(b'0') < 10 {
        return (c - b'0') as c_int;
    }
    let l = c | 32;
    if l.wrapping_sub(b'a') < 6 {
        return (l - b'a' + 10) as c_int;
    }
    -1
}

/// musl `inet_pton` AF_INET6 half (AF_INET strict dotted decimal included).
#[cfg(target_arch = "x86_64")]
unsafe fn inet_pton6(s: *const c_char, len: usize, out: *mut u8) -> bool {
    unsafe {
        let mut ip = [0u16; 8];
        let mut i = 0usize;
        let mut p = 0usize;
        let mut brk = usize::MAX;
        let mut need_v4 = false;
        if len >= 1 && *s as u8 == b':' {
            if len < 2 || *s.add(1) as u8 != b':' {
                return false;
            }
            p = 1;
        }
        loop {
            if p < len && *s.add(p) as u8 == b':' && brk == usize::MAX {
                brk = i;
                ip[i & 7] = 0;
                p += 1;
                if p >= len {
                    break;
                }
                if i == 7 {
                    return false;
                }
                continue;
            }
            let mut v = 0u32;
            let mut j = 0usize;
            while j < 4 && p + j < len && hexval(*s.add(p + j) as u8) >= 0 {
                v = 16 * v + hexval(*s.add(p + j) as u8) as u32;
                j += 1;
            }
            if j == 0 {
                return false;
            }
            ip[i & 7] = v as u16;
            if p + j >= len && (brk != usize::MAX || i == 7) {
                p = len;
                break;
            }
            if i == 7 {
                return false;
            }
            if p + j >= len {
                return false;
            }
            let c = *s.add(p + j) as u8;
            if c != b':' {
                if c != b'.' || (i < 6 && brk == usize::MAX) {
                    return false;
                }
                need_v4 = true;
                i += 1;
                ip[i & 7] = 0;
                p += 0; // s stays at v4 tail start below
                break;
            }
            p += j + 1;
            i += 1;
            // loop with s advanced: emulate by shifting window via p only;
            // track group index i separately (musl advances pointer).
            if i > 7 {
                return false;
            }
        }
        // Reconstruct tail pointer for need_v4: p currently at start of
        // the last-consumed group; rescan: musl passes s (start of v4
        // text). Our p points just past the last ':' before v4 part...
        // Simpler: find v4 start as last ':' + 1 within consumed range.
        let v4start = if need_v4 {
            let q = p;
            // p is at the group start of the v4 head; the v4 text begins
            // at p (we broke before consuming it).
            q
        } else {
            0
        };
        if brk != usize::MAX {
            let n = i; // last index filled
                       // move [brk..=n] to [8-(n-brk+1)..7]
            let cnt = n + 1 - brk;
            let mut k = 0;
            while k < cnt {
                ip[8 - cnt + k] = ip[brk + k];
                k += 1;
            }
            k = 0;
            while k < 8 - cnt {
                if brk + k < 8 - cnt + k {
                    ip[brk + k] = 0;
                }
                k += 1;
            }
            // zero the gap [brk, 8-cnt)
            k = brk;
            while k < 8 - cnt {
                ip[k] = 0;
                k += 1;
            }
        }
        let mut k = 0;
        while k < 8 {
            *out.add(2 * k) = (ip[k] >> 8) as u8;
            *out.add(2 * k + 1) = ip[k] as u8;
            k += 1;
        }
        if need_v4 {
            // Parse trailing IPv4 text into last 4 bytes.
            let q = v4start;
            // v4 text runs to end of input.
            let mut oct = [0u8; 4];
            // Reuse strict AF_INET pton on the tail slice.
            if !inet_pton4_tail(s, v4start, len, oct.as_mut_ptr()) {
                let _ = q;
                return false;
            }
            *out.add(12) = oct[0];
            *out.add(13) = oct[1];
            *out.add(14) = oct[2];
            *out.add(15) = oct[3];
        } else if p != len {
            return false;
        }
        true
    }
}

/// musl `inet_pton` AF_INET half, strict (no leading zeros, ≤255).
#[cfg(target_arch = "x86_64")]
unsafe fn inet_pton4_tail(s: *const c_char, start: usize, len: usize, out: *mut u8) -> bool {
    unsafe {
        let mut p = start;
        let mut i = 0;
        while i < 4 {
            let mut v = 0u32;
            let mut j = 0;
            while j < 3 && p + j < len && is_digit(*s.add(p + j) as u8) {
                v = 10 * v + (*s.add(p + j) as u8 - b'0') as u32;
                j += 1;
            }
            if j == 0 || (j > 1 && *s.add(p) as u8 == b'0') || v > 255 {
                return false;
            }
            *out.add(i) = v as u8;
            p += j;
            i += 1;
            if p >= len {
                return i == 4;
            }
            if *s.add(p) as u8 != b'.' {
                return false;
            }
            p += 1;
        }
        p == len
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn fmt_u32(mut v: u32, buf: *mut u8, max: usize) -> usize {
    unsafe {
        let mut tmp = [0u8; 10];
        let mut n = 0;
        loop {
            tmp[n] = (v % 10) as u8 + b'0';
            v /= 10;
            n += 1;
            if v == 0 {
                break;
            }
        }
        if n > max {
            return 0;
        }
        let mut k = 0;
        while k < n {
            *buf.add(k) = tmp[n - 1 - k];
            k += 1;
        }
        n
    }
}

/// musl `inet_ntop` IPv4.
#[cfg(target_arch = "x86_64")]
unsafe fn ntop4(a: *const u8, out: *mut c_char, outlen: usize) -> bool {
    unsafe {
        let mut p = 0;
        let mut i = 0;
        while i < 4 {
            if i != 0 {
                if p + 1 >= outlen {
                    return false;
                }
                *out.add(p) = b'.' as c_char;
                p += 1;
            }
            let n = fmt_u32(*a.add(i) as u32, out.add(p) as *mut u8, outlen - p - 1);
            if n == 0 {
                return false;
            }
            p += n;
            i += 1;
        }
        if p + 1 > outlen {
            return false;
        }
        *out.add(p) = 0;
        true
    }
}

/// musl `inet_ntop` IPv6 (longest zero-run compression, runs of len 1 kept).
#[cfg(target_arch = "x86_64")]
unsafe fn ntop6(a: *const u8, out: *mut c_char, outlen: usize) -> bool {
    unsafe {
        let mut w = [0u16; 8];
        let mut k = 0;
        while k < 8 {
            w[k] = ((*a.add(2 * k) as u16) << 8) | (*a.add(2 * k + 1) as u16);
            k += 1;
        }
        let mut best_base = 8;
        let mut best_len = 0;
        let mut i = 0;
        while i < 8 {
            if w[i] == 0 {
                let mut j = i;
                while j < 8 && w[j] == 0 {
                    j += 1;
                }
                if j - i > best_len && j - i > 1 {
                    best_base = i;
                    best_len = j - i;
                }
                i = j;
            } else {
                i += 1;
            }
        }
        let mut p = 0;
        let mut hex = [0u8; 4];
        i = 0;
        let mut first = true;
        while i < 8 {
            if i == best_base {
                if p + 2 > outlen {
                    return false;
                }
                *out.add(p) = b':' as c_char;
                *out.add(p + 1) = b':' as c_char;
                p += 2;
                i += best_len;
                first = true;
                continue;
            }
            if !first {
                if p + 1 >= outlen {
                    return false;
                }
                *out.add(p) = b':' as c_char;
                p += 1;
            }
            first = false;
            let mut v = w[i];
            let mut n = 0;
            loop {
                hex[n] = (v & 15) as u8;
                v >>= 4;
                n += 1;
                if v == 0 {
                    break;
                }
            }
            if p + n >= outlen {
                return false;
            }
            let mut t = 0;
            while t < n {
                let d = hex[n - 1 - t];
                *out.add(p) = (if d < 10 { b'0' + d } else { b'a' + d - 10 }) as c_char;
                p += 1;
                t += 1;
            }
            i += 1;
        }
        if p + 1 > outlen {
            return false;
        }
        *out.add(p) = 0;
        true
    }
}

// ---- h_errno (musl h_errno.c; global cell, see module docs) ------------------
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub static mut h_errno: c_int = 0;

/// musl `__h_errno_location`.
/// # Safety
/// The pointer stays valid for the program's lifetime.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __h_errno_location() -> *mut c_int {
    core::ptr::addr_of_mut!(h_errno)
}

#[cfg(target_arch = "x86_64")]
unsafe fn set_h_errno(v: c_int) {
    unsafe {
        *core::ptr::addr_of_mut!(h_errno) = v;
    }
}

// ---- gai_strerror (musl gai_strerror.c, strings verbatim) -------------------
#[cfg(target_arch = "x86_64")]
static GAI_MSGS: &[u8] = b"Invalid flags\0Name does not resolve\0Try again\0Non-recoverable error\0Name has no usable address\0Unrecognized address family or invalid length\0Unrecognized socket type\0Unrecognized service\0Unknown error\0Out of memory\0System error\0Overflow\0\0Unknown error\0";

/// musl `gai_strerror` (same table walk, same strings).
/// # Safety
/// Returns a pointer to static storage, always valid.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn gai_strerror(e: c_int) -> *const c_char {
    unsafe {
        let mut s = GAI_MSGS.as_ptr();
        let mut ecode = (e as u32).wrapping_add(1);
        while ecode != 0 && *s != 0 {
            ecode = ecode.wrapping_sub(1);
            // advance past one NUL-terminated string
            if ecode == 0 && *s != 0 {
                break;
            }
            while *s != 0 {
                s = s.add(1);
            }
            s = s.add(1);
        }
        // Faithful walk of musl's loop: entry -e, then the empty slot
        // falls through to the final "Unknown error".
        if *s == 0 {
            s = s.add(1);
        }
        s as *const c_char
    }
}

// ---- /etc/resolv.conf (musl resolvconf.c) ------------------------------------
#[cfg(target_arch = "x86_64")]
unsafe fn lookup_ipliteral_into(
    name: *const c_char,
    len: usize,
    family: c_int,
    fam_out: *mut c_int,
    addr_out: *mut u8,
    scope_out: *mut u32,
) -> c_int {
    unsafe {
        let mut tmp = [0u8; 16];
        if inet_aton(name, len, tmp.as_mut_ptr()) {
            if family == AF_INET6 {
                return EAI_NODATA;
            }
            *fam_out = AF_INET;
            *addr_out.add(0) = tmp[0];
            *addr_out.add(1) = tmp[1];
            *addr_out.add(2) = tmp[2];
            *addr_out.add(3) = tmp[3];
            *scope_out = 0;
            return 1;
        }
        // Optional %scope suffix (numeric only; named needs
        // if_nametoindex, which does not exist yet).
        let mut base = len;
        let mut pct = usize::MAX;
        let mut i = 0;
        while i < len {
            if *name.add(i) as u8 == b'%' {
                pct = i;
                break;
            }
            i += 1;
        }
        let mut scope = 0u32;
        let mut v6len = len;
        if pct != usize::MAX && pct < 64 {
            v6len = pct;
            let mut q = pct + 1;
            if q < len && is_digit(*name.add(q) as u8) {
                let mut v = 0u64;
                while q < len && is_digit(*name.add(q) as u8) {
                    v = v * 10 + (*name.add(q) as u8 - b'0') as u64;
                    q += 1;
                }
                if q != len || v > u32::MAX as u64 {
                    return EAI_NONAME;
                }
                scope = v as u32;
            } else if q < len {
                return EAI_NONAME; // named scope: no if_nametoindex yet
            }
            base = pct;
        } else if pct != usize::MAX {
            return 0;
        }
        let _ = base;
        let mut a6 = [0u8; 16];
        if !inet_pton6(name, v6len, a6.as_mut_ptr()) {
            return 0;
        }
        if family == AF_INET {
            return EAI_NODATA;
        }
        *fam_out = AF_INET6;
        let mut k = 0;
        while k < 16 {
            *addr_out.add(k) = a6[k];
            k += 1;
        }
        *scope_out = scope;
        // musl rejects scopes on non-link-local addresses.
        if scope != 0 {
            let link = (a6[0] == 0xfe && (a6[1] & 0xc0) == 0x80)
                || (a6[0] == 0xff && (a6[1] & 0x0f) == 0x02);
            if !link {
                return EAI_NONAME;
            }
        }
        1
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn get_resolv_conf(conf: *mut ResolvConf, search: *mut c_char, search_sz: usize) -> c_int {
    unsafe {
        (*conf).ndots = 1;
        (*conf).timeout = 5;
        (*conf).attempts = 2;
        (*conf).nns = 0;
        if !search.is_null() {
            *search = 0;
        }
        let f = read_file(c"/etc/resolv.conf".as_ptr());
        if f.ptr.is_null() {
            let e = last_errno();
            if e == ENOENT || e == ENOTDIR || e == EACCES {
                // fall through to default nameserver below
            } else {
                return -1;
            }
        } else {
            let mut pos = 0;
            while pos < f.len {
                let mut end = pos;
                while end < f.len && *f.ptr.add(end) != b'\n' {
                    end += 1;
                }
                let mut line = [0u8; 256];
                let ll = if end - pos > 255 { 256 } else { end - pos };
                // Truncated lines are ignored (musl reads the rest out).
                let truncated = end == f.len || (end < f.len && end - pos >= 256);
                let mut k = 0;
                while k < ll && k < 256 {
                    line[k] = *f.ptr.add(pos + k);
                    k += 1;
                }
                pos = if end < f.len { end + 1 } else { end };
                if truncated && ll >= 256 {
                    continue;
                }
                parse_resolv_line(&line, ll, conf, search, search_sz);
            }
            free_file(f);
        }
        if (*conf).nns == 0 {
            let mut fam = 0;
            let mut sc = 0;
            let lo = b"127.0.0.1";
            lookup_ipliteral_into(
                lo.as_ptr() as *const c_char,
                lo.len(),
                AF_UNSPEC,
                &mut fam,
                (*conf).ns_addr[0].as_mut_ptr(),
                &mut sc,
            );
            (*conf).ns_family[0] = AF_INET;
            (*conf).nns = 1;
        }
        0
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn parse_resolv_line(
    line: &[u8; 256],
    ll: usize,
    conf: *mut ResolvConf,
    search: *mut c_char,
    search_sz: usize,
) {
    unsafe {
        let starts = |w: &[u8]| -> bool {
            if ll < w.len() {
                return false;
            }
            let mut k = 0;
            while k < w.len() {
                if line[k] != w[k] {
                    return false;
                }
                k += 1;
            }
            ll > w.len() && is_space(line[w.len()])
        };
        if starts(b"options") {
            // Find ndots:/attempts:/timeout: tokens.
            let mut p = 7;
            while p < ll {
                while p < ll && is_space(line[p]) {
                    p += 1;
                }
                if p + 6 <= ll
                    && line[p..p + 6] == *b"ndots:"
                    && p + 6 < ll
                    && is_digit(line[p + 6])
                {
                    let mut v = 0u32;
                    let mut q = p + 6;
                    while q < ll && is_digit(line[q]) {
                        v = v * 10 + (line[q] - b'0') as u32;
                        q += 1;
                    }
                    (*conf).ndots = if v > 15 { 15 } else { v };
                } else if p + 9 <= ll
                    && line[p..p + 9] == *b"attempts:"
                    && p + 9 < ll
                    && is_digit(line[p + 9])
                {
                    let mut v = 0u32;
                    let mut q = p + 9;
                    while q < ll && is_digit(line[q]) {
                        v = v * 10 + (line[q] - b'0') as u32;
                        q += 1;
                    }
                    (*conf).attempts = if v > 10 { 10 } else { v };
                } else if p + 8 <= ll
                    && line[p..p + 8] == *b"timeout:"
                    && p + 8 < ll
                    && (is_digit(line[p + 8]) || line[p + 8] == b'.')
                {
                    let mut v = 0u32;
                    let mut q = p + 8;
                    while q < ll && is_digit(line[q]) {
                        v = v * 10 + (line[q] - b'0') as u32;
                        q += 1;
                    }
                    (*conf).timeout = if v > 60 { 60 } else { v };
                }
                while p < ll && !is_space(line[p]) {
                    p += 1;
                }
            }
            return;
        }
        if starts(b"nameserver") {
            if (*conf).nns >= MAXNS {
                return;
            }
            let mut p = 10;
            while p < ll && is_space(line[p]) {
                p += 1;
            }
            let mut z = p;
            while z < ll && !is_space(line[z]) {
                z += 1;
            }
            // Copy token to NUL-terminated scratch.
            let mut tok = [0i8; 64];
            let tl = z - p;
            if tl == 0 || tl >= 64 {
                return;
            }
            let mut k = 0;
            while k < tl {
                tok[k] = line[p + k] as i8;
                k += 1;
            }
            tok[tl] = 0;
            let n = (*conf).nns;
            let mut fam = 0;
            let mut sc = 0;
            let r = lookup_ipliteral_into(
                tok.as_ptr(),
                tl,
                AF_UNSPEC,
                &mut fam,
                (*conf).ns_addr[n].as_mut_ptr(),
                &mut sc,
            );
            if r > 0 {
                (*conf).ns_family[n] = fam;
                (*conf).ns_scope[n] = sc;
                (*conf).nns = n + 1;
            }
            return;
        }
        if search.is_null() {
            return;
        }
        if !(starts(b"domain") || starts(b"search")) {
            return;
        }
        let mut p = 6;
        while p < ll && is_space(line[p]) {
            p += 1;
        }
        let mut l = 0;
        while p + l < ll && (line[p + l] != b'\n') {
            l += 1;
        }
        while l > 0 && is_space(line[p + l - 1]) {
            l -= 1;
        }
        if l >= search_sz || l == 0 {
            return;
        }
        let mut k = 0;
        while k < l {
            *search.add(k) = line[p + k] as c_char;
            k += 1;
        }
        *search.add(l) = 0;
    }
}

// ---- res_mkquery (musl res_mkquery.c) ----------------------------------------
#[cfg(target_arch = "x86_64")]
unsafe fn mkquery_inner(
    op: c_int,
    dname: *const c_char,
    dlen: usize,
    class: c_int,
    type_: c_int,
    buf: *mut u8,
    buflen: usize,
) -> c_int {
    unsafe {
        let mut l = dlen;
        if l > 0 && *dname.add(l - 1) as u8 == b'.' {
            l -= 1;
        }
        if l > 0 && *dname.add(l - 1) as u8 == b'.' {
            return -1;
        }
        let n = 17 + l + (if l > 0 { 1 } else { 0 });
        if l > 253 || buflen < n || op as u32 > 15 || class as u32 > 255 || type_ as u32 > 255 {
            return -1;
        }
        let mut q = [0u8; 280];
        q[2] = (op as u8).wrapping_mul(8).wrapping_add(1);
        q[3] = 32; // AD
        q[5] = 1;
        let mut k = 0;
        while k < l {
            q[13 + k] = *dname.add(k) as u8;
            k += 1;
        }
        let mut i = 13;
        while q[i] != 0 {
            let mut j = i;
            while q[j] != 0 && q[j] != b'.' {
                j += 1;
            }
            if (j - i) as u32 - 1 > 62 {
                return -1;
            }
            q[i - 1] = (j - i) as u8;
            i = j + 1;
        }
        q[i + 1] = type_ as u8;
        q[i + 3] = class as u8;
        let mut ts = crate::time::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        crate::time::clock_gettime(
            crate::time::CLOCK_REALTIME,
            &mut ts as *mut crate::time::Timespec,
        );
        let ns = ts.tv_nsec as u64 as u32;
        let id = (ns.wrapping_add(ns / 65536)) & 0xffff;
        q[0] = (id / 256) as u8;
        q[1] = (id % 256) as u8;
        let mut t = 0;
        while t < n {
            *buf.add(t) = q[t];
            t += 1;
        }
        n as c_int
    }
}

/// musl `res_mkquery` (+ `__res_mkquery`; same body, no alias needed).
/// # Safety
/// `dname` NUL-terminated; `buf` writable for `buflen`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn res_mkquery(
    op: c_int,
    dname: *const c_char,
    class: c_int,
    type_: c_int,
    _data: *const c_uchar,
    _datalen: c_int,
    _newrr: *const c_uchar,
    buf: *mut c_uchar,
    buflen: c_int,
) -> c_int {
    unsafe {
        if dname.is_null() || buf.is_null() || buflen < 0 {
            return -1;
        }
        let l = cstrnlen(dname, 255);
        mkquery_inner(op, dname, l, class, type_, buf, buflen as usize)
    }
}

// ---- dn_expand (musl dn_expand.c) --------------------------------------------
#[cfg(target_arch = "x86_64")]
unsafe fn dn_expand_inner(
    base: *const u8,
    end: *const u8,
    src: *const u8,
    dest: *mut c_char,
    space: usize,
) -> c_int {
    unsafe {
        if src == end || space == 0 {
            return -1;
        }
        let mut p = src;
        let cap = if space > 254 { 254 } else { space };
        let mut dn = 0usize; // bytes written
        let mut len = -1isize;
        let mut i = 0isize;
        let span = end as usize - base as usize;
        while i < span as isize {
            if p >= end {
                return -1;
            }
            let c = *p;
            if c & 0xc0 != 0 {
                if p.add(1) == end {
                    return -1;
                }
                let j = (((p.read() & 0x3f) as usize) << 8) | (p.add(1).read() as usize);
                if len < 0 {
                    len = p as isize - src as isize + 2;
                }
                if j >= span {
                    return -1;
                }
                p = base.add(j);
            } else if c != 0 {
                if dn != 0 {
                    if dn + 1 >= cap {
                        return -1;
                    }
                    *dest.add(dn) = b'.' as c_char;
                    dn += 1;
                }
                let j = c as usize;
                p = p.add(1);
                if j >= end as usize - p as usize || j >= cap - dn {
                    return -1;
                }
                let mut k = 0;
                while k < j {
                    *dest.add(dn) = *p.add(k) as c_char;
                    dn += 1;
                    k += 1;
                }
                p = p.add(j);
            } else {
                if dn + 1 > cap && cap < space {
                    return -1;
                }
                *dest.add(dn) = 0;
                if len < 0 {
                    len = p as isize - src as isize + 1;
                }
                return len as c_int;
            }
            i += 2;
        }
        -1
    }
}

// ---- dns_parse (musl dns_parse.c) --------------------------------------------
#[cfg(target_arch = "x86_64")]
type DnsCb = unsafe fn(
    ctx: *mut c_void,
    rr: c_int,
    data: *const u8,
    len: c_int,
    pkt: *const u8,
    plen: c_int,
) -> c_int;

#[cfg(target_arch = "x86_64")]
unsafe fn dns_parse_inner(r: *const u8, rlen: c_int, cb: DnsCb, ctx: *mut c_void) -> c_int {
    unsafe {
        if rlen < 12 {
            return -1;
        }
        if *r.add(3) & 15 != 0 {
            return 0;
        }
        let mut p = r.add(12);
        let end = r.add(rlen as usize);
        let mut qd = (*r.add(4) as c_int) * 256 + (*r.add(5) as c_int);
        let mut an = (*r.add(6) as c_int) * 256 + (*r.add(7) as c_int);
        while qd > 0 {
            qd -= 1;
            while p < end && (*p).wrapping_sub(1) < 127 {
                p = p.add(1);
            }
            if p > end.sub(6) {
                return -1;
            }
            let skip = if *p != 0 { 1 } else { 0 };
            p = p.add(5 + skip);
        }
        while an > 0 {
            an -= 1;
            while p < end && (*p).wrapping_sub(1) < 127 {
                p = p.add(1);
            }
            if p > end.sub(12) {
                return -1;
            }
            let skip = if *p != 0 { 1 } else { 0 };
            p = p.add(1 + skip);
            let len = (*p.add(8) as usize) * 256 + (*p.add(9) as usize);
            if p.add(10 + len) > end {
                return -1;
            }
            if cb(ctx, *p.add(1) as c_int, p.add(10), len as c_int, r, rlen) < 0 {
                return -1;
            }
            p = p.add(10 + len);
        }
        0
    }
}

// ---- res_send path (musl res_msend.c, sequential + TCP retry) -----------------
#[cfg(target_arch = "x86_64")]
unsafe fn mono_ms() -> u64 {
    unsafe {
        let mut ts = crate::time::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if crate::time::clock_gettime(
            crate::time::CLOCK_MONOTONIC,
            &mut ts as *mut crate::time::Timespec,
        ) != 0
        {
            return 0;
        }
        (ts.tv_sec as u64)
            .wrapping_mul(1000)
            .wrapping_add(ts.tv_nsec as u64 / 1000000)
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn build_ns(conf: *const ResolvConf, idx: usize, fam: *mut c_int, sa: *mut u8) -> usize {
    unsafe {
        if (*conf).ns_family[idx] == AF_INET {
            *fam = AF_INET;
            let s = sa as *mut SockAddrIn;
            (*s).sin_family = AF_INET as u16;
            (*s).sin_port = 53u16.to_be();
            (*s).sin_addr = ((*conf).ns_addr[idx][0] as u32)
                | ((*conf).ns_addr[idx][1] as u32) << 8
                | ((*conf).ns_addr[idx][2] as u32) << 16
                | ((*conf).ns_addr[idx][3] as u32) << 24;
            let mut k = 0;
            while k < 8 {
                (*s).sin_zero[k] = 0;
                k += 1;
            }
            size_of::<SockAddrIn>()
        } else {
            *fam = AF_INET6;
            let s = sa as *mut SockAddrIn6;
            (*s).sin6_family = AF_INET6 as u16;
            (*s).sin6_port = 53u16.to_be();
            (*s).sin6_flowinfo = 0;
            let mut k = 0;
            while k < 16 {
                (*s).sin6_addr[k] = (*conf).ns_addr[idx][k];
                k += 1;
            }
            (*s).sin6_scope_id = (*conf).ns_scope[idx];
            size_of::<SockAddrIn6>()
        }
    }
}

/// Blocking TCP retry for a truncated (TC) answer. Returns reply length or 0.
#[cfg(target_arch = "x86_64")]
unsafe fn tcp_retry(
    conf: *const ResolvConf,
    idx: usize,
    q: *const u8,
    ql: usize,
    ans: *mut u8,
    asize: usize,
    budget_ms: c_int,
) -> usize {
    unsafe {
        let mut fam = 0;
        let mut sab = [0u8; 28];
        let sl = build_ns(conf, idx, &mut fam, sab.as_mut_ptr());
        let fd = crate::net::socket(fam, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if fd < 0 {
            return 0;
        }
        let mut connected = false;
        if crate::net::connect(fd, sab.as_ptr() as *const c_void, sl as u32) == 0 {
            connected = true;
        } else if last_errno() == EINPROGRESS {
            let mut pfd = crate::poll::Pollfd {
                fd,
                events: crate::poll::POLLOUT,
                revents: 0,
            };
            if crate::poll::poll(&mut pfd as *mut crate::poll::Pollfd, 1, budget_ms) > 0 {
                let mut err = 0 as c_int;
                let mut elen = 4u32;
                if crate::net::getsockopt(
                    fd,
                    SOL_SOCKET,
                    SO_ERROR,
                    &mut err as *mut c_int as *mut c_void,
                    &mut elen as *mut u32,
                ) == 0
                    && err == 0
                {
                    connected = true;
                }
            }
        }
        if !connected {
            crate::unistd::close(fd);
            return 0;
        }
        // Back to blocking for the short exchange.
        crate::fcntl::fcntl(fd, F_SETFL, 0);
        let hdr = [(ql >> 8) as u8, (ql & 0xff) as u8];
        if crate::net::sendto(
            fd,
            hdr.as_ptr() as *const c_void,
            2,
            MSG_NOSIGNAL,
            null_mut(),
            0,
        ) != 2
        {
            crate::unistd::close(fd);
            return 0;
        }
        let mut sent = 0;
        while sent < ql {
            let r = crate::net::sendto(
                fd,
                q.add(sent) as *const c_void,
                ql - sent,
                MSG_NOSIGNAL,
                null_mut(),
                0,
            );
            if r <= 0 {
                crate::unistd::close(fd);
                return 0;
            }
            sent += r as usize;
        }
        let mut pfd = crate::poll::Pollfd {
            fd,
            events: crate::poll::POLLIN,
            revents: 0,
        };
        if crate::poll::poll(&mut pfd as *mut crate::poll::Pollfd, 1, budget_ms) <= 0 {
            crate::unistd::close(fd);
            return 0;
        }
        let mut rhdr = [0u8; 2];
        let mut got = 0;
        while got < 2 {
            let r = crate::net::recvfrom(
                fd,
                rhdr.as_mut_ptr().add(got) as *mut c_void,
                2 - got,
                0,
                null_mut(),
                null_mut(),
            );
            if r <= 0 {
                crate::unistd::close(fd);
                return 0;
            }
            got += r as usize;
        }
        let alen = (rhdr[0] as usize) * 256 + rhdr[1] as usize;
        if alen < 12 || alen > asize {
            crate::unistd::close(fd);
            return 0;
        }
        got = 0;
        while got < alen {
            if crate::poll::poll(&mut pfd as *mut crate::poll::Pollfd, 1, budget_ms) <= 0 {
                crate::unistd::close(fd);
                return 0;
            }
            let r = crate::net::recvfrom(
                fd,
                ans.add(got) as *mut c_void,
                alen - got,
                0,
                null_mut(),
                null_mut(),
            );
            if r <= 0 {
                crate::unistd::close(fd);
                return 0;
            }
            got += r as usize;
        }
        crate::unistd::close(fd);
        // Accept only answer/empty rcode here; caller re-checks.
        alen
    }
}

/// One query through the configured servers (sequential attempts).
#[cfg(target_arch = "x86_64")]
unsafe fn res_send_one(
    q: *const u8,
    ql: usize,
    ans: *mut u8,
    asize: usize,
    conf: *const ResolvConf,
) -> usize {
    unsafe {
        let timeout_ms = (*conf).timeout as u64 * 1000;
        let attempts = if (*conf).attempts == 0 {
            1
        } else {
            (*conf).attempts
        };
        let t0 = mono_ms();
        let mut att = 0;
        while att < attempts {
            let retry = timeout_ms / attempts as u64;
            let mut ns = 0;
            while ns < (*conf).nns {
                let elapsed = mono_ms().wrapping_sub(t0);
                if elapsed >= timeout_ms {
                    return 0;
                }
                let mut fam = 0;
                let mut sab = [0u8; 28];
                let sl = build_ns(conf, ns, &mut fam, sab.as_mut_ptr());
                let fd =
                    crate::net::socket(fam, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
                if fd < 0 {
                    ns += 1;
                    continue;
                }
                // Bind wildcard (musl binds before send).
                if fam == AF_INET {
                    let mut w = SockAddrIn {
                        sin_family: AF_INET as u16,
                        sin_port: 0,
                        sin_addr: 0,
                        sin_zero: [0; 8],
                    };
                    crate::net::bind(
                        fd,
                        &w as *const SockAddrIn as *const c_void,
                        size_of::<SockAddrIn>() as u32,
                    );
                    let _ = &mut w;
                } else {
                    let mut w = SockAddrIn6 {
                        sin6_family: AF_INET6 as u16,
                        sin6_port: 0,
                        sin6_flowinfo: 0,
                        sin6_addr: [0; 16],
                        sin6_scope_id: 0,
                    };
                    crate::net::bind(
                        fd,
                        &w as *const SockAddrIn6 as *const c_void,
                        size_of::<SockAddrIn6>() as u32,
                    );
                    let _ = &mut w;
                }
                crate::net::sendto(
                    fd,
                    q as *const c_void,
                    ql,
                    MSG_NOSIGNAL,
                    sab.as_ptr() as *const c_void,
                    sl as u32,
                );
                let remain = retry as c_int;
                let mut pfd = crate::poll::Pollfd {
                    fd,
                    events: crate::poll::POLLIN,
                    revents: 0,
                };
                let t1 = mono_ms();
                while mono_ms().wrapping_sub(t1) < retry {
                    let left = (retry - mono_ms().wrapping_sub(t1)) as c_int;
                    if crate::poll::poll(&mut pfd as *mut crate::poll::Pollfd, 1, left) <= 0 {
                        break;
                    }
                    let r = crate::net::recvfrom(
                        fd,
                        ans as *mut c_void,
                        asize,
                        0,
                        null_mut(),
                        null_mut(),
                    );
                    if r < 4 {
                        continue;
                    }
                    // Match query ID (musl matches both ID bytes).
                    if *ans.add(0) != *q.add(0) || *ans.add(1) != *q.add(1) {
                        continue;
                    }
                    let rlen = r as usize;
                    match *ans.add(3) & 15 {
                        0 | 3 => {
                            crate::unistd::close(fd);
                            // TC-bit: TCP retry (musl res_msend behavior).
                            if *ans.add(2) & 2 != 0 {
                                let left2 = (timeout_ms - mono_ms().wrapping_sub(t0)) as c_int;
                                if left2 <= 0 {
                                    return 0;
                                }
                                return tcp_retry(conf, ns, q, ql, ans, asize, left2);
                            }
                            return rlen;
                        }
                        2 => break,    // SERVFAIL: next server immediately
                        _ => continue, // REFUSED etc: keep waiting
                    }
                }
                let _ = remain;
                crate::unistd::close(fd);
                ns += 1;
            }
            att += 1;
        }
        0
    }
}

/// musl `__res_send`.
/// # Safety
/// `msg` readable for `msglen`; `answer` writable for `anslen`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn res_send(
    msg: *const c_uchar,
    msglen: c_int,
    answer: *mut c_uchar,
    anslen: c_int,
) -> c_int {
    unsafe {
        if msg.is_null() || answer.is_null() || msglen < 0 || anslen < 0 {
            return -1;
        }
        if anslen < 512 {
            let mut tmp = [0u8; 512];
            let r = res_send(msg, msglen, tmp.as_mut_ptr(), 512);
            if r >= 0 {
                let n = if r as usize > anslen as usize {
                    anslen as usize
                } else {
                    r as usize
                };
                let mut k = 0;
                while k < n {
                    *answer.add(k) = tmp[k];
                    k += 1;
                }
            }
            return r;
        }
        let mut conf = ResolvConf {
            ns_family: [0; MAXNS],
            ns_addr: [[0; 16]; MAXNS],
            ns_scope: [0; MAXNS],
            nns: 0,
            attempts: 0,
            ndots: 0,
            timeout: 0,
        };
        if get_resolv_conf(&mut conf as *mut ResolvConf, null_mut(), 0) < 0 {
            return -1;
        }
        let r = res_send_one(
            msg,
            msglen as usize,
            answer,
            anslen as usize,
            &conf as *const ResolvConf,
        );
        if r == 0 {
            return -1;
        }
        r as c_int
    }
}

// ---- res_query / res_search / res_init / __res_state --------------------------
#[cfg(target_arch = "x86_64")]
unsafe fn res_query_inner(
    name: *const c_char,
    class: c_int,
    type_: c_int,
    dest: *mut c_uchar,
    len: c_int,
) -> c_int {
    unsafe {
        if name.is_null() || dest.is_null() || len < 0 {
            set_h_errno(TRY_AGAIN);
            return -1;
        }
        let nl = cstrnlen(name, 255);
        let mut q = [0u8; 280];
        let ql = mkquery_inner(0, name, nl, class, type_, q.as_mut_ptr(), q.len());
        if ql < 0 {
            set_h_errno(TRY_AGAIN);
            return -1;
        }
        let r = res_send(q.as_ptr(), ql, dest, len);
        if r < 12 {
            set_h_errno(TRY_AGAIN);
            return -1;
        }
        match *dest.add(3) & 15 {
            3 => {
                set_h_errno(HOST_NOT_FOUND);
                -1
            }
            0 if *dest.add(6) == 0 && *dest.add(7) == 0 => {
                set_h_errno(NO_DATA);
                -1
            }
            _ => r,
        }
    }
}

/// musl `res_query`.
/// # Safety
/// `name` NUL-terminated; `dest` writable for `len`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn res_query(
    name: *const c_char,
    class: c_int,
    type_: c_int,
    dest: *mut c_uchar,
    len: c_int,
) -> c_int {
    unsafe { res_query_inner(name, class, type_, dest, len) }
}

/// musl `res_search` (weak alias of res_query: identical body).
/// # Safety
/// Same contract as [`res_query`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn res_search(
    name: *const c_char,
    class: c_int,
    type_: c_int,
    dest: *mut c_uchar,
    len: c_int,
) -> c_int {
    unsafe { res_query_inner(name, class, type_, dest, len) }
}

/// musl `res_querydomain`.
/// # Safety
/// `name`/`domain` NUL-terminated; `dest` writable for `len`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn res_querydomain(
    name: *const c_char,
    domain: *const c_char,
    class: c_int,
    type_: c_int,
    dest: *mut c_uchar,
    len: c_int,
) -> c_int {
    unsafe {
        if name.is_null() || domain.is_null() {
            set_h_errno(TRY_AGAIN);
            return -1;
        }
        let nl = cstrnlen(name, 255);
        let dl = cstrnlen(domain, 255);
        if nl + dl + 1 > 254 {
            return -1;
        }
        let mut tmp = [0i8; 255];
        let mut k = 0;
        while k < nl {
            tmp[k] = *name.add(k);
            k += 1;
        }
        tmp[nl] = b'.' as c_char;
        k = 0;
        while k <= dl {
            tmp[nl + 1 + k] = *domain.add(k);
            k += 1;
        }
        res_query_inner(tmp.as_ptr(), class, type_, dest, len)
    }
}

/// musl `res_init` (always 0; lookup re-reads resolv.conf per call).
///
/// # Safety
///
/// No pointers; touches only process-global resolver state.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn res_init() -> c_int {
    0
}

#[cfg(target_arch = "x86_64")]
static mut RES_STATE_DUMMY: ResState = ResState { _pad: [0; 72] };

/// musl `__res_state` (dummy static, purely for broken apps).
/// # Safety
/// The pointer stays valid for the program's lifetime.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn __res_state() -> *mut ResState {
    core::ptr::addr_of_mut!(RES_STATE_DUMMY)
}

// ---- lookup_serv (musl lookup_serv.c + builtin fallback) ----------------------
#[cfg(target_arch = "x86_64")]
static BUILTIN_SERVS: &[(&[u8], u16)] = &[
    (b"http", 80),
    (b"https", 443),
    (b"ssh", 22),
    (b"ftp", 21),
    (b"smtp", 25),
    (b"domain", 53),
    (b"pop3", 110),
    (b"imap", 143),
    (b"tftp", 69),
    (b"telnet", 23),
    (b"ntp", 123),
    (b"finger", 79),
    (b"nntp", 119),
];

#[cfg(target_arch = "x86_64")]
unsafe fn parse_u16(s: *const c_char, len: usize, out: *mut u16) -> bool {
    unsafe {
        if len == 0 {
            return false;
        }
        let mut v = 0u32;
        let mut k = 0;
        while k < len {
            let b = *s.add(k) as u8;
            if !is_digit(b) {
                return false;
            }
            v = v * 10 + (b - b'0') as u32;
            if v > 65535 {
                return false;
            }
            k += 1;
        }
        *out = v as u16;
        true
    }
}

/// musl `__lookup_serv` (+ builtin-table fallback when the file misses).
#[cfg(target_arch = "x86_64")]
unsafe fn lookup_serv_inner(
    buf: *mut Service,
    name: *const c_char,
    proto: c_int,
    socktype: c_int,
    flags: c_int,
) -> c_int {
    unsafe {
        let (mut want_tcp, mut want_udp) = (false, false);
        let mut eff_proto = proto;
        match socktype {
            SOCK_STREAM => {
                if proto == 0 {
                    eff_proto = IPPROTO_TCP;
                }
                if eff_proto != IPPROTO_TCP {
                    return EAI_SERVICE;
                }
                want_tcp = true;
            }
            SOCK_DGRAM => {
                if proto == 0 {
                    eff_proto = IPPROTO_UDP;
                }
                if eff_proto != IPPROTO_UDP {
                    return EAI_SERVICE;
                }
                want_udp = true;
            }
            0 => {
                want_tcp = eff_proto != IPPROTO_UDP;
                want_udp = eff_proto != IPPROTO_TCP;
            }
            _ => {
                if !name.is_null() {
                    return EAI_SERVICE;
                }
                (*buf.add(0)).port = 0;
                (*buf.add(0)).proto = proto as u8;
                (*buf.add(0)).socktype = socktype as u8;
                return 1;
            }
        }
        if !name.is_null() {
            let nl = cstrlen(name);
            if nl == 0 {
                return EAI_SERVICE;
            }
            // Numeric port?
            let mut alldig = true;
            let mut k = 0;
            while k < nl {
                if !is_digit(*name.add(k) as u8) {
                    alldig = false;
                    break;
                }
                k += 1;
            }
            if alldig {
                let mut port = 0u16;
                if !parse_u16(name, nl, &mut port as *mut u16) {
                    return EAI_SERVICE;
                }
                let mut cnt = 0;
                if want_tcp {
                    (*buf.add(cnt)).port = port;
                    (*buf.add(cnt)).socktype = SOCK_DGRAM as u8; // fixed below
                    (*buf.add(cnt)).proto = IPPROTO_TCP as u8;
                    (*buf.add(cnt)).socktype = SOCK_STREAM as u8;
                    cnt += 1;
                }
                if want_udp {
                    (*buf.add(cnt)).port = port;
                    (*buf.add(cnt)).socktype = SOCK_DGRAM as u8;
                    (*buf.add(cnt)).proto = IPPROTO_UDP as u8;
                    cnt += 1;
                }
                return cnt as c_int;
            }
            if flags & AI_NUMERICSERV != 0 {
                return EAI_NONAME;
            }
            let mut cnt = 0;
            let f = read_file(c"/etc/services".as_ptr());
            if !f.ptr.is_null() {
                let mut pos = 0;
                while pos < f.len && (cnt as usize) < MAXSERVS {
                    let mut end = pos;
                    while end < f.len && *f.ptr.add(end) != b'\n' {
                        end += 1;
                    }
                    // Strip comment.
                    let mut cut = pos;
                    while cut < end && *f.ptr.add(cut) != b'#' {
                        cut += 1;
                    }
                    let le = cut;
                    // Token-match name like musl (whitespace-delimited).
                    let mut hit = false;
                    let mut p = pos;
                    while p + nl <= le {
                        let before_ok = p == pos || is_space(*f.ptr.add(p - 1));
                        let after_ok = p + nl >= le || is_space(*f.ptr.add(p + nl));
                        if before_ok && after_ok {
                            let mut m = true;
                            let mut t = 0;
                            while t < nl {
                                if *f.ptr.add(p + t) != *name.add(t) as u8 {
                                    m = false;
                                    break;
                                }
                                t += 1;
                            }
                            if m {
                                hit = true;
                                break;
                            }
                        }
                        // advance to next token start
                        while p < le && !is_space(*f.ptr.add(p)) {
                            p += 1;
                        }
                        while p < le && is_space(*f.ptr.add(p)) {
                            p += 1;
                        }
                        if p == pos {
                            break;
                        }
                    }
                    if hit {
                        // Skip canonical name, parse port/proto.
                        let mut q = pos;
                        while q < le && !is_space(*f.ptr.add(q)) {
                            q += 1;
                        }
                        while q < le && is_space(*f.ptr.add(q)) {
                            q += 1;
                        }
                        let mut v = 0u32;
                        let mut digits = 0;
                        while q < le && is_digit(*f.ptr.add(q)) {
                            v = v * 10 + (*f.ptr.add(q) - b'0') as u32;
                            q += 1;
                            digits += 1;
                        }
                        if digits > 0 && v <= 65535 {
                            let is_udp = q + 4 <= le
                                && *f.ptr.add(q) == b'/'
                                && *f.ptr.add(q + 1) == b'u'
                                && *f.ptr.add(q + 2) == b'd'
                                && *f.ptr.add(q + 3) == b'p';
                            let is_tcp = q + 4 <= le
                                && *f.ptr.add(q) == b'/'
                                && *f.ptr.add(q + 1) == b't'
                                && *f.ptr.add(q + 2) == b'c'
                                && *f.ptr.add(q + 3) == b'p';
                            if is_udp && want_udp {
                                (*buf.add(cnt as usize)).port = v as u16;
                                (*buf.add(cnt as usize)).socktype = SOCK_DGRAM as u8;
                                (*buf.add(cnt as usize)).proto = IPPROTO_UDP as u8;
                                cnt += 1;
                            }
                            if is_tcp && want_tcp {
                                (*buf.add(cnt as usize)).port = v as u16;
                                (*buf.add(cnt as usize)).socktype = SOCK_STREAM as u8;
                                (*buf.add(cnt as usize)).proto = IPPROTO_TCP as u8;
                                cnt += 1;
                            }
                        }
                    }
                    pos = if end < f.len { end + 1 } else { end };
                }
                free_file(f);
                if cnt > 0 {
                    return cnt;
                }
                // Fall through to builtin table (hermetic-CI fallback).
            } else {
                let e = last_errno();
                if e != ENOENT && e != ENOTDIR && e != EACCES {
                    return EAI_SYSTEM;
                }
            }
            // Builtin fallback (deviation noted in module docs).
            let mut b = 0;
            while b < BUILTIN_SERVS.len() {
                let (nm, port) = BUILTIN_SERVS[b];
                if nm.len() == nl {
                    let mut m = true;
                    let mut t = 0;
                    while t < nl {
                        if nm[t] != *name.add(t) as u8 {
                            m = false;
                            break;
                        }
                        t += 1;
                    }
                    if m {
                        let mut cnt = 0;
                        if want_tcp && (cnt as usize) < MAXSERVS {
                            (*buf.add(cnt as usize)).port = port;
                            (*buf.add(cnt as usize)).socktype = SOCK_STREAM as u8;
                            (*buf.add(cnt as usize)).proto = IPPROTO_TCP as u8;
                            cnt += 1;
                        }
                        if want_udp && (cnt as usize) < MAXSERVS {
                            (*buf.add(cnt as usize)).port = port;
                            (*buf.add(cnt as usize)).socktype = SOCK_DGRAM as u8;
                            (*buf.add(cnt as usize)).proto = IPPROTO_UDP as u8;
                            cnt += 1;
                        }
                        if cnt > 0 {
                            return cnt;
                        }
                    }
                }
                b += 1;
            }
            return EAI_SERVICE;
        }
        // serv == NULL with valid socktype: wildcard port handled by caller
        // shape; musl reaches here only via name==NULL + socktype 0 path
        // (returns 0 services → getaddrinfo multiplies by addresses with
        // port 0). Mirror: single zero service.
        (*buf.add(0)).port = 0;
        (*buf.add(0)).proto = eff_proto as u8;
        (*buf.add(0)).socktype = socktype as u8;
        1
    }
}

// ---- lookup_name pieces (musl lookup_name.c) ----------------------------------
#[cfg(target_arch = "x86_64")]
unsafe fn name_from_null(
    buf: *mut Address,
    name_is_null: bool,
    family: c_int,
    flags: c_int,
) -> c_int {
    unsafe {
        if !name_is_null {
            return 0;
        }
        let mut cnt = 0;
        if flags & AI_PASSIVE != 0 {
            if family != AF_INET6 {
                (*buf.add(cnt)).family = AF_INET;
                (*buf.add(cnt)).scopeid = 0;
                (*buf.add(cnt)).addr = [0; 16];
                cnt += 1;
            }
            if family != AF_INET {
                (*buf.add(cnt)).family = AF_INET6;
                (*buf.add(cnt)).scopeid = 0;
                (*buf.add(cnt)).addr = [0; 16];
                cnt += 1;
            }
        } else {
            if family != AF_INET6 {
                (*buf.add(cnt)).family = AF_INET;
                (*buf.add(cnt)).scopeid = 0;
                (*buf.add(cnt)).addr = [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                cnt += 1;
            }
            if family != AF_INET {
                (*buf.add(cnt)).family = AF_INET6;
                (*buf.add(cnt)).scopeid = 0;
                (*buf.add(cnt)).addr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
                cnt += 1;
            }
        }
        cnt as c_int
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn name_from_numeric(
    buf: *mut Address,
    name: *const c_char,
    len: usize,
    family: c_int,
) -> c_int {
    unsafe {
        let mut fam = 0;
        let mut sc = 0;
        let mut tmp = [0u8; 16];
        let r = lookup_ipliteral_into(name, len, family, &mut fam, tmp.as_mut_ptr(), &mut sc);
        if r <= 0 {
            return r;
        }
        (*buf).family = fam;
        (*buf).scopeid = sc;
        (*buf).addr = [0; 16];
        if fam == AF_INET {
            (*buf).addr[0] = tmp[0];
            (*buf).addr[1] = tmp[1];
            (*buf).addr[2] = tmp[2];
            (*buf).addr[3] = tmp[3];
        } else {
            (*buf).addr = tmp;
        }
        1
    }
}

/// musl `name_from_hosts`.
#[cfg(target_arch = "x86_64")]
unsafe fn name_from_hosts(
    buf: *mut Address,
    canon: *mut c_char,
    name: *const c_char,
    nlen: usize,
    family: c_int,
) -> c_int {
    unsafe {
        let f = read_file(c"/etc/hosts".as_ptr());
        if f.ptr.is_null() {
            let e = last_errno();
            if e == ENOENT || e == ENOTDIR || e == EACCES {
                return 0;
            }
            return EAI_SYSTEM;
        }
        let mut cnt = 0;
        let mut badfam = 0;
        let mut have_canon = false;
        let mut pos = 0;
        while pos < f.len && (cnt as usize) < MAXADDRS {
            let mut end = pos;
            while end < f.len && *f.ptr.add(end) != b'\n' {
                end += 1;
            }
            let mut le = end;
            // Strip comment.
            let mut c = pos;
            while c < end {
                if *f.ptr.add(c) == b'#' {
                    le = c;
                    break;
                }
                c += 1;
            }
            // Token match (whitespace-delimited), scanning from pos+1
            // so the address field itself never matches.
            let mut hit = false;
            let mut p = pos + 1;
            while p + nlen <= le {
                let before_ok = is_space(*f.ptr.add(p - 1));
                let after_ok = p + nlen >= le || is_space(*f.ptr.add(p + nlen));
                if before_ok && after_ok {
                    let mut m = true;
                    let mut t = 0;
                    while t < nlen {
                        if *f.ptr.add(p + t) != *name.add(t) as u8 {
                            m = false;
                            break;
                        }
                        t += 1;
                    }
                    if m {
                        hit = true;
                        break;
                    }
                    p += 1;
                } else {
                    p += 1;
                }
            }
            if hit {
                // Isolate address: first token.
                let mut q = pos;
                while q < le && !is_space(*f.ptr.add(q)) {
                    q += 1;
                }
                let alen = q - pos;
                let mut fam = 0;
                let mut sc = 0;
                let mut tmp = [0u8; 16];
                // Copy token to scratch for the parsers.
                let mut tok = [0i8; 64];
                if alen < 64 {
                    let mut t = 0;
                    while t < alen {
                        tok[t] = *f.ptr.add(pos + t) as i8;
                        t += 1;
                    }
                    tok[alen] = 0;
                    let r = lookup_ipliteral_into(
                        tok.as_ptr(),
                        alen,
                        family,
                        &mut fam,
                        tmp.as_mut_ptr(),
                        &mut sc,
                    );
                    if r == 1 {
                        (*buf.add(cnt as usize)).family = fam;
                        (*buf.add(cnt as usize)).scopeid = sc;
                        (*buf.add(cnt as usize)).addr = [0; 16];
                        if fam == AF_INET {
                            (*buf.add(cnt as usize)).addr[0] = tmp[0];
                            (*buf.add(cnt as usize)).addr[1] = tmp[1];
                            (*buf.add(cnt as usize)).addr[2] = tmp[2];
                            (*buf.add(cnt as usize)).addr[3] = tmp[3];
                        } else {
                            (*buf.add(cnt as usize)).addr = tmp;
                        }
                        cnt += 1;
                        if !have_canon {
                            // First name after address = canonical.
                            let mut n = q;
                            while n < le && is_space(*f.ptr.add(n)) {
                                n += 1;
                            }
                            let mut z = n;
                            while z < le && !is_space(*f.ptr.add(z)) {
                                z += 1;
                            }
                            if z > n
                                && z - n < 256
                                && is_valid_hostname(f.ptr.add(n) as *const c_char, z - n)
                            {
                                let mut t = 0;
                                while t <= z - n {
                                    *canon.add(t) = *f.ptr.add(n + t) as c_char;
                                    t += 1;
                                }
                                have_canon = true;
                            }
                        }
                    } else if r != 0 {
                        badfam = EAI_NODATA;
                    }
                }
            }
            pos = if end < f.len { end + 1 } else { end };
        }
        free_file(f);
        if cnt > 0 {
            cnt
        } else {
            badfam
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct DpcCtx {
    addrs: *mut Address,
    canon: *mut c_char,
    cnt: c_int,
    rrtype: c_int,
}

#[cfg(target_arch = "x86_64")]
unsafe fn dns_parse_cb(
    ctx: *mut c_void,
    rr: c_int,
    data: *const u8,
    len: c_int,
    pkt: *const u8,
    plen: c_int,
) -> c_int {
    unsafe {
        const RR_A: c_int = 1;
        const RR_CNAME: c_int = 5;
        const RR_AAAA: c_int = 28;
        let c = ctx as *mut DpcCtx;
        if rr == RR_CNAME {
            let mut tmp = [0i8; 256];
            if dn_expand_inner(pkt, pkt.add(plen as usize), data, tmp.as_mut_ptr(), 256) > 0 {
                let tl = cstrlen(tmp.as_ptr());
                if tl < 256 && is_valid_hostname(tmp.as_ptr(), tl) {
                    let mut k = 0;
                    while k <= tl {
                        *(*c).canon.add(k) = tmp[k];
                        k += 1;
                    }
                }
            }
            return 0;
        }
        if (*c).cnt as usize >= MAXADDRS {
            return 0;
        }
        if rr != (*c).rrtype {
            return 0;
        }
        let fam = match rr {
            RR_A => {
                if len != 4 {
                    return -1;
                }
                AF_INET
            }
            RR_AAAA => {
                if len != 16 {
                    return -1;
                }
                AF_INET6
            }
            _ => return 0,
        };
        let n = (*c).cnt as usize;
        (*(*c).addrs.add(n)).family = fam;
        (*(*c).addrs.add(n)).scopeid = 0;
        (*(*c).addrs.add(n)).addr = [0; 16];
        let mut k = 0;
        while k < len as usize {
            (*(*c).addrs.add(n)).addr[k] = *data.add(k);
            k += 1;
        }
        (*c).cnt += 1;
        0
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn name_from_dns(
    buf: *mut Address,
    canon: *mut c_char,
    name: *const c_char,
    nlen: usize,
    family: c_int,
    conf: *const ResolvConf,
) -> c_int {
    unsafe {
        const RR_A: c_int = 1;
        const RR_AAAA: c_int = 28;
        let mut q0 = [0u8; 280];
        let mut q1 = [0u8; 280];
        let mut a0 = [0u8; 4800];
        let mut a1 = [0u8; 4800];
        let mut nq = 0usize;
        let mut qtypes = [0 as c_int; 2];
        // musl queries v6 (AAAA) unless family==AF_INET, v4 (A) unless AF_INET6.
        // (lookup.h afrr table pairs AF_INET6→RR_A oddly; net effect:)
        if family != AF_INET {
            let ql = mkquery_inner(0, name, nlen, 1, RR_AAAA, q0.as_mut_ptr(), q0.len());
            if ql < 0 {
                return 0;
            }
            q0[3] = 0;
            qtypes[nq] = RR_AAAA;
            nq += 1;
        }
        if family != AF_INET6 {
            let ql = mkquery_inner(0, name, nlen, 1, RR_A, q1.as_mut_ptr(), q1.len());
            if ql < 0 {
                return 0;
            }
            q1[3] = 0;
            if nq == 1 && q1[0] == q0[0] && q1[1] == q0[1] {
                q1[0] = q1[0].wrapping_add(1);
            }
            qtypes[nq] = RR_A;
            nq += 1;
        }
        let mut alens = [0usize; 2];
        let mut k = 0;
        while k < nq {
            let (q, a) = if k == 0 {
                (q0.as_ptr(), a0.as_mut_ptr())
            } else {
                (q1.as_ptr(), a1.as_mut_ptr())
            };
            // Query length recompute: header(12)+name+4; mkquery wrote it.
            let ql = {
                // Walk qname to find length (labels + root + type/class).
                let mut p = 12;
                loop {
                    let l = *q.add(p) as usize;
                    p += 1 + l;
                    if l == 0 {
                        break;
                    }
                    if p > 280 {
                        break;
                    }
                }
                p + 4
            };
            alens[k] = res_send_one(q, ql, a, 4800, conf);
            k += 1;
        }
        let mut i = 0;
        while i < nq {
            let (a, alen) = if i == 0 {
                (a0.as_ptr(), alens[0])
            } else {
                (a1.as_ptr(), alens[1])
            };
            if alen < 4 {
                return EAI_AGAIN;
            }
            match *a.add(3) & 15 {
                2 => return EAI_AGAIN,
                3 => return 0,
                0 => {}
                _ => return EAI_FAIL,
            }
            i += 1;
        }
        let mut ctx = DpcCtx {
            addrs: buf,
            canon,
            cnt: 0,
            rrtype: 0,
        };
        let mut j = nq;
        while j > 0 {
            j -= 1;
            ctx.rrtype = qtypes[j];
            let (a, alen) = if j == 0 {
                (a0.as_ptr(), alens[0])
            } else {
                (a1.as_ptr(), alens[1])
            };
            let al = if alen > 4800 { 4800 } else { alen };
            dns_parse_inner(
                a,
                al as c_int,
                dns_parse_cb,
                &mut ctx as *mut DpcCtx as *mut c_void,
            );
        }
        if ctx.cnt > 0 {
            return ctx.cnt;
        }
        EAI_NODATA
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn name_from_dns_search(
    buf: *mut Address,
    canon: *mut c_char,
    name: *const c_char,
    nlen: usize,
    family: c_int,
) -> c_int {
    unsafe {
        let mut conf = ResolvConf {
            ns_family: [0; MAXNS],
            ns_addr: [[0; 16]; MAXNS],
            ns_scope: [0; MAXNS],
            nns: 0,
            attempts: 0,
            ndots: 0,
            timeout: 0,
        };
        let mut search = [0i8; 256];
        if get_resolv_conf(
            &mut conf as *mut ResolvConf,
            search.as_mut_ptr(),
            search.len(),
        ) < 0
        {
            return -1;
        }
        let mut dots = 0;
        let mut l = 0;
        while l < nlen {
            if *name.add(l) as u8 == b'.' {
                dots += 1;
            }
            l += 1;
        }
        if dots >= conf.ndots || (l > 0 && *name.add(l - 1) as u8 == b'.') {
            search[0] = 0;
        }
        if l > 0 && *name.add(l - 1) as u8 == b'.' {
            l -= 1;
        }
        if l == 0 || (l > 0 && *name.add(l - 1) as u8 == b'.') || l >= 256 {
            return EAI_NONAME;
        }
        // canon = name + '.' + search-domain staging (musl shape).
        let mut k = 0;
        while k < l {
            *canon.add(k) = *name.add(k);
            k += 1;
        }
        *canon.add(l) = b'.' as c_char;
        let mut p = 0;
        while search[p] != 0 {
            while search[p] != 0 && is_space(search[p] as u8) {
                p += 1;
            }
            let mut z = p;
            while search[z] != 0 && !is_space(search[z] as u8) {
                z += 1;
            }
            if z == p {
                break;
            }
            if z - p < 256 - l - 1 {
                let mut t = 0;
                while t < z - p {
                    *canon.add(l + 1 + t) = search[p + t];
                    t += 1;
                }
                *canon.add(l + 1 + (z - p)) = 0;
                let cl = l + 1 + (z - p);
                let cnt = name_from_dns(buf, canon, canon, cl, family, &conf as *const ResolvConf);
                if cnt != 0 {
                    return cnt;
                }
            }
            p = z;
        }
        *canon.add(l) = 0;
        // Bare name: strip nothing else; query as-is.
        let mut bare = [0i8; 256];
        k = 0;
        while k < l {
            bare[k] = *name.add(k);
            k += 1;
        }
        bare[l] = 0;
        name_from_dns(
            buf,
            canon,
            bare.as_ptr(),
            l,
            family,
            &conf as *const ResolvConf,
        )
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn lookup_name_inner(
    buf: *mut Address,
    canon: *mut c_char,
    name: *const c_char,
    family: c_int,
    flags: c_int,
) -> c_int {
    unsafe {
        *canon = 0;
        let mut nlen = 0;
        let is_null = name.is_null();
        if !is_null {
            nlen = cstrnlen(name, 255);
            if nlen == 0 || nlen >= 255 {
                return EAI_NONAME;
            }
            let mut k = 0;
            while k <= nlen {
                *canon.add(k) = *name.add(k);
                k += 1;
            }
        }
        let mut fam = family;
        let mut fl = flags;
        if fl & AI_V4MAPPED != 0 {
            if fam == AF_INET6 {
                fam = AF_UNSPEC;
            } else {
                fl -= AI_V4MAPPED;
            }
        }
        let mut cnt = name_from_null(buf, is_null, fam, fl);
        if cnt == 0 {
            cnt = name_from_numeric(buf, name, nlen, fam);
        }
        if cnt == 0 && fl & AI_NUMERICHOST == 0 && !is_null {
            cnt = name_from_hosts(buf, canon, name, nlen, fam);
            if cnt == 0 {
                cnt = name_from_dns_search(buf, canon, name, nlen, fam);
            }
        }
        if cnt <= 0 {
            return if cnt != 0 { cnt } else { EAI_NONAME };
        }
        if fl & AI_V4MAPPED != 0 {
            if fl & AI_ALL == 0 {
                let mut i = 0;
                while i < cnt as usize && (*buf.add(i)).family != AF_INET6 {
                    i += 1;
                }
                if i < cnt as usize {
                    let mut j = 0;
                    let mut t = i;
                    while t < cnt as usize {
                        if (*buf.add(t)).family == AF_INET6 {
                            (*buf.add(j)) = *buf.add(t);
                            j += 1;
                        }
                        t += 1;
                    }
                    cnt = j as c_int;
                }
            }
            let mut i = 0;
            while i < cnt as usize {
                if (*buf.add(i)).family == AF_INET {
                    let mut v4 = [0u8; 4];
                    v4.copy_from_slice(core::slice::from_raw_parts(
                        core::ptr::addr_of!((*buf.add(i)).addr) as *const u8,
                        4,
                    ));
                    core::ptr::copy_nonoverlapping(
                        [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff].as_ptr(),
                        core::ptr::addr_of_mut!((*buf.add(i)).addr) as *mut u8,
                        12,
                    );
                    core::ptr::copy_nonoverlapping(
                        v4.as_ptr(),
                        (core::ptr::addr_of_mut!((*buf.add(i)).addr) as *mut u8).add(12),
                        4,
                    );
                    (*buf.add(i)).family = AF_INET6;
                }
                i += 1;
            }
        }
        cnt
    }
}

// ---- getaddrinfo / freeaddrinfo (musl getaddrinfo.c, freeaddrinfo.c) ---------
/// musl `getaddrinfo`.
/// # Safety
/// `host`/`serv`/`hint` follow musl's contract (nullable host/serv);
/// on success `*res` must be released with [`freeaddrinfo`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getaddrinfo(
    host: *const c_char,
    serv: *const c_char,
    hint: *const AddrInfo,
    res: *mut *mut AddrInfo,
) -> c_int {
    unsafe {
        if res.is_null() {
            return EAI_SYSTEM;
        }
        *res = null_mut();
        if host.is_null() && serv.is_null() {
            return EAI_NONAME;
        }
        let mut family = AF_UNSPEC;
        let mut flags = 0;
        let mut proto = 0;
        let mut socktype = 0;
        if !hint.is_null() {
            family = (*hint).ai_family;
            flags = (*hint).ai_flags;
            proto = (*hint).ai_protocol;
            socktype = (*hint).ai_socktype;
            const MASK: c_int = AI_PASSIVE
                | AI_CANONNAME
                | AI_NUMERICHOST
                | AI_V4MAPPED
                | AI_ALL
                | AI_ADDRCONFIG
                | AI_NUMERICSERV;
            if flags & MASK != flags {
                return EAI_BADFLAGS;
            }
            match family {
                AF_INET | AF_INET6 | AF_UNSPEC => {}
                _ => return EAI_FAMILY,
            }
        }
        let mut no_family = false;
        if flags & AI_ADDRCONFIG != 0 {
            // musl's loopback-connect probe (no getifaddrs involved).
            let lo4 = SockAddrIn {
                sin_family: AF_INET as u16,
                sin_port: 0xffff,
                sin_addr: 0x0100007f,
                sin_zero: [0; 8],
            };
            let lo6 = SockAddrIn6 {
                sin6_family: AF_INET6 as u16,
                sin6_port: 0xffff,
                sin6_flowinfo: 0,
                sin6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                sin6_scope_id: 0,
            };
            let tfs = [AF_INET, AF_INET6];
            let mut i = 0;
            while i < 2 {
                if family != tfs[1 - i] {
                    let s = crate::net::socket(tfs[i], SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
                    if s >= 0 {
                        let r = if tfs[i] == AF_INET {
                            crate::net::connect(
                                s,
                                &lo4 as *const SockAddrIn as *const c_void,
                                size_of::<SockAddrIn>() as u32,
                            )
                        } else {
                            crate::net::connect(
                                s,
                                &lo6 as *const SockAddrIn6 as *const c_void,
                                size_of::<SockAddrIn6>() as u32,
                            )
                        };
                        let se = last_errno();
                        crate::unistd::close(s);
                        if r == 0 {
                            i += 1;
                            continue;
                        }
                        match se {
                            // EADDRNOTAVAIL/EAFNOSUPPORT/EHOSTUNREACH/
                            // ENETDOWN/ENETUNREACH → family unusable.
                            97 | 99 | 113 | 100 | 101 => {}
                            _ => return EAI_SYSTEM,
                        }
                    } else {
                        match last_errno() {
                            97 | 99 | 113 | 100 | 101 => {}
                            _ => return EAI_SYSTEM,
                        }
                    }
                    if family == tfs[i] {
                        no_family = true;
                    }
                    family = tfs[1 - i];
                }
                i += 1;
            }
        }
        let mut ports = [Service {
            port: 0,
            proto: 0,
            socktype: 0,
        }; MAXSERVS];
        let nservs = lookup_serv_inner(ports.as_mut_ptr(), serv, proto, socktype, flags);
        if nservs < 0 {
            return nservs;
        }
        let mut addrs = [Address {
            family: 0,
            scopeid: 0,
            addr: [0; 16],
        }; MAXADDRS];
        let mut canon = [0i8; 256];
        let naddrs = lookup_name_inner(addrs.as_mut_ptr(), canon.as_mut_ptr(), host, family, flags);
        if naddrs < 0 {
            return naddrs;
        }
        if no_family {
            return EAI_NODATA;
        }
        let nais = nservs as usize * naddrs as usize;
        let mut canon_len = 0;
        while canon_len < 256 && canon[canon_len] != 0 {
            canon_len += 1;
        }
        let total = nais * size_of::<AiBuf>() + canon_len + 1;
        let out = crate::malloc::calloc(1, total) as *mut AiBuf;
        if out.is_null() {
            return EAI_MEMORY;
        }
        let outcanon = if canon_len > 0 {
            let oc = (out as *mut u8).add(nais * size_of::<AiBuf>()) as *mut c_char;
            let mut k = 0;
            while k <= canon_len {
                *oc.add(k) = canon[k];
                k += 1;
            }
            oc
        } else {
            null_mut()
        };
        let mut k = 0;
        let mut i = 0;
        while i < naddrs as usize {
            let mut j = 0;
            while j < nservs as usize {
                (*out.add(k)).slot = k as i16;
                (*out.add(k)).ai.ai_flags = 0;
                (*out.add(k)).ai.ai_family = addrs[i].family;
                (*out.add(k)).ai.ai_socktype = ports[j].socktype as c_int;
                (*out.add(k)).ai.ai_protocol = ports[j].proto as c_int;
                (*out.add(k)).ai.ai_addrlen = if addrs[i].family == AF_INET {
                    size_of::<SockAddrIn>() as u32
                } else {
                    size_of::<SockAddrIn6>() as u32
                };
                (*out.add(k)).ai.ai_addr =
                    &mut (*out.add(k)).sa as *mut SockAddrMax as *mut SockAddr;
                (*out.add(k)).ai.ai_canonname = outcanon;
                (*out.add(k)).ai.ai_next = if k + 1 < nais {
                    &mut (*out.add(k + 1)).ai as *mut AddrInfo
                } else {
                    null_mut()
                };
                if addrs[i].family == AF_INET {
                    (*out.add(k)).sa.sin.sin_family = AF_INET as u16;
                    (*out.add(k)).sa.sin.sin_port = ports[j].port.to_be();
                    (*out.add(k)).sa.sin.sin_addr = (addrs[i].addr[0] as u32)
                        | ((addrs[i].addr[1] as u32) << 8)
                        | ((addrs[i].addr[2] as u32) << 16)
                        | ((addrs[i].addr[3] as u32) << 24);
                    let mut z = 0;
                    while z < 8 {
                        (*out.add(k)).sa.sin.sin_zero[z] = 0;
                        z += 1;
                    }
                } else {
                    (*out.add(k)).sa.sin6.sin6_family = AF_INET6 as u16;
                    (*out.add(k)).sa.sin6.sin6_port = ports[j].port.to_be();
                    (*out.add(k)).sa.sin6.sin6_flowinfo = 0;
                    let mut z = 0;
                    while z < 16 {
                        (*out.add(k)).sa.sin6.sin6_addr[z] = addrs[i].addr[z];
                        z += 1;
                    }
                    (*out.add(k)).sa.sin6.sin6_scope_id = addrs[i].scopeid;
                }
                k += 1;
                j += 1;
            }
            i += 1;
        }
        (*out).ref_ = nais as i16;
        *res = &mut (*out).ai as *mut AddrInfo;
        0
    }
}

/// musl `freeaddrinfo` (same slot/ref walk).
/// # Safety
/// `p` must come from [`getaddrinfo`] and be freed exactly once.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn freeaddrinfo(p: *mut AddrInfo) {
    unsafe {
        if p.is_null() {
            return;
        }
        let mut cnt = 1usize;
        let mut q = p;
        while !(*q).ai_next.is_null() {
            cnt += 1;
            q = (*q).ai_next;
        }
        let mut b = (q as *mut u8).sub(core::mem::offset_of!(AiBuf, ai)) as *mut AiBuf;
        b = b.sub((*b).slot as usize);
        (*b).ref_ -= cnt as i16;
        if (*b).ref_ == 0 {
            crate::malloc::free(b as *mut c_void);
        }
    }
}

// ---- getnameinfo (musl getnameinfo.c) -----------------------------------------
#[cfg(target_arch = "x86_64")]
unsafe fn reverse_hosts(buf: *mut c_char, a: *const u8, scopeid: u32, family: c_int) {
    unsafe {
        let f = read_file(c"/etc/hosts".as_ptr());
        if f.ptr.is_null() {
            return;
        }
        // Normalize v4 to v4-mapped for comparison (musl shape).
        let mut key = [0u8; 16];
        if family == AF_INET {
            key[0..10].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            key[10] = 0xff;
            key[11] = 0xff;
            key[12] = *a.add(0);
            key[13] = *a.add(1);
            key[14] = *a.add(2);
            key[15] = *a.add(3);
        } else {
            let mut k = 0;
            while k < 16 {
                key[k] = *a.add(k);
                k += 1;
            }
        }
        let mut pos = 0;
        while pos < f.len {
            let mut end = pos;
            while end < f.len && *f.ptr.add(end) != b'\n' {
                end += 1;
            }
            let mut le = end;
            let mut c = pos;
            while c < end {
                if *f.ptr.add(c) == b'#' {
                    le = c;
                    break;
                }
                c += 1;
            }
            let mut q = pos;
            while q < le && !is_space(*f.ptr.add(q)) {
                q += 1;
            }
            if q < le {
                let alen = q - pos;
                let mut tok = [0i8; 64];
                if alen < 64 {
                    let mut t = 0;
                    while t < alen {
                        tok[t] = *f.ptr.add(pos + t) as i8;
                        t += 1;
                    }
                    tok[alen] = 0;
                    let mut fam = 0;
                    let mut sc = 0;
                    let mut tmp = [0u8; 16];
                    if lookup_ipliteral_into(
                        tok.as_ptr(),
                        alen,
                        AF_UNSPEC,
                        &mut fam,
                        tmp.as_mut_ptr(),
                        &mut sc,
                    ) > 0
                    {
                        let mut cmp = [0u8; 16];
                        if fam == AF_INET {
                            cmp[0..10].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
                            cmp[10] = 0xff;
                            cmp[11] = 0xff;
                            cmp[12..16].copy_from_slice(&tmp[0..4]);
                            sc = 0;
                        } else {
                            cmp.copy_from_slice(&tmp);
                        }
                        if cmp == key && sc == scopeid {
                            let mut n = q;
                            while n < le && is_space(*f.ptr.add(n)) {
                                n += 1;
                            }
                            let mut z = n;
                            while z < le && !is_space(*f.ptr.add(z)) {
                                z += 1;
                            }
                            if z > n && z - n < 256 {
                                let mut t = 0;
                                while t <= z - n {
                                    *buf.add(t) = *f.ptr.add(n + t) as c_char;
                                    t += 1;
                                }
                                free_file(f);
                                return;
                            }
                        }
                    }
                }
            }
            pos = if end < f.len { end + 1 } else { end };
        }
        free_file(f);
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn reverse_services(buf: *mut c_char, port: u16, dgram: bool) -> bool {
    unsafe {
        let f = read_file(c"/etc/services".as_ptr());
        if !f.ptr.is_null() {
            let mut pos = 0;
            while pos < f.len {
                let mut end = pos;
                while end < f.len && *f.ptr.add(end) != b'\n' {
                    end += 1;
                }
                let mut le = end;
                let mut c = pos;
                while c < end {
                    if *f.ptr.add(c) == b'#' {
                        le = c;
                        break;
                    }
                    c += 1;
                }
                let mut q = pos;
                while q < le && !is_space(*f.ptr.add(q)) {
                    q += 1;
                }
                if q < le && q - pos <= 32 {
                    let mut r = q;
                    while r < le && is_space(*f.ptr.add(r)) {
                        r += 1;
                    }
                    let mut v = 0u32;
                    let mut digits = 0;
                    while r < le && is_digit(*f.ptr.add(r)) {
                        v = v * 10 + (*f.ptr.add(r) - b'0') as u32;
                        r += 1;
                        digits += 1;
                    }
                    if digits > 0 && v == port as u32 {
                        let want = if dgram { b"/udp" } else { b"/tcp" };
                        if r + 4 <= le
                            && *f.ptr.add(r) == want[0]
                            && *f.ptr.add(r + 1) == want[1]
                            && *f.ptr.add(r + 2) == want[2]
                            && *f.ptr.add(r + 3) == want[3]
                        {
                            let mut t = 0;
                            while t < q - pos {
                                *buf.add(t) = *f.ptr.add(pos + t) as c_char;
                                t += 1;
                            }
                            *buf.add(q - pos) = 0;
                            free_file(f);
                            return true;
                        }
                    }
                }
                pos = if end < f.len { end + 1 } else { end };
            }
            free_file(f);
        }
        // Builtin fallback (same table as lookup path).
        let mut b = 0;
        while b < BUILTIN_SERVS.len() {
            if BUILTIN_SERVS[b].1 == port {
                let nm = BUILTIN_SERVS[b].0;
                let mut t = 0;
                while t < nm.len() {
                    *buf.add(t) = nm[t] as c_char;
                    t += 1;
                }
                *buf.add(nm.len()) = 0;
                return true;
            }
            b += 1;
        }
        false
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn ptr_record_cb(
    ctx: *mut c_void,
    rr: c_int,
    data: *const u8,
    _len: c_int,
    pkt: *const u8,
    plen: c_int,
) -> c_int {
    unsafe {
        if rr != 12 {
            return 0;
        }
        if dn_expand_inner(pkt, pkt.add(plen as usize), data, ctx as *mut c_char, 256) <= 0 {
            *(ctx as *mut c_char) = 0;
        }
        0
    }
}

/// musl `getnameinfo`.
/// # Safety
/// `sa` readable for `sl`; `node`/`serv` writable for their lengths.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getnameinfo(
    sa: *const SockAddr,
    sl: u32,
    node: *mut c_char,
    nodelen: u32,
    serv: *mut c_char,
    servlen: u32,
    flags: c_int,
) -> c_int {
    unsafe {
        if sa.is_null() {
            return EAI_FAMILY;
        }
        let af = (*sa).sa_family as c_int;
        let (a, scopeid) = match af {
            AF_INET => {
                if sl < size_of::<SockAddrIn>() as u32 {
                    return EAI_FAMILY;
                }
                let s = sa as *const SockAddrIn;
                (&(*s).sin_addr as *const u32 as *const u8, 0u32)
            }
            AF_INET6 => {
                if sl < size_of::<SockAddrIn6>() as u32 {
                    return EAI_FAMILY;
                }
                let s = sa as *const SockAddrIn6;
                ((*s).sin6_addr.as_ptr(), (*s).sin6_scope_id)
            }
            _ => return EAI_FAMILY,
        };
        if !node.is_null() && nodelen > 0 {
            let mut buf = [0i8; 256];
            buf[0] = 0;
            if flags & NI_NUMERICHOST == 0 {
                reverse_hosts(buf.as_mut_ptr(), a, scopeid, af);
            }
            if buf[0] == 0 && flags & NI_NUMERICHOST == 0 {
                // DNS PTR query (musl shape).
                let mut ptr = [0i8; 80];
                if af == AF_INET {
                    let b = [*a.add(0), *a.add(1), *a.add(2), *a.add(3)];
                    let mut p = 0;
                    let mut i = 3i32;
                    while i >= 0 {
                        p += fmt_u32(
                            b[i as usize] as u32,
                            ptr.as_mut_ptr().add(p) as *mut u8,
                            80 - p - 14,
                        );
                        ptr[p] = b'.' as c_char;
                        p += 1;
                        i -= 1;
                    }
                    let suf = b"in-addr.arpa";
                    let mut t = 0;
                    while t < suf.len() {
                        ptr[p] = suf[t] as c_char;
                        p += 1;
                        t += 1;
                    }
                    ptr[p] = 0;
                } else {
                    // v4-mapped v6 answers via the v4 suffix (musl shape).
                    let mut v4 = false;
                    let mut k = 0;
                    while k < 12 {
                        let want = if k < 10 { 0 } else { 0xff };
                        if *a.add(k) != want {
                            break;
                        }
                        k += 1;
                    }
                    if k == 12 {
                        let b = [*a.add(12), *a.add(13), *a.add(14), *a.add(15)];
                        let mut p = 0;
                        let mut i = 3i32;
                        while i >= 0 {
                            p += fmt_u32(
                                b[i as usize] as u32,
                                ptr.as_mut_ptr().add(p) as *mut u8,
                                80 - p - 14,
                            );
                            ptr[p] = b'.' as c_char;
                            p += 1;
                            i -= 1;
                        }
                        let suf = b"in-addr.arpa";
                        let mut t = 0;
                        while t < suf.len() {
                            ptr[p] = suf[t] as c_char;
                            p += 1;
                            t += 1;
                        }
                        ptr[p] = 0;
                        v4 = true;
                    }
                    if !v4 {
                        let xd = b"0123456789abcdef";
                        let mut p = 0;
                        let mut i = 15i32;
                        while i >= 0 {
                            ptr[p] = xd[(*a.add(i as usize) & 15) as usize] as c_char;
                            ptr[p + 1] = b'.' as c_char;
                            ptr[p + 2] = xd[(*a.add(i as usize) >> 4) as usize] as c_char;
                            ptr[p + 3] = b'.' as c_char;
                            p += 4;
                            i -= 1;
                        }
                        let suf = b"ip6.arpa";
                        let mut t = 0;
                        while t < suf.len() {
                            ptr[p] = suf[t] as c_char;
                            p += 1;
                            t += 1;
                        }
                        ptr[p] = 0;
                    }
                    let _ = v4;
                }
                let pl = cstrlen(ptr.as_ptr());
                let mut q = [0u8; 110];
                let ql = mkquery_inner(0, ptr.as_ptr(), pl, 1, 12, q.as_mut_ptr(), q.len());
                if ql > 0 {
                    let mut reply = [0u8; 512];
                    let r = res_send(q.as_ptr(), ql, reply.as_mut_ptr(), 512);
                    if r > 0 {
                        let rl = if r as usize > 512 { 512 } else { r as usize };
                        buf[0] = 0;
                        dns_parse_inner(
                            reply.as_ptr(),
                            rl as c_int,
                            ptr_record_cb,
                            buf.as_mut_ptr() as *mut c_void,
                        );
                    }
                }
            }
            if buf[0] == 0 {
                if flags & NI_NAMEREQD != 0 {
                    return EAI_NONAME;
                }
                let ok = if af == AF_INET {
                    ntop4(a, buf.as_mut_ptr(), 256)
                } else {
                    ntop6(a, buf.as_mut_ptr(), 256)
                };
                if !ok {
                    return EAI_OVERFLOW;
                }
                if scopeid != 0 {
                    // Numeric scope (no if_indextoname yet).
                    let mut bl = cstrlen(buf.as_ptr());
                    if bl + 12 >= 256 {
                        return EAI_OVERFLOW;
                    }
                    buf[bl] = b'%' as c_char;
                    bl += 1;
                    bl += fmt_u32(scopeid, buf.as_mut_ptr().add(bl) as *mut u8, 256 - bl - 1);
                    buf[bl] = 0;
                }
            }
            let bl = cstrlen(buf.as_ptr());
            if bl as u32 >= nodelen {
                return EAI_OVERFLOW;
            }
            let mut k = 0;
            while k <= bl {
                *node.add(k) = buf[k];
                k += 1;
            }
        }
        if !serv.is_null() && servlen > 0 {
            let port = u16::from_be((*(sa as *const SockAddrIn)).sin_port);
            let mut buf = [0i8; 32];
            buf[0] = 0;
            if flags & NI_NUMERICSERV == 0 {
                reverse_services(buf.as_mut_ptr(), port, flags & NI_DGRAM != 0);
            }
            if buf[0] == 0 {
                let n = fmt_u32(port as u32, buf.as_mut_ptr() as *mut u8, 31);
                buf[n] = 0;
            }
            let bl = cstrlen(buf.as_ptr());
            if bl as u32 >= servlen {
                return EAI_OVERFLOW;
            }
            let mut k = 0;
            while k <= bl {
                *serv.add(k) = buf[k];
                k += 1;
            }
        }
        0
    }
}

// ---- legacy gethostby* (musl gethostbyname2_r.c, gethostbyaddr_r.c, …) --------
/// musl `gethostbyname2_r`.
/// # Safety
/// `h`/`buf`(`buflen`)/`res`/`err` form musl's caller-buffer contract.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn gethostbyname2_r(
    name: *const c_char,
    af: c_int,
    h: *mut Hostent,
    buf: *mut c_char,
    buflen: usize,
    res: *mut *mut Hostent,
    err: *mut c_int,
) -> c_int {
    unsafe {
        if res.is_null() || err.is_null() || h.is_null() || buf.is_null() || name.is_null() {
            return EINVAL;
        }
        *res = null_mut();
        if af != AF_INET && af != AF_INET6 {
            *err = NO_RECOVERY;
            return EINVAL;
        }
        let nlen = cstrlen(name);
        let mut addrs = [Address {
            family: 0,
            scopeid: 0,
            addr: [0; 16],
        }; MAXADDRS];
        let mut canon = [0i8; 256];
        let cnt = lookup_name_inner(
            addrs.as_mut_ptr(),
            canon.as_mut_ptr(),
            name,
            af,
            AI_CANONNAME,
        );
        if cnt < 0 {
            match cnt {
                EAI_NONAME => {
                    *err = HOST_NOT_FOUND;
                    return 0;
                }
                EAI_NODATA => {
                    *err = NO_DATA;
                    return 0;
                }
                EAI_AGAIN => {
                    *err = TRY_AGAIN;
                    return EAGAIN;
                }
                EAI_SYSTEM => {
                    *err = NO_RECOVERY;
                    return last_errno();
                }
                _ => {
                    *err = NO_RECOVERY;
                    return EBADMSG;
                }
            }
        }
        let hlen = if af == AF_INET6 { 16 } else { 4 };
        let align = ((buf as usize).wrapping_neg()) & (size_of::<*mut c_char>() - 1);
        let canon_len = cstrlen(canon.as_ptr());
        let need = 4 * size_of::<*mut c_char>()
            + (cnt as usize + 1) * (size_of::<*mut c_char>() + hlen)
            + nlen
            + 1
            + canon_len
            + 1
            + align;
        if need > buflen {
            return ERANGE;
        }
        let mut p = buf.add(align);
        (*h).h_addrtype = af;
        (*h).h_length = hlen as c_int;
        (*h).h_aliases = p as *mut *mut c_char;
        p = p.add(3 * size_of::<*mut c_char>());
        (*h).h_addr_list = p as *mut *mut c_char;
        p = p.add((cnt as usize + 1) * size_of::<*mut c_char>());
        let mut i = 0;
        while i < cnt as usize {
            *(*h).h_addr_list.add(i) = p;
            let off = 0;
            let mut t = 0;
            while t < hlen {
                *p.add(t) = addrs[i].addr[off + t] as c_char;
                t += 1;
            }
            p = p.add(hlen);
            i += 1;
        }
        *(*h).h_addr_list.add(i) = null_mut();
        (*h).h_name = p;
        *(*h).h_aliases.add(0) = p;
        let mut t = 0;
        while t <= canon_len {
            *p.add(t) = canon[t];
            t += 1;
        }
        p = p.add(canon_len + 1);
        // Alias = queried name when it differs from canon.
        let mut same = canon_len == nlen;
        if same {
            let mut t = 0;
            while t < nlen {
                if *name.add(t) != canon[t] {
                    same = false;
                    break;
                }
                t += 1;
            }
        }
        if !same {
            *(*h).h_aliases.add(1) = p;
            let mut t = 0;
            while t <= nlen {
                *p.add(t) = *name.add(t);
                t += 1;
            }
        } else {
            *(*h).h_aliases.add(1) = null_mut();
        }
        *(*h).h_aliases.add(2) = null_mut();
        *res = h;
        0
    }
}

/// musl `gethostbyname_r` (thin wrapper over AF_INET).
/// # Safety
/// Same contract as [`gethostbyname2_r`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn gethostbyname_r(
    name: *const c_char,
    h: *mut Hostent,
    buf: *mut c_char,
    buflen: usize,
    res: *mut *mut Hostent,
    err: *mut c_int,
) -> c_int {
    unsafe { gethostbyname2_r(name, AF_INET, h, buf, buflen, res, err) }
}

#[cfg(target_arch = "x86_64")]
static mut HOST_BUF: *mut Hostent = null_mut();

/// Shared growable-static engine for `gethostbyname`/`gethostbyname2`
/// (musl `gethostbyname2.c`; static buffer, not thread-safe by design).
#[cfg(target_arch = "x86_64")]
unsafe fn hostbyname_static(name: *const c_char, af: c_int) -> *mut Hostent {
    unsafe {
        let mut size = 63usize;
        loop {
            crate::malloc::free(HOST_BUF as *mut c_void);
            HOST_BUF = crate::malloc::malloc(size + size + 1) as *mut Hostent;
            size = size * 2 + 1;
            if HOST_BUF.is_null() {
                set_h_errno(NO_RECOVERY);
                return null_mut();
            }
            let total = size - size_of::<Hostent>();
            let mut res: *mut Hostent = null_mut();
            let err = gethostbyname2_r(
                name,
                af,
                HOST_BUF,
                (HOST_BUF as *mut u8).add(size_of::<Hostent>()) as *mut c_char,
                total,
                &mut res as *mut *mut Hostent,
                core::ptr::addr_of_mut!(h_errno),
            );
            if err != ERANGE {
                return res;
            }
        }
    }
}

/// musl `gethostbyname2` (static buffer; NOT thread-safe, see module docs).
/// # Safety
/// `name` NUL-terminated; returned pointer is a shared static.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn gethostbyname2(name: *const c_char, af: c_int) -> *mut Hostent {
    unsafe {
        if name.is_null() {
            return null_mut();
        }
        hostbyname_static(name, af)
    }
}

/// musl `gethostbyname` (static buffer; NOT thread-safe, see module docs).
/// # Safety
/// `name` NUL-terminated; returned pointer is a shared static.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn gethostbyname(name: *const c_char) -> *mut Hostent {
    unsafe {
        if name.is_null() {
            return null_mut();
        }
        hostbyname_static(name, AF_INET)
    }
}

/// musl `gethostbyaddr_r`.
/// # Safety
/// `a` readable for `l`; `h`/`buf`(`buflen`)/`res`/`err` caller-buffer contract.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn gethostbyaddr_r(
    a: *const c_void,
    l: u32,
    af: c_int,
    h: *mut Hostent,
    buf: *mut c_char,
    buflen: usize,
    res: *mut *mut Hostent,
    err: *mut c_int,
) -> c_int {
    unsafe {
        if res.is_null() || err.is_null() || h.is_null() || buf.is_null() || a.is_null() {
            return EINVAL;
        }
        *res = null_mut();
        let (len_ok, sl) = if af == AF_INET6 && l == 16 {
            (true, size_of::<SockAddrIn6>() as u32)
        } else if af == AF_INET && l == 4 {
            (true, size_of::<SockAddrIn>() as u32)
        } else {
            *err = NO_RECOVERY;
            return EINVAL;
        };
        let _ = (len_ok, sl);
        let align_gap =
            size_of::<*mut c_char>() - ((buf as usize) & (size_of::<*mut c_char>() - 1));
        if buflen <= 5 * size_of::<*mut c_char>() - align_gap + l as usize {
            return ERANGE;
        }
        let mut p = buf.add(align_gap);
        let left = buflen - (5 * size_of::<*mut c_char>() - align_gap + l as usize);
        (*h).h_addr_list = p as *mut *mut c_char;
        p = p.add(2 * size_of::<*mut c_char>());
        (*h).h_aliases = p as *mut *mut c_char;
        p = p.add(2 * size_of::<*mut c_char>());
        *(*h).h_addr_list.add(0) = p;
        let mut t = 0;
        while t < l as usize {
            *p.add(t) = *(a as *const u8).add(t) as c_char;
            t += 1;
        }
        p = p.add(l as usize);
        *(*h).h_addr_list.add(1) = null_mut();
        *(*h).h_aliases.add(0) = p;
        *(*h).h_aliases.add(1) = null_mut();
        // Resolve through getnameinfo (musl shape).
        let r = if af == AF_INET {
            let sin = SockAddrIn {
                sin_family: AF_INET as u16,
                sin_port: 0,
                sin_addr: (*(a as *const u32)),
                sin_zero: [0; 8],
            };
            getnameinfo(
                &sin as *const SockAddrIn as *const SockAddr,
                size_of::<SockAddrIn>() as u32,
                p,
                left as u32,
                null_mut(),
                0,
                0,
            )
        } else {
            let mut sin6 = SockAddrIn6 {
                sin6_family: AF_INET6 as u16,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: [0; 16],
                sin6_scope_id: 0,
            };
            let mut t = 0;
            while t < 16 {
                sin6.sin6_addr[t] = *(a as *const u8).add(t);
                t += 1;
            }
            getnameinfo(
                &sin6 as *const SockAddrIn6 as *const SockAddr,
                size_of::<SockAddrIn6>() as u32,
                p,
                left as u32,
                null_mut(),
                0,
                0,
            )
        };
        let _ = left;
        match r {
            EAI_AGAIN => {
                *err = TRY_AGAIN;
                return EAGAIN;
            }
            EAI_OVERFLOW => return ERANGE,
            EAI_SYSTEM => {
                *err = NO_RECOVERY;
                return last_errno();
            }
            0 => {}
            _ => {
                *err = NO_RECOVERY;
                return EBADMSG;
            }
        }
        (*h).h_addrtype = af;
        (*h).h_length = l as c_int;
        (*h).h_name = *(*h).h_aliases.add(0);
        *res = h;
        0
    }
}

/// musl `gethostbyaddr` (static buffer; NOT thread-safe, see module docs).
/// # Safety
/// `a` readable for `l`; returned pointer is a shared static.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn gethostbyaddr(a: *const c_void, l: u32, af: c_int) -> *mut Hostent {
    unsafe {
        if a.is_null() {
            return null_mut();
        }
        let mut size = 63usize;
        loop {
            crate::malloc::free(HOST_BUF as *mut c_void);
            HOST_BUF = crate::malloc::malloc(size + size + 1) as *mut Hostent;
            size = size * 2 + 1;
            if HOST_BUF.is_null() {
                set_h_errno(NO_RECOVERY);
                return null_mut();
            }
            let total = size - size_of::<Hostent>();
            let mut res: *mut Hostent = null_mut();
            let err = gethostbyaddr_r(
                a,
                l,
                af,
                HOST_BUF,
                (HOST_BUF as *mut u8).add(size_of::<Hostent>()) as *mut c_char,
                total,
                &mut res as *mut *mut Hostent,
                core::ptr::addr_of_mut!(h_errno),
            );
            if err != ERANGE {
                return res;
            }
        }
    }
}

// ---- getservby* (musl getservbyname_r.c, getservbyport_r.c, …) ----------------
#[cfg(target_arch = "x86_64")]
static TCP_STR: &[u8] = b"tcp\0";
#[cfg(target_arch = "x86_64")]
static UDP_STR: &[u8] = b"udp\0";

/// musl `getservbyname_r` (numeric strings are not service records).
/// # Safety
/// `se`/`buf`(`buflen`)/`res` form musl's caller-buffer contract.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getservbyname_r(
    name: *const c_char,
    prots: *const c_char,
    se: *mut Servent,
    buf: *mut c_char,
    buflen: usize,
    res: *mut *mut Servent,
) -> c_int {
    unsafe {
        if res.is_null() || se.is_null() || name.is_null() {
            return EINVAL;
        }
        *res = null_mut();
        let nl = cstrlen(name);
        let mut alldig = nl > 0;
        let mut k = 0;
        while k < nl {
            if !is_digit(*name.add(k) as u8) {
                alldig = false;
                break;
            }
            k += 1;
        }
        if alldig {
            return ENOENT;
        }
        let align = ((buf as usize).wrapping_neg()) & 7;
        if buflen < 2 * size_of::<*mut c_char>() + align {
            return ERANGE;
        }
        let proto = if prots.is_null() {
            0
        } else if cstr_eq(prots, b"tcp") {
            IPPROTO_TCP
        } else if cstr_eq(prots, b"udp") {
            IPPROTO_UDP
        } else {
            return EINVAL;
        };
        let mut servs = [Service {
            port: 0,
            proto: 0,
            socktype: 0,
        }; MAXSERVS];
        // socktype 0: fills tcp+udp entries (name is non-numeric here).
        let cnt = lookup_serv_inner(servs.as_mut_ptr(), name, proto, 0, 0);
        if cnt < 0 {
            match cnt {
                EAI_MEMORY | EAI_SYSTEM => return ENOMEM,
                _ => return ENOENT,
            }
        }
        if cnt == 0 {
            return ENOENT;
        }
        (*se).s_name = name as *mut c_char;
        (*se).s_aliases = buf.add(align) as *mut *mut c_char;
        *(*se).s_aliases.add(0) = (*se).s_name;
        *(*se).s_aliases.add(1) = null_mut();
        (*se).s_port = (servs[0].port as c_int).to_be();
        (*se).s_proto = if servs[0].proto == IPPROTO_TCP as u8 {
            TCP_STR.as_ptr() as *mut c_char
        } else {
            UDP_STR.as_ptr() as *mut c_char
        };
        *res = se;
        0
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn cstr_eq(s: *const c_char, lit: &[u8]) -> bool {
    unsafe {
        // lit without trailing NUL.
        let mut k = 0;
        while k < lit.len() {
            if *s.add(k) != lit[k] as c_char {
                return false;
            }
            k += 1;
        }
        *s.add(lit.len()) == 0
    }
}

/// musl `getservbyport_r` (resolves the name through reverse lookup).
/// # Safety
/// `se`/`buf`(`buflen`)/`res` form musl's caller-buffer contract.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getservbyport_r(
    port: c_int,
    prots: *const c_char,
    se: *mut Servent,
    buf: *mut c_char,
    buflen: usize,
    res: *mut *mut Servent,
) -> c_int {
    unsafe {
        if res.is_null() || se.is_null() {
            return EINVAL;
        }
        if prots.is_null() {
            let r = getservbyport_r(
                port,
                TCP_STR.as_ptr() as *const c_char,
                se,
                buf,
                buflen,
                res,
            );
            if r != 0 {
                return getservbyport_r(
                    port,
                    UDP_STR.as_ptr() as *const c_char,
                    se,
                    buf,
                    buflen,
                    res,
                );
            }
            return r;
        }
        *res = null_mut();
        let gap = size_of::<*mut c_char>() - ((buf as usize) & (size_of::<*mut c_char>() - 1));
        if buflen <= 3 * size_of::<*mut c_char>() - gap {
            return ERANGE;
        }
        let mut p = buf.add(gap);
        let mut left = buflen - gap;
        if !cstr_eq(prots, b"tcp") && !cstr_eq(prots, b"udp") {
            return EINVAL;
        }
        (*se).s_port = port;
        (*se).s_proto = prots as *mut c_char;
        (*se).s_aliases = p as *mut *mut c_char;
        p = p.add(2 * size_of::<*mut c_char>());
        left -= 2 * size_of::<*mut c_char>();
        *(*se).s_aliases.add(1) = null_mut();
        *(*se).s_aliases.add(0) = p;
        (*se).s_name = p;
        let sin = SockAddrIn {
            sin_family: AF_INET as u16,
            sin_port: port as u16,
            sin_addr: 0,
            sin_zero: [0; 8],
        };
        let dgram = cstr_eq(prots, b"udp");
        let r = getnameinfo(
            &sin as *const SockAddrIn as *const SockAddr,
            size_of::<SockAddrIn>() as u32,
            null_mut(),
            0,
            p,
            left as u32,
            if dgram { NI_DGRAM } else { 0 },
        );
        match r {
            EAI_MEMORY | EAI_SYSTEM => return ENOMEM,
            EAI_OVERFLOW => return ERANGE,
            0 => {}
            _ => return ENOENT,
        }
        // A numeric port string is not a service record (musl shape).
        let mut v = 0u32;
        let mut k = 0;
        let bl = cstrlen(p);
        while k < bl {
            let b = *p.add(k) as u8;
            if !is_digit(b) {
                break;
            }
            v = v * 10 + (b - b'0') as u32;
            k += 1;
        }
        if k == bl && bl > 0 && v == u16::from_be(port as u16) as u32 {
            return ENOENT;
        }
        *res = se;
        0
    }
}

#[cfg(target_arch = "x86_64")]
static mut SERV_STATIC: Servent = Servent {
    s_name: null_mut(),
    s_aliases: null_mut(),
    s_port: 0,
    s_proto: null_mut(),
};
#[cfg(target_arch = "x86_64")]
static mut SERV_ALIASES: [*mut c_char; 2] = [null_mut(); 2];
#[cfg(target_arch = "x86_64")]
static mut SERV_NAMEBUF: [c_char; 32] = [0; 32];

/// musl `getservbyname` (static buffer; NOT thread-safe, see module docs).
/// # Safety
/// `name`/`prots` NUL-terminated (prots nullable); shared static returned.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getservbyname(name: *const c_char, prots: *const c_char) -> *mut Servent {
    unsafe {
        if name.is_null() {
            return null_mut();
        }
        let mut res: *mut Servent = null_mut();
        let r = getservbyname_r(
            name,
            prots,
            core::ptr::addr_of_mut!(SERV_STATIC),
            core::ptr::addr_of_mut!(SERV_ALIASES).cast::<c_char>(),
            size_of::<[*mut c_char; 2]>(),
            &mut res as *mut *mut Servent,
        );
        if r != 0 {
            return null_mut();
        }
        res
    }
}

/// musl `getservbyport` (static buffer; NOT thread-safe, see module docs).
/// # Safety
/// `prots` NUL-terminated (nullable); shared static returned.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getservbyport(port: c_int, prots: *const c_char) -> *mut Servent {
    unsafe {
        let mut res: *mut Servent = null_mut();
        let r = getservbyport_r(
            port,
            prots,
            core::ptr::addr_of_mut!(SERV_STATIC),
            core::ptr::addr_of_mut!(SERV_NAMEBUF).cast::<c_char>(),
            32 * size_of::<c_char>(),
            &mut res as *mut *mut Servent,
        );
        if r != 0 {
            return null_mut();
        }
        res
    }
}

// ---- getprotoby* (musl proto.c: same static table) -----------------------------
#[cfg(target_arch = "x86_64")]
static PROTO_TABLE: &[(u8, &[u8])] = &[
    (0, b"ip"),
    (1, b"icmp"),
    (2, b"igmp"),
    (3, b"ggp"),
    (4, b"ipencap"),
    (5, b"st"),
    (6, b"tcp"),
    (8, b"egp"),
    (12, b"pup"),
    (17, b"udp"),
    (20, b"hmp"),
    (22, b"xns-idp"),
    (27, b"rdp"),
    (29, b"iso-tp4"),
    (36, b"xtp"),
    (37, b"ddp"),
    (38, b"idpr-cmtp"),
    (41, b"ipv6"),
    (43, b"ipv6-route"),
    (44, b"ipv6-frag"),
    (45, b"idrp"),
    (46, b"rsvp"),
    (47, b"gre"),
    (50, b"esp"),
    (51, b"ah"),
    (57, b"skip"),
    (58, b"ipv6-icmp"),
    (59, b"ipv6-nonxt"),
    (60, b"ipv6-opts"),
    (73, b"rspf"),
    (81, b"vmtp"),
    (89, b"ospf"),
    (94, b"ipip"),
    (98, b"encap"),
    (103, b"pim"),
    (255, b"raw"),
];

#[cfg(target_arch = "x86_64")]
static mut PROTO_IDX: usize = 0;
#[cfg(target_arch = "x86_64")]
static mut PROTO_CUR: Protoent = Protoent {
    p_name: null_mut(),
    p_aliases: null_mut(),
    p_proto: 0,
};
#[cfg(target_arch = "x86_64")]
static mut PROTO_ALIASES: [*mut c_char; 1] = [null_mut(); 1];
// NUL-terminated scratch for the current name (longest is "ipv6-nonxt").
#[cfg(target_arch = "x86_64")]
static mut PROTO_NAME: [c_char; 16] = [0; 16];

#[cfg(target_arch = "x86_64")]
unsafe fn proto_fill(i: usize) -> *mut Protoent {
    unsafe {
        let (num, nm) = PROTO_TABLE[i];
        let mut k = 0;
        while k < nm.len() {
            PROTO_NAME[k] = nm[k] as c_char;
            k += 1;
        }
        PROTO_NAME[nm.len()] = 0;
        PROTO_CUR.p_proto = num as c_int;
        PROTO_CUR.p_name = core::ptr::addr_of_mut!(PROTO_NAME).cast::<c_char>();
        PROTO_ALIASES[0] = null_mut();
        PROTO_CUR.p_aliases = core::ptr::addr_of_mut!(PROTO_ALIASES).cast::<*mut c_char>();
        core::ptr::addr_of_mut!(PROTO_CUR)
    }
}

/// musl `endprotoent` (reset the cursor).
///
/// # Safety
///
/// No pointers; resets a process-global cursor.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn endprotoent() {
    unsafe {
        PROTO_IDX = 0;
    }
}

/// musl `setprotoent` (`stayopen` ignored like musl).
/// # Safety
/// No-op cursor reset.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setprotoent(_stayopen: c_int) {
    unsafe {
        PROTO_IDX = 0;
    }
}

/// musl `getprotoent` (static; NOT thread-safe, see module docs).
/// # Safety
/// Returned pointer is a shared static.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getprotoent() -> *mut Protoent {
    unsafe {
        if PROTO_IDX >= PROTO_TABLE.len() {
            return null_mut();
        }
        let p = proto_fill(PROTO_IDX);
        PROTO_IDX += 1;
        p
    }
}

/// musl `getprotobyname`.
/// # Safety
/// `name` NUL-terminated; returned pointer is a shared static.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getprotobyname(name: *const c_char) -> *mut Protoent {
    unsafe {
        if name.is_null() {
            return null_mut();
        }
        endprotoent();
        loop {
            let p = getprotoent();
            if p.is_null() {
                return null_mut();
            }
            let pn = (*p).p_name;
            let mut k = 0;
            loop {
                let a = *name.add(k);
                let b = *pn.add(k);
                if a != b {
                    break;
                }
                if a == 0 {
                    return p;
                }
                k += 1;
            }
        }
    }
}

/// musl `getprotobynumber`.
/// # Safety
/// Returned pointer is a shared static.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getprotobynumber(num: c_int) -> *mut Protoent {
    unsafe {
        endprotoent();
        loop {
            let p = getprotoent();
            if p.is_null() {
                return null_mut();
            }
            if (*p).p_proto == num {
                return p;
            }
        }
    }
}
