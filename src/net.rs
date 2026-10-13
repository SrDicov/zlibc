//! D4 packet 2: thin socket syscall wrappers (no logic, no state).
//!
//! Each entry is one raw syscall returning the kernel result with errno
//! through the per-thread cell (`syscall_ret`), exactly musl's contract
//! at the ABI boundary (`src/network/*.c` are all thin like this).
//! Address structures stay behind raw pointers — layout work belongs to
//! a headers wave, behavior works today.

use core::ffi::{c_int, c_void};

use crate::syscall::{syscall2, syscall3, syscall4, syscall6, syscall_ret};

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_SOCKET: usize = 41; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_CONNECT: usize = 42; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_ACCEPT: usize = 43; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_SENDTO: usize = 44; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_RECVFROM: usize = 45; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_SHUTDOWN: usize = 48; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_BIND: usize = 49; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_LISTEN: usize = 50; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_GETSOCKNAME: usize = 51; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_GETPEERNAME: usize = 52; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_SOCKETPAIR: usize = 53; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_SETSOCKOPT: usize = 54; // TODO: generate from arch bits/syscall.h
#[cfg(target_arch = "x86_64")]
const SYS_GETSOCKOPT: usize = 55; // TODO: generate from arch bits/syscall.h
/// musl `include/sys/socket.h`.
pub const AF_UNIX: c_int = 1;
pub const SOCK_STREAM: c_int = 1;

/// Create an endpoint (musl `socket`).
///
/// # Safety
///
/// Pure syscall wrapper; no pointers involved.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn socket(domain: c_int, stype: c_int, protocol: c_int) -> c_int {
    unsafe {
        syscall_ret(syscall3(
            SYS_SOCKET,
            domain as usize,
            stype as usize,
            protocol as usize,
        )) as c_int
    }
}

/// Bind an address (musl `bind`).
///
/// # Safety
///
/// `addr` must point to `len` valid address bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn bind(fd: c_int, addr: *const c_void, len: u32) -> c_int {
    unsafe { syscall_ret(syscall3(SYS_BIND, fd as usize, addr as usize, len as usize)) as c_int }
}

/// Initiate a connection (musl `connect`).
///
/// # Safety
///
/// Same address contract as [`bind`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn connect(fd: c_int, addr: *const c_void, len: u32) -> c_int {
    unsafe {
        syscall_ret(syscall3(
            SYS_CONNECT,
            fd as usize,
            addr as usize,
            len as usize,
        )) as c_int
    }
}

/// Mark a socket passive (musl `listen`).
///
/// # Safety
///
/// `fd` must be a socket.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn listen(fd: c_int, backlog: c_int) -> c_int {
    unsafe { syscall_ret(syscall2(SYS_LISTEN, fd as usize, backlog as usize)) as c_int }
}

/// Accept a connection (musl `accept`).
///
/// # Safety
///
/// `addr`/`len` follow the `getsockname` contract (nullable pair).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn accept(fd: c_int, addr: *mut c_void, len: *mut u32) -> c_int {
    unsafe {
        syscall_ret(syscall3(
            SYS_ACCEPT,
            fd as usize,
            addr as usize,
            len as usize,
        )) as c_int
    }
}

/// Send a message (musl `sendto`; `send` = null address).
///
/// # Safety
///
/// `buf` readable for `len` bytes; address pair nullable together.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sendto(
    fd: c_int,
    buf: *const c_void,
    len: usize,
    flags: c_int,
    addr: *const c_void,
    alen: u32,
) -> isize {
    unsafe {
        syscall_ret(syscall6(
            SYS_SENDTO,
            fd as usize,
            buf as usize,
            len,
            flags as usize,
            addr as usize,
            alen as usize,
        ))
    }
}

/// Receive a message (musl `recvfrom`; `recv` = null address pair).
///
/// # Safety
///
/// `buf` writable for `len` bytes; `addr`/`len` nullable together.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn recvfrom(
    fd: c_int,
    buf: *mut c_void,
    len: usize,
    flags: c_int,
    addr: *mut c_void,
    alen: *mut u32,
) -> isize {
    unsafe {
        syscall_ret(syscall6(
            SYS_RECVFROM,
            fd as usize,
            buf as usize,
            len,
            flags as usize,
            addr as usize,
            alen as usize,
        ))
    }
}

/// Shut part of a connection (musl `shutdown`).
///
/// # Safety
///
/// `fd` must be a socket.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn shutdown(fd: c_int, how: c_int) -> c_int {
    unsafe { syscall_ret(syscall2(SYS_SHUTDOWN, fd as usize, how as usize)) as c_int }
}

/// Create a connected pair (musl `socketpair`).
///
/// # Safety
///
/// `fds` must hold two writable ints.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn socketpair(
    domain: c_int,
    stype: c_int,
    protocol: c_int,
    fds: *mut c_int,
) -> c_int {
    unsafe {
        syscall_ret(syscall4(
            SYS_SOCKETPAIR,
            domain as usize,
            stype as usize,
            protocol as usize,
            fds as usize,
        )) as c_int
    }
}

/// Set an option (musl `setsockopt`).
///
/// # Safety
///
/// `opt` readable for `len` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setsockopt(
    fd: c_int,
    level: c_int,
    name: c_int,
    opt: *const c_void,
    len: u32,
) -> c_int {
    unsafe {
        syscall_ret(syscall6(
            SYS_SETSOCKOPT,
            fd as usize,
            level as usize,
            name as usize,
            opt as usize,
            len as usize,
            0,
        )) as c_int
    }
}

/// Get an option (musl `getsockopt`).
///
/// # Safety
///
/// `opt`/`len` form a valid value-length pair.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getsockopt(
    fd: c_int,
    level: c_int,
    name: c_int,
    opt: *mut c_void,
    len: *mut u32,
) -> c_int {
    unsafe {
        syscall_ret(syscall6(
            SYS_GETSOCKOPT,
            fd as usize,
            level as usize,
            name as usize,
            opt as usize,
            len as usize,
            0,
        )) as c_int
    }
}

/// Local address of a socket (musl `getsockname`).
///
/// # Safety
///
/// `addr` writable for `*len` bytes; `len` readable/writable.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getsockname(fd: c_int, addr: *mut c_void, len: *mut u32) -> c_int {
    unsafe {
        syscall_ret(syscall3(
            SYS_GETSOCKNAME,
            fd as usize,
            addr as usize,
            len as usize,
        )) as c_int
    }
}

/// Peer address of a socket (musl `getpeername`).
///
/// # Safety
///
/// Same contract as [`getsockname`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getpeername(fd: c_int, addr: *mut c_void, len: *mut u32) -> c_int {
    unsafe {
        syscall_ret(syscall3(
            SYS_GETPEERNAME,
            fd as usize,
            addr as usize,
            len as usize,
        )) as c_int
    }
}

#[cfg(test)]
mod tests {
    use super::{recvfrom, sendto, socketpair, AF_UNIX, SOCK_STREAM};
    use core::ffi::{c_int, c_void};

    use crate::syscall::{syscall3, syscall_ret};

    /// musl `arch/x86_64/bits/syscall.h.in` (`SYS_close`, test cleanup).
    const SYS_CLOSE: usize = 3;

    unsafe fn close(fd: c_int) {
        unsafe {
            let _ = syscall_ret(syscall3(SYS_CLOSE, fd as usize, 0, 0));
        }
    }

    #[test]
    fn socketpair_send_recv_roundtrip() {
        unsafe {
            let mut fds = [0 as c_int; 2];
            assert_eq!(socketpair(AF_UNIX, SOCK_STREAM, 0, fds.as_mut_ptr()), 0);
            let msg = b"ping";
            assert_eq!(
                sendto(
                    fds[1],
                    msg.as_ptr() as *const c_void,
                    msg.len(),
                    0,
                    core::ptr::null(),
                    0
                ),
                msg.len() as isize
            );
            let mut back = [0u8; 8];
            assert_eq!(
                recvfrom(
                    fds[0],
                    back.as_mut_ptr() as *mut c_void,
                    back.len(),
                    0,
                    core::ptr::null_mut(),
                    core::ptr::null_mut()
                ),
                msg.len() as isize
            );
            assert_eq!(&back[..msg.len()], msg);
            close(fds[0]);
            close(fds[1]);
        }
    }
}
