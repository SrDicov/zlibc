//! Panic handler: report to fd 2 with raw syscalls, then exit the process.
//!
//! This replaces the `loop {}` placeholder in src/lib.rs (that file is
//! coordinator-owned; its deletion patch is proposed in the workstream
//! report, not applied here).
//!
//! Panic-time code trusts nothing but the kernel: no `syscall_ret` /
//! `__syscall!` (those store errno through `__errno_location`, which has
//! no real definition until TLS lands in Wave 2/3), no allocation, no
//! formatting machinery beyond `core::fmt` into a fixed-size stack
//! buffer. Behavior mirrors musl's fatal-error convention — a short
//! diagnostic to fd 2, then the whole process dies (cf. musl
//! src/env/__stack_chk_fail.c ending in process death, and
//! src/exit/exit.c routing it through `_Exit`, whose raw form here is
//! `exit_group` so every thread dies with us).

/// x86_64 `exit_group` (musl arch/x86_64/bits/syscall.h.in:232).
#[cfg(target_arch = "x86_64")]
pub const SYS_EXIT_GROUP: usize = 231; // TODO: generate from arch bits/syscall.h

/// Fixed-size stack buffer for the panic message (`core::fmt` target).
///
/// `write_str` copies what fits and silently drops the rest: the panic
/// path must never panic itself, so truncation beats unwrapping.
struct PanicMsg {
    buf: [u8; 256],
    len: usize,
}

impl core::fmt::Write for PanicMsg {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let room = self.buf.len() - self.len;
        let n = bytes.len().min(room);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        Ok(())
    }
}

// libtest provides its own handler under cfg(test); this gate keeps
// `cargo test` free of duplicate-`#[panic_handler]` errors.
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    #[cfg(target_arch = "x86_64")]
    {
        const PREFIX: &[u8] = b"zlibc panic: ";

        let mut msg = PanicMsg {
            buf: [0; 256],
            len: 0,
        };
        let _ = core::fmt::write(&mut msg, format_args!("{}\n", info.message()));

        // Raw syscalls only (see module docs for why errno is untouched).
        unsafe {
            let _ = crate::syscall::syscall3(
                crate::syscall::SYS_WRITE,
                2,
                PREFIX.as_ptr() as usize,
                PREFIX.len(),
            );
            let _ = crate::syscall::syscall3(
                crate::syscall::SYS_WRITE,
                2,
                msg.buf.as_ptr() as usize,
                msg.len,
            );
            // 101 matches the Rust `panic=unwind` default exit status.
            let _ = crate::syscall::syscall1(SYS_EXIT_GROUP, 101);
        }
    }
    loop {}
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use super::PanicMsg;

    /// A short message (the common panic case) lands whole in the buffer.
    #[test]
    fn short_message_fits_whole() {
        let mut msg = PanicMsg {
            buf: [0; 256],
            len: 0,
        };
        let _ = msg.write_str("boom\n");
        assert_eq!(&msg.buf[..msg.len], b"boom\n");
    }

    /// A huge message fills the buffer and drops the rest, no panic.
    #[test]
    fn long_message_truncates_without_panicking() {
        let mut msg = PanicMsg {
            buf: [0; 256],
            len: 0,
        };
        for _ in 0..64 {
            let _ = msg.write_str("0123456789abcdef");
        }
        assert_eq!(msg.len, 256);
        assert_eq!(&msg.buf[..16], b"0123456789abcdef");
    }
}
