//! Unwinder personality stub for `-nostdlib` + `panic=abort` bins.
//!
//! Prebuilt `core` objects reference `rust_eh_personality`, and
//! `-nostdlib` drops the library that would otherwise provide it. Under
//! `panic=abort` it is unreachable; shared here (never in the lib) so a
//! future unwinding world still gets a link error instead of a silent
//! abort.

/// See module docs.
#[no_mangle]
pub extern "C" fn rust_eh_personality() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
