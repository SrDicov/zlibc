//! Weak-alias support for ELF x86_64.
//!
//! Stable Rust cannot express musl's `weak_alias(old, new)` from musl
//! src/include/features.h:8-9
//! (`extern __typeof(old) new __attribute__((__weak__, __alias__(#old)))`),
//! so this module lowers the same idea to assembler directives (`.weak NEW`
//! plus `.set NEW, OLD`) emitted with `core::arch::global_asm!`, gated to
//! `target_arch = "x86_64"` (ELF-only directives).
//!
//! Exactly one musl-faithful pair is aliased here; later waves extend the
//! list once their target symbols are defined.

/// Define a weak ELF alias `$new` for the existing symbol `$old`.
///
/// Emits `.weak $new` + `.set $new, $old` via `core::arch::global_asm!`
/// (x86_64 only).
///
/// Argument order is `(new/alias, old/target)`, so the invocation below
/// reads swapped relative to musl's C macro, which takes `(old, new)`
/// (musl src/errno/__errno_location.c:9); the emitted directives carry the
/// identical meaning.
///
/// Export choice: `#[macro_export]` (crate root). A plain `macro_rules!`
/// macro without it would only be visible textually inside this module;
/// future users in other modules (e.g. a Wave 2/3 `errno.rs` defining
/// `__errno_location`) reach it as `crate::weak_alias!` with no
/// `#[macro_use]` wiring, which the coordinator-owned `src/lib.rs` never
/// needs to provide.
#[cfg(target_arch = "x86_64")]
#[macro_export]
macro_rules! weak_alias {
    ($new:ident, $old:ident) => {
        core::arch::global_asm!(concat!(
            ".weak ",
            stringify!($new),
            "\n.set ",
            stringify!($new),
            ", ",
            stringify!($old),
            "\n"
        ));
    };
}

// The `___errno_location` weak alias is NOT emitted here: a `.set` to an
// externally-defined target leaves no linkable weak record with this
// toolchain's assembler (proven by link failure in CI), so
// `crate::errno` defines it as a forwarding function instead. The
// `weak_alias!` macro above stays for the boot-hook aliases in
// `crate::start` (presence verification deferred to the first real
// link).
