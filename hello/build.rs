//! Scopes `-nostdlib` to this package's final binary links only.
//!
//! A workspace-wide `RUSTFLAGS`/config would poison the host build tools
//! too (a build script linked without start files has no `_start` and
//! faults at startup — observed in CI). `cargo:rustc-link-arg` from here
//! applies to hello's bins after this script runs, leaving every build
//! script and dependency link untouched.

fn main() {
    println!("cargo:rustc-link-arg=-nostdlib");
}
