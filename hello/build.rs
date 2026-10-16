//! Scopes `-nostdlib` to this package's final binary links only.
//!
//! A workspace-wide `RUSTFLAGS`/config would poison the host build tools
//! too (a build script linked without start files has no `_start` and
//! faults at startup — observed in CI). `cargo:rustc-link-arg` from here
//! applies to hello's bins after this script runs, leaving every build
//! script and dependency link untouched.

fn main() {
    let libdir =
        std::env::var("ZLIBC_GATE_LIBDIR").unwrap_or_else(|_| "/tmp/zlibc-gate-deps".to_string());
    // Optional search path for gate binaries that carry a DT_NEEDED edge
    // to their own shared object; harmless on the regular hello bins.
    println!("cargo:rustc-link-search=native={libdir}");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{libdir}");
    println!("cargo:rustc-link-arg=-nostdlib");
}
