# zlibc

A from-scratch rewrite of [musl libc](https://musl.libc.org) in Rust —
an ABI-exact, drop-in replacement for `libc.so`, built `#![no_std]`.

> **Status: Phase 1 skeleton (x86_64).** The crate does not link or run
> yet. What exists today is the foundation everything else will stand on:
> ABI-mirrored types, raw syscall dispatch, and a build-time proof that
> the two agree with musl bit-for-bit.

## The one rule

**Every struct size and field offset is measured from the real musl
headers at build time, and the build fails if Rust disagrees.**

`build.rs` compiles `probe/probe.c` against genuine musl headers with
gcc (`-nostdinc -ffreestanding`, the same flags musl uses for itself),
extracts `sizeof`/`offsetof` for every mirrored field, and `src/lib.rs`
`static_assert`s each one against the `#[repr(C)]` types in
`src/abi.rs`. Layout drift is a compile error, not a debugging session.

## Layout

| Path | What |
|---|---|
| `src/lib.rs` | `#![no_std]` root + the compile-time ABI contract (asserts) |
| `src/abi.rs` | `#[repr(C)]` mirrors: `IoFile` (`struct _IO_FILE`), `PthreadHead` (pthread Parts 1+3; Part 2 is deliberately free — musl marks it non-ABI) |
| `src/syscall.rs` | Raw `syscall` dispatch (`syscall0..3`, `__syscall!`, `syscall_ret` errno translation) for x86_64 |
| `build.rs` | Generates `bits/alltypes.h` with musl's own `tools/mkalltypes.sed`, runs the probe, emits constants |
| `probe/probe.c` | `sizeof`/`offsetof` extraction against real musl headers |

## Build (CI does this; local build is optional)

Prerequisites: Rust stable (≥ 1.77, for `core::mem::offset_of!`), gcc,
and a musl source tree:

```bash
git clone https://github.com/SrDicov/musl.git ~/musl   # or upstream
export MUSL_SRC=~/musl                                  # default: /home/dicov/musl
cargo build
cargo build --target x86_64-unknown-linux-musl
cargo test
```

Every push and PR is built and tested on GitHub Actions (host build,
`x86_64-unknown-linux-musl` build, tests, Clippy, rustfmt) — see
`.github/workflows/ci.yml`.

## Design notes

- `compiler_builtins` is a foundational dependency: freestanding Rust
  needs compiler runtime helpers (`__udivti3`, …). Zero-dependency
  `no_std` is not a realistic goal for a libc.
- C `volatile int lock` stays a plain `c_int` field; volatility is
  enforced at access sites via volatile intrinsics, never by changing
  the layout type.
- Weak aliases and hidden visibility are emitted via `global_asm!`
  (`.weak` / `.set`) — documented in the architecture plan, not yet
  implemented.
- `pthread_t` and word-size types are per-arch `#[cfg]` by design,
  mirroring musl's `alltypes.h.in`.

## License

MIT — see [LICENSE](LICENSE). This is an independent reimplementation
inspired by musl's design; it contains no musl source code. The build
probe *reads* musl headers at compile time but ships no part of them.
