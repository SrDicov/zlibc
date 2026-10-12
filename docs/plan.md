# zlibc — coordination plan

## Hard rules

1. Only two remote branches, ever as steady state: `main`, `testing`.
   Work branches `ws/<name>` live in local worktrees; they may be pushed
   to origin **transiently** to run CI (this machine has no Rust
   toolchain — CI is our only compiler) and are deleted after merge.
2. `main` only receives merges from `testing` with green CI. No direct
   commits to `main`.
3. `#![no_std]`, no `std`, no allocator until mallocng (Ola 4) exists.
4. Exact ABI: probe asserts are the source of truth.
5. GPL-3.0-only. Zero copied musl/glibc code: clean reimplementation.
   The probe reads headers but ships none.
6. Before proposing a merge: `cargo fmt --check`, `cargo clippy
   --all-targets -- -D warnings`, `cargo build` (host +
   `x86_64-unknown-linux-musl`), `cargo test` — all in CI.
7. One merge to `testing` = one push. After each push, check CI. If red,
   revert and hand the failure back to the owning subagent.

## Environment constraint (verified)

- Dev machine: Chimera Linux x86_64, `sh`, 2 cores, 3.8 GiB RAM,
  **no rustc/cargo, no `make` on PATH** (`~/.local/bin/make` wrapper),
  minimal userland (do not assume `grep`/`head` — prefer `git`/`gh`
  plumbing and POSIX `sh`). Nothing compiles locally; validation = CI.

## File ownership per wave

- `src/syscall.rs` → single owner per wave.
- `src/abi.rs` → single owner per wave; others propose patches.
- `src/lib.rs` → coordinator only; subagents propose assert/module lines.
- `build.rs` + `probe/probe.c` → single owner per wave.
- New modules (`src/ldso/`, `src/pthread/`, `src/stdio/`, `src/malloc/`,
  `src/errno.rs`, `src/symbols.rs`, …) → one subagent per file/dir.
- `.github/workflows/`, `docs/` → coordinator only.

## Wave 1 — close Phase 1 (x86_64)

Evidence correction: musl x86_64 provides `__syscall0..6`
(`arch/x86_64/syscall_arch.h`, 7 dispatchers, max 6 args). There is no
`__syscall7` on this arch — A1 implements `syscall4..6`, not `..7`.

### A1 — `syscall4..6` (owner: `src/syscall.rs`, worktree `../zlibc-a1`)
- Add `syscall4` (arg4 in `r10`), `syscall5` (`r8`), `syscall6` (`r9`),
  same `asm!` discipline as 0..3 (clobber `rcx`/`r11`, no `nomem`,
  no `preserves_flags`), each with `# Safety` docs (Clippy
  `-D warnings` requires them).
- Extend `__syscall!` with 5-, 6-, 7-token arms (n + 4..6 args).
- Report: symbols added, risks. No other files touched.

### A2 — types + real errno (owner: `src/abi.rs`, `src/errno.rs`,
### worktree `../zlibc-a2`)
- `src/abi.rs`: add arch-conditioned `pub type PthreadT`
  (musl `include/alltypes.h.in`: `unsigned long` vs `struct __pthread *`
  per arch; x86_64 uses the pointer form — verify against the probe,
  do not guess).
- New `src/errno.rs`: real `__errno_location` backed by
  `#[thread_local] static` + `UnsafeCell<c_int>`, `#[no_mangle]
  pub unsafe extern "C"`. Remove the `extern "C"` declaration in
  `src/syscall.rs` (coordinator applies; A2 proposes the patch).
- Probe: add `SIZE_PTHREAD_T` (+ any new type sizes) to
  `probe/probe.c`; propose the matching `lib.rs` assert lines for the
  coordinator to paste (A2 does NOT touch `src/lib.rs`, `build.rs`
  stays coordinator-owned this wave — probe.c edits go through
  coordinator review to keep the 37 green asserts intact).
- Report: offsets measured, TLS approach, risks.
- OUTCOME (CI-verified): `PthreadT` + `SIZE_PTHREAD_T` probe accepted
  (probe measured 38 values, asserts green). **But `#[thread_local]`
  is nightly-only (E0658, rust-lang/rust#29594) — it does NOT build on
  stable.** Real `__errno_location` DEFERRED to Wave 2/3, when zlibc
  owns TLS/TP setup. A2 merge reverted (`testing` reset to `cd1325f`,
  A1 re-merged solo); `ws/a2` branch kept for cherry-picking the good
  parts. Fixup workstream: `ws/a2f`.

### A3 — weak aliases (owner: `src/symbols.rs`, after A1+A2 green)
- `global_asm!` emitting `.weak` + `.set` (+ `.hidden` where musl
  hides) for the Phase-1 symbol list agreed from A1/A2 output
  (e.g. public `write` → hidden `__write` pattern).
- Propose a CI `nm`/`readelf` check step (coordinator owns
  `.github/workflows/`).
- Gate: expected symbols present with correct binding in CI log.

### Wave 1 gate
CI green on `testing` + extended asserts + `nm` output. Then merge
`testing → main`, tag `v0.1`.

CLOSED (v0.1): 38 probe values green; `syscall0..6` + `__syscall!`;
`getpid` functional test proves real dispatch; `weak_alias!` +
`___errno_location` alias proven by address-identity test. Advances:
compat ABI (1), 100% Rust no_std sin dependencias (2). Sin debilitar
ningún principio (revisión de cierre: 3 neutro, 4 sin bugs musl nuevos,
5/6/7/8 intactos). `__errno_location` real diferido a Ola 2/3 (E0658).

## Later waves (summary; contracts written before each launches)

- **Wave 2** — boot + ldso: B1 `src/start.rs` (`_start`, `__libc_start_main`,
  auxv, SSP, `struct __libc`, exit path); B2 `src/ldso/dso.rs` + hashes;
  B3 `src/ldso/reloc.rs`; B4 `src/panic.rs` + `src/mem/`.
  Gate: minimal dynamic binary + hello world linked against zlibc run.
- **Wave 3** — pthreads: C1 create/clone/TLS/`__unmapself`; C2 futex +
  sync (futex interface fixed first so C1/C2 parallelize); C3 synccall.
  Gate: N-thread + mutex/condvar test, no deadlocks.
- **Wave 4** — stdio, mallocng, libm, locale/network/misc, validation.
  Gate: hello + pthreads + malloc/stdio running, CI green on `main`.

## "100% done" criteria

- All public musl x86_64 symbols present with correct signature/ABI.
- Static + dynamic hello world and a pthreads binary run on zlibc.
- Probe asserts cover the whole musl `alltypes.h`.
- CI green on `main`.
