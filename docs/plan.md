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

## Wave 2 contract — boot + ldso (x86_64)

Wave goal line: esta ola avanza **compat ABI + POSIX** (arranque y carga
dinámica son contrato observable), sin comprometer los demás.

Evidence (all verified in /home/dicov/musl):
- `_start` asm: arch/x86_64/crt_arch.h (xor rbp, rdi=rsp, align rsp 16,
  call `_start_c`; also `.weak/.hidden _DYNAMIC` + lea — keep, documented).
- `_start_c(long *p)`: argc=p[0], argv=p+1, then
  `__libc_start_main(main, argc, argv, _init, _fini, 0)` (crt/crt1.c).
- `struct __libc` exact fields: src/internal/libc.h:20-31
  (can_do_threads, threaded, secure, need_locks, threads_minus_1,
  auxv, tls_head, tls_size/align/cnt, page_size, global_locale).
- `exit()` order: src/exit/exit.c — exit_lock CAS → `__funcs_on_exit()`
  → `__libc_exit_fini()` (fini_array) → `__stdio_exit()` → `_Exit()`.
  atexit/stdio hooks are WEAK dummies until Waves 3/4 define them.
- `struct dso` exact fields: ldso/dynlink.c:67-121 (x86_64: no
  DL_FDPIC → `base` first, `loadmap` pointer at tail; `buf[]` flex tail
  contributes 0 to sizeof — omit in Rust, assert still holds).
- `struct tls_module`: src/internal/libc.h:14-18
  (next, image, len, size, align, offset). Lives in `crate::ldso::dso`;
  B1 uses it only through that path.
- Hashes: `sysv_hash`/`gnu_hash` ldso/dynlink.c:241-264. Pure fns.
- SSP: `__stack_chk_guard` + `__init_ssp` in src/env/__stack_chk_fail.c
  (memcpy entropy bytes, else `addr*1103515245` fallback).
- Syscalls needed: SYS_exit=60, SYS_exit_group=231, SYS_mmap=9
  (arch/x86_64/bits/syscall.h.in). Hardcode `pub const` with TODO to
  generate from bits/, same as existing SYS_WRITE.
- Existing `#[panic_handler]` in src/lib.rs MOVES to B4's src/panic.rs
  (B4 proposes the lib.rs deletion patch; coordinator applies).

### B1 — src/start.rs (worktree ../zlibc-b1, owns src/start.rs)
`_start` (naked, replicates crt_arch.h), `_start_c`, `__libc_start_main`
(envp→auxv scan, `__hwcap`, `__init_ssp(AT_RANDOM)`, secure check per
src/env/__libc_start_main.c:42-43, populate `__libc`), `struct __libc`
mirror HERE (not abi.rs — avoids contention), `exit()` with
single-threaded `shortcut:` (no TID yet; full lock when pthreads land),
weak dummies for `__funcs_on_exit`/`__stdio_exit` via `weak_alias!`.
Tests: pure-fn auxv-scan tests only — never execute `_start`/`exit` in
tests. Proposes `pub mod start;` line for coordinator.

### B2 — src/ldso/ (worktree ../zlibc-b2, owns src/ldso/)
`src/ldso/mod.rs` + `src/ldso/dso.rs`: ELF64 repr(C) types as needed
(verify against musl include/elf.h), FULL `Dso` mirror + probe asserts
(B2 proposes probe.c lines + lib.rs asserts; coordinator applies),
`sysv_hash`/`gnu_hash` with hand-derived vectors (document derivation;
static fns in dynlink.c can't be probed and copying them into probe.c
would break the clean-room rule), DSO list wiring (next/prev), ELF
map/load populating dynv/syms/strings/hashtab via DT_* tags (mmap/open/
read via existing `__syscall!`). Relocation APPLICATION is B3, not B2.
Proposes `pub mod ldso;` line for coordinator.

### B4 — src/panic.rs + src/mem/ (worktree ../zlibc-b4, owns both)
Upgraded panic handler (fd-2 message via raw write + exit_group; fixed
stack buffer + core::fmt, no alloc), proposes lib.rs deletion patch for
the old `loop {}` handler. `memcpy`/`memmove`/`memset` with exact musl
signatures, correct byte loops + `shortcut:` (word-at-a-time when
measured, per principle 5). Tests call `crate::mem::*` directly
(never link against host symbols).

### B3 — src/ldso/reloc.rs (launches after B2 lands)
GOT/PLT RELATIVE relocs, lazy binding stubs, TLSDESC basics. Contract
written from B2's merged `Dso`. Not launched yet.

### Wave 2 gate
`cargo test` green + a follow-up wave boots a binary (full hello-world
runs when B3 + Wave 3 threads exist; this wave delivers the pieces).
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
