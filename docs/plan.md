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
## Wave 3 contract — pthreads + futex (x86_64)

Wave goal line: esta ola avanza **compat ABI + POSIX** (hilos y
sincronización son contrato POSIX observable), sin comprometer los demás.

Evidence (all verified in /home/dicov/musl):
- Mutex overlay: `_m_type=__i[0]`, `_m_lock=__vi[1]`, `_m_waiters=__vi[2]`,
  `_m_prev=__p[3]`, `_m_next=__p[4]`, `_m_count=__i[5]`
  (src/internal/pthread_impl.h:86-91); opaque size 40B
  (include/alltypes.h.in:87: int[10]/void*[5] on 64-bit).
- Cond overlay: `_c_shared=__p[0]`, `_c_seq=__vi[2]`, `_c_waiters=__vi[3]`,
  `_c_clock=__i[4]`, `_c_lock=__vi[8]`, `_c_head=__p[1]`, `_c_tail=__p[5]`
  (pthread_impl.h:92-97); opaque size 48B (alltypes.h.in:89).
- Lock encoding (src/thread/pthread_mutex_trylock.c:14-35): owner TID in
  low 30 bits (`& 0x3fffffff`), `MAYBE_WAITERS = 0x80000000`, robust bit
  `0x40000000`.
- `__wait` (src/thread/__wait.c): 100 spins → waiters++ → FUTEX_WAIT loop
  → waiters--, with ENOSYS fallback to non-PRIVATE.
- Futex ops (src/internal/futex.h): WAIT=0, WAKE=1, PRIVATE=128,
  CLOCK_REALTIME=256.
- Syscalls (arch/x86_64/bits/syscall.h.in): futex=202, clone=56,
  tkill=200, tgkill=234, set_tid_address=218, nanosleep=35.
- Clone flags (src/thread/pthread_create.c:243-245): VM|FS|FILES|SIGHAND|
  THREAD|SYSVSEM|SETTLS|PARENT_SETTID|CHILD_CLEARTID|DETACHED (all 10).
- SIGSYNCCALL=34 (pthread_impl.h:131); `__synccall` decl
  src/internal/libc.h:55.

### C2 — futex + mutex + condvar (worktree ../zlibc-c2, LAUNCHED EARLY)
Independent of B2/B3: touches only src/futex.rs + src/sync.rs (+ additive
probe lines). Needs only the existing `__syscall!` machinery.
- src/futex.rs: op consts, SYS_FUTEX=202, futex_wait/wake (private +
  shared), `__wait` equivalent (spins, waiters counting, ENOSYS fallback).
- src/sync.rs: `MutexT` = `[u64; 5]` + index accessors mirroring the
  `_m_*` macros; lock/unlock/trylock for NORMAL/RECURSIVE/ERRORCHECK;
  robust/PI/PP explicitly deferred with `shortcut:`.
  `CondT` = `[u64; 6]` + `_c_*` accessors; wait/signal/broadcast per musl
  src/thread/cnd_wait.c, cnd_signal.c, cnd_broadcast.c (C2 reads those
  files first); timedwait deferred with `shortcut:` (needs clock).
- Probe (additive): SIZE_MUTEX/SIZE_COND + OFF_M_*/OFF_C_* using musl's
  own index macros, e.g. `(size_t)&((pthread_mutex_t*)0)->_m_lock`
  (needs pthread_impl.h — already included in probe.c).
- Tests: threaded counter via std::thread + condvar rendezvous, calling
  `crate::` paths. NOTE (verified reasoning): our `#[no_mangle]`
  pthread_mutex_*/cond_* interpose host glibc symbols in the test binary,
  which is benign — std never calls pthread_mutex/cond internally
  (parking-lot-style atomics), and tests address our fns explicitly.
- Gate: counter + rendezvous green, no deadlocks.

### C1 — create/clone/TLS (launches after B2 merges; needs TlsModule path)
src/thread/: create.rs (mmap stack + mprotect guard + clone with all 10
flags; child trampoline mirroring src/thread/x86_64/clone.s — C1 reads it
first), tls.rs (TP setup per src/env/__init_tls.c + x86_64
set_thread_area mechanism — C1 reads those first), unmapself (naked
munmap+exit per arch asm), join/detach/self/equal minimum for the gate
test. Depends on merged B2 (`crate::ldso::dso::TlsModule`) and B4 mem.

### C3 — synccall (launches after C1; needs real threads + TIDs)
src/thread/synccall.rs: `__synccall` per musl src/thread/synccall.c (C3
verifies the filename first), SIGSYNCCALL handler, caller/target/exit
sems over C2 futex, atomics-only in handler (AS-safe). Depends on C1+C2.

### Wave 3 gate
N-thread counter + mutex/condvar rendezvous test green, then merge
`testing → main`, tag `v0.2`.
- **Wave 4** — stdio, mallocng, libm, locale/network/misc, validation.
  Gate: hello + pthreads + malloc/stdio running, CI green on `main`.

## "100% done" criteria

- All public musl x86_64 symbols present with correct signature/ABI.
- Static + dynamic hello world and a pthreads binary run on zlibc.
- Probe asserts cover the whole musl `alltypes.h`.
- CI green on `main`.
