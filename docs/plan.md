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
  stable.** Interim resolution: `src/errno.rs` now holds a
  process-global cell (`shortcut:`) — observationally identical with no
  threads, and it makes the weak alias + `syscall_ret` path fully
  functional and host-independent. Wave 3 REPLACES its body with the
  TP-based version (never a second definition — that would be a
  duplicate symbol); `ws/a2` branch kept for the `PthreadT` history.
  Fixup workstream: `ws/a2f`.

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

### B3 — src/ldso/reloc.rs (launches after B2 merges; needs `Dso`)
New file, exclusively B3's. Uses `crate::ldso::dso::{Dso, find_sym}`
(B2's merged paths — binding) + `crate::mem::memcpy` (B4, merged).
Mirrors musl `do_relocs` (ldso/dynlink.c:383-530 — B3 reads it fully
first, plus `reloc_all` for the IRELATIVE path):
- `do_relocs(dso, rel, rel_size, stride)` with stride 2 (REL) / 3 (RELA,
  incl. the lazy table at dynlink.c:589). Addend rules: RELA→rel[2];
  REL GOT/PLT/COPY→0; else re-read `*reloc_addr` (ldso addend
  save/reuse is ldso-self-only — skip with `shortcut:` until self-host).
- Cases: NONE(skip), OFFSET(fallthrough), SYMBOLIC/GOT/PLT
  (`*addr = sym_val+addend`), USYMBOLIC (memcpy), RELATIVE
  (`base+addend`), SYM_OR_REL, COPY (memcpy sym_val, st_size), OFFSET32
  (u32), DTPMOD/DTPOFF/TPOFF (x86_64: NO TLS_ABOVE_TP →
  `tls_val - tls.offset + addend`; TPOFF_NEG per arch macro),
  IRELATIVE (call resolver: `((addr)(base+addend))()`), TLSDESC.
- Lazy: unresolved PLT/GOT → saved triples into `dso->lazy`
  (dynlink.c:439-446) when `dso->lazy` set; applied later by reloc_all.
- Lookup: STB_LOCAL → local def; else B2's `find_sym`, then `get_lfs64`
  fallback; missing non-weak-undef → fatal to fd 2 + exit_group
  (`shortcut:` — no longjmp/setjmp until a later wave; mirrors musl's
  error+longjmp outcome: process dies with a diagnostic).
- TLSDESC needing dynamic DTV (`tls_id > static_tls_cnt`) → same fatal
  path (`shortcut:` — musl mallocs a `td_index`; we have no allocator
  until Wave 4 mallocng). Static-TLS TLSDESC fully works.
- Stores: plain writes like musl (NOT volatile — musl proves plain
  stores + its barriers suffice on real hardware; the arch plan's
  volatile rule is over-engineering. Decision recorded here per
  principle 3: musl lo hace más simple).
- R_TYPE/R_SYM extraction + `laddr` exactly per musl macros (B3 reads
  them; x86_64 REL_* numeric values from include/elf.h:3004-3047 and
  arch/x86_64/reloc.h:3-13).
- Tests: hand-built minimal RELA tables against a fake Dso image in
  memory — RELATIVE, SYMBOLIC (self-def), GLOB_DAT, JUMP_SLOT,
  DTPMOD/TPOFF with a static TLS module, IRELATIVE resolver call,
  lazy-save path. No real ELF execution (that's the Wave 2 gate
  follow-up, not B3).
- Proposes nothing for lib.rs (lives under `src/ldso/`, already wired).

### Wave 2 gate
`cargo test` green + a follow-up wave boots a binary (full hello-world
runs when B3 + Wave 3 threads exist; this wave delivers the pieces).

CLOSED (v0.2): `_start`/`__libc_start_main`/SSP/`exit`, ELF64 + `Dso`
mirror, sysv/gnu hashes, ELF loader, `do_relocs` + lookup + lazy,
panic handler, mem trio — 112 probe values, 34 tests green. Advances:
compat ABI (1), POSIX (arranque/carga como contrato) (3). Sin debilitar
principios (revisión de cierre: 2/5/6/7/8 intactos; 4: IRELATIVE
documentado como extensión deliberada — musl lo rechaza, ningún binario
musl lo contiene, sin ruptura de compat).
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

### C1 — create/clone/TLS (worktree ../zlibc-c1, owns src/thread/)
Depends on merged B2 (`crate::ldso::dso::TlsModule`) and B4 mem.
Evidence (all verified in /home/dicov/musl):
- `__clone` (src/thread/x86_64/clone.s): arg shuffle
  (func→r9 saved, stack aligned 16, child arg popped), `clone` (56),
  child calls func then `exit` (60); parent returns TID.
- `__set_thread_area` (src/thread/x86_64/__set_thread_area.s):
  `arch_prctl` (158) with `ARCH_SET_FS = 0x1002`.
- `__unmapself` (src/thread/x86_64/__unmapself.s): `munmap` (11) of
  its own stack, then `exit` (60) — naked, never returns.
- `__init_tp` (src/env/__init_tls.c:17-33): self-assign, SET_FS,
  `can_do_threads`, detach=JOINABLE, TID via `set_tid_address` (218),
  locale, robust self-ref, sysinfo, circular list.
- `__copy_tls` (same file): x86_64 has NO TLS_ABOVE_TP → DTV below TP,
  `dtv[0]=cnt`, images copied per module.
- Clone flags: all 10 (pthread_create.c:243-245). Stack/guard sizing:
  C1 reads default_attr.c + pthread_create.c:260-300 first, no guessing.
- The working thread struct: Parts 1+3 frozen (`PthreadHead`); Part 2
  is explicitly non-ABI (pthread_impl.h) — C1 lays it out freely with
  at least: tid, detach_state, stack base/size (munmap on detached
  death), join result, start routine/arg. Justify every field in a
  comment.
- Main-thread TP: B1 deferred `__init_tls`; C1 owns an
  `ensure_main_tp()` called at the top of `pthread_create`
  (`shortcut:`, boot-time init moves to start.rs later).
- Scope: create/join/detach/self/equal + TP setup + unmapself. Attrs:
  accept defaults + detachstate + stacksize/guardsize, reject the rest
  with ENOTSUP (same gate pattern as C2's check_type). Cancel points,
  keys, atfork, barriers: explicitly OUT (later waves, `shortcut:`).
- Tests: spawn N threads computing partial sums, join all, exact total;
  detached thread observed to exit (join returns ESRCH... musl detaches:
  test via tryjoin-after-sleep is timing-flaky — instead assert
  detach returns 0 and the thread ran (atomic flag)). No timing
  assumptions anywhere.
- Proposes `pub mod thread;` line for coordinator.

### C3 — synccall (worktree ../zlibc-c3, owns src/thread/synccall.rs)
Needs real threads + TIDs (C1 merged ✓) + C2 futex (merged ✓).
Design decision (no global list exists — C1 self-links): the thread
registry lives HERE, not in create.rs: head pointer + futex lock
(`AtomicI32`, C2 primitives) in synccall.rs, with `register`/`unregister`
fns. C3 may add the minimal hooks in create.rs (register after successful
clone; unregister in `thread_exit` on BOTH paths — join only unmaps, the
thread is already unlinked) — flag each hook line with a comment.
`__synccall` per musl src/thread/synccall.c (C3 verifies the filename
first): block SIGSYNCCALL via rt_sigprocmask (14), take the registry
lock, caller/target/exit sems, `tkill` (200) the wave, AS-safe handler
(atomics + futex waits only, zero allocation/locks/panics), run the
callback on every thread including caller, release. Handler installed
via raw rt_sigaction (13). Signal number 34 (pthread_impl.h:131).
Tests: N threads spinning on a flag + synccall incrementing a shared
counter (expect exactly N target-runs + 1 caller-run), no timing
assumptions (spin on atomics, never sleep-then-hope). No cancel
integration (OUT). Proposes nothing for lib.rs (lives under
src/thread/, already wired).

### Wave 3 gate
N-thread counter + mutex/condvar rendezvous test green, then merge
`testing → main`, tag `v0.2`.

CLOSED (v0.3): futex + mutex/condvar (opaque mirrors, exact encoding),
clone/create/join/detach + TLS + unmapself, synccall registry + wave —
112 probe values, 40 tests green, full suite parallel. Advances: compat
ABI (1), POSIX hilos (3). Sin debilitar principios (revisión de cierre:
2/5/6/7/8 intactos; 4: sin bugs musl nuevos, IRELATIVE ya anotado).
Lecciones caras: (a) `SA_RESTORER` + trampolín real obligatorios — sin
ellos este kernel acepta `rt_sigaction` pero jamás despacha (ni siquiera
falla); musl tenía razón y el fallback vDSO no existe aquí; (b) detach
sobre hilo ya muerto hace join+unmap silencioso — los tests de ciclo de
vida solo tocan hilos garantizados vivos, o el segundo detach firma un
use-after-unmap nondeterminista.
- **Wave 4** — stdio, mallocng, libm, locale/network/misc, validation.
  Gate: hello + pthreads + malloc/stdio running, CI green on `main`.
  Packets (each one push, green before next): D0 errno per-thread DONE
  (`THREAD_MAGIC`); D3a `fabs/copysign` DONE; D2 allocator DONE
  (free-list + aligned doors, whole suite runs on it); D1 stdio DONE
  (buffered FILE + `printf` via naked `va_start` trampolines — stable has
  no `va_start`, nightly-only `c_variadic`); D3b directed roundings DONE;
  D4 locale stubs + socket wrappers DONE; D5 gate DONE. CLOSED (v0.4).
  Known flake (1 in ~8, unreproduced in 7 straight runs incl. a ×5
  stress): one serial-step SIGSEGV inside the D5 test, no output line —
  shared-heap/trampoline timing suspect, no evidence; do not chase
  without a backtrace.
- **Wave 5 follow-ups** — v0.8: fixed the join/unmap race behind the
  flake (null-rip cores): the joiner could unmap a child's stack between
  its `DT_EXITED` store and its `SYS_EXIT` while the child still ran a
  `wake` *call*; exit now publishes + wakes + dies in one opaque
  registers-only trap block (musl's store+wake barrier discipline).
  Validated by 60/60 clean trap-loop iterations plus a green suite.
- **Wave 6** — dynamic linker, ending in a musl-gcc hello running
  unmodified (Alpine gate groundwork). Packet 6A DONE: `_dlstart`
  bootstrap (`src/ldso/dlstart.rs`: auxv skip, bias via `AT_BASE` or
  `AT_PHDR` scan, RELATIVE-only self-reloc for REL/RELA/RELR, musl-exact
  entry asm behind `cfg(not(test))`, 63 tests green). Lesson: write the
  *target slot* (`base + rel[0]`), never the table entry — caught by the
  suite, fixed line-faithful to `dlstart.c`. Next: 6B link-map +
  cross-DSO lookup, 6C dynamic TLS, 6D lazy PLT + `libdl`, 6E musl-gcc
  gate.
- **Audit batch (v0.11, all green, 73 tests):** three parallel audits,
  every load-bearing finding fixed + tested — pre-clone registry link
  (detached-child UAF), honest `raw_clone` clobbers, magic-gated canary,
  DIAG-free wave handler, atomic errno fallback, malloc corruption
  aborts (double/foreign, subprocess death tests) + arena checks +
  1024-entry map, fp-walker 176 (proven by induction: the stack holds
  only excess args), `w+` modes, `send`/`recv`, locale-64, ldso
  `skip_relative`/head-interposition/TLS guards/stride guards/shared
  `r_type`/`_start` sealed, convergent TLS init. Deliberate keeps:
  fused exit store (operational safety over model nit), mid-live-chunk
  frees (C-UB, documented), sub-136B foreign `FS` (no user barrier
  exists).
- **Wave 5** — a real binary on zlibc only. Packet 1 DONE (v0.5):
  `hello/` consumer crate (`panic=abort`, `-nostdlib` scoped from its
  own build script so host build tools keep working, `rust_eh_personality`
  stub living in hello — never in the lib) boots through our `_start` →
  `main` → `puts` → `exit`, asserting exact bytes + status in CI.
  Packet 2 DONE (v0.6): `hello-threads` — clone/join + `printf` in a real
  binary, covering the path unit tests never touch (`ensure_main_tp`
  taking over `FS` at real boot instead of early-returning for glibc).
  Packets 3-4 DONE (v0.7): `hello-malloc` (three size classes,
  calloc-zero, realloc-grow, formatted report) and `hello-args` (real
  kernel argc/argv plus one pinned env var, `argv[0]` excluded as
  runner-dependent). Toolchain lessons: a bin with zero `zlibc::` paths
  never loads the rlib metadata, so `extern crate zlibc;` is
  load-bearing for the panic handler (proven by removal); a `main` that
  dereferences argv must be `unsafe fn`.
  Packet 5 DONE (v0.9): `hello-fs` — real `fopen`/`fwrite`/`fclose`/
  `fread` roundtrip on the filesystem plus `memcmp` (the missing fourth
  of the mem trio, musl ordering). CLOSED: five binaries run on zlibc
  only, 59 lib tests green.

## "100% done" criteria

- All public musl x86_64 symbols present with correct signature/ABI.
- Static + dynamic hello world and a pthreads binary run on zlibc.
- Probe asserts cover the whole musl `alltypes.h`.
- CI green on `main`.
