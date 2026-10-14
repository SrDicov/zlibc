//! Thread-pointer setup and TLS block layout (x86_64).
//!
//! Clean-room mirrors of musl `src/env/__init_tls.c:14-72` (`__init_tp`,
//! `__copy_tls`) and `src/thread/x86_64/__set_thread_area.s` (`SET_FS`).
//! x86_64 has no `TLS_ABOVE_TP`, so the DTV lives below the TCB,
//! `dtv[0]` is the module count, and `TP_ADJ` is the identity.
//! Module records are [`crate::ldso::dso::TlsModule`]; the list is empty
//! today (the loader records no `PT_TLS` yet) and the loops below already
//! handle the general case for when it does.

use core::ffi::{c_int, c_void};
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicUsize, Ordering};

use crate::abi::PthreadHead;
use crate::ldso::dso::TlsModule;
use crate::mem::memcpy;
use crate::syscall::{syscall1, syscall2};

use super::{Thread, ARCH_SET_FS, SYS_ARCH_PRCTL, SYS_SET_TID_ADDRESS};

/// TCB alignment (musl `__init_tls.c:30-35`: `MIN_TLS_ALIGN`, 16 here).
const TLS_ALIGN: usize = 16;

/// Registered TLS modules (head) and count. Writers run only before
/// threads exist (image load); readers run any time, so both go through
/// atomics (`Acquire` reads pair with the `Release` writes below — the
/// only cross-thread edge here; no concurrent writers exist by contract).
static TLS_HEAD: AtomicPtr<TlsModule> = AtomicPtr::new(core::ptr::null_mut());
static TLS_CNT: AtomicUsize = AtomicUsize::new(0);

/// Register one static-TLS module record, lent by the loader (which owns
/// the storage). Prepends to the list.
///
/// # Safety
///
/// `m` must point to a valid, initialized `TlsModule` that outlives all
/// threads, and no thread may be creating concurrently with this call.
/// Offsets are loader-assigned (musl `static_init_tls`); until the loader
/// computes them, only a null list is meaningful — registration with
/// unassigned offsets would corrupt `copy_tls`.
// shortcut(TLS offsets): `static_init_tls` offset assignment
// (`__init_tls.c:105-123`) moves here when ldso reports `PT_TLS`.
pub unsafe fn register_tls_module(m: *mut TlsModule) {
    unsafe {
        (*m).next = TLS_HEAD.load(Ordering::Acquire);
        TLS_HEAD.store(m, Ordering::Release);
        TLS_CNT.fetch_add(1, Ordering::Release);
    }
}

/// TLS block footprint: DTV head + TCB + module images, 16-aligned
/// (musl `__init_tls.c:126-131` shape, without the above-TP terms).
pub(crate) fn current_tls_size() -> usize {
    let mut size = 2 * size_of::<usize>() + size_of::<Thread>();
    unsafe {
        let mut m = TLS_HEAD.load(Ordering::Acquire);
        while !m.is_null() {
            size = size.wrapping_add((*m).size).wrapping_add((*m).align);
            m = (*m).next;
        }
    }
    size.wrapping_add(TLS_ALIGN - 1) & !(TLS_ALIGN - 1)
}

/// Carve the TCB + DTV out of `[base, base+size)` (musl `__copy_tls`,
/// no-`TLS_ABOVE_TP` arm, `__init_tls.c:57-71`): `dtv = mem`, TCB placed
/// top-down 16-aligned, `dtv[0] = cnt`, one image copied per module.
/// Returns the TCB with head (`this`, `dtv`, self-links) wired; the
/// caller fills Part 2 plus canary/sysinfo.
///
/// # Safety
///
/// `base` must start a writable mapping of at least `size` bytes with
/// `size >= current_tls_size()`. The returned pointer stays valid until
/// the mapping is unmapped.
pub(crate) unsafe fn copy_tls(base: *mut u8, size: usize) -> *mut Thread {
    unsafe {
        let dtv = base as *mut usize;
        let mut mem = (base as usize)
            .wrapping_add(size)
            .wrapping_sub(size_of::<Thread>());
        mem &= !(TLS_ALIGN - 1);
        let td = mem as *mut Thread;
        let mut i = 1usize;
        let mut m = TLS_HEAD.load(Ordering::Acquire);
        while !m.is_null() {
            // `DTP_OFFSET` is 0 on x86_64 (pthread_impl.h:113-115).
            dtv.add(i).write((td as usize).wrapping_sub((*m).offset));
            memcpy(
                (td as *mut u8).wrapping_sub((*m).offset) as *mut c_void,
                (*m).image as *const c_void,
                (*m).len,
            );
            i += 1;
            m = (*m).next;
        }
        dtv.write(TLS_CNT.load(Ordering::Acquire));
        (*td).head.this = td.cast::<PthreadHead>();
        (*td).head.dtv = dtv;
        // shortcut(no thread list): musl links every thread into a global
        // list (create.c:372-376); C1 self-links. C3 synccall needs real
        // enumeration — it owns the list.
        (*td).head.prev = td.cast::<PthreadHead>();
        (*td).head.next = td.cast::<PthreadHead>();
        td
    }
}

/// Set the thread pointer (`__set_thread_area.s:6-10`:
/// `arch_prctl(ARCH_SET_FS, tp)`). Returns the raw kernel result.
///
/// # Safety
///
/// `tp` must be a valid TCB for the calling thread; callable from any
/// thread context (each thread owns its `FS` base).
pub(crate) unsafe fn set_tp(tp: usize) -> isize {
    unsafe { syscall2(SYS_ARCH_PRCTL, ARCH_SET_FS, tp) }
}

/// Read the thread pointer (`arch/x86_64/pthread_arch.h:1-6`).
pub(crate) fn get_tp() -> usize {
    let tp: usize;
    unsafe {
        core::arch::asm!("mov %fs:0, {0}", out(reg) tp, options(att_syntax));
    }
    tp
}

static DONE: AtomicBool = AtomicBool::new(false);
static mut MAIN_THREAD: Thread = unsafe { core::mem::zeroed() };
static mut MAIN_DTV: [usize; 2] = [0; 2];
/// `set_tid_address` word for the main thread (musl passes
/// `&__thread_list_lock` in `__init_tp`; with no list yet this private
/// word only anchors the clear-tid registration — shortcut).
static mut MAIN_TID_CLEAR: c_int = 0;

/// Point `FS` at a TCB for the calling (main) thread, once
/// (musl `__init_tp`, `__init_tls.c:14-28`, reduced: self-assign, SET_FS,
/// joinable state, TID via `set_tid_address`, self-list; locale/robust/
/// sysinfo/canary come with their owning waves — shortcut).
/// Convergent: whoever arrives first initializes (idempotent writes),
/// then publishes with `Release`; latecomers observe it via `Acquire`
/// and return. The `swap`-first shape used to publish before the init
/// completed, exposing a half-built TCB.
pub(crate) fn ensure_main_tp() {
    if DONE.load(Ordering::Acquire) {
        return;
    }
    // shortcut(hosted guest): a freestanding boot always sees FS == 0
    // (the kernel clears it on exec). A nonzero FS means a foreign
    // runtime already owns this thread (e.g. glibc under `cargo test`);
    // taking it over would kill the host process on its next TLS touch,
    // so leave it. Clone()d threads still get real TPs via CLONE_SETTLS.
    if get_tp() != 0 {
        return;
    }
    unsafe {
        let td = core::ptr::addr_of_mut!(MAIN_THREAD);
        (*td).head.this = td.cast::<PthreadHead>();
        (*td).head.dtv = core::ptr::addr_of_mut!(MAIN_DTV).cast::<usize>();
        (*td).head.prev = td.cast::<PthreadHead>();
        (*td).head.next = td.cast::<PthreadHead>();
        (*td).detach_state = AtomicI32::new(super::DT_JOINABLE);
        (*td).errno_val = 0;
        (*td).magic = super::THREAD_MAGIC;
        core::ptr::addr_of_mut!(MAIN_DTV).cast::<usize>().write(0);
        let tid = syscall1(
            SYS_SET_TID_ADDRESS,
            core::ptr::addr_of_mut!(MAIN_TID_CLEAR) as usize,
        ) as c_int;
        (*td).tid = tid;
        // `SET_FS` on a valid static cannot fail; ignore the result like
        // musl ignores a zero return (`__init_tls.c:18-20` checks `< 0`,
        // and failure here always means a kernel bug).
        let _ = set_tp(td as usize);
        DONE.store(true, Ordering::Release);
    }
}
