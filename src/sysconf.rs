//! Config, resources, logging, uts, crypt, mntent, utmpx (musl `src/conf/*`,
//! `src/misc/{getrlimit,getrusage,sysinfo,syslog,mntent}`, `src/linux/prlimit.c`,
//! `src/unistd/{gethostname,sethostname,getdomainname,setdomainname}`,
//! `src/crypt/*`, `src/legacy/{utmpx,ulimit}.c`).
//!
//! Documented deviations from musl:
//!
//! - bcrypt (`$2a$`/`$2y$` salts) is not implemented: `crypt`/`crypt_r`
//!   return `"*"` for those salts (musl computes real bcrypt).
//!   `// ponytail: port crypt_blowfish.c when a consumer verifies bcrypt hashes.`
//! - `syslog` omits musl's `Mmm DD HH:MM:SS` timestamp; the `<pri>ident[pid]:
//!   msg` framing and `/dev/log` datagram delivery match.
//! - syslog state is guarded by a core spinlock, not musl's
//!   pthread-cancel-safe mutex; identical behavior for non-cancelled callers.
//! - `crypt`/`getmntent` use process-static buffers like musl (MT-Unsafe,
//!   same contract).

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr::{addr_of_mut, null_mut};

use crate::errno::{__errno_location, errno_store};
use crate::syscall::{syscall1, syscall2, syscall3, syscall4, syscall_ret};
use crate::time::Timeval;

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_UNAME: usize = 63;
#[cfg(target_arch = "x86_64")]
const SYS_GETRUSAGE: usize = 98;
#[cfg(target_arch = "x86_64")]
const SYS_SYSINFO: usize = 99;
#[cfg(target_arch = "x86_64")]
const SYS_SYSLOG: usize = 103;
#[cfg(target_arch = "x86_64")]
const SYS_ACCT: usize = 163;
#[cfg(target_arch = "x86_64")]
const SYS_SETHOSTNAME: usize = 170;
#[cfg(target_arch = "x86_64")]
const SYS_SETDOMAINNAME: usize = 171;
#[cfg(target_arch = "x86_64")]
const SYS_SCHED_GETAFFINITY: usize = 204;
#[cfg(target_arch = "x86_64")]
const SYS_PRLIMIT64: usize = 302;

// ---- errno ------------------------------------------------------------------
#[cfg(target_arch = "x86_64")]
const EINVAL: c_int = 22;
#[cfg(target_arch = "x86_64")]
const ENOENT: c_int = 2;
#[cfg(target_arch = "x86_64")]
const ENAMETOOLONG: c_int = 36;
#[cfg(target_arch = "x86_64")]
const ENOTSUP: c_int = 95;

#[cfg(target_arch = "x86_64")]
fn set_err(e: c_int) {
    unsafe {
        errno_store(__errno_location(), e);
    }
}

// ---- limits (musl include/limits.h + unistd.h) ------------------------------
#[cfg(target_arch = "x86_64")]
const ARG_MAX_V: c_long = 131072;
#[cfg(target_arch = "x86_64")]
const IOV_MAX_V: c_long = 1024;
#[cfg(target_arch = "x86_64")]
const SYMLOOP_MAX_V: c_long = 40;
#[cfg(target_arch = "x86_64")]
const TZNAME_MAX_V: c_long = 6;
#[cfg(target_arch = "x86_64")]
const TTY_NAME_MAX_V: c_long = 32;
#[cfg(target_arch = "x86_64")]
const HOST_NAME_MAX_V: c_long = 255;
#[cfg(target_arch = "x86_64")]
const LOGIN_NAME_MAX_V: c_long = 256;
#[cfg(target_arch = "x86_64")]
const COLL_WEIGHTS_MAX_V: c_long = 2;
#[cfg(target_arch = "x86_64")]
const RE_DUP_MAX_V: c_long = 255;
#[cfg(target_arch = "x86_64")]
const NZERO_V: c_long = 20;
#[cfg(target_arch = "x86_64")]
const POSIX_VERSION_V: c_long = 200809;
#[cfg(target_arch = "x86_64")]
const XOPEN_VERSION_V: c_long = 700;
#[cfg(target_arch = "x86_64")]
const PTHREAD_KEYS_MAX_V: c_long = 128;
#[cfg(target_arch = "x86_64")]
const PTHREAD_STACK_MIN_V: c_long = 2048;
#[cfg(target_arch = "x86_64")]
const PTHREAD_DESTRUCTOR_ITERATIONS_V: c_long = 4;
#[cfg(target_arch = "x86_64")]
const SEM_VALUE_MAX_V: c_long = 0x7fffffff;
#[cfg(target_arch = "x86_64")]
const SEM_NSEMS_MAX_V: c_long = 256;
#[cfg(target_arch = "x86_64")]
const MQ_PRIO_MAX_V: c_long = 32768;
#[cfg(target_arch = "x86_64")]
const DELAYTIMER_MAX_V: c_long = 0x7fffffff;
#[cfg(target_arch = "x86_64")]
const RTSIG_MAX_V: c_long = 30;
#[cfg(target_arch = "x86_64")]
const PAGE_SIZE_V: c_long = 4096;
#[cfg(target_arch = "x86_64")]
const CLK_TCK_V: c_long = 100;
#[cfg(target_arch = "x86_64")]
const NGROUPS_MAX_V: c_long = 32;
#[cfg(target_arch = "x86_64")]
const MINSIGSTKSZ_V: c_ulong = 2048;
#[cfg(target_arch = "x86_64")]
const SIGSTKSZ_V: c_ulong = 8192;

// ---- resource / pathconf / syslog / ulimit ids -------------------------------
#[cfg(target_arch = "x86_64")]
pub const RLIMIT_CPU: c_int = 0;
#[cfg(target_arch = "x86_64")]
pub const RLIMIT_FSIZE: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const RLIMIT_DATA: c_int = 2;
#[cfg(target_arch = "x86_64")]
pub const RLIMIT_STACK: c_int = 3;
#[cfg(target_arch = "x86_64")]
pub const RLIMIT_CORE: c_int = 4;
#[cfg(target_arch = "x86_64")]
pub const RLIMIT_RSS: c_int = 5;
#[cfg(target_arch = "x86_64")]
pub const RLIMIT_NPROC: c_int = 6;
#[cfg(target_arch = "x86_64")]
pub const RLIMIT_NOFILE: c_int = 7;
#[cfg(target_arch = "x86_64")]
pub const RLIMIT_MEMLOCK: c_int = 8;
#[cfg(target_arch = "x86_64")]
pub const RLIMIT_AS: c_int = 9;
#[cfg(target_arch = "x86_64")]
pub const RLIMIT_LOCKS: c_int = 10;
#[cfg(target_arch = "x86_64")]
pub const RLIMIT_SIGPENDING: c_int = 11;
#[cfg(target_arch = "x86_64")]
pub const RLIMIT_MSGQUEUE: c_int = 12;
#[cfg(target_arch = "x86_64")]
pub const RLIMIT_NICE: c_int = 13;
#[cfg(target_arch = "x86_64")]
pub const RLIMIT_RTPRIO: c_int = 14;
#[cfg(target_arch = "x86_64")]
pub const RLIMIT_RTTIME: c_int = 15;
#[cfg(target_arch = "x86_64")]
pub const RLIM_INFINITY: u64 = !0u64;
#[cfg(target_arch = "x86_64")]
pub const RUSAGE_SELF: c_int = 0;
#[cfg(target_arch = "x86_64")]
pub const RUSAGE_CHILDREN: c_int = -1;
#[cfg(target_arch = "x86_64")]
pub const RUSAGE_THREAD: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const UL_GETFSIZE: c_int = 1;
#[cfg(target_arch = "x86_64")]
pub const UL_SETFSIZE: c_int = 2;
#[cfg(target_arch = "x86_64")]
const AT_NULL: c_ulong = 0;
#[cfg(target_arch = "x86_64")]
const AT_MINSIGSTKSZ: c_ulong = 51;
#[cfg(target_arch = "x86_64")]
const LOG_PRIMASK_V: c_int = 7;
#[cfg(target_arch = "x86_64")]
pub const LOG_PID: c_int = 0x01;
#[cfg(target_arch = "x86_64")]
pub const LOG_CONS: c_int = 0x02;
#[cfg(target_arch = "x86_64")]
pub const LOG_NDELAY: c_int = 0x08;
#[cfg(target_arch = "x86_64")]
pub const LOG_PERROR: c_int = 0x20;

// ---- Types -------------------------------------------------------------------
/// musl `struct rlimit` (`sys/resource.h`): two `rlim_t` (`u64`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Rlimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

/// musl `struct rusage` (`sys/resource.h`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Rusage {
    pub ru_utime: Timeval,
    pub ru_stime: Timeval,
    pub ru_maxrss: c_long,
    pub ru_ixrss: c_long,
    pub ru_idrss: c_long,
    pub ru_isrss: c_long,
    pub ru_minflt: c_long,
    pub ru_majflt: c_long,
    pub ru_nswap: c_long,
    pub ru_inblock: c_long,
    pub ru_oublock: c_long,
    pub ru_msgsnd: c_long,
    pub ru_msgrcv: c_long,
    pub ru_nsignals: c_long,
    pub ru_nvcsw: c_long,
    pub ru_nivcsw: c_long,
    pub __reserved: [c_long; 16],
}

/// musl `struct utsname` (`sys/utsname.h`): six 65-byte names.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Utsname {
    pub sysname: [c_char; 65],
    pub nodename: [c_char; 65],
    pub release: [c_char; 65],
    pub version: [c_char; 65],
    pub machine: [c_char; 65],
    pub domainname: [c_char; 65],
}

/// musl `struct sysinfo` (`sys/sysinfo.h`, user layout).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Sysinfo {
    pub uptime: u64,
    pub loads: [u64; 3],
    pub totalram: u64,
    pub freeram: u64,
    pub sharedram: u64,
    pub bufferram: u64,
    pub totalswap: u64,
    pub freeswap: u64,
    pub procs: u16,
    pub pad: u16,
    pub totalhigh: u64,
    pub freehigh: u64,
    pub mem_unit: u32,
    pub __reserved: [u8; 256],
}

/// Kernel layout the `SYS_sysinfo` trap fills (musl `kernel_sysinfo`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct KernelSysinfo {
    uptime: i64,
    loads: [u64; 3],
    totalram: u64,
    freeram: u64,
    sharedram: u64,
    bufferram: u64,
    totalswap: u64,
    freeswap: u64,
    procs: i16,
    pad: i16,
    totalhigh: u64,
    freehigh: u64,
    mem_unit: u32,
}

/// musl `struct mntent` (`mntent.h`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Mntent {
    pub mnt_fsname: *mut c_char,
    pub mnt_dir: *mut c_char,
    pub mnt_type: *mut c_char,
    pub mnt_opts: *mut c_char,
    pub mnt_freq: c_int,
    pub mnt_passno: c_int,
}

/// musl `struct utmpx` (`utmpx.h`, little-endian).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Utmpx {
    pub ut_type: i16,
    pub __ut_pad1: i16,
    pub ut_pid: i32,
    pub ut_line: [c_char; 32],
    pub ut_id: [c_char; 4],
    pub ut_user: [c_char; 32],
    pub ut_host: [c_char; 256],
    pub ut_exit_termination: i16,
    pub ut_exit_exit: i16,
    pub ut_session: i32,
    pub __ut_pad2: i32,
    pub ut_tv: Timeval,
    pub ut_addr_v6: [u32; 4],
    pub __unused: [c_char; 20],
}

/// musl `struct crypt_data` (`crypt.h`): opaque 256-byte buffer.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct CryptData {
    pub initialized: c_int,
    pub __buf: [c_char; 256],
}

// ---- small C-string helpers ----------------------------------------------------
#[cfg(target_arch = "x86_64")]
unsafe fn c_strlen(s: *const c_char) -> usize {
    unsafe {
        let mut n = 0usize;
        while *s.add(n) != 0 {
            n = n.wrapping_add(1);
        }
        n
    }
}

// ---- sysconf (musl src/conf/sysconf.c) ------------------------------------------
#[cfg(target_arch = "x86_64")]
unsafe fn rlim_cur(res: c_int) -> c_long {
    unsafe {
        let mut lim: Rlimit = core::mem::zeroed();
        if getrlimit(res, &mut lim) != 0 {
            return -1;
        }
        if lim.rlim_cur == RLIM_INFINITY {
            return -1;
        }
        if lim.rlim_cur > c_long::MAX as u64 {
            return c_long::MAX;
        }
        lim.rlim_cur as c_long
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn nprocessors() -> c_long {
    unsafe {
        let mut set = [1u8; 128];
        syscall_ret(syscall3(
            SYS_SCHED_GETAFFINITY,
            0,
            set.len(),
            set.as_mut_ptr() as usize,
        ));
        let mut cnt = 0 as c_long;
        for b in set {
            let mut v = b;
            while v != 0 {
                v &= v.wrapping_sub(1);
                cnt = cnt.wrapping_add(1);
            }
        }
        cnt
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn phys_pages(avail: bool) -> c_long {
    unsafe {
        let mut si: Sysinfo = core::mem::zeroed();
        if sysinfo(&mut si) != 0 {
            return -1;
        }
        let unit = if si.mem_unit == 0 {
            1u64
        } else {
            si.mem_unit as u64
        };
        let mut mem = if avail {
            si.freeram.wrapping_add(si.bufferram)
        } else {
            si.totalram
        };
        mem = mem.saturating_mul(unit) / PAGE_SIZE_V as u64;
        if mem > c_long::MAX as u64 {
            c_long::MAX
        } else {
            mem as c_long
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn sigstk_size(big: bool) -> c_long {
    unsafe {
        let mut frame = getauxval(AT_MINSIGSTKSZ);
        if frame < MINSIGSTKSZ_V.wrapping_sub(1024) {
            frame = MINSIGSTKSZ_V.wrapping_sub(1024);
        }
        let mut val = frame.wrapping_add(1024);
        if big {
            val = val.wrapping_add(SIGSTKSZ_V.wrapping_sub(MINSIGSTKSZ_V));
        }
        if val > c_long::MAX as c_ulong {
            c_long::MAX
        } else {
            val as c_long
        }
    }
}

/// System configuration value (musl `sysconf`: table + `JT_*`/`RLIM_*`
/// computed entries; unknown names fail `EINVAL`).
///
/// # Safety
///
/// Pure value query; no pointers involved.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sysconf(name: c_int) -> c_long {
    unsafe {
        match name {
            0 => ARG_MAX_V,
            1 => rlim_cur(RLIMIT_NPROC),
            2 => CLK_TCK_V,
            3 => NGROUPS_MAX_V,
            4 => rlim_cur(RLIMIT_NOFILE),
            5 => -1,
            6 => TZNAME_MAX_V,
            7 => 1,
            8 => 1,
            9 | 11 | 12 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 29 | 47 | 52 | 67 | 68 | 77
            | 78 | 79 | 82 | 91 | 93 | 94 | 132 | 133 | 137 | 138 | 139 | 149 | 153 | 154 | 157
            | 159 | 164 | 235 | 236 => POSIX_VERSION_V,
            10 | 13 | 14 | 23 | 24 | 27 | 34 | 35 | 43 | 48 | 49 | 50 | 51 | 76 | 80 | 81 | 87
            | 88 | 95 | 97 | 98 | 99 | 100 | 125 | 126 | 127 | 128 | 129 | 130 | 131 | 160
            | 161 | 165 | 168 | 169 | 170 | 171 | 172 | 174 | 175 | 176 | 177 | 178 | 179 | 181
            | 182 | 183 | 184 | 237 | 238 | 239 | 240 | 241 | 242 | 243 | 244 | 245 => -1,
            25 => 0,
            26 => DELAYTIMER_MAX_V,
            28 => MQ_PRIO_MAX_V,
            30 => PAGE_SIZE_V,
            31 => RTSIG_MAX_V,
            32 => SEM_NSEMS_MAX_V,
            33 => SEM_VALUE_MAX_V,
            36..=39 => 2048,
            40 => COLL_WEIGHTS_MAX_V,
            42 => -1,
            44 => RE_DUP_MAX_V,
            46 => POSIX_VERSION_V,
            69 | 70 => 1024,
            60 => IOV_MAX_V,
            71 => LOGIN_NAME_MAX_V,
            72 => TTY_NAME_MAX_V,
            73 => PTHREAD_DESTRUCTOR_ITERATIONS_V,
            74 => PTHREAD_KEYS_MAX_V,
            75 => PTHREAD_STACK_MIN_V,
            83 | 84 => nprocessors(),
            89 | 90 => XOPEN_VERSION_V,
            85 => phys_pages(false),
            86 => phys_pages(true),
            109 => NZERO_V,
            173 => SYMLOOP_MAX_V,
            180 => HOST_NAME_MAX_V,
            246 => 0,
            247 | 248 => -1,
            249 => sigstk_size(false),
            250 => sigstk_size(true),
            155 => 1,
            _ => {
                set_err(EINVAL);
                -1
            }
        }
    }
}

// ---- confstr (musl src/conf/confstr.c) -------------------------------------------
/// Configuration string (musl `confstr`: only `_CS_PATH` is non-empty).
///
/// # Safety
///
/// `buf` must be writable for `len` bytes (or null when `len` is 0).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn confstr(name: c_int, buf: *mut c_char, len: usize) -> usize {
    unsafe {
        let s: &[u8] = if name == 0 { b"/bin:/usr/bin" } else { b"" };
        if name != 0 {
            let u = name as c_uint;
            if (u & !4u32) != 1 && u.wrapping_sub(1116) > 35 {
                set_err(EINVAL);
                return 0;
            }
        }
        let n = s.len();
        if len != 0 && !buf.is_null() {
            let k = n.min(len.wrapping_sub(1));
            core::ptr::copy_nonoverlapping(s.as_ptr() as *const c_char, buf, k);
            *buf.add(k) = 0;
        }
        n.wrapping_add(1)
    }
}

// ---- pathconf (musl src/conf/{pathconf,fpathconf}.c) -------------------------------
/// Path limits (musl `fpathconf`: constant table; `fd` is unused).
///
/// # Safety
///
/// No pointers involved.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn fpathconf(_fd: c_int, name: c_int) -> c_long {
    match name {
        0 => 255,
        1 => 255,
        2 => 255,
        3 => 255,
        4 => 4096,
        5 => 4096,
        6 => 1,
        7 => 1,
        8 => 0,
        9 => 1,
        10 => -1,
        11 => -1,
        12 => -1,
        13 => 64,
        14..=18 => 4096,
        19 => -1,
        20 => 1,
        _ => {
            set_err(EINVAL);
            -1
        }
    }
}

/// Path limits by name (musl `pathconf`: `fpathconf(-1, ...)`).
///
/// # Safety
///
/// `path` must point to a NUL-terminated string (unused beyond that).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn pathconf(_path: *const c_char, name: c_int) -> c_long {
    unsafe { fpathconf(-1, name) }
}

// ---- rlimit (musl src/misc/getrlimit.c + setrlimit/prlimit) --------------------------
#[cfg(target_arch = "x86_64")]
unsafe fn prlimit_inner(pid: c_uint, res: c_int, new: *const Rlimit, old: *mut Rlimit) -> c_int {
    unsafe {
        syscall_ret(syscall4(
            SYS_PRLIMIT64,
            pid as usize,
            res as usize,
            new as usize,
            old as usize,
        )) as c_int
    }
}

#[cfg(target_arch = "x86_64")]
fn fix_rlim(v: &mut u64) {
    if *v == !0u64 {
        *v = RLIM_INFINITY;
    }
}

/// Resource limits (musl `getrlimit`: `prlimit64` + infinity fixup).
///
/// # Safety
///
/// `rlim` must point to a writable `Rlimit`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getrlimit(res: c_int, rlim: *mut Rlimit) -> c_int {
    unsafe {
        if rlim.is_null() {
            set_err(EINVAL);
            return -1;
        }
        let r = prlimit_inner(0, res, null_mut(), rlim);
        if r == 0 {
            fix_rlim(&mut (*rlim).rlim_cur);
            fix_rlim(&mut (*rlim).rlim_max);
        }
        r
    }
}

/// Set resource limits (musl `setrlimit`: `prlimit64`).
///
/// # Safety
///
/// `rlim` must point to a readable `Rlimit`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setrlimit(res: c_int, rlim: *const Rlimit) -> c_int {
    unsafe { prlimit_inner(0, res, rlim, null_mut()) }
}

/// Process resource limits (musl `prlimit`: direct trap).
///
/// # Safety
///
/// `new`/`old` must be null or point to readable/writable `Rlimit`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn prlimit(
    pid: c_uint,
    res: c_int,
    new: *const Rlimit,
    old: *mut Rlimit,
) -> c_int {
    unsafe { prlimit_inner(pid, res, new, old) }
}

// ---- getrusage (musl src/misc/getrusage.c) ----------------------------------------------
/// Resource usage (musl `getrusage`: direct trap).
///
/// # Safety
///
/// `ru` must point to a writable `Rusage`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getrusage(who: c_int, ru: *mut Rusage) -> c_int {
    unsafe {
        if ru.is_null() {
            set_err(EINVAL);
            return -1;
        }
        syscall_ret(syscall2(SYS_GETRUSAGE, who as usize, ru as usize)) as c_int
    }
}

// ---- ulimit (musl src/legacy/ulimit.c) --------------------------------------------------
///
/// File-size limit in 512-byte blocks (musl `ulimit`: fixed two-word shape —
/// same definedness rule as `prctl` in `crate::misc`; `val` is only read
/// for `UL_SETFSIZE`).
///
/// # Safety
///
/// Pure value call.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ulimit(cmd: c_int, val: c_long) -> c_long {
    unsafe {
        let mut rl: Rlimit = core::mem::zeroed();
        if getrlimit(RLIMIT_FSIZE, &mut rl) != 0 {
            return -1;
        }
        if cmd == UL_SETFSIZE {
            rl.rlim_cur = (val as u64).wrapping_mul(512);
            if setrlimit(RLIMIT_FSIZE, &rl) != 0 {
                return -1;
            }
        }
        (rl.rlim_cur / 512) as c_long
    }
}

// ---- uname / sysinfo / auxv / host --------------------------------------------------------
///
/// System name (musl `uname`: direct trap).
///
/// # Safety
///
/// `uts` must point to a writable `Utsname`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn uname(uts: *mut Utsname) -> c_int {
    unsafe {
        if uts.is_null() {
            set_err(EINVAL);
            return -1;
        }
        syscall_ret(syscall1(SYS_UNAME, uts as usize)) as c_int
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn sysinfo_raw(out: *mut Sysinfo) -> c_int {
    unsafe {
        let mut k: KernelSysinfo = core::mem::zeroed();
        let r = syscall_ret(syscall1(
            SYS_SYSINFO,
            (&mut k) as *mut KernelSysinfo as usize,
        ));
        if r != 0 {
            return r as c_int;
        }
        let max = k.totalram | k.totalswap;
        let shifts = if max == 0 {
            0u32
        } else {
            let b = 63 - max.leading_zeros();
            if b >= 32 {
                b - 31
            } else {
                0
            }
        };
        let o = &mut *out;
        o.uptime = k.uptime as u64;
        o.loads = k.loads;
        o.totalram = k.totalram >> shifts;
        o.freeram = k.freeram >> shifts;
        o.sharedram = k.sharedram >> shifts;
        o.bufferram = k.bufferram >> shifts;
        o.totalswap = k.totalswap >> shifts;
        o.freeswap = k.freeswap >> shifts;
        o.procs = k.procs as u16;
        o.pad = 0;
        o.totalhigh = k.totalhigh >> shifts;
        o.freehigh = k.freehigh >> shifts;
        o.mem_unit = ((if k.mem_unit == 0 {
            1u64
        } else {
            k.mem_unit as u64
        }) << shifts) as u32;
        o.__reserved = [0; 256];
        0
    }
}

/// System statistics (musl `sysinfo`: trap + 64-bit unit scaling).
///
/// # Safety
///
/// `info` must point to a writable `Sysinfo`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sysinfo(info: *mut Sysinfo) -> c_int {
    unsafe {
        if info.is_null() {
            set_err(EINVAL);
            return -1;
        }
        sysinfo_raw(info)
    }
}

/// Aux vector value (musl `getauxval`: scans `/proc/self/auxv`; 0 when absent).
///
/// # Safety
///
/// Pure value query.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getauxval(ty: c_ulong) -> c_ulong {
    unsafe {
        if ty == AT_NULL {
            return 0;
        }
        let fd = crate::fcntl::open(c"/proc/self/auxv".as_ptr(), 0, 0);
        if fd < 0 {
            return 0;
        }
        let mut ans = 0 as c_ulong;
        let mut pair = [0 as c_ulong; 2];
        loop {
            let mut got = 0usize;
            while got < 16 {
                let r = crate::unistd::read(
                    fd,
                    (pair.as_mut_ptr() as *mut u8).add(got) as *mut c_void,
                    16 - got,
                );
                if r <= 0 {
                    break;
                }
                got += r as usize;
            }
            if got < 16 {
                break;
            }
            if pair[0] == AT_NULL {
                break;
            }
            if pair[0] == ty {
                ans = pair[1];
                break;
            }
        }
        crate::unistd::close(fd);
        ans
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn copy_uname_field(dst: *mut c_char, len: usize, off: usize) -> c_int {
    unsafe {
        let mut u: Utsname = core::mem::zeroed();
        if uname(&mut u) != 0 {
            return -1;
        }
        let base = (&u as *const Utsname) as *const c_char;
        let src = base.add(off);
        let n = c_strlen(src);
        if len == 0 || n >= len {
            set_err(ENAMETOOLONG);
            return -1;
        }
        core::ptr::copy_nonoverlapping(src, dst, n.wrapping_add(1));
        0
    }
}

/// Host name (musl: `uname` nodename copy).
///
/// # Safety
///
/// `name` must be writable for `len` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn gethostname(name: *mut c_char, len: usize) -> c_int {
    unsafe {
        if name.is_null() {
            set_err(EINVAL);
            return -1;
        }
        copy_uname_field(name, len, core::mem::offset_of!(Utsname, nodename))
    }
}

/// Set host name (musl: direct trap).
///
/// # Safety
///
/// `name` must be readable for `len` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn sethostname(name: *const c_char, len: usize) -> c_int {
    unsafe {
        if name.is_null() {
            set_err(EINVAL);
            return -1;
        }
        syscall_ret(syscall2(SYS_SETHOSTNAME, name as usize, len)) as c_int
    }
}

/// Domain name (musl: `uname` domainname copy).
///
/// # Safety
///
/// `name` must be writable for `len` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getdomainname(name: *mut c_char, len: usize) -> c_int {
    unsafe {
        if name.is_null() {
            set_err(EINVAL);
            return -1;
        }
        copy_uname_field(name, len, core::mem::offset_of!(Utsname, domainname))
    }
}

/// Set domain name (musl: direct trap).
///
/// # Safety
///
/// `name` must be readable for `len` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setdomainname(name: *const c_char, len: usize) -> c_int {
    unsafe {
        if name.is_null() {
            set_err(EINVAL);
            return -1;
        }
        syscall_ret(syscall2(SYS_SETDOMAINNAME, name as usize, len)) as c_int
    }
}

// ---- syslog (musl src/misc/syslog.c) -------------------------------------------------------
#[cfg(target_arch = "x86_64")]
const SOCK_DGRAM_V: c_int = 2;
#[cfg(target_arch = "x86_64")]
const SOCK_CLOEXEC_V: c_int = 0o2000000;
#[cfg(target_arch = "x86_64")]
const AF_UNIX_V: c_int = 1;

#[cfg(target_arch = "x86_64")]
static mut LOG_IDENT: [c_char; 32] = [0; 32];
#[cfg(target_arch = "x86_64")]
static mut LOG_OPT: c_int = 0;
#[cfg(target_arch = "x86_64")]
static mut LOG_FACILITY: c_int = 8;
#[cfg(target_arch = "x86_64")]
static mut LOG_MASK_V: c_int = 0xff;
#[cfg(target_arch = "x86_64")]
static mut LOG_FD: c_int = -1;
// ponytail: spinlock, per-facility sockets if syslog throughput matters.
#[cfg(target_arch = "x86_64")]
static LOG_LOCK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[cfg(target_arch = "x86_64")]
fn log_lock() {
    while LOG_LOCK.swap(true, core::sync::atomic::Ordering::Acquire) {
        core::hint::spin_loop();
    }
}

#[cfg(target_arch = "x86_64")]
fn log_unlock() {
    LOG_LOCK.store(false, core::sync::atomic::Ordering::Release);
}

#[cfg(target_arch = "x86_64")]
unsafe fn log_open_locked() {
    unsafe {
        if LOG_FD >= 0 {
            return;
        }
        let fd = crate::net::socket(AF_UNIX_V, SOCK_DGRAM_V | SOCK_CLOEXEC_V, 0);
        if fd < 0 {
            return;
        }
        let mut addr = [0u8; 16];
        addr[0] = AF_UNIX_V as u8;
        addr[1] = 0;
        let path = b"/dev/log";
        addr[2..2 + path.len()].copy_from_slice(path);
        let r = crate::net::connect(
            fd,
            addr.as_ptr() as *const c_void,
            (2 + path.len() + 1) as u32,
        );
        if r != 0 {
            crate::unistd::close(fd);
            return;
        }
        LOG_FD = fd;
    }
}

/// Set the log priority mask (musl `setlogmask`).
///
/// # Safety
///
/// Pure value call.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setlogmask(mask: c_int) -> c_int {
    unsafe {
        log_lock();
        let old = LOG_MASK_V;
        if mask != 0 {
            LOG_MASK_V = mask;
        }
        log_unlock();
        old
    }
}

/// Open a syslog connection (musl `openlog`: stores ident/option/facility).
///
/// # Safety
///
/// `ident` must be null or point to a NUL-terminated string.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn openlog(ident: *const c_char, opt: c_int, facility: c_int) {
    unsafe {
        log_lock();
        if ident.is_null() {
            *addr_of_mut!(LOG_IDENT).cast::<c_char>() = 0;
        } else {
            let n = c_strlen(ident).min(31);
            core::ptr::copy_nonoverlapping(ident, addr_of_mut!(LOG_IDENT).cast::<c_char>(), n);
            *addr_of_mut!(LOG_IDENT).cast::<c_char>().add(n) = 0;
        }
        LOG_OPT = opt;
        LOG_FACILITY = facility;
        if (opt & LOG_NDELAY) != 0 {
            log_open_locked();
        }
        log_unlock();
    }
}

/// Close the syslog connection (musl `closelog`).
///
/// # Safety
///
/// Pure state call.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn closelog() {
    unsafe {
        log_lock();
        if LOG_FD >= 0 {
            crate::unistd::close(LOG_FD);
            LOG_FD = -1;
        }
        log_unlock();
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn syslog_send(prio: c_int, msg: *const c_char, len: usize) {
    unsafe {
        log_lock();
        let mask = LOG_MASK_V;
        let opt = LOG_OPT;
        let mut ident = [0 as c_char; 32];
        ident.copy_from_slice(&*addr_of_mut!(LOG_IDENT).cast::<[c_char; 32]>());
        if (mask & (1 << (prio & LOG_PRIMASK_V))) == 0 {
            log_unlock();
            return;
        }
        log_open_locked();
        let fd = LOG_FD;
        log_unlock();
        // Frame: "<pri>ident[pid]: msg" (timestamp omitted, see module docs).
        let mut head = [0u8; 96];
        let mut hn = 0usize;
        hn += put_uint(&mut head[hn..], b'<', (prio & 0x3ff) as c_uint);
        head[hn] = b'>';
        hn += 1;
        let mut il = 0usize;
        while il < 31 && ident[il] != 0 {
            il += 1;
        }
        if il > 0 && hn + il + 16 < head.len() {
            core::ptr::copy_nonoverlapping(
                ident.as_ptr() as *const u8,
                head.as_mut_ptr().add(hn),
                il,
            );
            hn += il;
        }
        if (opt & LOG_PID) != 0 && hn + 16 < head.len() {
            let pid = crate::unistd::getpid();
            head[hn] = b'[';
            hn += 1;
            hn += put_int(&mut head[hn..], pid as c_long);
            head[hn] = b']';
            hn += 1;
        }
        if hn + 2 < head.len() {
            head[hn] = b':';
            head[hn + 1] = b' ';
            hn += 2;
        }
        if fd >= 0 {
            let parts = [
                crate::unistd::Iovec {
                    base: head.as_ptr() as *mut c_void,
                    len: hn,
                },
                crate::unistd::Iovec {
                    base: msg as *mut c_void,
                    len,
                },
            ];
            let _ = crate::unistd::writev(fd, parts.as_ptr(), 2);
            if (opt & LOG_CONS) != 0 {
                let _ = crate::unistd::writev(2, parts.as_ptr(), 2);
            }
        } else if (opt & LOG_CONS) != 0 {
            let parts = [
                crate::unistd::Iovec {
                    base: head.as_ptr() as *mut c_void,
                    len: hn,
                },
                crate::unistd::Iovec {
                    base: msg as *mut c_void,
                    len,
                },
            ];
            let _ = crate::unistd::writev(2, parts.as_ptr(), 2);
        }
        if (opt & LOG_PERROR) != 0 {
            let parts = [
                crate::unistd::Iovec {
                    base: head.as_ptr() as *mut c_void,
                    len: hn,
                },
                crate::unistd::Iovec {
                    base: msg as *mut c_void,
                    len,
                },
            ];
            let _ = crate::unistd::writev(2, parts.as_ptr(), 2);
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn put_uint(out: &mut [u8], open: u8, v: c_uint) -> usize {
    let mut tmp = [0u8; 12];
    let mut n: usize;
    let mut x = v;
    tmp[0] = open;
    n = 1;
    if x == 0 {
        tmp[1] = b'0';
        n = 2;
    } else {
        let mut digs = [0u8; 10];
        let mut nd = 0usize;
        while x > 0 {
            digs[nd] = b'0'.wrapping_add((x % 10) as u8);
            nd += 1;
            x /= 10;
        }
        while nd > 0 && n < tmp.len() {
            nd -= 1;
            tmp[n] = digs[nd];
            n += 1;
        }
    }
    let k = n.min(out.len());
    out[..k].copy_from_slice(&tmp[..k]);
    k
}

#[cfg(target_arch = "x86_64")]
fn put_int(out: &mut [u8], v: c_long) -> usize {
    if v < 0 {
        if out.is_empty() {
            return 0;
        }
        out[0] = b'-';
        1 + put_uint(&mut out[1..], b'0', v.wrapping_neg() as c_uint)
    } else {
        let mut tmp = [0u8; 12];
        let k = put_uint(&mut tmp[..], b'0', v as c_uint);
        let n = k.saturating_sub(1).min(out.len());
        out[..n].copy_from_slice(&tmp[1..1 + n]);
        n
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn syslog_inner(prio: c_int, fmt: *const c_char, tag: *mut crate::stdio::VaList) {
    unsafe {
        if fmt.is_null() {
            return;
        }
        let mut buf = [0u8; 1024];
        let r = crate::stdio::vsnprintf(buf.as_mut_ptr() as *mut c_char, buf.len(), fmt, tag);
        if r < 0 {
            return;
        }
        let n = (r as usize).min(buf.len().wrapping_sub(1));
        syslog_send(prio, buf.as_ptr() as *const c_char, n);
    }
}

/// System log with format (musl `syslog`: naked trampoline builds the
/// `VaList` tag exactly like `va_trampoline!` in `crate::stdio` — a macro
/// cannot be used here because the gate greps literal `#[no_mangle]` sites).
///
/// # Safety
///
/// `fmt` must point to a NUL-terminated format; trailing args must match it.
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[unsafe(naked)]
pub unsafe extern "C" fn syslog() {
    core::arch::naked_asm!(
        "mov rax, rsp",
        "sub rsp, 312",
        "mov [rsp], rdi",
        "mov [rsp+8], rsi",
        "mov [rsp+16], rdx",
        "mov [rsp+24], rcx",
        "mov [rsp+32], r8",
        "mov [rsp+40], r9",
        "movups [rsp+48], xmm0",
        "movups [rsp+64], xmm1",
        "movups [rsp+80], xmm2",
        "movups [rsp+96], xmm3",
        "movups [rsp+112], xmm4",
        "movups [rsp+128], xmm5",
        "movups [rsp+144], xmm6",
        "movups [rsp+160], xmm7",
        "mov dword ptr [rsp+176], 16",
        "mov dword ptr [rsp+180], 48",
        "lea rcx, [rax+8]",
        "mov [rsp+184], rcx",
        "mov [rsp+192], rsp",
        "lea rdx, [rsp+176]",
        "call {inner}",
        "add rsp, 312",
        "ret",
        inner = sym syslog_inner,
    )
}

/// System log with `va_list` (musl `vsyslog`).
///
/// # Safety
///
/// `fmt` valid; `ap` a live tag matching it.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn vsyslog(prio: c_int, fmt: *const c_char, ap: *mut crate::stdio::VaList) {
    unsafe {
        syslog_inner(prio, fmt, ap);
    }
}

// ---- klogctl / acct ------------------------------------------------------------------
///
/// Kernel log control (musl: direct `SYS_syslog` trap).
///
/// # Safety
///
/// `buf` must be writable for `len` bytes when the type reads.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn klogctl(ty: c_int, buf: *mut c_char, len: c_int) -> c_int {
    unsafe {
        syscall_ret(syscall3(
            SYS_SYSLOG,
            ty as usize,
            buf as usize,
            len as usize,
        )) as c_int
    }
}

/// Process accounting (musl: direct trap; null path disables).
///
/// # Safety
///
/// `path` must be null or point to a NUL-terminated string.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn acct(path: *const c_char) -> c_int {
    unsafe { syscall_ret(syscall1(SYS_ACCT, path as usize)) as c_int }
}

static KEY_SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
static PSBOX: [[u32; 64]; 8] = [
    [
        0x00808200, 0x00000000, 0x00008000, 0x00808202, 0x00808002, 0x00008202, 0x00000002,
        0x00008000, 0x00000200, 0x00808200, 0x00808202, 0x00000200, 0x00800202, 0x00808002,
        0x00800000, 0x00000002, 0x00000202, 0x00800200, 0x00800200, 0x00008200, 0x00008200,
        0x00808000, 0x00808000, 0x00800202, 0x00008002, 0x00800002, 0x00800002, 0x00008002,
        0x00000000, 0x00000202, 0x00008202, 0x00800000, 0x00008000, 0x00808202, 0x00000002,
        0x00808000, 0x00808200, 0x00800000, 0x00800000, 0x00000200, 0x00808002, 0x00008000,
        0x00008200, 0x00800002, 0x00000200, 0x00000002, 0x00800202, 0x00008202, 0x00808202,
        0x00008002, 0x00808000, 0x00800202, 0x00800002, 0x00000202, 0x00008202, 0x00808200,
        0x00000202, 0x00800200, 0x00800200, 0x00000000, 0x00008002, 0x00008200, 0x00000000,
        0x00808002,
    ],
    [
        0x40084010, 0x40004000, 0x00004000, 0x00084010, 0x00080000, 0x00000010, 0x40080010,
        0x40004010, 0x40000010, 0x40084010, 0x40084000, 0x40000000, 0x40004000, 0x00080000,
        0x00000010, 0x40080010, 0x00084000, 0x00080010, 0x40004010, 0x00000000, 0x40000000,
        0x00004000, 0x00084010, 0x40080000, 0x00080010, 0x40000010, 0x00000000, 0x00084000,
        0x00004010, 0x40084000, 0x40080000, 0x00004010, 0x00000000, 0x00084010, 0x40080010,
        0x00080000, 0x40004010, 0x40080000, 0x40084000, 0x00004000, 0x40080000, 0x40004000,
        0x00000010, 0x40084010, 0x00084010, 0x00000010, 0x00004000, 0x40000000, 0x00004010,
        0x40084000, 0x00080000, 0x40000010, 0x00080010, 0x40004010, 0x40000010, 0x00080010,
        0x00084000, 0x00000000, 0x40004000, 0x00004010, 0x40000000, 0x40080010, 0x40084010,
        0x00084000,
    ],
    [
        0x00000104, 0x04010100, 0x00000000, 0x04010004, 0x04000100, 0x00000000, 0x00010104,
        0x04000100, 0x00010004, 0x04000004, 0x04000004, 0x00010000, 0x04010104, 0x00010004,
        0x04010000, 0x00000104, 0x04000000, 0x00000004, 0x04010100, 0x00000100, 0x00010100,
        0x04010000, 0x04010004, 0x00010104, 0x04000104, 0x00010100, 0x00010000, 0x04000104,
        0x00000004, 0x04010104, 0x00000100, 0x04000000, 0x04010100, 0x04000000, 0x00010004,
        0x00000104, 0x00010000, 0x04010100, 0x04000100, 0x00000000, 0x00000100, 0x00010004,
        0x04010104, 0x04000100, 0x04000004, 0x00000100, 0x00000000, 0x04010004, 0x04000104,
        0x00010000, 0x04000000, 0x04010104, 0x00000004, 0x00010104, 0x00010100, 0x04000004,
        0x04010000, 0x04000104, 0x00000104, 0x04010000, 0x00010104, 0x00000004, 0x04010004,
        0x00010100,
    ],
    [
        0x80401000, 0x80001040, 0x80001040, 0x00000040, 0x00401040, 0x80400040, 0x80400000,
        0x80001000, 0x00000000, 0x00401000, 0x00401000, 0x80401040, 0x80000040, 0x00000000,
        0x00400040, 0x80400000, 0x80000000, 0x00001000, 0x00400000, 0x80401000, 0x00000040,
        0x00400000, 0x80001000, 0x00001040, 0x80400040, 0x80000000, 0x00001040, 0x00400040,
        0x00001000, 0x00401040, 0x80401040, 0x80000040, 0x00400040, 0x80400000, 0x00401000,
        0x80401040, 0x80000040, 0x00000000, 0x00000000, 0x00401000, 0x00001040, 0x00400040,
        0x80400040, 0x80000000, 0x80401000, 0x80001040, 0x80001040, 0x00000040, 0x80401040,
        0x80000040, 0x80000000, 0x00001000, 0x80400000, 0x80001000, 0x00401040, 0x80400040,
        0x80001000, 0x00001040, 0x00400000, 0x80401000, 0x00000040, 0x00400000, 0x00001000,
        0x00401040,
    ],
    [
        0x00000080, 0x01040080, 0x01040000, 0x21000080, 0x00040000, 0x00000080, 0x20000000,
        0x01040000, 0x20040080, 0x00040000, 0x01000080, 0x20040080, 0x21000080, 0x21040000,
        0x00040080, 0x20000000, 0x01000000, 0x20040000, 0x20040000, 0x00000000, 0x20000080,
        0x21040080, 0x21040080, 0x01000080, 0x21040000, 0x20000080, 0x00000000, 0x21000000,
        0x01040080, 0x01000000, 0x21000000, 0x00040080, 0x00040000, 0x21000080, 0x00000080,
        0x01000000, 0x20000000, 0x01040000, 0x21000080, 0x20040080, 0x01000080, 0x20000000,
        0x21040000, 0x01040080, 0x20040080, 0x00000080, 0x01000000, 0x21040000, 0x21040080,
        0x00040080, 0x21000000, 0x21040080, 0x01040000, 0x00000000, 0x20040000, 0x21000000,
        0x00040080, 0x01000080, 0x20000080, 0x00040000, 0x00000000, 0x20040000, 0x01040080,
        0x20000080,
    ],
    [
        0x10000008, 0x10200000, 0x00002000, 0x10202008, 0x10200000, 0x00000008, 0x10202008,
        0x00200000, 0x10002000, 0x00202008, 0x00200000, 0x10000008, 0x00200008, 0x10002000,
        0x10000000, 0x00002008, 0x00000000, 0x00200008, 0x10002008, 0x00002000, 0x00202000,
        0x10002008, 0x00000008, 0x10200008, 0x10200008, 0x00000000, 0x00202008, 0x10202000,
        0x00002008, 0x00202000, 0x10202000, 0x10000000, 0x10002000, 0x00000008, 0x10200008,
        0x00202000, 0x10202008, 0x00200000, 0x00002008, 0x10000008, 0x00200000, 0x10002000,
        0x10000000, 0x00002008, 0x10000008, 0x10202008, 0x00202000, 0x10200000, 0x00202008,
        0x10202000, 0x00000000, 0x10200008, 0x00000008, 0x00002000, 0x10200000, 0x00202008,
        0x00002000, 0x00200008, 0x10002008, 0x00000000, 0x10202000, 0x10000000, 0x00200008,
        0x10002008,
    ],
    [
        0x00100000, 0x02100001, 0x02000401, 0x00000000, 0x00000400, 0x02000401, 0x00100401,
        0x02100400, 0x02100401, 0x00100000, 0x00000000, 0x02000001, 0x00000001, 0x02000000,
        0x02100001, 0x00000401, 0x02000400, 0x00100401, 0x00100001, 0x02000400, 0x02000001,
        0x02100000, 0x02100400, 0x00100001, 0x02100000, 0x00000400, 0x00000401, 0x02100401,
        0x00100400, 0x00000001, 0x02000000, 0x00100400, 0x02000000, 0x00100400, 0x00100000,
        0x02000401, 0x02000401, 0x02100001, 0x02100001, 0x00000001, 0x00100001, 0x02000000,
        0x02000400, 0x00100000, 0x02100400, 0x00000401, 0x00100401, 0x02100400, 0x00000401,
        0x02000001, 0x02100401, 0x02100000, 0x00100400, 0x00000000, 0x00000001, 0x02100401,
        0x00000000, 0x00100401, 0x02100000, 0x00000400, 0x02000001, 0x02000400, 0x00000400,
        0x00100001,
    ],
    [
        0x08000820, 0x00000800, 0x00020000, 0x08020820, 0x08000000, 0x08000820, 0x00000020,
        0x08000000, 0x00020020, 0x08020000, 0x08020820, 0x00020800, 0x08020800, 0x00020820,
        0x00000800, 0x00000020, 0x08020000, 0x08000020, 0x08000800, 0x00000820, 0x00020800,
        0x00020020, 0x08020020, 0x08020800, 0x00000820, 0x00000000, 0x00000000, 0x08020020,
        0x08000020, 0x08000800, 0x00020820, 0x00020000, 0x00020820, 0x00020000, 0x08020800,
        0x00000800, 0x00000020, 0x08020020, 0x00000800, 0x00020820, 0x08000800, 0x00000020,
        0x08000020, 0x08020000, 0x08020020, 0x08000000, 0x00020000, 0x08000820, 0x00000000,
        0x08020820, 0x00020020, 0x08000020, 0x08020000, 0x08000800, 0x08000820, 0x00000000,
        0x08020820, 0x00020800, 0x00020800, 0x00000820, 0x00000820, 0x00020020, 0x08000000,
        0x08020800,
    ],
];
static IP_MASKL: [[u32; 16]; 16] = [
    [
        0x00000000, 0x00010000, 0x00000000, 0x00010000, 0x01000000, 0x01010000, 0x01000000,
        0x01010000, 0x00000000, 0x00010000, 0x00000000, 0x00010000, 0x01000000, 0x01010000,
        0x01000000, 0x01010000,
    ],
    [
        0x00000000, 0x00000001, 0x00000000, 0x00000001, 0x00000100, 0x00000101, 0x00000100,
        0x00000101, 0x00000000, 0x00000001, 0x00000000, 0x00000001, 0x00000100, 0x00000101,
        0x00000100, 0x00000101,
    ],
    [
        0x00000000, 0x00020000, 0x00000000, 0x00020000, 0x02000000, 0x02020000, 0x02000000,
        0x02020000, 0x00000000, 0x00020000, 0x00000000, 0x00020000, 0x02000000, 0x02020000,
        0x02000000, 0x02020000,
    ],
    [
        0x00000000, 0x00000002, 0x00000000, 0x00000002, 0x00000200, 0x00000202, 0x00000200,
        0x00000202, 0x00000000, 0x00000002, 0x00000000, 0x00000002, 0x00000200, 0x00000202,
        0x00000200, 0x00000202,
    ],
    [
        0x00000000, 0x00040000, 0x00000000, 0x00040000, 0x04000000, 0x04040000, 0x04000000,
        0x04040000, 0x00000000, 0x00040000, 0x00000000, 0x00040000, 0x04000000, 0x04040000,
        0x04000000, 0x04040000,
    ],
    [
        0x00000000, 0x00000004, 0x00000000, 0x00000004, 0x00000400, 0x00000404, 0x00000400,
        0x00000404, 0x00000000, 0x00000004, 0x00000000, 0x00000004, 0x00000400, 0x00000404,
        0x00000400, 0x00000404,
    ],
    [
        0x00000000, 0x00080000, 0x00000000, 0x00080000, 0x08000000, 0x08080000, 0x08000000,
        0x08080000, 0x00000000, 0x00080000, 0x00000000, 0x00080000, 0x08000000, 0x08080000,
        0x08000000, 0x08080000,
    ],
    [
        0x00000000, 0x00000008, 0x00000000, 0x00000008, 0x00000800, 0x00000808, 0x00000800,
        0x00000808, 0x00000000, 0x00000008, 0x00000000, 0x00000008, 0x00000800, 0x00000808,
        0x00000800, 0x00000808,
    ],
    [
        0x00000000, 0x00100000, 0x00000000, 0x00100000, 0x10000000, 0x10100000, 0x10000000,
        0x10100000, 0x00000000, 0x00100000, 0x00000000, 0x00100000, 0x10000000, 0x10100000,
        0x10000000, 0x10100000,
    ],
    [
        0x00000000, 0x00000010, 0x00000000, 0x00000010, 0x00001000, 0x00001010, 0x00001000,
        0x00001010, 0x00000000, 0x00000010, 0x00000000, 0x00000010, 0x00001000, 0x00001010,
        0x00001000, 0x00001010,
    ],
    [
        0x00000000, 0x00200000, 0x00000000, 0x00200000, 0x20000000, 0x20200000, 0x20000000,
        0x20200000, 0x00000000, 0x00200000, 0x00000000, 0x00200000, 0x20000000, 0x20200000,
        0x20000000, 0x20200000,
    ],
    [
        0x00000000, 0x00000020, 0x00000000, 0x00000020, 0x00002000, 0x00002020, 0x00002000,
        0x00002020, 0x00000000, 0x00000020, 0x00000000, 0x00000020, 0x00002000, 0x00002020,
        0x00002000, 0x00002020,
    ],
    [
        0x00000000, 0x00400000, 0x00000000, 0x00400000, 0x40000000, 0x40400000, 0x40000000,
        0x40400000, 0x00000000, 0x00400000, 0x00000000, 0x00400000, 0x40000000, 0x40400000,
        0x40000000, 0x40400000,
    ],
    [
        0x00000000, 0x00000040, 0x00000000, 0x00000040, 0x00004000, 0x00004040, 0x00004000,
        0x00004040, 0x00000000, 0x00000040, 0x00000000, 0x00000040, 0x00004000, 0x00004040,
        0x00004000, 0x00004040,
    ],
    [
        0x00000000, 0x00800000, 0x00000000, 0x00800000, 0x80000000, 0x80800000, 0x80000000,
        0x80800000, 0x00000000, 0x00800000, 0x00000000, 0x00800000, 0x80000000, 0x80800000,
        0x80000000, 0x80800000,
    ],
    [
        0x00000000, 0x00000080, 0x00000000, 0x00000080, 0x00008000, 0x00008080, 0x00008000,
        0x00008080, 0x00000000, 0x00000080, 0x00000000, 0x00000080, 0x00008000, 0x00008080,
        0x00008000, 0x00008080,
    ],
];
static IP_MASKR: [[u32; 16]; 16] = [
    [
        0x00000000, 0x00000000, 0x00010000, 0x00010000, 0x00000000, 0x00000000, 0x00010000,
        0x00010000, 0x01000000, 0x01000000, 0x01010000, 0x01010000, 0x01000000, 0x01000000,
        0x01010000, 0x01010000,
    ],
    [
        0x00000000, 0x00000000, 0x00000001, 0x00000001, 0x00000000, 0x00000000, 0x00000001,
        0x00000001, 0x00000100, 0x00000100, 0x00000101, 0x00000101, 0x00000100, 0x00000100,
        0x00000101, 0x00000101,
    ],
    [
        0x00000000, 0x00000000, 0x00020000, 0x00020000, 0x00000000, 0x00000000, 0x00020000,
        0x00020000, 0x02000000, 0x02000000, 0x02020000, 0x02020000, 0x02000000, 0x02000000,
        0x02020000, 0x02020000,
    ],
    [
        0x00000000, 0x00000000, 0x00000002, 0x00000002, 0x00000000, 0x00000000, 0x00000002,
        0x00000002, 0x00000200, 0x00000200, 0x00000202, 0x00000202, 0x00000200, 0x00000200,
        0x00000202, 0x00000202,
    ],
    [
        0x00000000, 0x00000000, 0x00040000, 0x00040000, 0x00000000, 0x00000000, 0x00040000,
        0x00040000, 0x04000000, 0x04000000, 0x04040000, 0x04040000, 0x04000000, 0x04000000,
        0x04040000, 0x04040000,
    ],
    [
        0x00000000, 0x00000000, 0x00000004, 0x00000004, 0x00000000, 0x00000000, 0x00000004,
        0x00000004, 0x00000400, 0x00000400, 0x00000404, 0x00000404, 0x00000400, 0x00000400,
        0x00000404, 0x00000404,
    ],
    [
        0x00000000, 0x00000000, 0x00080000, 0x00080000, 0x00000000, 0x00000000, 0x00080000,
        0x00080000, 0x08000000, 0x08000000, 0x08080000, 0x08080000, 0x08000000, 0x08000000,
        0x08080000, 0x08080000,
    ],
    [
        0x00000000, 0x00000000, 0x00000008, 0x00000008, 0x00000000, 0x00000000, 0x00000008,
        0x00000008, 0x00000800, 0x00000800, 0x00000808, 0x00000808, 0x00000800, 0x00000800,
        0x00000808, 0x00000808,
    ],
    [
        0x00000000, 0x00000000, 0x00100000, 0x00100000, 0x00000000, 0x00000000, 0x00100000,
        0x00100000, 0x10000000, 0x10000000, 0x10100000, 0x10100000, 0x10000000, 0x10000000,
        0x10100000, 0x10100000,
    ],
    [
        0x00000000, 0x00000000, 0x00000010, 0x00000010, 0x00000000, 0x00000000, 0x00000010,
        0x00000010, 0x00001000, 0x00001000, 0x00001010, 0x00001010, 0x00001000, 0x00001000,
        0x00001010, 0x00001010,
    ],
    [
        0x00000000, 0x00000000, 0x00200000, 0x00200000, 0x00000000, 0x00000000, 0x00200000,
        0x00200000, 0x20000000, 0x20000000, 0x20200000, 0x20200000, 0x20000000, 0x20000000,
        0x20200000, 0x20200000,
    ],
    [
        0x00000000, 0x00000000, 0x00000020, 0x00000020, 0x00000000, 0x00000000, 0x00000020,
        0x00000020, 0x00002000, 0x00002000, 0x00002020, 0x00002020, 0x00002000, 0x00002000,
        0x00002020, 0x00002020,
    ],
    [
        0x00000000, 0x00000000, 0x00400000, 0x00400000, 0x00000000, 0x00000000, 0x00400000,
        0x00400000, 0x40000000, 0x40000000, 0x40400000, 0x40400000, 0x40000000, 0x40000000,
        0x40400000, 0x40400000,
    ],
    [
        0x00000000, 0x00000000, 0x00000040, 0x00000040, 0x00000000, 0x00000000, 0x00000040,
        0x00000040, 0x00004000, 0x00004000, 0x00004040, 0x00004040, 0x00004000, 0x00004000,
        0x00004040, 0x00004040,
    ],
    [
        0x00000000, 0x00000000, 0x00800000, 0x00800000, 0x00000000, 0x00000000, 0x00800000,
        0x00800000, 0x80000000, 0x80000000, 0x80800000, 0x80800000, 0x80000000, 0x80000000,
        0x80800000, 0x80800000,
    ],
    [
        0x00000000, 0x00000000, 0x00000080, 0x00000080, 0x00000000, 0x00000000, 0x00000080,
        0x00000080, 0x00008000, 0x00008000, 0x00008080, 0x00008080, 0x00008000, 0x00008000,
        0x00008080, 0x00008080,
    ],
];
static FP_MASKL: [[u32; 16]; 8] = [
    [
        0x00000000, 0x40000000, 0x00400000, 0x40400000, 0x00004000, 0x40004000, 0x00404000,
        0x40404000, 0x00000040, 0x40000040, 0x00400040, 0x40400040, 0x00004040, 0x40004040,
        0x00404040, 0x40404040,
    ],
    [
        0x00000000, 0x10000000, 0x00100000, 0x10100000, 0x00001000, 0x10001000, 0x00101000,
        0x10101000, 0x00000010, 0x10000010, 0x00100010, 0x10100010, 0x00001010, 0x10001010,
        0x00101010, 0x10101010,
    ],
    [
        0x00000000, 0x04000000, 0x00040000, 0x04040000, 0x00000400, 0x04000400, 0x00040400,
        0x04040400, 0x00000004, 0x04000004, 0x00040004, 0x04040004, 0x00000404, 0x04000404,
        0x00040404, 0x04040404,
    ],
    [
        0x00000000, 0x01000000, 0x00010000, 0x01010000, 0x00000100, 0x01000100, 0x00010100,
        0x01010100, 0x00000001, 0x01000001, 0x00010001, 0x01010001, 0x00000101, 0x01000101,
        0x00010101, 0x01010101,
    ],
    [
        0x00000000, 0x80000000, 0x00800000, 0x80800000, 0x00008000, 0x80008000, 0x00808000,
        0x80808000, 0x00000080, 0x80000080, 0x00800080, 0x80800080, 0x00008080, 0x80008080,
        0x00808080, 0x80808080,
    ],
    [
        0x00000000, 0x20000000, 0x00200000, 0x20200000, 0x00002000, 0x20002000, 0x00202000,
        0x20202000, 0x00000020, 0x20000020, 0x00200020, 0x20200020, 0x00002020, 0x20002020,
        0x00202020, 0x20202020,
    ],
    [
        0x00000000, 0x08000000, 0x00080000, 0x08080000, 0x00000800, 0x08000800, 0x00080800,
        0x08080800, 0x00000008, 0x08000008, 0x00080008, 0x08080008, 0x00000808, 0x08000808,
        0x00080808, 0x08080808,
    ],
    [
        0x00000000, 0x02000000, 0x00020000, 0x02020000, 0x00000200, 0x02000200, 0x00020200,
        0x02020200, 0x00000002, 0x02000002, 0x00020002, 0x02020002, 0x00000202, 0x02000202,
        0x00020202, 0x02020202,
    ],
];
static FP_MASKR: [[u32; 16]; 8] = [
    [
        0x00000000, 0x40000000, 0x00400000, 0x40400000, 0x00004000, 0x40004000, 0x00404000,
        0x40404000, 0x00000040, 0x40000040, 0x00400040, 0x40400040, 0x00004040, 0x40004040,
        0x00404040, 0x40404040,
    ],
    [
        0x00000000, 0x10000000, 0x00100000, 0x10100000, 0x00001000, 0x10001000, 0x00101000,
        0x10101000, 0x00000010, 0x10000010, 0x00100010, 0x10100010, 0x00001010, 0x10001010,
        0x00101010, 0x10101010,
    ],
    [
        0x00000000, 0x04000000, 0x00040000, 0x04040000, 0x00000400, 0x04000400, 0x00040400,
        0x04040400, 0x00000004, 0x04000004, 0x00040004, 0x04040004, 0x00000404, 0x04000404,
        0x00040404, 0x04040404,
    ],
    [
        0x00000000, 0x01000000, 0x00010000, 0x01010000, 0x00000100, 0x01000100, 0x00010100,
        0x01010100, 0x00000001, 0x01000001, 0x00010001, 0x01010001, 0x00000101, 0x01000101,
        0x00010101, 0x01010101,
    ],
    [
        0x00000000, 0x80000000, 0x00800000, 0x80800000, 0x00008000, 0x80008000, 0x00808000,
        0x80808000, 0x00000080, 0x80000080, 0x00800080, 0x80800080, 0x00008080, 0x80008080,
        0x00808080, 0x80808080,
    ],
    [
        0x00000000, 0x20000000, 0x00200000, 0x20200000, 0x00002000, 0x20002000, 0x00202000,
        0x20202000, 0x00000020, 0x20000020, 0x00200020, 0x20200020, 0x00002020, 0x20002020,
        0x00202020, 0x20202020,
    ],
    [
        0x00000000, 0x08000000, 0x00080000, 0x08080000, 0x00000800, 0x08000800, 0x00080800,
        0x08080800, 0x00000008, 0x08000008, 0x00080008, 0x08080008, 0x00000808, 0x08000808,
        0x00080808, 0x08080808,
    ],
    [
        0x00000000, 0x02000000, 0x00020000, 0x02020000, 0x00000200, 0x02000200, 0x00020200,
        0x02020200, 0x00000002, 0x02000002, 0x00020002, 0x02020002, 0x00000202, 0x02000202,
        0x00020202, 0x02020202,
    ],
];
static KEY_PERM_MASKL: [[u32; 16]; 8] = [
    [
        0x00000000, 0x00000000, 0x00000010, 0x00000010, 0x00001000, 0x00001000, 0x00001010,
        0x00001010, 0x00100000, 0x00100000, 0x00100010, 0x00100010, 0x00101000, 0x00101000,
        0x00101010, 0x00101010,
    ],
    [
        0x00000000, 0x00000000, 0x00000020, 0x00000020, 0x00002000, 0x00002000, 0x00002020,
        0x00002020, 0x00200000, 0x00200000, 0x00200020, 0x00200020, 0x00202000, 0x00202000,
        0x00202020, 0x00202020,
    ],
    [
        0x00000000, 0x00000000, 0x00000040, 0x00000040, 0x00004000, 0x00004000, 0x00004040,
        0x00004040, 0x00400000, 0x00400000, 0x00400040, 0x00400040, 0x00404000, 0x00404000,
        0x00404040, 0x00404040,
    ],
    [
        0x00000000, 0x00000000, 0x00000080, 0x00000080, 0x00008000, 0x00008000, 0x00008080,
        0x00008080, 0x00800000, 0x00800000, 0x00800080, 0x00800080, 0x00808000, 0x00808000,
        0x00808080, 0x00808080,
    ],
    [
        0x00000000, 0x00000001, 0x00000100, 0x00000101, 0x00010000, 0x00010001, 0x00010100,
        0x00010101, 0x01000000, 0x01000001, 0x01000100, 0x01000101, 0x01010000, 0x01010001,
        0x01010100, 0x01010101,
    ],
    [
        0x00000000, 0x00000002, 0x00000200, 0x00000202, 0x00020000, 0x00020002, 0x00020200,
        0x00020202, 0x02000000, 0x02000002, 0x02000200, 0x02000202, 0x02020000, 0x02020002,
        0x02020200, 0x02020202,
    ],
    [
        0x00000000, 0x00000004, 0x00000400, 0x00000404, 0x00040000, 0x00040004, 0x00040400,
        0x00040404, 0x04000000, 0x04000004, 0x04000400, 0x04000404, 0x04040000, 0x04040004,
        0x04040400, 0x04040404,
    ],
    [
        0x00000000, 0x00000008, 0x00000800, 0x00000808, 0x00080000, 0x00080008, 0x00080800,
        0x00080808, 0x08000000, 0x08000008, 0x08000800, 0x08000808, 0x08080000, 0x08080008,
        0x08080800, 0x08080808,
    ],
];
static KEY_PERM_MASKR: [[u32; 16]; 12] = [
    [
        0x00000000, 0x00000001, 0x00000000, 0x00000001, 0x00000000, 0x00000001, 0x00000000,
        0x00000001, 0x00000000, 0x00000001, 0x00000000, 0x00000001, 0x00000000, 0x00000001,
        0x00000000, 0x00000001,
    ],
    [
        0x00000000, 0x00000000, 0x00100000, 0x00100000, 0x00001000, 0x00001000, 0x00101000,
        0x00101000, 0x00000010, 0x00000010, 0x00100010, 0x00100010, 0x00001010, 0x00001010,
        0x00101010, 0x00101010,
    ],
    [
        0x00000000, 0x00000002, 0x00000000, 0x00000002, 0x00000000, 0x00000002, 0x00000000,
        0x00000002, 0x00000000, 0x00000002, 0x00000000, 0x00000002, 0x00000000, 0x00000002,
        0x00000000, 0x00000002,
    ],
    [
        0x00000000, 0x00000000, 0x00200000, 0x00200000, 0x00002000, 0x00002000, 0x00202000,
        0x00202000, 0x00000020, 0x00000020, 0x00200020, 0x00200020, 0x00002020, 0x00002020,
        0x00202020, 0x00202020,
    ],
    [
        0x00000000, 0x00000004, 0x00000000, 0x00000004, 0x00000000, 0x00000004, 0x00000000,
        0x00000004, 0x00000000, 0x00000004, 0x00000000, 0x00000004, 0x00000000, 0x00000004,
        0x00000000, 0x00000004,
    ],
    [
        0x00000000, 0x00000000, 0x00400000, 0x00400000, 0x00004000, 0x00004000, 0x00404000,
        0x00404000, 0x00000040, 0x00000040, 0x00400040, 0x00400040, 0x00004040, 0x00004040,
        0x00404040, 0x00404040,
    ],
    [
        0x00000000, 0x00000008, 0x00000000, 0x00000008, 0x00000000, 0x00000008, 0x00000000,
        0x00000008, 0x00000000, 0x00000008, 0x00000000, 0x00000008, 0x00000000, 0x00000008,
        0x00000000, 0x00000008,
    ],
    [
        0x00000000, 0x00000000, 0x00800000, 0x00800000, 0x00008000, 0x00008000, 0x00808000,
        0x00808000, 0x00000080, 0x00000080, 0x00800080, 0x00800080, 0x00008080, 0x00008080,
        0x00808080, 0x00808080,
    ],
    [
        0x00000000, 0x00000000, 0x01000000, 0x01000000, 0x00010000, 0x00010000, 0x01010000,
        0x01010000, 0x00000100, 0x00000100, 0x01000100, 0x01000100, 0x00010100, 0x00010100,
        0x01010100, 0x01010100,
    ],
    [
        0x00000000, 0x00000000, 0x02000000, 0x02000000, 0x00020000, 0x00020000, 0x02020000,
        0x02020000, 0x00000200, 0x00000200, 0x02000200, 0x02000200, 0x00020200, 0x00020200,
        0x02020200, 0x02020200,
    ],
    [
        0x00000000, 0x00000000, 0x04000000, 0x04000000, 0x00040000, 0x00040000, 0x04040000,
        0x04040000, 0x00000400, 0x00000400, 0x04000400, 0x04000400, 0x00040400, 0x00040400,
        0x04040400, 0x04040400,
    ],
    [
        0x00000000, 0x00000000, 0x08000000, 0x08000000, 0x00080000, 0x00080000, 0x08080000,
        0x08080000, 0x00000800, 0x00000800, 0x08000800, 0x08000800, 0x00080800, 0x00080800,
        0x08080800, 0x08080800,
    ],
];
static COMP_MASKL0: [[u32; 8]; 4] = [
    [
        0x00000000, 0x00020000, 0x00000001, 0x00020001, 0x00080000, 0x000a0000, 0x00080001,
        0x000a0001,
    ],
    [
        0x00000000, 0x00001000, 0x00000000, 0x00001000, 0x00000040, 0x00001040, 0x00000040,
        0x00001040,
    ],
    [
        0x00000000, 0x00400000, 0x00000020, 0x00400020, 0x00008000, 0x00408000, 0x00008020,
        0x00408020,
    ],
    [
        0x00000000, 0x00100000, 0x00000800, 0x00100800, 0x00000000, 0x00100000, 0x00000800,
        0x00100800,
    ],
];
static COMP_MASKR0: [[u32; 8]; 4] = [
    [
        0x00000000, 0x00200000, 0x00020000, 0x00220000, 0x00000002, 0x00200002, 0x00020002,
        0x00220002,
    ],
    [
        0x00000000, 0x00000000, 0x00100000, 0x00100000, 0x00000004, 0x00000004, 0x00100004,
        0x00100004,
    ],
    [
        0x00000000, 0x00004000, 0x00000800, 0x00004800, 0x00000000, 0x00004000, 0x00000800,
        0x00004800,
    ],
    [
        0x00000000, 0x00400000, 0x00008000, 0x00408000, 0x00000008, 0x00400008, 0x00008008,
        0x00408008,
    ],
];
static COMP_MASKL1: [[u32; 16]; 4] = [
    [
        0x00000000, 0x00000010, 0x00004000, 0x00004010, 0x00040000, 0x00040010, 0x00044000,
        0x00044010, 0x00000100, 0x00000110, 0x00004100, 0x00004110, 0x00040100, 0x00040110,
        0x00044100, 0x00044110,
    ],
    [
        0x00000000, 0x00800000, 0x00000002, 0x00800002, 0x00000200, 0x00800200, 0x00000202,
        0x00800202, 0x00200000, 0x00a00000, 0x00200002, 0x00a00002, 0x00200200, 0x00a00200,
        0x00200202, 0x00a00202,
    ],
    [
        0x00000000, 0x00002000, 0x00000004, 0x00002004, 0x00000400, 0x00002400, 0x00000404,
        0x00002404, 0x00000000, 0x00002000, 0x00000004, 0x00002004, 0x00000400, 0x00002400,
        0x00000404, 0x00002404,
    ],
    [
        0x00000000, 0x00010000, 0x00000008, 0x00010008, 0x00000080, 0x00010080, 0x00000088,
        0x00010088, 0x00000000, 0x00010000, 0x00000008, 0x00010008, 0x00000080, 0x00010080,
        0x00000088, 0x00010088,
    ],
];
static COMP_MASKR1: [[u32; 16]; 4] = [
    [
        0x00000000, 0x00000000, 0x00000080, 0x00000080, 0x00002000, 0x00002000, 0x00002080,
        0x00002080, 0x00000001, 0x00000001, 0x00000081, 0x00000081, 0x00002001, 0x00002001,
        0x00002081, 0x00002081,
    ],
    [
        0x00000000, 0x00000010, 0x00800000, 0x00800010, 0x00010000, 0x00010010, 0x00810000,
        0x00810010, 0x00000200, 0x00000210, 0x00800200, 0x00800210, 0x00010200, 0x00010210,
        0x00810200, 0x00810210,
    ],
    [
        0x00000000, 0x00000400, 0x00001000, 0x00001400, 0x00080000, 0x00080400, 0x00081000,
        0x00081400, 0x00000020, 0x00000420, 0x00001020, 0x00001420, 0x00080020, 0x00080420,
        0x00081020, 0x00081420,
    ],
    [
        0x00000000, 0x00000100, 0x00040000, 0x00040100, 0x00000000, 0x00000100, 0x00040000,
        0x00040100, 0x00000040, 0x00000140, 0x00040040, 0x00040140, 0x00000040, 0x00000140,
        0x00040040, 0x00040140,
    ],
];

static MD5_TAB: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];
static SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
static SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

// ---- DES crypt (musl src/crypt/crypt_des.c, tables above) -------------------------------
#[cfg(target_arch = "x86_64")]
struct ExpandedKey {
    l: [u32; 16],
    r: [u32; 16],
}

#[cfg(target_arch = "x86_64")]
const ASCII64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#[cfg(target_arch = "x86_64")]
fn ascii_to_bin(ch: c_int) -> u32 {
    let sch = if ch < 0x80 { ch } else { ch - 0x100 };
    let mut r = sch - b'.' as c_int;
    if sch >= b'A' as c_int {
        r = sch - (b'A' as c_int - 12);
        if sch >= b'a' as c_int {
            r = sch - (b'a' as c_int - 38);
        }
    }
    (r & 0x3f) as u32
}

#[cfg(target_arch = "x86_64")]
fn ascii_is_unsafe(ch: u8) -> bool {
    ch == 0 || ch == b'\n' || ch == b':'
}

#[cfg(target_arch = "x86_64")]
fn setup_salt(salt: u32) -> u32 {
    let mut bits = 0u32;
    let mut bit = 1u32;
    let mut obit = 0x800000u32;
    for _ in 0..24 {
        if salt & bit != 0 {
            bits |= obit;
        }
        bit <<= 1;
        obit >>= 1;
    }
    bits
}

#[cfg(target_arch = "x86_64")]
fn des_setkey(key: &[u8; 8], ekey: &mut ExpandedKey) {
    let raw0 = (key[3] as u32)
        | ((key[2] as u32) << 8)
        | ((key[1] as u32) << 16)
        | ((key[0] as u32) << 24);
    let raw1 = (key[7] as u32)
        | ((key[6] as u32) << 8)
        | ((key[5] as u32) << 16)
        | ((key[4] as u32) << 24);
    let (mut k0, mut k1) = (0u32, 0u32);
    let mut ibit = 28u32;
    for i in 0..4 {
        let j = i << 1;
        k0 |= KEY_PERM_MASKL[i][((raw0 >> ibit) & 0xf) as usize]
            | KEY_PERM_MASKL[i + 4][((raw1 >> ibit) & 0xf) as usize];
        k1 |= KEY_PERM_MASKR[j][((raw0 >> ibit) & 0xf) as usize];
        ibit = ibit.wrapping_sub(4);
        k1 |= KEY_PERM_MASKR[j + 1][((raw0 >> ibit) & 0xf) as usize]
            | KEY_PERM_MASKR[i + 8][((raw1 >> ibit) & 0xf) as usize];
        ibit = ibit.wrapping_sub(4);
    }
    let mut shifts = 0u32;
    for (round, sh) in KEY_SHIFTS.iter().enumerate() {
        shifts += *sh as u32;
        // 28-bit rotates (musl masks after the OR; a 32-bit rotate leaks
        // key bits into the top nibble and poisons every subkey).
        let t0 = ((k0 << shifts) | (k0 >> (28 - shifts))) & 0x0fff_ffff;
        let t1 = ((k1 << shifts) | (k1 >> (28 - shifts))) & 0x0fff_ffff;
        let (mut kl, mut kr) = (0u32, 0u32);
        let mut ib = 25u32;
        for i in 0..4 {
            kl |= COMP_MASKL0[i][((t0 >> ib) & 7) as usize];
            kr |= COMP_MASKR0[i][((t1 >> ib) & 7) as usize];
            ib = ib.wrapping_sub(4);
            kl |= COMP_MASKL1[i][((t0 >> ib) & 0xf) as usize];
            kr |= COMP_MASKR1[i][((t1 >> ib) & 0xf) as usize];
            ib = ib.wrapping_sub(3);
        }
        ekey.l[round] = kl;
        ekey.r[round] = kr;
    }
}

#[cfg(target_arch = "x86_64")]
fn do_des(l_in: u32, r_in: u32, count: u32, saltbits: u32, ekey: &ExpandedKey) -> (u32, u32) {
    let (mut l, mut r) = (0u32, 0u32);
    if l_in | r_in != 0 {
        let mut ibit = 28u32;
        for i in 0..8 {
            l |= IP_MASKL[i][((l_in >> ibit) & 0xf) as usize]
                | IP_MASKL[i + 8][((r_in >> ibit) & 0xf) as usize];
            r |= IP_MASKR[i][((l_in >> ibit) & 0xf) as usize]
                | IP_MASKR[i + 8][((r_in >> ibit) & 0xf) as usize];
            ibit = ibit.wrapping_sub(4);
        }
    }
    let mut n = count;
    while {
        let nn = n;
        n = n.wrapping_sub(1);
        nn != 0
    } {
        let mut round = 16usize;
        let (mut kl, mut kr) = (0usize, 0usize);
        let mut f = 0u32;
        while {
            let rr = round;
            round = round.wrapping_sub(1);
            rr != 0
        } {
            let mut r48l = ((r & 1) << 23)
                | ((r & 0xf8000000) >> 9)
                | ((r & 0x1f800000) >> 11)
                | ((r & 0x01f80000) >> 13)
                | ((r & 0x001f8000) >> 15);
            let mut r48r = ((r & 0x0001f800) << 7)
                | ((r & 0x00001f80) << 5)
                | ((r & 0x000001f8) << 3)
                | ((r & 0x0000001f) << 1)
                | ((r & 0x80000000) >> 31);
            f = (r48l ^ r48r) & saltbits;
            r48l ^= f ^ ekey.l[kl];
            kl += 1;
            r48r ^= f ^ ekey.r[kr];
            kr += 1;
            f = PSBOX[0][(r48l >> 18) as usize]
                | PSBOX[1][((r48l >> 12) & 0x3f) as usize]
                | PSBOX[2][((r48l >> 6) & 0x3f) as usize]
                | PSBOX[3][(r48l & 0x3f) as usize]
                | PSBOX[4][(r48r >> 18) as usize]
                | PSBOX[5][((r48r >> 12) & 0x3f) as usize]
                | PSBOX[6][((r48r >> 6) & 0x3f) as usize]
                | PSBOX[7][(r48r & 0x3f) as usize];
            f ^= l;
            l = r;
            r = f;
        }
        r = l;
        l = f;
    }
    let (mut lo, mut ro) = (0u32, 0u32);
    let mut ibit = 28u32;
    for i in 0..4 {
        ro |= FP_MASKR[i][((l >> ibit) & 0xf) as usize]
            | FP_MASKR[i + 4][((r >> ibit) & 0xf) as usize];
        ibit -= 4;
        lo |= FP_MASKL[i][((l >> ibit) & 0xf) as usize]
            | FP_MASKL[i + 4][((r >> ibit) & 0xf) as usize];
        ibit = ibit.wrapping_sub(4);
    }
    (lo, ro)
}

#[cfg(target_arch = "x86_64")]
unsafe fn des_cipher(inp: *const u8, out: *mut u8, count: u32, saltbits: u32, ekey: &ExpandedKey) {
    unsafe {
        let rawl = (*inp.add(3) as u32)
            | ((*inp.add(2) as u32) << 8)
            | ((*inp.add(1) as u32) << 16)
            | ((*inp as u32) << 24);
        let rawr = (*inp.add(7) as u32)
            | ((*inp.add(6) as u32) << 8)
            | ((*inp.add(5) as u32) << 16)
            | ((*inp.add(4) as u32) << 24);
        let (lo, ro) = do_des(rawl, rawr, count, saltbits, ekey);
        *out = (lo >> 24) as u8;
        *out.add(1) = (lo >> 16) as u8;
        *out.add(2) = (lo >> 8) as u8;
        *out.add(3) = lo as u8;
        *out.add(4) = (ro >> 24) as u8;
        *out.add(5) = (ro >> 16) as u8;
        *out.add(6) = (ro >> 8) as u8;
        *out.add(7) = ro as u8;
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn crypt_extended(key: *const u8, setting: *const u8, output: *mut u8) -> *mut u8 {
    unsafe {
        let mut ekey = ExpandedKey {
            l: [0; 16],
            r: [0; 16],
        };
        let mut keybuf = [0u8; 8];
        let mut kp = key;
        for q in keybuf.iter_mut() {
            *q = (*kp).wrapping_shl(1);
            if *kp != 0 {
                kp = kp.add(1);
            }
        }
        des_setkey(&keybuf, &mut ekey);
        let mut p: *mut u8;
        let (count, salt): (u32, u32);
        if *setting == b'_' {
            let mut c = 0u32;
            for i in 1..5 {
                let v = ascii_to_bin(*setting.add(i) as c_int);
                if ASCII64[v as usize] != *setting.add(i) {
                    return null_mut();
                }
                c |= v << ((i - 1) * 6);
            }
            if c == 0 {
                return null_mut();
            }
            let mut s = 0u32;
            for i in 5..9 {
                let v = ascii_to_bin(*setting.add(i) as c_int);
                if ASCII64[v as usize] != *setting.add(i) {
                    return null_mut();
                }
                s |= v << ((i - 5) * 6);
            }
            count = c;
            salt = s;
            let mut kk = key;
            while *kk != 0 {
                des_cipher(keybuf.as_ptr(), keybuf.as_mut_ptr(), 1, 0, &ekey);
                let mut q = 0usize;
                while q < 8 && *kk != 0 {
                    keybuf[q] ^= (*kk).wrapping_shl(1);
                    q += 1;
                    kk = kk.add(1);
                }
                des_setkey(&keybuf, &mut ekey);
            }
            core::ptr::copy_nonoverlapping(setting, output, 9);
            *output.add(9) = 0;
            p = output.add(9);
        } else {
            count = 25;
            if ascii_is_unsafe(*setting) || ascii_is_unsafe(*setting.add(1)) {
                return null_mut();
            }
            salt = (ascii_to_bin(*setting.add(1) as c_int) << 6) | ascii_to_bin(*setting as c_int);
            *output = *setting;
            *output.add(1) = *setting.add(1);
            p = output.add(2);
        }
        let (r0, r1) = do_des(0, 0, count, setup_salt(salt), &ekey);
        let mut l = r0 >> 8;
        for sh in [18, 12, 6, 0] {
            *p = ASCII64[((l >> sh) & 0x3f) as usize];
            p = p.add(1);
        }
        l = (r0 << 16) | ((r1 >> 16) & 0xffff);
        for sh in [18, 12, 6, 0] {
            *p = ASCII64[((l >> sh) & 0x3f) as usize];
            p = p.add(1);
        }
        l = r1 << 2;
        for sh in [12, 6, 0] {
            *p = ASCII64[((l >> sh) & 0x3f) as usize];
            p = p.add(1);
        }
        *p = 0;
        output
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn crypt_des(
    key: *const c_char,
    setting: *const c_char,
    output: *mut c_char,
) -> *mut c_char {
    unsafe {
        let test_key: &[u8] = b"\x80\xff\x80\x01 \x7f\x81\x80\x80\x0d\x0a\xff\x7f \x81 test";
        let (test_setting, test_hash): (&[u8], &[u8]);
        if *setting as u8 != b'_' {
            test_setting = b"\x80x";
            test_hash = b"\x80x22/wK52ZKGA";
        } else {
            test_setting = b"_0.../9Zz";
            test_hash = b"_0.../9ZzX7iSJNd21sU";
        }
        let r = crypt_extended(key as *const u8, setting as *const u8, output as *mut u8);
        let mut tb = [0u8; 21];
        let q = crypt_extended(test_key.as_ptr(), test_setting.as_ptr(), tb.as_mut_ptr());
        let mut ok = !q.is_null() && !r.is_null();
        if ok {
            for i in 0..test_hash.len() {
                if tb[i] != test_hash[i] {
                    ok = false;
                    break;
                }
            }
            ok = ok && tb[test_hash.len()] == 0;
        }
        if ok {
            r as *mut c_char
        } else if *setting == b'*' as c_char {
            c"x".as_ptr() as *mut c_char
        } else {
            c"*".as_ptr() as *mut c_char
        }
    }
}

// ---- md5 crypt (musl src/crypt/crypt_md5.c) --------------------------------------------
#[cfg(target_arch = "x86_64")]
struct Md5 {
    len: u64,
    h: [u32; 4],
    buf: [u8; 64],
}

#[cfg(target_arch = "x86_64")]
fn md5_rol(n: u32, k: u32) -> u32 {
    n.rotate_left(k)
}

#[cfg(target_arch = "x86_64")]
fn md5_process(s: &mut Md5, blk: &[u8; 64]) {
    let mut w = [0u32; 16];
    for i in 0..16 {
        w[i] = blk[4 * i] as u32
            | ((blk[4 * i + 1] as u32) << 8)
            | ((blk[4 * i + 2] as u32) << 16)
            | ((blk[4 * i + 3] as u32) << 24);
    }
    let (mut a, mut b, mut c, mut d) = (s.h[0], s.h[1], s.h[2], s.h[3]);
    let f = |x: u32, y: u32, z: u32| z ^ (x & (y ^ z));
    let g = |x: u32, y: u32, z: u32| y ^ (z & (y ^ x));
    let h = |x: u32, y: u32, z: u32| x ^ y ^ z;
    let iv = |x: u32, y: u32, z: u32| y ^ (x | !z);
    let mut i = 0usize;
    while i < 16 {
        a = md5_rol(
            a.wrapping_add(f(b, c, d))
                .wrapping_add(w[i])
                .wrapping_add(MD5_TAB[i]),
            7,
        )
        .wrapping_add(b);
        i += 1;
        d = md5_rol(
            d.wrapping_add(f(a, b, c))
                .wrapping_add(w[i])
                .wrapping_add(MD5_TAB[i]),
            12,
        )
        .wrapping_add(a);
        i += 1;
        c = md5_rol(
            c.wrapping_add(f(d, a, b))
                .wrapping_add(w[i])
                .wrapping_add(MD5_TAB[i]),
            17,
        )
        .wrapping_add(d);
        i += 1;
        b = md5_rol(
            b.wrapping_add(f(c, d, a))
                .wrapping_add(w[i])
                .wrapping_add(MD5_TAB[i]),
            22,
        )
        .wrapping_add(c);
        i += 1;
    }
    while i < 32 {
        a = md5_rol(
            a.wrapping_add(g(b, c, d))
                .wrapping_add(w[(5 * i + 1) % 16])
                .wrapping_add(MD5_TAB[i]),
            5,
        )
        .wrapping_add(b);
        i += 1;
        d = md5_rol(
            d.wrapping_add(g(a, b, c))
                .wrapping_add(w[(5 * i + 1) % 16])
                .wrapping_add(MD5_TAB[i]),
            9,
        )
        .wrapping_add(a);
        i += 1;
        c = md5_rol(
            c.wrapping_add(g(d, a, b))
                .wrapping_add(w[(5 * i + 1) % 16])
                .wrapping_add(MD5_TAB[i]),
            14,
        )
        .wrapping_add(d);
        i += 1;
        b = md5_rol(
            b.wrapping_add(g(c, d, a))
                .wrapping_add(w[(5 * i + 1) % 16])
                .wrapping_add(MD5_TAB[i]),
            20,
        )
        .wrapping_add(c);
        i += 1;
    }
    while i < 48 {
        a = md5_rol(
            a.wrapping_add(h(b, c, d))
                .wrapping_add(w[(3 * i + 5) % 16])
                .wrapping_add(MD5_TAB[i]),
            4,
        )
        .wrapping_add(b);
        i += 1;
        d = md5_rol(
            d.wrapping_add(h(a, b, c))
                .wrapping_add(w[(3 * i + 5) % 16])
                .wrapping_add(MD5_TAB[i]),
            11,
        )
        .wrapping_add(a);
        i += 1;
        c = md5_rol(
            c.wrapping_add(h(d, a, b))
                .wrapping_add(w[(3 * i + 5) % 16])
                .wrapping_add(MD5_TAB[i]),
            16,
        )
        .wrapping_add(d);
        i += 1;
        b = md5_rol(
            b.wrapping_add(h(c, d, a))
                .wrapping_add(w[(3 * i + 5) % 16])
                .wrapping_add(MD5_TAB[i]),
            23,
        )
        .wrapping_add(c);
        i += 1;
    }
    while i < 64 {
        a = md5_rol(
            a.wrapping_add(iv(b, c, d))
                .wrapping_add(w[(7 * i) % 16])
                .wrapping_add(MD5_TAB[i]),
            6,
        )
        .wrapping_add(b);
        i += 1;
        d = md5_rol(
            d.wrapping_add(iv(a, b, c))
                .wrapping_add(w[(7 * i) % 16])
                .wrapping_add(MD5_TAB[i]),
            10,
        )
        .wrapping_add(a);
        i += 1;
        c = md5_rol(
            c.wrapping_add(iv(d, a, b))
                .wrapping_add(w[(7 * i) % 16])
                .wrapping_add(MD5_TAB[i]),
            15,
        )
        .wrapping_add(d);
        i += 1;
        b = md5_rol(
            b.wrapping_add(iv(c, d, a))
                .wrapping_add(w[(7 * i) % 16])
                .wrapping_add(MD5_TAB[i]),
            21,
        )
        .wrapping_add(c);
        i += 1;
    }
    s.h[0] = s.h[0].wrapping_add(a);
    s.h[1] = s.h[1].wrapping_add(b);
    s.h[2] = s.h[2].wrapping_add(c);
    s.h[3] = s.h[3].wrapping_add(d);
}

#[cfg(target_arch = "x86_64")]
fn md5_update(s: &mut Md5, m: &[u8]) {
    let mut p = m;
    let mut r = (s.len % 64) as usize;
    s.len += m.len() as u64;
    if r != 0 {
        if p.len() < 64 - r {
            s.buf[r..r + p.len()].copy_from_slice(p);
            return;
        }
        let k = 64 - r;
        s.buf[r..64].copy_from_slice(&p[..k]);
        p = &p[k..];
        let b = s.buf;
        md5_process(s, &b);
    }
    while p.len() >= 64 {
        let mut b = [0u8; 64];
        b.copy_from_slice(&p[..64]);
        md5_process(s, &b);
        p = &p[64..];
    }
    r = (s.len % 64) as usize;
    let start = r.wrapping_sub(p.len());
    s.buf[start..r].copy_from_slice(p);
}

#[cfg(target_arch = "x86_64")]
fn md5_sum(s: &mut Md5) -> [u8; 16] {
    let mut r = (s.len % 64) as usize;
    s.buf[r] = 0x80;
    r += 1;
    if r > 56 {
        s.buf[r..].fill(0);
        let b = s.buf;
        md5_process(s, &b);
        r = 0;
    }
    s.buf[r..56].fill(0);
    let bits = s.len.wrapping_mul(8);
    s.buf[56..64].copy_from_slice(&bits.to_le_bytes());
    let b = s.buf;
    md5_process(s, &b);
    let mut md = [0u8; 16];
    for i in 0..4 {
        md[4 * i..4 * i + 4].copy_from_slice(&s.h[i].to_le_bytes());
    }
    md
}

#[cfg(target_arch = "x86_64")]
fn md5_init() -> Md5 {
    Md5 {
        len: 0,
        h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
        buf: [0; 64],
    }
}

#[cfg(target_arch = "x86_64")]
fn md5_crypt(key: &[u8], setting: &[u8], output: &mut [u8; 64]) -> bool {
    if key.len() > 30000 {
        return false;
    }
    if setting.len() < 3 || &setting[..3] != b"$1$" {
        return false;
    }
    let mut slen = 0usize;
    while slen < 8
        && slen + 3 < setting.len()
        && setting[3 + slen] != 0
        && setting[3 + slen] != b'$'
    {
        slen += 1;
    }
    let salt = &setting[3..3 + slen];
    let mut ctx = md5_init();
    md5_update(&mut ctx, key);
    md5_update(&mut ctx, salt);
    md5_update(&mut ctx, key);
    let mut md = md5_sum(&mut ctx);
    ctx = md5_init();
    md5_update(&mut ctx, key);
    md5_update(&mut ctx, &setting[..3 + slen]);
    let mut i = key.len();
    while i > 16 {
        md5_update(&mut ctx, &md);
        i -= 16;
    }
    md5_update(&mut ctx, &md[..i]);
    md[0] = 0;
    let mut k = key.len();
    while k != 0 {
        if k & 1 != 0 {
            md5_update(&mut ctx, &md[..1]);
        } else {
            md5_update(&mut ctx, &key[..1]);
        }
        k >>= 1;
    }
    md = md5_sum(&mut ctx);
    for i in 0..1000u32 {
        ctx = md5_init();
        if i & 1 != 0 {
            md5_update(&mut ctx, key);
        } else {
            md5_update(&mut ctx, &md);
        }
        if i % 3 != 0 {
            md5_update(&mut ctx, salt);
        }
        if i % 7 != 0 {
            md5_update(&mut ctx, key);
        }
        if i & 1 != 0 {
            md5_update(&mut ctx, &md);
        } else {
            md5_update(&mut ctx, key);
        }
        md = md5_sum(&mut ctx);
    }
    output[..3 + slen].copy_from_slice(&setting[..3 + slen]);
    let mut o = 3 + slen;
    output[o] = b'$';
    o += 1;
    const PERM: [[usize; 3]; 5] = [[0, 6, 12], [1, 7, 13], [2, 8, 14], [3, 9, 15], [4, 10, 5]];
    for g in PERM {
        let mut u = ((md[g[0]] as u32) << 16) | ((md[g[1]] as u32) << 8) | md[g[2]] as u32;
        for _ in 0..4 {
            output[o] = ASCII64[(u % 64) as usize];
            o += 1;
            u /= 64;
        }
    }
    let mut u = md[11] as u32;
    for _ in 0..2 {
        output[o] = ASCII64[(u % 64) as usize];
        o += 1;
        u /= 64;
    }
    output[o] = 0;
    true
}

#[cfg(target_arch = "x86_64")]
fn crypt_md5(key: &[u8], setting: &[u8], output: &mut [u8]) -> bool {
    let mut obuf = [0u8; 64];
    let ok_self_src = md5_crypt(key, setting, &mut obuf);
    let tk: &[u8] = b"Xy01@#\x01\x02\x80\x7f\xff\r\n\x81\t !";
    let ts: &[u8] = b"$1$abcd0123$";
    let th: &[u8] = b"$1$abcd0123$9Qcg8DyviekV3tDGMZynJ1";
    let mut tb = [0u8; 64];
    let ok_test = md5_crypt(tk, ts, &mut tb);
    if !ok_self_src || !ok_test {
        return false;
    }
    for i in 0..th.len() {
        if tb[i] != th[i] {
            return false;
        }
    }
    if tb[th.len()] != 0 {
        return false;
    }
    let n = unsafe { c_strlen(obuf.as_ptr() as *const c_char) };
    if n + 1 > output.len() {
        return false;
    }
    output[..n + 1].copy_from_slice(&obuf[..n + 1]);
    true
}

// ---- sha256 crypt (musl src/crypt/crypt_sha256.c) ------------------------------
#[cfg(target_arch = "x86_64")]
struct Sha256 {
    len: u64,
    h: [u32; 8],
    buf: [u8; 64],
}

#[cfg(target_arch = "x86_64")]
fn sha256_ror(n: u32, k: u32) -> u32 {
    n.rotate_right(k)
}

#[cfg(target_arch = "x86_64")]
fn sha256_process(s: &mut Sha256, blk: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = ((blk[4 * i] as u32) << 24)
            | ((blk[4 * i + 1] as u32) << 16)
            | ((blk[4 * i + 2] as u32) << 8)
            | blk[4 * i + 3] as u32;
    }
    for i in 16..64 {
        let r0 = sha256_ror(w[i - 15], 7) ^ sha256_ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        let r1 = sha256_ror(w[i - 2], 17) ^ sha256_ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = r1
            .wrapping_add(w[i - 7])
            .wrapping_add(r0)
            .wrapping_add(w[i - 16]);
    }
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) = (
        s.h[0], s.h[1], s.h[2], s.h[3], s.h[4], s.h[5], s.h[6], s.h[7],
    );
    for i in 0..64 {
        let s1 = sha256_ror(e, 6) ^ sha256_ror(e, 11) ^ sha256_ror(e, 25);
        let ch = g ^ (e & (f ^ g));
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = sha256_ror(a, 2) ^ sha256_ror(a, 13) ^ sha256_ror(a, 22);
        let maj = (a & b) | (c & (a | b));
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    s.h[0] = s.h[0].wrapping_add(a);
    s.h[1] = s.h[1].wrapping_add(b);
    s.h[2] = s.h[2].wrapping_add(c);
    s.h[3] = s.h[3].wrapping_add(d);
    s.h[4] = s.h[4].wrapping_add(e);
    s.h[5] = s.h[5].wrapping_add(f);
    s.h[6] = s.h[6].wrapping_add(g);
    s.h[7] = s.h[7].wrapping_add(hh);
}

#[cfg(target_arch = "x86_64")]
fn sha256_update(s: &mut Sha256, m: &[u8]) {
    let mut p = m;
    let r = (s.len % 64) as usize;
    s.len += m.len() as u64;
    if r != 0 {
        if p.len() < 64 - r {
            s.buf[r..r + p.len()].copy_from_slice(p);
            return;
        }
        let k = 64 - r;
        s.buf[r..64].copy_from_slice(&p[..k]);
        p = &p[k..];
        let b = s.buf;
        sha256_process(s, &b);
    }
    while p.len() >= 64 {
        let mut b = [0u8; 64];
        b.copy_from_slice(&p[..64]);
        sha256_process(s, &b);
        p = &p[64..];
    }
    let rr = (s.len % 64) as usize;
    s.buf[rr.wrapping_sub(p.len())..rr].copy_from_slice(p);
}

#[cfg(target_arch = "x86_64")]
fn sha256_sum(s: &mut Sha256) -> [u8; 32] {
    let mut r = (s.len % 64) as usize;
    s.buf[r] = 0x80;
    r += 1;
    if r > 56 {
        s.buf[r..].fill(0);
        let b = s.buf;
        sha256_process(s, &b);
        r = 0;
    }
    s.buf[r..56].fill(0);
    let bits = s.len.wrapping_mul(8);
    s.buf[56..64].copy_from_slice(&bits.to_be_bytes());
    let b = s.buf;
    sha256_process(s, &b);
    let mut md = [0u8; 32];
    for i in 0..8 {
        md[4 * i..4 * i + 4].copy_from_slice(&s.h[i].to_be_bytes());
    }
    md
}

#[cfg(target_arch = "x86_64")]
fn sha256_init() -> Sha256 {
    Sha256 {
        len: 0,
        h: [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ],
        buf: [0; 64],
    }
}

#[cfg(target_arch = "x86_64")]
fn sha256_hashmd(s: &mut Sha256, n: usize, md: &[u8; 32]) {
    let mut i = n;
    while i > 32 {
        sha256_update(s, md);
        i -= 32;
    }
    sha256_update(s, &md[..i]);
}

#[cfg(target_arch = "x86_64")]
fn sha256_crypt(key: &[u8], setting: &[u8], prefix: u8, output: &mut [u8]) -> bool {
    if key.len() > 256 {
        return false;
    }
    if setting.len() < 3 || setting[0] != b'$' || setting[1] != prefix || setting[2] != b'$' {
        return false;
    }
    let mut salt = &setting[3..];
    let mut rounds = 5000u32;
    let mut roundstr = [0u8; 20];
    let mut roundlen = 0usize;
    if salt.len() >= 7 && &salt[..7] == b"rounds=" {
        salt = &salt[7..];
        let mut u = 0u64;
        let mut nd = 0usize;
        while nd < salt.len() && salt[nd].is_ascii_digit() {
            u = u * 10 + (salt[nd] - b'0') as u64;
            nd += 1;
        }
        if nd == 0 || nd >= salt.len() || salt[nd] != b'$' {
            return false;
        }
        salt = &salt[nd + 1..];
        if u < 1000 {
            rounds = 1000;
        } else if u > 9999999 {
            return false;
        } else {
            rounds = u as u32;
        }
        let n = format_rounds(rounds, &mut roundstr);
        roundlen = n;
    }
    let mut slen = 0usize;
    while slen < 16 && slen < salt.len() && salt[slen] != 0 && salt[slen] != b'$' {
        if salt[slen] == b'\n' || salt[slen] == b':' {
            return false;
        }
        slen += 1;
    }
    let salt = &salt[..slen];
    let mut ctx = sha256_init();
    sha256_update(&mut ctx, key);
    sha256_update(&mut ctx, salt);
    sha256_update(&mut ctx, key);
    let mut md = sha256_sum(&mut ctx);
    ctx = sha256_init();
    sha256_update(&mut ctx, key);
    sha256_update(&mut ctx, salt);
    sha256_hashmd(&mut ctx, key.len(), &md);
    let mut i = key.len();
    while i > 0 {
        if i & 1 != 0 {
            sha256_update(&mut ctx, &md);
        } else {
            sha256_update(&mut ctx, key);
        }
        i >>= 1;
    }
    md = sha256_sum(&mut ctx);
    ctx = sha256_init();
    for _ in 0..key.len() {
        sha256_update(&mut ctx, key);
    }
    let kmd = sha256_sum(&mut ctx);
    ctx = sha256_init();
    for _ in 0..16 + md[0] as usize {
        sha256_update(&mut ctx, salt);
    }
    let smd = sha256_sum(&mut ctx);
    for i in 0..rounds {
        ctx = sha256_init();
        if i & 1 != 0 {
            sha256_hashmd(&mut ctx, key.len(), &kmd);
        } else {
            sha256_update(&mut ctx, &md);
        }
        if i % 3 != 0 {
            sha256_update(&mut ctx, &smd[..slen]);
        }
        if i % 7 != 0 {
            sha256_hashmd(&mut ctx, key.len(), &kmd);
        }
        if i & 1 != 0 {
            sha256_update(&mut ctx, &md);
        } else {
            sha256_hashmd(&mut ctx, key.len(), &kmd);
        }
        md = sha256_sum(&mut ctx);
    }
    let mut o = 0usize;
    let put = |out: &mut [u8], o: &mut usize, bytes: &[u8]| {
        for b in bytes {
            if *o < out.len() {
                out[*o] = *b;
                *o += 1;
            }
        }
    };
    put(output, &mut o, b"$");
    put(output, &mut o, &[prefix]);
    put(output, &mut o, b"$");
    if roundlen > 0 {
        put(output, &mut o, &roundstr[..roundlen]);
    }
    put(output, &mut o, salt);
    put(output, &mut o, b"$");
    const PERM: [[usize; 3]; 10] = [
        [0, 10, 20],
        [21, 1, 11],
        [12, 22, 2],
        [3, 13, 23],
        [24, 4, 14],
        [15, 25, 5],
        [6, 16, 26],
        [27, 7, 17],
        [18, 28, 8],
        [9, 19, 29],
    ];
    for g in PERM {
        let mut u = ((md[g[0]] as u32) << 16) | ((md[g[1]] as u32) << 8) | md[g[2]] as u32;
        for _ in 0..4 {
            if o < output.len() {
                output[o] = ASCII64[(u % 64) as usize];
                o += 1;
            }
            u /= 64;
        }
    }
    let mut u = ((md[31] as u32) << 8) | md[30] as u32;
    for _ in 0..3 {
        if o < output.len() {
            output[o] = ASCII64[(u % 64) as usize];
            o += 1;
        }
        u /= 64;
    }
    if o < output.len() {
        output[o] = 0;
    }
    true
}

#[cfg(target_arch = "x86_64")]
fn format_rounds(r: u32, out: &mut [u8; 20]) -> usize {
    let pre = b"rounds=";
    out[..7].copy_from_slice(pre);
    let mut n = 7usize;
    let mut div = 10000000u32;
    let mut started = false;
    while div > 0 {
        let d = r / div % 10;
        div /= 10;
        if d != 0 || started || div == 0 {
            started = true;
            out[n] = b'0' + d as u8;
            n += 1;
        }
    }
    out[n] = b'$';
    n + 1
}

#[cfg(target_arch = "x86_64")]
fn crypt_sha256_wrap(key: &[u8], setting: &[u8], output: &mut [u8]) -> bool {
    let ok = sha256_crypt(key, setting, b'5', output);
    let tk: &[u8] = b"Xy01@#\x01\x02\x80\x7f\xff\r\n\x81\t !";
    let ts: &[u8] = b"$5$rounds=1234$abc0123456789$";
    let th: &[u8] = b"$5$rounds=1234$abc0123456789$3VfDjPt05VHFn47C/ojFZ6KRPYrOjj1lLbH.dkF3bZ6";
    let mut tb = [0u8; 128];
    if !ok || !sha256_crypt(tk, ts, b'5', &mut tb) {
        return false;
    }
    tb.get(..th.len()) == Some(th)
}

// ---- sha512 crypt (musl src/crypt/crypt_sha512.c) ------------------------------
#[cfg(target_arch = "x86_64")]
struct Sha512 {
    len: u64,
    h: [u64; 8],
    buf: [u8; 128],
}

#[cfg(target_arch = "x86_64")]
fn sha512_ror(n: u64, k: u32) -> u64 {
    n.rotate_right(k)
}

#[cfg(target_arch = "x86_64")]
fn sha512_process(s: &mut Sha512, blk: &[u8; 128]) {
    let mut w = [0u64; 80];
    for i in 0..16 {
        w[i] = ((blk[8 * i] as u64) << 56)
            | ((blk[8 * i + 1] as u64) << 48)
            | ((blk[8 * i + 2] as u64) << 40)
            | ((blk[8 * i + 3] as u64) << 32)
            | ((blk[8 * i + 4] as u64) << 24)
            | ((blk[8 * i + 5] as u64) << 16)
            | ((blk[8 * i + 6] as u64) << 8)
            | blk[8 * i + 7] as u64;
    }
    for i in 16..80 {
        let r0 = sha512_ror(w[i - 15], 1) ^ sha512_ror(w[i - 15], 8) ^ (w[i - 15] >> 7);
        let r1 = sha512_ror(w[i - 2], 19) ^ sha512_ror(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = r1
            .wrapping_add(w[i - 7])
            .wrapping_add(r0)
            .wrapping_add(w[i - 16]);
    }
    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) = (
        s.h[0], s.h[1], s.h[2], s.h[3], s.h[4], s.h[5], s.h[6], s.h[7],
    );
    for i in 0..80 {
        let s1 = sha512_ror(e, 14) ^ sha512_ror(e, 18) ^ sha512_ror(e, 41);
        let ch = g ^ (e & (f ^ g));
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA512_K[i])
            .wrapping_add(w[i]);
        let s0 = sha512_ror(a, 28) ^ sha512_ror(a, 34) ^ sha512_ror(a, 39);
        let maj = (a & b) | (c & (a | b));
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    s.h[0] = s.h[0].wrapping_add(a);
    s.h[1] = s.h[1].wrapping_add(b);
    s.h[2] = s.h[2].wrapping_add(c);
    s.h[3] = s.h[3].wrapping_add(d);
    s.h[4] = s.h[4].wrapping_add(e);
    s.h[5] = s.h[5].wrapping_add(f);
    s.h[6] = s.h[6].wrapping_add(g);
    s.h[7] = s.h[7].wrapping_add(hh);
}

#[cfg(target_arch = "x86_64")]
fn sha512_update(s: &mut Sha512, m: &[u8]) {
    let mut p = m;
    let r = (s.len % 128) as usize;
    s.len += m.len() as u64;
    if r != 0 {
        if p.len() < 128 - r {
            s.buf[r..r + p.len()].copy_from_slice(p);
            return;
        }
        let k = 128 - r;
        s.buf[r..128].copy_from_slice(&p[..k]);
        p = &p[k..];
        let b = s.buf;
        sha512_process(s, &b);
    }
    while p.len() >= 128 {
        let mut b = [0u8; 128];
        b.copy_from_slice(&p[..128]);
        sha512_process(s, &b);
        p = &p[128..];
    }
    let rr = (s.len % 128) as usize;
    s.buf[rr.wrapping_sub(p.len())..rr].copy_from_slice(p);
}

#[cfg(target_arch = "x86_64")]
fn sha512_sum(s: &mut Sha512) -> [u8; 64] {
    let mut r = (s.len % 128) as usize;
    s.buf[r] = 0x80;
    r += 1;
    if r > 112 {
        s.buf[r..].fill(0);
        let b = s.buf;
        sha512_process(s, &b);
        r = 0;
    }
    s.buf[r..120].fill(0);
    let bits = s.len.wrapping_mul(8);
    s.buf[120..128].copy_from_slice(&bits.to_be_bytes());
    let b = s.buf;
    sha512_process(s, &b);
    let mut md = [0u8; 64];
    for i in 0..8 {
        md[8 * i..8 * i + 8].copy_from_slice(&s.h[i].to_be_bytes());
    }
    md
}

#[cfg(target_arch = "x86_64")]
fn sha512_init() -> Sha512 {
    Sha512 {
        len: 0,
        h: [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ],
        buf: [0; 128],
    }
}

#[cfg(target_arch = "x86_64")]
fn sha512_hashmd(s: &mut Sha512, n: usize, md: &[u8; 64]) {
    let mut i = n;
    while i > 64 {
        sha512_update(s, md);
        i -= 64;
    }
    sha512_update(s, &md[..i]);
}

#[cfg(target_arch = "x86_64")]
fn sha512_crypt(key: &[u8], setting: &[u8], output: &mut [u8]) -> bool {
    if key.len() > 256 {
        return false;
    }
    if setting.len() < 3 || setting[0] != b'$' || setting[1] != b'6' || setting[2] != b'$' {
        return false;
    }
    let mut salt = &setting[3..];
    let mut rounds = 5000u32;
    let mut roundstr = [0u8; 20];
    let mut roundlen = 0usize;
    if salt.len() >= 7 && &salt[..7] == b"rounds=" {
        salt = &salt[7..];
        let mut u = 0u64;
        let mut nd = 0usize;
        while nd < salt.len() && salt[nd].is_ascii_digit() {
            u = u * 10 + (salt[nd] - b'0') as u64;
            nd += 1;
        }
        if nd == 0 || nd >= salt.len() || salt[nd] != b'$' {
            return false;
        }
        salt = &salt[nd + 1..];
        if u < 1000 {
            rounds = 1000;
        } else if u > 9999999 {
            return false;
        } else {
            rounds = u as u32;
        }
        roundlen = format_rounds(rounds, &mut roundstr);
    }
    let mut slen = 0usize;
    while slen < 16 && slen < salt.len() && salt[slen] != 0 && salt[slen] != b'$' {
        if salt[slen] == b'\n' || salt[slen] == b':' {
            return false;
        }
        slen += 1;
    }
    let salt = &salt[..slen];
    let mut ctx = sha512_init();
    sha512_update(&mut ctx, key);
    sha512_update(&mut ctx, salt);
    sha512_update(&mut ctx, key);
    let mut md = sha512_sum(&mut ctx);
    ctx = sha512_init();
    sha512_update(&mut ctx, key);
    sha512_update(&mut ctx, salt);
    sha512_hashmd(&mut ctx, key.len(), &md);
    let mut i = key.len();
    while i > 0 {
        if i & 1 != 0 {
            sha512_update(&mut ctx, &md);
        } else {
            sha512_update(&mut ctx, key);
        }
        i >>= 1;
    }
    md = sha512_sum(&mut ctx);
    ctx = sha512_init();
    for _ in 0..key.len() {
        sha512_update(&mut ctx, key);
    }
    let kmd = sha512_sum(&mut ctx);
    ctx = sha512_init();
    for _ in 0..16 + md[0] as usize {
        sha512_update(&mut ctx, salt);
    }
    let smd = sha512_sum(&mut ctx);
    for i in 0..rounds {
        ctx = sha512_init();
        if i & 1 != 0 {
            sha512_hashmd(&mut ctx, key.len(), &kmd);
        } else {
            sha512_update(&mut ctx, &md);
        }
        if i % 3 != 0 {
            sha512_update(&mut ctx, &smd[..slen]);
        }
        if i % 7 != 0 {
            sha512_hashmd(&mut ctx, key.len(), &kmd);
        }
        if i & 1 != 0 {
            sha512_update(&mut ctx, &md);
        } else {
            sha512_hashmd(&mut ctx, key.len(), &kmd);
        }
        md = sha512_sum(&mut ctx);
    }
    let mut o = 0usize;
    let mut put = |bytes: &[u8]| {
        for b in bytes {
            if o < output.len() {
                output[o] = *b;
                o += 1;
            }
        }
    };
    put(b"$6$");
    if roundlen > 0 {
        put(&roundstr[..roundlen]);
    }
    put(salt);
    put(b"$");
    const PERM: [[usize; 3]; 21] = [
        [0, 21, 42],
        [22, 43, 1],
        [44, 2, 23],
        [3, 24, 45],
        [25, 46, 4],
        [47, 5, 26],
        [6, 27, 48],
        [28, 49, 7],
        [50, 8, 29],
        [9, 30, 51],
        [31, 52, 10],
        [53, 11, 32],
        [12, 33, 54],
        [34, 55, 13],
        [56, 14, 35],
        [15, 36, 57],
        [37, 58, 16],
        [59, 17, 38],
        [18, 39, 60],
        [40, 61, 19],
        [62, 20, 41],
    ];
    for g in PERM {
        let mut u = ((md[g[0]] as u32) << 16) | ((md[g[1]] as u32) << 8) | md[g[2]] as u32;
        for _ in 0..4 {
            if o < output.len() {
                output[o] = ASCII64[(u % 64) as usize];
                o += 1;
            }
            u /= 64;
        }
    }
    {
        let mut u = md[63] as u32;
        for _ in 0..2 {
            if o < output.len() {
                output[o] = ASCII64[(u % 64) as usize];
                o += 1;
            }
            u /= 64;
        }
    }
    if o < output.len() {
        output[o] = 0;
    }
    true
}

#[cfg(target_arch = "x86_64")]
fn crypt_sha512_wrap(key: &[u8], setting: &[u8], output: &mut [u8]) -> bool {
    let ok = sha512_crypt(key, setting, output);
    let tk: &[u8] = b"Xy01@#\x01\x02\x80\x7f\xff\r\n\x81\t !";
    let ts: &[u8] = b"$6$rounds=1234$abc0123456789$";
    let th: &[u8] = b"$6$rounds=1234$abc0123456789$BCpt8zLrc/RcyuXmCDOE1ALqMXB2MH6n1g891HhFj8.w7LxGv.FTkqq6Vxc/km3Y0jE0j24jY5PIv/oOu6reg1";
    let mut tb = [0u8; 256];
    if !ok || !sha512_crypt(tk, ts, &mut tb) {
        return false;
    }
    tb.get(..th.len()) == Some(th)
}

// ---- crypt family (musl src/crypt/crypt.c, crypt_r.c, encrypt.c) -------------------
#[cfg(target_arch = "x86_64")]
static mut CRYPT_BUF: [c_char; 128] = [0; 128];

#[cfg(target_arch = "x86_64")]
unsafe fn crypt_r_inner(
    key: *const c_char,
    setting: *const c_char,
    out: *mut c_char,
) -> *mut c_char {
    unsafe {
        if key.is_null() || setting.is_null() || out.is_null() {
            return null_mut();
        }
        let klen = c_strlen(key);
        let slen = c_strlen(setting);
        let keyb = core::slice::from_raw_parts(key as *const u8, klen);
        let setb = core::slice::from_raw_parts(setting as *const u8, slen);
        let outb = core::slice::from_raw_parts_mut(out as *mut u8, 128);
        let ok = if slen > 2 && setb[0] == b'$' && setb[1] != 0 && setb[2] != 0 {
            match (setb[1], setb[2]) {
                (b'1', b'$') => {
                    let mut tmp = [0u8; 64];
                    crypt_md5(keyb, setb, &mut tmp) && copy_out(&tmp, outb)
                }
                (b'5', b'$') => crypt_sha256_wrap(keyb, setb, outb),
                (b'6', b'$') => crypt_sha512_wrap(keyb, setb, outb),
                // bcrypt ($2a$/$2y$) has no implementation here (see module docs).
                _ => false,
            }
        } else {
            let mut tmp = [0u8; 21];
            let r = crypt_des(
                key as *const c_char,
                setting as *const c_char,
                tmp.as_mut_ptr() as *mut c_char,
            );
            if r == tmp.as_mut_ptr() as *mut c_char {
                let n = c_strlen(tmp.as_ptr() as *const c_char);
                outb[..n + 1].copy_from_slice(&tmp[..n + 1]);
                true
            } else {
                false
            }
        };
        if ok {
            out
        } else {
            outb[0] = b'*';
            outb[1] = 0;
            out
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn copy_out(tmp: &[u8; 64], out: &mut [u8]) -> bool {
    let mut n = 0usize;
    while n < tmp.len() && tmp[n] != 0 {
        n += 1;
    }
    if n + 1 > out.len() {
        return false;
    }
    out[..n + 1].copy_from_slice(&tmp[..n + 1]);
    true
}

/// One-way password hash (musl `crypt_r`: DES/MD5/SHA-256/SHA-512; bcrypt
/// salts yield `"*"` — see module docs).
///
/// # Safety
///
/// All three pointers must be valid; `data` must hold a `CryptData`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn crypt_r(
    key: *const c_char,
    setting: *const c_char,
    data: *mut CryptData,
) -> *mut c_char {
    unsafe { crypt_r_inner(key, setting, data as *mut c_char) }
}

/// One-way password hash, static buffer (musl `crypt`).
///
/// # Safety
///
/// `key`/`setting` must point to NUL-terminated strings.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn crypt(key: *const c_char, setting: *const c_char) -> *mut c_char {
    unsafe { crypt_r_inner(key, setting, addr_of_mut!(CRYPT_BUF).cast()) }
}

#[cfg(target_arch = "x86_64")]
static mut ENCRYPT_KEY: ExpandedKey = ExpandedKey {
    l: [0; 16],
    r: [0; 16],
};

/// Set DES key from 64 ASCII bits (musl `setkey`).
///
/// # Safety
///
/// `key` must point to 64 readable bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setkey(key: *const c_char) {
    unsafe {
        if key.is_null() {
            return;
        }
        let mut bkey = [0u8; 8];
        for (i, bk) in bkey.iter_mut().enumerate() {
            let mut b = 0u8;
            for j in (0..8).rev() {
                b |= (*key.add(i * 8 + (7 - j)) as u8 & 1) << j;
            }
            *bk = b;
        }
        des_setkey(&bkey, &mut *addr_of_mut!(ENCRYPT_KEY));
    }
}

/// DES encrypt one 64-bit block in place (musl `encrypt`).
///
/// # Safety
///
/// `block` must point to 64 writable bytes holding ASCII bits.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn encrypt(block: *mut c_char, edflag: c_int) {
    unsafe {
        if block.is_null() {
            return;
        }
        let mut b = [0u32; 2];
        for (i, bb) in b.iter_mut().enumerate() {
            for j in (0..32).rev() {
                *bb |= (*block.add(i * 32 + (31 - j)) as u32 & 1) << j;
            }
        }
        let mut dk = ExpandedKey {
            l: [0; 16],
            r: [0; 16],
        };
        let ek = &*addr_of_mut!(ENCRYPT_KEY);
        let k: &ExpandedKey = if edflag != 0 {
            for i in 0..16 {
                dk.l[i] = ek.l[15 - i];
                dk.r[i] = ek.r[15 - i];
            }
            &dk
        } else {
            ek
        };
        let (o0, o1) = do_des(b[0], b[1], 1, 0, k);
        b[0] = o0;
        b[1] = o1;
        for (i, bb) in b.iter().enumerate() {
            for j in (0..32).rev() {
                *block.add(i * 32 + (31 - j)) = ((bb >> j) & 1) as c_char;
            }
        }
    }
}

// ---- mntent (musl src/misc/mntent.c) ----------------------------------------------------
#[cfg(target_arch = "x86_64")]
static mut MNT_STATIC: Mntent = Mntent {
    mnt_fsname: null_mut(),
    mnt_dir: null_mut(),
    mnt_type: null_mut(),
    mnt_opts: null_mut(),
    mnt_freq: 0,
    mnt_passno: 0,
};
#[cfg(target_arch = "x86_64")]
static mut MNT_BUF: [c_char; 4096] = [0; 4096];

/// Open a mount table (musl `setmntent`: `fopen`).
///
/// # Safety
///
/// `name`/`mode` must point to NUL-terminated strings.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setmntent(
    name: *const c_char,
    mode: *const c_char,
) -> *mut crate::stdio::File {
    unsafe { crate::stdio::fopen(name, mode) }
}

/// Close a mount table (musl `endmntent`: 1, closing when open).
///
/// # Safety
///
/// `f` must be null or a live stream from [`setmntent`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn endmntent(f: *mut crate::stdio::File) -> c_int {
    unsafe {
        if !f.is_null() {
            crate::stdio::fclose(f);
        }
        1
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn unescape_ent(beg: *mut c_char) {
    unsafe {
        let mut d = beg;
        let mut s = beg as *const c_char;
        while *s != 0 {
            if *s != b'\\' as c_char {
                *d = *s;
                d = d.add(1);
                s = s.add(1);
                continue;
            }
            if *s.add(1) == b'\\' as c_char {
                s = s.add(1);
                *d = *s;
                d = d.add(1);
                s = s.add(1);
                continue;
            }
            let mut cval = 0u8;
            let mut v = s.add(1);
            for _ in 0..3 {
                let c = *v;
                if c < b'0' as c_char || c > b'7' as c_char {
                    break;
                }
                cval = cval
                    .wrapping_mul(8)
                    .wrapping_add((c - b'0' as c_char) as u8);
                v = v.add(1);
            }
            *d = cval as c_char;
            d = d.add(1);
            s = v;
        }
        *d = 0;
    }
}

/// Read one mount entry (musl `getmntent_r`: 0 ok, `ERANGE`, else `ENOENT`
/// at EOF).
///
/// # Safety
///
/// `f` live; `mnt` writable; `buf` writable for `buflen` bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getmntent_r(
    f: *mut crate::stdio::File,
    mnt: *mut Mntent,
    buf: *mut c_char,
    buflen: c_int,
) -> c_int {
    unsafe {
        if f.is_null() || mnt.is_null() || buf.is_null() || buflen <= 0 {
            set_err(EINVAL);
            return EINVAL;
        }
        let line = crate::stdio::file::fgets(buf, buflen, f);
        if line.is_null() {
            return ENOENT;
        }
        // Fields: fsname dir type opts [freq [passno]], blanks/comments skipped.
        let mut p = buf;
        while *p == b' ' as c_char || *p == b'\t' as c_char {
            p = p.add(1);
        }
        if *p == 0 || *p == b'#' as c_char || *p == b'\n' as c_char {
            return getmntent_r(f, mnt, buf, buflen);
        }
        let mut fld = [null_mut::<c_char>(); 4];
        for fl in fld.iter_mut() {
            *fl = p;
            while *p != 0 && *p != b' ' as c_char && *p != b'\t' as c_char && *p != b'\n' as c_char
            {
                p = p.add(1);
            }
            if *p == 0 {
                set_err(EINVAL);
                return EINVAL;
            }
            *p = 0;
            p = p.add(1);
            while *p == b' ' as c_char || *p == b'\t' as c_char {
                p = p.add(1);
            }
            unescape_ent(*fl);
        }
        let mut freq = 0 as c_int;
        let mut pass = 0 as c_int;
        let mut neg = false;
        if *p == b'-' as c_char {
            neg = true;
            p = p.add(1);
        }
        while *p >= b'0' as c_char && *p <= b'9' as c_char {
            freq = freq
                .wrapping_mul(10)
                .wrapping_add((*p - b'0' as c_char) as c_int);
            p = p.add(1);
        }
        if neg {
            freq = freq.wrapping_neg();
        }
        while *p == b' ' as c_char || *p == b'\t' as c_char {
            p = p.add(1);
        }
        neg = false;
        if *p == b'-' as c_char {
            neg = true;
            p = p.add(1);
        }
        while *p >= b'0' as c_char && *p <= b'9' as c_char {
            pass = pass
                .wrapping_mul(10)
                .wrapping_add((*p - b'0' as c_char) as c_int);
            p = p.add(1);
        }
        if neg {
            pass = pass.wrapping_neg();
        }
        (*mnt).mnt_fsname = fld[0];
        (*mnt).mnt_dir = fld[1];
        (*mnt).mnt_type = fld[2];
        (*mnt).mnt_opts = fld[3];
        (*mnt).mnt_freq = freq;
        (*mnt).mnt_passno = pass;
        0
    }
}

/// Read one mount entry into static storage (musl `getmntent`).
///
/// # Safety
///
/// `f` must be a live stream from [`setmntent`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getmntent(f: *mut crate::stdio::File) -> *mut Mntent {
    unsafe {
        let r = getmntent_r(
            f,
            addr_of_mut!(MNT_STATIC),
            addr_of_mut!(MNT_BUF).cast(),
            4096,
        );
        if r != 0 {
            null_mut()
        } else {
            addr_of_mut!(MNT_STATIC)
        }
    }
}

/// Append one entry (musl `addmntent`: `fputs` field by field).
///
/// # Safety
///
/// `f` live; `mnt` readable with valid fields.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn addmntent(f: *mut crate::stdio::File, mnt: *const Mntent) -> c_int {
    unsafe {
        if f.is_null() || mnt.is_null() {
            set_err(EINVAL);
            return -1;
        }
        let fields = [
            (*mnt).mnt_fsname,
            (*mnt).mnt_dir,
            (*mnt).mnt_type,
            (*mnt).mnt_opts,
        ];
        for fl in fields {
            if fl.is_null() || crate::stdio::fputs(fl, f) < 0 {
                return -1;
            }
            if crate::stdio::file::fputc(b' ' as c_int, f) < 0 {
                return -1;
            }
        }
        // freq passno\n via small decimal helper.
        let mut nb = [0 as c_char; 32];
        let mut n = 0usize;
        for v in [(*mnt).mnt_freq, (*mnt).mnt_passno] {
            let mut digs = [0u8; 12];
            let mut x = v as c_long;
            let neg = x < 0;
            if neg {
                x = x.wrapping_neg();
            }
            let mut nd = 0usize;
            while x > 0 {
                digs[nd] = b'0'.wrapping_add((x % 10) as u8);
                nd += 1;
                x /= 10;
            }
            if nd == 0 {
                digs[0] = b'0';
                nd = 1;
            }
            if neg && n < nb.len() {
                nb[n] = b'-' as c_char;
                n += 1;
            }
            while nd > 0 && n < nb.len() {
                nd -= 1;
                nb[n] = digs[nd] as c_char;
                n += 1;
            }
            if n < nb.len() {
                nb[n] = b' ' as c_char;
                n += 1;
            }
        }
        if n > 0 {
            nb[n - 1] = b'\n' as c_char;
            for bb in nb[..n].iter() {
                if crate::stdio::file::fputc(*bb as c_int, f) < 0 {
                    return -1;
                }
            }
        }
        0
    }
}

/// Match a mount option (musl `hasmntopt`: comma-separated, `=value` ok).
///
/// # Safety
///
/// `mnt` readable; `opt` NUL-terminated without `=`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn hasmntopt(mnt: *const Mntent, opt: *const c_char) -> *mut c_char {
    unsafe {
        if mnt.is_null() || opt.is_null() || (*mnt).mnt_opts.is_null() {
            return null_mut();
        }
        let on = c_strlen(opt);
        let mut p = (*mnt).mnt_opts;
        loop {
            while *p == b',' as c_char {
                p = p.add(1);
            }
            if *p == 0 {
                return null_mut();
            }
            let mut i = 0usize;
            while i < on && *p.add(i) == *opt.add(i) && *opt.add(i) != 0 {
                i += 1;
            }
            if i == on && *opt.add(i) == 0 {
                let c = *p.add(i);
                if c == 0 || c == b',' as c_char || c == b'=' as c_char {
                    return p;
                }
            }
            while *p != 0 && *p != b',' as c_char {
                p = p.add(1);
            }
        }
    }
}

// ---- utmpx (musl src/legacy/utmpx.c: pure stubs) ----------------------------------------
///
/// Login accounting database (musl: every entry is a stub — null / no-op).
/// The eight non-`x` spellings are `weak_alias!`es, exactly like musl.
///
/// # Safety
///
/// See each function.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn endutxent() {}

/// # Safety
///
/// No-op.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn setutxent() {}

/// # Safety
///
/// Always null (no database).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getutxent() -> *mut Utmpx {
    null_mut()
}

/// # Safety
///
/// Always null (no database).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getutxid(_ut: *const Utmpx) -> *mut Utmpx {
    null_mut()
}

/// # Safety
///
/// Always null (no database).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn getutxline(_ut: *const Utmpx) -> *mut Utmpx {
    null_mut()
}

/// # Safety
///
/// Always null (no database).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn pututxline(_ut: *const Utmpx) -> *mut Utmpx {
    null_mut()
}

/// # Safety
///
/// No-op.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn updwtmpx(_f: *const c_char, _u: *const Utmpx) {}

/// # Safety
///
/// Always `ENOTSUP`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn utmpxname(_f: *const c_char) -> c_int {
    set_err(ENOTSUP);
    -1
}

#[cfg(target_arch = "x86_64")]
crate::weak_alias!(endutent, endutxent);
#[cfg(target_arch = "x86_64")]
crate::weak_alias!(setutent, setutxent);
#[cfg(target_arch = "x86_64")]
crate::weak_alias!(getutent, getutxent);
#[cfg(target_arch = "x86_64")]
crate::weak_alias!(getutid, getutxid);
#[cfg(target_arch = "x86_64")]
crate::weak_alias!(getutline, getutxline);
#[cfg(target_arch = "x86_64")]
crate::weak_alias!(pututline, pututxline);
#[cfg(target_arch = "x86_64")]
crate::weak_alias!(updwtmp, updwtmpx);
#[cfg(target_arch = "x86_64")]
crate::weak_alias!(utmpname, utmpxname);

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::{
        acct, closelog, confstr, crypt, crypt_r, encrypt, endmntent, fpathconf, getauxval,
        getdomainname, gethostname, getmntent, getrlimit, getrusage, getutxent, hasmntopt, klogctl,
        openlog, pathconf, prlimit, setkey, setlogmask, setmntent, sysconf, sysinfo, ulimit, uname,
        utmpxname, CryptData, Rlimit, Rusage, Sysinfo, Utsname, RLIMIT_FSIZE, RLIMIT_NOFILE,
        RUSAGE_SELF, UL_GETFSIZE,
    };
    use core::ffi::{c_char, c_int, c_ulong};
    use std::format;
    use std::vec::Vec;

    extern "C" {
        fn syslog(prio: c_int, fmt: *const c_char, ...) -> ();
    }

    fn cstr(b: &[u8]) -> *const c_char {
        b.as_ptr() as *const c_char
    }

    #[test]
    fn sysconf_values_match_musl_table() {
        unsafe {
            assert_eq!(sysconf(30), 4096); // _SC_PAGESIZE
            assert_eq!(sysconf(2), 100); // _SC_CLK_TCK
            assert_eq!(sysconf(3), 32); // _SC_NGROUPS_MAX
            assert_eq!(sysconf(7), 1); // _SC_JOB_CONTROL
            assert_eq!(sysconf(60), 1024); // _SC_IOV_MAX
            assert_eq!(sysconf(89), 700); // _SC_XOPEN_VERSION
            assert_eq!(sysconf(29), 200809); // _SC_VERSION
            assert!(sysconf(83) >= 1); // _SC_NPROCESSORS_CONF
            assert!(sysconf(85) > 0); // _SC_PHYS_PAGES
            assert_eq!(sysconf(71), 256); // _SC_LOGIN_NAME_MAX
            assert!(sysconf(249) >= 2048); // _SC_MINSIGSTKSZ
        }
    }

    #[test]
    fn sysconf_bad_name_is_einval() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            assert_eq!(sysconf(-1), -1);
            assert_eq!(
                crate::errno::errno_load(crate::errno::__errno_location()),
                22
            );
            assert_eq!(sysconf(41), -1); // gap in musl's table
        }
    }

    #[test]
    fn confstr_path_roundtrip() {
        unsafe {
            let mut buf = [0 as c_char; 32];
            let r = confstr(0, buf.as_mut_ptr(), buf.len());
            assert_eq!(r, 14); // 13 chars + NUL, like musl's snprintf+1
            assert_eq!(
                std::ffi::CStr::from_ptr(buf.as_ptr()).to_bytes(),
                b"/bin:/usr/bin"
            );
        }
    }

    #[test]
    fn pathconf_tables_match_musl() {
        unsafe {
            assert_eq!(pathconf(cstr(b"/tmp\0"), 3), 255); // _PC_NAME_MAX
            assert_eq!(fpathconf(0, 4), 4096); // _PC_PATH_MAX
            assert_eq!(fpathconf(0, 13), 64); // _PC_FILESIZEBITS
            assert_eq!(fpathconf(0, 20), 1); // _PC_2_SYMLINKS
        }
    }

    #[test]
    fn rlimit_and_ulimit_agree() {
        unsafe {
            let mut rl: Rlimit = core::mem::zeroed();
            assert_eq!(getrlimit(RLIMIT_NOFILE, &mut rl), 0);
            assert!(rl.rlim_cur > 0 && rl.rlim_cur <= rl.rlim_max);
            assert!(ulimit(UL_GETFSIZE, 0) > 0);
            let mut old: Rlimit = core::mem::zeroed();
            assert_eq!(prlimit(0, RLIMIT_FSIZE, core::ptr::null(), &mut old), 0);
            assert!(old.rlim_cur > 0);
        }
    }

    #[test]
    fn uname_and_hostname_agree() {
        unsafe {
            let mut u: Utsname = core::mem::zeroed();
            assert_eq!(uname(&mut u), 0);
            assert!(u.sysname[0] != 0 && u.release[0] != 0 && u.machine[0] != 0);
            let mut hn = [0 as c_char; 256];
            assert_eq!(gethostname(hn.as_mut_ptr(), hn.len()), 0);
            assert_eq!(
                std::ffi::CStr::from_ptr(hn.as_ptr()).to_bytes(),
                std::ffi::CStr::from_ptr(u.nodename.as_ptr()).to_bytes()
            );
            let mut dn = [0 as c_char; 65];
            assert_eq!(getdomainname(dn.as_mut_ptr(), dn.len()), 0);
        }
    }

    #[test]
    fn rusage_and_sysinfo_work() {
        unsafe {
            let mut ru: Rusage = core::mem::zeroed();
            assert_eq!(getrusage(RUSAGE_SELF, &mut ru), 0);
            let mut si: Sysinfo = core::mem::zeroed();
            assert_eq!(sysinfo(&mut si), 0);
            assert!(si.totalram > 0 && si.mem_unit > 0);
        }
    }

    #[test]
    fn auxv_pagesize_matches_sysconf() {
        unsafe {
            assert_eq!(getauxval(6), sysconf(30) as c_ulong);
            assert_eq!(getauxval(0), 0);
        }
    }

    #[test]
    fn logmask_roundtrips_and_syslog_survives() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let old = setlogmask(0);
            assert_ne!(old, 0);
            assert_eq!(setlogmask(old), old);
            openlog(cstr(b"zlibc-test\0"), 0x01, 8);
            syslog(6, cstr(b"zlibc sysconf smoke %d\0"), 0, 0, 0, 0, 0, 0);
            closelog();
            setlogmask(old);
        }
    }

    #[test]
    fn klogctl_rejects_without_privs_but_traps() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            // Type 3 (read) needs privilege; what matters is a real trap
            // answer (errno set), not success.
            let mut buf = [0 as c_char; 64];
            let r = klogctl(3, buf.as_mut_ptr(), buf.len() as c_int);
            assert!(r >= 0 || crate::errno::errno_load(crate::errno::__errno_location()) != 0);
            assert_eq!(acct(core::ptr::null::<c_char>()), -1);
        }
    }

    #[test]
    fn des_crypt_matches_libc_oracle() {
        unsafe {
            let h = crypt(cstr(b"pw\0"), cstr(b"aa\0"));
            assert!(!h.is_null());
            let s = std::ffi::CStr::from_ptr(h).to_bytes();
            assert_eq!(s, b"aa5V9MSdgw5ec");
            let mut data: CryptData = core::mem::zeroed();
            let h2 = crypt_r(cstr(b"pw\0"), cstr(b"aa\0"), &mut data);
            assert_eq!(h2, &mut data as *mut CryptData as *mut c_char);
            let s2 = std::ffi::CStr::from_ptr(h2).to_bytes();
            assert_eq!(s2, b"aa5V9MSdgw5ec");
        }
    }

    #[test]
    fn modular_crypt_matches_libc_oracle() {
        unsafe {
            for (key, set, want) in [
                (
                    b"password\0".as_slice(),
                    b"$1$abcd0123$\0".as_slice(),
                    b"$1$abcd0123$U.n6Jj1fRNp16L12zcPVi.".as_slice(),
                ),
                (
                    b"hello\0",
                    b"$5$rounds=1000$salt1234$\0",
                    b"$5$rounds=1000$salt1234$9jXMIBcbxJ8xe1HKAsczY4HuRxSVB5jBpI0uvyw/AqC".as_slice(),
                ),
                (
                    b"hello\0",
                    b"$6$rounds=1000$salt1234$\0",
                    b"$6$rounds=1000$salt1234$yKjRRthrPMxyR7ZoEm8Jgm2g0GP3SDMfHXg.FErhtu6F8raFgnSMONZhewhWW8MO8zUrshnghsAEvtkieXrFz0".as_slice(),
                ),
            ] {
                let h = crypt(cstr(key), cstr(set));
                assert!(!h.is_null());
                assert_eq!(std::ffi::CStr::from_ptr(h).to_bytes(), want);
            }
            // bcrypt has no implementation here: closed failure "*".
            let hb = crypt(cstr(b"pw\0"), cstr(b"$2a$05$abcdefghijklmnopqrstuu\0"));
            assert_eq!(std::ffi::CStr::from_ptr(hb).to_bytes(), b"*");
        }
    }

    #[test]
    fn des_block_roundtrips() {
        unsafe {
            setkey(cstr(
                b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\0",
            ));
            let mut blk = [b'0' as c_char; 64];
            encrypt(blk.as_mut_ptr(), 0);
            // musl's contract is bit0-per-byte: encrypt emits binary
            // 0/1 (verified byte-exact against musl-gcc above), so mask.
            let enc_bits: Vec<u8> = blk.iter().map(|b| (*b as u8) & 1).collect();
            assert!(enc_bits.iter().any(|b| *b != 0));
            encrypt(blk.as_mut_ptr(), 1);
            let dec_bits: Vec<u8> = blk.iter().map(|b| (*b as u8) & 1).collect();
            assert!(dec_bits.iter().all(|b| *b == 0));
        }
    }

    #[test]
    fn mntent_reads_a_table() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            let path = format!("/tmp/zlibc-mnt-{}-{}.tab", std::process::id(), 10);
            std::fs::write(&path, b"/dev/sda1 / ext4 rw,relatime 0 1\n").unwrap();
            let pathz = format!("{path}\0");
            let f = setmntent(cstr(pathz.as_bytes()), cstr(b"r\0"));
            assert!(!f.is_null());
            let e = getmntent(f);
            assert!(!e.is_null());
            assert_eq!(std::ffi::CStr::from_ptr((*e).mnt_dir).to_bytes(), b"/");
            assert!(!hasmntopt(e, cstr(b"rw\0")).is_null());
            assert!(hasmntopt(e, cstr(b"ro\0")).is_null());
            assert_eq!(endmntent(f), 1);
            std::fs::remove_file(&path).unwrap();
        }
    }

    #[test]
    fn utmpx_stubs_match_musl() {
        let _guard = crate::ldso::testlock::lock();
        unsafe {
            assert!(getutxent().is_null());
            assert_eq!(utmpxname(cstr(b"/nonexistent\0")), -1);
            assert_eq!(
                crate::errno::errno_load(crate::errno::__errno_location()),
                95
            );
        }
    }
}
