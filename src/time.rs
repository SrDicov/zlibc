//! Time of day, clocks, sleeps and calendar (musl `src/time/*`).
//!
//! Clean-room mirror of musl's `clock_gettime.c`, `clock_getres.c`,
//! `clock_nanosleep.c`, `clock_settime.c`, `gettimeofday.c`,
//! `nanosleep.c`, `time.c`, `gmtime{,_r}.c`, `localtime{,_r}.c`,
//! `mktime.c`, `timegm.c`, `asctime{,_r}.c`, `ctime{,_r}.c`,
//! `difftime.c`, `strftime.c`, `strptime.c`, `tzset.c` plus the
//! internal `__secs_to_tm` / `__tm_to_secs` / `__month_to_secs` /
//! `__year_to_secs` converters. Only the helpers underneath differ
//! (raw syscalls, own formatting; see each item).
//!
//! TIMEZONE REALITY (documented, not solved): no tzdata parser exists
//! yet (own wave), so there is nothing to map and no POSIX-TZ rule
//! engine. `localtime`/`localtime_r` behave as UTC, `mktime`/`timegm`
//! assume UTC, and `tzset` only (re)establishes the UTC statics; it
//! does not read `TZ`. This deviates from musl-with-Olson (which would
//! apply `TZ`/zoneinfo) but is identical to musl-without-tzdata, whose
//! fallback for an unparseable/missing zone is also UTC. `tzname` is
//! `{"UTC","UTC"}`, `daylight = 0`, `timezone = 0`.
//!
//! Other deliberate deviations from musl:
//! - No vDSO: `clock_gettime`/`gettimeofday`/`time` always trap through
//!   raw `SYS_clock_gettime` (228). Identical results, slower path.
//! - `Timespec`/`Timeval` are defined locally here; the clocks wave
//!   owns the public ones later (merge note, same as `epoll`/`poll`).
//! - `asctime` with out-of-range `wday`/`mon` prints `"???"` where
//!   musl would read a neighboring C-locale string (musl's `asctime`
//!   has no range guard; `strftime` prints empty). Garbage-in either
//!   way; ours is at least in-bounds.
//! - `difftime` uses `wrapping_sub` (musl's plain `-` is UB on
//!   overflow in C and wraps in practice); identical on all inputs
//!   that do not overflow `i64`.
//! - musl's `%F` rewind logic, `%s` (parse-only), and the `+`/width
//!   re-padding for `%C`/`%F`/`%G`/`%Y` are ported; `%O`/`%E` are
//!   consumed and ignored exactly like musl (it skips the modifier
//!   with `f++` and formats the base conversion).

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr::{addr_of_mut, null, null_mut};

use crate::errno::{__errno_location, errno_store};
use crate::syscall::{syscall2, syscall4, syscall_ret};

// ---- Syscalls (musl arch/x86_64/bits/syscall.h.in) --------------------------
#[cfg(target_arch = "x86_64")]
const SYS_NANOSLEEP: usize = 35;
#[cfg(target_arch = "x86_64")]
const SYS_SETTIMEOFDAY: usize = 164;
#[cfg(target_arch = "x86_64")]
const SYS_CLOCK_SETTIME: usize = 227;
#[cfg(target_arch = "x86_64")]
const SYS_CLOCK_GETTIME: usize = 228;
#[cfg(target_arch = "x86_64")]
const SYS_CLOCK_GETRES: usize = 229;
#[cfg(target_arch = "x86_64")]
const SYS_CLOCK_NANOSLEEP: usize = 230;

// ---- Errnos (musl arch/generic/bits/errno.h) --------------------------------
#[cfg(target_arch = "x86_64")]
const EFAULT: c_int = 14;
#[cfg(target_arch = "x86_64")]
const EINVAL: c_int = 22;
#[cfg(target_arch = "x86_64")]
const EOVERFLOW: c_int = 75;

// ---- Types ------------------------------------------------------------------
// musl `include/time.h` (`struct tm` with the glibc-compat `gmtoff`/`zone`
// tail) and `struct timespec`; musl `sys/time.h` (`struct timeval`,
// `struct timezone`). `time_t` is `i64` on x86_64 musl (`long`).
#[cfg(target_arch = "x86_64")]
#[allow(non_camel_case_types)]
pub type time_t = i64;
#[cfg(target_arch = "x86_64")]
#[allow(non_camel_case_types)]
pub type clockid_t = c_int;
#[cfg(target_arch = "x86_64")]
#[allow(non_camel_case_types)]
pub type suseconds_t = c_long;

/// Local `struct timespec` (clocks wave owns the public one; note the
/// future merge). Field order matches musl: seconds, nanoseconds.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Timespec {
    pub tv_sec: time_t,
    pub tv_nsec: c_long,
}

/// Local `struct timeval` (same merge note as [`Timespec`]).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Timeval {
    pub tv_sec: time_t,
    pub tv_usec: suseconds_t,
}

/// musl `struct timezone` (`sys/time.h`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Timezone {
    pub tz_minuteswest: c_int,
    pub tz_dsttime: c_int,
}

/// musl `struct tm` (`include/time.h:30-41`), order and sizes verbatim.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct Tm {
    pub tm_sec: c_int,
    pub tm_min: c_int,
    pub tm_hour: c_int,
    pub tm_mday: c_int,
    pub tm_mon: c_int,
    pub tm_year: c_int,
    pub tm_wday: c_int,
    pub tm_yday: c_int,
    pub tm_isdst: c_int,
    pub tm_gmtoff: c_long,
    pub tm_zone: *const c_char,
}

#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<Timespec>() == 16);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<Timeval>() == 16);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<Tm>() == 56);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(Tm, tm_isdst) == 32);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(Tm, tm_gmtoff) == 40);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::offset_of!(Tm, tm_zone) == 48);

// musl `include/time.h:87-98`.
#[cfg(target_arch = "x86_64")]
pub const CLOCK_REALTIME: clockid_t = 0;
#[cfg(target_arch = "x86_64")]
pub const CLOCK_MONOTONIC: clockid_t = 1;
#[cfg(target_arch = "x86_64")]
pub const CLOCK_PROCESS_CPUTIME_ID: clockid_t = 2;
#[cfg(target_arch = "x86_64")]
pub const CLOCK_THREAD_CPUTIME_ID: clockid_t = 3;
#[cfg(target_arch = "x86_64")]
pub const CLOCK_MONOTONIC_RAW: clockid_t = 4;
#[cfg(target_arch = "x86_64")]
pub const CLOCK_REALTIME_COARSE: clockid_t = 5;
#[cfg(target_arch = "x86_64")]
pub const CLOCK_MONOTONIC_COARSE: clockid_t = 6;
#[cfg(target_arch = "x86_64")]
pub const CLOCK_BOOTTIME: clockid_t = 7;
#[cfg(target_arch = "x86_64")]
pub const CLOCK_REALTIME_ALARM: clockid_t = 8;
#[cfg(target_arch = "x86_64")]
pub const CLOCK_BOOTTIME_ALARM: clockid_t = 9;
#[cfg(target_arch = "x86_64")]
pub const CLOCK_SGI_CYCLE: clockid_t = 10;
#[cfg(target_arch = "x86_64")]
pub const CLOCK_TAI: clockid_t = 11;
/// musl `include/time.h:100`.
#[cfg(target_arch = "x86_64")]
pub const TIMER_ABSTIME: c_int = 1;
/// musl `include/time.h:65`.
#[cfg(target_arch = "x86_64")]
pub const CLOCKS_PER_SEC: c_long = 1_000_000;

// ---- Global timezone state (musl `__tz.c`) ----------------------------------
// UTC only (see module docs). Initialized pointers live in `.data`,
// which is exactly where musl's live; no COMMON involved.
#[cfg(target_arch = "x86_64")]
static UTC_STD: [c_char; 4] = [85, 84, 67, 0]; // "UTC"
#[cfg(target_arch = "x86_64")]
static UTC_DST: [c_char; 4] = [85, 84, 67, 0]; // "UTC"
/// musl `tzname[2]`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub static mut tzname: [*mut c_char; 2] = [
    UTC_STD.as_ptr() as *mut c_char,
    UTC_DST.as_ptr() as *mut c_char,
];
/// musl `daylight`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub static mut daylight: c_int = 0;
/// musl `timezone`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub static mut timezone: c_long = 0;

// ---- Internal converters (musl `__secs_to_tm` etc., verbatim logic) ---------

/// musl `__secs_to_tm.c`: 2000-03-01 (mod-400 year, right after feb29).
#[cfg(target_arch = "x86_64")]
const LEAPOCH: i64 = 946684800 + 86400 * (31 + 29);
#[cfg(target_arch = "x86_64")]
const DAYS_PER_400Y: i64 = 365 * 400 + 97;
#[cfg(target_arch = "x86_64")]
const DAYS_PER_100Y: i64 = 365 * 100 + 24;
#[cfg(target_arch = "x86_64")]
const DAYS_PER_4Y: i64 = 365 * 4 + 1;
/// musl's year-overflow guard (`INT_MIN/MAX * 31622400`).
#[cfg(target_arch = "x86_64")]
const SECS_MIN: i64 = (c_int::MIN as i64).wrapping_mul(31_622_400);
#[cfg(target_arch = "x86_64")]
const SECS_MAX: i64 = (c_int::MAX as i64).wrapping_mul(31_622_400);

/// musl `__secs_to_tm` (logic verbatim; `wrapping_*` for the
/// overflow-UB the C version merely gets away with).
#[cfg(target_arch = "x86_64")]
fn secs_to_tm(t: i64, tm: &mut Tm) -> c_int {
    const DAYS_IN_MONTH: [i64; 12] = [31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 29];
    if !(SECS_MIN..=SECS_MAX).contains(&t) {
        return -1;
    }
    let secs = t.wrapping_sub(LEAPOCH);
    // musl's truncating-division form (negative remainders folded by hand).
    let days = secs / 86400;
    let rs = secs % 86400;
    let (days, remsecs) = if rs < 0 {
        (days - 1, (rs + 86400) as c_int)
    } else {
        (days, rs as c_int)
    };
    let mut wday = (3 + days) % 7;
    if wday < 0 {
        wday += 7;
    }
    let mut qc_cycles = days / DAYS_PER_400Y;
    let mut remdays = days % DAYS_PER_400Y;
    if remdays < 0 {
        remdays += DAYS_PER_400Y;
        qc_cycles -= 1;
    }
    let mut c_cycles = remdays / DAYS_PER_100Y;
    if c_cycles == 4 {
        c_cycles -= 1;
    }
    remdays -= c_cycles * DAYS_PER_100Y;
    let mut q_cycles = remdays / DAYS_PER_4Y;
    if q_cycles == 25 {
        q_cycles -= 1;
    }
    remdays -= q_cycles * DAYS_PER_4Y;
    let mut remyears = remdays / 365;
    if remyears == 4 {
        remyears -= 1;
    }
    remdays -= remyears * 365;
    let leap = remyears == 0 && (q_cycles != 0 || c_cycles == 0);
    let mut yday = remdays + 31 + 28 + leap as i64;
    if yday >= 365 + leap as i64 {
        yday -= 365 + leap as i64;
    }
    let mut years = remyears + 4 * q_cycles + 100 * c_cycles + 400 * qc_cycles;
    let mut months: i64 = 0;
    while DAYS_IN_MONTH[months as usize] <= remdays {
        remdays -= DAYS_IN_MONTH[months as usize];
        months += 1;
    }
    if months >= 10 {
        months -= 12;
        years += 1;
    }
    if years + 100 > c_int::MAX as i64 || years + 100 < c_int::MIN as i64 {
        return -1;
    }
    tm.tm_year = (years + 100) as c_int;
    tm.tm_mon = (months + 2) as c_int;
    tm.tm_mday = (remdays + 1) as c_int;
    tm.tm_wday = wday as c_int;
    tm.tm_yday = yday as c_int;
    tm.tm_hour = remsecs / 3600;
    tm.tm_min = remsecs / 60 % 60;
    tm.tm_sec = remsecs % 60;
    0
}

/// musl `__month_to_secs.c` (table verbatim).
#[cfg(target_arch = "x86_64")]
fn month_to_secs(month: c_int, is_leap: c_int) -> c_int {
    const SECS_THROUGH_MONTH: [c_int; 12] = [
        0,
        31 * 86400,
        59 * 86400,
        90 * 86400,
        120 * 86400,
        151 * 86400,
        181 * 86400,
        212 * 86400,
        243 * 86400,
        273 * 86400,
        304 * 86400,
        334 * 86400,
    ];
    let mut t = SECS_THROUGH_MONTH[month as usize];
    if is_leap != 0 && month >= 2 {
        t += 86400;
    }
    t
}

/// musl `__year_to_secs.c` (logic verbatim).
#[cfg(target_arch = "x86_64")]
fn year_to_secs(year: i64, is_leap: &mut c_int) -> i64 {
    if (year as u64).wrapping_sub(2) <= 136 {
        let y = year as c_int;
        let mut leaps = (y - 68) >> 2;
        if (y - 68) & 3 == 0 {
            leaps -= 1;
            *is_leap = 1;
        } else {
            *is_leap = 0;
        }
        return 31_536_000i64
            .wrapping_mul((y - 70) as i64)
            .wrapping_add(86400i64.wrapping_mul(leaps as i64));
    }
    let mut cycles = (year - 100) / 400;
    let mut rem = (year - 100) % 400;
    if rem < 0 {
        cycles -= 1;
        rem += 400;
    }
    let centuries: i64;
    let mut leaps: i64;
    if rem == 0 {
        *is_leap = 1;
        centuries = 0;
        leaps = 0;
    } else {
        if rem >= 200 {
            if rem >= 300 {
                centuries = 3;
                rem -= 300;
            } else {
                centuries = 2;
                rem -= 200;
            }
        } else if rem >= 100 {
            centuries = 1;
            rem -= 100;
        } else {
            centuries = 0;
        }
        if rem == 0 {
            *is_leap = 0;
            leaps = 0;
        } else {
            leaps = rem / 4;
            rem %= 4;
            *is_leap = (rem == 0) as c_int;
        }
    }
    leaps += 97 * cycles + 24 * centuries - *is_leap as i64;
    (year - 100)
        .wrapping_mul(31_536_000)
        .wrapping_add(leaps.wrapping_mul(86400))
        .wrapping_add(946684800)
        .wrapping_add(86400)
}

/// musl `__tm_to_secs.c` (normalizes out-of-range months like musl).
#[cfg(target_arch = "x86_64")]
fn tm_to_secs(tm: &Tm) -> i64 {
    let mut is_leap = 0;
    let mut year = tm.tm_year as i64;
    let mut month = tm.tm_mon;
    if !(0..12).contains(&month) {
        let mut adj = month / 12;
        month %= 12;
        if month < 0 {
            adj -= 1;
            month += 12;
        }
        year += adj as i64;
    }
    let mut t = year_to_secs(year, &mut is_leap);
    t = t.wrapping_add(month_to_secs(month, is_leap) as i64);
    t = t.wrapping_add(86400i64.wrapping_mul((tm.tm_mday as i64).wrapping_sub(1)));
    t = t.wrapping_add(3600i64.wrapping_mul(tm.tm_hour as i64));
    t = t.wrapping_add(60i64.wrapping_mul(tm.tm_min as i64));
    t.wrapping_add(tm.tm_sec as i64)
}

// ---- C-locale names (musl `src/locale/langinfo.c` `c_time`) ------------------
#[cfg(target_arch = "x86_64")]
const ABDAY: [&[u8]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
#[cfg(target_arch = "x86_64")]
const DAY: [&[u8]; 7] = [
    b"Sunday",
    b"Monday",
    b"Tuesday",
    b"Wednesday",
    b"Thursday",
    b"Friday",
    b"Saturday",
];
#[cfg(target_arch = "x86_64")]
const ABMON: [&[u8]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];
#[cfg(target_arch = "x86_64")]
const MON: [&[u8]; 12] = [
    b"January",
    b"February",
    b"March",
    b"April",
    b"May",
    b"June",
    b"July",
    b"August",
    b"September",
    b"October",
    b"November",
    b"December",
];

// ---- Byte helpers (local; musl uses its ctype/locale tables) ----------------
#[cfg(target_arch = "x86_64")]
fn b_isdigit(c: u8) -> bool {
    c.wrapping_sub(b'0') < 10
}
#[cfg(target_arch = "x86_64")]
fn b_isspace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\x0B' | b'\x0C' | b'\r')
}
#[cfg(target_arch = "x86_64")]
fn b_isalpha(c: u8) -> bool {
    c.wrapping_sub(b'A') < 26 || c.wrapping_sub(b'a') < 26
}
#[cfg(target_arch = "x86_64")]
fn b_tolower(c: u8) -> u8 {
    if c.wrapping_sub(b'A') < 26 {
        c + 32
    } else {
        c
    }
}
/// `strlen` over a C string.
///
/// # Safety
///
/// `p` must point to a valid NUL-terminated byte string.
#[cfg(target_arch = "x86_64")]
unsafe fn c_strlen(p: *const c_char) -> usize {
    unsafe {
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        n
    }
}
/// Case-insensitive prefix match of `name` at `s`; length on match.
///
/// # Safety
///
/// `s` must point to readable bytes for `name.len()` (the caller
/// guarantees NUL termination, so short reads stop at NUL mismatch).
#[cfg(target_arch = "x86_64")]
unsafe fn match_name(s: *const u8, name: &[u8]) -> Option<usize> {
    unsafe {
        for (i, &b) in name.iter().enumerate() {
            let c = *s.add(i);
            if c == 0 || b_tolower(c) != b_tolower(b) {
                return None;
            }
        }
        Some(name.len())
    }
}

// ---- Clocks -----------------------------------------------------------------

/// musl `__clock_gettime` without the vDSO: raw `SYS_clock_gettime`
/// always (see module docs).
///
/// # Safety
///
/// `ts` must point to a writable [`Timespec`] (may be null only if the
/// kernel accepts it, i.e. never on success; musl passes it through
/// unchecked too).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn clock_gettime(clk: clockid_t, ts: *mut Timespec) -> c_int {
    unsafe { syscall_ret(syscall2(SYS_CLOCK_GETTIME, clk as usize, ts as usize)) as c_int }
}

/// musl `clock_getres.c` (64-bit path: result straight into `*ts`).
///
/// # Safety
///
/// `ts` may be null; otherwise must point to a writable [`Timespec`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn clock_getres(clk: clockid_t, ts: *mut Timespec) -> c_int {
    unsafe { syscall_ret(syscall2(SYS_CLOCK_GETRES, clk as usize, ts as usize)) as c_int }
}

/// musl `__clock_nanosleep` (64-bit path). Returns the errno value
/// itself, not -1: `EINVAL` for `CLOCK_THREAD_CPUTIME_ID`,
/// `CLOCK_REALTIME` without flags goes through `nanosleep`, and
/// `TIMER_ABSTIME` leaves `*rem` alone (the kernel only fills it for
/// relative sleeps — musl relies on the same behavior).
///
/// # Safety
///
/// `req` must point to a readable [`Timespec`]; `rem` may be null,
/// otherwise must point to a writable [`Timespec`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn clock_nanosleep(
    clk: clockid_t,
    flags: c_int,
    req: *const Timespec,
    rem: *mut Timespec,
) -> c_int {
    unsafe {
        if clk == CLOCK_THREAD_CPUTIME_ID {
            return EINVAL;
        }
        if clk == CLOCK_REALTIME && flags == 0 {
            let r = syscall2(SYS_NANOSLEEP, req as usize, rem as usize);
            return if r == 0 { 0 } else { (-r) as c_int };
        }
        let r = syscall4(
            SYS_CLOCK_NANOSLEEP,
            clk as usize,
            flags as usize,
            req as usize,
            rem as usize,
        );
        if r == 0 {
            0
        } else {
            (-r) as c_int
        }
    }
}

/// musl `clock_settime.c` (64-bit path).
///
/// # Safety
///
/// `ts` must point to a readable [`Timespec`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn clock_settime(clk: clockid_t, ts: *const Timespec) -> c_int {
    unsafe { syscall_ret(syscall2(SYS_CLOCK_SETTIME, clk as usize, ts as usize)) as c_int }
}

/// musl `gettimeofday.c`: `clock_gettime(CLOCK_REALTIME)` converted to
/// `tv_usec`; `tz` ignored; null `tv` returns 0.
///
/// # Safety
///
/// `tv` may be null; otherwise must point to a writable [`Timeval`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn gettimeofday(tv: *mut Timeval, tz: *mut c_void) -> c_int {
    unsafe {
        let _ = tz;
        if tv.is_null() {
            return 0;
        }
        let mut ts = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        clock_gettime(CLOCK_REALTIME, &mut ts);
        (*tv).tv_sec = ts.tv_sec;
        (*tv).tv_usec = (ts.tv_nsec / 1000) as suseconds_t;
        0
    }
}

/// `settimeofday` (musl `src/misc/settimeofday.c` shape): raw trap.
///
/// # Safety
///
/// `tv`/`tz` follow the kernel contract (either may be null).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn settimeofday(tv: *const Timeval, tz: *const Timezone) -> c_int {
    unsafe { syscall_ret(syscall2(SYS_SETTIMEOFDAY, tv as usize, tz as usize)) as c_int }
}

/// musl `nanosleep.c`: `__clock_nanosleep(CLOCK_REALTIME, 0, ...)`
/// with `EINTR` remainder semantics (the kernel fills `*rem`).
///
/// # Safety
///
/// `req` must point to a readable [`Timespec`]; `rem` may be null,
/// otherwise must point to a writable [`Timespec`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn nanosleep(req: *const Timespec, rem: *mut Timespec) -> c_int {
    unsafe {
        let e = clock_nanosleep(CLOCK_REALTIME, 0, req, rem);
        if e == 0 {
            0
        } else {
            errno_store(__errno_location(), e);
            -1
        }
    }
}

/// musl `time.c`.
///
/// # Safety
///
/// `t` may be null; otherwise must point to writable `time_t`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn time(t: *mut time_t) -> time_t {
    unsafe {
        let mut ts = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        clock_gettime(CLOCK_REALTIME, &mut ts);
        if !t.is_null() {
            *t = ts.tv_sec;
        }
        ts.tv_sec
    }
}

// ---- Broken-down time (UTC; see module docs) --------------------------------

/// musl `gmtime_r.c` (`__gmtime_r` body): UTC, `isdst = 0`.
///
/// # Safety
///
/// Both pointers must be valid; `tm` must point to a writable [`Tm`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn gmtime_r(t: *const time_t, tm: *mut Tm) -> *mut Tm {
    unsafe {
        if t.is_null() || tm.is_null() {
            errno_store(__errno_location(), EFAULT);
            return null_mut();
        }
        if secs_to_tm(*t, &mut *tm) < 0 {
            errno_store(__errno_location(), EOVERFLOW);
            return null_mut();
        }
        (*tm).tm_isdst = 0;
        (*tm).tm_gmtoff = 0;
        (*tm).tm_zone = UTC_STD.as_ptr();
        tm
    }
}

/// musl `gmtime.c`: static buffer, non-reentrant.
///
/// # Safety
///
/// `t` must point to a readable `time_t`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn gmtime(t: *const time_t) -> *mut Tm {
    unsafe {
        static mut TM: Tm = Tm {
            tm_sec: 0,
            tm_min: 0,
            tm_hour: 0,
            tm_mday: 0,
            tm_mon: 0,
            tm_year: 0,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
            tm_gmtoff: 0,
            tm_zone: null(),
        };
        gmtime_r(t, addr_of_mut!(TM))
    }
}

/// musl `localtime_r.c` (`__localtime_r` body) with the UTC zone:
/// range check verbatim, then `secs_to_tm` straight (zero `gmtoff`).
///
/// # Safety
///
/// Both pointers must be valid; `tm` must point to a writable [`Tm`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn localtime_r(t: *const time_t, tm: *mut Tm) -> *mut Tm {
    unsafe {
        if t.is_null() || tm.is_null() {
            errno_store(__errno_location(), EFAULT);
            return null_mut();
        }
        if *t < SECS_MIN || *t > SECS_MAX {
            errno_store(__errno_location(), EOVERFLOW);
            return null_mut();
        }
        if secs_to_tm(*t, &mut *tm) < 0 {
            errno_store(__errno_location(), EOVERFLOW);
            return null_mut();
        }
        (*tm).tm_isdst = 0;
        (*tm).tm_gmtoff = 0;
        (*tm).tm_zone = UTC_STD.as_ptr();
        tm
    }
}

/// musl `localtime.c`: static buffer, non-reentrant.
///
/// # Safety
///
/// `t` must point to a readable `time_t`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn localtime(t: *const time_t) -> *mut Tm {
    unsafe {
        static mut TM: Tm = Tm {
            tm_sec: 0,
            tm_min: 0,
            tm_hour: 0,
            tm_mday: 0,
            tm_mon: 0,
            tm_year: 0,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
            tm_gmtoff: 0,
            tm_zone: null(),
        };
        localtime_r(t, addr_of_mut!(TM))
    }
}

/// musl `mktime.c` with the UTC zone folded in (zero offsets, so the
/// DST disambiguation is a no-op): `tm_to_secs`, range check,
/// normalize back into `*tm`.
///
/// # Safety
///
/// `tm` must point to a readable and writable [`Tm`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn mktime(tm: *mut Tm) -> time_t {
    unsafe {
        if tm.is_null() {
            errno_store(__errno_location(), EFAULT);
            return -1;
        }
        let t = tm_to_secs(&*tm);
        if !(SECS_MIN..=SECS_MAX).contains(&t) {
            errno_store(__errno_location(), EOVERFLOW);
            return -1;
        }
        let mut new_tm = Tm {
            tm_sec: 0,
            tm_min: 0,
            tm_hour: 0,
            tm_mday: 0,
            tm_mon: 0,
            tm_year: 0,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
            tm_gmtoff: 0,
            tm_zone: UTC_STD.as_ptr(),
        };
        if secs_to_tm(t, &mut new_tm) < 0 {
            errno_store(__errno_location(), EOVERFLOW);
            return -1;
        }
        new_tm.tm_isdst = 0;
        new_tm.tm_gmtoff = 0;
        new_tm.tm_zone = UTC_STD.as_ptr();
        *tm = new_tm;
        t
    }
}

/// musl `timegm.c`: `tm_to_secs` plus normalization writeback.
///
/// # Safety
///
/// `tm` must point to a readable and writable [`Tm`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn timegm(tm: *mut Tm) -> time_t {
    unsafe {
        if tm.is_null() {
            errno_store(__errno_location(), EFAULT);
            return -1;
        }
        let t = tm_to_secs(&*tm);
        let mut new_tm = Tm {
            tm_sec: 0,
            tm_min: 0,
            tm_hour: 0,
            tm_mday: 0,
            tm_mon: 0,
            tm_year: 0,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
            tm_gmtoff: 0,
            tm_zone: UTC_STD.as_ptr(),
        };
        if secs_to_tm(t, &mut new_tm) < 0 {
            errno_store(__errno_location(), EOVERFLOW);
            return -1;
        }
        new_tm.tm_isdst = 0;
        new_tm.tm_gmtoff = 0;
        new_tm.tm_zone = UTC_STD.as_ptr();
        *tm = new_tm;
        t
    }
}

/// musl `difftime.c` (`wrapping_sub`; see module docs).
/// Seconds between calendar times (musl `difftime`).
///
/// # Safety
///
/// Pure function of its arguments.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn difftime(t1: time_t, t0: time_t) -> f64 {
    t1.wrapping_sub(t0) as f64
}

/// musl `tzset.c`/`__tz.c` reduced to the UTC reality: re-establish
/// the UTC statics. Does not read `TZ` (no tzdata/parser wave yet).
/// Re-establish UTC statics; TZ unread (no tzdata wave yet).
///
/// # Safety
///
/// Resets process-global timezone state; single-threaded contract.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn tzset() {
    unsafe {
        *addr_of_mut!(tzname).cast::<*mut c_char>() = UTC_STD.as_ptr() as *mut c_char;
        *addr_of_mut!(tzname).cast::<*mut c_char>().add(1) = UTC_DST.as_ptr() as *mut c_char;
        *addr_of_mut!(daylight) = 0;
        *addr_of_mut!(timezone) = 0;
    }
}

// ---- asctime/ctime (musl `asctime_r.c`, `ctime_r.c`) -------------------------

/// Shared body of [`asctime`] and [`asctime_r`]: exactly musl's
/// `"%.3s %.3s%3d %.2d:%.2d:%.2d %d\n"` (26 bytes with NUL).
/// Out-of-range `wday`/`mon` print `"???"` (see module docs).
///
/// # Safety
///
/// `tm` must point to a readable [`Tm`]; `buf` must fit 26 bytes.
#[cfg(target_arch = "x86_64")]
unsafe fn asctime_into(tm: *const Tm, buf: *mut c_char) {
    unsafe {
        let t = &*tm;
        let wd = if (t.tm_wday as usize) < 7 {
            ABDAY[t.tm_wday as usize]
        } else {
            b"???"
        };
        let mo = if (t.tm_mon as usize) < 12 {
            ABMON[t.tm_mon as usize]
        } else {
            b"???"
        };
        let mut b = [0u8; 26];
        let mut n = 0;
        for &c in wd.iter().take(3) {
            b[n] = c;
            n += 1;
        }
        b[n] = b' ';
        n += 1;
        for &c in mo.iter().take(3) {
            b[n] = c;
            n += 1;
        }
        // "%3d" mday, "%02d" x3, "%d" year, "\n".
        let mut num = [0u8; 16];
        let ml = dec_into(&mut num, t.tm_mday as i64);
        let pad = 3usize.saturating_sub(ml);
        for _ in 0..pad {
            b[n] = b' ';
            n += 1;
        }
        for &c in num[..ml].iter() {
            b[n] = c;
            n += 1;
        }
        b[n] = b' ';
        n += 1;
        for &v in [t.tm_hour, t.tm_min, t.tm_sec].iter() {
            let l = dec02_into(&mut num, v as i64);
            for &c in num[..l].iter() {
                b[n] = c;
                n += 1;
            }
            b[n] = b':';
            n += 1;
        }
        n -= 1; // drop last ':'
        b[n] = b' ';
        n += 1;
        let yl = dec_into(&mut num, 1900i64.wrapping_add(t.tm_year as i64));
        for &c in num[..yl].iter() {
            b[n] = c;
            n += 1;
        }
        b[n] = b'\n';
        n += 1;
        b[n] = 0;
        for (i, &c) in b.iter().enumerate() {
            *buf.add(i) = c as c_char;
            if c == 0 {
                break;
            }
        }
    }
}

/// Decimal rendering of `v` (sign + digits) into `out`; returns length.
#[cfg(target_arch = "x86_64")]
fn dec_into(out: &mut [u8; 16], v: i64) -> usize {
    let mut tmp = [0u8; 20];
    let neg = v < 0;
    let mut u = (v as u64).wrapping_neg_cond(neg);
    let mut n = 0;
    loop {
        tmp[n] = b'0' + (u % 10) as u8;
        u /= 10;
        n += 1;
        if u == 0 {
            break;
        }
    }
    let mut l = 0;
    if neg {
        out[0] = b'-';
        l = 1;
    }
    for i in (0..n).rev() {
        out[l] = tmp[i];
        l += 1;
    }
    l
}

/// `%02d`-style two-digit rendering (sign + zero-pad to 2).
#[cfg(target_arch = "x86_64")]
fn dec02_into(out: &mut [u8; 16], v: i64) -> usize {
    if v < 0 {
        out[0] = b'-';
        let l = dec_into(out, v.wrapping_neg());
        // shift right by one for the sign: dec_into overwrote out[0].
        // Rebuild: '-' + zero-padded magnitude.
        let mut mag = [0u8; 16];
        let ml = dec02_mag(&mut mag, (v as u64).wrapping_neg());
        out[0] = b'-';
        let mut l2 = 1;
        for &c in mag[..ml].iter() {
            out[l2] = c;
            l2 += 1;
        }
        let _ = l;
        return l2;
    }
    dec02_mag(out, v as u64)
}

#[cfg(target_arch = "x86_64")]
fn dec02_mag(out: &mut [u8; 16], mut u: u64) -> usize {
    let mut tmp = [0u8; 20];
    let mut n = 0;
    loop {
        tmp[n] = b'0' + (u % 10) as u8;
        u /= 10;
        n += 1;
        if u == 0 {
            break;
        }
    }
    while n < 2 {
        tmp[n] = b'0';
        n += 1;
    }
    for i in 0..n {
        out[i] = tmp[n - 1 - i];
    }
    n
}

#[cfg(target_arch = "x86_64")]
trait WrappingNeg {
    fn wrapping_neg_cond(self, neg: bool) -> Self;
}
#[cfg(target_arch = "x86_64")]
impl WrappingNeg for u64 {
    fn wrapping_neg_cond(self, neg: bool) -> Self {
        if neg {
            self.wrapping_neg()
        } else {
            self
        }
    }
}

/// musl `asctime_r.c` (`__asctime_r` body).
///
/// # Safety
///
/// `tm` must point to a readable [`Tm`]; `buf` must fit 26 bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn asctime_r(tm: *const Tm, buf: *mut c_char) -> *mut c_char {
    unsafe {
        if tm.is_null() || buf.is_null() {
            errno_store(__errno_location(), EFAULT);
            return null_mut();
        }
        asctime_into(tm, buf);
        buf
    }
}

/// musl `asctime.c`: static 26-byte buffer, non-reentrant.
///
/// # Safety
///
/// `tm` must point to a readable [`Tm`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn asctime(tm: *const Tm) -> *mut c_char {
    unsafe {
        static mut BUF: [c_char; 26] = [0; 26];
        if tm.is_null() {
            errno_store(__errno_location(), EFAULT);
            return null_mut();
        }
        asctime_into(tm, addr_of_mut!(BUF).cast());
        addr_of_mut!(BUF).cast()
    }
}

/// musl `ctime_r.c`: `localtime_r` + `asctime_r`.
///
/// # Safety
///
/// `t` must point to a readable `time_t`; `buf` must fit 26 bytes.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ctime_r(t: *const time_t, buf: *mut c_char) -> *mut c_char {
    unsafe {
        let mut tm = Tm {
            tm_sec: 0,
            tm_min: 0,
            tm_hour: 0,
            tm_mday: 0,
            tm_mon: 0,
            tm_year: 0,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
            tm_gmtoff: 0,
            tm_zone: null(),
        };
        if localtime_r(t, &mut tm).is_null() {
            return null_mut();
        }
        asctime_r(&tm, buf)
    }
}

/// musl `ctime.c`: `localtime` + `asctime`.
///
/// # Safety
///
/// `t` must point to a readable `time_t`.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ctime(t: *const time_t) -> *mut c_char {
    unsafe {
        let tm = localtime(t);
        if tm.is_null() {
            return null_mut();
        }
        asctime(tm)
    }
}

// ---- strftime (musl `strftime.c`, C locale only) -----------------------------

/// Scratch for one conversion (musl uses `char buf[100]`).
#[cfg(target_arch = "x86_64")]
const FMT_SCRATCH: usize = 128;

#[cfg(target_arch = "x86_64")]
fn is_leap_year(y: c_int) -> bool {
    let mut yy = y as i64;
    if yy > c_int::MAX as i64 - 1900 {
        yy -= 2000;
    }
    yy += 1900;
    yy % 4 == 0 && (yy % 100 != 0 || yy % 400 == 0)
}

/// musl `week_num`.
#[cfg(target_arch = "x86_64")]
fn week_num(tm: &Tm) -> i64 {
    let mut val = (tm.tm_yday as i64 + 7 - (tm.tm_wday as i64 + 6) % 7) / 7;
    if ((tm.tm_wday as i64 + 371 - tm.tm_yday as i64 - 2) % 7 + 7) % 7 <= 2 {
        val += 1;
    }
    if val == 0 {
        val = 52;
        let dec31 = ((tm.tm_wday as i64 + 7 - tm.tm_yday as i64 - 1) % 7 + 7) % 7;
        if dec31 == 4 || (dec31 == 5 && is_leap_year(tm.tm_year % 400 - 1)) {
            val += 1;
        }
    } else if val == 53 {
        let jan1 = ((tm.tm_wday as i64 + 371 - tm.tm_yday as i64) % 7 + 7) % 7;
        if jan1 != 4 && (jan1 != 3 || !is_leap_year(tm.tm_year)) {
            val = 1;
        }
    }
    val
}

/// One formatted number into `out` with musl's pad semantics:
/// `-` = no pad, `_` = space pad, otherwise zero pad.
///
/// Returns the byte length.
#[cfg(target_arch = "x86_64")]
fn fmt_number(out: &mut [u8; FMT_SCRATCH], val: i64, width: usize, pad: u8) -> usize {
    let mut dig = [0u8; 16];
    let dl = dec_into(&mut dig, val);
    let neg = val < 0;
    let maglen = if neg { dl - 1 } else { dl };
    let mag = if neg { &dig[1..dl] } else { &dig[..dl] };
    let mut n = 0;
    if neg {
        out[0] = b'-';
        n = 1;
    }
    let total = if maglen > width { maglen } else { width };
    let fill = if pad == b'-' {
        0
    } else {
        total.saturating_sub(maglen)
    };
    let fc = if pad == b'_' { b' ' } else { b'0' };
    for _ in 0..fill {
        out[n] = fc;
        n += 1;
    }
    for &c in mag.iter() {
        out[n] = c;
        n += 1;
    }
    n
}

/// One `strftime` conversion into `out` (musl `__strftime_fmt_1` for the
/// C locale). `f` is the conversion byte, `pad` the flag (`-`/`_`/`0`
/// or 0). Returns the byte length, or `None` for unknown conversions.
/// `recurse` handles `%c`/`%D`/`%F`/`%R`/`%r`/`%T`/`%x`/`%X`.
#[cfg(target_arch = "x86_64")]
fn fmt_1(
    out: &mut [u8; FMT_SCRATCH],
    f: u8,
    tm: &Tm,
    pad: u8,
    recurse: &mut impl FnMut(&mut [u8; FMT_SCRATCH], &[u8]) -> Option<usize>,
) -> Option<usize> {
    let put = |out: &mut [u8; FMT_SCRATCH], s: &[u8]| -> Option<usize> {
        let n = s.len().min(out.len());
        out[..n].copy_from_slice(&s[..n]);
        Some(n)
    };
    match f {
        b'a' => {
            if tm.tm_wday as u32 > 6 {
                return put(out, b"");
            }
            put(out, ABDAY[tm.tm_wday as usize])
        }
        b'A' => {
            if tm.tm_wday as u32 > 6 {
                return put(out, b"");
            }
            put(out, DAY[tm.tm_wday as usize])
        }
        b'h' | b'b' => {
            if tm.tm_mon as u32 > 11 {
                return put(out, b"");
            }
            put(out, ABMON[tm.tm_mon as usize])
        }
        b'B' => {
            if tm.tm_mon as u32 > 11 {
                return put(out, b"");
            }
            put(out, MON[tm.tm_mon as usize])
        }
        b'c' => recurse(out, b"%a %b %e %T %Y"),
        b'C' => {
            let v = (1900i64.wrapping_add(tm.tm_year as i64)) / 100;
            Some(fmt_number(out, v, 2, if pad == 0 { b'0' } else { pad }))
        }
        b'd' => Some(fmt_number(
            out,
            tm.tm_mday as i64,
            2,
            if pad == 0 { b'0' } else { pad },
        )),
        b'e' => Some(fmt_number(
            out,
            tm.tm_mday as i64,
            2,
            if pad == 0 { b'_' } else { pad },
        )),
        b'D' => recurse(out, b"%m/%d/%y"),
        b'F' => recurse(out, b"%Y-%m-%d"),
        b'g' | b'G' => {
            let mut v = tm.tm_year as i64 + 1900;
            let wn = week_num(tm);
            if tm.tm_yday < 3 && wn != 1 {
                v -= 1;
            } else if tm.tm_yday > 360 && wn == 1 {
                v += 1;
            }
            if f == b'g' {
                Some(fmt_number(
                    out,
                    v % 100,
                    2,
                    if pad == 0 { b'0' } else { pad },
                ))
            } else {
                Some(fmt_number(out, v, 4, if pad == 0 { b'0' } else { pad }))
            }
        }
        b'H' => Some(fmt_number(
            out,
            tm.tm_hour as i64,
            2,
            if pad == 0 { b'0' } else { pad },
        )),
        b'I' => {
            let mut v = tm.tm_hour as i64;
            if v == 0 {
                v = 12;
            } else if v > 12 {
                v -= 12;
            }
            Some(fmt_number(out, v, 2, if pad == 0 { b'0' } else { pad }))
        }
        b'j' => Some(fmt_number(
            out,
            tm.tm_yday as i64 + 1,
            3,
            if pad == 0 { b'0' } else { pad },
        )),
        b'm' => Some(fmt_number(
            out,
            tm.tm_mon as i64 + 1,
            2,
            if pad == 0 { b'0' } else { pad },
        )),
        b'M' => Some(fmt_number(
            out,
            tm.tm_min as i64,
            2,
            if pad == 0 { b'0' } else { pad },
        )),
        b'n' => put(out, b"\n"),
        b'p' => put(out, if tm.tm_hour >= 12 { b"PM" } else { b"AM" }),
        b'r' => recurse(out, b"%I:%M:%S %p"),
        b'R' => recurse(out, b"%H:%M"),
        b's' => {
            let v = tm_to_secs(tm).wrapping_sub(tm.tm_gmtoff);
            Some(fmt_number(out, v, 1, if pad == 0 { b'0' } else { pad }))
        }
        b'S' => Some(fmt_number(
            out,
            tm.tm_sec as i64,
            2,
            if pad == 0 { b'0' } else { pad },
        )),
        b't' => put(out, b"\t"),
        b'T' => recurse(out, b"%H:%M:%S"),
        b'u' => {
            let v = if tm.tm_wday == 0 {
                7
            } else {
                tm.tm_wday as i64
            };
            Some(fmt_number(out, v, 1, if pad == 0 { b'0' } else { pad }))
        }
        b'U' => {
            let v = (tm.tm_yday as i64 + 7 - tm.tm_wday as i64) / 7;
            Some(fmt_number(out, v, 2, if pad == 0 { b'0' } else { pad }))
        }
        b'W' => {
            let v = (tm.tm_yday as i64 + 7 - (tm.tm_wday as i64 + 6) % 7) / 7;
            Some(fmt_number(out, v, 2, if pad == 0 { b'0' } else { pad }))
        }
        b'V' => Some(fmt_number(
            out,
            week_num(tm),
            2,
            if pad == 0 { b'0' } else { pad },
        )),
        b'w' => Some(fmt_number(
            out,
            tm.tm_wday as i64,
            1,
            if pad == 0 { b'0' } else { pad },
        )),
        b'x' => recurse(out, b"%m/%d/%y"),
        b'X' => recurse(out, b"%H:%M:%S"),
        b'y' => {
            let mut v = (tm.tm_year as i64 + 1900) % 100;
            if v < 0 {
                v = -v;
            }
            Some(fmt_number(out, v, 2, if pad == 0 { b'0' } else { pad }))
        }
        b'Y' => {
            let v = tm.tm_year as i64 + 1900;
            if v >= 10000 {
                out[0] = b'+';
                let mut dig = [0u8; 16];
                let dl = dec_into(&mut dig, v);
                // dec_into never emits '+' so copy from the digits.
                let src = if dig[0] == b'-' {
                    &dig[1..dl]
                } else {
                    &dig[..dl]
                };
                if dig[0] == b'-' {
                    out[0] = b'-';
                }
                out[1..1 + src.len()].copy_from_slice(src);
                return Some(1 + src.len());
            }
            Some(fmt_number(out, v, 4, if pad == 0 { b'0' } else { pad }))
        }
        b'z' => {
            if tm.tm_isdst < 0 {
                return put(out, b"");
            }
            let off = tm.tm_gmtoff;
            let v = off / 3600 * 100 + off % 3600 / 60;
            out[0] = if v < 0 { b'-' } else { b'+' };
            let mut u = if v < 0 { (-v) as u64 } else { v as u64 };
            let mut tmp = [b'0'; 4];
            for i in (0..4).rev() {
                tmp[i] = b'0' + (u % 10) as u8;
                u /= 10;
            }
            out[1..5].copy_from_slice(&tmp);
            Some(5)
        }
        b'Z' => {
            if tm.tm_isdst < 0 {
                return put(out, b"");
            }
            if tm.tm_zone.is_null() {
                return put(out, b"UTC");
            }
            let len = unsafe { c_strlen(tm.tm_zone) };
            let bytes = unsafe { core::slice::from_raw_parts(tm.tm_zone as *const u8, len) };
            put(out, bytes)
        }
        b'%' => put(out, b"%"),
        _ => None,
    }
}

/// musl `__strftime_l` (C locale): returns bytes written excluding NUL,
/// 0 when truncated or on unknown conversion (buffer still NUL-padded
/// per musl: `s[min(l,n-1)] = 0`).
///
/// # Safety
///
/// `s` must point to `n` writable bytes, `f` to a NUL-terminated
/// format string, `tm` to a readable [`Tm`].
#[cfg(target_arch = "x86_64")]
unsafe fn strftime_inner(s: *mut c_char, n: usize, f: *const c_char, tm: &Tm) -> usize {
    unsafe fn run(
        s: *mut c_char,
        n: usize,
        f: *const c_char,
        tm: &Tm,
        depth: u32,
    ) -> Option<usize> {
        unsafe {
            let mut l = 0usize;
            let mut p = f;
            // Recursive expansions reuse one scratch buffer per level.
            let mut scratch = [0u8; FMT_SCRATCH];
            loop {
                let c = *p;
                if c == 0 {
                    if l < n {
                        *s.add(l) = 0;
                    } else if n > 0 {
                        *s.add(n - 1) = 0;
                    }
                    return Some(l);
                }
                if c != b'%' as c_char {
                    if l < n {
                        *s.add(l) = c;
                    } else {
                        return None;
                    }
                    l += 1;
                    p = p.add(1);
                    continue;
                }
                p = p.add(1);
                let mut pad = 0u8;
                let c1 = *p as u8;
                if c1 == b'-' || c1 == b'_' || c1 == b'0' {
                    pad = c1;
                    p = p.add(1);
                }
                let mut plus = false;
                if *p as u8 == b'+' {
                    plus = true;
                    p = p.add(1);
                }
                // Width: only meaningful for C/F/G/Y (musl); parse but
                // otherwise ignore like musl does.
                let mut width: usize = 0;
                let mut has_width = false;
                while b_isdigit(*p as u8) {
                    has_width = true;
                    width = width
                        .saturating_mul(10)
                        .saturating_add((*p as u8 - b'0') as usize);
                    p = p.add(1);
                }
                let conv = *p as u8;
                let wide = matches!(conv, b'C' | b'F' | b'G' | b'Y') && has_width;
                if conv == b'E' || conv == b'O' {
                    p = p.add(1);
                }
                let fc = *p;
                if fc == 0 {
                    return None;
                }
                p = p.add(1);
                if depth < 8
                    && matches!(
                        fc as u8,
                        b'c' | b'D' | b'F' | b'R' | b'r' | b'T' | b'x' | b'X'
                    )
                {
                    let sub: &[u8] = match fc as u8 {
                        b'c' => b"%a %b %e %T %Y",
                        b'D' | b'x' => b"%m/%d/%y",
                        b'F' => b"%Y-%m-%d",
                        b'R' => b"%H:%M",
                        b'r' => b"%I:%M:%S %p",
                        _ => b"%H:%M:%S",
                    };
                    let mut subz = [0u8; 16];
                    subz[..sub.len()].copy_from_slice(sub);
                    let k = run(
                        scratch.as_mut_ptr().cast(),
                        scratch.len(),
                        subz.as_ptr().cast(),
                        tm,
                        depth + 1,
                    )?;
                    let (mut tptr, mut k) = (scratch.as_ptr(), k);
                    // musl `+`/width re-padding for wide years.
                    if wide || plus {
                        while k > 0 && (*tptr == b'+' || *tptr == b'-') {
                            tptr = tptr.add(1);
                            k -= 1;
                        }
                        let sl = core::slice::from_raw_parts(tptr, k);
                        let mut nz = 0;
                        while nz + 1 < sl.len() && sl[nz] == b'0' && b_isdigit(sl[nz + 1]) {
                            nz += 1;
                        }
                        tptr = tptr.add(nz);
                        k -= nz;
                        let mut w = if width > k { width } else { k };
                        let sl = core::slice::from_raw_parts(tptr, k);
                        let mut d = 0;
                        while d < sl.len() && b_isdigit(sl[d]) {
                            d += 1;
                        }
                        let thresh = if conv == b'C' { 3 } else { 5 };
                        if tm.tm_year < -1900 {
                            if l < n {
                                *s.add(l) = b'-' as c_char;
                            } else {
                                return None;
                            }
                            l += 1;
                            w = w.saturating_sub(1);
                        } else if plus && d + (w - k) >= thresh {
                            if l < n {
                                *s.add(l) = b'+' as c_char;
                            } else {
                                return None;
                            }
                            l += 1;
                            w = w.saturating_sub(1);
                        }
                        while w > k {
                            if l < n {
                                *s.add(l) = b'0' as c_char;
                            } else {
                                return None;
                            }
                            l += 1;
                            w -= 1;
                        }
                    }
                    let sl = core::slice::from_raw_parts(tptr, k);
                    let mut kk = k;
                    if kk > n.saturating_sub(l) {
                        kk = n.saturating_sub(l);
                    }
                    for (i, b) in sl.iter().take(kk).enumerate() {
                        *s.add(l + i) = *b as c_char;
                    }
                    l += kk;
                    if k > kk {
                        return None;
                    }
                    continue;
                }
                if depth >= 8 {
                    return None;
                }
                let mut tmp = [0u8; FMT_SCRATCH];
                let mut out = [0u8; FMT_SCRATCH];
                let _ = &mut tmp;
                let k = {
                    let mut rec = |_b: &mut [u8; FMT_SCRATCH], _f: &[u8]| -> Option<usize> { None };
                    fmt_1(&mut out, fc as u8, tm, pad, &mut rec)?
                };
                // musl `+`/width re-padding for C/G/Y numbers.
                let mut tptr = out.as_ptr();
                let mut k = k;
                if wide || plus {
                    while k > 0 && (*tptr == b'+' || *tptr == b'-') {
                        tptr = tptr.add(1);
                        k -= 1;
                    }
                    let sl = core::slice::from_raw_parts(tptr, k);
                    let mut nz = 0;
                    while nz + 1 < sl.len() && sl[nz] == b'0' && b_isdigit(sl[nz + 1]) {
                        nz += 1;
                    }
                    tptr = tptr.add(nz);
                    k -= nz;
                    let mut w = if width > k { width } else { k };
                    let sl = core::slice::from_raw_parts(tptr, k);
                    let mut d = 0;
                    while d < sl.len() && b_isdigit(sl[d]) {
                        d += 1;
                    }
                    let thresh = if conv == b'C' { 3 } else { 5 };
                    if tm.tm_year < -1900 {
                        if l < n {
                            *s.add(l) = b'-' as c_char;
                        } else {
                            return None;
                        }
                        l += 1;
                        w = w.saturating_sub(1);
                    } else if plus && d + (w - k) >= thresh {
                        if l < n {
                            *s.add(l) = b'+' as c_char;
                        } else {
                            return None;
                        }
                        l += 1;
                        w = w.saturating_sub(1);
                    }
                    while w > k {
                        if l < n {
                            *s.add(l) = b'0' as c_char;
                        } else {
                            return None;
                        }
                        l += 1;
                        w -= 1;
                    }
                }
                let sl = core::slice::from_raw_parts(tptr, k);
                let mut kk = k;
                if kk > n.saturating_sub(l) {
                    kk = n.saturating_sub(l);
                }
                for (i, b) in sl.iter().take(kk).enumerate() {
                    *s.add(l + i) = *b as c_char;
                }
                l += kk;
                if k > kk {
                    return None;
                }
            }
        }
    }
    unsafe {
        if n == 0 {
            return 0;
        }
        if s.is_null() || f.is_null() {
            return 0;
        }
        match run(s, n, f, tm, 0) {
            Some(l) if l < n => l,
            // Truncated or unknown conversion: NUL at s[n-1], return 0.
            Some(_) | None => {
                *s.add(n - 1) = 0;
                0
            }
        }
    }
}

/// musl `strftime` (C locale).
///
/// # Safety
///
/// `s` must point to `n` writable bytes, `format` to a NUL-terminated
/// string, `tm` to a readable [`Tm`].
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn strftime(
    s: *mut c_char,
    n: usize,
    format: *const c_char,
    tm: *const Tm,
) -> usize {
    unsafe {
        if s.is_null() || format.is_null() || tm.is_null() {
            return 0;
        }
        strftime_inner(s, n, format, &*tm)
    }
}

// ---- strptime (musl `strptime.c`, C locale only) -----------------------------

/// Recursive worker: musl's `strptime` body.
///
/// # Safety
///
/// `s`/`f` point to NUL-terminated strings; `tm` to a writable [`Tm`].
/// Returns the first unconsumed byte of `s`, or null on mismatch.
#[cfg(target_arch = "x86_64")]
unsafe fn strptime_inner(s: *const c_char, f: *const c_char, tm: *mut Tm) -> *mut c_char {
    unsafe {
        let mut s = s as *mut c_char;
        let mut f = f;
        let mut century = 0;
        let mut relyear = 0;
        let mut want_century = 0;
        while *f != 0 {
            if *f != b'%' as c_char {
                if b_isspace(*f as u8) {
                    while *s != 0 && b_isspace(*s as u8) {
                        s = s.add(1);
                    }
                } else if *s != *f {
                    return null_mut();
                } else {
                    s = s.add(1);
                }
                f = f.add(1);
                continue;
            }
            f = f.add(1);
            if *f as u8 == b'+' {
                f = f.add(1);
            }
            let mut w: i64 = -1;
            if b_isdigit(*f as u8) {
                w = 0;
                while b_isdigit(*f as u8) {
                    w = w
                        .saturating_mul(10)
                        .saturating_add((*f as u8 - b'0') as i64);
                    f = f.add(1);
                }
            }
            let conv = *f;
            if conv == 0 {
                return null_mut();
            }
            f = f.add(1);
            match conv as u8 {
                b'a' | b'A' => {
                    let mut hit = false;
                    // Full names first (musl scans i = 2*range-1 down).
                    for i in (0..14).rev() {
                        let name = if i >= 7 { DAY[i - 7] } else { ABDAY[i] };
                        if let Some(n) = match_name(s as *const u8, name) {
                            s = s.add(n);
                            (*tm).tm_wday = (i % 7) as c_int;
                            hit = true;
                            break;
                        }
                    }
                    if !hit {
                        return null_mut();
                    }
                }
                b'b' | b'B' | b'h' => {
                    let mut hit = false;
                    for i in (0..24).rev() {
                        let name = if i >= 12 { MON[i - 12] } else { ABMON[i] };
                        if let Some(n) = match_name(s as *const u8, name) {
                            s = s.add(n);
                            (*tm).tm_mon = (i % 12) as c_int;
                            hit = true;
                            break;
                        }
                    }
                    if !hit {
                        return null_mut();
                    }
                }
                b'c' => {
                    s = strptime_inner(s, c"%a %b %e %T %Y".as_ptr(), tm);
                    if s.is_null() {
                        return null_mut();
                    }
                }
                b'C' => {
                    if w < 0 {
                        w = 2;
                    }
                    want_century |= 2;
                    if !parse_digits(&mut s, &mut century, w, false) {
                        return null_mut();
                    }
                }
                b'd' | b'e' => {
                    if !parse_range(&mut s, &mut (*tm).tm_mday, 1, 31) {
                        return null_mut();
                    }
                }
                b'D' => {
                    s = strptime_inner(s, c"%m/%d/%y".as_ptr(), tm);
                    if s.is_null() {
                        return null_mut();
                    }
                }
                b'F' => {
                    // musl: width-limited temp buffer, year subfield
                    // itself unlimited; rewind what the inner parse
                    // did not consume.
                    let wlim = if w < 0 { usize::MAX } else { w as usize };
                    let mut tmp = [0u8; 20];
                    let mut i = 0;
                    if *s == b'-' as c_char || *s == b'+' as c_char {
                        tmp[0] = *s as u8;
                        s = s.add(1);
                        i = 1;
                    }
                    while *s as u8 == b'0' && b_isdigit(*s.add(1) as u8) {
                        s = s.add(1);
                    }
                    while *s != 0 && i < wlim && i + 1 < tmp.len() {
                        tmp[i] = *s as u8;
                        s = s.add(1);
                        i += 1;
                    }
                    tmp[i] = 0;
                    let p = strptime_inner(tmp.as_ptr().cast(), c"%12Y-%m-%d".as_ptr(), tm);
                    if p.is_null() {
                        return null_mut();
                    }
                    let used = p as usize - tmp.as_ptr() as usize;
                    s = (s as usize - (i - used)) as *mut c_char;
                }
                b'H' => {
                    if !parse_range(&mut s, &mut (*tm).tm_hour, 0, 24) {
                        return null_mut();
                    }
                }
                b'I' => {
                    if !parse_range(&mut s, &mut (*tm).tm_hour, 1, 12) {
                        return null_mut();
                    }
                }
                b'j' => {
                    let mut v = 0;
                    if !parse_range(&mut s, &mut v, 1, 366) {
                        return null_mut();
                    }
                    (*tm).tm_yday = v - 1;
                }
                b'm' => {
                    let mut v = 0;
                    if !parse_range(&mut s, &mut v, 1, 12) {
                        return null_mut();
                    }
                    (*tm).tm_mon = v - 1;
                }
                b'M' => {
                    if !parse_range(&mut s, &mut (*tm).tm_min, 0, 60) {
                        return null_mut();
                    }
                }
                b'n' | b't' => {
                    while *s != 0 && b_isspace(*s as u8) {
                        s = s.add(1);
                    }
                }
                b'p' => {
                    if let Some(n) = match_name(s as *const u8, b"AM") {
                        (*tm).tm_hour %= 12;
                        s = s.add(n);
                    } else if let Some(n) = match_name(s as *const u8, b"PM") {
                        (*tm).tm_hour %= 12;
                        (*tm).tm_hour += 12;
                        s = s.add(n);
                    } else {
                        return null_mut();
                    }
                }
                b'r' => {
                    s = strptime_inner(s, c"%I:%M:%S %p".as_ptr(), tm);
                    if s.is_null() {
                        return null_mut();
                    }
                }
                b'R' => {
                    s = strptime_inner(s, c"%H:%M".as_ptr(), tm);
                    if s.is_null() {
                        return null_mut();
                    }
                }
                b's' => {
                    if *s == b'-' as c_char {
                        s = s.add(1);
                    }
                    if !b_isdigit(*s as u8) {
                        return null_mut();
                    }
                    while b_isdigit(*s as u8) {
                        s = s.add(1);
                    }
                }
                b'S' => {
                    if !parse_range(&mut s, &mut (*tm).tm_sec, 0, 61) {
                        return null_mut();
                    }
                }
                b'T' => {
                    s = strptime_inner(s, c"%H:%M:%S".as_ptr(), tm);
                    if s.is_null() {
                        return null_mut();
                    }
                }
                b'U' | b'W' => {
                    let mut dummy = 0;
                    if !parse_range(&mut s, &mut dummy, 0, 54) {
                        return null_mut();
                    }
                }
                b'V' => {
                    let mut dummy = 0;
                    if !parse_range(&mut s, &mut dummy, 1, 53) {
                        return null_mut();
                    }
                }
                b'g' => {
                    let mut dummy = 0;
                    if !parse_digits(&mut s, &mut dummy, 2, false) {
                        return null_mut();
                    }
                }
                b'G' => {
                    let mut dummy = 0;
                    if !parse_digits(&mut s, &mut dummy, if w < 0 { 4 } else { w }, true) {
                        return null_mut();
                    }
                }
                b'u' => {
                    if !parse_range(&mut s, &mut (*tm).tm_wday, 1, 7) {
                        return null_mut();
                    }
                }
                b'w' => {
                    if !parse_range(&mut s, &mut (*tm).tm_wday, 0, 7) {
                        return null_mut();
                    }
                }
                b'x' => {
                    s = strptime_inner(s, c"%m/%d/%y".as_ptr(), tm);
                    if s.is_null() {
                        return null_mut();
                    }
                }
                b'X' => {
                    s = strptime_inner(s, c"%H:%M:%S".as_ptr(), tm);
                    if s.is_null() {
                        return null_mut();
                    }
                }
                b'y' => {
                    want_century |= 1;
                    if !parse_digits(&mut s, &mut relyear, 2, false) {
                        return null_mut();
                    }
                }
                b'Y' => {
                    want_century = 0;
                    if !parse_digits(&mut s, &mut (*tm).tm_year, if w < 0 { 4 } else { w }, true) {
                        return null_mut();
                    }
                    (*tm).tm_year -= 1900;
                }
                b'z' => {
                    let neg = if *s == b'+' as c_char {
                        false
                    } else if *s == b'-' as c_char {
                        true
                    } else {
                        return null_mut();
                    };
                    for i in 1..5 {
                        if !b_isdigit(*s.add(i) as u8) {
                            return null_mut();
                        }
                    }
                    let d = |i: usize| (*s.add(i) as u8 - b'0') as c_long;
                    let mut off = d(1) * 36000 + d(2) * 3600 + d(3) * 600 + d(4) * 60;
                    if neg {
                        off = -off;
                    }
                    (*tm).tm_gmtoff = off;
                    s = s.add(5);
                }
                b'Z' => {
                    // musl `__tzname_to_isdst`: match tzname[0]/[1],
                    // else skip alpha. Ours are both "UTC".
                    let mut matched = false;
                    for zi in 0..2 {
                        let zp = *addr_of_mut!(tzname).cast::<*mut c_char>().add(zi);
                        if zp.is_null() {
                            continue;
                        }
                        let zl = c_strlen(zp);
                        let zs = core::slice::from_raw_parts(zp as *const u8, zl);
                        let mut ok = !zs.is_empty();
                        for (i, &b) in zs.iter().enumerate() {
                            if *s.add(i) == 0 || b_tolower(*s.add(i) as u8) != b_tolower(b) {
                                ok = false;
                                break;
                            }
                        }
                        if ok {
                            s = s.add(zl);
                            (*tm).tm_isdst = zi as c_int;
                            matched = true;
                            break;
                        }
                    }
                    if !matched {
                        while b_isalpha(*s as u8) {
                            s = s.add(1);
                        }
                    }
                }
                b'%' => {
                    if *s != b'%' as c_char {
                        return null_mut();
                    }
                    s = s.add(1);
                }
                _ => return null_mut(),
            }
        }
        if want_century != 0 {
            (*tm).tm_year = relyear;
            if want_century & 2 != 0 {
                (*tm).tm_year += century * 100 - 1900;
            } else if (*tm).tm_year <= 68 {
                (*tm).tm_year += 100;
            }
        }
        s
    }
}

/// musl `numeric_range`: greedy digits bounded by `min+range`
/// magnitude, then the range check, no `adj` (caller adjusts).
///
/// # Safety
///
/// `s` points into a NUL-terminated string; `dest` is writable.
#[cfg(target_arch = "x86_64")]
unsafe fn parse_range(s: &mut *mut c_char, dest: &mut c_int, min: c_int, range: c_int) -> bool {
    unsafe {
        if !b_isdigit(**s as u8) {
            return false;
        }
        let mut v: c_int = 0;
        let mut i: c_int = 1;
        while i <= min + range && b_isdigit(**s as u8) {
            v = v
                .saturating_mul(10)
                .saturating_add((**s as u8 - b'0') as c_int);
            *s = (*s).add(1);
            i = i.saturating_mul(10);
        }
        if (v - min) as u32 >= range as u32 {
            return false;
        }
        *dest = v;
        true
    }
}

/// musl `numeric_digits`: optional sign, up to `w` digits.
///
/// # Safety
///
/// `s` points into a NUL-terminated string; `dest` is writable.
#[cfg(target_arch = "x86_64")]
unsafe fn parse_digits(s: &mut *mut c_char, dest: &mut c_int, w: i64, signed: bool) -> bool {
    unsafe {
        let mut neg = false;
        if **s == b'+' as c_char {
            *s = (*s).add(1);
        } else if signed && **s == b'-' as c_char {
            neg = true;
            *s = (*s).add(1);
        } else if !signed && **s == b'-' as c_char {
            // Unsigned slots (%C/%y/%g): musl only skips '+'.
            return false;
        }
        if !b_isdigit(**s as u8) {
            return false;
        }
        let mut v: c_int = 0;
        let mut i: i64 = 0;
        while i < w && b_isdigit(**s as u8) {
            v = v
                .saturating_mul(10)
                .saturating_add((**s as u8 - b'0') as c_int);
            *s = (*s).add(1);
            i += 1;
        }
        *dest = if neg { v.saturating_neg() } else { v };
        true
    }
}

/// musl `strptime`.
///
/// # Safety
///
/// `s`/`format` point to NUL-terminated strings; `tm` to a writable
/// [`Tm`]. Returns the first unconsumed byte of `s`, or null.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn strptime(
    s: *const c_char,
    format: *const c_char,
    tm: *mut Tm,
) -> *mut c_char {
    unsafe {
        if s.is_null() || format.is_null() || tm.is_null() {
            return null_mut();
        }
        strptime_inner(s, format, tm)
    }
}

// ---- Tests ------------------------------------------------------------------
#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use core::ffi::c_char;
    use std::string::String;
    use std::vec::Vec;

    fn cstr(b: &[u8]) -> *const c_char {
        b.as_ptr().cast()
    }

    unsafe fn fmt_of(tm: &Tm, fmt: &[u8]) -> (String, usize) {
        unsafe {
            let mut buf = [0 as c_char; 128];
            let mut fz = [0u8; 128];
            fz[..fmt.len()].copy_from_slice(fmt);
            let n = strftime(buf.as_mut_ptr(), buf.len(), fz.as_ptr().cast(), tm);
            let mut v = Vec::new();
            let mut i = 0;
            while buf[i] != 0 {
                v.push(buf[i] as u8);
                i += 1;
            }
            (String::from_utf8(v).unwrap(), n)
        }
    }

    #[test]
    fn clock_gettime_monotonic_nondecreasing_and_realtime_sane() {
        unsafe {
            let mut a = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let mut b = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            assert_eq!(clock_gettime(CLOCK_MONOTONIC, &mut a), 0);
            assert_eq!(clock_gettime(CLOCK_MONOTONIC, &mut b), 0);
            assert!(b.tv_sec > a.tv_sec || (b.tv_sec == a.tv_sec && b.tv_nsec >= a.tv_nsec));
            let mut r = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            assert_eq!(clock_gettime(CLOCK_REALTIME, &mut r), 0);
            // Sane: after 2020-01-01 (1577836800), nsec in range.
            assert!(r.tv_sec > 1_577_836_800);
            assert!(r.tv_nsec >= 0 && r.tv_nsec < 1_000_000_000);
            // getres works, null ok.
            assert_eq!(clock_getres(CLOCK_REALTIME, &mut a), 0);
            assert_eq!(clock_getres(CLOCK_REALTIME, null_mut()), 0);
        }
    }

    #[test]
    fn gmtime_epoch_and_roundtrips() {
        unsafe {
            let t: time_t = 0;
            let mut tm = Tm {
                tm_sec: 0,
                tm_min: 0,
                tm_hour: 0,
                tm_mday: 0,
                tm_mon: 0,
                tm_year: 0,
                tm_wday: 0,
                tm_yday: 0,
                tm_isdst: 0,
                tm_gmtoff: 0,
                tm_zone: null(),
            };
            let p = gmtime_r(&t, &mut tm);
            assert!(!p.is_null());
            // Thu 1970-01-01 00:00:00 UTC.
            assert_eq!((tm.tm_year, tm.tm_mon, tm.tm_mday), (70, 0, 1));
            assert_eq!((tm.tm_hour, tm.tm_min, tm.tm_sec), (0, 0, 0));
            assert_eq!(tm.tm_wday, 4);
            assert_eq!(tm.tm_yday, 0);
            assert_eq!(tm.tm_isdst, 0);
            // Leap day 2000-02-29 roundtrip via timegm.
            let mut leap = Tm {
                tm_sec: 7,
                tm_min: 6,
                tm_hour: 5,
                tm_mday: 29,
                tm_mon: 1,
                tm_year: 100,
                tm_wday: 0,
                tm_yday: 0,
                tm_isdst: 0,
                tm_gmtoff: 0,
                tm_zone: null(),
            };
            let tt = timegm(&mut leap);
            assert_eq!(tt, 951_800_767);
            assert_eq!((leap.tm_wday, leap.tm_yday), (2, 59));
            // mktime agrees (UTC) and normalizes.
            let mut mk = Tm {
                tm_sec: 7,
                tm_min: 6,
                tm_hour: 5,
                tm_mday: 29,
                tm_mon: 1,
                tm_year: 100,
                tm_wday: 0,
                tm_yday: 0,
                tm_isdst: 0,
                tm_gmtoff: 0,
                tm_zone: null(),
            };
            assert_eq!(mktime(&mut mk), 951_800_767);
            assert_eq!(
                (mk.tm_wday, mk.tm_yday, mk.tm_mon, mk.tm_mday),
                (2, 59, 1, 29)
            );
            // localtime == gmtime under UTC.
            let mut lt = core::mem::zeroed::<Tm>();
            assert!(!localtime_r(&t, &mut lt).is_null());
            assert_eq!(
                (lt.tm_year, lt.tm_mon, lt.tm_mday, lt.tm_wday),
                (70, 0, 1, 4)
            );
            // time() agrees with clock_gettime.
            let mut ts = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            clock_gettime(CLOCK_REALTIME, &mut ts);
            let mut now: time_t = 0;
            assert!((time(&mut now) - ts.tv_sec).abs() <= 1);
        }
    }

    #[test]
    fn strftime_strptime_roundtrip() {
        unsafe {
            let tm = Tm {
                tm_sec: 7,
                tm_min: 6,
                tm_hour: 5,
                tm_mday: 29,
                tm_mon: 1,
                tm_year: 100,
                tm_wday: 2,
                tm_yday: 59,
                tm_isdst: 0,
                tm_gmtoff: 0,
                tm_zone: cstr(b"UTC\0"),
            };
            let (s, n) = fmt_of(&tm, b"%Y-%m-%d");
            assert_eq!((s.as_str(), n), ("2000-02-29", 10));
            let (s, _) = fmt_of(
                &tm,
                b"%a %A %b %B %H:%M:%S %p %j %U %w %u %C %y %Y %z %Z %%",
            );
            assert_eq!(
                s.as_str(),
                "Tue Tuesday Feb February 05:06:07 AM 060 09 2 2 20 00 2000 +0000 UTC %"
            );
            // strptime parses "%Y-%m-%d" back.
            let mut out: Tm = core::mem::zeroed();
            let src = b"2000-02-29\0";
            let fmt = b"%Y-%m-%d\0";
            let end = strptime(cstr(src), cstr(fmt), &mut out);
            assert!(!end.is_null());
            assert_eq!(end as usize - src.as_ptr() as usize, 10);
            assert_eq!((out.tm_year, out.tm_mon, out.tm_mday), (100, 1, 29));
            // Mismatch returns null.
            let bad = b"not-a-date\0";
            assert!(strptime(cstr(bad), cstr(fmt), &mut out).is_null());
        }
    }

    #[test]
    fn asctime_ctime_difftime_gettimeofday() {
        unsafe {
            let tm = Tm {
                tm_sec: 7,
                tm_min: 6,
                tm_hour: 5,
                tm_mday: 29,
                tm_mon: 1,
                tm_year: 100,
                tm_wday: 2,
                tm_yday: 59,
                tm_isdst: 0,
                tm_gmtoff: 0,
                tm_zone: cstr(b"UTC\0"),
            };
            let mut buf = [0 as c_char; 26];
            assert!(!asctime_r(&tm, buf.as_mut_ptr()).is_null());
            let s: Vec<u8> = buf
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8)
                .collect();
            assert_eq!(s.as_slice(), b"Tue Feb 29 05:06:07 2000\n");
            // ctime(0) exact.
            let t: time_t = 0;
            let mut cbuf = [0 as c_char; 26];
            assert!(!ctime_r(&t, cbuf.as_mut_ptr()).is_null());
            let s: Vec<u8> = cbuf
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8)
                .collect();
            assert_eq!(s.as_slice(), b"Thu Jan  1 00:00:00 1970\n");
            assert_eq!(difftime(200, 150), 50.0);
            let mut tv = Timeval {
                tv_sec: 0,
                tv_usec: 0,
            };
            assert_eq!(gettimeofday(&mut tv, null_mut()), 0);
            assert!(tv.tv_sec > 1_577_836_800);
            assert_eq!(gettimeofday(null_mut(), null_mut()), 0);
            tzset();
            assert_eq!(core::ptr::addr_of!(daylight).read(), 0);
            assert_eq!(core::ptr::addr_of!(timezone).read(), 0);
        }
    }

    #[test]
    fn sleeps_are_short_and_report_eintr_path() {
        unsafe {
            let req = Timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000,
            };
            assert_eq!(nanosleep(&req, null_mut()), 0);
            assert_eq!(clock_nanosleep(CLOCK_MONOTONIC, 0, &req, null_mut()), 0);
            // TIMER_ABSTIME with a past time returns immediately.
            let mut now = Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            clock_gettime(CLOCK_MONOTONIC, &mut now);
            assert_eq!(
                clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &now, null_mut()),
                0
            );
            // Bad clock rejected like musl.
            assert_eq!(
                clock_nanosleep(CLOCK_THREAD_CPUTIME_ID, 0, &req, null_mut()),
                EINVAL
            );
        }
    }
}
