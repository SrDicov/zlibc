//! C-LOCALE-ONLY locale surface (musl `src/locale/*`, reimplemented).
//!
//! C-LOCALE-ONLY SCOPE, READ FIRST: no locale data tables exist in this
//! crate (own wave), so every category stays "C", always:
//! - `setlocale` accepts only `"C"` and `""` (env means C here) and returns
//!   a static `"C"`; any other name is NULL. Real musl instead accepts every
//!   name (stub map keeps the name, contents stay C), honors `POSIX` and
//!   `C.UTF-8` builtins, and parses `;`-joined `LC_ALL` composites — all of
//!   that is OUT until locale data lands.
//! - `newlocale` never allocates: its result is always all-C, so it returns
//!   the static C locale (or `base` unchanged when `base` is heap-owned /
//!   mask selects nothing, exactly like musl's in-place/builtin shortcuts).
//!   A NULL `name` returns NULL (musl dereferences it and segfaults); `base`
//!   is never dereferenced.
//! - `duplocale` hands out slots from a fixed 32-slot static pool (musl:
//!   `malloc`; NULL input returns NULL instead of musl's segfault).
//!   `freelocale` releases pool slots and ignores everything else.
//! - `uselocale` keeps the current locale in a process-global `AtomicPtr`
//!   (documented gap: per-thread locale arrives with the TSD wave;
//!   single-threaded behavior is identical to musl).
//! - `nl_langinfo(CODESET)` returns `"ANSI_X3.4-1968"` per the spec pinned
//!   for this wave; note the real musl `langinfo.c:35` returns `"ASCII"`
//!   for the C locale (`cat[LC_CTYPE]` NULL) and `"UTF-8"` for C.UTF-8.
//!   Every other item mirrors musl's C tables exactly.
//!
//! `LC_*`, `Lconv`, and `localeconv` keep their existing shape/behavior.

use core::ffi::{c_char, c_int, c_void};
use core::mem::size_of;
use core::ptr::{addr_of, null_mut};
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

/// musl `include/locale.h:18-24` categories.
pub const LC_CTYPE: c_int = 0;
pub const LC_NUMERIC: c_int = 1;
pub const LC_TIME: c_int = 2;
pub const LC_COLLATE: c_int = 3;
pub const LC_MONETARY: c_int = 4;
pub const LC_MESSAGES: c_int = 5;
pub const LC_ALL: c_int = 6;

/// musl `include/locale.h:68-74` category mask bits.
pub const LC_CTYPE_MASK: c_int = 1 << LC_CTYPE;
pub const LC_NUMERIC_MASK: c_int = 1 << LC_NUMERIC;
pub const LC_TIME_MASK: c_int = 1 << LC_TIME;
pub const LC_COLLATE_MASK: c_int = 1 << LC_COLLATE;
pub const LC_MONETARY_MASK: c_int = 1 << LC_MONETARY;
pub const LC_MESSAGES_MASK: c_int = 1 << LC_MESSAGES;
pub const LC_ALL_MASK: c_int = 0x7fff_ffff;

/// musl `include/langinfo.h` `nl_item` values (verified against the header).
#[allow(non_camel_case_types)]
pub type nl_item = c_int;
pub const ABDAY_1: c_int = 0x20000;
pub const ABDAY_2: c_int = 0x20001;
pub const ABDAY_3: c_int = 0x20002;
pub const ABDAY_4: c_int = 0x20003;
pub const ABDAY_5: c_int = 0x20004;
pub const ABDAY_6: c_int = 0x20005;
pub const ABDAY_7: c_int = 0x20006;
pub const DAY_1: c_int = 0x20007;
pub const DAY_2: c_int = 0x20008;
pub const DAY_3: c_int = 0x20009;
pub const DAY_4: c_int = 0x2000a;
pub const DAY_5: c_int = 0x2000b;
pub const DAY_6: c_int = 0x2000c;
pub const DAY_7: c_int = 0x2000d;
pub const ABMON_1: c_int = 0x2000e;
pub const ABMON_2: c_int = 0x2000f;
pub const ABMON_3: c_int = 0x20010;
pub const ABMON_4: c_int = 0x20011;
pub const ABMON_5: c_int = 0x20012;
pub const ABMON_6: c_int = 0x20013;
pub const ABMON_7: c_int = 0x20014;
pub const ABMON_8: c_int = 0x20015;
pub const ABMON_9: c_int = 0x20016;
pub const ABMON_10: c_int = 0x20017;
pub const ABMON_11: c_int = 0x20018;
pub const ABMON_12: c_int = 0x20019;
pub const MON_1: c_int = 0x2001a;
pub const MON_2: c_int = 0x2001b;
pub const MON_3: c_int = 0x2001c;
pub const MON_4: c_int = 0x2001d;
pub const MON_5: c_int = 0x2001e;
pub const MON_6: c_int = 0x2001f;
pub const MON_7: c_int = 0x20020;
pub const MON_8: c_int = 0x20021;
pub const MON_9: c_int = 0x20022;
pub const MON_10: c_int = 0x20023;
pub const MON_11: c_int = 0x20024;
pub const MON_12: c_int = 0x20025;
pub const AM_STR: c_int = 0x20026;
pub const PM_STR: c_int = 0x20027;
pub const D_T_FMT: c_int = 0x20028;
pub const D_FMT: c_int = 0x20029;
pub const T_FMT: c_int = 0x2002a;
pub const T_FMT_AMPM: c_int = 0x2002b;
pub const ERA: c_int = 0x2002c;
pub const ERA_D_FMT: c_int = 0x2002e;
pub const ALT_DIGITS: c_int = 0x2002f;
pub const ERA_D_T_FMT: c_int = 0x20030;
pub const ERA_T_FMT: c_int = 0x20031;
pub const CODESET: c_int = 14;
pub const CRNCYSTR: c_int = 0x4000f;
pub const RADIXCHAR: c_int = 0x10000;
pub const THOUSEP: c_int = 0x10001;
pub const YESEXPR: c_int = 0x50000;
pub const NOEXPR: c_int = 0x50001;
pub const YESSTR: c_int = 0x50002;
pub const NOSTR: c_int = 0x50003;

/// musl `struct __locale_struct` (`src/internal/libc.h:10-12`): six
/// category-map pointers; the C locale is all-NULL, like `__c_locale`.
/// Opaque to callers: handles travel as `locale_t`, never by value.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Locale {
    cat: [*const c_void; 6],
}
// SAFETY: `cat` entries are never mutated or dereferenced by this crate —
// every locale is all-NULL (C) and pool slots are written only by the
// atomic bitmap, never through the pointers — so sharing is data-race-free.
unsafe impl Sync for Locale {}

/// musl `locale_t` (`include/alltypes.h.in:75`): pointer to the struct.
#[allow(non_camel_case_types)]
pub type locale_t = *mut Locale;

/// musl `LC_GLOBAL_LOCALE` (`include/locale.h:66`): `(locale_t)-1`.
pub const LC_GLOBAL_LOCALE: locale_t = !0usize as locale_t;

const CAT_BITS: c_int = 0x3f;

/// The C locale handed out by `newlocale` (musl's `C_LOCALE`). Kept distinct
/// from `GLOBAL_LOCALE` so `uselocale` can tell "this exact C object" apart
/// from "the global locale", exactly like musl's `C_LOCALE` vs
/// `&libc.global_locale`.
static C_LOCALE_OBJ: Locale = Locale {
    cat: [core::ptr::null(); 6],
};
/// Process-global locale (musl's `libc.global_locale`); all-C.
static GLOBAL_LOCALE: Locale = Locale {
    cat: [core::ptr::null(); 6],
};
/// musl `CURRENT_LOCALE` is per-thread; WITHOUT TSD this is process-global
/// (per-thread locale arrives with the TSD wave). Starts at the global
/// locale, so querying before any `uselocale` yields `LC_GLOBAL_LOCALE`,
/// like musl's freshly-created thread.
static CURRENT_LOCALE: AtomicPtr<Locale> = AtomicPtr::new(addr_of!(GLOBAL_LOCALE) as *mut Locale);

// ponytail: fixed 32-slot pool instead of malloc — every locale here is
// all-C, so slots are pre-zeroed statics and alloc/free only flip bitmap
// bits; grow the pool (widen the AtomicU32) if NULLs appear under load.
const POOL_CAP: usize = 32;
static POOL: [Locale; POOL_CAP] = [Locale {
    cat: [core::ptr::null(); 6],
}; POOL_CAP];
static POOL_USED: AtomicU32 = AtomicU32::new(0);

fn c_locale() -> locale_t {
    addr_of!(C_LOCALE_OBJ) as locale_t
}

fn global_locale() -> locale_t {
    addr_of!(GLOBAL_LOCALE) as locale_t
}

/// Only `"C"` and `""` (env, which means C here) name the C locale.
fn valid_name(bytes: &[u8]) -> bool {
    bytes == b"C" || bytes.is_empty()
}

fn c_len(p: *const c_char) -> usize {
    let mut n = 0usize;
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
    }
    n
}

/// musl's `__loc_is_allocated`: true only for our own pool slots in use.
fn pool_index(loc: locale_t) -> Option<u32> {
    let base = addr_of!(POOL) as usize;
    let off = (loc as usize).wrapping_sub(base);
    if !off.is_multiple_of(size_of::<Locale>()) || off / size_of::<Locale>() >= POOL_CAP {
        return None;
    }
    Some((off / size_of::<Locale>()) as u32)
}

fn pool_alloc() -> locale_t {
    let mut used = POOL_USED.load(Ordering::Acquire);
    loop {
        let free = !used;
        if free == 0 {
            return null_mut();
        }
        let i = free.trailing_zeros();
        if i as usize >= POOL_CAP {
            return null_mut();
        }
        match POOL_USED.compare_exchange_weak(
            used,
            used | (1u32 << i),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return &POOL[i as usize] as *const Locale as locale_t,
            Err(v) => used = v,
        }
    }
}

fn pool_free(loc: locale_t) {
    if let Some(i) = pool_index(loc) {
        POOL_USED.fetch_and(!(1u32 << i), Ordering::Release);
    }
}

static C_NAME: [u8; 2] = [b'C', 0];

/// Select/query the C locale (musl `setlocale`, C-only contract: the name
/// must be `"C"`/`""`, else NULL; bad category is NULL).
///
/// # Safety
///
/// `name` must be null (query) or a valid NUL-terminated string. The
/// returned pointer is a static `"C"` valid forever.
#[no_mangle]
pub unsafe extern "C" fn setlocale(cat: c_int, name: *const c_char) -> *mut c_char {
    if !(0..=LC_ALL).contains(&cat) {
        return null_mut();
    }
    if name.is_null() {
        return addr_of!(C_NAME) as *mut c_char;
    }
    let bytes = unsafe { core::slice::from_raw_parts(name as *const u8, c_len(name)) };
    if valid_name(bytes) {
        addr_of!(C_NAME) as *mut c_char
    } else {
        null_mut()
    }
}

/// Build/adjust a locale (musl `newlocale`, C-only: the result is always
/// all-C, so no allocation ever happens).
///
/// Mask bit `1<<i` rebuilds category `i` from `name`; unset bits copy
/// `base` (or stay C for a null `base`) — hence mask-with-nothing-selected
/// returns `base` itself, like musl's in-place/builtin shortcuts.
///
/// # Safety
///
/// `name` must be a valid NUL-terminated string (null is a hard NULL, not
/// musl's segfault). `base` must be null or from `newlocale`/`duplocale`;
/// anything else is treated as C and never dereferenced.
#[no_mangle]
pub unsafe extern "C" fn newlocale(mask: c_int, name: *const c_char, base: locale_t) -> locale_t {
    if name.is_null() {
        return null_mut();
    }
    let bytes = unsafe { core::slice::from_raw_parts(name as *const u8, c_len(name)) };
    if !valid_name(bytes) {
        return null_mut();
    }
    if mask & CAT_BITS == 0 {
        return if base.is_null() { c_locale() } else { base };
    }
    if pool_index(base).is_some_and(|i| POOL_USED.load(Ordering::Acquire) & (1u32 << i) != 0) {
        base
    } else {
        c_locale()
    }
}

/// Copy a locale (musl `duplocale`: always a fresh object; `LC_GLOBAL_LOCALE`
/// copies the global C locale; null input is NULL, not musl's segfault).
///
/// # Safety
///
/// `old` must be null, `LC_GLOBAL_LOCALE`, or from `newlocale`/`duplocale`;
/// anything else still yields an independent C locale and is never
/// dereferenced. Returns NULL when the pool is exhausted.
#[no_mangle]
pub unsafe extern "C" fn duplocale(old: locale_t) -> locale_t {
    if old.is_null() {
        return null_mut();
    }
    pool_alloc()
}

/// Release a locale (musl `freelocale`: frees heap-owned locales, ignores
/// builtins, the global locale, and null).
///
/// # Safety
///
/// Any pointer is safe to pass; only live pool slots are affected.
#[no_mangle]
pub unsafe extern "C" fn freelocale(loc: locale_t) {
    pool_free(loc);
}

/// Switch/query the current locale (musl `uselocale`: null queries;
/// `LC_GLOBAL_LOCALE` selects/returns the global locale).
///
/// # Safety
///
/// `new`, when non-null and not `LC_GLOBAL_LOCALE`, must be from
/// `newlocale`/`duplocale` and stay alive until replaced; it is stored, not
/// dereferenced. Process-global until the TSD wave (see module docs).
#[no_mangle]
pub unsafe extern "C" fn uselocale(new: locale_t) -> locale_t {
    let old = CURRENT_LOCALE.load(Ordering::Acquire);
    if !new.is_null() {
        let eff = if new == LC_GLOBAL_LOCALE {
            global_locale()
        } else {
            new
        };
        CURRENT_LOCALE.store(eff, Ordering::Release);
    }
    if old == global_locale() {
        LC_GLOBAL_LOCALE
    } else {
        old
    }
}

/// musl `struct lconv` (`include/locale.h:26-52`): ten string slots then
/// `char` fields. Only `decimal_point` differs from empty/`CHAR_MAX` in the
/// C locale. (Kept as-is from the D4 stubs, incl. the 12-field tail.)
#[repr(C)]
pub struct Lconv {
    pub decimal_point: *mut c_char,
    pub thousands_sep: *mut c_char,
    pub grouping: *mut c_char,
    pub int_curr_symbol: *mut c_char,
    pub currency_symbol: *mut c_char,
    pub mon_decimal_point: *mut c_char,
    pub mon_thousands_sep: *mut c_char,
    pub mon_grouping: *mut c_char,
    pub positive_sign: *mut c_char,
    pub negative_sign: *mut c_char,
    pub int_frac_digits: c_char,
    pub frac_digits: c_char,
    pub p_cs_precedes: c_char,
    pub p_sep_by_space: c_char,
    pub n_cs_precedes: c_char,
    pub n_sep_by_space: c_char,
    pub p_sign_posn: c_char,
    pub n_sign_posn: c_char,
    pub int_p_cs_precedes: c_char,
    pub int_p_sep_by_space: c_char,
    pub int_n_cs_precedes: c_char,
    pub int_n_sep_by_space: c_char,
}

static mut DOT: [u8; 2] = [b'.', 0];
static mut EMPTY: [u8; 1] = [0];
static mut POSIX_LCONV: Lconv = Lconv {
    decimal_point: core::ptr::addr_of_mut!(DOT) as *mut c_char,
    thousands_sep: core::ptr::addr_of_mut!(EMPTY) as *mut c_char,
    grouping: core::ptr::addr_of_mut!(EMPTY) as *mut c_char,
    int_curr_symbol: core::ptr::addr_of_mut!(EMPTY) as *mut c_char,
    currency_symbol: core::ptr::addr_of_mut!(EMPTY) as *mut c_char,
    mon_decimal_point: core::ptr::addr_of_mut!(EMPTY) as *mut c_char,
    mon_thousands_sep: core::ptr::addr_of_mut!(EMPTY) as *mut c_char,
    mon_grouping: core::ptr::addr_of_mut!(EMPTY) as *mut c_char,
    positive_sign: core::ptr::addr_of_mut!(EMPTY) as *mut c_char,
    negative_sign: core::ptr::addr_of_mut!(EMPTY) as *mut c_char,
    int_frac_digits: 127,
    frac_digits: 127,
    p_cs_precedes: 127,
    p_sep_by_space: 127,
    n_cs_precedes: 127,
    n_sep_by_space: 127,
    p_sign_posn: 127,
    n_sign_posn: 127,
    int_p_cs_precedes: 127,
    int_p_sep_by_space: 127,
    int_n_cs_precedes: 127,
    int_n_sep_by_space: 127,
};

/// Numeric formatting conventions for the C locale (musl `localeconv`).
///
/// # Safety
///
/// The returned pointer stays valid forever (static storage); the
/// pointee must only be read, never written.
#[no_mangle]
pub unsafe extern "C" fn localeconv() -> *mut Lconv {
    core::ptr::addr_of_mut!(POSIX_LCONV)
}

/// `LC_TIME` C strings by `nl_item` low 16 bits (musl `langinfo.c` `c_time`
/// order: abbrev days, full days, abbrev months, full months, AM/PM,
/// formats; `ERA`/`idx 0x2d` are `""`).
fn time_str(idx: c_int) -> *mut c_char {
    match idx {
        0 => c"Sun".as_ptr() as *mut c_char,
        1 => c"Mon".as_ptr() as *mut c_char,
        2 => c"Tue".as_ptr() as *mut c_char,
        3 => c"Wed".as_ptr() as *mut c_char,
        4 => c"Thu".as_ptr() as *mut c_char,
        5 => c"Fri".as_ptr() as *mut c_char,
        6 => c"Sat".as_ptr() as *mut c_char,
        7 => c"Sunday".as_ptr() as *mut c_char,
        8 => c"Monday".as_ptr() as *mut c_char,
        9 => c"Tuesday".as_ptr() as *mut c_char,
        10 => c"Wednesday".as_ptr() as *mut c_char,
        11 => c"Thursday".as_ptr() as *mut c_char,
        12 => c"Friday".as_ptr() as *mut c_char,
        13 => c"Saturday".as_ptr() as *mut c_char,
        14 => c"Jan".as_ptr() as *mut c_char,
        15 => c"Feb".as_ptr() as *mut c_char,
        16 => c"Mar".as_ptr() as *mut c_char,
        17 => c"Apr".as_ptr() as *mut c_char,
        18 => c"May".as_ptr() as *mut c_char,
        19 => c"Jun".as_ptr() as *mut c_char,
        20 => c"Jul".as_ptr() as *mut c_char,
        21 => c"Aug".as_ptr() as *mut c_char,
        22 => c"Sep".as_ptr() as *mut c_char,
        23 => c"Oct".as_ptr() as *mut c_char,
        24 => c"Nov".as_ptr() as *mut c_char,
        25 => c"Dec".as_ptr() as *mut c_char,
        26 => c"January".as_ptr() as *mut c_char,
        27 => c"February".as_ptr() as *mut c_char,
        28 => c"March".as_ptr() as *mut c_char,
        29 => c"April".as_ptr() as *mut c_char,
        30 => c"May".as_ptr() as *mut c_char,
        31 => c"June".as_ptr() as *mut c_char,
        32 => c"July".as_ptr() as *mut c_char,
        33 => c"August".as_ptr() as *mut c_char,
        34 => c"September".as_ptr() as *mut c_char,
        35 => c"October".as_ptr() as *mut c_char,
        36 => c"November".as_ptr() as *mut c_char,
        37 => c"December".as_ptr() as *mut c_char,
        38 => c"AM".as_ptr() as *mut c_char,
        39 => c"PM".as_ptr() as *mut c_char,
        40 => c"%a %b %e %T %Y".as_ptr() as *mut c_char,
        41 => c"%m/%d/%y".as_ptr() as *mut c_char,
        42 => c"%H:%M:%S".as_ptr() as *mut c_char,
        43 => c"%I:%M:%S %p".as_ptr() as *mut c_char,
        46 => c"%m/%d/%y".as_ptr() as *mut c_char,
        47 => c"0123456789".as_ptr() as *mut c_char,
        48 => c"%a %b %e %T %Y".as_ptr() as *mut c_char,
        49 => c"%H:%M:%S".as_ptr() as *mut c_char,
        _ => c"".as_ptr() as *mut c_char,
    }
}

/// Language/cultural data for the C locale (musl `nl_langinfo`: unhandled
/// items yield `""`; `CODESET` is pinned to `"ANSI_X3.4-1968"` per spec —
/// real musl answers `"ASCII"` here, see module docs).
///
/// # Safety
///
/// The returned pointer stays valid forever (static storage); the pointee
/// must only be read, never written.
#[no_mangle]
pub unsafe extern "C" fn nl_langinfo(item: nl_item) -> *mut c_char {
    if item == CODESET {
        return c"ANSI_X3.4-1968".as_ptr() as *mut c_char;
    }
    let cat = item >> 16;
    let idx = item & 0xffff;
    // musl `_NL_LOCALE_NAME(cat)` extension: every category is C here.
    if idx == 0xffff && cat < LC_ALL {
        return c"C".as_ptr() as *mut c_char;
    }
    match cat {
        LC_NUMERIC => match idx {
            0 => c".".as_ptr() as *mut c_char,
            _ => c"".as_ptr() as *mut c_char,
        },
        LC_TIME => {
            if idx > 0x31 {
                c"".as_ptr() as *mut c_char
            } else {
                time_str(idx)
            }
        }
        LC_MONETARY => c"".as_ptr() as *mut c_char,
        LC_MESSAGES => match idx {
            0 => c"^[yY]".as_ptr() as *mut c_char,
            1 => c"^[nN]".as_ptr() as *mut c_char,
            2 => c"yes".as_ptr() as *mut c_char,
            3 => c"no".as_ptr() as *mut c_char,
            _ => c"".as_ptr() as *mut c_char,
        },
        _ => c"".as_ptr() as *mut c_char,
    }
}

#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn isalnum_l(c: c_int, _loc: locale_t) -> c_int {
    unsafe { crate::ctype::isalnum(c) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn isalpha_l(c: c_int, _loc: locale_t) -> c_int {
    unsafe { crate::ctype::isalpha(c) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn isblank_l(c: c_int, _loc: locale_t) -> c_int {
    unsafe { crate::ctype::isblank(c) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn iscntrl_l(c: c_int, _loc: locale_t) -> c_int {
    unsafe { crate::ctype::iscntrl(c) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn isdigit_l(c: c_int, _loc: locale_t) -> c_int {
    unsafe { crate::ctype::isdigit(c) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn isgraph_l(c: c_int, _loc: locale_t) -> c_int {
    unsafe { crate::ctype::isgraph(c) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn islower_l(c: c_int, _loc: locale_t) -> c_int {
    unsafe { crate::ctype::islower(c) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn isprint_l(c: c_int, _loc: locale_t) -> c_int {
    unsafe { crate::ctype::isprint(c) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn ispunct_l(c: c_int, _loc: locale_t) -> c_int {
    unsafe { crate::ctype::ispunct(c) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn isspace_l(c: c_int, _loc: locale_t) -> c_int {
    unsafe { crate::ctype::isspace(c) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn isupper_l(c: c_int, _loc: locale_t) -> c_int {
    unsafe { crate::ctype::isupper(c) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn isxdigit_l(c: c_int, _loc: locale_t) -> c_int {
    unsafe { crate::ctype::isxdigit(c) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn tolower_l(c: c_int, _loc: locale_t) -> c_int {
    unsafe { crate::ctype::tolower(c) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn toupper_l(c: c_int, _loc: locale_t) -> c_int {
    unsafe { crate::ctype::toupper(c) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn iswalnum_l(wc: u32, _loc: locale_t) -> c_int {
    unsafe { crate::wide::iswalnum(wc) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn iswalpha_l(wc: u32, _loc: locale_t) -> c_int {
    unsafe { crate::wide::iswalpha(wc) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn iswblank_l(wc: u32, _loc: locale_t) -> c_int {
    unsafe { crate::wide::iswblank(wc) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn iswcntrl_l(wc: u32, _loc: locale_t) -> c_int {
    unsafe { crate::wide::iswcntrl(wc) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn iswdigit_l(wc: u32, _loc: locale_t) -> c_int {
    unsafe { crate::wide::iswdigit(wc) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn iswgraph_l(wc: u32, _loc: locale_t) -> c_int {
    unsafe { crate::wide::iswgraph(wc) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn iswlower_l(wc: u32, _loc: locale_t) -> c_int {
    unsafe { crate::wide::iswlower(wc) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn iswprint_l(wc: u32, _loc: locale_t) -> c_int {
    unsafe { crate::wide::iswprint(wc) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn iswpunct_l(wc: u32, _loc: locale_t) -> c_int {
    unsafe { crate::wide::iswpunct(wc) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn iswspace_l(wc: u32, _loc: locale_t) -> c_int {
    unsafe { crate::wide::iswspace(wc) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn iswupper_l(wc: u32, _loc: locale_t) -> c_int {
    unsafe { crate::wide::iswupper(wc) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn iswxdigit_l(wc: u32, _loc: locale_t) -> c_int {
    unsafe { crate::wide::iswxdigit(wc) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn towlower_l(wc: u32, _loc: locale_t) -> u32 {
    unsafe { crate::wide::towlower(wc) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn towupper_l(wc: u32, _loc: locale_t) -> u32 {
    unsafe { crate::wide::towupper(wc) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn iswctype_l(wc: u32, t: usize, _loc: locale_t) -> c_int {
    unsafe { crate::wide::iswctype(wc, t) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn towctrans_l(wc: u32, t: usize, _loc: locale_t) -> u32 {
    unsafe { crate::wide::towctrans(wc, t) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn wctype_l(s: *const c_char, _loc: locale_t) -> usize {
    unsafe { crate::wide::wctype(s) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn wctrans_l(s: *const c_char, _loc: locale_t) -> usize {
    unsafe { crate::wide::wctrans(s) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn strcasecmp_l(l: *const c_char, r: *const c_char, _loc: locale_t) -> c_int {
    unsafe { crate::string::strcasecmp(l, r) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn strncasecmp_l(
    l: *const c_char,
    r: *const c_char,
    n: usize,
    _loc: locale_t,
) -> c_int {
    unsafe { crate::string::strncasecmp(l, r, n) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn strcoll_l(_l: *const c_char, _r: *const c_char, _loc: locale_t) -> c_int {
    0
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn strxfrm_l(
    d: *mut c_char,
    s: *const c_char,
    n: usize,
    _loc: locale_t,
) -> usize {
    unsafe { crate::string::strxfrm(d, s, n) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn strerror_l(e: c_int, _loc: locale_t) -> *mut c_char {
    unsafe { crate::string::strerror(e) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn nl_langinfo_l(item: nl_item, _loc: locale_t) -> *mut c_char {
    unsafe { nl_langinfo(item) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn strtod_l(s: *const c_char, e: *mut *mut c_char, _loc: locale_t) -> f64 {
    unsafe { crate::stdlib::strtod(s, e) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn strtof_l(s: *const c_char, e: *mut *mut c_char, _loc: locale_t) -> f32 {
    unsafe { crate::stdlib::strtof(s, e) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn strtold_l(s: *const c_char, e: *mut *mut c_char, _loc: locale_t) -> f64 {
    unsafe { crate::stdlib::strtod(s, e) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn wcscoll_l(l: *const i32, r: *const i32, _loc: locale_t) -> c_int {
    unsafe { crate::wide::wcscmp(l, r) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn wcsxfrm_l(_d: *mut i32, s: *const i32, n: usize, _loc: locale_t) -> usize {
    unsafe { crate::wide::wcslen(s).min(n) }
}
#[cfg(target_arch = "x86_64")]
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn wcsftime_l(
    s: *mut i32,
    n: usize,
    fmt: *const i32,
    tm: *const crate::time::Tm,
    _loc: locale_t,
) -> usize {
    // musl's wcsftime_l delegates to strftime then widens; minimal
    // version: 0 (musl's C locale formats via strftime_l too).
    let _ = (s, n, fmt, tm);
    0
}
#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::null;

    unsafe fn to_str(p: *const c_char) -> &'static str {
        unsafe {
            let mut n = 0usize;
            while *p.add(n) != 0 {
                n += 1;
            }
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(p as *const u8, n))
        }
    }

    #[test]
    fn setlocale_c_only_contract() {
        unsafe {
            // Queries and valid sets always read "C", every category.
            assert_eq!(to_str(setlocale(LC_ALL, null())), "C");
            assert_eq!(to_str(setlocale(LC_CTYPE, null())), "C");
            assert_eq!(to_str(setlocale(LC_ALL, c"C".as_ptr())), "C");
            assert_eq!(to_str(setlocale(LC_NUMERIC, c"".as_ptr())), "C");
            // Anything else is NULL: foreign names, musl builtins outside
            // this wave's scope, and ';'-joined LC_ALL composites.
            assert!(setlocale(LC_CTYPE, c"de_DE.UTF-8".as_ptr()).is_null());
            assert!(setlocale(LC_ALL, c"C.UTF-8".as_ptr()).is_null());
            assert!(setlocale(LC_ALL, c"POSIX".as_ptr()).is_null());
            assert!(setlocale(LC_ALL, c"C;C;C;C;C;C".as_ptr()).is_null());
            assert!(setlocale(99, null()).is_null());
            assert!(setlocale(-2, null()).is_null());
        }
    }

    #[test]
    fn localeconv_is_plain_c() {
        unsafe {
            let l = localeconv();
            assert!(!l.is_null());
            assert_eq!(to_str((*l).decimal_point), ".");
            assert_eq!(to_str((*l).thousands_sep), "");
            assert_eq!((*l).frac_digits, 127);
            assert_eq!((*l).p_sign_posn, 127);
        }
    }

    #[test]
    fn newlocale_mask_roundtrip() {
        unsafe {
            let l = newlocale(LC_ALL_MASK, c"C".as_ptr(), null_mut());
            assert!(!l.is_null());
            // Same C contents through a single-category mask.
            assert_eq!(newlocale(LC_NUMERIC_MASK, c"C".as_ptr(), null_mut()), l);
            // Empty mask keeps base as-is; empty mask + null base is C.
            assert_eq!(newlocale(0, c"C".as_ptr(), l), l);
            assert!(!newlocale(0, c"C".as_ptr(), null_mut()).is_null());
            // Bad names and null names fail, never crash.
            assert!(newlocale(LC_ALL_MASK, c"de_DE".as_ptr(), null_mut()).is_null());
            assert!(newlocale(LC_ALL_MASK, null(), null_mut()).is_null());
        }
    }

    #[test]
    fn duplocale_independence() {
        unsafe {
            let l = newlocale(LC_ALL_MASK, c"C".as_ptr(), null_mut());
            let d1 = duplocale(l);
            let d2 = duplocale(l);
            assert!(!d1.is_null() && !d2.is_null());
            assert_ne!(d1, d2);
            assert_ne!(d1, l);
            // Freeing one leaves the other and builtins usable.
            freelocale(d1);
            assert!(!duplocale(d2).is_null());
            freelocale(d2);
            freelocale(null_mut());
            freelocale(l); // builtin: ignored, pool untouched
            assert!(!duplocale(l).is_null());
        }
    }

    #[test]
    fn uselocale_set_get_restore() {
        unsafe {
            assert_eq!(uselocale(null_mut()), LC_GLOBAL_LOCALE);
            let d = duplocale(newlocale(LC_ALL_MASK, c"C".as_ptr(), null_mut()));
            assert_eq!(uselocale(d), LC_GLOBAL_LOCALE);
            assert_eq!(uselocale(null_mut()), d);
            assert_eq!(uselocale(LC_GLOBAL_LOCALE), d);
            assert_eq!(uselocale(null_mut()), LC_GLOBAL_LOCALE);
            freelocale(d);
        }
    }

    #[test]
    fn nl_langinfo_c_tables() {
        unsafe {
            assert_eq!(to_str(nl_langinfo(CODESET)), "ANSI_X3.4-1968");
            assert_eq!(to_str(nl_langinfo(RADIXCHAR)), ".");
            assert_eq!(to_str(nl_langinfo(THOUSEP)), "");
            assert_eq!(to_str(nl_langinfo(ABDAY_1)), "Sun");
            assert_eq!(to_str(nl_langinfo(DAY_1)), "Sunday");
            assert_eq!(to_str(nl_langinfo(ABMON_1)), "Jan");
            assert_eq!(to_str(nl_langinfo(MON_1)), "January");
            assert_eq!(to_str(nl_langinfo(AM_STR)), "AM");
            assert_eq!(to_str(nl_langinfo(PM_STR)), "PM");
            assert_eq!(to_str(nl_langinfo(D_T_FMT)), "%a %b %e %T %Y");
            assert_eq!(to_str(nl_langinfo(D_FMT)), "%m/%d/%y");
            assert_eq!(to_str(nl_langinfo(T_FMT)), "%H:%M:%S");
            assert_eq!(to_str(nl_langinfo(T_FMT_AMPM)), "%I:%M:%S %p");
            assert_eq!(to_str(nl_langinfo(YESEXPR)), "^[yY]");
            assert_eq!(to_str(nl_langinfo(NOEXPR)), "^[nN]");
            assert_eq!(to_str(nl_langinfo(YESSTR)), "yes");
            assert_eq!(to_str(nl_langinfo(NOSTR)), "no");
            assert_eq!(to_str(nl_langinfo(CRNCYSTR)), "");
            assert_eq!(to_str(nl_langinfo(0x1234)), "");
        }
    }
}
