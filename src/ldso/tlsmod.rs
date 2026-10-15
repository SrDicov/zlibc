//! Wave 6 packet 6C — TLS module geometry: offsets, alignment, block size.
//!
//! musl lays static-TLS modules out **downward** from the thread pointer
//! on x86_64 (`TLS_ABOVE_TP` is undefined for this arch, so every formula
//! below is the `#else` arm). Two paths produce an offset:
//!
//! * the first module (the executable's own `PT_TLS`) pads `size` so the
//!   module ends on an `align` boundary, and uses the padded size as the
//!   downward distance (`__init_tls.c:114-121`);
//! * every module after it bumps a running high-water mark and pulls it
//!   back to the smallest value congruent to its image address
//!   (`dynlink.c:1238-1243`).
//!
//! Both exist for one reason: a module's runtime address must satisfy
//! `addr ≡ image (mod align)`, which plain size accumulation breaks. The
//! tests assert that congruence directly, because a sign slip here is a
//! silent misalignment that only shows up as a corrupt `__thread int x`
//! in some unrelated program.

use core::mem::size_of;

use super::dso::TlsModule;
use crate::thread::Thread;

/// musl `MIN_TLS_ALIGN` = `offsetof(struct builtin_tls, pt)`
/// (`__init_tls.c:35`): `builtin_tls` is `{ char c; struct pthread pt;
/// void *space[16]; }`, so the floor is the offset of `pt`, which is 8
/// on x86_64 whatever `sizeof(struct pthread)` is.
pub const MIN_TLS_ALIGN: usize = 8;

/// Round `v` up to a multiple of `a` (musl `ALIGN`, `dynlink.c:49`).
/// # Panics
///
/// Debug-only: `a` must be a power of two, or at least non-zero.
pub fn align_up(v: usize, a: usize) -> usize {
    debug_assert!(a.is_power_of_two(), "alignment must be a power of two");
    v.wrapping_add(a - 1) & !(a - 1)
}

/// Round `v` down to a multiple of `a`.
///
/// # Panics
///
/// Debug-only: `a` must be a power of two, or at least non-zero.
pub fn align_down(v: usize, a: usize) -> usize {
    debug_assert!(a.is_power_of_two(), "alignment must be a power of two");
    v & !(a - 1)
}

/// musl `MAXP2(a,b) = -(-(a)&-(b))` (`dynlink.c:48`): the larger power of
/// two, used to raise the block alignment to the strictest module.
pub fn max_pow2(a: usize, b: usize) -> usize {
    a.max(b)
}

/// Pad a module's `size` so `image + size` lands on an `align` boundary
/// (musl `__init_tls.c:115`).
///
/// The mask is `(-size - image) & (align - 1)`, i.e. the distance from
/// `image + size` up to the next multiple of `align`. After this call,
/// `image + size ≡ 0 (mod align)` — which is exactly the congruence the
/// first module's offset (`= size`) needs, since its runtime address is
/// `tp - offset` and `tp` is `align`-aligned.
pub fn pad_size(image: usize, size: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two(), "alignment must be a power of two");
    size.wrapping_add((0usize.wrapping_sub(size).wrapping_sub(image)) & (align - 1))
}

/// Offset for the **first** module: the padded size, used as a downward
/// distance from the thread pointer (musl `__init_tls.c:121`,
/// `dynlink.c:1938-1940` — the dynamic loader pads and takes the result
/// as `tls_offset` too).
pub fn first_offset(image: usize, size: usize, align: usize) -> usize {
    pad_size(image, size, align)
}

/// Offset for the next module after a running high-water mark
/// `tls_offset` (musl `dynlink.c:1238-1243`):
///
/// ```text
/// tls_offset += size + align - 1;
/// tls_offset -= (tls_offset + image) & (align - 1);
/// ```
///
/// Step one may overshoot; step two pulls it back to the smallest value
/// that is still `≡ image (mod align)`. The result is therefore the
/// least offset above the previous mark with the required congruence —
/// modules are placed downward, so higher offset means lower address.
pub fn next_offset(tls_offset: usize, image: usize, size: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two(), "alignment must be a power of two");
    let bumped = tls_offset.wrapping_add(size).wrapping_add(align - 1);
    bumped.wrapping_sub(bumped.wrapping_add(image) & (align - 1))
}

/// Total per-thread TLS block, musl `update_tls_size` (`dynlink.c:1640`):
///
/// ```text
/// ALIGN((1+tls_cnt)*sizeof(void*) + tls_offset + sizeof(pthread) + tls_align*2, tls_align)
/// ```
///
/// `1+tls_cnt` words are the DTV (slot 0 holds the count). The
/// `tls_align*2` slop absorbs the downward rounding of the TCB against
/// absolute zero in `copy_tls`, which would otherwise walk off the front
/// of the block.
pub fn block_size(tls_cnt: usize, tls_offset: usize, tls_align: usize, tcb: usize) -> usize {
    let dtv = (1 + tls_cnt) * size_of::<usize>();
    align_up(dtv + tls_offset + tcb + tls_align * 2, tls_align)
}

/// Fill `m` from a `PT_TLS` program header and assign the first module's
/// offset (musl `__init_tls.c:105-121`).
///
/// `image` is the *runtime* address of the template, i.e. already biased
/// by the load base; its contents hold unrelocated pointers, which is why
/// the image is copied rather than shared.
///
/// Returns the padded `size`, which is also `m.offset`.
///
/// # Safety
///
/// `m` must be writable and outlive every thread.
pub unsafe fn init_first_module(
    m: *mut TlsModule,
    image: usize,
    filesz: usize,
    memsz: usize,
    align: usize,
) -> usize {
    unsafe {
        (*m).image = image as *mut core::ffi::c_void;
        (*m).len = filesz;
        (*m).size = memsz;
        (*m).align = if align < MIN_TLS_ALIGN {
            MIN_TLS_ALIGN
        } else {
            align
        };
        let padded = pad_size(image, (*m).size, (*m).align);
        (*m).size = padded;
        // x86_64 has no TLS_ABOVE_TP: the offset is a downward distance
        // from the thread pointer, so it *is* the padded size.
        (*m).offset = padded;
        padded
    }
}

/// Advance the loader's TLS geometry for a module placed after
/// `tls_offset` (musl `dynlink.c:1233,1238-1243`), writing
/// `m.offset` and returning the `(tls_offset, tls_align)` pair to keep.
///
/// # Safety
///
/// `m` must be writable with `image`, `size` and `align` already set.
pub unsafe fn place_module(
    m: *mut TlsModule,
    tls_offset: usize,
    tls_align: usize,
) -> (usize, usize) {
    unsafe {
        let align = if (*m).align < MIN_TLS_ALIGN {
            MIN_TLS_ALIGN
        } else {
            (*m).align
        };
        (*m).align = align;
        let tls_align = max_pow2(tls_align, align);
        let offset = next_offset(tls_offset, (*m).image as usize, (*m).size, align);
        (*m).offset = offset;
        (offset, tls_align)
    }
}

/// `sizeof(struct pthread)` as our TCB sees it, spelled out so the
/// formulas above read like musl's (`dynlink.c:1647`).
pub const fn tcb_size() -> usize {
    size_of::<Thread>()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The invariant every formula exists to satisfy: a module's runtime
    /// address `tp - offset` must be congruent to its image modulo its
    /// own alignment.
    fn assert_congruent(image: usize, offset: usize, align: usize) {
        assert_eq!(
            (image + offset) & (align - 1),
            0,
            "image {image:#x} + offset {offset:#x} must be {align}-aligned"
        );
    }

    #[test]
    fn first_module_offset_makes_image_plus_size_aligned() {
        // A 64-byte module of 32-byte alignment at an arbitrary address.
        let image = 0x5555_5555_5a40usize;
        let padded = pad_size(image, 64, 32);
        assert_eq!(padded % 32, 0, "padded size keeps the tail aligned");
        assert_eq!(first_offset(image, 64, 32), padded);
        // And the real property: tp - offset lands where the module goes.
        assert_congruent(image, padded, 32);
    }

    #[test]
    fn next_offsets_rise_and_stay_congruent() {
        // Three modules, deliberately different sizes and alignments and
        // image addresses, chained through the running mark like the
        // loader does.
        let mods: [(usize, usize, usize); 3] = [
            (0x7fff_0000_0010, 8, 8),
            (0x7fff_0000_1234, 128, 16),
            (0x7fff_0000_5678, 4096, 64),
        ];
        let mut tls_offset = 0usize;
        for (image, size, align) in mods {
            let off = next_offset(tls_offset, image, size, align);
            assert!(
                off > tls_offset || tls_offset == 0,
                "offset {off} must rise above the previous mark {tls_offset}"
            );
            assert_congruent(image, off, align);
            tls_offset = off;
        }
    }

    #[test]
    fn next_offset_matches_a_direct_recomputation() {
        // Same formula spelled independently, to pin the two-step shape.
        let image = 0x7f00_1234usize;
        let size = 100usize;
        let align = 64usize;
        let tls_offset = 4096usize;
        let got = next_offset(tls_offset, image, size, align);
        let mut want = tls_offset + size + align - 1;
        want -= (want + image) & (align - 1);
        assert_eq!(got, want);
        assert_congruent(image, got, align);
    }

    #[test]
    fn align_floor_is_eight() {
        // A 1-byte-aligned PT_TLS still gets the floor, or the TCB would
        // be placed on a boundary the block cannot guarantee.
        assert_eq!(MIN_TLS_ALIGN, 8);
        let mut m: TlsModule = unsafe { core::mem::zeroed() };
        unsafe {
            init_first_module(&mut m as *mut TlsModule, 0x1000, 4, 4, 1);
        }
        assert_eq!(m.align, MIN_TLS_ALIGN);
    }

    #[test]
    fn block_size_covers_dtv_tcb_and_slop() {
        let tls_cnt = 3usize;
        let tls_offset = 4096usize;
        let tls_align = 64usize;
        let size = block_size(tls_cnt, tls_offset, tls_align, tcb_size());
        assert_eq!(size % tls_align, 0, "block is tls_align-aligned");
        // Everything that must fit is inside.
        let need = (1 + tls_cnt) * size_of::<usize>() + tls_offset + tcb_size();
        assert!(size >= need);
        assert!(size >= need + tls_align * 2, "the 2x slop is present");
    }

    #[test]
    fn init_first_module_records_the_phdr() {
        let mut m: TlsModule = unsafe { core::mem::zeroed() };
        let image = 0x7f00_2000usize;
        let size = unsafe { init_first_module(&mut m as *mut TlsModule, image, 12, 40, 16) };
        assert_eq!(m.len, 12, "filesz: the initialized part");
        assert_eq!(m.image as usize, image);
        assert_eq!(m.offset, size);
        assert_eq!(m.size, size, "size is stored padded");
        assert!(m.size >= 40, "padding only ever grows the block");
    }

    #[test]
    fn place_module_raises_the_block_alignment() {
        let mut m: TlsModule = unsafe { core::mem::zeroed() };
        m.image = 0x7f00_3000 as *mut core::ffi::c_void;
        m.size = 64;
        m.align = 128;
        let (off, align) = unsafe { place_module(&mut m as *mut TlsModule, 1024, 16) };
        assert_eq!(align, 128, "block alignment follows the strictest module");
        assert_eq!(m.offset, off);
        assert_congruent(m.image as usize, off, 128);
        assert!(off >= 1024);
    }
}
