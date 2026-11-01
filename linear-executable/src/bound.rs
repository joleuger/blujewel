// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! Finding an LE/LX image inside a **bound** file, and the frame its two
//! file-absolute header fields have to be read in.
//!
//! A bound file is one DOS program that contains two: a DOS stub, an extender
//! kernel, and the application image a binder folded in. The two families in
//! this corpus differ in one decisive way:
//!
//! - **A rebinding binder** (Open Watcom's; the pair
//!   `testdata/fixtures/dos4gw-bound.BIN` / `dos32a-bound.BIN`) writes the
//!   *result's* `MZ[0x3C]` and adds the prefix size to the image's
//!   `data_pages` (0x80), so both fields describe the new, outer file. The
//!   outer MZ header is the frame: file offset 0.
//! - **A bundling binder**  stores the application file **byte for byte**, its own MZ
//!   header included, after the kernel, and touches nothing. The outer
//!   `MZ[0x3C]` is then not an offset at all (all three store `00 09 B4 00`,
//!   low half zero) and `data_pages` still counts from the start of the
//!   embedded application.
//!
//! So the frame is neither the LE header nor byte 0: it is **the MZ header
//! whose `e_lfanew` points at the LE header**, which is exactly what
//! [`crate::le::LE::header_offset`] reads. Slicing the buffer at that MZ header
//! makes both bases line up at once — the header-relative tables resolve through
//! `e_lfanew`, and `data_pages` (0x80) and `non_resident_names` (0x88) count
//! from the embedded file's start again, which is what they mean.

use crate::headers::header_from_bytes;
use crate::le::PtrLE;
use crate::{
    Error, DOS_E_LFANEW_OFFSET, DOS_SIGNATURE, LE_HEADER_SIZE, LE_SIGNATURE, LX_SIGNATURE,
};

/// Offset of the MZ header's relocation-table pointer — the field that tells a
/// loadable DOS header from a stub that only borrows the magic. Every image
/// frame in this corpus carries 0x40 there; the three game files' *outer*
/// headers carry 0x1E.
const DOS_RELOC_POINTER: usize = 0x18;

/// Where one LE/LX image sits inside a buffer, and what its file-absolute
/// fields count from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Location {
    /// File offset of the LE/LX header.
    pub header_at: usize,
    /// File offset of the header that frames the file-absolute fields: the
    /// start of the image's own file, which is byte 0 unless the image was
    /// bundled whole inside another program.
    pub frame_at: usize,
    /// That header's `e_lfanew`, which by construction satisfies
    /// `frame_at + frame_lfanew == header_at`.
    pub frame_lfanew: u32,
    /// `true` when the outer DOS header did not lead to the image — its
    /// `e_lfanew` was zero, out of range, or pointed at something that is not
    /// an LE/LX image — and [`locate`] found the header by scanning instead.
    pub found_by_scan: bool,
}

impl Location {
    /// The buffer to read this image through: the file sliced at
    /// [`Location::frame_at`], so `header_offset()` lands on the image while
    /// the file-absolute fields keep the frame they were written with.
    #[must_use]
    pub fn view<'a>(&self, data: &'a [u8]) -> PtrLE<'a> {
        PtrLE::from_slice(&data[self.frame_at..])
    }
}

/// Find the LE/LX image in `data`: the DOS header first, then — only when that
/// header is not a loadable one at all — an aligned scan, then the frame the
/// image's file-absolute fields count from.
///
/// The DOS header is trusted when it is a loadable one: relocation table at
/// 0x18 == 0x40 and a non-zero low half in `e_lfanew`. **A trusted header that
/// does not point at an LE/LX image ends the search** — that is a PE file
/// (`le-inspect` keeps reporting `invalid LE/LX signature: 0x5A4D`, the file's
/// first word, where `0x4550` "PE" sits at `e_lfanew`) or a `W3`/`W4` archive,
/// and scanning their bytes for an image would turn a clear refusal into a
/// bogus parse. Only an *untrusted* header — the bundling binder's, where
/// `e_lfanew` is a byte-swapped pair with a zero low half and the relocation
/// pointer is not 0x40 — means "there is a bundled image in here, and this
/// header does not say where".
///
/// That search is a **2-byte-aligned scan**: an `LE`/`LX` magic whose two
/// following bytes (`byte_order`, `word_order`) are both zero and whose page
/// size is a non-zero power of two.
///
/// The frame is then the MZ header nearest to the header (nearest = innermost,
/// so an embedded application wins over the outer program) whose `e_lfanew`
/// points exactly at it. A plain file keeps frame 0 and byte-for-byte the
/// behaviour it had before this module existed; so does an image that starts at
/// offset 0 (an archive member, whose binder stripped the stub).
///
/// A file with no image yields [`Error::InvalidSignature`] carrying the
/// file's **first two bytes** — for a PE file that is `0x5A4D` ("MZ"), which
/// is what `le-inspect` reports; `0x4550` ("PE") is what sits at `e_lfanew`.
pub fn locate(data: &[u8]) -> Result<Location, Error> {
    let not_an_image = || Error::InvalidSignature(u16_at(data, 0).unwrap_or(0));

    if let Some(lfanew) = trusted_dos_lfanew(data) {
        return if is_image_at(data, lfanew) {
            Ok(Location {
                header_at: lfanew,
                frame_at: 0,
                frame_lfanew: u32::try_from(lfanew).unwrap_or(u32::MAX),
                found_by_scan: false,
            })
        } else {
            Err(not_an_image())
        };
    }

    // No loadable DOS header: either the image is the file (an archive member
    // with its stub stripped), or a bundled image the outer stub does not
    // describe, or there is no image here.
    if is_image_at(data, 0) {
        return Ok(Location {
            header_at: 0,
            frame_at: 0,
            frame_lfanew: 0,
            found_by_scan: false,
        });
    }
    let header_at = scan_for_image(data).ok_or_else(not_an_image)?;
    // A bundled image carries its own file header, and that header is the
    // frame. Without it there is nothing to say what `data_pages` counts
    // from, so refuse rather than read the wrong page bytes.
    let (frame_at, frame_lfanew) = frame_for(data, header_at).ok_or_else(not_an_image)?;
    Ok(Location {
        header_at,
        frame_at,
        frame_lfanew,
        found_by_scan: true,
    })
}

/// The MZ header nearest to `header_at`, scanning backwards from it, whose
/// `e_lfanew` points exactly at `header_at`; its offset and that `e_lfanew`.
///
/// The equation is the whole test and it is a 32-bit one, which is why no
/// other heuristic is needed: on all seven files of the bound corpus it
/// matches exactly one offset.
fn frame_for(data: &[u8], header_at: usize) -> Option<(usize, u32)> {
    if header_at < DOS_E_LFANEW_OFFSET {
        return None;
    }
    (0..header_at - DOS_E_LFANEW_OFFSET).rev().find_map(|at| {
        let lfanew = u32_at(data, at + DOS_E_LFANEW_OFFSET)?;
        let points_at_image =
            u16_at(data, at)? == DOS_SIGNATURE && at + lfanew as usize == header_at;
        points_at_image.then_some((at, lfanew))
    })
}

/// `Some(e_lfanew)` when a loadable DOS header at offset 0 points inside the
/// file. A low half of zero means "not bound via this MZ header" — the value
/// is then a byte-swapped pair, not an offset (0x09B40000 in each game file).
fn trusted_dos_lfanew(data: &[u8]) -> Option<usize> {
    if u16_at(data, 0)? != DOS_SIGNATURE || u16_at(data, DOS_RELOC_POINTER)? != 0x40 {
        return None;
    }
    let lfanew = u32_at(data, DOS_E_LFANEW_OFFSET)?;
    if lfanew.trailing_zeros() >= 16 {
        return None;
    }
    let offset = lfanew as usize;
    if offset <= DOS_E_LFANEW_OFFSET || offset >= data.len() {
        return None;
    }
    Some(offset)
}

/// Candidate image position: at least a whole header, LE/LX magic, both order
/// bytes zero, page size a non-zero power of two.
fn is_image_at(data: &[u8], at: usize) -> bool {
    let Some(rest) = data.get(at..at + LE_HEADER_SIZE) else {
        return false;
    };
    let Ok(header) = header_from_bytes(rest) else {
        return false;
    };
    (header.magic == LE_SIGNATURE || header.magic == LX_SIGNATURE)
        && header.byte_order == 0
        && header.word_order == 0
        && header.validate().is_ok()
}

/// Every even offset that can hold a whole header, inclusive of the position
/// flush with the end of the buffer.
fn scan_for_image(data: &[u8]) -> Option<usize> {
    (0..=data.len().saturating_sub(LE_HEADER_SIZE))
        .step_by(2)
        .find(|&at| is_image_at(data, at))
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    let b = data.get(at..at + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    let b = data.get(at..at + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
