// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! `W3` `VxD` archive: uncompressed container for multiple `VxD` (LE) images.
//!
//! A `W3` file is a DOS MZ wrapper whose `e_lfanew` points at the `W3` header
//! (see `VXDLIB.txt` "Technical Stuff", and the VMM32 analysis notes).
//!
//! ```text
//! W3 header (16 bytes + 16 bytes per member):
//!   0x00  "W3"
//!   0x02  OS-Lo
//!   0x03  OS-Hi            (0x0400 = Windows 4.0)
//!   0x04  VxD count (u16 LE)
//!   0x06  10 reserved bytes
//!   0x10  member #1: name[8] (space-padded), LE file offset (u32),
//!         LE header size (u32)
//!   0x20  member #2: … (16 bytes each)
//! ```
//!
//! Member offsets are **file-absolute**; each member is a bare LE image —
//! it starts with the `LE` magic itself, with no MZ stub in front of it
//! (verified against `singlew3.BIN` / `doublew3.BIN` and their standalone
//! images in `tests/w3_w4_archives.rs`).
//!
//! Because the offsets are absolute, a `W3` body that is not at the start of
//! its buffer needs the base it was cut out at. That is the difference between
//! the two constructors:
//!
//! - [`W3Archive::parse`] reads a whole file: the header at `offset`, member
//!   offsets already absolute in the same buffer (`member_base` = 0).
//! - [`W3Archive::parse_with_base`] reads a body extracted from something
//!   else — the decompressed payload of a `W4` archive. Its index 0 is where
//!   the archive's own header sat, so the member offsets still carry that
//!   base: `singlew4.BIN` decompresses to 8192 bytes whose first member is
//!   listed at 0x1400, i.e. 0x1400 − 0x1000 = 0x400 into the body. Passing the
//!   base as 0 would read a different member's bytes, so `parse_with_base`
//!   rejects a member that the wrong base would put past the end.

use crate::Buffer;
use crate::{vec, Error, Vec, LE_HEADER_SIZE, LE_SIGNATURE, LX_SIGNATURE, W3_SIGNATURE};

/// One member of a W3 archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct W3Member {
    /// 8-character member name (space-padded, e.g. `"VMM    "`).
    pub name: [u8; 8],
    /// File-absolute offset of the member's LE image.
    pub file_offset: u32,
    /// Size of the member's LE image (bytes).
    pub size: u32,
}

impl W3Member {
    /// The trimmed member name as ASCII (spaces stripped).
    #[must_use]
    pub fn name_trimmed(&self) -> &str {
        // Space-padded ASCII by format definition; non-ASCII is rendered
        // lossily for diagnostics.
        let end = self.name.iter().position(|&b| b == b' ').unwrap_or(8);
        core::str::from_utf8(&self.name[..end]).unwrap_or("?")
    }
}

/// Parsed W3 header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct W3Header {
    /// OS version (0x0400 = Windows 4.0).
    pub os: u16,
    /// Number of members.
    pub member_count: u16,
}

/// Check whether a buffer starts with a W3 signature at `offset`.
#[must_use]
pub fn is_w3_at(buf: &[u8], offset: usize) -> bool {
    buf.get(offset..offset + 2) == Some(W3_SIGNATURE)
}

/// Parse the W3 header at `offset`.
///
/// Only the 20-byte header is read; use [`W3Archive::members`] for the
/// member table.
pub fn parse_header(buf: &impl Buffer, offset: usize) -> Result<W3Header, Error> {
    if !is_w3_at(
        buf.get_slice(offset, 2)
            .map_err(|_| Error::TableOutOfBounds("w3_header", offset, offset + 2))?,
        0,
    ) {
        return Err(Error::ArchiveCorrupt("w3"));
    }
    let os = buf.read_u16(offset + 2)?;
    let member_count = buf.read_u16(offset + 4)?;
    Ok(W3Header { os, member_count })
}

/// A parsed W3 archive (header + member table).
pub struct W3Archive<'a> {
    /// The W3 header.
    pub header: W3Header,
    /// File-absolute offset of the W3 header inside `buf`.
    pub offset: usize,
    /// The member table.
    pub members: Vec<W3Member>,
    /// Buffer position 0 of this archive, expressed in the same frame as
    /// [`W3Member::file_offset`] — 0 for a whole file, and the offset of the
    /// container's own header for a body cut out of one (see the module docs).
    pub member_base: u32,
    /// The underlying buffer (kept for member extraction).
    buf: &'a (dyn Buffer + 'a),
}

impl core::fmt::Debug for W3Archive<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("W3Archive")
            .field("header", &self.header)
            .field("offset", &format_args!("{:#x}", self.offset))
            .field("member_base", &format_args!("{:#x}", self.member_base))
            .field("members", &self.members)
            .finish()
    }
}

impl<'a> W3Archive<'a> {
    /// Parse the full W3 header + member table of a whole file at `offset`.
    pub fn parse(buf: &'a impl Buffer, offset: usize) -> Result<Self, Error> {
        Self::parse_with_base(buf, offset, 0)
    }

    /// Parse the W3 header at `offset` of `buf`, reading the member table with
    /// `member_base` subtracted from every [`W3Member::file_offset`].
    ///
    /// A member whose block the base would place outside `buf` is rejected:
    /// a `W4` body read with the wrong base would otherwise silently return
    /// another member's bytes.
    pub fn parse_with_base(
        buf: &'a impl Buffer,
        offset: usize,
        member_base: u32,
    ) -> Result<Self, Error> {
        let header = parse_header(buf, offset)?;
        let table_start = offset + 0x10;
        let table_end = table_start.saturating_add(header.member_count as usize * 16);
        if table_end > buf.len() {
            return Err(Error::TableOutOfBounds(
                "w3_members",
                table_start,
                table_end,
            ));
        }
        let mut members = Vec::with_capacity(header.member_count as usize);
        for i in 0..header.member_count as usize {
            let o = table_start + i * 16;
            let name_bytes = buf.get_slice(o, 8)?;
            let mut name = [0u8; 8];
            name.copy_from_slice(name_bytes);
            let member = W3Member {
                name,
                file_offset: buf.read_u32(o + 8)?,
                size: buf.read_u32(o + 12)?,
            };
            let start = member
                .file_offset
                .checked_sub(member_base)
                .ok_or(Error::ArchiveCorrupt("w3_member_offset"))?;
            let end = start
                .checked_add(member.size)
                .ok_or(Error::ArchiveCorrupt("w3_member_size"))?;
            if end as usize > buf.len() {
                return Err(Error::TableOutOfBounds(
                    "w3_member_data",
                    start as usize,
                    buf.len(),
                ));
            }
            members.push(member);
        }
        Ok(Self {
            header,
            offset,
            members,
            member_base,
            buf,
        })
    }

    /// Where one member's image starts in this buffer (0-based index).
    pub fn member_at(&self, index: usize) -> Result<usize, Error> {
        let Some(member) = self.members.get(index) else {
            return Err(Error::ArchiveCorrupt("w3_member_index"));
        };
        member
            .file_offset
            .checked_sub(self.member_base)
            .map(|at| at as usize)
            .ok_or(Error::ArchiveCorrupt("w3_member_offset"))
    }

    /// The member's declared block: `size` bytes from its start, which covers
    /// its LE header and loader tables but **not** its page data — the pages
    /// live at the header's file-absolute `data_pages`, and the gap in between
    /// is zero padding.
    pub fn member_data(&self, index: usize) -> Result<&[u8], Error> {
        let Some(member) = self.members.get(index) else {
            return Err(Error::ArchiveCorrupt("w3_member_index"));
        };
        self.buf
            .get_slice(self.member_at(index)?, member.size as usize)
    }

    /// The member's whole span: from its start to the next member's start, or
    /// to the end of the buffer for the last one. This is the unit an
    /// extractor copies — header, tables, padding, pages and all — and it is
    /// how the 44 members of a `W4` archive were measured against their
    /// extracted copies.
    ///
    /// The next member is the one with the smallest start after this one, so a
    /// member table that is not sorted still bounds its member instead of
    /// running it into a later one.
    pub fn member_span(&self, index: usize) -> Result<&[u8], Error> {
        let start = self.member_at(index)?;
        let mut end = self.buf.len();
        for other in 0..self.members.len() {
            let other = self.member_at(other)?;
            if other > start && other < end {
                end = other;
            }
        }
        self.buf.get_slice(start, end - start)
    }

    /// The member as a standalone file: `prefix` followed by its whole
    /// [`member_span`](Self::member_span), with the two file-absolute fields of
    /// `FORMAT_GROUND_TRUTH.md` §3.2 rewritten so that they count from the
    /// start of the file being written:
    ///
    /// ```text
    /// data_pages        -= member.file_offset - prefix.len()
    /// non_resident_names -= member.file_offset - prefix.len()
    /// ```
    ///
    /// The operand is the member table's own offset, **not** the position the
    /// member happens to occupy in this buffer, and the difference matters for
    /// the body of a `W4`: there [`member_base`](Self::member_base) is the
    /// container header, so a member listed at 0x1400 sits at 0x400 of the
    /// decoded body — while the two fields inside it still say 0x1600-style,
    /// because `devlib` wrote them for the container file. Subtracting the
    /// buffer position instead moves them by 0x1000 too little and leaves a
    /// `data_pages` that points at the padding behind the real page area: a
    /// same-length wrong answer, so every page reads and reads zeros.
    ///
    /// `non_resident_names` often **wraps**, and that is the container's own
    /// condition rather than a defect here: `devlib` rebases only `data_pages`
    /// and leaves the stale standalone pointer in the member.
    ///
    /// # Errors
    ///
    /// `ArchiveCorrupt("w3_member_index")`, `TableOutOfBounds("w3_member_data")`
    /// from the span, `TableOutOfBounds("w3_member_header")` if the span is
    /// shorter than the 0xB0-byte image header, and `InvalidSignature(magic)`
    /// if the member does not start with `LE`/`LX`.
    pub fn member_standalone(&self, index: usize, prefix: &[u8]) -> Result<Vec<u8>, Error> {
        let start = self.member_at(index)?;
        let span = self.member_span(index)?;
        if span.len() < LE_HEADER_SIZE {
            return Err(Error::TableOutOfBounds(
                "w3_member_header",
                start,
                start + span.len(),
            ));
        }
        let magic = u16::from_le_bytes([span[0], span[1]]);
        if magic != LE_SIGNATURE && magic != LX_SIGNATURE {
            return Err(Error::InvalidSignature(magic));
        }

        let mut out = Vec::with_capacity(prefix.len() + span.len());
        out.extend_from_slice(prefix);
        out.extend_from_slice(span);

        // Both fields are absolute in the file the linker wrote, so the shift
        // is the distance between that file's image start — the member table's
        // offset, which is the same frame the fields count from — and ours.
        // Wrapping is intended: see the doc comment.
        let shift = self.members[index]
            .file_offset
            .wrapping_sub(prefix.len() as u32);
        for field in [0x80, 0x88] {
            let at = prefix.len() + field;
            let old = u32::from_le_bytes([out[at], out[at + 1], out[at + 2], out[at + 3]]);
            out[at..at + 4].copy_from_slice(&old.wrapping_sub(shift).to_le_bytes());
        }
        Ok(out)
    }
}

/// The conventional prefix for a standalone member image: `prefix_len` zero
/// bytes carrying the three fields a reader actually looks at — `MZ` at 0, a
/// relocation-table pointer of `0x40` with a count of 0 at `0x18` (the
/// "no relocations" DOS header every image frame in both corpora stores), and
/// `e_lfanew` at `0x3C` pointing at the image behind it.
///
/// A prefix shorter than `0x40` has no room for the DOS header fields, so it
/// says so by being all zeros.
#[must_use]
pub fn standalone_stub(prefix_len: usize) -> Vec<u8> {
    let mut stub = vec![0u8; prefix_len];
    if prefix_len >= 0x40 {
        stub[0..2].copy_from_slice(b"MZ");
        stub[0x18..0x1A].copy_from_slice(&0x40u16.to_le_bytes());
        stub[0x3C..0x40].copy_from_slice(&(prefix_len as u32).to_le_bytes());
    }
    stub
}
