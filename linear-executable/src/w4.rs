// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! `W4` `VxD` archive: **compressed** container (Windows 95).
//!
//! A `W4` file is a DOS MZ wrapper whose `e_lfanew` points at the `W4`
//! header. Everything from that header onward is stored as a single
//! **archive body** split into independently compressed chunks, and that body
//! is a complete `W3` archive — it starts with its own `W3` signature — so the
//! pipeline is: W4 chunks → codec → [`crate::w3::W3Archive`].
//!
//! ```text
//! W4 header (16 bytes + 4 bytes per chunk):
//!   0x00  "W4"
//!   0x02  OS-Lo
//!   0x03  OS-Hi            (0x040A in every file measured here)
//!   0x04  chunk size (u16 LE) — the DECOMPRESSED size of one chunk (8192 in
//!         every file measured here)
//!   0x06  chunk count (u16 LE)
//!   0x08  compression id (2 ASCII bytes; "DS" = MRCI / DoubleSpace)
//!   0x0A  6 reserved bytes (zero in every file measured here)
//!   0x10  chunk #1 file offset (u32, file-absolute), chunk #2, …
//!         (non-decreasing; the last chunk ends at end of file)
//! ```
//!
//! The chunk framing was settled by decoding the two committed `"DS"` archives
//! byte-exactly against their unpacked twins (`singlew4.BIN` →
//! `singlew3.BIN[0x1000..]`, `doublew4.BIN` → `doublew3.BIN[0x1000..]`) and
//! the 270-chunk `VMM32.VXD` against the 44 members it holds:
//!
//! - **A chunk is one independent codec block.** Its bit window and its copy
//!   window restart at the chunk boundary — the byte-exact 270-chunk decode is
//!   what proves that, since a window carried across a boundary would desync
//!   everything after the first chunk.
//! - **A chunk expands to exactly `chunk_size` bytes**. The rest of the
//!   last chunk is zero padding, which the unpacked file truncates. A block
//!   can also stop early on its own end marker, which is why the output length
//!   is summed per chunk instead of computed as `count × size`.
//! - **A chunk whose stored span equals `chunk_size` is stored raw** (no
//!   codec). No chunk in either corpus is stored that way — every stored span
//!   is smaller than 8192 — so the rule is exercised only by the synthetic
//!   image in `tests/w4_decompress.rs`.
//! - **The member offsets inside the body stay archive-file-absolute**: they
//!   count from the start of the `W4`/`W3` header, not from the start of the
//!   decompressed stream. In `singlew4.BIN` the first member is at 0x1400
//!   while the stream is only 8192 bytes long, so a reader of the stream must
//!   pass that base to [`crate::w3::W3Archive::parse_with_base`].
//!
//! The `"DS"` codec at the end of this module decodes the bit layout above:
//! LSB-first tokens, three copy-distance forms, and a bounded Elias gamma
//! length prefix.

use crate::Buffer;
use crate::{Error, Vec, W4_SIGNATURE};

/// The "DS" (`MRCI` / `DoubleSpace`) compression id.
pub const CODEC_DS: &[u8; 2] = b"DS";

/// Parsed W4 header + chunk table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct W4Header {
    /// OS version (0x0400 = Windows 4.0).
    pub os: u16,
    /// **Decompressed** chunk size in bytes (8192 in every file measured
    /// here). A chunk's stored span is `next_offset − offset` — see
    /// [`W4Archive::stored_chunk_size`], which is the number that bounds the
    /// bytes actually on disk.
    pub chunk_size: u16,
    /// Number of chunks.
    pub chunk_count: u16,
    /// Compression codec id (2 ASCII bytes).
    pub codec: [u8; 2],
}

/// Check whether a buffer starts with a W4 signature at `offset`.
#[must_use]
pub fn is_w4_at(buf: &[u8], offset: usize) -> bool {
    buf.get(offset..offset + 2) == Some(W4_SIGNATURE)
}

/// Parse the W4 header at `offset`.
pub fn parse_header(buf: &impl Buffer, offset: usize) -> Result<W4Header, Error> {
    let sig = buf
        .get_slice(offset, 2)
        .map_err(|_| Error::TableOutOfBounds("w4_header", offset, offset + 2))?;
    if sig != W4_SIGNATURE {
        return Err(Error::ArchiveCorrupt("w4"));
    }
    let os = buf.read_u16(offset + 2)?;
    let chunk_size = buf.read_u16(offset + 4)?;
    let chunk_count = buf.read_u16(offset + 6)?;
    let codec_bytes = buf.get_slice(offset + 8, 2)?;
    let mut codec = [0u8; 2];
    codec.copy_from_slice(codec_bytes);
    Ok(W4Header {
        os,
        chunk_size,
        chunk_count,
        codec,
    })
}

/// A parsed W4 archive (header + chunk table).
pub struct W4Archive<'a> {
    /// The W4 header.
    pub header: W4Header,
    /// File-absolute offset of the W4 header inside `buf` — and therefore the
    /// base that the member offsets of the decompressed body count from.
    pub offset: usize,
    /// File-absolute start offset of each compressed chunk.
    pub chunk_offsets: Vec<u32>,
    /// The underlying buffer.
    buf: &'a (dyn Buffer + 'a),
}

impl core::fmt::Debug for W4Archive<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("W4Archive")
            .field("header", &self.header)
            .field("offset", &format_args!("{:#x}", self.offset))
            .field("chunk_count", &self.chunk_offsets.len())
            .finish()
    }
}

impl<'a> W4Archive<'a> {
    /// Parse the W4 header + chunk table at `offset`.
    ///
    /// The chunk table is validated while it is read: every chunk must start
    /// inside the file, at or after the end of the chunk table, and the
    /// offsets must be non-decreasing. Without that check a stored span is
    /// computed by subtraction and a bogus offset silently yields a negative
    /// (i.e. huge) span.
    pub fn parse(buf: &'a impl Buffer, offset: usize) -> Result<Self, Error> {
        let header = parse_header(buf, offset)?;
        let table_start = offset + 0x10;
        let table_end = table_start.saturating_add(header.chunk_count as usize * 4);
        if table_end > buf.len() {
            return Err(Error::TableOutOfBounds("w4_chunks", table_start, table_end));
        }
        let mut chunk_offsets: Vec<u32> = Vec::with_capacity(header.chunk_count as usize);
        for i in 0..header.chunk_count as usize {
            let raw = buf.read_u32(table_start + i * 4)?;
            let at = raw as usize;
            if !(table_end..=buf.len()).contains(&at) {
                return Err(Error::TableOutOfBounds("w4_chunk_data", at, buf.len()));
            }
            if let Some(&previous) = chunk_offsets.last() {
                if raw < previous {
                    return Err(Error::ArchiveCorrupt("w4_chunk_order"));
                }
            }
            chunk_offsets.push(raw);
        }
        Ok(Self {
            header,
            offset,
            chunk_offsets,
            buf,
        })
    }

    /// Stored size in **bytes on disk** of one chunk (0-based index): up to
    /// the next chunk, and end of file for the last one. This is not
    /// [`W4Header::chunk_size`], which is the decompressed size.
    pub fn stored_chunk_size(&self, index: usize) -> Result<usize, Error> {
        let Some(&start) = self.chunk_offsets.get(index) else {
            return Err(Error::ArchiveCorrupt("w4_chunk_index"));
        };
        let start = start as usize;
        let end = if index + 1 < self.chunk_offsets.len() {
            self.chunk_offsets[index + 1] as usize
        } else {
            self.buf.len()
        };
        end.checked_sub(start)
            .ok_or(Error::ArchiveCorrupt("w4_chunk_order"))
    }

    /// Decompress the archive body: the concatenation of the decoded chunks,
    /// which is a complete `W3` archive (starting with its `W3` signature).
    ///
    /// The result is *not* re-based: the member offsets inside it are still
    /// archive-file-absolute, so parsing it takes the base explicitly —
    ///
    /// ```text
    /// let body = w4.decompress()?;
    /// let w3 = W3Archive::parse_with_base(&body, 0, u32::try_from(w4.offset)?)?;
    /// ```
    ///
    /// An unknown codec id yields [`Error::UnsupportedCodec`]; a chunk that
    /// decodes to a malformed bit stream yields [`Error::ArchiveCorrupt`].
    pub fn decompress(&self) -> Result<Vec<u8>, Error> {
        if self.header.codec != *CODEC_DS {
            return Err(Error::UnsupportedCodec(u16::from_le_bytes(
                self.header.codec,
            )));
        }
        let chunk_size = usize::from(self.header.chunk_size);
        if chunk_size == 0 {
            return Err(Error::ArchiveCorrupt("w4_chunk_size"));
        }
        // Capacity grows with the decoded output instead of being reserved
        // from `chunk_count × chunk_size`, which a crafted header could inflate
        // without any matching input bytes behind it.
        let mut out = Vec::with_capacity(self.buf.len());
        for index in 0..self.chunk_offsets.len() {
            let start = self.chunk_offsets[index] as usize;
            let span = self.stored_chunk_size(index)?;
            let stored = self.buf.get_slice(start, span)?;
            if span == chunk_size {
                // Stored raw, the way a block that does not compress well is
                // kept. Its span equals the decompressed size by definition.
                out.extend_from_slice(stored);
            } else {
                ds_decompress(stored, &mut out, chunk_size)?;
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// MRCI / DoubleSpace ("DS") codec
// ---------------------------------------------------------------------------

/// The long-form copy distance that marks a sector break rather than naming
/// a copy source.
///
/// It is the largest distance the 15-bit long form can encode
/// (`320 + 0xFFF`), so only that form can produce it. The decoder consumes
/// the token, reads no length prefix, emits no output, and carries on with
/// the next token. Unlike distance zero, it does not end the block.
const DS_SECTOR_BREAK: usize = 4415;

/// LSB-first bit cursor over one stored chunk.
///
/// The codec reads bits from the low bit of each byte upward and consumes the
/// bytes in order, which is what a little-endian load of the next bytes would
/// give. Reading past the end of the chunk yields zero bits: that is what the
/// block decoder relies on to stop on its end marker when the stored span is
/// not byte-aligned to the last token.
struct BitStream<'a> {
    bytes: &'a [u8],
    /// Next bit to read, counted from the start of `bytes`.
    position: usize,
}

impl<'a> BitStream<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn bit_at(&self, position: usize) -> u32 {
        match self.bytes.get(position >> 3) {
            Some(&byte) => u32::from((byte >> (position & 7)) & 1),
            None => 0,
        }
    }

    /// The next `count` bits, least significant first, without consuming them.
    fn peek(&self, count: u32) -> u32 {
        let mut value = 0u32;
        for index in 0..count {
            value |= self.bit_at(self.position + index as usize) << index;
        }
        value
    }

    fn take(&mut self, count: u32) -> u32 {
        let value = self.peek(count);
        self.position += count as usize;
        value
    }

    fn skip(&mut self, count: u32) {
        self.position += count as usize;
    }
}

/// The length prefix that follows a copy token: a bounded, offset-by-one form
/// of Elias gamma coding.
///
/// Gamma codes `length - 1`: for `k = floor(log2(length - 1))` the bit pattern
/// is `k` zero bits, one terminating bit, then the `k` low-order bits of
/// `length - 1`. Written as `value`, that decodes to
///
/// ```text
/// length = 2^k + value + 1     (1 + 2k bits in total)
/// ```
///
/// The run of leading zeros is capped at eight, which bounds a copy at
/// 2..=512 bytes — so a chunk of 8192 zero bytes costs sixteen copy tokens,
/// not one. Nine zero bits in a row cannot be a length prefix at all: the
/// block is malformed.
fn elias_gamma_decode(bits: &mut BitStream<'_>) -> Result<usize, Error> {
    let mut zeroes = 0u32;
    while zeroes < 9 && bits.bit_at(bits.position) == 0 {
        zeroes += 1;
        bits.position += 1;
    }
    if zeroes == 9 {
        return Err(Error::ArchiveCorrupt("elias_gamma_decode"));
    }
    bits.skip(1);
    let extra = bits.take(zeroes);
    Ok((1usize << zeroes) + extra as usize + 1)
}

/// Decode one `"DS"` block, appending at most `chunk_size` bytes to `out`.
///
/// The block is an LZ77-style stream of literals and back-references over the
/// [`BitStream`] cursor. A token starts with two bits that select a literal or
/// a copy, and the three copy forms differ in how many further bits their
/// distance carries:
///
/// ```text
/// 01 xxxxxxx          literal 0x80 | x          (9 bits)
/// 10 xxxxxxx          literal x                 (9 bits)
/// 00 dddddd           copy, distance d          (8 bits)
/// 110 dddddddd        copy, distance 64 + d     (11 bits)
/// 111 dddddddddddd    copy, distance 320 + d    (15 bits)
/// ```
///
/// A copy distance counts back from the current output position and copies
/// byte by byte forwards, so a match may overlap what it has just written —
/// that is what lets a distance of 1 repeat one byte. The history is the
/// current chunk only: a distance reaching behind the block's first byte, or a
/// copy running past `chunk_size`, is corrupt.
///
/// Distance zero is the block's end marker, and [`DS_SECTOR_BREAK`] consumes
/// its token without reading a length or emitting anything. `Ok` means either
/// marker was reached — possibly before `chunk_size` bytes — or the chunk is
/// full. A malformed stream returns [`Error::ArchiveCorrupt`] naming the
/// reason, because a caller has to tell "the block ended" from "the block is
/// corrupt".
fn ds_decompress(stored: &[u8], out: &mut Vec<u8>, chunk_size: usize) -> Result<(), Error> {
    let mut bits = BitStream::new(stored);
    let block_start = out.len();

    while out.len() - block_start < chunk_size {
        // Bits are read low bit first, so the token's low two bits arrive as
        // 0b_second_first: 00 short copy, 10 plain literal, 01 literal with
        // bit 7 set, 11 the two long-distance forms — whose third bit is read
        // only on that path.
        let distance = match bits.take(2) {
            0b00 => bits.take(6) as usize,
            0b10 => {
                out.push(bits.take(7) as u8);
                continue;
            }
            0b01 => {
                out.push(0x80 | bits.take(7) as u8);
                continue;
            }
            _ => {
                if bits.take(1) == 0 {
                    64 + bits.take(8) as usize
                } else {
                    320 + bits.take(12) as usize
                }
            }
        };

        if distance == 0 {
            break; // the block's end marker
        }
        if distance == DS_SECTOR_BREAK {
            continue; // consumed: no length, no output
        }

        let length = elias_gamma_decode(&mut bits)?;

        let produced = out.len() - block_start;
        if distance > produced {
            return Err(Error::ArchiveCorrupt("ds_underflow"));
        }
        if produced + length > chunk_size {
            return Err(Error::ArchiveCorrupt("ds_chunk_overflow"));
        }
        for _ in 0..length {
            let byte = out[out.len() - distance];
            out.push(byte);
        }
    }
    Ok(())
}
