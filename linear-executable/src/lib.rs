// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! # linear-executable — LE/LX (Linear Executable) Format Parser
//!
//! Import name `linear_executable`; the crate is published as
//! `linear-executable`.
//!
//! A Rust library for parsing LE and LX (Linear Executable) files:
//!
//! - **LE** — DOS-extender applications (DOS4G/W, PMODE/W, DOS/32A,
//!   `CauseWay`) and `VxD` device drivers (Windows 3.x / 9x)
//! - **LX** — OS/2 2.x executables, DLLs, and device drivers
//!
//! ## Features
//!
//! - **Parsing**: LE/LX headers, object tables, object page tables, resident
//!   names, and page data (types 0 raw / 1 iterated / 3 zero-filled), including
//!   reassembly of complete object images
//! - **Containers**: `W3` (uncompressed `VxD` archive) and `W4` (compressed `VxD`
//!   archive) header/member parsing, and `W4` "DS" (`MRCI`/`DoubleSpace`)
//!   decompression — [`w4`] decodes the bit layout described in its module docs
//! - **Zero-copy header access**: `get_le_header_ref()` returns `&LeHeader`
//!   directly from the underlying buffer
//! - **`no_std` support**: compile without the standard library
//!
//! ## Safety model
//!
//! Every read is bounds-checked against the buffer length; malformed or
//! truncated input yields an [`Error`], never a panic or out-of-bounds access.
//! Real-world LE files (especially `VxD`s from the Windows 9x era) are often
//! malformed, so defensive parsing is a hard requirement.
//!
//! ## Quick Start
//!
//! ```
//! # let Some(bytes) = linear_executable::doc_fixture() else { return };
//! use linear_executable::{VecLE, LE};
//!
//! let le = VecLE::from_memory(bytes);
//! let header = le.get_le_header().unwrap();
//! assert_eq!(header.module_pages(), 2);
//!
//! // Tables are parsed on demand
//! let objects = le.get_object_table().unwrap();
//! assert_eq!(objects.len(), 2);
//! ```
//!
//! ## `no_std` Usage
//!
//! ```toml
//! [dependencies]
//! linear-executable = { version = "0.1", default-features = false, features = ["alloc"] }
//! ```
//!
//! In `no_std` mode (with the `alloc` feature), parsed strings are borrowed
//! from the buffer (`PascalString`).

#![no_std]
#![warn(clippy::pedantic)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::too_many_lines
)]

// Conditional std imports
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

// Unit tests link std via the test harness even in no_std builds, so the
// test code can use `std::...` paths under `--features alloc` alone.
#[cfg(all(test, not(feature = "std")))]
extern crate std;

// The public API returns heap-allocated data (Vec); at least one of
// `std` or `alloc` must be enabled.
#[cfg(not(any(feature = "std", feature = "alloc")))]
compile_error!(
    "the `linear-executable` crate requires the `std` or `alloc` feature: the \
     public API returns heap-allocated data (Vec). Use `--features alloc` for \
     no_std builds."
);

// Re-export Vec (and the `vec!` macro) for use in other modules.
#[cfg(all(feature = "alloc", not(feature = "std")))]
pub(crate) use alloc::vec;
#[cfg(all(feature = "alloc", not(feature = "std")))]
pub use alloc::vec::Vec;
#[cfg(feature = "std")]
pub(crate) use std::vec;
#[cfg(feature = "std")]
pub use std::vec::Vec;

// Public modules
pub mod bound;
#[cfg(feature = "disasm")]
pub mod disasm;
pub mod headers;
pub mod le;
pub mod types;
pub mod w3;
pub mod w4;

// Re-export key types at crate root
pub use headers::*;
pub use le::*;
pub use types::*;

// ---------------------------------------------------------------------------
// Error enum
// ---------------------------------------------------------------------------

use core::fmt;

/// Error types for LE/LX parsing operations.
///
/// In `std` mode, `IoError` and `Utf8Error` variants carry their std
/// counterparts. In `no_std` mode, these variants are unavailable.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// I/O error (only available with `std` feature)
    #[cfg(feature = "std")]
    IoError(std::io::Error),

    /// UTF-8 validation error (only available with `std` feature)
    #[cfg(feature = "std")]
    Utf8Error(std::str::Utf8Error),

    /// The file does not start with MZ signature and has no LE/LX signature
    /// at offset 0 either
    InvalidSignature(u16),

    /// Header field offset is out of bounds
    HeaderOutOfBounds(usize),

    /// File too short to contain the 0xB0-byte LE/LX header
    HeaderTooSmall,

    /// The page size field is zero or not a power of two
    InvalidPageSize(u32),

    /// File too short for a requested table read (`table_name`, offset, bound)
    TableOutOfBounds(&'static str, usize, usize),

    /// Object number not found in the object table (1-based)
    ObjectNotFound(u32),

    /// Page index not found in the object page table (0-based)
    PageNotFound(u32),

    /// Invalid Pascal string (length exceeds available data, or the data is
    /// not valid UTF-8)
    InvalidPascalString,

    /// Object table is internally inconsistent (page range exceeds module
    /// page count, zero first-page index, …)
    ObjectTableCorrupt,

    /// Entry (export) table is malformed
    EntryTableCorrupt,

    /// A fixup record's source type is one the format leaves undefined (1 or
    /// 4), so the record has no length and the rest of the table cannot be
    /// located
    UnsupportedFixupSource(u8),

    /// Page data stream is corrupt (iterated-page record overruns its input)
    PageDataCorrupt,

    /// Page type is not supported by this parser build or by the format
    /// variant in use (2 = invalid by design, 4 = range-of-pages,
    /// 5 = compressed/LX-only, …)
    UnsupportedPageType(u8),

    /// W4 archive compression codec is not implemented (`codec` id as the
    /// two header bytes combined into a u16, e.g. `0x5344` = "DS")
    UnsupportedCodec(u16),

    /// W3/W4 archive structure is corrupt
    ArchiveCorrupt(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "std")]
            Error::IoError(e) => write!(f, "I/O error: {e}"),
            #[cfg(feature = "std")]
            Error::Utf8Error(e) => write!(f, "UTF-8 error: {e}"),
            Error::InvalidSignature(sig) => {
                write!(
                    f,
                    "invalid LE/LX signature: 0x{sig:04X} (expected 0x{LE_SIGNATURE:04X} \"LE\" \
                     or 0x{LX_SIGNATURE:04X} \"LX\")"
                )
            }
            Error::HeaderOutOfBounds(offset) => {
                write!(f, "header field offset 0x{offset:04X} is out of bounds")
            }
            Error::HeaderTooSmall => {
                write!(
                    f,
                    "file too short to contain the {LE_HEADER_SIZE}-byte LE/LX header"
                )
            }
            Error::InvalidPageSize(size) => {
                write!(
                    f,
                    "invalid page size: {size} (must be a non-zero power of two)"
                )
            }
            Error::TableOutOfBounds(name, offset, bound) => {
                write!(
                    f,
                    "table '{name}' out of bounds: offset 0x{offset:04X} (bound 0x{bound:04X})"
                )
            }
            Error::ObjectNotFound(num) => {
                write!(f, "object number {num} not found")
            }
            Error::PageNotFound(index) => {
                write!(f, "page index {index} not found")
            }
            Error::InvalidPascalString => {
                write!(f, "invalid Pascal string: length exceeds available data")
            }
            Error::ObjectTableCorrupt => {
                write!(
                    f,
                    "object table corrupt: page range exceeds module page count"
                )
            }
            Error::EntryTableCorrupt => {
                write!(f, "entry (export) table corrupt")
            }
            Error::UnsupportedFixupSource(ty) => {
                write!(
                    f,
                    "fixup record source type {ty} is left undefined by the format, so the \
                     record has no length"
                )
            }
            Error::PageDataCorrupt => {
                write!(f, "page data corrupt: decoded stream overruns its bounds")
            }
            Error::UnsupportedPageType(ty) => {
                write!(f, "unsupported page type: {ty}")
            }
            Error::UnsupportedCodec(codec) => {
                write!(
                    f,
                    "unsupported W4 compression codec: {:?} (0x{codec:04X})",
                    core::str::from_utf8(&codec.to_le_bytes()).unwrap_or("?")
                )
            }
            Error::ArchiveCorrupt(what) => {
                write!(f, "archive corrupt: {what}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(feature = "std")]
            Error::IoError(e) => Some(e),
            #[cfg(feature = "std")]
            Error::Utf8Error(e) => Some(e),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// DOS MZ signature
pub const DOS_SIGNATURE: u16 = 0x5A4D; // "MZ" in little-endian

/// LE signature ("LE" in little-endian)
pub const LE_SIGNATURE: u16 = 0x454C;

/// LX signature ("LX" in little-endian)
pub const LX_SIGNATURE: u16 = 0x584C;

/// W3 archive signature (byte string "W3")
pub const W3_SIGNATURE: &[u8; 2] = b"W3";

/// W4 archive signature (byte string "W4")
pub const W4_SIGNATURE: &[u8; 2] = b"W4";

/// LE/LX header size on disk: 0xB0 bytes (180), uniform for LE and LX.
pub const LE_HEADER_SIZE: usize = 0xB0;

/// Size of the optional region that follows the 0xB0-byte header, i.e.
/// header-relative `0xB0..=0xC3`: `e32_res3[12]`, `e32_winresoff`,
/// `e32_winreslen`, `e32_devid`, `e32_ddkver` in Wine's `IMAGE_VXD_HEADER`
/// (whose header is therefore 0xC4 bytes).
///
/// [`LE::get_header_tail`]: crate::le::LE::get_header_tail
pub const LE_HEADER_TAIL_SIZE: usize = 0x14;

/// Size of one object-table record: 24 bytes (6 x u32)
pub const OBJECT_RECORD_SIZE: usize = 24;

/// Size of one LE object-page-table entry: 4 bytes
/// (3-byte big-endian file page number + 1-byte flags)
pub const LE_PAGE_ENTRY_SIZE: usize = 4;

/// Size of one LX object-page-table entry: 8 bytes
/// (u32 data offset + u16 data size + u16 flags)
pub const LX_PAGE_ENTRY_SIZE: usize = 8;

/// Offset of `e_lfanew` within the DOS header
pub const DOS_E_LFANEW_OFFSET: usize = 0x3C;

// ---------------------------------------------------------------------------
// Utility: align to boundary
// ---------------------------------------------------------------------------

/// Align `value` up to the next multiple of `boundary`.
///
/// `boundary` must be a power of two.
#[must_use]
pub fn align(value: usize, boundary: usize) -> usize {
    debug_assert!(
        boundary.is_power_of_two(),
        "boundary must be a power of two"
    );
    (value + boundary - 1) & !(boundary - 1)
}

// ---------------------------------------------------------------------------
// Fixture helper for doc examples
// ---------------------------------------------------------------------------

/// Bytes of the golden fixture `testdata/fixtures/hallasm.BIN`, or `None`
/// when it is not available in this build/checkout.
///
/// Every example in these docs that wants a *real* LE file uses this guard:
///
/// ```text
/// # let Some(bytes) = linear_executable::doc_fixture() else { return };
/// ```
///
/// Mirrors `doc_fixture()` from the sibling `ne` crate (ne-rs): the fixture
/// ships with the source repository but is deliberately **excluded from the
/// published crate** (`include` in `Cargo.toml`) — uploading raw 16/32-bit
/// `.exe` blobs to a package registry trips antivirus scanners on download.
#[must_use]
pub fn doc_fixture() -> Option<Vec<u8>> {
    fixture_impl()
}

#[cfg(all(feature = "std", feature = "fixtures"))]
fn fixture_impl() -> Option<Vec<u8>> {
    std::fs::read("testdata/fixtures/hallasm.BIN").ok()
}

#[cfg(not(all(feature = "std", feature = "fixtures")))]
fn fixture_impl() -> Option<Vec<u8>> {
    None
}
