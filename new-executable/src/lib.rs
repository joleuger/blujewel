// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! # new-executable — NE (New Executable) Format Parser
//!
//! A Rust library for parsing NE (New Executable) format files used by
//! Windows 16-bit and OS/2 16-bit.
//!
//! ## Features
//!
//! - **Parsing**: NE headers, segment tables, entry tables (exports),
//!   module references, imported names, resident names, resources, relocations
//! - **Zero-copy header access**: `get_ne_header_ref()` returns `&ImageOS2Header`
//!   directly from the underlying buffer
//! - **`no_std` support**: Compile without the standard library
//! - **Feature flags**: `alloc` for heap allocation in `no_std`, `hash` for MD5/SHA,
//!   `validation` for CRC32 checksum verification
//!
//! ## Quick Start
//!
//! ```
//! // The examples in these docs run against the shipped golden fixture,
//! // DUALBTN.bin, when it is available (`fixtures` feature) and skip
//! // gracefully when it is not — see [`doc_fixture`].
//! # let Some(bytes) = ne::doc_fixture() else { return };
//! use ne::{VecNE, NE};
//!
//! let ne = VecNE::from_memory(bytes);
//! let header = ne.get_valid_ne_header().unwrap();
//! assert_eq!(header.version(), "NE v5 (Windows 3.1)");
//!
//! // Tables are parsed on demand
//! let segments = ne.get_segment_table().unwrap();
//! assert_eq!(segments.len(), 2);
//! let entry_table = ne::types::EntryTable::parse(&ne).unwrap();
//! ```
//!
//! ## `no_std` Usage
//!
//! ```toml
//! [dependencies]
//! ne = { version = "0.1", default-features = false }
//! ```
//!
//! In `no_std` mode (with the `alloc` feature), parsed strings are borrowed
//! from the NE buffer (`PascalString`).

#![no_std]
#![cfg_attr(feature = "std", allow(unused_imports))]
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

#[cfg(feature = "std")]
extern crate core;

// Unit tests link std via the test harness even in no_std builds, so the
// test module can use `std::...` paths under `--features alloc` alone.
#[cfg(all(test, not(feature = "std")))]
extern crate std;

// The public API returns heap-allocated data (Vec); at least one of
// `std` or `alloc` must be enabled.
#[cfg(not(any(feature = "std", feature = "alloc")))]
compile_error!(
    "the `ne` crate requires the `std` or `alloc` feature: the public API \
     returns heap-allocated data (Vec). Use `--features alloc` for no_std builds."
);

// Re-export Vec (and HashSet, std-only — `alloc::collections` has no
// HashSet) for use in other modules.
#[cfg(all(feature = "alloc", not(feature = "std")))]
pub use alloc::vec::Vec;
#[cfg(feature = "std")]
pub use std::collections::HashSet;
#[cfg(feature = "std")]
pub use std::vec::Vec;

// Public modules
pub mod headers;
pub mod ne;
pub mod types;

// Disassembly facts layer (see DISASM_PLAN.md). Gated so a build without
// `disasm` contains neither this module nor iced-x86. Not re-exported at
// the crate root: its names (`Syntax`, `Listing`, …) stay module-scoped.
#[cfg(feature = "disasm")]
pub mod disasm;

// OMF import-library reader (see OMF.md). Gated because it is analysis-side
// data: a loader needs none of it. Not re-exported at the crate root either.
#[cfg(feature = "omf")]
pub mod omf;

#[cfg(test)]
mod tests;

// Re-export key types at crate root
pub use headers::*;
pub use ne::*;
pub use types::*;

// ---------------------------------------------------------------------------
// Error enum
// ---------------------------------------------------------------------------

use core::fmt;

/// Error types for NE parsing operations.
///
/// In `std` mode, `IoError` and `Utf8Error` variants carry their std counterparts.
/// In `no_std` mode, these variants are unavailable.
///
/// All NE-defined enums include an `Unknown(u8)` variant for forward compatibility.
/// Enums are marked `#[non_exhaustive]` to prevent breakage when new variants are
/// added in future Rust releases.
#[derive(Debug)]
pub enum Error {
    /// I/O error (only available with `std` feature)
    #[cfg(feature = "std")]
    IoError(std::io::Error),

    /// UTF-8 validation error (only available with `std` feature)
    #[cfg(feature = "std")]
    Utf8Error(std::str::Utf8Error),

    /// The file does not start with MZ signature
    InvalidDOSSignature(u16),

    /// The file does not have NE signature at the expected offset
    InvalidNESignature(u16),

    /// Header field offset is out of bounds
    HeaderOutOfBounds(usize),

    /// File too short to contain claimed header size
    HeaderTooSmall,

    /// Header version indicators are inconsistent (ambiguous v4 vs v5 detection)
    HeaderVersionMismatch,

    /// Header data truncated mid-parse (offset, `expected_size`)
    HeaderTruncated(usize, usize),

    /// Segment number not found
    SegmentNotFound(u16),

    /// Entry ordinal not found
    EntryNotFound(u16),

    /// Resource not found
    ResourceNotFound,

    /// Entry table parsing error (malformed bundle chain, cycle detected, or overflow)
    EntryTableCorrupt,

    /// Invalid resident name (Pascal string exceeds buffer, not valid ASCII/UTF-8)
    InvalidPascalString,

    /// Table offset is zero (table not present)
    TableNotPresent(&'static str),

    /// Out of bounds reading table data (`table_name`, offset, bound)
    TableOutOfBounds(&'static str, usize, usize),

    /// Bundle chain exceeded maximum length (`u16::MAX` entries)
    EntryTableOverflow,

    /// A relocation chain contains a cycle (a link points back to an
    /// already-visited position within the segment)
    RelocationChainCorrupt,

    /// Resource offset alignment shift value is invalid
    InvalidResourceAlignment(u16),

    /// DOS header is too short to contain the fields that need validating
    ///
    /// NOTE: `e_lfarlc` (0x18) is 0x40 in every corpus file but is NOT used
    /// for NE detection. The only reliable NE detection is the `NE`
    /// signature at `e_lfanew` (u32, DOS header offset 0x3C).
    InvalidDOSStubFields,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "std")]
            Error::IoError(e) => write!(f, "I/O error: {e}"),
            #[cfg(feature = "std")]
            Error::Utf8Error(e) => write!(f, "UTF-8 error: {e}"),
            Error::InvalidDOSSignature(sig) => {
                write!(f, "invalid DOS signature: 0x{sig:04X} (expected 0x5A4D)")
            }
            Error::InvalidNESignature(sig) => {
                write!(
                    f,
                    "invalid NE signature at offset: 0x{sig:04X} (expected 0x0045)"
                )
            }
            Error::HeaderOutOfBounds(offset) => {
                write!(f, "header field offset 0x{offset:04X} is out of bounds")
            }
            Error::HeaderTooSmall => {
                write!(f, "file too short to contain claimed header size")
            }
            Error::HeaderVersionMismatch => {
                write!(f, "header version indicators are inconsistent (v4 vs v5)")
            }
            Error::HeaderTruncated(offset, expected) => {
                write!(
                    f,
                    "header truncated at offset 0x{offset:04X}, expected {expected} bytes"
                )
            }
            Error::SegmentNotFound(seg) => {
                write!(f, "segment number {seg} not found")
            }
            Error::EntryNotFound(ordinal) => {
                write!(f, "entry ordinal {ordinal} not found")
            }
            Error::ResourceNotFound => {
                write!(f, "resource not found")
            }
            Error::EntryTableCorrupt => {
                write!(f, "entry table corrupt: malformed bundle chain")
            }
            Error::InvalidPascalString => {
                write!(
                    f,
                    "invalid Pascal string: exceeds buffer or not valid ASCII"
                )
            }
            Error::TableNotPresent(name) => {
                write!(f, "table not present: {name}")
            }
            Error::TableOutOfBounds(name, offset, bound) => {
                write!(
                    f,
                    "table '{name}' out of bounds: offset 0x{offset:04X} (bound 0x{bound:04X})"
                )
            }
            Error::EntryTableOverflow => {
                write!(f, "entry table bundle chain exceeded maximum length")
            }
            Error::RelocationChainCorrupt => {
                write!(f, "relocation chain corrupt: cycle detected in segment")
            }
            Error::InvalidResourceAlignment(shift) => {
                write!(f, "invalid resource alignment shift: {shift} (must be > 0)")
            }
            Error::InvalidDOSStubFields => {
                write!(
                    f,
                    "invalid DOS stub fields: file too short to contain DOS header (e_lfarlc is not used for NE detection)"
                )
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

/// NE signature ("NE" in little-endian, same for v4 and v5)
pub const NE_SIGNATURE: u16 = 0x454E;

/// Maximum bundle chain length to prevent infinite loops
pub const MAX_BUNDLE_CHAIN_LENGTH: u16 = u16::MAX;

/// Default resource alignment shift (4-byte alignment → shift = 2)
pub const DEFAULT_RESOURCE_ALIGNMENT_SHIFT: u16 = 2;

/// NE header size on disk for v4 files (OS/2 1.x): 60 bytes (0x00-0x3B).
///
/// The v4 layout is the v5 layout minus the trailing 4 bytes
/// (`swap_area` at 0x3C and `expected_version` at 0x3E, both v5-only).
/// No v4 fixtures exist in the test corpus; the 60-byte size follows the
/// Open Watcom `exeos2.h` definition.
///
/// Note: the `ImageOS2Header` struct is always the full 64-byte SDK layout;
/// for v4 files the trailing 4 bytes (v5-only fields) do not exist on disk
/// and read back as zero.
pub const NE_HEADER_SIZE_V4: usize = 60;

/// NE header size on disk for v5 files (Windows `IMAGE_OS2_HEADER`):
/// 64 bytes (0x00-0x3F). This is also `size_of::<ImageOS2Header>()`.
///
/// All Windows NE files in the reference corpus use this layout uniformly.
/// Version detection is by linker version (major >= 5), not by any flag bit.
pub const NE_HEADER_SIZE_V5: usize = 64;

/// Minimum DOS header size
pub const DOS_HEADER_SIZE: usize = 64;

/// Offset of `e_lfanew` within DOS header
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

/// Bytes of the golden fixture `testdata/fixtures/DUALBTN.bin`, or `None`
/// when it is not available in this build/checkout.
///
/// Every example in these docs that wants a *real* NE file uses this guard:
///
/// ```text
/// # let Some(bytes) = ne::doc_fixture() else { return };
/// ```
///
/// # Why does this exist?
///
/// The examples are more useful when they assert against a genuine NE file
/// (DUALBTN.bin, fully annotated in `example.md`) instead of hand-tuned
/// synthetic bytes. The fixture ships with the source repository, but it is
/// deliberately **excluded from the published crate** (`include` in
/// `Cargo.toml`): uploading raw 16-bit `.exe` blobs to a package registry
/// trips antivirus scanners on download, so the published crate carries no
/// binary test data at all. That safety property and always-runnable
/// examples cannot both have the published crate — so the examples deal in
/// facts on the real file *when present* and skip cleanly when not. This
/// function is the single switch that encodes that trade-off.
///
/// # Why is it public?
///
/// Doc examples compile as separate crates that link only the *public* API,
/// so the helper cannot be private. It is **not** part of the NE-parsing
/// API — application code should never call it.
///
/// # When does it return `Some`?
///
/// Only when all of: the `std` and `fixtures` features are enabled (the
/// standard repo verification run `cargo test --features fixtures`), and the
/// file is readable from the crate checkout. Published-crate builds never
/// satisfy this, so examples skip there — never fail.
#[must_use]
pub fn doc_fixture() -> Option<Vec<u8>> {
    fixture_impl()
}

#[cfg(all(feature = "std", feature = "fixtures"))]
fn fixture_impl() -> Option<Vec<u8>> {
    // Same location the `fixtures` test suite uses: `cargo test` runs with
    // the crate root as working directory. Missing file → None, not panic.
    std::fs::read("testdata/fixtures/DUALBTN.bin").ok()
}

#[cfg(not(all(feature = "std", feature = "fixtures")))]
fn fixture_impl() -> Option<Vec<u8>> {
    None
}

/// Bytes of the OMF fixture `testdata/fixtures/SIMPLIB_LIB.BIN`, or `None`
/// when it is not available in this build/checkout.
///
/// Same contract and same reasoning as [`doc_fixture`]: used by the
/// `ne::omf` doc examples, present only in a repo checkout with `std` +
/// `fixtures`, never in the published crate.
#[must_use]
pub fn doc_omf_library() -> Option<Vec<u8>> {
    omf_fixture_impl()
}

#[cfg(all(feature = "std", feature = "fixtures"))]
fn omf_fixture_impl() -> Option<Vec<u8>> {
    std::fs::read("testdata/fixtures/SIMPLIB_LIB.BIN").ok()
}

#[cfg(not(all(feature = "std", feature = "fixtures")))]
fn omf_fixture_impl() -> Option<Vec<u8>> {
    None
}

// ---------------------------------------------------------------------------
// Hash utilities (optional, gated by `hash` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "hash")]
pub mod hash {
    //! Hash utilities for NE files.
    //!
    //! Provides MD5, SHA1, and SHA256 hashing on NE buffer data.
    //! Same interface as exe-rs's `HashData` and `Entropy` traits.
    //!
    //! NE files do not have an imphash equivalent — import resolution works
    //! fundamentally differently (Pascal strings, module refs, no IAT thunks).

    use md5::Md5;
    use sha1::Sha1;
    use sha2::{Digest, Sha256};

    /// Hash data using MD5
    ///
    /// # Examples
    ///
    /// ```
    /// let digest = ne::hash::md5(b"NE"); // the NE signature bytes
    /// let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    /// assert_eq!(hex, "dc33066c3993e0d50896e533fd692ce0");
    /// ```
    #[must_use]
    pub fn md5(data: &[u8]) -> [u8; 16] {
        Md5::digest(data).into()
    }

    /// Hash data using SHA1
    #[must_use]
    pub fn sha1(data: &[u8]) -> [u8; 20] {
        Sha1::digest(data).into()
    }

    /// Hash data using SHA256
    #[must_use]
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    /// Calculate Shannon entropy of data
    #[must_use]
    pub fn entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0u32; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        #[allow(clippy::cast_precision_loss)]
        let len = data.len() as f64;
        let mut ent = 0.0;
        for &count in &freq {
            if count == 0 {
                continue;
            }
            let p = f64::from(count) / len;
            ent -= p * p.log2();
        }
        ent
    }
}

#[cfg(feature = "hash")]
pub use hash::entropy;
