// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
// //! NE header structures and constants.
//!
//! All structures are `#[repr(C, packed)]` — they match the on-disk NE format
//! byte-for-byte. Modifications via `get_mut_ne_header_ref()` are in-place
//! (zero-copy).
//!
//! # Warning
//!
//! These structs are intentionally ABI-layout-specific. Do not rely on their
//! size or layout being stable across Rust versions or targets — they are
//! designed to map directly to the on-disk NE file format.

use bitflags::bitflags;
use core::fmt;

use crate::{NE_HEADER_SIZE_V4, NE_HEADER_SIZE_V5};

// ---------------------------------------------------------------------------
// NE Executable Type (ne_exetyp)
// ---------------------------------------------------------------------------

/// Target operating system for this NE file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ExeType {
    /// Invalid or unknown executable type
    Invalid = 0,
    /// OS/2 16-bit
    Os2 = 1,
    /// Windows 16-bit
    Win = 2,
}

impl ExeType {
    /// Try to create from a raw u8 value.
    ///
    /// Valid values: 0 = Windows, 1 = OS/2, 2 = Windows 16-bit.
    /// Values 3 (DOS 4), 4 (Windows/386), and higher are treated as invalid
    /// for forward compatibility.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(ExeType::Os2),
            2 => Some(ExeType::Win),
            // 0 = Windows (per NE_FORMAT.md), 3 = DOS 4, 4 = Windows/386,
            // 5+ = reserved — all map to Invalid for forward compatibility.
            _ => Some(ExeType::Invalid),
        }
    }

    /// Try to create from a raw u16 value (legacy API).
    ///
    /// # Safety
    ///
    /// Values above `u8::MAX` are truncated to `u8`.
    #[must_use]
    pub fn from_u16(value: u16) -> Option<Self> {
        #[allow(clippy::cast_possible_truncation)]
        Self::from_u8(value as u8)
    }
}

impl fmt::Display for ExeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExeType::Invalid => write!(f, "Invalid"),
            ExeType::Os2 => write!(f, "OS/2 16-bit"),
            ExeType::Win => write!(f, "Windows 16-bit"),
        }
    }
}

// ---------------------------------------------------------------------------
// NE Flags (ne_flags) — Microsoft SDK on-disk format
// ---------------------------------------------------------------------------

bitflags! {
    /// NE module flags (header offset 0x0C)
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NeFlags: u16 {
        /// SINGLEDATA: module has one data segment; set for DLLs.
        const SINGLEDATA = 0x0001;

        /// MULTIPLEDATA: module has multiple data segments;
        /// set for Windows applications.
        const MULTIPLEDATA = 0x0002;

        /// First segment contains code that loads the application.
        const FIRST_SEG_CONTAINS_LOADER = 0x0800;

        /// Linker detected errors at link time but created the file anyway.
        const LINKER_ERRORS = 0x2000;

        /// Library module (DLL): CS:IP points to an initialization
        /// procedure that performs a far return.
        const LIBRARY = 0x8000;
    }
}

// ---------------------------------------------------------------------------
// Segment Flags (on-disk, Microsoft SDK format)
// ---------------------------------------------------------------------------

bitflags! {
    /// Segment flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SegmentFlags: u16 {
        /// Data segment (as opposed to code)
        const DATA = 0x0001;

        /// Allocated segment
        const ALLOCATED = 0x0002;

        /// Loaded segment
        const LOADED = 0x0004;

        /// Iterated segment
        const ITERATED = 0x0008;

        /// Moveable segment
        const MOVEABLE = 0x0010;

        /// Shareable segment (can be mapped to multiple tasks)
        const SHAREABLE = 0x0020;

        /// Preloaded segment (loaded even if not referenced)
        const PRELOAD = 0x0040;

        /// Read-only / execute-only segment
        const READONLY = 0x0080;

        /// Segment needs relocation data
        const RELOC_DATA = 0x0100;

        /// Segment selfloads (loaded at any address)
        const SELFLOAD = 0x0800;

        /// Discardable segment
        const DISCARDABLE = 0x1000;

        /// 32-bit segment
        const FLAGS32BIT = 0x2000;

        /// Apply flags mask
        const FLAGS_MASK = 0xFFFF;
    }
}

// ---------------------------------------------------------------------------
// Segment Alignment
// ---------------------------------------------------------------------------

/// NE sector alignment, as encoded by the header's `alignment` field
/// (offset 0x32).
///
/// The field is a **shift count**: the logical sector size is
/// `1 << shift` bytes. It is typically 4 (/a:16 → 16-byte sectors)
//  and defaults to 9 (/a:512 → 512-byte sectors).
/// Segment record `offset` fields are expressed in these sectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SegmentAlignment {
    /// 1-byte sectors (shift 0)
    Shift0 = 0,
    /// 2-byte sectors (shift 1)
    Shift1 = 1,
    /// 4-byte sectors (shift 2)
    Shift2 = 2,
    /// 8-byte sectors (shift 3)
    Shift3 = 3,
    /// 16-byte sectors (shift 4, /a:16 — the typical value)
    Shift4 = 4,
    /// 32-byte sectors (shift 5)
    Shift5 = 5,
    /// Any other shift count (e.g. 9 = 512-byte sectors, the default)
    Reserved(u8),
}

impl SegmentAlignment {
    /// Try to create from a raw u8 shift count.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(SegmentAlignment::Shift0),
            1 => Some(SegmentAlignment::Shift1),
            2 => Some(SegmentAlignment::Shift2),
            3 => Some(SegmentAlignment::Shift3),
            4 => Some(SegmentAlignment::Shift4),
            5 => Some(SegmentAlignment::Shift5),
            v => Some(SegmentAlignment::Reserved(v)),
        }
    }

    /// The raw shift count.
    #[must_use]
    pub fn shift(&self) -> u32 {
        match self {
            SegmentAlignment::Shift0 => 0,
            SegmentAlignment::Shift1 => 1,
            SegmentAlignment::Shift2 => 2,
            SegmentAlignment::Shift3 => 3,
            SegmentAlignment::Shift4 => 4,
            SegmentAlignment::Shift5 => 5,
            SegmentAlignment::Reserved(v) => u32::from(*v),
        }
    }

    /// The sector size in bytes (`1 << shift`), saturating on overflow.
    #[must_use]
    pub fn alignment_bytes(&self) -> usize {
        1usize.checked_shl(self.shift()).unwrap_or(usize::MAX)
    }
}

// ---------------------------------------------------------------------------
// Segment Combine Type
// ---------------------------------------------------------------------------

/// How segments of the same name are combined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SegmentCombine {
    /// Null (no combining)
    Null = 0,
    /// System (OS/2)
    System = 1,
    /// Common (shared data)
    Common = 2,
    /// Public (standard combining)
    Public = 3,
    /// Unused (4-7 are reserved)
    Reserved(u8),
}

impl SegmentCombine {
    /// Try to create from a raw u8 value.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(SegmentCombine::Null),
            1 => Some(SegmentCombine::System),
            2 => Some(SegmentCombine::Common),
            3 => Some(SegmentCombine::Public),
            v => Some(SegmentCombine::Reserved(v)),
        }
    }
}

// ---------------------------------------------------------------------------
// IMAGE_OS2_HEADER — NE Header
// ---------------------------------------------------------------------------

/// The NE (New Executable) header structure.
///
/// This is a **single 64-byte struct** matching the Windows
/// `IMAGE_OS2_HEADER` layout (offsets 0x00-0x3F; last field
/// `expected_version` at 0x3E). True v4 (OS/2 1.x) headers are 60 bytes
/// on disk; the trailing fields at offsets 0x3C-0x3F (`swap_area`,
/// `expected_version`) do not exist there and must only be accessed
/// after confirming the header is v5.
///
/// # Version Detection
///
/// See `ImageOS2Header::is_v5()`: the linker version (major >= 5) is
/// authoritative. There is no `hdrsize` field and no version flag bit.
///
/// # Layout
///
/// This struct is `#[repr(C, packed)]` and matches the on-disk NE format
/// byte-for-byte. Modifications are in-place via `get_mut_ne_header_ref()`.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ImageOS2Header {
    // --- NE header fields (offsets 0x00-0x3F, matching the Windows 3.1 SDK) ---
    /// "NE" signature (little-endian 0x454E) — always present
    pub signature: u16,

    /// Linker version (high nibble) — actually:
    /// bytes 0x02 and 0x03 in the spec
    pub linker_version: u8,

    /// Linker minor version
    pub linker_minor_version: u8,

    /// Entry table offset (RVA from start of NE header)
    pub entry_table_offset: u16,

    /// Entry table size
    pub entry_table_size: u16,

    /// Checksum (CRC32 of header, zero during calculation)
    pub checksum: u32,

    /// Flags (`ne_flags`)
    pub flags: u16,

    /// Automatic data segment selector
    pub auto_data_sel: u16,

    /// Initial heap value
    pub heap_init: u16,

    /// Initial stack value
    pub stack_init: u16,

    /// Initial CS:IP — selector in high16, offset in low16 (u32, little-endian).
    /// e.g. CS=0x0001, IP=0x001A → 0x0001001A
    pub csip: u32,

    /// Initial SS:SP — selector in high16, offset in low16 (u32, little-endian).
    /// e.g. SS=0x0002, SP=0x0000 → 0x00020000
    pub sssp: u32,

    /// Segment count (1-based)
    pub seg_count: u16,

    /// Module reference count
    pub mod_count: u16,

    /// Non-resident name table size
    pub non_res_name_size: u16,

    /// Segment table offset (RVA from start of NE header)
    pub seg_table_offset: u16,

    /// Resource table offset (RVA from start of NE header)
    pub resource_table_offset: u16,

    /// Resident name table offset (RVA from start of NE header)
    pub res_name_table_offset: u16,

    /// Module reference table offset (RVA from start of NE header)
    pub mod_table_offset: u16,

    /// Imported names table offset (RVA from start of NE header)
    pub imported_names_table_offset: u16,

    /// Non-resident name table offset (FILE offset from start of file —
    /// the only table pointer that is not NE-header-relative)
    pub non_res_name_table_offset: u32,

    /// Internal entry table entries
    pub mod_internal_entries: u16,

    /// Alignment shift count
    pub alignment: u16,

    /// Resource count
    pub resource_count: u16,

    /// Execution type (`ne_exetyp`, 1 byte)
    pub exe_type: u8,

    /// Other flags (1 byte)
    pub other_flags: u8,

    /// Return thunk offset / start of gangload area (present in v4 too)
    pub ret_thunk_offset: u16,

    /// Segment reference bytes offset / gangload size (present in v4 too)
    pub seg_ref_bytes_offset: u16,

    /// Swap area (NE v5 only; absent on disk in 60-byte v4 headers)
    pub swap_area: u16,

    /// Expected Windows version (NE v5 only; absent on disk in 60-byte v4
    /// headers — reads back as zero there)
    pub expected_version: u16,
}

impl ImageOS2Header {
    /// Size of this header in bytes on disk.
    ///
    /// Returns `NE_HEADER_SIZE_V5` (64, SDK layout) for v5 headers or
    /// `NE_HEADER_SIZE_V4` (60) for v4 (OS/2 1.x) headers.
    /// Note: the Rust struct itself is always 64 bytes.
    #[must_use]
    pub fn header_size(&self) -> usize {
        if self.is_v5() {
            NE_HEADER_SIZE_V5
        } else {
            NE_HEADER_SIZE_V4
        }
    }

    /// Check if this is an NE v5 header (64-byte SDK layout).
    ///
    /// Detection is based on the linker version: major >= 5 means v5.
    /// There is no version flag bit — the flags bit 0 (0x0001) is
    /// SINGLEDATA and must not be used here.
    #[must_use]
    pub fn is_v5(&self) -> bool {
        self.linker_version >= 5
    }

    /// Get the executable type (OS/2 vs Windows).
    #[must_use]
    pub fn exe_type(&self) -> ExeType {
        ExeType::from_u8(self.exe_type).unwrap_or(ExeType::Invalid)
    }

    /// Get the version as a string.
    #[must_use]
    pub fn version(&self) -> &'static str {
        if self.is_v5() {
            "NE v5 (Windows 3.1)"
        } else {
            "NE v4 (OS/2)"
        }
    }

    /// Ensure this header is v5. Returns `Error::HeaderVersionMismatch` if not.
    pub fn ensure_v5(&self) -> Result<(), crate::Error> {
        if self.is_v5() {
            Ok(())
        } else {
            Err(crate::Error::HeaderVersionMismatch)
        }
    }

    /// Get v5-only fields (only valid for v5 headers).
    ///
    /// `swap_area` (0x3C) and `expected_version` (0x3E) do not exist on
    /// disk in 60-byte v4 headers and read back as zero there.
    #[must_use]
    pub fn v5_fields(&self) -> Option<V5Fields> {
        if self.is_v5() {
            Some(V5Fields {
                swap_area: self.swap_area,
                expected_version: self.expected_version,
            })
        } else {
            None
        }
    }

    /// Get common (v4) fields — valid for all NE headers.
    #[must_use]
    pub fn common_fields(&self) -> CommonFields {
        CommonFields {
            linker_version: self.linker_version,
            linker_minor_version: self.linker_minor_version,
            entry_table_offset: self.entry_table_offset,
            entry_table_size: self.entry_table_size,
            checksum: self.checksum,
            flags: self.flags,
            auto_data_sel: self.auto_data_sel,
            heap_init: self.heap_init,
            stack_init: self.stack_init,
            csip: self.csip,
            sssp: self.sssp,
            seg_count: self.seg_count,
            mod_count: self.mod_count,
            non_res_name_size: self.non_res_name_size,
            seg_table_offset: self.seg_table_offset,
            resource_table_offset: self.resource_table_offset,
            res_name_table_offset: self.res_name_table_offset,
            mod_table_offset: self.mod_table_offset,
            imported_names_table_offset: self.imported_names_table_offset,
            non_res_name_table_offset: self.non_res_name_table_offset,
            mod_internal_entries: self.mod_internal_entries,
            alignment: self.alignment,
            resource_count: self.resource_count,
            exe_type: self.exe_type,
            other_flags: self.other_flags,
            ret_thunk_offset: self.ret_thunk_offset,
            seg_ref_bytes_offset: self.seg_ref_bytes_offset,
        }
    }
}

// SAFETY: This struct is `#[repr(C, packed)]` with only primitive fields.
// It is used for zero-copy access to NE header data from a buffer.
unsafe impl Send for ImageOS2Header {}
unsafe impl Sync for ImageOS2Header {}

/// Common (v4/v5) header fields — valid for all NE headers.
///
/// Includes `ret_thunk_offset` and `seg_ref_bytes_offset` (offsets 0x38
/// and 0x3A), which are part of the 60-byte v4 header as well.
#[derive(Debug, Clone, Copy)]
pub struct CommonFields {
    pub linker_version: u8,
    pub linker_minor_version: u8,
    pub entry_table_offset: u16,
    pub entry_table_size: u16,
    pub checksum: u32,
    pub flags: u16,
    pub auto_data_sel: u16,
    pub heap_init: u16,
    pub stack_init: u16,
    pub csip: u32,
    pub sssp: u32,
    pub seg_count: u16,
    pub mod_count: u16,
    pub non_res_name_size: u16,
    pub seg_table_offset: u16,
    pub resource_table_offset: u16,
    pub res_name_table_offset: u16,
    pub mod_table_offset: u16,
    pub imported_names_table_offset: u16,
    pub non_res_name_table_offset: u32,
    pub mod_internal_entries: u16,
    pub alignment: u16,
    pub resource_count: u16,
    pub exe_type: u8,
    pub other_flags: u8,
    pub ret_thunk_offset: u16,
    pub seg_ref_bytes_offset: u16,
}

/// v5-only header fields (NE v5 / Windows 3.1).
///
/// These two fields (offsets 0x3C-0x3F) are absent on disk in 60-byte v4
/// headers.
#[derive(Debug, Clone, Copy)]
pub struct V5Fields {
    pub swap_area: u16,
    pub expected_version: u16,
}

// ---------------------------------------------------------------------------
// Segment Record (8 bytes)
// ---------------------------------------------------------------------------

/// Segment record in the NE segment table (8 bytes on disk).
///
/// This matches the Wine source `struct ne_segment_table_entry_s`:
/// `seg_data_offset`, `seg_data_length`, `seg_flags`, `min_alloc`.
///
/// `#[repr(C, packed)]` — matches the on-disk format byte-for-byte.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SegmentRecord {
    /// Segment data offset as a sector offset relative to file start (byte 0).
    /// NOT an RVA. Convert to file offset with: `sector_offset << alignment_shift`.
    pub offset: u16,

    /// Length of segment data on disk.
    pub length: u16,

    /// Segment flags (`SegmentFlags` bitflags).
    pub flags: u16,

    /// Minimum memory allocation size for this segment.
    pub minalloc: u16,
}

// SAFETY: This struct is `#[repr(C, packed)]` with only primitive fields.
unsafe impl Send for SegmentRecord {}
unsafe impl Sync for SegmentRecord {}

impl SegmentRecord {
    /// Get the segment flags as a bitflags struct.
    #[must_use]
    pub fn segment_flags(&self) -> SegmentFlags {
        SegmentFlags::from_bits_truncate(self.flags)
    }

    /// Is this a data segment?
    #[must_use]
    pub fn is_data(&self) -> bool {
        self.segment_flags().contains(SegmentFlags::DATA)
    }

    /// Is this a moveable segment?
    #[must_use]
    pub fn is_moveable(&self) -> bool {
        self.segment_flags().contains(SegmentFlags::MOVEABLE)
    }

    /// Is this a shareable segment?
    #[must_use]
    pub fn is_shared(&self) -> bool {
        self.segment_flags().contains(SegmentFlags::SHAREABLE)
    }

    /// Is this a discardable segment?
    #[must_use]
    pub fn is_discardable(&self) -> bool {
        self.segment_flags().contains(SegmentFlags::DISCARDABLE)
    }

    /// Segment data sector offset relative to file start.
    /// NOT an RVA. Convert to file offset with: `offset << alignment_shift`.
    #[must_use]
    pub fn offset(&self) -> u16 {
        self.offset
    }

    /// Length of segment data on disk.
    #[must_use]
    pub fn length(&self) -> u16 {
        self.length
    }

    /// Minimum memory allocation size.
    #[must_use]
    pub fn minalloc(&self) -> u16 {
        self.minalloc
    }
}
