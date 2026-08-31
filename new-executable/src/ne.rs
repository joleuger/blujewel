// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! Core NE buffer abstraction.
//!
//! Defines the `Buffer` trait (raw data access), the `NE` trait (NE-specific operations),
//! and the two buffer implementations: `VecNE` and `PtrNE<'a>`.

use crate::{
    headers::{ImageOS2Header, NeFlags, SegmentRecord},
    Error, DOS_E_LFANEW_OFFSET, DOS_HEADER_SIZE, DOS_SIGNATURE, NE_HEADER_SIZE_V4,
    NE_HEADER_SIZE_V5, NE_SIGNATURE,
};
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

/// Minimum size of a valid NE file (DOS header + minimum v4 NE header).
pub const MIN_NE_FILE_SIZE: usize = DOS_HEADER_SIZE + NE_HEADER_SIZE_V4;

/// DOS header offset of the `e_lfarlc` field (stub relocation table).
/// Per the DOS header layout this is at offset 0x18 (0x16 is `e_cs`).
/// NOTE: This field is NOT reliable for NE detection — it is 0x40 in every
/// corpus file, but the only reliable NE detection is the `NE` signature
/// at `e_lfanew` (a u32 at DOS header offset 0x3C).
pub const DOS_E_LFARLC_OFFSET: usize = 0x18;

// ---------------------------------------------------------------------------
// Buffer trait
// ---------------------------------------------------------------------------

/// Raw byte buffer access for NE parsing.
///
/// This is the foundational trait that all NE buffer types implement.
/// It provides safe access to the underlying byte data by offset and length.
pub trait Buffer {
    /// Get a slice of bytes from the buffer at the given offset and length.
    ///
    /// Returns `Error::HeaderOutOfBounds` if the requested range extends
    /// past the end of the buffer.
    fn get_slice(&self, offset: usize, len: usize) -> Result<&[u8], Error>;

    /// Get the total length of the buffer in bytes.
    fn len(&self) -> usize;

    /// Check if the buffer is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read a single byte from the buffer.
    fn read_u8(&self, offset: usize) -> Result<u8, Error> {
        let bytes = self.get_slice(offset, 1)?;
        Ok(bytes[0])
    }

    /// Read a little-endian u16 from the buffer.
    fn read_u16(&self, offset: usize) -> Result<u16, Error> {
        let bytes = self.get_slice(offset, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Read a little-endian u32 from the buffer.
    fn read_u32(&self, offset: usize) -> Result<u32, Error> {
        let bytes = self.get_slice(offset, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a little-endian u64 from the buffer.
    fn read_u64(&self, offset: usize) -> Result<u64, Error> {
        let bytes = self.get_slice(offset, 8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }
}

// ---------------------------------------------------------------------------
// NE trait — all NE-specific operations
// ---------------------------------------------------------------------------

/// NE-specific operations trait.
///
/// All NE parsing flows through this trait. It provides header access,
/// segment table operations, logical address translation, and convenience
/// accessors for table offsets.
pub trait NE: Buffer {
    /// Get the NE header as a value (copies the header).
    ///
    /// Returns `Error::InvalidNESignature` if the NE signature is not found
    /// at the expected offset.
    fn get_ne_header(&self) -> Result<ImageOS2Header, Error>;

    /// Get the NE header as a borrowed reference (zero-copy).
    ///
    /// The returned reference is valid as long as the underlying buffer
    /// does not change. This enables in-place modification via `get_mut_ne_header_ref()`.
    fn get_ne_header_ref(&self) -> Result<&ImageOS2Header, Error>;

    /// Get the NE header as a mutable reference (zero-copy, in-place modification).
    fn get_mut_ne_header_ref(&mut self) -> Result<&mut ImageOS2Header, Error>;

    /// Get the NE header and validate it.
    ///
    /// Checks:
    /// - DOS signature at offset 0
    /// - `e_lfanew` (u32, offset 0x3C) points at the `NE` signature —
    ///   the only reliable NE detection method
    /// - File is large enough to contain the NE header
    ///
    /// NOTE: `e_lfarlc` is intentionally NOT validated — valid NE files
    /// may hold any value there (e.g. 0).
    fn get_valid_ne_header(&self) -> Result<ImageOS2Header, Error>;

    /// Validate that the DOS header is large enough to read its fields.
    ///
    /// `e_lfarlc` (offset 0x18) is read but its value is not checked —
    /// it is not an authoritative NE-detection criterion.
    ///
    /// # Returns
    /// - `Ok(())` if valid
    /// - `Error::InvalidDOSStubFields` if the DOS header is truncated
    fn validate_dos_stub_fields(&self) -> Result<(), Error>;

    /// Check if this NE module is a DLL (Library).
    ///
    /// Per osdev.org and Windows 3.00 Developer's Notes, the library flag is bit 15
    /// (0x8000) in the NE header flags. This is the only difference between an
    /// EXE program and a DLL library.
    fn is_library(&self) -> bool;

    /// Get the expected processor modes supported by this module.
    ///
    /// Per osdev.org NE-Format specification, processor mode support is determined by:
    /// - `expctwinver[1]` (`expected_version` high byte for v5 headers)
    /// - `FlagWord & 0x0008` (GAMEIMAGE bit)
    /// - `OS2EXEFlags & 0x04` (OS/2 protected mode bit)
    ///
    /// # Returns
    /// A tuple `(real_mode, protected_mode)` indicating which modes are supported.
    fn supported_processor_modes(&self) -> (bool, bool);

    /// Get the segment table (all segment records).
    fn get_segment_table(&self) -> Result<Vec<SegmentRecord>, Error>;

    /// Get a segment record by its 1-based segment number.
    ///
    /// Returns `None` if the segment number is out of range.
    fn segment_by_number(&self, num: u16) -> Option<SegmentRecord>;

    /// Get the DOS stub (data between end of DOS header and start of NE header).
    ///
    /// Returns `None` if there is no stub data.
    fn get_dos_stub(&self) -> Option<&[u8]>;

    /// Get the total file data as a slice.
    fn as_slice(&self) -> &[u8];

    /// Convert a logical address (segment number + offset) to a file offset.
    ///
    /// # Arguments
    /// * `seg_num` — 1-based segment number
    /// * `offset` — offset within the segment
    fn logical_to_offset(&self, seg_num: u16, offset: u16) -> Result<usize, Error>;

    /// Get the data of a specific segment.
    ///
    /// Returns the segment's data as a byte slice.
    fn get_segment_data(&self, seg_num: u16) -> Result<&[u8], Error>;

    /// Get the number of segments.
    fn segment_count(&self) -> u16;

    /// Get the entry table offset (file offset).
    fn entry_table_offset(&self) -> u16;

    /// Get the segment table offset (file offset).
    fn segment_table_offset(&self) -> u16;

    /// Get the resource table offset (file offset).
    fn resource_table_offset(&self) -> u16;

    /// Get the resident names table offset (file offset).
    fn resident_name_table_offset(&self) -> u16;

    /// Get the module reference table offset (file offset).
    fn module_ref_table_offset(&self) -> u16;

    /// Get the imported names table offset (file offset).
    fn imported_names_table_offset(&self) -> u16;

    /// Get the relocation table offset (file offset).
    fn relocation_table_offset(&self) -> u16;

    /// Get the non-resident name table offset (FILE offset, NOT RVA).
    ///
    /// Unlike all other table offsets, this is an absolute file offset
    /// relative to the start of the file (byte 0), NOT relative to the
    /// NE header start. Do NOT add `e_lfanew` to this value.
    fn non_resident_name_table_offset(&self) -> u32;

    /// Get the number of entries in the entry table.
    fn entry_table_entry_count(&self) -> u16;

    /// Get the header as a raw byte slice (aligned to header size).
    fn header_slice(&self) -> Result<&[u8], Error>;

    // ---------------------------------------------------------------------------
    // NE offset helpers — NE header offsets are relative to e_lfanew, not file start
    // ---------------------------------------------------------------------------

    /// Get the file offset where the NE header starts (a.k.a. `e_lfanew`).
    ///
    /// `e_lfanew` is a u32 field at DOS header offset 0x3C.
    fn ne_header_file_offset(&self) -> Result<usize, Error> {
        let e_lfanew = self.read_u32(DOS_E_LFANEW_OFFSET)? as usize;
        Ok(e_lfanew)
    }

    /// Convert a NE-header-relative offset (RVA) to an absolute file offset.
    ///
    /// NE header fields store offsets relative to the NE header's file position
    /// (`e_lfanew`), not absolute file offsets. This method converts them.
    ///
    /// A relative offset of 0 is returned as 0 — it means "table not present"
    /// (e.g. `resource_table_offset == 0`), not "the file start".
    fn ne_offset_to_file(&self, relative: u16) -> Result<usize, Error> {
        if relative == 0 {
            return Ok(0);
        }
        let e_lfanew = self.ne_header_file_offset()?;
        Ok(e_lfanew + relative as usize)
    }
}

// ---------------------------------------------------------------------------
// VecNE — in-memory buffer backed by Vec<u8>
// ---------------------------------------------------------------------------

/// In-memory NE buffer backed by a `Vec<u8>`.
///
/// This is the primary buffer type for parsing NE files from disk or memory.
pub struct VecNE {
    data: Vec<u8>,
}

impl VecNE {
    /// Create a `VecNE` from a file path.
    #[cfg(feature = "std")]
    pub fn from_disk_file(path: &str) -> Result<Self, Error> {
        #[cfg(feature = "std")]
        {
            use std::fs;
            let bytes = fs::read(path).map_err(Error::IoError)?;
            Ok(Self { data: bytes })
        }
    }

    /// Create a `VecNE` from in-memory data.
    #[must_use]
    pub fn from_memory(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a `VecNE` from a byte slice (copies the data).
    #[must_use]
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }
}

impl Buffer for VecNE {
    fn get_slice(&self, offset: usize, len: usize) -> Result<&[u8], Error> {
        if offset + len > self.data.len() {
            return Err(Error::HeaderOutOfBounds(offset + len));
        }
        Ok(&self.data[offset..offset + len])
    }

    fn len(&self) -> usize {
        self.data.len()
    }
}

impl NE for VecNE {
    fn get_ne_header(&self) -> Result<ImageOS2Header, Error> {
        let e_lfanew = self.read_u32(DOS_E_LFANEW_OFFSET)? as usize;
        self.read_header_at(e_lfanew)
    }

    fn get_ne_header_ref(&self) -> Result<&ImageOS2Header, Error> {
        let e_lfanew = self.read_u32(DOS_E_LFANEW_OFFSET)? as usize;
        // The reference covers the full 64-byte struct; require that many
        // bytes past e_lfanew (v4 files have tables there, so this holds
        // for any well-formed file).
        if e_lfanew + NE_HEADER_SIZE_V5 > self.data.len() {
            return Err(Error::HeaderTooSmall);
        }
        // SAFETY: header_ptr points into self.data which has a known layout and lifetime
        // The caller must not modify self.data while holding this reference.
        let header_ptr = unsafe { self.data.as_ptr().add(e_lfanew).cast::<ImageOS2Header>() };
        Ok(unsafe { &*header_ptr })
    }

    fn get_mut_ne_header_ref(&mut self) -> Result<&mut ImageOS2Header, Error> {
        // Validate first
        self.get_valid_ne_header()?;
        let e_lfanew = self.read_u32(DOS_E_LFANEW_OFFSET)? as usize;
        if e_lfanew + NE_HEADER_SIZE_V5 > self.data.len() {
            return Err(Error::HeaderTooSmall);
        }
        // SAFETY: header_ptr points into self.data which has a known layout and lifetime
        let header_ptr = unsafe {
            self.data
                .as_mut_ptr()
                .add(e_lfanew)
                .cast::<ImageOS2Header>()
        };
        Ok(unsafe { &mut *header_ptr })
    }

    fn get_valid_ne_header(&self) -> Result<ImageOS2Header, Error> {
        // Check DOS signature
        if self.len() < DOS_HEADER_SIZE {
            return Err(Error::HeaderTooSmall);
        }
        let dos_sig = self.read_u16(0)?;
        if dos_sig != DOS_SIGNATURE {
            return Err(Error::InvalidDOSSignature(dos_sig));
        }

        // Read e_lfanew (u32 field)
        let e_lfanew = self.read_u32(DOS_E_LFANEW_OFFSET)? as usize;
        // detect_header_size also validates the NE signature and that at
        // least the v4 minimum fits.
        self.detect_header_size(e_lfanew)?;
        // The header accessors materialize the full 64-byte struct.
        if e_lfanew + NE_HEADER_SIZE_V5 > self.len() {
            return Err(Error::HeaderTooSmall);
        }

        self.get_ne_header()
    }

    fn validate_dos_stub_fields(&self) -> Result<(), Error> {
        // e_lfarlc (offset 0x18) is read but not value-checked: it is 0x40
        // in every corpus file, but the only reliable NE detection is the
        // "NE" signature at e_lfanew.
        if self.len() < DOS_HEADER_SIZE {
            return Err(Error::InvalidDOSStubFields);
        }
        let _e_lfarlc = self.read_u16(DOS_E_LFARLC_OFFSET)?;
        // We read but don't validate — e_lfarlc value is not authoritative for NE detection.
        Ok(())
    }

    fn is_library(&self) -> bool {
        // Library (DLL) flag is bit 15 (0x8000) of the header flags
        // (NeFlags::LIBRARY per the Windows 3.1 spec).
        match self.get_ne_header() {
            Ok(header) => NeFlags::from_bits_truncate(header.flags).contains(NeFlags::LIBRARY),
            Err(_) => false,
        }
    }

    fn supported_processor_modes(&self) -> (bool, bool) {
        // Possible values:
        // - 36h (exe_type): value 2 = Windows
        // - 37h (other_flags) bit 1 (0x02): Windows 2.x application running
        //   in version 3.x protected mode (i.e. real-mode application code)
        // - 3Eh (expected_version, v5 only): high byte = expected major version
        //
        // Returns (real_mode, protected_mode). Windows 3.x+ modules are
        // protected-mode; Windows 1.x/2.x (expected major < 3, v4 headers,
        // or the Win2.x-in-PM flag) are real-mode.
        let Ok(header) = self.get_ne_header() else {
            return (false, false);
        };
        let is_windows = header.exe_type == 2;
        let expver_major = if header.is_v5() {
            (header.expected_version >> 8) & 0xFF
        } else {
            0 // v4 headers carry no expected version; treat as pre-3.x
        };
        let win2x_in_pm = is_windows && header.other_flags & 0x02 != 0;

        let protected = if is_windows {
            header.is_v5() && expver_major >= 3
        } else {
            // OS/2: v5 (2.x+) modules are protected-mode
            header.is_v5()
        };
        let real = !protected || win2x_in_pm;
        (real, protected)
    }

    fn get_segment_table(&self) -> Result<Vec<SegmentRecord>, Error> {
        let header = self.get_valid_ne_header()?;
        let seg_count = header.common_fields().seg_count as usize;
        if seg_count == 0 {
            return Ok(Vec::new());
        }

        // seg_table_offset is an RVA relative to NE header start.
        // Add the NE header file offset (e_lfanew) to get the file offset.
        let e_lfanew = self.ne_header_file_offset()?;
        let seg_table_file_off = e_lfanew + header.common_fields().seg_table_offset as usize;
        let rec_size = core::mem::size_of::<SegmentRecord>();
        let total_size = seg_count * rec_size;

        if seg_table_file_off + total_size > self.len() {
            return Err(Error::TableOutOfBounds(
                "segment_table",
                seg_table_file_off + total_size,
                self.len(),
            ));
        }

        let mut segments = Vec::with_capacity(seg_count);
        for i in 0..seg_count {
            let file_offset = seg_table_file_off + i * rec_size;
            let bytes = self.get_slice(file_offset, rec_size)?;
            // SAFETY: SegmentRecord is #[repr(C, packed)] with only primitive fields
            let record =
                unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<SegmentRecord>()) };
            segments.push(record);
        }

        Ok(segments)
    }

    fn segment_by_number(&self, num: u16) -> Option<SegmentRecord> {
        // Segment numbers are 1-based
        if num == 0 {
            return None;
        }
        let segments = self.get_segment_table().ok()?;
        let idx = (num - 1) as usize;
        segments.get(idx).copied()
    }

    fn get_dos_stub(&self) -> Option<&[u8]> {
        let e_lfanew = self.read_u32(DOS_E_LFANEW_OFFSET).ok()? as usize;
        if e_lfanew > DOS_HEADER_SIZE {
            Some(&self.data[DOS_HEADER_SIZE..e_lfanew])
        } else {
            None
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.data
    }

    fn logical_to_offset(&self, seg_num: u16, offset: u16) -> Result<usize, Error> {
        // Find the segment record
        let segments = self.get_segment_table()?;
        let seg_idx = (seg_num - 1) as usize;
        let _seg = segments
            .get(seg_idx)
            .ok_or(Error::SegmentNotFound(seg_num))?;

        // Get segment data
        let seg_data = self.get_segment_data(seg_num)?;

        // Validate offset is within segment
        let offset = offset as usize;
        if offset > seg_data.len() {
            return Err(Error::HeaderOutOfBounds(offset));
        }

        // Calculate file offset: segment start offset + alignment padding + data offset
        let seg_start = self.segment_start_offset(seg_num)?;
        let aligned_offset = seg_start + offset;
        Ok(aligned_offset)
    }

    fn get_segment_data(&self, seg_num: u16) -> Result<&[u8], Error> {
        let segments = self.get_segment_table()?;
        let seg_idx = (seg_num - 1) as usize;
        let seg = segments
            .get(seg_idx)
            .ok_or(Error::SegmentNotFound(seg_num))?;

        // Find the segment's file offset by looking at the relocation table
        // For simplicity, we use a heuristic: segments are laid out after the header
        // and tables. A proper implementation would track segment boundaries from
        // the relocation data.
        let seg_start = self.segment_start_offset(seg_num)?;
        let seg_end = self.segment_end_offset(seg_num, *seg)?;

        self.get_slice(seg_start, seg_end - seg_start)
    }

    fn segment_count(&self) -> u16 {
        match self.get_valid_ne_header() {
            Ok(h) => h.common_fields().seg_count,
            Err(_) => 0,
        }
    }

    fn entry_table_offset(&self) -> u16 {
        match self.get_valid_ne_header() {
            Ok(h) => {
                let rel = h.common_fields().entry_table_offset;
                self.ne_offset_to_file(rel).unwrap_or(0) as u16
            }
            Err(_) => 0,
        }
    }

    fn segment_table_offset(&self) -> u16 {
        match self.get_valid_ne_header() {
            Ok(h) => {
                let rel = h.common_fields().seg_table_offset;
                self.ne_offset_to_file(rel).unwrap_or(0) as u16
            }
            Err(_) => 0,
        }
    }

    fn resource_table_offset(&self) -> u16 {
        match self.get_valid_ne_header() {
            Ok(h) => {
                let rel = h.common_fields().resource_table_offset;
                self.ne_offset_to_file(rel).unwrap_or(0) as u16
            }
            Err(_) => 0,
        }
    }

    fn resident_name_table_offset(&self) -> u16 {
        match self.get_valid_ne_header() {
            Ok(h) => {
                let rel = h.common_fields().res_name_table_offset;
                self.ne_offset_to_file(rel).unwrap_or(0) as u16
            }
            Err(_) => 0,
        }
    }

    fn module_ref_table_offset(&self) -> u16 {
        match self.get_valid_ne_header() {
            Ok(h) => {
                let rel = h.common_fields().mod_table_offset;
                self.ne_offset_to_file(rel).unwrap_or(0) as u16
            }
            Err(_) => 0,
        }
    }

    fn imported_names_table_offset(&self) -> u16 {
        match self.get_valid_ne_header() {
            Ok(h) => {
                let rel = h.common_fields().imported_names_table_offset;
                self.ne_offset_to_file(rel).unwrap_or(0) as u16
            }
            Err(_) => 0,
        }
    }

    fn non_resident_name_table_offset(&self) -> u32 {
        // Non-resident name table offset is a FILE offset (not RVA).
        // Unlike all other NE table offsets, this is relative to file start (byte 0).
        match self.get_valid_ne_header() {
            Ok(h) => h.common_fields().non_res_name_table_offset,
            Err(_) => 0,
        }
    }

    fn relocation_table_offset(&self) -> u16 {
        // NE files don't have a global relocation table offset in the header.
        // Relocations are stored per-segment within the segment data area.
        0
    }

    fn entry_table_entry_count(&self) -> u16 {
        match self.get_valid_ne_header() {
            Ok(h) => h.common_fields().entry_table_size,
            Err(_) => 0,
        }
    }

    fn header_slice(&self) -> Result<&[u8], Error> {
        let header = self.get_valid_ne_header()?;
        let size = header.header_size();
        let e_lfanew = self.ne_header_file_offset()?;
        self.get_slice(e_lfanew, size)
    }
}

impl VecNE {
    /// Detect the on-disk NE header size at `e_lfanew`.
    ///
    /// The **linker version** (header byte 0x02) is authoritative:
    /// major >= 5 → v5 (64-byte SDK layout), otherwise v4 (60 bytes,
    /// OS/2 1.x). The old `VERSION_BIT` heuristic (flags bit 0) is wrong:
    /// that bit is SINGLEDATA and is clear in many
    /// valid v5 Windows files (e.g. DUALBTN.bin, WINMINE.EXE).
    fn detect_header_size(&self, e_lfanew: usize) -> Result<usize, Error> {
        if e_lfanew + NE_HEADER_SIZE_V4 > self.len() {
            return Err(Error::HeaderTooSmall);
        }

        let ne_sig = self.read_u16(e_lfanew)?;
        if ne_sig != NE_SIGNATURE {
            return Err(Error::InvalidNESignature(ne_sig));
        }

        let linker_version = self.read_u8(e_lfanew + 2)?;
        Ok(if linker_version >= 5 {
            NE_HEADER_SIZE_V5
        } else {
            NE_HEADER_SIZE_V4
        })
    }

    /// Read the NE header from a given offset.
    ///
    /// The Rust struct is always the full 64-byte SDK layout. For v4
    /// headers (60 bytes on disk) the trailing 4 bytes do not exist, so
    /// they are zero-filled; v5-only accessors are gated by `is_v5()`.
    fn read_header_at(&self, e_lfanew: usize) -> Result<ImageOS2Header, Error> {
        let header_size = self.detect_header_size(e_lfanew)?;
        let mut buf = [0u8; NE_HEADER_SIZE_V5];
        let bytes = self.get_slice(e_lfanew, header_size)?;
        buf[..header_size].copy_from_slice(bytes);

        // SAFETY: buf is a valid 64-byte buffer; ImageOS2Header is
        // #[repr(C, packed)] with only primitive fields.
        Ok(unsafe { core::ptr::read_unaligned(buf.as_ptr().cast::<ImageOS2Header>()) })
    }

    /// Calculate the start offset of a segment in the file.
    ///
    /// This is a simplified implementation. A full implementation would
    /// track segment boundaries from the relocation table.
    fn segment_start_offset(&self, seg_num: u16) -> Result<usize, Error> {
        let header = self.get_valid_ne_header()?;
        let seg_count = header.common_fields().seg_count as usize;
        if seg_num < 1 || (seg_num as usize) > seg_count {
            return Err(Error::SegmentNotFound(seg_num));
        }

        // The segment table offset is an RVA from NE header start.
        let e_lfanew = self.ne_header_file_offset()?;
        let seg_table_rva = header.common_fields().seg_table_offset as usize;
        let seg_table_file_off = e_lfanew + seg_table_rva;

        // Each segment record is 8 bytes.
        // The `offset` field is a SECTOR OFFSET (not RVA), relative to file start.
        let rec_size = core::mem::size_of::<SegmentRecord>();
        let file_offset = seg_table_file_off + (seg_num as usize - 1) * rec_size;
        let bytes = self.get_slice(file_offset, rec_size)?;
        // SAFETY: SegmentRecord is #[repr(C, packed)]
        let record = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<SegmentRecord>()) };

        // Sector offset → file offset: shift left by alignment_shift
        let alignment_shift = header.common_fields().alignment as usize;
        let sector_offset = record.offset as usize;
        Ok(sector_offset << alignment_shift)
    }

    /// Calculate the end offset of a segment in the file.
    fn segment_end_offset(&self, seg_num: u16, seg: SegmentRecord) -> Result<usize, Error> {
        let _header = self.get_valid_ne_header()?;
        let length = seg.length as usize;

        if length == 0 {
            // No data — return rest of file (simplified)
            Ok(self.len())
        } else {
            // length is in bytes
            let start = self.segment_start_offset(seg_num)?;
            Ok(start + length)
        }
    }
}

// ---------------------------------------------------------------------------
// PtrNE<'a> — pointer-backed buffer
// ---------------------------------------------------------------------------

/// Pointer-backed NE buffer for loaded images.
///
/// The `'a` lifetime ties the parsed data to the backing pointer's validity.
/// The caller must guarantee that `ptr` remains valid and unmoved for the
/// entire lifetime `'a`.
pub struct PtrNE<'a> {
    ptr: *const u8,
    len: usize,
    _marker: core::marker::PhantomData<&'a u8>,
}

unsafe impl Send for PtrNE<'_> {}
unsafe impl Sync for PtrNE<'_> {}

impl PtrNE<'_> {
    /// Create a `PtrNE` from a raw pointer and length.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - `ptr` is non-null and properly aligned
    /// - The memory region `[ptr, ptr + len)` is valid for reads
    /// - The memory region remains valid and unmoved for the lifetime `'a`
    /// - The data contains a valid NE file
    #[must_use]
    pub const fn from_memory(ptr: *const u8, len: usize) -> Self {
        Self {
            ptr,
            len,
            _marker: core::marker::PhantomData,
        }
    }
}

impl Buffer for PtrNE<'_> {
    fn get_slice(&self, offset: usize, len: usize) -> Result<&[u8], Error> {
        if offset + len > self.len {
            return Err(Error::HeaderOutOfBounds(offset + len));
        }
        // SAFETY: We've verified the offset is within bounds, and the caller
        // has guaranteed the memory region is valid for the lifetime 'a.
        Ok(unsafe { core::slice::from_raw_parts(self.ptr.add(offset), len) })
    }

    fn len(&self) -> usize {
        self.len
    }
}

impl NE for PtrNE<'_> {
    fn get_ne_header(&self) -> Result<ImageOS2Header, Error> {
        let e_lfanew = self.read_u32(DOS_E_LFANEW_OFFSET)? as usize;
        // The struct is 64 bytes; require that many past e_lfanew. For v4
        // files the trailing 4 bytes are file content (tables) — memory-safe,
        // and v5-only accessors are gated by `is_v5()`.
        if e_lfanew + NE_HEADER_SIZE_V5 > self.len {
            return Err(Error::HeaderTooSmall);
        }

        // SAFETY: The caller has guaranteed the memory region is valid for 'a,
        // and ImageOS2Header is #[repr(C, packed)] with only primitive fields.
        let header_ptr = unsafe { self.ptr.add(e_lfanew).cast::<ImageOS2Header>() };
        Ok(unsafe { core::ptr::read_unaligned(header_ptr) })
    }

    fn get_ne_header_ref(&self) -> Result<&ImageOS2Header, Error> {
        let e_lfanew = self.read_u32(DOS_E_LFANEW_OFFSET)? as usize;
        if e_lfanew + NE_HEADER_SIZE_V5 > self.len {
            return Err(Error::HeaderTooSmall);
        }

        // SAFETY: Caller guarantees memory validity for 'a
        let header_ptr = unsafe { self.ptr.add(e_lfanew).cast::<ImageOS2Header>() };
        Ok(unsafe { &*header_ptr })
    }

    fn get_mut_ne_header_ref(&mut self) -> Result<&mut ImageOS2Header, Error> {
        // PtrNE is typically used for read-only loaded images, but we support
        // mutable access for completeness.
        self.get_valid_ne_header()?;
        let e_lfanew = self.read_u32(DOS_E_LFANEW_OFFSET)? as usize;
        // SAFETY: Caller guarantees memory validity for 'a
        let header_ptr = unsafe { self.ptr.add(e_lfanew) as *mut ImageOS2Header };
        Ok(unsafe { &mut *header_ptr })
    }

    fn get_valid_ne_header(&self) -> Result<ImageOS2Header, Error> {
        // Check minimum size (DOS header)
        if self.len < DOS_HEADER_SIZE {
            return Err(Error::HeaderTooSmall);
        }

        // Check DOS signature
        let dos_sig = self.read_u16(0)?;
        if dos_sig != DOS_SIGNATURE {
            return Err(Error::InvalidDOSSignature(dos_sig));
        }

        // Validate DOS stub fields (size check only — e_lfarlc is not
        // an authoritative NE-detection criterion)
        self.validate_dos_stub_fields()?;

        // Read e_lfanew (u32 field)
        let e_lfanew = self.read_u32(DOS_E_LFANEW_OFFSET)? as usize;
        if e_lfanew + NE_HEADER_SIZE_V5 > self.len {
            return Err(Error::HeaderTooSmall);
        }

        // Check NE signature — the only reliable NE detection method
        let ne_sig = self.read_u16(e_lfanew)?;
        if ne_sig != NE_SIGNATURE {
            return Err(Error::InvalidNESignature(ne_sig));
        }

        self.get_ne_header()
    }

    fn validate_dos_stub_fields(&self) -> Result<(), Error> {
        // e_lfarlc (offset 0x18) is read but not value-checked: it is 0x40
        // in every corpus file, but the only reliable NE detection is the
        // "NE" signature at e_lfanew.
        if self.len < DOS_HEADER_SIZE {
            return Err(Error::InvalidDOSStubFields);
        }
        let _e_lfarlc = self.read_u16(DOS_E_LFARLC_OFFSET)?;
        // We read but don't validate — e_lfarlc value is not authoritative for NE detection.
        Ok(())
    }

    fn is_library(&self) -> bool {
        // Library (DLL) flag is bit 15 (0x8000) of the header flags
        // (NeFlags::LIBRARY).
        match self.get_ne_header() {
            Ok(header) => NeFlags::from_bits_truncate(header.flags).contains(NeFlags::LIBRARY),
            Err(_) => false,
        }
    }

    fn supported_processor_modes(&self) -> (bool, bool) {
        // Possible values:
        // - 36h (exe_type): value 2 = Windows
        // - 37h (other_flags) bit 1 (0x02): Windows 2.x application running
        //   in version 3.x protected mode (i.e. real-mode application code)
        // - 3Eh (expected_version, v5 only): high byte = expected major version
        //
        // Returns (real_mode, protected_mode). Windows 3.x+ modules are
        // protected-mode; Windows 1.x/2.x (expected major < 3, v4 headers,
        // or the Win2.x-in-PM flag) are real-mode.
        let Ok(header) = self.get_ne_header() else {
            return (false, false);
        };
        let is_windows = header.exe_type == 2;
        let expver_major = if header.is_v5() {
            (header.expected_version >> 8) & 0xFF
        } else {
            0 // v4 headers carry no expected version; treat as pre-3.x
        };
        let win2x_in_pm = is_windows && header.other_flags & 0x02 != 0;

        let protected = if is_windows {
            header.is_v5() && expver_major >= 3
        } else {
            // OS/2: v5 (2.x+) modules are protected-mode
            header.is_v5()
        };
        let real = !protected || win2x_in_pm;
        (real, protected)
    }

    fn get_segment_table(&self) -> Result<Vec<SegmentRecord>, Error> {
        let header = self.get_valid_ne_header()?;
        let seg_count = header.common_fields().seg_count as usize;
        if seg_count == 0 {
            return Ok(Vec::new());
        }

        // seg_table_offset is an RVA relative to NE header start.
        // Add the NE header buffer offset (e_lfanew) to get the buffer offset.
        let e_lfanew = self.ne_header_file_offset()?;
        let seg_table_buf_off = e_lfanew + header.common_fields().seg_table_offset as usize;
        let rec_size = core::mem::size_of::<SegmentRecord>();
        let total_size = seg_count * rec_size;

        if seg_table_buf_off + total_size > self.len {
            return Err(Error::TableOutOfBounds(
                "segment_table",
                seg_table_buf_off + total_size,
                self.len,
            ));
        }

        let mut segments = Vec::with_capacity(seg_count);
        for i in 0..seg_count {
            let offset = seg_table_buf_off + i * rec_size;
            let bytes = self.get_slice(offset, rec_size)?;
            // SAFETY: SegmentRecord is #[repr(C, packed)] with only primitive fields
            let record =
                unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<SegmentRecord>()) };
            segments.push(record);
        }

        Ok(segments)
    }

    fn segment_by_number(&self, num: u16) -> Option<SegmentRecord> {
        if num == 0 {
            return None;
        }
        let segments = self.get_segment_table().ok()?;
        let idx = (num - 1) as usize;
        segments.get(idx).copied()
    }

    fn get_dos_stub(&self) -> Option<&[u8]> {
        let e_lfanew = self.read_u32(DOS_E_LFANEW_OFFSET).ok()? as usize;
        if e_lfanew > DOS_HEADER_SIZE {
            // SAFETY: Caller guarantees memory validity
            Some(unsafe {
                core::slice::from_raw_parts(
                    self.ptr.add(DOS_HEADER_SIZE),
                    e_lfanew - DOS_HEADER_SIZE,
                )
            })
        } else {
            None
        }
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: Caller guarantees memory validity for 'a
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }

    fn logical_to_offset(&self, seg_num: u16, offset: u16) -> Result<usize, Error> {
        let segments = self.get_segment_table()?;
        let seg_idx = (seg_num - 1) as usize;
        let _seg = segments
            .get(seg_idx)
            .ok_or(Error::SegmentNotFound(seg_num))?;

        let seg_data = self.get_segment_data(seg_num)?;
        let offset = offset as usize;
        if offset > seg_data.len() {
            return Err(Error::HeaderOutOfBounds(offset));
        }

        let seg_start = self.segment_start_offset(seg_num)?;
        Ok(seg_start + offset)
    }

    fn get_segment_data(&self, seg_num: u16) -> Result<&[u8], Error> {
        let segments = self.get_segment_table()?;
        let seg_idx = (seg_num - 1) as usize;
        let seg = segments
            .get(seg_idx)
            .ok_or(Error::SegmentNotFound(seg_num))?;

        let seg_start = self.segment_start_offset(seg_num)?;
        let seg_end = self.segment_end_offset(seg_num, *seg)?;

        self.get_slice(seg_start, seg_end - seg_start)
    }

    fn segment_count(&self) -> u16 {
        match self.get_valid_ne_header() {
            Ok(h) => h.common_fields().seg_count,
            Err(_) => 0,
        }
    }

    fn entry_table_offset(&self) -> u16 {
        match self.get_valid_ne_header() {
            Ok(h) => {
                let rel = h.common_fields().entry_table_offset;
                self.ne_offset_to_file(rel).unwrap_or(0) as u16
            }
            Err(_) => 0,
        }
    }

    fn segment_table_offset(&self) -> u16 {
        match self.get_valid_ne_header() {
            Ok(h) => {
                let rel = h.common_fields().seg_table_offset;
                self.ne_offset_to_file(rel).unwrap_or(0) as u16
            }
            Err(_) => 0,
        }
    }

    fn resource_table_offset(&self) -> u16 {
        match self.get_valid_ne_header() {
            Ok(h) => {
                let rel = h.common_fields().resource_table_offset;
                self.ne_offset_to_file(rel).unwrap_or(0) as u16
            }
            Err(_) => 0,
        }
    }

    fn resident_name_table_offset(&self) -> u16 {
        match self.get_valid_ne_header() {
            Ok(h) => {
                let rel = h.common_fields().res_name_table_offset;
                self.ne_offset_to_file(rel).unwrap_or(0) as u16
            }
            Err(_) => 0,
        }
    }

    fn module_ref_table_offset(&self) -> u16 {
        match self.get_valid_ne_header() {
            Ok(h) => {
                let rel = h.common_fields().mod_table_offset;
                self.ne_offset_to_file(rel).unwrap_or(0) as u16
            }
            Err(_) => 0,
        }
    }

    fn imported_names_table_offset(&self) -> u16 {
        match self.get_valid_ne_header() {
            Ok(h) => {
                let rel = h.common_fields().imported_names_table_offset;
                self.ne_offset_to_file(rel).unwrap_or(0) as u16
            }
            Err(_) => 0,
        }
    }

    fn non_resident_name_table_offset(&self) -> u32 {
        // Non-resident name table offset is a FILE offset (not RVA).
        // Unlike all other NE table offsets, this is relative to file start (byte 0).
        match self.get_valid_ne_header() {
            Ok(h) => h.common_fields().non_res_name_table_offset,
            Err(_) => 0,
        }
    }

    fn relocation_table_offset(&self) -> u16 {
        // NE files don't have a global relocation table offset in the header.
        // Relocations are stored per-segment within the segment data area.
        0
    }

    fn entry_table_entry_count(&self) -> u16 {
        match self.get_valid_ne_header() {
            Ok(h) => h.common_fields().entry_table_size,
            Err(_) => 0,
        }
    }

    fn header_slice(&self) -> Result<&[u8], Error> {
        let header = self.get_valid_ne_header()?;
        let size = header.header_size();
        let e_lfanew = self.ne_header_file_offset()?;
        self.get_slice(e_lfanew, size)
    }
}

impl PtrNE<'_> {
    /// Calculate the start offset of a segment.
    fn segment_start_offset(&self, seg_num: u16) -> Result<usize, Error> {
        let header = self.get_valid_ne_header()?;
        let seg_count = header.common_fields().seg_count as usize;
        if seg_num < 1 || (seg_num as usize) > seg_count {
            return Err(Error::SegmentNotFound(seg_num));
        }

        // The segment table offset is an RVA from NE header start.
        let e_lfanew = self.ne_header_file_offset()?;
        let seg_table_rva = header.common_fields().seg_table_offset as usize;
        let seg_table_buf_off = e_lfanew + seg_table_rva;

        // Each segment record is 8 bytes.
        // The `offset` field is a SECTOR OFFSET (not RVA), relative to file start.
        let rec_size = core::mem::size_of::<SegmentRecord>();
        let buf_offset = seg_table_buf_off + (seg_num as usize - 1) * rec_size;
        let bytes = self.get_slice(buf_offset, rec_size)?;
        // SAFETY: SegmentRecord is #[repr(C, packed)]
        let record = unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<SegmentRecord>()) };

        // Sector offset → file offset: shift left by alignment_shift
        let alignment_shift = header.common_fields().alignment as usize;
        let sector_offset = record.offset as usize;
        Ok(sector_offset << alignment_shift)
    }

    /// Calculate the end offset of a segment.
    fn segment_end_offset(&self, seg_num: u16, seg: SegmentRecord) -> Result<usize, Error> {
        let length = seg.length as usize;
        if length == 0 {
            Ok(self.len())
        } else {
            let start = self.segment_start_offset(seg_num)?;
            Ok(start + length)
        }
    }
}
