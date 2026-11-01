// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! LE/LX header structures (on-disk layout, 0xB0 bytes).
//!
//! The layout is uniform for LE and LX; the two formats differ in the
//! object page table entry size (LE: 4 B, LX: 8 B) and in the meaning of
//! the field at 0x2C (`last page bytes` in LE, `page offset shift` in LX).
//!
//! **Offset bases**:
//! - Most table pointers (`object_table`, `object_page_table`, `resident_names`,
//!   `entry_table`, `directive_table`, `fixup_page_table`, `fixup_record_table`,
//!   `import_modules`, `import_procedures`, …) are **relative to the start of
//!   the LE/LX header** → add the header offset to get a file offset.
//! - `data_pages` (0x80) and `non_resident_names` (0x88) are
//!   **file-absolute** → never add the header offset again.
//! - Object page table entries are **data-section-relative** (LE: a file page
//!   number; LX: a shift-based offset) → see [`crate::le`].

use core::mem;

use crate::{Error, LE_HEADER_SIZE, LE_HEADER_TAIL_SIZE, LE_SIGNATURE, LX_SIGNATURE};

/// LE/LX header (0xB0 = 180 bytes on disk), little-endian.
///
/// `#[repr(C, packed)]`: byte-for-byte on-disk layout. Access fields through
/// the accessor methods (taking a reference to a packed field is a
/// compile-time error, E0793).
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct LeHeader {
    /// Magic: "LE" (`0x454C`) or "LX" (`0x584C`). Offset 0x00.
    pub magic: u16,
    /// Byte order (0 = little-endian in all verified files). Offset 0x02.
    ///
    /// NOTE: verified Open Watcom files are 0 and are unambiguously
    /// little-endian. Treat as informational, never as a gate.
    pub byte_order: u8,
    /// Word order. Offset 0x03. (Same caveat as `byte_order`.)
    pub word_order: u8,
    /// Format level (0 in all verified files). Offset 0x04.
    pub format_level: u32,
    /// CPU type (2 = i86). Offset 0x08.
    pub cpu: u16,
    /// Target OS (1 = OS/2; `VxD` files are also 1). Offset 0x0A.
    pub os: u16,
    /// Module version. Offset 0x0C.
    pub module_version: u32,
    /// Module flags (0x200 in all verified files). Offset 0x10.
    pub module_flags: u32,
    /// Number of pages in the module. Offset 0x14.
    pub module_pages: u32,
    /// Start object (1-based object number holding EIP). Offset 0x18.
    pub start_object: u32,
    /// Entry point (offset within the start object). Offset 0x1C.
    pub eip: u32,
    /// Stack object (1-based object number). Offset 0x20.
    pub stack_object: u32,
    /// Initial stack pointer (offset within the stack object). Offset 0x24.
    pub esp: u32,
    /// Page size (4096 in all verified files). Offset 0x28.
    pub page_size: u32,
    /// **LE:** number of bytes on the last page (on disk).
    /// **LX:** page offset shift (log2 of page offset alignment). Offset 0x2C.
    pub last_page_bytes_or_shift: u32,
    /// Size of the fixup section (fixup page table + fixup record table).
    /// Offset 0x30.
    pub fixup_size: u32,
    /// Checksum of the fixup section. Offset 0x34.
    pub fixup_checksum: u32,
    /// Size of the (optional) loader section. Offset 0x38.
    pub loader_size: u32,
    /// Checksum of the loader section. Offset 0x3C.
    pub loader_checksum: u32,
    /// Object table offset, **header-relative**. Offset 0x40.
    pub object_table: u32,
    /// Number of objects. Offset 0x44.
    pub object_count: u32,
    /// Object page table offset, **header-relative**. Offset 0x48.
    pub object_page_table: u32,
    /// Iterated data map offset (practically unused). Offset 0x4C.
    pub iterated_map: u32,
    /// Resource table offset. Offset 0x50.
    pub resource_table: u32,
    /// Number of resources. Offset 0x54.
    pub resource_count: u32,
    /// Resident name table offset, **header-relative**. Offset 0x58.
    pub resident_names: u32,
    /// Entry (export) table offset, **header-relative**. Offset 0x5C.
    pub entry_table: u32,
    /// Module format directives table offset. Offset 0x60.
    pub directive_table: u32,
    /// Number of module format directives. Offset 0x64.
    pub directive_count: u32,
    /// Fixup page table offset, **header-relative**. Offset 0x68.
    pub fixup_page_table: u32,
    /// Fixup record table offset, **header-relative**. Offset 0x6C.
    pub fixup_record_table: u32,
    /// Import module table offset. Offset 0x70.
    pub import_modules: u32,
    /// Number of import modules. Offset 0x74.
    pub import_module_count: u32,
    /// Import procedure table offset. Offset 0x78.
    pub import_procedures: u32,
    /// Page checksum table offset. Offset 0x7C.
    pub page_checksum: u32,
    /// Offset of the data pages, **file-absolute** (never add the header
    /// offset). Offset 0x80.
    pub data_pages: u32,
    /// Number of preload pages (front of the data section). Offset 0x84.
    pub preload_pages: u32,
    /// Non-resident name table offset, **file-absolute**. Offset 0x88.
    pub non_resident_names: u32,
    /// Size of the non-resident name table. Offset 0x8C.
    pub non_resident_names_size: u32,
    /// Checksum of the non-resident name table. Offset 0x90.
    pub non_resident_checksum: u32,
    /// Auto-data object (1-based object number; 0 = none). Offset 0x94.
    pub auto_data: u32,
    /// Debug info offset. Offset 0x98.
    pub debug_info: u32,
    /// Debug info length. Offset 0x9C.
    pub debug_length: u32,
    /// Instance pages in the preload area. Offset 0xA0.
    pub preload_instance_pages: u32,
    /// Instance pages in the demand area. Offset 0xA4.
    pub demand_instance_pages: u32,
    /// Heap size. Offset 0xA8.
    pub heap_size: u32,
    /// Stack size. Offset 0xAC.
    pub stack_size: u32,
}

impl LeHeader {
    /// Size of the header on disk in bytes (0xB0).
    pub const SIZE: usize = LE_HEADER_SIZE;

    /// Zero-copy view of a buffer slice as `LeHeader`.
    ///
    /// The slice must be at least [`LeHeader::SIZE`] bytes. The caller must
    /// keep the source buffer alive for the lifetime of the reference.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self, Error> {
        if bytes.len() < LE_HEADER_SIZE {
            return Err(Error::HeaderTooSmall);
        }
        // SAFETY: `bytes` is a valid `u8` slice of sufficient length;
        // `LeHeader` is `#[repr(C, packed)]` with only integer fields, so any
        // alignment is acceptable and any byte pattern is a valid value.
        Ok(unsafe { &*(bytes.as_ptr().cast::<LeHeader>()) })
    }

    /// Magic: "LE" (`LE_SIGNATURE`) or "LX" (`LX_SIGNATURE`).
    #[must_use]
    pub fn magic(&self) -> u16 {
        self.magic
    }

    /// `true` for LX files, `false` for LE files.
    #[must_use]
    pub fn is_lx(&self) -> bool {
        self.magic == LX_SIGNATURE
    }

    /// Human-readable signature name.
    #[must_use]
    pub fn signature_name(&self) -> &'static str {
        match self.magic {
            LE_SIGNATURE => "LE",
            LX_SIGNATURE => "LX",
            _ => "?",
        }
    }

    /// Number of pages in the module.
    #[must_use]
    pub fn module_pages(&self) -> u32 {
        self.module_pages
    }

    /// Page size (4096 in all verified files).
    #[must_use]
    pub fn page_size(&self) -> u32 {
        self.page_size
    }

    /// **LE only:** number of bytes stored on the last page of the module.
    ///
    /// In LX files this field is the page offset shift instead — use
    /// [`LeHeader::page_offset_shift`] there.
    #[must_use]
    pub fn last_page_bytes(&self) -> u32 {
        debug_assert!(!self.is_lx(), "last_page_bytes() is LE-only");
        self.last_page_bytes_or_shift
    }

    /// **LX only:** page offset shift for data section offsets.
    ///
    /// In LE files this field holds the last page's byte count instead —
    /// use [`LeHeader::last_page_bytes`] there.
    #[must_use]
    pub fn page_offset_shift(&self) -> u32 {
        debug_assert!(self.is_lx(), "page_offset_shift() is LX-only");
        self.last_page_bytes_or_shift
    }

    /// Object table offset relative to the LE/LX header start.
    #[must_use]
    pub fn object_table_offset(&self) -> usize {
        self.object_table as usize
    }

    /// Number of objects.
    #[must_use]
    pub fn object_count(&self) -> u32 {
        self.object_count
    }

    /// Object page table offset relative to the LE/LX header start.
    #[must_use]
    pub fn object_page_table_offset(&self) -> usize {
        self.object_page_table as usize
    }

    /// Resident name table offset relative to the LE/LX header start.
    #[must_use]
    pub fn resident_names_offset(&self) -> usize {
        self.resident_names as usize
    }

    /// Entry (export) table offset relative to the LE/LX header start.
    #[must_use]
    pub fn entry_table_offset(&self) -> usize {
        self.entry_table as usize
    }

    /// Data pages offset, **file-absolute**.
    #[must_use]
    pub fn data_pages_offset(&self) -> usize {
        self.data_pages as usize
    }

    // -- Remaining field accessors -------------------------------------
    //
    // Direct `header.field` references are a compile-time error (E0793,
    // packed fields), so all consumers go through these copy-by-value
    // accessors.

    #[must_use]
    pub fn byte_order(&self) -> u8 {
        self.byte_order
    }

    #[must_use]
    pub fn word_order(&self) -> u8 {
        self.word_order
    }

    #[must_use]
    pub fn format_level(&self) -> u32 {
        self.format_level
    }

    #[must_use]
    pub fn cpu(&self) -> u16 {
        self.cpu
    }

    #[must_use]
    pub fn os(&self) -> u16 {
        self.os
    }

    #[must_use]
    pub fn module_version(&self) -> u32 {
        self.module_version
    }

    #[must_use]
    pub fn module_flags(&self) -> u32 {
        self.module_flags
    }

    #[must_use]
    pub fn start_object(&self) -> u32 {
        self.start_object
    }

    #[must_use]
    pub fn eip(&self) -> u32 {
        self.eip
    }

    #[must_use]
    pub fn stack_object(&self) -> u32 {
        self.stack_object
    }

    #[must_use]
    pub fn esp(&self) -> u32 {
        self.esp
    }

    #[must_use]
    pub fn fixup_size(&self) -> u32 {
        self.fixup_size
    }

    #[must_use]
    pub fn fixup_checksum(&self) -> u32 {
        self.fixup_checksum
    }

    #[must_use]
    pub fn loader_size(&self) -> u32 {
        self.loader_size
    }

    #[must_use]
    pub fn loader_checksum(&self) -> u32 {
        self.loader_checksum
    }

    #[must_use]
    pub fn iterated_map(&self) -> u32 {
        self.iterated_map
    }

    #[must_use]
    pub fn resource_table(&self) -> u32 {
        self.resource_table
    }

    #[must_use]
    pub fn resource_count(&self) -> u32 {
        self.resource_count
    }

    #[must_use]
    pub fn directive_table(&self) -> u32 {
        self.directive_table
    }

    #[must_use]
    pub fn directive_count(&self) -> u32 {
        self.directive_count
    }

    #[must_use]
    pub fn fixup_page_table(&self) -> u32 {
        self.fixup_page_table
    }

    #[must_use]
    pub fn fixup_record_table(&self) -> u32 {
        self.fixup_record_table
    }

    #[must_use]
    pub fn import_modules(&self) -> u32 {
        self.import_modules
    }

    #[must_use]
    pub fn import_module_count(&self) -> u32 {
        self.import_module_count
    }

    #[must_use]
    pub fn import_procedures(&self) -> u32 {
        self.import_procedures
    }

    #[must_use]
    pub fn page_checksum(&self) -> u32 {
        self.page_checksum
    }

    #[must_use]
    pub fn preload_pages(&self) -> u32 {
        self.preload_pages
    }

    #[must_use]
    pub fn non_resident_names(&self) -> u32 {
        self.non_resident_names
    }

    #[must_use]
    pub fn non_resident_names_size(&self) -> u32 {
        self.non_resident_names_size
    }

    #[must_use]
    pub fn non_resident_checksum(&self) -> u32 {
        self.non_resident_checksum
    }

    #[must_use]
    pub fn auto_data(&self) -> u32 {
        self.auto_data
    }

    #[must_use]
    pub fn debug_info(&self) -> u32 {
        self.debug_info
    }

    #[must_use]
    pub fn debug_length(&self) -> u32 {
        self.debug_length
    }

    #[must_use]
    pub fn preload_instance_pages(&self) -> u32 {
        self.preload_instance_pages
    }

    #[must_use]
    pub fn demand_instance_pages(&self) -> u32 {
        self.demand_instance_pages
    }

    #[must_use]
    pub fn heap_size(&self) -> u32 {
        self.heap_size
    }

    #[must_use]
    pub fn stack_size(&self) -> u32 {
        self.stack_size
    }

    /// Basic structural validation: signature, page size, and page count.
    ///
    /// Deliberately permissive — real-world files (especially `VxD`s) carry
    /// reserved/zeroed fields that must not be rejected.
    pub fn validate(&self) -> Result<(), Error> {
        if self.magic != LE_SIGNATURE && self.magic != LX_SIGNATURE {
            return Err(Error::InvalidSignature(self.magic));
        }
        if self.page_size == 0 || !self.page_size.is_power_of_two() {
            return Err(Error::InvalidPageSize(self.page_size));
        }
        Ok(())
    }
}

// A manual Debug is required (derive(Debug) would reference packed fields,
// E0793) and deliberately shows the load-bearing fields only, not all 45.
#[allow(clippy::missing_fields_in_debug)]
impl core::fmt::Debug for LeHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Packed fields must be copied to locals before use in format args
        // (taking a reference to a packed field is E0793).
        let byte_order = self.byte_order;
        let word_order = self.word_order;
        let format_level = self.format_level;
        let cpu = self.cpu;
        let os = self.os;
        let module_flags = self.module_flags;
        let module_pages = self.module_pages;
        let start_object = self.start_object;
        let eip = self.eip;
        let stack_object = self.stack_object;
        let esp = self.esp;
        let page_size = self.page_size;
        let last_page_bytes_or_shift = self.last_page_bytes_or_shift;
        let fixup_size = self.fixup_size;
        let object_table = self.object_table;
        let object_count = self.object_count;
        let object_page_table = self.object_page_table;
        let resident_names = self.resident_names;
        let entry_table = self.entry_table;
        let data_pages = self.data_pages;
        let preload_pages = self.preload_pages;
        let stack_size = self.stack_size;
        f.debug_struct("LeHeader")
            .field("magic", &format_args!("\"{}\"", self.signature_name()))
            .field("byte_order", &byte_order)
            .field("word_order", &word_order)
            .field("format_level", &format_level)
            .field("cpu", &cpu)
            .field("os", &os)
            .field("module_flags", &format_args!("{module_flags:#06x}"))
            .field("module_pages", &module_pages)
            .field("start_object", &start_object)
            .field("eip", &format_args!("{eip:#x}"))
            .field("stack_object", &stack_object)
            .field("esp", &format_args!("{esp:#x}"))
            .field("page_size", &page_size)
            .field("last_page_bytes_or_shift", &last_page_bytes_or_shift)
            .field("fixup_size", &fixup_size)
            .field("object_table", &format_args!("{object_table:#x}"))
            .field("object_count", &object_count)
            .field("object_page_table", &format_args!("{object_page_table:#x}"))
            .field("resident_names", &format_args!("{resident_names:#x}"))
            .field("entry_table", &format_args!("{entry_table:#x}"))
            .field("data_pages", &format_args!("{data_pages:#x}"))
            .field("preload_pages", &preload_pages)
            .field("stack_size", &format_args!("{stack_size:#x}"))
            .finish()
    }
}

impl PartialEq for LeHeader {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for LeHeader {}

impl LeHeader {
    /// Exact on-disk bytes (0xB0), for comparisons and serialization.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; LE_HEADER_SIZE] {
        // SAFETY: `LeHeader` is `#[repr(C, packed)]` with only integer
        // fields; its in-memory size equals `LE_HEADER_SIZE`.
        let mut out = [0u8; LE_HEADER_SIZE];
        unsafe {
            core::ptr::copy_nonoverlapping(
                core::ptr::from_ref(self).cast::<u8>(),
                out.as_mut_ptr(),
                LE_HEADER_SIZE,
            );
        }
        out
    }
}

/// The 20 bytes that follow the 0xB0-byte header, at header-relative
/// `0xB0..=0xC3`.
///
/// `VxD` images put values here — `testdata/fixtures/hellovxd.BIN` stores
/// `ddk_version` `0x040A`, `vmdisp9xvxd.BIN` device id `0x4333` and DDK
/// version `0x0400` — while every OS/2 and DOS-extender fixture in this
/// corpus leaves it zero. No fixture starts a table at `0xB0` (their object
/// tables begin at header-relative `0xC4`), but the read is gated on that
/// anyway ([`crate::le::LE::get_header_tail`]): a toolchain that did would
/// make these fields meaningless.
///
/// Deliberately **not** `#[repr(C, packed)]`: it is always built by copying
/// values out of the buffer, so the packed-access pitfalls do not apply.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LeHeaderTail {
    /// Header-relative `0xB0..0xB8` (`e32_res3`), observed all-zero.
    pub reserved: [u8; 8],
    /// Header-relative `0xB8` (`e32_winresoff`): `VxD` resource table offset,
    /// relative to the LE/LX header. 0 = none.
    pub winres_offset: u32,
    /// Header-relative `0xBC` (`e32_winreslen`): `VxD` resource table size.
    pub winres_length: u32,
    /// Header-relative `0xC0` (`e32_devid`): `VxD` device identifier.
    pub device_id: u16,
    /// Header-relative `0xC2` (`e32_ddkver`): DDK version that built the
    /// image (`0x040A` in `hellovxd.BIN` and `hello2vxd.BIN`).
    pub ddk_version: u16,
}

impl LeHeaderTail {
    /// Size of this region on disk (0x14 bytes).
    pub const SIZE: usize = LE_HEADER_TAIL_SIZE;

    /// Copy the fields out of `bytes`, which must start at the region itself
    /// (i.e. at the header start + [`LE_HEADER_SIZE`]).
    ///
    /// Returns `None` when `bytes` is shorter than [`Self::SIZE`].
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let b = bytes.get(..LE_HEADER_TAIL_SIZE)?;
        Some(Self {
            reserved: [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]],
            winres_offset: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            winres_length: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
            device_id: u16::from_le_bytes([b[16], b[17]]),
            ddk_version: u16::from_le_bytes([b[18], b[19]]),
        })
    }

    /// `true` when every byte of the region is zero, which is what every
    /// non-Microsoft file in this corpus stores.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.reserved.iter().all(|&b| b == 0)
            && self.winres_offset == 0
            && self.winres_length == 0
            && self.device_id == 0
            && self.ddk_version == 0
    }
}

/// Build an owned [`LeHeader`] from a raw byte slice (memcpy).
///
/// Used by [`crate::le::LE::get_le_header`] for the non-zero-copy path.
pub fn header_from_bytes(bytes: &[u8]) -> Result<LeHeader, Error> {
    if bytes.len() < LE_HEADER_SIZE {
        return Err(Error::HeaderTooSmall);
    }
    // SAFETY: `LeHeader` is `#[repr(C, packed)]` with only integer fields;
    // any byte pattern is a valid value.
    let mut header: LeHeader = unsafe { mem::zeroed() };
    unsafe {
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            core::ptr::from_mut(&mut header).cast::<u8>(),
            LE_HEADER_SIZE,
        );
    }
    Ok(header)
}
