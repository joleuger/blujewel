// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! Parsed NE data structures.
//!
//! These types represent the parsed form of the various tables found in an
//! NE file. They are built by `parse` functions that take a reference to a
//! [`NE`](crate::NE) implementation.
//!
//! All parsers are **lazy** — tables are only read from the buffer when
//! explicitly requested, not during header parsing.
//!
//! # Offset conventions
//!
//! The `NE` trait's table accessors (`entry_table_offset()`,
//! `resource_table_offset()`, ...) return **file offsets**. The header's
//! table pointer fields (offsets 0x06-0x2A) are RVAs relative to the NE
//! header start, except `ne_nrestab` (0x2C) which is already a file offset.

use crate::{Error, SegmentFlags, NE};

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

// ---------------------------------------------------------------------------
// Pascal String
// ---------------------------------------------------------------------------

/// A Pascal string borrowed from the NE buffer.
///
/// Derefs to `[u8]` — use `.as_str()` for UTF-8 validated access.
/// NE Pascal strings are length-prefixed ASCII bytes; they are not
/// guaranteed to be valid UTF-8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PascalString<'a> {
    pub data: &'a [u8],
}

impl<'a> PascalString<'a> {
    /// Get the string length (number of bytes, not including the length byte).
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the string is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.data
    }

    /// Convert to a UTF-8 string (returns Error if not valid UTF-8).
    pub fn as_str(&self) -> Result<&'a str, Error> {
        core::str::from_utf8(self.data).map_err(|_| Error::InvalidPascalString)
    }
}

impl core::ops::Deref for PascalString<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.data
    }
}

// ---------------------------------------------------------------------------
// Resident Name Table
// ---------------------------------------------------------------------------

/// A resident name entry: a name + 2-byte ordinal suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidentName<'a> {
    pub name: PascalString<'a>,
    pub ordinal: u16,
}

/// Parsed resident names table.
pub struct ResidentNameTable<'a> {
    pub entries: Vec<ResidentName<'a>>,
}

impl<'a> ResidentNameTable<'a> {
    /// Parse the resident names table from an NE buffer.
    ///
    /// The resident names table is a sequence of Pascal strings (length byte +
    /// ASCII bytes) followed by 2-byte ordinal suffixes. Each name-ordinal pair
    /// is: `[len][name_bytes...][ordinal_lo][ordinal_hi]`. The table ends at a
    /// zero length byte. The first entry is the module name itself.
    pub fn parse<P: NE>(ne: &'a P) -> Result<Self, Error> {
        let offset = ne.resident_name_table_offset() as usize;
        if offset == 0 {
            return Ok(ResidentNameTable {
                entries: Vec::new(),
            });
        }

        let mut entries = Vec::new();
        let mut pos = offset;

        loop {
            // Read Pascal string length
            let len_byte = ne.get_slice(pos, 1)?[0] as usize;
            pos += 1;

            if len_byte == 0 {
                // End of table
                break;
            }

            // Read name bytes
            let name_bytes = ne.get_slice(pos, len_byte)?;
            pos += len_byte;

            // Read 2-byte ordinal suffix
            let ordinal = ne.read_u16(pos)?;
            pos += 2;

            entries.push(ResidentName {
                name: PascalString { data: name_bytes },
                ordinal,
            });
        }

        Ok(ResidentNameTable { entries })
    }

    /// Find an entry by ordinal.
    #[must_use]
    pub fn by_ordinal(&self, ordinal: u16) -> Option<&ResidentName<'a>> {
        self.entries.iter().find(|e| e.ordinal == ordinal)
    }

    /// Find an entry by name (case-insensitive, NE names are ASCII).
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&ResidentName<'a>> {
        self.entries
            .iter()
            .find(|e| e.name.as_bytes().eq_ignore_ascii_case(name.as_bytes()))
    }
}

// ---------------------------------------------------------------------------
// Non-Resident Name Table
// ---------------------------------------------------------------------------

/// Parsed non-resident names table.
///
/// Same entry format as the resident names table
/// (`[len][name_bytes...][ordinal: u16]`, terminated by a zero length byte),
/// but located at the **absolute file offset** `ne_nrestab` (header offset
/// 0x2C, a u32) and bounded by `ne_cbnrestab`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonResidentNameTable<'a> {
    pub entries: Vec<ResidentName<'a>>,
}

impl<'a> NonResidentNameTable<'a> {
    /// Parse the non-resident names table from an NE buffer.
    ///
    /// An absent table (size or offset zero) yields an empty result.
    pub fn parse<P: NE>(ne: &'a P) -> Result<Self, Error> {
        let header = ne.get_valid_ne_header()?;
        let fields = header.common_fields();
        let size = fields.non_res_name_size as usize;
        let offset = fields.non_res_name_table_offset as usize;
        if size == 0 || offset == 0 {
            return Ok(Self {
                entries: Vec::new(),
            });
        }

        let end = offset.saturating_add(size).min(ne.len());
        let mut entries = Vec::new();
        let mut pos = offset;

        while pos < end {
            let len_byte = ne.get_slice(pos, 1)?[0] as usize;
            pos += 1;
            if len_byte == 0 {
                break;
            }
            let name_bytes = ne.get_slice(pos, len_byte)?;
            pos += len_byte;
            let ordinal = ne.read_u16(pos)?;
            pos += 2;
            entries.push(ResidentName {
                name: PascalString { data: name_bytes },
                ordinal,
            });
        }

        Ok(Self { entries })
    }

    /// Find an entry by ordinal.
    #[must_use]
    pub fn by_ordinal(&self, ordinal: u16) -> Option<&ResidentName<'a>> {
        self.entries.iter().find(|e| e.ordinal == ordinal)
    }
}

// ---------------------------------------------------------------------------
// Module Reference Table
// ---------------------------------------------------------------------------

/// Parsed module reference table.
///
/// Each entry is a WORD (u16) that is an offset into the Imported Names Table.
pub struct ModuleRefTable {
    pub offsets: Vec<u16>,
    pub count: u16,
}

impl ModuleRefTable {
    /// Parse the module reference table.
    ///
    /// The module reference table starts at `ne_modtab` and contains
    /// `ne_cmod` WORDs (where `ne_cmod` is the module count from the header).
    pub fn parse<P: NE>(ne: &P) -> Result<Self, Error> {
        let offset = ne.module_ref_table_offset();
        if offset == 0 {
            return Err(Error::TableNotPresent("module_ref"));
        }

        // Read module count from the NE header
        let header = ne.get_valid_ne_header()?;
        let mod_count = header.common_fields().mod_count;

        let mut offsets = Vec::with_capacity(mod_count as usize);
        let mut pos = offset as usize;

        for _ in 0..mod_count {
            let word = ne.read_u16(pos)?;
            offsets.push(word);
            pos += 2;
        }

        Ok(ModuleRefTable {
            offsets,
            count: mod_count,
        })
    }

    /// Resolve a module name from the ITL by index.
    pub fn get_name<'a, P: NE>(&self, ne: &'a P, index: usize) -> Result<PascalString<'a>, Error> {
        if index >= self.offsets.len() {
            return Err(Error::TableOutOfBounds(
                "module_ref",
                index,
                self.offsets.len(),
            ));
        }

        let itl_offset = ne.imported_names_table_offset() as usize;
        let str_offset = self.offsets[index] as usize + itl_offset;
        let bytes = ne.get_slice(str_offset, 1)?;
        let len = bytes[0] as usize;
        let data = ne.get_slice(str_offset + 1, len)?;

        Ok(PascalString { data })
    }

    /// Resolve a module name for an `IMPORT_ORDINAL` relocation.
    ///
    /// Per `NE_FORMAT.md` Section 24.7:
    /// 1. Use `mod_ref_index` to get offset from module reference table
    /// 2. Add ITL offset to get Pascal string location
    /// 3. Read Pascal string (1 byte length + ASCII bytes)
    pub fn resolve_import_ordinal_name<'a, P: NE>(
        &self,
        ne: &'a P,
        mod_ref_index: u16,
    ) -> Result<PascalString<'a>, Error> {
        if mod_ref_index == 0 || mod_ref_index as usize > self.offsets.len() {
            return Err(Error::TableOutOfBounds(
                "module_ref",
                mod_ref_index as usize,
                self.offsets.len(),
            ));
        }

        // Index is 1-based per NE_FORMAT.md Section 24.7 formula
        let idx = (mod_ref_index - 1) as usize;
        let offset = self.offsets[idx] as usize;
        let itl_offset = ne.imported_names_table_offset() as usize;
        let str_offset = itl_offset + offset;

        let bytes = ne.get_slice(str_offset, 1)?;
        let len = bytes[0] as usize;
        let data = ne.get_slice(str_offset + 1, len)?;

        Ok(PascalString { data })
    }

    /// Resolve a procedure name for an `IMPORT_NAME` relocation.
    ///
    /// Per `NE_FORMAT.md` Section 24.8:
    /// 1. Use `proc_name_offset` directly from the relocation entry
    /// 2. Add ITL offset to get Pascal string location
    /// 3. Read Pascal string (1 byte length + ASCII bytes)
    pub fn resolve_import_name<P: NE>(
        ne: &P,
        proc_name_offset: u16,
    ) -> Result<PascalString<'_>, Error> {
        let itl_offset = ne.imported_names_table_offset() as usize;
        let str_offset = itl_offset + proc_name_offset as usize;

        let bytes = ne.get_slice(str_offset, 1)?;
        let len = bytes[0] as usize;
        let data = ne.get_slice(str_offset + 1, len)?;

        Ok(PascalString { data })
    }
}

// ---------------------------------------------------------------------------
// Imported Names Table (ITL)
// ---------------------------------------------------------------------------

/// Parsed imported names table.
///
/// Contains the Pascal strings (module and procedure names) referenced by
/// the Module Reference Table and by NAME relocations.
pub struct ImportedNamesTable<'a> {
    pub module_names: Vec<PascalString<'a>>,
}

impl<'a> ImportedNamesTable<'a> {
    /// Parse the imported names table.
    ///
    /// The ITL is a **contiguous sequence of Pascal strings** starting at
    /// `ne_imptab` — there is no padding between entries. The first entry
    /// is the empty string (length 0), the ordinal-0 placeholder, and empty
    /// strings must be preserved.
    ///
    /// The table extent runs to the entry table (which immediately follows
    /// the ITL in the reference layout) or to the end of the buffer when the
    /// entry table is absent or precedes the ITL.
    pub fn parse<P: NE>(ne: &'a P) -> Result<Self, Error> {
        let offset = ne.imported_names_table_offset();
        if offset == 0 {
            return Err(Error::TableNotPresent("imported_names"));
        }

        let header = ne.get_valid_ne_header()?;
        let itl_rva = header.imported_names_table_offset as usize;
        let end = if header.entry_table_offset as usize > itl_rva {
            offset as usize + (header.entry_table_offset as usize - itl_rva)
        } else {
            ne.len()
        };

        let mut module_names: Vec<PascalString<'a>> = Vec::new();
        let mut pos = offset as usize;

        while pos < end {
            let len_byte = ne.read_u8(pos)? as usize;
            let data = ne.get_slice(pos + 1, len_byte)?;
            module_names.push(PascalString { data });
            pos += 1 + len_byte;
        }

        Ok(ImportedNamesTable { module_names })
    }

    /// Get module names as UTF-8 strings (returns first non-UTF-8 error).
    pub fn names_str(&self) -> Result<Vec<&'a str>, Error> {
        self.module_names
            .iter()
            .map(|s: &PascalString<'a>| s.as_str())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Entry Table (Exports)
// ---------------------------------------------------------------------------

/// Export entry kind.
///
/// Mirrors the `type` byte of the entry-table records (Wine
/// `dump_ne_exports`):
/// - `Fixed` — the type byte (0x01-0xFD) **is** the 1-based segment number;
///   the record carries 3 bytes per entry (`flags` + `offset`).
/// - `Constant` — type 0xFE; 3 bytes per entry (`flags` + `value`).
/// - `Movable` — type 0xFF; 6 bytes per entry
///   (`flags` + `x` + `x` + `seg` + `offset`).
///
/// (Type 0x00 marks *unused* ordinals — no data bytes — and is represented
/// by a `None` slot in [`EntryTable::entries`], not by an entry.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryType {
    /// Fixed entry — segment number is encoded in the record's type byte.
    Fixed { seg_num: u8, offset: u16 },
    /// Constant entry.
    Constant { value: u16 },
    /// Movable entry.
    Movable { seg_num: u8, offset: u16 },
}

/// A single exported entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportEntry {
    /// Flags byte (bit 7 = private).
    pub flags: u8,
    /// Kind of entry, with its payload.
    pub entry_type: EntryType,
}

impl ExportEntry {
    /// The 1-based segment number (Fixed and Movable entries).
    #[must_use]
    pub fn seg_num(&self) -> Option<u8> {
        match self.entry_type {
            EntryType::Fixed { seg_num, .. } | EntryType::Movable { seg_num, .. } => Some(seg_num),
            EntryType::Constant { .. } => None,
        }
    }

    /// The segment offset (Fixed and Movable entries).
    #[must_use]
    pub fn offset(&self) -> Option<u16> {
        match self.entry_type {
            EntryType::Fixed { offset, .. } | EntryType::Movable { offset, .. } => Some(offset),
            EntryType::Constant { .. } => None,
        }
    }

    /// The constant value (Constant entries).
    #[must_use]
    pub fn constant_value(&self) -> Option<u16> {
        match self.entry_type {
            EntryType::Constant { value } => Some(value),
            _ => None,
        }
    }
}

/// Parsed entry table (export table).
///
/// The on-disk format is a sequence of **records**
/// `[count: u8][type: u8][entry bytes...]` starting at `ne_enttab`, bounded
/// by `ne_cbenttab` bytes. The table ends at the first record with
/// `count == 0` or when the size bound is reached. Ordinals are assigned
/// sequentially from 1 in record order:
/// - type 0x00: `count` *unused* ordinals (no data bytes);
/// - type 0xFF: `count` movable entries, 6 bytes each;
/// - type 0xFE: `count` constant entries, 3 bytes each;
/// - type 0x01-0xFD: `count` fixed entries, 3 bytes each, in the segment
///   named by the type byte.
///
/// `entries[i]` holds the export for ordinal `i + 1`; `None` marks an
/// unused ordinal. A 1-byte table containing `0x00` means "no exports".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EntryTable {
    /// Exports by ordinal: index `i` is ordinal `i + 1`.
    pub entries: Vec<Option<ExportEntry>>,
}

impl EntryTable {
    /// Parse the entry table from an NE buffer.
    ///
    /// Returns [`Error::TableNotPresent`] if the header does not reference
    /// an entry table.
    pub fn parse<P: NE>(ne: &P) -> Result<Self, Error> {
        let start = ne.entry_table_offset() as usize;
        if start == 0 {
            return Err(Error::TableNotPresent("entry_table"));
        }

        let header = ne.get_valid_ne_header()?;
        let size = header.common_fields().entry_table_size as usize;
        let end = start + size;
        let mut entries: Vec<Option<ExportEntry>> = Vec::new();
        let mut pos = start;

        while pos < end {
            // Record header: [count: u8][type: u8]
            let count = ne.read_u8(pos)?;
            let etype = ne.read_u8(pos + 1)?;
            pos += 2;

            if count == 0 {
                break; // terminator record
            }

            // Bytes per entry by record type (Wine `dump_ne_exports`).
            let bytes_per_entry = match etype {
                0x00 => 0, // unused ordinals carry no data
                0xFF => 6,
                _ => 3,
            };

            // The record data must fit inside the declared table size
            // (the 2 header bytes were already consumed above).
            if end - pos < count as usize * bytes_per_entry {
                return Err(Error::EntryTableCorrupt);
            }

            if etype == 0x00 {
                for _ in 0..count {
                    entries.push(None);
                }
                // Same bound as for typed records below: the total ordinal
                // slot count must fit a u16 regardless of record type.
                if entries.len() > u16::MAX as usize {
                    return Err(Error::EntryTableOverflow);
                }
                continue;
            }

            for _ in 0..count {
                let entry = if etype == 0xFF {
                    // Movable: [flags][x][x][seg: u8][offset: u16]
                    let flags = ne.read_u8(pos)?;
                    let seg_num = ne.read_u8(pos + 3)?;
                    let offset = ne.read_u16(pos + 4)?;
                    pos += 6;
                    ExportEntry {
                        flags,
                        entry_type: EntryType::Movable { seg_num, offset },
                    }
                } else if etype == 0xFE {
                    // Constant: [flags][value: u16]
                    let flags = ne.read_u8(pos)?;
                    let value = ne.read_u16(pos + 1)?;
                    pos += 3;
                    ExportEntry {
                        flags,
                        entry_type: EntryType::Constant { value },
                    }
                } else {
                    // Fixed (0x01-0xFD): [flags][offset: u16]; the segment
                    // number is the type byte itself.
                    let flags = ne.read_u8(pos)?;
                    let offset = ne.read_u16(pos + 1)?;
                    pos += 3;
                    ExportEntry {
                        flags,
                        entry_type: EntryType::Fixed {
                            seg_num: etype,
                            offset,
                        },
                    }
                };
                entries.push(Some(entry));
            }

            if entries.len() > u16::MAX as usize {
                return Err(Error::EntryTableOverflow);
            }
        }

        Ok(Self { entries })
    }

    /// Get an export by ordinal (1-based).
    ///
    /// Returns `None` for ordinal 0 or for unused ordinals.
    #[must_use]
    pub fn get_export(&self, ordinal: u16) -> Option<&ExportEntry> {
        if ordinal == 0 {
            return None;
        }
        self.entries
            .get(ordinal as usize - 1)
            .and_then(|e| e.as_ref())
    }

    /// Get the total number of present exports (excluding unused ordinals).
    #[must_use]
    pub fn export_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }
}

// ---------------------------------------------------------------------------
// Resource Table
// ---------------------------------------------------------------------------

/// Resource type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceTypeId<'a> {
    /// Predefined type (high bit set on disk): `RT_STRING`, `RT_ICON`, etc.
    Ordinal(u16),
    /// Custom type name (Pascal string at an offset into the table).
    Name(PascalString<'a>),
}

/// A single resource record (NAMEINFO).
#[derive(Debug, Clone, Copy)]
pub struct ResourceRecord<'a> {
    /// File offset of the resource data (on-disk value shifted left by the
    /// table's size shift).
    pub offset: u32,
    /// Length of the resource data in bytes (on-disk value shifted left by
    /// the table's size shift).
    pub length: u32,
    /// MOVEABLE, PURE, PRELOAD, DISCARDABLE flags.
    pub flags: u16,
    /// Ordinal or string name.
    pub id: ResourceId<'a>,
    /// Reserved.
    pub handle: u16,
    /// Reserved.
    pub usage: u16,
}

/// Resource ID (ordinal or string name).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceId<'a> {
    /// Predefined ordinal (high bit set on disk).
    Ordinal(u16),
    /// Pascal string name at an offset into the resource table.
    Name(PascalString<'a>),
}

/// Type information block in the resource table (TYPEINFO + its NAMEINFOs).
pub struct TypeInfo<'a> {
    pub type_id: ResourceTypeId<'a>,
    pub records: Vec<ResourceRecord<'a>>,
}

/// Parsed resource table.
pub struct ResourceTable<'a> {
    /// The table's own size shift (first word of the table) — NOT the
    /// header's alignment field. Both `offset` and `length` in the
    /// records are stored right-shifted by this value.
    pub alignment_shift: u16,
    pub type_info: Vec<TypeInfo<'a>>,
}

impl<'a> ResourceTable<'a> {
    /// Parse the resource table from an NE buffer.
    ///
    /// Format: the first word of the table is the
    /// table's own **size shift**. Type info records are 8 bytes
    /// (`type_id`, `count`, reserved DWORD); each resource record is 12 bytes
    /// (`offset`, `length`, `flags`, `id`, `handle`, `usage`) with both
    /// `offset` and `length` shifted left by the size shift. A type record
    /// with `type_id == 0` ends the table, as does reaching the resident
    /// name table (the two tables are adjacent in real files).
    pub fn parse<P: NE>(ne: &'a P) -> Result<Self, Error> {
        let start = ne.resource_table_offset() as usize;
        if start == 0 {
            return Err(Error::TableNotPresent("resource_table"));
        }

        let header = ne.get_valid_ne_header()?;

        // No resources declared — nothing to parse. The pointer may still
        // reference the resident name table (as in DUALBTN, where
        // rsrctab == restab and resource_count == 0).
        if header.common_fields().resource_count == 0 {
            return Ok(Self {
                alignment_shift: 0,
                type_info: Vec::new(),
            });
        }

        // The first word of the table is its own size shift — not the
        // header's alignment field.
        let size_shift = ne.read_u16(start)?;
        if size_shift > 16 {
            return Err(Error::InvalidResourceAlignment(size_shift));
        }

        // Wine also stops the type loop once it reaches the resident name
        // table (adjacent in real files).
        let restab = ne.resident_name_table_offset() as usize;

        let mut type_info: Vec<TypeInfo<'a>> = Vec::new();
        let mut pos = start + 2;

        loop {
            if restab > 0 && pos >= restab {
                break;
            }

            // TYPEINFO: [type_id: u16][count: u16][reserved: u32]
            let type_id_raw = ne.read_u16(pos)?;
            if type_id_raw == 0 {
                break; // terminator record
            }
            let record_count = ne.read_u16(pos + 2)?;
            pos += 8;

            let type_id = if type_id_raw & 0x8000 != 0 {
                ResourceTypeId::Ordinal(type_id_raw & 0x7FFF)
            } else {
                let name_offset = start + type_id_raw as usize;
                let len = ne.read_u8(name_offset)? as usize;
                let data = ne.get_slice(name_offset + 1, len)?;
                ResourceTypeId::Name(PascalString { data })
            };

            let mut records: Vec<ResourceRecord<'a>> = Vec::with_capacity(record_count as usize);
            for _ in 0..record_count {
                // NAMEINFO: [offset][length][flags][id][handle][usage]
                let offset_raw = ne.read_u16(pos)?;
                let length_raw = ne.read_u16(pos + 2)?;
                let flags = ne.read_u16(pos + 4)?;
                let id_raw = ne.read_u16(pos + 6)?;
                let handle = ne.read_u16(pos + 8)?;
                let usage = ne.read_u16(pos + 10)?;
                pos += 12;

                let id = if id_raw & 0x8000 != 0 {
                    ResourceId::Ordinal(id_raw & 0x7FFF)
                } else {
                    let name_offset = start + id_raw as usize;
                    let len = ne.read_u8(name_offset)? as usize;
                    let data = ne.get_slice(name_offset + 1, len)?;
                    ResourceId::Name(PascalString { data })
                };

                records.push(ResourceRecord {
                    offset: u32::from(offset_raw) << size_shift,
                    length: u32::from(length_raw) << size_shift,
                    flags,
                    id,
                    handle,
                    usage,
                });
            }

            type_info.push(TypeInfo { type_id, records });
        }

        Ok(Self {
            alignment_shift: size_shift,
            type_info,
        })
    }
}

// ---------------------------------------------------------------------------
// Relocation Table
// ---------------------------------------------------------------------------

/// Address type in a relocation entry.
///
/// Defines what portion of a target address is being relocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum AddressType {
    /// 0x00: Low byte of a 16-bit offset
    LowByte = 0,
    /// 0x02: 16-bit selector
    Selector = 2,
    /// 0x03: 32-bit far pointer (selector:offset)
    Pointer32 = 3,
    /// 0x05: 16-bit offset
    Offset16 = 5,
    /// 0x0B: 48-bit pointer
    Pointer48 = 11,
    /// 0x0D: 32-bit offset
    Offset32 = 13,
    /// Unrecognized address type — preserved for forward compatibility
    Unknown(u8),
}

impl AddressType {
    /// The raw on-disk byte.
    #[must_use]
    pub fn as_u8(&self) -> u8 {
        match self {
            AddressType::LowByte => 0,
            AddressType::Selector => 2,
            AddressType::Pointer32 => 3,
            AddressType::Offset16 => 5,
            AddressType::Pointer48 => 11,
            AddressType::Offset32 => 13,
            AddressType::Unknown(v) => *v,
        }
    }
}

impl From<u8> for AddressType {
    fn from(v: u8) -> Self {
        match v {
            0 => AddressType::LowByte,
            2 => AddressType::Selector,
            3 => AddressType::Pointer32,
            5 => AddressType::Offset16,
            11 => AddressType::Pointer48,
            13 => AddressType::Offset32,
            v => AddressType::Unknown(v),
        }
    }
}

/// Relocation type (Wine `NE_RELTYPE_*`).
///
/// Only bits 0-1 of the on-disk type byte select the type; bit 2 is the
/// additive flag ([`RelocationEntry::is_additive`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum RelocationType {
    /// 0x00: Internal reference (segment:offset, or self-module ordinal)
    Internal = 0,
    /// 0x01: Imported ordinal (module reference index + ordinal)
    Ordinal = 1,
    /// 0x02: Imported name (module reference index + ITL name offset)
    Name = 2,
    /// 0x03: OS-specific fixup (see [`OsFixupType`])
    OSGlobal = 3,
    /// Unrecognized relocation type — preserved for forward compatibility
    Unknown(u8),
}

impl From<u8> for RelocationType {
    fn from(v: u8) -> Self {
        match v {
            0 => RelocationType::Internal,
            1 => RelocationType::Ordinal,
            2 => RelocationType::Name,
            3 => RelocationType::OSGlobal,
            v => RelocationType::Unknown(v),
        }
    }
}

/// OS-specific fixup type for relocation entries 
///
/// Per `NE_FORMAT.md` Section 24.6, these are floating-point instruction fixups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsFixupType {
    /// 0x0001: Floating-Point Instruction Addr Register Quad-Quad (FIARQQ/FJARQQ)
    FiArQq,
    /// 0x0002: Floating-Point Instruction Stack Register Quad-Quad (FISRQQ/FJSRQQ)
    FiSrQq,
    /// 0x0003: Floating-Point Instruction Control Register Quad-Quad (FICRQQ/FJCRQQ)
    FiCrQq,
    /// 0x0004: Floating-Point Instruction Enable Register Quad (FIERQQ)
    FiErQq,
    /// 0x0005: Floating-Point Instruction Data Register Quad (FIDRQQ)
    FiDrQq,
    /// 0x0006: Floating-Point Instruction Word Register Quad (FIWRQQ)
    FiWrQq,
    /// Unrecognized OS fixup type — preserved for forward compatibility
    Unknown(u16),
}

impl From<u16> for OsFixupType {
    fn from(v: u16) -> Self {
        match v {
            1 => OsFixupType::FiArQq,
            2 => OsFixupType::FiSrQq,
            3 => OsFixupType::FiCrQq,
            4 => OsFixupType::FiErQq,
            5 => OsFixupType::FiDrQq,
            6 => OsFixupType::FiWrQq,
            v => OsFixupType::Unknown(v),
        }
    }
}

/// A single 8-byte NE relocation entry.
///
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0      | 1    | `address_type` |
/// | 1      | 1    | `relocation_type` (bits 0-1) + additive flag (bit 2) |
/// | 2      | 2    | `offset` — start of the chain, segment-relative |
/// | 4      | 2    | `target1` |
/// | 6      | 2    | `target2` |
///
/// The `offset` field is the **first link** of a chain inside the segment:
/// the 16-bit value stored at that segment offset is the *next* link, and
/// `0xFFFF` terminates the chain. [`RelocationEntry::resolve_chain`] walks
/// the chain and returns every offset that receives the target value.
///
/// Target interpretation (Wine `dump_relocations`):
/// - [`RelocationType::Internal`] — if `target1 & 0xFF == 0xFF` the entry
///   references the module itself (name = first resident name, ordinal =
///   `target2`); otherwise `target1` is a 1-based segment number and
///   `target2` an offset within that segment.
/// - [`RelocationType::Ordinal`] — `target1` is a 1-based module reference
///   index, `target2` the function ordinal.
/// - [`RelocationType::Name`] — `target1` is a 1-based module reference
///   index, `target2` the byte offset of the Pascal name in the ITL.
#[derive(Debug, Clone, Copy)]
pub struct RelocationEntry {
    /// Address type to fix up.
    pub address_type: AddressType,
    /// Relocation type (bits 0-1 of the on-disk type byte).
    pub relocation_type: RelocationType,
    /// Whether the target value is **added** to the existing content
    /// (bit 2 of the on-disk type byte) rather than replacing it.
    pub is_additive: bool,
    /// 1-based segment number whose data contains the chain (parse context).
    pub segment_number: u16,
    /// Start of the chain, segment-relative (the on-disk `offset` field).
    pub offset: u16,
    /// First target word (interpretation depends on the relocation type).
    pub target1: u16,
    /// Second target word (interpretation depends on the relocation type).
    pub target2: u16,
}

impl RelocationEntry {
    /// True for internal references to the module itself
    /// (`target1 & 0xFF == 0xFF`), where `target2` is an export ordinal.
    #[must_use]
    pub fn is_self_module_ref(&self) -> bool {
        matches!(self.relocation_type, RelocationType::Internal) && self.target1 & 0xFF == 0xFF
    }

    /// 1-based module reference index (Ordinal / Name references).
    #[must_use]
    pub fn mod_ref_index(&self) -> Option<u16> {
        match self.relocation_type {
            RelocationType::Ordinal | RelocationType::Name => Some(self.target1),
            _ => None,
        }
    }

    /// Function ordinal (Ordinal references).
    #[must_use]
    pub fn ordinal_number(&self) -> Option<u16> {
        matches!(self.relocation_type, RelocationType::Ordinal).then_some(self.target2)
    }

    /// Byte offset of the Pascal procedure name in the ITL (Name references).
    #[must_use]
    pub fn proc_name_offset(&self) -> Option<u16> {
        matches!(self.relocation_type, RelocationType::Name).then_some(self.target2)
    }

    /// Walk the relocation chain within `segment_data` and return every
    /// segment-relative offset that receives the target value.
    ///
    /// The chain starts at [`Self::offset`]; at each link the 16-bit value
    /// stored there is the *next* link, and `0xFFFF` terminates the chain.
    pub fn resolve_chain(&self, segment_data: &[u8]) -> Result<Vec<u16>, Error> {
        let mut links: Vec<u16> = Vec::new();
        let mut pos = self.offset;

        while pos != 0xFFFF {
            // Cycle/runaway guard: a chain can touch at most len/2 words.
            if links.len() * 2 > segment_data.len() {
                return Err(Error::RelocationChainCorrupt);
            }
            let p = pos as usize;
            if p + 2 > segment_data.len() {
                return Err(Error::TableOutOfBounds(
                    "relocation_chain",
                    p,
                    segment_data.len(),
                ));
            }
            let next = u16::from_le_bytes([segment_data[p], segment_data[p + 1]]);
            links.push(pos);
            pos = next;
        }

        Ok(links)
    }
}

/// Parsed relocation table.
///
/// Relocation data is stored **per segment**, immediately after each
/// segment's on-disk data when the segment carries the `RELOC_DATA` flag
/// (0x0100): `[count: u16][entries...]`. This struct concatenates the
/// entries of all such segments in segment order.
#[derive(Debug)]
pub struct RelocationTable {
    pub entries: Vec<RelocationEntry>,
}

impl<'a> RelocationTable {
    /// Parse the per-segment relocation tables from an NE buffer.
    ///
    /// For each segment with the `RELOC_DATA` flag, the relocation block
    /// starts at `(seg_data_offset << alignment) + seg_data_length` (the
    /// segment record's offset is a sector offset, not an RVA). The block
    /// begins with a u16 entry count followed by 8-byte entries.
    pub fn parse<P: NE>(ne: &'a P) -> Result<Self, Error> {
        let header = ne.get_valid_ne_header()?;
        let segments = ne.get_segment_table()?;
        let shift = header.common_fields().alignment as usize;
        let mut entries: Vec<RelocationEntry> = Vec::new();

        for (i, seg) in segments.iter().enumerate() {
            if !seg.segment_flags().contains(SegmentFlags::RELOC_DATA) {
                continue;
            }
            let seg_num = i as u16 + 1;

            // Relocations sit right after the segment data:
            //   base = (seg_data_offset << alignment) + seg_data_length
            let base = ((seg.offset as usize) << shift) + (seg.length as usize);
            if base + 2 > ne.len() {
                continue; // unreadable relocation count — skip defensively
            }

            let reloc_count = ne.read_u16(base)? as usize;
            let mut pos = base + 2;

            for _ in 0..reloc_count {
                if pos + 8 > ne.len() {
                    return Err(Error::TableOutOfBounds(
                        "relocation_table",
                        pos + 8,
                        ne.len(),
                    ));
                }
                let raw = ne.get_slice(pos, 8)?;
                let type_raw = raw[1];
                entries.push(RelocationEntry {
                    address_type: AddressType::from(raw[0]),
                    relocation_type: RelocationType::from(type_raw & 0x03),
                    is_additive: type_raw & 0x04 != 0,
                    segment_number: seg_num,
                    offset: u16::from_le_bytes([raw[2], raw[3]]),
                    target1: u16::from_le_bytes([raw[4], raw[5]]),
                    target2: u16::from_le_bytes([raw[6], raw[7]]),
                });
                pos += 8;
            }
        }

        Ok(Self { entries })
    }
}
