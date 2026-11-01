// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! The `LE` trait (buffer + LE/LX operations) and its implementations
//! [`VecLE`] (owned `Vec<u8>`) and [`PtrLE`] (borrowed slice).
//!
//! Tables are parsed **lazily** on demand,.
//!
//! **Offset bases** (critical):
//!
//! | Offset type | Reference point | Used by |
//! |---|---|---|
//! | Header-relative | start of the LE/LX header (`e_lfanew`) | most table pointers |
//! | File-absolute | start of the file the linker wrote | `data_pages`, `non_resident_names` |
//! | Data-section | `data_pages` | page data (LE: page number; LX: shifted offset) |
//!
//! "File-absolute" means the file **the linker wrote**, which for a
//! *bound* image (an extender plus an application in one file) is not the
//! file on disk: [`crate::bound`] resolves the difference, and slicing the
//! buffer at the offset it reports is what makes both bases line up.

use crate::headers::{header_from_bytes, LeHeader, LeHeaderTail};
use crate::types::{
    EntryBundle, EntryFlags, EntryPoint, EntryType, FixupRecord, FixupSourceFlags, FixupSourceType,
    FixupTarget, FixupTargetFlags, LePageEntry, NameEntry, ObjectFlags, ObjectRecord, PageType,
    PascalString,
};
use crate::{
    vec, Error, Vec, DOS_E_LFANEW_OFFSET, DOS_SIGNATURE, LE_HEADER_SIZE, LE_HEADER_TAIL_SIZE,
    LE_PAGE_ENTRY_SIZE, LE_SIGNATURE, LX_PAGE_ENTRY_SIZE, LX_SIGNATURE, OBJECT_RECORD_SIZE,
};

// ---------------------------------------------------------------------------
// Buffer trait
// ---------------------------------------------------------------------------

/// Generic binary buffer. Multi-byte reads are **little-endian** (the LE/LX
/// format is little-endian; the header's byte-order bytes are treated as
/// informational.
pub trait Buffer {
    /// A slice of `len` bytes starting at `offset`, or an error when it
    /// exceeds the buffer.
    fn get_slice(&self, offset: usize, len: usize) -> Result<&[u8], Error>;

    /// Total buffer length in bytes.
    fn len(&self) -> usize;

    /// Whether the buffer is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read one byte.
    fn read_u8(&self, offset: usize) -> Result<u8, Error> {
        Ok(self.get_slice(offset, 1)?[0])
    }

    /// Read a little-endian u16.
    fn read_u16(&self, offset: usize) -> Result<u16, Error> {
        let b = self.get_slice(offset, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Read a little-endian u32.
    fn read_u32(&self, offset: usize) -> Result<u32, Error> {
        let b = self.get_slice(offset, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a little-endian u64.
    fn read_u64(&self, offset: usize) -> Result<u64, Error> {
        let b = self.get_slice(offset, 8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
}

// ---------------------------------------------------------------------------
// LE trait
// ---------------------------------------------------------------------------

/// LE/LX file operations. All reads are bounds-checked; malformed input
/// yields an [`Error`], never a panic.
pub trait LE: Buffer {
    /// Offset of the LE/LX header in the file.
    ///
    /// Files normally start with a DOS MZ header; the header offset is
    /// `e_lfanew` (DOS header offset 0x3C). Files without an MZ header
    /// start with the LE/LX header at offset 0.
    fn header_offset(&self) -> Result<usize, Error>;

    /// Zero-copy view of the LE/LX header (no signature validation).
    fn get_le_header_ref(&self) -> Result<&LeHeader, Error>;

    /// Owned copy of the LE/LX header (no signature validation).
    fn get_le_header(&self) -> Result<LeHeader, Error>;

    /// Header validated for signature and basic structural sanity.
    fn get_valid_le_header(&self) -> Result<LeHeader, Error>;

    /// The object table (24-byte records, 1-based object numbers).
    fn get_object_table(&self) -> Result<Vec<ObjectRecord>, Error>;

    /// The object page table (LE: 4-byte entries, LX: 8-byte entries).
    fn get_page_table(&self) -> Result<Vec<LePageEntry>, Error>;

    /// Resident name table: module name first, then the exported names.
    ///
    /// `[LEN][STRING][ORDINAL DW]` entries — the same shape as the
    /// non-resident table — terminated by a zero length byte and bounded by
    /// `entry_table`. A module that only names itself yields a one-entry
    /// `Vec` (the Watcom fixtures).
    fn get_resident_names(&self) -> Result<Vec<NameEntry<'_>>, Error>;

    /// The entry (export) table, decoded into bundles.
    ///
    /// Grammar and ordinal numbering are documented on
    /// [`crate::types::EntryType`]. The table has no count field and no
    /// terminator in the draft: it is scanned until its first byte is the
    /// end-of-table `0`, bounded by the next non-zero header-relative table
    /// offset after it (verified: the loader tables are laid out back to back
    /// — in `testdata/fixtures/hellovxd.BIN` the entry table at `0xE9` ends
    /// at `0xF3`, where the fixup page table starts, with `00 00 00` padding
    /// in between). A malformed table yields [`Error::EntryTableCorrupt`]; a
    /// module that exports nothing yields an empty `Vec`.
    fn get_entry_table(&self) -> Result<Vec<EntryBundle>, Error>;

    /// The non-resident name table: `[LEN][STRING][ORDINAL DW]` entries,
    /// terminated by a zero length byte.
    ///
    /// `non_resident_names` (0x88) is **file-absolute**, and
    /// `non_resident_names_size` (0x8C) gives the table's size — the only LE
    /// table with an explicit size. The declared size covers the terminator,
    /// not just the entries. A module without one yields an empty
    /// `Vec`.
    fn get_non_resident_names(&self) -> Result<Vec<NameEntry<'_>>, Error>;

    /// Imported module names in table order; the 1-based position in this
    /// list is the module ordinal a fixup record or forwarder refers to.
    fn get_import_modules(&self) -> Result<Vec<PascalString<'_>>, Error>;

    /// Imported procedure names in table order.
    ///
    /// The first entry is a **mandatory null entry** (`LEN` 0, no string)
    /// so a walk that treats the leading `00` as the terminator finds nothing. The index in
    /// the returned list is therefore **one past** the table position: entry
    /// 0 of the table is the null entry, `list[0]` is the first name.
    ///
    /// The table's end is the end of the fixup section.
    /// Where that bound is not usable the walk falls back to the next table
    /// pointer / the data area. It yields an empty `Vec` when the module
    /// table is empty, which is what the three `VxD` fixtures describe.
    fn get_import_procedures(&self) -> Result<Vec<PascalString<'_>>, Error>;

    /// The fixup page table: one u32 per module page **plus one sentinel**
    /// entry, so `module_pages + 1` entries. The last one is not a page's
    /// offset — it is the size of the fixup record table.
    fn get_fixup_page_table(&self) -> Result<Vec<u32>, Error>;

    /// The fixup record table, decoded record by record.
    ///
    /// Records are variable length, so the table is **walked**, never divided:
    /// the fixup-page-table sentinel gives the table's end and each record's
    /// own two leading bytes give its length. Measured byte-exact on every
    /// LE/LX file in both corpora — the thirteen committed fixtures,
    /// each one ending exactly on the sentinel, page span by page
    /// span (that is also why the sentinel, not `fixup_size`, bounds this
    /// table).
    ///
    /// Records come back in table order, grouped by the page the fixup page
    /// table says they belong to; [`crate::types::FixupRecord::page`] is the
    /// 0-based row of the object page table, matching [`Self::read_page`].
    /// A module with no fixup page table yields an empty `Vec`. A record whose
    /// source type the format leaves undefined yields
    /// [`Error::UnsupportedFixupSource`]; one that would run past the sentinel
    /// yields [`Error::TableOutOfBounds`] — never a panic.
    fn get_fixup_records(&self) -> Result<Vec<FixupRecord>, Error>;

    /// The 20 bytes at header-relative `0xB0..=0xC3` (`VxD` resource table
    /// pointer, device id, DDK version), or `None` when the file does not
    /// have them: either the buffer ends inside that region, or one of the
    /// header's table pointers starts inside it. Every LE/LX fixture here
    /// leaves the region unclaimed — their object tables start at
    /// header-relative `0xC4` — so the answer is `Some`; the check exists for
    /// files that do start a table there, where reading those bytes as
    /// `ddk_version` would be a fabrication.
    fn get_header_tail(&self) -> Result<Option<LeHeaderTail>, Error>;

    /// Decode one module page to its in-memory form (padded to the page
    /// size). `index` is a **0-based index into the object page table**, not
    /// a page number: the page numbers stored in those entries are only the
    /// storage slots, and real producers permute them.
    /// In LE the short page is therefore the entry whose **page number equals
    /// `module_pages`**, not the last table entry.
    /// Supports page types 0 (raw), 1 (iterated) and 3 (zero-filled); other
    /// types yield [`Error::UnsupportedPageType`].
    fn read_page(&self, index: u32) -> Result<Vec<u8>, Error>;

    /// Reassemble the complete in-memory image of one object (1-based
    /// number): its pages concatenated, truncated to the object's virtual
    /// size. A stack/data object whose virtual size exceeds its pages is
    /// zero-extended (verified behavior of Open Watcom DOS32A output).
    fn object_image(&self, object_number: u32) -> Result<Vec<u8>, Error>;
}

// ---------------------------------------------------------------------------
// LE trait implementations (shared logic, generic over Buffer)
// ---------------------------------------------------------------------------

impl<T: Buffer + ?Sized> LE for T {
    fn header_offset(&self) -> Result<usize, Error> {
        if self.len() >= 2 && self.read_u16(0)? == DOS_SIGNATURE {
            let off = self.read_u32(DOS_E_LFANEW_OFFSET)? as usize;
            // `e_lfanew` must point past the DOS header and inside the file.
            if off == 0 || off < 0x40 || off >= self.len() {
                return Err(Error::HeaderOutOfBounds(off));
            }
            Ok(off)
        } else {
            // No MZ header: the LE/LX header starts at offset 0.
            Ok(0)
        }
    }

    fn get_le_header_ref(&self) -> Result<&LeHeader, Error> {
        let off = self.header_offset()?;
        if self.len() < off.saturating_add(LE_HEADER_SIZE) {
            return Err(Error::HeaderTooSmall);
        }
        LeHeader::from_bytes(self.get_slice(off, LE_HEADER_SIZE)?)
    }

    fn get_le_header(&self) -> Result<LeHeader, Error> {
        let off = self.header_offset()?;
        if self.len() < off.saturating_add(LE_HEADER_SIZE) {
            return Err(Error::HeaderTooSmall);
        }
        header_from_bytes(self.get_slice(off, LE_HEADER_SIZE)?)
    }

    fn get_valid_le_header(&self) -> Result<LeHeader, Error> {
        // Signature first: a short file with a wrong magic reports
        // `InvalidSignature`, not `HeaderTooSmall` (diagnostic quality).
        let off = self.header_offset()?;
        if self.len() >= off.saturating_add(2) {
            let sig = self.read_u16(off)?;
            if sig != LE_SIGNATURE && sig != LX_SIGNATURE {
                return Err(Error::InvalidSignature(sig));
            }
        }
        let header = self.get_le_header()?;
        header.validate()?;
        Ok(header)
    }

    fn get_object_table(&self) -> Result<Vec<ObjectRecord>, Error> {
        let header = self.get_valid_le_header()?;
        let count = header.object_count as usize;
        if count == 0 {
            return Ok(Vec::new());
        }
        let start = self.header_offset()? + header.object_table_offset();
        let end = start.saturating_add(count * OBJECT_RECORD_SIZE);
        if end > self.len() {
            return Err(Error::TableOutOfBounds("object_table", start, end));
        }
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let o = start + i * OBJECT_RECORD_SIZE;
            let first_page = self.read_u32(o + 12)?;
            let page_count = self.read_u32(o + 16)?;
            // Page numbers are 1-based; the object's last page number must
            // not exceed the module's page count.
            if first_page == 0
                || first_page as usize + page_count as usize - 1 > header.module_pages as usize
            {
                return Err(Error::ObjectTableCorrupt);
            }
            out.push(ObjectRecord {
                virtual_size: self.read_u32(o)?,
                relocation_base: self.read_u32(o + 4)?,
                // `from_bits_retain`, not `from_bits_truncate`: bits 8–10 are
                // the object-type field and would otherwise be dropped before
                // `ObjectRecord::object_type` could read them.
                flags: ObjectFlags::from_bits_retain(self.read_u32(o + 8)?),
                first_page,
                page_count,
                // Object-record field +20: the Microsoft DDK linker stores a
                // four-character object name there (`"LCOD"` in every
                // `testdata/fixtures/hello*.BIN` object), `wlink` zeroes it.
                object_name: [
                    self.read_u8(o + 20)?,
                    self.read_u8(o + 21)?,
                    self.read_u8(o + 22)?,
                    self.read_u8(o + 23)?,
                ],
            });
        }
        Ok(out)
    }

    fn get_page_table(&self) -> Result<Vec<LePageEntry>, Error> {
        let header = self.get_valid_le_header()?;
        let count = header.module_pages as usize;
        if count == 0 {
            return Ok(Vec::new());
        }
        let entry_size = if header.is_lx() {
            LX_PAGE_ENTRY_SIZE
        } else {
            LE_PAGE_ENTRY_SIZE
        };
        let start = self.header_offset()? + header.object_page_table_offset();
        let end = start.saturating_add(count * entry_size);
        if end > self.len() {
            return Err(Error::TableOutOfBounds("object_page_table", start, end));
        }
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let o = start + i * entry_size;
            if header.is_lx() {
                out.push(LePageEntry::Lx {
                    data_offset: self.read_u32(o)?,
                    data_size: self.read_u16(o + 4)?,
                    flags: self.read_u16(o + 6)?,
                });
            } else {
                // LE: 3-byte BIG-ENDIAN file page number + 1-byte flags.
                let b = self
                    .get_slice(o, LE_PAGE_ENTRY_SIZE)
                    .map_err(|_| Error::TableOutOfBounds("object_page_table", o, o + 4))?;
                let file_page = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
                out.push(LePageEntry::Le {
                    file_page,
                    flags: b[3],
                });
            }
        }
        Ok(out)
    }

    fn get_resident_names(&self) -> Result<Vec<NameEntry<'_>>, Error> {
        let header = self.get_valid_le_header()?;
        if header.resident_names == 0 {
            return Ok(Vec::new());
        }
        let base = self.header_offset()?;
        let start = base + header.resident_names_offset();
        // The table occupies [resident_names, entry_table) when the entry
        // table follows it in the file; otherwise parse to the buffer end
        // (defensive; every verified file has the entry table after it).
        let end = if header.entry_table != 0
            && header.entry_table_offset() > header.resident_names_offset()
        {
            base + header.entry_table_offset()
        } else {
            self.len()
        };
        if start >= end {
            return Ok(Vec::new());
        }
        walk_name_entries(self, "resident_names", start, end.min(self.len()))
    }

    fn get_entry_table(&self) -> Result<Vec<EntryBundle>, Error> {
        let header = self.get_valid_le_header()?;
        if header.entry_table == 0 {
            return Ok(Vec::new());
        }
        let base = self.header_offset()?;
        let start = base + header.entry_table_offset();
        let end = table_end(self, &header, start);
        if start >= end.min(self.len()) {
            return Err(Error::TableOutOfBounds("entry_table", start, end));
        }
        let mut out = Vec::new();
        let mut pos = start;
        // Ordinals are positional: numbered from 1, across bundles in file
        // order, with an unused bundle consuming `count` ordinals.
        let mut next_ordinal = 1u32;
        loop {
            if pos >= end {
                break;
            }
            let count = self.read_u8(pos)?;
            // A zero count ends the table. Producers pad the tail with 00
            // bytes (`hellovxd.BIN` stores `00 00 00` between its last
            // bundle and the fixup page table).
            if count == 0 {
                break;
            }
            let kind = EntryType::from_byte(self.read_u8(pos + 1)?);
            // The two header bytes are followed by an OBJECT word for the
            // entry types and a RESERVED word for forwarders; an unused
            // bundle has no word at all.
            let has_object = !matches!(kind, EntryType::Unused);
            let header_size = if has_object { 4 } else { 2 };
            let entry_size = kind.entry_size();
            let total = header_size + count as usize * entry_size;
            if matches!(kind, EntryType::Unknown(_)) {
                // A bundle type the format does not define — including one
                // with the 0x80 "parameter typing information" bit, whose
                // payload no document specifies. Refuse rather than guess.
                return Err(Error::EntryTableCorrupt);
            }
            if pos + total > end {
                return Err(Error::EntryTableCorrupt);
            }
            let object = if has_object {
                u16::from_le_bytes([self.read_u8(pos + 2)?, self.read_u8(pos + 3)?])
            } else {
                0
            };
            let mut entries = Vec::new();
            // An unused bundle carries no entry data at all: it only consumes
            // ordinals, so its entry loop must not run.
            if entry_size > 0 {
                entries = Vec::with_capacity(count as usize);
                let mut p = pos + header_size;
                for _ in 0..count {
                    let flags = EntryFlags::from_bits_retain(self.read_u8(p)?);
                    let entry = match kind {
                        EntryType::Entry16 => EntryPoint::Offset16 {
                            flags,
                            offset: self.read_u16(p + 1)?,
                        },
                        EntryType::CallGate16 => EntryPoint::CallGate {
                            flags,
                            offset: self.read_u16(p + 1)?,
                            callgate: self.read_u16(p + 3)?,
                        },
                        EntryType::Entry32 => EntryPoint::Offset32 {
                            flags,
                            offset: self.read_u32(p + 1)?,
                        },
                        EntryType::Forwarder => EntryPoint::Forwarder {
                            flags,
                            module_ordinal: self.read_u16(p + 1)?,
                            value: self.read_u32(p + 3)?,
                        },
                        // Unreachable: `Unused` never enters this loop and
                        // `Unknown` is rejected above.
                        EntryType::Unused | EntryType::Unknown(_) => {
                            return Err(Error::EntryTableCorrupt);
                        }
                    };
                    entries.push(entry);
                    p += entry_size;
                }
            }
            out.push(EntryBundle {
                kind,
                object,
                first_ordinal: next_ordinal,
                count,
                entries,
            });
            next_ordinal += u32::from(count);
            pos += total;
        }
        Ok(out)
    }

    fn get_non_resident_names(&self) -> Result<Vec<NameEntry<'_>>, Error> {
        let header = self.get_valid_le_header()?;
        if header.non_resident_names == 0 || header.non_resident_names_size == 0 {
            return Ok(Vec::new());
        }
        // File-absolute (0x88) — never add the header offset.
        let start = header.non_resident_names as usize;
        let declared_end = start.saturating_add(header.non_resident_names_size as usize);
        let end = declared_end.min(self.len());
        if start >= end {
            return Err(Error::TableOutOfBounds(
                "non_resident_names",
                start,
                declared_end,
            ));
        }
        walk_name_entries(self, "non_resident_names", start, end)
    }

    fn get_import_modules(&self) -> Result<Vec<PascalString<'_>>, Error> {
        let header = self.get_valid_le_header()?;
        if header.import_modules == 0 || header.import_module_count == 0 {
            return Ok(Vec::new());
        }
        let base = self.header_offset()?;
        let start = base + header.import_modules as usize;
        // Bounded by the import procedure table, which follows it: measured
        // byte-exact on `os2-lx.BIN` (`0x209..0x212` = the 9-byte entry
        // `[8]"DOSCALLS"`).
        walk_pascal_names(
            self,
            "import_modules",
            start,
            table_end(self, &header, start),
        )
    }

    fn get_import_procedures(&self) -> Result<Vec<PascalString<'_>>, Error> {
        let header = self.get_valid_le_header()?;
        // A procedure name can only belong to an imported module, so an empty
        // module table means no procedure names either. That matters because
        // the three VxD fixtures store `import_procedures == import_modules`
        // (both `0x10E` in `hellovxd.BIN`, `0xC3B` in `vmdisp9xvxd.BIN`) at a
        // position where the next byte is *not* zero, so a walk from there
        // would invent a name.
        if header.import_procedures == 0
            || header.import_module_count == 0
            || header.import_procedures == header.import_modules
        {
            return Ok(Vec::new());
        }
        let base = self.header_offset()?;
        let start = base + header.import_procedures as usize;
        // The fixup section ends the procedure table: page table + record
        // table + module names + procedure names, measured from
        // `fixup_page_table`. Where the pair is unusable
        // (`fixup_page_table` 0, or a size that runs past the buffer, which
        // `vmdisp9xvxd.BIN` stores as ASCII), fall back to the next table
        // pointer / the data area.
        let section = header
            .fixup_page_table
            .checked_add(header.fixup_size)
            .and_then(|offset| usize::try_from(offset).ok())
            .filter(|_| header.fixup_page_table != 0)
            .map(|offset| base + offset)
            .filter(|&end| end <= self.len());
        let end = section.unwrap_or_else(|| table_end(self, &header, start));
        if end <= start {
            return Ok(Vec::new());
        }
        let limit = end.min(self.len());
        let mut out = Vec::new();
        let mut pos = start;
        // The mandatory null entry: `[LEN]` 0, no string bytes. Only the
        // first entry may be empty this way — everywhere else a zero length
        // byte still terminates the table.
        if self.read_u8(pos)? == 0 {
            pos += 1;
        }
        while pos < limit {
            let rest = self
                .get_slice(pos, limit - pos)
                .map_err(|_| Error::TableOutOfBounds("import_procedures", pos, limit))?;
            let Some(name) = PascalString::new(rest) else {
                break;
            };
            if name.char_len() == 0 {
                break;
            }
            out.push(name);
            pos += 1 + name.char_len();
        }
        Ok(out)
    }

    fn get_fixup_page_table(&self) -> Result<Vec<u32>, Error> {
        let header = self.get_valid_le_header()?;
        if header.fixup_page_table == 0 {
            return Ok(Vec::new());
        }
        let base = self.header_offset()?;
        let start = base + header.fixup_page_table as usize;
        // `module_pages + 1` entries: the extra one is the fixup record
        // table's size, not a page offset.
        let count = header.module_pages as usize + 1;
        let end = start.saturating_add(count * 4);
        if end > self.len() {
            return Err(Error::TableOutOfBounds("fixup_page_table", start, end));
        }
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            out.push(self.read_u32(start + i * 4)?);
        }
        Ok(out)
    }

    fn get_fixup_records(&self) -> Result<Vec<FixupRecord>, Error> {
        let header = self.get_valid_le_header()?;
        if header.fixup_page_table == 0 {
            return Ok(Vec::new());
        }
        let page_table = self.get_fixup_page_table()?;
        let Some(&sentinel) = page_table.last() else {
            return Ok(Vec::new());
        };
        if sentinel == 0 {
            return Ok(Vec::new());
        }
        if header.fixup_record_table == 0 {
            return Err(Error::TableOutOfBounds(
                "fixup_record_table",
                self.header_offset()?,
                self.len(),
            ));
        }
        let base = self.header_offset()? + header.fixup_record_table as usize;
        let bound = base + sentinel as usize;
        if bound > self.len() {
            return Err(Error::TableOutOfBounds(
                "fixup_record_table",
                base,
                self.len(),
            ));
        }
        // Walk one page span at a time so each record can be attributed to the
        // object-page-table row its records belong to. A span that dips below
        // its own start (a malformed entry) is treated as empty rather than
        // rejected: the sentinel, not the page table, decides the table's end.
        let mut out = Vec::new();
        for row in 0..page_table.len() - 1 {
            let start = page_table[row] as usize;
            let stop = usize::max(page_table[row + 1] as usize, start);
            let mut pos = start;
            while pos < stop {
                let record = read_fixup_record(self, base + pos, base, row as u32, bound)?;
                pos += record.size;
                out.push(record);
            }
        }
        Ok(out)
    }

    fn get_header_tail(&self) -> Result<Option<LeHeaderTail>, Error> {
        let header = self.get_valid_le_header()?;
        let base = self.header_offset()?;
        let region = base + LE_HEADER_SIZE;
        if self.len() < region + LE_HEADER_TAIL_SIZE {
            return Ok(None);
        }
        // A header-relative table pointer inside `0xB0..0xC4` means the bytes
        // there belong to that table, not to the tail.
        let claims_tail = |off: u32| {
            let off = off as usize;
            off != 0 && (LE_HEADER_SIZE..LE_HEADER_SIZE + LE_HEADER_TAIL_SIZE).contains(&off)
        };
        let claimed = table_pointers(&header)
            .into_iter()
            .any(claims_tail)
            // For a stubless image (header at offset 0) the two file-absolute
            // pointers are header-relative too, so they get the same check.
            || (base == 0
                && [header.data_pages, header.non_resident_names]
                    .into_iter()
                    .any(claims_tail));
        if claimed {
            return Ok(None);
        }
        let bytes = self.get_slice(region, LE_HEADER_TAIL_SIZE).map_err(|_| {
            Error::TableOutOfBounds("header_tail", region, region + LE_HEADER_TAIL_SIZE)
        })?;
        Ok(LeHeaderTail::from_bytes(bytes))
    }

    fn read_page(&self, index: u32) -> Result<Vec<u8>, Error> {
        let header = self.get_valid_le_header()?;
        let pages = self.get_page_table()?;
        let Some(entry) = pages.get(index as usize) else {
            return Err(Error::PageNotFound(index));
        };
        let page_size = header.page_size as usize;
        match entry {
            LePageEntry::Le { file_page, .. } => {
                match entry.page_type() {
                    PageType::ZeroFilled => Ok(vec![0u8; page_size]),
                    PageType::Legal | PageType::Iterated => {
                        if *file_page == 0 {
                            return Err(Error::PageDataCorrupt);
                        }
                        let off =
                            header.data_pages_offset() + (*file_page as usize - 1) * page_size;
                        // The short page is the one whose stored **page number**
                        // is `module_pages`, not the last entry of the table:
                        // page numbers are storage slots and may be permuted.
                        let is_last = *file_page as usize == header.module_pages as usize;
                        let on_disk = if is_last {
                            // LE: the last page stores only its real byte count.
                            (header.last_page_bytes() as usize).min(page_size)
                        } else {
                            page_size
                        };
                        let raw = self.get_slice(off, on_disk).map_err(|_| {
                            Error::TableOutOfBounds("page_data", off, off + on_disk)
                        })?;
                        if matches!(entry.page_type(), PageType::Iterated) {
                            decode_iterated(raw, page_size)
                        } else {
                            let mut page = raw.to_vec();
                            page.resize(page_size, 0);
                            Ok(page)
                        }
                    }
                    other => Err(Error::UnsupportedPageType(other.num())),
                }
            }
            LePageEntry::Lx {
                data_offset,
                data_size,
                ..
            } => match entry.page_type() {
                PageType::ZeroFilled => Ok(vec![0u8; page_size]),
                PageType::Legal | PageType::Iterated => {
                    let off = header.data_pages_offset()
                        + ((*data_offset as usize) << header.page_offset_shift());
                    let raw = self.get_slice(off, *data_size as usize).map_err(|_| {
                        Error::TableOutOfBounds("page_data", off, off + *data_size as usize)
                    })?;
                    if matches!(entry.page_type(), PageType::Iterated) {
                        decode_iterated(raw, page_size)
                    } else {
                        let mut page = raw.to_vec();
                        page.resize(page_size, 0);
                        Ok(page)
                    }
                }
                other => Err(Error::UnsupportedPageType(other.num())),
            },
        }
    }

    fn object_image(&self, object_number: u32) -> Result<Vec<u8>, Error> {
        let objects = self.get_object_table()?;
        let Some(obj) = objects.get(object_number as usize - 1) else {
            return Err(Error::ObjectNotFound(object_number));
        };
        let mut image = Vec::new();
        for k in 0..obj.page_count {
            image.extend(self.read_page(obj.first_page - 1 + k)?);
        }
        let vsize = obj.virtual_size as usize;
        if image.len() < vsize {
            // Verified Watcom behavior: a stack/data object may claim more
            // memory than its pages hold; the remainder is zero-filled.
            image.resize(vsize, 0);
        }
        image.truncate(vsize);
        Ok(image)
    }
}

// ---------------------------------------------------------------------------
// Shared helpers for the uncounted loader tables
// ---------------------------------------------------------------------------

/// Every header-relative table pointer in the header.
///
/// These tables are laid out back to back with no directory, so a table that
/// carries neither a count nor a terminator can only be bounded by the next
/// pointer after it — that is how the entry table and the import procedure
/// name table are walked.
fn table_pointers(header: &LeHeader) -> [u32; 13] {
    [
        header.object_table,
        header.object_page_table,
        header.iterated_map,
        header.resource_table,
        header.resident_names,
        header.entry_table,
        header.directive_table,
        header.fixup_page_table,
        header.fixup_record_table,
        header.import_modules,
        header.import_procedures,
        header.page_checksum,
        header.debug_info,
    ]
}

/// Smallest non-zero header-relative table offset strictly greater than
/// `after` (both as file offsets); the buffer length when there is none.
fn next_table_bound<T: Buffer + ?Sized>(buf: &T, after: usize) -> usize {
    let Ok(header) = buf.get_le_header() else {
        return buf.len();
    };
    let Ok(base) = buf.header_offset() else {
        return buf.len();
    };
    table_pointers(&header)
        .into_iter()
        .filter(|&off| off != 0)
        .map(|off| base + off as usize)
        .filter(|file_off| *file_off > after)
        .min()
        .unwrap_or(buf.len())
}

/// Where an uncounted table that starts at file offset `start` ends: the next
/// table pointer after it, the start of the data area, or the buffer end —
/// whichever comes first.
///
/// The data-area bound is what closes the *last* table in the file, and it is
/// exact: in `os2-lx.BIN` the import procedure names span `0x212..0x214`
/// (`data_pages` = `0x214`), in `vmdisp9xvxd.BIN` `0xCBB..0xCBC`
/// (`data_pages` = `0xCBC`).
fn table_end<T: Buffer + ?Sized>(buf: &T, header: &LeHeader, start: usize) -> usize {
    let mut end = next_table_bound(buf, start).min(buf.len());
    let data = header.data_pages as usize;
    if data > start {
        end = end.min(data);
    }
    end
}

/// Walk a table of `[LEN][ASCII]` entries from `start` up to `limit`,
/// stopping at a zero length byte (the terminator every producer writes), at
/// `limit`, or on truncated trailing data.
fn walk_pascal_names<'a, T: Buffer + ?Sized>(
    buf: &'a T,
    table: &'static str,
    start: usize,
    limit: usize,
) -> Result<Vec<PascalString<'a>>, Error> {
    let limit = limit.min(buf.len());
    if start >= limit {
        return Err(Error::TableOutOfBounds(table, start, limit));
    }
    let mut out = Vec::new();
    let mut pos = start;
    while pos < limit {
        let rest = buf
            .get_slice(pos, limit - pos)
            .map_err(|_| Error::TableOutOfBounds(table, pos, limit))?;
        let Some(name) = PascalString::new(rest) else {
            break;
        };
        if name.char_len() == 0 {
            break;
        }
        out.push(name);
        pos += 1 + name.char_len();
    }
    Ok(out)
}

/// Walk a name table whose entries are `[LEN][STRING][ORDINAL DW]` — the
/// resident and non-resident tables share the shape.
///
/// Stops on a zero length byte (the terminator), on truncated trailing data,
/// or at `limit`. Every file in the corpus ends its name list this way; the
/// one that is large enough to discriminate the layout `vmdisp9xvxd.BIN`
// (`[7]"VXD_DDB" 01 00`, exactly its declared size) —
/// require the ordinal word: without it the walk stops after the module name
/// because the low byte of the next entry's ordinal reads as the terminator.
fn walk_name_entries<'a, T: Buffer + ?Sized>(
    buf: &'a T,
    table: &'static str,
    start: usize,
    limit: usize,
) -> Result<Vec<NameEntry<'a>>, Error> {
    let limit = limit.min(buf.len());
    if start >= limit {
        return Err(Error::TableOutOfBounds(table, start, limit));
    }
    let mut out = Vec::new();
    let mut pos = start;
    while pos < limit {
        let rest = buf
            .get_slice(pos, limit - pos)
            .map_err(|_| Error::TableOutOfBounds(table, pos, limit))?;
        let Some(name) = PascalString::new(rest) else {
            break;
        };
        if name.char_len() == 0 {
            break;
        }
        let entry_len = 1 + name.char_len() + 2;
        if entry_len > rest.len() {
            break; // the ordinal word is cut off
        }
        out.push(NameEntry {
            name,
            ordinal: buf.read_u16(pos + 1 + name.char_len())?,
        });
        pos += entry_len;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Fixup record decoder
// ---------------------------------------------------------------------------

/// Decode the fixup record that starts at `at`.
///
/// `table` is the record table's first byte (so the record can report its own
/// offset), `page` the object-page-table row this record's page span belongs
/// to, and `bound` the table's end — the fixup page table's size sentinel. A
/// record is allowed to run past the page span its row names (the fixup page
/// table is not a per-record index and real producers let a long record cross
/// a span boundary), but never past `bound`.
///
/// The record's length is derived from its own two leading bytes, never
/// assumed: the source byte selects the source-offset form and the
/// target-flags byte the target form and field widths, exactly as `wdump -f`
/// decodes them.
fn read_fixup_record<T: Buffer + ?Sized>(
    buf: &T,
    at: usize,
    table: usize,
    page: u32,
    bound: usize,
) -> Result<FixupRecord, Error> {
    let fits = |pos: usize, n: usize| -> Result<(), Error> {
        if pos.saturating_add(n) > bound {
            return Err(Error::TableOutOfBounds("fixup_record_table", pos, bound));
        }
        Ok(())
    };
    fits(at, 2)?;
    let source_byte = buf.read_u8(at)?;
    let target_flags = FixupTargetFlags::from_bits_truncate(buf.read_u8(at + 1)?);
    let source_type = FixupSourceType::from_byte(source_byte & 0x0F);
    let source_flags = FixupSourceFlags::from_bits_truncate(source_byte);
    if matches!(source_type, FixupSourceType::Undefined(_)) {
        // An undefined source type gives the record no length, so the rest of
        // the table is unlocatable. Refuse instead of guessing a width.
        return Err(Error::UnsupportedFixupSource(source_type.num()));
    }
    let listed = source_flags.contains(FixupSourceFlags::SOURCE_LIST);
    // `INDEX_16` widens whichever index the target form uses: the object
    // number, the import module ordinal, or the entry ordinal.
    let index_size = usize::from(target_flags.contains(FixupTargetFlags::INDEX_16)) + 1;
    let mut pos = at + 2;
    let mut source_offsets = Vec::new();
    let mut list_count = 0usize;
    if listed {
        fits(pos, 1)?;
        list_count = usize::from(buf.read_u8(pos)?);
        pos += 1;
        // The list itself trails the record; account for its span now so a
        // truncated one is caught before anything is pushed.
        fits(pos, 2 * list_count)?;
    } else {
        fits(pos, 2)?;
        source_offsets.push(buf.read_u16(pos)?);
        pos += 2;
    }
    let target = match target_flags.target_type() {
        0 => {
            fits(pos, index_size)?;
            let object = if index_size == 2 {
                buf.read_u16(pos)?
            } else {
                u16::from(buf.read_u8(pos)?)
            };
            pos += index_size;
            // A selector source has no target-offset field at all; every other
            // source type stores one.
            let offset = if matches!(source_type, FixupSourceType::Selector16) {
                None
            } else {
                let wide = target_flags.contains(FixupTargetFlags::TARGET_OFFSET_32);
                let size = usize::from(wide) * 2 + 2;
                fits(pos, size)?;
                let value = if wide {
                    buf.read_u32(pos)?
                } else {
                    u32::from(buf.read_u16(pos)?)
                };
                pos += size;
                Some(value)
            };
            FixupTarget::Internal { object, offset }
        }
        1 => {
            fits(pos, index_size)?;
            let module_ordinal = if index_size == 2 {
                buf.read_u16(pos)?
            } else {
                u16::from(buf.read_u8(pos)?)
            };
            pos += index_size;
            let size = if target_flags.contains(FixupTargetFlags::ORDINAL_8) {
                1
            } else if target_flags.contains(FixupTargetFlags::TARGET_OFFSET_32) {
                4
            } else {
                2
            };
            fits(pos, size)?;
            let ordinal = match size {
                1 => u32::from(buf.read_u8(pos)?),
                4 => buf.read_u32(pos)?,
                _ => u32::from(buf.read_u16(pos)?),
            };
            pos += size;
            FixupTarget::ImportByOrdinal {
                module_ordinal,
                ordinal,
            }
        }
        2 => {
            fits(pos, index_size)?;
            let module_ordinal = if index_size == 2 {
                buf.read_u16(pos)?
            } else {
                u16::from(buf.read_u8(pos)?)
            };
            pos += index_size;
            let wide = target_flags.contains(FixupTargetFlags::TARGET_OFFSET_32);
            let size = usize::from(wide) * 2 + 2;
            fits(pos, size)?;
            let name_offset = if wide {
                buf.read_u32(pos)?
            } else {
                u32::from(buf.read_u16(pos)?)
            };
            pos += size;
            FixupTarget::ImportByName {
                module_ordinal,
                name_offset,
            }
        }
        _ => {
            fits(pos, index_size)?;
            let ordinal = if index_size == 2 {
                u32::from(buf.read_u16(pos)?)
            } else {
                u32::from(buf.read_u8(pos)?)
            };
            pos += index_size;
            FixupTarget::EntryTable { ordinal }
        }
    };
    let additive = if target_flags.contains(FixupTargetFlags::ADDITIVE) {
        let wide = target_flags.contains(FixupTargetFlags::ADDITIVE_32);
        let size = usize::from(wide) * 2 + 2;
        fits(pos, size)?;
        let value = if wide {
            buf.read_u32(pos)?
        } else {
            u32::from(buf.read_u16(pos)?)
        };
        pos += size;
        Some(value)
    } else {
        None
    };
    if listed {
        for _ in 0..list_count {
            source_offsets.push(buf.read_u16(pos)?);
            pos += 2;
        }
    }
    Ok(FixupRecord {
        page,
        offset: (at - table) as u32,
        source_type,
        source_flags,
        target_flags,
        source_offsets,
        target,
        additive,
        size: pos - at,
    })
}

// ---------------------------------------------------------------------------
// Iterated page (EXEPACK:1, page type 1) decoder
// ---------------------------------------------------------------------------

/// Decode an iterated data page (page type 1).
///
/// Stream format: records of `[iterations: u16 LE][length: u16 LE]`
/// followed by `length` data bytes, repeated `iterations` times. Ends on a
/// record with `iterations == 0` or when the page is full; the remainder of
/// the page is zero-filled.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn decode_iterated(src: &[u8], page_size: usize) -> Result<Vec<u8>, Error> {
    let mut out: Vec<u8> = Vec::with_capacity(page_size.min(src.len() * 2 + 64));
    let mut p = 0usize;
    while p + 4 <= src.len() && out.len() < page_size {
        let iterations = u16::from_le_bytes([src[p], src[p + 1]]) as usize;
        let length = u16::from_le_bytes([src[p + 2], src[p + 3]]) as usize;
        p += 4;
        if iterations == 0 {
            break;
        }
        if length == 0 || p + length > src.len() {
            return Err(Error::PageDataCorrupt);
        }
        let block = &src[p..p + length];
        p += length;
        for _ in 0..iterations {
            if out.len() >= page_size {
                break;
            }
            let take = length.min(page_size - out.len());
            out.extend_from_slice(&block[..take]);
        }
    }
    out.resize(page_size, 0);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Buffer implementations
// ---------------------------------------------------------------------------

/// Owned, `Vec<u8>`-backed buffer.
#[derive(Clone, Debug)]
pub struct VecLE {
    data: Vec<u8>,
}

impl VecLE {
    /// Wrap an owned byte vector.
    #[must_use]
    pub fn from_memory(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Copy a byte slice into an owned buffer.
    #[must_use]
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    /// Read a file from disk (requires `std`).
    #[cfg(feature = "std")]
    pub fn from_disk_file(path: impl AsRef<std::path::Path>) -> Result<Self, Error> {
        let data = std::fs::read(path.as_ref()).map_err(Error::IoError)?;
        Ok(Self { data })
    }
}

impl Buffer for VecLE {
    fn get_slice(&self, offset: usize, len: usize) -> Result<&[u8], Error> {
        let end = offset.saturating_add(len);
        if end > self.data.len() || offset > self.data.len() {
            return Err(Error::TableOutOfBounds("buffer", offset, end));
        }
        Ok(&self.data[offset..end])
    }

    fn len(&self) -> usize {
        self.data.len()
    }
}

/// Borrowed, slice-backed buffer.
#[derive(Clone, Copy, Debug)]
pub struct PtrLE<'a> {
    data: &'a [u8],
}

impl<'a> PtrLE<'a> {
    /// Wrap a byte slice.
    #[must_use]
    pub fn from_slice(data: &'a [u8]) -> Self {
        Self { data }
    }
}

impl Buffer for PtrLE<'_> {
    fn get_slice(&self, offset: usize, len: usize) -> Result<&[u8], Error> {
        let end = offset.saturating_add(len);
        if end > self.data.len() || offset > self.data.len() {
            return Err(Error::TableOutOfBounds("buffer", offset, end));
        }
        Ok(&self.data[offset..end])
    }

    fn len(&self) -> usize {
        self.data.len()
    }
}
