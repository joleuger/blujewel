// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! Parsed table types: Pascal strings, object records, page entries, entry
//! (export) bundles, non-resident names.

use bitflags::bitflags;

use crate::Error;
use crate::Vec;

// ---------------------------------------------------------------------------
// PascalString
// ---------------------------------------------------------------------------

/// A length-prefixed string (u8 length, then ASCII bytes), borrowed from the
/// buffer. Not guaranteed UTF-8 — use [`PascalString::as_str`] (fallible) or
/// [`PascalString::as_bytes`] for raw access.
///
/// In the LE resident name table the first entry is the module name,
/// followed by one entry per object. The length byte may carry overload
/// bits (bit 7) in some toolchains — see [`PascalString::is_overloaded`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PascalString<'a> {
    len: u8,
    data: &'a [u8],
}

impl<'a> PascalString<'a> {
    /// Wrap a raw slice whose first byte is the length prefix.
    ///
    /// The overload bit (bit 7) of the length byte is masked for the data
    /// bounds. Returns `None` when the declared length exceeds the
    /// available data.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        let len = *bytes.first()?;
        let char_len = (len as usize) & 0x7F;
        if bytes.len() < 1 + char_len {
            return None;
        }
        Some(Self {
            len,
            data: &bytes[1..=char_len],
        })
    }

    /// Length byte as stored (may include overload bits).
    #[must_use]
    pub fn raw_len(&self) -> u8 {
        self.len
    }

    /// Number of characters (`len & 0x7F`).
    #[must_use]
    pub fn char_len(&self) -> usize {
        self.len as usize & 0x7F
    }

    /// Whether the overload bit (bit 7) of the length byte is set.
    #[must_use]
    pub fn is_overloaded(&self) -> bool {
        self.len & 0x80 != 0
    }

    /// The string bytes (without the length prefix).
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// The string as a `str`, if it is valid UTF-8.
    pub fn as_str(&self) -> Result<&'a str, Error> {
        // Mirrors ne-rs: the std-only `Utf8Error` variant is not constructible
        // in no_std builds, so the fallible conversion maps to the
        // always-available `InvalidPascalString`.
        core::str::from_utf8(self.data).map_err(|_| Error::InvalidPascalString)
    }
}

impl core::fmt::Display for PascalString<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.as_str() {
            Ok(s) => write!(f, "{s}"),
            // Lossy display for debugging/diagnostic output.
            Err(_) => write!(f, "<{} invalid-utf8 bytes>", self.data.len()),
        }
    }
}

// ---------------------------------------------------------------------------
// Object table
// ---------------------------------------------------------------------------

// Object flags, the u32 at object-record offset 8.
//
// The bit meanings are taken from the Open Watcom C tool `wdump`.
// `wdump` prints for the fixtures (`READABLE | EXECUTABLE | PRELOAD | BIG`
// for the DDK-built VxD's 0x2045).
//
// Bits 8–10 are **not** independent flags: they form the object-type field
// (`OBJTYPEMASK` = 0x0700) — read it with [`ObjectRecord::object_type`].
bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ObjectFlags: u32 {
        /// 0x0001 `OBJREAD`: the object is readable.
        const READABLE = 0x0001;
        /// 0x0002 `OBJWRITE`: the object is writable (a data object).
        const WRITABLE = 0x0002;
        /// 0x0004 `NSEXRD`: the object is executable / shareable-execute.
        const EXECUTABLE = 0x0004;
        /// 0x0008 `OBJRSRC`: the object holds resources.
        const RESOURCE = 0x0008;
        /// 0x0010 `NSDISCARD`: the object may be discarded.
        const DISCARDABLE = 0x0010;
        /// 0x0020 `NSSHARED`: the object is shared between instances.
        const SHARED = 0x0020;
        /// 0x0040 `NSPRELOAD`: the object's pages are preloaded (the LX
        /// objects of `os2-lx.BIN` are the corpus case *without* this bit).
        const PRELOAD = 0x0040;
        /// 0x0080 `OBJINVALID`: the object is not valid.
        const INVALID = 0x0080;
        /// 0x1000 `OBJALIAS16`: 16-bit alias.
        const ALIAS_16 = 0x1000;
        /// 0x2000 `OBJBIGDEF`: 32-bit object by default (set in every
        /// verified object).
        const BIG_DEFAULT = 0x2000;
        /// 0x4000 `NSCONFORM`: conforming object.
        const CONFORM = 0x4000;
        /// 0x8000 `OBJIOPL`: I/O privilege level object.
        const IOPL = 0x8000;
    }
}

/// The object-type field (object flags bits 8–10, `OBJTYPEMASK` = 0x0700).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObjectType {
    /// 0x0000 `OBJNONPERM`: not permanent.
    NonPermanent,
    /// 0x0100 `OBJPERM`: permanent.
    Permanent,
    /// 0x0200 `OBJRESIDENT`: resident.
    Resident,
    /// 0x0300 `OBJCONTIG`: contiguous.
    Contiguous,
    /// 0x0400 `OBJDYNAMIC`: dynamic.
    Dynamic,
    /// Any other value of the three-bit field.
    Unknown(u8),
}

impl ObjectType {
    /// Decode from a raw object-flags word.
    #[must_use]
    pub const fn from_flags(flags: u32) -> Self {
        match (flags >> 8) & 7 {
            0 => Self::NonPermanent,
            1 => Self::Permanent,
            2 => Self::Resident,
            3 => Self::Contiguous,
            4 => Self::Dynamic,
            n => Self::Unknown(n as u8),
        }
    }
}

/// One object table record (24 bytes on disk, 6 x u32, little-endian).
///
/// Objects are referenced **1-based** (object number 1 = first record).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectRecord {
    /// Virtual (in-memory) size of the object in bytes.
    ///
    /// NOTE: for the stack/data object of verified Watcom DOS32A files this
    /// exceeds `page_count * page_size` — the extender allocates the full
    /// `vsize` and the on-disk last page holds only the initialized prefix.
    pub virtual_size: u32,
    /// Relocation base address of the object (0x10000 for code, 0x20000 for
    /// data in the verified fixtures).
    pub relocation_base: u32,
    /// Object flags (`0x0700` is the object-type field, see
    /// [`ObjectRecord::object_type`]).
    pub flags: ObjectFlags,
    /// Index of the first page-table entry of this object (**1-based**).
    pub first_page: u32,
    /// Number of page-table entries belonging to this object.
    pub page_count: u32,
    /// Object record field +20, stored as four raw bytes.
    ///
    /// The Microsoft DDK linker puts the object name there: every
    /// `testdata/fixtures/hello* vxd` object carries `b"LCOD"`, where all
    /// `wlink`-built objects are zero.
    /// Nothing in this corpus uses it as a name-table
    /// handle, so it is exposed verbatim rather than resolved.
    pub object_name: [u8; 4],
}

impl ObjectRecord {
    /// The object-type field (flags bits 8–10).
    #[must_use]
    pub const fn object_type(&self) -> ObjectType {
        ObjectType::from_flags(self.flags.bits())
    }

    /// [`Self::object_name`] trimmed of trailing NULs, `None` when the field
    /// is empty or is not ASCII-visible.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        let end = self
            .object_name
            .iter()
            .rposition(|&b| b != 0)
            .map_or(0, |p| p + 1);
        core::str::from_utf8(&self.object_name[..end])
            .ok()
            .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic()))
    }
}

// ---------------------------------------------------------------------------
// Object page table
// ---------------------------------------------------------------------------

/// Page type, bits 0–1 of a page table entry's flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PageType {
    /// Type 0: legal physical page — raw data (padded to page size).
    Legal,
    /// Type 1: iterated data page (EXEPACK:1 RLE).
    Iterated,
    /// Type 2: invalid page — never valid, an error on access by design.
    Invalid,
    /// Type 3: zero-filled page — no data on disk.
    ZeroFilled,
    /// Type 4: range of pages — not produced by any common tool; the parser
    /// must not silently ignore it.
    Range,
    /// Type 5: compressed page (EXEPACK:2, LX only; reconstructed format,
    /// not implemented in this parser yet).
    Compressed,
    /// Unknown page type.
    Unknown(u8),
}

impl PageType {
    /// Decode from the low two bits of a page entry's flags byte.
    #[must_use]
    pub const fn from_flags(flags: u16) -> Self {
        match flags & 0x03 {
            0 => Self::Legal,
            1 => Self::Iterated,
            2 => Self::Invalid,
            3 => Self::ZeroFilled,
            4 => Self::Range,
            5 => Self::Compressed,
            n => Self::Unknown(n as u8),
        }
    }

    /// The numeric page type (low two bits of the flags).
    #[must_use]
    pub const fn num(self) -> u8 {
        match self {
            Self::Legal => 0,
            Self::Iterated => 1,
            Self::Invalid => 2,
            Self::ZeroFilled => 3,
            Self::Range => 4,
            Self::Compressed => 5,
            Self::Unknown(n) => n,
        }
    }
}

/// One object page table entry.
///
/// LE and LX differ in on-disk layout:
///
/// - **LE (4 bytes):** 3-byte **big-endian** file page number (1-based) +
///   1-byte flags. Page data lives at
///   `data_pages + (file_page - 1) * page_size`, and the last module page
///   stores only `last_page_bytes` bytes.
/// - **LX (8 bytes):** u32 data offset + u16 data size + u16 flags. Page
///   data lives at `data_pages + (data_offset << page_offset_shift)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LePageEntry {
    /// LE 4-byte entry.
    Le {
        /// 1-based file page number (big-endian in the file). 0 = unverified
        /// (treated as invalid on access).
        file_page: u32,
        /// Flags; bits 0–1 are the page type.
        flags: u8,
    },
    /// LX 8-byte entry.
    Lx {
        /// Data section offset (shifted by the header's page offset shift).
        data_offset: u32,
        /// Bytes on disk (for compressed pages: compressed size).
        data_size: u16,
        /// Flags; bits 0–1 are the page type.
        flags: u16,
    },
}

impl LePageEntry {
    /// The page type (low two bits of flags).
    #[must_use]
    pub fn page_type(&self) -> PageType {
        match self {
            Self::Le { flags, .. } => PageType::from_flags(u16::from(*flags)),
            Self::Lx { flags, .. } => PageType::from_flags(*flags),
        }
    }
}

// ---------------------------------------------------------------------------
// Entry (export) table
// ---------------------------------------------------------------------------

// Bundle types and entry flags. On-disk grammar:
//
// ```text
// bundle := CNT:u8 TYPE:u8 (OBJECT:u16 | RESERVED:u16)? entry*   // len(CNT)
// type 0 (unused)  : 2-byte header, no entry data (CNT ordinals are skipped)
// type 1 (16-bit)  : FLAGS:u8 OFFSET:u16                          (3 B/entry)
// type 2 (callgate): FLAGS:u8 OFFSET:u16 CALLGATE:u16             (5 B/entry)
// type 3 (32-bit)  : FLAGS:u8 OFFSET:u32                          (5 B/entry)
// type 4 (forwarder): FLAGS:u8 MOD_ORD:u16 OFFSET_OR_ORDNUM:u32   (7 B/entry)
// ```
//
// A `CNT` of 0 terminates the table — the draft says so explicitly ("the
// entry table is terminated by a single zero byte"), which is what every
// fixture stores.
//
// Ordinals are **not stored**: they are positional, numbered from 1 across
// bundles in file order (a `type 0` bundle consumes `CNT` ordinals). That is
// how `wdump` reports "ordinal = 0001" for a single-entry bundle.
//
// Bit 7 of `TYPE` (`0x80` in both the draft and `exe386.h`'s `TYPEINFO`)
// announces "parameter typing information present". Neither document defines
// where that information is or how long it is, so this parser does not guess:
// such a bundle decodes to [`EntryType::Unknown`] and the table is reported
// as [`crate::Error::EntryTableCorrupt`]. No file in this corpus sets the bit.

/// The `TYPE` byte of an entry-table bundle header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryType {
    /// 0: unused entries — `CNT` ordinals are skipped, no entry data.
    Unused,
    /// 1: 16-bit entry.
    Entry16,
    /// 2: 286 call-gate entry (5 bytes: the callgate selector is a field the
    /// loader fills in).
    CallGate16,
    /// 3: 32-bit entry (the kind every verified fixture uses).
    Entry32,
    /// 4: forwarder entry.
    Forwarder,
    /// Any other type byte — including one with the `0x80` "parameter typing
    /// information" bit set, whose payload the format documents never define.
    Unknown(u8),
}

impl EntryType {
    /// Decode the bundle type byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Unused,
            1 => Self::Entry16,
            2 => Self::CallGate16,
            3 => Self::Entry32,
            4 => Self::Forwarder,
            other => Self::Unknown(other),
        }
    }

    /// The numeric bundle type.
    #[must_use]
    pub const fn num(self) -> u8 {
        match self {
            Self::Unused => 0,
            Self::Entry16 => 1,
            Self::CallGate16 => 2,
            Self::Entry32 => 3,
            Self::Forwarder => 4,
            Self::Unknown(n) => n,
        }
    }

    /// Bytes per entry in a bundle of this type (0 for the unused type, whose
    /// bundles carry no entry data).
    #[must_use]
    pub const fn entry_size(self) -> usize {
        match self {
            Self::Entry16 => 3,
            Self::CallGate16 | Self::Entry32 => 5,
            Self::Forwarder => 7,
            // The unused type's bundles carry no entry data; an unknown type
            // has no defined size at all (such a table is rejected).
            Self::Unused | Self::Unknown(_) => 0,
        }
    }
}

bitflags! {
    /// Flags byte of one entry-table entry.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct EntryFlags: u8 {
        /// 0x01 `E32EXPORT`: the entry is exported.
        const EXPORT = 0x01;
        /// 0x02 `E32SHARED`: the entry is shared (`wdump` prints this as
        /// "SHARED DATA"; both `hellovxd.BIN` and `hello2vxd.BIN` set it on
        /// their device-descriptor export).
        const SHARED = 0x02;
    }
}

impl EntryFlags {
    /// Parameter count, bits 3–7 (`E32PARAMS` = 0xF8).
    #[must_use]
    pub const fn param_count(self) -> u8 {
        (self.bits() >> 3) & 0x1F
    }
}

/// One decoded entry-table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryPoint {
    /// 16-bit entry.
    Offset16 {
        /// Entry flags.
        flags: EntryFlags,
        /// Offset within the bundle's object.
        offset: u16,
    },
    /// 32-bit entry.
    Offset32 {
        /// Entry flags.
        flags: EntryFlags,
        /// Offset within the bundle's object.
        offset: u32,
    },
    /// 286 call-gate entry.
    CallGate {
        /// Entry flags.
        flags: EntryFlags,
        /// Offset within the bundle's object.
        offset: u16,
        /// Call-gate selector (reserved; the loader fills it).
        callgate: u16,
    },
    /// Forwarder: the entry resolves to an import of another module.
    Forwarder {
        /// Entry flags; bit 0 = import by ordinal.
        flags: EntryFlags,
        /// 1-based index into the import module table.
        module_ordinal: u16,
        /// Procedure-name offset, or the import ordinal when
        /// `flags::EXPORT`'s low bit says "by ordinal".
        value: u32,
    },
}

impl EntryPoint {
    /// The flags byte of the entry.
    #[must_use]
    pub const fn flags(&self) -> EntryFlags {
        match self {
            Self::Offset16 { flags, .. }
            | Self::Offset32 { flags, .. }
            | Self::CallGate { flags, .. }
            | Self::Forwarder { flags, .. } => *flags,
        }
    }
}

/// One entry-table bundle: a type, the object its entries live in, and the
/// entries themselves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryBundle {
    /// Bundle type byte.
    pub kind: EntryType,
    /// Object number the entries belong to (1-based). `0` for the unused
    /// type, whose header carries no object field.
    pub object: u16,
    /// Ordinal of the first entry of this bundle (positional, from 1).
    pub first_ordinal: u32,
    /// The `CNT` byte: how many ordinals this bundle declares. For the entry
    /// types this equals [`Self::entries`]`.len()`; for the unused type it is
    /// the number of ordinals skipped while `entries` stays empty, and is the
    /// only place that count survives decoding.
    /// skips 349 of its 1015 ordinals this way).
    pub count: u8,
    /// The entries (`count` of them; empty for the unused type).
    pub entries: Vec<EntryPoint>,
}

/// One name-table entry — the same shape in the **resident** and the
/// **non-resident** table.
///
/// The ordinal is still *stored* data, not the export's identity: the entry
/// table numbers exports positionally, and the two `VxD` fixtures store 0
/// (`hellovxd.BIN` `HELLO_DDB`) and 1 (`vmdisp9xvxd.BIN` `VXD_DDB`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameEntry<'a> {
    /// The name bytes.
    pub name: PascalString<'a>,
    /// The two bytes following the string, as stored.
    pub ordinal: u16,
}

// ---------------------------------------------------------------------------
// Fixup records
// ---------------------------------------------------------------------------

// The fixup record table is the one table in this format whose records are
// *variable length*: the first two bytes say how long the rest of the record
// is. The layout below was measured record-for-record over every LE/LX file in
// the corpora.

/// The low nibble of a fixup record's first byte (`nr_stype`): the kind of
/// value at the fixup's **source** location inside its page.
///
/// Values 1 and 4 are left undefined by the format and give a record no length,
/// so a table carrying one is reported as
/// [`crate::Error::UnsupportedFixupSource`] rather than guessed at. No file in
/// this corpus uses them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixupSourceType {
    /// 0: an 8-bit value.
    Byte,
    /// 2: a 16-bit selector — the only source type whose record has **no**
    /// target-offset field.
    Selector16,
    /// 3: a 16:16 pointer.
    Ptr16_16,
    /// 5: a 16-bit offset.
    Offset16,
    /// 6: a 16:32 pointer.
    Ptr16_32,
    /// 7: a 32-bit offset — the form every Watcom fixture and every extracted
    /// `VMM32` member uses.
    Offset32,
    /// 8: a 32-bit self-relative (call/jump displacement) offset; every OS/2
    /// import fixup in this corpus has this source type.
    SelfRelative32,
    /// A source type the format does not define (1, 4, or a value the mask
    /// cannot name).
    Undefined(u8),
}

impl FixupSourceType {
    /// Decode the low nibble of the source byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Byte,
            2 => Self::Selector16,
            3 => Self::Ptr16_16,
            5 => Self::Offset16,
            6 => Self::Ptr16_32,
            7 => Self::Offset32,
            8 => Self::SelfRelative32,
            other => Self::Undefined(other),
        }
    }

    /// The numeric source type (the low nibble as stored).
    #[must_use]
    pub const fn num(self) -> u8 {
        match self {
            Self::Byte => 0,
            Self::Selector16 => 2,
            Self::Ptr16_16 => 3,
            Self::Offset16 => 5,
            Self::Ptr16_32 => 6,
            Self::Offset32 => 7,
            Self::SelfRelative32 => 8,
            Self::Undefined(n) => n,
        }
    }
}

bitflags! {
    /// The modifier bits of the fixup record's **first byte** — the same byte
    /// that carries [`FixupSourceType`], and the two sets do not overlap.
    ///
    /// The source-list bit lives in the source byte, not in the target-flags
    /// byte, and `testdata/fixtures/hellovxd.BIN` is the file that says so: its
    /// record table starts `27 00`, i.e. source type 7 with `0x20` set, and the
    /// record then reads `count 03 | object 01 | target 0050 | 007F 00A8 00BE`
    /// — 12 bytes, after which the second record starts at offset 12 and the
    /// table ends exactly on the sentinel.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FixupSourceFlags: u8 {
        /// 0x10: the source location holds the object's 16:16 alias of the
        /// target rather than its flat form.
        const ALIAS = 0x10;
        /// 0x20: the record fixes more than one source offset. The two-byte
        /// source-offset field becomes a **one-byte count** and the list of
        /// u16 offsets trails the rest of the record (after any additive).
        const SOURCE_LIST = 0x20;
    }
}

bitflags! {
    /// The second byte of a fixup record (`nr_flags`): which target form
    /// follows and how wide its fields are.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FixupTargetFlags: u8 {
        /// 0x03: the target type mask — see [`FixupTarget`].
        const TARGET_TYPE_MASK = 0x03;
        /// 0x04: an additive value trails the target data.
        const ADDITIVE = 0x04;
        /// 0x08: internal chaining — this record is the head of a chain whose
        /// rest lives **inside the page**, not in the record table. No file in
        /// this corpus sets it, so the chain walk is untested here; the flag is
        /// reported rather than acted on.
        const CHAINED = 0x08;
        /// 0x10: the target offset (and, for an ordinal-bound import, the
        /// ordinal) is 32 bits, not 16 (`many-pages.BIN`: 48 nine-byte
        /// records; `big-bss.BIN`: 5).
        const TARGET_OFFSET_32 = 0x10;
        /// 0x20: the additive value is 32 bits, not 16. Not exercised by any
        /// file here.
        const ADDITIVE_32 = 0x20;
        /// 0x40: the object number / module ordinal / entry ordinal is a
        /// **word**, not a byte.
        const INDEX_16 = 0x40;
        /// 0x80: an ordinal-bound import's ordinal is one byte, not two. This
        /// is why a record table is not a multiple of 7: `os2-lx.BIN` mixes 11
        /// seven-byte records with three six-byte ones (0x5F = 95 bytes).
        const ORDINAL_8 = 0x80;
    }
}

impl FixupTargetFlags {
    /// The target type (`TARGET_TYPE_MASK`), selecting the [`FixupTarget`]
    /// variant.
    #[must_use]
    pub const fn target_type(self) -> u8 {
        self.bits() & 0x03
    }
}

/// The target half of a fixup record — what the source location is fixed to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixupTarget {
    /// Target type 0: somewhere in this module. `object` is the 1-based object
    /// number (`r32_objmod`); `offset` is absent **only** for the
    /// [`FixupSourceType::Selector16`] source type, whose record has no
    /// target-offset field at all.
    Internal {
        /// 1-based object number.
        object: u16,
        /// Offset within that object, or `None` for a selector-only record.
        offset: Option<u32>,
    },
    /// Target type 1: an import bound **by ordinal**.
    ImportByOrdinal {
        /// 1-based index into [`crate::le::LE::get_import_modules`].
        module_ordinal: u16,
        /// The import ordinal, as stored.
        ordinal: u32,
    },
    /// Target type 2: an import bound **by name**.
    ImportByName {
        /// 1-based index into [`crate::le::LE::get_import_modules`].
        module_ordinal: u16,
        /// A **byte offset into the import procedure name table**, not an
        /// index: `testdata/fixtures/os2-impexp.BIN` stores `0x0001` and
        /// `0x0010`, which are the offsets of `DosLoadModule_` and
        /// `WinQueryWindowPos_` — the first one because the table begins with
        /// its mandatory null entry.
        name_offset: u32,
    },
    /// Target type 3: an entry of this module's own entry table, by ordinal.
    EntryTable {
        /// Ordinal into the entry table.
        ordinal: u32,
    },
}

/// One decoded record of the fixup record table.
///
/// Records are stored grouped by page, in the order the fixup page table
/// describes; [`Self::page`] and [`Self::offset`] say where the record came
/// from, and [`Self::size`] its length in bytes, so a caller can re-walk the
/// table or check it against [`crate::le::LE::get_fixup_page_table`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixupRecord {
    /// The module page this record fixes: a **0-based row of the object page
    /// table** — the row the fixup page table is parallel to, not the page
    /// *number* stored in that row (page numbers are storage slots and are
    /// permuted in real files.
    pub page: u32,
    /// Byte offset of this record within the fixup record table.
    pub offset: u32,
    /// Source type (low nibble of the first byte).
    pub source_type: FixupSourceType,
    /// Modifier bits of the first byte ([`FixupSourceFlags`]).
    pub source_flags: FixupSourceFlags,
    /// The target-flags byte (`nr_flags`).
    pub target_flags: FixupTargetFlags,
    /// Source offsets **within the page**, in stored order. One element for a
    /// plain record; `count` for a [`FixupSourceFlags::SOURCE_LIST`] record,
    /// whose list trails the record — the two forms are unified here.
    pub source_offsets: Vec<u16>,
    /// The target.
    pub target: FixupTarget,
    /// The additive value, present when [`FixupTargetFlags::ADDITIVE`] is set.
    pub additive: Option<u32>,
    /// Bytes this record occupies in the table.
    pub size: usize,
}

impl FixupRecord {
    /// Whether this record refers to the target's 16:16 alias.
    #[must_use]
    pub const fn alias(&self) -> bool {
        self.source_flags.contains(FixupSourceFlags::ALIAS)
    }

    /// Whether the rest of this record's fixup chain lives inside the page
    /// ([`FixupTargetFlags::CHAINED`]).
    #[must_use]
    pub const fn chained(&self) -> bool {
        self.target_flags.contains(FixupTargetFlags::CHAINED)
    }
}
