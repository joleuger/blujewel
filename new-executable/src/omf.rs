// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! OMF (Object Module Format) 16-bit import libraries (feature `omf`).
//!
//! Answers one question for an NE analyst: **which API is ordinal *n* of
//! module `M`?** The answer lives in the `IMPDEF` records of the OMF import
//! library the binary was linked against (`LIBW.LIB` for the Windows 3.x core
//! DLLs), not in the NE file itself.
//!
//! What lives here (facts only — the `omf-inspect` binary and
//! `ne-inspect --lib` own all presentation):
//! - Record framing: `[type][len:u16][contents][chk]`, checksum **never**
//!   validated ([`Records`]).
//! - Library container: LIBHDR → page size, page-aligned module walk,
//!   dictionary skipped ([`Library`]).
//! - COMENT sub-records: IMPDEF / EXPDEF / LIBMOD ([`Impdef`], [`Expdef`],
//!   [`Comment`]).
//! - [`OrdinalIndex`]: a `(target module, ordinal) → names` map merged across
//!   any number of libraries, joined case-insensitively.
//! - [`resolve_ne_imports`]: joins an NE file's `IMPORT_ORDINAL` relocations
//!   against such an index.
//!
//! Why a cargo feature: an OS or interpreter that merely *loads* NE files
//! needs none of this — OMF libraries are link-time analysis data. See
//! `Cargo.toml`.

use core::fmt;
use std::collections::BTreeMap;
use std::format;
use std::string::{String, ToString};
use std::vec::Vec;

use crate::types::{ModuleRefTable, PascalString, RelocationTable, RelocationType};
use crate::NE;

// ---------------------------------------------------------------------------
// Record type bytes — OS/2 numbering
//
// The Intel-8086 numbering differs for PUBDEF/LINNUM/LNAMES/SEGDEF/GRPDEF/
// LIDATA. Everything Microsoft or IBM produced for Windows 3.x / OS/2 uses
// the numbers below; mixing the two systems up yields plausible garbage.
// ---------------------------------------------------------------------------

/// `LIBHDR` — library header. Also byte 0 of every `.LIB`
/// ([`is_omf_library`]).
pub const REC_LIBHDR: u8 = 0xF0;
/// `LIBDIR` — library directory. Its presence ends the module area.
pub const REC_LIBDIR: u8 = 0xF1;
/// `THEADR` — module name header (`IMPLIB` emits this, not `LHEADR`).
pub const REC_THEADR: u8 = 0x80;
/// `LHEADR` — library-module name header.
pub const REC_LHEADR: u8 = 0x82;
/// `COMENT` — carrier for IMPDEF / EXPDEF / LIBMOD / … ([`Comment`]).
pub const REC_COMENT: u8 = 0x88;
/// `MODEND` — end of an object module.
pub const REC_MODEND: u8 = 0x8A;
/// `MODEND32` — 32-bit variant of [`REC_MODEND`].
pub const REC_MODEND32: u8 = 0x8B;
/// `EXTDEF` — undefined externals (user code, not import libraries).
pub const REC_EXTDEF: u8 = 0x8C;
/// `PUBDEF` — public definitions (OS/2 numbering: 0x90, not Intel's 0x8E).
pub const REC_PUBDEF: u8 = 0x90;
/// `LINNUM` — line numbers (0x94, not Intel's 0xA8).
pub const REC_LINNUM: u8 = 0x94;
/// `LNAMES` — module name pool (0x96, not Intel's 0x90).
pub const REC_LNAMES: u8 = 0x96;
/// `SEGDEF` — segment definition (0x98, not Intel's 0x92).
pub const REC_SEGDEF: u8 = 0x98;
/// `GRPDEF` — group definition (0x9A, not Intel's 0x94).
pub const REC_GRPDEF: u8 = 0x9A;
/// `LIDATA` — initialiser data (0xA0, not Intel's 0xA2).
pub const REC_LIDATA: u8 = 0xA0;

/// Label for a record type byte (analysis output only; `None` for types this
/// module has no name for).
#[must_use]
pub fn record_type_name(record_type: u8) -> Option<&'static str> {
    Some(match record_type {
        REC_LIBHDR => "LIBHDR",
        REC_LIBDIR => "LIBDIR",
        REC_THEADR => "THEADR",
        REC_LHEADR => "LHEADR",
        REC_COMENT => "COMENT",
        REC_MODEND => "MODEND",
        REC_MODEND32 => "MODEND32",
        REC_EXTDEF => "EXTDEF",
        REC_PUBDEF => "PUBDEF",
        REC_LINNUM => "LINNUM",
        REC_LNAMES => "LNAMES",
        REC_SEGDEF => "SEGDEF",
        REC_GRPDEF => "GRPDEF",
        REC_LIDATA => "LIDATA",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// COMENT classes and OMF-extension subtypes
// ---------------------------------------------------------------------------

/// COMENT comment-type bit 7: this record continues the previous COMENT's
/// body, so there is **no** class byte.
pub const COMMENT_CONTINUATION: u8 = 0x80;
/// Comment class `A0`: OMF extension carrier, subtyped by the next byte.
pub const COMMENT_OMFEXT: u8 = 0xA0;
/// Comment class `A3`: `LIBMOD` — the name of a module archived in a library.
pub const COMMENT_LIBMOD: u8 = 0xA3;
/// Comment class `A2`: link-pass separator (subtype `01`), seen once in
/// the `profc` module of `LIBW.LIB`.
pub const COMMENT_LINKPASS: u8 = 0xA2;
/// Comment class `9F`: library indicator.
pub const COMMENT_LIBRARY: u8 = 0x9F;
/// `COMMENT_OMFEXT` subtype 01: import definition.
pub const OMFEXT_IMPDEF: u8 = 0x01;
/// `COMMENT_OMFEXT` subtype 02: export definition.
pub const OMFEXT_EXPDEF: u8 = 0x02;
/// `COMMENT_OMFEXT` subtype 03: include module definition.
pub const OMFEXT_INCDEF: u8 = 0x03;
/// `COMMENT_OMFEXT` subtype 05: linked-directory reference.
pub const OMFEXT_LNKDIR: u8 = 0x05;

/// `EXPDEF` flag bits.
pub mod expdef_flag {
    /// Bit 7 `OrdBit`: the export is by ordinal, so the 2-byte ordinal field
    /// is present. Without it there is **no** ordinal field at all.
    pub const ORDINAL: u8 = 0x80;
    /// Bit 6 `ResidentName`: keep the name in the loader's resident table.
    pub const RESIDENT: u8 = 0x40;
    /// Bit 5 `NoData`: the entry point uses no initialised data.
    pub const NO_DATA: u8 = 0x20;
    /// Bits 0–4 `ParmCount`: parameter **word** count.
    pub const PARM_COUNT: u8 = 0x1F;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors while reading an OMF library.
///
/// Deliberately separate from [`crate::Error`]: OMF is a different format
/// domain and this module is feature-gated, so the core NE error type stays
/// untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Byte 0 is not a `LIBHDR` record (the payload is that byte). Not an
    /// OMF library — most often an NE file or an object module.
    NotALibrary(u8),
    /// The file ends before the header/record its length fields promise
    /// (`what`, file offset).
    Truncated(&'static str, usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotALibrary(byte) => write!(
                f,
                "not an OMF library: first record is 0x{byte:02X}, expected 0xF0 (LIBHDR)"
            ),
            Error::Truncated(what, offset) => {
                write!(f, "{what} truncated at file offset 0x{offset:04X}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// True when `data` starts with a `LIBHDR` record.
///
/// The `0xF0` test alone is enough in practice — it is never a record type in
/// the middle of an object module — and is how the OMF samples here are
/// detected. [`Library::parse`] does the strict check.
#[must_use]
pub fn is_omf_library(data: &[u8]) -> bool {
    matches!(data.first(), Some(&REC_LIBHDR))
}

// ---------------------------------------------------------------------------
// Record framing
// ---------------------------------------------------------------------------

/// One OMF record: `type(1) length(2) contents… checksum(1)`, where
/// `length` counts the contents **plus** the checksum byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    /// Record type byte.
    pub record_type: u8,
    /// File offset of the type byte.
    pub offset: usize,
    /// Contents only — the `length` field and the trailing checksum are
    /// excluded.
    pub body: &'a [u8],
    /// Value of the `length` field.
    pub record_length: usize,
    /// File offset just past the checksum byte.
    pub end: usize,
}

impl Record<'_> {
    /// Total bytes this record occupies on disk.
    #[must_use]
    pub fn total_len(&self) -> usize {
        self.record_length + 3
    }
}

/// Sequential reader over a record stream.
///
/// Stops — no panic, no resync — at the first record that is zero-length or
/// that would run past `limit`, which is what inter-module padding and the
/// dictionary area look like from inside the stream. [`Library::parse`]
/// handles those at the module level instead, by skipping to the next page
/// boundary.
///
/// The checksum byte is stepped over, never validated.
#[derive(Debug, Clone)]
pub struct Records<'a> {
    data: &'a [u8],
    pos: usize,
    limit: usize,
}

impl<'a> Records<'a> {
    /// Iterate the records in `data[start..limit]`.
    #[must_use]
    pub fn new(data: &'a [u8], start: usize, limit: usize) -> Self {
        Records {
            data,
            pos: start,
            limit: limit.min(data.len()),
        }
    }
}

impl<'a> Iterator for Records<'a> {
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.pos;
        if start >= self.limit || start + 3 > self.limit {
            return None;
        }
        let record_type = self.data[start];
        let record_length =
            u16::from_le_bytes([self.data[start + 1], self.data[start + 2]]) as usize;
        let end = start + 3 + record_length;
        if record_length == 0 || end > self.limit {
            return None;
        }
        self.pos = end;
        Some(Record {
            record_type,
            offset: start,
            body: &self.data[start + 3..end - 1],
            record_length,
            end,
        })
    }
}

/// Read a `<count,char>` name ("Pascal string") at `pos`.
///
/// Returns the name and the offset after it; `None` when the count byte or
/// the characters run past the end of `data`. A zero-length name is a valid
/// result — it is the "null name" / "same as the other name" marker.
fn pascal(data: &[u8], pos: usize) -> Option<(PascalString<'_>, usize)> {
    let len = *data.get(pos)? as usize;
    let end = pos + 1 + len;
    if end > data.len() {
        return None;
    }
    Some((
        PascalString {
            data: &data[pos + 1..end],
        },
        end,
    ))
}

fn u16_at(data: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*data.get(pos)?, *data.get(pos + 1)?]))
}

// ---------------------------------------------------------------------------
// IMPDEF — the ordinal → name answer
// ---------------------------------------------------------------------------

/// An `IMPDEF` record: "the symbol `internal_name` is import *n* of
/// `module_name`". One symbol per record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Impdef<'a> {
    /// The symbol the calling object module references (it appears again in
    /// that module's `EXTDEF`). Case is as `IMPLIB` emitted it.
    pub internal_name: PascalString<'a>,
    /// Target module (`USER`, `GDI`, `KERNEL`, `SIMPLIB`, …) — no extension.
    pub module_name: PascalString<'a>,
    /// `Some(ordinal)` when the `OrdFlag` byte is non-zero; `None` when the
    /// import is resolved by name.
    pub ordinal: Option<u16>,
    /// Export name for the name form. `None` means either "the `OrdFlag` form"
    /// (no such field) or a zero-length name, i.e. "the export name equals
    /// [`Impdef::internal_name`]" — see [`Impdef::export_name`].
    pub raw_export_name: Option<PascalString<'a>>,
}

impl<'a> Impdef<'a> {
    /// Parse from a COMENT body (`body[3]` is the `OrdFlag`).
    fn parse(body: &'a [u8]) -> Option<Self> {
        let ord_flag = *body.get(3)?;
        let (internal_name, pos) = pascal(body, 4)?;
        let (module_name, pos) = pascal(body, pos)?;
        if ord_flag == 0 {
            let (export_name, _) = pascal(body, pos)?;
            Some(Impdef {
                internal_name,
                module_name,
                ordinal: None,
                raw_export_name: (!export_name.is_empty()).then_some(export_name),
            })
        } else {
            Some(Impdef {
                internal_name,
                module_name,
                ordinal: Some(u16_at(body, pos)?),
                raw_export_name: None,
            })
        }
    }

    /// True when the import is resolved by ordinal.
    #[must_use]
    pub fn is_by_ordinal(&self) -> bool {
        self.ordinal.is_some()
    }

    /// The name the target module exports, for name-resolved imports.
    /// `None` in the ordinal form; a zero-length export name resolves to
    /// [`Impdef::internal_name`].
    #[must_use]
    pub fn export_name(&self) -> Option<PascalString<'a>> {
        if self.ordinal.is_some() {
            return None;
        }
        Some(self.raw_export_name.unwrap_or(self.internal_name))
    }
}

// ---------------------------------------------------------------------------
// EXPDEF
// ---------------------------------------------------------------------------

/// An `EXPDEF` record. Absent from all three sample libraries, so this is
/// spec-only parsing (OMF import libraries essentially never
/// carry signature information).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expdef<'a> {
    /// `ExpFlag` byte.
    pub flags: u8,
    /// Name as exported.
    pub exported_name: PascalString<'a>,
    /// Symbol implementing it; empty means "same as `exported_name`".
    pub internal_name: PascalString<'a>,
    /// Present only when `flags & 0x80`.
    pub ordinal: Option<u16>,
}

impl<'a> Expdef<'a> {
    fn parse(body: &'a [u8]) -> Option<Self> {
        let flags = *body.get(3)?;
        let (exported_name, pos) = pascal(body, 4)?;
        let (internal_name, pos) = pascal(body, pos)?;
        let ordinal = if flags & expdef_flag::ORDINAL != 0 {
            Some(u16_at(body, pos)?)
        } else {
            None
        };
        Some(Expdef {
            flags,
            exported_name,
            internal_name,
            ordinal,
        })
    }

    /// The name callers see, following the "empty internal name means the
    /// same name" rule.
    #[must_use]
    pub fn effective_internal_name(&self) -> PascalString<'a> {
        if self.internal_name.is_empty() {
            self.exported_name
        } else {
            self.internal_name
        }
    }

    /// Parameter word count (bits 0–4). Zero unless the export is a callgate.
    #[must_use]
    pub fn parm_count(&self) -> u8 {
        self.flags & expdef_flag::PARM_COUNT
    }

    /// Bit 6: the name is kept in the loader's resident name table.
    #[must_use]
    pub fn resident_name(&self) -> bool {
        self.flags & expdef_flag::RESIDENT != 0
    }

    /// Bit 5: the entry point uses no initialised data.
    #[must_use]
    pub fn no_data(&self) -> bool {
        self.flags & expdef_flag::NO_DATA != 0
    }
}

// ---------------------------------------------------------------------------
// COMENT payload
// ---------------------------------------------------------------------------

/// The interesting payloads of a COMENT record. Anything else is kept as
/// [`Comment::Other`] rather than treated as corruption: unknown classes and
/// subtypes must be skipped, not fatal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Comment<'a> {
    /// `IMPDEF`.
    Impdef(Impdef<'a>),
    /// `EXPDEF`.
    Expdef(Expdef<'a>),
    /// Class `A3`: the module name — a `<count,char>` name, so reading it as
    /// raw bytes leaves the count byte in the string.
    Libmod(PascalString<'a>),
    /// Comment-type bit 7: a continuation of the previous COMENT, so no class
    /// byte is present.
    Continuation,
    /// Anything else, with its class and (when present) subtype bytes.
    Other { class: u8, subtype: Option<u8> },
}

impl<'a> Comment<'a> {
    /// Interpret a COMENT body. `None` only when the body cannot even hold a
    /// comment-type byte, or when an IMPDEF/EXPDEF body is truncated.
    #[must_use]
    pub fn parse(body: &'a [u8]) -> Option<Self> {
        let comment_type = *body.first()?;
        if comment_type & COMMENT_CONTINUATION != 0 {
            return Some(Comment::Continuation);
        }
        let class = *body.get(1)?;
        match class {
            COMMENT_OMFEXT => {
                let subtype = *body.get(2)?;
                match subtype {
                    OMFEXT_IMPDEF => Some(Comment::Impdef(Impdef::parse(body)?)),
                    OMFEXT_EXPDEF => Some(Comment::Expdef(Expdef::parse(body)?)),
                    other => Some(Comment::Other {
                        class,
                        subtype: Some(other),
                    }),
                }
            }
            COMMENT_LIBMOD => pascal(body, 2).map(|(name, _)| Comment::Libmod(name)),
            other => Some(Comment::Other {
                class: other,
                subtype: body.get(2).copied(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Object module inside a library
// ---------------------------------------------------------------------------

/// One module of a library: everything from its header record through its
/// `MODEND`.
///
/// A module may contain **more than one** header record.
#[derive(Debug, Clone)]
pub struct Module<'a> {
    /// File offset of the module's first record.
    pub offset: usize,
    /// Names of every `THEADR` / `LHEADR` inside the module, in order.
    pub header_names: Vec<PascalString<'a>>,
    /// `LIBMOD` name, when the module carries one (import stubs do not).
    pub libmod: Option<PascalString<'a>>,
    /// `IMPDEF` subrecords.
    pub impdefs: Vec<Impdef<'a>>,
    /// `EXPDEF` subrecords.
    pub expdefs: Vec<Expdef<'a>>,
    /// COMENT payloads that are neither IMPDEF nor EXPDEF.
    pub comments: Vec<Comment<'a>>,
    /// Record types in file order (lets a caller check module *shape*).
    pub record_types: Vec<u8>,
    /// False when the module ran out of records before its `MODEND`.
    pub complete: bool,
}

impl<'a> Module<'a> {
    #[must_use]
    fn new(offset: usize) -> Self {
        Module {
            offset,
            header_names: Vec::new(),
            libmod: None,
            impdefs: Vec::new(),
            expdefs: Vec::new(),
            comments: Vec::new(),
            record_types: Vec::new(),
            complete: false,
        }
    }

    /// Name of the module: the `LIBMOD` name if present, else the first
    /// header name.
    #[must_use]
    pub fn name(&self) -> Option<&PascalString<'a>> {
        self.libmod.as_ref().or_else(|| self.header_names.first())
    }

    /// `THEADR COMENT MODEND` — the three-record import stub every `IMPLIB`
    /// module is.
    #[must_use]
    pub fn is_import_stub(&self) -> bool {
        matches!(
            self.record_types.as_slice(),
            [REC_THEADR, REC_COMENT, REC_MODEND]
        )
    }

    /// Total records in the module.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.record_types.len()
    }
}

// ---------------------------------------------------------------------------
// Library
// ---------------------------------------------------------------------------

/// A parsed 16-bit OMF library (`.LIB`).
///
/// The dictionary area is located but never parsed: every ordinal↔name pair
/// is already in the IMPDEF records, and a failed dictionary parse must never
/// stop the tool.
#[derive(Debug, Clone)]
pub struct Library<'a> {
    /// Total size of the file this was parsed from.
    pub file_len: usize,
    /// File offset of the dictionary area (0 ⇒ not recorded).
    pub dict_offset: u32,
    /// Number of 512-byte dictionary blocks. **Not** a module count.
    pub dict_blocks: u16,
    /// LIBHDR flags byte (`0x01` in `LIBW.LIB`, `0x00` in the others).
    pub flags: u8,
    /// LIBHDR library name (usually the null name).
    pub name: PascalString<'a>,
    /// Module-boundary page size — see [`Library::parse`] for the derivation.
    pub page_size: usize,
    /// The modules of `[page_size, dict_offset)`.
    pub modules: Vec<Module<'a>>,
    /// Record-type inventory over the module area (never the dictionary).
    pub record_counts: BTreeMap<u8, usize>,
    /// Non-fatal problems found while parsing (a caller should show these).
    pub warnings: Vec<String>,
}

impl<'a> Library<'a> {
    /// Parse an OMF library.
    ///
    /// Page size is not stored anywhere. The LIBHDR record is padded to fill
    /// exactly the first page, so `page = record_length + 3`. That derivation
    /// is then *validated* — the first byte
    /// at `page` must be a module header, and the dictionary offset must be a
    /// page multiple — and falls back to 16 when it does not hold.
    ///
    /// ```
    /// use ne::omf::Library;
    ///
    /// # let Some(bytes) = ne::doc_omf_library() else { return };
    /// let library = Library::parse(&bytes).unwrap();
    /// assert_eq!(library.module_count(), 1);
    /// let impdef = &library.modules[0].impdefs[0];
    /// assert_eq!(impdef.internal_name.as_str().unwrap(), "SIMPLIB_METHOD");
    /// assert_eq!(impdef.module_name.as_str().unwrap(), "SIMPLIB");
    /// // SIMPLIB.DEF declares no ordinal, so IMPLIB emitted the name form:
    /// assert_eq!(impdef.ordinal, None);
    /// ```
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < 3 {
            return Err(Error::Truncated("LIBHDR record", 0));
        }
        if data[0] != REC_LIBHDR {
            return Err(Error::NotALibrary(data[0]));
        }
        let hdr_len = u16::from_le_bytes([data[1], data[2]]) as usize;
        // dict_off(4) + dict_blocks(2) + flags(1) + at least a null name(1)
        if hdr_len < 8 || 3 + hdr_len > data.len() {
            return Err(Error::Truncated("LIBHDR contents", 0));
        }
        let body = &data[3..3 + hdr_len - 1];
        let dict_offset = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
        let dict_blocks = u16::from_le_bytes([body[4], body[5]]);
        let flags = body[6];
        let name = pascal(body, 7).map_or(PascalString { data: &[] }, |(name, _)| name);

        let mut warnings: Vec<String> = Vec::new();
        let derived = hdr_len + 3;
        let page_size = if page_is_plausible(data, derived, dict_offset) {
            derived
        } else {
            warnings.push(format!(
                "LIBHDR padding implies a page size of {derived}, which does not line up with \
                 the module area; using 16"
            ));
            16
        };

        let module_area = if dict_offset == 0 {
            data.len()
        } else {
            (dict_offset as usize).min(data.len())
        };

        let mut modules: Vec<Module<'a>> = Vec::new();
        let mut record_counts: BTreeMap<u8, usize> = BTreeMap::new();
        let mut pos = page_size;

        while pos < module_area {
            // A module starts on a page boundary with a header record.
            // Anything else (LIBDIR, zero padding, the dictionary) means the
            // module area is over.
            if !matches!(data[pos], REC_THEADR | REC_LHEADR) {
                break;
            }
            let mut module = Module::new(pos);
            let mut last_end = pos;
            let mut complete = false;
            for record in Records::new(data, pos, module_area) {
                *record_counts.entry(record.record_type).or_default() += 1;
                module.record_types.push(record.record_type);
                last_end = record.end;
                match record.record_type {
                    REC_THEADR | REC_LHEADR => {
                        if let Some((name, _)) = pascal(record.body, 0) {
                            module.header_names.push(name);
                        }
                    }
                    REC_COMENT => match Comment::parse(record.body) {
                        Some(Comment::Impdef(impdef)) => module.impdefs.push(impdef),
                        Some(Comment::Expdef(expdef)) => module.expdefs.push(expdef),
                        Some(Comment::Libmod(name)) => module.libmod = Some(name),
                        Some(other) => module.comments.push(other),
                        None => warnings.push(format!(
                            "COMENT at 0x{:04X} is too short to parse",
                            record.offset
                        )),
                    },
                    REC_MODEND | REC_MODEND32 => {
                        complete = true;
                        break;
                    }
                    _ => {}
                }
            }
            module.complete = complete;
            if !complete {
                warnings.push(format!(
                    "module at 0x{pos:04X} has no MODEND before the end of the module area"
                ));
            }
            modules.push(module);
            if !complete {
                break;
            }
            // Bytes between the MODEND and the next page boundary are
            // padding — skip them rather than read a record there.
            pos = last_end.div_ceil(page_size) * page_size;
        }

        if modules.is_empty() && module_area > page_size {
            warnings.push(format!(
                "no modules found in [{page_size:#06x}, {module_area:#06x})"
            ));
        }

        Ok(Library {
            file_len: data.len(),
            dict_offset,
            dict_blocks,
            flags,
            name,
            page_size,
            modules,
            record_counts,
            warnings,
        })
    }

    /// Module count.
    #[must_use]
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Total IMPDEF records across all modules.
    #[must_use]
    pub fn impdef_count(&self) -> usize {
        self.modules.iter().map(|m| m.impdefs.len()).sum()
    }

    /// Total EXPDEF records.
    #[must_use]
    pub fn expdef_count(&self) -> usize {
        self.modules.iter().map(|m| m.expdefs.len()).sum()
    }

    /// Count of a record type in the module area.
    #[must_use]
    pub fn record_count(&self, record_type: u8) -> usize {
        self.record_counts.get(&record_type).copied().unwrap_or(0)
    }

    /// Build an [`OrdinalIndex`] from this library alone.
    #[must_use]
    pub fn ordinal_index(&self) -> OrdinalIndex {
        let mut index = OrdinalIndex::new();
        index.add_library(self);
        index
    }
}

fn page_is_plausible(data: &[u8], page: usize, dict_offset: u32) -> bool {
    if page < 4 {
        return false;
    }
    if dict_offset != 0 && !dict_offset.is_multiple_of(page as u32) {
        return false;
    }
    matches!(data.get(page), Some(&REC_THEADR | &REC_LHEADR))
}

// ---------------------------------------------------------------------------
// Ordinal index
// ---------------------------------------------------------------------------

/// Case-folded key: module names in `.DEF` files, in the library and in an
/// NE's imported-names table agree only case-insensitively.
///  Names are ASCII, so ASCII folding is the right operation.
fn key(name: &str) -> String {
    name.to_ascii_uppercase()
}

/// Merged `(target module, ordinal) → names` map over any number of OMF
/// libraries.
///
/// Ordinal spaces are **per target module** — `USER #420` and `GDI #420` are
/// different functions  — so the module name is part
/// of every key. One ordinal can carry several names (aliases from the `.DEF`
/// files: `USER #420 → _WSPRINTF | _wsprintf`); they are kept as a list,
/// never collapsed.
///
/// ```
/// use ne::omf::OrdinalIndex;
///
/// # let Some(bytes) = ne::doc_omf_library() else { return };
/// let mut index = OrdinalIndex::new();
/// index.merge(&bytes).unwrap();
/// // SIMPLIB_LIB.BIN declares its one import by name, so it has no ordinal:
/// assert!(index.resolve_all("SIMPLIB", 1).is_empty());
/// assert_eq!(
///     index
///         .internal_names_for("simplib", "SIMPLIB_METHOD")
///         .first()
///         .map(String::as_str),
///     Some("SIMPLIB_METHOD"),
///     // the lookup is case-insensitive; the stored name is as IMPLIB wrote it
/// );
/// ```
#[derive(Debug, Clone, Default)]
pub struct OrdinalIndex {
    /// `MODULE → ordinal → names` (module keys uppercased, names as emitted).
    ordinals: BTreeMap<String, BTreeMap<u16, Vec<String>>>,
    /// Name-resolved imports: `MODULE → export name → internal names`. These
    /// have no ordinal at all (`SIMPLIB_LIB.BIN` is entirely of this kind).
    names: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    warnings: Vec<String>,
    library_count: usize,
    impdef_count: usize,
    expdef_count: usize,
}

impl OrdinalIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge one parsed library into the index.
    pub fn add_library(&mut self, library: &Library<'_>) {
        self.library_count += 1;
        self.warnings.extend(library.warnings.iter().cloned());
        for module in &library.modules {
            for impdef in &module.impdefs {
                self.impdef_count += 1;
                let (Ok(internal), Ok(target)) =
                    (impdef.internal_name.as_str(), impdef.module_name.as_str())
                else {
                    self.warnings.push(format!(
                        "IMPDEF in module at 0x{:04X} has a non-ASCII name",
                        module.offset
                    ));
                    continue;
                };
                if let Some(ordinal) = impdef.ordinal {
                    push_unique(
                        self.ordinals
                            .entry(key(target))
                            .or_default()
                            .entry(ordinal)
                            .or_default(),
                        internal,
                    );
                    continue;
                }
                let export = impdef
                    .export_name()
                    .map_or(Ok(internal), |name| name.as_str());
                let Ok(export) = export else { continue };
                push_unique(
                    self.names
                        .entry(key(target))
                        .or_default()
                        .entry(key(export))
                        .or_default(),
                    internal,
                );
            }
            self.expdef_count += module.expdefs.len();
        }
    }

    /// Parse `data` as an OMF library and merge it in.
    pub fn merge(&mut self, data: &[u8]) -> Result<(), Error> {
        let library = Library::parse(data)?;
        self.add_library(&library);
        Ok(())
    }

    /// First name for `(module, ordinal)`, or `None` when the libraries do
    /// not cover that ordinal — holes are normal.
    #[must_use]
    pub fn resolve(&self, module: &str, ordinal: u16) -> Option<&str> {
        self.resolve_all(module, ordinal)
            .first()
            .map(String::as_str)
    }

    /// Every name for `(module, ordinal)` — aliases included.
    #[must_use]
    pub fn resolve_all(&self, module: &str, ordinal: u16) -> &[String] {
        self.ordinals
            .get(&key(module))
            .and_then(|by_ordinal| by_ordinal.get(&ordinal))
            .map_or(&[][..], Vec::as_slice)
    }

    /// Internal symbol names that link against `export_name` in `module`
    /// (name-resolved imports only).
    #[must_use]
    pub fn internal_names_for(&self, module: &str, export_name: &str) -> &[String] {
        self.names
            .get(&key(module))
            .and_then(|by_name| by_name.get(&key(export_name)))
            .map_or(&[][..], Vec::as_slice)
    }

    /// The whole ordinal table: `MODULE → ordinal → names`. Keys are
    /// uppercased module names; iteration is ordinal-ordered.
    #[must_use]
    pub fn by_target_module(&self) -> &BTreeMap<String, BTreeMap<u16, Vec<String>>> {
        &self.ordinals
    }

    /// Name-resolved imports: `MODULE → export name → internal names`.
    #[must_use]
    pub fn by_target_module_name_form(&self) -> &BTreeMap<String, BTreeMap<String, Vec<String>>> {
        &self.names
    }

    /// Number of distinct target modules covered — 5 in `LIBW.LIB` (GDI,
    /// KERNEL, KEYBOARD, SOUND, USER).
    #[must_use]
    pub fn target_module_count(&self) -> usize {
        self.ordinals.len() + self.names.len()
    }

    /// Number of libraries merged.
    #[must_use]
    pub fn library_count(&self) -> usize {
        self.library_count
    }

    /// IMPDEF records merged (one per import symbol).
    #[must_use]
    pub fn impdef_count(&self) -> usize {
        self.impdef_count
    }

    /// EXPDEF records merged (0 for import libraries).
    #[must_use]
    pub fn expdef_count(&self) -> usize {
        self.expdef_count
    }

    /// Distinct ordinals covered across all target modules.
    #[must_use]
    pub fn ordinal_count(&self) -> usize {
        self.ordinals.values().map(BTreeMap::len).sum()
    }

    /// Name-resolved imports merged.
    #[must_use]
    pub fn name_form_count(&self) -> usize {
        self.names.values().map(BTreeMap::len).sum()
    }

    /// Non-fatal problems seen while merging (odd page sizes, non-ASCII
    /// names, modules without MODEND).
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

fn push_unique(list: &mut Vec<String>, name: &str) {
    if !list.iter().any(|existing| existing == name) {
        list.push(name.to_string());
    }
}

// ---------------------------------------------------------------------------
// Joining an NE file against the index
// ---------------------------------------------------------------------------

/// One `IMPORT_ORDINAL` relocation in an NE file, with whatever the OMF
/// libraries say about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSite {
    /// Position of the relocation in [`RelocationTable::entries`].
    pub reloc_index: usize,
    /// 1-based segment number the relocation belongs to.
    pub segment_number: u16,
    /// Chain head, segment-relative.
    pub offset: u16,
    /// 1-based module reference index (`target1`).
    pub module_ref_index: u16,
    /// Module name from the NE file's own module reference table.
    pub module: String,
    /// Imported ordinal (`target2`).
    pub ordinal: u16,
    /// Resolved names (aliases kept); empty ⇒ not covered by the libraries.
    pub names: Vec<String>,
}

/// A distinct import of one module, aggregated over all its relocation sites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedImport {
    /// Imported ordinal.
    pub ordinal: u16,
    /// Resolved names (aliases kept); empty when unresolved.
    pub names: Vec<String>,
    /// How many relocation sites patch this one import.
    pub site_count: usize,
}

/// Every ordinal import of an NE file, resolved against an [`OrdinalIndex`].
#[derive(Debug, Clone, Default)]
pub struct ImportReport {
    /// One entry per ordinal-import relocation, in relocation-table order.
    pub sites: Vec<ImportSite>,
    /// `module name (as spelled in the NE file) → distinct imports, sorted by
    /// ordinal`.
    pub by_module: BTreeMap<String, Vec<ResolvedImport>>,
}

impl ImportReport {
    /// Ordinal imports with at least one resolved name.
    #[must_use]
    pub fn resolved_sites(&self) -> usize {
        self.sites.iter().filter(|s| !s.names.is_empty()).count()
    }

    /// Ordinal imports the loaded libraries say nothing about.
    #[must_use]
    pub fn unresolved_sites(&self) -> usize {
        self.sites.len() - self.resolved_sites()
    }

    /// Distinct `(module, ordinal)` pairs no library covers — a work queue,
    /// not proof of an undocumented API.
    #[must_use]
    pub fn unresolved_keys(&self) -> Vec<(String, u16)> {
        self.by_module
            .iter()
            .flat_map(|(module, imports)| {
                imports
                    .iter()
                    .filter(|i| i.names.is_empty())
                    .map(move |i| (module.clone(), i.ordinal))
            })
            .collect()
    }
}

/// Resolve the ordinal imports of `ne` against `index`.
///
/// The NE side of the join is the module reference table: `target1` of an
/// `IMPORT_ORDINAL` relocation is a **1-based** index into it, and the name
/// stored there keys the OMF index. A file with no module reference or
/// relocation table yields an empty report rather than an error.
///
/// # Errors
///
/// Propagates [`crate::Error`] from the module reference and relocation table
/// parses.
pub fn resolve_ne_imports<P: NE>(
    ne: &P,
    index: &OrdinalIndex,
) -> Result<ImportReport, crate::Error> {
    let module_refs = match ModuleRefTable::parse(ne) {
        Ok(mrt) => mrt,
        Err(crate::Error::TableNotPresent(_)) => return Ok(ImportReport::default()),
        Err(e) => return Err(e),
    };
    let relocations = match RelocationTable::parse(ne) {
        Ok(rt) => rt,
        Err(crate::Error::TableNotPresent(_)) => return Ok(ImportReport::default()),
        Err(e) => return Err(e),
    };

    let mut report = ImportReport::default();
    for (reloc_index, entry) in relocations.entries.iter().enumerate() {
        let (Some(module_ref_index), Some(ordinal)) =
            (entry.mod_ref_index(), entry.ordinal_number())
        else {
            continue;
        };
        if module_ref_index == 0 {
            continue;
        }
        let module = module_refs
            .get_name(ne, (module_ref_index - 1) as usize)
            .and_then(|name| name.as_str().map(String::from))
            .unwrap_or_else(|_| format!("??({module_ref_index})"));
        let names = index.resolve_all(&module, ordinal).to_vec();
        report.sites.push(ImportSite {
            reloc_index,
            segment_number: entry.segment_number,
            offset: entry.offset,
            module_ref_index,
            module: module.clone(),
            ordinal,
            names: names.clone(),
        });
        let imports = report.by_module.entry(module).or_default();
        if let Some(existing) = imports.iter_mut().find(|i| i.ordinal == ordinal) {
            existing.site_count += 1;
            if existing.names.is_empty() {
                existing.names = names;
            }
        } else {
            imports.push(ResolvedImport {
                ordinal,
                names,
                site_count: 1,
            });
        }
    }
    for imports in report.by_module.values_mut() {
        imports.sort_by_key(|i| i.ordinal);
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// Unit tests — synthetic records only, no fixture files. The fixture-backed
// suite lives in tests/omf_library.rs.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

    /// Assemble a record with valid framing (and a real checksum, which the
    /// parser is required to ignore).
    fn record(record_type: u8, contents: &[u8]) -> Vec<u8> {
        let length = (contents.len() + 1) as u16;
        let mut out = vec![record_type, (length & 0xFF) as u8, (length >> 8) as u8];
        out.extend_from_slice(contents);
        let sum: u32 = out.iter().copied().map(u32::from).sum();
        out.push((256 - (sum % 256)) as u8);
        out
    }

    fn pascal_bytes(text: &str) -> Vec<u8> {
        let mut out = vec![text.len() as u8];
        out.extend_from_slice(text.as_bytes());
        out
    }

    fn impdef_contents(internal: &str, module: &str, ordinal: Option<u16>) -> Vec<u8> {
        let mut contents = vec![
            0x00,
            COMMENT_OMFEXT,
            OMFEXT_IMPDEF,
            u8::from(ordinal.is_some()),
        ];
        contents.extend(pascal_bytes(internal));
        contents.extend(pascal_bytes(module));
        if let Some(ordinal) = ordinal {
            contents.extend_from_slice(&ordinal.to_le_bytes());
        } else {
            contents.push(0);
        }
        contents
    }

    /// LIBHDR with the sample layout (record length 13 ⇒ page 16), padded to
    /// fill that page.
    fn libhdr(dict_offset: u32, dict_blocks: u16, flags: u8) -> Vec<u8> {
        let contents: Vec<u8> = dict_offset
            .to_le_bytes()
            .into_iter()
            .chain(dict_blocks.to_le_bytes())
            .chain(core::iter::once(flags))
            .chain(core::iter::once(0))
            // Page padding: real libraries pad the LIBHDR record to a 16-byte
            // page, which is where the derived page size comes from.
            .chain([0u8; 4])
            .collect();
        let mut out = record(REC_LIBHDR, &contents);
        while out.len() < 16 {
            out.push(0);
        }
        out
    }

    /// The three-record `IMPLIB` import stub, page-padded.
    fn stub(module: &str, symbol: &str, ordinal: Option<u16>) -> Vec<u8> {
        let mut out = record(REC_THEADR, &pascal_bytes(symbol));
        out.extend(record(
            REC_COMENT,
            &impdef_contents(symbol, module, ordinal),
        ));
        out.extend(record(REC_MODEND, &[0]));
        while !out.len().is_multiple_of(16) {
            out.push(0);
        }
        out
    }

    #[test]
    fn record_stream_stops_on_zero_length_and_truncation() {
        let data = [0x80u8, 2, 0, 0x00, 0x00, 0x80, 9, 0];
        let recs: Vec<_> = Records::new(&data, 0, data.len()).collect();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].record_type, REC_THEADR);
        assert_eq!(recs[0].total_len(), 5);
    }

    #[test]
    fn libhdr_fields_and_page_derivation() {
        let mut data = libhdr(0x200, 2, 0x00);
        data.extend(stub("SIMPLIB", "SIMPLIB_METHOD", None));
        let lib = Library::parse(&data).unwrap();
        assert_eq!(lib.dict_offset, 0x200);
        assert_eq!(lib.dict_blocks, 2);
        assert_eq!(lib.flags, 0);
        assert!(lib.name.is_empty());
        assert_eq!(lib.page_size, 16);
        assert!(lib.warnings.is_empty(), "{:?}", lib.warnings);
    }

    #[test]
    fn implib_stub_shape_and_impdef_ordinal() {
        let mut data = libhdr(0x100, 1, 0x01);
        data.extend(stub("KERNEL", "FATALEXIT", Some(1)));
        let lib = Library::parse(&data).unwrap();
        assert_eq!(lib.module_count(), 1);
        assert_eq!(lib.impdef_count(), 1);
        assert_eq!(lib.expdef_count(), 0);
        let module = &lib.modules[0];
        assert!(module.is_import_stub(), "{:?}", module.record_types);
        assert!(module.complete);
        assert_eq!(module.record_count(), 3);
        assert_eq!(
            module.header_names[0].as_str().unwrap(),
            "FATALEXIT",
            "THEADR name is the imported symbol"
        );
        assert!(module.libmod.is_none());
        let impdef = &module.impdefs[0];
        assert_eq!(impdef.internal_name.as_str().unwrap(), "FATALEXIT");
        assert_eq!(impdef.module_name.as_str().unwrap(), "KERNEL");
        assert_eq!(impdef.ordinal, Some(1));
        assert!(impdef.is_by_ordinal());
        assert_eq!(impdef.export_name(), None);
    }

    #[test]
    fn name_form_impdef_treats_zero_length_as_same_name() {
        let mut data = libhdr(0x100, 1, 0x00);
        data.extend(stub("SIMPLIB", "simplib_method", None));
        let lib = Library::parse(&data).unwrap();
        let impdef = &lib.modules[0].impdefs[0];
        assert!(!impdef.is_by_ordinal());
        assert_eq!(impdef.ordinal, None);
        assert_eq!(impdef.raw_export_name, None);
        assert_eq!(
            impdef.export_name().unwrap().as_str().unwrap(),
            "simplib_method"
        );
    }

    #[test]
    fn module_area_stops_at_libdir_and_skips_modend_padding() {
        // MODEND ends mid-page; the gap to the page boundary is padding, and
        // a LIBDIR record ends the module area.
        let mut data = libhdr(0x200, 2, 0x00);
        data.extend(stub("USER", "MESSAGEBOX", Some(1)));
        data.extend(record(REC_LIBDIR, &[0u8; 10]));
        let lib = Library::parse(&data).unwrap();
        assert_eq!(lib.module_count(), 1);
        assert_eq!(
            lib.record_count(REC_LIBDIR),
            0,
            "the dictionary area is not inventoried"
        );
        assert_eq!(lib.record_count(REC_THEADR), 1);
    }

    #[test]
    fn implausible_page_size_falls_back_to_16() {
        // Both validation branches (OMF.md §12 audit item 4): a dictionary
        // offset that is not a page multiple, and a derived page that does not
        // start on a module header record.
        let mut dict_misaligned = libhdr(0x101, 1, 0x00);
        dict_misaligned.extend(stub("GDI", "BITBLT", Some(34)));
        let lib = Library::parse(&dict_misaligned).unwrap();
        assert_eq!(lib.page_size, 16);
        assert_eq!(lib.module_count(), 1);
        assert!(!lib.warnings.is_empty(), "the fallback must be reported");

        let mut bogus_page = libhdr(0x140, 1, 0x00);
        bogus_page.extend(stub("GDI", "BITBLT", Some(34)));
        bogus_page[1] = 0x25; // LIBHDR record length 37 ⇒ derived page 40
        let lib = Library::parse(&bogus_page).unwrap();
        assert_eq!(lib.page_size, 16);
        assert_eq!(lib.impdef_count(), 1);
        assert_eq!(lib.modules[0].offset, 16, "module area starts at page 16");
        assert!(lib.warnings.iter().any(|w| w.contains("page size of 40")));
    }

    #[test]
    fn libmod_name_drops_the_count_byte() {
        // `00 a3 05 'profc'` must read as "profc".
        let body = [0x00u8, COMMENT_LIBMOD, 5, b'p', b'r', b'o', b'f', b'c'];
        match Comment::parse(&body).unwrap() {
            Comment::Libmod(name) => assert_eq!(name.as_str().unwrap(), "profc"),
            other => panic!("expected LIBMOD, got {other:?}"),
        }
    }

    #[test]
    fn expdef_ordinal_requires_the_ordinal_bit() {
        // no ordinal field unless flags & 0x80.
        let name_form = [
            0x00u8,
            COMMENT_OMFEXT,
            OMFEXT_EXPDEF,
            0x40, // ResidentName, no OrdBit
            3,
            b'F',
            b'o',
            b'o',
            3,
            b'F',
            b'o',
            b'o',
        ];
        let expdef = match Comment::parse(&name_form).unwrap() {
            Comment::Expdef(expdef) => expdef,
            other => panic!("expected EXPDEF, got {other:?}"),
        };
        assert_eq!(expdef.ordinal, None);
        assert!(expdef.resident_name());
        assert_eq!(expdef.effective_internal_name().as_str().unwrap(), "Foo");

        let ordinal_form = [
            0x00u8,
            COMMENT_OMFEXT,
            OMFEXT_EXPDEF,
            0x80 | 0x02, // OrdBit + 2 parameter words
            3,
            b'E',
            b'x',
            b'P',
            0, // empty internal name ⇒ same as the exported name
            0x34,
            0x12,
        ];
        let expdef = match Comment::parse(&ordinal_form).unwrap() {
            Comment::Expdef(expdef) => expdef,
            other => panic!("expected EXPDEF, got {other:?}"),
        };
        assert_eq!(expdef.ordinal, Some(0x1234));
        assert_eq!(expdef.parm_count(), 2);
        assert!(!expdef.no_data());
        assert_eq!(expdef.effective_internal_name().as_str().unwrap(), "ExP");
    }

    #[test]
    fn comment_continuation_has_no_class_byte() {
        // bit 7 set ⇒ never index body[1].
        assert_eq!(Comment::parse(&[0x80u8]).unwrap(), Comment::Continuation);
    }

    #[test]
    fn unknown_comment_classes_and_subtypes_are_skipped_not_fatal() {
        match Comment::parse(&[0x00u8, COMMENT_OMFEXT, 0x99]).unwrap() {
            Comment::Other {
                class: COMMENT_OMFEXT,
                subtype,
            } => assert_eq!(subtype, Some(0x99)),
            other => panic!("expected Other, got {other:?}"),
        }
        match Comment::parse(&[0x00u8, 0xC0, 0x01]).unwrap() {
            Comment::Other { class, subtype } => {
                assert_eq!(class, 0xC0);
                assert_eq!(subtype, Some(0x01));
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn checksum_is_never_validated() {
        let mut data = libhdr(0x100, 1, 0x00);
        let mut stub_bytes = stub("SOUND", "SOUNDOUTPUT", Some(4));
        stub_bytes[15] ^= 0xFF; // corrupt the THEADR checksum on purpose
        data.extend(stub_bytes);
        let lib = Library::parse(&data).unwrap();
        assert_eq!(lib.impdef_count(), 1);
    }

    #[test]
    fn more_than_one_header_record_stays_one_module() {
        // the `profc` module has three THEADR records; starting a
        // new module at each one loses its LIBMOD name.
        let mut data = libhdr(0x200, 2, 0x00);
        let mut module = record(REC_THEADR, &pascal_bytes("main"));
        module.extend(record(
            REC_COMENT,
            &[0x00, COMMENT_LIBMOD, 5, b'p', b'r', b'o', b'f', b'c'],
        ));
        module.extend(record(REC_THEADR, &pascal_bytes("sibl")));
        module.extend(record(REC_THEADR, &pascal_bytes("spys")));
        module.extend(record(REC_MODEND, &[0]));
        while !module.len().is_multiple_of(16) {
            module.push(0);
        }
        data.extend(module);
        let lib = Library::parse(&data).unwrap();
        assert_eq!(lib.module_count(), 1);
        assert_eq!(lib.modules[0].header_names.len(), 3);
        assert!(!lib.modules[0].is_import_stub());
        assert_eq!(lib.modules[0].name().unwrap().as_str().unwrap(), "profc");
    }

    #[test]
    fn index_keys_by_module_and_keeps_aliases() {
        let mut data = libhdr(0x300, 3, 0x01);
        data.extend(stub("USER", "_WSPRINTF", Some(420)));
        data.extend(stub("USER", "_wsprintf", Some(420)));
        data.extend(stub("GDI", "BITBLT", Some(34)));
        let lib = Library::parse(&data).unwrap();
        let index = lib.ordinal_index();
        assert_eq!(index.impdef_count(), 3);
        assert_eq!(index.target_module_count(), 2);
        assert_eq!(index.resolve("user", 420), Some("_WSPRINTF"));
        assert_eq!(
            index.resolve_all("USER", 420).to_vec(),
            vec!["_WSPRINTF".to_string(), "_wsprintf".to_string()]
        );
        assert_eq!(index.resolve("GDI", 34), Some("BITBLT"));
        assert_eq!(
            index.resolve("GDI", 420),
            None,
            "ordinal spaces are per module"
        );
        assert_eq!(index.resolve("USER", 419), None, "holes are normal");
    }

    #[test]
    fn index_merges_several_libraries() {
        let mut a = libhdr(0x100, 1, 0x00);
        a.extend(stub("USER", "MESSAGEBOX", Some(1)));
        let mut b = libhdr(0x100, 1, 0x00);
        b.extend(stub("MMSYSTEM", "midiOutOpen", Some(2)));
        let mut index = OrdinalIndex::new();
        index.merge(&a).unwrap();
        index.merge(&b).unwrap();
        assert_eq!(index.library_count(), 2);
        assert_eq!(index.ordinal_count(), 2);
        assert_eq!(index.resolve("MMSYSTEM", 2), Some("midiOutOpen"));
    }

    #[test]
    fn name_form_lands_in_the_name_index_not_the_ordinal_index() {
        let mut data = libhdr(0x100, 1, 0x00);
        data.extend(stub("SIMPLIB", "SIMPLIB_METHOD", None));
        let index = Library::parse(&data).unwrap().ordinal_index();
        assert_eq!(index.ordinal_count(), 0);
        assert_eq!(index.name_form_count(), 1);
        assert_eq!(
            index
                .internal_names_for("simplib", "simplib_method")
                .to_vec(),
            vec!["SIMPLIB_METHOD".to_string()]
        );
    }

    #[test]
    fn non_library_first_byte_is_reported() {
        assert!(!is_omf_library(b"NE\x00\x00"));
        assert!(is_omf_library(&[REC_LIBHDR, 0x0D, 0x00]));
        assert_eq!(
            Library::parse(b"MZ\x00\x00\x00").unwrap_err(),
            Error::NotALibrary(b'M')
        );
        assert_eq!(
            Library::parse(&[REC_LIBHDR, 0x0D]).unwrap_err(),
            Error::Truncated("LIBHDR record", 0)
        );
    }
}
