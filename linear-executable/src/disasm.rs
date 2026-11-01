// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! Disassembly support for LE/LX modules (feature `disasm`).
//!
//! This is the **facts layer** of the disassembler: it answers LE/LX questions
//! that a consumer of a code listing (CLI, emulator, relocator) would
//! otherwise rederive from the format — and rederive wrongly. It contains **no
//! presentation**: no column layout, no `println!`, no policy about where a
//! listing starts or how wide a column is. The `le-disasm` binary owns all of
//! that (the same split as `le-inspect`, and the same one the sibling `ne`
//! crate uses).
//!
//! What lives here:
//! - **Per-object bitness**: an object's default operand size comes from its
//!   own flag word ([`Bitness::of_object`]), not from the module.
//! - **The module's entry point**: the header pair when it names one, else the
//!   entry table ([`entry_point`]).
//! - **Fixup attribution**: the fixup record table is grouped by *page*, and a
//!   code listing is laid out in *objects*, so the patch slots have to be
//!   re-keyed ([`build_fixup_maps`]).
//! - **Import names**: an import fixup's name field is a **byte offset into the
//!   import procedure table**, resolved here ([`import_reference`]).
//! - **The sweep**: a linear decode with iced-x86 (the only place iced is
//!   reachable from library code) that never invents an instruction for
//!   undecodable bytes — those come back as flagged data lines
//!   ([`list_code`]).
//!
//! iced-x86 is wired to this module only; a build without `--features disasm`
//! contains neither iced nor any of this code. `disasm` implies `std` because
//! iced is used with its `std` feature.

use crate::le::LE;
use crate::types::{FixupSourceType, FixupTarget, ObjectFlags, ObjectRecord};
use crate::{Error, Vec};
// This crate is `no_std`, so the std prelude — including `Box`, `String`,
// `ToOwned` and `format!` — is not in scope; this module is `std`-gated
// (`disasm` implies `std` because iced-x86 is wired with its `std` feature),
// so it imports what it uses from `std` explicitly.
use core::fmt;
use iced_x86::{Code, Decoder, DecoderOptions, Formatter, GasFormatter, IntelFormatter};
use std::borrow::ToOwned;
use std::boxed::Box;
use std::collections::BTreeMap;
use std::format;
use std::string::String;

// ---------------------------------------------------------------------------
// Bitness
// ---------------------------------------------------------------------------

/// Default operand and address size of the instructions in one object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bitness {
    /// 16-bit object.
    Bit16,
    /// 32-bit object.
    Bit32,
}

impl Bitness {
    /// The size iced-x86 is configured with (16 or 32).
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::Bit16 => 16,
            Self::Bit32 => 32,
        }
    }

    /// The object's default operand size: object flag `0x2000`
    /// ([`ObjectFlags::BIG_DEFAULT`], `OBJBIGDEF`) selects 32-bit, its absence
    /// 16-bit.
    #[must_use]
    pub fn of_object(object: &ObjectRecord) -> Self {
        if object.flags.contains(ObjectFlags::BIG_DEFAULT) {
            Self::Bit32
        } else {
            Self::Bit16
        }
    }
}

impl fmt::Display for Bitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-bit", self.bits())
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Where an [`ModuleEntry`] came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryOrigin {
    /// The header's `start_object` / `eip` pair.
    Header,
    /// An entry-table bundle, at this ordinal.
    EntryTable {
        /// Ordinal in the entry table.
        ordinal: u32,
    },
}

/// The address a module starts executing at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleEntry {
    /// 1-based object number.
    pub object: u16,
    /// Offset within that object's image.
    pub offset: u32,
    /// Flat address the loader maps it at: the object's relocation base plus
    /// [`Self::offset`].
    pub linear: u32,
    /// Which table said so.
    pub origin: EntryOrigin,
}

/// The module's entry point, or `None` when neither the header nor the entry
/// table names a loadable one.
///
/// The header pair wins: `start_object` is a **1-based** object number and
/// `eip` an offset inside it (`hallasm.BIN` ⇒ 1/0x0, `os2-lx.BIN` ⇒ 1/0xE4,
// A start object of 0 names no
/// object, because objects count from 1, and `u32::MAX` cannot index the table
/// either; both fall through to the entry table. That fall-through is not
/// hypothetical: both DDK-built drivers, `hellovxd.BIN` and `vmdisp9xvxd.BIN`,
/// store 0/0x0 and carry their entry in the entry table (`hellovxd.BIN`
/// `Entry32` bundle, object 1, ordinal 1, offset 0), which is how a `VxD` is
/// entered at all.
///
/// On the entry-table path the lowest **exported** entry is taken; a bundle
/// whose object field is 0 (the unused type) is skipped. An entry table this
/// parser cannot walk yields no entry point rather than an error — the header
/// form is the primary one and a broken export table should not hide a valid
/// `eip`; [`crate::le::LE::get_entry_table`] is the call that reports it.
pub fn entry_point(le: &impl LE) -> Result<Option<ModuleEntry>, Error> {
    let header = le.get_valid_le_header()?;
    let objects = le.get_object_table()?;

    let start = header.start_object() as usize;
    if start >= 1 && start <= objects.len() {
        let object = &objects[start - 1];
        let eip = header.eip();
        if (eip as usize) < object.virtual_size as usize {
            return Ok(Some(ModuleEntry {
                object: start as u16,
                offset: eip,
                linear: object.relocation_base.wrapping_add(eip),
                origin: EntryOrigin::Header,
            }));
        }
    }

    let Ok(bundles) = le.get_entry_table() else {
        return Ok(None);
    };
    for bundle in bundles.iter().filter(|b| b.object >= 1) {
        for (index, entry) in bundle.entries.iter().enumerate() {
            if !entry.flags().contains(crate::types::EntryFlags::EXPORT) {
                continue;
            }
            let offset = match *entry {
                crate::types::EntryPoint::Offset16 { offset, .. }
                | crate::types::EntryPoint::CallGate { offset, .. } => u32::from(offset),
                crate::types::EntryPoint::Offset32 { offset, .. } => offset,
                // A forwarder has no code in this module to disassemble.
                crate::types::EntryPoint::Forwarder { .. } => continue,
            };
            let ordinal = bundle.first_ordinal + index as u32;
            let Some(object) = objects.get(bundle.object as usize - 1) else {
                continue;
            };
            return Ok(Some(ModuleEntry {
                object: bundle.object,
                offset,
                linear: object.relocation_base.wrapping_add(offset),
                origin: EntryOrigin::EntryTable { ordinal },
            }));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Fixup map
// ---------------------------------------------------------------------------

/// One fixup that patches a specific byte range of one object image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixupNote {
    /// The record's source type — what kind of value the patch slot holds.
    pub source_type: FixupSourceType,
    /// The record's target.
    pub target: FixupTarget,
    /// The record fixes the target's 16:16 alias ([`crate::types::FixupRecord::alias`]).
    pub alias: bool,
    /// The rest of this fixup's chain lives inside the page
    /// ([`crate::types::FixupRecord::chained`]) — reported, not followed.
    pub chained: bool,
    /// Additive value of the record, when it carries one.
    pub additive: Option<u32>,
}

impl fmt::Display for FixupNote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.target {
            FixupTarget::Internal { object, offset } => match offset {
                Some(offset) => write!(f, "object {object} offset 0x{offset:X}")?,
                None => write!(f, "object {object} (selector, no offset)")?,
            },
            FixupTarget::ImportByOrdinal {
                module_ordinal,
                ordinal,
            } => write!(f, "import module {module_ordinal} ordinal 0x{ordinal:X}")?,
            FixupTarget::ImportByName {
                module_ordinal,
                name_offset,
            } => write!(
                f,
                "import module {module_ordinal} procedure @0x{name_offset:X}"
            )?,
            FixupTarget::EntryTable { ordinal } => write!(f, "entry ordinal {ordinal}")?,
        }
        if self.alias {
            write!(f, ", alias")?;
        }
        if self.chained {
            write!(f, ", chained")?;
        }
        if let Some(additive) = self.additive {
            write!(f, ", +0x{additive:X}")?;
        }
        write!(f, " [{}]", self.source_type.num())
    }
}

/// Patch slots of one object image, keyed by offset within that image.
pub type FixupMap = BTreeMap<u32, Vec<FixupNote>>;

/// Every object's [`FixupMap`], plus the slots that could not be placed.
#[derive(Clone, Debug, Default)]
pub struct FixupMaps {
    /// Keyed by 1-based object number.
    pub by_object: BTreeMap<u16, FixupMap>,
    /// Patch slots that belong to no object image: their page row is outside
    /// every object's page block, or past that object's `vsize`. A fixup table
    /// and an object table that disagree is data, not an error to hide, so it
    /// is counted here instead of silently dropped.
    pub unmapped_slots: usize,
}

impl FixupMaps {
    /// The map of one object, empty when it has none.
    #[must_use]
    pub fn map_of(&self, object_number: u16) -> Option<&FixupMap> {
        self.by_object.get(&object_number)
    }

    /// Number of **distinct** offsets that carry at least one note.
    ///
    /// Two records may patch the same offset.
    #[must_use]
    pub fn placed_slots(&self) -> usize {
        self.by_object.values().map(BTreeMap::len).sum()
    }

    /// Total number of notes placed in every object: one per source offset that
    /// landed inside an object image, so a slot patched twice is counted twice.
    #[must_use]
    pub fn placed_notes(&self) -> usize {
        self.by_object
            .values()
            .map(|map| map.values().map(Vec::len).sum::<usize>())
            .sum()
    }
}

/// Re-key the fixup record table from pages to objects.
///
/// A record says "the page at row *r* of the object page table, offsets
/// *s1, s2, …*" — `FixupRecord::page` is a 0-based **row**, and the source
/// offsets are within that page — while a listing runs along an object image.
/// The two frames are linked by the object table: object *k* owns rows
/// `first_page-1 .. first_page-1 + page_count` of the page table, in table
/// order, which is exactly the order [`crate::le::LE::object_image`]
/// concatenates them in (and each row reads to a full `page_size`, zero-padded
/// when shorter). So
///
/// ```text
/// object offset = (row - (first_page - 1)) * page_size + offset_in_page
/// ```
///
/// A record on row 4 of `vmdisp9xvxd.BIN` (objects: rows 1–4 and 5) lands in
/// object 2 at `(4 - 4) * 4096 + src`, and its `0x28`-of-row-0 sibling lands
/// in object 1 at `0x28`. In `hellovxd.BIN` the three-offset source list of the
/// first record gives three slots in object 1, at 0x7F, 0xA8 and 0xBE, and the
/// second record adds 0x18.
pub fn build_fixup_maps(le: &impl LE) -> Result<FixupMaps, Error> {
    let header = le.get_valid_le_header()?;
    let objects = le.get_object_table()?;
    let records = le.get_fixup_records()?;
    let page_size = header.page_size() as usize;

    let mut maps = FixupMaps::default();
    for record in &records {
        let row = record.page as usize;
        let owner = objects.iter().enumerate().find(|(_, object)| {
            let first = object.first_page as usize - 1;
            row >= first && row < first + object.page_count as usize
        });
        let note = || FixupNote {
            source_type: record.source_type,
            target: record.target,
            alias: record.alias(),
            chained: record.chained(),
            additive: record.additive,
        };
        let Some((index, object)) = owner else {
            maps.unmapped_slots += record.source_offsets.len();
            continue;
        };
        let base = (row - (object.first_page as usize - 1)) * page_size;
        let vsize = object.virtual_size as usize;
        let map = maps.by_object.entry((index + 1) as u16).or_default();
        for &source in &record.source_offsets {
            let at = base + source as usize;
            if at >= vsize {
                maps.unmapped_slots += 1;
                continue;
            }
            map.entry(at as u32).or_default().push(note());
        }
    }
    Ok(maps)
}

// ---------------------------------------------------------------------------
// Import names
// ---------------------------------------------------------------------------

/// An import target with its names resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportRef {
    /// Import module name, `None` when the ordinal is out of range or the name
    /// is not UTF-8.
    pub module: Option<String>,
    /// Import procedure name, for a by-name target only.
    pub procedure: Option<String>,
    /// Import ordinal, for an ordinal-bound target only.
    pub ordinal: Option<u32>,
}

impl ImportRef {
    /// `MODULE.Procedure`, `MODULE#ordinal`, or `MODULE` — whichever parts
    /// resolved.
    #[must_use]
    pub fn display(&self) -> String {
        let module = self.module.clone().unwrap_or_else(|| "?".to_owned());
        if let Some(procedure) = &self.procedure {
            return format!("{module}.{procedure}");
        }
        if let Some(ordinal) = self.ordinal {
            return format!("{module}#{ordinal:#X}");
        }
        module
    }
}

/// Resolve an import fixup target to its module and procedure names.
///
/// Returns `None` for a target that is not an import (internal or entry-table).
/// A by-name target's `name_offset` is a **byte offset into the import
/// procedure table**, not an index into it, and it counts from the table's
/// mandatory null entry: `os2-impexp.BIN` stores 0x1 and 0x10, which are the
/// offsets of `DosLoadModule_` and `WinQueryWindowPos_` in a table whose first
/// byte is that `00` terminator, so 0x1 is the first name. Resolving it as an
/// index would name `WinQueryWindowPos_` for 1 and nothing for 0x10.
pub fn import_reference(le: &impl LE, target: &FixupTarget) -> Result<Option<ImportRef>, Error> {
    let (module_ordinal, name_offset, ordinal) = match target {
        FixupTarget::ImportByOrdinal {
            module_ordinal,
            ordinal,
        } => (*module_ordinal, None, Some(*ordinal)),
        FixupTarget::ImportByName {
            module_ordinal,
            name_offset,
        } => (*module_ordinal, Some(*name_offset), None),
        _ => return Ok(None),
    };

    let modules = le.get_import_modules()?;
    let module = modules
        .get(module_ordinal as usize - 1)
        .and_then(|m| m.as_str().ok())
        .map(str::to_owned);

    let procedure = match name_offset {
        Some(offset) => import_procedure_at(le, offset)?,
        None => None,
    };

    Ok(Some(ImportRef {
        module,
        procedure,
        ordinal,
    }))
}

/// The procedure name stored at byte offset `offset` of the import procedure
/// table, counting bytes from the table's first byte.
///
/// The offsets are located by re-walking the entries
/// [`crate::le::LE::get_import_procedures`] already returned — one entry is
/// `1 + LEN` bytes — rather than by scanning raw bytes here, so the table's own
/// bounds and its two producer traps (a zero module table, and the `VxD` shape
/// where `import_procedures` equals `import_modules`) are inherited from the
/// reader instead of being re-derived.
fn import_procedure_at(le: &impl LE, offset: u32) -> Result<Option<String>, Error> {
    let header = le.get_valid_le_header()?;
    let import_procedures = header.import_procedures() as usize;
    if import_procedures == 0 {
        return Ok(None);
    }
    let base = le.header_offset()? + import_procedures;
    let procedures = le.get_import_procedures()?;
    // The mandatory null entry is one zero byte at the front of the table, so
    // the first name is at offset 1; the record's offset counts from byte 0.
    let mut at = usize::from(le.read_u8(base)? == 0);
    for name in &procedures {
        if at == offset as usize {
            return Ok(name.as_str().ok().map(str::to_owned));
        }
        at += 1 + name.char_len();
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

/// Instruction text syntax for [`list_code`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Syntax {
    /// Intel mnemonics and operand order (default).
    #[default]
    Intel,
    /// AT&T (GAS) mnemonics and operand order.
    Gas,
}

/// One line of a [`Listing`]: an instruction, or one undecodable byte.
#[derive(Clone, Debug)]
pub struct ListedLine<'a> {
    /// Offset within the object image this sweep ran over.
    pub offset: u32,
    /// Flat address the loader maps this byte at — the object's relocation base
    /// plus [`Self::offset`]. The decoder is configured with it, so
    /// near-branch targets already print as flat addresses.
    pub linear: u32,
    /// The bytes this line covers (one byte when [`Self::is_data`]).
    pub bytes: &'a [u8],
    /// Instruction text in the requested syntax; empty for a data line.
    pub text: String,
    /// Fixups patching inside this line, in offset order. Empty when
    /// [`list_code`] was called without a map.
    pub notes: Vec<FixupNote>,
    /// `true`: undecodable or truncated byte. The caller decides how to label
    /// it (typically `db 0xNN`); it is never a guessed instruction.
    pub is_data: bool,
}

/// Result of a linear code sweep.
#[derive(Clone, Debug)]
pub struct Listing<'a> {
    /// Lines in ascending offset order.
    pub lines: Vec<ListedLine<'a>>,
    /// Number of instruction lines.
    pub instructions: usize,
    /// Number of bytes that did not decode.
    pub data_bytes: usize,
}

impl Listing<'_> {
    /// Bytes covered by the lines; always the window length the sweep was
    /// given, which is what makes silently dropped bytes a caller-side bug.
    #[must_use]
    pub fn covered_bytes(&self) -> usize {
        self.lines.iter().map(|line| line.bytes.len()).sum()
    }
}

/// Linear sweep of `window`: `count` bytes starting at object-image offset
/// `start`, where `relocation_base` is that object's relocation base.
///
/// The decoder is created with the **flat** address of each byte as its
/// instruction pointer, so `call`/`jmp` targets print as loader-visible linear
/// addresses (`call 00010034h` for object base 0x10000 + offset 0x34) rather
/// than window-relative ones. Bytes that fail to decode, an instruction cut
/// short by the window end, and a decoder that cannot be built at all all
/// become one-byte [`ListedLine::is_data`] lines and the sweep continues, so
/// malformed code yields a listing rather than an error or a panic.
///
/// When `fixups` is given, every note whose patch slot falls inside a line is
/// attached to it — including a slot in the middle of a multi-byte instruction,
/// which is the normal case for a 32-bit absolute fixup of an operand.
///
/// # Examples
///
/// ```
/// # let Some(bytes) = linear_executable::doc_fixture() else { return };
/// use linear_executable::disasm::{self, Bitness, Syntax};
/// use linear_executable::{VecLE, LE};
///
/// let le = VecLE::from_memory(bytes);
/// let image = le.object_image(1).unwrap();
/// // hallasm.BIN enters at object 1 offset 0; its whole object is 15 bytes:
/// // `$`-string print and terminate, five instructions, no data.
/// let listing = disasm::list_code(&image, 0, 0x10000, Bitness::Bit32, Syntax::Intel, None);
/// assert_eq!(image.len(), 15);
/// assert_eq!(listing.covered_bytes(), 15);
/// assert_eq!(listing.instructions, 5);
/// assert_eq!(listing.data_bytes, 0);
/// assert_eq!(listing.lines[0].text, "mov ah,9");
/// assert_eq!(listing.lines[2].text, "int 21h");
/// assert_eq!(listing.lines[0].linear, 0x10000);
/// ```
#[must_use]
pub fn list_code<'a>(
    window: &'a [u8],
    start: u32,
    relocation_base: u32,
    bitness: Bitness,
    syntax: Syntax,
    fixups: Option<&FixupMap>,
) -> Listing<'a> {
    let mut formatter: Box<dyn Formatter> = match syntax {
        Syntax::Intel => Box::new(IntelFormatter::new()),
        Syntax::Gas => Box::new(GasFormatter::new()),
    };
    let mut lines: Vec<ListedLine<'a>> = Vec::new();
    let mut instructions = 0usize;
    let mut data_bytes = 0usize;
    let mut off = 0usize;

    while off < window.len() {
        let offset = start.wrapping_add(off as u32);
        let linear = relocation_base.wrapping_add(offset);
        let decoded = Decoder::try_with_ip(
            bitness.bits(),
            &window[off..],
            u64::from(linear),
            DecoderOptions::NONE,
        )
        .ok()
        .map(|mut decoder| decoder.decode());

        let instruction =
            decoded.filter(|insn| insn.code() != Code::INVALID && insn.len() <= window.len() - off);

        if let Some(insn) = instruction {
            let len = insn.len();
            let mut text = String::new();
            formatter.format(&insn, &mut text);
            let bytes = &window[off..off + len];
            let notes = notes_in(fixups, offset, len);
            instructions += 1;
            lines.push(ListedLine {
                offset,
                linear,
                bytes,
                text,
                notes,
                is_data: false,
            });
            off += len;
        } else {
            let bytes = &window[off..=off];
            let notes = notes_in(fixups, offset, 1);
            data_bytes += 1;
            lines.push(ListedLine {
                offset,
                linear,
                bytes,
                text: String::new(),
                notes,
                is_data: true,
            });
            off += 1;
        }
    }

    Listing {
        lines,
        instructions,
        data_bytes,
    }
}

/// Notes whose patch slot lies inside `[offset, offset + len)`.
fn notes_in(fixups: Option<&FixupMap>, offset: u32, len: usize) -> Vec<FixupNote> {
    let Some(map) = fixups else {
        return Vec::new();
    };
    let end = offset.saturating_add(len as u32);
    map.range(offset..end)
        .flat_map(|(_, notes)| notes.clone())
        .collect()
}
