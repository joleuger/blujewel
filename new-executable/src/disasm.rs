// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! Disassembly support for NE code segments (feature `disasm`).
//!
//! This module is the **facts layer** of the disassembler: it answers
//! NE-specific questions that any consumer of a code listing (CLI, emulator,
//! interpreter) otherwise has to rederive from the format spec.
//! It deliberately contains **no presentation**: no column layout, no
//! `println!`, no default policy about where a listing starts. The `ne-disasm`
//! binary owns all of that.
//!
//! What lives here:
//! - Segment data resolution: zero `length` means 0x10000, ALLOCATED segments
//!   have no file data, records may overrun the file ([`segment_data`]).
//! - Loader-fixup semantics: every relocation chain is walked
//!   ([`RelocationEntry::resolve_chain`]) and each patch slot is mapped to a
//!   typed [`FixupNote`] with the target resolved through the module
//!   reference table ([`build_fixup_maps`]).
//! - Entry-point semantics: entry-table records are resolved onto segment
//!   addresses with their flags, so a consumer can tell an exported entry
//!   from an internal one instead of guessing from the record type
//!   ([`build_entry_maps`]).
//! - 16-bit decoding: a linear sweep that decodes with iced-x86 (the only
//!   place iced is reachable from library code) and never invents an
//!   instruction for undecodable bytes — they come back as explicitly
//!   flagged data lines ([`list_code`]).
//!
//! iced-x86 is wired to this module only; a build without `--features
//! disasm` contains neither iced nor any of this code. `disasm` implies
//! `std` because iced-x86 is used with its `std` feature.

use std::collections::BTreeMap;
use std::format;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use iced_x86::{Code, Decoder, DecoderOptions, Formatter, GasFormatter, IntelFormatter};

use crate::headers::SegmentRecord;
use crate::types::{EntryTable, EntryType, ModuleRefTable, RelocationEntry, RelocationTable};
use crate::{AddressType, Buffer, RelocationType, SegmentFlags, NE};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Decode the header `csip` field into the entry point `(segment, offset)`:
/// the high word is the 1-based segment number, the low word the offset
/// within it.
///
/// # Examples
///
/// ```
/// use new_executable::disasm;
/// assert_eq!(disasm::entry_point(0x0001_001A), (1, 0x1A)); // DUALBTN: 1:001A
/// ```
#[must_use]
pub fn entry_point(csip: u32) -> (u16, u32) {
    ((csip >> 16) as u16, csip & 0xFFFF)
}

// ---------------------------------------------------------------------------
// Segment data
// ---------------------------------------------------------------------------

/// The loader treats a zero `length` as 0x10000 (64 KiB segment).
///
/// # Examples
///
/// ```
/// use new_executable::{disasm, SegmentRecord};
/// let full_64k = SegmentRecord { offset: 0, length: 0, flags: 0, minalloc: 0 };
/// assert_eq!(disasm::segment_data_length(full_64k), 0x10000);
/// ```
#[must_use]
pub fn segment_data_length(rec: SegmentRecord) -> usize {
    if rec.length == 0 {
        0x10000
    } else {
        usize::from(rec.length)
    }
}

/// File offset of a segment's data: the record `offset` is a sector value,
/// shifted by the header alignment shift (file-absolute, no `e_lfanew`).
///
/// # Examples
///
/// ```
/// use new_executable::{disasm, SegmentRecord};
/// // DUALBTN.bin segment 1: sector 0x14 at 16-byte alignment (shift 4)
/// let seg1 = SegmentRecord { offset: 0x14, length: 0x9CA, flags: 0, minalloc: 0 };
/// assert_eq!(disasm::segment_file_offset(seg1, 4), 0x140);
/// ```
#[must_use]
pub fn segment_file_offset(rec: SegmentRecord, align_shift: usize) -> usize {
    usize::from(rec.offset) << align_shift
}

/// Raw data of a segment, truncated to the file size if the record overruns.
///
/// Returns `(data, truncated)` — `data` borrows the buffer. `None` when the
/// segment has no file data: ALLOCATED segments are allocated at load time,
/// and a base offset past EOF is treated the same way.
pub fn segment_data(ne: &impl NE, rec: SegmentRecord, align_shift: usize) -> Option<(&[u8], bool)> {
    if rec.segment_flags().contains(SegmentFlags::ALLOCATED) {
        return None;
    }
    let base = segment_file_offset(rec, align_shift);
    if base >= ne.len() {
        return None;
    }
    let want = segment_data_length(rec);
    let len = want.min(ne.len() - base);
    ne.get_slice(base, len)
        .ok()
        .map(|d| (d, want > ne.len() - base))
}

// ---------------------------------------------------------------------------
// Fixups
// ---------------------------------------------------------------------------

/// What a loader fixup patches the chain with, resolved as far as the
/// module reference table allows.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixupTarget {
    /// Import from another module: `module` is the module name (e.g.
    /// `KERNEL`), `export` the function ordinal as decimal text (e.g. `91`)
    /// or the imported name when the relocation names it. Unresolved names
    /// read `?`.
    Import { module: String, export: String },
    /// Pointer into a loaded segment: 1-based `segment`, `offset` within it.
    Internal { segment: u16, offset: u16 },
    /// Reference into this module itself (module ref `0xFFFF`); the value is
    /// the raw target2 (an index into this module's import table).
    SelfModule(u16),
    /// OS-specific global fixup; the operand pair is opaque here.
    OSGlobal { target1: u16, target2: u16 },
    /// Relocation type or operands the parser could not interpret.
    Unknown { target1: u16, target2: u16 },
}

impl core::fmt::Display for FixupTarget {
    /// Wine-`winedump`-style text, e.g. `KERNEL.178`, `1:00AB`, `self.23`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Import { module, export } => write!(f, "{module}.{export}"),
            Self::Internal { segment, offset } => write!(f, "{segment}:{offset:04X}"),
            Self::SelfModule(target2) => write!(f, "self.{target2}"),
            Self::OSGlobal { target1, target2 } => {
                write!(f, "osgglobal(t1={target1:04X}, t2={target2:04X})")
            }
            Self::Unknown { target1, target2 } => write!(f, "t1={target1:04X} t2={target2:04X}"),
        }
    }
}

/// One loader fixup: patch kind, patched-with value, and chain health.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixupNote {
    /// Patch width/action, e.g. [`AddressType::Pointer32`].
    pub address_type: AddressType,
    /// What the loader writes at the patch slot.
    pub target: FixupTarget,
    /// Bit 0x04 of the relocation type: the value is ADDED to the existing
    /// content instead of replacing it.
    pub additive: bool,
    /// The patch chain could not be walked (cycle or corrupt link), so the
    /// note sits at the chain head instead of its links.
    pub chain_corrupt: bool,
}

impl FixupNote {
    /// Wine-`winedump`-style patch-type name: `byte`, `sel`, `off16`,
    /// `ptr32`, `ptr48`, `off32`.
    #[must_use]
    pub fn address_type_name(&self) -> &'static str {
        match self.address_type {
            AddressType::LowByte => "byte",
            AddressType::Selector => "sel",
            AddressType::Pointer32 => "ptr32",
            AddressType::Offset16 => "off16",
            AddressType::Pointer48 => "ptr48",
            AddressType::Offset32 => "off32",
            _ => "???",
        }
    }
}

impl core::fmt::Display for FixupNote {
    /// e.g. `ptr32 = KERNEL.91`, `off16 = 2:0123 (add)`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} = {}", self.address_type_name(), self.target)?;
        if self.additive {
            f.write_str(" (add)")?;
        }
        if self.chain_corrupt {
            f.write_str(" [chain corrupt]")?;
        }
        Ok(())
    }
}

/// Fixup slots of one segment: segment offset -> notes. Several fixups may
/// patch the same byte, and every chain link is listed, so the values
/// are vectors. Iterates in segment-offset order.
pub type FixupMap = BTreeMap<u16, Vec<FixupNote>>;

fn push_note(map: &mut FixupMap, at: u16, note: FixupNote) {
    let notes = map.entry(at).or_default();
    if !notes.contains(&note) {
        notes.push(note);
    }
}

fn module_name(ne: &impl NE, mrt: Option<&ModuleRefTable>, idx: Option<u16>) -> String {
    mrt.and_then(|m| idx.and_then(|i| m.resolve_import_ordinal_name(ne, i).ok()))
        .and_then(|p| p.as_str().ok())
        .unwrap_or("?")
        .to_string()
}

fn resolve_proc_name(ne: &impl NE, mrt: Option<&ModuleRefTable>, off: u16) -> String {
    mrt.and_then(|_| ModuleRefTable::resolve_import_name(ne, off).ok())
        .and_then(|p| p.as_str().ok())
        .unwrap_or("?")
        .to_string()
}

fn resolve_target(
    entry: &RelocationEntry,
    ne: &impl NE,
    mrt: Option<&ModuleRefTable>,
) -> FixupTarget {
    match entry.relocation_type {
        RelocationType::Internal => {
            if entry.is_self_module_ref() {
                FixupTarget::SelfModule(entry.target2)
            } else {
                FixupTarget::Internal {
                    segment: entry.target1,
                    offset: entry.target2,
                }
            }
        }
        RelocationType::Ordinal => FixupTarget::Import {
            module: module_name(ne, mrt, entry.mod_ref_index()),
            export: entry.target2.to_string(),
        },
        RelocationType::Name => FixupTarget::Import {
            module: module_name(ne, mrt, entry.mod_ref_index()),
            export: entry
                .proc_name_offset()
                .map_or_else(|| "?".to_string(), |o| resolve_proc_name(ne, mrt, o)),
        },
        RelocationType::OSGlobal => FixupTarget::OSGlobal {
            target1: entry.target1,
            target2: entry.target2,
        },
        _ => FixupTarget::Unknown {
            target1: entry.target1,
            target2: entry.target2,
        },
    }
}

/// Resolve every relocation entry to its segment and patch slots, producing
/// one [`FixupMap`] per segment (index = segment number - 1).
///
/// Each entry's full chain is walked via
/// [`RelocationEntry::resolve_chain`] and the note is attached to every
/// link; entries whose chain cannot be walked (cycle/corrupt) are attached
/// at the chain head with [`FixupNote::chain_corrupt`] set. Entries naming
/// a nonexistent segment (possible in corrupt files) are skipped. The module
/// reference table is optional: if it fails to parse, targets resolve to
/// `?` instead of failing the whole map.
///
/// # Examples
///
/// ```
/// # let Some(bytes) = new_executable::doc_fixture() else { return };
/// use new_executable::disasm;
/// use new_executable::types::RelocationTable;
/// # use new_executable::{VecNE, NE};
/// let ne = VecNE::from_memory(bytes);
/// let header = ne.get_valid_ne_header().unwrap();
/// let segments = ne.get_segment_table().unwrap();
/// let relocs = RelocationTable::parse(&ne).unwrap();
/// let maps = disasm::build_fixup_maps(&ne, &relocs, &segments, header.alignment as usize);
///
/// // The `call far` at segment 1 offset 0x1D carries its 4-byte import
/// // pointer at 0x1E — DUALBTN patches it with KERNEL ordinal 91 (INITTASK):
/// let notes = maps[0].get(&0x1E).expect("segment 1, patch slot 0x1E");
/// assert_eq!(notes[0].to_string(), "ptr32 = KERNEL.91");
/// ```
pub fn build_fixup_maps(
    ne: &impl NE,
    relocs: &RelocationTable,
    segments: &[SegmentRecord],
    align_shift: usize,
) -> Vec<FixupMap> {
    let mrt = ModuleRefTable::parse(ne).ok();
    let mut per_seg = vec![FixupMap::new(); segments.len()];
    for entry in &relocs.entries {
        let note = FixupNote {
            address_type: entry.address_type,
            target: resolve_target(entry, ne, mrt.as_ref()),
            additive: entry.is_additive,
            chain_corrupt: false,
        };
        // A corrupt file may name segment 0 or a segment past the table.
        let Some(idx) = usize::from(entry.segment_number).checked_sub(1) else {
            continue;
        };
        let Some(rec) = segments.get(idx) else {
            continue;
        };
        let Some((data, _)) = segment_data(ne, *rec, align_shift) else {
            continue;
        };
        match entry.resolve_chain(data) {
            Ok(links) => {
                for link in links {
                    push_note(&mut per_seg[idx], link, note.clone());
                }
            }
            Err(_) => push_note(
                &mut per_seg[idx],
                entry.offset,
                FixupNote {
                    chain_corrupt: true,
                    ..note
                },
            ),
        }
    }
    per_seg
}

// ---------------------------------------------------------------------------
// Entry-table addresses (entry points)
// ---------------------------------------------------------------------------

/// One entry-table record that names an address inside a segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryNote {
    /// 1-based ordinal in the entry table.
    pub ordinal: u16,
    /// Raw entry flags byte: bit 0 exported, bit 1 global (shared) data
    /// segment, bits 3-7 ring-transition stack words.
    pub flags: u8,
    /// `true` for a movable (bundle type `0xFF`) record.
    pub movable: bool,
}

impl EntryNote {
    /// Bit 0: the entry is exported, i.e. other modules may import it. When
    /// clear the entry is an internal entry point — it still has a real
    /// address and is still a code boundary, but it is not callable from
    /// outside the module. Set in every entry of the 19-file corpus.
    #[must_use]
    pub fn exported(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

impl core::fmt::Display for EntryNote {
    /// e.g. `export 77 (movable)`, `entry 12 internal (fixed)`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.exported() {
            write!(
                f,
                "export {} ({})",
                self.ordinal,
                if self.movable { "movable" } else { "fixed" }
            )
        } else {
            write!(
                f,
                "entry {} internal ({})",
                self.ordinal,
                if self.movable { "movable" } else { "fixed" }
            )
        }
    }
}

/// Entry-table addresses inside one segment: segment offset -> records.
/// Several ordinals can name the same address, and an address can be both a
/// fixed entry and the target of a branch, so the values are vectors.
/// Iterates in segment-offset order.
pub type EntryMap = BTreeMap<u16, Vec<EntryNote>>;

/// Resolve a module's entry table onto its segments: index 0 = segment 1.
///
/// Records that carry no address cannot name a location and are skipped:
/// `Constant` (type `0xFE`) records hold a value rather than an address, and
/// unused (`type 0`) slots have no record at all. A `seg_num` of 0 or past
/// `seg_count` (possible in a corrupt file) is skipped too.
///
/// Flags are carried through rather than filtered on: [`EntryNote::exported`]
/// is what tells a consumer whether the loader accepts the entry as an import
/// target, and a non-exported entry is still an instruction boundary worth
/// annotating. Of the 1322 address-bearing entries in the corpus, the 1287
/// that are exported also land on an instruction boundary of an independent
/// linear sweep of the same segment.
///
/// # Examples
///
/// ```
/// use new_executable::disasm::build_entry_maps;
/// use new_executable::types::{EntryTable, EntryType, ExportEntry};
///
/// let table = EntryTable {
///     entries: vec![
///         Some(ExportEntry { flags: 0x03, entry_type: EntryType::Fixed { seg_num: 1, offset: 0x1A } }),
///         None, // unused ordinal 2
///         Some(ExportEntry { flags: 0x01, entry_type: EntryType::Movable { seg_num: 1, offset: 0x40 } }),
///         Some(ExportEntry { flags: 0x01, entry_type: EntryType::Constant { value: 7 } }),
///     ],
/// };
/// let maps = build_entry_maps(&table, 2);
/// assert_eq!(maps[0][&0x1A][0].to_string(), "export 1 (fixed)");
/// assert_eq!(maps[0][&0x40][0].to_string(), "export 3 (movable)");
/// assert_eq!(maps[0][&0x1A][0].flags, 0x03); // shared data segment bit set
/// assert!(maps[1].is_empty());               // segment 2 has no entries
/// ```
#[must_use]
pub fn build_entry_maps(table: &EntryTable, seg_count: usize) -> Vec<EntryMap> {
    let mut per_seg = vec![EntryMap::new(); seg_count];
    for (idx, slot) in table.entries.iter().enumerate() {
        let Some(rec) = slot else { continue };
        let (seg_num, offset, movable) = match rec.entry_type {
            EntryType::Fixed { seg_num, offset } => (seg_num, offset, false),
            EntryType::Movable { seg_num, offset } => (seg_num, offset, true),
            EntryType::Constant { .. } => continue,
        };
        let Some(i) = usize::from(seg_num).checked_sub(1) else {
            continue;
        };
        let Some(map) = per_seg.get_mut(i) else {
            continue;
        };
        // The parser caps the ordinal slot count at u16::MAX, so an
        // out-of-range ordinal means a hand-built table, not a parsed file.
        let Ok(ordinal) = u16::try_from(idx + 1) else {
            continue;
        };
        let note = EntryNote {
            ordinal,
            flags: rec.flags,
            movable,
        };
        let notes = map.entry(offset).or_default();
        if !notes.contains(&note) {
            notes.push(note);
        }
    }
    per_seg
}

// ---------------------------------------------------------------------------
// Linear code listing
// ---------------------------------------------------------------------------

/// Instruction text syntax for [`list_code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Syntax {
    /// Intel mnemonics and operand order (default).
    #[default]
    Intel,
    /// AT&T (GAS) mnemonics and operand order.
    Gas,
}

/// One line of a [`Listing`]: an instruction, or one undecodable byte.
#[derive(Debug, Clone)]
pub struct ListedLine<'a> {
    /// Segment-relative offset of the first byte.
    pub offset: u32,
    /// Absolute file offset of the first byte.
    pub file_offset: usize,
    /// The bytes this line covers (one byte when [`Self::is_data`]).
    pub bytes: &'a [u8],
    /// Instruction text in the requested syntax with near-branch targets
    /// resolved to segment-relative addresses; empty for data lines.
    pub text: String,
    /// Loader fixups patching inside this line, in segment-offset order.
    /// Empty when [`list_code`] was called without a fixup map.
    pub notes: Vec<FixupNote>,
    /// `true`: undecodable or truncated byte — the consumer decides how to
    /// label it (e.g. `db 0xNN`); it is never a guessed instruction (P4).
    pub is_data: bool,
}

/// Result of a linear code sweep: every input byte is covered by exactly
/// one line, so `instructions + data_bytes` accounting cannot hide bytes.
#[derive(Debug, Clone)]
pub struct Listing<'a> {
    /// The lines, in ascending offset order.
    pub lines: Vec<ListedLine<'a>>,
    /// Number of decoded instruction lines.
    pub instructions: usize,
    /// Number of data (undecodable byte) lines.
    pub data_bytes: usize,
}

/// Linear sweep of `window`, the bytes `[start, end)` of one code segment,
/// where `start` is the segment-relative offset of `window[0]` and
/// `file_base` the file offset of the segment's byte 0 — a line at segment
/// offset `o` gets absolute file offset `file_base + o`.
///
/// The decoder is created with the segment offset as its instruction
/// pointer, so the formatter already prints near-branch targets resolved
/// against the segment base (e.g. `je short 0012h`). Bytes that fail to
/// decode, or an instruction truncated at the window end, become one-byte
/// [`ListedLinew_executable::is_data`] lines and the sweep continues; the summary
/// counts in [`Listing`] make silent byte loss a caller-side bug. When
/// `fixups` is given, every note is attached to the line that contains its
/// patch slot.
///
/// # Examples
///
/// ```
/// # let Some(bytes) = new_executable::doc_fixture() else { return };
/// use new_executable::disasm::{self, Syntax};
/// # use new_executable::{VecNE, NE};
/// let ne = VecNE::from_memory(bytes);
/// let header = ne.get_valid_ne_header().unwrap();
/// let segments = ne.get_segment_table().unwrap();
/// let (code, _truncated) =
///     disasm::segment_data(&ne, segments[0], header.alignment as usize).unwrap();
///
/// // Sweep the entry code of DUALBTN.bin: entry point 1:001A, 0x38 bytes.
/// // `start` is segment-relative; `file_base` (0x140) is segment 1's file
/// // offset, so a line at 0x1A reports file offset 0x15A.
/// let listing = disasm::list_code(&code[0x1A..0x52], 0x1A, 0x140, Syntax::Intel, None);
/// assert_eq!(listing.instructions, 17);
/// assert_eq!(listing.data_bytes, 0);
/// assert_eq!(listing.lines[0].text, "xor bp,bp");
/// assert_eq!(listing.lines[0].file_offset, 0x15A);
/// ```
pub fn list_code<'a>(
    window: &'a [u8],
    start: u32,
    file_base: usize,
    syntax: Syntax,
    fixups: Option<&FixupMap>,
) -> Listing<'a> {
    let mut lines = Vec::new();
    let mut off = 0usize;
    while off < window.len() {
        let abs = start + off as u32;
        let mut decoder = Decoder::with_ip(
            16,
            &window[off..],
            u64::from(abs as u16),
            DecoderOptions::NONE,
        );
        let insn = decoder.decode();

        if insn.code() == Code::INVALID || insn.len() > window.len() - off {
            let notes = fixups.map_or_else(Vec::new, |m| {
                m.get(&(abs as u16)).cloned().unwrap_or_default()
            });
            lines.push(ListedLine {
                offset: abs,
                file_offset: file_base + abs as usize,
                bytes: &window[off..=off],
                text: String::new(),
                notes,
                is_data: true,
            });
            off += 1;
            continue;
        }

        let ilen = insn.len();
        let text = format_insn(syntax, &insn);
        let notes = fixups.map_or_else(Vec::new, |m| {
            let lo = abs as u16;
            let hi = lo.saturating_add(ilen as u16);
            m.range(lo..hi).flat_map(|(_, v)| v.clone()).collect()
        });
        lines.push(ListedLine {
            offset: abs,
            file_offset: file_base + abs as usize,
            bytes: &window[off..off + ilen],
            text,
            notes,
            is_data: false,
        });
        off += ilen;
    }
    let instructions = lines.iter().filter(|l| !l.is_data).count();
    Listing {
        data_bytes: lines.len() - instructions,
        instructions,
        lines,
    }
}

fn format_insn(syntax: Syntax, insn: &iced_x86::Instruction) -> String {
    let mut text = String::new();
    match syntax {
        Syntax::Gas => GasFormatter::new().format(insn, &mut text),
        Syntax::Intel => IntelFormatter::new().format(insn, &mut text),
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DUALBTN segment 1 from the entry point (same bytes as the CLI golden
    /// and `tests/iced_spike.rs`).
    const ENTRY: &[u8] = &[
        0x33, 0xED, 0x55, 0x9A, 0xFF, 0xFF, 0x00, 0x00, 0x0B, 0xC0, 0x74, 0xEC, 0x8C, 0x06, 0x46,
        0x00, 0x81, 0xC1, 0x00, 0x01, 0x72, 0xE2, 0x89, 0x0E, 0x10, 0x00, 0x89, 0x36, 0x12, 0x00,
        0x89, 0x3E, 0x14, 0x00, 0x89, 0x1E, 0x16, 0x00, 0x8C, 0x06, 0x18, 0x00, 0x89, 0x16, 0x1A,
        0x00, 0x9A, 0xFF, 0xFF, 0x00, 0x00, 0x86, 0xC4, 0xA3, 0x48, 0x00,
    ];

    fn rec(offset: u16, length: u16, flags: u16) -> SegmentRecord {
        SegmentRecord {
            offset,
            length,
            flags,
            minalloc: 0,
        }
    }

    #[test]
    fn entry_point_splits_csip() {
        assert_eq!(entry_point(0x0001_001A), (1, 0x001A));
        assert_eq!(entry_point(0), (0, 0));
    }

    #[test]
    fn segment_length_zero_means_64k() {
        assert_eq!(segment_data_length(rec(0, 0, 0)), 0x10000);
        assert_eq!(segment_data_length(rec(0, 0x9CA, 0)), 0x9CA);
    }

    #[test]
    fn file_offset_is_sector_shifted() {
        // DUALBTN segment 1: sector 0x14, shift 4 -> file offset 0x140.
        assert_eq!(segment_file_offset(rec(0x14, 0x9CA, 0), 4), 0x140);
    }

    #[test]
    fn list_code_decodes_full_entry_window() {
        // file_base is the segment's file offset (DUALBTN seg 1: 0x140);
        // the entry byte 0x1A lands at file offset 0x15A.
        let listing = list_code(ENTRY, 0x1A, 0x140, Syntax::Intel, None);
        assert_eq!((listing.instructions, listing.data_bytes), (17, 0));
        // Every input byte is covered exactly once.
        assert_eq!(
            listing.lines.iter().map(|l| l.bytes.len()).sum::<usize>(),
            ENTRY.len()
        );
        assert_eq!(listing.lines[0].text, "xor bp,bp");
        assert_eq!(listing.lines[0].offset, 0x1A);
        assert_eq!(listing.lines[0].file_offset, 0x15A);
        // branch target resolved against the segment base by the
        // decoder IP, not by the caller.
        assert!(listing.lines.iter().any(|l| l.text == "je short 0012h"));
    }

    #[test]
    fn list_code_gas_syntax() {
        let intel = list_code(&ENTRY[0x03..0x08], 0x1D, 0, Syntax::Intel, None);
        let gas = list_code(&ENTRY[0x03..0x08], 0x1D, 0, Syntax::Gas, None);
        assert_eq!(intel.lines[0].text, "call far 0FFFFh,0");
        assert!(
            gas.lines[0].text.starts_with("lcall"),
            "gas text: {}",
            gas.lines[0].text
        );
    }

    #[test]
    fn undecodable_bytes_come_back_as_data_lines() {
        // 0F 0F (3DNow! escape without suffix) and a truncated lone 0F.
        for probe in [&[0x0Fu8, 0x0F, 0xFF, 0xFF][..], &[0x0F][..]] {
            let listing = list_code(probe, 0, 0, Syntax::Intel, None);
            assert!(
                listing.data_bytes > 0,
                "probe {probe:02X?} produced no data lines"
            );
            assert_eq!(
                listing.lines.iter().map(|l| l.bytes.len()).sum::<usize>(),
                probe.len()
            );
            assert!(listing
                .lines
                .iter()
                .filter(|l| l.is_data)
                .all(|l| l.text.is_empty() && l.bytes.len() == 1));
        }
    }

    #[test]
    fn segment_data_skips_allocated_and_flags_truncation() {
        let ne = crate::VecNE::from_memory(ENTRY.to_vec());
        // ALLOCATED (0x0002): no file data.
        assert!(segment_data(&ne, rec(0, 0x10, 0x0002), 4).is_none());
        // Record overrunning this 56-byte buffer: truncated flag set.
        let (data, truncated) = segment_data(&ne, rec(0, 0x9CA, 0), 0).expect("readable");
        assert!(truncated);
        assert_eq!(data.len(), ENTRY.len());
    }

    #[cfg(feature = "fixtures")]
    mod fixtures {
        use super::*;

        fn dualbtn() -> crate::VecNE {
            crate::VecNE::from_disk_file("testdata/fixtures/DUALBTN.bin").expect("fixture present")
        }

        #[test]
        fn dualbtn_fixup_maps_carry_typed_notes() {
            let ne = dualbtn();
            let header = ne.get_valid_ne_header().unwrap();
            let shift = usize::from(header.common_fields().alignment);
            let segments = ne.get_segment_table().unwrap();
            let relocs = RelocationTable::parse(&ne).unwrap();
            let maps = build_fixup_maps(&ne, &relocs, &segments, shift);
            let seg1 = &maps[0];

            let note_at =
                |off: u16| -> Vec<String> { seg1[&off].iter().map(ToString::to_string).collect() };
            assert_eq!(note_at(0x10), ["off16 = KERNEL.178"]);
            assert_eq!(note_at(0x18), ["sel = 1:0000"]);
            assert_eq!(note_at(0x1E), ["ptr32 = KERNEL.91"]);
            assert_eq!(note_at(0x49), ["ptr32 = KERNEL.3"]);

            // The same facts, typed: the 0x1E note is a resolved KERNEL
            // ordinal import with a sound chain.
            let note = &seg1[&0x1E][0];
            assert_eq!(note.address_type, AddressType::Pointer32);
            assert_eq!(
                note.target,
                FixupTarget::Import {
                    module: "KERNEL".into(),
                    export: "91".into()
                }
            );
            assert!(!note.additive);
            assert!(!note.chain_corrupt);
        }

        #[test]
        fn dualbtn_listing_matches_cli_facts() {
            // The exact facts the ne-disasm CLI prints for the golden window
            // (tests/ne_disasm_snapshot.rs): 17 instructions, 0 data bytes.
            let ne = dualbtn();
            let header = ne.get_valid_ne_header().unwrap();
            let shift = usize::from(header.common_fields().alignment);
            let segments = ne.get_segment_table().unwrap();
            let (start, ip) = entry_point(header.common_fields().csip);
            assert_eq!((start, ip), (1, 0x1A));
            let (data, _) = segment_data(&ne, segments[0], shift).unwrap();
            let listing = list_code(
                &data[0x1A..0x52],
                0x1A,
                segment_file_offset(segments[0], shift),
                Syntax::Intel,
                None,
            );
            assert_eq!((listing.instructions, listing.data_bytes), (17, 0));
        }
    }
}
