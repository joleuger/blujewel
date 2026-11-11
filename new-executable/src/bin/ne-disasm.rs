// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! ne-disasm — disassemble code segments of NE (16-bit Windows/OS/2) files.
//!
//! Usage: `ne-disasm [OPTIONS] <FILE>` (see `--help`).
//!
//! This binary is the **presentation layer** of the disassembler: argument
//! parsing, listing policy (which segments, where a listing starts) and
//! text layout. All NE and decoder knowledge lives in the library's
//! `new_executable::disasm` facts module (`src/disasm.rs`), gated behind the same
//! `disasm` feature — iced-x86 is never referenced from this file, and the
//! `ne-inspect` binary and library core never see any of it.
//!
//! Design rules:
//! - decoding comes from iced-x86 in 16-bit mode, not a hand table.
//! - undecodable bytes print as explicit `db 0xNN` data lines, never as
//!   plausible-looking instructions, and the summary line counts every byte.
//! - listing starts at the header CS:IP, not segment offset 0; pre-entry
//!   bytes are not listed, their fixups and entry points are reported as
//!   comments.
//! - DATA / ALLOCATED / ITERATED segments are labeled and skipped.
//! - every line carries the segment-relative and the file offset.
//! - fixup slots are annotated from full chain walks
//!   (`new_executable::disasm::build_fixup_maps`), additive fixups marked.
//! - near-branch targets resolved to segment-relative addresses — the
//!   library decoder runs with the segment offset as its IP, so the
//!   formatter prints the resolved target (verified: `je short 0012h`).
//! - Entry points: entry-table records are annotated on the line they name
//!   (`new_executable::disasm::build_entry_maps`), phrased by flag bit 0 (`export 77
//!   (movable)` vs `entry 77 internal (fixed)`). An entry address the sweep
//!   did not start an instruction at is reported as a comment, never dropped
//!   and never silently left unannotated.

#![warn(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::unused_format_specs)]

use std::collections::BTreeSet;
use std::env;
use std::process;

use new_executable::disasm::{self, EntryMap, FixupMap, Syntax};
use new_executable::headers::SegmentRecord;
use new_executable::types::{EntryTable, RelocationTable};
use new_executable::{SegmentFlags, VecNE, NE};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
ne-disasm — disassemble code segments of NE (16-bit) files

USAGE:
    ne-disasm [OPTIONS] <FILE>

ARGS:
    <FILE>            NE executable to disassemble

OPTIONS:
    --segment <N>     segment number (1-based); default: the entry CS
    --from <OFF>      start offset in the segment (0x.. or decimal);
                      default: entry IP for the entry segment, else 0
    --to <OFF>        end offset, exclusive; default: segment length
    --count <N>       number of bytes to list (alternative to --to)
    --all             list every code segment
    --syntax <S>      intel (default) | gas (AT&T)
    --no-fixups       omit loader-fixup annotations
    --no-entries      omit entry-table (export) annotations
    -V, --version     print version
    -h, --help        print help

Numbers: `0x…` is hex, anything else is decimal (--segment 10 = segment 10).

Bytes before the entry point are never listed (loader padding / fixup slots);
fixup slots found there are reported as comment lines instead. Undecodable
bytes are listed as `db 0xNN` data lines, never silently skipped. Entry-table
records that name an address in the listed range are annotated on that line
(`export 77 (movable)`); an entry address the sweep cannot reproduce is
reported as a comment instead of dropped.";

struct Options {
    file: String,
    segment: Option<u16>,
    from: Option<u32>,
    to: Option<u32>,
    count: Option<u32>,
    all: bool,
    syntax: Syntax,
    fixups: bool,
    entries: bool,
}

/// `0x`-prefixed values are hex; anything else is decimal. Reading a bare
/// value as hex used to make `--segment 10` mean segment 16 silently.
fn parse_num(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x").or(s.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }
    s.parse().ok()
}

fn parse_args() -> Result<Options, String> {
    let mut file: Option<String> = None;
    let mut segment = None;
    let mut from = None;
    let mut to = None;
    let mut count = None;
    let mut all = false;
    let mut syntax = Syntax::Intel;
    let mut fixups = true;
    let mut entries = true;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut next_value = |name: &str| {
            args.next()
                .ok_or_else(|| format!("missing value for {name}"))
        };
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                process::exit(0);
            }
            "-V" | "--version" => {
                println!("ne-disasm {VERSION} (engine: iced-x86, 16-bit mode)");
                process::exit(0);
            }
            "--all" => all = true,
            "--no-fixups" => fixups = false,
            "--no-entries" => entries = false,
            "--segment" => {
                let raw = next_value("--segment")?;
                let v = parse_num(&raw)
                    .and_then(|v| u16::try_from(v).ok())
                    .filter(|v| *v >= 1);
                segment = Some(v.ok_or_else(|| format!("invalid --segment: {raw}"))?);
            }
            "--from" => {
                let raw = next_value("--from")?;
                from = Some(parse_num(&raw).ok_or_else(|| format!("invalid --from: {raw}"))?);
            }
            "--to" => {
                let raw = next_value("--to")?;
                to = Some(parse_num(&raw).ok_or_else(|| format!("invalid --to: {raw}"))?);
            }
            "--count" => {
                let raw = next_value("--count")?;
                count = Some(parse_num(&raw).ok_or_else(|| format!("invalid --count: {raw}"))?);
            }
            "--syntax" => {
                let v = next_value("--syntax")?;
                syntax = match v.as_str() {
                    "intel" => Syntax::Intel,
                    "gas" | "att" => Syntax::Gas,
                    other => return Err(format!("invalid --syntax: {other} (intel|gas)")),
                };
            }
            _ => {
                if arg.starts_with('-') && arg.len() > 1 {
                    return Err(format!("unknown option: {arg}"));
                }
                if file.is_some() {
                    return Err(format!("unexpected extra argument: {arg}"));
                }
                file = Some(arg);
            }
        }
    }

    let file = file.ok_or_else(|| "missing <FILE> argument".to_string())?;
    if count.is_some() && to.is_some() {
        return Err("--count and --to are mutually exclusive".to_string());
    }
    Ok(Options {
        file,
        segment,
        from,
        to,
        count,
        all,
        syntax,
        fixups,
        entries,
    })
}

/// Per-file facts every segment listing needs.
struct EntryPoint {
    shift: usize,
    seg: u16,
    ip: u32,
}

/// A listing that skips a segment must still say what the entry table claims
/// lives there: those addresses are real, just not listable here.
fn skipped_segment_note(entries: &EntryMap) {
    let n: usize = entries.values().map(Vec::len).sum();
    if n > 0 {
        println!(
            "  ; note: {n} entry point(s) name addresses in this segment, which is not listed"
        );
    }
}

/// Fixup slots below the listing start are reported as comments instead of
/// listed instructions (pre-entry bytes are never disassembled).
fn fixups_before_listing(fixups: &FixupMap, start16: u16, enabled: bool) {
    if !enabled {
        return;
    }
    for (pos, notes) in fixups.range(..start16) {
        for note in notes {
            println!("  ; fixup slot 0x{pos:04X} (before listing start): fixup {note}");
        }
    }
}

/// Entry points below the listing start are named as well: the listing skips
/// those bytes, but the addresses they name are still real.
fn entries_before_listing(entries: &EntryMap, start16: u16) {
    for (pos, notes) in entries.range(..start16) {
        for note in notes {
            println!("  ; entry point 0x{pos:04X} (before listing start): {note}");
        }
    }
}

/// An entry address inside the listed range that the sweep did not start an
/// instruction at is said out loud: either the entry is not an instruction
/// boundary or the sweep desynced on the way to it. Both are worth knowing;
/// silently annotating nothing is not.
fn entry_gaps(entries: &EntryMap, start16: u16, end16: u16, listed: &BTreeSet<u16>) {
    for (pos, notes) in entries.range(start16..end16) {
        if listed.contains(pos) {
            continue;
        }
        let names = notes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "  ; entry point 0x{pos:04X} is not an instruction boundary in this sweep: {names}"
        );
    }
    let outside: usize = entries.range(end16..).map(|(_, v)| v.len()).sum();
    if outside > 0 {
        println!("  ; note: {outside} entry point(s) past the listed range");
    }
}

fn list_segment(
    ne: &VecNE,
    seg_num: u16,
    rec: SegmentRecord,
    ep: &EntryPoint,
    opts: &Options,
    fixups: &FixupMap,
    entries: &EntryMap,
) {
    let flags = rec.segment_flags();
    let kind = if flags.contains(SegmentFlags::DATA) {
        "data"
    } else {
        "code"
    };
    let base = disasm::segment_file_offset(rec, ep.shift);
    let flags_raw = rec.flags;
    print!(
        "Segment {seg_num} ({kind}) — file offset 0x{base:X}, length 0x{:X}, flags {:#06X} ({flags:?})",
        disasm::segment_data_length(rec),
        flags_raw,
    );
    if seg_num == ep.seg {
        let (s, ip) = (ep.seg, ep.ip);
        print!("  [entry point {s}:{ip:04X}]");
    }
    println!();

    if flags.contains(SegmentFlags::ALLOCATED) {
        println!("  ; allocated at load time — no file data, nothing to list");
        skipped_segment_note(entries);
        return;
    }
    if flags.contains(SegmentFlags::ITERATED) {
        println!("  ; ITERATED segment — loader-expanded at run time; the expansion encoding is unresolved, so it is not listed");
        skipped_segment_note(entries);
        return;
    }
    if flags.contains(SegmentFlags::DATA) {
        if let Some((data, _)) = disasm::segment_data(ne, rec, ep.shift) {
            println!(
                "  ; data segment — not disassembled ({} bytes at file 0x{base:X})",
                data.len()
            );
        }
        skipped_segment_note(entries);
        return;
    }
    let Some((data, truncated)) = disasm::segment_data(ne, rec, ep.shift) else {
        println!("  ; no readable file data for this segment");
        skipped_segment_note(entries);
        return;
    };
    if truncated {
        println!("  ; note: record length overruns the file — listing truncated to the file end");
    }

    // Listing bounds. Default start: entry IP for the entry segment (P5:
    // bytes before it are never listed), 0 for any other segment.
    let seg_len = data.len() as u32;
    let start = opts.from.unwrap_or(if seg_num == ep.seg {
        ep.ip.min(seg_len)
    } else {
        0
    });
    if start >= seg_len {
        println!("  ; start offset {start:#X} is past the segment end (0x{seg_len:X})");
        return;
    }
    let end = if let Some(n) = opts.count {
        start.saturating_add(n)
    } else {
        opts.to.unwrap_or(seg_len)
    }
    .min(seg_len)
    .max(start + 1);

    // Fixup slots before the listing start are reported as comments (P5).
    let start16 = u16::try_from(start).unwrap_or(u16::MAX);
    let end16 = u16::try_from(end).unwrap_or(u16::MAX);
    fixups_before_listing(fixups, start16, opts.fixups);
    entries_before_listing(entries, start16);

    println!("  {:>6}  {:>8}  {:<24}  Text", "Offset", "File", "Bytes");
    let fixup_map = opts.fixups.then_some(fixups);
    let listing = disasm::list_code(
        &data[start as usize..end as usize],
        start,
        base,
        opts.syntax,
        fixup_map,
    );
    for line in &listing.lines {
        print_line(line, entries);
    }

    println!(
        "  ; listed {} instruction(s) + {} data byte(s), covering 0x{start:X}-0x{end:X}",
        listing.instructions, listing.data_bytes
    );
    if opts.fixups {
        let outside = fixups.range(end16..).map(|(_, v)| v.len()).sum::<usize>();
        if outside > 0 {
            println!("  ; note: {outside} fixup slot(s) past the listed range");
        }
    }
    // An entry address inside the listed range that the sweep did not start
    // an instruction at is said out loud, as are the ones past its
    // end.
    let listed: BTreeSet<u16> = listing
        .lines
        .iter()
        .filter_map(|l| u16::try_from(l.offset).ok())
        .collect();
    entry_gaps(entries, start16, end16, &listed);
}

/// One listing line: dual offsets, raw bytes, text (or `db` for data),
/// followed by the fixup annotations of that instruction, and any
/// entry-table record that names its first byte.
fn print_line(line: &disasm::ListedLine<'_>, entries: &EntryMap) {
    let hex = line
        .bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ");
    let file_off = line.file_offset;
    let mut tail = String::new();
    for note in &line.notes {
        tail.push_str(" ; fixup ");
        tail.push_str(&note.to_string());
    }
    if let Some(notes) = entries.get(&u16::try_from(line.offset).unwrap_or(u16::MAX)) {
        for note in notes {
            tail.push_str(" ; ");
            tail.push_str(&note.to_string());
        }
    }
    if line.is_data {
        println!(
            "  {:06X}  {file_off:#08X}  {hex:<24}  db {:02X}{tail}",
            line.offset, line.bytes[0]
        );
    } else {
        println!(
            "  {:06X}  {file_off:#08X}  {hex:<24}  {}{tail}",
            line.offset, line.text
        );
    }
}

fn run() -> Result<(), String> {
    let opts = parse_args()?;

    let ne = VecNE::from_disk_file(&opts.file).map_err(|e| format!("{}: {e}", opts.file))?;
    let header = ne
        .get_valid_ne_header()
        .map_err(|e| format!("not a valid NE file: {e}"))?;
    let fields = header.common_fields();
    let shift = usize::from(fields.alignment);
    let (entry_seg, entry_ip) = disasm::entry_point(fields.csip);

    let segments = ne
        .get_segment_table()
        .map_err(|e| format!("segment table: {e}"))?;
    if segments.is_empty() {
        return Err("file has no segments".to_string());
    }

    let fixups: Vec<FixupMap> = if opts.fixups {
        match RelocationTable::parse(&ne) {
            Ok(relocs) => disasm::build_fixup_maps(&ne, &relocs, &segments, shift),
            Err(e) => {
                eprintln!("ne-disasm: warning: relocation table: {e} — listing without fixups");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    let entry_maps: Vec<EntryMap> = if opts.entries {
        match EntryTable::parse(&ne) {
            Ok(table) => disasm::build_entry_maps(&table, segments.len()),
            Err(e) => {
                eprintln!(
                    "ne-disasm: warning: entry table: {e} — listing without entry annotations"
                );
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    println!("ne-disasm: {}", opts.file);
    let segs_to_list: Vec<u16> = if opts.all {
        (1..=segments.len() as u16).collect()
    } else if let Some(seg) = opts.segment {
        if usize::from(seg) > segments.len() {
            return Err(format!(
                "segment {seg} out of range (file has {})",
                segments.len()
            ));
        }
        vec![seg]
    } else {
        if !(1..=segments.len()).contains(&usize::from(entry_seg)) {
            return Err(format!(
                "header entry CS {entry_seg} is out of range; use --segment"
            ));
        }
        vec![entry_seg]
    };

    let ep = EntryPoint {
        shift,
        seg: entry_seg,
        ip: entry_ip,
    };
    for seg_num in segs_to_list {
        let rec = segments[usize::from(seg_num) - 1];
        let idx = usize::from(seg_num) - 1;
        // A segment with no relocation block and a file whose relocation or
        // entry table was not parsed at all both mean "no annotations here".
        list_segment(
            &ne,
            seg_num,
            rec,
            &ep,
            &opts,
            fixups.get(idx).unwrap_or(&FixupMap::default()),
            entry_maps.get(idx).unwrap_or(&EntryMap::default()),
        );
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("ne-disasm: {e}");
        eprintln!("try --help");
        process::exit(1);
    }
}
