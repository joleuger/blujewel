// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! `le-inspect` — detailed report on LE/LX files and W3/W4 VxD archives.
//!
//! Usage:
//! ```text
//! le-inspect [OPTIONS] <FILE>
//! ```
//!
//! The file is sniffed (LE, LX, W3, W4) and the matching report is printed.
//! Exit codes: 0 = ok, 1 = parse error, 3 = usage error.

use linear_executable::bound::{self, Location};
use linear_executable::le::LE;
use linear_executable::types::{
    EntryFlags, EntryPoint, FixupRecord, FixupSourceFlags, FixupTarget, LePageEntry,
};
use linear_executable::w3::W3Archive;
use linear_executable::w4::W4Archive;
use linear_executable::{
    Error, DOS_E_LFANEW_OFFSET, DOS_SIGNATURE, LE_HEADER_SIZE, LE_SIGNATURE, LX_SIGNATURE,
    W3_SIGNATURE, W4_SIGNATURE,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(3);
    }

    // Parse options (order-independent, mirrors ne-inspect).
    let mut file: Option<&str> = None;
    let mut format: Option<&str> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --format requires an argument");
                    std::process::exit(3);
                }
                format = Some(args[i].as_str());
            }
            "--version" | "-V" => {
                println!("le-inspect {VERSION}");
                return;
            }
            "--help" | "-h" => {
                print_usage();
                return;
            }
            other if other.starts_with('-') => {
                eprintln!("error: unknown option {other:?}");
                std::process::exit(3);
            }
            other => {
                if file.is_none() {
                    file = Some(other);
                }
            }
        }
        i += 1;
    }
    let Some(file) = file else {
        eprintln!("error: missing file argument");
        print_usage();
        std::process::exit(3);
    };
    let format = format.unwrap_or("detailed");
    if format != "detailed" {
        eprintln!("error: format {format:?} is not implemented (only \"detailed\")");
        std::process::exit(3);
    }

    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: cannot read {file}: {e}");
            std::process::exit(1);
        }
    };

    match run(&data) {
        Ok(()) => {}
        Err(Error::UnsupportedCodec(codec)) => {
            eprintln!("error: W4 archive uses codec {:?}", codec);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

const USAGE: &str = "\
Usage: le-inspect [OPTIONS] <FILE>

Inspects LE/LX (Linear Executable) files and W3/W4 VxD archives.

Options:
  --format <FORMAT>   Output format (default: detailed)
  --version, -V       Print version
  --help, -h          Print this help

Formats: detailed is the only implemented one; any other value is a usage
error (exit 3).";

fn print_usage() {
    println!("le-inspect {VERSION}\n\n{USAGE}");
}

/// Sniff the file and run the matching report.
fn run(data: &[u8]) -> Result<(), Error> {
    // Archives first: in a `devlib` container `e_lfanew` points at the `W3`
    // or `W4` header, and only there — the members have their own report.
    let candidates: Vec<usize> =
        if data.len() >= 4 && u16::from_le_bytes([data[0], data[1]]) == DOS_SIGNATURE {
            let off = u32::from_le_bytes([
                data[DOS_E_LFANEW_OFFSET],
                data[DOS_E_LFANEW_OFFSET + 1],
                data[DOS_E_LFANEW_OFFSET + 2],
                data[DOS_E_LFANEW_OFFSET + 3],
            ]) as usize;
            if off > 0 && off < data.len() {
                vec![off, 0]
            } else {
                vec![0]
            }
        } else {
            vec![0]
        };

    for off in candidates {
        match sniff_at(data, off) {
            Some(Kind::W3) => return w3_report(data, off),
            Some(Kind::W4) => return w4_report(data, off),
            Some(Kind::Le) | None => {}
        }
    }

    // An LE/LX image, wherever in the file it is: an unbound file, a bound one
    // whose binder rebased the header fields, and a bound one whose binder
    // bundled the application whole all resolve here — see
    // `linear_executable::bound`.
    let location = bound::locate(data)?;
    le_report(data, location)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Le,
    W3,
    W4,
}

fn sniff_at(data: &[u8], off: usize) -> Option<Kind> {
    if data.len() >= off + 2 {
        let sig = u16::from_le_bytes([data[off], data[off + 1]]);
        if sig == LE_SIGNATURE || sig == LX_SIGNATURE {
            return Some(Kind::Le);
        }
        if data[off..off + 2] == *W3_SIGNATURE {
            return Some(Kind::W3);
        }
        if data[off..off + 2] == *W4_SIGNATURE {
            return Some(Kind::W4);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// LE/LX report
// ---------------------------------------------------------------------------

fn le_report(data: &[u8], location: Location) -> Result<(), Error> {
    // Every offset below is a file offset: the view is based at the image's
    // frame, so `frame_at` plus a view-relative offset is the position in the
    // file the user is looking at.
    let frame = location.frame_at;
    let buf = location.view(data);
    let header = buf.get_valid_le_header()?;

    println!("File: {} bytes", data.len());
    println!(
        "Format: {} (header @ 0x{:04X}, {} bytes)",
        header.signature_name(),
        location.header_at,
        LE_HEADER_SIZE
    );
    if location.found_by_scan {
        println!(
            "  bound image: the DOS header's e_lfanew does not lead here; found \
             by an aligned scan"
        );
        println!(
            "  frame      : MZ header @ 0x{frame:04X}, its e_lfanew {:#X} points at \
             the image",
            location.frame_lfanew
        );
    }
    println!(
        "  magic        : {:?} (0x{sig:04X})",
        header.signature_name(),
        sig = header.magic()
    );
    println!(
        "  byte/word order: {}/{} (informational)",
        header.byte_order(),
        header.word_order()
    );
    println!("  level        : {}", header.format_level());
    println!("  cpu          : {} (2 = i86)", header.cpu());
    println!("  os           : {} (1 = OS/2)", header.os());
    println!("  mflags       : {:#06X}", header.module_flags());
    println!("  pages        : {}", header.module_pages());
    println!("  page size    : {}", header.page_size());
    if header.is_lx() {
        println!("  page shift   : {}", header.page_offset_shift());
    } else {
        println!("  last page    : {} bytes", header.last_page_bytes());
    }
    println!("  start object : {}", header.start_object());
    println!("  EIP          : {:#X}", header.eip());
    println!("  stack object : {}", header.stack_object());
    println!("  ESP          : {:#X}", header.esp());
    println!(
        "  fixup section: {:#X} bytes @ frectab {:#X}",
        header.fixup_size(),
        header.fixup_record_table()
    );
    println!(
        "  data pages   : {:#X} (file-absolute{})",
        header.data_pages_offset(),
        if frame == 0 {
            String::new()
        } else {
            format!(
                ", = 0x{:X} in this file",
                frame + header.data_pages_offset()
            )
        }
    );
    println!("  preload pages: {}", header.preload_pages());
    println!(
        "  heap/stack   : {:#X} / {:#X}",
        header.heap_size(),
        header.stack_size()
    );

    // Entry (export) table: the 1-byte `00` form means no exports.
    let ent = location.header_at + header.entry_table_offset();
    if header.entry_table_offset() != 0 && ent < data.len() {
        println!(
            "  entry table  : {:#X} @ 0x{:04X} {}",
            header.entry_table_offset(),
            ent,
            if data[ent] == 0 { "(no exports)" } else { "" }
        );
    }

    // Objects
    println!("\nObjects:");
    let objects = buf.get_object_table()?;
    for (i, o) in objects.iter().enumerate() {
        print!(
            "  [{}] vsize={:#X}  rbase={:#X}  flags={:#06X}  pages={}..{}",
            i + 1,
            o.virtual_size,
            o.relocation_base,
            o.flags.bits(),
            o.first_page,
            o.first_page + o.page_count - 1
        );
        if let Some(name) = o.name() {
            print!("  name={name}");
        }
        println!("  type={:?}", o.object_type());
    }

    // Pages
    println!("\nPages:");
    let pages = buf.get_page_table()?;
    for (i, p) in pages.iter().enumerate() {
        match p {
            LePageEntry::Le { file_page, .. } => {
                let off = frame
                    + header.data_pages_offset()
                    + (*file_page as usize).saturating_sub(1) * header.page_size() as usize;
                let is_last = *file_page as usize == header.module_pages() as usize;
                let size = if is_last {
                    header.last_page_bytes() as usize
                } else {
                    header.page_size() as usize
                };
                println!(
                    "  [{}] file page {file_page}  type={}  @ 0x{off:04X}  {size} bytes",
                    i + 1,
                    p.page_type().num()
                );
            }
            LePageEntry::Lx {
                data_offset,
                data_size,
                ..
            } => {
                println!(
                    "  [{}] data_off={data_offset:#X}  size={data_size:#X}  type={}",
                    i + 1,
                    p.page_type().num()
                );
            }
            // LePageEntry is #[non_exhaustive].
            other => {
                println!(
                    "  [{}] type={} (no details)",
                    i + 1,
                    other.page_type().num()
                );
            }
        }
    }

    // Resident names
    println!("\nResident names:");
    for (i, entry) in buf.get_resident_names()?.iter().enumerate() {
        println!("  [{}] {} (ordinal {:#06X})", i, entry.name, entry.ordinal);
    }

    loader_tables(&buf);

    // Object images (first 16 bytes of each)
    println!("\nObject images:");
    for (i, _o) in objects.iter().enumerate() {
        let image = buf.object_image(i as u32 + 1)?;
        let preview: Vec<String> = image.iter().take(16).map(|b| format!("{b:02X}")).collect();
        let ascii: String = image
            .iter()
            .take(16)
            .map(|&b| {
                if (0x20..0x7F).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!(
            "  [{}] {} bytes  {:<32}  {ascii}",
            i + 1,
            image.len(),
            preview.join(" ")
        );
    }
    Ok(())
}

/// The loader tables: non-resident names, exports, imports, fixup page
/// table, header tail.
///
/// Every one of them is optional, and real files carry pointers that are
/// only valid somewhere else — a member extracted from a W3/W4 archive keeps
/// its file-absolute table offsets, which land outside the extracted file.
/// Such a table is reported where it would appear and does not abort the
/// report: `le-inspect` exits 1 only for an image whose core structures
/// (header, objects, pages, resident names, object images) do not parse.
fn loader_tables(buf: &impl linear_executable::le::LE) {
    match buf.get_non_resident_names() {
        Ok(list) => {
            if !list.is_empty() {
                println!("\nNon-resident names:");
                for entry in &list {
                    println!("  {} (ordinal {:#06X})", entry.name, entry.ordinal);
                }
            }
        }
        Err(e) => println!("\nNon-resident names: not readable ({e})"),
    }

    match buf.get_entry_table() {
        Ok(bundles) => {
            if bundles.is_empty() {
                println!("\nEntry table: no exported entry points");
            } else {
                println!("\nEntry table:");
                for (i, b) in bundles.iter().enumerate() {
                    // An unused bundle declares ordinals but carries no entry
                    // data, so its CNT byte is the whole payload.
                    let payload = if b.entries.is_empty() {
                        format!("{} ordinal{}", b.count, if b.count == 1 { "" } else { "s" })
                    } else {
                        format!(
                            "{} entr{}",
                            b.entries.len(),
                            if b.entries.len() == 1 { "y" } else { "ies" }
                        )
                    };
                    println!(
                        "  [{}] {:?} bundle, object {}, first ordinal {}, {}",
                        i + 1,
                        b.kind,
                        b.object,
                        b.first_ordinal,
                        payload
                    );
                    for (j, entry) in b.entries.iter().enumerate() {
                        print_entry(b.first_ordinal + j as u32, entry);
                    }
                }
            }
        }
        Err(e) => println!("\nEntry table: not readable ({e})"),
    }

    match buf.get_import_modules() {
        Ok(list) => {
            if !list.is_empty() {
                println!("\nImport modules:");
                for (i, name) in list.iter().enumerate() {
                    println!("  [{}] {name}", i + 1);
                }
            }
        }
        Err(e) => println!("\nImport modules: not readable ({e})"),
    }
    match buf.get_import_procedures() {
        Ok(list) => {
            if !list.is_empty() {
                println!("\nImport procedures:");
                for (i, name) in list.iter().enumerate() {
                    println!("  [{}] {name}", i + 1);
                }
            }
        }
        Err(e) => println!("\nImport procedures: not readable ({e})"),
    }

    // `module_pages + 1` entries; the last is the record-table size, not a
    // page offset.
    match buf.get_fixup_page_table() {
        Ok(table) => {
            if !table.is_empty() {
                print!("\nFixup page table ({} entries):", table.len());
                for value in &table {
                    print!(" {value:#X}");
                }
                println!("  (last entry = fixup record table size)");
            }
        }
        Err(e) => println!("\nFixup page table: not readable ({e})"),
    }

    // Records are walked, never counted by dividing the table by a record
    // width — the widths vary inside one table (§9.4).
    match buf.get_fixup_records() {
        Ok(records) => {
            if !records.is_empty() {
                println!(
                    "\nFixup record table ({} record{}):",
                    records.len(),
                    if records.len() == 1 { "" } else { "s" }
                );
                for record in &records {
                    print_fixup_record(record);
                }
            }
        }
        Err(e) => println!("\nFixup records: not decodable ({e})"),
    }

    match buf.get_header_tail() {
        Ok(Some(tail)) => println!(
            "\nHeader tail: winres {:#X}+{:#X}  devid {:#06X}  ddkver {:#06X}",
            tail.winres_offset, tail.winres_length, tail.device_id, tail.ddk_version
        ),
        Ok(None) => {}
        Err(e) => println!("\nHeader tail: not readable ({e})"),
    }
}

fn print_entry(ordinal: u32, entry: &EntryPoint) {
    let flags = entry.flags();
    print!(
        "      ordinal {ordinal}: {}{}",
        if flags.contains(EntryFlags::EXPORT) {
            "exported"
        } else {
            "internal"
        },
        if flags.contains(EntryFlags::SHARED) {
            " shared"
        } else {
            ""
        }
    );
    match entry {
        EntryPoint::Offset16 { offset, .. } => println!(" offset {offset:#X} (16-bit)"),
        EntryPoint::Offset32 { offset, .. } => println!(" offset {offset:#X}"),
        EntryPoint::CallGate {
            offset, callgate, ..
        } => println!(" offset {offset:#X}, callgate {callgate:#X}"),
        EntryPoint::Forwarder {
            module_ordinal,
            value,
            ..
        } => println!(" forwards to import module {module_ordinal}, value {value:#X}"),
        // EntryPoint is #[non_exhaustive].
        other => println!(" {other:?}"),
    }
}

/// One fixup record per line. A source list longer than [`MAX_PRINTED_SOURCES`]
/// is elided with its remainder counted, so a 255-offset record stays readable.
fn print_fixup_record(record: &FixupRecord) {
    print!(
        "  @0x{offset:04X} {src_byte:02X}/{tgt_flags:02X} page {} {source_type:?}{}{}{} ->",
        record.page,
        if record.alias() { " alias" } else { "" },
        if record.chained() { " chained" } else { "" },
        // A one-entry source list and a single source offset decode to the
        // same shape, so the flag is printed rather than inferred.
        if record.source_flags.contains(FixupSourceFlags::SOURCE_LIST) {
            " list"
        } else {
            ""
        },
        offset = record.offset,
        // The two bytes as stored, so a reader can compare one line against
        // one `wdump -f` row without re-deriving either.
        src_byte = record.source_type.num() | record.source_flags.bits(),
        tgt_flags = record.target_flags.bits(),
        source_type = record.source_type,
    );
    match record.target {
        FixupTarget::Internal { object, offset } => {
            print!(" internal object {object}");
            match offset {
                Some(value) => print!(" offset {value:#X}"),
                // A selector source has no target-offset field to print.
                None => print!(" (selector source: no offset field)"),
            }
        }
        FixupTarget::ImportByOrdinal {
            module_ordinal,
            ordinal,
        } => print!(" import module {module_ordinal} ordinal {ordinal}"),
        FixupTarget::ImportByName {
            module_ordinal,
            name_offset,
        } => print!(" import module {module_ordinal} name offset {name_offset:#X}"),
        FixupTarget::EntryTable { ordinal } => print!(" entry-table ordinal {ordinal}"),
        // FixupTarget is #[non_exhaustive].
        other => print!(" {other:?}"),
    }
    if let Some(additive) = record.additive {
        print!(" + {additive:#X}");
    }
    print!("  src");
    for source in record.source_offsets.iter().take(MAX_PRINTED_SOURCES) {
        print!(" {source:#04X}");
    }
    if let Some(more) = record.source_offsets.len().checked_sub(MAX_PRINTED_SOURCES) {
        if more > 0 {
            print!(" (+{more})");
        }
    }
    println!("  ({} B)", record.size);
}

/// How many source offsets one printed record shows before eliding the rest.
const MAX_PRINTED_SOURCES: usize = 8;

// ---------------------------------------------------------------------------
// W3 / W4 reports
// ---------------------------------------------------------------------------

fn w3_report(data: &[u8], off: usize) -> Result<(), Error> {
    let buf = linear_executable::VecLE::from_slice(data);
    let archive = W3Archive::parse(&buf, off)?;
    println!("Format: W3 (uncompressed VxD archive, header @ 0x{off:04X})");
    println!(
        "  OS: {:#06X}  members: {}",
        archive.header.os, archive.header.member_count
    );
    print_member_table(&archive);
    Ok(())
}

/// The member table of a parsed `W3` archive. `declared` is the member's own
/// `size` field (header plus loader tables); `span` runs to the next member
/// and is what holds the pages too.
fn print_member_table(archive: &W3Archive<'_>) {
    for (i, m) in archive.members.iter().enumerate() {
        let span = archive
            .member_span(i)
            .map_or_else(|_| String::new(), |s| format!("span {}", s.len()));
        println!(
            "  [{}] {:<8} @ 0x{:04X}  {} bytes declared, {}",
            i + 1,
            m.name_trimmed(),
            m.file_offset,
            m.size,
            span
        );
    }
}

fn w4_report(data: &[u8], off: usize) -> Result<(), Error> {
    let buf = linear_executable::VecLE::from_slice(data);
    let archive = W4Archive::parse(&buf, off)?;
    println!("Format: W4 (compressed VxD archive, header @ 0x{off:04X})");
    println!(
        "  OS: {:#06X}  chunk size (decompressed): {}  chunks: {}  codec: {:?}",
        archive.header.os,
        archive.header.chunk_size,
        archive.header.chunk_count,
        core::str::from_utf8(&archive.header.codec).unwrap_or("?")
    );
    let mut stored = 0usize;
    for index in 0..archive.chunk_offsets.len() {
        stored += archive.stored_chunk_size(index)?;
    }
    println!(
        "  chunks: {} stored bytes ({} on disk, last chunk ends at EOF)",
        stored,
        data.len()
    );
    // A 270-chunk archive is a table nobody reads on a terminal, so its rows
    // are listed only while it is short enough to scan.
    if archive.chunk_offsets.len() <= 16 {
        for index in 0..archive.chunk_offsets.len() {
            println!(
                "  [{}] @ 0x{:04X}  {} bytes",
                index + 1,
                archive.chunk_offsets[index],
                archive.stored_chunk_size(index)?
            );
        }
    }
    match archive.decompress() {
        Ok(body) => {
            println!("\nArchive body: {} bytes decompressed", body.len());
            let inner = linear_executable::VecLE::from_memory(body);
            // The body's member offsets still count from the archive header,
            // which is what `off` is.
            match W3Archive::parse_with_base(&inner, 0, off as u32) {
                Ok(archive) => {
                    println!("Inner archive: W3 (header @ 0x0000, member base {off:#06X})");
                    println!(
                        "  OS: {:#06X}  members: {}",
                        archive.header.os, archive.header.member_count
                    );
                    print_member_table(&archive);
                }
                Err(e) => println!("Inner archive: not a readable W3 ({e})"),
            }
        }
        Err(e) => println!("\nArchive body: not decodable ({e})"),
    }
    Ok(())
}
