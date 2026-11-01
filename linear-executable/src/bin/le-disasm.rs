// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! `le-disasm` — linear disassembly of an LE/LX module's code (feature `disasm`).
//!
//! Usage:
//! ```text
//! le-disasm [OPTIONS] <FILE>
//! ```
//!
//! Presentation only: every format fact it prints comes from
//! `linear_executable::disasm` or the parser's own tables. Exit codes:
//! 0 = ok, 1 = parse error, 3 = usage error (same contract as `le-inspect`).

use core::fmt;

use linear_executable::bound;
use linear_executable::disasm::{self, Bitness, EntryOrigin, ListedLine, Syntax};
use linear_executable::le::LE;
use linear_executable::types::ObjectRecord;
use linear_executable::{Error, DOS_E_LFANEW_OFFSET, LE_HEADER_SIZE, W3_SIGNATURE, W4_SIGNATURE};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
Usage: le-disasm [OPTIONS] <FILE>

Linearly disassembles code of an LE/LX (Linear Executable) image.

Options:
  --object <N>    1-based object number to disassemble (default: the object the
                  module's entry point is in)
  --offset <0xN>  Start at this offset inside the object (hex; default: the
                  entry point's offset, or 0 with --object)
  --count <N>     Number of bytes to decode (decimal; default: to the end of
                  the object)
  --all           One listing per object, instead of the entry point's
  --syntax <S>    intel | gas (default: intel)
  --fixups        Annotate each line with the fixups that patch its bytes
  --width <N>     Hex bytes per line, decimal (default 8; 0 hides the column)
  --version, -V   Print version
  --help, -h      Print this help

Without --object the listing starts at the module entry point: the header's
start object and eip when they name one, else the lowest exported entry-table
entry. Operand size is per object: an object without flag 0x2000 (BIG_DEFAULT)
is listed as 16-bit code. A W3/W4 archive is refused (exit 1) — use le-inspect
for containers; the devlib archives start with an MZ stub and carry their W3/W4
signature at e_lfanew, which is where this sniff looks as well.";

struct Options {
    file: String,
    object: Option<u32>,
    offset: Option<u32>,
    count: Option<usize>,
    all: bool,
    fixups: bool,
    syntax: Syntax,
    width: usize,
}

/// A failure with the exit code it maps to: a library parse error is 1, a
/// mistake in the command line (or a module that needs one more option to say
/// what to list) is 3.
struct Failure {
    message: String,
    code: i32,
}

impl Failure {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 3,
        }
    }
}

impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        Self {
            message: e.to_string(),
            code: 1,
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(3);
    }

    // Options are order-independent, mirroring le-inspect.
    let mut file: Option<String> = None;
    let mut object: Option<u32> = None;
    let mut offset: Option<u32> = None;
    let mut count: Option<usize> = None;
    let mut all = false;
    let mut fixups = false;
    let mut syntax = Syntax::Intel;
    let mut width = 8usize;
    let mut i = 1;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--object" => object = Some(parse_number(arg, &args, &mut i, 16)),
            "--offset" => offset = Some(parse_number(arg, &args, &mut i, 16)),
            "--count" => count = Some(parse_number(arg, &args, &mut i, 10) as usize),
            "--width" => width = parse_number(arg, &args, &mut i, 10) as usize,
            "--all" => all = true,
            "--fixups" => fixups = true,
            "--syntax" => {
                i += 1;
                if i >= args.len() {
                    usage_err(&format!("{arg} requires an argument"));
                }
                syntax = match args[i].to_ascii_lowercase().as_str() {
                    "intel" => Syntax::Intel,
                    "gas" => Syntax::Gas,
                    other => usage_err(&format!("unknown syntax {other:?} (intel or gas)")),
                };
            }
            "--version" | "-V" => {
                println!("le-disasm {VERSION}");
                return;
            }
            "--help" | "-h" => {
                print_usage();
                return;
            }
            other if other.starts_with('-') => usage_err(&format!("unknown option {other:?}")),
            other => {
                if file.is_none() {
                    file = Some(other.to_owned());
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
    if count == Some(0) {
        usage_err("--count must be at least 1");
    }
    if width > 32 {
        usage_err("--width must be 32 or less");
    }
    let options = Options {
        file,
        object,
        offset,
        count,
        all,
        fixups,
        syntax,
        width,
    };

    let data = match std::fs::read(&options.file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", options.file);
            std::process::exit(1);
        }
    };

    if let Err(e) = run(&data, &options) {
        eprintln!("error: {e}");
        std::process::exit(e.code);
    }
}

fn print_usage() {
    println!("le-disasm {VERSION}\n\n{USAGE}");
}

fn usage_err(message: &str) -> ! {
    eprintln!("error: {message}");
    std::process::exit(3);
}

/// One numeric option value in `radix`; absent or unparseable is a usage error.
fn parse_number(name: &str, args: &[String], i: &mut usize, radix: u32) -> u32 {
    *i += 1;
    if *i >= args.len() {
        usage_err(&format!("{name} requires an argument"));
    }
    let given = args[*i].as_str();
    let text = given.trim_start_matches("0x").trim_start_matches("0X");
    match u32::from_str_radix(text, radix) {
        Ok(value) => value,
        Err(_) => usage_err(&format!(
            "{name} needs a base-{radix} number, got {given:?}"
        )),
    }
}

/// One listing target: an object plus the offset inside it to start at.
struct Target {
    number: u32,
    start: u32,
}

fn run(data: &[u8], options: &Options) -> Result<(), Failure> {
    if is_archive(data) {
        return Err(Failure {
            message: format!(
                "{} is a W3/W4 archive: le-disasm lists the code of one LE/LX image, \
                 use le-inspect to report a container",
                options.file
            ),
            code: 1,
        });
    }

    // An LE/LX image anywhere in the file — unbound, bound by a rebinding
    // binder, or bound with the application bundled whole — resolves through
    // `linear_executable::bound`, exactly as in le-inspect.
    let location = bound::locate(data)?;
    let buf = location.view(data);
    let header = buf.get_valid_le_header()?;
    let objects = buf.get_object_table()?;
    let entry = disasm::entry_point(&buf)?;

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
    }
    match entry {
        Some(e) => {
            // EntryOrigin is #[non_exhaustive] as seen from this bin's crate,
            // so the arms below cannot be the whole story.
            let (origin, ordinal) = match e.origin {
                EntryOrigin::Header => ("header start object/eip", String::new()),
                EntryOrigin::EntryTable { ordinal } => {
                    ("entry table", format!(", ordinal {ordinal}"))
                }
                _ => ("an unknown source", String::new()),
            };
            println!(
                "Entry: object {} offset 0x{:X} (linear 0x{:X}, from {origin}{ordinal})",
                e.object, e.offset, e.linear
            );
        }
        None => println!(
            "Entry: none — the header's start object names no object and the entry \
             table has no exported entry"
        ),
    }

    let maps = if options.fixups {
        let maps = disasm::build_fixup_maps(&buf)?;
        println!(
            "Fixups: {} patch slot(s) inside object images, {} outside them",
            maps.placed_slots(),
            maps.unmapped_slots
        );
        Some(maps)
    } else {
        None
    };

    let targets = if options.all {
        (1..=objects.len() as u32)
            .map(|number| Target {
                number,
                start: match entry {
                    Some(e) if u32::from(e.object) == number => e.offset,
                    _ => 0,
                },
            })
            .collect()
    } else if let Some(number) = options.object {
        let Some(object) = objects.get(number as usize - 1) else {
            return Err(Failure::usage(format!(
                "object {number} does not exist: the object table has {} record(s)",
                objects.len()
            )));
        };
        let start = match options.offset {
            Some(offset) if (offset as usize) < object.virtual_size as usize => offset,
            Some(offset) => {
                return Err(past_end(number, offset, object.virtual_size));
            }
            None => match entry {
                Some(e) if u32::from(e.object) == number => e.offset,
                _ => 0,
            },
        };
        vec![Target { number, start }]
    } else {
        match entry {
            Some(e) => {
                if let Some(offset) = options.offset {
                    let object = &objects[e.object as usize - 1];
                    if (offset as usize) >= object.virtual_size as usize {
                        return Err(past_end(e.object as u32, offset, object.virtual_size));
                    }
                }
                vec![Target {
                    number: u32::from(e.object),
                    start: options.offset.unwrap_or(e.offset),
                }]
            }
            None => {
                return Err(Failure::usage(
                    "the module names no entry point: say what to list with \
                     --object <N> [--offset 0x<N>]",
                ))
            }
        }
    };

    for target in targets {
        let object = &objects[target.number as usize - 1];
        let image = buf.object_image(target.number)?;
        let start = (target.start as usize).min(image.len());
        let end = match options.count {
            Some(count) => start.saturating_add(count).min(image.len()),
            None => image.len(),
        };
        let bitness = Bitness::of_object(object);
        let fixups = maps.as_ref().and_then(|m| m.map_of(target.number as u16));

        println!();
        println!(
            "Object {}: vsize 0x{:X}, relocation base 0x{:X}, page rows {}..{}, {bitness}{}{}",
            target.number,
            object.virtual_size,
            object.relocation_base,
            object.first_page,
            object.first_page + object.page_count - 1,
            big_default_note(object),
            match object.name() {
                Some(name) => format!(", name {name}"),
                None => String::new(),
            }
        );
        let listing = disasm::list_code(
            &image[start..end],
            target.start,
            object.relocation_base,
            bitness,
            options.syntax,
            fixups,
        );
        for line in &listing.lines {
            print_line(line, options, &buf, entry, target.number);
        }
        println!(
            "  -- {} line(s): {} instruction(s), {} undecodable byte(s), {} byte(s) listed",
            listing.lines.len(),
            listing.instructions,
            listing.data_bytes,
            listing.covered_bytes()
        );
    }

    Ok(())
}

/// A W3/W4 container signature at either place a reader looks: offset 0, or
/// the position the DOS header's `e_lfanew` gives.
///
/// Both matter because `devlib` writes the archives with a 4096-byte MZ stub:
/// `singlew3.BIN` opens with `MZ` and carries `W3` at `e_lfanew` 0x1000, so a
/// sniff at offset 0 alone never sees a container.
fn is_archive(data: &[u8]) -> bool {
    let marks_container = |off: usize| {
        data.len() >= off + 2
            && (data[off..off + 2] == *W3_SIGNATURE || data[off..off + 2] == *W4_SIGNATURE)
    };
    if marks_container(0) {
        return true;
    }
    if data.len() < DOS_E_LFANEW_OFFSET + 4 || data[..2] != *b"MZ" {
        return false;
    }
    let lfanew = u32::from_le_bytes([
        data[DOS_E_LFANEW_OFFSET],
        data[DOS_E_LFANEW_OFFSET + 1],
        data[DOS_E_LFANEW_OFFSET + 2],
        data[DOS_E_LFANEW_OFFSET + 3],
    ]);
    marks_container(lfanew as usize)
}

/// An offset that is past the end of the object it was given with.
fn past_end(number: u32, offset: u32, virtual_size: u32) -> Failure {
    Failure::usage(format!(
        "--offset 0x{offset:X} is past the end of object {number} (vsize 0x{virtual_size:X})"
    ))
}

fn big_default_note(object: &ObjectRecord) -> String {
    if Bitness::of_object(object) == Bitness::Bit16 {
        return " (object flag 0x2000 BIG_DEFAULT clear)".to_owned();
    }
    String::new()
}

/// One line of output: offset, hex bytes, text, then the entry marker and the
/// fixups that patch this line's bytes.
fn print_line(
    line: &ListedLine<'_>,
    options: &Options,
    buf: &impl LE,
    entry: Option<disasm::ModuleEntry>,
    object_number: u32,
) {
    let hex = if options.width == 0 {
        String::new()
    } else {
        let shown = line
            .bytes
            .iter()
            .take(options.width)
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<String>>()
            .join(" ");
        format!("{shown:<width$}", width = options.width * 3 - 1)
    };
    let text = if line.is_data {
        format!("db 0x{:02X}", line.bytes[0])
    } else {
        line.text.clone()
    };

    let mut annotations: Vec<String> = Vec::new();
    if let Some(entry) = entry {
        if u32::from(entry.object) == object_number && entry.offset == line.offset {
            annotations.push("entry".to_owned());
        }
    }
    for note in &line.notes {
        // The target as names where the module has names for it, else as the
        // table coordinates the record stores. The arrow says which way the
        // value flows: this byte range receives that value.
        let rendered = match disasm::import_reference(buf, &note.target) {
            Ok(Some(import)) => format!("{} [{}]", import.display(), note.source_type.num()),
            _ => note.to_string(),
        };
        annotations.push(format!("fixup here -> {rendered}"));
    }
    let annotation = if annotations.is_empty() {
        String::new()
    } else {
        format!("  ; {}", annotations.join("; "))
    };
    println!(
        "  {offset:08X}  {hex}  {text}{annotation}",
        offset = line.offset
    );
}
