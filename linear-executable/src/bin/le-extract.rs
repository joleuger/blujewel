// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! `le-extract` — writes the members of a `W3`/`W4` container as standalone
//! `LE`/`LX` files that `le-inspect` and `le-disasm` can read.
//!
//! Usage:
//! ```text
//! le-extract [OPTIONS] <FILE>
//! ```
//!
//! Presentation plus one convention, nothing else: the container walk, the
//! span that may be copied, and the rebase of the two file-absolute header
//! fields all come from `linear_executable::w3`. What belongs to this bin is
//! the **prefix** in front of a member — a `W3` member has no MZ stub of its
//! own and the format does not say what a standalone one carries, so this tool
//! chooses one and says so (see `USAGE.md`).
//!
//! Exit codes: 0 = ok, 1 = parse error or an unwritable output, 3 = usage
//! error (the same contract as `le-inspect` and `le-disasm`).

use std::collections::BTreeSet;
use std::path::PathBuf;

use linear_executable::le::VecLE;
use linear_executable::w3::{self, W3Archive, W3Member};
use linear_executable::w4::W4Archive;
use linear_executable::{Error, Vec, DOS_E_LFANEW_OFFSET, W3_SIGNATURE, W4_SIGNATURE};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The stub length used unless the caller says otherwise.
const DEFAULT_STUB_LEN: usize = 0x80;

const USAGE: &str = "\
Usage: le-extract [OPTIONS] <FILE>

Writes each member of a W3 (uncompressed) or W4 (MRCI-compressed) container as
its own file, named <MEMBER>.VXD in the member table's spelling.

Options:
  --out <DIR>     Directory to write into (created if missing; default: .)
  --raw           Write the member's span verbatim: no prefix, no rebase. A
                  debugging view: such a file keeps its container-absolute page
                  area, so le-inspect either refuses it or reads zero-filled
                  pages, depending on how long the span is
  --no-stub       A bare image: no prefix, both file-absolute header fields
                  shifted by the whole member offset
  --stub <FILE>   Use this MZ stub in front of the image instead of the default
                  one (at least 0x40 bytes). Only its e_lfanew is rewritten, to
                  the length of the stub, because that is the one field that has
                  to describe the file being written
  --member <N>    Extract only this 1-based member of the table (repeatable)
  --version, -V   Print version
  --help, -h      Print this help

Default: a rebased standalone image -- the default 0x80-byte stub plus the
member's span, with data_pages (header 0x80) and non_resident_names (0x88)
rewritten to count from the start of the new file. Everything else is verbatim.
A stub shorter than 0x40 bytes is refused: it cannot carry e_lfanew, and a file
whose image no header points at is not readable by anyone.";

/// What goes in front of the span, and whether the fields get rebased at all.
enum Mode {
    Raw,
    Rebased(Vec<u8>),
}

struct Options {
    file: String,
    out: PathBuf,
    mode: Mode,
    /// 0-based member indices; empty means every member of the table.
    members: Vec<usize>,
}

/// A failure with the exit code it maps to: a library parse error is 1, a
/// mistake in the command line is 3, and a container that cannot name its
/// members without collision is 1 as well.
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

impl From<std::io::Error> for Failure {
    fn from(e: std::io::Error) -> Self {
        Self {
            message: e.to_string(),
            code: 1,
        }
    }
}

impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(3);
    }

    // Options are order-independent, mirroring the other two bins.
    let mut file: Option<String> = None;
    let mut out = PathBuf::from(".");
    let mut raw = false;
    let mut no_stub = false;
    let mut stub_file: Option<String> = None;
    let mut members: Vec<usize> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--out" => {
                i += 1;
                if i >= args.len() {
                    usage_err("--out requires an argument");
                }
                out = PathBuf::from(&args[i]);
            }
            "--stub" => {
                i += 1;
                if i >= args.len() {
                    usage_err("--stub requires a file argument");
                }
                stub_file = Some(args[i].clone());
            }
            "--member" => {
                let one_based = parse_number(arg, &args, &mut i);
                if one_based == 0 {
                    usage_err("--member is 1-based, so 0 names no member");
                }
                members.push(usize::try_from(one_based - 1).unwrap_or(usize::MAX));
            }
            "--raw" => raw = true,
            "--no-stub" => no_stub = true,
            "--version" | "-V" => {
                println!("le-extract {VERSION}");
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
    if raw && no_stub {
        usage_err("--raw writes the span verbatim, so --no-stub has nothing to say");
    }
    if raw && stub_file.is_some() {
        usage_err("--raw writes the span verbatim, so --stub has nothing to prepend");
    }
    let mode = if raw {
        Mode::Raw
    } else if no_stub {
        Mode::Rebased(Vec::new())
    } else if let Some(path) = stub_file {
        Mode::Rebased(match read_stub(&path) {
            Ok(stub) => stub,
            Err(e) => usage_err(&e),
        })
    } else {
        Mode::Rebased(w3::standalone_stub(DEFAULT_STUB_LEN))
    };

    let options = Options {
        file,
        out,
        mode,
        members,
    };
    let data = match std::fs::read(&options.file) {
        Ok(data) => data,
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
    println!("le-extract {VERSION}\n\n{USAGE}");
}

fn usage_err(message: &str) -> ! {
    eprintln!("error: {message}");
    std::process::exit(3);
}

/// One numeric option value, decimal; absent or unparseable is a usage error.
fn parse_number(name: &str, args: &[String], i: &mut usize) -> u32 {
    *i += 1;
    if *i >= args.len() {
        usage_err(&format!("{name} requires an argument"));
    }
    let given = args[*i].as_str();
    match given.parse::<u32>() {
        Ok(value) => value,
        Err(_) => usage_err(&format!("{name} needs a decimal number, got {given:?}")),
    }
}

/// A caller-supplied stub: at least a DOS header long, starting with `MZ`,
/// with `e_lfanew` rewritten to its own length.
fn read_stub(path: &str) -> Result<Vec<u8>, String> {
    let data = std::fs::read(path).map_err(|e| format!("cannot read stub {path}: {e}"))?;
    if data.len() < 0x40 {
        return Err(format!(
            "stub {path} is {} bytes, too short to carry e_lfanew at 0x3C",
            data.len()
        ));
    }
    if data[..2] != *b"MZ" {
        return Err(format!("stub {path} does not start with MZ"));
    }
    let mut stub = data;
    let len = u32::try_from(stub.len()).map_err(|_| "stub is longer than 4 GiB".to_owned())?;
    stub[DOS_E_LFANEW_OFFSET..DOS_E_LFANEW_OFFSET + 4].copy_from_slice(&len.to_le_bytes());
    Ok(stub)
}

/// Where the container's own signature sits, and which kind it is. Like
/// `le-disasm`'s refusal, this looks at offset 0 **and** `e_lfanew`, because a
/// `devlib` archive hides its signature behind a 4096-byte MZ stub.
fn container_at(data: &[u8]) -> Option<(usize, bool)> {
    let at = |off: usize| -> Option<bool> {
        if data.get(off..off + 2) == Some(W3_SIGNATURE) {
            Some(false)
        } else if data.get(off..off + 2) == Some(W4_SIGNATURE) {
            Some(true)
        } else {
            None
        }
    };
    if let Some(w4) = at(0) {
        return Some((0, w4));
    }
    if data.len() >= DOS_E_LFANEW_OFFSET + 4 && data[..2] == *b"MZ" {
        let lfanew = u32::from_le_bytes([
            data[DOS_E_LFANEW_OFFSET],
            data[DOS_E_LFANEW_OFFSET + 1],
            data[DOS_E_LFANEW_OFFSET + 2],
            data[DOS_E_LFANEW_OFFSET + 3],
        ]);
        if let Some(w4) = at(usize::try_from(lfanew).unwrap_or(usize::MAX)) {
            return Some((usize::try_from(lfanew).unwrap_or(0), w4));
        }
    }
    None
}

fn run(data: &[u8], options: &Options) -> Result<(), Failure> {
    let Some((at, w4)) = container_at(data) else {
        return Err(Failure {
            message: format!(
                "{} is not a W3/W4 container: no \"W3\"/\"W4\" signature at 0 or at \
                 e_lfanew (le-inspect reports a plain LE/LX image)",
                options.file
            ),
            code: 1,
        });
    };

    // A W4 body is itself a W3 archive, and its member offsets still count from
    // where the container header sat, so the base is explicit (see
    // `W3Archive::parse_with_base`).
    let buf = VecLE::from_memory(data.to_vec());
    if w4 {
        let packed = W4Archive::parse(&buf, at)?;
        println!(
            "{}: W4 container, codec {:?}, {} chunk(s)",
            options.file,
            String::from_utf8_lossy(&packed.header.codec),
            packed.header.chunk_count
        );
        let body = packed.decompress()?;
        let body = VecLE::from_memory(body);
        let archive = W3Archive::parse_with_base(&body, 0, u32::try_from(at).unwrap_or(u32::MAX))?;
        write_members(&archive, options)
    } else {
        let archive = W3Archive::parse(&buf, at)?;
        println!(
            "{}: W3 container, {} member(s)",
            options.file,
            archive.members.len()
        );
        write_members(&archive, options)
    }
}

fn write_members(archive: &W3Archive<'_>, options: &Options) -> Result<(), Failure> {
    let selected: Vec<usize> = if options.members.is_empty() {
        (0..archive.members.len()).collect()
    } else {
        for &index in &options.members {
            if index >= archive.members.len() {
                return Err(Failure::usage(format!(
                    "--member {} is past the table of {} member(s)",
                    index + 1,
                    archive.members.len()
                )));
            }
        }
        options.members.clone()
    };

    // The member table is untrusted input, and `--out` is a directory the user
    // chose: names are kept inside it, and two members may not be made to
    // overwrite each other.
    let names: Vec<String> = selected
        .iter()
        .map(|&index| file_name(&archive.members[index], index))
        .collect();
    let mut seen = BTreeSet::new();
    for name in &names {
        if !seen.insert(name.clone()) {
            return Err(Failure {
                message: format!(
                    "two members would both be written as {name}; use --member to take one at a time"
                ),
                code: 1,
            });
        }
    }

    std::fs::create_dir_all(&options.out)?;
    for (&index, name) in selected.iter().zip(&names) {
        let path = options.out.join(name);
        match &options.mode {
            Mode::Raw => {
                let span = archive.member_span(index)?;
                std::fs::write(&path, span)?;
                println!(
                    "  {name}: {} bytes, span verbatim (no prefix, no rebase)",
                    span.len()
                );
            }
            Mode::Rebased(prefix) => {
                let span = archive.member_span(index)?;
                let before = fields_of(span);
                let out = archive.member_standalone(index, prefix)?;
                std::fs::write(&path, &out)?;
                let after = fields_of(&out[prefix.len()..]);
                println!(
                    "  {name}: {} bytes = {} prefix + {} span, data_pages {:#06x} -> \
                     {:#06x}, non_resident_names {:#010x} -> {:#010x}",
                    out.len(),
                    prefix.len(),
                    span.len(),
                    before.0,
                    after.0,
                    before.1,
                    after.1
                );
            }
        }
    }
    Ok(())
}

/// `data_pages` and `non_resident_names` of an image, for the report line.
fn fields_of(image: &[u8]) -> (u32, u32) {
    let at = |off: usize| {
        u32::from_le_bytes([image[off], image[off + 1], image[off + 2], image[off + 3]])
    };
    (at(0x80), at(0x88))
}

/// A file name for one member slot: the table's 8 characters, with anything
/// that is not a plain file-name character turned into `_`, and the index
/// keeping a name that would otherwise name nothing.
fn file_name(member: &W3Member, index: usize) -> String {
    let cleaned: String = member
        .name_trimmed()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let stem = if cleaned.is_empty() || cleaned.chars().all(|c| c == '.') {
        format!("MEMBER{}", index + 1)
    } else {
        cleaned
    };
    format!("{stem}.VXD")
}
