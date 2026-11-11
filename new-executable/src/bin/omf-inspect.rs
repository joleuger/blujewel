// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! omf-inspect — read 16-bit OMF import libraries (`.LIB`).
//!
//! Usage: `omf-inspect [OPTIONS] <LIB>...` (see `--help`).
//!
//! The presentation layer for the `ne::omf` facts module (behind the same
//! `omf` feature): it reports what a library declares — the
//! `(target module, ordinal) → name` table that `ne-inspect --lib` uses to
//! name the ordinals of an NE file. All OMF knowledge lives in `src/omf.rs`
//! (see `OMF.md`).

#![warn(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::too_many_lines)]

use std::env;
use std::fs;
use std::process;

use ne::omf::{self, Library};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
omf-inspect — read 16-bit OMF import libraries (.LIB)

USAGE:
    omf-inspect [OPTIONS] <LIB>...

ARGS:
    <LIB>            OMF library; several may be given and their ordinal
                     tables are merged (later files add to earlier ones)

OPTIONS:
    --module <NAME>  report only this target module (USER, KERNEL, …;
                     case-insensitive)
    --ordinal <N>    report only this ordinal (needs --module)
    --find <TEXT>    report only names containing TEXT (case-insensitive)
    --summary        header, counts and per-module summary; no ordinal tables
    --json           machine-readable output
    -V, --version    print version
    -h, --help       print help

The library's own module count (855 in LIBW.LIB) is not the number of target
DLLs (5): each import is a three-record stub and every ordinal belongs to one
target module's own ordinal space. Dictionary blocks are located, not parsed.";

struct Options {
    files: Vec<String>,
    module: Option<String>,
    ordinal: Option<u16>,
    find: Option<String>,
    summary: bool,
    json: bool,
}

fn parse_args() -> Result<Options, String> {
    let mut opts = Options {
        files: Vec::new(),
        module: None,
        ordinal: None,
        find: None,
        summary: false,
        json: false,
    };
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
                println!("omf-inspect {VERSION}");
                process::exit(0);
            }
            "--summary" => opts.summary = true,
            "--json" => opts.json = true,
            "--module" => opts.module = Some(next_value("--module")?),
            "--find" => opts.find = Some(next_value("--find")?),
            "--ordinal" => {
                let raw = next_value("--ordinal")?;
                let digits = raw
                    .strip_prefix("0x")
                    .or(raw.strip_prefix("0X"))
                    .unwrap_or(&raw);
                opts.ordinal = Some(
                    u16::from_str_radix(digits, 16)
                        .or_else(|_| digits.parse::<u16>())
                        .map_err(|_| format!("not an ordinal: {raw}"))?,
                );
            }
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(format!("unknown option '{other}'"));
            }
            other => opts.files.push(other.to_string()),
        }
    }
    if opts.files.is_empty() {
        return Err("no library given".to_string());
    }
    if opts.ordinal.is_some() && opts.module.is_none() {
        return Err("--ordinal needs --module".to_string());
    }
    Ok(opts)
}

fn main() {
    let opts = match parse_args() {
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("Error: {e}\n\n{USAGE}");
            process::exit(3);
        }
    };

    let mut index = omf::OrdinalIndex::new();
    let mut declarations: Vec<String> = Vec::new();
    let mut exit_code = 0;

    for file in &opts.files {
        let data = match fs::read(file) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Error loading '{file}': {e}");
                exit_code = 2;
                continue;
            }
        };
        let library = match Library::parse(&data) {
            Ok(library) => library,
            Err(e) => {
                eprintln!("Error: '{file}': {e}");
                exit_code = 1;
                continue;
            }
        };
        for warning in &library.warnings {
            eprintln!("warning: {file}: {warning}");
        }
        if opts.json {
            declarations.push(declaration_lines(&library));
        } else {
            print_library(&opts, file, &library);
        }
        index.add_library(&library);
    }

    if opts.json {
        print_json(&opts, &declarations, &index);
    } else {
        print_index(&opts, &index);
    }
    process::exit(exit_code);
}

fn matches_find(opts: &Options, names: &[String]) -> bool {
    opts.find.as_ref().is_none_or(|find| {
        let find = find.to_ascii_lowercase();
        names.iter().any(|n| n.to_ascii_lowercase().contains(&find))
    })
}

// ---------------------------------------------------------------------------
// Text output
// ---------------------------------------------------------------------------

fn print_library(opts: &Options, file: &str, library: &Library<'_>) {
    println!("{file}: {} bytes", library.file_len);
    println!(
        "  LIBHDR       dict_off 0x{:08X}  blocks {} x 512 B  flags 0x{:02X}  name {:?}",
        library.dict_offset,
        library.dict_blocks,
        library.flags,
        library.name.as_str().unwrap_or("<non-ascii>")
    );
    println!(
        "  page size    {} (LIBHDR record padded to exactly one page)",
        library.page_size
    );

    let stubs = library
        .modules
        .iter()
        .filter(|m| m.is_import_stub())
        .count();
    println!(
        "  modules      {} total — {} import stubs, {} with content",
        library.module_count(),
        stubs,
        library.module_count() - stubs
    );
    let name_form = library
        .modules
        .iter()
        .flat_map(|m| &m.impdefs)
        .filter(|i| !i.is_by_ordinal())
        .count();
    println!(
        "  declares     IMPDEF {} ({} by ordinal, {} by name)  EXPDEF {}",
        library.impdef_count(),
        library.impdef_count() - name_form,
        name_form,
        library.expdef_count()
    );

    let records: Vec<String> = library
        .record_counts
        .iter()
        .map(|(record_type, count)| {
            format!(
                "{}(0x{record_type:02X}) x{count}",
                omf::record_type_name(*record_type).unwrap_or("UNKNOWN")
            )
        })
        .collect();
    println!("  records      {}", records.join("  "));

    let libmods: Vec<String> = library
        .modules
        .iter()
        .filter_map(|m| {
            m.libmod
                .map(|n| format!("{} @0x{:X}", n.as_str().unwrap_or("?"), m.offset))
        })
        .collect();
    if !libmods.is_empty() {
        println!("  LIBMOD       {}", libmods.join(", "));
    }

    let exports: Vec<String> = library
        .modules
        .iter()
        .flat_map(|m| &m.expdefs)
        .map(|e| {
            format!(
                "{} {}",
                e.exported_name.as_str().unwrap_or("?"),
                match e.ordinal {
                    Some(ordinal) => format!("ordinal {ordinal}"),
                    None => "by name".to_string(),
                }
            )
        })
        .collect();
    if !exports.is_empty() {
        // OMF carries no signatures beyond this callgate parm count (OMF.md §7).
        println!("  EXPDEF       {}", exports.join(", "));
    }

    if opts.summary {
        println!();
        return;
    }

    // Per-module declarations, in file order — what `IMPLIB` emitted.
    for module in &library.modules {
        for impdef in &module.impdefs {
            let target = impdef.module_name.as_str().unwrap_or("?");
            if !module_matches(opts, target) {
                continue;
            }
            if let Some(wanted) = opts.ordinal {
                if impdef.ordinal != Some(wanted) {
                    continue;
                }
            }
            if !matches_find(
                opts,
                &[impdef.internal_name.as_str().unwrap_or("?").to_string()],
            ) {
                continue;
            }
            println!(
                "  {:26} <- {:10} ! {}",
                impdef.internal_name.as_str().unwrap_or("?"),
                target,
                match impdef.ordinal {
                    Some(ordinal) => format!("ordinal {ordinal}"),
                    None => format!(
                        "name {}",
                        impdef
                            .export_name()
                            .and_then(|n| n.as_str().ok())
                            .unwrap_or("?")
                    ),
                }
            );
        }
    }
    println!();
}

fn print_index(opts: &Options, index: &omf::OrdinalIndex) {
    println!("Merged ordinal index");
    println!(
        "  {} libraries, {} IMPDEF, {} EXPDEF, {} target modules, {} ordinals, {} name-resolved",
        index.library_count(),
        index.impdef_count(),
        index.expdef_count(),
        index.target_module_count(),
        index.ordinal_count(),
        index.name_form_count()
    );

    for (module, by_ordinal) in index.by_target_module() {
        if !module_matches(opts, module) {
            continue;
        }
        let (Some(lo), Some(hi)) = (by_ordinal.keys().next(), by_ordinal.keys().next_back()) else {
            continue;
        };
        let names: usize = by_ordinal.values().map(Vec::len).sum();
        let aliases = by_ordinal.values().filter(|n| n.len() > 1).count();
        println!(
            "\n== {module}: {names} names, {} ordinals {lo}..{hi}, {} holes, {aliases} alias ordinal(s)",
            by_ordinal.len(),
            *hi as usize - *lo as usize + 1 - by_ordinal.len()
        );
        if opts.summary {
            continue;
        }
        for (ordinal, names) in by_ordinal {
            if opts.ordinal.is_some_and(|wanted| *ordinal != wanted) {
                continue;
            }
            if !matches_find(opts, names) {
                continue;
            }
            println!("  {ordinal:>6}  {}", names.join(" | "));
        }
    }

    for (module, by_name) in index.by_target_module_name_form() {
        if !module_matches(opts, module) {
            continue;
        }
        println!(
            "\n== {module}: {} name-resolved import(s), no ordinals",
            by_name.len()
        );
        if opts.summary {
            continue;
        }
        for (export, internals) in by_name {
            if !matches_find(opts, internals) {
                continue;
            }
            println!("  {export:32}  {}", internals.join(" | "));
        }
    }
}

fn module_matches(opts: &Options, module: &str) -> bool {
    opts.module
        .as_ref()
        .is_none_or(|filter| module.eq_ignore_ascii_case(filter))
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", json_escape(s))
}

/// One library's declaration, as a JSON object body.
fn declaration_lines(library: &Library<'_>) -> String {
    let records: Vec<String> = library
        .record_counts
        .iter()
        .map(|(record_type, count)| {
            format!(
                "{{\"type\": \"0x{record_type:02X}\", \"name\": {}, \"count\": {count}}}",
                json_str(omf::record_type_name(*record_type).unwrap_or("UNKNOWN"))
            )
        })
        .collect();
    let imports: Vec<String> = library
        .modules
        .iter()
        .flat_map(|m| &m.impdefs)
        .map(|impdef| {
            let target = impdef.module_name.as_str().unwrap_or("?");
            let resolved = match impdef.ordinal {
                Some(ordinal) => format!("\"ordinal\": {ordinal}"),
                None => format!(
                    "\"export_name\": {}",
                    json_str(
                        impdef
                            .export_name()
                            .and_then(|n| n.as_str().ok())
                            .unwrap_or("?")
                    )
                ),
            };
            format!(
                "{{\"internal_name\": {}, \"module\": {}, {}}}",
                json_str(impdef.internal_name.as_str().unwrap_or("?")),
                json_str(target),
                resolved
            )
        })
        .collect();
    format!(
        "{{\n    \"file_len\": {},\n    \"dict_offset\": \"0x{:08X}\",\n    \"dict_blocks\": {},\n    \"flags\": \"0x{:02X}\",\n    \"page_size\": {},\n    \"module_count\": {},\n    \"impdef_count\": {},\n    \"expdef_count\": {},\n    \"records\": [{}],\n    \"impdefs\": [{}]\n  }}",
        library.file_len,
        library.dict_offset,
        library.dict_blocks,
        library.flags,
        library.page_size,
        library.module_count(),
        library.impdef_count(),
        library.expdef_count(),
        records.join(", "),
        imports.join(", ")
    )
}

fn print_json(opts: &Options, declarations: &[String], index: &omf::OrdinalIndex) {
    let modules: Vec<String> = index
        .by_target_module()
        .iter()
        .filter(|(module, _)| module_matches(opts, module))
        .map(|(module, by_ordinal)| {
            let entries: Vec<String> = by_ordinal
                .iter()
                .filter(|(ordinal, names)| {
                    opts.ordinal.is_none_or(|wanted| **ordinal == wanted)
                        && matches_find(opts, names)
                })
                .map(|(ordinal, names)| {
                    format!(
                        "{{\"ordinal\": {ordinal}, \"names\": [{}]}}",
                        names
                            .iter()
                            .map(|n| json_str(n))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })
                .collect();
            format!(
                "{{\"module\": {}, \"ordinal_count\": {}, \"ordinals\": [{}]}}",
                json_str(module),
                by_ordinal.len(),
                entries.join(", ")
            )
        })
        .collect();

    let name_form: Vec<String> = index
        .by_target_module_name_form()
        .iter()
        .filter(|(module, _)| module_matches(opts, module))
        .map(|(module, by_name)| {
            let entries: Vec<String> = by_name
                .iter()
                .map(|(export, internals)| {
                    format!(
                        "{{\"export_name\": {}, \"internal_names\": [{}]}}",
                        json_str(export),
                        internals
                            .iter()
                            .map(|n| json_str(n))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })
                .collect();
            format!(
                "{{\"module\": {}, \"name_resolved\": [{}]}}",
                json_str(module),
                entries.join(", ")
            )
        })
        .collect();

    println!(
        "{{\n  \"libraries\": [\n  {}],\n  \"target_modules\": [{}],\n  \"name_resolved_modules\": [{}],\n  \"warnings\": [{}]\n}}",
        declarations.join(",\n  "),
        modules.join(",\n    "),
        name_form.join(",\n    "),
        index
            .warnings()
            .iter()
            .map(|w| json_str(w))
            .collect::<Vec<_>>()
            .join(", ")
    );
}
