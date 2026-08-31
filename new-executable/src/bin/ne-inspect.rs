// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! ne-inspect — NE (New Executable) format inspector
//!
//! See USAGE.md for full documentation.

use std::collections::HashMap;
use std::env;
use std::process;

use new_executable::headers::*;
use new_executable::types::*;
use new_executable::{Buffer, VecNE, NE};

#[rustfmt::skip]
const OUTPUT_FORMATS: &[(&str, &str)] = &[
    ("detailed", "Human-readable detailed report (default)"),
    ("json",     "Machine-readable JSON output"),
    ("winedump", "winedump-compatible NE header output"),
];

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} [OPTIONS] <FILE>", args[0]);
        eprintln!();
        eprintln!("Options:");
        eprintln!(
            "  --format <FORMAT>   Output format: detailed, json, winedump (default: detailed)"
        );
        process::exit(3);
    }

    // Parse options
    let mut file_idx = None;
    let mut format: Option<&str> = None;
    let mut list_formats = false;
    let mut show_version = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --format requires an argument");
                    process::exit(3);
                }
                format = Some(&args[i]);
            }
            "--list-formats" => {
                list_formats = true;
            }
            "--version" => {
                show_version = true;
            }
            "-h" | "--help" => {
                print_help();
                process::exit(0);
            }
            other if other.starts_with('-') => {
                eprintln!("Error: unknown option '{}'", other);
                process::exit(3);
            }
            _ => {
                if file_idx.is_none() {
                    file_idx = Some(i);
                }
            }
        }
        i += 1;
    }

    if list_formats {
        println!("Available output formats:\n");
        for (name, desc) in OUTPUT_FORMATS {
            println!("  {:16} — {}", name, desc);
        }
        println!();
        println!("For filtered/programmatic output, use --format json and filter with jq.");
        process::exit(0);
    }

    if show_version {
        println!("ne-inspect {}", env!("CARGO_PKG_VERSION"));
        process::exit(0);
    }

    let file_idx = file_idx.expect("No file argument provided");
    let file = &args[file_idx];

    let format = format.unwrap_or("detailed");
    if !OUTPUT_FORMATS.iter().any(|(n, _)| *n == format) {
        eprintln!(
            "Error: unknown format '{}'. Use --list-formats to see available formats.",
            format
        );
        process::exit(3);
    }

    // Load the file
    let ne = match VecNE::from_disk_file(file) {
        Ok(ne) => ne,
        Err(e) => {
            eprintln!("Error loading '{}': {}", file, e);
            process::exit(2);
        }
    };

    let header = match ne.get_valid_ne_header() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    let basename = file.rsplit('/').next().unwrap_or(file);

    match format {
        "json" => print_json(basename, &ne, &header),
        "detailed" => print_detailed(basename, &ne, &header),
        "winedump" => print_winedump(&ne, &header),
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fmt_flags(flags: u16, table: &[(&str, u16)]) -> String {
    table
        .iter()
        .filter(|(_, bit)| flags & *bit != 0)
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(", ")
}

// Map a module ref index to its name (cached)
fn build_module_cache(ne: &VecNE) -> Result<HashMap<usize, String>, new_executable::Error> {
    let mrt = ModuleRefTable::parse(ne)?;
    let mut cache = HashMap::new();
    for i in 0..mrt.offsets.len() {
        if let Ok(name) = mrt.get_name(ne, i) {
            if let Ok(s) = name.as_str() {
                cache.insert(i, s.to_string());
            }
        }
    }
    Ok(cache)
}

// ---------------------------------------------------------------------------
// Mode: detailed (unified human-readable output)
// ---------------------------------------------------------------------------

fn print_detailed(basename: &str, ne: &VecNE, header: &ImageOS2Header) {
    print_section(basename, "HEADER");
    print_header_section(ne, header);
    println!();
    print_section(basename, "SEGMENTS");
    print_segments_section(ne);
    println!();
    print_section(basename, "EXPORTS");
    print_exports_section(ne);
    println!();
    print_section(basename, "IMPORTS");
    print_imports_section(ne);
    println!();
    print_section(basename, "RESOURCES");
    print_resources_section(ne);
    println!();
    print_section(basename, "RELOCATIONS");
    print_relocations_section(ne);
    println!();
    print_section(basename, "TABLES");
    print_tables_section(ne);
}

fn print_section(basename: &str, section: &str) {
    println!("NE Inspector — {} ({})", basename, section);
    println!("{}", "─".repeat(60));
}

// ---------------------------------------------------------------------------
// Mode: winedump
// ---------------------------------------------------------------------------

/// Segment flags in Wine `get_seg_flags` order (EXECUTEONLY and READONLY
/// both map to bit 0x0080, so both names appear when it is set).
fn wine_seg_flags(flags: u16) -> String {
    let mut s = String::new();
    if flags & 0x0001 != 0 {
        s.push_str(" DATA");
    }
    if flags & 0x0002 != 0 {
        s.push_str(" ALLOCATED");
    }
    if flags & 0x0004 != 0 {
        s.push_str(" LOADED");
    }
    if flags & 0x0008 != 0 {
        s.push_str(" ITERATED");
    }
    if flags & 0x0010 != 0 {
        s.push_str(" MOVEABLE");
    }
    if flags & 0x0020 != 0 {
        s.push_str(" SHAREABLE");
    }
    if flags & 0x0040 != 0 {
        s.push_str(" PRELOAD");
    }
    if flags & 0x0080 != 0 {
        s.push_str(" EXECUTEONLY READONLY");
    }
    if flags & 0x0100 != 0 {
        s.push_str(" RELOC_DATA");
    }
    if flags & 0x0800 != 0 {
        s.push_str(" SELFLOAD");
    }
    if flags & 0x1000 != 0 {
        s.push_str(" DISCARDABLE");
    }
    if flags & 0x2000 != 0 {
        s.push_str(" 32BIT");
    }
    if s.is_empty() {
        String::new()
    } else {
        format!("({})", s.trim_start())
    }
}

/// Address-type name per Wine `get_reloc_name` (bit 7 ignored, ` add` suffix
/// for additive relocations).
fn wine_reloc_name(entry: &RelocationEntry) -> String {
    let base = match entry.address_type.as_u8() & 0x7f {
        0 => "byte",
        2 => "sel",
        3 => "ptr32",
        5 => "off16",
        11 => "ptr48",
        13 => "off32",
        _ => "???",
    };
    if entry.is_additive {
        format!("{base} add")
    } else {
        base.to_string()
    }
}

/// Export name per Wine `get_export_name`: resident names (skipping the first
/// entry, the module name) then non-resident names; empty when not found.
fn wine_export_name(
    resident: &ResidentNameTable,
    non_res: &NonResidentNameTable,
    ordinal: u16,
) -> String {
    if resident.entries.len() > 1 {
        for e in &resident.entries[1..] {
            if e.ordinal == ordinal {
                return e.name.as_str().unwrap_or("").to_string();
            }
        }
    }
    non_res
        .by_ordinal(ordinal)
        .map(|e| e.name.as_str().unwrap_or("").to_string())
        .unwrap_or_default()
}

/// Relocation target string per Wine `dump_relocations` (the switch on
/// `relocation_type & 3`; OSFIXUP prints the raw type byte).
fn wine_reloc_target(
    entry: &RelocationEntry,
    ne: &VecNE,
    module_cache: &HashMap<usize, String>,
    self_module_name: &str,
) -> String {
    let raw_type = match entry.relocation_type {
        RelocationType::Internal => 0u8,
        RelocationType::Ordinal => 1,
        RelocationType::Name => 2,
        RelocationType::OSGlobal => 3,
        RelocationType::Unknown(v) => v & 0x03,
        _ => 0,
    };
    match raw_type {
        1 => {
            let mod_name = module_name_str(module_cache, entry.mod_ref_index());
            format!("{mod_name}.{}", entry.target2)
        }
        2 => {
            let mod_name = module_name_str(module_cache, entry.mod_ref_index());
            let proc = ModuleRefTable::resolve_import_name(ne, entry.target2)
                .and_then(|p| p.as_str())
                .ok()
                .unwrap_or("");
            format!("{mod_name}.{proc}")
        }
        3 => {
            let raw = raw_type | if entry.is_additive { 0x04 } else { 0x00 };
            format!(
                "TYPE {}, OFFSET {:04x}, TARGET {:04x} {:04x}",
                raw, entry.offset, entry.target1, entry.target2
            )
        }
        _ => {
            if (entry.target1 & 0xFF) == 0xFF {
                format!("{self_module_name}.{}", entry.target2)
            } else {
                format!("{}:{:04x}", entry.target1, entry.target2)
            }
        }
    }
}

/// Module name for a 1-based module reference index (Wine:
/// `mod_name = imptab + modref[target1 - 1]`).
fn module_name_str(module_cache: &HashMap<usize, String>, idx: Option<u16>) -> String {
    idx.and_then(|i| module_cache.get(&(i as usize - 1)).cloned())
        .unwrap_or_else(|| "?".to_string())
}

/// Resource type name per Wine `get_resource_type` (ordinal type IDs).
fn resource_type_name(id: u16) -> String {
    match id {
        0x8001 => "CURSOR".to_string(),
        0x8002 => "BITMAP".to_string(),
        0x8003 => "ICON".to_string(),
        0x8004 => "MENU".to_string(),
        0x8005 => "DIALOG".to_string(),
        0x8006 => "STRING".to_string(),
        0x8007 => "FONTDIR".to_string(),
        0x8008 => "FONT".to_string(),
        0x8009 => "ACCELERATOR".to_string(),
        0x800a => "RCDATA".to_string(),
        0x800c => "CURSOR_GROUP".to_string(),
        0x800e => "ICON_GROUP".to_string(),
        0x8010 => "VERSION".to_string(),
        0x80cc => "SCALABLE_FONTPATH".to_string(),
        _ => format!("{id:04x}"),
    }
}

fn print_winedump(ne: &VecNE, header: &ImageOS2Header) {
    let fields = header.common_fields();

    // --- File header (Wine `dump_ne_header`) ---
    println!("File header:");
    println!(
        "Linker version:      {}.{}",
        fields.linker_version, fields.linker_minor_version
    );
    println!(
        "Entry table:         {:x} len {}",
        fields.entry_table_offset, fields.entry_table_size
    );
    println!("Checksum:            {:08x}", fields.checksum);
    println!("Flags:               {:04x}", fields.flags);
    println!("Auto data segment:   {:x}", fields.auto_data_sel);
    println!("Heap size:           {} bytes", fields.heap_init);
    println!("Stack size:          {} bytes", fields.stack_init);
    println!(
        "Stack pointer:       {:x}:{:04x}",
        (fields.sssp >> 16) as u16,
        fields.sssp as u16
    );
    println!(
        "Entry point:         {:x}:{:04x}",
        (fields.csip >> 16) as u16,
        fields.csip as u16
    );
    println!("Number of segments:  {}", fields.seg_count);
    println!("Number of modrefs:   {}", fields.mod_count);
    println!("Segment table:       {:x}", fields.seg_table_offset);
    println!("Resource table:      {:x}", fields.resource_table_offset);
    println!("Resident name table: {:x}", fields.res_name_table_offset);
    println!("Module table:        {:x}", fields.mod_table_offset);
    println!(
        "Import table:        {:x}",
        fields.imported_names_table_offset
    );
    println!(
        "Non-resident table:  {:x}",
        fields.non_res_name_table_offset
    );
    println!("Exe type:            {:x}", fields.exe_type);
    println!("Other flags:         {:x}", fields.other_flags);
    let shift = fields.alignment as u32;
    let pret = fields.ret_thunk_offset as u32;
    let segref = fields.seg_ref_bytes_offset as u32;
    println!(
        "Fast load area:      {:x}-{:x}",
        pret << shift,
        (pret + segref) << shift
    );
    if let Some(v5) = header.v5_fields() {
        println!(
            "Expected version:    {}.{}",
            (v5.expected_version >> 8) & 0xFF,
            v5.expected_version & 0xFF
        );
    }

    // --- Names (Wine `dump_ne_names`) ---
    let resident = ResidentNameTable::parse(ne).unwrap_or(ResidentNameTable {
        entries: Vec::new(),
    });
    let non_res = NonResidentNameTable::parse(ne).unwrap_or(NonResidentNameTable {
        entries: Vec::new(),
    });

    println!("\nResident name table:");
    for entry in &resident.entries {
        if let Ok(s) = entry.name.as_str() {
            println!(" {:4}: {}", entry.ordinal, s);
        }
    }
    if fields.non_res_name_size != 0 {
        println!("\nNon-resident name table:");
        for entry in &non_res.entries {
            if let Ok(s) = entry.name.as_str() {
                println!(" {:4}: {}", entry.ordinal, s);
            }
        }
    }

    // --- Resources (Wine `dump_ne_resources`, entry lines only) ---
    println!("\nResources:");
    if let Ok(rt) = ResourceTable::parse(ne) {
        for t in &rt.type_info {
            let type_str = match &t.type_id {
                ResourceTypeId::Ordinal(n) => resource_type_name(*n),
                ResourceTypeId::Name(s) => s.as_str().unwrap_or("").to_string(),
            };
            for r in &t.records {
                let id_str = match &r.id {
                    ResourceId::Ordinal(n) => format!("{:04x}", n),
                    ResourceId::Name(s) => s.as_str().unwrap_or("").to_string(),
                };
                println!(
                    "  {} name {} flags {:04x} length {:04x}",
                    type_str, id_str, r.flags, r.length
                );
            }
        }
    }

    // --- Exports (Wine `dump_ne_exports`) ---
    if fields.entry_table_size != 0 {
        if let Ok(first) = ne.read_u8(ne.entry_table_offset() as usize) {
            if first != 0 {
                println!("\nExported entry points:");
                if let Ok(et) = EntryTable::parse(ne) {
                    for (i, slot) in et.entries.iter().enumerate() {
                        let Some(e) = slot else { continue };
                        let ordinal = i + 1;
                        let name = wine_export_name(&resident, &non_res, ordinal as u16);
                        match &e.entry_type {
                            EntryType::Movable { seg_num, offset } => {
                                println!(
                                    " {:4} MOVABLE {}:{:04x} {}",
                                    ordinal, seg_num, offset, name
                                );
                            }
                            EntryType::Constant { value } => {
                                println!(" {:4} CONST     {:04x} {}", ordinal, value, name);
                            }
                            EntryType::Fixed { seg_num, offset } => {
                                println!(
                                    " {:4} FIXED   {}:{:04x} {}",
                                    ordinal, seg_num, offset, name
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    // --- Segments + per-segment relocations (Wine `dump_ne_segment`,
    // `dump_relocations`) ---
    let segments = ne.get_segment_table().unwrap_or_default();
    let reloc = match RelocationTable::parse(ne) {
        Ok(r) => r,
        Err(_) => RelocationTable {
            entries: Vec::new(),
        },
    };
    let module_cache = build_module_cache(ne).unwrap_or_default();
    let self_module_name = resident
        .entries
        .first()
        .and_then(|e| e.name.as_str().ok())
        .unwrap_or("");

    for (idx, seg) in segments.iter().enumerate() {
        let seg_num = idx + 1;
        // Copy packed fields to locals to avoid unaligned reference
        let seg_offset = seg.offset;
        let seg_length = seg.length;
        let seg_flags = seg.flags;
        let seg_minalloc = seg.minalloc;

        println!("\nSegment {}:", seg_num);
        println!("  File offset: {:08x}", (seg_offset as u32) << shift);
        println!("  Length:      {:08x}", seg_length);
        println!(
            "  Flags:       {:08x} {}",
            seg_flags,
            wine_seg_flags(seg_flags)
        );
        println!("  Alloc size:  {:08x}", seg_minalloc);
        if seg_flags & SegmentFlags::RELOC_DATA.bits() != 0 {
            println!("  Relocations:");
            for (n, entry) in reloc
                .entries
                .iter()
                .filter(|e| e.segment_number == seg_num as u16)
                .enumerate()
            {
                println!(
                    "{:6}: {} = {}",
                    n + 1,
                    wine_reloc_name(entry),
                    wine_reloc_target(entry, ne, &module_cache, self_module_name)
                );
            }
        }
    }
}

// JSON output
// ---------------------------------------------------------------------------

/// Escape a string for JSON output.
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn print_json(basename: &str, ne: &VecNE, header: &ImageOS2Header) {
    let fields = header.common_fields();
    let exe_type = header.exe_type();
    let is_dll = ne.is_library();
    let version = header.version();
    let segments = ne.get_segment_table().unwrap_or_default();

    // Segments JSON array
    let segments_json: Vec<String> = segments.iter().enumerate().map(|(i, seg)| {
        let seg_flags = seg.flags; // copy from packed struct
        let seg_length = seg.length; // copy from packed struct
        let seg_minalloc = seg.minalloc; // copy from packed struct
        let seg_offset = seg.offset; // copy from packed struct
        let flags_str = fmt_flags(seg_flags, &[
            ("DATA", SegmentFlags::DATA.bits()),
            ("MOVEABLE", SegmentFlags::MOVEABLE.bits()),
            ("SHAREABLE", SegmentFlags::SHAREABLE.bits()),
            ("PRELOAD", SegmentFlags::PRELOAD.bits()),
            ("DISCARDABLE", SegmentFlags::DISCARDABLE.bits()),
            ("READONLY", SegmentFlags::READONLY.bits()),
            ("RELOC_DATA", SegmentFlags::RELOC_DATA.bits()),
            ("SELFLOAD", SegmentFlags::SELFLOAD.bits()),
        ]);
        format!(
            "    {{\"number\": {}, \"offset\": \"0x{:04X}\", \"length\": \"0x{:04X}\", \"flags\": {}, \"flags_str\": \"{}\", \"minalloc\": \"0x{:04X}\"}}",
            i + 1,
            seg_offset,
            seg_length,
            seg_flags,
            if flags_str.is_empty() { "NONE".to_string() } else { flags_str },
            seg_minalloc,
        )
    }).collect();

    // v5 fields
    let v5_json = if header.is_v5() {
        // Copy packed fields to locals to avoid unaligned reference
        let pretthunks = header.ret_thunk_offset;
        let psegrefbytes = header.seg_ref_bytes_offset;
        let swaparea = header.swap_area;
        let expver = header.expected_version;
        format!(
            r#",
    "v5_fields": {{
      "ret_thunk_offset": "0x{:04X}",
      "seg_ref_bytes_offset": "0x{:04X}",
      "swap_area": "0x{:04X}",
      "expected_version": "{}.{}",
      "fast_load_area": "0x{:x}-0x{:x}"
    }}"#,
            pretthunks,
            psegrefbytes,
            swaparea,
            (expver >> 8) as u8,
            expver & 0xFF,
            pretthunks << fields.alignment,
            (pretthunks as u32 + psegrefbytes as u32) << fields.alignment
        )
    } else {
        String::new()
    };

    // Build JSON using write_to_string for clarity
    let mut out = String::new();

    // Copy packed fields to locals to avoid unaligned reference
    let sig = header.signature; // copy from packed struct
    out.push_str(&format!(
        r#"{{
  "file": "{}",
  "header": {{
    "signature": "0x{:04X}",
    "linker_version": "{}.{}",
    "entry_table": {{
      "offset": "0x{:04X}",
      "size": "0x{:04X}"
    }},
    "checksum": "0x{:08X}",
    "flags": "0x{:04X}",
    "auto_data": "0x{:04X}",
    "heap_init": "0x{:04X}",
    "stack_init": "0x{:04X}",
    "csip": "0x{:04X}:0x{:04X}",
    "sssp": "0x{:04X}:0x{:04X}",
    "segment_count": {},
    "module_count": {},
    "exe_type": "{}",
    "version": "{}",
    "is_dll": {},
    "is_v5": {}{}
  }},"#,
        json_escape(basename),
        sig,
        fields.linker_version,
        fields.linker_minor_version,
        fields.entry_table_offset,
        fields.entry_table_size,
        fields.checksum,
        fields.flags,
        fields.auto_data_sel,
        fields.heap_init,
        fields.stack_init,
        (fields.csip >> 16) as u16,
        fields.csip as u16,
        (fields.sssp >> 16) as u16,
        fields.sssp as u16,
        fields.seg_count,
        fields.mod_count,
        exe_type,
        version,
        is_dll,
        header.is_v5(),
        v5_json
    ));

    // Tables
    out.push_str(&format!(
        r#"
  "tables": {{
    "segment": "0x{:04X}",
    "resource": "0x{:04X}",
    "resident_names": "0x{:04X}",
    "module_refs": "0x{:04X}",
    "imported_names": "0x{:04X}",
    "non_resident_names": "0x{:08X}"
  }},"#,
        fields.seg_table_offset,
        fields.resource_table_offset,
        fields.res_name_table_offset,
        fields.mod_table_offset,
        fields.imported_names_table_offset,
        fields.non_res_name_table_offset
    ));

    // Summary
    let entry_table = EntryTable::parse(ne).unwrap_or(EntryTable {
        entries: Vec::new(),
    });
    let export_count = entry_table.export_count();
    let module_cache = build_module_cache(ne).unwrap_or_default();
    let resource_table = ResourceTable::parse(ne).unwrap_or(ResourceTable {
        type_info: Vec::new(),
        alignment_shift: 0,
    });
    let resource_types = resource_table.type_info.len();

    out.push_str(&format!(
        r#"
  "summary": {{
    "segment_count": {},
    "module_count": {},
    "export_count": {},
    "resource_type_count": {},
    "is_dll": {}
  }},"#,
        segments.len(),
        module_cache.len(),
        export_count,
        resource_types,
        is_dll
    ));

    // Segments
    out.push_str("\n  \"segments\": [\n");
    out.push_str(&segments_json.join(",\n"));
    out.push_str("\n  ]\n}");

    println!("{}", out);
}

// ---------------------------------------------------------------------------
// Section wrappers (for "full" detailed output)
// ---------------------------------------------------------------------------

fn print_header_section(_ne: &VecNE, header: &ImageOS2Header) {
    let fields = header.common_fields();
    let sig = header.signature;
    let lk_ver = header.linker_version;
    let lk_min = header.linker_minor_version;
    let entry_off = fields.entry_table_offset;
    let entry_sz = fields.entry_table_size;
    let cksum = fields.checksum;
    let fl = fields.flags;
    let auto_d = fields.auto_data_sel;
    let heap_i = fields.heap_init;
    let stack_i = fields.stack_init;
    let csip = fields.csip;
    let sssp = fields.sssp;
    let seg_c = fields.seg_count;
    let mod_c = fields.mod_count;
    let non_res = fields.non_res_name_size;

    println!("  Signature:      0x{:04X} (\"NE\")", sig);
    println!("  Linker Version: {}.{}", lk_ver, lk_min);
    println!(
        "  Entry Table:    0x{:04X} (offset) / 0x{:04X} (size)",
        entry_off, entry_sz
    );
    println!("  Checksum:       0x{:08X}", cksum);
    println!("  Flags:          0x{:04X}", fl);
    println!("  Auto Data:      0x{:04X}", auto_d);
    println!(
        "  Heap Init:      0x{:04X} ({} bytes)",
        heap_i, heap_i as usize
    );
    println!(
        "  Stack Init:     0x{:04X} ({} bytes)",
        stack_i, stack_i as usize
    );
    println!(
        "  CS:IP:          0x{:04X}:0x{:04X}",
        (csip >> 16) as u16,
        csip as u16
    );
    println!(
        "  SS:SP:          0x{:04X}:0x{:04X}",
        (sssp >> 16) as u16,
        sssp as u16
    );
    println!("  Segments:       {}", seg_c);
    println!("  Module Refs:    {}", mod_c);
    println!("  Non-Res Names:  {} bytes", non_res);
    println!("  Exe Type:       {}", header.exe_type());

    let align_val = fields.alignment as u8;
    let align_bytes = SegmentAlignment::from_u8(align_val)
        .map(|a| a.alignment_bytes())
        .unwrap_or(1usize.checked_shl(align_val as u32).unwrap_or(usize::MAX));
    println!(
        "  Alignment:      {} (shift={})",
        align_bytes, fields.alignment
    );

    println!("  Ret Thunk Off:  0x{:04X}", fields.ret_thunk_offset);
    println!("  Seg Ref Bytes:  0x{:04X}", fields.seg_ref_bytes_offset);
    if let Some(v5) = header.v5_fields() {
        println!("  Swap Area:      0x{:04X}", v5.swap_area);
        println!(
            "  Expected Ver:   {}.{}",
            (v5.expected_version >> 8) as u8,
            (v5.expected_version & 0xFF) as u8
        );
    }
}

fn print_segments_section(ne: &VecNE) {
    let segments = match ne.get_segment_table() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  Error: {}", e);
            return;
        }
    };

    if segments.is_empty() {
        println!("  No segments.");
        return;
    }

    println!(
        "  {:>3}  {:28}  {:10}  {:10}  {:10}",
        "#", "Flags", "Size", "Offset", "MinAlloc"
    );
    println!("  ---  ----------------------------  ----------  ----------  ----------");

    for (i, seg) in segments.iter().enumerate() {
        let seg_num = (i + 1) as u16;
        let flags_str = fmt_flags(
            seg.flags,
            &[
                ("DATA", SegmentFlags::DATA.bits()),
                ("MOVEABLE", SegmentFlags::MOVEABLE.bits()),
                ("SHAREABLE", SegmentFlags::SHAREABLE.bits()),
                ("PRELOAD", SegmentFlags::PRELOAD.bits()),
                ("DISCARDABLE", SegmentFlags::DISCARDABLE.bits()),
                ("READONLY", SegmentFlags::READONLY.bits()),
                ("RELOC_DATA", SegmentFlags::RELOC_DATA.bits()),
                ("SELFLOAD", SegmentFlags::SELFLOAD.bits()),
            ],
        );
        let seg_length = seg.length;
        let seg_minalloc = seg.minalloc;
        let seg_offset = seg.offset;
        let size_str = format!("0x{:04X}", seg_length);
        println!(
            "  {:>3}  {:28}  {:10}  {:10}  {:10}",
            seg_num,
            if flags_str.is_empty() {
                "NONE"
            } else {
                &flags_str
            },
            size_str,
            format!("0x{:04X}", seg_offset),
            format!("0x{:04X}", seg_minalloc)
        );
    }
}

fn print_exports_section(ne: &VecNE) {
    let entry_table = match EntryTable::parse(ne) {
        Ok(et) => et,
        Err(_) => {
            println!("  No entry table.");
            return;
        }
    };

    if entry_table.export_count() == 0 {
        println!("  No exports.");
        return;
    }

    let total = entry_table.export_count();
    println!("  {} export(s):\n", total);

    let resident_names = match ResidentNameTable::parse(ne) {
        Ok(rnt) => rnt,
        Err(_) => ResidentNameTable {
            entries: Vec::new(),
        },
    };
    let non_res_names = match NonResidentNameTable::parse(ne) {
        Ok(nrt) => nrt,
        Err(_) => NonResidentNameTable {
            entries: Vec::new(),
        },
    };

    println!(
        "  {:>6}  {:>8}  {:>8}  Name",
        "Ordinal", "Segment", "Offset"
    );
    println!("  ------  --------  --------  ------");

    for (i, export) in entry_table.entries.iter().enumerate() {
        if let Some(e) = export {
            let ordinal = i as u16 + 1;
            let seg_str = e
                .seg_num()
                .map_or_else(|| "----".to_string(), |s| format!("{:04X}", s));
            let off_str = match e.offset() {
                Some(o) => format!("{:04X}", o),
                None => e
                    .constant_value()
                    .map_or_else(|| "----".to_string(), |v| format!("{:04X}", v)),
            };
            // Export names may live in either the resident or the
            // non-resident name table (Wine `get_export_name` order).
            let name = wine_export_name(&resident_names, &non_res_names, ordinal);
            let name = if name.is_empty() { "?" } else { name.as_str() };
            println!("  0x{:04X}  {}  {}  {}", ordinal, seg_str, off_str, name);
        }
    }
}

fn print_imports_section(ne: &VecNE) {
    let module_cache = match build_module_cache(ne) {
        Ok(c) => c,
        Err(_) => {
            println!("  No module reference table.");
            return;
        }
    };

    if module_cache.is_empty() {
        println!("  No imports.");
        return;
    }

    let mut modules: Vec<_> = module_cache.iter().collect();
    modules.sort_by(|a, b| a.1.to_lowercase().cmp(&b.1.to_lowercase()));

    println!("  {:<20}  {:>10}  {:>6}", "Module", "ModRefIdx", "Procs");
    println!("  --------------------  ----------  --------");

    let reloc_table = match RelocationTable::parse(ne) {
        Ok(rt) => rt,
        Err(_) => RelocationTable {
            entries: Vec::new(),
        },
    };

    let mut module_imports: HashMap<String, Vec<&RelocationEntry>> = HashMap::new();
    for entry in &reloc_table.entries {
        let Some(mod_idx) = entry.mod_ref_index() else {
            continue;
        };
        let mod_name = module_cache
            .get(&((mod_idx - 1) as usize))
            .cloned()
            .unwrap_or_else(|| format!("??({})", mod_idx));
        module_imports.entry(mod_name).or_default().push(entry);
    }

    for (idx, mod_name) in modules.iter() {
        let count = module_imports
            .get(mod_name.as_str())
            .map(|e| e.len())
            .unwrap_or(0);
        // Module reference indices are 1-based in NE files.
        println!("  {:<20}  {:>10}  {:>6}", mod_name, *idx + 1, count);
    }
}

fn print_resources_section(ne: &VecNE) {
    let resource_table = match ResourceTable::parse(ne) {
        Ok(rt) => rt,
        Err(_) => {
            println!("  No resource table.");
            return;
        }
    };

    if resource_table.type_info.is_empty() {
        println!("  No resources.");
        return;
    }

    let total_entries: usize = resource_table
        .type_info
        .iter()
        .map(|t| t.records.len())
        .sum();
    println!(
        "  {} resource type(s), {} entry(s), alignment shift = {}\n",
        resource_table.type_info.len(),
        total_entries,
        resource_table.alignment_shift
    );

    for type_info in &resource_table.type_info {
        let type_name = match &type_info.type_id {
            ResourceTypeId::Ordinal(n) => match *n {
                1 => "RT_CURSOR".to_string(),
                2 => "RT_BITMAP".to_string(),
                3 => "RT_ICON".to_string(),
                4 => "RT_MENU".to_string(),
                5 => "RT_DIALOG".to_string(),
                6 => "RT_STRING".to_string(),
                7 => "RT_FONTDIR".to_string(),
                8 => "RT_FONT".to_string(),
                9 => "RT_ACCEL".to_string(),
                10 => "RT_RCDATA".to_string(),
                11 => "RT_MESSAGETABLE".to_string(),
                12 => "RT_GROUP_CURSOR".to_string(),
                14 => "RT_GROUP_ICON".to_string(),
                16 => "RT_VERSION".to_string(),
                n => format!("RT_0x{:04X}", n),
            },
            ResourceTypeId::Name(name) => match name.as_str() {
                Ok(s) => s.to_string(),
                Err(_) => "?".to_string(),
            },
        };

        println!("  Type: {}", type_name);
        println!("  {:>4}  {:>10}  {:>8}  Flags", "ID", "Offset", "Length");
        println!("  ----  ----------  --------  -----------");

        for record in &type_info.records {
            let id_str = match &record.id {
                ResourceId::Ordinal(n) => format!("0x{:04X}", n),
                ResourceId::Name(name) => match name.as_str() {
                    Ok(s) => s.to_string(),
                    Err(_) => "?".to_string(),
                },
            };
            let mut f = Vec::new();
            if record.flags & 0x0010 != 0 {
                f.push("MOVEABLE");
            }
            if record.flags & 0x0020 != 0 {
                f.push("PURE");
            }
            if record.flags & 0x0040 != 0 {
                f.push("PRELOAD");
            }
            let flags_str = if f.is_empty() {
                "NONE".to_string()
            } else {
                f.join(", ")
            };
            println!(
                "  {}  0x{:06X}  0x{:04X}  {}",
                id_str, record.offset, record.length, flags_str
            );
        }
        println!();
    }
}

fn print_relocations_section(ne: &VecNE) {
    let reloc_table = match RelocationTable::parse(ne) {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("  Error: {}", e);
            return;
        }
    };

    if reloc_table.entries.is_empty() {
        println!("  No relocations.");
        return;
    }

    let module_cache = build_module_cache(ne).unwrap_or_default();

    println!("  {} relocation(s):\n", reloc_table.entries.len());

    for (i, entry) in reloc_table.entries.iter().enumerate() {
        let addr_str = match entry.address_type {
            AddressType::LowByte => "LOBYTE".to_string(),
            AddressType::Selector => "SELECTOR".to_string(),
            AddressType::Pointer32 => "POINTER32".to_string(),
            AddressType::Offset16 => "OFFSET16".to_string(),
            AddressType::Pointer48 => "POINTER48".to_string(),
            AddressType::Offset32 => "OFFSET32".to_string(),
            AddressType::Unknown(v) => format!("UNKNOWN({})", v),
            _ => "??".to_string(),
        };
        let reloc_str = match entry.relocation_type {
            RelocationType::Internal => "INTERNALREF".to_string(),
            RelocationType::Ordinal => "IMPORTORDINAL".to_string(),
            RelocationType::Name => "IMPORTNAME".to_string(),
            RelocationType::OSGlobal => "OSFIXUP".to_string(),
            RelocationType::Unknown(v) => format!("UNKNOWN({})", v),
            _ => "??".to_string(),
        };

        let target_str = if entry.relocation_type == RelocationType::Internal {
            if entry.is_self_module_ref() {
                format!("self ord=0x{:04X} [movable]", entry.target2)
            } else {
                format!("seg=0x{:04X} off=0x{:04X}", entry.target1, entry.target2)
            }
        } else if let Some(mod_idx) = entry.mod_ref_index() {
            let mod_name = module_cache
                .get(&(mod_idx as usize - 1))
                .cloned()
                .unwrap_or_else(|| format!("??({})", mod_idx));
            if entry.relocation_type == RelocationType::Name {
                let proc_name = ModuleRefTable::resolve_import_name(ne, entry.target2)
                    .and_then(|p| p.as_str())
                    .ok()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("??(0x{:04X})", entry.target2));
                format!("mod={} proc={}", mod_name, proc_name)
            } else {
                format!("mod={} ord=0x{:04X}", mod_name, entry.target2)
            }
        } else {
            format!("t1=0x{:04X} t2=0x{:04X}", entry.target1, entry.target2)
        };

        let additive_str = if entry.is_additive {
            " [+ADDITIVE]"
        } else {
            ""
        };
        println!(
            "  [{:>4}]  0x{:04X}  {:>10}  {:>13}  {}{}",
            i + 1,
            entry.offset,
            addr_str,
            reloc_str,
            target_str,
            additive_str
        );
    }
}

fn print_tables_section(ne: &VecNE) {
    match ResidentNameTable::parse(ne) {
        Ok(rnt) => {
            if rnt.entries.is_empty() {
                println!("  Resident Names: (empty)");
            } else {
                println!("  {:>6}  Name", "Ordinal");
                println!("  ------  ------");
                for entry in &rnt.entries {
                    println!(
                        "  0x{:04X}  {}",
                        entry.ordinal,
                        entry.name.as_str().unwrap_or("?")
                    );
                }
            }
        }
        Err(new_executable::Error::TableNotPresent(_)) => println!("  Resident Names: (not present)"),
        Err(e) => println!("  Resident Names Error: {}", e),
    }

    match ModuleRefTable::parse(ne) {
        Ok(mrt) => {
            if mrt.count == 0 {
                println!("  Module Refs: (empty)");
            } else {
                println!("  {:>6}  Module Name", "Index");
                println!("  ------  ------");
                // Module reference indices are 1-based in NE files.
                for i in 0..mrt.count {
                    println!(
                        "  {:>6}  {}",
                        i + 1,
                        mrt.get_name(ne, i as usize)
                            .and_then(|p| p.as_str())
                            .unwrap_or("?")
                    );
                }
            }
        }
        Err(new_executable::Error::TableNotPresent(_)) => println!("  Module Refs: (not present)"),
        Err(e) => println!("  Module Refs Error: {}", e),
    }
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

fn print_help() {
    println!("ne-inspect — NE (New Executable) format inspector");
    println!();
    println!("Usage: ne-inspect [OPTIONS] <FILE>");
    println!();
    println!("Arguments:");
    println!("  <FILE>    Path to a NE-format file (.exe, .dll, .drv, .fon)");
    println!();
    println!("Options:");
    println!("  --format <FORMAT>   Output format (default: detailed)");
    println!("                      Available: detailed, json, winedump");
    println!("  --list-formats      Show available formats and exit");
    println!("  --version           Show version and exit");
    println!();
    println!("With --format detailed:");
    println!("  --mode <MODE>       Detail level: summary, header, segments,");
    println!("                      exports, imports, resources, relocations,");
    println!("                      tables, full (default: full)");
    println!("  --list-modes        Show available modes and exit");
    println!();
    println!("  -h, --help          Show this help");
    println!();
    println!("Exit Codes:");
    println!("  0   Success");
    println!("  1   Parse error (invalid file, missing fields, etc.)");
    println!("  2   File not found or I/O error");
    println!("  3   Invalid arguments");
}
