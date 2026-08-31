// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! Dump relocation tables from NE files (development helper).
//!
//! Usage: `dump_relocs <file1> [file2 ...]`
//!
//! For each relocation entry this prints the Wine-style description
//! (`<n>: <addr> = <target>`) plus the resolved chain offsets within the
//! segment, to cross-check against `winedump --relocations`.

#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::unused_format_specs)]

use std::borrow::Cow;
use std::env;
use std::fs;

use new_executable::types::{ModuleRefTable, RelocationEntry, RelocationTable};
use new_executable::{AddressType, Buffer, RelocationType, SegmentRecord, NE};


fn addr_name(t: AddressType) -> Cow<'static, str> {
    match t {
        AddressType::LowByte => Cow::Borrowed("byte"),
        AddressType::Selector => Cow::Borrowed("sel"),
        AddressType::Pointer32 => Cow::Borrowed("ptr32"),
        AddressType::Offset16 => Cow::Borrowed("off16"),
        AddressType::Pointer48 => Cow::Borrowed("ptr48"),
        AddressType::Offset32 => Cow::Borrowed("off32"),
        AddressType::Unknown(v) => Cow::Owned(format!("???({v:02x})")),
        _ => Cow::Borrowed("???"),
    }
}

fn module_name(ne: &new_executable::VecNE, mod_table: &ModuleRefTable, idx: Option<u16>) -> String {
    match idx
        .and_then(|i| mod_table.resolve_import_ordinal_name(ne, i).ok())
        .and_then(|p| p.as_str().ok())
    {
        Some(s) => s.to_string(),
        None => "?".to_string(),
    }
}

fn target_str(entry: &RelocationEntry, ne: &new_executable::VecNE, mod_table: &ModuleRefTable) -> String {
    match entry.relocation_type {
        RelocationType::Internal => {
            if entry.is_self_module_ref() {
                format!("self.{}", entry.target2)
            } else {
                format!("{}:{:04X}", entry.target1, entry.target2)
            }
        }
        RelocationType::Ordinal => {
            let mod_name = module_name(ne, mod_table, entry.mod_ref_index());
            format!("{mod_name}.{}", entry.target2)
        }
        RelocationType::Name => {
            let mod_name = module_name(ne, mod_table, entry.mod_ref_index());
            let proc = entry
                .proc_name_offset()
                .and_then(|off| ModuleRefTable::resolve_import_name(ne, off).ok())
                .and_then(|p| p.as_str().ok())
                .unwrap_or("?");
            format!("{mod_name}.{proc}")
        }
        RelocationType::OSGlobal => format!(
            "TYPE {}, OFFSET {:04X}, TARGET {:04X} {:04X}",
            if entry.is_additive { 7 } else { 3 },
            entry.offset,
            entry.target1,
            entry.target2,
        ),
        RelocationType::Unknown(v) => format!("UNKNOWN({v:02x})"),
        _ => format!("t1={:04X} t2={:04X}", entry.target1, entry.target2),
    }
}

fn print_entry(
    i: usize,
    entry: &RelocationEntry,
    ne: &new_executable::VecNE,
    segs: &[SegmentRecord],
    mod_table: &ModuleRefTable,
) {
    let addr = addr_name(entry.address_type);
    let target = target_str(entry, ne, mod_table);

    // Resolve the chain within the owning segment's data.
    let seg_base = ne.logical_to_offset(entry.segment_number, 0).unwrap_or(0);
    let seg_len = segs
        .get(entry.segment_number as usize - 1)
        .map_or(0, |s| s.length as usize);
    let seg_data = ne.get_slice(seg_base, seg_len).unwrap_or(&[]);
    let links = entry.resolve_chain(seg_data).unwrap_or_default();
    let links_str = links
        .iter()
        .map(|l| format!("0x{l:04X}"))
        .collect::<Vec<_>>()
        .join(" ");

    let rt_raw = match entry.relocation_type {
        RelocationType::Ordinal => 0x01,
        RelocationType::Name => 0x02,
        RelocationType::OSGlobal => 0x03,
        RelocationType::Unknown(v) => v & 0x03,
        _ => 0x00,
    } | if entry.is_additive { 0x04 } else { 0x00 };
    let raw = [
        entry.address_type.as_u8(),
        rt_raw,
        (entry.offset & 0xFF) as u8,
        (entry.offset >> 8) as u8,
        (entry.target1 & 0xFF) as u8,
        (entry.target1 >> 8) as u8,
        (entry.target2 & 0xFF) as u8,
        (entry.target2 >> 8) as u8,
    ];

    let add = if entry.is_additive { " add" } else { "" };
    println!(
        "  Entry {:2}: {}{} = {}  chain=[{}]",
        i + 1,
        addr,
        add,
        target,
        links_str
    );
    println!(
        "                 raw: {}  (seg {} @ 0x{:04X})",
        raw.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" "),
        entry.segment_number,
        seg_base,
    );
}

fn dump_file(path: &str) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading {path}: {e}");
            return;
        }
    };

    let ne = new_executable::VecNE::from_slice(&data);

    let header = match ne.get_valid_ne_header() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error getting header from {path}: {e}");
            return;
        }
    };

    let seg_count = header.seg_count;
    let alignment = header.alignment;

    println!("\n=== {path} ===");
    println!(
        "NE v{}, seg_count={seg_count}, align=2^{alignment:2} ({})",
        header.version(),
        1u32 << alignment
    );

    let segs = match ne.get_segment_table() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error getting segment table from {path}: {e}");
            return;
        }
    };
    if segs.is_empty() {
        println!("  (no segments)");
        return;
    }

    for (i, seg) in segs.iter().enumerate() {
        // `i + 1` fits a u16: the segment table holds `seg_count` entries
        // and `seg_count` itself is a u16.
        let seg_num = u16::try_from(i + 1).expect("segment index fits u16: seg_count is u16");
        let base = ne.logical_to_offset(seg_num, 0).unwrap_or(0);
        let seg_length = seg.length;
        let seg_flags = seg.flags;
        println!(
            "  Segment {seg_num}: file 0x{base:04X}, len 0x{seg_length:04X}, flags 0x{seg_flags:04X}"
        );
    }

    let reloc = match RelocationTable::parse(&ne) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error parsing relocations from {path}: {e}");
            return;
        }
    };

    println!("Relocation entries: {}", reloc.entries.len());

    let mod_table = match ModuleRefTable::parse(&ne) {
        Ok(m) => m,
        Err(_) => ModuleRefTable {
            offsets: Vec::new(),
            count: 0,
        },
    };

    for (i, entry) in reloc.entries.iter().enumerate() {
        print_entry(i, entry, &ne, &segs, &mod_table);
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("Usage: dump_relocs <file> [file ...]");
        std::process::exit(1);
    }

    for path in &args {
        dump_file(path);
    }
}
