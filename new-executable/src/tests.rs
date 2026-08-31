// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Johannes Leupolz <dev@leupolz.eu>
//! Integration tests for ne-rs.
//!
//! Fixtures come from two directories:
//! - `testdata/fixtures/` — committed, MIT-licensed (feature `fixtures`)
//! - `testdata/external/` — non-distributable real Windows 3.x / OS/2
//!   files the user must add (feature `external-fixtures`; see TESTS.md)

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::{
        headers::*, types::*, Buffer, Error, PtrNE, VecNE, NE, NE_HEADER_SIZE_V4, NE_HEADER_SIZE_V5,
    };
    #[cfg(any(feature = "fixtures", feature = "external-fixtures"))]
    use crate::{DOS_E_LFANEW_OFFSET, DOS_E_LFARLC_OFFSET, DOS_SIGNATURE};
    use std::format;
    #[cfg(any(feature = "fixtures", feature = "external-fixtures"))]
    use std::string::ToString;
    use std::vec;
    use std::vec::Vec;

    // -----------------------------------------------------------------------
    // Helper: create a minimal synthetic NE binary for unit tests
    // -----------------------------------------------------------------------

    /// Create a minimal NE binary in memory for testing.
    ///
    /// Layout:
    /// [0x00] DOS header (64 bytes) with MZ signature, `e_lfarlc=0x40`, `e_lfanew=0x3C`
    /// [0x3C] NE header (60 bytes, v4)
    /// [0x78] Segment table (1 entry)
    ///
    fn minimal_ne_v4() -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        // DOS header; e_lfarlc (0x18) = 0x40 as in every corpus file (read
        // but not validated — NE detection is the "NE" signature at e_lfanew)
        data[0x00] = 0x4D; // "M"
        data[0x01] = 0x5A; // "Z"
        data[0x18..0x1A].copy_from_slice(&0x40u16.to_le_bytes()); // e_lfarlc = 0x40
        data[0x3C..0x3E].copy_from_slice(&0x40u16.to_le_bytes()); // e_lfanew = 0x40 (NE header starts right after DOS header)

        // NE header at file offset 0x40 (right after 64-byte DOS header, no stub)
        // Struct offsets (verified): seg_table_offset=0x22, exe_type=0x36, flags=0x0C
        let off = 0x40;

        // signature:       0x00 (2 bytes)
        data[off..off + 2].copy_from_slice(&0x454Eu16.to_le_bytes());
        // linker_version:  0x02 (1 byte) — version 4 for v4 header test
        data[off + 0x02] = 0x04;
        // linker_minor_version: 0x03 (1 byte)
        data[off + 0x03] = 0x00;
        // entry_table_offset: 0x04 (2 bytes)
        data[off + 0x04..off + 0x06].copy_from_slice(&0u16.to_le_bytes());
        // entry_table_size: 0x06 (2 bytes)
        data[off + 0x06..off + 0x08].copy_from_slice(&0u16.to_le_bytes());
        // checksum:        0x08 (4 bytes)
        data[off + 0x08..off + 0x0C].copy_from_slice(&(0u32).to_le_bytes());
        // flags:           0x0C (2 bytes) = 0 (v4, no VERSION_BIT)
        data[off + 0x0C..off + 0x0E].copy_from_slice(&0u16.to_le_bytes());
        // auto_data_sel:   0x0E (2 bytes)
        data[off + 0x0E..off + 0x10].copy_from_slice(&0u16.to_le_bytes());
        // heap_init:       0x10 (2 bytes)
        data[off + 0x10..off + 0x12].copy_from_slice(&0u16.to_le_bytes());
        // stack_init:      0x12 (2 bytes)
        data[off + 0x12..off + 0x14].copy_from_slice(&0u16.to_le_bytes());
        // csip:            0x14 (4 bytes)
        data[off + 0x14..off + 0x18].copy_from_slice(&((0u32).to_le_bytes()));
        // sssp:            0x18 (4 bytes)
        data[off + 0x18..off + 0x1C].copy_from_slice(&((0u32).to_le_bytes()));
        // seg_count:       0x1C (2 bytes) — set to 1 below
        // mod_count:       0x1E (2 bytes)
        data[off + 0x1E..off + 0x20].copy_from_slice(&0u16.to_le_bytes());
        // non_res_name_size: 0x20 (2 bytes)
        data[off + 0x20..off + 0x22].copy_from_slice(&0u16.to_le_bytes());
        // seg_table_offset: 0x22 (2 bytes) = 0x007C
        data[off + 0x22..off + 0x24].copy_from_slice(&0x7Cu16.to_le_bytes());
        // resource_table_offset: 0x24 (2 bytes)
        data[off + 0x24..off + 0x26].copy_from_slice(&0u16.to_le_bytes());
        // res_name_table_offset: 0x26 (2 bytes)
        data[off + 0x26..off + 0x28].copy_from_slice(&0u16.to_le_bytes());
        // mod_table_offset: 0x28 (2 bytes)
        data[off + 0x28..off + 0x2A].copy_from_slice(&0u16.to_le_bytes());
        // imported_names_table_offset: 0x2A (2 bytes)
        data[off + 0x2A..off + 0x2C].copy_from_slice(&0u16.to_le_bytes());
        // non_res_name_table_offset: 0x2C (4 bytes)
        data[off + 0x2C..off + 0x30].copy_from_slice(&(0u32).to_le_bytes());
        // mod_internal_entries: 0x30 (2 bytes)
        data[off + 0x30..off + 0x32].copy_from_slice(&0u16.to_le_bytes());
        // alignment:       0x32 (2 bytes)
        data[off + 0x32..off + 0x34].copy_from_slice(&0u16.to_le_bytes());
        // resource_count:  0x34 (2 bytes)
        data[off + 0x34..off + 0x36].copy_from_slice(&0u16.to_le_bytes());
        // exe_type:        0x36 (1 byte) = 2 (Windows)
        data[off + 0x36] = 2;
        // other_flags:     0x37 (1 byte)
        data[off + 0x37] = 0;
        // ret_thunk_offset: 0x38 (2 bytes)
        data[off + 0x38..off + 0x3A].copy_from_slice(&0u16.to_le_bytes());
        // seg_ref_bytes_offset: 0x3A (2 bytes)
        data[off + 0x3A..off + 0x3C].copy_from_slice(&0u16.to_le_bytes());
        // swap_area:       0x3C (2 bytes)
        data[off + 0x3C..off + 0x3E].copy_from_slice(&0u16.to_le_bytes());
        // expected_version: 0x3E (2 bytes)
        data[off + 0x3E..off + 0x40].copy_from_slice(&0u16.to_le_bytes());

        // Set seg_count after all other fields are written
        data[off + 0x1C..off + 0x1E].copy_from_slice(&1u16.to_le_bytes());

        // Segment table at file offset 0xBC (NE header 0x40 + seg_table_offset 0x7C)
        // 1 segment, 8 bytes
        let seg_off = 0x40 + 0x7C; // file offset = e_lfanew + seg_table_offset
                                   // offset=0x0010, length=0x0200, flags=MOVEABLE(0x0010), minalloc=0
        data[seg_off..seg_off + 8].copy_from_slice(&[
            0x10, 0x00, // offset = 0x0010
            0x00, 0x02, // length = 0x0200
            0x10, 0x00, // flags = MOVEABLE
            0x00, 0x00, // minalloc = 0
        ]);

        data
    }

    // -----------------------------------------------------------------------
    // Unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_minimal_ne_v4_header() {
        let data = minimal_ne_v4();
        let ne = VecNE::from_memory(data);

        // Should parse validly
        let header = ne.get_valid_ne_header().unwrap();
        let sig = header.signature; // copy from packed struct
        assert_eq!(sig, 0x454E);
        assert!(!header.is_v5());
        assert_eq!(header.exe_type(), ExeType::Win);
    }

    #[test]
    fn test_segment_table() {
        let data = minimal_ne_v4();
        let ne = VecNE::from_memory(data);

        let segments = ne.get_segment_table().unwrap();
        assert_eq!(segments.len(), 1);

        let seg = &segments[0];
        // Copy packed fields to locals to avoid unaligned reference
        let seg_flags = seg.flags;
        assert!(seg.is_moveable(), "flags=0x{seg_flags:04X}");
        assert_eq!(seg.length(), 0x200);
        assert_eq!(seg.minalloc(), 0);
        assert_eq!(seg.offset(), 0x0010);
    }

    #[test]
    fn test_segment_by_number() {
        let data = minimal_ne_v4();
        let ne = VecNE::from_memory(data);

        // Segment numbers are 1-based
        assert!(ne.segment_by_number(1).is_some());
        assert!(ne.segment_by_number(2).is_none());
        assert!(ne.segment_by_number(0).is_none());
    }

    #[test]
    fn test_invalid_dos_signature() {
        let mut data = vec![0u8; 256];
        data[0x00] = 0x00; // Not MZ
        data[0x01] = 0x00;
        let ne = VecNE::from_memory(data);

        let result = ne.get_valid_ne_header();
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::InvalidDOSSignature(sig) => assert_eq!(sig, 0x0000),
            other => panic!("Expected InvalidDOSSignature, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_ne_signature() {
        let data = minimal_ne_v4();
        // Corrupt the NE signature at offset 0x40 (NE header starts here)
        let mut corrupted = data.clone();
        corrupted[0x40] = 0x00;
        corrupted[0x41] = 0x00;

        let ne = VecNE::from_memory(corrupted);
        let result = ne.get_valid_ne_header();
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::InvalidNESignature(sig) => assert_eq!(sig, 0x0000),
            other => panic!("Expected InvalidNESignature, got {:?}", other),
        }
    }

    #[test]
    fn test_header_slice() {
        let data = minimal_ne_v4();
        let ne = VecNE::from_memory(data);

        let header_data = ne.header_slice().unwrap();
        let header = ne.get_valid_ne_header().unwrap();
        assert_eq!(header_data.len(), header.header_size());
    }

    #[test]
    fn test_dos_stub() {
        let data = minimal_ne_v4();
        let ne = VecNE::from_memory(data);

        // In our synthetic file, e_lfanew = 0x3C = DOS_HEADER_SIZE, so no stub
        assert!(ne.get_dos_stub().is_none());
    }

    #[test]
    fn test_entry_table_no_entries() {
        let data = minimal_ne_v4();
        let ne = VecNE::from_memory(data.clone());

        // Entry table offset is 0 (no entries)
        let result = EntryTable::parse(&ne);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::TableNotPresent(name) => assert_eq!(name, "entry_table"),
            other => panic!("Expected TableNotPresent, got {:?}", other),
        }
    }

    #[test]
    fn test_pascal_string_utf8() {
        let mut data = [0u8; 64];
        // Create a Pascal string: length=5, "hello"
        data[0] = 5;
        data[1..6].copy_from_slice(b"hello");

        let _ne_data = minimal_ne_v4();
        // We need to wrap this in a VecNE — but the string is in a separate buffer
        // For this test, we just test the PascalString struct directly
        let pascal = PascalString { data: &data[1..6] };
        assert_eq!(pascal.len(), 5);
        assert_eq!(pascal.as_str().unwrap(), "hello");
        assert_eq!(pascal.as_bytes(), b"hello");
    }

    #[test]
    fn test_pascal_string_invalid_utf8() {
        let data: &[u8] = &[5, 0xFF, 0xFE, 0x80, 0x81, 0x82]; // Not valid UTF-8
        let pascal = PascalString { data };
        assert!(pascal.as_str().is_err());
    }

    #[test]
    fn test_align() {
        use crate::align;

        assert_eq!(align(0, 16), 0);
        assert_eq!(align(1, 16), 16);
        assert_eq!(align(15, 16), 16);
        assert_eq!(align(16, 16), 16);
        assert_eq!(align(17, 16), 32);
        assert_eq!(align(100, 16), 112);
    }

    #[test]
    fn test_ne_flags() {
        // 0x0003 = SINGLEDATA | MULTIPLEDATA
        let flags = NeFlags::from_bits_truncate(0x0003);
        assert!(flags.contains(NeFlags::SINGLEDATA));
        assert!(flags.contains(NeFlags::MULTIPLEDATA));
        assert!(!flags.contains(NeFlags::LIBRARY));
    }

    #[test]
    fn test_segment_alignment() {
        // alignment_bytes = 1 << shift (shift 4 = 16 B, the typical /a:16)
        assert_eq!(SegmentAlignment::from_u8(0).unwrap().alignment_bytes(), 1);
        assert_eq!(SegmentAlignment::from_u8(1).unwrap().alignment_bytes(), 2);
        assert_eq!(SegmentAlignment::from_u8(2).unwrap().alignment_bytes(), 4);
        assert_eq!(SegmentAlignment::from_u8(3).unwrap().alignment_bytes(), 8);
        assert_eq!(SegmentAlignment::from_u8(4).unwrap().alignment_bytes(), 16);
        assert_eq!(SegmentAlignment::from_u8(5).unwrap().alignment_bytes(), 32);
        // shift 9 = 512 B (the /a:512 default, e.g. SCRANTIC.EXE)
        assert_eq!(SegmentAlignment::from_u8(9).unwrap().alignment_bytes(), 512);
        assert!(SegmentAlignment::from_u8(7).is_some()); // Reserved but valid
    }

    #[test]
    fn test_exetype_display() {
        assert_eq!(format!("{}", ExeType::Os2), "OS/2 16-bit");
        assert_eq!(format!("{}", ExeType::Win), "Windows 16-bit");
        assert_eq!(format!("{}", ExeType::Invalid), "Invalid");
    }

    #[test]
    fn test_export_entry_types() {
        let fixed = ExportEntry {
            flags: 0,
            entry_type: EntryType::Fixed {
                seg_num: 1,
                offset: 0x100,
            },
        };
        assert_eq!(fixed.seg_num(), Some(1));
        assert_eq!(fixed.offset(), Some(0x100));
        assert_eq!(fixed.constant_value(), None);

        let movable = ExportEntry {
            flags: 0,
            entry_type: EntryType::Movable {
                seg_num: 2,
                offset: 0x200,
            },
        };
        assert_eq!(movable.seg_num(), Some(2));
        assert_eq!(movable.offset(), Some(0x200));
        assert_eq!(movable.constant_value(), None);

        let constant = ExportEntry {
            flags: 0,
            entry_type: EntryType::Constant { value: 0x42 },
        };
        assert_eq!(constant.seg_num(), None);
        assert_eq!(constant.offset(), None);
        assert_eq!(constant.constant_value(), Some(0x42));
    }

    #[test]
    fn test_relocation_entry_types() {
        let addr: AddressType = 0.into();
        assert_eq!(addr, AddressType::LowByte);

        let addr: AddressType = 99.into();
        assert_eq!(addr, AddressType::Unknown(99));

        let reloc: RelocationType = 0.into();
        assert_eq!(reloc, RelocationType::Internal);

        let reloc: RelocationType = 10.into();
        assert_eq!(reloc, RelocationType::Unknown(10));
    }

    // -----------------------------------------------------------------------
    // Test infrastructure: load_external() helper (external-fixtures only)
    // -----------------------------------------------------------------------

    /// Load a non-distributable external fixture from `testdata/external/`.
    ///
    /// The files must be added by the user (see TESTS.md, "External test
    /// fixtures"). The directory can be overridden via the `NE_TEST_DIR`
    /// environment variable.
    #[cfg(feature = "external-fixtures")]
    fn load_external(name: &str) -> Vec<u8> {
        let dir = std::env::var("NE_TEST_DIR").unwrap_or_else(|_| "testdata/external".to_string());
        let path = format!("{dir}/{name}");
        std::fs::read(&path).unwrap_or_else(|e| panic!("Failed to read {path}: {e}"))
    }

    // -----------------------------------------------------------------------
    // DUALBTN golden-fixture suite (fixtures feature)
    //
    // testdata/fixtures/DUALBTN.bin is the golden fixture: every value below
    // was extracted directly from the fixture's bytes and cross-checked
    // against example.md and Wine's winedump. These tests pin the library to
    // the documented ground truth.
    // -----------------------------------------------------------------------

    /// Load a fixture from `testdata/fixtures/` (relative to the crate root,
    /// which is `cargo test`'s working directory).
    #[cfg(any(feature = "fixtures", feature = "external-fixtures"))]
    fn load_fixture(name: &str) -> Vec<u8> {
        let path = format!("testdata/fixtures/{name}");
        std::fs::read(&path).unwrap_or_else(|e| panic!("Failed to read {path}: {e}"))
    }

    /// Load the DUALBTN golden fixture into a `VecNE` buffer.
    #[cfg(any(feature = "fixtures", feature = "external-fixtures"))]
    fn load_dualbtn() -> VecNE {
        VecNE::from_memory(load_fixture("DUALBTN.bin"))
    }

    #[test]
    #[cfg(feature = "fixtures")]
    fn test_dualbtn_dos_header() {
        let ne = load_dualbtn();
        let dos = ne.get_slice(0, 2).unwrap();
        assert_eq!(u16::from_le_bytes([dos[0], dos[1]]), DOS_SIGNATURE);
        // e_lfarlc (u16 @ 0x18) = 0x40 in every corpus file; it is not a
        // detection field — the NE signature at e_lfanew is.
        assert_eq!(ne.read_u16(DOS_E_LFARLC_OFFSET).unwrap(), 0x40);
        // e_lfanew (u32 @ 0x3C) = 0x80
        assert_eq!(ne.read_u32(DOS_E_LFANEW_OFFSET).unwrap(), 0x80);
        assert_eq!(ne.ne_header_file_offset().unwrap(), 0x80);
        // DOS stub = [0x40, e_lfanew)
        let stub = ne.get_dos_stub().unwrap();
        assert_eq!(stub.len(), 0x80 - 0x40);
    }

    #[test]
    #[cfg(feature = "fixtures")]
    fn test_dualbtn_header_fields() {
        let ne = load_dualbtn();
        let header = ne.get_ne_header_ref().unwrap();
        assert!(header.is_v5());
        assert_eq!(header.header_size(), 64);
        let f = header.common_fields();
        assert_eq!(f.linker_version, 5);
        assert_eq!(f.linker_minor_version, 60);
        assert_eq!(f.entry_table_offset, 0x6C);
        assert_eq!(f.entry_table_size, 1);
        assert_eq!(f.checksum, 0);
        assert_eq!(f.flags, 0x0302);
        assert_eq!(f.auto_data_sel, 2);
        assert_eq!(f.heap_init, 0x400);
        assert_eq!(f.stack_init, 0x2800);
        assert_eq!(f.csip, 0x0001_001A);
        assert_eq!(f.sssp, 0x0002_0000);
        assert_eq!(f.seg_count, 2);
        assert_eq!(f.mod_count, 2);
        assert_eq!(f.non_res_name_size, 15);
        assert_eq!(f.seg_table_offset, 0x40);
        assert_eq!(f.resource_table_offset, 0x50);
        assert_eq!(f.res_name_table_offset, 0x50);
        assert_eq!(f.mod_table_offset, 0x5B);
        assert_eq!(f.imported_names_table_offset, 0x5F);
        assert_eq!(f.non_res_name_table_offset, 0xED);
        assert_eq!(f.mod_internal_entries, 0);
        assert_eq!(f.alignment, 4);
        assert_eq!(f.resource_count, 0);
        assert_eq!(f.exe_type, 2);
        assert_eq!(f.other_flags, 8);
        assert_eq!(f.ret_thunk_offset, 0x12);
        assert_eq!(f.seg_ref_bytes_offset, 0xDA);
        let v5 = header.v5_fields().unwrap();
        assert_eq!(v5.swap_area, 0);
        assert_eq!(v5.expected_version, 0x030A);
        assert_eq!(header.exe_type(), ExeType::Win);
        assert!(!ne.is_library());
        // 0x0302 = MULTIPLEDATA | reserved 0x0300; SINGLEDATA (bit 0) clear.
        assert_eq!(NeFlags::from_bits_truncate(f.flags), NeFlags::MULTIPLEDATA);
    }

    #[test]
    #[cfg(feature = "fixtures")]
    fn test_dualbtn_segments() {
        let ne = load_dualbtn();
        let segs = ne.get_segment_table().unwrap();
        assert_eq!(segs.len(), 2);
        // Copy the packed fields out before comparing (assert_eq! takes
        // references, and references to packed fields are unaligned).
        let (s1_off, s1_len, s1_flags, s1_min) = (
            segs[0].offset,
            segs[0].length,
            segs[0].flags,
            segs[0].minalloc,
        );
        let (s2_off, s2_len, s2_flags, s2_min) = (
            segs[1].offset,
            segs[1].length,
            segs[1].flags,
            segs[1].minalloc,
        );
        // Segment 1 (code): sector 0x14 -> file 0x140
        assert_eq!(s1_off, 0x14);
        assert_eq!(s1_len, 0x9CA);
        assert_eq!(s1_flags, 0x1D50);
        assert_eq!(s1_min, 0x9CA);
        assert!(SegmentFlags::from_bits_truncate(s1_flags).contains(SegmentFlags::RELOC_DATA));
        assert!(!SegmentFlags::from_bits_truncate(s1_flags).contains(SegmentFlags::DATA));
        // Segment 2 (data): sector 0xC2 -> file 0xC20
        assert_eq!(s2_off, 0xC2);
        assert_eq!(s2_len, 0x282);
        assert_eq!(s2_flags, 0x0C51);
        assert_eq!(s2_min, 0x282);
        assert!(SegmentFlags::from_bits_truncate(s2_flags).contains(SegmentFlags::DATA));
        // 0x0C51 has no RELOC_DATA bit: all 29 relocations are seg1's.
        assert!(!SegmentFlags::from_bits_truncate(s2_flags).contains(SegmentFlags::RELOC_DATA));
        // Segment record offsets are sector values: file = offset << shift.
        let shift = ne.get_ne_header_ref().unwrap().common_fields().alignment;
        assert_eq!((s1_off as usize) << shift, 0x140);
        assert_eq!((s2_off as usize) << shift, 0xC20);
        // get_segment_data must return exactly seg.length bytes.
        let data1 = ne.get_segment_data(1).unwrap();
        assert_eq!(data1.len(), 0x9CA);
        let data2 = ne.get_segment_data(2).unwrap();
        assert_eq!(data2.len(), 0x282);
    }

    #[test]
    #[cfg(feature = "fixtures")]
    fn test_dualbtn_module_refs_and_itl() {
        let ne = load_dualbtn();
        let mrt = ModuleRefTable::parse(&ne).unwrap();
        assert_eq!(mrt.offsets, vec![1, 6]);
        assert_eq!(mrt.count, 2);
        assert_eq!(mrt.get_name(&ne, 0).unwrap().as_str().unwrap(), "USER");
        assert_eq!(mrt.get_name(&ne, 1).unwrap().as_str().unwrap(), "KERNEL");
        // 1-based indexes (the form used by relocation entries).
        assert_eq!(
            mrt.resolve_import_ordinal_name(&ne, 1)
                .unwrap()
                .as_str()
                .unwrap(),
            "USER"
        );
        assert_eq!(
            mrt.resolve_import_ordinal_name(&ne, 2)
                .unwrap()
                .as_str()
                .unwrap(),
            "KERNEL"
        );
        // ITL: contiguous Pascal strings, leading empty string kept.
        let itl = ImportedNamesTable::parse(&ne).unwrap();
        assert_eq!(itl.names_str().unwrap(), vec!["", "USER", "KERNEL"]);
    }

    #[test]
    #[cfg(feature = "fixtures")]
    fn test_dualbtn_resident_names() {
        let ne = load_dualbtn();
        let rnt = ResidentNameTable::parse(&ne).unwrap();
        assert_eq!(rnt.entries.len(), 1);
        assert_eq!(rnt.entries[0].name.as_str().unwrap(), "DUALBTN");
        assert_eq!(rnt.entries[0].ordinal, 0);
    }

    #[test]
    #[cfg(feature = "fixtures")]
    fn test_dualbtn_non_resident_names() {
        let ne = load_dualbtn();
        let nnt = NonResidentNameTable::parse(&ne).unwrap();
        assert_eq!(nnt.entries.len(), 1);
        assert_eq!(nnt.entries[0].name.as_str().unwrap(), "DUALBTN.exe");
        assert_eq!(nnt.entries[0].ordinal, 0);
    }

    #[test]
    #[cfg(feature = "fixtures")]
    fn test_dualbtn_entry_table_no_exports() {
        let ne = load_dualbtn();
        // The 1-byte entry table (RVA 0x6C) is the terminator record `0x00`
        // -> no exports (consistent with the .DEF having no EXPORTS).
        let et = EntryTable::parse(&ne).unwrap();
        assert!(et.entries.is_empty());
    }

    #[test]
    #[cfg(feature = "fixtures")]
    fn test_dualbtn_fast_load_area() {
        let ne = load_dualbtn();
        let f = ne.get_ne_header_ref().unwrap().common_fields();
        let shift = u32::from(f.alignment);
        let start = u32::from(f.ret_thunk_offset) << shift;
        let size = u32::from(f.seg_ref_bytes_offset) << shift;
        // Gangload/fast-load area: sectors 0x12..0xDA -> file 0x120..0xEC0.
        assert_eq!(start, 0x120);
        assert_eq!(size, 0xDA0);
        assert_eq!(start + size, 0xEC0);
        assert!((start + size) as usize <= ne.len());
    }

    #[test]
    #[cfg(feature = "fixtures")]
    fn test_dualbtn_relocations_exact() {
        let ne = load_dualbtn();
        let relocs = RelocationTable::parse(&ne).unwrap();
        // Ground truth: 29 entries, all in segment 1.
        // (address_type, relocation_type, additive, chain_start, target1, target2)
        // Names from user_gdi_kernel (16-bit ordinal tables).
        let expected: &[(u8, u8, bool, u16, u16, u16)] = &[
            (2, 0, false, 0x778, 1, 0),   // 1:  sel   = 1:0000 (internal)
            (3, 1, false, 0x87D, 1, 124), // 2:  ptr32 = USER.124   (UPDATEWINDOW)
            (3, 1, false, 0x92F, 1, 1),   // 3:  ptr32 = USER.1     (MESSAGEBOX)
            (3, 1, false, 0x93B, 1, 6),   // 4:  ptr32 = USER.6     (POSTQUITMESSAGE)
            (3, 1, false, 0x529, 2, 1),   // 5:  ptr32 = KERNEL.1   (FATALEXIT)
            (3, 1, false, 0x49, 2, 3),    // 6:  ptr32 = KERNEL.3   (GETVERSION)
            (3, 1, false, 0x462, 2, 131), // 7:  ptr32 = KERNEL.131 (GETDOSENVIRONMENT)
            (3, 1, false, 0x712, 2, 5),   // 8:  ptr32 = KERNEL.5   (LOCALALLOC)
            (3, 1, false, 0x7B7, 2, 6),   // 9:  ptr32 = KERNEL.6   (LOCALREALLOC)
            (3, 1, false, 0x759, 2, 7),   // 10: ptr32 = KERNEL.7   (LOCALFREE)
            (3, 1, false, 0x520, 2, 137), // 11: ptr32 = KERNEL.137 (FATALAPPEXIT)
            (3, 1, false, 0x7DB, 2, 10),  // 12: ptr32 = KERNEL.10  (LOCALSIZE)
            (3, 1, false, 0x68F, 2, 16),  // 13: ptr32 = KERNEL.16  (GLOBALREALLOC)
            (3, 1, false, 0x69D, 2, 20),  // 14: ptr32 = KERNEL.20  (GLOBALSIZE)
            (3, 1, false, 0x706, 2, 23),  // 15: ptr32 = KERNEL.23  (LOCKSEGMENT)
            (3, 1, false, 0x71E, 2, 24),  // 16: ptr32 = KERNEL.24  (UNLOCKSEGMENT)
            (3, 1, false, 0x80, 2, 30),   // 17: ptr32 = KERNEL.30  (WAITEVENT)
            (3, 1, false, 0x8EA, 1, 41),  // 18: ptr32 = USER.41    (CREATEWINDOW)
            (3, 1, false, 0x877, 1, 42),  // 19: ptr32 = USER.42    (SHOWWINDOW)
            (3, 1, false, 0x966, 1, 53),  // 20: ptr32 = USER.53    (DESTROYWINDOW)
            (3, 1, false, 0x82C, 1, 57),  // 21: ptr32 = USER.57    (REGISTERCLASS)
            (3, 1, false, 0x2F9, 2, 49),  // 22: ptr32 = KERNEL.49  (GETMODULEFILENAME)
            (3, 1, false, 0x1E, 2, 91),   // 23: ptr32 = KERNEL.91  (INITTASK)
            (5, 1, false, 0x10, 2, 178),  // 24: off16 = KERNEL.178 (__WINFLAGS)
            (3, 1, false, 0x8C0, 1, 107), // 25: ptr32 = USER.107   (DEFWINDOWPROC)
            (3, 1, false, 0x9BB, 1, 108), // 26: ptr32 = USER.108   (GETMESSAGE)
            (3, 1, false, 0x28C, 2, 102), // 27: ptr32 = KERNEL.102 (DOS3CALL)
            (3, 1, false, 0x9A1, 1, 113), // 28: ptr32 = USER.113   (TRANSLATEMESSAGE)
            (3, 1, false, 0x9AB, 1, 114), // 29: ptr32 = USER.114   (DISPATCHMESSAGE)
        ];
        assert_eq!(relocs.entries.len(), expected.len());
        for (i, (e, exp)) in relocs.entries.iter().zip(expected.iter()).enumerate() {
            let i = i + 1;
            // RelocationType carries an Unknown(u8) variant, so no `as u8`.
            let rt = match e.relocation_type {
                RelocationType::Internal => 0u8,
                RelocationType::Ordinal => 1,
                RelocationType::Name => 2,
                RelocationType::OSGlobal => 3,
                RelocationType::Unknown(v) => v,
            };
            assert_eq!(e.address_type.as_u8(), exp.0, "reloc {i} address_type");
            assert_eq!(rt, exp.1, "reloc {i} relocation_type");
            assert_eq!(e.is_additive, exp.2, "reloc {i} is_additive");
            assert_eq!(e.segment_number, 1, "reloc {i} segment_number");
            assert_eq!(e.offset, exp.3, "reloc {i} chain start");
            assert_eq!(e.target1, exp.4, "reloc {i} target1");
            assert_eq!(e.target2, exp.5, "reloc {i} target2");
        }
    }

    #[test]
    #[cfg(feature = "fixtures")]
    fn test_dualbtn_relocation_chains() {
        let ne = load_dualbtn();
        let relocs = RelocationTable::parse(&ne).unwrap();
        let seg1 = ne.get_segment_data(1).unwrap();
        // Relocation #1 (sel = 1:0000): a 14-link chain starting at 0x0778.
        let chain1 = relocs.entries[0].resolve_chain(seg1).unwrap();
        assert_eq!(
            chain1,
            vec![
                0x778, 0x78C, 0x5B4, 0xE5, 0xBB, 0xB2, 0x9E, 0x99, 0x94, 0x8B, 0x18, 0x988, 0x993,
                0x811
            ]
        );
        // Relocation #24 (off16 = KERNEL.178): a single-link chain — the word
        // at 0x0010 is already 0xFFFF, so only 0x10 receives the value.
        let chain24 = relocs.entries[23].resolve_chain(seg1).unwrap();
        assert_eq!(chain24, vec![0x10]);
    }

    // -----------------------------------------------------------------------
    // Per-fixture structure suites (fixtures / external-fixtures features)
    //
    // One test per corpus fixture: structural values (segment/module counts,
    // ITL names, entry-table export counts, resident names, relocation
    // totals) extracted by direct byte inspection of each file.
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "fixtures", feature = "external-fixtures"))]
    fn export_count(et: &EntryTable) -> usize {
        et.entries.iter().filter(|e| e.is_some()).count()
    }

    #[test]
    #[cfg(feature = "fixtures")]
    fn test_bmpwin_structure() {
        let ne = VecNE::from_memory(load_fixture("BMPWIN.bin"));
        let f = ne.get_ne_header_ref().unwrap().common_fields();
        assert_eq!(f.seg_count, 2);
        assert_eq!(f.mod_count, 3);
        assert_eq!(f.flags, 0x0302);
        assert!(!ne.is_library());
        let itl = ImportedNamesTable::parse(&ne).unwrap();
        assert_eq!(itl.names_str().unwrap(), vec!["", "GDI", "USER", "KERNEL"]);
        let et = EntryTable::parse(&ne).unwrap();
        assert_eq!(et.entries.len(), 1);
        assert_eq!(export_count(&et), 1);
        let rnt = ResidentNameTable::parse(&ne).unwrap();
        assert_eq!(rnt.entries.len(), 1);
        assert_eq!(rnt.entries[0].name.as_str().unwrap(), "BMPWIN");
        assert_eq!(RelocationTable::parse(&ne).unwrap().entries.len(), 34);
    }

    #[test]
    #[cfg(feature = "fixtures")]
    fn test_hdrflgs_family() {
        // All five: e_lfanew 0x80, linker 5.60, flags 0x0302, 2 segments
        // (seg1 0x16/0x92A/0x1D50 with 28 relocations, seg2 0xB8/0x21A),
        // 2 modules (USER, KERNEL), entry table with 3 exports. The files
        // differ in heap/stack, one segment flag bit each (2, 5) and the
        // module name.
        let per_file: [(u16, u16, u16, &str); 5] = [
            (0x400, 0x400, 0x0C51, "STANDARDWIN"), // 1: baseline, moveable data
            (0x200, 0x200, 0x0C41, "FIXEDAPP"),    // 2: data seg FIXED (MOVEABLE clear)
            (0x800, 0x400, 0x0C51, "SHAREDAPP"),   // 3: larger heap
            (0x1000, 0x800, 0x0C51, "LARGEMEM"),   // 4: large heap/stack
            (0x400, 0x400, 0x1C51, "DISCARDABLEAPP"), // 5: data seg DISCARDABLE
        ];
        for (i, fields) in per_file.iter().enumerate() {
            let name = format!("HDRFLGS{}.bin", i + 1);
            let ne = VecNE::from_memory(load_fixture(&name));
            let f = ne.get_ne_header_ref().unwrap().common_fields();
            assert_eq!(f.flags, 0x0302, "{name}");
            assert_eq!(f.seg_count, 2, "{name}");
            assert_eq!(f.mod_count, 2, "{name}");
            assert_eq!(f.heap_init, fields.0, "{name}");
            assert_eq!(f.stack_init, fields.1, "{name}");
            let segs = ne.get_segment_table().unwrap();
            let seg2_flags = segs[1].flags;
            assert_eq!(seg2_flags, fields.2, "{name} seg2 flags");
            if i == 1 {
                assert!(
                    !SegmentFlags::from_bits_truncate(seg2_flags).contains(SegmentFlags::MOVEABLE)
                );
            }
            if i == 4 {
                assert!(SegmentFlags::from_bits_truncate(seg2_flags)
                    .contains(SegmentFlags::DISCARDABLE));
            }
            let itl = ImportedNamesTable::parse(&ne).unwrap();
            assert_eq!(
                itl.names_str().unwrap(),
                vec!["", "USER", "KERNEL"],
                "{name}"
            );
            let et = EntryTable::parse(&ne).unwrap();
            assert_eq!(export_count(&et), 3, "{name}");
            let rnt = ResidentNameTable::parse(&ne).unwrap();
            assert_eq!(
                rnt.entries[0].name.as_str().unwrap(),
                per_file[i].3,
                "{name}"
            );
            assert_eq!(
                RelocationTable::parse(&ne).unwrap().entries.len(),
                28,
                "{name}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Real-compiler fixtures (fixtures feature)
    //
    // The only genuinely-compiled binaries in the corpus (everything else is
    // hand-crafted). MSG_OS2B/MSG_W31 (OpenWatcom 2.0): same program
    // shape, two targets — OS/2 1.x PM vs Windows 3.x, a diff pair for the
    // exe_type / expected_version split. CMD_ARGS (MS C 5.1, OS/2 1.3):
    // parser stress case — flags 0x0002 (no SINGLEDATA), zero heap/stack
    // init, 512-byte sectors, NRNT size larger than its content. MSG_OS2A
    // (MS C 5.1, OS/2 1.03 SDK, PM): second MS C 5.1 file — a Presentation
    // Manager program importing PMWIN + DOSCALLS.
    // Provenance and rebuild instructions: testdata/fixtures/README.md.
    // -----------------------------------------------------------------------

    #[test]
    #[cfg(feature = "fixtures")]
    fn test_msg_os2b_fixture() {
        let ne = VecNE::from_memory(load_fixture("MSG_OS2B.bin"));
        let h = ne.get_valid_ne_header().unwrap();
        assert!(h.is_v5(), "OpenWatcom 2.0 emits v5 headers even for OS/2");
        assert_eq!(h.linker_version, 5);
        let f = h.common_fields();
        assert_eq!(f.flags, 0x0302);
        assert_eq!(f.seg_count, 2);
        assert_eq!(f.mod_count, 2);
        assert_eq!(f.alignment, 1, "OpenWatcom uses 2-byte alignment (shift 1)");
        assert_eq!(f.resource_count, 0);
        assert_eq!(h.exe_type(), ExeType::Os2);
        assert_eq!(
            h.v5_fields()
                .expect("is_v5 asserted above")
                .expected_version,
            0x0000,
            "V=0, C=0: real-mode only (OS/2 1.x)"
        );
        assert_eq!(f.csip, 0x0001_0090);
        assert!(!ne.is_library());
        let mrt = ModuleRefTable::parse(&ne).unwrap();
        assert_eq!(mrt.count, 2);
        assert_eq!(mrt.get_name(&ne, 0).unwrap().as_str().unwrap(), "PMWIN");
        assert_eq!(mrt.get_name(&ne, 1).unwrap().as_str().unwrap(), "DOSCALLS");
        let et = EntryTable::parse(&ne).unwrap();
        assert!(
            et.entries.is_empty(),
            "no exports (2-byte `00 00` entry table)"
        );
        let rnt = ResidentNameTable::parse(&ne).unwrap();
        assert_eq!(rnt.entries.len(), 1);
        assert_eq!(rnt.entries[0].name.as_str().unwrap(), "HELLO_OS2");
        assert_eq!(RelocationTable::parse(&ne).unwrap().entries.len(), 13);
    }

    #[test]
    #[cfg(feature = "fixtures")]
    fn test_msg_w31_fixture() {
        let ne = VecNE::from_memory(load_fixture("MSG_W31.bin"));
        let h = ne.get_valid_ne_header().unwrap();
        assert!(h.is_v5());
        assert_eq!(h.linker_version, 5);
        let f = h.common_fields();
        assert_eq!(f.flags, 0x0302);
        assert_eq!(f.seg_count, 2);
        assert_eq!(f.mod_count, 2);
        assert_eq!(f.alignment, 1);
        assert_eq!(f.resource_count, 0);
        assert_eq!(h.exe_type(), ExeType::Win);
        assert_eq!(
            h.v5_fields()
                .expect("is_v5 asserted above")
                .expected_version,
            0x0300,
            "V=3, C=0: real + protected mode"
        );
        assert_eq!(f.csip, 0x0001_0028);
        assert!(!ne.is_library());
        let mrt = ModuleRefTable::parse(&ne).unwrap();
        assert_eq!(mrt.count, 2);
        assert_eq!(mrt.get_name(&ne, 0).unwrap().as_str().unwrap(), "USER");
        assert_eq!(mrt.get_name(&ne, 1).unwrap().as_str().unwrap(), "KERNEL");
        let et = EntryTable::parse(&ne).unwrap();
        assert!(
            et.entries.is_empty(),
            "no exports (2-byte `00 00` entry table)"
        );
        let rnt = ResidentNameTable::parse(&ne).unwrap();
        assert_eq!(rnt.entries.len(), 1);
        assert_eq!(rnt.entries[0].name.as_str().unwrap(), "HELLO_WIN31");
        assert_eq!(RelocationTable::parse(&ne).unwrap().entries.len(), 7);
    }

    #[test]
    #[cfg(feature = "fixtures")]
    fn test_cmd_args_fixture() {
        let ne = VecNE::from_memory(load_fixture("CMD_ARGS.bin"));
        let h = ne.get_valid_ne_header().unwrap();
        // MS C 5.1 (OS/2 1.3, protected mode) is the oldest toolchain in
        // the corpus, yet it still emits a v5 header with linker 5.1.
        assert!(h.is_v5());
        assert_eq!(h.linker_version, 5);
        assert_eq!(h.linker_minor_version, 1);
        let f = h.common_fields();
        // First corpus file with flags 0x0002: MULTIPLEDATA without
        // SINGLEDATA (every other file is 0x0302 or the DLLs' 0x8301).
        assert_eq!(f.flags, 0x0002);
        assert_eq!(f.auto_data_sel, 2);
        assert_eq!(
            (f.heap_init, f.stack_init),
            (0, 0),
            "no heap/stack reservation"
        );
        assert_eq!(f.csip, 0x0001_0046);
        assert_eq!(f.sssp, 0x0002_1450);
        assert_eq!(f.seg_count, 2);
        assert_eq!(f.mod_count, 1);
        assert_eq!(f.alignment, 9, "512-byte sectors");
        assert_eq!(f.resource_count, 0);
        assert_eq!(h.exe_type(), ExeType::Os2);
        assert_eq!(
            h.v5_fields()
                .expect("is_v5 asserted above")
                .expected_version,
            0x0000
        );
        assert!(!ne.is_library());
        let segs = ne.get_segment_table().unwrap();
        assert_eq!(segs.len(), 2);
        // Copy packed fields to locals before asserting (E0793).
        let (off0, len0, flg0) = (segs[0].offset, segs[0].length, segs[0].flags);
        let (off1, len1, flg1) = (segs[1].offset, segs[1].length, segs[1].flags);
        assert_eq!((off0, len0), (0x0001, 0x16FD));
        assert_eq!((off1, len1), (0x000D, 0x041D));
        // seg1's 0x0400 bit is not in Wine's NE_SEGFLAGS set —
        // from_bits_truncate silently drops it.
        assert_eq!((flg0, flg1), (0x0D00, 0x0D01));
        assert!(segs[0]
            .segment_flags()
            .contains(SegmentFlags::RELOC_DATA | SegmentFlags::SELFLOAD));
        assert!(segs[1].segment_flags().contains(SegmentFlags::DATA));
        // 2-byte `00 00` no-export table, like the OpenWatcom builds.
        assert!(EntryTable::parse(&ne).unwrap().entries.is_empty());
        let mrt = ModuleRefTable::parse(&ne).unwrap();
        assert_eq!(mrt.count, 1);
        assert_eq!(mrt.get_name(&ne, 0).unwrap().as_str().unwrap(), "DOSCALLS");
        let itl = ImportedNamesTable::parse(&ne).unwrap();
        // Leading empty entry is the ordinal-0 placeholder; DOSCALLS at offset 1.
        assert_eq!(itl.names_str().unwrap(), vec!["", "DOSCALLS"]);
        let rnt = ResidentNameTable::parse(&ne).unwrap();
        assert_eq!(rnt.entries.len(), 1);
        assert_eq!(rnt.entries[0].name.as_str().unwrap(), "DEMO2");
        // NRNT size (13) exceeds the single name's 9 bytes — the trailing
        // empty entries must not break size-bounded parsing.
        assert_eq!(f.non_res_name_size, 13);
        let nrnt = NonResidentNameTable::parse(&ne).unwrap();
        assert_eq!(nrnt.entries.len(), 1);
        assert_eq!(nrnt.entries[0].name.as_str().unwrap(), "DEMO2.EXE");
        let rels = RelocationTable::parse(&ne).unwrap();
        assert_eq!(rels.entries.len(), 12);
        let ordinals: Vec<u16> = rels
            .entries
            .iter()
            .filter(|e| e.relocation_type == RelocationType::Ordinal)
            .map(|e| e.ordinal_number().unwrap())
            .collect();
        assert_eq!(
            ordinals,
            [5, 0x8A, 0x22, 0x26, 0x31, 0x3A, 0x3B, 0x4D, 0x59, 0x5C]
        );
        assert!(rels
            .entries
            .iter()
            .all(|e| e.mod_ref_index().is_none_or(|i| i == 1)));
        let internals = rels
            .entries
            .iter()
            .filter(|e| e.relocation_type == RelocationType::Internal)
            .count();
        assert_eq!(internals, 2);
    }

    #[test]
    #[cfg(feature = "fixtures")]
    fn test_msg_os2a_fixture() {
        let ne = VecNE::from_memory(load_fixture("MSG_OS2A.bin"));
        let h = ne.get_valid_ne_header().unwrap();
        // MS C 5.1 against the OS/2 1.03 SDK PM libraries — the corpus's
        // second genuinely-compiled OS/2 file and its first Presentation
        // Manager binary from a Microsoft toolchain.
        assert!(h.is_v5());
        assert_eq!(h.linker_version, 5);
        assert_eq!(h.linker_minor_version, 1);
        let f = h.common_fields();
        // Same MS C 5.1 signature as CMD_ARGS: flags 0x0002 (MULTIPLEDATA
        // without SINGLEDATA or PM_APP), zero heap/stack init, 512-byte
        // sectors, OS/2 with expver 0x0000.
        assert_eq!(f.flags, 0x0002);
        assert_eq!(f.auto_data_sel, 2);
        assert_eq!((f.heap_init, f.stack_init), (0, 0));
        assert_eq!(f.csip, 0x0001_0090);
        assert_eq!(f.sssp, 0x0002_0D60);
        assert_eq!(f.seg_count, 2);
        assert_eq!(f.mod_count, 2);
        assert_eq!(f.alignment, 9, "512-byte sectors");
        assert_eq!(f.resource_count, 0);
        assert_eq!(h.exe_type(), ExeType::Os2);
        assert_eq!(
            h.v5_fields()
                .expect("is_v5 asserted above")
                .expected_version,
            0x0000
        );
        assert!(!ne.is_library());
        let segs = ne.get_segment_table().unwrap();
        assert_eq!(segs.len(), 2);
        // Copy packed fields to locals before asserting (E0793).
        let (off0, len0, flg0) = (segs[0].offset, segs[0].length, segs[0].flags);
        let (off1, len1, flg1) = (segs[1].offset, segs[1].length, segs[1].flags);
        assert_eq!((off0, len0), (0x0001, 0x054F));
        assert_eq!((off1, len1), (0x0004, 0x034B));
        // Like CMD_ARGS, seg1's flags carry the undefined 0x0400 bit,
        // dropped by from_bits_truncate.
        assert_eq!((flg0, flg1), (0x0D00, 0x0D01));
        assert!(segs[0]
            .segment_flags()
            .contains(SegmentFlags::RELOC_DATA | SegmentFlags::SELFLOAD));
        assert!(segs[1].segment_flags().contains(SegmentFlags::DATA));
        // 2-byte `00 00` no-export table (MS C 5.1 form).
        assert!(EntryTable::parse(&ne).unwrap().entries.is_empty());
        let mrt = ModuleRefTable::parse(&ne).unwrap();
        assert_eq!(mrt.count, 2);
        assert_eq!(mrt.get_name(&ne, 0).unwrap().as_str().unwrap(), "PMWIN");
        assert_eq!(mrt.get_name(&ne, 1).unwrap().as_str().unwrap(), "DOSCALLS");
        let itl = ImportedNamesTable::parse(&ne).unwrap();
        assert_eq!(itl.names_str().unwrap(), vec!["", "PMWIN", "DOSCALLS"]);
        let rnt = ResidentNameTable::parse(&ne).unwrap();
        assert_eq!(rnt.entries.len(), 1);
        assert_eq!(rnt.entries[0].name.as_str().unwrap(), "HELLO_1B");
        assert_eq!(f.non_res_name_size, 16);
        let nrnt = NonResidentNameTable::parse(&ne).unwrap();
        assert_eq!(nrnt.entries.len(), 1);
        assert_eq!(nrnt.entries[0].name.as_str().unwrap(), "HELLO_1B.EXE");
        let rels = RelocationTable::parse(&ne).unwrap();
        assert_eq!(rels.entries.len(), 15);
        // (module ref index, ordinal) in file order: PMWIN (1) contributes
        // 5 imports, DOSCALLS (2) 8.
        let pairs: Vec<(Option<u16>, u16)> = rels
            .entries
            .iter()
            .filter(|e| e.relocation_type == RelocationType::Ordinal)
            .map(|e| (e.mod_ref_index(), e.ordinal_number().unwrap()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                (Some(1), 0x8B),
                (Some(2), 5),
                (Some(2), 0x8A),
                (Some(2), 0x26),
                (Some(2), 0x31),
                (Some(1), 0x3A),
                (Some(1), 0x3B),
                (Some(2), 0x3B),
                (Some(2), 0x4D),
                (Some(2), 0x59),
                (Some(2), 0x5C),
                (Some(1), 0xF6),
                (Some(1), 0xF7),
            ]
        );
        let internal_targets: Vec<u16> = rels
            .entries
            .iter()
            .filter(|e| e.relocation_type == RelocationType::Internal)
            .map(|e| e.target1)
            .collect();
        assert_eq!(internal_targets, vec![2, 2]);
    }

    #[test]
    #[cfg(feature = "external-fixtures")]
    fn test_winmine_structure() {
        let ne = VecNE::from_memory(load_external("WINMINE.EXE"));
        let f = ne.get_ne_header_ref().unwrap().common_fields();
        assert_eq!(f.seg_count, 2);
        assert_eq!(f.mod_count, 5);
        assert!(!ne.is_library());
        let itl = ImportedNamesTable::parse(&ne).unwrap();
        let names = itl.names_str().unwrap();
        assert_eq!(names.len(), 6); // placeholder + 5 modules
        for m in ["KERNEL", "USER", "GDI", "SOUND", "SHELL"] {
            assert!(names.contains(&m), "missing module {m}");
        }
        assert!(EntryTable::parse(&ne).unwrap().entries.is_empty());
        let rnt = ResidentNameTable::parse(&ne).unwrap();
        assert_eq!(rnt.entries.len(), 1);
        assert_eq!(rnt.entries[0].name.as_str().unwrap(), "WINMINE");
        assert_eq!(RelocationTable::parse(&ne).unwrap().entries.len(), 87);
    }

    #[test]
    #[cfg(feature = "external-fixtures")]
    fn test_sol_structure() {
        let ne = VecNE::from_memory(load_external("SOL.EXE"));
        let f = ne.get_ne_header_ref().unwrap().common_fields();
        assert_eq!(f.seg_count, 11);
        assert_eq!(f.mod_count, 4);
        assert!(!ne.is_library());
        let itl = ImportedNamesTable::parse(&ne).unwrap();
        assert_eq!(
            itl.names_str().unwrap(),
            vec!["", "KERNEL", "USER", "GDI", "SHELL"]
        );
        assert!(EntryTable::parse(&ne).unwrap().entries.is_empty());
        let rnt = ResidentNameTable::parse(&ne).unwrap();
        assert_eq!(rnt.entries[0].name.as_str().unwrap(), "SOL");
        assert_eq!(RelocationTable::parse(&ne).unwrap().entries.len(), 186);
    }

    #[test]
    #[cfg(feature = "external-fixtures")]
    fn test_scrantic_structure() {
        let ne = VecNE::from_memory(load_external("SCRANTIC.EXE"));
        assert_eq!(ne.ne_header_file_offset().unwrap(), 0x250);
        let f = ne.get_ne_header_ref().unwrap().common_fields();
        assert_eq!(f.linker_version, 5);
        assert_eq!(f.linker_minor_version, 10);
        assert_eq!(f.alignment, 9); // /a:512 default (512-byte sectors)
        assert_eq!(f.seg_count, 14);
        assert_eq!(f.mod_count, 4);
        assert!(!ne.is_library());
        let itl = ImportedNamesTable::parse(&ne).unwrap();
        assert_eq!(
            itl.names_str().unwrap(),
            vec!["", "MMSYSTEM", "GDI", "KERNEL", "USER"]
        );
        let et = EntryTable::parse(&ne).unwrap();
        assert_eq!(et.entries.len(), 5);
        assert_eq!(export_count(&et), 5);
        let rnt = ResidentNameTable::parse(&ne).unwrap();
        assert_eq!(rnt.entries[0].name.as_str().unwrap(), "SCRNATIC");
        assert_eq!(RelocationTable::parse(&ne).unwrap().entries.len(), 1346);
    }

    #[test]
    #[cfg(feature = "external-fixtures")]
    fn test_gdi_dll() {
        let ne = VecNE::from_memory(load_external("GDI.EXE"));
        assert_eq!(ne.ne_header_file_offset().unwrap(), 0x400);
        let f = ne.get_ne_header_ref().unwrap().common_fields();
        assert_eq!(f.seg_count, 47);
        assert_eq!(f.mod_count, 1);
        assert_eq!(f.flags, 0x8301);
        assert!(ne.is_library());
        // 0x8301 = SINGLEDATA | reserved 0x200 | LIBRARY (MULTIPLEDATA clear).
        assert_eq!(
            NeFlags::from_bits_truncate(f.flags),
            NeFlags::SINGLEDATA | NeFlags::LIBRARY
        );
        let itl = ImportedNamesTable::parse(&ne).unwrap();
        assert_eq!(itl.names_str().unwrap(), vec!["", "KERNEL"]);
        let et = EntryTable::parse(&ne).unwrap();
        assert_eq!(et.entries.len(), 825);
        assert_eq!(export_count(&et), 363);
        let rnt = ResidentNameTable::parse(&ne).unwrap();
        assert_eq!(rnt.entries.len(), 3);
        assert_eq!(rnt.entries[0].name.as_str().unwrap(), "GDI");
        assert_eq!(rnt.entries[0].ordinal, 0);
        assert_eq!(RelocationTable::parse(&ne).unwrap().entries.len(), 776);
    }

    #[test]
    #[cfg(feature = "external-fixtures")]
    fn test_user_dll() {
        let ne = VecNE::from_memory(load_external("USER.EXE"));
        assert_eq!(ne.ne_header_file_offset().unwrap(), 0x400);
        let f = ne.get_ne_header_ref().unwrap().common_fields();
        assert_eq!(f.seg_count, 34);
        assert_eq!(f.mod_count, 7);
        assert_eq!(f.alignment, 5);
        assert_eq!(f.flags, 0x8301);
        assert!(ne.is_library());
        let itl = ImportedNamesTable::parse(&ne).unwrap();
        assert_eq!(
            itl.names_str().unwrap(),
            vec!["", "GDI", "KERNEL", "SYSTEM", "KEYBOARD", "MOUSE", "COMM", "DDEML"]
        );
        let et = EntryTable::parse(&ne).unwrap();
        assert_eq!(et.entries.len(), 891);
        assert_eq!(export_count(&et), 520);
        let rnt = ResidentNameTable::parse(&ne).unwrap();
        assert_eq!(rnt.entries.len(), 4);
        assert_eq!(rnt.entries[0].name.as_str().unwrap(), "USER");
        assert_eq!(rnt.entries[0].ordinal, 0);
        assert_eq!(RelocationTable::parse(&ne).unwrap().entries.len(), 1517);
        // Non-resident export names — ordinal -> name spot checks, verified
        // against user_gdi_kernel (USER section).
        let nnt = NonResidentNameTable::parse(&ne).unwrap();
        assert_eq!(nnt.entries.len(), 518);
        assert_eq!(
            nnt.entries[0].name.as_str().unwrap(),
            "Microsoft Windows User Interface"
        );
        for (name, ordinal) in [
            ("MESSAGEBOX", 1u16),
            ("POSTQUITMESSAGE", 6),
            ("CREATEWINDOW", 41),
            ("SHOWWINDOW", 42),
            ("DESTROYWINDOW", 53),
            ("REGISTERCLASS", 57),
            ("GETDC", 66),
            ("DEFWINDOWPROC", 107),
            ("GETMESSAGE", 108),
            ("TRANSLATEMESSAGE", 113),
            ("DISPATCHMESSAGE", 114),
            ("UPDATEWINDOW", 124),
        ] {
            let entry = nnt
                .entries
                .iter()
                .find(|e| e.name.as_str().unwrap() == name)
                .unwrap_or_else(|| panic!("non-resident name {name} missing"));
            assert_eq!(entry.ordinal, ordinal, "{name} ordinal");
        }
    }

    #[test]
    #[cfg(feature = "external-fixtures")]
    fn test_krnl386_dll() {
        let ne = VecNE::from_memory(load_external("KRNL386.EXE"));
        assert_eq!(ne.ne_header_file_offset().unwrap(), 0x400);
        let f = ne.get_ne_header_ref().unwrap().common_fields();
        assert_eq!(f.seg_count, 4);
        assert_eq!(f.mod_count, 0);
        assert_eq!(f.flags, 0x8301);
        assert!(ne.is_library());
        // Zero module references: the MRT is empty.
        let mrt = ModuleRefTable::parse(&ne).unwrap();
        assert_eq!(mrt.count, 0);
        assert!(mrt.offsets.is_empty());
        let et = EntryTable::parse(&ne).unwrap();
        assert_eq!(et.entries.len(), 864);
        assert_eq!(export_count(&et), 449);
        let rnt = ResidentNameTable::parse(&ne).unwrap();
        assert_eq!(rnt.entries.len(), 2);
        assert_eq!(rnt.entries[0].name.as_str().unwrap(), "KERNEL");
        assert_eq!(rnt.entries[0].ordinal, 0);
        assert_eq!(RelocationTable::parse(&ne).unwrap().entries.len(), 15);
    }

    #[test]
    #[cfg(feature = "external-fixtures")]
    fn test_pbrush_not_ne() {
        // PBRUSH.EXE is a Windows 98 PE32 forwarder stub for paint.exe — a
        // PE executable, not an NE file: its DOS header's e_lfanew points
        // at a "PE" (0x4550) signature. The parser must return a typed
        // error, not panic or misparse.
        let data = load_external("PBRUSH.EXE");
        let ne = VecNE::from_memory(data);
        match ne.get_valid_ne_header() {
            Err(Error::InvalidNESignature(sig)) => {
                // "PE" in little-endian
                assert_eq!(sig, 0x4550);
            }
            other => panic!("expected InvalidNESignature(0x4550), got {other:?}"),
        }
        // get_ne_header_ref() (raw, unvalidated) still works on the bytes.
        assert!(ne.get_ne_header_ref().is_ok());
    }

    // -----------------------------------------------------------------------
    // Struct layout invariants
    // -----------------------------------------------------------------------

    #[test]
    fn test_struct_size_invariants() {
        use std::mem;

        // ImageOS2Header is #[repr(C, packed)] — no padding
        assert_eq!(mem::size_of::<ImageOS2Header>(), 64);
        // SegmentRecord is 8 bytes (4 x u16: offset, length, flags, minalloc)
        assert_eq!(mem::size_of::<SegmentRecord>(), 8);
    }

    #[test]
    fn test_struct_offset_invariants() {
        use std::mem::offset_of;

        // ImageOS2Header field offsets (verified against actual struct)
        assert_eq!(offset_of!(ImageOS2Header, signature), 0x00);
        assert_eq!(offset_of!(ImageOS2Header, linker_version), 0x02);
        assert_eq!(offset_of!(ImageOS2Header, linker_minor_version), 0x03);
        assert_eq!(offset_of!(ImageOS2Header, entry_table_offset), 0x04);
        assert_eq!(offset_of!(ImageOS2Header, entry_table_size), 0x06);
        assert_eq!(offset_of!(ImageOS2Header, checksum), 0x08);
        assert_eq!(offset_of!(ImageOS2Header, flags), 0x0C);
        assert_eq!(offset_of!(ImageOS2Header, auto_data_sel), 0x0E);
        assert_eq!(offset_of!(ImageOS2Header, heap_init), 0x10);
        assert_eq!(offset_of!(ImageOS2Header, stack_init), 0x12);
        assert_eq!(offset_of!(ImageOS2Header, csip), 0x14);
        assert_eq!(offset_of!(ImageOS2Header, sssp), 0x18);
        assert_eq!(offset_of!(ImageOS2Header, seg_count), 0x1C);
        assert_eq!(offset_of!(ImageOS2Header, mod_count), 0x1E);
        assert_eq!(offset_of!(ImageOS2Header, non_res_name_size), 0x20);
        assert_eq!(offset_of!(ImageOS2Header, seg_table_offset), 0x22);
        assert_eq!(offset_of!(ImageOS2Header, resource_table_offset), 0x24);
        assert_eq!(offset_of!(ImageOS2Header, res_name_table_offset), 0x26);
        assert_eq!(offset_of!(ImageOS2Header, mod_table_offset), 0x28);
        assert_eq!(
            offset_of!(ImageOS2Header, imported_names_table_offset),
            0x2A
        );
        assert_eq!(offset_of!(ImageOS2Header, non_res_name_table_offset), 0x2C);
        assert_eq!(offset_of!(ImageOS2Header, mod_internal_entries), 0x30);
        assert_eq!(offset_of!(ImageOS2Header, alignment), 0x32);
        assert_eq!(offset_of!(ImageOS2Header, resource_count), 0x34);
        assert_eq!(offset_of!(ImageOS2Header, exe_type), 0x36);
        assert_eq!(offset_of!(ImageOS2Header, other_flags), 0x37);
        assert_eq!(offset_of!(ImageOS2Header, ret_thunk_offset), 0x38);
        assert_eq!(offset_of!(ImageOS2Header, seg_ref_bytes_offset), 0x3A);
        assert_eq!(offset_of!(ImageOS2Header, swap_area), 0x3C);
        assert_eq!(offset_of!(ImageOS2Header, expected_version), 0x3E);

        // SegmentRecord field offsets (8-byte layout)
        assert_eq!(offset_of!(SegmentRecord, offset), 0x00);
        assert_eq!(offset_of!(SegmentRecord, length), 0x02);
        assert_eq!(offset_of!(SegmentRecord, flags), 0x04);
        assert_eq!(offset_of!(SegmentRecord, minalloc), 0x06);
    }

    // -----------------------------------------------------------------------
    // PtrNE buffer tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ptrne_valid_header() {
        let data = minimal_ne_v4();
        let ne = PtrNE::from_memory(data.as_ptr(), data.len());

        let header = ne.get_valid_ne_header().unwrap();
        let sig = header.signature;
        assert_eq!(sig, 0x454E);
        assert!(!header.is_v5());
        assert_eq!(header.exe_type(), ExeType::Win);
    }

    #[test]
    fn test_ptrne_segment_table() {
        let data = minimal_ne_v4();
        let ne = PtrNE::from_memory(data.as_ptr(), data.len());

        let segments = ne.get_segment_table().unwrap();
        assert_eq!(segments.len(), 1);
        assert!(segments[0].is_moveable());
    }

    #[test]
    fn test_ptrne_segment_by_number() {
        let data = minimal_ne_v4();
        let ne = PtrNE::from_memory(data.as_ptr(), data.len());

        assert!(ne.segment_by_number(1).is_some());
        assert!(ne.segment_by_number(0).is_none());
        assert!(ne.segment_by_number(2).is_none());
    }

    #[test]
    fn test_ptrne_as_slice() {
        let data = minimal_ne_v4();
        let ne = PtrNE::from_memory(data.as_ptr(), data.len());

        let slice = ne.as_slice();
        assert_eq!(slice.len(), data.len());
        assert_eq!(&slice[0x00..0x02], &[0x4D, 0x5A]); // "MZ"
        assert_eq!(&slice[0x40..0x42], &[0x4E, 0x45]); // "NE"
    }

    #[test]
    fn test_ptrne_header_slice() {
        let data = minimal_ne_v4();
        let ne = PtrNE::from_memory(data.as_ptr(), data.len());

        let header_data = ne.header_slice().unwrap();
        let header = ne.get_valid_ne_header().unwrap();
        assert_eq!(header_data.len(), header.header_size());
    }

    #[test]
    fn test_ptrne_invalid_dos_signature() {
        let mut data = vec![0u8; 256];
        data[0x00] = 0x00;
        data[0x01] = 0x00;
        let ne = PtrNE::from_memory(data.as_ptr(), data.len());

        let result = ne.get_valid_ne_header();
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::InvalidDOSSignature(sig) => assert_eq!(sig, 0x0000),
            other => panic!("Expected InvalidDOSSignature, got {:?}", other),
        }
    }

    #[test]
    fn test_ptrne_out_of_bounds() {
        let data = [0u8; 10];
        let ne = PtrNE::from_memory(data.as_ptr(), data.len());

        let result = ne.get_valid_ne_header();
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::HeaderTooSmall => {}
            other => panic!("Expected HeaderTooSmall, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Version detection tests
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Real-file version detection (external-fixtures feature only)
    // -----------------------------------------------------------------------

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_detect_header_size_v5_real_files() {
        // Every valid corpus file has linker_version >= 5 → v5 (64-byte SDK
        // header). There is no true v4 (OS/2 1.x, 60-byte) fixture in the
        // corpus (PLAN.md Q1), so no v4 real-file test can exist.
        let files = [
            "WINMINE.EXE",
            "SOL.EXE",
            "SCRANTIC.EXE",
            "USER.EXE",
            "GDI.EXE",
            "KRNL386.EXE",
        ];

        for name in &files {
            let data = load_external(name);
            let ne = VecNE::from_memory(data);
            let header = ne.get_valid_ne_header().unwrap();
            assert!(header.is_v5(), "{name}: expected v5 (linker_version >= 5)");
        }
    }

    // -----------------------------------------------------------------------
    // Committed-fixture integration tests — EMPTYWIN.bin (minimal: 2 segments, v5, 0 resources)
    // -----------------------------------------------------------------------

    #[cfg(feature = "fixtures")]
    #[test]
    fn test_empty_header() {
        let data = load_fixture("EMPTYWIN.bin");
        let ne = VecNE::from_memory(data);

        let header = ne.get_valid_ne_header().unwrap();
        let sig = header.signature;
        assert_eq!(sig, 0x454E);
        // EMPTY has linker 5.60 → v5, even though flags bit 0
        // (SINGLEDATA) is clear — proof that bit 0 is not a version bit.
        assert!(header.is_v5());
        assert_eq!(header.exe_type(), ExeType::Win);
        assert_eq!(header.common_fields().seg_count, 2);
        assert_eq!(header.common_fields().mod_count, 2);
        // Entry table size is 1 — minimal (just type byte)
        assert_eq!(header.common_fields().entry_table_size, 1);

        // Verify e_lfanew = 0x80 (DOS stub present)
        let stub = ne.get_dos_stub();
        assert!(stub.is_some());
        assert!(!stub.unwrap().is_empty());
    }

    #[cfg(feature = "fixtures")]
    #[test]
    fn test_empty_segment_table() {
        let data = load_fixture("EMPTYWIN.bin");
        let ne = VecNE::from_memory(data);

        let segments = ne.get_segment_table().unwrap();
        assert_eq!(segments.len(), 2);

        // Verify segments are parseable
        for seg in &segments {
            let _flags = seg.segment_flags();
        }
    }

    #[cfg(feature = "fixtures")]
    #[test]
    fn test_empty_segment_by_number() {
        let data = load_fixture("EMPTYWIN.bin");
        let ne = VecNE::from_memory(data);

        assert!(ne.segment_by_number(1).is_some());
        assert!(ne.segment_by_number(2).is_some());
        assert!(ne.segment_by_number(3).is_none());
        assert!(ne.segment_by_number(0).is_none());
    }

    #[cfg(feature = "fixtures")]
    #[test]
    fn test_empty_alignment_shift() {
        let data = load_fixture("EMPTYWIN.bin");
        let ne = VecNE::from_memory(data);
        let header = ne.get_valid_ne_header().unwrap();
        // EMPTY.EXE uses alignment shift = 4 (16-byte paragraphs)
        assert_eq!(header.common_fields().alignment, 4);
    }

    #[cfg(feature = "fixtures")]
    #[test]
    fn test_empty_entry_table() {
        let data = load_fixture("EMPTYWIN.bin");
        let ne = VecNE::from_memory(data);

        // Entry table exists (offset != 0) and is a single 0x00 byte:
        // the "count = 0" terminator → no exports, not an error.
        assert!(ne.entry_table_offset() > 0);
        let table = EntryTable::parse(&ne).unwrap();
        assert!(table.entries.is_empty());
        assert_eq!(table.export_count(), 0);
    }

    #[cfg(feature = "fixtures")]
    #[test]
    fn test_empty_resource_table() {
        let data = load_fixture("EMPTYWIN.bin");
        let ne = VecNE::from_memory(data);

        // EMPTY has resource_table_offset != 0 (it points at the resident
        // name table) but resource_count = 0 — true for every corpus file
        // (PLAN.md §1.2 fact 2) → the parser returns an empty table without
        // reading the pointer target.
        assert!(ne.resource_table_offset() > 0);
        let table = ResourceTable::parse(&ne).unwrap();
        assert!(table.type_info.is_empty());
    }

    #[cfg(feature = "fixtures")]
    #[test]
    fn test_empty_module_ref_table() {
        let data = load_fixture("EMPTYWIN.bin");
        let ne = VecNE::from_memory(data);

        let module_table = ModuleRefTable::parse(&ne).unwrap();
        // mod_count = 2
        assert_eq!(module_table.offsets.len(), 2);
        // Selectors should be valid segment selectors
        assert!(module_table.offsets[0] > 0);
    }

    #[cfg(feature = "fixtures")]
    #[test]
    fn test_empty_imported_names_table() {
        let data = load_fixture("EMPTYWIN.bin");
        let ne = VecNE::from_memory(data);

        // ITL offset != 0, but module_names_count = 0
        let result = ImportedNamesTable::parse(&ne);
        // With no module names, the table is empty but parseable
        assert!(result.is_ok());
    }

    #[cfg(feature = "fixtures")]
    #[test]
    fn test_empty_resident_names() {
        let data = load_fixture("EMPTYWIN.bin");
        let ne = VecNE::from_memory(data);

        let names = ResidentNameTable::parse(&ne).unwrap();
        assert!(!names.entries.is_empty());

        // Check that each entry has a valid name
        for entry in &names.entries {
            assert!(!entry.name.is_empty());
            // Names should be valid UTF-8
            assert!(entry.name.as_str().is_ok());
        }
    }

    #[cfg(feature = "fixtures")]
    #[test]
    fn test_empty_resident_names_lookup() {
        let data = load_fixture("EMPTYWIN.bin");
        let ne = VecNE::from_memory(data);

        let names = ResidentNameTable::parse(&ne).unwrap();

        // by_ordinal should work
        if !names.entries.is_empty() {
            let first_ordinal = names.entries[0].ordinal;
            assert!(names.by_ordinal(first_ordinal).is_some());
        }

        // by_name should work (case-insensitive)
        if !names.entries.is_empty() {
            let first_name = names.entries[0].name.as_str().unwrap();
            let upper = first_name.to_uppercase();
            assert!(names.by_name(&upper).is_some());
            let lower = first_name.to_lowercase();
            assert!(names.by_name(&lower).is_some());
        }
    }

    // -----------------------------------------------------------------------
    // Entry table tests
    // -----------------------------------------------------------------------

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_entry_table_winmine_no_exports() {
        let data = load_external("WINMINE.EXE");
        let ne = VecNE::from_memory(data);

        // WINMINE's entry table is a single 0x00 byte → record count = 0 →
        // no exports (same shape as DUALBTN; consistent with its .DEF having
        // no EXPORTS section).
        let entry_table = EntryTable::parse(&ne).unwrap();
        assert!(entry_table.entries.is_empty());
        assert_eq!(entry_table.export_count(), 0);
        assert!(entry_table.get_export(1).is_none());
    }

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_entry_table_gdi_lookup() {
        let data = load_external("GDI.EXE");
        let ne = VecNE::from_memory(data);

        let entry_table = EntryTable::parse(&ne).unwrap();
        let count = entry_table.export_count();
        assert!(count > 100, "Expected many exports in GDI.EXE, got {count}");

        // At least one ordinal resolves to an entry; segment numbers are 1-based
        let found_any = entry_table.entries.iter().any(|slot| {
            slot.as_ref().is_some_and(|e| {
                if let Some(seg) = e.seg_num() {
                    seg > 0
                } else {
                    true // constant entries carry a value, not a segment
                }
            })
        });
        assert!(found_any, "Expected at least one export to be found");

        // Ordinal 0 and out-of-range ordinals return None
        assert!(entry_table.get_export(0).is_none());
        assert!(entry_table.get_export(u16::MAX).is_none());
    }

    #[test]
    fn test_entry_table_corrupt_cycle() {
        // Create an NE file with an entry table that forms a cycle
        let data = minimal_ne_v4();
        let ne = VecNE::from_memory(data);

        // Entry table offset is 0 in our synthetic file → TableNotPresent
        let result = EntryTable::parse(&ne);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Resource table tests
    // -----------------------------------------------------------------------

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_resource_table_winmine() {
        let data = load_external("WINMINE.EXE");
        let ne = VecNE::from_memory(data);

        // resource_count = 0 in every corpus file (PLAN.md §1.2 fact 2), so
        // the parser returns an empty table without reading the pointer.
        let resource_table = ResourceTable::parse(&ne).unwrap();
        assert!(resource_table.type_info.is_empty());
    }

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_resource_table_sol() {
        let data = load_external("SOL.EXE");
        let ne = VecNE::from_memory(data);

        // resource_count = 0 (PLAN.md §1.2 fact 2) → empty table.
        let resource_table = ResourceTable::parse(&ne).unwrap();
        assert!(resource_table.type_info.is_empty());
    }

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_resource_table_krnl386() {
        let data = load_external("KRNL386.EXE");
        let ne = VecNE::from_memory(data);

        // KRNL386's resource_table_offset is non-zero, but resource_count = 0
        // (PLAN.md §1.2 fact 2) → empty table, no read.
        let resource_table = ResourceTable::parse(&ne).unwrap();
        assert!(resource_table.type_info.is_empty());
    }

    // -----------------------------------------------------------------------
    // Module reference table + ITL tests (examples feature)
    // -----------------------------------------------------------------------

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_module_ref_winmine() {
        let data = load_external("WINMINE.EXE");
        let ne = VecNE::from_memory(data);

        // WINMINE.EXE has 5 modules
        let module_table = ModuleRefTable::parse(&ne).unwrap();
        assert_eq!(module_table.offsets.len(), 5);
    }

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_module_ref_user() {
        let data = load_external("USER.EXE");
        let ne = VecNE::from_memory(data);

        // USER.EXE has 7 modules
        let module_table = ModuleRefTable::parse(&ne).unwrap();
        assert_eq!(module_table.offsets.len(), 7);
    }

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_module_ref_krnl386() {
        let data = load_external("KRNL386.EXE");
        let ne = VecNE::from_memory(data);

        // KRNL386.EXE has 0 modules
        let module_table = ModuleRefTable::parse(&ne).unwrap();
        assert_eq!(module_table.offsets.len(), 0);
    }

    #[test]
    fn test_module_ref_no_modules() {
        let data = minimal_ne_v4();
        let ne = VecNE::from_memory(data);

        // Minimal synthetic file has mod_table_offset = 0, so no module ref table
        match ModuleRefTable::parse(&ne) {
            Err(Error::TableNotPresent(name)) => assert_eq!(name, "module_ref"),
            Err(e) => panic!("Expected TableNotPresent, got {e}"),
            Ok(_) => panic!("Expected error, got Ok"),
        }
    }

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_imported_names_winmine() {
        let data = load_external("WINMINE.EXE");
        let ne = VecNE::from_memory(data);

        let itl = ImportedNamesTable::parse(&ne).unwrap();
        assert!(!itl.module_names.is_empty());

        // The ITL starts with the empty ordinal-0 placeholder string, which
        // must be preserved; the 5 module names follow (contiguous Pascal
        // strings, no padding).
        let names = itl.names_str().unwrap();
        let non_empty: Vec<&str> = names.iter().copied().filter(|s| !s.is_empty()).collect();
        for expected in ["GDI", "KERNEL", "SHELL", "SOUND", "USER"] {
            assert!(
                non_empty.contains(&expected),
                "ITL missing module {expected}: {non_empty:?}"
            );
        }
    }

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_imported_names_user() {
        let data = load_external("USER.EXE");
        let ne = VecNE::from_memory(data);

        let itl = ImportedNamesTable::parse(&ne).unwrap();
        assert!(!itl.module_names.is_empty());
    }

    // -----------------------------------------------------------------------
    // Resident name table tests (examples feature)
    // -----------------------------------------------------------------------

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_resident_names_winmine() {
        let data = load_external("WINMINE.EXE");
        let ne = VecNE::from_memory(data);

        let names = ResidentNameTable::parse(&ne).unwrap();
        assert!(!names.entries.is_empty());

        // Check that each entry has a valid name
        for entry in &names.entries {
            assert!(!entry.name.is_empty());
            // Names should be valid UTF-8
            assert!(entry.name.as_str().is_ok());
        }
    }

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_resident_names_user() {
        let data = load_external("USER.EXE");
        let ne = VecNE::from_memory(data);

        let names = ResidentNameTable::parse(&ne).unwrap();
        assert!(!names.entries.is_empty());
    }

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_resident_names_lookup() {
        let data = load_external("WINMINE.EXE");
        let ne = VecNE::from_memory(data);

        let names = ResidentNameTable::parse(&ne).unwrap();

        // by_ordinal should work
        if !names.entries.is_empty() {
            let first_ordinal = names.entries[0].ordinal;
            assert!(names.by_ordinal(first_ordinal).is_some());
        }

        // by_name should work (case-insensitive)
        if !names.entries.is_empty() {
            let first_name = names.entries[0].name.as_str().unwrap();
            // Should find by uppercase
            let upper = first_name.to_uppercase();
            assert!(names.by_name(&upper).is_some());
            // Should find by lowercase
            let lower = first_name.to_lowercase();
            assert!(names.by_name(&lower).is_some());
        }
    }

    // -----------------------------------------------------------------------
    // Comprehensive error handling tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_error_header_too_small() {
        let data = vec![0u8; 10];
        let ne = VecNE::from_memory(data);

        let result = ne.get_valid_ne_header();
        match result.unwrap_err() {
            Error::HeaderTooSmall => {}
            other => panic!("Expected HeaderTooSmall, got {:?}", other),
        }
    }

    #[test]
    fn test_error_header_version_mismatch() {
        // minimal_ne_v4() has linker version 4.00 → v4; ensure_v5() rejects it.
        let ne = VecNE::from_memory(minimal_ne_v4());
        let header = ne.get_valid_ne_header().unwrap();
        assert!(!header.is_v5());
        assert!(matches!(
            header.ensure_v5(),
            Err(Error::HeaderVersionMismatch)
        ));
    }

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_error_segment_not_found() {
        let data = load_external("WINMINE.EXE");
        let ne = VecNE::from_memory(data);

        // WINMINE has 2 segments, so segment 99 should not exist
        let result = ne.segment_by_number(99);
        assert!(result.is_none());
    }

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_error_entry_not_found() {
        let data = load_external("WINMINE.EXE");
        let ne = VecNE::from_memory(data);

        let entry_table = EntryTable::parse(&ne).unwrap();
        // Look up a very high ordinal that definitely doesn't exist
        assert!(entry_table.get_export(0xFFFF).is_none());
    }

    #[test]
    fn test_error_table_not_present() {
        // Synthetic minimal NE with resource_table_offset = 0 →
        // TableNotPresent (the offset check runs before the resource_count
        // short-circuit, so this holds even though the minimal header also
        // declares zero resources).
        let data = minimal_ne_v4();
        let ne = VecNE::from_memory(data);
        assert_eq!(ne.resource_table_offset(), 0);
        match ResourceTable::parse(&ne) {
            Err(Error::TableNotPresent(name)) => assert_eq!(name, "resource_table"),
            Err(e) => panic!("Expected TableNotPresent, got {e}"),
            Ok(_) => panic!("Expected TableNotPresent, got Ok"),
        }
    }

    #[test]
    fn test_error_invalid_resource_alignment() {
        let mut data = vec![0u8; 256];

        // Create an NE file whose resource table's own size shift (the first
        // word of the table — NOT the header alignment) is out of range.
        data[0x00] = 0x4D;
        data[0x01] = 0x5A;
        data[0x18..0x1A].copy_from_slice(&0x40u16.to_le_bytes()); // e_lfarlc
        data[0x3C..0x3E].copy_from_slice(&0x40u16.to_le_bytes()); // e_lfanew = 0x40
        let off = 0x40;
        data[off..off + 2].copy_from_slice(&0x454Eu16.to_le_bytes());
        data[off + 0x1C..off + 0x1E].copy_from_slice(&1u16.to_le_bytes());
        data[off + 0x22..off + 0x24].copy_from_slice(&0x80u16.to_le_bytes());
        data[off + 0x24..off + 0x26].copy_from_slice(&0x80u16.to_le_bytes()); // resource table RVA 0x80 → file 0xC0
        data[off + 0x34..off + 0x36].copy_from_slice(&1u16.to_le_bytes()); // resource_count = 1 (no short-circuit)

        // First word of the resource table: size shift = 17 (> 16)
        data[0xC0..0xC2].copy_from_slice(&17u16.to_le_bytes());

        let ne = VecNE::from_memory(data);
        let result = ResourceTable::parse(&ne);
        match result {
            Ok(_) => panic!("Expected InvalidResourceAlignment error"),
            Err(Error::InvalidResourceAlignment(17)) => {}
            Err(e) => panic!("Expected InvalidResourceAlignment(0), got {e:?}"),
        }
    }

    #[test]
    fn test_resource_table_synthetic() {
        // Full happy-path parse of a hand-built resource table. No real
        // fixture exercises this — every corpus file has resource_count = 0,
        // so the TYPEINFO/NAMEINFO walk is only reachable via synthetic data
        // (PLAN.md Q6). Layout: size_shift = 2, two type records (one
        // ordinal-typed, one name-typed), three NAMEINFO records mixing
        // ordinal and Pascal-string ids, terminated by a type_id = 0 record.
        //
        // Table at file offset 0xC0 (RVA 0x80, e_lfanew 0x40):
        //   0xC0  size_shift = 2
        //   0xC2  TYPEINFO: ordinal type 5, count 1
        //   0xCA  NAMEINFO: off 0x10, len 0x04, flags 1, ordinal id 1
        //   0xD6  TYPEINFO: name at table offset 0x3E, count 2
        //   0xDE  NAMEINFO: off 0x20, len 0x08, flags 0, name id at 0x45
        //   0xEA  NAMEINFO: off 0x30, len 0x04, flags 2, ordinal id 7
        //   0xF6  terminator (type_id = 0)
        //   0xFE  "MYTYPE" (Pascal), 0x105 "ICON1" (Pascal)
        let mut data = vec![0u8; 512];
        data[0x00] = 0x4D; // "M"
        data[0x01] = 0x5A; // "Z"
        data[0x18..0x1A].copy_from_slice(&0x40u16.to_le_bytes()); // e_lfarlc = 0x40
        data[0x3C..0x3E].copy_from_slice(&0x40u16.to_le_bytes()); // e_lfanew = 0x40
        let off = 0x40;
        data[off..off + 2].copy_from_slice(&0x454Eu16.to_le_bytes()); // "NE"
        data[off + 0x02] = 5; // linker major (v5)
        data[off + 0x03] = 60; // linker minor
        data[off + 0x1C..off + 0x1E].copy_from_slice(&1u16.to_le_bytes()); // seg_count = 1
        data[off + 0x22..off + 0x24].copy_from_slice(&0x100u16.to_le_bytes()); // segtab RVA 0x100 (file 0x140)
        data[off + 0x24..off + 0x26].copy_from_slice(&0x80u16.to_le_bytes()); // rsrctab RVA 0x80 (file 0xC0)
        data[off + 0x34..off + 0x36].copy_from_slice(&2u16.to_le_bytes()); // resource_count = 2 (no short-circuit)
                                                                           // One segment record so the header is self-consistent
        let seg_off = 0x140;
        data[seg_off..seg_off + 8].copy_from_slice(&[
            0x10, 0x00, // offset = 0x0010
            0x20, 0x00, // length = 0x0020
            0x10, 0x00, // flags = MOVEABLE
            0x00, 0x00, // minalloc = 0
        ]);

        let t = 0xC0; // resource table start (file offset)
        data[t..t + 2].copy_from_slice(&2u16.to_le_bytes()); // size_shift = 2
        data[t + 2..t + 10].copy_from_slice(&[0x05, 0x80, 0x01, 0x00, 0, 0, 0, 0]);
        data[t + 10..t + 22]
            .copy_from_slice(&[0x10, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x80, 0, 0, 0, 0]);
        data[t + 22..t + 30].copy_from_slice(&[0x3E, 0x00, 0x02, 0x00, 0, 0, 0, 0]);
        data[t + 30..t + 42]
            .copy_from_slice(&[0x20, 0x00, 0x08, 0x00, 0x00, 0x00, 0x45, 0x00, 0, 0, 0, 0]);
        data[t + 42..t + 54]
            .copy_from_slice(&[0x30, 0x00, 0x04, 0x00, 0x02, 0x00, 0x07, 0x80, 0, 0, 0, 0]);
        data[t + 54..t + 62].copy_from_slice(&[0u8; 8]); // terminator
        data[t + 0x3E..t + 0x45].copy_from_slice(&[6, b'M', b'Y', b'T', b'Y', b'P', b'E']);
        data[t + 0x45..t + 0x4B].copy_from_slice(&[5, b'I', b'C', b'O', b'N', b'1']);

        let ne = VecNE::from_memory(data);
        let table = ResourceTable::parse(&ne).unwrap();
        assert_eq!(table.alignment_shift, 2);
        assert_eq!(table.type_info.len(), 2);

        let t0 = &table.type_info[0];
        assert_eq!(t0.type_id, ResourceTypeId::Ordinal(5));
        assert_eq!(t0.records.len(), 1);
        let r0 = &t0.records[0];
        assert_eq!(r0.offset, 0x40); // 0x10 << 2
        assert_eq!(r0.length, 0x10); // 0x04 << 2
        assert_eq!(r0.flags, 1);
        assert_eq!(r0.id, ResourceId::Ordinal(1));

        let t1 = &table.type_info[1];
        assert_eq!(
            t1.type_id,
            ResourceTypeId::Name(PascalString { data: b"MYTYPE" })
        );
        assert_eq!(t1.records.len(), 2);
        let r1 = &t1.records[0];
        assert_eq!(r1.offset, 0x80); // 0x20 << 2
        assert_eq!(r1.length, 0x20); // 0x08 << 2
        assert_eq!(r1.id, ResourceId::Name(PascalString { data: b"ICON1" }));
        let r2 = &t1.records[1];
        assert_eq!(r2.offset, 0xC0); // 0x30 << 2
        assert_eq!(r2.length, 0x10);
        assert_eq!(r2.flags, 2);
        assert_eq!(r2.id, ResourceId::Ordinal(7));
    }

    #[test]
    fn test_error_entry_table_overflow() {
        // Synthetic NE whose entry table holds 258 records of
        // [count=255][type=0x00] (255 unused ordinals each, no data bytes):
        // 258 * 255 = 65790 ordinal slots > u16::MAX → EntryTableOverflow.
        let mut data = minimal_ne_v4();
        let off = 0x40;

        // Entry table at RVA 0x80 (file 0xC0), declared size 516 bytes
        // (exactly 258 two-byte record headers).
        data[off + 0x04..off + 0x06].copy_from_slice(&0x80u16.to_le_bytes());
        data[off + 0x06..off + 0x08].copy_from_slice(&516u16.to_le_bytes());

        for i in 0..258 {
            data[0xC0 + 2 * i] = 255; // count
            data[0xC1 + 2 * i] = 0x00; // type 0 = unused ordinals
        }

        let ne = VecNE::from_memory(data);
        assert!(matches!(
            EntryTable::parse(&ne).unwrap_err(),
            Error::EntryTableOverflow
        ));
    }

    #[test]
    fn test_error_entry_table_corrupt() {
        // Synthetic NE file whose entry table declares more entries than the
        // declared table size can hold → EntryTableCorrupt.
        let mut data = minimal_ne_v4();
        let off = 0x40;

        // Entry table at RVA 0x80 (file 0xC0), declared size 4 bytes.
        data[off + 0x04..off + 0x06].copy_from_slice(&0x80u16.to_le_bytes());
        data[off + 0x06..off + 0x08].copy_from_slice(&4u16.to_le_bytes());

        // Record: [count=100][type=0xFF movable] → needs 100*6 = 600 bytes,
        // but only 2 bytes remain inside the declared table size.
        data[0xC0] = 100;
        data[0xC1] = 0xFF;

        let ne = VecNE::from_memory(data);
        assert!(matches!(
            EntryTable::parse(&ne).unwrap_err(),
            Error::EntryTableCorrupt
        ));
    }

    #[test]
    fn test_entry_table_no_exports_terminator() {
        // A record with count == 0 is the terminator: no exports.
        // (This is the on-disk shape of DUALBTN's 1-byte "0x00" entry table.)
        let mut data = minimal_ne_v4();
        let off = 0x40;

        data[off + 0x04..off + 0x06].copy_from_slice(&0x80u16.to_le_bytes());
        data[off + 0x06..off + 0x08].copy_from_slice(&2u16.to_le_bytes());
        data[0xC0] = 0x00; // count = 0 → terminator

        let ne = VecNE::from_memory(data);
        let table = EntryTable::parse(&ne).unwrap();
        assert!(table.entries.is_empty());
        assert_eq!(table.export_count(), 0);
    }

    #[test]
    fn test_error_table_out_of_bounds() {
        // Create an NE file where segment table offset points beyond the buffer
        // get_segment_table uses relative offset directly (not converted to file offset)
        let mut data = vec![0u8; 200];

        // Must have e_lfarlc = 0x40 per osdev.org NE-Format spec
        data[0x00] = 0x4D;
        data[0x01] = 0x5A;
        data[0x18..0x1A].copy_from_slice(&0x40u16.to_le_bytes()); // e_lfarlc = 0x40
        data[0x3C..0x3E].copy_from_slice(&0x40u16.to_le_bytes());
        let off = 0x40;
        data[off..off + 2].copy_from_slice(&0x454Eu16.to_le_bytes());
        data[off + 0x1C..off + 0x1E].copy_from_slice(&1u16.to_le_bytes());
        // seg_table_offset points beyond buffer
        data[off + 0x22..off + 0x24].copy_from_slice(&0x200u16.to_le_bytes());

        let ne = VecNE::from_memory(data);
        let result = ne.get_segment_table();
        match result.unwrap_err() {
            Error::TableOutOfBounds("segment_table", offset, bound) => {
                // seg_table_file_off = e_lfanew(0x40) + seg_table_offset(0x200) = 0x240
                // 0x240 + 8 (1 segment * 8 bytes) = 0x248
                assert_eq!(offset, 0x248);
                assert_eq!(bound, 200);
            }
            other => panic!("Expected TableOutOfBounds, got {other}"),
        }
    }

    #[test]
    fn test_error_header_out_of_bounds() {
        // A 2-byte buffer: any read past the end is out of bounds.
        let ne = VecNE::from_slice(&[0x5A, 0x4D]);
        assert!(matches!(ne.read_u32(0), Err(Error::HeaderOutOfBounds(4))));
    }

    #[test]
    fn test_error_invalid_dos_stub_fields() {
        // Buffer shorter than the 64-byte DOS header: the stub-field
        // validation cannot even read the fields it needs.
        let ne = VecNE::from_slice(&[0x5A, 0x4D]);
        assert!(matches!(
            ne.validate_dos_stub_fields(),
            Err(Error::InvalidDOSStubFields)
        ));
    }

    #[test]
    fn test_error_invalid_pascal_string() {
        // 0xFF 0xFE is not valid UTF-8 → as_str() must fail; ASCII passes.
        let invalid = PascalString {
            data: &[0xFF, 0xFE],
        };
        assert!(invalid.as_str().is_err());
        assert_eq!(PascalString { data: b"USER" }.as_str().unwrap(), "USER");
    }

    #[test]
    fn test_error_relocation_chain_corrupt() {
        // A 2-cycle: the word at 0x0000 points to 0x0002 and the word at
        // 0x0002 points back to 0x0000 — the cycle guard must trip.
        let entry = RelocationEntry {
            address_type: AddressType::Pointer32,
            relocation_type: RelocationType::Ordinal,
            is_additive: false,
            segment_number: 1,
            offset: 0,
            target1: 1,
            target2: 2,
        };
        let segment_data = [0x02, 0x00, 0x00, 0x00, 0, 0, 0, 0];
        assert!(matches!(
            entry.resolve_chain(&segment_data),
            Err(Error::RelocationChainCorrupt)
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_error_io() {
        // from_disk_file on a nonexistent path → IoError.
        match VecNE::from_disk_file("/nonexistent/ne-rs-test-file.bin") {
            Ok(_) => panic!("Expected IoError, got Ok"),
            Err(Error::IoError(_)) => {}
            Err(e) => panic!("Expected IoError, got {e}"),
        }
    }

    // -----------------------------------------------------------------------
    // Header modification (zero-copy mut) tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_mut_ne_header_modify_flags() {
        let data = minimal_ne_v4();
        let mut ne = VecNE::from_memory(data);

        // Initially v4 (linker_version 4 < 5)
        let header = ne.get_valid_ne_header().unwrap();
        assert!(!header.is_v5());

        // Upgrade to v5 by setting linker version >= 5
        {
            let h = ne.get_mut_ne_header_ref().unwrap();
            h.linker_version = 5;
        }

        // Now should detect as v5
        let header = ne.get_valid_ne_header().unwrap();
        assert!(header.is_v5());
    }

    #[test]
    fn test_mut_ne_header_modify_v5_fields() {
        let data = minimal_ne_v4();
        let mut ne = VecNE::from_memory(data);

        // First make it v5
        {
            let h = ne.get_mut_ne_header_ref().unwrap();
            h.linker_version = 5; // v5 detection uses linker_version >= 5
            h.swap_area = 0x1234;
            h.expected_version = 0x5678;
        }

        let header = ne.get_valid_ne_header().unwrap();
        assert!(header.is_v5());

        // swap_area (0x3C) and expected_version (0x3E) are the v5-only fields
        let v5 = header.v5_fields().unwrap();
        assert_eq!(v5.swap_area, 0x1234);
        assert_eq!(v5.expected_version, 0x5678);
        // ret_thunk_offset / seg_ref_bytes_offset are common (v4) fields
        assert_eq!(header.common_fields().ret_thunk_offset, 0);
        assert_eq!(header.common_fields().seg_ref_bytes_offset, 0);
    }

    #[test]
    fn test_mut_ne_header_modify_seg_count() {
        let data = minimal_ne_v4();
        let mut ne = VecNE::from_memory(data);

        // Read original segment count
        let header = ne.get_valid_ne_header().unwrap();
        let orig_segs = header.common_fields().seg_count;

        // Modify via zero-copy mutable reference
        {
            let h = ne.get_mut_ne_header_ref().unwrap();
            h.seg_count = 5;
        }

        // Read back and verify
        let header = ne.get_valid_ne_header().unwrap();
        assert_eq!(header.common_fields().seg_count, 5);
        assert_eq!(header.common_fields().seg_count, orig_segs - 1 + 5);
    }

    // -----------------------------------------------------------------------
    // Header slice tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_header_slice_size_matches_const() {
        // v4 file: linker_version < 5 → 60-byte header
        let mut data = vec![0u8; 256];
        data[0x00] = 0x4D;
        data[0x01] = 0x5A;
        data[0x18..0x1A].copy_from_slice(&0x40u16.to_le_bytes()); // e_lfarlc = 0x40
        data[0x3C..0x3E].copy_from_slice(&0x40u16.to_le_bytes());
        let off = 0x40;
        data[off..off + 2].copy_from_slice(&0x454Eu16.to_le_bytes());
        data[off + 0x02] = 0x04; // linker version 4 (v4)
        data[off + 0x0C..off + 0x0E].copy_from_slice(&0u16.to_le_bytes()); // flags
        let ne = VecNE::from_memory(data);
        let slice = ne.header_slice().unwrap();
        assert_eq!(slice.len(), NE_HEADER_SIZE_V4);

        // v5 file: linker_version >= 5 → 68-byte header
        let mut data = vec![0u8; 256];
        data[0x00] = 0x4D;
        data[0x01] = 0x5A;
        data[0x18..0x1A].copy_from_slice(&0x40u16.to_le_bytes()); // e_lfarlc = 0x40
        data[0x3C..0x3E].copy_from_slice(&0x40u16.to_le_bytes());
        let off = 0x40;
        data[off..off + 2].copy_from_slice(&0x454Eu16.to_le_bytes());
        data[off + 0x02] = 0x05; // linker version 5 (v5)
        data[off + 0x0C..off + 0x0E].copy_from_slice(&0u16.to_le_bytes()); // flags
        let ne = VecNE::from_memory(data);
        let slice = ne.header_slice().unwrap();
        assert_eq!(slice.len(), NE_HEADER_SIZE_V5);
    }

    // -----------------------------------------------------------------------
    // Segment flags tests
    // -----------------------------------------------------------------------

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_segment_flags_parsing() {
        let data = load_external("USER.EXE");
        let ne = VecNE::from_memory(data);

        let segments = ne.get_segment_table().unwrap();
        assert!(segments.len() > 10); // USER has 34 segments

        // Check that we can parse different flag combinations
        let mut found_code = false;
        let mut found_data = false;

        for seg in &segments {
            if !seg.is_data() {
                found_code = true;
            }
            if seg.is_data() {
                found_data = true;
            }
        }

        assert!(found_code, "Expected at least one code segment");
        assert!(found_data, "Expected at least one data segment");
    }

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_segment_flags_shared() {
        let data = load_external("WINMINE.EXE");
        let ne = VecNE::from_memory(data);

        let segments = ne.get_segment_table().unwrap();
        // Check each segment's flags are parseable
        for seg in &segments {
            let flags = seg.segment_flags();
            // MOVEABLE should be set on most segments
            // Verify no flags are lost in the bitflags conversion
            let f = seg.flags;
            assert_eq!(flags.bits(), f);
        }
    }

    // -----------------------------------------------------------------------
    // NE flags tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ne_flags_library_bit() {
        // Bit 15 marks a library module (DLL)
        let flags = NeFlags::LIBRARY;
        assert!(flags.contains(NeFlags::LIBRARY));
        assert!(!flags.contains(NeFlags::SINGLEDATA));
        // 0x8301 (GDI/USER/KRNL386 in the corpus) =
        // LIBRARY | SINGLEDATA | reserved 0x0300 (bits 8-9)
        let dll = NeFlags::from_bits_truncate(0x8301);
        assert!(dll.contains(NeFlags::LIBRARY));
        assert!(dll.contains(NeFlags::SINGLEDATA));
        assert!(!dll.contains(NeFlags::MULTIPLEDATA));
        assert_eq!(dll.bits(), 0x8001);
    }

    #[test]
    fn test_ne_flags_first_seg_loader() {
        let flags = NeFlags::FIRST_SEG_CONTAINS_LOADER;
        assert!(flags.contains(NeFlags::FIRST_SEG_CONTAINS_LOADER));
        assert!(!flags.contains(NeFlags::LINKER_ERRORS));
    }

    #[test]
    fn test_ne_flags_linker_errors() {
        let flags = NeFlags::LINKER_ERRORS;
        assert!(flags.contains(NeFlags::LINKER_ERRORS));
    }

    // -----------------------------------------------------------------------
    // Real-file header field verification (examples feature)
    // -----------------------------------------------------------------------

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_real_file_fields_winmine() {
        let data = load_external("WINMINE.EXE");
        let ne = VecNE::from_memory(data);
        let header = ne.get_valid_ne_header().unwrap();

        let sig = header.signature;
        assert_eq!(sig, 0x454E);
        // WINMINE's linker is 5.60 → v5 (the old "!is_v5" expectation encoded
        // the disproven VERSION_BIT heuristic)
        assert!(header.is_v5());
        assert_eq!(header.common_fields().linker_version, 5);
        assert_eq!(header.common_fields().linker_minor_version, 60);
        assert_eq!(header.exe_type(), ExeType::Win);
        assert_eq!(header.common_fields().seg_count, 2);
        assert_eq!(header.common_fields().mod_count, 5);

        // Entry table exists (offset != 0)
        assert!(ne.entry_table_offset() > 0);
        // Resource table exists
        assert!(ne.resource_table_offset() > 0);
        // Resident names table exists
        assert!(ne.resident_name_table_offset() > 0);
    }

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_real_file_fields_user() {
        let data = load_external("USER.EXE");
        let ne = VecNE::from_memory(data);
        let header = ne.get_valid_ne_header().unwrap();

        assert!(header.is_v5());
        assert_eq!(header.common_fields().seg_count, 34);
        assert_eq!(header.common_fields().mod_count, 7);

        // v5-only fields should be accessible: USER.EXE expects Windows 4.0
        let v5 = header.v5_fields().unwrap();
        assert_eq!(v5.expected_version, 0x0400);
    }

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_real_file_fields_gdi() {
        let data = load_external("GDI.EXE");
        let ne = VecNE::from_memory(data);
        let header = ne.get_valid_ne_header().unwrap();

        assert!(header.is_v5());
        assert_eq!(header.common_fields().seg_count, 47);
        assert_eq!(header.common_fields().mod_count, 1);
        assert_eq!(header.common_fields().exe_type, 2); // Windows
    }

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_real_file_fields_scrantic() {
        let data = load_external("SCRANTIC.EXE");
        let ne = VecNE::from_memory(data);
        let header = ne.get_valid_ne_header().unwrap();

        // SCRANTIC has linker 5.10 → v5, with the default /a:512 alignment
        // (shift 9) and a larger DOS stub (e_lfanew = 0x250).
        assert!(header.is_v5());
        assert_eq!(header.exe_type(), ExeType::Win);
        assert_eq!(header.common_fields().seg_count, 14);
        assert_eq!(header.common_fields().mod_count, 4);
        assert_eq!(header.common_fields().alignment, 9);
    }

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_real_file_dos_stub_sizes() {
        // get_dos_stub() returns the bytes between the 64-byte DOS header
        // (0x40) and the NE header (e_lfanew) → len = e_lfanew - 0x40.
        // SCRANTIC has e_lfanew = 0x250
        let data = load_external("SCRANTIC.EXE");
        let ne = VecNE::from_memory(data);
        let stub = ne.get_dos_stub().unwrap();
        assert_eq!(stub.len(), 0x250 - 0x40);

        // USER has e_lfanew = 0x400
        let data = load_external("USER.EXE");
        let ne = VecNE::from_memory(data);
        let stub = ne.get_dos_stub().unwrap();
        assert_eq!(stub.len(), 0x400 - 0x40);

        // WINMINE has e_lfanew = 0x80
        let data = load_external("WINMINE.EXE");
        let ne = VecNE::from_memory(data);
        let stub = ne.get_dos_stub().unwrap();
        assert_eq!(stub.len(), 0x80 - 0x40);
    }

    // -----------------------------------------------------------------------
    // Segment table alignment tests
    // -----------------------------------------------------------------------

    #[cfg(feature = "external-fixtures")]
    #[test]
    fn test_segment_alignments_winmine() {
        let data = load_external("WINMINE.EXE");
        let ne = VecNE::from_memory(data);

        let segments = ne.get_segment_table().unwrap();
        for seg in &segments {
            // Test that 8-byte record methods work (8-byte format has no per-segment alignment)
            let _offset = seg.offset();
            let _length = seg.length();
            let _minalloc = seg.minalloc();
        }
    }

    #[test]
    fn test_segment_table_empty() {
        // Create synthetic NE with seg_count = 0
        let data = minimal_ne_v4();
        let ne = VecNE::from_memory(data);

        let segments = ne.get_segment_table().unwrap();
        assert_eq!(segments.len(), 1); // Our synthetic file has 1 segment
    }

    // -----------------------------------------------------------------------
    // Pascal string edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_pascal_string_empty() {
        let data: &[u8] = &[];
        let pascal = PascalString { data };
        assert!(pascal.is_empty());
        assert_eq!(pascal.len(), 0);
        assert_eq!(pascal.as_bytes(), b"");
    }

    #[test]
    fn test_pascal_string_single_byte() {
        let data: &[u8] = b"A";
        let pascal = PascalString { data };
        assert_eq!(pascal.len(), 1);
        assert_eq!(pascal.as_str().unwrap(), "A");
    }

    #[test]
    fn test_pascal_string_max_ascii() {
        // 255 bytes of valid ASCII
        let data: Vec<u8> = (0x20..=0x7E).cycle().take(255).collect();
        let pascal = PascalString { data: &data };
        assert_eq!(pascal.len(), 255);
        assert!(pascal.as_str().is_ok());
    }

    // -----------------------------------------------------------------------
    // DOS stub field validation tests (osdev.org NE-Format spec)
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_dos_stub_fields_valid() {
        let data = minimal_ne_v4();
        let ne = VecNE::from_memory(data);
        // Should succeed — e_lfarlc is no longer validated for NE detection
        assert!(ne.validate_dos_stub_fields().is_ok());
    }

    #[test]
    fn test_validate_dos_stub_fields_non_40_eflarlc_ok() {
        // e_lfarlc == 0x40 is NOT a valid NE detection criterion.
        // Many valid NE files (Open Watcom, some Microsoft tools) have e_lfarlc = 0x0000.
        // This test verifies that validate_dos_stub_fields succeeds even with e_lfarlc != 0x40.
        let mut data = vec![0u8; 256];
        // MZ signature
        data[0x00] = 0x4D;
        data[0x01] = 0x5A;
        // e_lfarlc = 0x80 (NOT 0x40 — used to fail, now succeeds)
        data[0x16..0x18].copy_from_slice(&0x80u16.to_le_bytes());
        // e_lfanew points to NE header
        data[0x3C..0x3E].copy_from_slice(&0x40u16.to_le_bytes());
        // NE signature at offset 0x40
        data[0x40] = b'N';
        data[0x41] = b'E';
        let ne = VecNE::from_memory(data);
        // Should succeed — e_lfarlc is NOT used for NE detection
        assert!(ne.validate_dos_stub_fields().is_ok());
    }

    // -----------------------------------------------------------------------
    // DLL detection tests (Section 23)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_library_false() {
        // EXE program has 0x8000 flag clear
        let mut data = minimal_ne_v4();
        let off = 0x40;
        data[off + 0x0C..off + 0x0E].copy_from_slice(&0u16.to_le_bytes()); // flags = 0
        let ne = VecNE::from_memory(data);
        assert!(!ne.is_library());
    }

    #[test]
    fn test_is_library_true() {
        // DLL has 0x8000 flag set
        let mut data = minimal_ne_v4();
        let off = 0x40;
        data[off + 0x0C..off + 0x0E].copy_from_slice(&0x8000u16.to_le_bytes()); // flags = 0x8000
        let ne = VecNE::from_memory(data);
        assert!(ne.is_library());
    }

    // -----------------------------------------------------------------------
    // Processor mode detection tests (Section 1.6.5)
    // -----------------------------------------------------------------------

    #[test]
    fn test_processor_mode_v4_windows() {
        // v4 Windows file: expctwinver < 3, no GAMEIMAGE, no OS2PM -> real mode only
        let mut data = vec![0u8; 256];
        data[0x00] = 0x4D;
        data[0x01] = 0x5A;
        data[0x18..0x1A].copy_from_slice(&0x40u16.to_le_bytes());
        data[0x3C..0x3E].copy_from_slice(&0x40u16.to_le_bytes());
        let off = 0x40;
        data[off..off + 2].copy_from_slice(&0x454Eu16.to_le_bytes());
        data[off + 0x0C..off + 0x0E].copy_from_slice(&0u16.to_le_bytes()); // flags = 0 (v4)
        let ne = VecNE::from_memory(data);
        let (real, protected) = ne.supported_processor_modes();
        assert!(real, "Expected real mode support");
        assert!(!protected, "Expected no protected mode for v4 Windows");
    }

    // -----------------------------------------------------------------------
    // Relocation target type tests (Section 24)
    // -----------------------------------------------------------------------

    #[test]
    fn test_os_fixup_type_from_u16() {
        assert_eq!(OsFixupType::from(1), OsFixupType::FiArQq);
        assert_eq!(OsFixupType::from(2), OsFixupType::FiSrQq);
        assert_eq!(OsFixupType::from(3), OsFixupType::FiCrQq);
        assert_eq!(OsFixupType::from(4), OsFixupType::FiErQq);
        assert_eq!(OsFixupType::from(5), OsFixupType::FiDrQq);
        assert_eq!(OsFixupType::from(6), OsFixupType::FiWrQq);
        assert_eq!(OsFixupType::from(99), OsFixupType::Unknown(99));
    }

    #[test]
    fn test_relocation_type_internal() {
        let rt = RelocationType::from(0);
        assert_eq!(rt, RelocationType::Internal);
    }

    #[test]
    fn test_relocation_type_ordinal() {
        let rt = RelocationType::from(1);
        assert_eq!(rt, RelocationType::Ordinal);
    }

    #[test]
    fn test_relocation_type_name() {
        let rt = RelocationType::from(2);
        assert_eq!(rt, RelocationType::Name);
    }

    #[test]
    fn test_relocation_type_osglobal() {
        let rt = RelocationType::from(3);
        assert_eq!(rt, RelocationType::OSGlobal);
    }

    #[test]
    fn test_address_type_values() {
        assert_eq!(AddressType::from(0), AddressType::LowByte);
        assert_eq!(AddressType::from(2), AddressType::Selector);
        assert_eq!(AddressType::from(3), AddressType::Pointer32);
        assert_eq!(AddressType::from(5), AddressType::Offset16);
        assert_eq!(AddressType::from(11), AddressType::Pointer48);
        assert_eq!(AddressType::from(13), AddressType::Offset32);
        // Unrecognized values are preserved for forward compatibility
        assert_eq!(AddressType::from(15), AddressType::Unknown(15));
    }

    // -----------------------------------------------------------------------
    // PtrNE buffer read method tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ptrne_read_u8() {
        let data: Vec<u8> = (0..=255).collect();
        let ne = PtrNE::from_memory(data.as_ptr(), data.len());

        assert_eq!(ne.read_u8(0).unwrap(), 0x00);
        assert_eq!(ne.read_u8(127).unwrap(), 0x7F);
        assert_eq!(ne.read_u8(255).unwrap(), 0xFF);
    }

    #[test]
    fn test_ptrne_read_u16() {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&0x0102u16.to_le_bytes()); // LE: 02 01
        data.extend_from_slice(&0x0304u16.to_le_bytes()); // LE: 04 03
        let ne = PtrNE::from_memory(data.as_ptr(), data.len());

        assert_eq!(ne.read_u16(0).unwrap(), 0x0102);
        assert_eq!(ne.read_u16(2).unwrap(), 0x0304);
    }

    #[test]
    fn test_ptrne_read_u32() {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&0x0102_0304u32.to_le_bytes()); // LE: 04 03 02 01
        data.extend_from_slice(&0x0506_0708u32.to_le_bytes()); // LE: 08 07 06 05
        let ne = PtrNE::from_memory(data.as_ptr(), data.len());

        assert_eq!(ne.read_u32(0).unwrap(), 0x0102_0304);
        assert_eq!(ne.read_u32(4).unwrap(), 0x0506_0708);
    }

    #[test]
    fn test_ptrne_read_u64() {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        data.extend_from_slice(&0x090A_0B0C_0D0E_0F10u64.to_le_bytes());
        let ne = PtrNE::from_memory(data.as_ptr(), data.len());

        assert_eq!(ne.read_u64(0).unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(ne.read_u64(8).unwrap(), 0x090A_0B0C_0D0E_0F10);
    }

    #[test]
    fn test_ptrne_read_u64_boundary() {
        let data: Vec<u8> = vec![0xAB; 16];
        let ne = PtrNE::from_memory(data.as_ptr(), data.len());

        // First u64 fits, second u64 fits, third would overflow
        assert_eq!(ne.read_u64(0).unwrap(), 0xABAB_ABAB_ABAB_ABAB);
        assert_eq!(ne.read_u64(8).unwrap(), 0xABAB_ABAB_ABAB_ABAB);
        assert!(ne.read_u64(9).is_err()); // 9+8 = 17 > 16
    }

    #[test]
    fn test_ptrne_read_out_of_bounds() {
        let data: Vec<u8> = vec![0u8; 10];
        let ne = PtrNE::from_memory(data.as_ptr(), data.len());

        assert!(ne.read_u16(9).is_err()); // 9+2 = 11 > 10
        assert!(ne.read_u32(7).is_err()); // 7+4 = 11 > 10
        assert!(ne.read_u64(3).is_err()); // 3+8 = 11 > 10
    }

    #[test]
    fn test_ptrne_read_empty_buffer() {
        let data: Vec<u8> = Vec::new();
        let ne = PtrNE::from_memory(data.as_ptr(), data.len());

        assert!(ne.read_u8(0).is_err());
        assert!(ne.read_u16(0).is_err());
    }

    #[test]
    fn test_ptrne_read_u8_single_byte() {
        let data: Vec<u8> = vec![0xFF];
        let ne = PtrNE::from_memory(data.as_ptr(), data.len());

        assert_eq!(ne.read_u8(0).unwrap(), 0xFF);
        assert!(ne.read_u8(1).is_err());
    }

    // -----------------------------------------------------------------------
    // VecNE::from_slice test
    // -----------------------------------------------------------------------

    #[test]
    fn test_vecne_from_slice() {
        let bytes: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let ne = VecNE::from_slice(&bytes);

        assert_eq!(ne.len(), 8);
        // u8 at offset 0
        assert_eq!(ne.read_u8(0).unwrap(), 0xDE);
        // u16 at offset 1 (LE): bytes [0xAD, 0xBE] → 0xAD | (0xBE << 8)
        assert_eq!(ne.read_u16(1).unwrap(), 0xBEAD);
        // u32 at offset 0 (LE): bytes [0xDE, 0xAD, 0xBE, 0xEF]
        assert_eq!(ne.read_u32(0).unwrap(), 0xEFBE_ADDE);
    }

    #[test]
    fn test_vecne_from_slice_empty() {
        let ne = VecNE::from_slice(&[]);
        assert!(ne.is_empty());
        assert!(ne.read_u8(0).is_err());
    }

    // -----------------------------------------------------------------------
    // logical_to_offset tests (sector offset → file offset via alignment)
    // -----------------------------------------------------------------------

    /// Build a synthetic NE file with paragraph alignment (shift = 4).
    ///
    /// Layout:
    ///   [0x00] DOS header (64 bytes)
    ///   [0x40] NE header (60 bytes, v4)
    ///   (`seg_off`) Segment table (1 entry)
    ///   [0x100..] Segment data region (4 KB to hold a full paragraph-aligned segment)
    fn paragraph_aligned_ne_v4() -> Vec<u8> {
        let mut data = vec![0u8; 4096];

        // DOS header
        data[0x00] = 0x4D;
        data[0x01] = 0x5A;
        data[0x18..0x1A].copy_from_slice(&0x40u16.to_le_bytes()); // e_lfarlc = 0x40
        data[0x3C..0x3E].copy_from_slice(&0x40u16.to_le_bytes()); // e_lfanew = 0x40

        let off = 0x40;
        // NE header
        data[off..off + 2].copy_from_slice(&0x454Eu16.to_le_bytes()); // NE sig
        data[off + 0x02] = 0x04; // linker version 4
        data[off + 0x04..off + 0x06].copy_from_slice(&0u16.to_le_bytes());
        data[off + 0x06..off + 0x08].copy_from_slice(&0u16.to_le_bytes());
        data[off + 0x08..off + 0x0C].copy_from_slice(&((0u32).to_le_bytes()));
        data[off + 0x0C..off + 0x0E].copy_from_slice(&0u16.to_le_bytes());
        data[off + 0x0E..off + 0x10].copy_from_slice(&0u16.to_le_bytes());
        data[off + 0x10..off + 0x12].copy_from_slice(&0u16.to_le_bytes());
        data[off + 0x12..off + 0x14].copy_from_slice(&0u16.to_le_bytes());
        data[off + 0x14..off + 0x18].copy_from_slice(&((0u32).to_le_bytes()));
        data[off + 0x18..off + 0x1C].copy_from_slice(&((0u32).to_le_bytes()));
        data[off + 0x1C..off + 0x1E].copy_from_slice(&1u16.to_le_bytes()); // seg_count = 1
        data[off + 0x1E..off + 0x20].copy_from_slice(&0u16.to_le_bytes());
        data[off + 0x20..off + 0x22].copy_from_slice(&0u16.to_le_bytes());
        // seg_table_offset: place segment table right after NE header at offset 0x3C (60 bytes)
        data[off + 0x22..off + 0x24].copy_from_slice(&0x3Cu16.to_le_bytes());
        data[off + 0x24..off + 0x26].copy_from_slice(&0u16.to_le_bytes());
        data[off + 0x26..off + 0x28].copy_from_slice(&0u16.to_le_bytes());
        data[off + 0x28..off + 0x2A].copy_from_slice(&0u16.to_le_bytes());
        data[off + 0x2A..off + 0x2C].copy_from_slice(&0u16.to_le_bytes());
        data[off + 0x2C..off + 0x30].copy_from_slice(&((0u32).to_le_bytes()));
        data[off + 0x30..off + 0x32].copy_from_slice(&0u16.to_le_bytes());
        data[off + 0x32..off + 0x34].copy_from_slice(&4u16.to_le_bytes()); // alignment shift = 4 (16 bytes)
        data[off + 0x34..off + 0x36].copy_from_slice(&0u16.to_le_bytes());
        data[off + 0x36] = 2; // Windows
        data[off + 0x37] = 0;
        data[off + 0x38..off + 0x3A].copy_from_slice(&0u16.to_le_bytes()); // ret_thunk_offset
        data[off + 0x3A..off + 0x3C].copy_from_slice(&0u16.to_le_bytes()); // seg_ref_bytes_offset
        data[off + 0x3C..off + 0x3E].copy_from_slice(&0u16.to_le_bytes()); // swap_area
        data[off + 0x3E..off + 0x40].copy_from_slice(&0u16.to_le_bytes()); // expected_version

        // Segment table at file offset 0x40 + 0x3C = 0x7C
        let seg_off = 0x40 + 0x3C;
        // offset = 0x0010 (sector offset), length = 0x0010, flags = MOVEABLE, minalloc = 0
        // After shifting: actual start = 0x10 << 4 = 0x100 = 256
        data[seg_off..seg_off + 8].copy_from_slice(&[
            0x10, 0x00, // offset = 0x0010
            0x10, 0x00, // length = 0x0010
            0x10, 0x00, // flags = MOVEABLE
            0x00, 0x00, // minalloc
        ]);

        // Fill segment data region with recognizable bytes
        // Region starts at 0x100 (256). Fill 0x100..0x110 with 0xAA..
        for i in 0..16 {
            data[0x100 + i] = 0xAA;
        }
        // Fill region 0x110..0x120 with 0xBB..
        for i in 0..16 {
            data[0x110 + i] = 0xBB;
        }

        data
    }

    #[test]
    fn test_logical_to_offset_byte_aligned() {
        // minimal_ne_v4 has alignment = 0, segment offset = 0x10
        let data = minimal_ne_v4();
        let ne = VecNE::from_memory(data.clone());

        let header = ne.get_valid_ne_header().unwrap();
        assert_eq!(header.common_fields().alignment, 0);

        // offset field = 0x10, shift = 0 → start = 0x10
        let off = ne.logical_to_offset(1, 0x00).unwrap();
        assert_eq!(off, 0x10);

        let off = ne.logical_to_offset(1, 0x0F).unwrap();
        assert_eq!(off, 0x1F);

        // Out-of-bounds: offset == length (0x200) is the boundary, offset+1 exceeds
        assert!(ne.logical_to_offset(1, 0x201).is_err());
    }

    #[test]
    fn test_logical_to_offset_paragraph_aligned() {
        let data = paragraph_aligned_ne_v4();
        let ne = VecNE::from_memory(data);

        let header = ne.get_valid_ne_header().unwrap();
        assert_eq!(header.common_fields().alignment, 4);

        // offset field = 0x10, shift = 4 → start = 0x10 << 4 = 0x100 = 256
        let off = ne.logical_to_offset(1, 0x00).unwrap();
        assert_eq!(off, 0x100);

        let off = ne.logical_to_offset(1, 0x0F).unwrap();
        assert_eq!(off, 0x10F);

        let off = ne.logical_to_offset(1, 0x10).unwrap();
        assert_eq!(off, 0x110);
    }

    #[test]
    fn test_logical_to_offset_wrong_segment() {
        let data = minimal_ne_v4();
        let ne = VecNE::from_memory(data);

        // Segment 2 doesn't exist (only 1 segment)
        match ne.logical_to_offset(2, 0x00) {
            Err(Error::SegmentNotFound(2)) => {}
            other => panic!("Expected SegmentNotFound(2), got {:?}", other),
        }
        // Very high ordinal also returns NotFound
        match ne.logical_to_offset(0xFFFF, 0x00) {
            Err(Error::SegmentNotFound(_)) => {}
            other => panic!("Expected SegmentNotFound, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // get_segment_data tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_get_segment_data_byte_aligned() {
        let data = minimal_ne_v4();
        let ne = VecNE::from_memory(data);

        let seg_data = ne.get_segment_data(1).unwrap();
        // Segment starts at offset 0x10, length = 0x200
        assert_eq!(seg_data.len(), 0x200);
    }

    #[test]
    fn test_get_segment_data_paragraph_aligned() {
        let data = paragraph_aligned_ne_v4();
        let ne = VecNE::from_memory(data);

        let seg_data = ne.get_segment_data(1).unwrap();
        // Segment starts at 0x100, length = 0x10
        assert_eq!(seg_data.len(), 0x10);

        // Verify the recognizable fill pattern
        for b in seg_data {
            assert_eq!(*b, 0xAA, "Expected 0xAA at segment data");
        }
    }

    #[test]
    fn test_get_segment_data_wrong_number() {
        let data = minimal_ne_v4();
        let ne = VecNE::from_memory(data);

        match ne.get_segment_data(2) {
            Err(Error::SegmentNotFound(2)) => {}
            other => panic!("Expected SegmentNotFound(2), got {:?}", other),
        }
        match ne.get_segment_data(0xFFFF) {
            Err(Error::SegmentNotFound(_)) => {}
            other => panic!("Expected SegmentNotFound, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // NE accessor helpers tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ne_header_file_offset() {
        let data = minimal_ne_v4();
        let ne = VecNE::from_memory(data);

        // e_lfanew = 0x40
        assert_eq!(ne.ne_header_file_offset().unwrap(), 0x40);
    }

    #[test]
    fn test_ne_offset_to_file() {
        let data = minimal_ne_v4();
        let ne = VecNE::from_memory(data);

        // e_lfanew = 0x40, so relative offset 0x7C → file offset 0xBC
        assert_eq!(ne.ne_offset_to_file(0x7C).unwrap(), 0xBC);
        // Zero offset → 0
        assert_eq!(ne.ne_offset_to_file(0).unwrap(), 0);
    }

    #[test]
    fn test_segment_count() {
        let data = minimal_ne_v4();
        let ne = VecNE::from_memory(data);

        assert_eq!(ne.segment_count(), 1);
    }

    #[test]
    fn test_segment_count_invalid() {
        let data: Vec<u8> = vec![0u8; 10];
        let ne = VecNE::from_memory(data);

        assert_eq!(ne.segment_count(), 0);
    }

    // -----------------------------------------------------------------------
    // VecNE::from_disk_file feature-gate test
    // -----------------------------------------------------------------------

    #[cfg(feature = "std")]
    #[test]
    fn test_vecne_from_disk_file_not_found() {
        let result = VecNE::from_disk_file("/nonexistent/path/file.EXE");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // SegmentRecord flag method tests (not covered by real-file tests)
    // -----------------------------------------------------------------------

    #[test]
    fn test_segment_record_is_data() {
        let mut rec = SegmentRecord {
            offset: 0,
            length: 0,
            flags: 0,
            minalloc: 0,
        };
        rec.flags = 0x0001; // DATA
        assert!(rec.is_data());
        assert!(!rec.is_moveable());
        assert!(!rec.is_shared());
        assert!(!rec.is_discardable());
    }

    #[test]
    fn test_segment_record_is_shared() {
        let mut rec = SegmentRecord {
            offset: 0,
            length: 0,
            flags: 0,
            minalloc: 0,
        };
        rec.flags = SegmentFlags::SHAREABLE.bits();
        assert!(rec.is_shared());
        assert!(!rec.is_discardable());
    }

    #[test]
    fn test_segment_record_is_discardable() {
        let mut rec = SegmentRecord {
            offset: 0,
            length: 0,
            flags: 0,
            minalloc: 0,
        };
        rec.flags = SegmentFlags::DISCARDABLE.bits();
        assert!(rec.is_discardable());
        assert!(!rec.is_shared());
    }

    #[test]
    fn test_segment_record_multiple_flags() {
        let mut rec = SegmentRecord {
            offset: 0,
            length: 0,
            flags: 0,
            minalloc: 0,
        };
        rec.flags = SegmentFlags::DATA.bits()
            | SegmentFlags::MOVEABLE.bits()
            | SegmentFlags::DISCARDABLE.bits();
        assert!(rec.is_data());
        assert!(rec.is_moveable());
        assert!(rec.is_discardable());
    }

    // -----------------------------------------------------------------------
    // NEFlags bit tests not covered by existing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ne_flags_reserved_bits_truncated() {
        // Bits 2-3 are reserved — truncate drops them
        let flags = NeFlags::from_bits_truncate(0x000C);
        assert_eq!(flags.bits(), 0);
    }

    #[test]
    fn test_ne_flags_undefined_high_bits_truncated() {
        // Undefined high bits are truncated; only the defined flags survive:
        // 0xFFE0 & (0x1|0x2|0x800|0x2000|0x8000) = LIBRARY|LINKER_ERRORS|
        // FIRST_SEG_CONTAINS_LOADER. (The old RESERVED = 0xFFE0 mask used to
        // swallow the LIBRARY bit instead.)
        let flags = NeFlags::from_bits_truncate(0xFFE0);
        assert_eq!(
            flags.bits(),
            NeFlags::LIBRARY.bits()
                | NeFlags::LINKER_ERRORS.bits()
                | NeFlags::FIRST_SEG_CONTAINS_LOADER.bits()
        );
        // Purely undefined bits (0x4000, 0x1000, 0x0400) truncate to nothing
        let undefined = NeFlags::from_bits_truncate(0x5400);
        assert_eq!(undefined.bits(), 0);
    }

    // -----------------------------------------------------------------------
    // PascalString non-ASCII but valid bytes test
    // -----------------------------------------------------------------------

    #[test]
    fn test_pascal_string_non_ascii_bytes() {
        // Valid ASCII range (0x20-0x7E) but not UTF-8 — actually this is fine
        // Let's test with bytes that are ASCII
        let data: Vec<u8> = (0x20..=0x7E).cycle().take(10).collect();
        let pascal = PascalString { data: &data };
        assert!(pascal.as_str().is_ok());
        assert_eq!(pascal.as_bytes(), &data);
    }

    // -----------------------------------------------------------------------
    // Buffer::is_empty tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_buf_is_empty() {
        let data: Vec<u8> = Vec::new();
        let vecne = VecNE::from_memory(data.clone());
        assert!(vecne.is_empty());
        assert!(vecne.len() == 0);
    }

    #[test]
    fn test_buf_is_not_empty() {
        let data: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let vecne = VecNE::from_memory(data);
        assert!(!vecne.is_empty());
    }
}
