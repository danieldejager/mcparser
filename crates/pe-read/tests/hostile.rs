//! Synthetic PE files built in code. No real samples are committed.
use pe_read::*;

/// Minimal 32-bit PE: one .text section at file 0x200 / RVA 0x1000, with an
/// import table for kernel32.dll!ExitProcess and user32.dll ordinal 5, and an
/// export directory naming one function.
fn build(is_64: bool) -> Vec<u8> {
    let mut b = vec![0u8; 0x400];
    b[0] = b'M';
    b[1] = b'Z';
    b[60..64].copy_from_slice(&0x80u32.to_le_bytes());
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    let fh = 0x84;
    let opt_size: u16 = if is_64 { 240 } else { 224 };
    put16(&mut b, fh, if is_64 { 0x8664 } else { 0x14c });
    put16(&mut b, fh + 2, 1);
    put32(&mut b, fh + 4, 0x5f00_0000);
    put16(&mut b, fh + 16, opt_size);
    put16(&mut b, fh + 18, 0x0102);
    let oh = fh + 20;
    put16(&mut b, oh, if is_64 { 0x20b } else { 0x10b });
    put32(&mut b, oh + 16, 0x1000);
    if is_64 {
        b[oh + 24..oh + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    } else {
        put32(&mut b, oh + 28, 0x40_0000);
    }
    put32(&mut b, oh + 60, 0x200);
    put16(&mut b, oh + 68, 3);
    let k = if is_64 { 16 } else { 0 };
    put32(&mut b, oh + 92 + k, 16);
    let dd = oh + 96 + k;
    put32(&mut b, dd, 0x1100);
    put32(&mut b, dd + 4, 0x40); // export
    put32(&mut b, dd + 8, 0x1000);
    put32(&mut b, dd + 12, 0x28); // import
    let st = oh + opt_size as usize;
    b[st..st + 5].copy_from_slice(b".text");
    put32(&mut b, st + 8, 0x200);
    put32(&mut b, st + 12, 0x1000);
    put32(&mut b, st + 16, 0x200);
    put32(&mut b, st + 20, 0x200);
    put32(&mut b, st + 36, 0x6000_0020);
    // section data at 0x200 == RVA 0x1000
    let base = 0x200;
    let at = |rva: u32| base + (rva - 0x1000) as usize;
    let w = if is_64 { 8 } else { 4 };
    // descriptor 0: kernel32, descriptor 1: user32, descriptor 2: zero
    put32(&mut b, at(0x1000), 0x1040);
    put32(&mut b, at(0x100c), 0x1080);
    put32(&mut b, at(0x1010), 0x1040);
    put32(&mut b, at(0x1014), 0x1050);
    put32(&mut b, at(0x1020), 0x1090);
    put32(&mut b, at(0x1024), 0x1050);
    put32(&mut b, at(0x1040), 0x1070); // thunk -> hint/name
    if is_64 {
        b[at(0x1050)..at(0x1050) + 8].copy_from_slice(&((1u64 << 63) | 5).to_le_bytes());
    } else {
        put32(&mut b, at(0x1050), 0x8000_0005);
    }
    let _ = w;
    b[at(0x1072)..at(0x1072) + 11].copy_from_slice(b"ExitProcess");
    b[at(0x1080)..at(0x1080) + 12].copy_from_slice(b"KERNEL32.dll");
    b[at(0x1090)..at(0x1090) + 10].copy_from_slice(b"user32.dll");
    // export directory at 0x1100
    let e = at(0x1100);
    put32(&mut b, e + 12, 0x1160);
    put32(&mut b, e + 16, 1);
    put32(&mut b, e + 20, 1);
    put32(&mut b, e + 24, 1);
    put32(&mut b, e + 28, 0x1140);
    put32(&mut b, e + 32, 0x1148);
    put32(&mut b, e + 36, 0x1150);
    put32(&mut b, at(0x1140), 0x1010);
    put32(&mut b, at(0x1148), 0x1170);
    put16(&mut b, at(0x1150), 0);
    b[at(0x1160)..at(0x1160) + 8].copy_from_slice(b"test.dll");
    b[at(0x1170)..at(0x1170) + 5].copy_from_slice(b"Hello");
    b
}
fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

#[test]
fn parses_synthetic_pe32() {
    let r = analyze(&build(false));
    assert!(r.is_pe, "{:?}", r.warnings);
    assert!(!r.is_64);
    assert_eq!(r.architecture(), "x86");
    assert_eq!(r.subsystem_name(), "windows_cui");
    assert_eq!(r.timestamp, 0x5f00_0000);
    assert_eq!(r.entry_point, 0x1000);
    assert_eq!(r.image_base, 0x40_0000);
    assert_eq!(r.sections.len(), 1);
    assert_eq!(r.sections[0].name, ".text");
    assert_eq!(r.imports.len(), 2);
    assert_eq!(r.imports[0].dll, "KERNEL32.dll");
    assert_eq!(r.imports[0].name, "ExitProcess");
    assert_eq!(r.imports[1].ordinal, Some(5));
    assert_eq!(r.export_dll_name, "test.dll");
    assert_eq!(r.exports.len(), 1);
    assert_eq!(r.exports[0].name, "Hello");
    assert!(!r.signed());
    assert_eq!(r.imphash.len(), 32);
    assert_eq!(r.hashes.sha256.len(), 64);
}

#[test]
fn parses_synthetic_pe32_plus() {
    let r = analyze(&build(true));
    assert!(r.is_64, "{:?}", r.warnings);
    assert_eq!(r.architecture(), "x64");
    assert_eq!(r.image_base, 0x1_4000_0000);
    assert_eq!(r.imports.len(), 2);
    assert_eq!(r.imports[1].ordinal, Some(5));
    assert_eq!(r.exports[0].name, "Hello");
}

#[test]
fn imphash_matches_pefile_style() {
    let imps = vec![
        Import {
            dll: "KERNEL32.dll".into(),
            name: "ExitProcess".into(),
            ordinal: None,
            delayed: false,
        },
        Import {
            dll: "user32.dll".into(),
            name: String::new(),
            ordinal: Some(5),
            delayed: false,
        },
    ];
    let expect = format!(
        "{:x}",
        <md5::Md5 as md5::Digest>::digest(b"kernel32.exitprocess,user32.ord5")
    );
    assert_eq!(imphash(&imps), expect);
}

#[test]
fn empty_and_tiny_inputs() {
    for n in 0..300 {
        let r = analyze(&vec![0u8; n]);
        assert!(!r.is_pe);
    }
    assert!(!analyze(b"MZ").is_pe);
}

#[test]
fn every_truncation_is_safe() {
    for is_64 in [false, true] {
        let full = build(is_64);
        for n in 0..full.len() {
            let _ = analyze(&full[..n]);
        }
    }
}

#[test]
fn bad_lfanew() {
    let mut b = build(false);
    put32(&mut b, 60, u32::MAX);
    assert!(!analyze(&b).is_pe);
    put32(&mut b, 60, 0x3ff);
    assert!(!analyze(&b).is_pe);
}

#[test]
fn huge_counts_are_capped() {
    let mut b = build(false);
    put16(&mut b, 0x86, 0xffff); // NumberOfSections
    put32(&mut b, 0x84 + 20 + 92, 0xffff_ffff); // NumberOfRvaAndSizes
    let r = analyze(&b);
    assert!(r.sections.len() <= MAX_SECTIONS);
    assert!(r.data_directories.len() <= 16);
    assert!(!r.warnings.is_empty());
}

#[test]
fn bad_rvas_and_sizes() {
    let mut b = build(false);
    let dd = 0x84 + 20 + 96;
    for i in 0..16 {
        put32(&mut b, dd + i * 8, 0xffff_fff0);
        put32(&mut b, dd + i * 8 + 4, 0xffff_ffff);
    }
    let r = analyze(&b);
    assert!(r.imports.is_empty() && r.exports.is_empty() && r.resources.is_empty());
    assert!(!r.certificate_present);
}

#[test]
fn overlapping_and_oversized_sections() {
    let mut b = build(false);
    put16(&mut b, 0x86, 3);
    let st = 0x84 + 20 + 224;
    for i in 1..3 {
        let s = st + i * 40;
        b[s..s + 5].copy_from_slice(b".evil");
        put32(&mut b, s + 8, 0xffff_ffff);
        put32(&mut b, s + 12, 0x1000);
        put32(&mut b, s + 16, 0xffff_ffff);
        put32(&mut b, s + 20, 0x100);
    }
    let r = analyze(&b);
    assert_eq!(r.sections.len(), 3);
    assert!(r.warnings.iter().any(|w| w.contains("overlap")));
}

#[test]
fn import_thunk_loop_is_bounded() {
    // Descriptor whose thunk array is the descriptor table itself and never ends in zero.
    let mut b = build(false);
    let at = |rva: u32| 0x200 + (rva - 0x1000) as usize;
    for i in 0..0x80 {
        put32(&mut b, at(0x1000) + i * 4, 0x1000);
    }
    let r = analyze(&b);
    assert!(r.imports.len() <= MAX_IMPORTS_TOTAL);
}

#[test]
fn resource_cycle_terminates() {
    let mut b = build(false);
    let dd = 0x84 + 20 + 96;
    put32(&mut b, dd + 16, 0x1180);
    put32(&mut b, dd + 20, 0x40);
    let r0 = 0x200 + 0x180;
    put16(&mut b, r0 + 14, 1);
    put32(&mut b, r0 + 16, 3);
    put32(&mut b, r0 + 20, 0x8000_0000); // points at itself
    let r = analyze(&b);
    assert!(r.resources.is_empty());
}

#[test]
fn pseudo_random_garbage_never_panics() {
    let base = build(false);
    let mut seed = 0x1234_5678_9abc_def0u64;
    for _ in 0..3000 {
        let mut b = base.clone();
        for _ in 0..16 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let i = (seed as usize) % b.len();
            b[i] = (seed >> 32) as u8;
        }
        let _ = analyze(&b);
    }
}

#[test]
fn entropy_bounds() {
    assert_eq!(entropy(&[]), 0.0);
    assert_eq!(entropy(&[7; 100]), 0.0);
    let all: Vec<u8> = (0..=255).collect();
    assert!((entropy(&all) - 8.0).abs() < 1e-9);
}
