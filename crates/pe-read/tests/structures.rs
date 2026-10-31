//! Certificates, version info, manifest and icons on synthetic PE files.
//! The PKCS#7 fixture was generated with openssl for a made-up "McParser
//! Test" CA and signer over the bytes "synthetic content"; no real sample.
use pe_read::*;

const P7: &[u8] = include_bytes!("fixtures/authenticode-synthetic.p7b");

fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

/// PE32 with one .rsrc section at file 0x200 / RVA 0x1000 (0x1000 bytes raw)
/// and room for data directories. Returns the bytes and the optional header
/// data directory offset.
pub fn base_pe(timestamp: u32) -> (Vec<u8>, usize) {
    let mut b = vec![0u8; 0x1200];
    b[0] = b'M';
    b[1] = b'Z';
    put32(&mut b, 60, 0x80);
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    let fh = 0x84;
    put16(&mut b, fh, 0x14c);
    put16(&mut b, fh + 2, 1);
    put32(&mut b, fh + 4, timestamp);
    put16(&mut b, fh + 16, 224);
    put16(&mut b, fh + 18, 0x0102);
    let oh = fh + 20;
    put16(&mut b, oh, 0x10b);
    put32(&mut b, oh + 28, 0x40_0000);
    put32(&mut b, oh + 60, 0x200);
    put16(&mut b, oh + 68, 2);
    put32(&mut b, oh + 92, 16);
    let st = oh + 224;
    b[st..st + 5].copy_from_slice(b".rsrc");
    put32(&mut b, st + 8, 0x1000);
    put32(&mut b, st + 12, 0x1000);
    put32(&mut b, st + 16, 0x1000);
    put32(&mut b, st + 20, 0x200);
    put32(&mut b, st + 36, 0x4000_0040);
    (b, oh + 96)
}

/// Append a WIN_CERTIFICATE holding `blob` and point directory 4 at it.
pub fn with_cert(mut b: Vec<u8>, dd: usize, blob: &[u8]) -> Vec<u8> {
    while b.len() % 8 != 0 {
        b.push(0);
    }
    let off = b.len();
    let len = 8 + blob.len();
    b.extend_from_slice(&(len as u32).to_le_bytes());
    b.extend_from_slice(&0x0200u16.to_le_bytes());
    b.extend_from_slice(&0x0002u16.to_le_bytes());
    b.extend_from_slice(blob);
    while b.len() % 8 != 0 {
        b.push(0);
    }
    let total = b.len() - off;
    put32(&mut b, dd + 4 * 8, off as u32);
    put32(&mut b, dd + 4 * 8 + 4, total as u32);
    b
}

#[test]
fn authenticode_chain_is_listed_not_verified() {
    let (b, dd) = base_pe(0x6a00_0000);
    let b = with_cert(b, dd, P7);
    let r = analyze(&b);
    assert!(r.certificate_present);
    assert_eq!(r.signatures.len(), 1);
    let s = &r.signatures[0];
    assert_eq!(s.error, "");
    assert_eq!(s.revision, 0x0200);
    assert_eq!(s.cert_type, 2);
    assert_eq!(s.digest_algorithm, "sha256");
    assert_eq!(s.certificates.len(), 2);
    let signer = s.signer().expect("signer found in chain");
    assert!(signer.is_signer);
    assert_eq!(signer.subject.common_name, "McParser Test Signer");
    assert_eq!(signer.subject.organization, "McParser Test");
    assert_eq!(signer.subject.org_unit, "Build");
    assert_eq!(signer.subject.country, "AU");
    assert_eq!(signer.issuer.common_name, "McParser Test Root");
    assert_eq!(signer.serial_hex, "12 34 56 78 90 ab cd ef 01");
    assert_eq!(signer.serial_dec, "335812727627494321921");
    assert_eq!(signer.version, 3);
    assert_eq!(signer.signature_algorithm, "sha256WithRSAEncryption");
    assert!(!signer.self_signed);
    assert!(signer.not_after > signer.not_before);
    let root = s.certificates.iter().find(|c| !c.is_signer).unwrap();
    assert!(root.self_signed);
    assert_eq!(s.signer_serial_dec, signer.serial_dec);
}

#[test]
fn signature_hints_fire_on_compile_time_outside_validity() {
    // 2001: long before the synthetic signer certificate was issued.
    let (b, dd) = base_pe(1_000_000_000);
    let r = analyze(&with_cert(b, dd, P7));
    let ind = extra::indicators(&r, 2_000_000_000);
    assert!(ind.iter().any(|i| i.rule == "signer_invalid_at_compile"));
    assert!(!ind.iter().any(|i| i.rule == "self_signed_signer"));
}

#[test]
fn hostile_certificate_tables() {
    let (b, dd) = base_pe(0x6a00_0000);
    // Garbage blob: decoded as an error, no panic, hint raised.
    let r = analyze(&with_cert(
        b.clone(),
        dd,
        &[0x30, 0x82, 0xff, 0xff, 1, 2, 3],
    ));
    assert_eq!(r.signatures.len(), 1);
    assert!(!r.signatures[0].error.is_empty());
    assert!(extra::indicators(&r, 2_000_000_000)
        .iter()
        .any(|i| i.rule == "signature_unparsed"));
    // Every truncation of a valid blob is safe.
    for n in (0..P7.len()).step_by(37) {
        let _ = analyze(&with_cert(b.clone(), dd, &P7[..n]));
    }
    // dwLength larger than the directory, zero, and pointing past the file.
    let mut x = with_cert(b.clone(), dd, P7);
    let off = u32::from_le_bytes(x[dd + 32..dd + 36].try_into().unwrap()) as usize;
    put32(&mut x, off, 0xffff_fff0);
    let r = analyze(&x);
    assert!(r.signatures[0].error.contains("does not fit"));
    put32(&mut x, off, 0);
    let _ = analyze(&x);
    put32(&mut x, dd + 32, 0xffff_ff00);
    let r = analyze(&x);
    assert!(r.signatures.is_empty());
    // Many tiny entries: capped.
    let mut y = b.clone();
    let start = y.len();
    for _ in 0..100 {
        y.extend_from_slice(&8u32.to_le_bytes());
        y.extend_from_slice(&[0, 2, 2, 0]);
    }
    put32(&mut y, dd + 32, start as u32);
    put32(&mut y, dd + 36, 800);
    let r = analyze(&y);
    assert_eq!(r.signatures.len(), cert::MAX_CERT_ENTRIES);
}

#[test]
fn decimal_serials() {
    assert_eq!(cert::be_to_decimal(&[]), "0");
    assert_eq!(cert::be_to_decimal(&[0x01, 0x00]), "256");
    assert_eq!(cert::be_to_decimal(&[0xff; 8]), "18446744073709551615");
}

/// Build a resource tree (type id -> name id -> lang 1033) into the .rsrc
/// section and point directory 2 at it. Data is placed after the tree.
pub fn with_resources(mut b: Vec<u8>, dd: usize, items: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    let mut types: Vec<u32> = items.iter().map(|i| i.0).collect();
    types.dedup();
    let mut t = vec![0u8; 0x1000];
    let mut next = 16 + 8 * types.len();
    let mut data_at = 0x800usize;
    put16(&mut t, 14, types.len() as u16);
    for (ti, ty) in types.iter().enumerate() {
        let names: Vec<&(u32, u32, Vec<u8>)> = items.iter().filter(|i| i.0 == *ty).collect();
        let tdir = next;
        next += 16 + 8 * names.len();
        put32(&mut t, 16 + ti * 8, *ty);
        put32(&mut t, 16 + ti * 8 + 4, 0x8000_0000 | tdir as u32);
        put16(&mut t, tdir + 14, names.len() as u16);
        for (ni, item) in names.iter().enumerate() {
            let ldir = next;
            next += 24;
            let de = next;
            next += 16;
            put32(&mut t, tdir + 16 + ni * 8, item.1);
            put32(&mut t, tdir + 16 + ni * 8 + 4, 0x8000_0000 | ldir as u32);
            put16(&mut t, ldir + 14, 1);
            put32(&mut t, ldir + 16, 1033);
            put32(&mut t, ldir + 20, de as u32);
            put32(&mut t, de, 0x1000 + data_at as u32);
            put32(&mut t, de + 4, item.2.len() as u32);
            t[data_at..data_at + item.2.len()].copy_from_slice(&item.2);
            data_at = (data_at + item.2.len() + 7) & !7;
        }
    }
    assert!(next < 0x800 && data_at <= 0x1000);
    b[0x200..0x1200].copy_from_slice(&t);
    put32(&mut b, dd + 2 * 8, 0x1000);
    put32(&mut b, dd + 2 * 8 + 4, 0x1000);
    b
}

fn w(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain([0])
        .flat_map(|c| c.to_le_bytes())
        .collect()
}
fn pad4(v: &mut Vec<u8>) {
    while v.len() % 4 != 0 {
        v.push(0);
    }
}
/// One version block; `value` is raw bytes and `text` says whether its
/// length counts UTF-16 units.
fn vblock(key: &str, value: &[u8], text: bool, kids: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![0u8; 6];
    v.extend(w(key));
    pad4(&mut v);
    v.extend_from_slice(value);
    pad4(&mut v);
    for k in kids {
        v.extend_from_slice(k);
        pad4(&mut v);
    }
    let len = v.len() as u16;
    let vl = if text { value.len() / 2 } else { value.len() } as u16;
    v[0..2].copy_from_slice(&len.to_le_bytes());
    v[2..4].copy_from_slice(&vl.to_le_bytes());
    v[4..6].copy_from_slice(&(text as u16).to_le_bytes());
    v
}

pub fn sample_version() -> Vec<u8> {
    let mut fixed = vec![0u8; 52];
    fixed[0..4].copy_from_slice(&0xFEEF04BDu32.to_le_bytes());
    fixed[8..12].copy_from_slice(&((1u32 << 16) | 2).to_le_bytes());
    fixed[12..16].copy_from_slice(&((3u32 << 16) | 4).to_le_bytes());
    fixed[16..20].copy_from_slice(&(1u32 << 16).to_le_bytes());
    fixed[28..32].copy_from_slice(&0x2u32.to_le_bytes());
    fixed[32..36].copy_from_slice(&0x40004u32.to_le_bytes());
    fixed[36..40].copy_from_slice(&1u32.to_le_bytes());
    let s = |k: &str, v: &str| vblock(k, &w(v), true, &[]);
    let table = vblock(
        "040904B0",
        &[],
        true,
        &[
            s("CompanyName", "McParser Test"),
            s("FileDescription", "Synthetic sample"),
            s("OriginalFilename", "sample.exe"),
            s("FileVersion", "1.2.3.4"),
        ],
    );
    let sfi = vblock("StringFileInfo", &[], true, &[table]);
    let tr = vblock("Translation", &[0x09, 0x04, 0xB0, 0x04], false, &[]);
    let vfi = vblock("VarFileInfo", &[], true, &[tr]);
    vblock("VS_VERSION_INFO", &fixed, false, &[sfi, vfi])
}

pub const SAMPLE_MANIFEST: &str = "\u{feff}<?xml version=\"1.0\"?><assembly><trustInfo><security><requestedPrivileges><requestedExecutionLevel level='requireAdministrator' uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><script>alert(1)</script></assembly>";

/// 16x16 32-bit DIB icon (header + pixels + AND mask).
pub fn sample_dib() -> Vec<u8> {
    let mut d = vec![0u8; 40];
    d[0..4].copy_from_slice(&40u32.to_le_bytes());
    d[4..8].copy_from_slice(&16u32.to_le_bytes());
    d[8..12].copy_from_slice(&32u32.to_le_bytes());
    d[12..14].copy_from_slice(&1u16.to_le_bytes());
    d[14..16].copy_from_slice(&32u16.to_le_bytes());
    for y in 0..16u8 {
        for x in 0..16u8 {
            d.extend_from_slice(&[x * 16, 0x6b, y * 16, 0xff]);
        }
    }
    d.extend(vec![0u8; 16 * 4]);
    d
}

pub fn sample_group(ids: &[u16]) -> Vec<u8> {
    let mut g = vec![0, 0, 1, 0];
    g.extend_from_slice(&(ids.len() as u16).to_le_bytes());
    for id in ids {
        g.extend_from_slice(&[16, 16, 0, 0, 1, 0, 32, 0]);
        g.extend_from_slice(&0u32.to_le_bytes());
        g.extend_from_slice(&id.to_le_bytes());
    }
    g
}

#[test]
fn version_manifest_and_icons_decode() {
    let (b, dd) = base_pe(0x6a00_0000);
    let png = {
        let mut p = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
        p.extend_from_slice(&32u32.to_be_bytes());
        p.extend_from_slice(&32u32.to_be_bytes());
        p.extend_from_slice(&[8, 6, 0, 0, 0, 0, 0, 0, 0]);
        p.extend(vec![0u8; 40]);
        p
    };
    let b = with_resources(
        b,
        dd,
        &[
            (3, 1, sample_dib()),
            (3, 2, png),
            (3, 3, vec![0x41; 64]),
            (14, 1, sample_group(&[1, 2, 3, 9])),
            (16, 1, sample_version()),
            (24, 1, SAMPLE_MANIFEST.as_bytes().to_vec()),
        ],
    );
    let r = analyze(&b);
    let v = r.version_info.as_ref().expect("version info");
    assert!(v.fixed_present);
    assert_eq!(v.file_version, "1.2.3.4");
    assert_eq!(v.product_version, "1.0.0.0");
    assert_eq!(v.get("CompanyName"), Some("McParser Test"));
    assert_eq!(v.get("OriginalFilename"), Some("sample.exe"));
    assert_eq!(v.strings[0].table, "040904B0");
    assert_eq!(v.translations, vec![(0x0409, 0x04B0)]);
    assert_eq!(rsrc::version_flag_names(v.flags), vec!["PRERELEASE"]);
    assert_eq!(rsrc::version_os_name(v.os), "NT / Windows32");
    let m = r.manifest.as_ref().expect("manifest");
    assert_eq!(m.execution_level, "requireAdministrator");
    assert_eq!(m.ui_access, "false");
    assert!(m.text.starts_with("<?xml"));
    // Bad payload (id 3) and the missing id 9 are skipped.
    assert_eq!(r.icons.len(), 2);
    assert_eq!(r.icons[0].format, "ico");
    assert_eq!(&r.icons[0].bytes[..6], &[0, 0, 1, 0, 1, 0]);
    assert_eq!(r.icons[1].format, "png");
    assert_eq!(r.icons[1].width, 32);
    assert!(r.resources.iter().all(|x| x.offset.is_some()));
    // Each resource carries MD5 and SHA256 of its own bytes.
    assert!(r.resources.iter().all(|x| x.md5.len() == 32 && x.sha256.len() == 64));
    let m = r.resources.iter().find(|x| x.type_name == "MANIFEST").unwrap();
    assert_eq!(m.size as usize, SAMPLE_MANIFEST.len());
}

#[test]
fn hostile_resource_payloads() {
    // Truncated, self-referencing and oversized version blocks never panic.
    for n in 0..sample_version().len() {
        let _ = rsrc::version_info(&sample_version()[..n]);
    }
    let mut v = sample_version();
    v[0..2].copy_from_slice(&0xffffu16.to_le_bytes());
    let _ = rsrc::version_info(&v);
    let mut zero_len_child = sample_version();
    let n = zero_len_child.len();
    zero_len_child[n - 40..].fill(0);
    let _ = rsrc::version_info(&zero_len_child);
    let mut bad_sig = sample_version();
    bad_sig[40..44].fill(0);
    let vi = rsrc::version_info(&bad_sig).unwrap();
    assert!(!vi.fixed_present);
    assert!(rsrc::version_info(&[0xff; 4096]).is_none());
    // Manifest caps, odd encodings and no level.
    let m = rsrc::manifest(&vec![b'a'; rsrc::MAX_MANIFEST_BYTES + 10]);
    assert!(m.truncated);
    assert_eq!(m.text.len(), rsrc::MAX_MANIFEST_BYTES);
    let _ = rsrc::manifest(&[0xff, 0xfe, 0x41]);
    let _ = rsrc::manifest(&[0xfe, 0xff]);
    assert_eq!(
        rsrc::manifest(b"requestedExecutionLevel level=").execution_level,
        ""
    );
    // Icons: compressed, bad planes, huge sizes, truncated pixels, giant PNG.
    let mut d = sample_dib();
    d[16] = 1;
    assert!(rsrc::icon_payload(&d).is_none());
    let mut d = sample_dib();
    d[12] = 2;
    assert!(rsrc::icon_payload(&d).is_none());
    let mut d = sample_dib();
    d[4..8].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
    assert!(rsrc::icon_payload(&d).is_none());
    let d = sample_dib();
    assert!(rsrc::icon_payload(&d[..d.len() - 1]).is_none());
    assert!(rsrc::icon_payload(&vec![0u8; rsrc::MAX_ICON_BYTES + 1]).is_none());
    let mut p = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
    p.extend_from_slice(&u32::MAX.to_be_bytes());
    p.extend(vec![0u8; 40]);
    assert!(rsrc::icon_payload(&p).is_none());
    assert!(rsrc::group_icon_entries(&[0, 0, 1, 0, 0xff, 0xff]).is_empty());
    // Many groups pointing at one icon are capped.
    let (b, dd) = base_pe(0);
    let items: Vec<_> = std::iter::once((3, 1, sample_dib()))
        .chain((1..30).map(|i| (14, i, sample_group(&[1; 2]))))
        .collect();
    let b = with_resources(b, dd, &items[..3]);
    let r = analyze(&b);
    assert!(r.icons.len() <= rsrc::MAX_ICONS);
}
