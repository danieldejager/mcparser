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
