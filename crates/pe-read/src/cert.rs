//! Authenticode signature parsing from the PE certificate table.
//!
//! Parse only. The PKCS#7 SignedData is decoded to list the signer and the
//! certificate chain. Nothing here checks a digest, verifies a signature or
//! decides trust; callers must label the result "signature present, not
//! verified".

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::{Decode, SliceReader};
use x509_cert::name::Name;
use x509_cert::Certificate;

/// Most WIN_CERTIFICATE entries read from one file.
pub const MAX_CERT_ENTRIES: usize = 8;
/// Largest single WIN_CERTIFICATE blob decoded.
pub const MAX_CERT_BLOB: usize = 4 * 1024 * 1024;
/// Most certificates listed per signature.
pub const MAX_CHAIN: usize = 32;
const MAX_TEXT: usize = 512;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct NameParts {
    pub full: String,
    pub common_name: String,
    pub organization: String,
    pub org_unit: String,
    pub country: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CertInfo {
    pub index: usize,
    pub subject: NameParts,
    pub issuer: NameParts,
    pub serial_hex: String,
    pub serial_dec: String,
    pub version: u8,
    pub signature_algorithm: String,
    /// Unix seconds.
    pub not_before: u64,
    pub not_after: u64,
    pub self_signed: bool,
    pub is_signer: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Signature {
    /// File offset of the WIN_CERTIFICATE header.
    pub offset: u64,
    pub length: u32,
    pub revision: u16,
    pub cert_type: u16,
    pub signed_data_version: u8,
    pub digest_algorithm: String,
    pub signature_algorithm: String,
    pub signer_issuer: NameParts,
    pub signer_serial_hex: String,
    pub signer_serial_dec: String,
    /// Index into `certificates` of the signing certificate, when found.
    pub signer_index: Option<usize>,
    pub certificates: Vec<CertInfo>,
    /// Why decoding stopped, when it did.
    pub error: String,
}

impl Signature {
    pub fn signer(&self) -> Option<&CertInfo> {
        self.signer_index.and_then(|i| self.certificates.get(i))
    }
}

fn cap(mut s: String) -> String {
    if s.len() > MAX_TEXT {
        let mut end = MAX_TEXT;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// Friendly name for common algorithm OIDs; the dotted OID otherwise.
pub fn oid_name(oid: &str) -> String {
    let n = match oid {
        "1.2.840.113549.1.1.1" => "rsaEncryption",
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.10045.2.1" => "ecPublicKey",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.2.840.113549.2.5" => "md5",
        "1.3.14.3.2.26" => "sha1",
        "2.16.840.1.101.3.4.2.1" => "sha256",
        "2.16.840.1.101.3.4.2.2" => "sha384",
        "2.16.840.1.101.3.4.2.3" => "sha512",
        _ => "",
    };
    if n.is_empty() {
        oid.to_string()
    } else {
        n.to_string()
    }
}

/// Weak digest names (MD5, SHA-1) as a hint only.
pub fn is_weak_digest(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("md5") || n.starts_with("sha1") || n.ends_with("sha1")
}

fn attr_text(tag: der::Tag, value: &[u8]) -> String {
    match tag {
        der::Tag::BmpString => {
            let u: Vec<u16> = value
                .chunks_exact(2)
                .take(MAX_TEXT)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&u)
        }
        _ => String::from_utf8_lossy(&value[..value.len().min(MAX_TEXT * 4)]).into_owned(),
    }
}

fn name_parts(n: &Name) -> NameParts {
    let mut p = NameParts::default();
    let mut full = Vec::new();
    for rdn in n.0.iter().take(64) {
        for atv in rdn.0.iter().take(16) {
            let oid = atv.oid.to_string();
            let text = cap(attr_text(der::Tagged::tag(&atv.value), atv.value.value()));
            let key = match oid.as_str() {
                "2.5.4.3" => "CN",
                "2.5.4.6" => "C",
                "2.5.4.7" => "L",
                "2.5.4.8" => "ST",
                "2.5.4.10" => "O",
                "2.5.4.11" => "OU",
                "1.2.840.113549.1.9.1" => "E",
                _ => "",
            };
            let slot = match key {
                "CN" => Some(&mut p.common_name),
                "O" => Some(&mut p.organization),
                "OU" => Some(&mut p.org_unit),
                "C" => Some(&mut p.country),
                _ => None,
            };
            if let Some(s) = slot {
                if s.is_empty() {
                    *s = text.clone();
                }
            }
            let k = if key.is_empty() { oid } else { key.to_string() };
            full.push(format!("{k}={text}"));
        }
    }
    // Most specific first, as Windows shows it.
    full.reverse();
    p.full = cap(full.join(", "));
    p
}

/// Big-endian unsigned bytes to a decimal string. Input is capped by callers.
pub fn be_to_decimal(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = vec![0];
    for &byte in bytes.iter().take(64) {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            let v = *d as u32 * 256 + carry;
            *d = (v % 10) as u8;
            carry = v / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    while digits.len() > 1 && digits.last() == Some(&0) {
        digits.pop();
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

fn serial(bytes: &[u8]) -> (String, String) {
    let b = &bytes[..bytes.len().min(64)];
    let hex: Vec<String> = b.iter().map(|x| format!("{x:02x}")).collect();
    (hex.join(" "), be_to_decimal(b))
}

fn cert_info(index: usize, c: &Certificate) -> CertInfo {
    let t = &c.tbs_certificate;
    let (serial_hex, serial_dec) = serial(t.serial_number.as_bytes());
    let version = match t.version {
        x509_cert::Version::V1 => 1,
        x509_cert::Version::V2 => 2,
        x509_cert::Version::V3 => 3,
    };
    CertInfo {
        index,
        subject: name_parts(&t.subject),
        issuer: name_parts(&t.issuer),
        serial_hex,
        serial_dec,
        version,
        signature_algorithm: oid_name(&c.signature_algorithm.oid.to_string()),
        not_before: t.validity.not_before.to_unix_duration().as_secs(),
        not_after: t.validity.not_after.to_unix_duration().as_secs(),
        self_signed: t.subject == t.issuer,
        is_signer: false,
    }
}

/// Decode one PKCS#7 ContentInfo holding SignedData. Trailing padding after
/// the DER value is allowed, as Authenticode blobs are 8-byte aligned.
pub fn parse_pkcs7(blob: &[u8], sig: &mut Signature) {
    let blob = &blob[..blob.len().min(MAX_CERT_BLOB)];
    let ci = match SliceReader::new(blob)
        .map_err(|e| e.to_string())
        .and_then(|mut r| ContentInfo::decode(&mut r).map_err(|e| e.to_string()))
    {
        Ok(ci) => ci,
        Err(e) => {
            sig.error = cap(format!("PKCS#7 ContentInfo not decoded: {e}"));
            return;
        }
    };
    if ci.content_type.to_string() != "1.2.840.113549.1.7.2" {
        sig.error = cap(format!(
            "ContentInfo type {} is not SignedData",
            ci.content_type
        ));
        return;
    }
    let sd: SignedData = match ci.content.decode_as() {
        Ok(sd) => sd,
        Err(e) => {
            sig.error = cap(format!("SignedData not decoded: {e}"));
            return;
        }
    };
    sig.signed_data_version = sd.version as u8;
    if let Some(set) = &sd.certificates {
        for choice in set.0.iter() {
            if sig.certificates.len() >= MAX_CHAIN {
                break;
            }
            if let CertificateChoices::Certificate(c) = choice {
                let i = sig.certificates.len();
                sig.certificates.push(cert_info(i, c));
            }
        }
    }
    let certs: Vec<&Certificate> = sd
        .certificates
        .iter()
        .flat_map(|s| s.0.iter())
        .filter_map(|c| match c {
            CertificateChoices::Certificate(c) => Some(c),
            _ => None,
        })
        .take(MAX_CHAIN)
        .collect();
    if let Some(si) = sd.signer_infos.0.iter().next() {
        sig.digest_algorithm = oid_name(&si.digest_alg.oid.to_string());
        sig.signature_algorithm = oid_name(&si.signature_algorithm.oid.to_string());
        if let SignerIdentifier::IssuerAndSerialNumber(ias) = &si.sid {
            sig.signer_issuer = name_parts(&ias.issuer);
            let (h, d) = serial(ias.serial_number.as_bytes());
            sig.signer_serial_hex = h;
            sig.signer_serial_dec = d;
            sig.signer_index = certs.iter().position(|c| {
                c.tbs_certificate.issuer == ias.issuer
                    && c.tbs_certificate.serial_number == ias.serial_number
            });
        }
    } else {
        sig.error = "SignedData has no SignerInfo".into();
    }
    if let Some(i) = sig.signer_index {
        if let Some(c) = sig.certificates.get_mut(i) {
            c.is_signer = true;
        }
    }
}

/// Walk the WIN_CERTIFICATE entries at file offset `off` (the certificate
/// directory holds a file offset, not an RVA) for `size` bytes.
pub fn authenticode(b: &[u8], off: u32, size: u32) -> Vec<Signature> {
    let mut out = Vec::new();
    let start = off as usize;
    let Some(end) = start.checked_add(size as usize).filter(|e| *e <= b.len()) else {
        return out;
    };
    let mut p = start;
    while p + 8 <= end && out.len() < MAX_CERT_ENTRIES {
        let len = u32::from_le_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]]);
        let revision = u16::from_le_bytes([b[p + 4], b[p + 5]]);
        let cert_type = u16::from_le_bytes([b[p + 6], b[p + 7]]);
        let mut sig = Signature {
            offset: p as u64,
            length: len,
            revision,
            cert_type,
            ..Default::default()
        };
        let body_end = p.checked_add(len as usize);
        match body_end {
            Some(e) if len >= 8 && e <= end => {
                if cert_type == 0x0002 {
                    parse_pkcs7(&b[p + 8..e], &mut sig);
                } else {
                    sig.error = format!("certificate type 0x{cert_type:04X} is not PKCS#7");
                }
            }
            _ => {
                sig.error = format!("WIN_CERTIFICATE length {len} does not fit the directory");
                out.push(sig);
                break;
            }
        }
        out.push(sig);
        // Entries are 8-byte aligned.
        let next = (p as u64 + len as u64 + 7) & !7;
        if next <= p as u64 {
            break;
        }
        p = next as usize;
    }
    out
}
