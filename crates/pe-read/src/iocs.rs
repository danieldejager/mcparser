//! Indicator candidates (URLs, domains, IP addresses, emails, registry keys,
//! file paths, named pipes, user agents) found in extracted PE strings.
//!
//! Parse only. Every scanner is hand written, walks its input once (plus
//! small, fixed look-arounds) and works on bounded input, so a hostile string
//! cannot cause super-linear work. No lookups are made: nothing here resolves
//! a name or contacts a host. Results are hints, not verdicts.

use crate::extra::PeString;

/// Most candidates kept per file.
pub const MAX_IOCS: usize = 5000;
/// Most candidates taken from one string.
pub const MAX_PER_STRING: usize = 32;
/// Longest input scanned per string (strings are already capped lower).
pub const MAX_INPUT: usize = 4096;
/// Longest value kept for one candidate.
pub const MAX_VALUE: usize = 1024;
/// Longest source string copy kept with a candidate.
pub const MAX_SOURCE: usize = 256;

#[derive(Debug, Clone, PartialEq)]
pub struct Ioc {
    /// url, domain, ipv4, ipv6, email, registry, path, pipe, user_agent
    pub kind: &'static str,
    /// Raw value as found (never defanged).
    pub value: String,
    /// Index of the source string in the extracted string list.
    pub string_idx: usize,
    /// Source string, capped at MAX_SOURCE characters.
    pub source: String,
    /// File offset of the value when known.
    pub offset: Option<u64>,
    /// Loopback, private, link-local, CGNAT, multicast, unspecified or
    /// broadcast address (or a URL / email on one).
    pub is_private: bool,
    /// Well-known benign host (Microsoft, W3C, certificate authorities,
    /// XML namespaces). A hint to deprioritise, not a verdict.
    pub benign_hint: bool,
    /// Encoding of the source string: ascii or utf16le.
    pub encoding: &'static str,
}

/// One candidate found in one string: kind, byte position, value.
#[derive(Debug, Clone, PartialEq)]
pub struct Found {
    pub kind: &'static str,
    pub pos: usize,
    pub value: String,
    pub is_private: bool,
    pub benign_hint: bool,
}

/// Candidates from all strings, deduplicated on (kind, value), first
/// occurrence kept, capped at MAX_IOCS.
pub fn extract(strings: &[PeString]) -> Vec<Ioc> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (i, s) in strings.iter().enumerate() {
        if out.len() >= MAX_IOCS {
            break;
        }
        let width = if s.encoding == "utf16le" { 2 } else { 1 };
        for f in scan(&s.value) {
            if out.len() >= MAX_IOCS {
                break;
            }
            if !seen.insert((f.kind, f.value.clone())) {
                continue;
            }
            // Strings are ASCII (one char per byte or per UTF-16 unit), so
            // the byte position maps straight to a file offset.
            let offset = if s.value.is_ascii() {
                Some(s.offset + (f.pos * width) as u64)
            } else {
                None
            };
            out.push(Ioc {
                kind: f.kind,
                value: f.value,
                string_idx: i,
                source: s.value.chars().take(MAX_SOURCE).collect(),
                offset,
                is_private: f.is_private,
                benign_hint: f.benign_hint,
                encoding: s.encoding,
            });
        }
    }
    out
}

/// Candidates in one string, in order of the scanners. Spans claimed by an
/// earlier scanner (URL, email, user agent, pipe, registry, path) are masked
/// before domains and IP addresses are looked for, so a URL host is not
/// reported twice.
pub fn scan(input: &str) -> Vec<Found> {
    let mut end = input.len().min(MAX_INPUT);
    while !input.is_char_boundary(end) {
        end -= 1;
    }
    let s = &input[..end];
    let b = s.as_bytes();
    let lower = s.to_ascii_lowercase();
    let lb = lower.as_bytes();
    let mut mask = vec![false; b.len()];
    let mut out = Vec::new();
    let add = |out: &mut Vec<Found>, mask: &mut [bool], kind, pos: usize, len: usize, private, benign| {
        for m in mask.iter_mut().skip(pos).take(len) {
            *m = true;
        }
        if out.len() < MAX_PER_STRING {
            let v: String = s[pos..pos + len].chars().take(MAX_VALUE).collect();
            out.push(Found { kind, pos, value: v, is_private: private, benign_hint: benign });
        }
    };

    // User agents: "Mozilla/" to the end of the string (quotes and control
    // characters end it), or the text after "User-Agent:".
    for (pat, skip) in [("mozilla/", 0usize), ("user-agent:", 11)] {
        if let Some(p) = lower.find(pat) {
            if mask[p] || (p > 0 && b[p - 1].is_ascii_alphanumeric()) {
                continue;
            }
            let mut st = p + skip;
            while st < b.len() && b[st] == b' ' {
                st += 1;
            }
            let mut e = st;
            while e < b.len() && b[e] != b'"' && b[e] != b'\'' && b[e] >= 0x20 && b[e] < 0x7f {
                e += 1;
            }
            let v = s[st..e].trim_end();
            if v.len() >= 8 && v.contains('/') {
                add(&mut out, &mut mask, "user_agent", st, v.len(), false, false);
            }
        }
    }

    // URLs.
    for scheme in ["https://", "http://", "ftp://"] {
        let mut from = 0;
        while let Some(rel) = lower[from..].find(scheme) {
            let p = from + rel;
            from = p + scheme.len();
            if mask[p] || (p > 0 && b[p - 1].is_ascii_alphanumeric()) {
                continue;
            }
            let mut e = from;
            while e < b.len() && url_char(b[e]) {
                e += 1;
            }
            while e > from && b".,;:)]}!?'".contains(&b[e - 1]) {
                e -= 1;
            }
            let host = url_host(&s[from..e]);
            let (ok, private) = host_check(host);
            if ok {
                let benign = benign_host(&host.to_ascii_lowercase());
                add(&mut out, &mut mask, "url", p, e - p, private, benign);
            }
            from = from.max(e);
        }
    }

    // Named pipes: \\.\pipe\name
    let mut from = 0;
    while let Some(rel) = lower[from..].find("\\\\.\\pipe\\") {
        let p = from + rel;
        let st = p + 9;
        let mut e = st;
        while e < b.len() && b[e] > 0x20 && b[e] < 0x7f && !b"\"'<>|".contains(&b[e]) {
            e += 1;
        }
        if e > st && !mask[p] {
            add(&mut out, &mut mask, "pipe", p, e - p, false, false);
        }
        from = e.max(p + 1);
    }

    // Registry keys: a hive prefix, or a SOFTWARE\ / SYSTEM\CurrentControlSet\
    // path at the start of a token.
    const HIVES: [&str; 12] = [
        "hkey_local_machine\\", "hkey_current_user\\", "hkey_classes_root\\", "hkey_users\\",
        "hkey_current_config\\", "hklm\\", "hkcu\\", "hkcr\\", "hku\\", "hkcc\\",
        "software\\", "system\\currentcontrolset\\",
    ];
    for hive in HIVES {
        let mut from = 0;
        while let Some(rel) = lower[from..].find(hive) {
            let p = from + rel;
            from = p + hive.len();
            let start_ok = p == 0 || !(b[p - 1].is_ascii_alphanumeric() || b[p - 1] == b'\\' || b[p - 1] == b'_');
            if mask[p] || !start_ok {
                continue;
            }
            let mut e = from;
            while e < b.len() && b[e] >= 0x20 && b[e] < 0x7f && !b"\"<>|".contains(&b[e]) {
                e += 1;
            }
            let v = s[p..e].trim_end();
            if v.len() > hive.len() {
                add(&mut out, &mut mask, "registry", p, v.len(), false, false);
                from = e;
            }
        }
    }

    // Windows paths: X:\..., %VAR%\..., \\server\share\...
    let mut i = 0;
    while i < b.len() {
        let st = i;
        let mut body = None;
        if i + 2 < b.len() && b[i].is_ascii_alphabetic() && b[i + 1] == b':' && b[i + 2] == b'\\' && (i == 0 || !b[i - 1].is_ascii_alphanumeric()) {
            body = Some(i + 3);
        } else if b[i] == b'%' && (i == 0 || !b[i - 1].is_ascii_alphanumeric()) {
            let mut j = i + 1;
            while j < b.len() && j - i <= 32 && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                j += 1;
            }
            if j > i + 1 && j + 1 < b.len() && b[j] == b'%' && b[j + 1] == b'\\' {
                body = Some(j + 2);
            }
        } else if i + 2 < b.len() && b[i] == b'\\' && b[i + 1] == b'\\' && b[i + 2].is_ascii_alphanumeric() && (i == 0 || b[i - 1] != b'\\') {
            body = Some(i + 2);
        }
        let Some(bs) = body else {
            i += 1;
            continue;
        };
        if mask[st] {
            i += 1;
            continue;
        }
        let mut e = bs;
        while e < b.len() && b[e] >= 0x20 && b[e] < 0x7f && !b"\"'<>|*?".contains(&b[e]) {
            if b[e] == b' ' && ends_with_ext(&lb[st..e]) {
                break;
            }
            e += 1;
        }
        let v = s[st..e].trim_end_matches([' ', '.', ',', ';', ')']);
        let unc_ok = b[st] != b'\\' || v[2..].contains('\\');
        if v.len() > bs - st && unc_ok {
            add(&mut out, &mut mask, "path", st, v.len(), false, false);
            i = st + v.len();
        } else {
            i = e.max(i + 1);
        }
    }

    // Email addresses: bounded scan either side of each '@'.
    for p in 0..b.len() {
        if b[p] != b'@' || mask[p] {
            continue;
        }
        let mut st = p;
        while st > 0 && p - st < 64 && !mask[st - 1] && (b[st - 1].is_ascii_alphanumeric() || b"._%+-".contains(&b[st - 1])) {
            st -= 1;
        }
        while st < p && b[st] == b'.' {
            st += 1;
        }
        let mut e = p + 1;
        while e < b.len() && e - p <= 253 && (b[e].is_ascii_alphanumeric() || b[e] == b'.' || b[e] == b'-') {
            e += 1;
        }
        while e > p + 1 && (b[e - 1] == b'.' || b[e - 1] == b'-') {
            e -= 1;
        }
        if st < p && domain_ok(&s[p + 1..e]) {
            let benign = benign_host(&lower[p + 1..e]);
            add(&mut out, &mut mask, "email", st, e - st, false, benign);
        }
    }

    // Tokens for domains and addresses: runs of [A-Za-z0-9.:-] outside the
    // masked spans. Each byte is visited once.
    let mut i = 0;
    while i < b.len() {
        if mask[i] || !token_char(b[i]) {
            i += 1;
            continue;
        }
        let st = i;
        while i < b.len() && !mask[i] && token_char(b[i]) {
            i += 1;
        }
        let tok = &s[st..i];
        let before = if st > 0 { b[st - 1] } else { b' ' };
        let after = if i < b.len() { b[i] } else { b' ' };
        if before == b'_' || after == b'_' {
            continue;
        }
        if tok.contains(':') {
            if let Some((v, private)) = ipv6(tok) {
                add(&mut out, &mut mask, "ipv6", st, v.len(), private, false);
                continue;
            }
            // host:port, or text with colons: look at each part.
            let mut off = 0;
            for part in tok.split(':') {
                if let Some(f) = host_token(part, &lower, st + off) {
                    if out.len() < MAX_PER_STRING {
                        out.push(f);
                    }
                }
                off += part.len() + 1;
            }
        } else if let Some(f) = host_token(tok, &lower, st) {
            if out.len() < MAX_PER_STRING {
                out.push(f);
            }
        }
    }
    out
}

fn host_token(tok: &str, lower: &str, pos: usize) -> Option<Found> {
    let t = tok.trim_matches(|c| c == '.' || c == '-');
    let lead = tok.len() - tok.trim_start_matches(['.', '-']).len();
    let pos = pos + lead;
    if t.is_empty() {
        return None;
    }
    if t.bytes().all(|c| c.is_ascii_digit() || c == b'.') {
        // A dotted quad right after "v", or in a string that talks about a
        // version or build, is a version number, not an address.
        if lead > 0 {
            return None;
        }
        let ip = ipv4(t)?;
        let pre = &lower[pos.saturating_sub(24)..pos];
        let prev = lower.as_bytes().get(pos.wrapping_sub(1)).copied().unwrap_or(b' ');
        if prev == b'v' || pre.contains("version") || pre.contains("ver") || pre.contains("build") || lower.contains("fileversion") || lower.contains("productversion") {
            return None;
        }
        return Some(Found { kind: "ipv4", pos, value: t.to_string(), is_private: private_v4(ip), benign_hint: false });
    }
    if domain_ok(t) {
        let benign = benign_host(&t.to_ascii_lowercase());
        return Some(Found { kind: "domain", pos, value: t.to_string(), is_private: false, benign_hint: benign });
    }
    None
}

fn token_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b':'
}

fn url_char(c: u8) -> bool {
    c > 0x20 && c < 0x7f && !b"\"'<>`^{}|\\".contains(&c)
}

fn ends_with_ext(l: &[u8]) -> bool {
    const EXT: [&[u8]; 13] = [b".exe", b".dll", b".sys", b".bat", b".cmd", b".ps1", b".vbs", b".js", b".scr", b".lnk", b".tmp", b".dat", b".pdb"];
    EXT.iter().any(|e| l.ends_with(e))
}

/// Host part of the text after a URL scheme: before the first / ? #, without
/// user info and port. IPv6 literals keep their brackets stripped.
pub fn url_host(rest: &str) -> &str {
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    let auth = auth.rsplit('@').next().unwrap_or("");
    if let Some(r) = auth.strip_prefix('[') {
        return r.split(']').next().unwrap_or("");
    }
    auth.split(':').next().unwrap_or("")
}

/// (looks like a real host, is a private/loopback address).
fn host_check(host: &str) -> (bool, bool) {
    if let Some(ip) = ipv4(host) {
        return (true, private_v4(ip));
    }
    if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        return (true, private_v6(&ip));
    }
    if host.eq_ignore_ascii_case("localhost") {
        return (true, true);
    }
    (domain_ok(host), false)
}

/// Strict dotted quad: four decimal octets 0 to 255, no leading zeros.
pub fn ipv4(t: &str) -> Option<[u8; 4]> {
    let mut o = [0u8; 4];
    let mut n = 0;
    for p in t.split('.') {
        if n == 4 || p.is_empty() || p.len() > 3 || !p.bytes().all(|c| c.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0')) {
            return None;
        }
        o[n] = p.parse::<u16>().ok().filter(|v| *v < 256)? as u8;
        n += 1;
    }
    (n == 4).then_some(o)
}

/// Not publicly routable: 0/8, 10/8, 100.64/10, 127/8, 169.254/16,
/// 172.16/12, 192.168/16, 224/4 and up (multicast, reserved, broadcast).
/// Documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24) are not
/// flagged.
pub fn private_v4(o: [u8; 4]) -> bool {
    o[0] == 0
        || o[0] == 10
        || o[0] == 127
        || (o[0] == 100 && (64..128).contains(&o[1]))
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (16..32).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || o[0] >= 224
}

fn private_v6(ip: &std::net::Ipv6Addr) -> bool {
    let s = ip.segments();
    ip.is_loopback() || ip.is_unspecified() || (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xff00) == 0xff00
        || ip.to_ipv4_mapped().map(|v| private_v4(v.octets())).unwrap_or(false)
}

/// An IPv6 address token. Bare "::", short C++-like "a::b" and anything that
/// does not parse are rejected.
fn ipv6(tok: &str) -> Option<(&str, bool)> {
    let t = tok.trim_end_matches(['.', '-']);
    if t.len() < 3 || t.len() > 45 {
        return None;
    }
    let ip = t.parse::<std::net::Ipv6Addr>().ok()?;
    let groups = t.split(':').filter(|g| !g.is_empty()).count();
    let l = t.to_ascii_lowercase();
    let known = l == "::1" || ["fe80:", "2001:", "2002:", "fc", "fd", "ff0", "::ffff:"].iter().any(|p| l.starts_with(p));
    if groups < 3 && !known {
        return None;
    }
    Some((t, private_v6(&ip)))
}

/// Plausible DNS name: two or more labels of letters, digits and hyphens,
/// a known lowercase top-level domain, not all digits.
pub fn domain_ok(d: &str) -> bool {
    if d.len() < 4 || d.len() > 253 || !d.contains('.') {
        return false;
    }
    let labels: Vec<&str> = d.split('.').collect();
    if labels.iter().any(|l| l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-') || !l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')) {
        return false;
    }
    let tld = labels[labels.len() - 1];
    // .NET names such as System.IO use an upper-case "TLD"; real hosts in
    // binaries are almost always lower case.
    if tld.bytes().any(|c| c.is_ascii_uppercase()) {
        return false;
    }
    TLDS.binary_search(&tld).is_ok()
}

/// Common and abused top-level domains. Left out on purpose because they
/// collide with file extensions in binaries: py, sh, rs, so, md, pl, cs, js.
const TLDS: &[&str] = &[
    "ae", "am", "app", "ar", "at", "au", "az", "be", "bg", "bid", "biz", "br", "buzz", "by", "ca", "cc", "cf",
    "ch", "cl", "click", "cloud", "club", "cn", "co", "com", "cz", "de", "dev", "dk", "ee", "es", "eu", "fi",
    "fr", "fun", "ga", "ge", "gov", "gq", "gr", "hk", "hr", "hu", "icu", "id", "ie", "il", "in", "info", "io",
    "ir", "is", "it", "jp", "kr", "kz", "li", "link", "live", "lt", "lu", "lv", "me", "ml", "mn", "mobi", "mx",
    "my", "name", "net", "nl", "no", "nu", "nz", "onion", "online", "org", "ph", "pk", "pro", "pt", "pw",
    "ro", "ru", "sa", "se", "sg", "shop", "site", "sk", "space", "store", "su", "tech", "th", "tk", "to",
    "top", "tr", "tv", "tw", "ua", "uk", "us", "uz", "vip", "vn", "website", "work", "ws", "xyz", "za",
];

/// Hosts that show up in benign binaries: Microsoft, XML namespaces and
/// certificate authorities (CRL, OCSP and CPS URLs).
const BENIGN: &[&str] = &[
    "microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com", "w3.org", "xmlsoap.org",
    "openxmlformats.org", "purl.org", "adobe.com", "digicert.com", "verisign.com", "symantec.com",
    "symcb.com", "symcd.com", "thawte.com", "geotrust.com", "globalsign.com", "globalsign.net",
    "sectigo.com", "comodoca.com", "comodo.com", "usertrust.com", "entrust.net", "godaddy.com",
    "letsencrypt.org", "identrust.com", "certum.pl", "certum.com", "ws.symantec.com", "apache.org",
];

pub fn benign_host(h: &str) -> bool {
    let h = h.trim_end_matches('.');
    BENIGN.iter().any(|d| h == *d || (h.len() > d.len() && h.ends_with(d) && h.as_bytes()[h.len() - d.len() - 1] == b'.'))
}

/// Defanged copy for display: hxxp, fxp and [.] (and [@] for emails).
pub fn defang(v: &str) -> String {
    let mut s = v.replace('.', "[.]").replace('@', "[@]");
    for (a, b) in [("http", "hxxp"), ("HTTP", "hXXp"), ("ftp://", "fxp://"), ("FTP://", "FXP://")] {
        s = s.replace(a, b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(s: &str) -> Vec<(&'static str, String)> {
        scan(s).into_iter().map(|f| (f.kind, f.value)).collect()
    }
    fn one(s: &str) -> Found {
        let v = scan(s);
        assert_eq!(v.len(), 1, "{s}: {v:?}");
        v.into_iter().next().unwrap()
    }

    #[test]
    fn tld_list_is_sorted() {
        let mut t = TLDS.to_vec();
        t.sort();
        assert_eq!(t, TLDS);
    }

    #[test]
    fn urls() {
        let f = one("GET http://c2.example.com:8080/gate.php?id=1 HTTP/1.1");
        assert_eq!((f.kind, f.value.as_str(), f.is_private, f.benign_hint), ("url", "http://c2.example.com:8080/gate.php?id=1", false, false));
        assert_eq!(one("x https://203.0.113.7/a\"").value, "https://203.0.113.7/a");
        assert_eq!(one("ftp://files.example.org/drop.bin").kind, "url");
        let p = one("http://192.168.1.10/x");
        assert!(p.is_private);
        assert!(one("http://[2001:db8::1]/x").kind == "url");
        let b = one("http://schemas.microsoft.com/SMI/2005/WindowsSettings");
        assert!(b.benign_hint);
        assert!(one("http://crl3.digicert.com/sha2-assured-cs-g1.crl").benign_hint);
        assert!(one("http://www.w3.org/2000/09/xmldsig#").benign_hint);
        // Trailing punctuation is not part of the URL.
        assert_eq!(one("see (https://example.net/a).").value, "https://example.net/a");
        // No host, or no plausible host: nothing.
        assert!(kinds("http://").is_empty());
        assert!(kinds("http://notahost/").is_empty());
    }

    #[test]
    fn defanged_input_is_not_refanged() {
        let v = kinds("hxxp://bad[.]example[.]com/x and bad[.]example.com");
        assert!(v.iter().all(|(k, _)| *k != "url"), "{v:?}");
        // Text after a bracket still reads as a name; it is reported as found.
        assert!(v.iter().all(|(_, val)| !val.contains('[')), "{v:?}");
        assert_eq!(defang("http://c2.example.com/a"), "hxxp://c2[.]example[.]com/a");
        assert_eq!(defang("a@example.com"), "a[@]example[.]com");
        assert_eq!(defang("198.51.100.7"), "198[.]51[.]100[.]7");
    }

    #[test]
    fn ipv4_public_private_and_versions() {
        let f = one("connect 198.51.100.23 now");
        assert_eq!((f.kind, f.value.as_str(), f.is_private), ("ipv4", "198.51.100.23", false));
        assert_eq!(one("192.0.2.5:443").value, "192.0.2.5");
        for p in ["10.0.0.1", "127.0.0.1", "192.168.0.5", "172.16.4.4", "169.254.1.1", "0.0.0.0", "100.64.0.1", "224.0.0.251", "255.255.255.255"] {
            assert!(one(p).is_private, "{p}");
        }
        assert!(!one("172.32.0.1").is_private);
        // Version lookalikes are skipped.
        assert!(kinds("FileVersion 10.0.19041.1").is_empty());
        assert!(kinds("v1.2.3.4").is_empty());
        assert!(kinds("version=\"6.0.0.0\"").is_empty());
        assert!(kinds("build 5.1.2.3").is_empty());
        assert!(kinds("Assembly 1.2.3.4.5").is_empty());
        assert!(kinds("256.1.1.1 01.2.3.4 1.2.3").is_empty());
    }

    #[test]
    fn ipv6() {
        let f = one("peer 2001:db8:85a3::8a2e:370:7334");
        assert_eq!((f.kind, f.is_private), ("ipv6", false));
        assert!(one("::1").is_private);
        assert!(one("fe80::1").is_private);
        assert!(one("fd00::5:6").is_private);
        // C++ scopes, times and MAC addresses are not addresses.
        assert!(kinds("std::vector a::b Foo::Bar").is_empty());
        assert!(kinds("12:30:45 00:11:22:33:44:55").is_empty());
    }

    #[test]
    fn domains() {
        let f = one("resolve update.example.com please");
        assert_eq!((f.kind, f.value.as_str()), ("domain", "update.example.com"));
        assert_eq!(one("abcdefghij.onion").kind, "domain");
        assert!(one("login.microsoftonline.com").benign_hint == false);
        assert!(one("go.microsoft.com").benign_hint);
        // File names, .NET namespaces and noise are not domains.
        assert!(kinds("kernel32.dll user32.DLL System.IO System.Net.Http a.b").is_empty());
        assert!(kinds("setup.py run.sh lib.rs main.js").is_empty());
        assert!(kinds("_foo.com_").is_empty());
    }

    #[test]
    fn emails() {
        let f = one("contact: ops-team@mail.example.com.");
        assert_eq!((f.kind, f.value.as_str()), ("email", "ops-team@mail.example.com"));
        assert!(one("signer@digicert.com").benign_hint);
        assert!(kinds("@example.com user@ a@b").is_empty() || kinds("@example.com user@ a@b").iter().all(|(k, _)| *k != "email"));
    }

    #[test]
    fn registry_paths_pipes_user_agents() {
        let r = one("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        assert_eq!(r.kind, "registry");
        assert_eq!(one("hklm\\SYSTEM\\CurrentControlSet\\Services\\svc").kind, "registry");
        assert_eq!(one("Software\\Classes\\ms-settings\\shell\\open\\command").kind, "registry");
        assert_eq!(one("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies").value, "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies");

        let p = one("C:\\Users\\Public\\Documents\\stage2.exe -silent");
        assert_eq!((p.kind, p.value.as_str()), ("path", "C:\\Users\\Public\\Documents\\stage2.exe"));
        assert_eq!(one("%APPDATA%\\Example\\cfg.dat").kind, "path");
        assert_eq!(one("C:\\Program Files\\Example App\\app.exe").value, "C:\\Program Files\\Example App\\app.exe");
        assert_eq!(one("\\\\fileserver\\share\\x.bin").kind, "path");

        let n = one("\\\\.\\pipe\\example_pipe_01");
        assert_eq!((n.kind, n.value.as_str()), ("pipe", "\\\\.\\pipe\\example_pipe_01"));

        let u = one("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        assert_eq!(u.kind, "user_agent");
        assert!(u.value.ends_with("537.36"));
        assert_eq!(one("User-Agent: ExampleBot/1.0").value, "ExampleBot/1.0");
    }

    #[test]
    fn noise_gives_nothing() {
        for s in ["GetProcAddress", "This program cannot be run in DOS mode.", "!This is a test", "abc.def", "1.0", "%s:%d", "::", "....", "@@@@", "C:", "\\\\", "HKLM\\"] {
            assert!(kinds(s).is_empty(), "{s}: {:?}", kinds(s));
        }
    }

    #[test]
    fn hostile_strings_are_bounded() {
        let long = "a.".repeat(50_000) + "com";
        let _ = scan(&long);
        let ats = "a@".repeat(50_000);
        let _ = scan(&ats);
        let colons = "1:".repeat(50_000);
        let _ = scan(&colons);
        let urls = "http://example.com/ ".repeat(10_000);
        assert!(scan(&urls).len() <= MAX_PER_STRING);
        let t = std::time::Instant::now();
        for _ in 0..20 {
            let _ = scan(&"http://x.example.com/".repeat(500));
            let _ = scan(&"C:\\a".repeat(2000));
            let _ = scan(&"HKCU\\".repeat(1000));
        }
        assert!(t.elapsed().as_secs() < 5);
    }

    #[test]
    fn extract_dedupes_and_maps_offsets() {
        let s = |off, enc, v: &str| PeString { offset: off, encoding: enc, category: "other", value: v.to_string() };
        let strings = vec![
            s(0x100, "ascii", "x http://c2.example.com/a"),
            s(0x200, "utf16le", "go 198.51.100.9"),
            s(0x300, "ascii", "http://c2.example.com/a"),
        ];
        let v = extract(&strings);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].offset, Some(0x102));
        assert_eq!((v[1].kind, v[1].encoding, v[1].offset, v[1].string_idx), ("ipv4", "utf16le", Some(0x200 + 6), 1));
        assert_eq!(v[1].source, "go 198.51.100.9");
    }
}
