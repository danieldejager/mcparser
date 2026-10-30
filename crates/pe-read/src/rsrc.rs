//! Decoders for resource payloads: VS_VERSIONINFO, RT_MANIFEST and icons.
//!
//! Parse only. Every length is checked against its parent block and the
//! payload, recursion depth and counts are capped, and anything odd is
//! skipped. Icon bytes are only passed on after their headers validate.

/// Largest VERSION resource decoded.
pub const MAX_VERSION_BYTES: usize = 64 * 1024;
pub const MAX_VERSION_STRINGS: usize = 256;
const MAX_VERSION_DEPTH: usize = 4;
const MAX_VALUE_CHARS: usize = 1024;
/// Manifest text kept, in bytes of the source payload.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// Icon payloads larger than this are skipped.
pub const MAX_ICON_BYTES: usize = 256 * 1024;
pub const MAX_ICONS: usize = 16;
/// Total icon bytes kept for previews.
pub const MAX_ICON_TOTAL: usize = 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct VersionString {
    /// Language and code page key, e.g. "040904B0".
    pub table: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct VersionInfo {
    pub fixed_present: bool,
    pub file_version: String,
    pub product_version: String,
    pub flags_mask: u32,
    pub flags: u32,
    pub os: u32,
    pub file_type: u32,
    pub file_subtype: u32,
    pub file_date: u64,
    pub strings: Vec<VersionString>,
    /// (language, code page) pairs from VarFileInfo\Translation.
    pub translations: Vec<(u16, u16)>,
    pub warnings: Vec<String>,
}

impl VersionInfo {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.strings
            .iter()
            .find(|s| s.key.eq_ignore_ascii_case(key))
            .map(|s| s.value.as_str())
    }
}

pub fn version_flag_names(flags: u32) -> Vec<&'static str> {
    const F: [(u32, &str); 6] = [
        (0x01, "DEBUG"),
        (0x02, "PRERELEASE"),
        (0x04, "PATCHED"),
        (0x08, "PRIVATEBUILD"),
        (0x10, "INFOINFERRED"),
        (0x20, "SPECIALBUILD"),
    ];
    F.iter()
        .filter(|(b, _)| flags & b != 0)
        .map(|(_, n)| *n)
        .collect()
}

pub fn version_os_name(os: u32) -> String {
    let hi = match os & 0xffff_0000 {
        0 => "",
        0x0001_0000 => "DOS",
        0x0002_0000 => "OS/2 16",
        0x0003_0000 => "OS/2 32",
        0x0004_0000 => "NT",
        _ => "other",
    };
    let lo = match os & 0xffff {
        0 => "",
        1 => "Windows16",
        2 => "PM16",
        3 => "PM32",
        4 => "Windows32",
        _ => "other",
    };
    match (hi, lo) {
        ("", "") => "unknown".into(),
        (h, "") => h.into(),
        ("", l) => l.into(),
        (h, l) => format!("{h} / {l}"),
    }
}

pub fn version_type_name(t: u32) -> &'static str {
    match t {
        1 => "APP",
        2 => "DLL",
        3 => "DRV",
        4 => "FONT",
        5 => "VXD",
        7 => "STATIC_LIB",
        _ => "unknown",
    }
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o.checked_add(2)?)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o.checked_add(4)?)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn align4(v: usize) -> usize {
    v.saturating_add(3) & !3
}

/// UTF-16LE NUL-terminated string starting at `o`, not past `end`. Returns
/// the text and the offset after the terminator.
fn wstr(b: &[u8], o: usize, end: usize, max_chars: usize) -> (String, usize) {
    let mut u = Vec::new();
    let mut p = o;
    while p + 2 <= end {
        let Some(c) = u16_at(b, p) else { break };
        p += 2;
        if c == 0 {
            break;
        }
        if u.len() < max_chars {
            u.push(c);
        }
    }
    let s: String = String::from_utf16_lossy(&u)
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    (s, p)
}

struct Block {
    value_len: usize,
    typ: u16,
    key: String,
    value: usize,
    children: usize,
    end: usize,
}

/// One version block header at `o`, clamped to `limit`.
fn block(b: &[u8], o: usize, limit: usize) -> Option<Block> {
    let len = u16_at(b, o)? as usize;
    let value_len = u16_at(b, o + 2)? as usize;
    let typ = u16_at(b, o + 4)?;
    if len < 6 {
        return None;
    }
    let end = o.checked_add(len)?.min(limit);
    let (key, after) = wstr(b, o + 6, end, 64);
    let value = align4(after);
    let vbytes = if typ == 1 { value_len * 2 } else { value_len };
    let children = align4(value.saturating_add(vbytes)).min(end);
    Some(Block {
        value_len,
        typ,
        key,
        value,
        children,
        end,
    })
}

/// Child blocks of a parent spanning `[start, end)`, capped.
fn children(b: &[u8], start: usize, end: usize) -> Vec<Block> {
    let mut out = Vec::new();
    let mut p = start;
    while p + 6 <= end && out.len() < MAX_VERSION_STRINGS {
        let Some(c) = block(b, p, end) else { break };
        let next = align4(c.end);
        out.push(c);
        if next <= p {
            break;
        }
        p = next;
    }
    out
}

/// Decode a VS_VERSIONINFO resource. None when the root is not VS_VERSION_INFO.
pub fn version_info(data: &[u8]) -> Option<VersionInfo> {
    let b = &data[..data.len().min(MAX_VERSION_BYTES)];
    let root = block(b, 0, b.len())?;
    if root.key != "VS_VERSION_INFO" {
        return None;
    }
    let mut v = VersionInfo::default();
    if root.value_len >= 52 && u32_at(b, root.value) == Some(0xFEEF_04BD) {
        let f = root.value;
        let g = |o| u32_at(b, f + o).unwrap_or(0);
        let ver =
            |ms: u32, ls: u32| format!("{}.{}.{}.{}", ms >> 16, ms & 0xffff, ls >> 16, ls & 0xffff);
        v.fixed_present = true;
        v.file_version = ver(g(8), g(12));
        v.product_version = ver(g(16), g(20));
        v.flags_mask = g(24);
        v.flags = g(28);
        v.os = g(32);
        v.file_type = g(36);
        v.file_subtype = g(40);
        v.file_date = (g(44) as u64) << 32 | g(48) as u64;
    } else if root.value_len > 0 {
        v.warnings
            .push("VS_FIXEDFILEINFO missing or bad signature".into());
    }
    walk(b, &root, 1, &mut v);
    Some(v)
}

fn walk(b: &[u8], parent: &Block, depth: usize, v: &mut VersionInfo) {
    if depth > MAX_VERSION_DEPTH {
        v.warnings.push("version info nested too deep".into());
        return;
    }
    for c in children(b, parent.children, parent.end) {
        match c.key.as_str() {
            "StringFileInfo" => {
                for table in children(b, c.children, c.end) {
                    for s in children(b, table.children, table.end) {
                        if v.strings.len() >= MAX_VERSION_STRINGS {
                            v.warnings.push("version strings capped".into());
                            return;
                        }
                        let value = if s.value_len == 0 {
                            String::new()
                        } else {
                            wstr(b, s.value, s.end, MAX_VALUE_CHARS).0
                        };
                        v.strings.push(VersionString {
                            table: table.key.to_uppercase(),
                            key: s.key.clone(),
                            value,
                        });
                    }
                }
            }
            "VarFileInfo" => {
                for var in children(b, c.children, c.end) {
                    if var.key == "Translation" && var.typ == 0 {
                        let n = (var.value_len / 4).min(64);
                        for i in 0..n {
                            if let (Some(l), Some(cp)) = (
                                u16_at(b, var.value + i * 4),
                                u16_at(b, var.value + i * 4 + 2),
                            ) {
                                if var.value + i * 4 + 4 <= var.end {
                                    v.translations.push((l, cp));
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Manifest {
    pub size: u32,
    pub truncated: bool,
    pub text: String,
    pub execution_level: String,
    pub ui_access: String,
}

/// Decode a manifest as text (UTF-8, or UTF-16 with a BOM), capped. The text
/// is never interpreted as markup; only `requestedExecutionLevel` is looked up
/// with a plain string search.
pub fn manifest(data: &[u8]) -> Manifest {
    let truncated = data.len() > MAX_MANIFEST_BYTES;
    let d = &data[..data.len().min(MAX_MANIFEST_BYTES)];
    let text = if d.starts_with(&[0xff, 0xfe]) || d.starts_with(&[0xfe, 0xff]) {
        let be = d[0] == 0xfe;
        let u: Vec<u16> = d[2..]
            .chunks_exact(2)
            .map(|c| {
                if be {
                    u16::from_be_bytes([c[0], c[1]])
                } else {
                    u16::from_le_bytes([c[0], c[1]])
                }
            })
            .collect();
        String::from_utf16_lossy(&u)
    } else {
        let d = d.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(d);
        String::from_utf8_lossy(d).into_owned()
    };
    let text: String = text
        .chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\r' && c != '\t' {
                '?'
            } else {
                c
            }
        })
        .collect();
    let (execution_level, ui_access) = match text.find("requestedExecutionLevel") {
        Some(i) => {
            let tag = &text[i..];
            let tag = &tag[..tag.find('>').unwrap_or(tag.len()).min(512)];
            (attr(tag, "level"), attr(tag, "uiAccess"))
        }
        None => (String::new(), String::new()),
    };
    Manifest {
        size: data.len().min(u32::MAX as usize) as u32,
        truncated,
        text,
        execution_level,
        ui_access,
    }
}

fn attr(tag: &str, name: &str) -> String {
    let mut rest = tag;
    while let Some(i) = rest.find(name) {
        let after = rest[i + name.len()..].trim_start();
        if let Some(v) = after.strip_prefix('=') {
            let v = v.trim_start();
            if let Some(q) = v.chars().next().filter(|q| *q == '"' || *q == '\'') {
                let body = &v[1..];
                if let Some(e) = body.find(q) {
                    return body[..e].chars().take(64).collect();
                }
            }
        }
        rest = &rest[i + name.len()..];
    }
    String::new()
}

#[derive(Debug, Clone, PartialEq)]
pub struct Icon {
    pub group: String,
    pub icon_id: u16,
    pub width: u32,
    pub height: u32,
    pub bit_count: u16,
    /// "png" or "ico" (a DIB wrapped in a one-image ICO container).
    pub format: &'static str,
    pub bytes: Vec<u8>,
}

/// GRPICONDIR entries: (width, height, bit count, icon id).
pub fn group_icon_entries(data: &[u8]) -> Vec<(u32, u32, u16, u16)> {
    let mut out = Vec::new();
    if u16_at(data, 0) != Some(0) || u16_at(data, 2) != Some(1) {
        return out;
    }
    let n = (u16_at(data, 4).unwrap_or(0) as usize).min(64);
    for i in 0..n {
        let e = 6 + i * 14;
        let (Some(w), Some(h), Some(bits), Some(id)) = (
            data.get(e),
            data.get(e + 1),
            u16_at(data, e + 6),
            u16_at(data, e + 12),
        ) else {
            break;
        };
        let w = if *w == 0 { 256 } else { *w as u32 };
        let h = if *h == 0 { 256 } else { *h as u32 };
        out.push((w, h, bits, id));
    }
    out
}

/// Validate one RT_ICON payload and return (format, width, height, bits,
/// bytes to show). PNG must have a well-formed IHDR; a DIB must be an
/// uncompressed BITMAPINFOHEADER whose pixel and mask data fit the payload.
pub fn icon_payload(data: &[u8]) -> Option<(&'static str, u32, u32, u16, Vec<u8>)> {
    if data.len() > MAX_ICON_BYTES || data.len() < 40 {
        return None;
    }
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        let ihdr_len = u32::from_be_bytes(data.get(8..12)?.try_into().ok()?);
        if ihdr_len != 13 || data.get(12..16)? != b"IHDR" {
            return None;
        }
        let w = u32::from_be_bytes(data.get(16..20)?.try_into().ok()?);
        let h = u32::from_be_bytes(data.get(20..24)?.try_into().ok()?);
        if !(1..=1024).contains(&w) || !(1..=1024).contains(&h) {
            return None;
        }
        let depth = *data.get(24)? as u16;
        return Some(("png", w, h, depth, data.to_vec()));
    }
    if u32_at(data, 0)? != 40 {
        return None;
    }
    let w = u32_at(data, 4)? as i32;
    let h2 = u32_at(data, 8)? as i32;
    let planes = u16_at(data, 12)?;
    let bits = u16_at(data, 14)?;
    let compression = u32_at(data, 16)?;
    if !(1..=256).contains(&w) || h2 <= 0 || h2 % 2 != 0 || !(1..=256).contains(&(h2 / 2)) {
        return None;
    }
    if planes != 1 || compression != 0 || ![1, 4, 8, 24, 32].contains(&bits) {
        return None;
    }
    let (w, h) = (w as usize, (h2 / 2) as usize);
    let palette = if bits <= 8 { (1usize << bits) * 4 } else { 0 };
    let xor_row = (w * bits as usize).div_ceil(32) * 4;
    let and_row = w.div_ceil(32) * 4;
    let need = 40 + palette + xor_row * h + and_row * h;
    if need > data.len() {
        return None;
    }
    let body = &data[..need];
    // One-image ICO container so the UI can show it as image/x-icon.
    let mut ico = Vec::with_capacity(22 + body.len());
    ico.extend_from_slice(&[0, 0, 1, 0, 1, 0]);
    ico.push(if w == 256 { 0 } else { w as u8 });
    ico.push(if h == 256 { 0 } else { h as u8 });
    ico.extend_from_slice(&[0, 0]);
    ico.extend_from_slice(&1u16.to_le_bytes());
    ico.extend_from_slice(&bits.to_le_bytes());
    ico.extend_from_slice(&(body.len() as u32).to_le_bytes());
    ico.extend_from_slice(&22u32.to_le_bytes());
    ico.extend_from_slice(body);
    Some(("ico", w as u32, h as u32, bits, ico))
}
