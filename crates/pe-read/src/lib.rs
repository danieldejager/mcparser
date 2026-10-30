//! Bounded, parse-only reader for PE (Portable Executable) files.
//!
//! The input is treated as hostile. Every offset and size is checked against
//! the buffer, counts are capped, and malformed structures produce warnings
//! instead of panics. Nothing here executes, loads or disassembles the file.
#![forbid(unsafe_code)]

pub mod cert;
pub mod extra;
pub mod rsrc;

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Largest file the analyzer reads into memory.
pub const MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;
pub const MAX_SECTIONS: usize = 96;
pub const MAX_IMPORT_DLLS: usize = 1024;
pub const MAX_IMPORTS_PER_DLL: usize = 8192;
pub const MAX_IMPORTS_TOTAL: usize = 65536;
pub const MAX_EXPORTS: usize = 65536;
pub const MAX_RESOURCES: usize = 8192;
pub const MAX_RESOURCE_DEPTH: usize = 3;
pub const MAX_DEBUG_ENTRIES: usize = 64;
pub const MAX_NAME_LEN: usize = 512;

pub const DATA_DIRECTORY_NAMES: [&str; 16] = [
    "Export",
    "Import",
    "Resource",
    "Exception",
    "Certificate",
    "BaseReloc",
    "Debug",
    "Architecture",
    "GlobalPtr",
    "TLS",
    "LoadConfig",
    "BoundImport",
    "IAT",
    "DelayImport",
    "CLR",
    "Reserved",
];

#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub name: &'static str,
    pub offset: u64,
    pub size: u8,
    pub value: u64,
}

#[derive(Debug, Clone, Default)]
pub struct DataDirectory {
    pub index: usize,
    pub name: &'static str,
    pub rva: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Section {
    pub index: usize,
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub characteristics: u32,
    pub entropy: f64,
    pub md5: String,
    pub header_offset: u64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Import {
    pub dll: String,
    pub name: String,
    pub ordinal: Option<u16>,
    pub delayed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Export {
    pub ordinal: u32,
    pub name: String,
    pub rva: u32,
    pub forwarder: String,
}

#[derive(Debug, Clone, Default)]
pub struct Resource {
    pub type_name: String,
    pub name: String,
    pub language: u32,
    pub rva: u32,
    pub size: u32,
    pub sha256: String,
    /// File offset of the data when the whole payload is in the file.
    pub offset: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct DebugEntry {
    pub kind: u32,
    pub timestamp: u32,
    pub size: u32,
    pub pdb_path: String,
    /// PointerToRawData, a file offset (0 when the data is not in the file).
    pub raw_offset: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Default)]
pub struct PeReport {
    pub file_size: u64,
    pub hashes: Hashes,
    pub is_pe: bool,
    pub is_64: bool,
    pub machine: u16,
    pub timestamp: u32,
    pub characteristics: u16,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub entry_point: u32,
    pub image_base: u64,
    pub dos_header: Vec<Field>,
    pub file_header: Vec<Field>,
    pub optional_header: Vec<Field>,
    pub data_directories: Vec<DataDirectory>,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub export_dll_name: String,
    pub resources: Vec<Resource>,
    pub tls_present: bool,
    pub tls_callbacks: u32,
    pub debug: Vec<DebugEntry>,
    pub certificate_present: bool,
    pub certificate_size: u32,
    /// Authenticode entries decoded from the certificate table. Parsed only,
    /// never verified.
    pub signatures: Vec<cert::Signature>,
    /// First RT_VERSION resource that decodes as VS_VERSIONINFO.
    pub version_info: Option<rsrc::VersionInfo>,
    /// First RT_MANIFEST resource as text (escape on display).
    pub manifest: Option<rsrc::Manifest>,
    /// Validated icon images from RT_GROUP_ICON / RT_ICON, capped.
    pub icons: Vec<rsrc::Icon>,
    pub clr_present: bool,
    pub imphash: String,
    pub overlay_size: u64,
    pub warnings: Vec<String>,
}

impl PeReport {
    pub fn architecture(&self) -> &'static str {
        machine_name(self.machine)
    }
    pub fn subsystem_name(&self) -> &'static str {
        subsystem_name(self.subsystem)
    }
    pub fn signed(&self) -> bool {
        self.certificate_present
    }
    pub fn is_dll(&self) -> bool {
        self.characteristics & 0x2000 != 0
    }
    pub fn is_dotnet(&self) -> bool {
        self.clr_present
    }
}

pub fn machine_name(m: u16) -> &'static str {
    match m {
        0x014c => "x86",
        0x8664 => "x64",
        0x01c0 => "ARM",
        0x01c4 => "ARMv7",
        0xaa64 => "ARM64",
        0x0200 => "IA64",
        0x0000 => "unknown",
        _ => "other",
    }
}

pub fn subsystem_name(s: u16) -> &'static str {
    match s {
        1 => "native",
        2 => "windows_gui",
        3 => "windows_cui",
        5 => "os2_cui",
        7 => "posix_cui",
        9 => "windows_ce_gui",
        10 => "efi_application",
        11 => "efi_boot_driver",
        12 => "efi_runtime_driver",
        13 => "efi_rom",
        14 => "xbox",
        16 => "windows_boot_application",
        _ => "unknown",
    }
}

pub fn characteristics_flags(c: u16) -> Vec<&'static str> {
    const F: [(u16, &str); 13] = [
        (0x0001, "RELOCS_STRIPPED"),
        (0x0002, "EXECUTABLE_IMAGE"),
        (0x0004, "LINE_NUMS_STRIPPED"),
        (0x0008, "LOCAL_SYMS_STRIPPED"),
        (0x0020, "LARGE_ADDRESS_AWARE"),
        (0x0100, "32BIT_MACHINE"),
        (0x0200, "DEBUG_STRIPPED"),
        (0x0400, "REMOVABLE_RUN_FROM_SWAP"),
        (0x0800, "NET_RUN_FROM_SWAP"),
        (0x1000, "SYSTEM"),
        (0x2000, "DLL"),
        (0x4000, "UP_SYSTEM_ONLY"),
        (0x0010, "AGGRESSIVE_WS_TRIM"),
    ];
    F.iter()
        .filter(|(b, _)| c & b != 0)
        .map(|(_, n)| *n)
        .collect()
}

/// Shannon entropy in bits per byte (0.0 to 8.0).
pub fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// ISO 8601 UTC for Unix seconds. Years past 9999 are clamped.
pub fn iso_time(secs: u64) -> String {
    let secs = secs.min(253_402_300_799);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hashes(bytes: &[u8]) -> Hashes {
    Hashes {
        md5: hex(&Md5::digest(bytes)),
        sha1: hex(&Sha1::digest(bytes)),
        sha256: hex(&Sha256::digest(bytes)),
    }
}

// ---- bounded readers -------------------------------------------------------

fn slice(b: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    let end = off.checked_add(len)?;
    b.get(off..end)
}
fn u8_at(b: &[u8], off: usize) -> Option<u8> {
    b.get(off).copied()
}
fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    slice(b, off, 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    slice(b, off, 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    slice(b, off, 8).map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}
fn read_n(b: &[u8], off: usize, size: u8) -> Option<u64> {
    match size {
        1 => u8_at(b, off).map(u64::from),
        2 => u16_at(b, off).map(u64::from),
        4 => u32_at(b, off).map(u64::from),
        8 => u64_at(b, off),
        _ => None,
    }
}

/// NUL-terminated ASCII string, capped, printable characters only.
fn cstr(b: &[u8], off: usize) -> Option<String> {
    let rest = b.get(off..)?;
    let end = rest
        .iter()
        .take(MAX_NAME_LEN)
        .position(|c| *c == 0)
        .unwrap_or(rest.len().min(MAX_NAME_LEN));
    Some(
        rest[..end]
            .iter()
            .map(|c| {
                if c.is_ascii_graphic() || *c == b' ' {
                    *c as char
                } else {
                    '?'
                }
            })
            .collect(),
    )
}

struct Ctx<'a> {
    b: &'a [u8],
    sections: Vec<Section>,
    headers_size: u32,
    warnings: Vec<String>,
}

impl Ctx<'_> {
    /// Map an RVA to a file offset using the section table. Returns None when the
    /// RVA is not backed by file bytes.
    fn rva(&self, rva: u32) -> Option<usize> {
        if rva < self.headers_size {
            return ((rva as usize) < self.b.len()).then_some(rva as usize);
        }
        for s in &self.sections {
            let span = s.virtual_size.max(s.raw_size);
            if rva >= s.virtual_address && (rva as u64) < s.virtual_address as u64 + span as u64 {
                let delta = rva - s.virtual_address;
                if delta >= s.raw_size {
                    return None;
                }
                let off = (s.raw_offset as u64).checked_add(delta as u64)?;
                return ((off as usize) < self.b.len()).then_some(off as usize);
            }
        }
        None
    }
    fn warn(&mut self, w: impl Into<String>) {
        if self.warnings.len() < 256 {
            self.warnings.push(w.into());
        }
    }
}

fn fields(b: &[u8], base: usize, spec: &[(&'static str, usize, u8)]) -> Vec<Field> {
    spec.iter()
        .filter_map(|(name, rel, size)| {
            let off = base.checked_add(*rel)?;
            read_n(b, off, *size).map(|value| Field {
                name,
                offset: off as u64,
                size: *size,
                value,
            })
        })
        .collect()
}

/// Analyze a file on disk. Refuses files above MAX_FILE_SIZE. Reads the bytes
/// only; the file is never loaded or executed.
pub fn analyze_path(path: &std::path::Path) -> Result<PeReport, String> {
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    if meta.len() > MAX_FILE_SIZE {
        return Err(format!("file is larger than {MAX_FILE_SIZE} bytes"));
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    Ok(analyze(&bytes))
}

/// Analyze PE bytes. Never panics; anything malformed becomes a warning.
pub fn analyze(b: &[u8]) -> PeReport {
    let mut r = PeReport {
        file_size: b.len() as u64,
        hashes: hashes(b),
        ..Default::default()
    };
    if u16_at(b, 0) != Some(0x5a4d) {
        r.warnings.push("no MZ signature".into());
        return r;
    }
    r.dos_header = fields(
        b,
        0,
        &[
            ("e_magic", 0, 2),
            ("e_cblp", 2, 2),
            ("e_cp", 4, 2),
            ("e_crlc", 6, 2),
            ("e_cparhdr", 8, 2),
            ("e_minalloc", 10, 2),
            ("e_maxalloc", 12, 2),
            ("e_ss", 14, 2),
            ("e_sp", 16, 2),
            ("e_csum", 18, 2),
            ("e_ip", 20, 2),
            ("e_cs", 22, 2),
            ("e_lfarlc", 24, 2),
            ("e_ovno", 26, 2),
            ("e_oemid", 36, 2),
            ("e_oeminfo", 38, 2),
            ("e_lfanew", 60, 4),
        ],
    );
    let Some(lfanew) = u32_at(b, 60) else {
        r.warnings.push("truncated DOS header".into());
        return r;
    };
    let nt = lfanew as usize;
    if u32_at(b, nt) != Some(0x0000_4550) {
        r.warnings.push("no PE signature at e_lfanew".into());
        return r;
    }
    let fh = nt + 4;
    r.file_header = fields(
        b,
        fh,
        &[
            ("Machine", 0, 2),
            ("NumberOfSections", 2, 2),
            ("TimeDateStamp", 4, 4),
            ("PointerToSymbolTable", 8, 4),
            ("NumberOfSymbols", 12, 4),
            ("SizeOfOptionalHeader", 16, 2),
            ("Characteristics", 18, 2),
        ],
    );
    let (Some(machine), Some(nsec), Some(ts), Some(opt_size), Some(chars)) = (
        u16_at(b, fh),
        u16_at(b, fh + 2),
        u32_at(b, fh + 4),
        u16_at(b, fh + 16),
        u16_at(b, fh + 18),
    ) else {
        r.warnings.push("truncated file header".into());
        return r;
    };
    r.is_pe = true;
    r.machine = machine;
    r.timestamp = ts;
    r.characteristics = chars;

    let oh = fh + 20;
    let magic = u16_at(b, oh).unwrap_or(0);
    r.is_64 = magic == 0x20b;
    if magic != 0x10b && magic != 0x20b {
        r.warnings
            .push(format!("unknown optional header magic 0x{magic:x}"));
    }
    let mut spec: Vec<(&'static str, usize, u8)> = vec![
        ("Magic", 0, 2),
        ("MajorLinkerVersion", 2, 1),
        ("MinorLinkerVersion", 3, 1),
        ("SizeOfCode", 4, 4),
        ("SizeOfInitializedData", 8, 4),
        ("SizeOfUninitializedData", 12, 4),
        ("AddressOfEntryPoint", 16, 4),
        ("BaseOfCode", 20, 4),
    ];
    let w = if r.is_64 { 8u8 } else { 4u8 };
    let k = if r.is_64 { 4usize } else { 0 }; // shift after ImageBase and the four stack/heap sizes
    if !r.is_64 {
        spec.push(("BaseOfData", 24, 4));
    }
    spec.extend_from_slice(&[
        ("ImageBase", 24 + if r.is_64 { 0 } else { 4 }, w),
        ("SectionAlignment", 32, 4),
        ("FileAlignment", 36, 4),
        ("MajorOperatingSystemVersion", 40, 2),
        ("MinorOperatingSystemVersion", 42, 2),
        ("MajorImageVersion", 44, 2),
        ("MinorImageVersion", 46, 2),
        ("MajorSubsystemVersion", 48, 2),
        ("MinorSubsystemVersion", 50, 2),
        ("Win32VersionValue", 52, 4),
        ("SizeOfImage", 56, 4),
        ("SizeOfHeaders", 60, 4),
        ("CheckSum", 64, 4),
        ("Subsystem", 68, 2),
        ("DllCharacteristics", 70, 2),
        ("SizeOfStackReserve", 72, w),
        ("SizeOfStackCommit", 76 + k, w),
        ("SizeOfHeapReserve", 80 + 2 * k, w),
        ("SizeOfHeapCommit", 84 + 3 * k, w),
        ("LoaderFlags", 88 + 4 * k, 4),
        ("NumberOfRvaAndSizes", 92 + 4 * k, 4),
    ]);
    // Only keep fields that lie inside the declared optional header.
    spec.retain(|(_, rel, size)| rel + *size as usize <= opt_size as usize);
    r.optional_header = fields(b, oh, &spec);
    let get = |n: &str| {
        r.optional_header
            .iter()
            .find(|f| f.name == n)
            .map(|f| f.value)
    };
    r.entry_point = get("AddressOfEntryPoint").unwrap_or(0) as u32;
    r.image_base = get("ImageBase").unwrap_or(0);
    r.subsystem = get("Subsystem").unwrap_or(0) as u16;
    r.dll_characteristics = get("DllCharacteristics").unwrap_or(0) as u16;
    let headers_size = get("SizeOfHeaders").unwrap_or(0) as u32;
    let ndirs_decl = get("NumberOfRvaAndSizes").unwrap_or(0) as usize;
    let dirs_off = oh + 96 + 4 * k;
    let room = (opt_size as usize).saturating_sub(96 + 4 * k) / 8;
    let ndirs = ndirs_decl.min(16).min(room);
    if ndirs_decl > 16 {
        r.warnings
            .push(format!("NumberOfRvaAndSizes {ndirs_decl} capped at 16"));
    }
    for i in 0..ndirs {
        let off = dirs_off + i * 8;
        let (Some(rva), Some(size)) = (u32_at(b, off), u32_at(b, off + 4)) else {
            break;
        };
        r.data_directories.push(DataDirectory {
            index: i,
            name: DATA_DIRECTORY_NAMES[i],
            rva,
            size,
        });
    }

    // Section table
    let st = oh + opt_size as usize;
    let mut count = nsec as usize;
    if count > MAX_SECTIONS {
        r.warnings
            .push(format!("NumberOfSections {count} capped at {MAX_SECTIONS}"));
        count = MAX_SECTIONS;
    }
    let mut ctx = Ctx {
        b,
        sections: Vec::new(),
        headers_size,
        warnings: std::mem::take(&mut r.warnings),
    };
    for i in 0..count {
        let so = st + i * 40;
        let Some(h) = slice(b, so, 40) else {
            ctx.warn(format!("section table truncated at entry {i}"));
            break;
        };
        let name = String::from_utf8_lossy(&h[..8])
            .trim_end_matches('\0')
            .to_string();
        let s = Section {
            index: i,
            name,
            virtual_size: u32_at(h, 8).unwrap_or(0),
            virtual_address: u32_at(h, 12).unwrap_or(0),
            raw_size: u32_at(h, 16).unwrap_or(0),
            raw_offset: u32_at(h, 20).unwrap_or(0),
            characteristics: u32_at(h, 36).unwrap_or(0),
            header_offset: so as u64,
            ..Default::default()
        };
        ctx.sections.push(s);
    }
    let mut max_end = 0u64;
    for s in &mut ctx.sections {
        let start = s.raw_offset as usize;
        let end = (start as u64 + s.raw_size as u64).min(b.len() as u64) as usize;
        if (s.raw_offset as u64 + s.raw_size as u64) > b.len() as u64 && s.raw_size > 0 {
            ctx.warnings
                .push(format!("section {} raw data runs past end of file", s.name));
        }
        let data = b.get(start..end.max(start)).unwrap_or(&[]);
        s.entropy = (entropy(data) * 1000.0).round() / 1000.0;
        s.md5 = hex(&Md5::digest(data));
        if s.raw_size > 0 {
            max_end = max_end.max(end as u64);
        }
    }
    // Overlapping raw ranges are legal but suspicious.
    for i in 0..ctx.sections.len() {
        for j in i + 1..ctx.sections.len() {
            let (a, c) = (&ctx.sections[i], &ctx.sections[j]);
            let (a0, a1) = (a.raw_offset as u64, a.raw_offset as u64 + a.raw_size as u64);
            let (c0, c1) = (c.raw_offset as u64, c.raw_offset as u64 + c.raw_size as u64);
            if a.raw_size > 0 && c.raw_size > 0 && a0 < c1 && c0 < a1 {
                let w = format!("sections {} and {} overlap on disk", a.name, c.name);
                ctx.warn(w);
            }
        }
    }
    if max_end > 0 && max_end < b.len() as u64 {
        r.overlay_size = b.len() as u64 - max_end;
    }

    let dir = |i: usize| {
        r.data_directories
            .get(i)
            .filter(|d| d.rva != 0 && d.size != 0)
            .cloned()
    };
    if let Some(d) = dir(1) {
        r.imports = imports(&mut ctx, d.rva, r.is_64, false);
    }
    if let Some(d) = dir(13) {
        let mut more = imports(&mut ctx, d.rva, r.is_64, true);
        r.imports.append(&mut more);
    }
    if let Some(d) = dir(0) {
        let (n, e) = exports(&mut ctx, &d);
        r.export_dll_name = n;
        r.exports = e;
    }
    if let Some(d) = dir(2) {
        r.resources = resources(&mut ctx, d.rva);
    }
    if let Some(d) = dir(9) {
        r.tls_present = true;
        r.tls_callbacks = tls_callbacks(&mut ctx, d.rva, r.is_64, r.image_base);
    }
    if let Some(d) = dir(6) {
        r.debug = debug(&mut ctx, &d);
    }
    if let Some(d) = dir(4) {
        // Certificate directory holds a file offset, not an RVA.
        r.certificate_size = d.size;
        let end = d.rva as u64 + d.size as u64;
        if end <= b.len() as u64 && d.size >= 8 {
            r.certificate_present = true;
            r.signatures = cert::authenticode(b, d.rva, d.size);
            for sg in &r.signatures {
                if !sg.error.is_empty() {
                    ctx.warn(format!("certificate at 0x{:X}: {}", sg.offset, sg.error));
                }
            }
        } else {
            ctx.warn("certificate directory points outside the file");
        }
        if r.overlay_size > 0 && d.rva as u64 >= max_end {
            r.overlay_size = r.overlay_size.saturating_sub(d.size as u64);
        }
    }
    if let Some(d) = dir(14) {
        r.clr_present = ctx.rva(d.rva).and_then(|o| u32_at(b, o)).is_some();
    }
    resource_payloads(&mut r, b);
    r.imphash = imphash(&r.imports);
    r.sections = std::mem::take(&mut ctx.sections);
    r.warnings = ctx.warnings;
    r
}

fn imports(ctx: &mut Ctx, rva: u32, is_64: bool, delayed: bool) -> Vec<Import> {
    let mut out = Vec::new();
    let Some(mut off) = ctx.rva(rva) else {
        ctx.warn("import directory RVA not in file");
        return out;
    };
    let desc = if delayed { 32 } else { 20 };
    for _ in 0..MAX_IMPORT_DLLS {
        let Some(d) = slice(ctx.b, off, desc) else {
            ctx.warn("import descriptor truncated");
            break;
        };
        if d.iter().all(|x| *x == 0) {
            break;
        }
        let (name_rva, thunk_rva) = if delayed {
            // attributes, name, hmod, IAT, INT, ...
            (
                u32_at(d, 4).unwrap_or(0),
                u32_at(d, 16)
                    .filter(|v| *v != 0)
                    .or(u32_at(d, 12))
                    .unwrap_or(0),
            )
        } else {
            (
                u32_at(d, 12).unwrap_or(0),
                u32_at(d, 0)
                    .filter(|v| *v != 0)
                    .or(u32_at(d, 16))
                    .unwrap_or(0),
            )
        };
        let dll = ctx
            .rva(name_rva)
            .and_then(|o| cstr(ctx.b, o))
            .unwrap_or_default();
        if dll.is_empty() {
            ctx.warn("import descriptor with unreadable DLL name");
        }
        let Some(mut t) = ctx.rva(thunk_rva) else {
            off += desc;
            continue;
        };
        let step = if is_64 { 8 } else { 4 };
        for _ in 0..MAX_IMPORTS_PER_DLL {
            if out.len() >= MAX_IMPORTS_TOTAL {
                ctx.warn("import count capped");
                return out;
            }
            let v = if is_64 {
                u64_at(ctx.b, t)
            } else {
                u32_at(ctx.b, t).map(u64::from)
            };
            let Some(v) = v else { break };
            if v == 0 {
                break;
            }
            let by_ord = if is_64 {
                v & (1 << 63) != 0
            } else {
                v & (1 << 31) != 0
            };
            let imp = if by_ord {
                Import {
                    dll: dll.clone(),
                    name: String::new(),
                    ordinal: Some((v & 0xffff) as u16),
                    delayed,
                }
            } else {
                let name = ctx
                    .rva((v & 0x7fff_ffff) as u32)
                    .and_then(|o| cstr(ctx.b, o + 2))
                    .unwrap_or_default();
                Import {
                    dll: dll.clone(),
                    name,
                    ordinal: None,
                    delayed,
                }
            };
            out.push(imp);
            t += step;
        }
        off += desc;
    }
    out
}

fn exports(ctx: &mut Ctx, d: &DataDirectory) -> (String, Vec<Export>) {
    let mut out = Vec::new();
    let Some(off) = ctx.rva(d.rva) else {
        ctx.warn("export directory RVA not in file");
        return (String::new(), out);
    };
    let b = ctx.b;
    let (
        Some(name_rva),
        Some(base),
        Some(nfunc),
        Some(nnames),
        Some(afun),
        Some(anames),
        Some(aords),
    ) = (
        u32_at(b, off + 12),
        u32_at(b, off + 16),
        u32_at(b, off + 20),
        u32_at(b, off + 24),
        u32_at(b, off + 28),
        u32_at(b, off + 32),
        u32_at(b, off + 36),
    )
    else {
        ctx.warn("export directory truncated");
        return (String::new(), out);
    };
    let dll = ctx
        .rva(name_rva)
        .and_then(|o| cstr(b, o))
        .unwrap_or_default();
    let nfunc = (nfunc as usize).min(MAX_EXPORTS);
    let nnames = (nnames as usize).min(MAX_EXPORTS);
    let mut names: std::collections::HashMap<usize, String> = std::collections::HashMap::new();
    if let (Some(n), Some(o)) = (ctx.rva(anames), ctx.rva(aords)) {
        for i in 0..nnames {
            let (Some(nr), Some(ord)) = (u32_at(b, n + i * 4), u16_at(b, o + i * 2)) else {
                break;
            };
            names
                .entry(ord as usize)
                .or_insert_with(|| ctx.rva(nr).and_then(|x| cstr(b, x)).unwrap_or_default());
        }
    }
    let Some(f) = ctx.rva(afun) else {
        return (dll, out);
    };
    for i in 0..nfunc {
        let Some(rva) = u32_at(b, f + i * 4) else {
            break;
        };
        if rva == 0 {
            continue;
        }
        let name = names.get(&i).cloned().unwrap_or_default();
        let fwd = if rva >= d.rva && (rva as u64) < d.rva as u64 + d.size as u64 {
            ctx.rva(rva).and_then(|o| cstr(b, o)).unwrap_or_default()
        } else {
            String::new()
        };
        out.push(Export {
            ordinal: base.wrapping_add(i as u32),
            name,
            rva,
            forwarder: fwd,
        });
    }
    (dll, out)
}

fn resource_type_name(id: u32) -> String {
    let n = match id {
        1 => "CURSOR",
        2 => "BITMAP",
        3 => "ICON",
        4 => "MENU",
        5 => "DIALOG",
        6 => "STRING",
        7 => "FONTDIR",
        8 => "FONT",
        9 => "ACCELERATOR",
        10 => "RCDATA",
        11 => "MESSAGETABLE",
        12 => "GROUP_CURSOR",
        14 => "GROUP_ICON",
        16 => "VERSION",
        17 => "DLGINCLUDE",
        19 => "PLUGPLAY",
        20 => "VXD",
        21 => "ANICURSOR",
        22 => "ANIICON",
        23 => "HTML",
        24 => "MANIFEST",
        _ => "",
    };
    if n.is_empty() {
        format!("#{id}")
    } else {
        n.to_string()
    }
}

fn resources(ctx: &mut Ctx, rva: u32) -> Vec<Resource> {
    let mut out = Vec::new();
    let Some(root) = ctx.rva(rva) else {
        ctx.warn("resource directory RVA not in file");
        return out;
    };
    // Iterative walk with an explicit stack; depth and total visits are capped so
    // cyclic directories cannot loop forever.
    let mut stack: Vec<(usize, usize, Vec<String>, u32)> = vec![(root, 0, Vec::new(), 0)];
    let mut visits = 0usize;
    while let Some((dir, depth, path, _)) = stack.pop() {
        visits += 1;
        if visits > MAX_RESOURCES * 2 {
            ctx.warn("resource walk capped");
            break;
        }
        let (Some(nn), Some(ni)) = (u16_at(ctx.b, dir + 12), u16_at(ctx.b, dir + 14)) else {
            ctx.warn("resource directory truncated");
            continue;
        };
        let n = (nn as usize + ni as usize).min(MAX_RESOURCES);
        for i in 0..n {
            let e = dir + 16 + i * 8;
            let (Some(id), Some(target)) = (u32_at(ctx.b, e), u32_at(ctx.b, e + 4)) else {
                break;
            };
            let label = if id & 0x8000_0000 != 0 {
                let so = root.checked_add((id & 0x7fff_ffff) as usize);
                so.and_then(|so| {
                    let len = (u16_at(ctx.b, so)? as usize).min(MAX_NAME_LEN);
                    let raw = slice(ctx.b, so + 2, len * 2)?;
                    let u: Vec<u16> = raw
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    Some(String::from_utf16_lossy(&u))
                })
                .unwrap_or_default()
            } else if depth == 0 {
                resource_type_name(id)
            } else {
                id.to_string()
            };
            let mut p = path.clone();
            p.push(label);
            let child = root.checked_add((target & 0x7fff_ffff) as usize);
            let Some(child) = child else { continue };
            if target & 0x8000_0000 != 0 {
                if depth + 1 >= MAX_RESOURCE_DEPTH {
                    ctx.warn("resource tree deeper than expected");
                    continue;
                }
                stack.push((child, depth + 1, p, id));
            } else {
                if out.len() >= MAX_RESOURCES {
                    ctx.warn("resource count capped");
                    return out;
                }
                let (Some(drva), Some(size)) = (u32_at(ctx.b, child), u32_at(ctx.b, child + 4))
                else {
                    continue;
                };
                let data_off = ctx
                    .rva(drva)
                    .filter(|o| slice(ctx.b, *o, size as usize).is_some());
                let sha256 = data_off
                    .and_then(|o| slice(ctx.b, o, size as usize))
                    .map(|d| hex(&Sha256::digest(d)))
                    .unwrap_or_default();
                out.push(Resource {
                    type_name: p.first().cloned().unwrap_or_default(),
                    name: p.get(1).cloned().unwrap_or_default(),
                    language: p.get(2).and_then(|l| l.parse().ok()).unwrap_or(id),
                    rva: drva,
                    size,
                    sha256,
                    offset: data_off.map(|o| o as u64),
                });
            }
        }
    }
    out
}

/// Bytes of one resource, if its offset was validated during the walk.
fn resource_bytes<'a>(b: &'a [u8], res: &Resource) -> Option<&'a [u8]> {
    slice(b, usize::try_from(res.offset?).ok()?, res.size as usize)
}

fn resource_payloads(r: &mut PeReport, b: &[u8]) {
    r.version_info = r
        .resources
        .iter()
        .filter(|x| x.type_name == "VERSION")
        .take(4)
        .find_map(|x| resource_bytes(b, x).and_then(rsrc::version_info));
    r.manifest = r
        .resources
        .iter()
        .find(|x| x.type_name == "MANIFEST")
        .and_then(|x| resource_bytes(b, x))
        .map(rsrc::manifest);
    let mut total = 0usize;
    'groups: for g in r
        .resources
        .iter()
        .filter(|x| x.type_name == "GROUP_ICON")
        .take(8)
    {
        let Some(gd) = resource_bytes(b, g) else {
            continue;
        };
        for (_w, _h, _bits, id) in rsrc::group_icon_entries(gd) {
            if r.icons.len() >= rsrc::MAX_ICONS {
                break 'groups;
            }
            let Some(icon) = r
                .resources
                .iter()
                .find(|x| x.type_name == "ICON" && x.name == id.to_string())
            else {
                continue;
            };
            let Some((format, width, height, bit_count, bytes)) =
                resource_bytes(b, icon).and_then(rsrc::icon_payload)
            else {
                continue;
            };
            if total + bytes.len() > rsrc::MAX_ICON_TOTAL {
                break 'groups;
            }
            total += bytes.len();
            r.icons.push(rsrc::Icon {
                group: g.name.clone(),
                icon_id: id,
                width,
                height,
                bit_count,
                format,
                bytes,
            });
        }
    }
}

fn tls_callbacks(ctx: &mut Ctx, rva: u32, is_64: bool, image_base: u64) -> u32 {
    let Some(off) = ctx.rva(rva) else {
        ctx.warn("TLS directory RVA not in file");
        return 0;
    };
    let va = if is_64 {
        u64_at(ctx.b, off + 24)
    } else {
        u32_at(ctx.b, off + 12).map(u64::from)
    };
    let Some(va) = va.filter(|v| *v != 0) else {
        return 0;
    };
    let Some(cb_rva) = va
        .checked_sub(image_base)
        .and_then(|v| u32::try_from(v).ok())
    else {
        return 0;
    };
    let Some(mut p) = ctx.rva(cb_rva) else {
        return 0;
    };
    let mut n = 0;
    while n < 256 {
        let v = if is_64 {
            u64_at(ctx.b, p)
        } else {
            u32_at(ctx.b, p).map(u64::from)
        };
        match v {
            Some(v) if v != 0 => {
                n += 1;
                p += if is_64 { 8 } else { 4 };
            }
            _ => break,
        }
    }
    n
}

fn debug(ctx: &mut Ctx, d: &DataDirectory) -> Vec<DebugEntry> {
    let mut out = Vec::new();
    let Some(off) = ctx.rva(d.rva) else {
        ctx.warn("debug directory RVA not in file");
        return out;
    };
    let n = (d.size as usize / 28).min(MAX_DEBUG_ENTRIES);
    for i in 0..n {
        let e = off + i * 28;
        let (Some(ts), Some(kind), Some(size), Some(ptr)) = (
            u32_at(ctx.b, e + 4),
            u32_at(ctx.b, e + 12),
            u32_at(ctx.b, e + 16),
            u32_at(ctx.b, e + 24),
        ) else {
            break;
        };
        let mut pdb = String::new();
        if kind == 2 && u32_at(ctx.b, ptr as usize) == Some(0x5344_5352) {
            // "RSDS"
            pdb = cstr(ctx.b, ptr as usize + 24).unwrap_or_default();
        }
        out.push(DebugEntry {
            kind,
            timestamp: ts,
            size,
            pdb_path: pdb,
            raw_offset: ptr,
        });
    }
    out
}

/// Import hash in the common pefile style: lowercase dll without extension,
/// dot, lowercase function (or ord<N>), joined by commas, then MD5. Delay
/// imports are left out, as pefile does.
pub fn imphash(imports: &[Import]) -> String {
    let parts: Vec<String> = imports
        .iter()
        .filter(|i| !i.delayed)
        .map(|i| {
            let dll = i.dll.to_ascii_lowercase();
            let dll = ["ocx", "sys", "dll"]
                .iter()
                .find_map(|ext| dll.strip_suffix(&format!(".{ext}")).map(str::to_string))
                .unwrap_or(dll);
            let f = match i.ordinal {
                Some(o) => format!("ord{o}"),
                None => i.name.to_ascii_lowercase(),
            };
            format!("{dll}.{f}")
        })
        .collect();
    if parts.is_empty() {
        return String::new();
    }
    hex(&Md5::digest(parts.join(",").as_bytes()))
}
