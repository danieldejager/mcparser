//! Static indicators, strings, Rich header and mitigations. All of these are
//! hints read from bytes, not verdicts.

use crate::PeReport;

pub const MAX_STRINGS: usize = 20_000;
pub const MAX_STRING_LEN: usize = 1024;

#[derive(Debug, Clone, PartialEq)]
pub struct Indicator {
    pub rule: &'static str,
    pub severity: &'static str, // info, low, medium, high
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PeString {
    pub offset: u64,
    pub encoding: &'static str, // ascii or utf16le
    pub category: &'static str, // url, ip, registry, file, other
    pub value: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RichEntry {
    pub product_id: u16,
    pub build: u16,
    pub count: u32,
}

/// Mitigation flags from DllCharacteristics, as (name, enabled).
pub fn mitigations(r: &PeReport) -> Vec<(&'static str, bool)> {
    let d = r.dll_characteristics;
    vec![
        ("ASLR (DYNAMIC_BASE)", d & 0x0040 != 0),
        ("High entropy VA", d & 0x0020 != 0),
        ("DEP (NX_COMPAT)", d & 0x0100 != 0),
        ("SEH allowed (not NO_SEH)", d & 0x0400 == 0),
        ("CFG (GUARD_CF)", d & 0x4000 != 0),
        ("Force integrity", d & 0x0080 != 0),
        ("AppContainer", d & 0x1000 != 0),
    ]
}

/// Index of the section that holds the entry point RVA.
pub fn entry_section(r: &PeReport) -> Option<usize> {
    r.sections.iter().position(|s| {
        let span = s.virtual_size.max(s.raw_size) as u64;
        r.entry_point >= s.virtual_address
            && (r.entry_point as u64) < s.virtual_address as u64 + span
    })
}

/// Rich header between the DOS stub and the PE header, decoded with its XOR key.
pub fn rich_header(b: &[u8]) -> Vec<RichEntry> {
    let lfanew = b
        .get(60..64)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
        .unwrap_or(0);
    let end = lfanew.min(b.len()).min(4096);
    let area = &b[..end];
    let Some(rich) = area.windows(4).rposition(|w| w == b"Rich") else {
        return Vec::new();
    };
    let Some(key) = area
        .get(rich + 4..rich + 8)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    else {
        return Vec::new();
    };
    let rd = |o: usize| {
        area.get(o..o + 4)
            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) ^ key)
    };
    // walk back to "DanS"
    let mut start = None;
    let mut o = rich;
    while o >= 4 {
        o -= 4;
        if rd(o) == Some(0x536e_6144) {
            start = Some(o);
            break;
        }
    }
    let Some(start) = start else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut p = start + 16; // DanS plus three padding dwords
    while p + 8 <= rich && out.len() < 512 {
        let (Some(id), Some(count)) = (rd(p), rd(p + 4)) else {
            break;
        };
        out.push(RichEntry {
            product_id: (id >> 16) as u16,
            build: (id & 0xffff) as u16,
            count,
        });
        p += 8;
    }
    out
}

fn categorize(s: &str) -> &'static str {
    let l = s.to_ascii_lowercase();
    if l.contains("http://") || l.contains("https://") || l.contains("ftp://") {
        return "url";
    }
    if l.starts_with("hkey_")
        || l.contains("\\software\\")
        || l.starts_with("software\\")
        || l.contains("currentversion\\run")
    {
        return "registry";
    }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.chars().all(|c| c.is_ascii_digit())
                && p.parse::<u16>().map(|v| v < 256).unwrap_or(false)
        })
    {
        return "ip";
    }
    const EXT: [&str; 12] = [
        ".exe", ".dll", ".sys", ".bat", ".ps1", ".vbs", ".js", ".scr", ".lnk", ".tmp", ".dat",
        ".cmd",
    ];
    if EXT.iter().any(|e| l.ends_with(e)) || l.contains(":\\") {
        return "file";
    }
    "other"
}

/// Printable ASCII and UTF-16LE strings of at least `min_len` characters.
pub fn strings(b: &[u8], min_len: usize) -> Vec<PeString> {
    let min_len = min_len.max(3);
    let mut out = Vec::new();
    let printable = |c: u8| (0x20..0x7f).contains(&c) || c == b'\t';
    let push = |out: &mut Vec<PeString>, off: usize, enc, s: String| {
        if out.len() < MAX_STRINGS {
            out.push(PeString {
                offset: off as u64,
                encoding: enc,
                category: categorize(&s),
                value: s,
            });
        }
    };
    let mut start = 0;
    let mut cur = String::new();
    for (i, c) in b.iter().enumerate() {
        if printable(*c) {
            if cur.is_empty() {
                start = i;
            }
            if cur.len() < MAX_STRING_LEN {
                cur.push(*c as char);
            }
        } else {
            if cur.len() >= min_len {
                push(&mut out, start, "ascii", std::mem::take(&mut cur));
            }
            cur.clear();
        }
    }
    if cur.len() >= min_len {
        push(&mut out, start, "ascii", cur);
    }
    for align in 0..2 {
        let mut cur = String::new();
        let mut start = 0;
        let mut i = align;
        while i + 1 < b.len() {
            let (lo, hi) = (b[i], b[i + 1]);
            if hi == 0 && printable(lo) {
                if cur.is_empty() {
                    start = i;
                }
                if cur.len() < MAX_STRING_LEN {
                    cur.push(lo as char);
                }
            } else {
                if cur.len() >= min_len {
                    push(&mut out, start, "utf16le", std::mem::take(&mut cur));
                }
                cur.clear();
            }
            i += 2;
        }
        if cur.len() >= min_len {
            push(&mut out, start, "utf16le", cur);
        }
    }
    out
}

const SUSPICIOUS_APIS: &[(&str, &str, &str)] = &[
    (
        "VirtualAllocEx",
        "process_injection",
        "allocates memory in another process",
    ),
    (
        "WriteProcessMemory",
        "process_injection",
        "writes into another process",
    ),
    (
        "CreateRemoteThread",
        "process_injection",
        "starts a thread in another process",
    ),
    (
        "NtCreateThreadEx",
        "process_injection",
        "starts a thread, often in another process",
    ),
    (
        "QueueUserAPC",
        "process_injection",
        "queues code to run in another thread",
    ),
    (
        "SetThreadContext",
        "process_injection",
        "changes a thread's registers",
    ),
    (
        "NtUnmapViewOfSection",
        "process_hollowing",
        "unmaps a section, used in process hollowing",
    ),
    (
        "SetWindowsHookExA",
        "hooking",
        "installs a system hook, used by keyloggers",
    ),
    (
        "SetWindowsHookExW",
        "hooking",
        "installs a system hook, used by keyloggers",
    ),
    ("GetAsyncKeyState", "keylogging", "reads key state"),
    ("IsDebuggerPresent", "anti_debug", "checks for a debugger"),
    (
        "CheckRemoteDebuggerPresent",
        "anti_debug",
        "checks for a debugger",
    ),
    (
        "AdjustTokenPrivileges",
        "privileges",
        "changes token privileges",
    ),
    ("OpenProcessToken", "privileges", "opens a process token"),
    ("CreateServiceA", "persistence", "creates a service"),
    ("CreateServiceW", "persistence", "creates a service"),
    ("RegSetValueExA", "registry", "writes registry values"),
    ("RegSetValueExW", "registry", "writes registry values"),
    (
        "URLDownloadToFileA",
        "network",
        "downloads a file from a URL",
    ),
    (
        "URLDownloadToFileW",
        "network",
        "downloads a file from a URL",
    ),
    ("InternetOpenA", "network", "uses WinINet"),
    ("InternetOpenW", "network", "uses WinINet"),
    ("InternetOpenUrlA", "network", "opens a URL"),
    ("InternetOpenUrlW", "network", "opens a URL"),
    ("HttpSendRequestA", "network", "sends HTTP requests"),
    ("WinHttpOpen", "network", "uses WinHTTP"),
    ("WSAStartup", "network", "uses Winsock"),
    ("connect", "network", "opens a socket connection"),
    ("CryptEncrypt", "crypto", "encrypts data with CryptoAPI"),
    ("CryptDecrypt", "crypto", "decrypts data with CryptoAPI"),
    ("CryptAcquireContextA", "crypto", "uses CryptoAPI"),
    ("CryptAcquireContextW", "crypto", "uses CryptoAPI"),
    ("BCryptEncrypt", "crypto", "encrypts data with CNG"),
    ("ShellExecuteA", "execution", "launches programs"),
    ("ShellExecuteW", "execution", "launches programs"),
    ("WinExec", "execution", "launches programs"),
    ("CreateProcessA", "execution", "launches programs"),
    ("CreateProcessW", "execution", "launches programs"),
];

const PACKER_SECTIONS: &[(&str, &str)] = &[
    ("UPX0", "UPX"),
    ("UPX1", "UPX"),
    ("UPX2", "UPX"),
    (".UPX", "UPX"),
    ("PEC2", "PECompact"),
    ("PEC2TO", "PECompact"),
    ("pec1", "PECompact"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    (".MPRESS1", "MPRESS"),
    (".MPRESS2", "MPRESS"),
    (".petite", "Petite"),
    (".themida", "Themida"),
    (".winlice", "WinLicense"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".nsp0", "NsPack"),
    (".nsp1", "NsPack"),
    ("FSG!", "FSG"),
    (".enigma1", "Enigma"),
    (".perplex", "Perplex"),
];

const KNOWN_SECTIONS: &[&str] = &[
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".pdata", ".idata", ".edata", ".tls", ".bss",
    ".crt", ".CRT", ".gfids", ".00cfg", ".didat", ".xdata", ".sdata", ".textbss", ".debug",
    ".orpc", ".retplne", ".voltbl", "CODE", "DATA", "BSS", ".ndata", ".fptable", "INIT", "PAGE",
    ".cormeta",
];

/// Static indicators. `now_secs` is the current time used for the future date check.
pub fn indicators(r: &PeReport, now_secs: u64) -> Vec<Indicator> {
    let mut out = Vec::new();
    let mut add = |rule, severity, reason: String| {
        out.push(Indicator {
            rule,
            severity,
            reason,
        })
    };
    if !r.is_pe {
        add("not_pe", "info", "no valid PE headers".into());
        return out;
    }
    // Timestamp: before 1995 or in the future. Zero and reproducible builds are common, so low severity.
    let ts = r.timestamp as u64;
    if ts != 0 && ts < 788_918_400 {
        add(
            "timestamp_too_old",
            "low",
            "compile time is before 1995, likely forged or a hash (reproducible build)".into(),
        );
    }
    if ts > now_secs + 86_400 {
        add(
            "timestamp_future",
            "medium",
            "compile time is in the future".into(),
        );
    }
    match entry_section(r) {
        None if r.entry_point != 0 => add(
            "entry_outside_sections",
            "high",
            format!(
                "entry point 0x{:X} is not inside any section",
                r.entry_point
            ),
        ),
        Some(i) => {
            let s = &r.sections[i];
            if s.name != ".text" && s.name != "CODE" && s.name != ".code" {
                add(
                    "entry_not_in_text",
                    "medium",
                    format!("entry point is in section '{}', not .text", s.name),
                );
            }
            if s.characteristics & 0x8000_0000 != 0 {
                add(
                    "entry_in_writable",
                    "medium",
                    format!("entry point section '{}' is writable", s.name),
                );
            }
        }
        None => {}
    }
    for s in &r.sections {
        let (x, w) = (
            s.characteristics & 0x2000_0000 != 0,
            s.characteristics & 0x8000_0000 != 0,
        );
        if x && w {
            add(
                "rwx_section",
                "high",
                format!("section '{}' is readable, writable and executable", s.name),
            );
        }
        if s.entropy >= 7.2 && s.raw_size >= 1024 {
            add(
                "high_entropy_section",
                "medium",
                format!(
                    "section '{}' entropy {:.2}, packed or encrypted data is possible",
                    s.name, s.entropy
                ),
            );
        }
        if s.raw_size == 0 && s.virtual_size > 0x10000 && x {
            add("empty_exec_section", "medium", format!("section '{}' has no raw data but is executable and large in memory (unpacking stub pattern)", s.name));
        }
        if let Some((_, p)) = PACKER_SECTIONS
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(&s.name))
        {
            add(
                "packer_section_name",
                "medium",
                format!("section name '{}' matches {p}; a hint only", s.name),
            );
        } else if !KNOWN_SECTIONS.contains(&s.name.as_str()) {
            add(
                "unusual_section_name",
                "low",
                format!("unusual section name '{}'", s.name.escape_default()),
            );
        }
        if s.name == ".rsrc" && r.file_size > 0 && s.raw_size as u64 * 2 > r.file_size {
            add(
                "large_resources",
                "low",
                format!(
                    ".rsrc is {} of {} bytes, payloads are sometimes stored in resources",
                    s.raw_size, r.file_size
                ),
            );
        }
    }
    if r.imports.is_empty() && !r.clr_present {
        add(
            "no_imports",
            "medium",
            "no import table, common for packed files".into(),
        );
    } else if !r.clr_present
        && r.imports.len() < 10
        && r.imports.iter().any(|i| {
            i.name == "GetProcAddress" || i.name == "LoadLibraryA" || i.name == "LoadLibraryW"
        })
    {
        add("few_imports_dynamic", "medium", format!("only {} imports including dynamic resolution (GetProcAddress/LoadLibrary), common for packers", r.imports.len()));
    }
    let mut seen = std::collections::BTreeSet::new();
    for i in &r.imports {
        if let Some((name, rule, why)) = SUSPICIOUS_APIS.iter().find(|(n, _, _)| *n == i.name) {
            if seen.insert(*name) {
                add(rule, "low", format!("imports {name} from {}: {why}", i.dll));
            }
        }
    }
    if r.overlay_size > 0 {
        add(
            "overlay",
            "low",
            format!(
                "{} bytes of overlay data after the last section",
                r.overlay_size
            ),
        );
    }
    if r.tls_callbacks > 0 {
        add(
            "tls_callbacks",
            "medium",
            format!(
                "{} TLS callbacks run before the entry point",
                r.tls_callbacks
            ),
        );
    }
    if !r.certificate_present {
        add(
            "unsigned",
            "info",
            "no Authenticode signature present".into(),
        );
    }
    let m = mitigations(r);
    for (name, on) in &m[..1] {
        if !on {
            add("no_aslr", "info", format!("{name} is off"));
        }
    }
    if r.dll_characteristics & 0x0100 == 0 {
        add("no_dep", "info", "DEP (NX_COMPAT) is off".into());
    }
    if r.warnings.iter().any(|w| w.contains("overlap")) {
        add(
            "overlapping_sections",
            "medium",
            "sections overlap on disk".into(),
        );
    }
    out
}
