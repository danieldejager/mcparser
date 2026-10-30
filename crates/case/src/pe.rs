//! PE file analysis results as SQL tables in the case events.duckdb.
//!
//! Parse only: files are read as bytes by `pe_read`. Nothing is executed,
//! loaded or disassembled. The MalwareBazaar check uses only the local dump
//! through `bazaar::attach_dump`; no network request is made here.

use std::path::{Path, PathBuf};

pub use pe_read::PeReport;

/// Most files analyzed from one case collection in one run.
pub const MAX_CASE_FILES: usize = 20_000;

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS pe_files (
    sha256 VARCHAR, md5 VARCHAR, sha1 VARCHAR, imphash VARCHAR, host_id VARCHAR, path VARCHAR, file_size BIGINT,
    is_pe BOOLEAN, is_64 BOOLEAN, is_dll BOOLEAN, is_dotnet BOOLEAN, architecture VARCHAR, machine INTEGER,
    subsystem VARCHAR, characteristics VARCHAR, dll_characteristics INTEGER, compile_time VARCHAR, timestamp BIGINT,
    entry_point BIGINT, image_base UBIGINT, section_count INTEGER, import_count INTEGER, export_count INTEGER,
    resource_count INTEGER, tls_present BOOLEAN, tls_callbacks INTEGER, signed BOOLEAN, certificate_size BIGINT,
    overlay_size BIGINT, pdb_path VARCHAR, warnings VARCHAR, analyzed_at VARCHAR
);
CREATE TABLE IF NOT EXISTS pe_sections (
    sha256 VARCHAR, idx INTEGER, name VARCHAR, virtual_address BIGINT, virtual_size BIGINT, raw_offset BIGINT,
    raw_size BIGINT, characteristics BIGINT, entropy DOUBLE, md5 VARCHAR
);
CREATE TABLE IF NOT EXISTS pe_imports (sha256 VARCHAR, dll VARCHAR, name VARCHAR, ordinal INTEGER, delayed BOOLEAN);
CREATE TABLE IF NOT EXISTS pe_exports (sha256 VARCHAR, ordinal BIGINT, name VARCHAR, rva BIGINT, forwarder VARCHAR);
CREATE TABLE IF NOT EXISTS pe_resources (
    sha256 VARCHAR, type VARCHAR, name VARCHAR, language BIGINT, rva BIGINT, size BIGINT, resource_sha256 VARCHAR
);
CREATE TABLE IF NOT EXISTS pe_indicators (sha256 VARCHAR, rule VARCHAR, severity VARCHAR, reason VARCHAR);
CREATE TABLE IF NOT EXISTS pe_strings (sha256 VARCHAR, file_offset BIGINT, encoding VARCHAR, category VARCHAR, value VARCHAR);
CREATE TABLE IF NOT EXISTS pe_rich (sha256 VARCHAR, product_id INTEGER, build INTEGER, count BIGINT);
CREATE TABLE IF NOT EXISTS pe_certificates (
    sha256 VARCHAR, signature_idx INTEGER, cert_idx INTEGER, is_signer BOOLEAN, subject VARCHAR, subject_cn VARCHAR,
    subject_o VARCHAR, subject_ou VARCHAR, subject_c VARCHAR, issuer VARCHAR, issuer_cn VARCHAR, issuer_o VARCHAR,
    issuer_c VARCHAR, serial_hex VARCHAR, serial_dec VARCHAR, version INTEGER, signature_algorithm VARCHAR,
    digest_algorithm VARCHAR, not_before VARCHAR, not_after VARCHAR, self_signed BOOLEAN, verified BOOLEAN
);
CREATE TABLE IF NOT EXISTS pe_version_info (sha256 VARCHAR, kind VARCHAR, lang_codepage VARCHAR, key VARCHAR, value VARCHAR);
CREATE TABLE IF NOT EXISTS pe_manifest (
    sha256 VARCHAR, size BIGINT, truncated BOOLEAN, execution_level VARCHAR, ui_access VARCHAR, text VARCHAR
);
CREATE TABLE IF NOT EXISTS pe_icons (
    sha256 VARCHAR, group_name VARCHAR, icon_id INTEGER, width INTEGER, height INTEGER, bit_count INTEGER,
    format VARCHAR, size BIGINT, icon_sha256 VARCHAR
);
CREATE TABLE IF NOT EXISTS pe_checks (sha256 VARCHAR, source VARCHAR, result VARCHAR, signature VARCHAR, file_name VARCHAR, checked_at VARCHAR);
";

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// ISO 8601 UTC for a PE TimeDateStamp (seconds since 1970).
pub fn iso_time(secs: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // civil_from_days (Howard Hinnant)
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

pub struct Check {
    pub result: String,
    pub signature: String,
    pub file_name: String,
}

/// Look up a SHA256 in the local MalwareBazaar dump. None when the dump is not
/// installed, so the caller can skip silently.
pub fn bazaar_check(conn: &duckdb::Connection, store: &Path, sha256: &str) -> Option<Check> {
    if !super::bazaar::attach_dump(conn, store).ok()? {
        return None;
    }
    let row = conn.query_row(
        "SELECT coalesce(signature, ''), coalesce(file_name, '') FROM mbz.malwarebazaar WHERE sha256 = ? LIMIT 1",
        [sha256],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    );
    Some(match row {
        Ok((signature, file_name)) => Check {
            result: "hit".into(),
            signature,
            file_name,
        },
        Err(_) => Check {
            result: "no hit".into(),
            signature: String::new(),
            file_name: String::new(),
        },
    })
}

/// Write one report into the PE tables, replacing earlier rows for the same
/// sha256 and host/path pair.
pub fn store_report(
    conn: &duckdb::Connection,
    host_id: &str,
    path: &str,
    r: &PeReport,
    x: &Extras,
    analyzed_at: &str,
) -> Result<(), String> {
    conn.execute_batch(SCHEMA).map_err(err)?;
    let sha = r.hashes.sha256.as_str();
    conn.execute(
        "DELETE FROM pe_files WHERE sha256 = ? AND host_id = ? AND path = ?",
        duckdb::params![sha, host_id, path],
    )
    .map_err(err)?;
    for t in [
        "pe_sections",
        "pe_imports",
        "pe_exports",
        "pe_resources",
        "pe_indicators",
        "pe_strings",
        "pe_rich",
        "pe_certificates",
        "pe_version_info",
        "pe_manifest",
        "pe_icons",
    ] {
        conn.execute(&format!("DELETE FROM {t} WHERE sha256 = ?"), [sha])
            .map_err(err)?;
    }
    let pdb = r
        .debug
        .iter()
        .find(|d| !d.pdb_path.is_empty())
        .map(|d| d.pdb_path.clone())
        .unwrap_or_default();
    conn.execute(
        "INSERT INTO pe_files VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        duckdb::params![
            sha, r.hashes.md5, r.hashes.sha1, r.imphash, host_id, path, r.file_size as i64,
            r.is_pe, r.is_64, r.is_dll(), r.is_dotnet(), r.architecture(), r.machine as i32,
            r.subsystem_name(), pe_read::characteristics_flags(r.characteristics).join("|"), r.dll_characteristics as i32,
            if r.is_pe { iso_time(r.timestamp) } else { String::new() }, r.timestamp as i64,
            r.entry_point as i64, r.image_base, r.sections.len() as i32, r.imports.len() as i32, r.exports.len() as i32,
            r.resources.len() as i32, r.tls_present, r.tls_callbacks as i32, r.signed(), r.certificate_size as i64,
            r.overlay_size as i64, pdb, r.warnings.join("; "), analyzed_at,
        ],
    ).map_err(err)?;
    let mut a = conn.appender("pe_sections").map_err(err)?;
    for s in &r.sections {
        a.append_row(duckdb::params![
            sha,
            s.index as i32,
            s.name,
            s.virtual_address as i64,
            s.virtual_size as i64,
            s.raw_offset as i64,
            s.raw_size as i64,
            s.characteristics as i64,
            s.entropy,
            s.md5
        ])
        .map_err(err)?;
    }
    drop(a);
    let mut a = conn.appender("pe_imports").map_err(err)?;
    for i in &r.imports {
        a.append_row(duckdb::params![
            sha,
            i.dll,
            i.name,
            i.ordinal.map(i32::from),
            i.delayed
        ])
        .map_err(err)?;
    }
    drop(a);
    let mut a = conn.appender("pe_exports").map_err(err)?;
    for e in &r.exports {
        a.append_row(duckdb::params![
            sha,
            e.ordinal as i64,
            e.name,
            e.rva as i64,
            e.forwarder
        ])
        .map_err(err)?;
    }
    drop(a);
    let mut a = conn.appender("pe_resources").map_err(err)?;
    for x in &r.resources {
        a.append_row(duckdb::params![
            sha,
            x.type_name,
            x.name,
            x.language as i64,
            x.rva as i64,
            x.size as i64,
            x.sha256
        ])
        .map_err(err)?;
    }
    drop(a);
    let mut a = conn.appender("pe_indicators").map_err(err)?;
    for i in &x.indicators {
        a.append_row(duckdb::params![sha, i.rule, i.severity, i.reason])
            .map_err(err)?;
    }
    drop(a);
    let mut a = conn.appender("pe_strings").map_err(err)?;
    for t in &x.strings {
        a.append_row(duckdb::params![
            sha,
            t.offset as i64,
            t.encoding,
            t.category,
            t.value
        ])
        .map_err(err)?;
    }
    drop(a);
    let mut a = conn.appender("pe_rich").map_err(err)?;
    for e in &x.rich {
        a.append_row(duckdb::params![
            sha,
            e.product_id as i32,
            e.build as i32,
            e.count as i64
        ])
        .map_err(err)?;
    }
    drop(a);
    // verified is always false: the signature is parsed, never checked.
    let mut a = conn.appender("pe_certificates").map_err(err)?;
    for (si, sg) in r.signatures.iter().enumerate() {
        for c in &sg.certificates {
            a.append_row(duckdb::params![
                sha,
                si as i32,
                c.index as i32,
                c.is_signer,
                c.subject.full,
                c.subject.common_name,
                c.subject.organization,
                c.subject.org_unit,
                c.subject.country,
                c.issuer.full,
                c.issuer.common_name,
                c.issuer.organization,
                c.issuer.country,
                c.serial_hex,
                c.serial_dec,
                c.version as i32,
                c.signature_algorithm,
                sg.digest_algorithm,
                pe_read::iso_time(c.not_before),
                pe_read::iso_time(c.not_after),
                c.self_signed,
                false
            ])
            .map_err(err)?;
        }
    }
    drop(a);
    let mut a = conn.appender("pe_version_info").map_err(err)?;
    if let Some(v) = &r.version_info {
        let mut put = |kind: &str, lc: &str, k: &str, val: &str| {
            a.append_row(duckdb::params![sha, kind, lc, k, val])
        };
        for (k, val) in version_fixed(v) {
            put("fixed", "", &k, &val).map_err(err)?;
        }
        for t in &v.strings {
            put("string", &t.table, &t.key, &t.value).map_err(err)?;
        }
        for (l, cp) in &v.translations {
            put(
                "translation",
                &format!("{l:04X}{cp:04X}"),
                "Translation",
                "",
            )
            .map_err(err)?;
        }
    }
    drop(a);
    if let Some(m) = &r.manifest {
        conn.execute(
            "INSERT INTO pe_manifest VALUES (?, ?, ?, ?, ?, ?)",
            duckdb::params![
                sha,
                m.size as i64,
                m.truncated,
                m.execution_level,
                m.ui_access,
                m.text
            ],
        )
        .map_err(err)?;
    }
    let mut a = conn.appender("pe_icons").map_err(err)?;
    for i in &r.icons {
        a.append_row(duckdb::params![
            sha,
            i.group,
            i.icon_id as i32,
            i.width as i32,
            i.height as i32,
            i.bit_count as i32,
            i.format,
            i.bytes.len() as i64,
            hex_digest(&i.bytes)
        ])
        .map_err(err)?;
    }
    Ok(())
}

fn hex_digest(b: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// VS_FIXEDFILEINFO as key/value pairs.
fn version_fixed(v: &pe_read::rsrc::VersionInfo) -> Vec<(String, String)> {
    if !v.fixed_present {
        return Vec::new();
    }
    vec![
        ("FileVersion".into(), v.file_version.clone()),
        ("ProductVersion".into(), v.product_version.clone()),
        (
            "FileFlags".into(),
            format!(
                "0x{:X} {}",
                v.flags,
                pe_read::rsrc::version_flag_names(v.flags & v.flags_mask).join(" ")
            )
            .trim()
            .to_string(),
        ),
        (
            "FileOS".into(),
            format!("0x{:X} {}", v.os, pe_read::rsrc::version_os_name(v.os)),
        ),
        (
            "FileType".into(),
            format!(
                "0x{:X} {}",
                v.file_type,
                pe_read::rsrc::version_type_name(v.file_type)
            ),
        ),
        ("FileSubtype".into(), format!("0x{:X}", v.file_subtype)),
        ("FileDate".into(), format!("0x{:016X}", v.file_date)),
    ]
}

/// Everything derived from the bytes besides the structural report.
pub struct Extras {
    pub indicators: Vec<pe_read::extra::Indicator>,
    pub strings: Vec<pe_read::extra::PeString>,
    pub rich: Vec<pe_read::extra::RichEntry>,
    /// Local MalwareBazaar dump result per resource sha256 ("hit" or
    /// "no hit"). Empty when the dump is not installed.
    pub resource_bazaar: std::collections::HashMap<String, String>,
}

pub fn extras(bytes: &[u8], r: &PeReport) -> Extras {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Extras {
        indicators: pe_read::extra::indicators(r, now),
        strings: pe_read::extra::strings(bytes, 5),
        rich: pe_read::extra::rich_header(bytes),
        resource_bazaar: Default::default(),
    }
}

pub struct Analyzed {
    pub path: PathBuf,
    pub report: PeReport,
    pub extras: Extras,
    pub check: Option<Check>,
}

/// Analyze one file, store it in `db_path`, and check it against the local
/// MalwareBazaar dump when installed.
pub fn analyze_file(
    db_path: &Path,
    store: &Path,
    host_id: &str,
    file: &Path,
    analyzed_at: &str,
) -> Result<Analyzed, String> {
    let meta = std::fs::metadata(file).map_err(err)?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    if meta.len() > pe_read::MAX_FILE_SIZE {
        return Err("file is too large to analyze".into());
    }
    let bytes = std::fs::read(file).map_err(err)?;
    let report = pe_read::analyze(&bytes);
    let mut extras = extras(&bytes, &report);
    drop(bytes);
    let conn = duckdb::Connection::open(db_path).map_err(err)?;
    let shown = file.to_string_lossy().to_string();
    store_report(&conn, host_id, &shown, &report, &extras, analyzed_at)?;
    let check = bazaar_check(&conn, store, &report.hashes.sha256);
    if let Some(c) = &check {
        conn.execute(
            "DELETE FROM pe_checks WHERE sha256 = ? AND source = 'malwarebazaar'",
            [&report.hashes.sha256],
        )
        .map_err(err)?;
        conn.execute(
            "INSERT INTO pe_checks VALUES (?, 'malwarebazaar', ?, ?, ?, ?)",
            duckdb::params![
                report.hashes.sha256,
                c.result,
                c.signature,
                c.file_name,
                analyzed_at
            ],
        )
        .map_err(err)?;
        // Same local dump, same connection: one lookup per distinct resource
        // hash. No network.
        for res in &report.resources {
            if res.sha256.is_empty() || extras.resource_bazaar.contains_key(&res.sha256) {
                continue;
            }
            let hit = conn
                .query_row(
                    "SELECT 1 FROM mbz.malwarebazaar WHERE sha256 = ? LIMIT 1",
                    [&res.sha256],
                    |_| Ok(()),
                )
                .is_ok();
            extras.resource_bazaar.insert(
                res.sha256.clone(),
                if hit { "hit" } else { "no hit" }.into(),
            );
        }
        let _ = conn.execute_batch("DETACH mbz;");
    }
    Ok(Analyzed {
        path: file.to_path_buf(),
        report,
        extras,
        check,
    })
}

fn starts_with_mz(path: &Path) -> bool {
    let mut head = [0u8; 2];
    std::fs::File::open(path)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head))
        .is_ok()
        && head == *b"MZ"
}

/// Files in a case's imported collections (files/<zip sha>) that start with MZ.
pub fn case_candidates(case_dir: &Path) -> Vec<(String, PathBuf)> {
    let catalog = case_dir.join("catalog.sqlite");
    let collections = super::collections(&catalog).unwrap_or_default();
    let mut out = Vec::new();
    for c in collections {
        let mut pending = vec![case_dir.join("files").join(&c.zip_sha256)];
        while let Some(dir) = pending.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let Ok(ft) = entry.file_type() else { continue };
                if ft.is_symlink() {
                    continue;
                }
                if ft.is_dir() {
                    pending.push(entry.path());
                    continue;
                }
                if out.len() >= MAX_CASE_FILES {
                    return out;
                }
                if starts_with_mz(&entry.path()) {
                    out.push((c.host_id.clone(), entry.path()));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn iso_time_known_values() {
        assert_eq!(super::iso_time(0), "1970-01-01T00:00:00Z");
        assert_eq!(super::iso_time(0x5f00_0000), "2020-07-04T04:05:20Z");
    }
}

/// JSON for the UI: a summary plus a tree of nodes, each with rows of
/// field, offset, size, value and meaning. Paths are shown as given.
pub fn report_json(
    path: &str,
    r: &PeReport,
    x: &Extras,
    check: Option<&Check>,
) -> serde_json::Value {
    use serde_json::json;
    let hexv = |v: u64| format!("0x{v:X}");
    let fields = |fs: &[pe_read::Field]| -> Vec<serde_json::Value> {
        fs.iter().map(|f| json!({"field": f.name, "offset": hexv(f.offset), "size": f.size, "value": hexv(f.value), "meaning": meaning(f.name, f.value)})).collect()
    };
    let row = |field: &str, offset: String, size: String, value: String, meaning: String| json!({"field": field, "offset": offset, "size": size, "value": value, "meaning": meaning});
    let dirs: Vec<_> = r
        .data_directories
        .iter()
        .map(|d| {
            row(
                d.name,
                String::new(),
                hexv(d.size as u64),
                hexv(d.rva as u64),
                if d.rva != 0 {
                    "present".into()
                } else {
                    String::new()
                },
            )
        })
        .collect();
    let sections: Vec<_> = r
        .sections
        .iter()
        .map(|s| {
            row(
                &s.name,
                hexv(s.header_offset),
                hexv(s.raw_size as u64),
                hexv(s.virtual_address as u64),
                format!(
                    "raw 0x{:X}, vsize 0x{:X}, entropy {:.3}, flags 0x{:08X}",
                    s.raw_offset, s.virtual_size, s.entropy, s.characteristics
                ),
            )
        })
        .collect();
    let imports: Vec<_> = r
        .imports
        .iter()
        .map(|i| {
            row(
                &i.dll,
                String::new(),
                String::new(),
                i.ordinal
                    .map(|o| format!("ord {o}"))
                    .unwrap_or_else(|| i.name.clone()),
                if i.delayed {
                    "delay load".into()
                } else {
                    String::new()
                },
            )
        })
        .collect();
    let exports: Vec<_> = r
        .exports
        .iter()
        .map(|e| {
            row(
                &e.name,
                String::new(),
                String::new(),
                hexv(e.rva as u64),
                if e.forwarder.is_empty() {
                    format!("ordinal {}", e.ordinal)
                } else {
                    format!("ordinal {}, forwards to {}", e.ordinal, e.forwarder)
                },
            )
        })
        .collect();
    let resources: Vec<_> = r
        .resources
        .iter()
        .map(|x| {
            row(
                &x.type_name,
                hexv(x.rva as u64),
                hexv(x.size as u64),
                x.name.clone(),
                format!("language {}", x.language),
            )
        })
        .collect();
    let debug: Vec<_> = r
        .debug
        .iter()
        .map(|d| {
            row(
                &format!("type {}", d.kind),
                String::new(),
                hexv(d.size as u64),
                iso_time(d.timestamp),
                d.pdb_path.clone(),
            )
        })
        .collect();
    let flag = |b: bool| if b { "yes" } else { "no" }.to_string();
    json!({
        "path": path,
        "summary": {
            "md5": r.hashes.md5, "sha1": r.hashes.sha1, "sha256": r.hashes.sha256, "imphash": r.imphash,
            "file_size": r.file_size, "is_pe": r.is_pe, "architecture": r.architecture(), "is_64": r.is_64,
            "subsystem": r.subsystem_name(), "characteristics": pe_read::characteristics_flags(r.characteristics),
            "compile_time": if r.is_pe { iso_time(r.timestamp) } else { String::new() }, "signed": r.signed(),
            "dotnet": r.is_dotnet(), "dll": r.is_dll(), "overlay_size": r.overlay_size, "warnings": r.warnings,
            "malwarebazaar": check.map(|c| json!({"result": c.result, "signature": c.signature, "file_name": c.file_name})),
        },
        "entry_section": pe_read::extra::entry_section(r).and_then(|i| r.sections.get(i)).map(|s| s.name.clone()),
        "mitigations": pe_read::extra::mitigations(r).iter().map(|(n, on)| json!({"name": n, "enabled": on})).collect::<Vec<_>>(),
        "indicators": x.indicators.iter().map(|i| json!({"rule": i.rule, "severity": i.severity, "reason": i.reason})).collect::<Vec<_>>(),
        "rich": x.rich.iter().map(|e| json!({"product_id": e.product_id, "build": e.build, "count": e.count})).collect::<Vec<_>>(),
        "strings": x.strings.iter().take(5000).map(|t| json!({"offset": t.offset, "encoding": t.encoding, "category": t.category, "value": t.value})).collect::<Vec<_>>(),
        "sections": r.sections.iter().map(|s| json!({"name": s.name, "virtual_size": s.virtual_size, "virtual_address": s.virtual_address,
            "raw_size": s.raw_size, "raw_offset": s.raw_offset, "entropy": s.entropy, "md5": s.md5, "flags": {
                "read": s.characteristics & 0x4000_0000 != 0, "write": s.characteristics & 0x8000_0000 != 0, "execute": s.characteristics & 0x2000_0000 != 0,
                "shared": s.characteristics & 0x1000_0000 != 0, "code": s.characteristics & 0x20 != 0},
            "ratio": if r.file_size > 0 { (s.raw_size as f64 / r.file_size as f64 * 100.0).round() } else { 0.0 }})).collect::<Vec<_>>(),
        "imports": r.imports.iter().map(|i| json!({"dll": i.dll, "name": i.name, "ordinal": i.ordinal, "delayed": i.delayed})).collect::<Vec<_>>(),
        "exports": r.exports.iter().map(|e| json!({"ordinal": e.ordinal, "name": e.name, "rva": e.rva, "forwarder": e.forwarder})).collect::<Vec<_>>(),
        "resources": r.resources.iter().map(|e| json!({"type": e.type_name, "name": e.name, "language": e.language, "rva": e.rva, "size": e.size, "sha256": e.sha256, "md5": e.md5, "offset": e.offset, "malwarebazaar": x.resource_bazaar.get(&e.sha256)})).collect::<Vec<_>>(),
        "debug": r.debug.iter().map(|d| json!({"type": d.kind, "timestamp": iso_time(d.timestamp), "size": d.size, "pdb_path": d.pdb_path, "raw_offset": d.raw_offset})).collect::<Vec<_>>(),
        "signatures": r.signatures.iter().map(signature_json).collect::<Vec<_>>(),
        "tls": {"present": r.tls_present, "callbacks": r.tls_callbacks},
        "version_info": r.version_info.as_ref().map(|v| json!({
            "fixed": version_fixed(v).into_iter().map(|(k, val)| json!({"key": k, "value": val})).collect::<Vec<_>>(),
            "strings": v.strings.iter().map(|t| json!({"table": t.table, "key": t.key, "value": t.value})).collect::<Vec<_>>(),
            "translations": v.translations.iter().map(|(l, cp)| format!("{l:04X}{cp:04X}")).collect::<Vec<_>>(),
            "warnings": v.warnings,
        })),
        "manifest": r.manifest.as_ref().map(|m| json!({"size": m.size, "truncated": m.truncated, "execution_level": m.execution_level, "ui_access": m.ui_access, "text": m.text})),
        "icons": r.icons.iter().map(|i| json!({"group": i.group, "icon_id": i.icon_id, "width": i.width, "height": i.height, "bit_count": i.bit_count,
            "data_url": format!("data:{};base64,{}", if i.format == "png" { "image/png" } else { "image/x-icon" }, base64(&i.bytes))})).collect::<Vec<_>>(),
        "tree": [
            {"id": "dos", "label": "DOS header", "rows": fields(&r.dos_header)},
            {"id": "nt", "label": "NT headers", "children": [
                {"id": "file", "label": "File header", "rows": fields(&r.file_header)},
                {"id": "optional", "label": "Optional header", "rows": fields(&r.optional_header)},
                {"id": "dirs", "label": "Data directories", "rows": dirs},
            ]},
            {"id": "sections", "label": "Section table", "rows": sections},
            {"id": "imports", "label": format!("Imports ({})", r.imports.len()), "rows": imports},
            {"id": "exports", "label": format!("Exports ({})", r.exports.len()), "rows": exports},
            {"id": "resources", "label": format!("Resources ({})", r.resources.len()), "rows": resources},
            {"id": "tls", "label": "TLS", "rows": [row("present", String::new(), String::new(), flag(r.tls_present), format!("{} callbacks", r.tls_callbacks))]},
            {"id": "debug", "label": "Debug", "rows": debug},
            {"id": "cert", "label": "Certificate", "rows": [row("present", String::new(), hexv(r.certificate_size as u64), flag(r.certificate_present), "Authenticode blob present, signature not verified".into())]},
            {"id": "clr", "label": ".NET (CLR)", "rows": [row("present", String::new(), String::new(), flag(r.clr_present), String::new())]},
        ],
    })
}

fn name_json(n: &pe_read::cert::NameParts) -> serde_json::Value {
    serde_json::json!({"full": n.full, "cn": n.common_name, "o": n.organization, "ou": n.org_unit, "c": n.country})
}

/// One Authenticode entry for the UI. `status` is fixed text: the signature
/// is parsed only and never verified.
fn signature_json(s: &pe_read::cert::Signature) -> serde_json::Value {
    use serde_json::json;
    json!({
        "status": "signature present, not verified",
        "offset": s.offset, "length": s.length, "revision": format!("0x{:04X}", s.revision),
        "cert_type": format!("0x{:04X}", s.cert_type), "version": s.signed_data_version,
        "digest_algorithm": s.digest_algorithm, "signature_algorithm": s.signature_algorithm,
        "signer_serial_hex": s.signer_serial_hex, "signer_serial_dec": s.signer_serial_dec,
        "signer_issuer": name_json(&s.signer_issuer), "signer_index": s.signer_index, "error": s.error,
        "certificates": s.certificates.iter().map(|c| json!({
            "index": c.index, "is_signer": c.is_signer, "self_signed": c.self_signed, "version": c.version,
            "subject": name_json(&c.subject), "issuer": name_json(&c.issuer),
            "serial_hex": c.serial_hex, "serial_dec": c.serial_dec, "signature_algorithm": c.signature_algorithm,
            "not_before": pe_read::iso_time(c.not_before), "not_after": pe_read::iso_time(c.not_after),
        })).collect::<Vec<_>>(),
    })
}

fn meaning(name: &str, v: u64) -> String {
    match name {
        "e_magic" => {
            if v == 0x5a4d {
                "MZ".into()
            } else {
                "bad".into()
            }
        }
        "Machine" => pe_read::machine_name(v as u16).into(),
        "TimeDateStamp" => iso_time(v as u32),
        "Characteristics" => pe_read::characteristics_flags(v as u16).join(" | "),
        "Magic" => match v {
            0x10b => "PE32".into(),
            0x20b => "PE32+".into(),
            _ => "unknown".into(),
        },
        "Subsystem" => pe_read::subsystem_name(v as u16).into(),
        _ => String::new(),
    }
}

fn base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            o.push(if i <= c.len() {
                T[(n >> (18 - 6 * i)) as usize & 63] as char
            } else {
                '='
            });
        }
    }
    o
}
