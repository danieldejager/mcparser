//! MalwareBazaar full dump: a machine-local DuckDB file next to the
//! marketplace store, an importer for the abuse.ch CSV (plain or zipped),
//! and a set-based matcher that joins every hash in a case against it.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// File name of the dump database, created next to marketplace.sqlite.
pub const DUMP_FILE: &str = "malwarebazaar.duckdb";
/// Per-hash lookup API (POST query=get_info&hash=..., header Auth-Key).
pub const DEFAULT_LOOKUP_ENDPOINT: &str = "https://mb-api.abuse.ch/api/v1/";
/// Bulk CSV export. `{key}` is replaced at runtime with the stored key and
/// the resulting URL is never logged or persisted.
pub const DEFAULT_EXPORT_TEMPLATE: &str = "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv";

pub fn dump_path(store: &Path) -> PathBuf {
    store.parent().unwrap_or(Path::new(".")).join(DUMP_FILE)
}

pub fn remove_dump(store: &Path) -> std::io::Result<()> {
    let path = dump_path(store);
    for p in [path.clone(), PathBuf::from(format!("{}.wal", path.display()))] {
        if p.exists() { std::fs::remove_file(p)?; }
    }
    Ok(())
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ImportCounts {
    pub read: u64,
    pub added: u64,
    pub updated: u64,
    pub unchanged: u64,
    pub total: u64,
}

/// Typed columns of the dump table, in table order after `sha256`. Each
/// entry is (column, header names that map to it). `note` comes last and
/// holds only header columns this list does not know, as JSON, or NULL.
pub const FIELDS: &[(&str, &[&str])] = &[
    ("md5", &["md5_hash", "md5"]),
    ("sha1", &["sha1_hash", "sha1"]),
    ("sha3_384", &["sha3_384_hash", "sha3_384"]),
    ("imphash", &["imphash"]),
    ("tlsh", &["tlsh"]),
    ("ssdeep", &["ssdeep"]),
    ("telfhash", &["telfhash"]),
    ("gimphash", &["gimphash"]),
    ("dhash_icon", &["dhash_icon"]),
    ("first_seen", &["first_seen_utc", "first_seen"]),
    ("last_seen", &["last_seen_utc", "last_seen"]),
    ("reporter", &["reporter"]),
    ("file_name", &["file_name", "filename"]),
    ("file_type", &["file_type_guess", "file_type", "filetype"]),
    ("mime_type", &["mime_type", "file_type_mime", "mimetype"]),
    ("file_size", &["file_size", "size"]),
    ("signature", &["signature"]),
    ("clamav", &["clamav"]),
    ("vtpercent", &["vtpercent", "vt_percent"]),
    ("tags", &["tags"]),
    ("delivery_method", &["delivery_method"]),
    ("origin_country", &["origin_country"]),
    ("intelligence", &["intelligence"]),
];

/// Column order of the abuse.ch CSV export when no header line is present.
const DEFAULT_ORDER: &[&str] = &["first_seen", "sha256", "md5", "sha1", "reporter", "file_name", "file_type", "mime_type", "signature", "clamav", "vtpercent", "imphash", "ssdeep", "tlsh"];

fn hash_column(name: &str) -> Option<usize> {
    match name { "md5" => Some(32), "sha1" => Some(40), "sha3_384" => Some(96), _ => None }
}

fn open_dump(path: &Path) -> Result<duckdb::Connection, String> {
    let db = duckdb::Connection::open(path).map_err(|e| e.to_string())?;
    let cols: Vec<String> = FIELDS.iter().map(|(c, _)| format!("{c} VARCHAR")).collect();
    db.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS malwarebazaar (sha256 VARCHAR PRIMARY KEY, {}, note VARCHAR);
         CREATE TABLE IF NOT EXISTS malwarebazaar_meta (key VARCHAR PRIMARY KEY, value VARCHAR);",
        cols.join(", ")
    )).map_err(|e| e.to_string())?;
    migrate(&db)?;
    Ok(db)
}

/// Older dumps had (sha256, md5, sha1, note) with file_name, signature,
/// file_type and reporter inside the note JSON. Add the missing columns and
/// move those values out of the note.
fn migrate(db: &duckdb::Connection) -> Result<(), String> {
    let mut have = Vec::new();
    {
        let mut stmt = db.prepare("SELECT column_name FROM information_schema.columns WHERE table_name = 'malwarebazaar' AND table_catalog = current_database()").map_err(|e| e.to_string())?;
        let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
        while let Some(r) = rows.next().map_err(|e| e.to_string())? { have.push(r.get::<_, String>(0).unwrap_or_default()); }
    }
    if have.iter().any(|c| c == "file_name") { return Ok(()); }
    for (c, _) in FIELDS {
        if !have.iter().any(|h| h == c) {
            db.execute_batch(&format!("ALTER TABLE malwarebazaar ADD COLUMN {c} VARCHAR")).map_err(|e| e.to_string())?;
        }
    }
    // Parsed in Rust: the DuckDB json extension is not bundled.
    let mut old: Vec<(String, String)> = Vec::new();
    {
        let mut stmt = db.prepare("SELECT sha256, note FROM malwarebazaar WHERE note IS NOT NULL").map_err(|e| e.to_string())?;
        let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
        while let Some(r) = rows.next().map_err(|e| e.to_string())? { old.push((r.get(0).unwrap_or_default(), r.get(1).unwrap_or_default())); }
    }
    db.execute_batch("BEGIN").map_err(|e| e.to_string())?;
    for (sha256, note) in old {
        let json: serde_json::Value = serde_json::from_str(&note).unwrap_or_default();
        let f = |k: &str| json.get(k).and_then(|v| v.as_str()).filter(|v| !v.is_empty()).map(str::to_string);
        db.execute(
            "UPDATE malwarebazaar SET file_name = ?, signature = ?, file_type = ?, reporter = ?, note = NULL WHERE sha256 = ?",
            duckdb::params![f("file_name"), f("signature"), f("file_type"), f("reporter"), sha256],
        ).map_err(|e| e.to_string())?;
    }
    db.execute_batch("COMMIT").map_err(|e| e.to_string())
}

/// Split one CSV line, honouring double quotes and doubled quotes.
pub fn split_csv(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => { cur.push('"'); chars.next(); }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out.into_iter().map(|s| s.trim().to_string()).collect()
}

/// Where each dump column sits in a CSV row.
struct Columns { sha256: usize, typed: Vec<Option<usize>>, extra: Vec<(String, usize)> }

fn normalise(name: &str) -> String {
    name.trim().trim_matches('"').trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

impl Columns {
    fn default_order() -> Self {
        let pos = |c: &str| DEFAULT_ORDER.iter().position(|d| *d == c);
        Columns { sha256: 1, typed: FIELDS.iter().map(|(c, _)| pos(c)).collect(), extra: Vec::new() }
    }
    /// A header line names sha256 or sha256_hash. Unknown names go to note.
    fn from_header(fields: &[String]) -> Option<Self> {
        let names: Vec<String> = fields.iter().map(|f| normalise(f)).collect();
        let sha256 = names.iter().position(|n| n == "sha256_hash" || n == "sha256")?;
        let typed: Vec<Option<usize>> = FIELDS.iter().map(|(_, aliases)| names.iter().position(|n| aliases.contains(&n.as_str()))).collect();
        let extra = names.iter().enumerate()
            .filter(|(i, n)| *i != sha256 && !n.is_empty() && !typed.contains(&Some(*i)))
            .map(|(i, n)| (n.clone(), i)).collect();
        Some(Columns { sha256, typed, extra })
    }
}

fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// If `file` is a zip, extract the first .csv/.txt member to a temp file by
/// streaming, and return that path. Otherwise return the file itself.
fn csv_source(file: &Path) -> Result<(PathBuf, bool), String> {
    let mut magic = [0u8; 4];
    {
        use std::io::Read;
        let mut f = std::fs::File::open(file).map_err(|e| format!("{}: {e}", file.display()))?;
        let _ = f.read(&mut magic);
    }
    if &magic != b"PK\x03\x04" { return Ok((file.to_path_buf(), false)); }
    let f = std::fs::File::open(file).map_err(|e| e.to_string())?;
    let mut archive = zip::ZipArchive::new(f).map_err(|e| format!("not a readable zip: {e}"))?;
    let index = (0..archive.len())
        .find(|&i| archive.name_for_index(i).and_then(|m| m.ok()).map(|m| { let n = m.to_ascii_lowercase(); n.ends_with(".csv") || n.ends_with(".txt") }).unwrap_or(false))
        .ok_or("the zip holds no .csv file")?;
    let mut member = archive.by_index(index).map_err(|e| e.to_string())?;
    let tmp = std::env::temp_dir().join(format!("mcparser-bazaar-{}-{}.csv", std::process::id(), super::sha256_bytes(file.display().to_string().as_bytes())[..8].to_string()));
    let mut out = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
    if let Err(e) = std::io::copy(&mut member, &mut out) { let _ = std::fs::remove_file(&tmp); return Err(e.to_string()); }
    Ok((tmp, true))
}

/// Import a CSV or zipped CSV into the dump. New hashes are added, existing
/// rows update only when a column changed.
pub fn import_dump(store: &Path, file: &Path, progress: &mut dyn FnMut(u64)) -> Result<ImportCounts, String> {
    let (csv, temp) = csv_source(file)?;
    let result = import_csv(store, &csv, file, progress);
    if temp { let _ = std::fs::remove_file(&csv); }
    result
}

fn import_csv(store: &Path, csv: &Path, original: &Path, progress: &mut dyn FnMut(u64)) -> Result<ImportCounts, String> {
    let db = open_dump(&dump_path(store))?;
    let names: Vec<&str> = FIELDS.iter().map(|(c, _)| *c).collect();
    db.execute_batch(&format!("CREATE OR REPLACE TEMP TABLE staging (sha256 VARCHAR, {}, note VARCHAR)", names.iter().map(|c| format!("{c} VARCHAR")).collect::<Vec<_>>().join(", "))).map_err(|e| e.to_string())?;
    let reader = BufReader::with_capacity(1 << 20, std::fs::File::open(csv).map_err(|e| e.to_string())?);
    let mut cols = Columns::default_order();
    let mut counts = ImportCounts::default();
    let mut newest = String::new();
    {
        let mut app = db.appender("staging").map_err(|e| e.to_string())?;
        for line in reader.lines() {
            let line = line.map_err(|e| e.to_string())?;
            let body = line.trim_start_matches('\u{feff}').trim();
            if body.is_empty() { continue; }
            let is_comment = body.starts_with('#');
            let fields = split_csv(body.trim_start_matches('#').trim());
            if let Some(found) = Columns::from_header(&fields) { cols = found; continue; }
            if is_comment { continue; }
            let get = |i: Option<usize>| i.and_then(|i| fields.get(i)).map(|s| s.to_string()).unwrap_or_default();
            let sha256 = get(Some(cols.sha256)).to_ascii_lowercase();
            if !is_hex(&sha256, 64) { continue; }
            let clean = |s: String| if s.is_empty() || s.eq_ignore_ascii_case("n/a") { None } else { Some(s) };
            let mut row: Vec<Option<String>> = vec![Some(sha256)];
            for ((name, _), idx) in FIELDS.iter().zip(&cols.typed) {
                let v = clean(get(*idx));
                row.push(match hash_column(name) {
                    Some(len) => v.map(|h| h.to_ascii_lowercase()).filter(|h| is_hex(h, len)),
                    None => v,
                });
            }
            let mut extra = serde_json::Map::new();
            for (k, i) in &cols.extra {
                if let Some(v) = clean(get(Some(*i))) { extra.insert(k.clone(), serde_json::Value::String(v)); }
            }
            row.push(if extra.is_empty() { None } else { Some(serde_json::Value::Object(extra).to_string()) });
            let seen = row[1 + names.iter().position(|c| *c == "first_seen").unwrap()].clone().unwrap_or_default();
            if seen > newest { newest = seen; }
            app.append_row(duckdb::appender_params_from_iter(row.iter())).map_err(|e| e.to_string())?;
            counts.read += 1;
            if counts.read % 100_000 == 0 { progress(counts.read); }
        }
        app.flush().map_err(|e| e.to_string())?;
    }
    let all: Vec<&str> = names.iter().copied().chain(["note"]).collect();
    let any: Vec<String> = all.iter().map(|c| format!("any_value({c}) AS {c}")).collect();
    let changed: Vec<String> = all.iter().map(|c| format!("i.{c} IS DISTINCT FROM m.{c}")).collect();
    let changed = changed.join(" OR ");
    let set: Vec<String> = all.iter().map(|c| format!("{c} = i.{c}")).collect();
    let cols_list = all.iter().map(|c| format!("i.{c}")).collect::<Vec<_>>().join(", ");
    // One row per hash inside one file.
    db.execute_batch(&format!(
        "CREATE OR REPLACE TEMP TABLE incoming AS SELECT sha256, {} FROM staging GROUP BY sha256;
         DROP TABLE staging;", any.join(", ")
    )).map_err(|e| e.to_string())?;
    let q = |sql: &str| -> Result<u64, String> { db.query_row(sql, [], |r| r.get::<_, i64>(0)).map(|v| v as u64).map_err(|e| e.to_string()) };
    counts.added = q("SELECT count(*) FROM incoming i ANTI JOIN malwarebazaar m USING (sha256)")?;
    counts.updated = q(&format!("SELECT count(*) FROM incoming i JOIN malwarebazaar m USING (sha256) WHERE {changed}"))?;
    let incoming = q("SELECT count(*) FROM incoming")?;
    counts.unchanged = incoming - counts.added - counts.updated;
    db.execute_batch(&format!(
        "BEGIN;
         UPDATE malwarebazaar m SET {} FROM incoming i WHERE m.sha256 = i.sha256 AND ({changed});
         INSERT INTO malwarebazaar (sha256, {}) SELECT i.sha256, {cols_list} FROM incoming i ANTI JOIN malwarebazaar m USING (sha256);
         COMMIT;
         DROP TABLE incoming;", set.join(", "), all.join(", ")
    )).map_err(|e| e.to_string())?;
    counts.total = q("SELECT count(*) FROM malwarebazaar")?;
    let name = original.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    for (k, v) in [("imported_at", super::chrono_now_pub()), ("source_file", name), ("newest_first_seen", newest)] {
        db.execute("INSERT OR REPLACE INTO malwarebazaar_meta VALUES (?, ?)", duckdb::params![k, v]).map_err(|e| e.to_string())?;
    }
    Ok(counts)
}

/// Row count and meta values of the dump, if it exists.
pub fn dump_info(store: &Path) -> Option<(u64, Vec<(String, String)>)> {
    let path = dump_path(store);
    if !path.exists() { return None; }
    let db = duckdb::Connection::open_with_flags(&path, duckdb::Config::default().access_mode(duckdb::AccessMode::ReadOnly).ok()?).ok()?;
    let total: i64 = db.query_row("SELECT count(*) FROM malwarebazaar", [], |r| r.get(0)).ok()?;
    let mut meta = Vec::new();
    if let Ok(mut stmt) = db.prepare("SELECT key, value FROM malwarebazaar_meta ORDER BY key") {
        if let Ok(mut rows) = stmt.query([]) {
            while let Ok(Some(row)) = rows.next() { meta.push((row.get(0).unwrap_or_default(), row.get(1).unwrap_or_default())); }
        }
    }
    Some((total as u64, meta))
}

/// Make the dump queryable on a connection when it exists. `malwarebazaar` is
/// the narrow lookup view; `malwarebazaar_full` has every column. Internal code
/// reads `mbz.malwarebazaar` directly.
pub fn attach_dump(conn: &duckdb::Connection, store: &Path) -> Result<bool, String> {
    let path = dump_path(store);
    if !path.exists() { return Ok(false); }
    let lit = path.to_string_lossy().replace('\'', "''");
    conn.execute_batch(&format!(
        "ATTACH IF NOT EXISTS '{lit}' AS mbz (READ_ONLY);
         CREATE OR REPLACE TEMP VIEW malwarebazaar_full AS SELECT * FROM mbz.malwarebazaar;
         CREATE OR REPLACE TEMP VIEW malwarebazaar AS SELECT sha256, sha1, md5, signature, file_name, first_seen FROM mbz.malwarebazaar;"
    )).map_err(|e| e.to_string())?;
    Ok(true)
}

pub struct BazaarHit {
    pub host_id: String,
    pub artifact: String,
    pub name: String,
    pub hash: String,
    pub kind: String,
    pub sha256: String,
    pub signature: String,
    pub file_name: String,
    pub file_type: String,
    pub source: String,
}

pub struct MatchOutcome {
    pub checked: u64,
    pub hits: Vec<BazaarHit>,
    pub unmatched: Vec<String>,
    pub dump_rows: u64,
    pub dump_meta: Vec<(String, String)>,
}

fn table_exists(conn: &duckdb::Connection, name: &str) -> bool {
    conn.query_row("SELECT count(*) FROM information_schema.tables WHERE table_name = ? AND table_schema = 'main' AND table_catalog = current_database()", [name], |r| r.get::<_, i64>(0)).map(|n| n > 0).unwrap_or(false)
}

const HEX: &str = r"'\b([0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})\b'";

fn gather(conn: &duckdb::Connection) -> Result<(), String> {
    conn.execute_batch("CREATE OR REPLACE TEMP TABLE case_hashes (host_id VARCHAR, artifact VARCHAR, name VARCHAR, hash VARCHAR)").map_err(|e| e.to_string())?;
    let mut parts: Vec<String> = Vec::new();
    if table_exists(&conn, "amcache") {
        parts.push("SELECT host_id, 'amcache', coalesce(nullif(path, ''), name), lower(trim(sha1)) FROM amcache WHERE sha1 IS NOT NULL AND sha1 <> ''".into());
    }
    if table_exists(&conn, "events") {
        parts.push(format!("SELECT coalesce(host_id, computer), 'events', provider || ' ' || CAST(event_id AS VARCHAR), unnest(regexp_extract_all(lower(event_data), {HEX})) FROM events WHERE regexp_matches(lower(event_data), {HEX})"));
    }
    for (table, col) in [("prefetch", "path"), ("shimcache", "path")] {
        if table_exists(&conn, table) {
            parts.push(format!("SELECT host_id, '{table}', {col}, unnest(regexp_extract_all(lower({col}), {HEX})) FROM {table} WHERE regexp_matches(lower({col}), {HEX})"));
        }
    }
    for part in &parts {
        conn.execute(&format!("INSERT INTO case_hashes {part}"), []).map_err(|e| e.to_string())?;
    }
    conn.execute_batch("DELETE FROM case_hashes WHERE length(hash) NOT IN (32, 40, 64)").map_err(|e| e.to_string())?;
    Ok(())
}

/// Gather every hash-like value in the case and join it against the dump.
pub fn match_case(store: &Path, db_path: &Path, progress: &mut dyn FnMut(u8, &str)) -> Result<MatchOutcome, String> {
    if dump_path(store).exists() { drop(open_dump(&dump_path(store))?); } // migrates an older schema
    let (dump_rows, dump_meta) = dump_info(store).ok_or("The MalwareBazaar dump is not loaded. Upload or fetch it first.")?;
    let conn = duckdb::Connection::open(db_path).map_err(|e| e.to_string())?;
    progress(10, "Gathering hashes from the case");
    gather(&conn)?;
    let checked: i64 = conn.query_row("SELECT count(DISTINCT hash) FROM case_hashes", [], |r| r.get(0)).map_err(|e| e.to_string())?;
    progress(40, &format!("Comparing {checked} hashes against {dump_rows} dump rows"));
    attach_dump(&conn, store)?;
    let sql = "WITH h AS (SELECT DISTINCT host_id, artifact, name, hash FROM case_hashes)
        SELECT h.host_id, h.artifact, h.name, h.hash, 'sha256', m.sha256, m.signature, m.file_name, m.file_type FROM h JOIN mbz.malwarebazaar m ON length(h.hash) = 64 AND m.sha256 = h.hash
        UNION ALL SELECT h.host_id, h.artifact, h.name, h.hash, 'sha1', m.sha256, m.signature, m.file_name, m.file_type FROM h JOIN mbz.malwarebazaar m ON length(h.hash) = 40 AND m.sha1 = h.hash
        UNION ALL SELECT h.host_id, h.artifact, h.name, h.hash, 'md5', m.sha256, m.signature, m.file_name, m.file_type FROM h JOIN mbz.malwarebazaar m ON length(h.hash) = 32 AND m.md5 = h.hash
        ORDER BY 1, 2, 3";
    let mut hits = Vec::new();
    {
        let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
        let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let field = |i: usize| row.get::<_, Option<String>>(i).ok().flatten().unwrap_or_default();
            hits.push(BazaarHit {
                host_id: row.get::<_, Option<String>>(0).ok().flatten().unwrap_or_default(),
                artifact: row.get(1).unwrap_or_default(),
                name: row.get::<_, Option<String>>(2).ok().flatten().unwrap_or_default(),
                hash: row.get(3).unwrap_or_default(),
                kind: row.get(4).unwrap_or_default(),
                sha256: row.get(5).unwrap_or_default(),
                signature: field(6),
                file_name: field(7),
                file_type: field(8),
                source: "local dump".into(),
            });
        }
    }
    progress(80, &format!("{} hits", hits.len()));
    let mut unmatched = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT c.hash FROM case_hashes c
             WHERE NOT EXISTS (SELECT 1 FROM mbz.malwarebazaar m WHERE m.sha256 = c.hash OR m.sha1 = c.hash OR m.md5 = c.hash) ORDER BY 1",
        ).map_err(|e| e.to_string())?;
        let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? { unmatched.push(row.get(0).unwrap_or_default()); }
    }
    let _ = conn.execute_batch("DROP TABLE case_hashes; DETACH mbz;");
    Ok(MatchOutcome { checked: checked as u64, hits, unmatched, dump_rows, dump_meta })
}

fn csv_cell(v: &str) -> String {
    if v.contains([',', '"', '\n']) { format!("\"{}\"", v.replace('"', "\"\"")) } else { v.to_string() }
}

/// Write reports/malwarebazaar-<stamp>.csv, .md and -unmatched.txt.
pub fn write_report(case_dir: &Path, stamp: &str, outcome: &MatchOutcome) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    let dir = case_dir.join("reports");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let csv = dir.join(format!("malwarebazaar-{stamp}.csv"));
    let md = dir.join(format!("malwarebazaar-{stamp}.md"));
    let un = dir.join(format!("malwarebazaar-{stamp}-unmatched.txt"));
    let mut f = std::io::BufWriter::new(std::fs::File::create(&csv).map_err(|e| e.to_string())?);
    writeln!(f, "host,artifact,path_or_name,hash,hash_kind,sha256,signature,file_name,file_type,source").map_err(|e| e.to_string())?;
    for h in &outcome.hits {
        writeln!(f, "{}", [&h.host_id, &h.artifact, &h.name, &h.hash, &h.kind, &h.sha256, &h.signature, &h.file_name, &h.file_type, &h.source].iter().map(|v| csv_cell(v)).collect::<Vec<_>>().join(",")).map_err(|e| e.to_string())?;
    }
    f.flush().map_err(|e| e.to_string())?;
    std::fs::write(&un, outcome.unmatched.join("\n")).map_err(|e| e.to_string())?;
    let meta = |k: &str| outcome.dump_meta.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone()).unwrap_or_default();
    let mut text = format!(
        "# MalwareBazaar match report\n\n- Report time (unix seconds): {stamp}\n- Hashes checked: {}\n- Matched (local dump): {}\n- Not in dump: {}\n- Dump rows: {}\n- Dump imported at (unix seconds): {}\n- Dump file: {}\n- Newest first_seen in dump: {}\n\nThe dump may be the recent export rather than every sample ever seen. A miss is not proof a file is clean.\n\n",
        outcome.checked, outcome.hits.len(), outcome.unmatched.len(), outcome.dump_rows, meta("imported_at"), meta("source_file"), meta("newest_first_seen"),
    );
    text.push_str("| Host | Artifact | Path or name | Hash | Signature | File name | File type | Source |\n|---|---|---|---|---|---|---|---|\n");
    for h in &outcome.hits {
        let c = |v: &str| v.replace('|', "\\|");
        text.push_str(&format!("| {} | {} | {} | {} | {} | {} | {} | {} |\n", c(&h.host_id), c(&h.artifact), c(&h.name), c(&h.hash), c(&h.signature), c(&h.file_name), c(&h.file_type), c(&h.source)));
    }
    if outcome.hits.is_empty() { text.push_str("| none | | | | | | | |\n"); }
    std::fs::write(&md, text).map_err(|e| e.to_string())?;
    Ok((csv, md, un))
}

/// Turn online get_info results (hash, sha256, signature, file_name) into hits
/// attributed to every host and artifact in the case that holds the hash.
pub fn online_hits(db_path: &Path, found: &[(String, String, String, String)]) -> Result<Vec<BazaarHit>, String> {
    let conn = duckdb::Connection::open(db_path).map_err(|e| e.to_string())?;
    gather(&conn)?;
    conn.execute_batch("CREATE OR REPLACE TEMP TABLE online_found (hash VARCHAR, sha256 VARCHAR, signature VARCHAR, file_name VARCHAR)").map_err(|e| e.to_string())?;
    for (h, s, sig, f) in found {
        conn.execute("INSERT INTO online_found VALUES (lower(trim(?)), lower(trim(?)), ?, ?)", [h, s, sig, f]).map_err(|e| e.to_string())?;
    }
    let mut stmt = conn.prepare("SELECT DISTINCT c.host_id, c.artifact, c.name, c.hash, CASE length(c.hash) WHEN 64 THEN 'sha256' WHEN 40 THEN 'sha1' ELSE 'md5' END, o.sha256, o.signature, o.file_name FROM case_hashes c JOIN online_found o ON o.hash = c.hash ORDER BY 1, 2, 3").map_err(|e| e.to_string())?;
    let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
    let mut hits = Vec::new();
    let s = |r: &duckdb::Row, i: usize| r.get::<_, Option<String>>(i).ok().flatten().unwrap_or_default();
    while let Some(r) = rows.next().map_err(|e| e.to_string())? {
        hits.push(BazaarHit { host_id: s(r, 0), artifact: s(r, 1), name: s(r, 2), hash: s(r, 3), kind: s(r, 4), sha256: s(r, 5), signature: s(r, 6), file_name: s(r, 7), file_type: String::new(), source: "online lookup".into() });
    }
    Ok(hits)
}

/// Append online lookup hits to an existing report pair.
pub fn append_report(csv: &Path, md: &Path, hits: &[BazaarHit], looked_up: usize) -> Result<(), String> {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new().append(true).open(csv).map_err(|e| e.to_string())?;
    for h in hits {
        writeln!(f, "{}", [&h.host_id, &h.artifact, &h.name, &h.hash, &h.kind, &h.sha256, &h.signature, &h.file_name, &h.file_type, &h.source].iter().map(|v| csv_cell(v)).collect::<Vec<_>>().join(",")).map_err(|e| e.to_string())?;
    }
    let mut text = std::fs::read_to_string(md).map_err(|e| e.to_string())?;
    text.push_str(&format!("
## Online lookup

- Hashes looked up online: {looked_up}
- Matched (online lookup): {}

| Host | Artifact | Path or name | Hash | Signature | File name | File type | Source |\n|---|---|---|---|---|---|---|---|\n", hits.len()));
    for h in hits {
        let c = |v: &str| v.replace('|', "\\|");
        text.push_str(&format!("| {} | {} | {} | {} | {} | {} | {} | {} |\n", c(&h.host_id), c(&h.artifact), c(&h.name), c(&h.hash), c(&h.signature), c(&h.file_name), c(&h.file_type), c(&h.source)));
    }
    if hits.is_empty() { text.push_str("| none | | | | | | | |\n"); }
    std::fs::write(md, text).map_err(|e| e.to_string())
}

impl BazaarHit {
    pub fn to_hunt(&self) -> super::HuntMatch {
        super::HuntMatch {
            source: self.artifact.clone(),
            host_id: self.host_id.clone(),
            column: self.kind.clone(),
            value: self.hash.clone(),
            ioc_kind: "hash".into(),
            ioc_value: format!("malwarebazaar:{}", self.sha256),
            context: format!("{} {} {} {} ({})", self.name, self.signature, self.file_name, self.file_type, self.source).chars().take(180).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mcparser-bz-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn hex(seed: u64, len: usize) -> String {
        let s = super::super::sha256_bytes(seed.to_string().as_bytes());
        s[..len].to_string()
    }

    #[test]
    fn split_handles_quotes() {
        assert_eq!(split_csv("\"a\", \"b,c\", \"d\"\"e\""), vec!["a", "b,c", "d\"e"]);
    }

    #[test]
    fn import_adds_then_updates_only_changed() {
        let d = tmp("upd");
        let store = d.join("marketplace.sqlite");
        let csv = d.join("a.csv");
        let (a, b) = (hex(1, 64), hex(2, 64));
        std::fs::write(&csv, format!("# header\n# \"first_seen_utc\",\"sha256_hash\",\"md5_hash\",\"sha1_hash\",\"reporter\",\"file_name\",\"file_type_guess\",\"mime_type\",\"signature\"\n\"2026-01-01 00:00:00\",\"{a}\",\"{}\",\"{}\",\"r\",\"x.exe\",\"exe\",\"app\",\"Fam\"\n\"2026-01-02 00:00:00\",\"{b}\",\"n/a\",\"n/a\",\"r\",\"y.dll\",\"dll\",\"app\",\"n/a\"\n", hex(3, 32), hex(4, 40))).unwrap();
        let c = import_dump(&store, &csv, &mut |_| {}).unwrap();
        assert_eq!((c.added, c.updated, c.unchanged, c.total), (2, 0, 0, 2));
        let c = import_dump(&store, &csv, &mut |_| {}).unwrap();
        assert_eq!((c.added, c.updated, c.unchanged), (0, 0, 2));
        std::fs::write(&csv, format!("\"2026-01-01\",\"{a}\",\"\",\"\",\"r\",\"x.exe\",\"exe\",\"app\",\"Renamed\"\n\"2026-01-03\",\"{}\",\"\",\"\",\"r\",\"z\",\"exe\",\"app\",\"\"\n", hex(5, 64))).unwrap();
        let c = import_dump(&store, &csv, &mut |_| {}).unwrap();
        assert_eq!((c.added, c.updated, c.unchanged, c.total), (1, 1, 0, 3));
        remove_dump(&store).unwrap();
        assert!(!dump_path(&store).exists());
    }

    #[test]
    fn matcher_joins_thousands_of_rows() {
        let d = tmp("match");
        let store = d.join("marketplace.sqlite");
        let csv = d.join("dump.csv");
        let mut body = String::new();
        for i in 0..5000u64 {
            body.push_str(&format!("\"2026-01-01\",\"{}\",\"{}\",\"{}\",\"r\",\"f{i}.exe\",\"exe\",\"app\",\"Sig{i}\"\n", hex(i, 64), hex(i + 100_000, 32), hex(i + 200_000, 40)));
        }
        std::fs::write(&csv, body).unwrap();
        import_dump(&store, &csv, &mut |_| {}).unwrap();
        let db_path = d.join("events.duckdb");
        let db = duckdb::Connection::open(&db_path).unwrap();
        db.execute_batch("CREATE TABLE amcache (host_id VARCHAR, kind VARCHAR, name VARCHAR, path VARCHAR, sha1 VARCHAR, size BIGINT, modified VARCHAR, publisher VARCHAR, version VARCHAR, key_path VARCHAR);
            CREATE TABLE events (source_sha256 VARCHAR, record_id BIGINT, event_id INTEGER, channel VARCHAR, provider VARCHAR, computer VARCHAR, time_created VARCHAR, event_data VARCHAR, host_id VARCHAR, log_name VARCHAR);").unwrap();
        for i in 0..3000u64 {
            let sha1 = if i % 100 == 0 { hex(i + 200_000, 40) } else { hex(i + 900_000, 40) };
            db.execute("INSERT INTO amcache (host_id, name, path, sha1) VALUES ('H1', ?, ?, ?)", duckdb::params![format!("n{i}"), format!("C:\\p{i}.exe"), sha1]).unwrap();
        }
        db.execute("INSERT INTO events (event_id, provider, computer, event_data, host_id) VALUES (1, 'Sysmon', 'PC', ?, 'H2')", [format!("{{\"Hashes\":\"SHA256={},MD5={}\"}}", hex(7, 64).to_uppercase(), hex(100_008, 32))]).unwrap();
        drop(db);
        let out = match_case(&store, &db_path, &mut |_, _| {}).unwrap();
        assert_eq!(out.hits.iter().filter(|h| h.artifact == "amcache").count(), 30);
        assert_eq!(out.hits.iter().filter(|h| h.artifact == "events").count(), 2);
        assert_eq!(out.checked, 3002);
        assert_eq!(out.unmatched.len(), 2970);
        let (csv, md, _) = write_report(&d, "1", &out).unwrap();
        assert!(std::fs::read_to_string(csv).unwrap().contains("Sig7"));
        assert!(std::fs::read_to_string(md).unwrap().contains("Hashes checked: 3002"));
    }

    #[test]
    fn narrow_and_full_views() {
        let d = tmp("views");
        let store = d.join("marketplace.sqlite");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/malwarebazaar/recent-sample.csv");
        import_dump(&store, &fixture, &mut |_| {}).unwrap();
        let conn = duckdb::Connection::open_in_memory().unwrap();
        assert!(attach_dump(&conn, &store).unwrap());
        let cols = |t: &str| -> Vec<String> {
            let mut st = conn.prepare(&format!("SELECT column_name FROM (DESCRIBE {t})")).unwrap();
            st.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect()
        };
        assert_eq!(cols("malwarebazaar"), ["sha256", "sha1", "md5", "signature", "file_name", "first_seen"]);
        let full = cols("malwarebazaar_full");
        for c in ["sha256", "md5", "sha1", "file_type", "tags", "reporter", "clamav", "imphash", "note"] { assert!(full.iter().any(|x| x == c), "{c}"); }
        assert!(full.len() > 20);
        let n: i64 = conn.query_row("SELECT count(*) FROM malwarebazaar", [], |r| r.get(0)).unwrap();
        let m: i64 = conn.query_row("SELECT count(*) FROM malwarebazaar_full", [], |r| r.get(0)).unwrap();
        assert_eq!((n, m), (3, 3));
    }

    #[test]
    fn fixture_fills_every_column() {
        let d = tmp("cols");
        let store = d.join("marketplace.sqlite");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/malwarebazaar/recent-sample.csv");
        let c = import_dump(&store, &fixture, &mut |_| {}).unwrap();
        assert_eq!((c.read, c.added), (3, 3));
        let db = duckdb::Connection::open(dump_path(&store)).unwrap();
        let row: Vec<Option<String>> = db.query_row(
            "SELECT md5, sha1, imphash, ssdeep, tlsh, first_seen, reporter, file_name, file_type, mime_type, signature, clamav, vtpercent, tags, note FROM malwarebazaar WHERE signature = 'AgentTesla'",
            [], |r| (0..15).map(|i| r.get(i)).collect()).unwrap();
        assert_eq!(row[0].as_deref(), Some("0123456789abcdef0123456789abcdef"));
        assert_eq!(row[1].as_deref(), Some("0123456789abcdef0123456789abcdef01234567"));
        assert_eq!(row[2].as_deref(), Some("f34d5f2d4577ed6d9ceec516c1f5a744"));
        assert_eq!(row[3].as_deref(), Some("3072:abc,def:ghi"));
        assert_eq!(row[5].as_deref(), Some("2026-10-28 01:02:03"));
        assert_eq!(row[7].as_deref(), Some("invoice, \"Q3\".exe"));
        assert_eq!(row[8].as_deref(), Some("exe"));
        assert_eq!(row[9].as_deref(), Some("application/x-dosexec"));
        assert_eq!(row[13].as_deref(), Some("exe,AgentTesla"));
        assert_eq!(row[14].as_deref(), Some("{\"custom_extra\":\"x1\"}"));
        // n/a and empty values become NULL, bad hashes are dropped.
        let (md5, sig, note): (Option<String>, Option<String>, Option<String>) = db.query_row("SELECT md5, signature, note FROM malwarebazaar WHERE file_name = 'b.dll'", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!((md5, sig, note), (None, None, None));
        drop(db);
        let c = import_dump(&store, &fixture, &mut |_| {}).unwrap();
        assert_eq!((c.added, c.updated, c.unchanged), (0, 0, 3));
        // A change in any one column updates only that row.
        let text = std::fs::read_to_string(&fixture).unwrap().replace("\"ssdeep-b\"", "\"ssdeep-b2\"");
        let changed = d.join("changed.csv");
        std::fs::write(&changed, text).unwrap();
        let c = import_dump(&store, &changed, &mut |_| {}).unwrap();
        assert_eq!((c.added, c.updated, c.unchanged), (0, 1, 2));
    }

    #[test]
    fn header_variants_map_to_columns() {
        let cols = Columns::from_header(&split_csv("SHA256, MD5 , File Name, file_type, Signature, odd")).unwrap();
        assert_eq!(cols.sha256, 0);
        let at = |name: &str| cols.typed[FIELDS.iter().position(|(c, _)| *c == name).unwrap()];
        assert_eq!((at("md5"), at("file_name"), at("file_type"), at("signature"), at("sha1")), (Some(1), Some(2), Some(3), Some(4), None));
        assert_eq!(cols.extra, vec![("odd".to_string(), 5)]);
    }

    #[test]
    fn old_note_schema_is_migrated() {
        let d = tmp("mig");
        let store = d.join("marketplace.sqlite");
        let a = hex(9, 64);
        {
            let db = duckdb::Connection::open(dump_path(&store)).unwrap();
            db.execute_batch("CREATE TABLE malwarebazaar (sha256 VARCHAR PRIMARY KEY, md5 VARCHAR, sha1 VARCHAR, note VARCHAR)").unwrap();
            db.execute("INSERT INTO malwarebazaar VALUES (?, NULL, NULL, '{\"file_name\":\"m.exe\",\"signature\":\"Old\",\"file_type\":\"exe\",\"reporter\":\"r\"}')", [&a]).unwrap();
        }
        let csv = d.join("e.csv");
        std::fs::write(&csv, "# empty\n").unwrap();
        import_dump(&store, &csv, &mut |_| {}).unwrap();
        let db = duckdb::Connection::open(dump_path(&store)).unwrap();
        let (f, s, n): (String, String, Option<String>) = db.query_row("SELECT file_name, signature, note FROM malwarebazaar", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!((f.as_str(), s.as_str(), n), ("m.exe", "Old", None));
    }

    /// One million synthetic dump rows. Run with `cargo test --release -- --ignored`.
    #[test]
    #[ignore]
    fn perf_one_million_rows() {
        let d = tmp("perf");
        let store = d.join("marketplace.sqlite");
        let csv = d.join("dump.csv");
        {
            let mut f = std::io::BufWriter::new(std::fs::File::create(&csv).unwrap());
            for i in 0..1_000_000u64 {
                writeln!(f, "\"2026-01-01\",\"{:064x}\",\"{:032x}\",\"{:040x}\",\"r\",\"f.exe\",\"exe\",\"app\",\"S\"", i, i, i).unwrap();
            }
        }
        let t = std::time::Instant::now();
        let c = import_dump(&store, &csv, &mut |_| {}).unwrap();
        assert_eq!(c.total, 1_000_000);
        let db_path = d.join("events.duckdb");
        let db = duckdb::Connection::open(&db_path).unwrap();
        db.execute_batch("CREATE TABLE amcache AS SELECT 'H' AS host_id, 'k' AS kind, 'n' AS name, 'p' AS path, printf('%040x', i) AS sha1 FROM range(0, 2000000, 20) t(i)").unwrap();
        drop(db);
        let out = match_case(&store, &db_path, &mut |_, _| {}).unwrap();
        assert_eq!(out.hits.len(), 50_000);
        eprintln!("1M import + match: {:?}", t.elapsed());
    }
}
