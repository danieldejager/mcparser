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

fn open_dump(path: &Path) -> Result<duckdb::Connection, String> {
    let db = duckdb::Connection::open(path).map_err(|e| e.to_string())?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS malwarebazaar (sha256 VARCHAR PRIMARY KEY, md5 VARCHAR, sha1 VARCHAR, note VARCHAR);
         CREATE TABLE IF NOT EXISTS malwarebazaar_meta (key VARCHAR PRIMARY KEY, value VARCHAR);",
    ).map_err(|e| e.to_string())?;
    Ok(db)
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

struct Columns { sha256: usize, md5: Option<usize>, sha1: Option<usize>, reporter: Option<usize>, file_name: Option<usize>, file_type: Option<usize>, signature: Option<usize>, first_seen: Option<usize> }

impl Columns {
    /// abuse.ch export order: first_seen_utc, sha256_hash, md5_hash, sha1_hash,
    /// reporter, file_name, file_type_guess, mime_type, signature, ...
    fn default_order() -> Self {
        Columns { sha256: 1, md5: Some(2), sha1: Some(3), reporter: Some(4), file_name: Some(5), file_type: Some(6), signature: Some(8), first_seen: Some(0) }
    }
    fn from_header(fields: &[String]) -> Option<Self> {
        let find = |names: &[&str]| fields.iter().position(|f| names.contains(&f.to_ascii_lowercase().as_str()));
        let sha256 = find(&["sha256_hash", "sha256"])?;
        Some(Columns {
            sha256,
            md5: find(&["md5_hash", "md5"]),
            sha1: find(&["sha1_hash", "sha1"]),
            reporter: find(&["reporter"]),
            file_name: find(&["file_name"]),
            file_type: find(&["file_type_guess", "file_type"]),
            signature: find(&["signature"]),
            first_seen: find(&["first_seen_utc", "first_seen"]),
        })
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
    db.execute_batch("CREATE OR REPLACE TEMP TABLE staging (sha256 VARCHAR, md5 VARCHAR, sha1 VARCHAR, note VARCHAR)").map_err(|e| e.to_string())?;
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
            let md5 = get(cols.md5).to_ascii_lowercase();
            let sha1 = get(cols.sha1).to_ascii_lowercase();
            let clean = |s: String| if s == "n/a" { String::new() } else { s };
            let note = serde_json::json!({
                "file_name": clean(get(cols.file_name)),
                "signature": clean(get(cols.signature)),
                "file_type": clean(get(cols.file_type)),
                "reporter": clean(get(cols.reporter)),
            }).to_string();
            let seen = get(cols.first_seen);
            if seen > newest { newest = seen; }
            app.append_row(duckdb::params![
                sha256,
                if is_hex(&md5, 32) { Some(md5) } else { None },
                if is_hex(&sha1, 40) { Some(sha1) } else { None },
                note
            ]).map_err(|e| e.to_string())?;
            counts.read += 1;
            if counts.read % 100_000 == 0 { progress(counts.read); }
        }
        app.flush().map_err(|e| e.to_string())?;
    }
    // Last row wins for duplicate hashes inside one file.
    db.execute_batch(
        "CREATE OR REPLACE TEMP TABLE incoming AS SELECT sha256, any_value(md5) AS md5, any_value(sha1) AS sha1, any_value(note) AS note FROM staging GROUP BY sha256;
         DROP TABLE staging;",
    ).map_err(|e| e.to_string())?;
    let q = |sql: &str| -> Result<u64, String> { db.query_row(sql, [], |r| r.get::<_, i64>(0)).map(|v| v as u64).map_err(|e| e.to_string()) };
    counts.added = q("SELECT count(*) FROM incoming i ANTI JOIN malwarebazaar m USING (sha256)")?;
    counts.updated = q("SELECT count(*) FROM incoming i JOIN malwarebazaar m USING (sha256) WHERE i.md5 IS DISTINCT FROM m.md5 OR i.sha1 IS DISTINCT FROM m.sha1 OR i.note IS DISTINCT FROM m.note")?;
    let incoming = q("SELECT count(*) FROM incoming")?;
    counts.unchanged = incoming - counts.added - counts.updated;
    db.execute_batch(
        "BEGIN;
         UPDATE malwarebazaar m SET md5 = i.md5, sha1 = i.sha1, note = i.note FROM incoming i
           WHERE m.sha256 = i.sha256 AND (i.md5 IS DISTINCT FROM m.md5 OR i.sha1 IS DISTINCT FROM m.sha1 OR i.note IS DISTINCT FROM m.note);
         INSERT INTO malwarebazaar SELECT i.sha256, i.md5, i.sha1, i.note FROM incoming i ANTI JOIN malwarebazaar m USING (sha256);
         COMMIT;
         DROP TABLE incoming;",
    ).map_err(|e| e.to_string())?;
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

/// Make `malwarebazaar` queryable on a connection when the dump exists.
pub fn attach_dump(conn: &duckdb::Connection, store: &Path) -> Result<bool, String> {
    let path = dump_path(store);
    if !path.exists() { return Ok(false); }
    let lit = path.to_string_lossy().replace('\'', "''");
    conn.execute_batch(&format!(
        "ATTACH IF NOT EXISTS '{lit}' AS mbz (READ_ONLY);
         CREATE OR REPLACE TEMP VIEW malwarebazaar AS SELECT * FROM mbz.malwarebazaar;"
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

/// Gather every hash-like value in the case and join it against the dump.
pub fn match_case(store: &Path, db_path: &Path, progress: &mut dyn FnMut(u8, &str)) -> Result<MatchOutcome, String> {
    let (dump_rows, dump_meta) = dump_info(store).ok_or("The MalwareBazaar dump is not loaded. Upload or fetch it first.")?;
    let conn = duckdb::Connection::open(db_path).map_err(|e| e.to_string())?;
    progress(10, "Gathering hashes from the case");
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
    let checked: i64 = conn.query_row("SELECT count(DISTINCT hash) FROM case_hashes", [], |r| r.get(0)).map_err(|e| e.to_string())?;
    progress(40, &format!("Comparing {checked} hashes against {dump_rows} dump rows"));
    attach_dump(&conn, store)?;
    let sql = "WITH h AS (SELECT DISTINCT host_id, artifact, name, hash FROM case_hashes)
        SELECT h.host_id, h.artifact, h.name, h.hash, 'sha256', m.sha256, m.note FROM h JOIN mbz.malwarebazaar m ON length(h.hash) = 64 AND m.sha256 = h.hash
        UNION ALL SELECT h.host_id, h.artifact, h.name, h.hash, 'sha1', m.sha256, m.note FROM h JOIN mbz.malwarebazaar m ON length(h.hash) = 40 AND m.sha1 = h.hash
        UNION ALL SELECT h.host_id, h.artifact, h.name, h.hash, 'md5', m.sha256, m.note FROM h JOIN mbz.malwarebazaar m ON length(h.hash) = 32 AND m.md5 = h.hash
        ORDER BY 1, 2, 3";
    let mut hits = Vec::new();
    {
        let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
        let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let note: String = row.get::<_, Option<String>>(6).ok().flatten().unwrap_or_default();
            let json: serde_json::Value = serde_json::from_str(&note).unwrap_or_default();
            let field = |k: &str| json.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            hits.push(BazaarHit {
                host_id: row.get::<_, Option<String>>(0).ok().flatten().unwrap_or_default(),
                artifact: row.get(1).unwrap_or_default(),
                name: row.get::<_, Option<String>>(2).ok().flatten().unwrap_or_default(),
                hash: row.get(3).unwrap_or_default(),
                kind: row.get(4).unwrap_or_default(),
                sha256: row.get(5).unwrap_or_default(),
                signature: field("signature"),
                file_name: field("file_name"),
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
    writeln!(f, "host,artifact,path_or_name,hash,hash_kind,sha256,signature,file_name,source").map_err(|e| e.to_string())?;
    for h in &outcome.hits {
        writeln!(f, "{}", [&h.host_id, &h.artifact, &h.name, &h.hash, &h.kind, &h.sha256, &h.signature, &h.file_name, &h.source].iter().map(|v| csv_cell(v)).collect::<Vec<_>>().join(",")).map_err(|e| e.to_string())?;
    }
    f.flush().map_err(|e| e.to_string())?;
    std::fs::write(&un, outcome.unmatched.join("\n")).map_err(|e| e.to_string())?;
    let meta = |k: &str| outcome.dump_meta.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone()).unwrap_or_default();
    let mut text = format!(
        "# MalwareBazaar match report\n\n- Report time (unix seconds): {stamp}\n- Hashes checked: {}\n- Matched (local dump): {}\n- Not in dump: {}\n- Dump rows: {}\n- Dump imported at (unix seconds): {}\n- Dump file: {}\n- Newest first_seen in dump: {}\n\nThe dump may be the recent export rather than every sample ever seen. A miss is not proof a file is clean.\n\n",
        outcome.checked, outcome.hits.len(), outcome.unmatched.len(), outcome.dump_rows, meta("imported_at"), meta("source_file"), meta("newest_first_seen"),
    );
    text.push_str("| Host | Artifact | Path or name | Hash | Signature | File name | Source |\n|---|---|---|---|---|---|---|\n");
    for h in &outcome.hits {
        let c = |v: &str| v.replace('|', "\\|");
        text.push_str(&format!("| {} | {} | {} | {} | {} | {} | {} |\n", c(&h.host_id), c(&h.artifact), c(&h.name), c(&h.hash), c(&h.signature), c(&h.file_name), c(&h.source)));
    }
    if outcome.hits.is_empty() { text.push_str("| none | | | | | | |\n"); }
    std::fs::write(&md, text).map_err(|e| e.to_string())?;
    Ok((csv, md, un))
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
            context: format!("{} {} {} ({})", self.name, self.signature, self.file_name, self.source).chars().take(180).collect(),
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
