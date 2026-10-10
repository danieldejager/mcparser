use duckdb::{Connection, params};
use model::Event;
use sha2::{Digest, Sha256};
use std::path::Path;

pub fn name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

pub struct Table {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

pub struct Source {
    pub sha256: String,
    pub path: String,
    pub records: i64,
}

pub struct SavedQuery {
    pub name: String,
    pub sql: String,
}

pub fn ingest(db_path: &Path, source_sha256: &str, events: &[Event]) -> Result<usize, duckdb::Error> {
    let conn = Connection::open(db_path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS events (
            source_sha256 VARCHAR,
            record_id BIGINT,
            event_id INTEGER,
            channel VARCHAR,
            provider VARCHAR,
            computer VARCHAR,
            time_created VARCHAR,
            event_data VARCHAR,
            host_id VARCHAR,
            log_name VARCHAR
        )",
    )?;
    let _ = conn.execute_batch("ALTER TABLE events ADD COLUMN IF NOT EXISTS host_id VARCHAR");
    let _ = conn.execute_batch("ALTER TABLE events ADD COLUMN IF NOT EXISTS log_name VARCHAR");
    let mut appender = conn.appender("events")?;
    for event in events {
        appender.append_row(params![
            source_sha256,
            event.record_id,
            event.event_id,
            event.channel,
            event.provider,
            event.computer,
            event.time_created,
            event.event_data,
            "",
            "",
        ])?;
    }
    appender.flush()?;
    Ok(events.len())
}

pub fn count_event_id(db_path: &Path, event_id: u32) -> Result<i64, duckdb::Error> {
    let conn = Connection::open(db_path)?;
    conn.query_row(
        "SELECT count(*) FROM events WHERE event_id = ?",
        [event_id],
        |row| row.get(0),
    )
}

pub fn query(db_path: &Path, sql: &str) -> Result<Vec<Vec<String>>, duckdb::Error> {
    Ok(query_table(db_path, sql)?.rows)
}

pub fn query_table(db_path: &Path, sql: &str) -> Result<Table, duckdb::Error> {
    let conn = Connection::open(db_path)?;
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query([])?;
    let mut table = Table {
        columns: Vec::new(),
        rows: Vec::new(),
    };
    while let Some(row) = rows.next()? {
        let column_count = row.as_ref().column_count();
        if table.columns.is_empty() {
            for i in 0..column_count {
                let name = row
                    .as_ref()
                    .column_name(i)
                    .map(|name| name.to_string())
                    .unwrap_or_else(|_| format!("column_{i}"));
                table.columns.push(name);
            }
        }
        let mut cols = Vec::with_capacity(column_count);
        for i in 0..column_count {
            cols.push(cell(row, i));
        }
        table.rows.push(cols);
    }
    Ok(table)
}

fn cell(row: &duckdb::Row, i: usize) -> String {
    if let Ok(value) = row.get::<_, i64>(i) {
        return value.to_string();
    }
    if let Ok(value) = row.get::<_, f64>(i) {
        return value.to_string();
    }
    if let Ok(value) = row.get::<_, String>(i) {
        return value;
    }
    String::new()
}

pub fn file_sha256(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = std::io::Read::read(&mut file, &mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn report_progress(pct: u8, message: &str) {
    println!("progress\t{pct}\t{message}");
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

pub fn artifact_done(catalog: &Path, name: &str, zip_sha: &str) -> Result<bool, rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM sources WHERE source_path = ?1 AND sha256 = ?2",
        rusqlite::params![name, format!("{zip_sha}:{name}")],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

pub fn record_artifact(catalog: &Path, name: &str, zip_sha: &str, records: i64) -> Result<(), rusqlite::Error> {
    record_source(catalog, Path::new(name), &format!("{zip_sha}:{name}"), records)
}

pub fn already_ingested(catalog: &Path, sha256: &str) -> Result<bool, rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM sources WHERE sha256 = ?1",
        [sha256],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

pub fn record_source(
    catalog: &Path,
    source: &Path,
    sha256: &str,
    records: i64,
) -> Result<(), rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    conn.execute(
        "INSERT INTO sources (sha256, source_path, records) VALUES (?1, ?2, ?3)",
        rusqlite::params![sha256, source.display().to_string(), records],
    )?;
    Ok(())
}

fn open_catalog(path: &Path) -> Result<rusqlite::Connection, rusqlite::Error> {
    let conn = rusqlite::Connection::open(path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sources (
            sha256 TEXT PRIMARY KEY,
            source_path TEXT NOT NULL,
            records INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS queries (
            name TEXT PRIMARY KEY,
            sql TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notes (
            record_id INTEGER PRIMARY KEY,
            body TEXT NOT NULL,
            query_sql TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sql TEXT NOT NULL,
            ran_at TEXT NOT NULL,
            row_count INTEGER NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            followed INTEGER
        )",
    )?;
    let _ = conn.execute("ALTER TABLE notes ADD COLUMN query_sql TEXT NOT NULL DEFAULT ''", []);
    let _ = conn.execute("ALTER TABLE runs ADD COLUMN label TEXT NOT NULL DEFAULT ''", []);
    let _ = conn.execute("ALTER TABLE runs ADD COLUMN followed INTEGER", []);
    let _ = conn.execute("ALTER TABLE runs ADD COLUMN analyst TEXT NOT NULL DEFAULT ''", []);
    let _ = conn.execute("ALTER TABLE runs ADD COLUMN kind TEXT NOT NULL DEFAULT 'run'", []);
    let _ = conn.execute("ALTER TABLE notes ADD COLUMN created TEXT NOT NULL DEFAULT ''", []);
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asked_at TEXT NOT NULL,
            vendor TEXT NOT NULL,
            question TEXT NOT NULL,
            sql TEXT NOT NULL,
            answer TEXT NOT NULL
        )",
        [],
    );
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS case_info (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS hosts (
            host_id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            fqdn TEXT NOT NULL,
            os TEXT NOT NULL,
            arch TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS collections (
            session_id TEXT PRIMARY KEY,
            host_id TEXT NOT NULL,
            collected_at TEXT NOT NULL,
            zip_sha256 TEXT NOT NULL,
            source_name TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            added_at TEXT NOT NULL,
            UNIQUE(kind, value)
        )",
    )?;
    Ok(conn)
}

pub fn source_sha_for_path(catalog: &Path, source: &Path) -> Result<Option<String>, rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    let mut stmt = conn.prepare("SELECT sha256 FROM sources WHERE source_path = ?1")?;
    let mut rows = stmt.query([source.display().to_string()])?;
    match rows.next()? {
        Some(row) => Ok(Some(row.get(0)?)),
        None => Ok(None),
    }
}

pub fn sources(catalog: &Path) -> Result<Vec<Source>, rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    let mut stmt = conn.prepare("SELECT sha256, source_path, records FROM sources ORDER BY source_path")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(Source {
            sha256: row.get(0)?,
            path: row.get(1)?,
            records: row.get(2)?,
        });
    }
    Ok(out)
}

pub fn remove_source(catalog: &Path, sha256: &str) -> Result<(), rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    conn.execute("DELETE FROM sources WHERE sha256 = ?1", [sha256])?;
    Ok(())
}

pub fn delete_events_for_source(db_path: &Path, sha256: &str) -> Result<usize, duckdb::Error> {
    let conn = Connection::open(db_path)?;
    conn.execute("DELETE FROM events WHERE source_sha256 = ?", [sha256])
}

pub fn save_query(catalog: &Path, name: &str, sql: &str) -> Result<(), rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    conn.execute(
        "INSERT INTO queries (name, sql) VALUES (?1, ?2)
         ON CONFLICT(name) DO UPDATE SET sql = excluded.sql",
        rusqlite::params![name, sql],
    )?;
    Ok(())
}

pub fn queries(catalog: &Path) -> Result<Vec<SavedQuery>, rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    let mut stmt = conn.prepare("SELECT name, sql FROM queries ORDER BY name")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(SavedQuery {
            name: row.get(0)?,
            sql: row.get(1)?,
        });
    }
    Ok(out)
}

pub struct Note {
    pub record_id: i64,
    pub body: String,
    pub query_sql: String,
    pub created: String,
}

pub fn save_note(catalog: &Path, record_id: i64, body: &str, query_sql: &str) -> Result<(), rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default();
    conn.execute(
        "INSERT INTO notes (record_id, body, query_sql, created) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(record_id) DO UPDATE SET body = excluded.body, query_sql = excluded.query_sql",
        rusqlite::params![record_id, body, query_sql, created],
    )?;
    Ok(())
}

pub fn notes(catalog: &Path) -> Result<Vec<Note>, rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    let mut stmt = conn.prepare("SELECT record_id, body, query_sql, created FROM notes ORDER BY record_id")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(Note { record_id: row.get(0)?, body: row.get(1)?, query_sql: row.get(2)?, created: row.get(3)? });
    }
    Ok(out)
}

pub struct Run {
    pub id: i64,
    pub sql: String,
    pub ran_at: String,
    pub row_count: i64,
    pub label: String,
    pub followed: Option<i64>,
    pub analyst: String,
    pub kind: String,
}

pub fn save_run(catalog: &Path, sql: &str, ran_at: &str, row_count: i64, label: &str, analyst: &str, kind: &str) -> Result<i64, rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    let followed: Option<i64> = conn.query_row("SELECT max(id) FROM runs", [], |row| row.get(0)).ok();
    conn.execute(
        "INSERT INTO runs (sql, ran_at, row_count, label, followed, analyst, kind) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![sql, ran_at, row_count, label, followed, analyst, kind],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn runs(catalog: &Path) -> Result<Vec<Run>, rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    let mut stmt = conn.prepare("SELECT id, sql, ran_at, row_count, label, followed, analyst, kind FROM runs ORDER BY id")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(Run {
            id: row.get(0)?,
            sql: row.get(1)?,
            ran_at: row.get(2)?,
            row_count: row.get(3)?,
            label: row.get(4)?,
            followed: row.get(5)?,
            analyst: row.get(6)?,
            kind: row.get(7)?,
        });
    }
    Ok(out)
}

pub struct Chat {
    pub id: i64,
    pub asked_at: String,
    pub vendor: String,
    pub question: String,
    pub sql: String,
    pub answer: String,
}

pub fn save_chat(catalog: &Path, vendor: &str, question: &str, sql: &str, answer: &str) -> Result<i64, rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    let asked_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default();
    conn.execute(
        "INSERT INTO chats (asked_at, vendor, question, sql, answer) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![asked_at, vendor, question, sql, answer],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn chats(catalog: &Path) -> Result<Vec<Chat>, rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    let mut stmt = conn.prepare("SELECT id, asked_at, vendor, question, sql, answer FROM chats ORDER BY id")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(Chat {
            id: row.get(0)?,
            asked_at: row.get(1)?,
            vendor: row.get(2)?,
            question: row.get(3)?,
            sql: row.get(4)?,
            answer: row.get(5)?,
        });
    }
    Ok(out)
}


pub struct Host {
    pub host_id: String,
    pub hostname: String,
    pub fqdn: String,
    pub os: String,
    pub arch: String,
}

pub struct Collection {
    pub session_id: String,
    pub host_id: String,
    pub collected_at: String,
    pub zip_sha256: String,
    pub source_name: String,
}

pub fn hosts(catalog: &Path) -> Result<Vec<Host>, rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    let mut stmt = conn.prepare("SELECT host_id, hostname, fqdn, os, arch FROM hosts ORDER BY hostname")?;
    let rows = stmt.query_map([], |row| {
        Ok(Host {
            host_id: row.get(0)?,
            hostname: row.get(1)?,
            fqdn: row.get(2)?,
            os: row.get(3)?,
            arch: row.get(4)?,
        })
    })?;
    rows.collect()
}

pub fn collections(catalog: &Path) -> Result<Vec<Collection>, rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    let mut stmt = conn.prepare(
        "SELECT session_id, host_id, collected_at, zip_sha256, source_name FROM collections ORDER BY collected_at",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(Collection {
            session_id: row.get(0)?,
            host_id: row.get(1)?,
            collected_at: row.get(2)?,
            zip_sha256: row.get(3)?,
            source_name: row.get(4)?,
        })
    })?;
    rows.collect()
}

fn keep_raw(name: &str) -> bool {
    let lower_path = name.to_ascii_lowercase();
    let lower = lower_path.rsplit(['/', '\\']).next().unwrap_or(&lower_path);
    lower == "ntuser.dat" || lower == "software.hiv" || lower == "system" || lower == "system.hiv"
        || lower == "amcache.hve" || lower == "srudb.dat" || lower.ends_with(".pf") || lower.ends_with(".json") || lower.ends_with(".jsonl")
        || lower.ends_with(".xml") || lower_path.contains("/tasks/") || lower_path.contains("\\tasks\\")
}

fn safe_name(name: &str) -> String {
    name.split(['/', '\\']).filter(|part| !part.is_empty() && *part != "." && *part != "..").collect::<Vec<_>>().join("/")
}

fn write_kept(case_dir: &Path, sha: &str, name: &str, bytes: &[u8]) -> Result<std::path::PathBuf, String> {
    if name.ends_with('/') || name.ends_with('\\') { return Err("directory entry".into()); }
    let relative = safe_name(name);
    if relative.is_empty() { return Err("empty archive name".into()); }
    let path = case_dir.join("files").join(sha).join(&relative);
    if path.is_dir() {
        std::fs::remove_dir_all(&path).map_err(|err| format!("{}: {err}", path.display()))?;
    }
    if let Some(parent) = path.parent() {
        let mut cursor = parent.to_path_buf();
        let mut blocked = Vec::new();
        while !cursor.exists() {
            blocked.push(cursor.clone());
            if !cursor.pop() { break; }
        }
        if cursor.is_file() {
            std::fs::remove_file(&cursor).map_err(|err| format!("{}: {err}", cursor.display()))?;
        }
        std::fs::create_dir_all(parent).map_err(|err| format!("{}: {err}", parent.display()))?;
    }
    std::fs::write(&path, bytes).map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(path)
}

pub fn import_collector(catalog: &Path, zip_path: &Path) -> Result<(Vec<Host>, Vec<Collection>, Vec<std::path::PathBuf>), String> {
    let sha = file_sha256(zip_path).map_err(|err| err.to_string())?;
    let file = std::fs::File::open(zip_path).map_err(|err| err.to_string())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|err| err.to_string())?;
    let mut client_info_names = Vec::new();
    let mut nested_zips = Vec::new();
    let mut raw_files = Vec::new();
    let entry_total = archive.len().max(1);
    for i in 0..entry_total {
        let mut entry = archive.by_index(i).map_err(|err| err.to_string())?;
        let name = entry.name().to_string();
        report_progress((2 + (i * 10 / entry_total)) as u8, &format!("Reading collector {}/{entry_total} {name}", i + 1));
        if name.ends_with("client_info.json") {
            client_info_names.push(name);
        } else if name.ends_with(".zip") && entry.size() < 80_000_000 {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut bytes).map_err(|err| err.to_string())?;
            nested_zips.push((name, bytes));
        } else if !name.ends_with('/') && !name.ends_with('\\') && keep_raw(&name) && entry.size() < 80_000_000 {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut bytes).map_err(|err| err.to_string())?;
            raw_files.push((name, bytes));
        }
    }
    let mut found: Vec<(String, Host, Collection)> = Vec::new();
    for name in client_info_names {
        let mut entry = archive.by_name(&name).map_err(|err| err.to_string())?;
        let mut body = String::new();
        std::io::Read::read_to_string(&mut entry, &mut body).map_err(|err| err.to_string())?;
        drop(entry);
        let host = host_from_client_info(&body)?;
        let session = collection_from_same_zip(&mut archive, &name, &host.host_id, &sha, zip_path)?;
        found.push((name, host, session));
    }
    let nested_total = nested_zips.len().max(1);
    for (index, (name, bytes)) in nested_zips.iter().enumerate() {
        report_progress((12 + (index * 4 / nested_total)) as u8, &format!("Reading {name}"));
        if let Some(hit) = nested_collector(&bytes, &sha, &name) {
            found.push(hit);
        }
    }
    if found.is_empty() {
        return Err("no client_info.json in collector zip".into());
    }
    let mut hosts = Vec::new();
    let mut saved = Vec::new();
    let conn = open_catalog(catalog).map_err(|err| err.to_string())?;
    for (_, host, collection) in &found {
        conn.execute(
            "INSERT INTO hosts (host_id, hostname, fqdn, os, arch) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(host_id) DO UPDATE SET hostname = excluded.hostname, fqdn = excluded.fqdn, os = excluded.os, arch = excluded.arch",
            rusqlite::params![host.host_id, host.hostname, host.fqdn, host.os, host.arch],
        ).map_err(|err| err.to_string())?;
        if !hosts.iter().any(|saved: &Host| saved.host_id == host.host_id) {
            hosts.push(host.clone_host());
        }
        conn.execute(
            "INSERT INTO collections (session_id, host_id, collected_at, zip_sha256, source_name) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(session_id) DO UPDATE SET host_id = excluded.host_id, collected_at = excluded.collected_at, zip_sha256 = excluded.zip_sha256, source_name = excluded.source_name",
            rusqlite::params![collection.session_id, host.host_id, collection.collected_at, collection.zip_sha256, collection.source_name],
        ).map_err(|err| err.to_string())?;
        saved.push(Collection {
            session_id: collection.session_id.clone(),
            host_id: host.host_id.clone(),
            collected_at: collection.collected_at.clone(),
            zip_sha256: collection.zip_sha256.clone(),
            source_name: collection.source_name.clone(),
        });
    }
    let case_dir = catalog.parent().unwrap_or(Path::new("."));
    let mut kept = Vec::new();
    let raw_total = raw_files.len().max(1);
    for (index, (name, bytes)) in raw_files.into_iter().enumerate() {
        if name.ends_with('/') || name.ends_with('\\') { continue; }
        report_progress((2 + (index * 14 / raw_total)) as u8, &format!("Reading {name}"));
        kept.push(write_kept(case_dir, &sha, &name, &bytes)?);
    }
    for (name, bytes) in &nested_zips {
        let cursor = std::io::Cursor::new(bytes);
        let mut nested = zip::ZipArchive::new(cursor).map_err(|err| err.to_string())?;
        for i in 0..nested.len() {
            let mut entry = nested.by_index(i).map_err(|err| err.to_string())?;
            let entry_name = entry.name().to_string();
            let lower_name = name.to_ascii_lowercase();
            let from_bundle = lower_name.contains("task") || lower_name.contains("service");
            if entry_name.ends_with('/') || entry.size() >= 80_000_000 || !(from_bundle || keep_raw(&entry_name)) { continue; }
            let mut body = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut body).map_err(|err| err.to_string())?;
            match write_kept(case_dir, &sha, &format!("{name}/{entry_name}"), &body) {
                Ok(path) => kept.push(path),
                Err(err) if err == "directory entry" => {}
                Err(err) => return Err(err),
            }
        }
    }
    Ok((hosts, saved, kept))
}

fn host_from_client_info(body: &str) -> Result<Host, String> {
    let value: serde_json::Value = serde_json::from_str(body).map_err(|err| err.to_string())?;
    let text = |key: &str| value.get(key).and_then(|item| item.as_str()).unwrap_or("").to_string();
    let host_id = text("HostID");
    if host_id.is_empty() {
        return Err("client_info.json has no HostID".into());
    }
    Ok(Host {
        host_id,
        hostname: text("Hostname"),
        fqdn: text("Fqdn"),
        os: text("Platform"),
        arch: text("Architecture"),
    })
}

fn collection_from_same_zip(archive: &mut zip::ZipArchive<std::fs::File>, client_info_name: &str, host_id: &str, sha: &str, zip_path: &Path) -> Result<Collection, String> {
    let context_name = client_info_name.replace("client_info.json", "collection_context.json");
    let mut collected_at = String::new();
    let mut session_id = String::new();
    if let Ok(mut entry) = archive.by_name(&context_name) {
        let mut body = String::new();
        std::io::Read::read_to_string(&mut entry, &mut body).map_err(|err| err.to_string())?;
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) {
            session_id = value.get("session_id").and_then(|item| item.as_str()).unwrap_or("").to_string();
        }
    }
    if session_id.is_empty() {
        session_id = format!("zip:{}", zip_path.file_name().and_then(|name| name.to_str()).unwrap_or("collector"));
    }
    if collected_at.is_empty() {
        collected_at = client_start_from(archive, client_info_name);
    }
    Ok(Collection {
        session_id,
        host_id: host_id.to_string(),
        collected_at,
        zip_sha256: sha.to_string(),
        source_name: zip_path.file_name().and_then(|name| name.to_str()).unwrap_or("collector").to_string(),
    })
}

fn client_start_from(archive: &mut zip::ZipArchive<std::fs::File>, client_info_name: &str) -> String {
    let Ok(mut entry) = archive.by_name(client_info_name) else { return String::new() };
    let mut body = String::new();
    if std::io::Read::read_to_string(&mut entry, &mut body).is_err() { return String::new() }
    serde_json::from_str::<serde_json::Value>(&body).ok().and_then(|value| value.get("ClientStart").and_then(|item| item.as_str()).map(|s| s.to_string())).unwrap_or_default()
}

fn nested_collector(bytes: &[u8], sha: &str, name: &str) -> Option<(String, Host, Collection)> {
    let cursor = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor).ok()?;
    let mut client = String::new();
    let mut context = String::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).ok()?;
        let entry_name = entry.name().to_string();
        if entry_name.ends_with("client_info.json") {
            std::io::Read::read_to_string(&mut entry, &mut client).ok()?;
        } else if entry_name.ends_with("collection_context.json") {
            std::io::Read::read_to_string(&mut entry, &mut context).ok()?;
        }
    }
    if client.is_empty() { return None }
    let host = host_from_client_info(&client).ok()?;
    let value: serde_json::Value = serde_json::from_str(&context).unwrap_or(serde_json::Value::Null);
    let session_id = value.get("session_id").and_then(|item| item.as_str()).unwrap_or("").to_string();
    let start = serde_json::from_str::<serde_json::Value>(&client).ok().and_then(|item| item.get("ClientStart").and_then(|v| v.as_str()).map(|s| s.to_string())).unwrap_or_default();
    let source_name = name.rsplit('/').next().unwrap_or(name).to_string();
    Some((name.to_string(), host, Collection {
        session_id: if session_id.is_empty() { source_name.clone() } else { session_id },
        host_id: String::new(),
        collected_at: start,
        zip_sha256: sha.to_string(),
        source_name,
    }))
}

impl Host {
    fn clone_host(&self) -> Host {
        Host { host_id: self.host_id.clone(), hostname: self.hostname.clone(), fqdn: self.fqdn.clone(), os: self.os.clone(), arch: self.arch.clone() }
    }
}

pub fn save_analyst(catalog: &Path, name: &str) -> Result<(), rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    conn.execute(
        "INSERT INTO case_info (key, value) VALUES ('analyst', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [name],
    )?;
    Ok(())
}

pub fn record_host(catalog: &Path, host: &Host) -> Result<(), rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    conn.execute(
        "INSERT INTO hosts (host_id, hostname, fqdn, os, arch) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(host_id) DO UPDATE SET hostname = excluded.hostname, fqdn = excluded.fqdn, os = excluded.os, arch = excluded.arch",
        rusqlite::params![host.host_id, host.hostname, host.fqdn, host.os, host.arch],
    )?;
    Ok(())
}

fn is_eventlogs_zip(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".zip") && lower.contains("eventlog")
}

pub struct LogPayload {
    pub name: String,
    pub bytes: Vec<u8>,
}

pub fn eventlog_payloads(zip_path: &Path) -> Result<Vec<LogPayload>, String> {
    let file = std::fs::File::open(zip_path).map_err(|err| err.to_string())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|err| err.to_string())?;
    let mut artifact = Vec::new();
    let mut raw = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|err| err.to_string())?;
        let name = entry.name().to_string();
        if is_eventlogs_zip(&name) && entry.size() < 200_000_000 {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut bytes).map_err(|err| err.to_string())?;
            artifact.push((name, bytes));
        } else if name.to_ascii_lowercase().ends_with(".evtx") && entry.size() < 200_000_000 {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut bytes).map_err(|err| err.to_string())?;
            raw.push(LogPayload { name, bytes });
        }
    }
    let mut logs = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (zip_name, bytes) in artifact {
        let cursor = std::io::Cursor::new(bytes);
        let mut nested = zip::ZipArchive::new(cursor).map_err(|err| err.to_string())?;
        for i in 0..nested.len() {
            let mut entry = nested.by_index(i).map_err(|err| err.to_string())?;
            let entry_name = entry.name().to_string();
            if !entry_name.to_ascii_lowercase().ends_with(".evtx") || entry.size() >= 200_000_000 { continue; }
            let mut body = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut body).map_err(|err| err.to_string())?;
            let sha = sha256_bytes(&body);
            if !seen.insert(sha) { continue; }
            logs.push(LogPayload { name: format!("{zip_name}/{entry_name}"), bytes: body });
        }
    }
    for log in raw {
        let sha = sha256_bytes(&log.bytes);
        if !seen.insert(sha) { continue; }
        logs.push(log);
    }
    Ok(logs)
}

pub fn ingest_for_host(db_path: &Path, source_sha256: &str, host_id: &str, log_name: &str, events: &[Event]) -> Result<usize, duckdb::Error> {
    let inserted = ingest(db_path, source_sha256, events)?;
    if inserted == 0 { return Ok(inserted); }
    let conn = Connection::open(db_path)?;
    conn.execute(
        "UPDATE events SET host_id = ?1, log_name = ?2 WHERE source_sha256 = ?3 AND (host_id IS NULL OR host_id = '')",
        params![host_id, log_name, source_sha256],
    )?;
    Ok(inserted)
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}


pub fn ingest_prefetch(catalog: &Path, db_path: &Path) -> Result<usize, String> {
    let conn = rusqlite::Connection::open(catalog).map_err(|err| err.to_string())?;
    let pairs = conn
        .prepare("SELECT host_id, zip_sha256 FROM collections")
        .map_err(|err| err.to_string())?
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .map_err(|err| err.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    let case_dir = catalog.parent().unwrap_or(Path::new("."));
    let db = duckdb::Connection::open(db_path).map_err(|err| err.to_string())?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS prefetch (
            host_id VARCHAR, pf_name VARCHAR, executable VARCHAR, run_count INTEGER, last_run VARCHAR, version INTEGER, path VARCHAR
        )",
    ).map_err(|err| err.to_string())?;
    let mut inserted = 0;
    for (host_id, sha) in pairs {
        let root = case_dir.join("files").join(&sha);
        if !root.exists() { continue; }
        db.execute("DELETE FROM prefetch WHERE host_id = ?", [host_id.as_str()]).map_err(|err| err.to_string())?;
        for path in prefetch_files(&root) {
            let bytes = std::fs::read(&path).map_err(|err| err.to_string())?;
            let parsed = match prefetch_core::parse(&bytes) {
                Ok(info) => info,
                Err(_) => continue,
            };
            let last = parsed.last_run_times.first().copied().unwrap_or(0);
            let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
            db.execute(
                "INSERT INTO prefetch (host_id, pf_name, executable, run_count, last_run, version, path) VALUES (?, ?, ?, ?, ?, ?, ?)",
                duckdb::params![host_id, name, parsed.executable, parsed.run_count, filetime_iso(last), parsed.version, executable_path(&parsed)],
            ).map_err(|err| err.to_string())?;
            inserted += 1;
        }
    }
    Ok(inserted)
}

fn prefetch_files(root: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = match std::fs::read_dir(&dir) { Ok(entries) => entries, Err(_) => continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() { pending.push(path); continue; }
            if path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext.eq_ignore_ascii_case("pf")) {
                found.push(path);
            }
        }
    }
    found
}

fn executable_path(info: &prefetch_core::PrefetchInfo) -> String {
    let needle = info.executable.to_ascii_lowercase();
    info.filenames.iter().find(|name| name.to_ascii_lowercase().ends_with(&needle)).cloned().unwrap_or_default()
}

fn filetime_iso(filetime: i64) -> String {
    if filetime <= 0 { return String::new(); }
    let secs = (filetime - 116444736000000000) / 10_000_000;
    if secs < 0 { return String::new(); }
    let days = secs.div_euclid(86400);
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    let tod = secs.rem_euclid(86400);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, m, d, tod / 3600, tod % 3600 / 60, tod % 60)
}


pub fn ingest_amcache(catalog: &Path, db_path: &Path) -> Result<usize, String> {
    let conn = rusqlite::Connection::open(catalog).map_err(|err| err.to_string())?;
    let pairs = conn
        .prepare("SELECT host_id, zip_sha256 FROM collections")
        .map_err(|err| err.to_string())?
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .map_err(|err| err.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    let case_dir = catalog.parent().unwrap_or(Path::new("."));
    let db = duckdb::Connection::open(db_path).map_err(|err| err.to_string())?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS amcache (
            host_id VARCHAR, kind VARCHAR, name VARCHAR, path VARCHAR, sha1 VARCHAR,
            size BIGINT, modified VARCHAR, publisher VARCHAR, version VARCHAR, key_path VARCHAR
        )",
    ).map_err(|err| err.to_string())?;
    let mut inserted = 0;
    for (host_id, sha) in pairs {
        let root = case_dir.join("files").join(&sha);
        if !root.exists() { continue; }
        db.execute("DELETE FROM amcache WHERE host_id = ?", [host_id.as_str()]).map_err(|err| err.to_string())?;
        for hive in amcache_hives(&root) {
            inserted += load_amcache_hive(&db, &host_id, &hive)?;
        }
    }
    Ok(inserted)
}

fn amcache_hives(root: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = match std::fs::read_dir(&dir) { Ok(entries) => entries, Err(_) => continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() { pending.push(path); continue; }
            let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("").to_ascii_lowercase();
            if name == "amcache.hve" || name.ends_with("amcache.hve") {
                found.push(path);
            }
        }
    }
    found
}

fn load_amcache_hive(db: &duckdb::Connection, host_id: &str, hive: &Path) -> Result<usize, String> {
    let mut builder = notatin::parser_builder::ParserBuilder::from_path(hive.to_path_buf());
    for suffix in ["LOG1", "LOG2", ".LOG1", ".LOG2"] {
        let log = std::path::PathBuf::from(format!("{}{suffix}", hive.display()));
        if log.exists() {
            builder.with_transaction_log(log);
        }
    }
    let parser = builder.build().map_err(|err| err.to_string())?;
    let mut inserted = 0;
    for key in notatin::parser::ParserIterator::new(&parser) {
        let kind = amcache_kind(&key.path);
        if kind.is_empty() { continue; }
        let values = key_strings(&key);
        if values.is_empty() { continue; }
        let path = first(&values, &["LowerCaseLongPath", "LongPath", "Path"]);
        let name = first(&values, &["Name", "ProductName", "FileName"]);
        if path.is_empty() && name.is_empty() { continue; }
        let sha = amcache_sha(first(&values, &["FileId", "SHA1"]));
        db.execute(
            "INSERT INTO amcache (host_id, kind, name, path, sha1, size, modified, publisher, version, key_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            duckdb::params![
                host_id,
                kind,
                name,
                path,
                sha,
                first(&values, &["Size", "FileSize", "SizeOfImage"]).parse::<i64>().unwrap_or(0),
                first(&values, &["LinkDate", "LastModified", "InstallDate", "Modified"]),
                first(&values, &["Publisher", "CompanyName"]),
                first(&values, &["Version", "BinFileVersion", "FileVersion"]),
                key.path,
            ],
        ).map_err(|err| err.to_string())?;
        inserted += 1;
    }
    Ok(inserted)
}

fn amcache_kind(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    if lower.contains("inventoryapplicationfile") { "file" }
    else if lower.contains("inventoryapplication") { "program" }
    else if lower.contains("inventorydriverbinary") { "driver" }
    else { "" }
}

fn key_strings(key: &notatin::cell_key_node::CellKeyNode) -> Vec<(String, String)> {
    key.value_iter().filter_map(|value| {
        let (content, _) = value.get_content();
        let text = match content {
            notatin::cell_value::CellValue::String(text) => text,
            notatin::cell_value::CellValue::U32(n) => n.to_string(),
            notatin::cell_value::CellValue::I32(n) => n.to_string(),
            notatin::cell_value::CellValue::U64(n) => n.to_string(),
            notatin::cell_value::CellValue::I64(n) => n.to_string(),
            notatin::cell_value::CellValue::MultiString(parts) => parts.join(", "),
            _ => return None,
        };
        Some((value.get_pretty_name(), text))
    }).collect()
}

fn first(values: &[(String, String)], names: &[&str]) -> String {
    for name in names {
        if let Some((_, text)) = values.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)) {
            return text.clone();
        }
    }
    String::new()
}

fn amcache_sha(raw: String) -> String {
    let trimmed = raw.trim().trim_start_matches("0000");
    if trimmed.len() == 40 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        trimmed.to_ascii_lowercase()
    } else {
        raw
    }
}


pub fn ingest_userassist(catalog: &Path, db_path: &Path) -> Result<usize, String> {
    let conn = rusqlite::Connection::open(catalog).map_err(|err| err.to_string())?;
    let pairs = conn
        .prepare("SELECT host_id, zip_sha256 FROM collections")
        .map_err(|err| err.to_string())?
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .map_err(|err| err.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    let case_dir = catalog.parent().unwrap_or(Path::new("."));
    let db = duckdb::Connection::open(db_path).map_err(|err| err.to_string())?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS userassist (
            host_id VARCHAR, guid VARCHAR, name VARCHAR, run_count INTEGER, last_run VARCHAR
        )",
    ).map_err(|err| err.to_string())?;
    let mut inserted = 0;
    for (host_id, sha) in pairs {
        let root = case_dir.join("files").join(&sha);
        if !root.exists() { continue; }
        db.execute("DELETE FROM userassist WHERE host_id = ?", [host_id.as_str()]).map_err(|err| err.to_string())?;
        let hives = ntuser_hives(&root);
        eprintln!("userassist hives={} root={}", hives.len(), root.display());
        for hive in hives {
            inserted += load_userassist(&db, &host_id, &hive)?;
        }
    }
    Ok(inserted)
}

fn ntuser_hives(root: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = match std::fs::read_dir(&dir) { Ok(entries) => entries, Err(_) => continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() { pending.push(path); continue; }
            let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
            if name.eq_ignore_ascii_case("NTUSER.DAT") {
                found.push(path);
            }
        }
    }
    found
}

fn load_userassist(db: &duckdb::Connection, host_id: &str, hive: &Path) -> Result<usize, String> {
    let parser = notatin::parser_builder::ParserBuilder::from_path(hive.to_path_buf())
        .build()
        .map_err(|err| err.to_string())?;
    let mut inserted = 0;
    let mut seen = 0;
    let mut total = 0;
    for key in notatin::parser::ParserIterator::new(&parser) {
        total += 1;
        if total <= 3 { eprintln!("userassist sample {}", key.path); }
        let lower = key.path.to_ascii_lowercase().replace('/', "\\");
        if !lower.contains("userassist") || !lower.contains("count") { continue; }
        seen += 1;
        let guid = key.path.rsplit('\\').nth(1).unwrap_or("").to_string();
        for value in key.value_iter() {
            let (content, _) = value.get_content();
            let (run_count, last_run) = match &content {
                notatin::cell_value::CellValue::Binary(bytes) => userassist_counts(bytes),
                _ => (0, String::new()),
            };
            let name = rot13(&value.get_pretty_name());
            if name.is_empty() { continue; }
            db.execute(
                "INSERT INTO userassist (host_id, guid, name, run_count, last_run) VALUES (?, ?, ?, ?, ?)",
                duckdb::params![host_id, guid, name, run_count, last_run],
            ).map_err(|err| err.to_string())?;
            inserted += 1;
        }
    }
    eprintln!("userassist keys={seen} total={total} hive={}", hive.display());
    Ok(inserted)
}

fn userassist_counts(bytes: &[u8]) -> (i64, String) {
    if bytes.len() < 8 { return (0, String::new()); }
    let run_count = i64::from(u32::from_le_bytes(bytes[4..8].try_into().unwrap_or([0; 4])));
    let last = if bytes.len() >= 68 {
        i64::from_le_bytes(bytes[60..68].try_into().unwrap_or([0; 8]))
    } else if bytes.len() >= 16 {
        i64::from_le_bytes(bytes[8..16].try_into().unwrap_or([0; 8]))
    } else {
        0
    };
    (run_count, filetime_iso(last))
}

fn rot13(text: &str) -> String {
    text.chars().map(|ch| match ch {
        'a'..='z' => char::from(b'a' + (ch as u8 - b'a' + 13) % 26),
        'A'..='Z' => char::from(b'A' + (ch as u8 - b'A' + 13) % 26),
        other => other,
    }).collect()
}


pub fn ingest_shimcache(catalog: &Path, db_path: &Path) -> Result<usize, String> {
    let conn = rusqlite::Connection::open(catalog).map_err(|err| err.to_string())?;
    let pairs = conn
        .prepare("SELECT host_id, zip_sha256 FROM collections")
        .map_err(|err| err.to_string())?
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .map_err(|err| err.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    let case_dir = catalog.parent().unwrap_or(Path::new("."));
    let db = duckdb::Connection::open(db_path).map_err(|err| err.to_string())?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS shimcache (
            host_id VARCHAR, path VARCHAR, modified VARCHAR, position INTEGER, executed VARCHAR, control_set VARCHAR
        )",
    ).map_err(|err| err.to_string())?;
    let mut inserted = 0;
    for (host_id, sha) in pairs {
        let root = case_dir.join("files").join(&sha);
        if !root.exists() { continue; }
        db.execute("DELETE FROM shimcache WHERE host_id = ?", [host_id.as_str()]).map_err(|err| err.to_string())?;
        for path in shimcache_files(&root) {
            inserted += load_shimcache_file(&db, &host_id, &path)?;
        }
    }
    Ok(inserted)
}

fn shimcache_files(root: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = match std::fs::read_dir(&dir) { Ok(entries) => entries, Err(_) => continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() { pending.push(path); continue; }
            let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("").to_ascii_lowercase();
            if name.ends_with(".json") || name.ends_with(".jsonl") || name == "system" || name == "system.hiv" {
                found.push(path);
            }
        }
    }
    found
}

fn load_shimcache_file(db: &duckdb::Connection, host_id: &str, path: &Path) -> Result<usize, String> {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("").to_ascii_lowercase();
    if name == "system" || name == "system.hiv" {
        return load_shimcache_hive(db, host_id, path);
    }
    let body = std::fs::read_to_string(path).map_err(|err| err.to_string())?;
    let mut rows = Vec::new();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(list) = value.as_array() {
            rows.extend(list.iter().cloned());
        } else if value.get("Path").is_some() || value.get("Name").is_some() {
            rows.push(value);
        }
    }
    if rows.is_empty() {
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() { continue; }
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                if value.get("Path").is_some() || value.get("Name").is_some() {
                    rows.push(value);
                }
            }
        }
    }
    let mut inserted = 0;
    for row in rows {
        let path_value = json_text(&row, &["Path", "Name", "path"]);
        if path_value.is_empty() { continue; }
        let modified = json_text(&row, &["ModificationTime", "LastMod", "modified"]);
        let position = row.get("Position").and_then(|item| item.as_i64()).unwrap_or(-1);
        let executed = json_text(&row, &["ExecutionFlag", "Executed", "Execution"]);
        let control = json_text(&row, &["ControlSet", "control_set"]);
        db.execute(
            "INSERT INTO shimcache (host_id, path, modified, position, executed, control_set) VALUES (?, ?, ?, ?, ?, ?)",
            duckdb::params![host_id, path_value, modified, position, executed, control],
        ).map_err(|err| err.to_string())?;
        inserted += 1;
    }
    Ok(inserted)
}

fn json_text(value: &serde_json::Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(item) = value.get(*key) {
            if let Some(text) = item.as_str() {
                if !text.is_empty() { return text.to_string(); }
            } else if !item.is_null() {
                let rendered = item.to_string();
                if rendered != "null" { return rendered.trim_matches('"').to_string(); }
            }
        }
    }
    String::new()
}

fn load_shimcache_hive(db: &duckdb::Connection, host_id: &str, hive: &Path) -> Result<usize, String> {
    let parser = notatin::parser_builder::ParserBuilder::from_path(hive.to_path_buf())
        .build()
        .map_err(|err| err.to_string())?;
    let mut inserted = 0;
    for key in notatin::parser::ParserIterator::new(&parser) {
        if !key.path.to_ascii_lowercase().contains("appcompatcache") { continue; }
        for value in key.value_iter() {
            if !value.get_pretty_name().eq_ignore_ascii_case("appcompatcache") { continue; }
            let (content, _) = value.get_content();
            let notatin::cell_value::CellValue::Binary(bytes) = content else { continue; };
            for row in parse_shimcache_blob(&bytes) {
                db.execute(
                    "INSERT INTO shimcache (host_id, path, modified, position, executed, control_set) VALUES (?, ?, ?, ?, ?, ?)",
                    duckdb::params![host_id, row.0, row.1, row.2, row.3, ""],
                ).map_err(|err| err.to_string())?;
                inserted += 1;
            }
        }
    }
    Ok(inserted)
}

fn parse_shimcache_blob(bytes: &[u8]) -> Vec<(String, String, i64, String)> {
    let mut rows = Vec::new();
    let mut index = 0;
    let mut position = 0i64;
    while index + 14 < bytes.len() {
        if &bytes[index..index + 4] != b"10ts" {
            index += 1;
            continue;
        }
        if index + 14 > bytes.len() { break; }
        let entry_len = u32::from_le_bytes(bytes[index + 8..index + 12].try_into().unwrap()) as usize;
        let path_len = u16::from_le_bytes(bytes[index + 12..index + 14].try_into().unwrap()) as usize;
        let path_at = index + 14;
        if entry_len < 14 || path_at + path_len + 8 > bytes.len() || path_len == 0 || path_len > 1024 {
            index += 4;
            continue;
        }
        let path = String::from_utf16_lossy(
            &bytes[path_at..path_at + path_len]
                .chunks(2)
                .filter_map(|pair| if pair.len() == 2 { Some(u16::from_le_bytes([pair[0], pair[1]])) } else { None })
                .collect::<Vec<_>>(),
        ).trim_end_matches('\u{0}').to_string();
        if !path.contains('\\') && !path.contains('/') {
            index += 4;
            continue;
        }
        let time_at = path_at + path_len;
        let filetime = i64::from_le_bytes(bytes[time_at..time_at + 8].try_into().unwrap());
        let data_at = time_at + 8;
        let mut executed = String::new();
        if data_at + 2 <= bytes.len() {
            let data_len = u16::from_le_bytes(bytes[data_at..data_at + 2].try_into().unwrap()) as usize;
            if data_len >= 4 && data_at + 2 + data_len <= bytes.len() {
                let data = &bytes[data_at + 2..data_at + 2 + data_len];
                let flag = u32::from_le_bytes(data[data.len() - 4..].try_into().unwrap());
                executed = if flag == 1 { "yes".into() } else { "no".into() };
            }
        }
        rows.push((path, filetime_iso(filetime), position, executed));
        position += 1;
        index += if entry_len > 4 { entry_len } else { 4 };
    }
    rows
}


pub fn ingest_srum(catalog: &Path, db_path: &Path) -> Result<usize, String> {
    let conn = rusqlite::Connection::open(catalog).map_err(|err| err.to_string())?;
    let pairs = conn
        .prepare("SELECT host_id, zip_sha256 FROM collections")
        .map_err(|err| err.to_string())?
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .map_err(|err| err.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    let case_dir = catalog.parent().unwrap_or(Path::new("."));
    let db = duckdb::Connection::open(db_path).map_err(|err| err.to_string())?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS srum (
            host_id VARCHAR, kind VARCHAR, timestamp VARCHAR, app VARCHAR, user_sid VARCHAR,
            bytes_sent BIGINT, bytes_received BIGINT, foreground_cycles BIGINT, background_cycles BIGINT
        )",
    ).map_err(|err| err.to_string())?;
    let mut inserted = 0;
    for (host_id, sha) in pairs {
        let root = case_dir.join("files").join(&sha);
        if !root.exists() { continue; }
        db.execute("DELETE FROM srum WHERE host_id = ?", [host_id.as_str()]).map_err(|err| err.to_string())?;
        let files = srum_files(&root);
        let total = files.len().max(1);
        for (index, path) in files.iter().enumerate() {
            report_progress((76 + (index * 24 / total)) as u8, &format!("Writing SRUM {}/{}", index + 1, files.len()));
            inserted += load_srum_file(&db, &host_id, path)?;
        }
    }
    Ok(inserted)
}

fn srum_files(root: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = match std::fs::read_dir(&dir) { Ok(entries) => entries, Err(_) => continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() { pending.push(path); continue; }
            let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("").to_ascii_lowercase();
            if name == "srudb.dat" || name.ends_with(".json") || name.ends_with(".jsonl") {
                found.push(path);
            }
        }
    }
    found
}

fn load_srum_file(db: &duckdb::Connection, host_id: &str, path: &Path) -> Result<usize, String> {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("").to_ascii_lowercase();
    if name == "srudb.dat" {
        return load_srudb(db, host_id, path);
    }
    let body = match std::fs::read_to_string(path) {
        Ok(body) => body,
        Err(_) => return Ok(0),
    };
    if !body.to_ascii_lowercase().contains("bytessent") && !body.to_ascii_lowercase().contains("foregroundcycletime") && !body.to_ascii_lowercase().contains("bytesrecvd") {
        return Ok(0);
    }
    let mut rows = Vec::new();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(list) = value.as_array() {
            rows.extend(list.iter().cloned());
        } else if value.get("App").is_some() || value.get("BytesSent").is_some() {
            rows.push(value);
        }
    }
    if rows.is_empty() {
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() { continue; }
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                rows.push(value);
            }
        }
    }
    let file = path.file_name().and_then(|name| name.to_str()).unwrap_or("srum");
    let total = rows.len().max(1);
    db.execute_batch("BEGIN").map_err(|err| err.to_string())?;
    let mut inserted = 0;
    for (index, row) in rows.iter().enumerate() {
        let app = json_text(row, &["App", "Application", "Exe", "app"]);
        let sent = json_i64(row, &["BytesSent", "bytes_sent"]);
        let received = json_i64(row, &["BytesRecvd", "BytesReceived", "bytes_received"]);
        if app.is_empty() && sent == 0 && received == 0 && json_text(row, &["TimeStamp", "Timestamp"]).is_empty() {
            continue;
        }
        let kind = if sent > 0 || received > 0 { "network" } else { "app" };
        db.execute(
            "INSERT INTO srum (host_id, kind, timestamp, app, user_sid, bytes_sent, bytes_received, foreground_cycles, background_cycles) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            duckdb::params![
                host_id,
                kind,
                json_text(row, &["TimeStamp", "Timestamp", "timestamp"]),
                app,
                json_text(row, &["UserSid", "User", "user_sid"]),
                sent,
                received,
                json_i64(row, &["ForegroundCycleTime", "foreground_cycles"]),
                json_i64(row, &["BackgroundCycleTime", "background_cycles"]),
            ],
        ).map_err(|err| err.to_string())?;
        inserted += 1;
        if inserted % 2000 == 0 {
            report_progress((76 + (index * 24 / total)) as u8, &format!("Writing SRUM {file} {inserted}/{}", rows.len()));
        }
    }
    db.execute_batch("COMMIT").map_err(|err| err.to_string())?;
    report_progress(99, &format!("Writing SRUM {file} {inserted}/{}", rows.len()));
    Ok(inserted)
}

fn json_i64(value: &serde_json::Value, keys: &[&str]) -> i64 {
    for key in keys {
        if let Some(item) = value.get(*key) {
            if let Some(n) = item.as_i64() { return n; }
            if let Some(n) = item.as_u64() { return n as i64; }
            if let Some(text) = item.as_str() {
                if let Ok(n) = text.parse::<i64>() { return n; }
            }
        }
    }
    0
}

fn load_srudb(db: &duckdb::Connection, host_id: &str, path: &Path) -> Result<usize, String> {
    let names = match srum_parser::parse_id_map(path) {
        Ok(rows) => rows.into_iter().map(|row| (row.id, row.name)).collect::<std::collections::HashMap<_, _>>(),
        Err(err) => {
            eprintln!("srum id map {}: {err}", path.display());
            std::collections::HashMap::new()
        }
    };
    let file = path.file_name().and_then(|name| name.to_str()).unwrap_or("SRUDB.dat");
    let mut inserted = 0;
    db.execute_batch("BEGIN").map_err(|err| err.to_string())?;
    match srum_parser::parse_network_usage(path) {
        Ok(rows) => {
            let total = rows.len().max(1);
            for (index, row) in rows.iter().enumerate() {
                let app = names.get(&row.app_id).cloned().unwrap_or_else(|| row.app_id.to_string());
                db.execute(
                    "INSERT INTO srum (host_id, kind, timestamp, app, user_sid, bytes_sent, bytes_received, foreground_cycles, background_cycles) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    duckdb::params![host_id, "network", row.timestamp.to_string(), app, row.user_id.to_string(), row.bytes_sent as i64, row.bytes_recv as i64, 0i64, 0i64],
                ).map_err(|err| err.to_string())?;
                inserted += 1;
                if inserted % 2000 == 0 {
                    report_progress((76 + (index * 12 / total)) as u8, &format!("Writing SRUM {file} network {inserted}/{}", rows.len()));
                }
            }
        }
        Err(err) => eprintln!("srum network {}: {err}", path.display()),
    }
    match srum_parser::parse_app_usage(path) {
        Ok(rows) => {
            let total = rows.len().max(1);
            for (index, row) in rows.iter().enumerate() {
                let app = names.get(&row.app_id).cloned().unwrap_or_else(|| row.app_id.to_string());
                db.execute(
                    "INSERT INTO srum (host_id, kind, timestamp, app, user_sid, bytes_sent, bytes_received, foreground_cycles, background_cycles) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    duckdb::params![host_id, "app", row.timestamp.to_string(), app, row.user_id.to_string(), 0i64, 0i64, row.foreground_cycles as i64, row.background_cycles as i64],
                ).map_err(|err| err.to_string())?;
                inserted += 1;
                if inserted % 2000 == 0 {
                    report_progress((88 + (index * 11 / total)) as u8, &format!("Writing SRUM {file} app {inserted}"));
                }
            }
        }
        Err(err) => eprintln!("srum app {}: {err}", path.display()),
    }
    db.execute_batch("COMMIT").map_err(|err| err.to_string())?;
    report_progress(99, &format!("Writing SRUM {file} {inserted} rows"));
    Ok(inserted)
}



pub fn ingest_services(catalog: &Path, db_path: &Path) -> Result<usize, String> {
    let conn = rusqlite::Connection::open(catalog).map_err(|err| err.to_string())?;
    let pairs = conn
        .prepare("SELECT host_id, zip_sha256 FROM collections")
        .map_err(|err| err.to_string())?
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .map_err(|err| err.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    let case_dir = catalog.parent().unwrap_or(Path::new("."));
    let db = duckdb::Connection::open(db_path).map_err(|err| err.to_string())?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS services (
            host_id VARCHAR, name VARCHAR, display_name VARCHAR, state VARCHAR, start_mode VARCHAR, path VARCHAR, user_id VARCHAR
        )",
    ).map_err(|err| err.to_string())?;
    let mut inserted = 0;
    for (host_id, sha) in pairs {
        let root = case_dir.join("files").join(&sha);
        if !root.exists() { continue; }
        db.execute("DELETE FROM services WHERE host_id = ?", [host_id.as_str()]).map_err(|err| err.to_string())?;
        let files = service_files(&root);
        let total = files.len().max(1);
        for (index, path) in files.iter().enumerate() {
            report_progress((40 + (index * 12 / total)) as u8, &format!("Writing services {}/{}", index + 1, files.len()));
            inserted += load_service_file(&db, &host_id, path)?;
        }
    }
    Ok(inserted)
}

fn service_files(root: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = match std::fs::read_dir(&dir) { Ok(entries) => entries, Err(_) => continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() { pending.push(path); continue; }
            if path.to_string_lossy().to_ascii_lowercase().contains("service") {
                found.push(path);
            }
        }
    }
    found
}

fn load_service_file(db: &duckdb::Connection, host_id: &str, path: &Path) -> Result<usize, String> {
    let bytes = match std::fs::read(path) { Ok(bytes) => bytes, Err(_) => return Ok(0) };
    let body = decode_text(&bytes);
    let mut rows = Vec::new();
    for line in body.lines() {
        let line = line.trim().trim_start_matches('\u{feff}');
        if line.is_empty() { continue; }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            collect_service_rows(&value, &mut rows);
        }
    }
    if rows.is_empty() {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) {
            collect_service_rows(&value, &mut rows);
        }
    }
    let mut inserted = 0;
    for row in rows {
        let name = json_text(&row, &["Name", "ServiceName", "name"]);
        let path_name = json_text(&row, &["PathName", "ImagePath", "ServiceDll", "path"]);
        if name.is_empty() && path_name.is_empty() { continue; }
        db.execute(
            "INSERT INTO services (host_id, name, display_name, state, start_mode, path, user_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
            duckdb::params![
                host_id,
                name,
                json_text(&row, &["DisplayName", "display_name"]),
                json_text(&row, &["State", "Status", "state"]),
                json_text(&row, &["StartMode", "Start", "start_mode"]),
                path_name,
                json_text(&row, &["UserName", "StartName", "Account", "user_id"]),
            ],
        ).map_err(|err| err.to_string())?;
        inserted += 1;
    }
    Ok(inserted)
}

fn collect_service_rows(value: &serde_json::Value, rows: &mut Vec<serde_json::Value>) {
    match value {
        serde_json::Value::Array(list) => { for item in list { collect_service_rows(item, rows); } }
        serde_json::Value::Object(map) => {
            if map.contains_key("Name") || map.contains_key("ServiceName") || map.contains_key("PathName") || map.contains_key("ImagePath") {
                rows.push(value.clone());
            }
            for item in map.values() { collect_service_rows(item, rows); }
        }
        _ => {}
    }
}

pub fn ingest_tasks(catalog: &Path, db_path: &Path) -> Result<usize, String> {
    let conn = rusqlite::Connection::open(catalog).map_err(|err| err.to_string())?;
    let pairs = conn
        .prepare("SELECT host_id, zip_sha256 FROM collections")
        .map_err(|err| err.to_string())?
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .map_err(|err| err.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    let case_dir = catalog.parent().unwrap_or(Path::new("."));
    let db = duckdb::Connection::open(db_path).map_err(|err| err.to_string())?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS tasks (
            host_id VARCHAR, path VARCHAR, command VARCHAR, arguments VARCHAR, user_id VARCHAR, enabled VARCHAR
        )",
    ).map_err(|err| err.to_string())?;
    let mut inserted = 0;
    for (host_id, sha) in pairs {
        let root = case_dir.join("files").join(&sha);
        if !root.exists() { continue; }
        db.execute("DELETE FROM tasks WHERE host_id = ?", [host_id.as_str()]).map_err(|err| err.to_string())?;
        let files = task_files(&root);
        let total = files.len().max(1);
        for (index, path) in files.iter().enumerate() {
            report_progress((52 + (index * 12 / total)) as u8, &format!("Writing tasks {}/{}", index + 1, files.len()));
            inserted += load_task_file(&db, &host_id, path)?;
        }
    }
    Ok(inserted)
}

fn task_files(root: &Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = match std::fs::read_dir(&dir) { Ok(entries) => entries, Err(_) => continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() { pending.push(path); continue; }
            let text = path.to_string_lossy().to_ascii_lowercase();
            if text.contains("task") || text.ends_with(".xml") {
                found.push(path);
            }
        }
    }
    found
}

fn load_task_file(db: &duckdb::Connection, host_id: &str, path: &Path) -> Result<usize, String> {
    let bytes = match std::fs::read(path) { Ok(bytes) => bytes, Err(_) => return Ok(0) };
    let body = decode_text(&bytes);
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return load_task_json(db, host_id, &body);
    }
    let lower = body.to_ascii_lowercase();
    if !lower.contains(r"<command") && !lower.contains(r"<task") && !lower.contains(r"<comhandler") {
        return Ok(0);
    }
    let command = {
        let command = xml_tag(&body, "Command");
        if !command.is_empty() { command } else { xml_tag(&body, "ClassId") }
    };
    let arguments = xml_tag(&body, "Arguments");
    db.execute(
        "INSERT INTO tasks (host_id, path, command, arguments, user_id, enabled) VALUES (?, ?, ?, ?, ?, ?)",
        duckdb::params![host_id, path.display().to_string(), command, arguments, xml_tag(&body, "UserId"), xml_tag(&body, "Enabled")],
    ).map_err(|err| err.to_string())?;
    Ok(1)
}

fn decode_text(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe {
        let units: Vec<u16> = bytes[2..].chunks(2).map(|pair| u16::from_le_bytes([pair[0], *pair.get(1).unwrap_or(&0)])).collect();
        return String::from_utf16_lossy(&units);
    }
    String::from_utf8_lossy(bytes).to_string()
}

fn xml_tag(body: &str, tag: &str) -> String {
    let open = format!("<{tag}");
    let Some(start) = body.to_ascii_lowercase().find(&open.to_ascii_lowercase()) else { return String::new() };
    let Some(gt) = body[start..].find('>') else { return String::new() };
    let from = start + gt + 1;
    let close = format!("</{tag}>");
    let Some(end) = body[from..].to_ascii_lowercase().find(&close.to_ascii_lowercase()) else { return String::new() };
    body[from..from + end].trim().to_string()
}

fn load_task_json(db: &duckdb::Connection, host_id: &str, body: &str) -> Result<usize, String> {
    let mut rows = Vec::new();
    for line in body.lines() {
        let line = line.trim().trim_start_matches('\u{feff}');
        if line.is_empty() { continue; }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            collect_task_rows(&value, &mut rows);
        }
    }
    if rows.is_empty() {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
            collect_task_rows(&value, &mut rows);
        }
    }
    let mut inserted = 0;
    for row in rows {
        let mut command = json_text(&row, &["Command", "command", "ComHandler"]);
        let mut arguments = json_text(&row, &["Arguments", "arguments"]);
        if let Some(exec) = row.get("Actions").and_then(|item| item.get("Exec")).or_else(|| row.get("Exec")) {
            if command.is_empty() { command = json_text(exec, &["Command", "command"]); }
            if arguments.is_empty() { arguments = json_text(exec, &["Arguments", "arguments"]); }
        }
        let path = json_text(&row, &["FullPath", "TaskName", "Path", "OSPath", "Name"]);
        if command.is_empty() && path.is_empty() { continue; }
        db.execute(
            "INSERT INTO tasks (host_id, path, command, arguments, user_id, enabled) VALUES (?, ?, ?, ?, ?, ?)",
            duckdb::params![host_id, path, command, arguments, json_text(&row, &["UserId", "Principal", "user_id"]), json_text(&row, &["Enabled", "enabled"])],
        ).map_err(|err| err.to_string())?;
        inserted += 1;
    }
    Ok(inserted)
}

fn collect_task_rows(value: &serde_json::Value, rows: &mut Vec<serde_json::Value>) {
    match value {
        serde_json::Value::Array(list) => { for item in list { collect_task_rows(item, rows); } }
        serde_json::Value::Object(map) => {
            if map.contains_key("Command") || map.contains_key("FullPath") || map.contains_key("OSPath") || map.contains_key("TaskName") || map.contains_key("Actions") {
                rows.push(value.clone());
            }
            for item in map.values() { collect_task_rows(item, rows); }
        }
        _ => {}
    }
}

pub struct Ioc {
    pub id: i64,
    pub kind: String,
    pub value: String,
    pub note: String,
    pub added_at: String,
}

pub fn add_ioc(catalog: &Path, kind: &str, value: &str, note: &str) -> Result<i64, rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    let added_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default();
    conn.execute(
        "INSERT INTO iocs (kind, value, note, added_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(kind, value) DO UPDATE SET note = excluded.note",
        rusqlite::params![kind, value, note, added_at],
    )?;
    let id: i64 = conn.query_row(
        "SELECT id FROM iocs WHERE kind = ?1 AND value = ?2",
        rusqlite::params![kind, value],
        |row| row.get(0),
    )?;
    Ok(id)
}

pub fn iocs(catalog: &Path) -> Result<Vec<Ioc>, rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    let mut stmt = conn.prepare("SELECT id, kind, value, note, added_at FROM iocs ORDER BY kind, value")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(Ioc {
            id: row.get(0)?,
            kind: row.get(1)?,
            value: row.get(2)?,
            note: row.get(3)?,
            added_at: row.get(4)?,
        });
    }
    Ok(out)
}

pub fn remove_ioc(catalog: &Path, id: i64) -> Result<(), rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    conn.execute("DELETE FROM iocs WHERE id = ?1", [id])?;
    Ok(())
}

pub fn update_ioc(catalog: &Path, id: i64, kind: &str, value: &str, note: &str) -> Result<(), rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    conn.execute(
        "UPDATE iocs SET kind = ?1, value = ?2, note = ?3 WHERE id = ?4",
        rusqlite::params![kind, value, note, id],
    )?;
    Ok(())
}

pub struct HuntMatch {
    pub source: String,
    pub host_id: String,
    pub column: String,
    pub value: String,
    pub ioc_kind: String,
    pub ioc_value: String,
    pub context: String,
}

pub fn hunt_iocs(catalog: &Path, db_path: &Path) -> Result<Vec<HuntMatch>, String> {
    let indicators = iocs(catalog).map_err(|err| err.to_string())?;
    if indicators.is_empty() {
        return Ok(Vec::new());
    }
    let db = duckdb::Connection::open(db_path).map_err(|err| err.to_string())?;
    let scans: &[(&str, &str, &str, &str)] = &[
        ("events", "SELECT computer, event_id, event_data FROM events", "event_data", "computer"),
        ("prefetch", "SELECT host_id, executable, path FROM prefetch", "executable", "host_id"),
        ("userassist", "SELECT host_id, name FROM userassist", "name", "host_id"),
        ("amcache", "SELECT host_id, name, path, sha1 FROM amcache", "name", "host_id"),
        ("shimcache", "SELECT host_id, path FROM shimcache", "path", "host_id"),
        ("services", "SELECT host_id, name, path FROM services", "name", "host_id"),
        ("tasks", "SELECT host_id, path, command FROM tasks", "path", "host_id"),
        ("srum", "SELECT host_id, app FROM srum", "app", "host_id"),
    ];
    let mut matches = Vec::new();
    for (index, (source, sql, column, _host_col)) in scans.iter().enumerate() {
        let pct = ((index as f64 + 1.0) / scans.len() as f64 * 100.0) as u8;
        report_progress(pct, &format!("Scanning {source}"));
        let mut stmt = match db.prepare(sql) {
            Ok(stmt) => stmt,
            Err(_) => continue,
        };
        let mut rows = match stmt.query([]) {
            Ok(rows) => rows,
            Err(_) => continue,
        };
        while let Ok(Some(row)) = rows.next() {
            let host: String = row.get(0).unwrap_or_default();
            let text = (0..row.as_ref().column_count())
                .map(|i| row.get::<_, String>(i).unwrap_or_default())
                .collect::<Vec<_>>()
                .join(" ");
            let lower = text.to_lowercase();
            for ioc in &indicators {
                if ioc.value.is_empty() { continue; }
                if lower.contains(&ioc.value.to_lowercase()) {
                    matches.push(HuntMatch {
                        source: source.to_string(),
                        host_id: host.clone(),
                        column: column.to_string(),
                        value: row.get::<_, String>(1).unwrap_or_default(),
                        ioc_kind: ioc.kind.clone(),
                        ioc_value: ioc.value.clone(),
                        context: text.chars().take(180).collect(),
                    });
                    break;
                }
            }
        }
    }
    report_progress(100, "Hunt complete");
    Ok(matches)
}
