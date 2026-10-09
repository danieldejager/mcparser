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
    let lower = name.rsplit('/').next().unwrap_or(name).to_ascii_lowercase();
    lower == "ntuser.dat" || lower == "software.hiv" || lower.ends_with(".pf")
}

fn safe_name(name: &str) -> String {
    name.split(['/', '\\']).filter(|part| !part.is_empty() && *part != "." && *part != "..").collect::<Vec<_>>().join("/")
}

fn write_kept(case_dir: &Path, sha: &str, name: &str, bytes: &[u8]) -> Result<std::path::PathBuf, String> {
    let relative = safe_name(name);
    if relative.is_empty() { return Err("empty archive name".into()); }
    let path = case_dir.join("files").join(sha).join(&relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    std::fs::write(&path, bytes).map_err(|err| err.to_string())?;
    Ok(path)
}

pub fn import_collector(catalog: &Path, zip_path: &Path) -> Result<(Vec<Host>, Vec<Collection>, Vec<std::path::PathBuf>), String> {
    let sha = file_sha256(zip_path).map_err(|err| err.to_string())?;
    let file = std::fs::File::open(zip_path).map_err(|err| err.to_string())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|err| err.to_string())?;
    let mut client_info_names = Vec::new();
    let mut nested_zips = Vec::new();
    let mut raw_files = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|err| err.to_string())?;
        let name = entry.name().to_string();
        if name.ends_with("client_info.json") {
            client_info_names.push(name);
        } else if name.ends_with(".zip") && entry.size() < 80_000_000 {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut bytes).map_err(|err| err.to_string())?;
            nested_zips.push((name, bytes));
        } else if keep_raw(&name) && entry.size() < 80_000_000 {
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
    for (name, bytes) in &nested_zips {
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
    for (name, bytes) in raw_files {
        kept.push(write_kept(case_dir, &sha, &name, &bytes)?);
    }
    for (name, bytes) in &nested_zips {
        let cursor = std::io::Cursor::new(bytes);
        let mut nested = zip::ZipArchive::new(cursor).map_err(|err| err.to_string())?;
        for i in 0..nested.len() {
            let mut entry = nested.by_index(i).map_err(|err| err.to_string())?;
            let entry_name = entry.name().to_string();
            if !keep_raw(&entry_name) || entry.size() >= 80_000_000 { continue; }
            let mut body = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut body).map_err(|err| err.to_string())?;
            kept.push(write_kept(case_dir, &sha, &format!("{name}/{entry_name}"), &body)?);
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
    for key in notatin::parser::ParserIterator::new(&parser) {
        let lower = key.path.to_ascii_lowercase().replace('/', "\\");
        if !lower.contains("userassist") || !lower.contains("count") { continue; }
        seen += 1;
        let guid = key.path.rsplit('\\').nth(1).unwrap_or("").to_string();
        for value in key.value_iter() {
            let (content, _) = value.get_content();
            let notatin::cell_value::CellValue::Binary(bytes) = content else { continue; };
            let (run_count, last_run) = userassist_counts(&bytes);
            let name = rot13(&value.get_pretty_name());
            if name.is_empty() || name.starts_with("UEME_") { continue; }
            db.execute(
                "INSERT INTO userassist (host_id, guid, name, run_count, last_run) VALUES (?, ?, ?, ?, ?)",
                duckdb::params![host_id, guid, name, run_count, last_run],
            ).map_err(|err| err.to_string())?;
            inserted += 1;
        }
    }
    eprintln!("userassist keys={seen} hive={}", hive.display());
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
