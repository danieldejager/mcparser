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
            event_data VARCHAR
        )",
    )?;
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

pub fn import_collector(catalog: &Path, zip_path: &Path) -> Result<(Host, Vec<Collection>), String> {
    let sha = file_sha256(zip_path).map_err(|err| err.to_string())?;
    let file = std::fs::File::open(zip_path).map_err(|err| err.to_string())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|err| err.to_string())?;
    let mut client_info_names = Vec::new();
    let mut nested_zips = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|err| err.to_string())?;
        let name = entry.name().to_string();
        if name.ends_with("client_info.json") {
            client_info_names.push(name);
        } else if name.ends_with(".zip") && entry.size() < 80_000_000 {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut bytes).map_err(|err| err.to_string())?;
            nested_zips.push((name, bytes));
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
    for (name, bytes) in nested_zips {
        if let Some(hit) = nested_collector(&bytes, &sha, &name) {
            found.push(hit);
        }
    }
    let Some((_, host, _)) = found.first() else {
        return Err("no client_info.json in collector zip".into());
    };
    let host = host.clone_host();
    let mut saved = Vec::new();
    let conn = open_catalog(catalog).map_err(|err| err.to_string())?;
    conn.execute(
        "INSERT INTO hosts (host_id, hostname, fqdn, os, arch) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(host_id) DO UPDATE SET hostname = excluded.hostname, fqdn = excluded.fqdn, os = excluded.os, arch = excluded.arch",
        rusqlite::params![host.host_id, host.hostname, host.fqdn, host.os, host.arch],
    ).map_err(|err| err.to_string())?;
    for (_, _, collection) in &found {
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
    Ok((host, saved))
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
