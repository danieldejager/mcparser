use duckdb::{Connection, params};
use model::Event;
use std::path::Path;
use sha2::{Digest, Sha256};

pub fn name() -> &'static str {
    env!("CARGO_PKG_NAME")
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
            time_created VARCHAR
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
    let conn = Connection::open(db_path)?;
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let column_count = row.as_ref().column_count();
        let mut cols = Vec::with_capacity(column_count);
        for i in 0..column_count {
            cols.push(cell(row, i));
        }
        out.push(cols);
    }
    Ok(out)
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
        )",
    )?;
    Ok(conn)
}