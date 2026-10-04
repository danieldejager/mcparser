pub fn source_sha_for_path(catalog: &Path, source: &Path) -> Result<Option<String>, rusqlite::Error> {
    let conn = open_catalog(catalog)?;
    let mut stmt = conn.prepare("SELECT sha256 FROM sources WHERE source_path = ?1")?;
    let mut rows = stmt.query([source.display().to_string()])?;
    match rows.next()? {
        Some(row) => Ok(Some(row.get(0)?)),
        None => Ok(None),
    }
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