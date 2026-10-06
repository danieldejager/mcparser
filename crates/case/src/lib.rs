pub struct SavedQuery {
    pub name: String,
    pub sql: String,
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
