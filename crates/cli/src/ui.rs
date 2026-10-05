use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;

const PAGE: &str = r#"<!doctype html>
<meta charset="utf-8">
<title>McParser</title>
<style>
body { font: 15px/1.4 ui-sans-serif, system-ui, sans-serif; margin: 2rem; max-width: 60rem; }
textarea { width: 100%; height: 6rem; font: 14px ui-monospace, monospace; }
pre { background: #f4f4f4; padding: 1rem; overflow: auto; }
button { margin-right: 0.5rem; }
</style>
<h1>McParser</h1>
<p id="case"></p>
<button id="stats">Stats</button>
<h2>Query</h2>
<textarea id="sql">SELECT event_id, count(*) FROM events GROUP BY event_id ORDER BY count(*) DESC LIMIT 20</textarea>
<p><button id="run">Run</button></p>
<pre id="out">Loading stats…</pre>
<script>
const out = document.getElementById('out');
async function loadStats() {
  const res = await fetch('/stats');
  out.textContent = await res.text();
}
document.getElementById('stats').onclick = loadStats;
document.getElementById('run').onclick = async () => {
  const res = await fetch('/query', { method: 'POST', body: document.getElementById('sql').value });
  out.textContent = await res.text();
};
loadStats();
</script>
"#;

pub fn serve(case_dir: &Path) -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8787")?;
    eprintln!("McParser UI at http://127.0.0.1:8787");
    eprintln!("case {}", case_dir.display());
    for mut stream in listener.incoming().flatten() {
        let mut buf = [0u8; 8192];
        let n = stream.read(&mut buf).unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]);
        let (status, content_type, body) = route(&req, case_dir);
        let header = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(body.as_bytes());
    }
    Ok(())
}

fn route(req: &str, case_dir: &Path) -> (&'static str, &'static str, String) {
    let line = req.lines().next().unwrap_or("");
    if line.starts_with("GET /stats") {
        return ("200 OK", "text/plain; charset=utf-8", stats(case_dir));
    }
    if line.starts_with("POST /query") {
        let sql = req.split("\r\n\r\n").nth(1).unwrap_or("").trim();
        return ("200 OK", "text/plain; charset=utf-8", query(case_dir, sql));
    }
    if line.starts_with("GET / ") || line.starts_with("GET /HTTP") {
        return ("200 OK", "text/html; charset=utf-8", PAGE.to_string());
    }
    ("404 Not Found", "text/plain; charset=utf-8", "not found".to_string())
}

fn stats(case_dir: &Path) -> String {
    let db = case_dir.join("events.duckdb");
    let sections = [
        ("time range", "SELECT min(time_created), max(time_created), count(*) FROM events"),
        ("channels", "SELECT channel, count(*) FROM events GROUP BY channel ORDER BY count(*) DESC"),
        ("providers", "SELECT provider, count(*) FROM events GROUP BY provider ORDER BY count(*) DESC"),
        ("event ids", "SELECT event_id, count(*) FROM events GROUP BY event_id ORDER BY count(*) DESC LIMIT 20"),
    ];
    let mut out = String::new();
    for (title, sql) in sections {
        out.push_str("# ");
        out.push_str(title);
        out.push('\n');
        out.push_str(&table(&db, sql));
        out.push('\n');
    }
    out
}

fn query(case_dir: &Path, sql: &str) -> String {
    if sql.is_empty() {
        return "empty query".to_string();
    }
    table(&case_dir.join("events.duckdb"), sql)
}

fn table(db: &Path, sql: &str) -> String {
    match case::query(db, sql) {
        Ok(rows) => rows
            .iter()
            .map(|row| row.join("\t"))
            .collect::<Vec<_>>()
            .join("\n"),
        Err(err) => err.to_string(),
    }
}
