use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("ingest") => ingest(&mut args),
        Some("query") => query(&mut args),
        Some("stats") => stats(&mut args),
        Some("queries") => queries(&mut args),
        Some("save-query") => save_query(&mut args),
        Some("notes") => notes(&mut args),
        Some("save-note") => save_note(&mut args),
        Some("runs") => runs(&mut args),
        Some("save-run") => save_run(&mut args),
        _ => {
            eprintln!("usage: mcparser ingest --case <dir> <file.evtx> [more.evtx...]");
            eprintln!("       mcparser query --case <dir> [--format table|csv|jsonl] \"<sql>\"");
            eprintln!("       mcparser stats --case <dir>");
            eprintln!("       mcparser queries --case <dir>");
            eprintln!("       mcparser save-query --case <dir> --name <name> \"<sql>\"");
            eprintln!("       mcparser notes --case <dir>");
            eprintln!("       mcparser save-note --case <dir> --record <id> \"<sentence>\"");
            eprintln!("       mcparser runs --case <dir>");
            eprintln!("       mcparser save-run --case <dir> --rows <n> \"<sql>\"");
            ExitCode::from(2)
        }
    }
}

fn ingest(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser ingest --case <dir> <file.evtx> [more.evtx...]");
        return ExitCode::from(2);
    };
    let paths: Vec<String> = args.collect();
    if paths.is_empty() {
        eprintln!("usage: mcparser ingest --case <dir> <file.evtx> [more.evtx...]");
        return ExitCode::from(2);
    }
    if let Err(err) = std::fs::create_dir_all(&case_dir) {
        eprintln!("{err}");
        return ExitCode::from(1);
    }

    let catalog = case_dir.join("catalog.sqlite");
    let db = case_dir.join("events.duckdb");
    for path in &paths {
        let sha256 = match case::file_sha256(path.as_ref()) {
            Ok(sha256) => sha256,
            Err(err) => {
                eprintln!("{path}: {err}");
                return ExitCode::from(1);
            }
        };
        match case::source_sha_for_path(&catalog, path.as_ref()) {
            Ok(Some(old)) if old == sha256 => {
                println!("skipped {path} sha256={sha256}");
                continue;
            }
            Ok(Some(old)) => {
                if let Err(err) = case::delete_events_for_source(&db, &old) {
                    eprintln!("{err}");
                    return ExitCode::from(1);
                }
                if let Err(err) = case::remove_source(&catalog, &old) {
                    eprintln!("{err}");
                    return ExitCode::from(1);
                }
                println!("replaced {path} old={old}");
            }
            Ok(None) => {}
            Err(err) => {
                eprintln!("{err}");
                return ExitCode::from(1);
            }
        }
        match case::already_ingested(&catalog, &sha256) {
            Ok(true) => {
                println!("skipped {path} sha256={sha256}");
                continue;
            }
            Ok(false) => {}
            Err(err) => {
                eprintln!("{err}");
                return ExitCode::from(1);
            }
        }

        let records = match evtx_read::records_json(path.as_ref()) {
            Ok(records) => records,
            Err(err) => {
                eprintln!("{path}: {err}");
                return ExitCode::from(1);
            }
        };
        let mut events = Vec::new();
        for json in &records {
            match model::from_json(json) {
                Ok(event) => events.push(event),
                Err(err) => {
                    eprintln!("{path}: {err}");
                    return ExitCode::from(1);
                }
            }
        }
        let inserted = match case::ingest(&db, &sha256, &events) {
            Ok(inserted) => inserted,
            Err(err) => {
                eprintln!("{err}");
                return ExitCode::from(1);
            }
        };
        if let Err(err) = case::record_source(&catalog, path.as_ref(), &sha256, inserted as i64) {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
        println!("inserted={inserted} file={path}");
    }
    ExitCode::SUCCESS
}

fn query(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser query --case <dir> [--format table|csv|jsonl] \"<sql>\"");
        return ExitCode::from(2);
    };
    let mut rest: Vec<String> = args.collect();
    let format = if rest.first().map(String::as_str) == Some("--format") {
        rest.remove(0);
        let Some(value) = rest.first().cloned() else {
            eprintln!("usage: mcparser query --case <dir> [--format table|csv|jsonl] \"<sql>\"");
            return ExitCode::from(2);
        };
        rest.remove(0);
        match value.as_str() {
            "table" | "csv" | "jsonl" => value,
            other => {
                eprintln!("unknown format: {other}");
                return ExitCode::from(2);
            }
        }
    } else {
        "table".to_string()
    };
    let Some(sql) = rest.first() else {
        eprintln!("usage: mcparser query --case <dir> [--format table|csv|jsonl] \"<sql>\"");
        return ExitCode::from(2);
    };
    let db = case_dir.join("events.duckdb");
    let table = match case::query_table(&db, sql) {
        Ok(table) => table,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    print_rows(&table.columns, &table.rows, &format);
    ExitCode::SUCCESS
}

fn stats(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser stats --case <dir>");
        return ExitCode::from(2);
    };
    let db = case_dir.join("events.duckdb");
    let sections = [
        (
            "time range",
            "SELECT min(time_created), max(time_created), count(*) FROM events",
        ),
        (
            "channels",
            "SELECT channel, count(*) FROM events GROUP BY channel ORDER BY count(*) DESC",
        ),
        (
            "providers",
            "SELECT provider, count(*) FROM events GROUP BY provider ORDER BY count(*) DESC",
        ),
        (
            "event ids",
            "SELECT event_id, count(*) FROM events GROUP BY event_id ORDER BY count(*) DESC",
        ),
    ];
    for (title, sql) in sections {
        println!("# {title}");
        let rows = match case::query(&db, sql) {
            Ok(rows) => rows,
            Err(err) => {
                eprintln!("{err}");
                return ExitCode::from(1);
            }
        };
        print_rows(&[], &rows, "table");
        println!();
    }
    println!("# sources");
    match case::sources(&case_dir.join("catalog.sqlite")) {
        Ok(sources) => {
            for source in sources {
                let size = std::fs::metadata(&source.path).map(|meta| meta.len()).unwrap_or(0);
                println!("{}\t{}\t{}\t{}", source.path, source.sha256, size, source.records);
            }
        }
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    }
    ExitCode::SUCCESS
}

fn queries(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser queries --case <dir>");
        return ExitCode::from(2);
    };
    match case::queries(&case_dir.join("catalog.sqlite")) {
        Ok(saved) => {
            for query in saved {
                println!("{}\t{}", query.name, query.sql.replace('\n', "\\n"));
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn save_query(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser save-query --case <dir> --name <name> \"<sql>\"");
        return ExitCode::from(2);
    };
    let mut rest: Vec<String> = args.collect();
    if rest.first().map(String::as_str) != Some("--name") || rest.len() < 3 {
        eprintln!("usage: mcparser save-query --case <dir> --name <name> \"<sql>\"");
        return ExitCode::from(2);
    }
    rest.remove(0);
    let name = rest.remove(0);
    let sql = rest.join(" ");
    if name.trim().is_empty() || sql.trim().is_empty() {
        eprintln!("name and sql are required");
        return ExitCode::from(2);
    }
    if let Err(err) = std::fs::create_dir_all(&case_dir) {
        eprintln!("{err}");
        return ExitCode::from(1);
    }
    match case::save_query(&case_dir.join("catalog.sqlite"), name.trim(), sql.trim()) {
        Ok(()) => {
            println!("saved {name}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}


fn notes(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser notes --case <dir>");
        return ExitCode::from(2);
    };
    match case::notes(&case_dir.join("catalog.sqlite")) {
        Ok(notes) => {
            for note in notes {
                println!("{}\t{}\t{}", note.record_id, note.body.replace('\n', "\\n"), note.query_sql.replace('\n', "\\n"));
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn save_note(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser save-note --case <dir> --record <id> \"<sentence>\"");
        return ExitCode::from(2);
    };
    let mut rest: Vec<String> = args.collect();
    if rest.first().map(String::as_str) != Some("--record") || rest.len() < 3 {
        eprintln!("usage: mcparser save-note --case <dir> --record <id> \"<sentence>\"");
        return ExitCode::from(2);
    }
    rest.remove(0);
    let record = rest.remove(0);
    let Ok(record_id) = record.parse::<i64>() else {
        eprintln!("record id must be a number");
        return ExitCode::from(2);
    };
    let mut query_sql = String::new();
    if rest.first().map(String::as_str) == Some("--sql") {
        rest.remove(0);
        if rest.is_empty() {
            eprintln!("usage: mcparser save-note --case <dir> --record <id> [--sql <sql>] \"<sentence>\"");
            return ExitCode::from(2);
        }
        query_sql = rest.remove(0);
    }
    let body = rest.join(" ");
    if body.trim().is_empty() {
        eprintln!("a sentence is required");
        return ExitCode::from(2);
    }
    match case::save_note(&case_dir.join("catalog.sqlite"), record_id, body.trim(), query_sql.trim()) {
        Ok(()) => {
            println!("noted {record_id}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}


fn runs(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser runs --case <dir>");
        return ExitCode::from(2);
    };
    match case::runs(&case_dir.join("catalog.sqlite")) {
        Ok(runs) => {
            for run in runs {
                println!("{}\t{}\t{}\t{}\t{}\t{}", run.id, run.ran_at, run.row_count, run.followed.map(|id| id.to_string()).unwrap_or_default(), run.label, run.sql.replace('\n', "\\n"));
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn save_run(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser save-run --case <dir> --rows <n> \"<sql>\"");
        return ExitCode::from(2);
    };
    let mut rest: Vec<String> = args.collect();
    if rest.first().map(String::as_str) != Some("--rows") || rest.len() < 3 {
        eprintln!("usage: mcparser save-run --case <dir> --rows <n> \"<sql>\"");
        return ExitCode::from(2);
    }
    rest.remove(0);
    let rows = rest.remove(0);
    let Ok(row_count) = rows.parse::<i64>() else {
        eprintln!("rows must be a number");
        return ExitCode::from(2);
    };
    let mut label = String::new();
    if rest.first().map(String::as_str) == Some("--label") {
        rest.remove(0);
        if rest.is_empty() {
            eprintln!("usage: mcparser save-run --case <dir> --rows <n> [--label <name>] \"<sql>\"");
            return ExitCode::from(2);
        }
        label = rest.remove(0);
    }
    let sql = rest.join(" ");
    if sql.trim().is_empty() {
        eprintln!("sql is required");
        return ExitCode::from(2);
    }
    let ran_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match case::save_run(&case_dir.join("catalog.sqlite"), sql.trim(), &ran_at.to_string(), row_count, label.trim()) {
        Ok(id) => {
            println!("ran id={id} rows={row_count}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn print_rows(columns: &[String], rows: &[Vec<String>], format: &str) {
    match format {
        "csv" => {
            if !columns.is_empty() {
                println!("{}", columns.iter().map(|cell| csv_cell(cell)).collect::<Vec<_>>().join(","));
            }
            for row in rows {
                println!(
                    "{}",
                    row.iter()
                        .map(|cell| csv_cell(cell))
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
        }
        "jsonl" => {
            for row in rows {
                let values: Vec<String> = row
                    .iter()
                    .map(|cell| format!("\"{}\"", json_escape(cell)))
                    .collect();
                println!("[{}]", values.join(","));
            }
        }
        _ => {
            for row in rows {
                println!("{}", row.join("\t"));
            }
        }
    }
}

fn csv_cell(value: &str) -> String {
    if value.contains([',', '"', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn case_dir(args: &mut impl Iterator<Item = String>) -> Option<PathBuf> {
    match args.next().as_deref() {
        Some("--case") => args.next().map(PathBuf::from),
        _ => None,
    }
}
