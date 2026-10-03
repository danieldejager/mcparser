use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("ingest") => ingest(&mut args),
        Some("query") => query(&mut args),
        _ => {
            eprintln!("usage: mcparser ingest <file.evtx> --case <dir>");
            eprintln!("       mcparser query --case <dir> \"<sql>\"");
            ExitCode::from(2)
        }
    }
}

fn ingest(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(path) = args.next() else {
        eprintln!("usage: mcparser ingest <file.evtx> --case <dir>");
        return ExitCode::from(2);
    };
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser ingest <file.evtx> --case <dir>");
        return ExitCode::from(2);
    };
    if let Err(err) = std::fs::create_dir_all(&case_dir) {
        eprintln!("{err}");
        return ExitCode::from(1);
    }

    let records = match evtx_read::records_json(path.as_ref()) {
        Ok(records) => records,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let mut events = Vec::new();
    for json in &records {
        match model::from_json(json) {
            Ok(event) => events.push(event),
            Err(err) => {
                eprintln!("{err}");
                return ExitCode::from(1);
            }
        }
    }

    let db = case_dir.join("events.duckdb");
    match case::ingest(&db, &events) {
        Ok(inserted) => {
            println!("mapped={} inserted={} db={}", events.len(), inserted, db.display());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn query(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser query --case <dir> \"<sql>\"");
        return ExitCode::from(2);
    };
    let Some(sql) = args.next() else {
        eprintln!("usage: mcparser query --case <dir> \"<sql>\"");
        return ExitCode::from(2);
    };
    let db = case_dir.join("events.duckdb");
    let rows = match case::query(&db, &sql) {
        Ok(rows) => rows,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    for row in rows {
        println!("{}", row.join("\t"));
    }
    ExitCode::SUCCESS
}

fn case_dir(args: &mut impl Iterator<Item = String>) -> Option<PathBuf> {
    match args.next().as_deref() {
        Some("--case") => args.next().map(PathBuf::from),
        _ => None,
    }
}