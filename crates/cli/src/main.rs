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