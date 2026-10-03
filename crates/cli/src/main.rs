use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: mcparser <file.evtx> [sql]");
        return ExitCode::from(2);
    };

    let count = match evtx_read::count_records(path.as_ref()) {
        Ok(count) => count,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    println!("ok={} err={}", count.ok, count.err);

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
    println!("mapped={}", events.len());

    let db = std::path::Path::new(&path).with_extension("duckdb");
    let inserted = match case::ingest(&db, &events) {
        Ok(inserted) => inserted,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    println!("inserted={inserted} db={}", db.display());

    let Some(sql) = args.next() else {
        return ExitCode::SUCCESS;
    };
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