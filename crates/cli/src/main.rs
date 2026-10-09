mod handoff;
use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1); // nosemgrep: rust.lang.security.args.args -- command names only, the handoff password is not read from argv
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
        Some("chats") => chats(&mut args),
        Some("save-chat") => save_chat(&mut args),
        Some("collect") => collect(&mut args),
        Some("hosts") => hosts(&mut args),
        Some("collections") => collections(&mut args),
        Some("prefetch") => prefetch(&mut args),
        Some("amcache") => amcache(&mut args),
        Some("shimcache") => shimcache(&mut args),
        Some("srum") => srum(&mut args),
        Some("tasks") => tasks(&mut args),
        Some("userassist") => userassist(&mut args),
        Some("save-analyst") => save_analyst(&mut args),
        Some("handoff") => handoff(&mut args),
        Some("open-handoff") => open_handoff(&mut args),
        Some("-h" | "--help" | "help") | None => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown command: {other}");
            eprintln!();
            print_help();
            ExitCode::from(2)
        }
    }
}

fn print_help() {
    println!(
        r#"McParser reads an offline Windows .evtx file and queries it with SQL.

Usage: mcparser <command> [options]

Commands:
  ingest         Read one or more .evtx files into a case
  collect        Read a Velociraptor offline zip into the case catalog
  hosts          List hosts recorded in a case
  collections    List collections recorded in a case
  save-analyst   Store the analyst name on the case
  query          Run SQL against the events in a case
  stats          Channels, providers, event ids, and the time range
  queries        List saved queries
  save-query     Store a named query in the case
  notes          List notes
  save-note      Attach a sentence to a record id
  runs           List successful Run-button trails
  save-run       Store a run without the window
  chats          List stored vendor turns
  save-chat      Store a question, a SELECT, and an answer
  handoff        Write a password-locked copy of the case
  open-handoff   Unpack a handoff into a folder
  help           Show this help

Options:
  -h, --help     Show this help

ingest:
  mcparser ingest --case <dir> <file.evtx> [more.evtx...]

collect:
  mcparser collect --case <dir> <collector.zip>
    Records the host and collection. It does not ingest events yet.

hosts:
  mcparser hosts --case <dir>

collections:
  mcparser collections --case <dir>
    A file whose bytes are already in the case is skipped.
    The same path with a new hash replaces the old rows.

query:
  mcparser query --case <dir> [--format table|csv|jsonl] "<sql>"
    --format is table by default. csv includes a header row.
    A command-line query is not written to the run trail.

stats:
  mcparser stats --case <dir>

queries:
  mcparser queries --case <dir>

save-query:
  mcparser save-query --case <dir> --name <name> "<sql>"

notes:
  mcparser notes --case <dir>

save-note:
  mcparser save-note --case <dir> --record <id> [--sql <sql>] "<sentence>"

runs:
  mcparser runs --case <dir>

save-run:
  mcparser save-run --case <dir> --rows <n> [--label <name>] [--analyst <name>] [--kind run|replay] "<sql>"

chats:
  mcparser chats --case <dir>

save-chat:
  mcparser save-chat --case <dir> --vendor <name> --question <text> --sql <sql> --answer <text>

handoff:
  mcparser handoff --case <dir> --out <file>
    Set MCPARSER_HANDOFF_PASSWORD. At least 8 characters. It is not stored.

open-handoff:
  mcparser open-handoff --file <file> --out <dir>
    Set MCPARSER_HANDOFF_PASSWORD. A wrong password is rejected.

A case directory holds events.duckdb and catalog.sqlite.
The API key is not in the case.
"#
    );
}

fn collect(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser collect --case <dir> [--analyst <name>] <collector.zip>");
        return ExitCode::from(2);
    };
    let mut rest: Vec<String> = args.collect();
    let mut analyst = String::new();
    if rest.first().map(String::as_str) == Some("--analyst") {
        rest.remove(0);
        analyst = rest.first().cloned().unwrap_or_default();
        if !rest.is_empty() {
            rest.remove(0);
        }
    }
    let Some(zip_path) = rest.first().cloned() else {
        eprintln!("usage: mcparser collect --case <dir> [--analyst <name>] <collector.zip>");
        return ExitCode::from(2);
    };
    if let Err(err) = std::fs::create_dir_all(&case_dir) {
        eprintln!("{err}");
        return ExitCode::from(1);
    }
    let catalog = case_dir.join("catalog.sqlite");
    if !analyst.trim().is_empty() {
        if let Err(err) = case::save_analyst(&catalog, analyst.trim()) {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    }
    case::report_progress(1, "Hashing collector");
    let sha = match case::file_sha256(zip_path.as_ref()) {
        Ok(sha) => sha,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    match case::import_collector(&catalog, zip_path.as_ref()) {
        Ok((hosts, collections, kept)) => {
            for host in &hosts {
                println!("host {} {} {} {}", host.host_id, host.hostname, host.os, host.arch);
            }
            for collection in collections {
                println!("collection {} {} {} {}", collection.session_id, collection.collected_at, collection.source_name, sha);
            }
            for path in kept {
                println!("kept {}", path.display());
            }
            let host_id = hosts.first().map(|host| host.host_id.clone()).unwrap_or_default();
            let db = case_dir.join("events.duckdb");
            match case::eventlog_payloads(zip_path.as_ref()) {
                Ok(logs) => {
                    let log_total = logs.len().max(1);
                    for (index, log) in logs.iter().enumerate() {
                        let sha = case::sha256_bytes(&log.bytes);
                        case::report_progress((16 + (index * 12 / log_total)) as u8, &format!("Writing events {}", log.name));
                        if case::already_ingested(&catalog, &sha).unwrap_or(false) {
                            println!("skipped {} sha256={sha}", log.name);
                            continue;
                        }
                        let records = match evtx_read::records_json_from_bytes(&log.bytes) {
                            Ok(records) => records,
                            Err(err) => {
                                eprintln!("{}: {err}", log.name);
                                return ExitCode::from(1);
                            }
                        };
                        let mut events = Vec::new();
                        for json in &records {
                            match model::from_json(json) {
                                Ok(event) => events.push(event),
                                Err(err) => {
                                    eprintln!("{}: {err}", log.name);
                                    return ExitCode::from(1);
                                }
                            }
                        }
                        let log_name = log.name.trim_start_matches("./").to_string();
                        match case::ingest_for_host(&db, &sha, &host_id, &log_name, &events) {
                            Ok(inserted) => println!("events {} inserted={inserted} host={host_id} log={log_name}", log.name),
                            Err(err) => {
                                eprintln!("{err}");
                                return ExitCode::from(1);
                            }
                        }
                        if let Err(err) = case::record_source(&catalog, Path::new(&log.name), &sha, events.len() as i64) {
                            eprintln!("{err}");
                            return ExitCode::from(1);
                        }
                    }
                }
                Err(err) => {
                    eprintln!("{err}");
                    return ExitCode::from(1);
                }
            }
            for (name, load) in [
                ("prefetch", case::ingest_prefetch as fn(&Path, &Path) -> Result<usize, String>),
                ("services", case::ingest_services),
                ("tasks", case::ingest_tasks),
                ("shimcache", case::ingest_shimcache),
                ("userassist", case::ingest_userassist),
                ("amcache", case::ingest_amcache),
                ("srum", case::ingest_srum),
            ] {
                if case::artifact_done(&catalog, name, &sha).unwrap_or(false) {
                    println!("skipped {name} sha256={sha}");
                    case::report_progress(match name { "prefetch" => 39, "services" => 51, "tasks" => 63, "shimcache" => 75, _ => 99 }, &format!("Skipped {name}, already loaded"));
                    continue;
                }
                case::report_progress(match name { "prefetch" => 28, "services" => 40, "tasks" => 52, "shimcache" => 64, _ => 76 }, &format!("Writing {name}"));
                match load(&catalog, &db) {
                    Ok(count) => {
                        println!("{name} inserted={count}");
                        if (name != "tasks" && name != "services") || count > 0 {
                            if let Err(err) = case::record_artifact(&catalog, name, &sha, count as i64) {
                                eprintln!("{err}");
                                return ExitCode::from(1);
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("{err}");
                        return ExitCode::from(1);
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn prefetch(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser prefetch --case <dir>");
        return ExitCode::from(2);
    };
    let catalog = case_dir.join("catalog.sqlite");
    let db = case_dir.join("events.duckdb");
    if let Err(err) = case::ingest_prefetch(&catalog, &db) {
        eprintln!("{err}");
        return ExitCode::from(1);
    }
    match case::query(&db, "SELECT host_id, executable, run_count, last_run, path FROM prefetch ORDER BY run_count DESC") {
        Ok(rows) => {
            print_rows(&[], &rows, "table");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn hosts(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser hosts --case <dir>");
        return ExitCode::from(2);
    };
    match case::hosts(&case_dir.join("catalog.sqlite")) {
        Ok(rows) => {
            for host in rows {
                println!("{}\t{}\t{}\t{}\t{}", host.host_id, host.hostname, host.fqdn, host.os, host.arch);
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn collections(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser collections --case <dir>");
        return ExitCode::from(2);
    };
    match case::collections(&case_dir.join("catalog.sqlite")) {
        Ok(rows) => {
            for collection in rows {
                println!("{}\t{}\t{}\t{}", collection.session_id, collection.host_id, collection.collected_at, collection.source_name);
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn save_analyst(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser save-analyst --case <dir> --name <analyst>");
        return ExitCode::from(2);
    };
    let mut name = String::new();
    let mut rest = args.collect::<Vec<_>>();
    if rest.first().map(String::as_str) == Some("--name") {
        rest.remove(0);
        name = rest.first().cloned().unwrap_or_default();
    }
    if name.trim().is_empty() {
        eprintln!("analyst name is required");
        return ExitCode::from(2);
    }
    if let Err(err) = std::fs::create_dir_all(&case_dir) {
        eprintln!("{err}");
        return ExitCode::from(1);
    }
    match case::save_analyst(&case_dir.join("catalog.sqlite"), name.trim()) {
        Ok(()) => {
            println!("saved analyst");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
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
        let computer = events.iter().find(|event| !event.computer.is_empty()).map(|event| event.computer.clone()).unwrap_or_else(|| path.clone());
        let host = case::Host { host_id: format!("evtx:{computer}"), hostname: computer.clone(), fqdn: computer, os: "Windows event log".into(), arch: String::new() };
        if let Err(err) = case::record_host(&catalog, &host) {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
        println!("host {} {} {} {}", host.host_id, host.hostname, host.os, host.arch);
        println!("file {path} sha256={sha256} inserted={inserted}");
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
                println!("{}\t{}\t{}\t{}", note.record_id, note.created, note.body.replace('\n', "\\n"), note.query_sql.replace('\n', "\\n"));
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
                println!("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}", run.id, run.ran_at, run.row_count, run.followed.map(|id| id.to_string()).unwrap_or_default(), run.label, run.analyst, run.kind, run.sql.replace('\n', "\\n"));
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
    let mut analyst = String::new();
    let mut kind = String::from("run");
    while let Some(flag) = rest.first().map(|s| s.as_str()) {
        if flag == "--label" || flag == "--analyst" || flag == "--kind" {
            let flag = rest.remove(0);
            if rest.is_empty() {
                eprintln!("usage: mcparser save-run --case <dir> --rows <n> [--label <name>] [--analyst <name>] [--kind run|replay] \"<sql>\"");
                return ExitCode::from(2);
            }
            let value = rest.remove(0);
            if flag == "--label" { label = value; }
            else if flag == "--analyst" { analyst = value; }
            else { kind = value; }
        } else {
            break;
        }
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
    match case::save_run(&case_dir.join("catalog.sqlite"), sql.trim(), &ran_at.to_string(), row_count, label.trim(), analyst.trim(), kind.trim()) {
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


fn chats(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser chats --case <dir>");
        return ExitCode::from(2);
    };
    match case::chats(&case_dir.join("catalog.sqlite")) {
        Ok(chats) => {
            for chat in chats {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    chat.id,
                    chat.asked_at,
                    chat.vendor,
                    chat.question.replace('\n', "\\n"),
                    chat.sql.replace('\n', "\\n"),
                    chat.answer.replace('\n', "\\n")
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn save_chat(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser save-chat --case <dir> --vendor <name> --question <text> --sql <sql> --answer <text>");
        return ExitCode::from(2);
    };
    let mut rest: Vec<String> = args.collect();
    let mut vendor = String::new();
    let mut question = String::new();
    let mut sql = String::new();
    let mut answer = String::new();
    while let Some(flag) = rest.first().map(|s| s.as_str()) {
        if flag == "--vendor" || flag == "--question" || flag == "--sql" || flag == "--answer" {
            let flag = rest.remove(0);
            if rest.is_empty() {
                eprintln!("usage: mcparser save-chat --case <dir> --vendor <name> --question <text> --sql <sql> --answer <text>");
                return ExitCode::from(2);
            }
            let value = rest.remove(0);
            if flag == "--vendor" { vendor = value; }
            else if flag == "--question" { question = value; }
            else if flag == "--sql" { sql = value; }
            else { answer = value; }
        } else {
            break;
        }
    }
    if vendor.is_empty() || question.is_empty() {
        eprintln!("vendor and question are required");
        return ExitCode::from(2);
    }
    match case::save_chat(&case_dir.join("catalog.sqlite"), vendor.trim(), question.trim(), sql.trim(), answer.trim()) {
        Ok(id) => {
            println!("chat {id}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}


fn handoff(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser handoff --case <dir> --out <file>");
        return ExitCode::from(2);
    };
    let mut rest: Vec<String> = args.collect();
    if rest.first().map(String::as_str) != Some("--out") || rest.len() < 2 {
        eprintln!("usage: mcparser handoff --case <dir> --out <file>");
        return ExitCode::from(2);
    }
    rest.remove(0);
    let out = rest.remove(0);
    let password = std::env::var("MCPARSER_HANDOFF_PASSWORD").unwrap_or_default();
    match handoff::export_handoff(&case_dir, out.as_ref(), &password) {
        Ok(()) => {
            println!("handoff {out}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn open_handoff(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let mut rest: Vec<String> = args.collect();
    if rest.first().map(String::as_str) != Some("--file") || rest.len() < 4 || rest.get(2).map(String::as_str) != Some("--out") {
        eprintln!("usage: mcparser open-handoff --file <file> --out <dir>");
        return ExitCode::from(2);
    }
    rest.remove(0);
    let file = rest.remove(0);
    rest.remove(0);
    let out = rest.remove(0);
    let password = std::env::var("MCPARSER_HANDOFF_PASSWORD").unwrap_or_default();
    match handoff::open_handoff(file.as_ref(), out.as_ref(), &password) {
        Ok(()) => {
            println!("opened {out}");
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




fn tasks(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser tasks --case <dir>");
        return ExitCode::from(2);
    };
    let catalog = case_dir.join("catalog.sqlite");
    let db = case_dir.join("events.duckdb");
    if let Err(err) = case::ingest_tasks(&catalog, &db) {
        eprintln!("{err}");
        return ExitCode::from(1);
    }
    match case::query(&db, "SELECT host_id, enabled, user_id, command, arguments, path FROM tasks ORDER BY command") {
        Ok(rows) => {
            print_rows(&[], &rows, "table");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn srum(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser srum --case <dir>");
        return ExitCode::from(2);
    };
    let catalog = case_dir.join("catalog.sqlite");
    let db = case_dir.join("events.duckdb");
    if let Err(err) = case::ingest_srum(&catalog, &db) {
        eprintln!("{err}");
        return ExitCode::from(1);
    }
    match case::query(&db, "SELECT host_id, kind, timestamp, app, user_sid, bytes_sent, bytes_received FROM srum ORDER BY bytes_sent DESC") {
        Ok(rows) => {
            print_rows(&[], &rows, "table");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn shimcache(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser shimcache --case <dir>");
        return ExitCode::from(2);
    };
    let catalog = case_dir.join("catalog.sqlite");
    let db = case_dir.join("events.duckdb");
    if let Err(err) = case::ingest_shimcache(&catalog, &db) {
        eprintln!("{err}");
        return ExitCode::from(1);
    }
    match case::query(&db, "SELECT host_id, position, executed, modified, path FROM shimcache ORDER BY position") {
        Ok(rows) => {
            print_rows(&[], &rows, "table");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}
fn amcache(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser amcache --case <dir>");
        return ExitCode::from(2);
    };
    let catalog = case_dir.join("catalog.sqlite");
    let db = case_dir.join("events.duckdb");
    if let Err(err) = case::ingest_amcache(&catalog, &db) {
        eprintln!("{err}");
        return ExitCode::from(1);
    }
    match case::query(&db, "SELECT host_id, kind, name, sha1, modified, path FROM amcache ORDER BY modified DESC") {
        Ok(rows) => {
            print_rows(&[], &rows, "table");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn userassist(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(case_dir) = case_dir(args) else {
        eprintln!("usage: mcparser userassist --case <dir>");
        return ExitCode::from(2);
    };
    let catalog = case_dir.join("catalog.sqlite");
    let db = case_dir.join("events.duckdb");
    match case::ingest_userassist(&catalog, &db) {
        Ok(count) => println!("userassist inserted={count}"),
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    }
    match case::query(&db, "SELECT host_id, run_count, last_run, name FROM userassist ORDER BY run_count DESC") {
        Ok(rows) => {
            print_rows(&[], &rows, "table");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}
