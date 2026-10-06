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
        _ => {
            eprintln!("usage: mcparser ingest --case <dir> <file.evtx> [more.evtx...]");
            eprintln!("       mcparser query --case <dir> [--format table|csv|jsonl] \"<sql>\"");
            eprintln!("       mcparser stats --case <dir>");
            eprintln!("       mcparser queries --case <dir>");
            eprintln!("       mcparser save-query --case <dir> --name <name> \"<sql>\"");
            ExitCode::from(2)
        }
    }
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
