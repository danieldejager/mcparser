use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: mcparser <file.evtx>");
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

    let mut mapped = 0u64;
    let mut map_err = 0u64;
    for json in &records {
        match model::from_json(json) {
            Ok(_) => mapped += 1,
            Err(_) => map_err += 1,
        }
    }
    println!("mapped={} map_err={}", mapped, map_err);
    ExitCode::SUCCESS
}