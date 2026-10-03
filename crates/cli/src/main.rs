use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: mcparser <file.evtx>");
        return ExitCode::from(2);
    };
    match evtx_read::count_records(path.as_ref()) {
        Ok(count) => {
            println!("ok={} err={}", count.ok, count.err);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}