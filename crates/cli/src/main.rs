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

    let json = match evtx_read::first_json(path.as_ref()) {
    Ok(json) => json,
    Err(err) => {
        eprintln!("{err}");
        return ExitCode::from(1);
    }
};
match model::from_json(&json) {
    Ok(event) => {
        println!(
            "record={} event_id={} channel={} provider={} computer={} time={}",
            event.record_id,
            event.event_id,
            event.channel,
            event.provider,
            event.computer,
            event.time_created
        );
        ExitCode::SUCCESS
    }
    Err(err) => {
        eprintln!("{err}");
        ExitCode::from(1)
    }
}
}