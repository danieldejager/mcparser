use evtx::EvtxParser;
use std::path::Path;

pub fn name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

pub struct ParseCount {
    pub ok: u64,
    pub err: u64,
}

pub fn count_records(path: &Path) -> Result<ParseCount, evtx::err::EvtxError> {
    let mut parser = EvtxParser::from_path(path)?;
    let mut count = ParseCount { ok: 0, err: 0 };
    for record in parser.records() {
        match record {
            Ok(_) => count.ok += 1,
            Err(_) => count.err += 1,
        }
    }
    Ok(count)
}

pub fn first_json(path: &Path) -> Result<String, evtx::err::EvtxError> {
    let mut parser = EvtxParser::from_path(path)?;
    match parser.records_json().next() {
        Some(Ok(record)) => Ok(record.data),
        Some(Err(err)) => Err(err),
        None => Ok(String::new()),
    }
}