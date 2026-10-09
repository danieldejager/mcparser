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
    let record = parser.records_json().next();
    match record {
        Some(Ok(record)) => Ok(record.data),
        Some(Err(err)) => Err(err),
        None => Ok(String::new()),
    }
}

pub fn records_json(path: &Path) -> Result<Vec<String>, evtx::err::EvtxError> {
    let mut parser = EvtxParser::from_path(path)?;
    let mut out = Vec::new();
    for record in parser.records_json() {
        out.push(record?.data);
    }
    Ok(out)
}
pub fn records_json_from_bytes(bytes: &[u8]) -> Result<Vec<String>, evtx::err::EvtxError> {
    let mut parser = EvtxParser::from_buffer(bytes.to_vec())?;
    let mut out = Vec::new();
    for record in parser.records_json() {
        out.push(record?.data);
    }
    Ok(out)
}
