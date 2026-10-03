use serde::Deserialize;
use serde_json::Value;

pub fn name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

#[derive(Debug)]
pub struct Event {
    pub record_id: u64,
    pub event_id: u32,
    pub channel: String,
    pub provider: String,
    pub computer: String,
    pub time_created: String,
}

#[derive(Deserialize)]
struct Raw {
    #[serde(rename = "Event")]
    event: RawEvent,
}

#[derive(Deserialize)]
struct RawEvent {
    #[serde(rename = "System")]
    system: RawSystem,
}

#[derive(Deserialize)]
struct RawSystem {
    #[serde(rename = "EventID")]
    event_id: Value,
    #[serde(rename = "EventRecordID")]
    record_id: u64,
    #[serde(rename = "Channel")]
    channel: String,
    #[serde(rename = "Computer")]
    computer: String,
    #[serde(rename = "Provider")]
    provider: AttrName,
    #[serde(rename = "TimeCreated")]
    time_created: AttrTime,
}

#[derive(Deserialize)]
struct AttrName {
    #[serde(rename = "#attributes")]
    attributes: NameAttr,
}

#[derive(Deserialize)]
struct NameAttr {
    #[serde(rename = "Name")]
    name: String,
}

#[derive(Deserialize)]
struct AttrTime {
    #[serde(rename = "#attributes")]
    attributes: TimeAttr,
}

#[derive(Deserialize)]
struct TimeAttr {
    #[serde(rename = "SystemTime")]
    system_time: String,
}

pub fn from_json(json: &str) -> Result<Event, String> {
    let raw: Raw = serde_json::from_str(json).map_err(|err| err.to_string())?;
    let system = raw.event.system;
    Ok(Event {
        record_id: system.record_id,
        event_id: event_id(&system.event_id)?,
        channel: system.channel,
        provider: system.provider.attributes.name,
        computer: system.computer,
        time_created: system.time_created.attributes.system_time,
    })
}

fn event_id(value: &Value) -> Result<u32, String> {
    if let Some(id) = value.as_u64() {
        return u32::try_from(id).map_err(|err| err.to_string());
    }
    value
        .get("#text")
        .and_then(Value::as_u64)
        .and_then(|id| u32::try_from(id).ok())
        .ok_or_else(|| format!("unrecognized EventID: {value}"))
}