//! Text for DuckDB result values, as shown by `mcparser query`.
//!
//! NULL is an empty string (the existing convention). Top level text is
//! shown as is. Nested values use DuckDB's own style: [1, 2], {'k': v} and
//! {k=v} for maps, with strings quoted and NULL written as NULL.

use duckdb::types::{TimeUnit, Value};

pub(crate) fn cell_text(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Text(s) | Value::Enum(s) => s.clone(),
        other => text(other),
    }
}

fn text(value: &Value) -> String {
    match value {
        Value::Null => "NULL".into(),
        Value::Boolean(b) => b.to_string(),
        Value::TinyInt(v) => v.to_string(),
        Value::SmallInt(v) => v.to_string(),
        Value::Int(v) => v.to_string(),
        Value::BigInt(v) => v.to_string(),
        Value::HugeInt(v) => v.to_string(),
        Value::UHugeInt(v) => v.to_string(),
        Value::UTinyInt(v) => v.to_string(),
        Value::USmallInt(v) => v.to_string(),
        Value::UInt(v) => v.to_string(),
        Value::UBigInt(v) => v.to_string(),
        Value::Float(v) => float(*v as f64, v.to_string()),
        Value::Double(v) => float(*v, v.to_string()),
        Value::Decimal(d) => d.to_string(),
        Value::Timestamp(unit, v) => timestamp(*unit, *v),
        Value::Date32(days) => date(*days as i64),
        Value::Time64(unit, v) => {
            let (secs, frac) = split(*unit, *v);
            time_of_day(secs, frac)
        }
        Value::Interval { months, days, nanos } => interval(*months, *days, *nanos),
        Value::Text(s) | Value::Enum(s) => s.clone(),
        Value::Blob(b) | Value::Geometry(b) => blob(b),
        Value::List(items) | Value::Array(items) => {
            format!("[{}]", items.iter().map(nested).collect::<Vec<_>>().join(", "))
        }
        Value::Struct(fields) => format!(
            "{{{}}}",
            fields.iter().map(|(k, v)| format!("{}: {}", quote(k), nested(v))).collect::<Vec<_>>().join(", ")
        ),
        Value::Map(entries) => format!(
            "{{{}}}",
            entries.iter().map(|(k, v)| format!("{}={}", nested(k), nested(v))).collect::<Vec<_>>().join(", ")
        ),
        Value::Union(inner) => text(inner),
        #[allow(unreachable_patterns)]
        other => format!("{other:?}"),
    }
}

fn nested(value: &Value) -> String {
    match value {
        Value::Text(s) | Value::Enum(s) => quote(s),
        other => text(other),
    }
}

fn quote(s: &str) -> String { format!("'{}'", s.replace('\'', "''")) }

fn float(v: f64, shown: String) -> String {
    if v.is_nan() { "nan".into() } else if v.is_infinite() { if v > 0.0 { "inf".into() } else { "-inf".into() } } else { shown }
}

fn blob(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        if (0x20..0x7f).contains(&b) && b != b'\\' { out.push(b as char) } else { out.push_str(&format!("\\x{b:02X}")) }
    }
    out
}

/// Whole seconds and the fraction as (digits, width).
fn split(unit: TimeUnit, v: i64) -> (i64, (i64, usize)) {
    let (per, width) = match unit {
        TimeUnit::Second => (1, 0),
        TimeUnit::Millisecond => (1_000, 3),
        TimeUnit::Microsecond => (1_000_000, 6),
        TimeUnit::Nanosecond => (1_000_000_000, 9),
    };
    (v.div_euclid(per), (v.rem_euclid(per), width))
}

fn fraction((digits, width): (i64, usize)) -> String {
    if digits == 0 || width == 0 { return String::new(); }
    let s = format!("{digits:0width$}");
    format!(".{}", s.trim_end_matches('0'))
}

fn time_of_day(secs: i64, frac: (i64, usize)) -> String {
    format!("{:02}:{:02}:{:02}{}", secs / 3600, secs / 60 % 60, secs % 60, fraction(frac))
}

fn timestamp(unit: TimeUnit, v: i64) -> String {
    let (secs, frac) = split(unit, v);
    format!("{} {}", date(secs.div_euclid(86_400)), time_of_day(secs.rem_euclid(86_400), frac))
}

/// Days since 1970-01-01 as YYYY-MM-DD (proleptic Gregorian).
fn date(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    if y < 0 { format!("{:04}-{m:02}-{d:02} (BC)", 1 - y) } else { format!("{y:04}-{m:02}-{d:02}") }
}

fn interval(months: i32, days: i32, nanos: i64) -> String {
    let mut parts = Vec::new();
    let plural = |n: i64, one: &str| format!("{n} {one}{}", if n.abs() == 1 { "" } else { "s" });
    let (years, months) = (months / 12, months % 12);
    if years != 0 { parts.push(plural(years as i64, "year")); }
    if months != 0 { parts.push(plural(months as i64, "month")); }
    if days != 0 { parts.push(plural(days as i64, "day")); }
    if nanos != 0 || parts.is_empty() {
        let sign = if nanos < 0 { "-" } else { "" };
        let n = nanos.unsigned_abs() as i64;
        let secs = n / 1_000_000_000;
        parts.push(format!("{sign}{}", time_of_day(secs, (n % 1_000_000_000 / 1_000, 6))));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_times() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(-1), "1969-12-31");
        assert_eq!(date(20_454), "2026-01-01");
        assert_eq!(timestamp(TimeUnit::Microsecond, 1_767_261_600_500_000), "2026-01-01 10:00:00.5");
        assert_eq!(timestamp(TimeUnit::Microsecond, -1), "1969-12-31 23:59:59.999999");
        assert_eq!(interval(14, 3, 3_723_000_000_000), "1 year 2 months 3 days 01:02:03");
        assert_eq!(interval(0, 0, 0), "00:00:00");
        assert_eq!(blob(b"MZ\x00\xff"), "MZ\\x00\\xFF");
    }
}
