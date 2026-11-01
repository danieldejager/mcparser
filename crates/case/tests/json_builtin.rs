// JSON functions must be compiled into DuckDB. The signed macOS app cannot
// load a downloaded extension, and offline use has no network, so this test
// runs with an empty HOME and extension autoinstall and autoload disabled.
use model::Event;

fn logon(record_id: u64, time: &str, user: &str, ip: &str, ws: &str, logon_type: &str) -> Event {
    Event {
        record_id,
        event_id: 4624,
        channel: "Security".into(),
        provider: "Microsoft-Windows-Security-Auditing".into(),
        computer: "DC01".into(),
        time_created: time.into(),
        event_data: format!(
            r#"{{"TargetUserName":"{user}","IpAddress":"{ip}","WorkstationName":"{ws}","LogonType":"{logon_type}"}}"#
        ),
    }
}

#[test]
fn json_functions_are_built_in() {
    let home = tempfile::tempdir().unwrap();
    std::env::set_var("HOME", home.path());
    std::env::set_var("USERPROFILE", home.path());
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("case.duckdb");
    let events = vec![
        logon(3, "2026-01-01T10:00:02Z", "bob", "10.0.0.9", "WS9", "3"),
        logon(1, "2026-01-01T10:00:00Z", "alice", "10.0.0.5", "WS5", "3"),
        logon(2, "2026-01-01T10:00:01Z", "SYSTEM", "-", "-", "5"),
    ];
    case::ingest(&db, "abc", &events).unwrap();

    let sql = "SELECT record_id, time_created, computer,
  json_extract_string(event_data, '$.TargetUserName') AS user,
  json_extract_string(event_data, '$.IpAddress') AS ip,
  json_extract_string(event_data, '$.WorkstationName') AS workstation
FROM events
WHERE event_id = 4624
  AND json_extract_string(event_data, '$.LogonType') = '3'
ORDER BY time_created";
    let table = case::query_table(&db, sql).expect("json_extract_string must work without a download");
    assert_eq!(table.columns, vec!["record_id", "time_created", "computer", "user", "ip", "workstation"]);
    assert_eq!(table.rows.len(), 2);
    assert_eq!(table.rows[0][3..], ["alice", "10.0.0.5", "WS5"]);
    assert_eq!(table.rows[1][3..], ["bob", "10.0.0.9", "WS9"]);

    let other = case::query_table(
        &db,
        "SELECT json_extract(event_data, '$.LogonType')::VARCHAR, json_valid(event_data)::VARCHAR, json_valid('{nope')::VARCHAR FROM events WHERE record_id = 2",
    )
    .expect("json_extract and json_valid must work without a download");
    assert_eq!(other.rows, vec![vec!["\"5\"".to_string(), "true".into(), "false".into()]]);

    assert!(std::fs::read_dir(home.path()).unwrap().next().is_none(), "nothing may be written to HOME/.duckdb");
}
