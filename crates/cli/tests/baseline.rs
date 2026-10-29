use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mcparser"))
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/evtx/security.evtx")
}

fn case(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("mcparser-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    path
}

#[test]
fn help_lists_every_command() {
    let out = bin().arg("--help").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    for command in ["ingest", "query", "stats", "queries", "save-query", "notes", "save-note", "runs", "save-run", "chats", "save-chat", "handoff", "open-handoff", "save-analyst", "hosts", "collect", "marketplace", "install-source", "uninstall-source", "import-hashes", "match-hashes", "source-config", "bazaar-import", "bazaar-info", "bazaar-match", "bazaar-online-hits", "ioc-upload"] {
        assert!(text.contains(command), "{command} missing from help");
    }
}

#[test]
fn security_fixture_counts() {
    let fixture = fixture();
    assert!(fixture.exists(), "missing {}; the workflow downloads it", fixture.display());
    let dir = case("counts");
    let ingest = bin().args(["ingest", "--case"]).arg(&dir).arg(&fixture).output().unwrap();
    assert!(ingest.status.success(), "{}", String::from_utf8_lossy(&ingest.stderr));
    let count = bin().args(["query", "--case"]).arg(&dir).arg("SELECT count(*) FROM events").output().unwrap();
    assert!(count.status.success(), "{}", String::from_utf8_lossy(&count.stderr));
    assert!(String::from_utf8_lossy(&count.stdout).contains("2261"));
    let boots = bin().args(["query", "--case"]).arg(&dir).arg("SELECT count(*) FROM events WHERE event_id = 4608").output().unwrap();
    assert!(String::from_utf8_lossy(&boots.stdout).contains("40"));
}

#[test]
fn saved_query_note_run_and_chat_round_trip() {
    let dir = case("catalog");
    std::fs::create_dir_all(&dir).unwrap();
    let sql = "SELECT event_id FROM events";
    assert!(bin().args(["save-query", "--case"]).arg(&dir).args(["--name", "ids", sql]).status().unwrap().success());
    let listed = bin().args(["queries", "--case"]).arg(&dir).output().unwrap();
    assert!(String::from_utf8_lossy(&listed.stdout).contains("ids"));
    assert!(bin().args(["save-note", "--case"]).arg(&dir).args(["--record", "51", "start of the trail"]).status().unwrap().success());
    let notes = bin().args(["notes", "--case"]).arg(&dir).output().unwrap();
    assert!(String::from_utf8_lossy(&notes.stdout).contains("start of the trail"));
    assert!(bin().args(["save-run", "--case"]).arg(&dir).args(["--rows", "3", "--analyst", "daniel", sql]).status().unwrap().success());
    let runs = bin().args(["runs", "--case"]).arg(&dir).output().unwrap();
    assert!(String::from_utf8_lossy(&runs.stdout).contains("daniel"));
    assert!(bin().args(["save-chat", "--case"]).arg(&dir).args(["--vendor", "claude", "--question", "who is fsir", "--sql", sql, "--answer", "not an admin"]).status().unwrap().success());
    let chats = bin().args(["chats", "--case"]).arg(&dir).output().unwrap();
    assert!(String::from_utf8_lossy(&chats.stdout).contains("who is fsir"));
}

#[test]
fn handoff_rejects_a_bad_password() {
    let dir = case("handoff");
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("case.mcpz");
    let short = bin().env("MCPARSER_HANDOFF_PASSWORD", "short").args(["handoff", "--case"]).arg(&dir).args(["--out"]).arg(&out).output().unwrap();
    assert!(!short.status.success());
    assert!(String::from_utf8_lossy(&short.stderr).to_lowercase().contains("password"));
    let good = bin().env("MCPARSER_HANDOFF_PASSWORD", "choose-a-long-password").args(["handoff", "--case"]).arg(&dir).args(["--out"]).arg(&out).output().unwrap();
    assert!(good.status.success(), "{}", String::from_utf8_lossy(&good.stderr));
    let opened = dir.join("opened");
    let wrong = bin().env("MCPARSER_HANDOFF_PASSWORD", "wrong-password").args(["open-handoff", "--file"]).arg(&out).args(["--out"]).arg(&opened).output().unwrap();
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stderr).to_lowercase().contains("password"));
}

#[test]
fn save_case_stores_the_analyst() {
    let dir = case("save-case");
    let missing = bin().args(["save-analyst", "--case"]).arg(&dir).args(["--name", ""]).output().unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("analyst name is required"));
    let saved = bin().args(["save-analyst", "--case"]).arg(&dir).args(["--name", "Daniel de Jager"]).output().unwrap();
    assert!(saved.status.success(), "{}", String::from_utf8_lossy(&saved.stderr));
    assert!(String::from_utf8_lossy(&saved.stdout).contains("saved analyst"));
    let again = bin().args(["save-analyst", "--case"]).arg(&dir).args(["--name", "Daniel de Jager"]).output().unwrap();
    assert!(again.status.success(), "{}", String::from_utf8_lossy(&again.stderr));
}
#[test]
fn case_holds_two_hosts_keyed_by_host_id() {
    let dir = case("hosts");
    std::fs::create_dir_all(&dir).unwrap();
    let script = format!(
        "import json, zipfile\nfrom pathlib import Path\nroot = Path({:?})\n\ndef pack(name, host_id, session):\n    info = json.dumps({{\"HostID\": host_id, \"Hostname\": \"shared\", \"Fqdn\": host_id + \".plant.local\", \"Platform\": \"windows\", \"Architecture\": \"amd64\"}}).encode()\n    context = json.dumps({{\"session_id\": session}}).encode()\n    with zipfile.ZipFile(root / name, \"w\") as z:\n        z.writestr(\"client_info.json\", info)\n        z.writestr(\"collection_context.json\", context)\npack(\"a.zip\", \"H1\", \"S1\")\npack(\"b.zip\", \"H2\", \"S2\")\n",
        dir
    );
    assert!(std::process::Command::new("python3").arg("-c").arg(script).status().unwrap().success());
    for name in ["a.zip", "b.zip"] {
        let out = bin().args(["collect", "--case"]).arg(&dir).arg(dir.join(name)).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }
    let hosts = bin().args(["hosts", "--case"]).arg(&dir).output().unwrap();
    let listed = String::from_utf8_lossy(&hosts.stdout);
    assert!(listed.contains("H1\tshared\tH1.plant.local\twindows\tamd64"), "{listed}");
    assert!(listed.contains("H2\tshared\tH2.plant.local\twindows\tamd64"), "{listed}");
    let collections = bin().args(["collections", "--case"]).arg(&dir).output().unwrap();
    let sessions = String::from_utf8_lossy(&collections.stdout);
    assert!(sessions.contains("S1\tH1"), "{sessions}");
    assert!(sessions.contains("S2\tH2"), "{sessions}");
}

#[test]
fn marketplace_install_and_match_respects_enabled_sources() {
    let store = std::env::temp_dir().join(format!("mcparser-market-{}.sqlite", std::process::id()));
    let _ = std::fs::remove_file(&store);
    let listed = bin().args(["marketplace", "--store"]).arg(&store).output().unwrap();
    assert!(listed.status.success(), "{}", String::from_utf8_lossy(&listed.stderr));
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(text.contains("malwarebazaar"));
    assert!(text.contains("not-installed"));

    let install = bin().args(["install-source", "--store"]).arg(&store).args(["--source", "malwarebazaar"]).output().unwrap();
    assert!(install.status.success(), "{}", String::from_utf8_lossy(&install.stderr));

    let list = std::env::temp_dir().join(format!("hashes-{}.txt", std::process::id()));
    std::fs::write(&list, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nnot-a-hash\n").unwrap();
    let imported = bin().args(["import-hashes", "--store"]).arg(&store).args(["--source", "malwarebazaar", "--file"]).arg(&list).output().unwrap();
    assert!(imported.status.success(), "{}", String::from_utf8_lossy(&imported.stderr));
    assert!(String::from_utf8_lossy(&imported.stdout).contains("imported 1"));

    let dir = case("market");
    std::fs::create_dir_all(&dir).unwrap();
    let matched = bin().args(["match-hashes", "--case"]).arg(&dir).args(["--store"]).arg(&store).output().unwrap();
    assert!(matched.status.success(), "{}", String::from_utf8_lossy(&matched.stderr));
    assert!(String::from_utf8_lossy(&matched.stdout).starts_with("hits "));

    let removed = bin().args(["uninstall-source", "--store"]).arg(&store).args(["--source", "malwarebazaar"]).output().unwrap();
    assert!(removed.status.success());
    let after = bin().args(["marketplace", "--store"]).arg(&store).output().unwrap();
    assert!(String::from_utf8_lossy(&after.stdout).contains("malwarebazaar\tMalwareBazaar full\tnot-installed"));
}


#[test]
fn ioc_upload_imports_pairs() {
    let dir = std::env::temp_dir().join(format!("mcparser-ioc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let csv = dir.join("iocs.csv");
    std::fs::write(&csv, "kind,value\nsha1,abc123\ndomain,evil.example\nip,203.0.113.5\n").unwrap();
    let store = dir.join("store.sqlite");
    let out = bin().args(["ioc-upload", "--file"]).arg(&csv).arg("--store").arg(&store).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("imported 3 IOCs"), "{text}");
    let again = bin().args(["ioc-upload", "--file"]).arg(&csv).arg("--store").arg(&store).output().unwrap();
    assert!(String::from_utf8_lossy(&again.stdout).contains("imported 0 IOCs"));
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 { crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 }; }
    }
    !crc
}

/// A minimal stored (uncompressed) zip with one member, built offline.
fn stored_zip(name: &str, data: &[u8]) -> Vec<u8> {
    let crc = crc32(data);
    let (n, len) = (name.len() as u16, data.len() as u32);
    let mut out = Vec::new();
    out.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(data);
    let cd_offset = out.len() as u32;
    let mut cd = vec![0x50, 0x4b, 0x01, 0x02, 20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    cd.extend_from_slice(&crc.to_le_bytes());
    cd.extend_from_slice(&len.to_le_bytes());
    cd.extend_from_slice(&len.to_le_bytes());
    cd.extend_from_slice(&n.to_le_bytes());
    cd.extend_from_slice(&[0u8; 12]);
    cd.extend_from_slice(&0u32.to_le_bytes());
    cd.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&cd);
    out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 1, 0, 1, 0]);
    out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn h(c: char, n: usize) -> String { std::iter::repeat(c).take(n).collect() }

const MB_HEADER: &str = "# MalwareBazaar recent export (synthetic test data)\n# \"first_seen_utc\",\"sha256_hash\",\"md5_hash\",\"sha1_hash\",\"reporter\",\"file_name\",\"file_type_guess\",\"mime_type\",\"signature\",\"clamav\",\"vtpercent\",\"imphash\",\"ssdeep\",\"tlsh\"\n";

fn mb_row(seen: &str, sha256: &str, md5: &str, sha1: &str, file: &str, sig: &str) -> String {
    format!("\"{seen}\", \"{sha256}\", \"{md5}\", \"{sha1}\", \"tester\", \"{file}\", \"exe\", \"application/x-dosexec\", \"{sig}\", \"n/a\", \"n/a\", \"n/a\", \"n/a\", \"n/a\"\n")
}

#[test]
fn bazaar_dump_import_query_match_and_uninstall() {
    let base = case("bazaar");
    std::fs::create_dir_all(&base).unwrap();
    let store = base.join("marketplace.sqlite");
    let st = |c: &mut Command| -> std::process::Output { c.output().unwrap() };
    let ok = |o: &std::process::Output| assert!(o.status.success(), "{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));

    let config = r#"{"lookupEndpoint":"http://127.0.0.1:9/api/v1/","exportUrl":"http://127.0.0.1:9/v2/files/exports/{key}/recent.csv","onlineLookup":false,"onlineMax":25}"#;
    let install = st(bin().args(["install-source", "--store"]).arg(&store).args(["--source", "malwarebazaar", "--config", config]));
    ok(&install);
    let cfg = st(bin().args(["source-config", "--store"]).arg(&store).args(["--source", "malwarebazaar"]));
    ok(&cfg);
    assert_eq!(String::from_utf8_lossy(&cfg.stdout).trim(), config);

    // First load: a plain CSV with two samples.
    let csv1 = base.join("recent.csv");
    let mut text = MB_HEADER.to_string();
    text.push_str(&mb_row("2026-10-01 00:00:00", &h('a', 64), &format!("{}a", h('1', 31)), &h('b', 40), "evil.exe", "AgentTesla"));
    text.push_str(&mb_row("2026-10-02 00:00:00", &h('c', 64), &format!("{}a", h('2', 31)), &h('d', 40), "worse.dll", "n/a"));
    std::fs::write(&csv1, &text).unwrap();
    let first = st(bin().args(["bazaar-import", "--store"]).arg(&store).arg("--file").arg(&csv1));
    ok(&first);
    let out = String::from_utf8_lossy(&first.stdout).to_string();
    assert!(out.contains("added\t2") && out.contains("updated\t0") && out.contains("total\t2"), "{out}");
    assert!(base.join("malwarebazaar.duckdb").exists());

    // Second load: zipped, one changed signature, one new, one unchanged.
    let mut text2 = MB_HEADER.to_string();
    text2.push_str(&mb_row("2026-10-01 00:00:00", &h('a', 64), &format!("{}a", h('1', 31)), &h('b', 40), "evil.exe", "AgentTesla"));
    text2.push_str(&mb_row("2026-10-02 00:00:00", &h('c', 64), &format!("{}a", h('2', 31)), &h('d', 40), "worse.dll", "Formbook"));
    text2.push_str(&mb_row("2026-10-03 00:00:00", &h('e', 64), &format!("{}a", h('3', 31)), &h('f', 40), "new.bin", "Lumma"));
    let zip = base.join("recent.zip");
    std::fs::write(&zip, stored_zip("recent.csv", text2.as_bytes())).unwrap();
    let second = st(bin().args(["bazaar-import", "--store"]).arg(&store).arg("--file").arg(&zip));
    ok(&second);
    let out = String::from_utf8_lossy(&second.stdout).to_string();
    assert!(out.contains("added\t1") && out.contains("updated\t1") && out.contains("unchanged\t1") && out.contains("total\t3"), "{out}");

    let info = st(bin().args(["bazaar-info", "--store"]).arg(&store));
    ok(&info);
    let out = String::from_utf8_lossy(&info.stdout).to_string();
    assert!(out.contains("rows\t3") && out.contains("newest_first_seen\t2026-10-03"), "{out}");

    // SQL editor without a case.
    let q = st(bin().args(["query", "--format", "csv", "--store"]).arg(&store).arg("SELECT sha256, md5, sha1, note FROM malwarebazaar WHERE note LIKE '%Formbook%'"));
    ok(&q);
    let out = String::from_utf8_lossy(&q.stdout).to_string();
    assert!(out.contains(&h('c', 64)) && out.contains(&format!("{}a", h('2', 31))) && out.contains(&h('d', 40)), "{out}");

    // A case with amcache and events holding hashes.
    let dir = base.join("case");
    std::fs::create_dir_all(&dir).unwrap();
    let setup = format!(
        "CREATE TABLE amcache AS SELECT * FROM (VALUES ('H1', 'C:\\\\x\\\\evil.exe', 'evil.exe', '{}'), ('H1', 'C:\\\\ok.exe', 'ok.exe', '{}')) t(host_id, path, name, sha1)",
        h('B', 40), h('9', 40));
    ok(&st(bin().args(["query", "--case"]).arg(&dir).arg(setup)));
    let ev = format!("CREATE TABLE events AS SELECT 'H2' AS host_id, 'H2' AS computer, 'Sysmon' AS provider, 1 AS event_id, 'Hashes=MD5={},SHA256={}' AS event_data", format!("{}a", h('3', 31)).to_uppercase(), h('7', 64));
    ok(&st(bin().args(["query", "--case"]).arg(&dir).arg(ev)));

    // SQL editor with a case.
    let q = st(bin().args(["query", "--format", "csv", "--case"]).arg(&dir).arg("--store").arg(&store).arg("SELECT count(*) AS n FROM malwarebazaar"));
    ok(&q);
    assert!(String::from_utf8_lossy(&q.stdout).contains('3'));

    let m = st(bin().args(["bazaar-match", "--case"]).arg(&dir).arg("--store").arg(&store));
    ok(&m);
    let out = String::from_utf8_lossy(&m.stdout).to_string();
    assert!(out.contains("progress\t100"), "{out}");
    assert!(out.contains("counts\t4\t2\t2\t3"), "{out}");
    let report = out.lines().find(|l| l.starts_with("report\t")).unwrap();
    let parts: Vec<&str> = report.split('\t').collect();
    let csv = std::fs::read_to_string(parts[1]).unwrap();
    assert!(csv.contains("H1,amcache") && csv.contains("AgentTesla") && csv.contains("local dump"), "{csv}");
    assert!(csv.contains("H2,events") && csv.contains("Lumma"), "{csv}");
    let md = std::fs::read_to_string(parts[2]).unwrap();
    assert!(md.contains("Dump rows: 3") && md.contains("recent export"), "{md}");
    let unmatched = std::fs::read_to_string(parts[3]).unwrap();
    assert!(unmatched.contains(&h('7', 64)) && unmatched.contains(&h('9', 40)));
    assert!(!parts[4].is_empty(), "run id");
    let hm = st(bin().args(["hunt-matches", "--case"]).arg(&dir).args(["--run", parts[4]]));
    ok(&hm);
    assert!(String::from_utf8_lossy(&hm.stdout).contains(&format!("malwarebazaar:{}", h('a', 64))));

    // Online lookup results get attributed and appended.
    let found = base.join("found.tsv");
    std::fs::write(&found, format!("{}\t{}\tRedLine\tonline.exe\n", h('7', 64), h('7', 64))).unwrap();
    let on = st(bin().args(["bazaar-online-hits", "--case"]).arg(&dir).arg("--file").arg(&found).args(["--csv", parts[1], "--md", parts[2], "--looked-up", "2"]));
    ok(&on);
    assert!(String::from_utf8_lossy(&on.stdout).contains("online\t1"));
    let csv = std::fs::read_to_string(parts[1]).unwrap();
    assert!(csv.contains("RedLine") && csv.contains("online lookup"), "{csv}");
    assert!(std::fs::read_to_string(parts[2]).unwrap().contains("Matched (online lookup): 1"));

    // Uninstall deletes the dump database.
    ok(&st(bin().args(["uninstall-source", "--store"]).arg(&store).args(["--source", "malwarebazaar"])));
    assert!(!base.join("malwarebazaar.duckdb").exists());
    let gone = st(bin().args(["bazaar-info", "--store"]).arg(&store));
    assert!(String::from_utf8_lossy(&gone.stdout).contains("rows\t0"));
}
