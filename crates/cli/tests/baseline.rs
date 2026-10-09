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
    for command in ["ingest", "query", "stats", "queries", "save-query", "notes", "save-note", "runs", "save-run", "chats", "save-chat", "handoff", "open-handoff", "save-analyst", "hosts", "collect"] {
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
fn collection_keeps_raw_files_and_records_the_zip_hash() {
    let dir = case("collection");
    std::fs::create_dir_all(&dir).unwrap();
    let zip_path = dir.join("collector.zip");
    let script = format!(
        "import json, zipfile\nfrom pathlib import Path\nouter = Path({:?})\nnested = outer.with_suffix('.nested.zip')\ninfo = json.dumps({{\"HostID\":\"H1\",\"Hostname\":\"plant\",\"Fqdn\":\"plant.local\",\"Platform\":\"windows\",\"Architecture\":\"amd64\"}}).encode()\nwith zipfile.ZipFile(nested, 'w') as z:\n    z.writestr('client_info.json', info)\n    z.writestr('NTUSER.DAT', b'ntuser-bytes')\n    z.writestr('SOFTWARE.hiv', b'software-bytes')\n    z.writestr('Prefetch/NOTEPAD.PF', b'pf-bytes')\nwith zipfile.ZipFile(outer, 'w') as z:\n    z.writestr('client_info.json', info)\n    z.write(nested, 'uploads/collection.zip')\n",
        zip_path
    );
    let made = std::process::Command::new("python3").arg("-c").arg(script).status().unwrap();
    assert!(made.success());
    let out = bin().args(["collect", "--case"]).arg(&dir).arg(&zip_path).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(text.contains("host H1 plant windows amd64"), "{text}");
    assert!(text.contains("kept "), "{text}");
    let files = std::fs::read_dir(dir.join("files")).unwrap().next().unwrap().unwrap().path();
    assert_eq!(std::fs::read(files.join("uploads/collection.zip/NTUSER.DAT")).unwrap(), b"ntuser-bytes");
    assert_eq!(std::fs::read(files.join("uploads/collection.zip/SOFTWARE.hiv")).unwrap(), b"software-bytes");
    assert_eq!(std::fs::read(files.join("uploads/collection.zip/Prefetch/NOTEPAD.PF")).unwrap(), b"pf-bytes");
    assert!(!dir.join("events.duckdb").exists());
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
