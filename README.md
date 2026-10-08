# McParser

Offline Windows event log parser. Open a `.evtx` file and query it with SQL. The same case runs on macOS, Windows, and Ubuntu. The log never has to be on a Windows machine.

Current release: **[0.2.6](https://github.com/danieldejager/mcparser/releases/tag/v0.2.8)**.

What is next: [McParser project](https://github.com/users/danieldejager/projects/2/views/1).

![McParser 0.2.6](docs/mcparser2.png)

A version tag builds the three installers. The workflow is `.github/workflows/release.yml`. You do not package a release by hand.

## Install

Download the file for your machine from the [0.2.6 release](https://github.com/danieldejager/mcparser/releases/tag/v0.2.6).

| Machine | File | Install |
| --- | --- | --- |
| Mac, Apple silicon | `McParser-0.2.6-arm64.dmg` | Open the image and drag McParser to Applications |
| Windows 11, ARM | `McParser Setup 0.2.6.exe` | Run the setup |
| Ubuntu, Intel or AMD | `McParser-0.2.6-amd64.deb` | `sudo apt install ./McParser-0.2.6-amd64.deb` |
| Ubuntu, ARM | `McParser-0.2.6-arm64.deb` | `sudo apt install ./McParser-0.2.6-arm64.deb` |

The Mac image is unsigned. A download from the browser is marked, and Gatekeeper then says the app is damaged. That is the missing signature, not a broken disk image. Clear the mark and open it:

```bash
xattr -cr /Applications/McParser.app
open /Applications/McParser.app
```

Signing and notarisation wait until the product is ready. The Windows setup is ARM64. It is not an Intel build. The packages are built by GitHub Actions when a `v*` tag is pushed.

## The window

File, then Open EVTX. Pick a log. McParser creates `<file>.mcp` beside it and ingests the file. That folder is the case. It holds `events.duckdb` and `catalog.sqlite`. Copy the folder and the other analyst has the same case.

The left pane collapses.

**Case.** Path, file name, size, SHA-256, event count, unique event ids, time range, channels, and providers. Refresh case reads the folder again. Analyst is the name written on the next run.

**Queries.** Save query asks for a name. A click loads that SQL into the editor. Run executes it.

**Hunts.** Choose a MITRE tactic, then a technique. A click loads that hunt. The first set is successful logon, network logon, failed logon, explicit credentials, account created, account changed, special privileges, and one account. One account still says `USER`. Replace it before Run.

The editor shows line numbers. Run sends the SQL to the case. Export CSV writes the current grid, including the column names. Click a result row whose query includes `record_id` to write a note.

**Audit.** Notes lists every note. Runs lists every successful Run: the SQL, the time, the row count, the hunt label, the previous run, the analyst, and whether it was a replay. A click there loads the SQL and marks the next run as a replay. Trail puts notes and runs on one list. Export trail writes `trail.csv`.

**AI Model.** The dropdown is Grok, Claude, or OpenAI. AI Integration, then Connect, saves that vendor's key. The key is encrypted with the macOS keychain or Windows DPAPI. It is not stored in the case. A vendor with no key says `Configure this integration` and no request is sent.

Ask writes one SELECT, runs it, and shows the answer beside the SQL. The first ask in a session asks you to confirm that row text will leave the machine. The `.evtx` file and the DuckDB file stay here. The reply is prefixed with the vendor. A completed ask is stored in the case. Open the case again and the question, the SELECT, and the answer are already in the pane. The other machine can read that transcript. It needs its own key to ask again.

## The command line

The app is the usual way in. The `mcparser` binary is the same parser.

```bash
mcparser ingest --case case.mcp Security.evtx System.evtx
mcparser stats --case case.mcp
mcparser query --case case.mcp \
  "SELECT event_id, count(*) FROM events GROUP BY event_id ORDER BY event_id"
mcparser query --case case.mcp --format csv \
  "SELECT time_created, event_id, json_extract_string(event_data, '$.TargetUserName') FROM events WHERE event_id = 4624 LIMIT 20"
mcparser save-query --case case.mcp --name fsir \
  "SELECT event_id, count(*) FROM events WHERE json_extract_string(event_data, '$.TargetUserName') = 'fsir' GROUP BY event_id"
mcparser queries --case case.mcp
mcparser save-note --case case.mcp --record 51 "fsir account created, start of the trail"
mcparser notes --case case.mcp
mcparser runs --case case.mcp
mcparser chats --case case.mcp
```

`--format` is `table`, `csv`, or `jsonl`. CSV includes a header row. Run these from the directory that contains `case.mcp`, or pass a full path. A relative path is resolved from the current directory.

A second ingest of the same bytes is skipped. The same path with a new hash replaces the old rows.

Columns are `source_sha256`, `record_id`, `event_id`, `channel`, `provider`, `computer`, `time_created`, and `event_data`. `event_data` is JSON. Filter a field with `json_extract_string(event_data, '$.TargetUserName')`.

A command-line query is not a run. Only the Run button writes the trail. A failed ask is not stored.

## Build from source

You need Rust. DuckDB and SQLite are compiled into the binary. Do not install them separately.

```bash
git clone https://github.com/danieldejager/mcparser.git
cd mcparser
cargo build --release
cd ui
npm install
npm start
```

The first build compiles DuckDB and can take several minutes. On Windows ARM, use the ARM64 developer shell so `link.exe` is the ARM64 linker.

Do not commit a case, `node_modules`, or `ui/dist`.

 

 

Author: Daniel de Jager. https://github.com/danieldejager/mcparser
