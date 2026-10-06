# McParser

Offline Windows event log parser. Point it at `.evtx` files and query them with SQL. No Windows Event Log API, so the same tool runs on macOS, Ubuntu, and Windows.

Current release: **[0.2.3](https://github.com/danieldejager/mcparser/releases/tag/v0.2.3)**.

What is next: [ROADMAP.md](ROADMAP.md). Chat design: [docs/grok-chat.md](docs/grok-chat.md).

![McParser stack](docs/Yenbd.jpg)

## Install

### macOS app

Download `McParser-0.2.3-arm64.dmg` from the [0.2.3 release](https://github.com/danieldejager/mcparser/releases/tag/v0.2.3). Open it and drag McParser to Applications. The image is unsigned, so Gatekeeper will warn. Right-click McParser and choose Open.

File → Open EVTX creates a case beside the log and ingests it.

### Windows app

Download `McParser Setup 0.2.3.exe` from the [0.2.3 release](https://github.com/danieldejager/mcparser/releases/tag/v0.2.3). This installer is ARM64. It runs on Windows 11 on Apple silicon. It is not an Intel build.

### From source

You need a Rust toolchain. DuckDB and SQLite are compiled into the binary. Do not install them separately. The first build compiles DuckDB and can take several minutes.

macOS, with Homebrew:

```bash
git clone https://github.com/danieldejager/mcparser.git
cd mcparser
brew install rust
cargo build --release
cp target/release/mcparser /usr/local/bin/mcparser
```

Ubuntu:

```bash
git clone https://github.com/danieldejager/mcparser.git
cd mcparser
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
cargo build --release
```

Windows ARM64: install Rust from https://rustup.rs and the Visual Studio 2022 Build Tools with the ARM64 C++ workload. In the Developer PowerShell for VS 2022:

```powershell
cargo build --release
```

The binary is `target\release\mcparser.exe`.

The desktop app:

```bash
cargo build -p mcparser
cd ui
npm install
npm start
```

## Desktop

The app is an Electron shell around the parser. File → Open EVTX creates `<file>.mcp` next to the log. The case pane shows file name, size, SHA-256, event count, unique event ids, time range, channels, and providers. Run SQL in the editor. Export CSV writes the current grid, including the column names.

Saved queries live in the case. Save query asks for a name. The list is under Queries. A click loads the SQL. Run executes it. Copying the `.mcp` folder takes the queries with it.

A note is a record id and a sentence. Click a result row whose query includes `record_id`. The note remembers the SQL that was open. Audit → Notes lists every note. A click loads that query and runs it.

## AI Model

AI Integration connects a vendor. The dropdown under AI Model is Grok, Claude, or OpenAI. Each key is encrypted with the macOS keychain or Windows DPAPI, in its own file, not in the case. A vendor with no key says `Configure this integration` and no request is sent.

Ask writes one SELECT. McParser runs it on the open case, capped at 50 rows, and the answer is shown beside the SQL. The first ask in a session asks you to confirm that row text will leave the machine. The `.evtx` file and the DuckDB file stay here. Replies are prefixed with the vendor.

## CLI

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
```

`--format` is `table` (default), `csv`, or `jsonl`. CSV includes a header row.

A case directory contains `events.duckdb` and `catalog.sqlite`. Do not commit it. Ingest skips a file whose bytes are already in the catalog. The same path with a new hash replaces the old rows.

Columns are `source_sha256`, `record_id`, `event_id`, `channel`, `provider`, `computer`, `time_created`, and `event_data`. `event_data` is JSON. Filter a field with `json_extract_string(event_data, '$.TargetUserName')`.

## What 0.2.3 does not do

Rendered message text is not in the `.evtx` file. It lives in the provider DLL, so 0.2.3 does not produce the English sentence. There is no shell. The macOS image is not notarised. The Windows installer is ARM64 only. There is no Ubuntu package. A failed vendor does not fall through to another.

## Stack

| Layer | Choice |
| --- | --- |
| Language | Rust parser, Electron desktop shell |
| Reader | `evtx` crate |
| Query | DuckDB |
| Catalog | SQLite |
| Commands | `ingest`, `query`, `stats`, `queries`, `save-query`, `notes`, `save-note` |
| Desktop | Electron, in `ui/` |
| Chat | Grok, Claude, or OpenAI. Keys in the OS keychain |

```text
crates/evtx-read
crates/model
crates/case
crates/query
crates/cli
ui/
```

Author: Daniel de Jager. https://github.com/danieldejager/mcparser
