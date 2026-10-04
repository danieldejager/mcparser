# McParser

Offline Windows event log parser. Point it at `.evtx` files and query them with SQL. No Windows Event Log API, so the same tool runs on macOS, Ubuntu, and Windows.

Current release: **0.1.0**. This is the CLI gate before a UI. There is no packaged binary yet. Install from source.

![McParser stack](docs/Yenbd.jpg)

## Install

You need a Rust toolchain. DuckDB and SQLite are compiled into the binary. Do not install them separately.

macOS, with Homebrew:

```bash
git clone https://github.com/danieldejager/mcparser.git
cd mcparser
brew install rust
cargo build --release
cp target/release/mcparser /usr/local/bin/mcparser
mcparser
```

Ubuntu:

```bash
git clone https://github.com/danieldejager/mcparser.git
cd mcparser
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
cargo build --release
```

Windows: install Rust from https://rustup.rs, then `cargo build --release` in this repo. The binary is `target\release\mcparser.exe`.

The first build compiles DuckDB and can take several minutes.

## Usage

```bash
mcparser ingest --case case.mcp Security.evtx System.evtx
mcparser stats --case case.mcp
mcparser query --case case.mcp \
  "SELECT event_id, count(*) FROM events GROUP BY event_id ORDER BY event_id"
mcparser query --case case.mcp --format csv \
  "SELECT time_created, event_id, json_extract_string(event_data, '$.TargetUserName') FROM events WHERE event_id = 4624 LIMIT 20"
```

`--format` is `table` (default), `csv`, or `jsonl`.

A case directory contains `events.duckdb` and `catalog.sqlite`. Do not commit it. Ingest skips a file whose bytes are already in the catalog. The same path with a new hash replaces the old rows.

Columns are `source_sha256`, `record_id`, `event_id`, `channel`, `provider`, `computer`, `time_created`, and `event_data`. `event_data` is JSON. Filter a field with `json_extract_string(event_data, '$.TargetUserName')`.

## What 0.1.0 does not do

Rendered message text is not in the `.evtx` file. It lives in the provider DLL, so 0.1.0 does not produce the English sentence. There is no shell, no saved queries, and no installer. `crates/query` is still empty. SQL runs in the case crate.

## Stack

| Layer | Choice |
| --- | --- |
| Language | Rust, one CLI binary |
| Reader | `evtx` crate |
| Query | DuckDB |
| Catalog | SQLite |
| Commands | `ingest`, `query`, `stats` |

```text
crates/evtx-read
crates/model
crates/case
crates/query
crates/cli
```
