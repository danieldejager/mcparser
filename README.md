# McParser

Offline Windows event log parser. Point it at `.evtx` files and query them with SQL. No Windows Event Log API, so the same binary runs on macOS, Ubuntu, and Windows.

## What it does

- Reads offline `.evtx` logs (BinXml). Corrupt chunks are warnings, not a hard stop
- Normalizes each record to a stable row: time, channel, provider, event id, computer, SID, and `event_data` JSON
- Stores a case directory: SQLite catalog plus DuckDB or Parquet events
- Runs real SQL through embedded DuckDB

v1 returns structured fields and reconstructed XML. The English message text usually lives in a provider DLL, which is not on macOS or Ubuntu, so rendered messages are not a parse dependency.

## Stack

One Rust CLI binary. Targets are macOS, Ubuntu, and Windows. Commands are `ingest`, `query`, `shell`, and `stats`.

Offline `.evtx` files go into three modules:

- `evtx` crate: BinXml reader
- model: normalized event row
- case catalog: SQLite

Those land in a DuckDB query engine. Output is table, JSONL, or CSV.

| Layer | Choice |
| --- | --- |
| Language | Rust, one CLI binary |
| Reader | `evtx` crate |
| Query | DuckDB |
| Catalog | SQLite |
| CLI | `clap` |

Users install the binary, not Rust or DuckDB.

```sql
SELECT time_created, computer, event_id, event_data
FROM events
WHERE channel = 'Security'
  AND event_id IN (4624, 4625)
  AND time_created >= TIMESTAMP '2024-01-01'
ORDER BY time_created;
```

## Layout

```text
crates/evtx-read
crates/model
crates/case
crates/query
crates/cli
```

Case directory: `catalog.sqlite`, event store, source hashes. Row identity is `(sha256 of file, record_id)`.
