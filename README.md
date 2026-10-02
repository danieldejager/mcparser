# McParser

Offline Windows event log parser. Point it at `.evtx` files and query them with SQL. No Windows Event Log API, so the same binary runs on macOS, Ubuntu, and Windows.

![McParser stack](docs/Yenbd.jpg)

## What it does

- Reads offline `.evtx` logs (BinXml), including corrupt-chunk warnings instead of a hard stop
- Normalizes each record to a stable row: time, channel, provider, event id, computer, SID, and `event_data` JSON
- Stores a case directory: SQLite catalog plus DuckDB or Parquet events
- Runs real SQL through embedded DuckDB

v1 returns structured fields and reconstructed XML. The English message text usually lives in a provider DLL, which is not on macOS or Ubuntu, so rendered messages are not a parse dependency.

## Stack

| Layer | Choice |
| --- | --- |
| Language | Rust, one CLI binary |
| Reader | `evtx` crate |
| Query | DuckDB |
| Catalog | SQLite |
| CLI | `clap`: `ingest`, `query`, `shell`, `stats` |

Targets: macOS, Ubuntu, Windows. Users install the binary, not Rust or DuckDB.

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
