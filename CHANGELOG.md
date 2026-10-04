# Changelog

## 0.1.0 — 2026-10-05

First CLI release. Offline `.evtx` ingest and SQL query, before a UI.

### Added

- Rust workspace: `evtx-read`, `model`, `case`, `cli`. `query` is reserved and empty.
- `mcparser ingest --case <dir> <file.evtx> [more.evtx...]`
- `mcparser query --case <dir> [--format table|csv|jsonl] "<sql>"`
- `mcparser stats --case <dir>` for time range, channels, providers, and event ids
- Case directory with `events.duckdb` and `catalog.sqlite`
- Skip a file whose SHA-256 is already in the catalog
- Replace rows when the same path has a new hash
- Row columns: `source_sha256`, `record_id`, `event_id`, `channel`, `provider`, `computer`, `time_created`, `event_data`
- `event_data` stored as JSON, filterable with `json_extract_string`

### Proven

- Security fixture: 2261 records, 0 parse errors, 2261 mapped
- Event 4608 count 40, event 4624 count 583
- `TargetUserName = SYSTEM` on event 4624 returns 377
- Same-byte copy is skipped
- Replacing that path with the System sample leaves one source and 1881 rows

### Not in this release

- Packaged binaries, Homebrew, winget
- Rendered provider messages
- Shell, saved queries, query macros
- Automated `cargo test` locks for the fixture counts

Install and usage: [README.md](README.md).
