# Changelog

## 0.1.0 — 2026-10-05

First release. Offline `.evtx` ingest, SQL query, and a macOS desktop app.

### Added

- Rust workspace: `evtx-read`, `model`, `case`, `cli`.
- `mcparser ingest --case <dir> <file.evtx> [more.evtx...]`
- `mcparser query --case <dir> [--format table|csv|jsonl] "<sql>"`
- `mcparser stats --case <dir>` for time range, channels, providers, and event ids
- Case directory with `events.duckdb` and `catalog.sqlite`
- Skip a file whose SHA-256 is already in the catalog
- Replace rows when the same path has a new hash
- Row columns: `source_sha256`, `record_id`, `event_id`, `channel`, `provider`, `computer`, `time_created`, `event_data`
- `event_data` stored as JSON, filterable with `json_extract_string`
- CSV query output includes column names
- Desktop UI in `ui/`: open an `.evtx`, create the case beside it, summarise the file, edit SQL, and export the grid as CSV
- Case summary: file name, size, SHA-256, event count, unique event ids, first and last time, channels, providers
- Menus: File, Edit, Window, Help. About names Daniel de Jager and links the repository and LinkedIn profile
- Unsigned macOS disk image, `McParser-0.1.0-arm64.dmg`, attached to this release

### Proven

- Security fixture: 2261 records, 0 parse errors, 2261 mapped
- Event 4608 count 40, event 4624 count 583
- `TargetUserName = SYSTEM` on event 4624 returns 377
- Same-byte copy is skipped
- Replacing that path with the System sample leaves one source and 1881 rows
- Installed Mac app opens after the icon is no longer written into the packaged archive

### Not in this release

- Signed or notarised macOS build. Gatekeeper warns; right-click the app and choose Open
- Ubuntu and Windows packages
- Homebrew, winget
- Rendered provider messages
- Shell, saved queries, query macros
- Automated `cargo test` locks for the fixture counts

Install and usage: [README.md](README.md).
