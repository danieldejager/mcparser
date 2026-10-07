# Changelog

## 0.2.5 — 2026-10-07

A run is part of the case. Audit lists the trail.

### Added

- A successful Run stores the SQL, the time, and the row count in `catalog.sqlite`
- Each run records the previous run id, so the list is a chain
- A hunt click labels the run. An editor run is labelled `query`
- Analyst name, stored on the run. The field stays in the window
- A click in Audit → Runs is a `replay`, not a second hunt
- Notes store a time. Audit → Trail lists notes and runs together
- Audit → Export trail writes `trail.csv`
- `mcparser save-run` and `mcparser runs`

### Not in this release

- A command-line query is not a run. Only the Run button writes the trail
- A trail line does not load the SQL. Audit → Runs does
- Chat is not on the trail
- New installer is built by the tag workflow when the runners accept the job

## 0.2.4 — 2026-10-06

Hunts are named SQL, filtered by MITRE tactic and technique. A click loads the query. Run still executes it.

### Added

- Hunts in the case pane: Successful logon, Network logon, Failed logon, Explicit credentials, Account created, Account changed, Special privileges, One account
- Tactic and technique selectors. The list shows only the hunts for that pair
- Case, Queries, and Hunts collapse
- Mappings: T1078, T1021, T1110, T1136, T1098, T1087

### Not in this release

- The other 20 or so Security-log hunts. This is the first set
- A note on a hunt is still a note on a record id

## 0.2.3 — 2026-10-06

The chat pane can use Grok, Claude, or OpenAI. The analyst picks the vendor. Each key is stored on its own.

### Added

- AI Integration menu. Connect Grok, Connect Claude, Connect OpenAI, Forget key
- AI Model pane with a vendor dropdown: Grok, Claude, OpenAI
- A vendor with no key says Configure this integration and no request is sent
- Claude calls `https://api.anthropic.com/v1/messages` with `claude-sonnet-4-5-20250929`
- OpenAI calls `https://api.openai.com/v1/chat/completions` with `gpt-4.1`
- Grok stays on `https://api.x.ai/v1/responses`
- Each key is encrypted with the macOS keychain or Windows DPAPI, in its own file: `grok-key.bin`, `claude-key.bin`, `openai-key.bin`
- Replies are prefixed with the vendor: `Grok:`, `Claude:`, `OpenAI:`
- The parser process does not inherit `XAI_API_KEY`, `ANTHROPIC_API_KEY`, or `OPENAI_API_KEY`
- The case file still stays on the machine. One SELECT, 50-row cap, confirm on the first ask

### Not in this release

- New installer. Build from `providers` to run it
- A failed vendor does not fall through to another

## 0.2.2 — 2026-10-06

A note is a record id and a sentence, stored in the case. Audit, then Notes, lists them after the fact.

### Added

- `mcparser save-note --case <dir> --record <id> [--sql <sql>] "<sentence>"`
- `mcparser notes --case <dir>`
- Notes stored in `catalog.sqlite`. The same record id replaces the sentence
- The note remembers the SQL that was in the editor when it was saved
- Click a result row to open the note sheet. The row must include `record_id`
- The grid shows a note column when `record_id` is selected
- Audit menu, Notes. The screen lists record, sentence, and query. A click loads that SQL and runs it

### Proven

- Record 51, the `fsir` account creation, can be marked as the start of the trail
- The note survives in the case folder

### Not in this release

- New installer. Build from `notes-in-a-row` to run it
- A note on a count query. There is no record id to attach it to
- Rendered provider messages

## 0.2.1 — 2026-10-06

Saved queries live in the case. Copy the `.mcp` folder and the queries go with it.

### Added

- `mcparser save-query --case <dir> --name <name> "<sql>"`
- `mcparser queries --case <dir>`
- Queries stored in `catalog.sqlite`, one name, one SELECT. The same name replaces the SQL
- Case pane lists saved queries. A click loads the editor. Run still executes it
- Save query asks for the name in the window. Electron does not show a browser prompt
- A relative case path in the window resolves from the repo, not from `ui/`

### Proven

- Security fixture re-ingested into `fixtures/data2.mcp`: 2261 events
- Saved query `fsir` returns 4720, 4722, 4723, 4724, 4738, 4624 (84), 4634 (8), 4647 (36), 4648 (43)
- The window lists `fsir` and `default` after Save query

### Not in this release

- New installer. Build from `saved-queries` to run it
- Query runs and notes are not stored yet
- Rendered provider messages

## 0.2.0 — 2026-10-06

Grok chat in the desktop app. Ask about the open case in plain language. The `.evtx` file and the DuckDB file stay on the machine.

### Added

- Grok menu between Window and Help: Connect Grok, Forget key, Show chat
- Chat pane: question, the SELECT that was run, and the answer
- Run on a reply copies that SQL into the editor and runs it with no row cap
- The key is encrypted with Electron safeStorage before it is written. macOS uses the login keychain. Windows uses DPAPI. The ciphertext is `grok-key.bin` in the app data folder, not in the case
- Forget key deletes that file
- First ask in a session asks the analyst to confirm that row text will leave the machine
- Only one SELECT is accepted. ATTACH, COPY, PRAGMA, and writes are rejected
- The local parser runs the SELECT with a 50-row cap. Those rows, the question, and the column names are what may be sent to `https://api.x.ai`
- The parser process does not inherit `XAI_API_KEY`

### Proven

- Security fixture, event 4624, `TargetUserName = SYSTEM`: 377
- Account `fsir`: 4720 created, 4722 enabled, 4738 changed, 4724 password reset, 4648 explicit logon from `127.0.0.1`
- A 403 before credits was a billing refusal. The same question succeeded after credits were added

### Not in this release

- New macOS or Windows installer. The 0.1.0 disk image and setup do not include the chat. Build from this branch to run it
- Signed or notarised macOS build
- Intel or x64 Windows installer
- Ubuntu package
- Rendered provider messages
- Saved chats

## 0.1.0 — 2026-10-05

First release. Offline `.evtx` ingest, SQL query, and desktop apps for macOS and Windows.

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
- Unsigned Windows installer, `McParser Setup 0.1.0.exe`, for ARM64 Windows. It runs on Windows 11 on Apple silicon. It is not an Intel build

### Proven

- Security fixture: 2261 records, 0 parse errors, 2261 mapped
- Event 4608 count 40, event 4624 count 583
- `TargetUserName = SYSTEM` on event 4624 returns 377
- Same-byte copy is skipped
- Replacing that path with the System sample leaves one source and 1881 rows
- Installed Mac app opens after the icon is no longer written into the packaged archive
- Windows ARM64 release parser builds with the Visual Studio 2022 ARM64 tools

### Not in this release

- Signed or notarised macOS build. Gatekeeper warns; right-click the app and choose Open
- Intel or x64 Windows installer
- Ubuntu package
- Homebrew, winget
- Rendered provider messages
- Shell, saved queries, query macros
- Automated `cargo test` locks for the fixture counts

Install and usage: [README.md](README.md).
