# Schema

A case is two files. `events.duckdb` is the timeline. `catalog.sqlite` is the case. The marketplace hash store is a third file, on the machine, and it does not travel with the case.

Every timeline table carries `host_id`. That is the join to `hosts` in the catalog. A case with one host has one value. A case with several has one per host.

## events.duckdb

This is the file you query. The tables below are created as the matching artifact is ingested. An empty table means that artifact was not in the collection.

### events

One row per Windows event. This is the table the SQL editor opens against.

| column | purpose |
|---|---|
| source_sha256 | Hash of the file the row came from. Joins to `sources`. |
| record_id | The record id inside that file. |
| event_id | The numeric event id, for example 4624. |
| channel | Security, System, Application, and so on. |
| provider | The provider name, for example Microsoft-Windows-Security-Auditing. |
| computer | The computer name in the event. |
| time_created | The event time, ISO 8601. |
| event_data | The event fields as a JSON string. |
| host_id | The host this file belongs to. |
| log_name | The log file name. |

`event_data` is not a set of columns. A name such as `TargetUserName` lives inside the JSON. Pull it out with `json_extract_string`.

```sql
SELECT event_id, time_created, computer,
  json_extract_string(event_data, '$.TargetUserName') AS user
FROM events
WHERE event_id = 4624
ORDER BY time_created
```

If a filter returns nothing, look at one raw row first and read the keys.

```sql
SELECT event_data FROM events WHERE event_id = 4624 LIMIT 1
```

### prefetch

Windows Prefetch. One row per `.pf` file. `executable` is the name, `run_count` is how many times it ran, `last_run` is the last time.

```sql
SELECT executable, run_count, last_run
FROM prefetch
WHERE executable ILIKE '%powershell%'
ORDER BY run_count DESC
```

### amcache

The Amcache hive. `kind` is the entry type. `sha1` is the file hash when the hive has one. `path` is the path on the host.

```sql
SELECT name, path, sha1, publisher
FROM amcache
WHERE path ILIKE '%\\temp\\%'
```

### userassist

Explorer UserAssist. Programs the user launched from the shell. `run_count` and `last_run` are the useful columns.

```sql
SELECT name, run_count, last_run
FROM userassist
ORDER BY run_count DESC
LIMIT 20
```

### shimcache

Application Compatibility Cache. `path` is the file, `modified` is the recorded time, `executed` says whether it was run.

```sql
SELECT path, modified, executed
FROM shimcache
WHERE path ILIKE '%.exe'
ORDER BY modified DESC
```

### srum

System Resource Usage Monitor. `kind` is the SRUM table. `app` is the application, `user_sid` is the user, and the byte columns are the network totals for that row.

```sql
SELECT app, user_sid, sum(bytes_sent) AS sent, sum(bytes_received) AS received
FROM srum
GROUP BY 1, 2
ORDER BY sent + received DESC
```

### services

Services on the host. `path` is the binary, `user_id` is the account it runs as, `start_mode` is how it starts.

```sql
SELECT name, path, user_id, start_mode
FROM services
WHERE start_mode = 'Auto'
```

### tasks

Scheduled tasks. `path` is the task path, `command` is what it runs, `user_id` is the account.

```sql
SELECT path, command, user_id
FROM tasks
WHERE command ILIKE '%powershell%'
```

### PE tables

File > Analyze PE File writes `pe_*` tables. Every one joins on `sha256`. The file is parsed only, never run or loaded, and its bytes are not stored. `pe_files` has one row per file; `pe_sections`, `pe_imports`, `pe_exports`, `pe_resources`, `pe_indicators`, `pe_strings`, `pe_rich`, `pe_certificates`, `pe_version_info`, `pe_manifest`, `pe_icons` and `pe_checks` hold the parts. Indicators are hints, not verdicts. `pe_certificates.verified` is always false: signatures are parsed, not checked.

Newer builds also write `pe_header_fields` (node `dos`, `file`, `optional` or `dirs`, with field, file_offset, size, value and meaning as text), `pe_mitigations` (name, enabled), `pe_debug` (type, timestamp, size, pdb_path, raw_offset) and `pe_signatures` (one row per Authenticode blob: offset, length, digest and signature algorithms, signer serial and issuer, error). They add `entry_section`, `certificate_present` and `clr_present` to `pe_files`, `file_offset`, `resource_md5` and `malwarebazaar` to `pe_resources`, `issuer_ou` to `pe_certificates`, and `data_base64` to `pe_icons` (only icons up to 64 KiB, at most 64 per file). Resource payloads are never stored, only offsets, sizes and hashes. A case from an earlier build gains these tables and columns the next time a file is analyzed into it; until then they are absent or NULL.

## catalog.sqlite

This is the case, not the timeline. The SQL editor does not open against it. The tables here hold the work you do on the case, and they travel in the `.mcpz`.

### sources

One row per ingested file. `sha256` is the key. A second ingest of the same bytes is skipped. A changed file is a new hash, and the old rows for the old hash are removed.

### queries

Named SQL. `name` is what you typed in Save query. `sql` is the statement. A click in the Queries list loads it back into the editor.

### notes

A sentence against a record. `record_id` is the key. `body` is the sentence. `query_sql` is the statement that was in the editor when the note was saved.

### runs

One row per statement you ran. `sql`, `ran_at`, `row_count`, `label`, `analyst`, and `kind`. `followed` points at the previous run, so the trail can be walked.

### chats

One row per AI turn. `vendor` is grok, claude, or openai. `question`, `sql`, and `answer` are the turn. The API key is not in this table.

### case_info

Key and value pairs for the case. The analyst name is one of them.

### hosts

One row per host. `host_id` is the key. `hostname`, `fqdn`, `os`, and `arch` describe it.

### collections

One row per collector zip. `session_id` is the key. `host_id` points at the host. `zip_sha256` is the hash of the zip, so the same zip is not ingested twice.

### iocs

Indicators for this case. `kind` is the type, `value` is the indicator, `note` is yours.

### hunt_matches

Rows a hunt wrote. `run_id` points at the run. `source` is the table the match came from. `host_id`, `column_name`, `value`, `ioc_kind`, and `ioc_value` describe the hit.

## Machine store

`hash_sources` and `hash_sets` live on the machine, not in the case. A source is a hash feed. A set is the hashes in that feed. A hunt reads the enabled sets and writes matches into the case. The hashes themselves do not travel in the `.mcpz`.

## Building a query

Start from the table that holds the thing you want. Events are `events`. A process that ran is `prefetch`, `userassist`, or `shimcache`. A file is `amcache`. Network bytes are `srum`. A service or a task is `services` or `tasks`.

Filter `events` by `event_id` first, then by a JSON field. Filter the other tables by `host_id` when the case has more than one host, and by the text column that holds the name or the path.

`ILIKE` is case-insensitive. `count(*)` with `GROUP BY` is the usual shape for a tally. `ORDER BY` the count or the time. `LIMIT` while you are looking.

A statement you want to keep is Save query. A statement you ran is already in `runs`. A sentence against a row is a note.
