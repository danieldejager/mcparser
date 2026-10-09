# The command line

The window is the usual way in. The `mcparser` binary is the same parser, and it reads the same case folder. You need a built binary for this. The installed application does not put the command on your path.

From the directory that contains the case, or with a full path.

## Import a collector zip

A Velociraptor offline collector zip becomes a host and a collection. Events, Prefetch, services, scheduled tasks, shimcache, UserAssist, Amcache, and SRUM are written into the same case. The raw files are kept under `files/` inside the case folder.

```bash
mcparser collect --case Emerio7.mcp /path/to/collector.zip
mcparser hosts --case Emerio7.mcp
mcparser collections --case Emerio7.mcp
```

A second import of the same zip skips an artifact whose hash is already recorded. UserAssist and Amcache can also be loaded on their own if the zip is already in the case:

```bash
mcparser userassist --case Emerio7.mcp
mcparser amcache --case Emerio7.mcp
```

`amcache inserted=0` means the zip had no `Amcache.hve`. It does not mean the command failed.

## Query a collection

`events` is the log. The other tables are not inside `events`. Quote `name` in DuckDB. It is a reserved word.

```bash
mcparser query --case Emerio7.mcp \
  "SELECT event_id, count(*) FROM events GROUP BY event_id ORDER BY count(*) DESC LIMIT 20"
mcparser query --case Emerio7.mcp \
  "SELECT executable, run_count, last_run FROM prefetch ORDER BY run_count DESC LIMIT 20"
mcparser query --case Emerio7.mcp \
  "SELECT run_count, last_run, \"name\" FROM userassist WHERE \"name\" NOT LIKE 'UEME_CTL%' ORDER BY run_count DESC LIMIT 20"
mcparser query --case Emerio7.mcp \
  "SELECT kind, \"name\", sha1, path FROM amcache WHERE kind = 'file' LIMIT 20"
mcparser query --case Emerio7.mcp \
  "SELECT path, modified FROM shimcache WHERE path NOT ILIKE '%\\Windows\\%' ORDER BY modified DESC LIMIT 20"
mcparser query --case Emerio7.mcp \
  "SELECT app, bytes_sent, bytes_received FROM srum WHERE kind = 'network' ORDER BY bytes_sent DESC LIMIT 20"
mcparser query --case Emerio7.mcp \
  "SELECT \"name\", start_mode, path FROM services WHERE path NOT ILIKE '%System32%' LIMIT 20"
mcparser query --case Emerio7.mcp \
  "SELECT command, arguments, path FROM tasks WHERE command NOT ILIKE '%System32%' LIMIT 20"
```

`--format` is `table`, `csv`, or `jsonl`. CSV includes a header row.

## Event logs, notes, and a handoff

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

A handoff from the command line takes the password from the environment, so it is not written into the shell history if you set it for that command only.

```bash
MCPARSER_HANDOFF_PASSWORD='choose-a-long-password' \
  mcparser handoff --case case.mcp --out handoff.mcpz
MCPARSER_HANDOFF_PASSWORD='choose-a-long-password' \
  mcparser open-handoff --file handoff.mcpz --out received.mcp
```

A query from this command does not write a run. If you need the trail, use the Run button. The command is the right tool for a count, a check, or a handoff when the window is not open.
