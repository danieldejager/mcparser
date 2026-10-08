# The command line

The window is the usual way in. The `mcparser` binary is the same parser, and it reads the same case folder. You need a built binary for this. The installed application does not put the command on your path.

From the directory that contains the case, or with a full path:

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

`--format` is `table`, `csv`, or `jsonl`. CSV includes a header row.

A handoff from the command line takes the password from the environment, so it is not written into the shell history if you set it for that command only.

```bash
MCPARSER_HANDOFF_PASSWORD='choose-a-long-password' \
  mcparser handoff --case case.mcp --out handoff.mcpz
MCPARSER_HANDOFF_PASSWORD='choose-a-long-password' \
  mcparser open-handoff --file handoff.mcpz --out received.mcp
```

A query from this command does not write a run. If you need the trail, use the Run button. The command is the right tool for a count, a check, or a handoff when the window is not open.
