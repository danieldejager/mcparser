# Query

The editor in the middle is SQL against the events table. Run sends the statement. The grid shows the rows. Export CSV writes the current grid, including the column names, and that button stays put while the grid scrolls.

The columns you can rely on are `source_sha256`, `record_id`, `event_id`, `channel`, `provider`, `computer`, `time_created`, and `event_data`. `event_data` is JSON. A name such as `TargetUserName` is not a column. It is a field inside that JSON, and DuckDB will pull it out if you ask.

This counts event 4624 where the target user is `fsir`.

```sql
SELECT event_id, count(*)
FROM events
WHERE event_id = 4624
  AND json_extract_string(event_data, '$.TargetUserName') = 'fsir'
```

The path `$.TargetUserName` has to match the key in the JSON. If the count comes back empty, look at one raw row first.

```sql
SELECT event_data
FROM events
WHERE event_id = 4624
LIMIT 1
```

Save query asks for a name and stores the statement in the catalog. A click in the Queries list loads it back into the editor. The query travels with the case folder. It does not travel with the application.

The editor has line numbers, and you can copy from it. If a hunt or a saved query loads a statement you do not want to lose, save it under your own name before you replace the text.
