# Grok chat

Status: design only. Not in 0.1.0.

The chat is a pane in the desktop app. It writes SQL, McParser runs that SQL on the open case, and Grok answers from the returned rows. The `.evtx` file and the DuckDB file never leave the machine.

![UI Mockup](docs/mockup_grok.png)

## Boundary

| Stays local | May be sent |
| --- | --- |
| `.evtx` bytes | The analyst's question |
| `events.duckdb` | Column names for the query |
| `catalog.sqlite` | At most 50 rows, cell text truncated |
| API key | The SQL that produced those rows |
| Case path | Case stats already shown in the sidebar: counts, channels, time range |

The renderer process never sees the key. The main process holds it and calls `https://api.x.ai`. The parser still runs as the local `mcparser` binary.

## Key

The analyst pastes an xAI key once. Electron `safeStorage` encrypts it with the macOS keychain or Windows DPAPI, then the ciphertext is stored in the app user-data directory. It is not written into the case, the repo, logs, or the chat transcript on disk.

Settings shows only the last four characters. Replace and Forget are the only operations. Forget deletes the ciphertext. No key, no chat. Ingest, query, and export do not change.

A packaged build does not contain a key. A debug build does not read a key from the environment.

## Request path

1. The analyst asks in the chat pane.
2. The main process sends Grok the question plus the table columns and the sidebar stats. No rows yet.
3. Grok returns a single `SELECT`. The app rejects anything that is not one read statement: no `ATTACH`, no `COPY`, no `PRAGMA`, no second statement.
4. The local parser runs that SQL with a 50-row limit.
5. The main process sends the question, the SQL, and those rows. Cell values are truncated.
6. The reply is shown with the SQL. Run copies that SQL into the editor. The analyst can run it again and see every row.

The analyst confirms the first send of a session. The confirm dialog names the case and says that row text will leave the machine. Later sends in that session do not ask again. Forget, or closing the case, resets the confirm.

## UI

The studio stays as it is. A chat column opens on the right, same width as the case pane.

- Header: Grok, and a settings control.
- Transcript: analyst questions, the SQL used, and the answer.
- Composer: one field and Ask.
- Empty state, no key: "Add an xAI key in Settings. The case stays on this machine."
- Empty state, key set: "Ask about this case."
- Settings sheet: key field, last four characters when set, Save, Replace, Forget.

The grid does not move. Ask does not change the editor until the analyst presses Run on a reply.

## Not in the first cut

Saved chats, agents, and a bot that runs while the analyst is away. Rendered message text. Sending the case file.
