# McParser user manual

Outline only. Current release is [0.2.8](https://github.com/danieldejager/mcparser/releases/tag/v0.2.8). The log-mark icon is on the rebuilt [0.2.7](https://github.com/danieldejager/mcparser/releases/tag/v0.2.7) packages.

This folder is the manual. The README at the repo root stays the short install page and points here.

## Who it is for

An analyst with an offline `.evtx` file. No Windows Event Log service. No account. No server.

## Chapters

1. What a case is. The `.mcp` folder, `events.duckdb`, `catalog.sqlite`, and what is not in the case.
2. Install. Mac disk image, Windows ARM setup, Ubuntu amd64 and arm64 deb. The unsigned Mac workaround.
3. Open a log. File, then Open EVTX. What the case pane shows.
4. Query. The editor, Run, Export CSV, `json_extract_string`.
5. Hunts. Tactic, technique, the shipped SQL, the `USER` placeholder.
6. Notes and the trail. A note, a run, a replay, Audit, then Trail, Export trail.
7. Ask. Grok, Claude, OpenAI. The key stays in the keychain. The transcript stays in the case.
8. Handoff. Export and open a `.mcpz`. A wrong password. What the file does not contain.
9. Command line. The same case, and the queries that do not write a run.
10. What this release does not do. Rendered messages, Intel Windows, signing.

## Diagrams

Mermaid, in the chapter that owns the process.

- Open a log, then query, then note.
- Ask: confirm, one SELECT, local run, store the turn.
- Handoff: encrypt, copy the file, decrypt on the other machine.

## File layout

```text
docs/manual/README.md          this outline, later the contents page
docs/manual/01-case.md
docs/manual/02-install.md
docs/manual/03-open.md
docs/manual/04-query.md
docs/manual/05-hunts.md
docs/manual/06-trail.md
docs/manual/07-ask.md
docs/manual/08-handoff.md
docs/manual/09-cli.md
docs/manual/10-limits.md
```

The root README, CHANGELOG, and ROADMAP link to `docs/manual/` once the chapters exist. Velociraptor stays on the project board. It is not a chapter.
