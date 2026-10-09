# The case

A case is a folder. Opening an `.evtx` creates it beside that file, named `<file>.mcp`. A collector import uses the folder you pass to `collect`. One case can hold more than one host.

`events.duckdb` holds the events and the collection tables: `prefetch`, `userassist`, `amcache`, `shimcache`, `srum`, `services`, and `tasks`. `catalog.sqlite` holds the hosts, the collections, and the work you did. The raw collector files stay under `files/`.

Two files live in that folder.

`events.duckdb` holds the events. Each row is one record from the log: the record id, the event id, the channel, the provider, the computer, the time, and a JSON object called `event_data`. The English sentence you would see in Event Viewer is not in this file. The fields are.

`catalog.sqlite` holds the work you did on those events. Saved queries, notes, the run trail, and the chat transcript all go here. The API key does not. The key stays in the keychain on the machine that asked the question.

If you copy the folder, you copy the events and the work. If you copy only the `.evtx` file, the other person starts again.

```mermaid
flowchart LR
  evtx[".evtx file"] --> case[".mcp folder"]
  case --> events["events.duckdb"]
  case --> catalog["catalog.sqlite"]
  catalog --> queries["saved queries"]
  catalog --> notes["notes and runs"]
  catalog --> chat["chat transcript"]
```

Treat the folder as the thing you keep. The window is only a way to look at it.
