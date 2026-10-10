# Hash Sources

The marketplace holds hash lists that the case can match against. Nothing is installed until you choose a card. The matching engine only sees sources that are installed and enabled.

Open it from the Window menu, Hash Sources. The sheet shows a card for each source. Filter by All, Installed, or Not installed.

Install a card to enable it. MalwareBazaar and Custom hash list take a local file: a CSV or a plain text list of MD5, SHA1, or SHA256 values. VirusTotal asks for an API key. The key is written to the operating system keychain and is not stored in the case folder. The key does not travel in the handoff.

Uninstall removes the source and its hashes from the case. Disable is the same as uninstall for now: the source is no longer used for matching.

Match the enabled sources from the terminal:

```
mcparser match-hashes --case fixtures/case.mcp
```

A hit names the artifact, the host, the hash, and the source that supplied it.

The installed sources, their non-secret config, and the imported hashes live in catalog.sqlite. They travel in the .mcpz. Keys do not. A machine that opens the handoff still has the lists, and it must supply its own key if a source needs one.
