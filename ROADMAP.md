# Roadmap

Current release: 0.1.0. What already shipped is in [CHANGELOG.md](CHANGELOG.md).

## Next

1. Grok chat on the open case. Ask a question in plain language. McParser runs the SQL locally and sends only the question, the columns, and the returned rows. The `.evtx` and the DuckDB file stay on the machine. The reply shows the SQL, and Run puts it in the editor.
2. Saved queries. Name a query and run it again on the current case.
3. Query shell. A prompt against the open case, same SQL as the desktop editor.
4. Rendered messages. The English sentence is not in the `.evtx` file. It needs the provider message template, without shipping Windows provider DLLs.
5. Signing. Notarise the macOS disk image. Sign the Windows installer.
6. Ubuntu package.
7. Intel Windows build. An x64 installer for a normal Windows PC. The 0.1.0 installer is ARM64 only.

## Not planned

- A Windows Event Log API dependency. The parser stays offline and cross-platform.
- Sending the case file to Grok.
