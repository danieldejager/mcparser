# What this release does not do

The grid shows fields. It does not show the English sentence Event Viewer would show. That sentence is built from a provider message table, and that table is not in the `.evtx` file. McParser can filter `TargetUserName`. It cannot print "An account was successfully logged on" unless that text was already in the event.

There is no Intel Windows installer. The Windows package is ARM64. An Intel laptop cannot run it.

The Mac image and the Ubuntu package are not signed. The Mac workaround is in the install chapter. Signing is waiting until the product is ready, not because the file is broken.

A failed ask is not stored. A command-line query is not a run. The chat transcript is not on the audit trail. A failed vendor does not fall through to another. If Claude has no key, choosing Claude does not silently ask Grok.

There is no server, and there is no account. Two analysts share a case by copying the folder or by exchanging a handoff file. They do not sign in to McParser.

Those are the edges of this release. The work inside them is the case, the query, the hunt, the note, the trail, the ask, and the handoff.
