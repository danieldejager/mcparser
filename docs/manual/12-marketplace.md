# Marketplace

The marketplace holds data sources the machine can match against any case. It is not tied to a case. Open it from Administration, Marketplace, or the Market button on the toolbar. No case needs to be open.

Sources appear as cards, grouped by category. Hash Sources is the first category. Filter by All, Not installed, or Installed. Each card shows the source logo, the name, the publisher, and a short description. Install and Uninstall are links on the card.

Nothing is installed until you choose a card. MalwareBazaar and Custom hash list take a local file of MD5, SHA1, or SHA256 values. VirusTotal asks for an API key. The key is written to the operating system keychain. Uninstall removes the integration and its imported hashes from the machine.

The installed sources and their hash lists live in a local store under the app's user data directory. They do not travel in the case or the .mcpz. Two machines can have different sources installed. That is expected.

When you match a case, the hits are written to that case. Each hit names the artifact, the host, the hash, and the source that supplied it, for example malwarebazaar. The hits travel with the case. The source list does not.

```
mcparser marketplace
mcparser install-source --source malwarebazaar
mcparser import-hashes --source malwarebazaar --file hashes.txt
mcparser match-hashes --case fixtures/case.mcp
```

## MalwareBazaar full

The MalwareBazaar full card, by abuse.ch, replaces the earlier MalwareBazaar card. Its id is still malwarebazaar, so the right-click lookup of a hash keeps working. Install asks for your abuse.ch Auth-Key. The key goes to the operating system keychain. It is never written to the store, the case, a report, a log, or the settings.

### Loading the dump

There are two ways to load the dump, and both can be used on the same machine.

- Fetch recent downloads the recent export from abuse.ch with the stored key. The download streams to a temporary file, which is deleted afterwards and also when the download fails. If abuse.ch answers 401 or 403 the card says the key was rejected. If it answers 429 the card says you are rate limited and should try again later. Any address shown in a message has the key replaced with ***.
- Upload zip or csv loads an export you already have. A zip is read by its first .csv member.

The dump lives in its own database, malwarebazaar.duckdb, next to marketplace.sqlite in the app's user data directory. It holds sha256, md5, sha1, and note. The note is JSON with file_name, signature, file_type, and reporter. A new hash is added. An existing row is updated only when one of its columns changed. After each load the card reports how many rows were added, updated, and unchanged.

The recent export covers recent samples, not every sample ever seen. The card shows the row count, the newest first_seen date in the dump, when it was loaded, and the file date sent by abuse.ch. Load it again to keep it current. Rows from earlier loads are kept.

Uninstall deletes the dump database and the stored key.

### Querying the dump

The SQL editor can read the dump as a table, with or without an open case:

```
SELECT * FROM malwarebazaar WHERE note LIKE '%AgentTesla%' LIMIT 100
```

The note column holds the JSON fields. A result larger than 50 MB is not drawn. The editor says so and asks for a LIMIT or a WHERE clause.

### Matching a case

Match case on the card, or the Bazaar button on the toolbar, runs in the background and shows progress in the status bar. It gathers every hash in the case: the SHA1 values from Amcache, hash values inside event data (for example Sysmon Hashes fields), and hash-like values in Prefetch and Shimcache paths. It joins them against the dump in one set-based query, so a large dump stays fast.

The result is written to the case under reports:

- malwarebazaar-<time>.csv with host, artifact, path or name, hash, hash kind, sha256, signature, file name, and source
- malwarebazaar-<time>.md with the counts, the dump size and dates, and the same hits as a table
- malwarebazaar-<time>-unmatched.txt with the hashes the dump did not know

Hits are also saved as hunt matches with their own run, the same way the Hunt button saves IOC hits, so they travel with the case. A notification says when the match is done, and the status line has an Open report link.

### Online lookup (optional)

The online lookup is off by default. When it is on, each hash the dump did not know is sent to the abuse.ch get_info API, up to the limit you set (25 by default). On HTTP 429 the lookup waits once, as asked by abuse.ch, and stops if it is limited again. Online hits are added to the report with the source online lookup. Local hits show the source local dump.

### Settings

The settings live in the config JSON of the malwarebazaar row in marketplace.sqlite:

```
{
  "lookupEndpoint": "https://mb-api.abuse.ch/api/v1/",
  "exportUrl": "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv",
  "onlineLookup": false,
  "onlineMax": 25
}
```

The exportUrl holds the placeholder {key}. The key is put in at the moment of the request and is never saved there. Read the settings with mcparser source-config --source malwarebazaar.

### Command line

```
mcparser bazaar-import --file recent.zip
mcparser bazaar-info
mcparser query "SELECT count(*) FROM malwarebazaar"
mcparser bazaar-match --case fixtures/case.mcp
```

The command line does not download. Fetch the export in the app, or download it yourself and use bazaar-import.
