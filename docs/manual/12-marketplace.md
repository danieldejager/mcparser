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
