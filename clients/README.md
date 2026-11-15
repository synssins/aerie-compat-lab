# Clients

| File | What |
|---|---|
| `specs.csv` | Each vendor spec file the clients are generated from: product, version, address and SHA-256 (retrieved 2026-11-15) |
| `generate.sh` (to write) | Downloads each file, refuses it if the hash differs, and generates Java, Python and TypeScript clients into `build/` |
| `community/` (to write) | Pinned versions of community client libraries, each with its license recorded |

Atlassian updates these files in place. When a hash stops matching, record the new hash in a pull request after checking what changed; never generate from an unpinned file.
