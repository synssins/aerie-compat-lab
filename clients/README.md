# Clients

| File | What |
|---|---|
| `specs.csv` | Each vendor spec file the clients are generated from: product, version, address and SHA-256 (retrieved 2026-11-15) |
| `generate.sh` | Downloads each file, refuses it if the hash differs, and generates Java (`java`), Python (`python`) and TypeScript (`typescript-axios`) clients into `build/` with openapi-generator 7.26.0, itself pinned by SHA-256. Needs bash, curl, sha256sum, Java 11+ and Python 3. `ONLY=<id>` and `LANGS="python"` narrow a run |
| `community/` (to write) | Pinned versions of community client libraries, each with its license recorded |

Atlassian updates these files in place. When a hash stops matching, record the new hash in a pull request after checking what changed; never generate from an unpinned file.

`typescript-fetch` is not used: openapi-generator 7.26.0 crashes on the Cloud v2 file (model `DatabaseNullLookupValue`). The generator runs with the `REMOVE_PROPERTIES_FROM_TYPE_OTHER_THAN_OBJECT` normalizer because the Data Center files declare some unused `RestList*` schemas as arrays with properties, which the Python generator otherwise turns into code that does not compile.
