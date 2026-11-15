# Clients

| File | What |
|---|---|
| `specs.csv` | Each spec file the clients are generated from: product, version, address and SHA-256 (vendor files retrieved 2026-11-15), and optionally the languages for that row. The last row is aerie's own released contract `contracts-v1` (`datacenter/openapi.yaml` inside the release archive), generated in Python only, for response-schema validation |
| `generate.sh` | Downloads each file, refuses it if the hash differs, generates Java (`java`, okhttp-gson), Python (`python`) and TypeScript (`typescript-axios`) clients into `build/` with openapi-generator 7.26.0, itself pinned by SHA-256, and builds each one (Python compile check, `mvn package`, `npm install` with `tsc`). Needs bash, curl, sha256sum, tar, Java 11+, Python 3, Maven and npm; the runner container in `harness/` has them all. `ONLY=<id>` and `LANGS="python"` narrow a run |
| `runners/` | `JavaRunner.java` and `ts-runner.js`: run a batch of suite calls through one generated Java or TypeScript client and return each raw answer to `suites/run.py` |
| `community/` (to write) | Pinned versions of community client libraries, each with its license recorded |

Atlassian updates these files in place. When a hash stops matching, record the new hash in a pull request after checking what changed; never generate from an unpinned file.

Generator work-arounds: the Java clients map `_links` to `underscoreLinks` (models with both `links` and `_links` otherwise get two fields named `links`), Cloud v2's `DatabaseNullLookupValue` (declared `enum: [null]`) is mapped to a plain JSON element in Java, where it would be an empty enum that does not compile, and the TypeScript clients map a parameter named `key` to `keyParam` (Data Center 10.x and later; the generated loop variable shadows it).

`typescript-fetch` is not used: openapi-generator 7.26.0 crashes on the Cloud v2 file (model `DatabaseNullLookupValue`). The generator runs with the `REMOVE_PROPERTIES_FROM_TYPE_OTHER_THAN_OBJECT` normalizer because the Data Center files declare some unused `RestList*` schemas as arrays with properties, which the Python generator otherwise turns into code that does not compile.
