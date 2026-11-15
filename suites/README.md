# Suites

One folder per surface and tier, matching the roadmap.

| Folder | Covers |
|---|---|
| `datacenter/t1` | Content, child content, descendants, attachments, labels, versions, body conversion, spaces, search, users, server information, long tasks |
| `datacenter/t2` | Content and space properties, restrictions, webhooks, space permissions, groups, label lists, watches |
| `datacenter/t3` | Administration operations |
| `cloud/v1` | Cloud v1 |
| `cloud/v2` | Cloud v2, by tier |
| `auth` | Basic auth, personal access tokens, OAuth 2.0 with PKCE and refresh |
| `migration` | Aerie-to-aerie migration through the Data Center surface |

Each operation gets a success case, a not-allowed case, a not-found case and, where it applies, paging and `expand` cases.

## Running a suite

Each suite folder holds a `scenarios.json`; `run.py` runs it with every client and writes the matrix.

```bash
bash clients/generate.sh
pip install -r suites/requirements.txt
python -I suites/run.py suites/datacenter/t1 --harness reports/harness.json --out reports/datacenter-t1
```

Clients in the matrix, for each pinned Data Center file: `http` (raw HTTP), `python-<spec>` and `java-<spec>` (generated clients whose strict models must accept every answer) and `ts-<spec>` (generated typescript-axios client, typed at compile time only, so the suite's checks judge what it hands back). Every operation is called by three languages. `python-aerie-dc-contracts-v1` is the Python client generated from aerie's own contract release `contracts-v1`: it validates each answer against the contract's response schemas. Cells are `PASS`, `FAIL` (wrong status, a check failed, or the client rejected the answer; the status and body are kept), `ERROR` (no answer reached the client: transport or setup), `BLOCKED` (a refusal case answered as expected, but its success case failed, so it proves nothing yet) and `N/A` (the operation is not in that spec version). Each failure gets `failures/<scenario>__<client>.json` with the request, the response and the diff. Expected statuses follow the response descriptions in the pinned spec files.

Scenarios run as `admin`, `user` or `noaccess` with basic auth, or as `token:<name>` with a seeded personal access token sent as `Authorization: Bearer` (`token:invalid` sends a token aerie never issued).

`python -I suites/test_run.py` checks the runner's check language, parameter typing and credentials.
