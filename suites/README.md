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

Clients in the matrix: `http` (raw HTTP) and `python-<spec>` (the generated Python client for each pinned Data Center file, whose strict models must accept every answer). Cells are `PASS`, `FAIL` (wrong status or a check failed), `ERROR` (the client rejected the answer or could not call), `BLOCKED` (a refusal case answered as expected, but its success case failed, so it proves nothing yet) and `N/A` (the operation is not in that spec version). Each failure gets `failures/<scenario>__<client>.json` with the request, the response and the diff. Expected statuses follow the response descriptions in the pinned spec files.

`python -I suites/test_run.py` checks the runner's check language.
