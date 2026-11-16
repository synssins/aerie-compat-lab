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

Clients in the matrix, for each pinned Data Center file: `http` (raw HTTP), `python-<spec>` and `java-<spec>` (generated clients whose strict models must accept every answer) and `ts-<spec>` (generated typescript-axios client, typed at compile time only, so the suite's checks judge what it hands back). Every operation is called by three languages. `python-aerie-dc-contracts-v6` is the Python client generated from aerie's own contract release `contracts-v6`: it validates each answer against the contract's response schemas. Cells are `PASS`, `FAIL` (wrong status, a check failed, or the client rejected the answer; the status and body are kept), `ERROR` (no answer reached the client: transport or setup), `BLOCKED` (a refusal case answered as expected, but its success case failed, so it proves nothing yet; or the scenario's setup steps could not make the objects its call needs) `N/A` (the operation is not in that spec version, or a case cannot be run yet; its failure file says why) and `RULED` (the client rejects the answer and a ruling says it always will, for example Q-0017: clients generated from DC 9.0.1 model the scan cursor as an object; the failure file names the ruling and keeps the answer). Each failure gets `failures/<scenario>__<client>.json` with the request, the response and the diff. Expected statuses follow the response descriptions in the pinned spec files.

The T1 suite covers all 52 T1 operations of aerie's Data Center contract. A scenario may carry a JSON `body`, multipart `form` fields (a file is `{"__file__": name, "content", "type"}`; it is sent as a file only where that spec declares binary, which is what its generated client can send) and `setup` steps. Setup steps run as raw HTTP once for each client before the calls, so each client writes to objects of its own: `{cx}` is the client's number, and a step's `save` keeps values from its answer (`{page}`, `{att}`, `{task}`). Write scenarios make their pages in the seeded space `LABW` and their spaces under keys such as `NS{cx}`, so the read scenarios on `LAB` keep their counts. Writes carry `X-Atlassian-Token: no-check`.

Scenarios run as `user` or `noaccess` with password Basic, as `admin` with Basic and the administrator's personal access token in the password field (accounts with sign-in codes are refused for password Basic), or as `token:<name>` with a seeded personal access token sent as `Authorization: Bearer` (`token:invalid` sends a token aerie never issued).

## Flow suites

A folder with a `cases.py` instead of `scenarios.json` is a flow suite: multi-step cases in Python, run with raw HTTP by the same `run.py` into the same matrix. `suites/auth` is one: HTTP Basic, personal access tokens and OAuth 2.0 on the Data Center surface, with the case names `identity-plan.md` (contracts-v6) gives for each build slice. Its `op` column names the slice. It runs last. The seed turns on aerie's test-install setting `allowHttpRedirects`, because the lab serves aerie over plain http and a production install refuses OAuth 2.0 there otherwise. The suite creates pages in `PRIV`, turns sign-in codes on for `lab-codes` and exempts it, waits five minutes for an access token to expire (`auth.oauth.refresh.after_access_expiry`), and reads the audit log for secrets (`auth.audit.no_secrets`). Its final cases lock the `lab-lockout` account and then rate-limit the caller at the token endpoint. Cases the lab cannot run yet are `N/A` with the reason in their file: an expired personal access token (the shortest lifetime is a day) and the `ADMIN` scope (no T1 operation needs it). Aerie's container log is scanned for secrets in `harness/run-lab.sh` and reported as `audit_scan_hits` in `run.json`.

`python -I suites/test_run.py` checks the runner's check language, parameter typing, credentials, form fields and multipart encoding.
