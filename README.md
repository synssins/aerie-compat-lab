# aerie-compat-lab

The compatibility lab for [Aerie](https://github.com/synssins/aerie), a self-hosted knowledge base. The lab proves that existing integrations work against aerie unchanged: it runs clients built from Atlassian's own published API specs against the aerie container image and reports every answer they reject.

An operation counts as compatible only when clients in at least two languages call it and accept every answer. If existing code doesn't work unchanged, it isn't done.

## The three repositories

Aerie is redeveloped under a clean-room method. The lab tests a black box: it needs the aerie image, never aerie's source.

| Repository | Role |
|---|---|
| [aerie-spec](https://github.com/synssins/aerie-spec) | Written specs and API contracts |
| [aerie](https://github.com/synssins/aerie) | The implementation, built only from the contracts |
| **aerie-compat-lab** (this one) | Runs vendors' published clients against the aerie image |

Only results leave the lab. [CLEAN_ROOM.md](CLEAN_ROOM.md) has the full policy.

## Client sets

| Set | Built from | Why |
|---|---|---|
| Generated clients: Java, Python, TypeScript | Atlassian's published OpenAPI files for Data Center 9.0.1, 9.2.4, 9.5.1, 10.2.20 and 11.1.0, and Cloud v1 and v2, pinned in [clients/specs.csv](clients/specs.csv) | Atlassian publishes no official SDK and points developers at generating clients from these files |
| Community clients | Widely used open-source libraries, after a license check | How many real integrations are written |
| Raw HTTP suites | Our own scenarios | Headers, paging links, error bodies and auth flows that generated clients don't check |

Generated clients are built at run time from the pinned files and checked against their SHA-256. Generated code is not committed.

## Layout

| Path | What |
|---|---|
| [CLEAN_ROOM.md](CLEAN_ROOM.md) | What may and may not come into the lab, and what may leave it |
| [clients/](clients/README.md) | The pinned spec list, the generation script, community client pins |
| [harness/](harness/README.md) | Starts the aerie image for the commit under test and seeds it |
| [suites/](suites/README.md) | Scenario suites per surface and tier |
| `reports/` | Not committed: CI artifacts with the result matrix and failure diffs |

## What a run does

1. Start the aerie image for the commit under test, seed it through aerie's own API, and register an OAuth client and tokens.
2. Run every suite for the surfaces in scope. Each operation gets a success case, a not-allowed case, a not-found case and, where it applies, paging and `expand` cases.
3. Fail on any answer a generated client cannot parse in strict mode, any wrong status code, and any field the contract promises that is missing.
4. Publish a matrix of operation by client by result, with the request, the response and the diff for each failure.

A failure where aerie disagrees with its contract is filed in `aerie`. A failure where the contract disagrees with the vendor's clients is filed in `aerie-spec`.

## Customer acceptance

Near the end, a customer runs their own integrations against a staging aerie loaded with a migrated copy of their site. Only their results come back; no customer code enters any repository.

## Status

Phase 1 in progress. Every suite fails until aerie passes it; that is the expected state. First tasks:

- [x] `harness/`: start a pinned aerie image and seed it through aerie's own API (contracts-v1 and v2); `harness/run-on-host.sh` runs the whole lab on a Docker host. Open gaps in [harness/README.md](harness/README.md)
- [x] `clients/generate.sh`: download each pinned spec, check its hash, generate the Java, Python and TypeScript clients
- [x] `suites/datacenter/t1`: the first scenarios for content, spaces and search, run by `suites/run.py` with raw HTTP and the generated Python clients
- [x] Java and TypeScript client runners: every operation is called by Python, Java and TypeScript clients, plus response-schema validation against aerie's `contracts-v3` Data Center contract
- [x] `suites/auth`: HTTP Basic, personal access tokens and OAuth 2.0 (authorization code with PKCE, refresh rotation, revocation), one case per item `identity-plan.md` names for each build slice
- [x] CI: `.github/workflows/lab.yml` checks the digest of `ghcr.io/synssins/aerie:latest` every 30 minutes and runs the lab when it has not tested that digest; it also runs by hand with a tag

## License

[Apache License 2.0](LICENSE). Clients generated at run time from vendors' spec files are not part of this repository.
