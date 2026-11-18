# security/zap

Every lab run on the Docker host (`harness/run-on-host.sh`, which sets `ZAP=1`) ends with a penetration test of the aerie image under test with OWASP ZAP. This is authorized testing of the owner's own software. The target is only the lab's own aerie container in compose project `aerie-lab`, started from the image under test and seeded with lab data.

## Isolation

- ZAP is the official image `ghcr.io/zaproxy/zaproxy`, version 2.17.0, pinned by digest in [harness/docker-compose.yml](../../harness/docker-compose.yml) (service `zap`, profile `zap`).
- It runs as part of project `aerie-lab` with `docker compose run --rm`, so each container is removed when its scan ends. The project's teardown removes anything left.
- ZAP joins only the network `scan`, which is `internal: true`. The lab's aerie joins it as well. From there ZAP reaches the lab's aerie and nothing else: not the live aerie, other containers, the host, the LAN or the internet. ZAP also runs with `-silent`, so it makes no update or callback requests.

## What runs

`harness/run-lab.sh` runs the stage after the suites, before the hand-off file is redacted.

1. **`scan.py prep`**, in the runner container:
   - Adds `lab-contributor`, `lab-supervisor` and `lab-owner`. It makes the space `SCAN` with one page and grants each account its role there. `lab-user` holds Reader on `SCAN`, and `lab-admin` is the administrator.
   - Signs each role in for a web session.
   - Takes `aerie/openapi.yaml` and `datacenter/openapi.yaml` from the newest contract release, `contracts-v9`, pinned by SHA-256 in `SCAN_CONTRACT` in `scan.py` (the suites keep their own pin in `clients/specs.csv`).
   - Writes `methods.json`, a lab-made definition of the plugin sign-in routes (`/api/v1/auth/methods`, `/outcome`, `/{plugin}/{method}/start`, `/{plugin}/{method}/callback`), which no contract release describes yet. Plugin and method come from `GET /api/v1/auth/methods`; the query names (`returnUrl`, `returnTo`, `return`, `redirect`, `state`, `code`, `error`) are probes.
   - Points path parameters at real objects. Space and page ids name `PRIV` and its home page, which only `lab-admin` may see. User ids name `lab-noaccess`, group ids `lab-readers`, token ids `lab-admin-pat-lab`, and plugin ids the first plugin `GET /api/v1/admin/plugins` lists.
   - Runs the lab access check. Every GET with real ids runs as every role. These answers are flagged:
     - any 2xx to an anonymous caller where the definition asks for authentication;
     - any 2xx for a role other than the administrator on `/api/v1/admin/`;
     - any 2xx for a role other than the administrator on `PRIV` or its page.
   - Runs three lab probes, recorded under `probes` in `prep.json`; a broken rule is a High (or, for a 5xx, Medium) `lab-access` finding:
     - **Plugin sign-in without a provider**: as anonymous and Reader, the outcome route, `start` with off-site return paths (`https://evil.example/x`, `//evil.example/x`, `/\evil.example/x`), and `callback` with no state, a forged state, a code only and an error. Flags a redirect off the site, a session cookie from a callback without a valid state, and any 5xx.
     - **Page history for members only**: a page with two versions in a new `SignedIn` space `HIST`, where Reader is not a member. Reader and anonymous must be refused `versions`, a version, `diff`, and on the vendor surface `history` and `version/1`, and the page's `history` field must be empty. The creator's answers are kept as the control.
     - **Deleting a user**: a fresh local user `lab-delete-me`. Every role but the administrator must be refused `DELETE /api/v1/admin/users/{id}`; the administrator's delete and the read after it are recorded. The user sources present are recorded. Only local users can be made: no identity provider is reachable from the scan network.
   - Writes one Automation Framework plan per role.
2. **One ZAP container per role**, each followed by `scan.py after`. That step checks the role's session still works and keeps the text around the evidence of each High and Medium GET for triage. The roles run in this order: anonymous, reader, contributor, supervisor, owner, admin. The administrator comes last because its scan may change settings or objects. Each plan has these jobs:
   - `insights` with `exitAutoLevel` blank. Otherwise ZAP's Insights add-on ends the plan at its "100% authentication failures" insight, which an active scan of refused requests always raises.
   - `replacer`, which adds the role's session cookie and `X-Atlassian-Token: no-check` to every request.
   - `openapi` imports of both definitions and of `methods.json`.
   - `spider` on the web app for 5 minutes.
   - `spiderAjax`, the browser-driven spider, for 10 minutes: headless Firefox inside the ZAP container (`shm_size: 1gb`), browsing through ZAP's proxy so the replacer adds the session. It stays on the internal network like the rest of ZAP.
   - A full `activeScan` with the default policy and no time limit.
   - A `traditional-json` report.
3. **`scan.py report`**:
   - Counts alert instances by risk and confidence for each role.
   - Lists every High and Medium instance with its URL, parameter, evidence and triage.
   - Checks that each role's session still works after its scan.
   - Blanks secrets with `harness/redact.py`. That covers every seeded password, sign-in code key, token and session cookie, and any aerie token beyond its short prefix.
   - Removes the plans, which contain the sessions.

## Sign-in codes

`lab-admin` has sign-in codes. Its scan uses the route the auth suite uses for a web session: password, then a code (`ctx.session` in `suites/auth/cases.py`). A personal access token would not reach most of the API. In `contracts-v6`, 152 of aerie's 180 operations are closed to tokens (`x-kb-api-token: closed`), the administrator routes among them. So each role scans with a web session. The token-open routes are scanned with that session too.

## Not scanned

These are excluded from the scan context and removed from the definitions ZAP imports. They would end the scan's own session or turn off password sign-in for every account. ZAP's OpenAPI import sends every operation in a definition and ignores the context's exclusions:

- `/api/v1/auth/signout`
- `/api/v1/admin/auth/local/disable`
- `DELETE /api/v1/me/codes` (the path's `GET` is scanned). Turning sign-in codes off ends every session of the account and gives the caller a new cookie, even when codes were not on. The scan keeps sending the old cookie, so the rest of its scan would run signed out. A run on 2026-11-16 lost the Reader, Contributor, Supervisor and Owner sessions this way. The administrator kept its session, because administrators cannot turn codes off.

The web app is a single-page app. The traditional spider and the AJAX spider cover its HTML, scripts and client-side routes (plugin settings pages among them), and the API it calls is covered through the definitions.

## Results and the gate

`reports/security-zap/` holds the following:

- `matrix.md`, which the host timer keeps with each run;
- `summary.json`, with every High and Medium instance;
- one ZAP report and one log per role;
- `prep.json`.

`run.json` gets `zap_gate` and `zap_seconds`.

The gate is **FAIL** in these cases:

- a High or Medium instance matches no entry in [baseline.json](baseline.json);
- a role produced no report;
- a role's session no longer works right after its scan, because its scan then ran at least partly signed out.

Triaged entries carry one of these verdicts:

- `false positive`, with the reason;
- `real`;
- `build room`, for where aerie disagrees with good practice.

A triaged entry does not fail the run. Entries marked `real` or `build room` stay listed in `matrix.md` until the build room fixes them, and then come out of the baseline.
