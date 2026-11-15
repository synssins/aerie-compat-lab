# Harness

Starts the aerie container image for the commit under test (`ghcr.io/synssins/aerie:<tag>`, tags look like `sha-cd7b0e8` or `latest`), waits until it answers, seeds it through aerie's own API, and hands the base address and credentials to the suites.

| File | What |
|---|---|
| `docker-compose.yml` | Compose project `aerie-lab`: the image on `AERIE_PORT` with an empty throwaway data volume, plus the `runner` toolbox (profile `runner`: Python 3.12 with the suite dependencies, JDK 17 with Maven, Node with npm) |
| `seed.json` | The fixture: users, a group, spaces `LAB`, `PRIV` and `LABW` (where the T1 write scenarios make their pages), 14 pages, a personal access token and an OAuth client |
| `seed.py` | Waits for aerie, seeds `seed.json` through `/api/v1`, writes the hand-off file `reports/harness.json` |
| `redact.py` | Blanks passwords, sign-in code keys and tokens in the hand-off file before it is kept |
| `test_seed.py` | Self-check for the sign-in code (RFC 6238 vectors) and the redaction |
| `run-lab.sh` | The whole lab in this checkout against one image, needing only docker and curl: used by `run-on-host.sh` and by CI |
| `run-on-host.sh` | Clones or updates the lab on a Docker host, then runs `run-lab.sh` there |
| `host-timer.sh` | The host's own timer: a crontab line for the host user that runs `run-on-host.sh` for each new `aerie:latest` digest |

## Seeding

`seed.py` uses only calls described in aerie's own `/api/v1` API in the published contract releases (`aerie/openapi.yaml`; `contracts-v1` as aerie behaves today, `contracts-v2` for the planned OAuth client registration):

| Step | Calls |
|---|---|
| First-run setup | `GET /api/v1/setup/status`, `POST /api/v1/setup` with the remote setup code the image writes to `/app/App_Data/setup-code.txt` |
| Admin sign-in codes | Setup answers 409 `{"step":"enroll"}`: administrators must enroll sign-in codes. `POST /api/v1/auth/codes/key`, then `POST /api/v1/auth/codes` with a TOTP code |
| Users | `POST /api/v1/admin/users/invite`, then `POST /api/v1/auth/local/password` with the invite's set-password token |
| Groups | `POST /api/v1/admin/groups`, `PUT /api/v1/admin/groups/{id}/members/{userId}` |
| Spaces | `POST /api/v1/spaces` (private), `PUT /api/v1/spaces/{id}/roles` granting each view group `Reader` by its key `local:<id>` |
| Pages | `POST /api/v1/spaces/{id}/pages` with parent, tags (the fixture's labels) and editor JSON body |
| Tokens | `POST /api/v1/tokens` as the owner, kind `Personal`, 30 days: `lab-user` Read and Write; `lab-admin` Write (the administrator's Basic credential), Read, and Read limited to `LAB` |
| OAuth clients | `POST /api/v1/admin/oauth/clients` (planned in contracts-v2): `lab-public` (public) and `lab-confidential`, PKCE, scopes `READ WRITE`, redirect `http://127.0.0.1:8765/callback`. Until aerie serves it, the hand-off records `GAP-SEED-OAUTH_CLIENTS` and only the OAuth cases fail |

The session cookies (`__Host-kb`, `__Host-kb-pending`) are `Secure`, so `seed.py` carries them by hand over the plain-HTTP lab network.

```bash
AERIE_TAG=latest docker compose -p aerie-lab -f harness/docker-compose.yml up -d aerie
AERIE_SETUP_CODE="$(docker compose -p aerie-lab -f harness/docker-compose.yml exec -T aerie cat /app/App_Data/setup-code.txt)" \
  python -I harness/seed.py
docker compose -p aerie-lab -f harness/docker-compose.yml --profile runner down -v
```

## Running on a Docker host

`run-on-host.sh` needs only docker, git and curl on the host. It clones or updates the lab under `~/aerie-compat-lab`, starts the image as compose project `aerie-lab` on host port 18090, seeds it, runs `clients/generate.sh` and the suites in the `runner` container, writes `reports/` (matrix, failures, generation and aerie logs, redacted hand-off, `run.json` with the image digest), and removes the project's containers, network and volume. It never uses host ports 8080 or 8081 and touches nothing outside its project and its checkout.

```bash
ssh docker-host 'bash -s -- latest' < harness/run-on-host.sh
ssh docker-host 'LAB_REF=my-branch AERIE_PORT=18091 bash -s -- sha-cd7b0e8' < harness/run-on-host.sh
```

`host-timer.sh install` (run on the host from a checkout) copies itself to `~/aerie-compat-lab/.timer/` and adds one line to the host user's crontab: every 30 minutes, under a lock, it reads the digest of `aerie:latest` anonymously and runs `run-on-host.sh` at `LAB_REF` (default `main`) when that digest has not been tested. Each run's `run.json` and matrices are kept in `.timer/runs/<UTC time>/`, the log in `.timer/log`. `host-timer.sh remove` takes the line out. No sudo and no system unit: it is the fallback for GitHub's scheduled trigger, which had not fired once on this repository.

## Open gaps and rulings

| Item | Status |
|---|---|
| `GAP-HEALTH` | aerie has no health endpoint; every unknown path returns the web app with 200 `text/html`. The harness waits for `GET /api/v1/setup/status` to answer 200 JSON |
| `GAP-SEED-OAUTH_CLIENTS` | Open until aerie serves `POST /api/v1/admin/oauth/clients` (planned in contracts-v2). Seeding still succeeds; only the OAuth cases fail |
| Space keys | Ruled (contracts-v2, `spaces.md`): aerie stores `lab` and `priv`; the compatible surface accepts any case and returns `LAB` and `PRIV` |
| Child pages | Ruled (contracts-v2, `content.md`): aerie nests pages only under folders, so `Lab Home` is seeded as a folder; the surface shows folders as pages with children |
| Home pages | Ruled (contracts-v2, `spaces.md`): aerie spaces have none; `homepage` is never returned, and clients list the top level with `depth=root` |
| Admin sign-in codes | Ruled (contracts-v2, `identity.md`): password Basic is refused for accounts with codes, so the hand-off's `admin` Basic credential carries the administrator's personal access token; `admin-password` keeps the password and the sign-in code key for the auth suite |
| Admin token in T1 | Basic with the administrator's token in the password field answers 401 on the current image, and the failures trip aerie's rate limit for every later call, so the T1 suite's fixtures, setup steps and admin scenarios use the same token as a bearer token (`admin_as` in `scenarios.json`). `suites/auth` still tests the Basic form |
| Attachments on folders | Ruled (contracts-v3, Q-0006, `attachments.md`): folders take attachments; `attachment.create.success` uploads to `Lab Home`, which is a folder |
| Visibility of new spaces | Ruled (contracts-v3, Q-0012, `spaces.md`): `POST /rest/api/space` is readable by everyone signed in, `_private` only by its creator; `space.create.visible` and `space.create_private.hidden` read them as `lab-noaccess` |
