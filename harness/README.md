# Harness

Starts the aerie container image for the commit under test (`ghcr.io/synssins/aerie:<tag>`, tags look like `sha-cd7b0e8` or `latest`), waits until it answers, seeds it through aerie's own API, and hands the base address and credentials to the suites.

| File | What |
|---|---|
| `docker-compose.yml` | Compose project `aerie-lab`: the image on `AERIE_PORT` with an empty throwaway data volume, plus the `runner` toolbox (profile `runner`: Python 3.12 with the suite dependencies, JDK 17 with Maven, Node with npm) |
| `seed.json` | The fixture: users, a group, spaces `LAB` and `PRIV`, 14 pages, a personal access token and an OAuth client |
| `seed.py` | Waits for aerie, seeds `seed.json` through `/api/v1`, writes the hand-off file `reports/harness.json` |
| `redact.py` | Blanks passwords, sign-in code keys and tokens in the hand-off file before it is kept |
| `test_seed.py` | Self-check for the sign-in code (RFC 6238 vectors) and the redaction |
| `run-lab.sh` | The whole lab in this checkout against one image, needing only docker and curl: used by `run-on-host.sh` and by CI |
| `run-on-host.sh` | Clones or updates the lab on a Docker host, then runs `run-lab.sh` there |

## Seeding

`seed.py` uses only calls described in the published contract release `contracts-v1` (`aerie/openapi.yaml`, aerie's own `/api/v1` API as it behaves today):

| Step | Calls |
|---|---|
| First-run setup | `GET /api/v1/setup/status`, `POST /api/v1/setup` with the remote setup code the image writes to `/app/App_Data/setup-code.txt` |
| Page parents (`GAP-PAGE-PARENT`) | aerie nests pages only under folders (`parentId`: "Must be a folder in this space"), so a fixture page with children (`Lab Home`) is created as a Folder. How the vendor surface shows a folder with child pages is for the spec room |
| Admin sign-in codes | Setup answers 409 `{"step":"enroll"}`: administrators must enroll sign-in codes. `POST /api/v1/auth/codes/key`, then `POST /api/v1/auth/codes` with a TOTP code |
| Users | `POST /api/v1/admin/users/invite`, then `POST /api/v1/auth/local/password` with the invite's set-password token |
| Groups | `POST /api/v1/admin/groups`, `PUT /api/v1/admin/groups/{id}/members/{userId}` |
| Spaces | `POST /api/v1/spaces` (private), `PUT /api/v1/spaces/{id}/roles` granting each view group `Reader` by its key `local:<id>` |
| Pages | `POST /api/v1/spaces/{id}/pages` with parent, tags (the fixture's labels) and editor JSON body |
| Tokens | `POST /api/v1/tokens` signed in as the owner, kind `Personal`, read scope, 30 days |

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

## Open gaps

| Gap | Status |
|---|---|
| `GAP-HEALTH` | aerie has no health endpoint; every unknown path returns the web app with 200 `text/html`. The harness waits for `GET /api/v1/setup/status` to answer 200 JSON |
| `GAP-SEED-OAUTH_CLIENTS` | aerie's API has no call to register an OAuth client; `lab-client` is not seeded |
| Space keys | aerie keys are 2-32 lowercase letters, digits and hyphens, so `LAB` and `PRIV` are created as `lab` and `priv`. How the vendor surface maps uppercase `spaceKey=LAB` is for the spec room |
| Space home pages | aerie spaces have no home page setting; `Lab Home` and `Private Home` are top-level pages |
| Admin sign-in codes | The admin must give a TOTP code at every sign-in. The hand-off records the key; how basic auth on the vendor surface treats an admin with codes is for the spec room |
