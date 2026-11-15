# Harness

Starts the aerie container image for the commit under test (`ghcr.io/synssins/aerie:<tag>`, tags look like `sha-cd7b0e8`), waits until it answers, seeds it through aerie's own API, and hands the base address and credentials to the suites.

| File | What |
|---|---|
| `docker-compose.yml` | Runs the image on `AERIE_PORT` (default 8080) with an empty data volume. Optional `aerie.env` (git-ignored) for settings the build room documents |
| `seed.json` | The fixture: users, groups, spaces `LAB` and `PRIV`, pages, a personal access token and an OAuth client |
| `seed.py` | Waits for aerie, seeds `seed.json`, writes the hand-off file `reports/harness.json` |

```bash
AERIE_TAG=sha-cd7b0e8 docker compose -f harness/docker-compose.yml up -d
python -I harness/seed.py
docker compose -f harness/docker-compose.yml down -v
```

## Open gaps

The lab may not read aerie's source, and the image serves no API description the lab knows of. Each step below is reported by `seed.py` as a `GAP-*` line and recorded in the hand-off file instead of guessed. Until they close, the hand-off has `"seeded": false` and every suite fails.

| Gap | Needed from the build room |
|---|---|
| `GAP-HEALTH` | A health endpoint (the image declares no `HEALTHCHECK`); until then `seed.py` polls `AERIE_HEALTH_PATH`, default `/` |
| `GAP-ADMIN` | How the first administrator is created: settings for `aerie.env`, a setup call, or a CLI command |
| `GAP-SEED-*` | aerie's own API calls to create users, groups, spaces (with view permissions), pages (with parent and labels), personal access tokens and an OAuth client. Fill them in `SEED_CALLS` in `seed.py` |
