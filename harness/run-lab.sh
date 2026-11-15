#!/usr/bin/env bash
# Runs the lab in this checkout against one aerie image: starts the image as its own compose project
# "aerie-lab" (own network, throwaway volume, host port $AERIE_PORT), generates and builds the clients,
# seeds aerie and runs the suites inside the "runner" container, writes reports/, and removes every
# container, network and volume of the project again. Needs only docker (with compose) and curl.
# Used by run-on-host.sh on the Docker host and by .github/workflows/lab.yml.
#
# Usage: bash harness/run-lab.sh [image-tag]          (default tag: latest)
# Settings (environment): AERIE_PORT (default 18090; never 8080 or 8081), SUITES (default datacenter/t1)
# Exit code: 0 when the harness worked (suite failures are results, not harness errors), 1 otherwise.
set -euo pipefail

TAG=${1:-${AERIE_TAG:-latest}}
PORT=${AERIE_PORT:-18090}
SUITES=${SUITES:-datacenter/t1}
PROJECT=aerie-lab

[[ "$TAG" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid aerie tag: '$TAG'" >&2; exit 1; }
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" != 8080 ] && [ "$PORT" != 8081 ] || { echo "refusing host port '$PORT'" >&2; exit 1; }

say() { echo "== $*"; }
cd "$(dirname "$0")/.."
echo "lab commit $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

export AERIE_TAG=$TAG AERIE_PORT=$PORT LAB_UID=$(id -u) LAB_GID=$(id -g)
dc() { docker compose -p "$PROJECT" -f harness/docker-compose.yml --profile runner "$@"; }
# </dev/null: docker must never read this script's stdin (run-on-host.sh may arrive on it).
runner() { dc run --rm -T runner "$@" </dev/null; }
teardown() {
  say "teardown of project $PROJECT"
  dc down -v --remove-orphans </dev/null >/dev/null 2>&1 || true
  left=$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")
  [ -z "$left" ] && echo "no $PROJECT containers left" || echo "WARNING: $PROJECT containers left: $left" >&2
}
trap teardown EXIT

# A clean slate: an aborted earlier run may have left the project behind.
dc down -v --remove-orphans </dev/null >/dev/null 2>&1 || true
if (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | awk '{print $4}' | grep -qE "[:.]$PORT\$"; then
  echo "host port $PORT is in use; set AERIE_PORT to a free one" >&2
  exit 1
fi
rm -rf reports && mkdir -p reports

say "runner image"
dc build -q runner </dev/null

say "image ghcr.io/synssins/aerie:$TAG"
dc pull -q aerie </dev/null
digest=$(docker image inspect -f '{{index .RepoDigests 0}}' "ghcr.io/synssins/aerie:$TAG")
echo "digest $digest"

say "client generation"
gen_rc=0
runner bash clients/generate.sh >reports/generate.log 2>&1 || gen_rc=$?
grep -E '^(==|   )' reports/generate.log | grep -vE 'hash ok| ok$' || true
echo "generate.sh exit $gen_rc ($(grep -cE ' (java|python|typescript-axios) ok$' reports/generate.log) language builds ok)"

say "self-checks"
runner python -I suites/test_run.py
runner python -I harness/test_seed.py

say "start aerie on host port $PORT"
dc up -d aerie </dev/null
for _ in $(seq 1 90); do
  curl -sf -o /dev/null "http://localhost:$PORT/api/v1/setup/status" && break
  sleep 2
done
# The remote setup code only exists inside this run's throwaway container; it is never written to disk.
AERIE_SETUP_CODE=$(dc exec -T aerie cat /app/App_Data/setup-code.txt </dev/null 2>/dev/null || true)
export AERIE_SETUP_CODE

say "seed"
seed_rc=0
runner python -I harness/seed.py --base-url http://aerie:8080 --out reports/harness.json || seed_rc=$?
unset AERIE_SETUP_CODE

suite_rc=0
for suite in $SUITES; do
  say "suite $suite"
  runner python -I suites/run.py "suites/$suite" --harness reports/harness.json --out "reports/${suite//\//-}" \
    >"reports/${suite//\//-}.log" 2>&1 || suite_rc=$?
  grep -E '^(Totals|- )' "reports/${suite//\//-}.log" || tail -n 5 "reports/${suite//\//-}.log"
done

dc logs --no-color aerie </dev/null >reports/aerie.log 2>&1 || true
runner python -I harness/redact.py reports/harness.json
cat >reports/run.json <<EOF
{"tag": "$TAG", "digest": "$digest", "lab_commit": "$(git rev-parse HEAD 2>/dev/null || echo unknown)", "host_port": $PORT,
 "generate_exit": $gen_rc, "seed_exit": $seed_rc, "suites_exit": $suite_rc, "finished": "$(date -u +%FT%TZ)"}
EOF
cat reports/run.json
[ "$seed_rc" = 0 ] && [ "$gen_rc" = 0 ]
