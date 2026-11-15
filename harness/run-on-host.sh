#!/usr/bin/env bash
# Runs the whole lab on a Docker host that has docker, git and curl but no java or node.
# It clones or updates the lab under $LAB_DIR, starts the aerie image under test as its own compose
# project "aerie-lab" (own network, throwaway volume, host port $AERIE_PORT), seeds it, generates the
# clients and runs the suites inside the "runner" container, writes everything to $LAB_DIR/reports/,
# and removes every container, network and volume of the project again.
#
# Usage on the host:         bash run-on-host.sh [image-tag]          (default tag: latest)
# From a workstation:        ssh docker-host 'bash -s -- latest' < harness/run-on-host.sh
# Settings (environment):    AERIE_PORT (default 18090; never 8080 or 8081), LAB_DIR (default ~/aerie-compat-lab),
#                            LAB_REPO, LAB_REF (branch to test, default main), SUITES (default datacenter/t1)
# Exit code: 0 when the harness worked (suite failures are results, not harness errors), 1 otherwise.
# It only ever touches the compose project aerie-lab and files under $LAB_DIR.
set -euo pipefail

TAG=${1:-${AERIE_TAG:-latest}}
PORT=${AERIE_PORT:-18090}
LAB_DIR=${LAB_DIR:-$HOME/aerie-compat-lab}
LAB_REPO=${LAB_REPO:-https://github.com/synssins/aerie-compat-lab}
LAB_REF=${LAB_REF:-main}
SUITES=${SUITES:-datacenter/t1}
PROJECT=aerie-lab

[[ "$TAG" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid aerie tag: '$TAG'" >&2; exit 1; }
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" != 8080 ] && [ "$PORT" != 8081 ] || { echo "refusing host port '$PORT'" >&2; exit 1; }

say() { echo "== $*"; }

say "lab checkout $LAB_DIR at $LAB_REF"
if [ -d "$LAB_DIR/.git" ]; then
  git -C "$LAB_DIR" fetch -q origin "$LAB_REF"
  git -C "$LAB_DIR" checkout -q --detach FETCH_HEAD
else
  git clone -q "$LAB_REPO" "$LAB_DIR"
  git -C "$LAB_DIR" fetch -q origin "$LAB_REF"
  git -C "$LAB_DIR" checkout -q --detach FETCH_HEAD
fi
cd "$LAB_DIR"
echo "lab commit $(git rev-parse --short HEAD)"

export AERIE_TAG=$TAG AERIE_PORT=$PORT LAB_UID=$(id -u) LAB_GID=$(id -g)
dc() { docker compose -p "$PROJECT" -f harness/docker-compose.yml --profile runner "$@"; }
# </dev/null: when this script arrives on stdin (ssh ... bash -s), docker would read the rest of it.
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
{"tag": "$TAG", "digest": "$digest", "lab_commit": "$(git rev-parse HEAD)", "host_port": $PORT,
 "generate_exit": $gen_rc, "seed_exit": $seed_rc, "suites_exit": $suite_rc, "finished": "$(date -u +%FT%TZ)"}
EOF
cat reports/run.json
[ "$seed_rc" = 0 ] && [ "$gen_rc" = 0 ]
