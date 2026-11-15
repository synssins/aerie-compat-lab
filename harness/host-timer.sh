#!/usr/bin/env bash
# The lab's own timer on the Docker host, for user synthesis's crontab (no sudo, no system unit).
# Every 30 minutes it reads the digest of ghcr.io/synssins/aerie:$TAG anonymously and, when no earlier
# timer run tested that digest, runs harness/run-on-host.sh (compose project aerie-lab only).
#
#   bash harness/host-timer.sh install   copy this script to $STATE/host-timer.sh, add one crontab line
#   bash harness/host-timer.sh remove    take the crontab line out (state and saved runs stay)
#   bash harness/host-timer.sh run       what cron calls; also safe to call by hand
#
# Settings (environment, or put in the crontab line): TAG (default latest), LAB_REF (default main),
# LAB_DIR (default ~/aerie-compat-lab). State lives in $LAB_DIR/.timer (git-ignored): the log, the
# tested digests, a lock, and runs/<UTC time>/ with run.json and the matrices of each run.
# The whole body is one { } block, so bash has read all of it before run-on-host.sh moves the checkout.
{
set -uo pipefail
TAG=${TAG:-latest}
LAB_REF=${LAB_REF:-main}
LAB_DIR=${LAB_DIR:-$HOME/aerie-compat-lab}
STATE=$LAB_DIR/.timer
MARK="# aerie-compat-lab host timer"
mkdir -p "$STATE/runs"

case "${1:-run}" in
  install)
    cp "$0" "$STATE/host-timer.sh"
    line="*/30 * * * * TAG=$TAG LAB_REF=$LAB_REF LAB_DIR=$LAB_DIR flock -n $STATE/lock bash $STATE/host-timer.sh run >> $STATE/log 2>&1 $MARK"
    { crontab -l 2>/dev/null | grep -vF "$MARK"; echo "$line"; } | crontab -
    crontab -l | grep -F "$MARK"
    exit 0 ;;
  remove)
    { crontab -l 2>/dev/null | grep -vF "$MARK"; } | crontab -
    echo "removed"; exit 0 ;;
  run) ;;
  *) echo "usage: $0 install|remove|run" >&2; exit 2 ;;
esac

[[ "$TAG" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid aerie tag: '$TAG'" >&2; exit 1; }
now=$(date -u +%Y%m%dT%H%M%SZ)
token=$(curl -fsS "https://ghcr.io/token?scope=repository:synssins/aerie:pull" | jq -r .token)
digest=$(curl -fsSI -H "Authorization: Bearer $token" \
  -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json" \
  "https://ghcr.io/v2/synssins/aerie/manifests/$TAG" | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}')
[ -n "$digest" ] || { echo "$now no digest for ghcr.io/synssins/aerie:$TAG"; exit 1; }
if grep -qxF "$digest" "$STATE/tested" 2>/dev/null; then
  echo "$now $TAG is $digest, already tested"; exit 0
fi

echo "$now $TAG is $digest, running the lab at $LAB_REF"
# run-on-host.sh is taken from the ref under test, so the checkout it moves is never the script running.
git -C "$LAB_DIR" fetch -q origin "$LAB_REF"
git -C "$LAB_DIR" show FETCH_HEAD:harness/run-on-host.sh | LAB_REF=$LAB_REF bash -s -- "$TAG"
rc=$?
out=$STATE/runs/$now
mkdir -p "$out"
cp "$LAB_DIR/reports/run.json" "$out/" 2>/dev/null
for m in "$LAB_DIR"/reports/*/matrix.md; do [ -f "$m" ] && cp "$m" "$out/$(basename "$(dirname "$m")").md"; done
[ "$rc" -eq 0 ] && echo "$digest" >> "$STATE/tested"
echo "$(date -u +%Y%m%dT%H%M%SZ) finished with exit $rc, saved in $out"
exit "$rc"
}
