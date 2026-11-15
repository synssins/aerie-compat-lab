#!/usr/bin/env bash
# Runs the whole lab on a Docker host that has docker, git and curl but no java or node: clones or
# updates the lab under $LAB_DIR at $LAB_REF, then runs harness/run-lab.sh there (compose project
# "aerie-lab", host port $AERIE_PORT, reports in $LAB_DIR/reports/, project removed afterwards).
#
# Usage on the host:         bash run-on-host.sh [image-tag]          (default tag: latest)
# From a workstation:        ssh docker-host 'bash -s -- latest' < harness/run-on-host.sh
# Settings (environment):    AERIE_PORT (default 18090; never 8080 or 8081), LAB_DIR (default ~/aerie-compat-lab),
#                            LAB_REPO, LAB_REF (branch to test, default main), SUITES (default "datacenter/t1 auth")
# Exit code: 0 when the harness worked (suite failures are results, not harness errors), 1 otherwise.
# It only ever touches the compose project aerie-lab and files under $LAB_DIR.
set -euo pipefail

TAG=${1:-${AERIE_TAG:-latest}}
LAB_DIR=${LAB_DIR:-$HOME/aerie-compat-lab}
LAB_REPO=${LAB_REPO:-https://github.com/synssins/aerie-compat-lab}
LAB_REF=${LAB_REF:-main}

[[ "$TAG" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid aerie tag: '$TAG'" >&2; exit 1; }

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
exec bash harness/run-lab.sh "$TAG"
