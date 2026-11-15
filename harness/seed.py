"""Wait for the aerie container, seed it from seed.json, and write the hand-off file for the suites.

Usage: python -I harness/seed.py [--base-url http://localhost:8080] [--out reports/harness.json]

Environment:
  AERIE_BASE_URL        default http://localhost:${AERIE_PORT:-8080}
  AERIE_HEALTH_PATH     path polled until it answers below 500 (default "/": see GAP-HEALTH)
  AERIE_ADMIN_USER / AERIE_ADMIN_PASSWORD
                        first administrator, however the build room says it is created (GAP-ADMIN)

Seeding goes through aerie's own API only. The lab may not read aerie's source and the image serves
no API description the lab knows of, so every seed call below is an open GAP: the step is reported,
not guessed. When the build room publishes the calls, fill in SEED_CALLS. Until then the hand-off has
"seeded": false and the suites fail, which is the expected Phase 1 state.
"""
import argparse
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent

GAPS = {
    "GAP-HEALTH": "No documented health endpoint; the image declares no HEALTHCHECK. Polling AERIE_HEALTH_PATH (default /).",
    "GAP-ADMIN": "How aerie creates its first administrator (env setting, setup endpoint or CLI) is not documented to the lab.",
}

# kind -> function(base_url, admin_auth, item) -> dict of ids/secrets. None = call not known yet (a GAP).
SEED_CALLS = {
    "users": None,
    "groups": None,
    "spaces": None,
    "pages": None,
    "tokens": None,
    "oauth_clients": None,
}


def wait_until_up(base_url, path, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(base_url + path, timeout=5) as r:
                return r.status
        except urllib.error.HTTPError as e:
            if e.code < 500:
                return e.code
            last = f"HTTP {e.code}"
        except OSError as e:
            last = str(e)
        time.sleep(2)
    raise SystemExit(f"aerie did not answer at {base_url}{path} within {timeout_s}s: {last}")


def main():
    ap = argparse.ArgumentParser()
    port = os.environ.get("AERIE_PORT", "8080")
    ap.add_argument("--base-url", default=os.environ.get("AERIE_BASE_URL", f"http://localhost:{port}"))
    ap.add_argument("--out", default="reports/harness.json")
    ap.add_argument("--timeout", type=int, default=180)
    args = ap.parse_args()
    base = args.base_url.rstrip("/")

    status = wait_until_up(base, os.environ.get("AERIE_HEALTH_PATH", "/"), args.timeout)
    print(f"aerie is up at {base} (HTTP {status})")

    plan = json.loads((HERE / "seed.json").read_text(encoding="utf-8"))
    admin_user = os.environ.get("AERIE_ADMIN_USER", "")
    admin_password = os.environ.get("AERIE_ADMIN_PASSWORD", "")
    gaps = dict(GAPS)
    if admin_user and admin_password:
        gaps.pop("GAP-ADMIN")

    # Lab users get fresh random passwords each run; they exist only inside the throwaway container.
    credentials = {u["name"]: {"user": u["name"], "password": secrets.token_urlsafe(18)} for u in plan["users"]}
    credentials["lab-admin"] = {"user": admin_user or "lab-admin", "password": admin_password or credentials["lab-admin"]["password"]}

    ids = {}
    for kind, call in SEED_CALLS.items():
        if call is None:
            gaps[f"GAP-SEED-{kind.upper()}"] = f"aerie's own API call to create {kind} is not known to the lab; {len(plan[kind])} item(s) not seeded."
            continue
        for item in plan[kind]:
            ids.update(call(base, credentials["lab-admin"], item))

    seeded = not any(k.startswith("GAP-SEED") or k == "GAP-ADMIN" for k in gaps)
    handoff = {
        "base_url": base,
        "seeded": seeded,
        "credentials": {"admin": credentials["lab-admin"], "user": credentials["lab-user"], "noaccess": credentials["lab-noaccess"]},
        "ids": ids,
        "plan": plan,
        "gaps": gaps,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(handoff, indent=2), encoding="utf-8")
    for k, v in gaps.items():
        print(f"{k}: {v}")
    print(f"hand-off written to {out} (seeded={seeded})")


if __name__ == "__main__":
    sys.exit(main())
