"""Wait for a fresh aerie container, seed it from seed.json, and write the hand-off file for the suites.

Usage: python -I harness/seed.py [--base-url http://localhost:8080] [--out reports/harness.json]

Environment:
  AERIE_BASE_URL        default http://localhost:${AERIE_PORT:-8080}
  AERIE_HEALTH_PATH     polled until it answers 200 JSON (default /api/v1/setup/status, see GAP-HEALTH)
  AERIE_SETUP_CODE      the remote setup code a fresh image writes to /app/App_Data/setup-code.txt
                        (read it with `docker compose exec -T aerie cat /app/App_Data/setup-code.txt`)

Seeding goes through aerie's own API only, as described by the published contract release
contracts-v1 (aerie/openapi.yaml, "Aerie API (as-is)" under /api/v1). Steps aerie's API has no call
for stay open GAPs: they are reported and recorded in the hand-off file, not guessed.
"""
import argparse
import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import struct
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
API = "/api/v1"

GAPS = {
    "GAP-HEALTH": "aerie serves no health endpoint (every unknown path returns the web app with 200 text/html); "
                  "readiness is GET /api/v1/setup/status answering 200 JSON.",
}
FIXTURE_GAPS = {
    "GAP-PAGE-PARENT": "aerie nests pages only under folders; fixture pages with children (lab_home) are seeded as Folder.",
}
OPEN_SEED_GAPS = {
    "oauth_clients": "aerie's API (contracts-v1) has no call to register an OAuth client; item(s) not seeded.",
}


class SeedError(Exception):
    pass


class Aerie:
    """Minimal JSON client for aerie's own API with its session cookies.

    The cookies (__Host-kb, and __Host-kb-pending during sign-in steps) are Secure; stdlib cookie jars
    will not send them back over the plain-HTTP lab network, so they are carried by hand."""

    def __init__(self, base):
        self.base = base
        self.cookies = {}

    def call(self, method, path, body=None, ok=(200, 201, 204)):
        """Returns the JSON body; a 409 listed in ok returns its body too (aerie's {"step": ...} answers)."""
        req = urllib.request.Request(self.base + API + path, method=method,
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={"Accept": "application/json", "Content-Type": "application/json"})
        if self.cookies:
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in self.cookies.items()))
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                status, headers, raw = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            status, headers, raw = e.code, e.headers, e.read()
        for c in headers.get_all("Set-Cookie") or []:
            name, _, value = c.split(";", 1)[0].partition("=")
            if name.startswith("__Host-kb"):
                self.cookies[name] = value
        if status not in ok:
            raise SeedError(f"{method} {API}{path} -> HTTP {status}: {raw[:500].decode('utf-8', 'replace')}")
        return json.loads(raw) if raw.strip() else None

    def signin(self, user, password):
        self.cookies = {}
        self.call("POST", "/auth/local/signin", {"userName": user, "password": password})
        return self


def wait_until_up(base_url, path, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(base_url + path, timeout=5) as r:
                if r.status == 200 and "json" in (r.headers.get("Content-Type") or ""):
                    return json.loads(r.read())
                last = f"HTTP {r.status} {r.headers.get('Content-Type')}"
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
        except OSError as e:
            last = str(e)
        time.sleep(2)
    raise SystemExit(f"aerie did not answer at {base_url}{path} within {timeout_s}s: {last}")


def totp(key, at=None):
    """RFC 6238 code (SHA-1, 6 digits, 30 s), the parameters aerie's otpauth URI states."""
    k = base64.b32decode(key.upper() + "=" * (-len(key) % 8))
    digest = hmac.new(k, struct.pack(">Q", int((at or time.time()) // 30)), hashlib.sha1).digest()
    off = digest[-1] & 15
    return "%06d" % ((struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000)


def content_json(body_html):
    """shortcut: storage-format fixture bodies become plain paragraphs in aerie's editor JSON; upgrade
    when a suite checks rich bodies."""
    paras = [html.unescape(re.sub(r"<[^>]+>", "", p)) for p in re.findall(r"<p>(.*?)</p>", body_html, re.S)] or [body_html]
    return json.dumps({"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": t}]} for t in paras if t]})


def expand_pages(plan_pages):
    for p in plan_pages:
        if "count" in p:
            for n in range(1, p["count"] + 1):
                yield dict(p, ref=f"{p['ref']}_{n:02}", title=p["title"].format(n=n), body=p["body"].format(n=n))
        else:
            yield p


def seed(base, plan, setup_code):
    """Seeds a fresh image. Returns (credentials, tokens, ids, steps). Raises SeedError on the first failed call."""
    steps = []
    admin_plan = next(u for u in plan["users"] if u.get("admin"))
    status = Aerie(base).call("GET", "/setup/status")
    if not status.get("required"):
        raise SeedError("aerie is already set up; the harness seeds only a fresh image")
    if status.get("codeRequired") and not setup_code:
        raise SeedError("setup needs the remote setup code: set AERIE_SETUP_CODE (see seed.py docstring)")
    admin, admin_user, admin_password = Aerie(base), admin_plan["name"], secrets.token_urlsafe(18)
    answer = admin.call("POST", "/setup", {"userName": admin_user, "displayName": admin_plan["display"],
                                           "password": admin_password, "code": setup_code or None}, ok=(200, 409))
    steps.append(f"setup: first administrator {admin_user} created by POST /api/v1/setup")
    totp_key = None
    if (answer or {}).get("step") == "enroll":
        # Administrators must enroll sign-in codes (GET /api/v1/admin/settings/codes answers requiredFor "admins").
        totp_key = admin.call("POST", "/auth/codes/key", {})["key"]
        admin.call("POST", "/auth/codes", {"code": totp(totp_key)})
        steps.append("setup: admin enrolled sign-in codes (POST /api/v1/auth/codes/key, then POST /api/v1/auth/codes with a TOTP code)")
    elif answer and "step" in answer:
        raise SeedError(f"POST /api/v1/setup asked for an unknown step: {answer}")
    me = admin.call("GET", "/me")
    if not me.get("isAdmin"):
        raise SeedError(f"{admin_user} is not an administrator")

    credentials = {admin_plan["name"]: {"user": admin_user, "password": admin_password, "totp_key": totp_key}}
    ids = {"users": {admin_plan["name"]: me["id"]}, "groups": {}, "spaces": {}, "pages": {}, "tokens": {}}
    for u in plan["users"]:
        if u is admin_plan:
            continue
        inv = admin.call("POST", "/admin/users/invite", {"userName": u["name"], "displayName": u["display"], "isAdmin": False})
        pw = secrets.token_urlsafe(18)
        Aerie(base).call("POST", "/auth/local/password", {"userId": inv["id"], "token": inv["setPasswordToken"], "password": pw})
        credentials[u["name"]] = {"user": u["name"], "password": pw}
        ids["users"][u["name"]] = inv["id"]
    steps.append(f"users: {len(plan['users']) - 1} invited (POST /api/v1/admin/users/invite) and given passwords (POST /api/v1/auth/local/password)")

    group_keys = {}
    for g in plan["groups"]:
        made = admin.call("POST", "/admin/groups", {"name": g["name"]})
        ids["groups"][g["name"]], group_keys[g["name"]] = made["id"], made["key"]
    for u in plan["users"]:
        for g in u.get("groups", []):
            admin.call("PUT", f"/admin/groups/{ids['groups'][g]}/members/{ids['users'][u['name']]}")
    steps.append(f"groups: {len(plan['groups'])} created (POST /api/v1/admin/groups), members added (PUT .../members/{{userId}})")

    for s in plan["spaces"]:
        # aerie space keys are 2-32 lowercase letters, digits and hyphens; the vendor surface uses uppercase.
        sid = admin.call("POST", "/spaces", {"name": s["name"], "key": s["key"].lower(), "description": s["description"],
                                              "isSensitive": False, "visibility": "Private"})["id"]
        ids["spaces"][s["key"]] = sid
        for g in s["view"]:
            # Space roles name a group by its key ("local:<id>"), as GET /api/v1/principals lists it.
            admin.call("PUT", f"/spaces/{sid}/roles", {"principalType": "Group", "principalId": group_keys[g], "role": "Reader"})
    steps.append(f"spaces: {len(plan['spaces'])} created private (POST /api/v1/spaces), view groups granted Reader (PUT /api/v1/spaces/{{id}}/roles)")

    pages = list(expand_pages(plan["pages"]))
    # aerie nests pages only under folders ("parentId: Must be a folder in this space"), so a fixture page
    # with children is created as a Folder (GAP-PAGE-PARENT).
    parents = {p["parent"] for p in pages if p.get("parent")}
    for p in pages:
        parent = ids["pages"][p["parent"]] if p.get("parent") else None
        ids["pages"][p["ref"]] = admin.call("POST", f"/spaces/{ids['spaces'][p['space']]}/pages", {
            "parentId": parent, "kind": "Folder" if p["ref"] in parents else "Page", "title": p["title"],
            "tags": p.get("labels") or None, "contentJson": content_json(p["body"])})["id"]
    steps.append(f"pages: {len(pages)} created with labels as tags, {len(parents)} parent(s) as Folder (POST /api/v1/spaces/{{id}}/pages)")

    tokens = {}
    for t in plan["tokens"]:
        owner = Aerie(base).signin(credentials[t["user"]]["user"], credentials[t["user"]]["password"])
        made = owner.call("POST", "/tokens", {"name": t["name"], "kind": "Personal", "days": t.get("days", 30),
                                              "scopes": [{"spaceId": None, "access": t.get("access", "Read")}]})
        tokens[t["name"]] = {"user": t["user"], "token": made["token"]}
        ids["tokens"][t["name"]] = made["info"]["id"]
    steps.append(f"tokens: {len(plan['tokens'])} personal token(s) created by their owner (POST /api/v1/tokens)")
    return credentials, tokens, ids, steps


def main():
    ap = argparse.ArgumentParser()
    port = os.environ.get("AERIE_PORT", "8080")
    ap.add_argument("--base-url", default=os.environ.get("AERIE_BASE_URL", f"http://localhost:{port}"))
    ap.add_argument("--out", default="reports/harness.json")
    ap.add_argument("--timeout", type=int, default=180)
    args = ap.parse_args()
    base = args.base_url.rstrip("/")

    status = wait_until_up(base, os.environ.get("AERIE_HEALTH_PATH", API + "/setup/status"), args.timeout)
    print(f"aerie is up at {base} (setup status {json.dumps(status)})")

    plan = json.loads((HERE / "seed.json").read_text(encoding="utf-8"))
    gaps = dict(GAPS)
    credentials, tokens, ids, steps, error = {}, {}, {}, [], None
    try:
        credentials, tokens, ids, steps = seed(base, plan, os.environ.get("AERIE_SETUP_CODE", "").strip())
    except SeedError as e:
        error = str(e)
        gaps["GAP-SEED-FAILED"] = error
    gaps.update(FIXTURE_GAPS)
    for kind, why in OPEN_SEED_GAPS.items():
        if plan.get(kind):
            gaps[f"GAP-SEED-{kind.upper()}"] = why

    missing = {"user": "", "password": ""}
    handoff = {
        "base_url": base,
        # The OAuth client gap does not block suites that use basic auth or tokens.
        "seeded": error is None,
        "credentials": {"admin": credentials.get("lab-admin", missing), "user": credentials.get("lab-user", missing),
                        "noaccess": credentials.get("lab-noaccess", missing)},
        "tokens": tokens,
        # aerie's own ids, nested so they never shadow the suites' vendor-surface fixtures.
        "ids": {"aerie": ids},
        "steps": steps,
        "plan": plan,
        "gaps": gaps,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(handoff, indent=2), encoding="utf-8")
    for s in steps:
        print("OK  " + s)
    for k, v in gaps.items():
        print(f"{k}: {v}")
    print(f"hand-off written to {out} (seeded={handoff['seeded']})")
    return 0 if error is None else 1


if __name__ == "__main__":
    sys.exit(main())
