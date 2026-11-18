"""The lab's security/zap stage: OWASP ZAP scans of the lab's own aerie container, one scan per role.

Usage (inside the runner container, from harness/run-lab.sh):
  python -I security/zap/scan.py prep   --harness reports/harness.json --out reports/security-zap
  python -I security/zap/scan.py after  --role reader --out reports/security-zap   (after each role's scan)
  python -I security/zap/scan.py report --harness reports/harness.json --out reports/security-zap

prep (before the scans, while reports/harness.json still holds the seeded secrets):
  - adds one account per space role (lab-contributor, lab-supervisor, lab-owner; lab-user is the Reader
    and lab-admin the administrator) and grants the roles on a new space SCAN with one page;
  - signs each role in for a web session (the administrator gives a sign-in code, as the auth suite does);
  - takes aerie/openapi.yaml and datacenter/openapi.yaml from the pinned contract release in
    clients/specs.csv, and points their path parameters at real objects that only the administrator may
    see (space PRIV, its home page), so each role's scan reaches them;
  - runs the lab access check: every GET of both definitions as every role, flagging answers a role
    must not get;
  - writes one ZAP Automation Framework plan per role into <out>/work (with the session; deleted by report).
after (right after each role's scan): whether the role's session still works, and for each High or Medium
  GET the text around its evidence in a fresh answer.
report (after the scans): counts by risk and confidence per role, every High and Medium alert with its
  triage from security/zap/baseline.json, the gate (FAIL when a High or Medium is not in the baseline),
  secrets blanked with harness/redact.py, and the work folder removed.
"""
import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

LAB = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(LAB / "harness"))
from redact import scrub  # noqa: E402
from seed import Aerie, SeedError, totp  # noqa: E402

# The scan imports the newest contract release (plugins, page history, user deletion), pinned here so the
# suites keep their own pin in clients/specs.csv. contracts-v9, retrieved 2026-11-17.
SCAN_CONTRACT = ("contracts-v9", "https://github.com/synssins/aerie-spec/releases/download/contracts-v9/contracts-v9.tar.gz",
                 "b24ccc7cebde41efdb16fdfd154e95fe43a6565f1fb25d6960566542e43537b6")
TARGET = "http://aerie:8080"
SCAN_SPACE = "scan"
# (role, account, space role on SCAN); the Reader and the administrator are seeded by harness/seed.py.
ROLES = [("anonymous", None, None), ("reader", "lab-user", "Reader"), ("contributor", "lab-contributor", "Contributor"),
         ("supervisor", "lab-supervisor", "Supervisor"), ("owner", "lab-owner", "Owner"), ("admin", "lab-admin", None)]
# Never scanned: they would end the scan's own session or switch password sign-in off for every account.
# They are also taken out of the definitions ZAP imports, because the OpenAPI import sends every operation
# regardless of the context's exclusions.
EXCLUDE = [r".*/api/v1/auth/signout.*", r".*/api/v1/admin/auth/local/disable.*"]
# Operations taken out of the definitions only (the path's other methods are scanned): turning sign-in codes
# off ends every session of the account and gives the caller a new cookie, even when codes were not on, so the
# rest of a role's scan would run signed out (found 2026-11-16; administrators cannot turn codes off).
EXCLUDE_OPS = [("delete", "/api/v1/me/codes")]
RISKS = ["High", "Medium", "Low", "Informational"]
CONFIDENCES = ["Confirmed", "High", "Medium", "Low", "False Positive"]


def sign_in(base, user, password, totp_key=None):
    s = Aerie(base)
    answer = s.call("POST", "/auth/local/signin", {"userName": user, "password": password}, ok=(200, 409))
    if (answer or {}).get("step") == "code":
        for attempt in range(2):
            try:
                s.call("POST", "/auth/local/code", {"code": totp(totp_key)})
                break
            except SeedError:
                if attempt:
                    raise
                time.sleep(31 - time.time() % 30)  # a code is accepted once; the auth suite may have used this one
    return s


def cookie_header(session):
    return "; ".join(f"{k}={v}" for k, v in session.cookies.items() if k == "__Host-kb")


def contract_definitions(work):
    """Both definitions of the pinned contract release, as JSON (converted with the pinned generator jar)."""
    _, url, sha = SCAN_CONTRACT
    raw = urllib.request.urlopen(url, timeout=120).read()
    if hashlib.sha256(raw).hexdigest() != sha:
        raise SystemExit(f"REFUSED {url}: SHA-256 is not the pinned {sha}")
    jar = sorted((LAB / "clients/build/tools").glob("openapi-generator-cli-*.jar"))[-1]  # verified by generate.sh
    out = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        for name in ("aerie", "datacenter"):
            src = work / f"{name}.yaml"
            src.write_bytes(tar.extractfile(f"./{name}/openapi.yaml").read())
            subprocess.run(["java", "-jar", str(jar), "generate", "-i", str(src), "-g", "openapi", "-o", str(work / name)],
                           check=True, stdout=subprocess.DEVNULL)
            out[name] = json.loads((work / name / "openapi.json").read_text(encoding="utf-8"))
            shutil.rmtree(work / name)
            src.unlink()
    return out


def point_at(spec, ids):
    """Gives each path parameter an example naming a real object, so ZAP's requests reach it."""
    rules = [(r"/api/v1/(admin/)?spaces/\{id\}", ids["space"]), (r"/api/v1/pages/\{id\}", ids["page"]),
             (r"/api/v1/(admin/)?users/\{id\}", ids["user"]), (r"/api/v1/admin/groups/\{id\}", ids["group"]),
             (r"/api/v1/tokens/\{id\}", ids["token"]), (r"/api/v1/admin/plugins/\{id\}", ids.get("plugin"))]
    for path, item in spec["paths"].items():
        value = next((v for rx, v in rules if re.match(rx, path)), None)
        for p in item.get("parameters", []) + [p for op in item.values() if isinstance(op, dict) for p in op.get("parameters", [])]:
            if p.get("name") in ("spaceKey", "spaceKeySingle"):
                p["example"] = "PRIV"
            elif p.get("in") == "path" and p.get("name") == "id" and value:
                p["example"] = value


def requires_auth(spec, op):
    sec = op.get("security", spec.get("security", []))
    return bool(sec) and all(req for req in sec)


def access_check(base, sessions, specs, ids):
    """Every GET whose path parameters all name real objects, as every role. Flags answers a role must not get:
    2xx for an anonymous caller where the definition asks for authentication; 2xx for any role but the
    administrator on /api/v1/admin/ or on the space PRIV and its page."""
    secret_ids = (ids["space"], ids["page"], "PRIV")
    findings, calls = [], 0
    for name, spec in specs.items():
        for path, item in spec["paths"].items():
            op = item.get("get")
            if not op:
                continue
            url = path
            for p in item.get("parameters", []) + op.get("parameters", []):
                if p.get("in") == "path" and "example" in p:
                    url = url.replace("{" + p["name"] + "}", str(p["example"]))
            if "{" in url:
                continue
            for role, s in sessions.items():
                if role == "admin":
                    continue
                req = urllib.request.Request(base + url, headers={"Accept": "application/json", **({"Cookie": s} if s else {})})
                try:
                    with urllib.request.urlopen(req, timeout=30) as r:
                        status, body = r.status, r.read(300)
                except urllib.error.HTTPError as e:
                    status, body = e.code, e.read(300)
                calls += 1
                if not 200 <= status < 300 or "text/html" in str(body[:20]).lower() or body.lstrip()[:1] == b"<":
                    continue
                why = None
                if role == "anonymous" and requires_auth(spec, op):
                    why = "anonymous caller answered 2xx where the definition asks for authentication"
                elif url.startswith("/api/v1/admin/"):
                    why = f"{role} answered 2xx on an administrator route"
                elif any(x in url for x in secret_ids):
                    why = f"{role} answered 2xx for the space PRIV, which only lab-admin may see"
                if why:
                    findings.append({"role": role, "pluginid": "lab-access", "alert": "Access control (lab access check)",
                                     "risk": "High", "confidence": "High", "method": "GET", "uri": TARGET + url,
                                     "param": "", "evidence": f"HTTP {status}: {body.decode('utf-8', 'replace')[:200]}",
                                     "otherinfo": why})
    return findings, calls


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def raw(base, method, url, cookie=""):
    """One request without following redirects: (status, headers, first 400 bytes of the body)."""
    req = urllib.request.Request(base + url, method=method, headers={"Accept": "application/json", **({"Cookie": cookie} if cookie else {})})
    try:
        with urllib.request.build_opener(_NoRedirect).open(req, timeout=30) as r:
            return r.status, r.headers, r.read(400)
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read(400)


def finding(role, method, url, status, body, why, risk="High"):
    return {"role": role, "pluginid": "lab-access", "alert": "Access control (lab access check)", "risk": risk,
            "confidence": "High", "method": method, "uri": TARGET + url, "param": "",
            "evidence": f"HTTP {status}: {body.decode('utf-8', 'replace')[:200]}", "otherinfo": why}


# Plugin sign-in routes are not in any contract release yet (named by the spec room, 2026-11-17). No provider is
# reachable from the scan network, so the lab scans what answers without one. The query names are probes.
METHOD_PATHS = ["/api/v1/auth/methods", "/api/v1/auth/methods/outcome", "/api/v1/auth/methods/{plugin}/{method}/start",
                "/api/v1/auth/methods/{plugin}/{method}/callback"]
RETURN_PARAMS = ["returnUrl", "returnTo", "return", "redirect"]
OFFSITE = ["https://evil.example/x", "//evil.example/x", "/\\evil.example/x"]


def methods_definition(plugin, method):
    """An OpenAPI fragment for the plugin sign-in routes, so ZAP's import and active scan reach them."""
    q = lambda names: [{"name": n, "in": "query", "schema": {"type": "string"}, "example": "/"} for n in names]  # noqa: E731
    path = [{"name": "plugin", "in": "path", "required": True, "schema": {"type": "string"}, "example": plugin},
            {"name": "method", "in": "path", "required": True, "schema": {"type": "string"}, "example": method}]
    ops = [{}, {}, {"parameters": path + q(RETURN_PARAMS)}, {"parameters": path + q(["state", "code", "error", "error_description"])}]
    return {"openapi": "3.0.3", "info": {"title": "lab: plugin sign-in methods", "version": "lab"},
            "paths": {p: {"get": {"responses": {"default": {"description": "any"}}, **o}} for p, o in zip(METHOD_PATHS, ops)}}


def sign_in_methods(base, sessions):
    """Answers of the plugin sign-in routes without a provider: state handling, return path, error paths.
    Flags a 5xx, a redirect off the site, and a callback with no or a forged state that signs anyone in."""
    status, _, body = raw(base, "GET", "/api/v1/auth/methods")
    seen = {"GET /api/v1/auth/methods": f"HTTP {status}: {body.decode('utf-8', 'replace')[:300]}"}
    try:
        listed = json.loads(body) if status == 200 else []
        listed = listed.get("methods", listed) if isinstance(listed, dict) else listed
        first = next((m for m in listed if isinstance(m, dict)), {})
        plugin, method = first.get("plugin") or first.get("pluginId") or "lab-none", first.get("method") or first.get("id") or "lab-none"
    except ValueError:
        plugin, method = "lab-none", "lab-none"
    findings = []
    start, callback = f"/api/v1/auth/methods/{plugin}/{method}/start", f"/api/v1/auth/methods/{plugin}/{method}/callback"
    urls = ["/api/v1/auth/methods/outcome", start, callback, callback + "?error=access_denied",
            callback + "?state=lab-forged&code=lab", callback + "?code=lab"]
    urls += [f"{start}?{p}={urllib.parse.quote(v, safe='')}" for p in RETURN_PARAMS for v in OFFSITE]
    urls += [f"/api/v1/auth/methods/outcome?{p}={urllib.parse.quote(v, safe='')}" for p in RETURN_PARAMS for v in OFFSITE]
    for role in ("anonymous", "reader"):
        for url in urls:
            status, headers, body = raw(base, "GET", url, sessions[role])
            loc = headers.get("Location") or ""
            seen[f"{role} GET {url}"] = f"HTTP {status}" + (f" Location {loc}" if loc else "") + f": {body.decode('utf-8', 'replace')[:160]}"
            host = urllib.parse.urlsplit(loc.replace("\\", "/")).netloc
            cookies = [c for c in headers.get_all("Set-Cookie") or [] if c.startswith("__Host-kb=") and "=;" not in c[:12]]
            if status >= 500:
                findings.append(finding(role, "GET", url, status, body, "server error on a plugin sign-in route", "Medium"))
            if host and host not in ("aerie:8080", "aerie"):
                findings.append(finding(role, "GET", url, status, loc.encode(), f"redirect off the site to {loc}"))
            if "callback" in url and "error=" not in url and cookies:
                findings.append(finding(role, "GET", url, status, body, "callback without a valid state set a session cookie"))
    return findings, {"plugin": plugin, "method": method, "answers": seen}


def history_check(base, admin, sessions):
    """Page history is for members of the space only: in a Signed-in space where Reader is not a member, the page
    itself answers (control), but its versions, version, diff and the page's history field are refused."""
    sid = admin.call("POST", "/spaces", {"name": "History", "key": "hist", "description": "security/zap history",
                                         "isSensitive": False, "visibility": "SignedIn"})["id"]
    page = admin.call("POST", f"/spaces/{sid}/pages", {"parentId": None, "kind": "Page", "title": "History Home", "tags": None,
                                                        "contentJson": json.dumps({"type": "doc", "content": []})})
    pid, notes = page["id"], {}
    try:
        cur = admin.call("GET", f"/pages/{pid}")
        admin.call("PUT", f"/pages/{pid}", {"title": "History Home", "baseVersion": str(cur.get("version")), "major": True, "note": "v2",
                                             "contentJson": json.dumps({"type": "doc", "content": [{"type": "paragraph", "content": [{"type": "text", "text": "v2"}]}]})})
    except SeedError as e:
        notes["second_version"] = str(e)[:300]
    versions = admin.call("GET", f"/pages/{pid}/versions")
    items = versions.get("versions", versions.get("items", [])) if isinstance(versions, dict) else versions or []
    nums = [str(v.get("version", v.get("number", v.get("id")))) for v in items if isinstance(v, dict)] or ["1"]
    status, body = get(base + "/rest/api/content?spaceKey=HIST&title=History%20Home", cookie_header(admin))
    dc_id = (json.loads(body).get("results") or [{}])[0].get("id") if status == 200 and body.lstrip()[:1] == "{" else None
    refused = [f"/api/v1/pages/{pid}/versions", f"/api/v1/pages/{pid}/versions/{nums[-1]}",
               f"/api/v1/pages/{pid}/diff?from={nums[0]}&to={nums[-1]}"]
    if dc_id:
        refused += [f"/rest/api/content/{dc_id}/history", f"/rest/api/content/{dc_id}/version/1"]
    findings, seen = [], {"page": pid, "dc_id": dc_id, "versions": nums, **notes}
    for role in ("reader", "anonymous"):
        status, body = get(base + f"/api/v1/pages/{pid}", sessions[role])
        seen[f"{role} GET page"] = f"HTTP {status}"
        history = json.loads(body).get("history") if status == 200 and body.lstrip()[:1] == "{" else None
        seen[f"{role} page history field"] = json.dumps(history)[:200]
        if history:
            findings.append(finding(role, "GET", f"/api/v1/pages/{pid}", status, json.dumps(history).encode(),
                                    "a non-member got the page's history field in a Signed-in space"))
        for url in refused:
            status, _, body = raw(base, "GET", url, sessions[role])
            seen[f"{role} GET {url}"] = f"HTTP {status}"
            if 200 <= status < 300:
                findings.append(finding(role, "GET", url, status, body, "a non-member got page history in a Signed-in space"))
    for url in refused[:3]:  # control: the space's member (its creator) gets them
        seen[f"admin GET {url}"] = f"HTTP {raw(base, 'GET', url, cookie_header(admin))[0]}"
    return findings, seen


def delete_user_check(base, admin, sessions):
    """Deleting a user: refused for every role but the administrator, done for the administrator, gone afterwards.
    Only local users can be made here (no identity provider is reachable); the sources present are recorded."""
    users = admin.call("GET", "/admin/users")
    users = users.get("users", users.get("items", [])) if isinstance(users, dict) else users
    seen = {"sources": sorted({u.get("source", "?") for u in users if isinstance(u, dict)})}
    inv = admin.call("POST", "/admin/users/invite", {"userName": "lab-delete-me", "displayName": "Lab Delete Me", "isAdmin": False})
    url, findings = f"/api/v1/admin/users/{inv['id']}", []
    for role, _, _ in ROLES[:-1]:
        status, _, body = raw(base, "DELETE", url, sessions[role])
        seen[f"{role} DELETE"] = f"HTTP {status}"
        if 200 <= status < 300:
            findings.append(finding(role, "DELETE", url, status, body, f"{role} deleted a user"))
    seen["admin DELETE"] = f"HTTP {raw(base, 'DELETE', url, cookie_header(admin))[0]}"
    seen["admin GET after delete"] = f"HTTP {raw(base, 'GET', url, cookie_header(admin))[0]}"
    return findings, seen


def plan(role, cookie):
    rules = [{"description": "vendor-surface writes", "matchType": "req_header", "matchString": "X-Atlassian-Token",
              "matchRegex": False, "replacementString": "no-check"}]
    if cookie:
        rules.append({"description": f"{role} web session", "matchType": "req_header", "matchString": "Cookie",
                      "matchRegex": False, "replacementString": cookie})
    wait = {"type": "passiveScan-wait", "parameters": {"maxDuration": 15}}
    return {
        "env": {"contexts": [{"name": "aerie", "urls": [TARGET + "/"], "excludePaths": EXCLUDE}],
                "parameters": {"failOnError": False, "failOnWarning": False, "continueOnFailure": True}},
        "jobs": [
            # ZAP's Insights add-on ends the plan on a High insight, such as "100% authentication failures",
            # which an active scan of refusals always produces; blank means insights never end the plan.
            {"type": "insights", "parameters": {"exitAutoLevel": ""}},
            {"type": "replacer", "parameters": {"deleteAllRules": True}, "rules": rules},
            {"type": "openapi", "parameters": {"apiFile": "/zap/wrk/aerie.json", "targetUrl": TARGET, "context": "aerie"}},
            {"type": "openapi", "parameters": {"apiFile": "/zap/wrk/datacenter.json", "targetUrl": TARGET, "context": "aerie"}},
            {"type": "openapi", "parameters": {"apiFile": "/zap/wrk/methods.json", "targetUrl": TARGET, "context": "aerie"}},
            {"type": "spider", "parameters": {"context": "aerie", "url": TARGET + "/", "maxDuration": 5}},
            # The browser-driven spider: headless Firefox in the ZAP image, through ZAP's proxy (so the replacer adds
            # the session), on the internal scan network only. It reaches the web app's routes, plugin settings pages among them.
            {"type": "spiderAjax", "parameters": {"context": "aerie", "url": TARGET + "/", "maxDuration": 10,
                                                  "browserId": "firefox-headless", "numberOfBrowsers": 2}},
            wait,
            {"type": "activeScan", "parameters": {"context": "aerie"}},
            wait,
            {"type": "report", "parameters": {"template": "traditional-json", "reportDir": "/zap/wrk/out", "reportFile": role}},
        ],
    }


def prep(args):
    h = json.loads(Path(args.harness).read_text(encoding="utf-8"))
    base, out = h["base_url"], Path(args.out)
    work = out / "work"
    shutil.rmtree(work, ignore_errors=True)
    (work / "out").mkdir(parents=True)
    a = h["credentials"]["admin-password"]
    admin = sign_in(base, a["user"], a["password"], a.get("totp_key"))
    secrets = [c.get(k) for c in h["credentials"].values() for k in ("password", "totp_key", "basic_token")]
    secrets += [t["token"] for t in h["tokens"].values()]

    passwords = {"lab-user": h["credentials"]["user"]["password"]}
    sid = admin.call("POST", "/spaces", {"name": "Scan", "key": SCAN_SPACE, "description": "security/zap roles",
                                         "isSensitive": False, "visibility": "Private"})["id"]
    for role, user, space_role in ROLES:
        if user and user not in passwords and user != a["user"]:
            inv = admin.call("POST", "/admin/users/invite", {"userName": user, "displayName": f"Lab {role.title()}", "isAdmin": False})
            passwords[user] = os.urandom(18).hex()
            Aerie(base).call("POST", "/auth/local/password", {"userId": inv["id"], "token": inv["setPasswordToken"], "password": passwords[user]})
        if space_role:
            principal = next(p for p in admin.call("GET", f"/principals?q={user}") if p.get("type") == "User" and user in (p.get("name"), p.get("detail")))
            admin.call("PUT", f"/spaces/{sid}/roles", {"principalType": "User", "principalId": principal["id"], "role": space_role})
    admin.call("POST", f"/spaces/{sid}/pages", {"parentId": None, "kind": "Page", "title": "Scan Home", "tags": None,
                                                 "contentJson": json.dumps({"type": "doc", "content": []})})
    secrets += list(passwords.values())

    sessions = {}
    for role, user, _ in ROLES:
        if user is None:
            sessions[role] = ""
        elif user == a["user"]:
            sessions[role] = cookie_header(admin)
        else:
            sessions[role] = cookie_header(sign_in(base, user, passwords[user]))
    secrets += [c.split("=", 1)[1] for c in sessions.values() if c]

    aid = h["ids"]["aerie"]
    ids = {"space": aid["spaces"]["PRIV"], "page": aid["pages"]["priv_home"], "user": aid["users"]["lab-noaccess"],
           "group": aid["groups"]["lab-readers"], "token": aid["tokens"]["lab-admin-pat-lab"]}
    plugins = (admin.call("GET", "/admin/plugins") or {}).get("plugins") or []
    ids["plugin"] = plugins[0]["id"] if plugins else None
    probes = {"plugins": [{k: p.get(k) for k in ("id", "state", "source", "settings")} for p in plugins]}
    specs = contract_definitions(work)
    for name, spec in specs.items():
        spec["paths"] = {k: v for k, v in spec["paths"].items() if not any(re.fullmatch(x, k) for x in EXCLUDE)}
        for method, path in EXCLUDE_OPS:
            spec["paths"].get(path, {}).pop(method, None)
        point_at(spec, ids)
        (work / f"{name}.json").write_text(json.dumps(spec), encoding="utf-8")
    findings, calls = access_check(base, sessions, specs, ids)
    for name, check in (("sign_in_methods", lambda: sign_in_methods(base, sessions)),
                        ("history", lambda: history_check(base, admin, sessions)),
                        ("delete_user", lambda: delete_user_check(base, admin, sessions))):
        try:
            more, probes[name] = check()
            findings += more
        except (SeedError, KeyError, ValueError, OSError) as e:  # one failed probe must not stop the scan
            probes[name] = {"error": f"{type(e).__name__}: {e}"[:400]}
    m = probes.get("sign_in_methods", {})
    (work / "methods.json").write_text(json.dumps(methods_definition(m.get("plugin", "lab-none"), m.get("method", "lab-none"))), encoding="utf-8")
    ops =[(spec, op) for spec in specs.values() for item in spec["paths"].values() for m, op in item.items()
           if m in ("get", "put", "post", "delete", "patch")]
    token_closed = sum(1 for spec, op in ops if op.get("x-kb-api-token") == "closed")

    for role, _, _ in ROLES:
        (work / f"{role}.yaml").write_text(json.dumps(plan(role, sessions[role]), indent=1), encoding="utf-8")
    (work / "roles.txt").write_text("\n".join(r for r, _, _ in ROLES) + "\n", encoding="utf-8")
    (work / "secrets.json").write_text(json.dumps(sorted({s for s in secrets if s})), encoding="utf-8")
    (out / "prep.json").write_text(json.dumps({
        "contract": SCAN_CONTRACT[0], "operations": len(ops), "token_closed_operations": token_closed,
        "excluded": EXCLUDE + [f"{m.upper()} {p}" for m, p in EXCLUDE_OPS], "scan_space": SCAN_SPACE, "access_check_calls": calls, "access_findings": findings, "probes": probes,
        "roles": {role: (user or "none") for role, user, _ in ROLES}}, indent=2), encoding="utf-8")
    print(f"prep: {len(ops)} operations, {calls} access-check calls, {len(findings)} access finding(s), plans for {len(ROLES)} roles")


def get(url, cookie):
    req = urllib.request.Request(url, headers={"Accept": "application/json", **({"Cookie": cookie} if cookie else {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""


def after(args):
    """Right after one role's scan: is its session still signed in, and what do its High and Medium GETs answer
    now (the text around the evidence, for triage)."""
    work = Path(args.out) / "work"
    rules = json.loads((work / f"{args.role}.yaml").read_text(encoding="utf-8"))["jobs"][1]["rules"]
    cookie = next((r["replacementString"] for r in rules if r["matchString"] == "Cookie"), None)
    result = {"session": get(TARGET + "/api/v1/me", cookie)[0] if cookie else None, "excerpts": {}}
    f = work / "out" / f"{args.role}.json"
    for site in json.loads(f.read_text(encoding="utf-8")).get("site", []) if f.is_file() else []:
        for al in site.get("alerts", []):
            for i in al.get("instances", []) if al["riskcode"] in ("2", "3") else []:
                if i.get("method") == "GET" and i.get("evidence") and i["uri"] not in result["excerpts"]:
                    status, body = get(i["uri"], cookie)
                    at = body.find(i["evidence"])
                    result["excerpts"][i["uri"]] = f"HTTP {status}: " + (body[max(0, at - 200):at + 200] if at >= 0 else "(evidence not in a fresh answer) " + body[:300])
    (work / f"after-{args.role}.json").write_text(json.dumps(result), encoding="utf-8")


def matches(entry, inst):
    return (str(entry["pluginid"]) == str(inst["pluginid"])
            and re.fullmatch(entry.get("uri", ".*"), inst["uri"]) is not None
            and re.fullmatch(entry.get("param", ".*"), inst.get("param") or "") is not None
            and inst["role"] in entry.get("roles", [inst["role"]]))


def report(args):
    out = Path(args.out)
    work = out / "work"
    secrets = json.loads((work / "secrets.json").read_text(encoding="utf-8")) if (work / "secrets.json").is_file() else []
    prepped = json.loads((out / "prep.json").read_text(encoding="utf-8"))
    baseline = json.loads((LAB / "security/zap/baseline.json").read_text(encoding="utf-8"))["triaged"]
    times = dict(line.split() for line in (work / "times.txt").read_text().split("\n") if line.strip()) if (work / "times.txt").is_file() else {}

    instances, counts, missing = list(prepped["access_findings"]), {}, []
    for role, _, _ in ROLES:
        f = work / "out" / f"{role}.json"
        counts[role] = {r: {c: 0 for c in CONFIDENCES} for r in RISKS}
        if not f.is_file():
            missing.append(role)
            continue
        for site in json.loads(f.read_text(encoding="utf-8")).get("site", []):
            for al in site.get("alerts", []):
                risk = RISKS[3 - int(al["riskcode"])]
                conf = {"0": "False Positive", "1": "Low", "2": "Medium", "3": "High", "4": "Confirmed"}[str(al["confidence"])]
                for i in al.get("instances", []):
                    counts[role][risk][conf] += 1
                    if risk in ("High", "Medium"):
                        instances.append({"role": role, "pluginid": al["pluginid"], "alert": al["alert"], "risk": risk,
                                          "confidence": conf, "method": i.get("method", ""), "uri": i.get("uri", ""),
                                          "param": i.get("param", ""), "attack": (i.get("attack") or "")[:200], "evidence": (i.get("evidence") or "")[:200],
                                          "otherinfo": (i.get("otherinfo") or "")[:300]})
    for f in prepped["access_findings"]:
        counts[f["role"]]["High"]["High"] += 1
    for inst in instances:
        entry = next((e for e in baseline if matches(e, inst)), None)
        inst["triage"] = f"{entry['verdict']}: {entry['reason']}" if entry else "untriaged"

    alive = {}
    for role, _, _ in ROLES:
        f = work / f"after-{role}.json"
        after = json.loads(f.read_text(encoding="utf-8")) if f.is_file() else {}
        if after.get("session"):
            alive[role] = after["session"]
        for inst in instances:
            if inst["role"] == role and inst["uri"] in after.get("excerpts", {}):
                inst["response_excerpt"] = after["excerpts"][inst["uri"]]
    untriaged = [i for i in instances if i["triage"] == "untriaged"]
    lost = [r for r, status in alive.items() if status != 200]  # its scan ran, at least partly, signed out
    gate = "FAIL" if untriaged or missing or lost else "PASS"
    summary = {"gate": gate, "untriaged": len(untriaged), "roles_without_report": missing, "roles_signed_out": lost, "seconds": times,
               "session_after_scan": alive, **{k: prepped[k] for k in ("contract", "operations", "token_closed_operations", "excluded", "roles", "access_check_calls")},
               "probes": prepped.get("probes", {}),
               "counts": counts, "high_medium": instances}
    text = scrub(json.dumps(summary, indent=2), secrets)
    (out / "summary.json").write_text(text, encoding="utf-8")
    summary = json.loads(text)
    (out / "matrix.md").write_text(matrix(summary), encoding="utf-8")
    for f in list((work / "out").glob("*.json")):
        (out / f.name).write_text(scrub(f.read_text(encoding="utf-8"), secrets), encoding="utf-8")
    (out / "prep.json").write_text(scrub((out / "prep.json").read_text(encoding="utf-8"), secrets), encoding="utf-8")
    for log in out.glob("*.log"):
        log.write_text(scrub(log.read_text(encoding="utf-8", errors="replace"), secrets), encoding="utf-8")
    shutil.rmtree(work)
    print(f"security/zap: {gate}, {len(instances)} High/Medium instance(s), {len(untriaged)} untriaged"
          + (f", no report for {', '.join(missing)}" if missing else ""))


def matrix(s):
    rows = ["# security/zap", "",
            f"Gate: **{s['gate']}** ({s['untriaged']} High or Medium not in `security/zap/baseline.json`"
            + (f"; no ZAP report for {', '.join(s['roles_without_report'])}" if s["roles_without_report"] else "")
            + (f"; signed out by the end of its scan: {', '.join(s['roles_signed_out'])}" if s["roles_signed_out"] else "") + ")", "",
            f"Contract `{s['contract']}`: {s['operations']} operations; {s['token_closed_operations']} are closed to tokens "
            "(`x-kb-api-token: closed`), so every role scans with a web session. Not scanned: "
            + ", ".join(f"`{x}`" for x in s["excluded"]) + ".", "",
            "| Role | Account | Seconds | Session after scan | High | Medium | Low | Info |", "|---|---|---|---|---|---|---|---|"]
    for role, c in s["counts"].items():
        rows.append(f"| {role} | {s['roles'][role]} | {s['seconds'].get(role, '-')} | {s['session_after_scan'].get(role, '-')} | "
                    + " | ".join(str(sum(c[r].values())) for r in RISKS) + " |")
    rows += ["", "Alert instances by risk and confidence:", "", "| Role | Risk | " + " | ".join(CONFIDENCES) + " |",
             "|---|---|" + "---|" * len(CONFIDENCES)]
    for role, c in s["counts"].items():
        for r in RISKS:
            if sum(c[r].values()):
                rows.append(f"| {role} | {r} | " + " | ".join(str(c[r][x]) for x in CONFIDENCES) + " |")
    groups = {}
    for i in s["high_medium"]:
        groups.setdefault((i["risk"], i["pluginid"], i["alert"], i["triage"]), []).append(i)
    rows += ["", "## High and Medium", "", "Every instance, with URL, parameter and evidence, is in `summary.json`.", ""]
    for (risk, pid, alert, triage), items in sorted(groups.items()):
        roles = sorted({i["role"] for i in items})
        rows += [f"### {risk}: {alert} (`{pid}`), {len(items)} instance(s)", "", f"Roles: {', '.join(roles)}. Triage: {triage}", ""]
        for i in items[:5]:
            rows.append(f"- {i['role']} {i['method']} `{i['uri']}` param `{i['param']}` evidence `{i['evidence'][:80]}`"
                        + (f" attack `{i['attack'][:80]}`" if i.get("attack") else ""))
        if len(items) > 5:
            rows.append(f"- ... {len(items) - 5} more")
        rows.append("")
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["prep", "after", "report"])
    ap.add_argument("--role")
    ap.add_argument("--harness", default="reports/harness.json")
    ap.add_argument("--out", default="reports/security-zap")
    a = ap.parse_args()
    {"prep": prep, "after": after, "report": report}[a.step](a)
