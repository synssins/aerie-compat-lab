"""The lab's security/zap stage: OWASP ZAP scans of the lab's own aerie container, one scan per role.

Usage (inside the runner container, from harness/run-lab.sh):
  python -I security/zap/scan.py prep   --harness reports/harness.json --out reports/security-zap
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
import urllib.request
from pathlib import Path

LAB = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(LAB / "harness"))
from redact import scrub  # noqa: E402
from seed import Aerie, SeedError, totp  # noqa: E402

CONTRACT = "aerie-dc-contracts-v6"
TARGET = "http://aerie:8080"
SCAN_SPACE = "scan"
# (role, account, space role on SCAN); the Reader and the administrator are seeded by harness/seed.py.
ROLES = [("anonymous", None, None), ("reader", "lab-user", "Reader"), ("contributor", "lab-contributor", "Contributor"),
         ("supervisor", "lab-supervisor", "Supervisor"), ("owner", "lab-owner", "Owner"), ("admin", "lab-admin", None)]
# Never scanned: they would end the scan's own session or switch password sign-in off for every account.
EXCLUDE = [r".*/api/v1/auth/signout.*", r".*/api/v1/admin/auth/local/disable.*"]
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
    row = next(line.split(",") for line in (LAB / "clients/specs.csv").read_text(encoding="utf-8").splitlines()
               if line.startswith(CONTRACT + ","))
    url, sha = row[3].split("#")[0], row[4].strip()
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
             (r"/api/v1/tokens/\{id\}", ids["token"])]
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
            {"type": "spider", "parameters": {"context": "aerie", "url": TARGET + "/", "maxDuration": 5}},
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
    specs = contract_definitions(work)
    for name, spec in specs.items():
        point_at(spec, ids)
        (work / f"{name}.json").write_text(json.dumps(spec), encoding="utf-8")
    findings, calls = access_check(base, sessions, specs, ids)
    ops = [(spec, op) for spec in specs.values() for item in spec["paths"].values() for m, op in item.items()
           if m in ("get", "put", "post", "delete", "patch")]
    token_closed = sum(1 for spec, op in ops if op.get("x-kb-api-token") == "closed")

    for role, _, _ in ROLES:
        (work / f"{role}.yaml").write_text(json.dumps(plan(role, sessions[role]), indent=1), encoding="utf-8")
    (work / "roles.txt").write_text("\n".join(r for r, _, _ in ROLES) + "\n", encoding="utf-8")
    (work / "secrets.json").write_text(json.dumps(sorted({s for s in secrets if s})), encoding="utf-8")
    (out / "prep.json").write_text(json.dumps({
        "contract": CONTRACT, "operations": len(ops), "token_closed_operations": token_closed,
        "excluded": EXCLUDE, "scan_space": SCAN_SPACE, "access_check_calls": calls, "access_findings": findings,
        "roles": {role: (user or "none") for role, user, _ in ROLES}}, indent=2), encoding="utf-8")
    print(f"prep: {len(ops)} operations, {calls} access-check calls, {len(findings)} access finding(s), plans for {len(ROLES)} roles")


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
                                          "param": i.get("param", ""), "evidence": (i.get("evidence") or "")[:200],
                                          "otherinfo": (i.get("otherinfo") or "")[:300]})
    for f in prepped["access_findings"]:
        counts[f["role"]]["High"]["High"] += 1
    for inst in instances:
        entry = next((e for e in baseline if matches(e, inst)), None)
        inst["triage"] = f"{entry['verdict']}: {entry['reason']}" if entry else "untriaged"

    alive = {}
    for role, _, _ in ROLES:
        cookie = next((p["replacementString"] for p in json.loads((work / f"{role}.yaml").read_text())["jobs"][1]["rules"]
                       if p["matchString"] == "Cookie"), None) if (work / f"{role}.yaml").is_file() else None
        if cookie:
            try:
                with urllib.request.urlopen(urllib.request.Request(TARGET + "/api/v1/me", headers={"Cookie": cookie}), timeout=30) as r:
                    alive[role] = r.status
            except urllib.error.HTTPError as e:
                alive[role] = e.code
    untriaged = [i for i in instances if i["triage"] == "untriaged"]
    gate = "FAIL" if untriaged or missing else "PASS"
    summary = {"gate": gate, "untriaged": len(untriaged), "roles_without_report": missing, "seconds": times,
               "session_after_scan": alive, **{k: prepped[k] for k in ("contract", "operations", "token_closed_operations", "excluded", "roles", "access_check_calls")},
               "counts": counts, "high_medium": instances}
    text = scrub(json.dumps(summary, indent=2), secrets)
    (out / "summary.json").write_text(text, encoding="utf-8")
    summary = json.loads(text)
    (out / "matrix.md").write_text(matrix(summary), encoding="utf-8")
    for f in list((work / "out").glob("*.json")):
        (out / f.name).write_text(scrub(f.read_text(encoding="utf-8"), secrets), encoding="utf-8")
    for log in out.glob("*.log"):
        log.write_text(scrub(log.read_text(encoding="utf-8", errors="replace"), secrets), encoding="utf-8")
    shutil.rmtree(work)
    print(f"security/zap: {gate}, {len(instances)} High/Medium instance(s), {len(untriaged)} untriaged"
          + (f", no report for {', '.join(missing)}" if missing else ""))


def matrix(s):
    rows = ["# security/zap", "",
            f"Gate: **{s['gate']}** ({s['untriaged']} High or Medium not in `security/zap/baseline.json`"
            + (f"; no ZAP report for {', '.join(s['roles_without_report'])}" if s["roles_without_report"] else "") + ")", "",
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
            rows.append(f"- {i['role']} {i['method']} `{i['uri']}` param `{i['param']}` evidence `{i['evidence'][:80]}`")
        if len(items) > 5:
            rows.append(f"- ... {len(items) - 5} more")
        rows.append("")
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["prep", "report"])
    ap.add_argument("--harness", default="reports/harness.json")
    ap.add_argument("--out", default="reports/security-zap")
    a = ap.parse_args()
    (prep if a.step == "prep" else report)(a)
