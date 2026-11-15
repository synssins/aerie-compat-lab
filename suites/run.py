"""Run one suite folder against aerie and write the operation-by-client result matrix.

Usage: python -I suites/run.py suites/datacenter/t1 [--harness reports/harness.json] [--out reports/datacenter-t1]
                               [--clients http,python-dc-9.2.4]

Clients:
  http           raw HTTP (stdlib), checks status codes, headers and bodies directly
  python-<spec>  the Python client generated from that pinned spec by clients/generate.sh; its strict
                 pydantic models must accept every response
Output in --out: matrix.md, matrix.json and failures/<scenario>__<client>.json (request, response, diff).
Exit code 1 when any cell is not PASS.
"""
import argparse
import base64
import importlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "clients" / "build"
MISSING = object()
NEGATIVE = {"not_allowed", "not_found", "invalid_cql"}


def get_path(doc, path):
    cur = doc
    for part in path.split("."):
        if isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        elif isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return MISSING
    return cur


def run_checks(doc, checks):
    """Return a list of human-readable mismatches; empty means every check passed."""
    diffs = []
    for kind, path, *args in checks:
        val = get_path(doc, path) if doc is not None else MISSING
        if kind == "exists":
            ok = val is not MISSING
        elif kind == "eq":
            ok = val == args[0]
        elif kind in ("len_le", "len_ge"):
            ok = isinstance(val, list) and (len(val) <= args[0] if kind == "len_le" else len(val) >= args[0])
        elif kind == "none_eq":
            ok = isinstance(val, list) and all(get_path(x, args[0]) != args[1] for x in val)
        else:
            raise ValueError(f"unknown check {kind}")
        if not ok:
            got = "<missing>" if val is MISSING else json.dumps(val)[:200]
            diffs.append(f"{kind} {path} {json.dumps(args)}: got {got}")
    return diffs


def subst(value, fixtures):
    if isinstance(value, str):
        return re.sub(r"\{(\w+)\}", lambda m: str(fixtures.get(m.group(1), m.group(0))), value)
    if isinstance(value, list):
        return [subst(v, fixtures) for v in value]
    if isinstance(value, dict):
        return {k: subst(v, fixtures) for k, v in value.items()}
    return value


def auth_header(cred):
    return "Basic " + base64.b64encode(f"{cred['user']}:{cred['password']}".encode()).decode()


def build_url(base, path_tmpl, path_params, params):
    path = re.sub(r"\{(\w+)\}", lambda m: urllib.parse.quote(str(path_params[m.group(1)]), safe=""), path_tmpl)
    query = urllib.parse.urlencode({k: str(v) for k, v in (params or {}).items()})
    return base + path + ("?" + query if query else "")


def http_call(base, cred, path_tmpl, path_params, params):
    url = build_url(base, path_tmpl, path_params, params)
    req = urllib.request.Request(url, headers={"Authorization": auth_header(cred), "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return url, r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return url, e.code, dict(e.headers), e.read()


class HttpClient:
    name = "http"

    def __init__(self, base):
        self.base = base

    def call(self, method, path_tmpl, path_params, params, cred):
        url, status, headers, body = http_call(self.base, cred, path_tmpl, path_params, params)
        return {"url": url, "status": status, "headers": headers, "body": body, "client_error": None}


def snake(name):
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()


class PythonClient:
    """Calls the operation through the generated client; a response its models reject is a failure."""

    def __init__(self, spec_id, base):
        self.name = f"python-{spec_id}"
        self.base = base
        pkg_dir = BUILD / "python" / spec_id
        if not pkg_dir.is_dir():
            raise FileNotFoundError(f"{pkg_dir} missing: run clients/generate.sh")
        sys.path.insert(0, str(pkg_dir))
        self.pkg = importlib.import_module("client_" + re.sub(r"[.-]", "_", spec_id))
        self.spec = json.loads((BUILD / "specs" / f"{spec_id}.json").read_text(encoding="utf-8"))
        self.apis = [getattr(self.pkg, n) for n in dir(self.pkg) if n.endswith("Api") and isinstance(getattr(self.pkg, n), type)]

    def method_for(self, method, path_tmpl):
        op = self.spec.get("paths", {}).get(path_tmpl, {}).get(method.lower())
        if not op:
            return None, None, {}
        # Pass each value in the type this spec version declares (string in 9.x, integer limit/start in 10.x+).
        types = {p.get("name"): p.get("schema", {}).get("type") for p in op.get("parameters", []) if isinstance(p, dict)}
        want = op["operationId"].replace("_", "").lower()
        for api in self.apis:
            for attr in dir(api):
                if attr.replace("_", "").lower() == want:
                    return api, attr, types
        raise LookupError(f"operationId {op['operationId']} not found in generated client")

    def call(self, method, path_tmpl, path_params, params, cred):
        url = build_url(self.base, path_tmpl, path_params, params)
        api_cls, attr, types = self.method_for(method, path_tmpl)
        if api_cls is None:
            return None  # operation not in this spec version
        cfg = self.pkg.Configuration(host=self.base)
        client = self.pkg.ApiClient(cfg)
        # The pinned specs declare no per-operation security, so the client would send no credentials.
        client.set_default_header("Authorization", auth_header(cred))
        api = api_cls(client)
        kwargs = {snake(k): v if types.get(k) in ("integer", "boolean") else [str(v)] if types.get(k) == "array" else str(v)
                  for k, v in {**path_params, **(params or {})}.items()}
        try:
            resp = getattr(api, attr + "_with_http_info")(**kwargs, _request_timeout=30)
            return {"url": url, "status": resp.status_code, "headers": dict(resp.headers or {}), "body": resp.raw_data, "client_error": None}
        except self.pkg.ApiException as e:
            return {"url": url, "status": e.status, "headers": dict(e.headers or {}), "body": (e.body or "").encode() if isinstance(e.body, str) else (e.body or b""), "client_error": None}
        except Exception as e:  # model validation, unexpected kwargs, transport
            return {"url": url, "status": None, "headers": {}, "body": b"", "client_error": f"{type(e).__name__}: {e}"[:2000]}


def evaluate(scn, res):
    diffs = []
    if res["client_error"]:
        diffs.append("client rejected the call or response: " + res["client_error"])
        return diffs
    expect = scn["expect"]
    if str(res["status"]) not in expect:
        diffs.append(f"status {res['status']}, expected one of {sorted(expect)}")
        return diffs
    checks = expect[str(res["status"])]
    if checks:
        try:
            doc = json.loads(res["body"] or b"null")
        except ValueError:
            diffs.append("body is not JSON")
            return diffs
        diffs += run_checks(doc, checks)
    return diffs


def resolve_fixtures(suite, handoff, base):
    found, notes = dict(handoff.get("ids", {})), []
    for name, how in suite.get("fixtures", {}).items():
        if name in found:
            continue
        try:
            _, status, _, body = http_call(base, handoff["credentials"]["admin"], how["path"], {}, how["params"])
            val = get_path(json.loads(body), how["pick"]) if status == 200 else MISSING
        except Exception as e:
            status, val = f"{type(e).__name__}", MISSING
        if val is MISSING:
            found[name] = f"UNRESOLVED-{name}"
            notes.append(f"fixture {name} not resolved (lookup status {status})")
        else:
            found[name] = val
    return found, notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("suite")
    ap.add_argument("--harness", default="reports/harness.json")
    ap.add_argument("--out")
    ap.add_argument("--clients", help="comma-separated subset, default: http plus python-<spec> for every spec in the suite")
    args = ap.parse_args()

    suite_dir = Path(args.suite)
    suite = json.loads((suite_dir / "scenarios.json").read_text(encoding="utf-8"))
    handoff = json.loads(Path(args.harness).read_text(encoding="utf-8"))
    base = handoff["base_url"].rstrip("/")
    out = Path(args.out or f"reports/{suite['surface']}-{suite['tier']}")
    (out / "failures").mkdir(parents=True, exist_ok=True)

    names = args.clients.split(",") if args.clients else ["http"] + [f"python-{s}" for s in suite["specs"]]
    clients, setup_errors = [], {}
    for n in names:
        try:
            clients.append(HttpClient(base) if n == "http" else PythonClient(n.removeprefix("python-"), base))
        except Exception as e:
            setup_errors[n] = f"{type(e).__name__}: {e}"

    fixtures, notes = resolve_fixtures(suite, handoff, base)
    if not handoff.get("seeded"):
        notes.append("harness reports seeded=false: " + ", ".join(handoff.get("gaps", {})))

    rows, cells_by = [], {}
    for scn in suite["scenarios"]:
        method, path_tmpl = scn["op"].split(" ", 1)
        path_params = subst(scn.get("path", {}), fixtures)
        params = subst(scn.get("params", {}), fixtures)
        scn_eval = dict(scn, expect=subst(scn["expect"], fixtures))
        cred = handoff["credentials"][scn["as"]]
        row = {"scenario": scn["id"], "op": scn["op"], "cells": {}}
        for n in names:
            if n in setup_errors:
                row["cells"][n] = "ERROR"
                continue
            client = next(c for c in clients if c.name == n)
            try:
                res = client.call(method, path_tmpl, path_params, params, cred)
            except Exception as e:
                res = {"url": build_url(base, path_tmpl, path_params, params), "status": None, "headers": {}, "body": b"",
                       "client_error": f"{type(e).__name__}: {e}"}
            if res is None:
                row["cells"][n] = "N/A"
                continue
            diffs = evaluate(scn_eval, res)
            # A refusal proves nothing while the matching success case fails (e.g. nothing seeded, every path 404).
            needs = scn.get("needs") or (scn["id"].rsplit(".", 1)[0] + ".success" if scn["id"].rsplit(".", 1)[1] in NEGATIVE else None)
            blocked = not diffs and needs and cells_by.get((needs, n)) != "PASS"
            if blocked:
                diffs = [f"passes only vacuously: {needs} did not pass for {n}"]
            row["cells"][n] = "PASS" if not diffs else "BLOCKED" if blocked else ("ERROR" if res["status"] is None else "FAIL")
            cells_by[(scn["id"], n)] = row["cells"][n]
            if diffs:
                body = res["body"].decode("utf-8", "replace") if isinstance(res["body"], bytes) else str(res["body"])
                (out / "failures" / f"{scn['id']}__{n}.json").write_text(json.dumps({
                    "scenario": scn["id"], "client": n, "as": scn["as"],
                    "request": {"method": method, "url": res["url"]},
                    "response": {"status": res["status"], "headers": res["headers"], "body": body[:20000]},
                    "expected": scn_eval["expect"], "diff": diffs,
                }, indent=2), encoding="utf-8")
        rows.append(row)

    (out / "matrix.json").write_text(json.dumps({"base_url": base, "clients": names, "setup_errors": setup_errors,
                                                 "notes": notes, "rows": rows}, indent=2), encoding="utf-8")
    md = [f"# {suite['surface']} {suite['tier']} against {base}", ""]
    md += [f"- {n}" for n in notes + [f"{k}: {v}" for k, v in setup_errors.items()]]
    md += ["", "| Scenario | Operation | " + " | ".join(names) + " |", "|---|---|" + "---|" * len(names)]
    md += [f"| {r['scenario']} | `{r['op']}` | " + " | ".join(r["cells"][n] for n in names) + " |" for r in rows]
    cells = [c for r in rows for c in r["cells"].values()]
    summary = {k: cells.count(k) for k in ("PASS", "FAIL", "BLOCKED", "ERROR", "N/A")}
    md += ["", "Totals: " + ", ".join(f"{k} {v}" for k, v in summary.items()),
           "", "BLOCKED: the refusal case answered as expected, but its success case failed, so it proves nothing yet."]
    (out / "matrix.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))
    return 0 if summary["FAIL"] == summary["BLOCKED"] == summary["ERROR"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
