"""Sets up aerie's generic OpenID Connect sign-in plugin against the lab's provider, then signs in through it in
every provider mode and writes the result matrix.

Usage (runner container, after harness/seed.py and before the hand-off is redacted):
  python -I harness/oidc_setup.py --harness reports/harness.json --plugin <package> --certs reports/oidc --out reports/oidc

Routes are aerie's own admin API as published in aerie's docs/api-reference.md and docs/plugins/developer-guide.md
at commit 2cf1f9c (no contract release has them yet): POST /api/v1/admin/plugins (package bytes, X-File-Name),
POST /api/v1/admin/plugins/{id}/signin-providers, GET and PUT /api/v1/admin/plugins/{id}/settings, the sign-in
routes under /api/v1/auth/methods. Provider settings are signIn.<provider id>.<name> (issuer, discovery, clientId,
clientSecret, scopes, subjectClaim, emailClaim, emailVerifiedClaim, nameClaim, userInfo, requiredClaim, requiredValues,
newAccounts, privateNetwork), as the build room gave them for 2cf1f9c.
"""
import argparse
import hashlib
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "security/zap"))
from seed import SeedError, wait_until_up  # noqa: E402
from scan import sign_in  # noqa: E402

PLUGIN_ID = "aerie.signin.oidc"
PLUGIN_SHA256 = "d8b19f7195140f1324e3dc0bb305ac8145ca53308e490ce12ef9a3e238b809d6"  # aerie.signin.oidc-1.0.0.kbplugin, 13,530 bytes
ISSUER = "https://oidc:8443"
# mode -> whether aerie must let the person in. Every other mode is a provider that misbehaves.
CASES = [("ok", "lab-oidc-new", True), ("ok", "lab-oidc-link", True), ("ok", "lab-oidc-unverified", False)] + [
    (m, "lab-oidc-new", False) for m in ("bad_signature", "alg_none", "wrong_issuer", "wrong_audience", "wrong_nonce",
                                         "no_nonce", "expired", "future_iat", "no_sub", "userinfo_sub_mismatch",
                                         "userinfo_signed", "wrong_azp", "error_redirect")] + [
    # The token names a key id the provider does not publish, but is signed by its one published key: a valid
    # signature, so letting the person in is correct (key selection may fall back to the published keys).
    ("wrong_kid", "lab-oidc-new", True)]
# Each on its own provider in aerie (aerie caches discovery), with Discovery address /d/<mode>/...; must be refused.
DISCOVERY_CASES = ["discovery_redirect", "discovery_wrong_issuer", "token_http_endpoint"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Browser:
    """Follows a sign-in by hand: keeps every cookie (aerie's are Secure and the lab is plain http), no redirects."""

    def __init__(self, ctx):
        self.cookies, self.ctx = {}, ctx

    def get(self, url, body=None, headers=None):
        req = urllib.request.Request(url, data=body, headers={"Accept": "application/json", **(headers or {})})
        if self.cookies and not url.startswith(ISSUER):
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in self.cookies.items()))
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.ctx), NoRedirect)
        try:
            r = opener.open(req, timeout=30)
        except urllib.error.HTTPError as e:
            r = e
        status = getattr(r, "status", None) or r.code
        for c in r.headers.get_all("Set-Cookie") or []:
            name, _, value = c.split(";", 1)[0].partition("=")
            if url.startswith(ISSUER):
                continue
            if value and "max-age=0" not in c.lower() and "expires=thu, 01 jan 1970" not in c.lower():
                self.cookies[name] = value
            else:
                self.cookies.pop(name, None)
        return status, r.headers, r.read(4000)


def location(status, headers, body):
    if status in (301, 302, 303, 307, 308):
        return headers.get("Location")
    try:
        return json.loads(body).get("location")
    except (ValueError, AttributeError):
        return None


def control(ctx, user, mode):
    req = urllib.request.Request(ISSUER + "/lab/next", data=json.dumps({"user": user, "mode": mode}).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
        assert r.status == 200


def sign_in_once(base, ctx, method, user, mode, return_to="/"):
    """One sign-in as a browser would do it, waiting out aerie's rate limit (up to 3 tries).
    Returns {who, message, back, throttled, steps}: who is the signed-in user name or None, message the sign-in
    screen's message, back the address the browser ended at (a path on this site, or the full address elsewhere)."""
    for attempt in range(3):
        control(ctx, user, mode)
        b, steps, back, wait = Browser(ctx), [], None, None
        url = f"{base}/api/v1/auth/methods/{PLUGIN_ID}/{method}/start?returnTo={urllib.parse.quote(return_to, safe='')}"
        for _ in range(6):
            status, headers, body = b.get(url)
            steps.append(f"GET {url.split('?')[0]} -> {status}" + (f": {body[:160].decode('utf-8', 'replace')}" if status >= 400 else ""))
            if status == 429:
                wait = int(headers.get("Retry-After") or 60)
                break
            nxt = location(status, headers, body)
            if not nxt:
                break
            url = urllib.parse.urljoin(url, nxt)
            if not url.startswith((base, ISSUER)):
                back = url  # the browser would leave the site here; the lab does not follow it
                break
            if url.startswith(base) and "/callback" not in url and "/start" not in url:
                back = url[len(base):]
                break
        if wait is None:
            break
        steps.append(f"rate limited; waiting {wait} s")
        time.sleep(min(wait, 120) + 1)
    status, _, body = b.get(base + "/api/v1/me")
    me = json.loads(body) if status == 200 else {}
    outcome = b.get(base + "/api/v1/auth/methods/outcome")[2][:300].decode("utf-8", "replace")
    steps.append(f"me -> {status}; outcome {outcome}")
    try:
        message = json.loads(outcome).get("message")
    except ValueError:
        message = None
    who = (me.get("userName") or (me.get("user") or {}).get("userName")) if status == 200 else None
    return {"who": who, "message": message, "back": back, "throttled": wait is not None, "steps": steps}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--harness", default="reports/harness.json")
    ap.add_argument("--plugin", required=True)
    ap.add_argument("--certs", default="reports/oidc")
    ap.add_argument("--out", default="reports/oidc")
    args = ap.parse_args()
    h = json.loads(Path(args.harness).read_text(encoding="utf-8"))
    base, out = h["base_url"], Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    ctx = ssl.create_default_context(cafile=str(Path(args.certs) / "ca.pem"))
    package = Path(args.plugin).read_bytes()
    if hashlib.sha256(package).hexdigest() != PLUGIN_SHA256:
        raise SystemExit(f"REFUSED {args.plugin}: SHA-256 is not the pinned {PLUGIN_SHA256}")
    a = h["credentials"]["admin-password"]
    admin = sign_in(base, a["user"], a["password"], a.get("totp_key"))
    report = {"plugin_sha256": PLUGIN_SHA256}

    if not any(p["id"] == PLUGIN_ID for p in admin.call("GET", "/admin/plugins")["plugins"]):
        req = urllib.request.Request(base + "/api/v1/admin/plugins", data=package, method="POST", headers={
            "Content-Type": "application/octet-stream", "X-File-Name": Path(args.plugin).name, "Accept": "application/json",
            "Cookie": "; ".join(f"{k}={v}" for k, v in admin.cookies.items())})
        with urllib.request.urlopen(req, timeout=60) as r:
            report["install"] = json.loads(r.read())
        if report["install"].get("restart"):
            time.sleep(5)  # aerie ends its process; the restart policy starts it again
            wait_until_up(base, "/api/v1/setup/status", 180)
            try:
                admin.call("GET", "/me")
            except SeedError:
                admin = sign_in(base, a["user"], a["password"], a.get("totp_key"))
    plugin = next(p for p in admin.call("GET", "/admin/plugins")["plugins"] if p["id"] == PLUGIN_ID)
    report["plugin_state"] = plugin.get("state")

    prov = admin.call("POST", f"/admin/plugins/{PLUGIN_ID}/signin-providers", {"title": "Lab provider"})
    report["provider"] = prov
    secret = os.environ.get("OIDC_CLIENT_SECRET") or ""
    if not secret:
        raise SystemExit("set OIDC_CLIENT_SECRET")
    # Keys signIn.<provider id>.<name>, named by the build room for 2cf1f9c (not yet in aerie's docs).
    k = f"signIn.{prov['id']}."
    values = {k + "issuer": ISSUER, k + "clientId": "lab-aerie", k + "clientSecret": secret,
              k + "privateNetwork": "true", k + "newAccounts": "true", k + "userInfo": "true"}
    report["saved"] = admin.call("PUT", f"/admin/plugins/{PLUGIN_ID}/settings", {"values": values})
    discovery_providers = {}
    for mode in DISCOVERY_CASES:
        dp = admin.call("POST", f"/admin/plugins/{PLUGIN_ID}/signin-providers", {"title": f"Lab {mode}"})
        k = f"signIn.{dp['id']}."
        admin.call("PUT", f"/admin/plugins/{PLUGIN_ID}/settings", {"values": {
            k + "issuer": ISSUER, k + "discovery": f"{ISSUER}/d/{mode}/.well-known/openid-configuration", k + "clientId": "lab-aerie",
            k + "clientSecret": secret, k + "privateNetwork": "true", k + "newAccounts": "true"}})
        discovery_providers[mode] = dp["id"]
    report["discovery_providers"] = discovery_providers
    # The account the provider's lab-oidc-link user is matched to by its verified address.
    admin.call("POST", "/admin/users/invite", {"userName": "lab-oidc-link", "displayName": "Lab OIDC Link", "isAdmin": False,
                                                "email": "lab-oidc-link@lab.test"})
    methods = json.loads(Browser(ctx).get(base + "/api/v1/auth/methods")[2] or b"[]")
    report["methods"] = methods
    method = next((m["id"].split("/")[-1] for m in methods if prov["id"] in m["id"]), prov["id"])

    rows = []
    for mode, user, admitted in CASES:
        r = sign_in_once(base, ctx, method, user, mode)
        # A refusal counts only when aerie refused the sign-in itself (its sign-in screen message), not a rate limit.
        ok = not r["throttled"] and (bool(r["who"]) if admitted else (not r["who"] and bool(r["message"])))
        rows.append({"mode": mode, "user": user, "expected": "signed in" if admitted else "refused",
                     "got": "rate limited" if r["throttled"] else (f"signed in as {r['who']}" if r["who"] else f"refused: {r['message']}"),
                     "result": "PASS" if ok else ("ERROR" if r["throttled"] else "FAIL"), "steps": r["steps"]})
    for mode, dpid in discovery_providers.items():
        r = sign_in_once(base, ctx, dpid, "lab-oidc-new", "ok")
        ok = not r["throttled"] and not r["who"] and bool(r["message"])
        rows.append({"mode": mode, "user": "lab-oidc-new", "expected": "refused",
                     "got": "rate limited" if r["throttled"] else (f"signed in as {r['who']}" if r["who"] else f"refused: {r['message']}"),
                     "result": "PASS" if ok else ("ERROR" if r["throttled"] else "FAIL"), "steps": r["steps"]})
    for bad in ("https://evil.example/x", "//evil.example/x", "/\\evil.example/x"):
        r = sign_in_once(base, ctx, method, "lab-oidc-new", "ok", bad)
        on_site = bool(r["back"]) and r["back"].startswith("/") and not r["back"].startswith(("//", "/\\")) and "evil.example" not in r["back"]
        ok = not r["throttled"] and bool(r["who"]) and on_site
        rows.append({"mode": f"ok, returnTo {bad}", "user": "lab-oidc-new", "expected": "signed in, back on this site",
                     "got": "rate limited" if r["throttled"] else f"{'signed in' if r['who'] else 'not signed in'}, back at {r['back']}",
                     "result": "PASS" if ok else ("ERROR" if r["throttled"] else "FAIL"), "steps": r["steps"]})
    report["cases"] = rows
    (out / "setup.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    md = ["# OIDC sign-in through aerie.signin.oidc", "", f"Provider `{prov['id']}`, method id `{method}`, plugin state {report['plugin_state']}.", "",
          "| Mode | User | Expected | Got | Result |", "|---|---|---|---|---|"]
    md += [f"| {r['mode']} | {r['user']} | {r['expected']} | {r['got']} | {r['result']} |" for r in rows]
    fails = sum(r["result"] != "PASS" for r in rows)
    md += ["", "Totals: " + ", ".join(f"{k} {sum(r['result'] == k for r in rows)}" for k in ("PASS", "FAIL", "ERROR"))]
    (out / "matrix.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
