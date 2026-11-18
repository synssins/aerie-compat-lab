"""auth suite: HTTP Basic, personal access tokens and OAuth 2.0 on the Data Center compatible surface.

Rules from the contract release contracts-v2: behaviour/identity.md (what aerie must do) and
behaviour/identity-plan.md (the build slices; the case names follow its suggestions). Each case is a
multi-step flow run with raw HTTP; run it through suites/run.py like any suite:

  python -I suites/run.py suites/auth --harness reports/harness.json --out reports/auth

Run it after the other suites: it creates pages in PRIV, changes a sign-in code exemption and back, and
its last cases lock the lab-lockout account and rate-limit the caller's address on purpose, and
auth.oauth.refresh.after_access_expiry waits five minutes for an access token to expire.
"""
import base64
import hashlib
import json
import re
import secrets
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "harness"))
from seed import Aerie, SeedError, totp  # noqa: E402

SUITE = {
    "surface": "auth", "tier": "datacenter",
    "fixtures": {
        "lab_home": {"path": "/rest/api/content", "params": {"spaceKey": "LAB", "title": "Lab Home"}, "pick": "results.0.id"},
        "priv_home": {"path": "/rest/api/content", "params": {"spaceKey": "PRIV", "title": "Private Home"}, "pick": "results.0.id"},
        "lab_child_01": {"path": "/rest/api/content", "params": {"spaceKey": "LAB", "title": "Lab Child 01"}, "pick": "results.0.id"},
    },
}
OAUTH = "/rest/oauth2/latest"
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
CASES = []


class Fail(Exception):
    pass


class NotRunnable(Exception):
    """The case cannot be run against any build yet; the reason is recorded and the cell is N/A."""


def case(cid, slice_no, needs=()):
    def wrap(fn):
        CASES.append((cid, slice_no, tuple(needs), fn))
        return fn
    return wrap


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


class Resp:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def header(self, name):
        return self.headers.get(name) if self.headers else None

    def json(self):
        try:
            return json.loads(self.body or b"null")
        except ValueError:
            return None


def basic(user, secret):
    return "Basic " + base64.b64encode(f"{user}:{secret}".encode()).decode()


def mask(url):
    return re.sub(r"(code|code_verifier|client_secret|refresh_token|token)=[^&]+", r"\1=***", url)


class Ctx:
    def __init__(self, base, handoff, fixtures):
        self.base, self.h, self.fx, self.log, self._sessions, self._last_code = base, handoff, fixtures, [], {}, None

    def req(self, method, path, auth=None, cookies=None, headers=None, data=None, form=None, query=None):
        url = self.base + path + ("?" + urllib.parse.urlencode(query) if query else "")
        hdr = {"Accept": "application/json", **(headers or {})}
        body = None
        if form is not None:
            body, hdr["Content-Type"] = urllib.parse.urlencode(form).encode(), "application/x-www-form-urlencoded"
        elif data is not None:
            body, hdr["Content-Type"] = json.dumps(data).encode(), "application/json"
        if auth:
            hdr["Authorization"] = auth
        if cookies:
            hdr["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        r = urllib.request.Request(url, data=body, method=method, headers=hdr)
        try:
            with OPENER.open(r, timeout=30) as x:
                res = Resp(x.status, x.headers, x.read())
        except urllib.error.HTTPError as e:
            res = Resp(e.code, e.headers, e.read())
        self.log.append({"method": method, "url": mask(url), "status": res.status,
                         "content_type": res.header("Content-Type"), "body": res.body[:400].decode("utf-8", "replace")})
        return res

    # credentials
    def cred(self, who):
        return self.h["credentials"][who]

    def token(self, name):
        t = self.h.get("tokens", {}).get(name)
        if not t:
            raise Fail(f"token {name} was not seeded")
        return t["token"]

    def session(self, who):
        """An aerie web session (cookies) for a lab user; the administrator also gives a sign-in code."""
        if who in self._sessions:
            return self._sessions[who]
        c = self.cred(who)
        s = Aerie(self.base)
        s.cookies = {}
        try:
            answer = s.call("POST", "/auth/local/signin", {"userName": c["user"], "password": c["password"]}, ok=(200, 409))
            if (answer or {}).get("step") == "code":
                step = int(time.time() // 30)
                if step == self._last_code:  # a code is accepted once; wait for the next one
                    time.sleep(30 - time.time() % 30 + 1)
                self._last_code = int(time.time() // 30)
                s.call("POST", "/auth/local/code", {"code": totp(c["totp_key"])})
        except SeedError as e:
            raise Fail(f"aerie sign-in as {c['user']} failed: {e}")
        self._sessions[who] = s
        return s

    def current_user(self, auth):
        r = self.req("GET", "/rest/api/user/current", auth=auth)
        return r, (r.json() or {}).get("username") if isinstance(r.json(), dict) else None

    def client(self, name):
        c = self.h.get("oauth_clients", {}).get(name)
        if not c:
            raise Fail(f"OAuth client {name} was not seeded: " + self.h.get("gaps", {}).get("GAP-SEED-OAUTH_CLIENTS", "unknown"))
        return c


def expect(cond, msg):
    if not cond:
        raise Fail(msg)


def expect_user(ctx, auth, username, what):
    r, user = ctx.current_user(auth)
    expect(r.status == 200 and user == username, f"{what}: GET /rest/api/user/current gave {r.status}, username {user!r}, expected 200 {username!r}")


def rest_error(r, status):
    j = r.json()
    expect(r.status == status, f"status {r.status}, expected {status}")
    expect(isinstance(j, dict) and j.get("statusCode") == status, f"body is not a RestError with statusCode {status}: {r.body[:200]!r}")
    return j


# --- OAuth helpers -------------------------------------------------------------------------------------

def pkce_pair():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def redirect_params(location, redirect_uri):
    if not location or not location.startswith(redirect_uri):
        return None
    return dict(urllib.parse.parse_qsl(urllib.parse.urlparse(location).query))


def authorize(ctx, who, client, scope="READ WRITE", allow=True, pkce=True, method="S256", state=None, **override):
    """Runs the browser part of the flow as `who`: authorize, consent if asked, back to the redirect URI.
    Returns (params on the redirect URI or None, verifier, the last response)."""
    s = ctx.session(who)
    verifier, challenge = pkce_pair()
    q = {"response_type": "code", "client_id": client["clientId"], "redirect_uri": client["redirect_uri"], "scope": scope,
         "state": state or secrets.token_urlsafe(12)}
    if pkce:
        q.update(code_challenge=challenge if method == "S256" else verifier, code_challenge_method=method)
    q.update(override)
    r = ctx.req("GET", f"{OAUTH}/authorize", cookies=s.cookies, query=q)
    loc = r.header("Location")
    got = redirect_params(loc, q["redirect_uri"])
    if got is None and r.status in (301, 302, 303, 307) and loc and UUID.search(loc):
        # aerie's consent page is a route of its web app (not in the contract); the pending request id is in it.
        rid = UUID.search(loc).group(0)
        try:
            d = s.call("POST", f"/oauth/authorize-requests/{rid}/decision", {"allow": allow})
        except SeedError as e:
            raise Fail(f"consent decision failed: {e}")
        got = redirect_params((d or {}).get("redirectTo"), q["redirect_uri"])
    return got, verifier, r


def token_call(ctx, client, form, client_auth="post", query=False):
    form = dict(form)
    auth = None
    if client["type"] == "confidential":
        if client_auth == "basic":
            auth = basic(client["clientId"], client["clientSecret"])
        else:
            form.update(client_id=client["clientId"], client_secret=client["clientSecret"])
    else:
        form["client_id"] = client["clientId"]
    if query:  # the vendor's own examples put the parameters in the POST's query string
        return ctx.req("POST", f"{OAUTH}/token", auth=auth, query=form)
    return ctx.req("POST", f"{OAUTH}/token", auth=auth, form=form)


def code_for(ctx, who, client_name, scope="READ WRITE"):
    client = ctx.client(client_name)
    got, verifier, r = authorize(ctx, who, client, scope=scope)
    expect(got and "code" in got, f"authorize did not come back with a code (status {r.status}, Location {mask(r.header('Location') or '')!r}, got {got})")
    return client, got["code"], verifier


def tokens(ctx, who="user", client_name="lab-public", scope="READ WRITE", client_auth="post", query=False):
    client, code, verifier = code_for(ctx, who, client_name, scope)
    r = token_call(ctx, client, {"grant_type": "authorization_code", "code": code, "redirect_uri": client["redirect_uri"],
                                 "code_verifier": verifier}, client_auth, query)
    j = r.json()
    expect(r.status == 200 and isinstance(j, dict) and j.get("access_token"), f"code exchange gave {r.status}: {r.body[:200]!r}")
    return client, j


def oauth_error(r, status, error):
    j = r.json()
    expect(r.status == status and isinstance(j, dict) and j.get("error") == error,
           f"expected {status} {{error: {error}}}, got {r.status} {r.body[:200]!r}")


def refresh(ctx, client, refresh_token, **extra):
    return token_call(ctx, client, {"grant_type": "refresh_token", "refresh_token": refresh_token, **extra})


def bearer(tok):
    return "Bearer " + tok


def new_page(space_key, title):
    return {"type": "page", "title": title, "space": {"key": space_key},
            "body": {"storage": {"value": "<p>auth suite</p>", "representation": "storage"}}}


# --- slice 1: credential resolution ------------------------------------------------------------------

@case("auth.basic.password.ok", 1)
def _(ctx):
    c = ctx.cred("user")
    expect_user(ctx, basic(c["user"], c["password"]), c["user"], "password Basic for a user without codes")


@case("auth.basic.password.wrong", 1, ["auth.basic.password.ok"])
def _(ctx):
    rest_error(ctx.req("GET", "/rest/api/user/current", auth=basic(ctx.cred("user")["user"], "not-the-password")), 401)


@case("auth.basic.codes_on.refused", 1, ["auth.basic.password.ok"])
def _(ctx):
    c = ctx.cred("admin-password")
    right = ctx.req("GET", "/rest/api/user/current", auth=basic(c["user"], c["password"]))
    wrong = ctx.req("GET", "/rest/api/user/current", auth=basic(c["user"], "not-the-password"))
    a, b = rest_error(right, 401), rest_error(wrong, 401)
    expect({k: a.get(k) for k in ("statusCode", "message", "reason", "data")} == {k: b.get(k) for k in ("statusCode", "message", "reason", "data")},
           "the refusal for the right password differs from the wrong-password answer")


@case("auth.basic.codes_exempt.ok", 1, ["auth.basic.codes_on.refused"])
def _(ctx):
    # contracts-v6 identity-plan.md slice 1: a user who is not an administrator turns codes on, is refused on
    # password Basic, is exempted by an administrator (204) and then gets 200.
    c = ctx.cred("codes")
    user_id = ctx.h["ids"]["aerie"]["users"][c["user"]]
    try:
        me = Aerie(ctx.base).signin(c["user"], c["password"])
        key = me.call("POST", "/auth/codes/key", {})["key"]
        me.call("POST", "/auth/codes", {"code": totp(key)})
    except SeedError as e:
        raise Fail(f"{c['user']} turning sign-in codes on failed: {e}")
    rest_error(ctx.req("GET", "/rest/api/user/current", auth=basic(c["user"], c["password"])), 401)
    try:
        ctx.session("admin-password").call("PUT", f"/admin/users/{user_id}/codes/exempt", {"exempt": True}, ok=(204,))
    except SeedError as e:
        raise Fail(f"exempting {c['user']} did not answer 204: {e}")
    expect_user(ctx, basic(c["user"], c["password"]), c["user"], "password Basic for an exempted user with codes on")


@case("auth.basic.codes_exempt.admin_refused", 1, ["auth.basic.codes_on.refused"])
def _(ctx):
    # Q-0020 (contracts-v6): administrators cannot be exempted; 409 and nothing changes. The lab has no emergency
    # administrator account to try.
    c = ctx.cred("admin-password")
    admin_id = ctx.h["ids"]["aerie"]["users"]["lab-admin"]
    try:
        ctx.session("admin-password").call("PUT", f"/admin/users/{admin_id}/codes/exempt", {"exempt": True}, ok=(409,))
    except SeedError as e:
        raise Fail(f"exempting the administrator did not answer 409: {e}")
    rest_error(ctx.req("GET", "/rest/api/user/current", auth=basic(c["user"], c["password"])), 401)


@case("auth.basic.token_in_password.ok", 1)
def _(ctx):
    expect_user(ctx, basic("lab-user", ctx.token("lab-user-pat")), "lab-user", "Basic with a token, account without codes")
    expect_user(ctx, basic("lab-admin", ctx.token("lab-admin-pat")), "lab-admin", "Basic with a token, account with codes")


@case("auth.basic.token_in_password.wrong_user", 1, ["auth.basic.token_in_password.ok"])
def _(ctx):
    rest_error(ctx.req("GET", "/rest/api/user/current", auth=basic("lab-noaccess", ctx.token("lab-user-pat"))), 401)


@case("auth.pat.bearer.ok", 1)
def _(ctx):
    expect_user(ctx, bearer(ctx.token("lab-user-pat")), "lab-user", "bearer personal access token")


@case("auth.pat.bearer.revoked", 1, ["auth.pat.bearer.ok"])
def _(ctx):
    s = ctx.session("user")
    try:
        made = s.call("POST", "/tokens", {"name": "auth-revoked", "kind": "Personal", "days": 1, "scopes": [{"spaceId": None, "access": "Read"}]})
        s.call("DELETE", f"/tokens/{made['info']['id']}")
    except SeedError as e:
        raise Fail(f"making and revoking a token through /api/v1/tokens failed: {e}")
    r = ctx.req("GET", "/rest/api/user/current", auth=bearer(made["token"]))
    rest_error(r, 401)
    expect('error="invalid_token"' in (r.header("WWW-Authenticate") or ""), f"WWW-Authenticate is {r.header('WWW-Authenticate')!r}")


@case("auth.pat.bearer.expired", 1)
def _(ctx):
    raise NotRunnable("aerie's token API issues tokens for 1 to 365 days, so the lab cannot make an expired token within a run")


@case("auth.no_cookie_set", 1, ["auth.basic.password.ok", "auth.pat.bearer.ok"])
def _(ctx):
    c = ctx.cred("user")
    for what, auth in (("Basic", basic(c["user"], c["password"])), ("bearer", bearer(ctx.token("lab-user-pat")))):
        r = ctx.req("GET", "/rest/api/user/current", auth=auth)
        expect(not r.header("Set-Cookie"), f"{what} answer sets a cookie")


@case("auth.cookie.write_needs_xsrf", 1)
def _(ctx):
    s = ctx.session("admin-password")
    r = ctx.req("POST", "/rest/api/content", cookies=s.cookies, data=new_page("PRIV", "auth xsrf without header"))
    expect(r.status == 403, f"cookie POST without X-Atlassian-Token gave {r.status}, expected 403")
    r = ctx.req("POST", "/rest/api/content", cookies=s.cookies, headers={"X-Atlassian-Token": "no-check"},
                data=new_page("PRIV", f"auth xsrf {secrets.token_hex(3)}"))
    expect(r.status == 200, f"cookie POST with X-Atlassian-Token gave {r.status}, expected 200")


@case("auth.header.malformed", 1, ["auth.pat.bearer.ok"])
def _(ctx):
    for value in ("Bearer", "Bearer ", "Weird abc"):
        r = ctx.req("GET", "/rest/api/content", auth=value, query={"spaceKey": "LAB"})
        expect(r.status == 401, f"Authorization {value!r} gave {r.status}, expected 401")


# --- slice 2: scope enforcement -----------------------------------------------------------------------

@case("auth.pat.write.ok", 2)
def _(ctx):
    r = ctx.req("POST", "/rest/api/content", auth=bearer(ctx.token("lab-admin-pat")), data=new_page("PRIV", f"auth pat write {secrets.token_hex(3)}"))
    expect(r.status == 200, f"a Write token of the space owner creating a page gave {r.status}, expected 200")


@case("auth.pat.read_only.write_refused", 2, ["auth.pat.write.ok"])
def _(ctx):
    r = ctx.req("POST", "/rest/api/content", auth=bearer(ctx.token("lab-admin-pat-read")), data=new_page("PRIV", "auth read token write"))
    expect(r.status == 403, f"a Read token creating a page gave {r.status}, expected 403")


@case("auth.pat.space_limited.hidden", 2)
def _(ctx):
    auth = bearer(ctx.token("lab-admin-pat-lab"))
    r = ctx.req("GET", f"/rest/api/content/{ctx.fx['lab_home']}", auth=auth)
    expect(r.status == 200, f"a token limited to LAB reading a LAB page gave {r.status}, expected 200")
    r = ctx.req("GET", f"/rest/api/content/{ctx.fx['priv_home']}", auth=auth)
    expect(r.status == 404, f"a token limited to LAB reading a PRIV page gave {r.status}, expected 404")
    r = ctx.req("GET", "/rest/api/search", auth=auth, query={"cql": "space = PRIV"})
    j = r.json()
    expect(r.status == 200 and isinstance(j, dict) and j.get("size") == 0, f"search in PRIV with a LAB token gave {r.status} {r.body[:120]!r}")


@case("auth.scope.permission_still_applies", 2, ["auth.pat.write.ok"])
def _(ctx):
    auth = bearer(ctx.token("lab-user-pat-write"))
    r = ctx.req("GET", f"/rest/api/content/{ctx.fx['lab_child_01']}", auth=auth, query={"expand": "version"})
    j = r.json()
    expect(r.status == 200 and isinstance(j, dict), f"reading the page to edit gave {r.status}")
    body = {"id": j.get("id"), "type": "page", "title": j.get("title"), "version": {"number": (j.get("version") or {}).get("number", 1) + 1},
            "body": {"storage": {"value": "<p>edited</p>", "representation": "storage"}}}
    r = ctx.req("PUT", f"/rest/api/content/{ctx.fx['lab_child_01']}", auth=auth, data=body)
    expect(r.status == 403, f"a Write token of a Reader editing a page gave {r.status}, expected 403")


# --- slice 4: client registration ---------------------------------------------------------------------

@case("auth.client.register", 4)
def _(ctx):
    s = ctx.session("admin-password")
    try:
        made = s.call("POST", "/admin/oauth/clients", {"name": "auth-register", "type": "confidential",
                                                       "redirectUris": ["http://127.0.0.1:8765/cb"], "scopes": ["READ"]})
    except SeedError as e:
        raise Fail(f"registering a client: {e}")
    cid, secret = (made.get("client") or {}).get("clientId") or "", made.get("clientSecret") or ""
    expect(re.fullmatch(r"[A-Za-z0-9]{32}", cid) is not None, f"clientId {cid!r} is not 32 characters from [A-Za-z0-9]")
    expect(len(secret) == 64, f"clientSecret has {len(secret)} characters, expected 64")
    s.call("DELETE", f"/admin/oauth/clients/{made['client']['id']}")


@case("auth.client.register.non_admin", 4, ["auth.client.register"])
def _(ctx):
    s = ctx.session("user")
    try:
        s.call("POST", "/admin/oauth/clients", {"name": "x", "type": "public", "redirectUris": ["http://127.0.0.1:8765/cb"], "scopes": ["READ"]}, ok=(403,))
    except SeedError as e:
        raise Fail(f"expected 403: {e}")


@case("auth.client.redirect.rejects", 4, ["auth.client.register"])
def _(ctx):
    s = ctx.session("admin-password")
    # The seed allows plain http (the lab has no https); identity.md refuses http redirect URIs only with the
    # test-install setting off, so the check runs with it off.
    try:
        before = s.call("GET", "/admin/auth/compat")
        s.call("PUT", "/admin/auth/compat", {**before, "allowHttpRedirects": False})
    except SeedError as e:
        raise Fail(f"turning allowHttpRedirects off failed: {e}")
    try:
        for uri in ("http://example.com/cb", "https://example.com/cb#frag", "https://*.example.com/cb"):
            try:
                s.call("POST", "/admin/oauth/clients", {"name": "x", "type": "public", "redirectUris": [uri], "scopes": ["READ"]}, ok=(400,))
            except SeedError as e:
                raise Fail(f"redirect URI {uri!r}: expected 400: {e}")
    finally:
        s.call("PUT", "/admin/auth/compat", before)


@case("auth.client.secret_not_readable", 4, ["auth.client.register"])
def _(ctx):
    s = ctx.session("admin-password")
    try:
        listed = s.call("GET", "/admin/oauth/clients")
        one = s.call("GET", f"/admin/oauth/clients/{listed[0]['id']}") if listed else None
    except SeedError as e:
        raise Fail(str(e))
    secrets_seen = [c for c in (listed or []) + ([one] if one else []) if c.get("clientSecret")]
    expect(listed and not secrets_seen, "the client list or read shows a secret" if secrets_seen else "no clients listed")


# --- slice 5: authorize endpoint and consent ----------------------------------------------------------

@case("auth.oauth.authorize.bad_redirect", 5, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    client = ctx.client("lab-public")
    got, _, r = authorize(ctx, "user", client, redirect_uri="http://127.0.0.1:8765/other")
    expect(r.status not in (301, 302, 303, 307), f"a wrong redirect_uri got a redirect ({r.status}, Location {mask(r.header('Location') or '')!r})")


@case("auth.oauth.authorize.unknown_client", 5, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    client = dict(ctx.client("lab-public"), clientId="A" * 32)
    got, _, r = authorize(ctx, "user", client)
    expect(r.status not in (301, 302, 303, 307), f"an unknown client_id got a redirect ({r.status})")


def redirect_error(ctx, error, **kw):
    client = ctx.client("lab-public")
    got, _, r = authorize(ctx, "user", client, **kw)
    expect(got is not None and got.get("error") == error, f"expected a redirect with error={error}, got {r.status} {got}")
    return got


@case("auth.oauth.authorize.missing_pkce", 5, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    redirect_error(ctx, "invalid_request", pkce=False)


@case("auth.oauth.authorize.plain_pkce", 5, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    redirect_error(ctx, "invalid_request", method="plain")


@case("auth.oauth.authorize.bad_scope", 5, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    redirect_error(ctx, "invalid_scope", scope="NOT_A_SCOPE")


@case("auth.oauth.consent.deny", 5, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    client = ctx.client("lab-public")
    got, _, r = authorize(ctx, "noaccess", client, allow=False, state="lab-state-1")
    expect(got is not None and got.get("error") == "access_denied" and got.get("state") == "lab-state-1",
           f"deny gave {r.status} {got}, expected error=access_denied and state=lab-state-1")


# --- slice 6: token endpoint --------------------------------------------------------------------------

@case("auth.oauth.pkce.full_flow", 6)
def _(ctx):
    client, j = tokens(ctx)
    expect(j.get("access_token", "").startswith("kbo_") and j.get("refresh_token", "").startswith("kbr_"), "tokens lack the kbo_/kbr_ prefixes")
    expect(str(j.get("token_type")).lower() == "bearer" and isinstance(j.get("expires_in"), int) and isinstance(j.get("created_at"), int)
           and j.get("scope"), f"token response fields: {sorted(j)}")
    expect_user(ctx, bearer(j["access_token"]), "lab-user", "OAuth access token")


@case("auth.oauth.consent.remembered", 5, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    client = ctx.client("lab-public")
    s = ctx.session("user")
    _, challenge = pkce_pair()
    q = {"response_type": "code", "client_id": client["clientId"], "redirect_uri": client["redirect_uri"], "scope": "READ WRITE",
         "code_challenge": challenge, "code_challenge_method": "S256"}
    r = ctx.req("GET", f"{OAUTH}/authorize", cookies=s.cookies, query=q)
    got = redirect_params(r.header("Location"), client["redirect_uri"])
    expect(got and "code" in got, f"a second authorization for the same scopes did not skip consent ({r.status})")


@case("auth.oauth.signin_with_codes", 5, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    code_for(ctx, "admin-password", "lab-public")


@case("auth.oauth.confidential.full_flow", 6, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    for how, query in (("post", True), ("basic", False)):
        _, j = tokens(ctx, client_name="lab-confidential", client_auth=how, query=query)
        expect_user(ctx, bearer(j["access_token"]), "lab-user", f"confidential client, secret by {how}")


@case("auth.oauth.code.reuse", 6, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    client, code, verifier = code_for(ctx, "user", "lab-public")
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": client["redirect_uri"], "code_verifier": verifier}
    first = token_call(ctx, client, form).json() or {}
    expect(first.get("access_token"), "the first exchange failed")
    oauth_error(token_call(ctx, client, form), 400, "invalid_grant")
    r, _ = ctx.current_user(bearer(first["access_token"]))
    expect(r.status == 401, f"the access token from a reused code still works ({r.status})")


@case("auth.oauth.code.wrong_verifier", 6, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    client, code, _ = code_for(ctx, "user", "lab-public")
    oauth_error(token_call(ctx, client, {"grant_type": "authorization_code", "code": code, "redirect_uri": client["redirect_uri"],
                                         "code_verifier": pkce_pair()[0]}), 400, "invalid_grant")


@case("auth.oauth.code.wrong_redirect", 6, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    client, code, verifier = code_for(ctx, "user", "lab-public")
    oauth_error(token_call(ctx, client, {"grant_type": "authorization_code", "code": code, "redirect_uri": "http://127.0.0.1:8765/other",
                                         "code_verifier": verifier}), 400, "invalid_grant")


@case("auth.oauth.client.bad_secret", 6, ["auth.oauth.confidential.full_flow"])
def _(ctx):
    client, code, verifier = code_for(ctx, "user", "lab-confidential")
    bad = dict(client, clientSecret="x" * 64)
    oauth_error(token_call(ctx, bad, {"grant_type": "authorization_code", "code": code, "redirect_uri": client["redirect_uri"],
                                      "code_verifier": verifier}), 401, "invalid_client")


# --- slice 7: OAuth access tokens on /rest/api --------------------------------------------------------

@case("auth.oauth.write_scope.ok", 7, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    _, j = tokens(ctx, who="admin-password", scope="READ WRITE")
    r = ctx.req("POST", "/rest/api/content", auth=bearer(j["access_token"]), data=new_page("PRIV", f"auth oauth write {secrets.token_hex(3)}"))
    expect(r.status == 200, f"a WRITE token of the space owner creating a page gave {r.status}, expected 200")


@case("auth.oauth.read_scope.write_refused", 7, ["auth.oauth.write_scope.ok"])
def _(ctx):
    _, j = tokens(ctx, who="admin-password", scope="READ")
    r = ctx.req("POST", "/rest/api/content", auth=bearer(j["access_token"]), data=new_page("PRIV", "auth oauth read write"))
    expect(r.status == 403 and 'error="insufficient_scope"' in (r.header("WWW-Authenticate") or ""),
           f"a READ token writing gave {r.status}, WWW-Authenticate {r.header('WWW-Authenticate')!r}")


@case("auth.oauth.admin_scope.non_admin_user", 7)
def _(ctx):
    raise NotRunnable("no T1 operation is administrative (identity.md, Scopes), so ADMIN scope has nothing to grant yet")


@case("auth.oauth.token_not_on_aerie_api", 7, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    _, j = tokens(ctx)
    r = ctx.req("GET", "/api/v1/me", auth=bearer(j["access_token"]))
    expect(r.status == 401, f"an OAuth token on /api/v1/me gave {r.status}, expected 401")


@case("auth.oauth.token_in_basic", 7, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    _, j = tokens(ctx)
    expect_user(ctx, basic("lab-user", j["access_token"]), "lab-user", "OAuth access token in the Basic password field")


# --- slice 8: refresh, rotation, reuse detection ------------------------------------------------------

@case("auth.oauth.refresh.ok", 8, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    client, j = tokens(ctx)
    r = refresh(ctx, client, j["refresh_token"], redirect_uri=client["redirect_uri"])
    n = r.json() or {}
    expect(r.status == 200 and n.get("access_token") and n.get("refresh_token") and n["refresh_token"] != j["refresh_token"],
           f"refresh gave {r.status} {r.body[:150]!r}")
    old, _ = ctx.current_user(bearer(j["access_token"]))
    expect(old.status == 401, f"the old access token still works after refresh ({old.status})")
    expect_user(ctx, bearer(n["access_token"]), "lab-user", "refreshed access token")


@case("auth.oauth.refresh.after_access_expiry", 8, ["auth.oauth.refresh.ok"])
def _(ctx):
    # identity.md "Lifetimes": the access token lifetime is a site setting, 300 s at least; this case waits it out.
    s = ctx.session("admin-password")
    try:
        before = s.call("GET", "/admin/auth/compat")
        s.call("PUT", "/admin/auth/compat", {**before, "accessTokenSeconds": 300})
    except SeedError as e:
        raise Fail(f"setting a 300 s access token lifetime failed: {e}")
    try:
        client, j = tokens(ctx)
    finally:
        s.call("PUT", "/admin/auth/compat", before)
    expect(j.get("expires_in") == 300, f"the token was issued for {j.get('expires_in')} s, expected 300")
    time.sleep(305)
    old, _ = ctx.current_user(bearer(j["access_token"]))
    expect(old.status == 401, f"the access token still works after it expired ({old.status})")
    r = refresh(ctx, client, j["refresh_token"])
    n = r.json() or {}
    expect(r.status == 200 and n.get("access_token"), f"refresh after the access token expired gave {r.status} {r.body[:150]!r}")
    expect_user(ctx, bearer(n["access_token"]), "lab-user", "access token refreshed after expiry")


@case("auth.oauth.refresh.reuse", 8, ["auth.oauth.refresh.ok"])
def _(ctx):
    client, j = tokens(ctx)
    n = refresh(ctx, client, j["refresh_token"]).json() or {}
    expect(n.get("access_token"), "the first refresh failed")
    oauth_error(refresh(ctx, client, j["refresh_token"]), 400, "invalid_grant")
    r, _ = ctx.current_user(bearer(n["access_token"]))
    expect(r.status == 401, f"after refresh-token reuse the newest access token still works ({r.status})")


@case("auth.oauth.refresh.narrow_scope", 8, ["auth.oauth.refresh.ok"])
def _(ctx):
    client, j = tokens(ctx, scope="READ WRITE")
    r = refresh(ctx, client, j["refresh_token"], scope="READ")
    n = r.json() or {}
    expect(r.status == 200 and n.get("scope") == "READ", f"narrowing to READ gave {r.status} scope {n.get('scope')!r}")
    oauth_error(refresh(ctx, client, n["refresh_token"], scope="READ WRITE ADMIN"), 400, "invalid_scope")


# --- slice 9: revocation, connected applications, metadata --------------------------------------------

@case("auth.oauth.revoke.refresh", 9, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    client, j = tokens(ctx)
    r = ctx.req("POST", f"{OAUTH}/revoke", form={"token": j["refresh_token"], "token_type_hint": "refresh_token", "client_id": client["clientId"]})
    expect(r.status == 200, f"revoke gave {r.status}")
    oauth_error(refresh(ctx, client, j["refresh_token"]), 400, "invalid_grant")
    a, _ = ctx.current_user(bearer(j["access_token"]))
    expect(a.status == 401, f"the access token still works after its refresh token was revoked ({a.status})")


@case("auth.oauth.revoke.unknown", 9, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    client = ctx.client("lab-public")
    r = ctx.req("POST", f"{OAUTH}/revoke", form={"token": "kbr_" + secrets.token_urlsafe(32), "client_id": client["clientId"]})
    expect(r.status == 200, f"revoking an unknown token gave {r.status}, expected 200")


@case("auth.oauth.user_revokes_grant", 9, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    _, j = tokens(ctx)
    s = ctx.session("user")
    try:
        grants = s.call("GET", "/me/oauth/grants")
        mine = [g for g in grants or [] if g.get("clientName") == "lab-public"]
        expect(mine, "the user's connected applications do not list lab-public")
        s.call("DELETE", f"/me/oauth/grants/{mine[0]['id']}")
    except SeedError as e:
        raise Fail(str(e))
    r, _ = ctx.current_user(bearer(j["access_token"]))
    expect(r.status == 401, f"the access token still works after the user revoked the grant ({r.status})")


@case("auth.oauth.metadata", 9)
def _(ctx):
    r = ctx.req("GET", "/.well-known/oauth-authorization-server")
    j = r.json()
    expect(r.status == 200 and isinstance(j, dict), f"metadata gave {r.status} {r.header('Content-Type')}")
    for k in ("issuer", "authorization_endpoint", "token_endpoint", "revocation_endpoint"):
        expect(j.get(k), f"metadata lacks {k}")
    expect("S256" in (j.get("code_challenge_methods_supported") or []), "metadata does not list S256")
    expect(j["authorization_endpoint"].endswith(f"{OAUTH}/authorize") and j["token_endpoint"].endswith(f"{OAUTH}/token"), "endpoint paths differ")


# --- slice 10: hardening ------------------------------------------------------------------------------

@case("auth.audit.no_secrets", 10)
def _(ctx):
    # The audit log, read through aerie's API after every other case but the last two; aerie's container log is
    # scanned by harness/run-lab.sh after the suites (run.json, audit_scan_hits).
    s = ctx.session("admin-password")
    entries = []
    try:
        for page in range(40):
            got = s.call("GET", f"/admin/audit?take=500&offset={page * 500}") or []
            entries += got
            if len(got) < 500:
                break
    except SeedError as e:
        raise Fail(f"reading the audit log failed: {e}")
    expect(entries, "the audit log is empty")
    text = json.dumps(entries)
    known = [c.get(k) for c in ctx.h["credentials"].values() for k in ("password", "totp_key")]
    known += [t.get("token") for t in ctx.h.get("tokens", {}).values()]
    known += [c.get("clientSecret") for c in ctx.h.get("oauth_clients", {}).values()]
    leaked = [k[:4] + "..." for k in known if k and len(k) >= 8 and k in text]
    expect(not leaked, f"the audit log holds {len(leaked)} seeded secret(s): {leaked}")
    whole = sorted({m[:12] + "..." for m in re.findall(r"kb[tor]_[A-Za-z0-9_-]{20,}", text)})
    expect(not whole, f"the audit log holds whole tokens: {whole}")


# --- hardening: intended behaviour changes of aerie 2cf1f9c (build room's list, 2026-11-18) ----------------

def declared_body(ctx, method, path, headers, declared, sent=b"", wait=20):
    """Sends a request whose Content-Length says `declared` bytes but only `sent` of them, and reads the answer.
    An answer that arrives proves the server decided without reading (consuming) the body.
    Returns (status or None, seconds)."""
    u = urllib.parse.urlsplit(ctx.base)
    head = f"{method} {path} HTTP/1.1\r\nHost: {u.netloc}\r\nContent-Length: {declared}\r\nConnection: close\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
    t0 = time.time()
    with socket.create_connection((u.hostname, u.port or 80), timeout=wait) as s:
        s.sendall(head.encode() + sent)
        try:
            first = s.recv(200)
        except (socket.timeout, OSError):
            first = b""
    m = re.match(rb"HTTP/1\.[01] (\d{3})", first)
    ctx.log.append({"method": method, "url": path, "declared_length": declared, "sent": len(sent),
                    "status": int(m.group(1)) if m else None, "seconds": round(time.time() - t0, 2)})
    return (int(m.group(1)) if m else None), time.time() - t0


def alive(ctx):
    r = ctx.req("GET", "/api/v1/setup/status")
    expect(r.status == 200, f"aerie did not answer after the request (setup status {r.status}): the process may have ended")


@case("hardening.write.unauthenticated_401", 11)
def _(ctx):
    r = ctx.req("POST", "/rest/api/content", headers={"X-Atlassian-Token": "no-check"}, data=new_page("LAB", "hardening anon"))
    expect(r.status == 401, f"write without sign-in gave {r.status}, expected 401")


@case("hardening.write.unauthenticated_401_before_body", 11, ["hardening.write.unauthenticated_401"])
def _(ctx):
    # 1 GB declared, 1 KB sent: the 401 must come without the server waiting for the rest.
    path = f"/rest/api/content/{ctx.fx['lab_home']}/child/attachment"
    status, secs = declared_body(ctx, "POST", path, {"X-Atlassian-Token": "no-check",
                                                     "Content-Type": "multipart/form-data; boundary=lab"}, 1 << 30, b"-" * 1024)
    expect(status == 401, f"upload without sign-in, 1 GB declared and 1 KB sent: got {status} after {secs:.1f} s, expected 401 at once")
    alive(ctx)


@case("hardening.cookie.cross_site_refused", 11, ["auth.cookie.write_needs_xsrf"])
def _(ctx):
    """Cookie writes from another site: 403 by Sec-Fetch-Site or by Origin, on the compatible surface and on aerie's
    own API; 2xx from the same origin. Every variant is tried, and all wrong answers are reported together."""
    s = ctx.session("admin-password")
    space = ctx.h["ids"]["aerie"]["spaces"]["PRIV"]
    writes = {
        "compatible surface POST /rest/api/content": lambda extra, n: ctx.req(
            "POST", "/rest/api/content", cookies=s.cookies, headers={"X-Atlassian-Token": "no-check", **extra},
            data=new_page("PRIV", f"hardening {n} {secrets.token_hex(3)}")),
        "aerie API POST /api/v1/spaces/{id}/pages": lambda extra, n: ctx.req(
            "POST", f"/api/v1/spaces/{space}/pages", cookies=s.cookies, headers=extra,
            data={"parentId": None, "kind": "Page", "title": f"hardening {n} {secrets.token_hex(3)}", "tags": None,
                  "contentJson": json.dumps({"type": "doc", "content": []})}),
    }
    wrong = []
    for where, write in writes.items():
        for what, extra in (("Sec-Fetch-Site: cross-site", {"Sec-Fetch-Site": "cross-site"}),
                            ("Origin https://evil.example", {"Origin": "https://evil.example"}),
                            ("Sec-Fetch-Site: same-site", {"Sec-Fetch-Site": "same-site"})):
            r = write(extra, "cross-site")
            if r.status != 403:
                wrong.append(f"{where} with {what}: {r.status}, expected 403")
        r = write({"Sec-Fetch-Site": "same-origin", "Origin": ctx.base}, "same-origin")
        if not 200 <= r.status < 300:
            wrong.append(f"{where} from the same origin: {r.status}, expected 2xx")
    expect(not wrong, "; ".join(wrong))


@case("hardening.session.max_age", 11)
def _(ctx):
    # shortcut: needs a run with aerie's session maximum age at its 15-minute minimum, which would end every
    # ZAP role's session mid-scan; run it in a run of its own when the setting's name and format are confirmed.
    raise NotRunnable("needs a dedicated run with Kb__Auth__SessionMaxAge at 15 minutes (it would sign out ZAP's roles)")


@case("hardening.code.second_use_refused", 11)
def _(ctx):
    c = ctx.cred("admin-password")
    for _attempt in range(3):
        if 30 - time.time() % 30 < 8:  # both sign-ins must fall in one 30 s code window
            time.sleep(30 - time.time() % 30 + 1)
        code = totp(c["totp_key"])
        first, second = Aerie(ctx.base), Aerie(ctx.base)
        for s in (first, second):
            s.cookies = {}
            answer = s.call("POST", "/auth/local/signin", {"userName": c["user"], "password": c["password"]}, ok=(200, 409))
            expect((answer or {}).get("step") == "code", f"admin sign-in did not ask for a code: {answer}")
        if int(time.time() // 30) == ctx._last_code:
            time.sleep(30 - time.time() % 30 + 1)
            continue  # the suite used this window's code already; take the next one
        window = int(time.time() // 30)
        try:
            first.call("POST", "/auth/local/code", {"code": code})
        except SeedError:
            ctx._last_code = window
            continue  # this window's code was used before the case; take the next one
        r = ctx.req("POST", "/api/v1/auth/local/code", cookies=second.cookies, data={"code": code})
        ctx._last_code = window
        if int(time.time() // 30) != window:
            continue
        expect(r.status == 401, f"the same code a second time in its window gave {r.status}, expected 401")
        return
    raise Fail("could not fit two sign-ins into one code window in 3 tries")


@case("hardening.convert.deep_nesting_400", 11)
def _(ctx):
    c = ctx.cred("user")
    deep = "<div>" * 5000 + "x" + "</div>" * 5000
    r = ctx.req("POST", "/rest/api/contentbody/convert/view", auth=basic(c["user"], c["password"]),
                headers={"X-Atlassian-Token": "no-check"}, data={"value": deep, "representation": "storage"})
    expect(r.status == 400, f"convert of 5,000 nested elements gave {r.status}, expected 400")
    alive(ctx)


@case("hardening.cql.deep_nesting_400", 11)
def _(ctx):
    c = ctx.cred("user")
    cql = "(" * 600 + "space = LAB" + ")" * 600  # deep, yet a URL under Kestrel's 8 KB request line
    r = ctx.req("GET", "/rest/api/content/search", auth=basic(c["user"], c["password"]), query={"cql": cql})
    expect(r.status == 400, f"CQL nested 600 deep gave {r.status}, expected 400")
    alive(ctx)


@case("hardening.upload.total_413", 11, ["auth.basic.token_in_password.ok"])
def _(ctx):
    # shortcut: the total limit is not published; 8 GB declared is above any limit that makes sense, so the
    # answer must be 413 before the body is read. Upgrade to "limit + 1 byte" when the limit is in a contract.
    # As the administrator on PRIV's page, so neither a permission nor a scope can be the reason for a refusal.
    path = f"/rest/api/content/{ctx.fx['priv_home']}/child/attachment"
    auth = {"Authorization": basic("lab-admin", ctx.token("lab-admin-pat")), "X-Atlassian-Token": "no-check"}
    boundary = "lab" + secrets.token_hex(8)
    crlf = "\r\n"
    part = (f"--{boundary}{crlf}Content-Disposition: form-data; name=\"file\"; filename=\"lab-{secrets.token_hex(3)}.txt\"{crlf}"
            f"Content-Type: text/plain{crlf}{crlf}lab upload{crlf}--{boundary}--{crlf}").encode()
    ctype = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    # Control: the same request, complete and small, is accepted; so a refusal below is about the size.
    req = urllib.request.Request(ctx.base + path, data=part, method="POST", headers={**auth, **ctype, "Accept": "application/json"})
    try:
        with OPENER.open(req, timeout=30) as x:
            control = x.status
    except urllib.error.HTTPError as e:
        control = e.code
    ctx.log.append({"method": "POST", "url": path, "control_upload_status": control})
    expect(200 <= control < 300, f"the control upload of one small file gave {control}, expected 2xx")
    status, secs = declared_body(ctx, "POST", path, {**auth, **ctype}, 8 << 30, part[:200])
    expect(status == 413, f"upload with 8 GB declared and 1 KB sent: got {status} after {secs:.1f} s, expected 413 at once")
    alive(ctx)


# Last three, in this order: the audit scan after everything else, then the lockout (locks lab-lockout and may
# slow the caller's address), then the token rate limit (limits the caller's address at the token endpoint).
LAST = ("auth.audit.no_secrets", "auth.basic.lockout", "auth.ratelimit.token")


@case("auth.basic.lockout", 1, ["auth.basic.password.wrong"])
def _(ctx):
    c = ctx.cred("lockout")
    for attempt in range(1, 31):
        r = ctx.req("GET", "/rest/api/user/current", auth=basic(c["user"], f"wrong-{attempt}"))
        if r.status == 429:
            expect(r.header("Retry-After"), "429 without Retry-After")
            return
        expect(r.status == 401, f"failed attempt {attempt} gave {r.status}, expected 401 then 429")
    raise Fail("30 wrong passwords never gave 429")


@case("auth.ratelimit.token", 10, ["auth.oauth.pkce.full_flow"])
def _(ctx):
    client = ctx.client("lab-public")
    for attempt in range(1, 301):
        r = token_call(ctx, client, {"grant_type": "authorization_code", "code": secrets.token_urlsafe(32),
                                     "redirect_uri": client["redirect_uri"], "code_verifier": secrets.token_urlsafe(48)})
        if r.status == 429:
            expect(r.header("Retry-After"), "429 without Retry-After")
            j = r.json()
            expect(isinstance(j, dict) and j.get("error") == "temporarily_unavailable",
                   f"the 429 body is not {{error: temporarily_unavailable}}: {r.body[:200]!r}")
            ctx.log = ctx.log[-3:]
            return
        expect(r.status == 400, f"bad code {attempt} gave {r.status}, expected 400 then 429")
    ctx.log = ctx.log[-3:]
    raise Fail("300 bad token requests never gave 429")


def run(base, handoff, fixtures, failures_dir):
    # Each case after the cases it needs; the LAST cases at the end, in their order.
    order, placed, pending = [], set(), [c for c in CASES if c[0] not in LAST]
    while pending:
        ready = [c for c in pending if all(n in placed for n in c[2])] or pending[:1]
        for c in ready:
            order.append(c)
            placed.add(c[0])
        pending = [c for c in pending if c[0] not in placed]
    order += sorted((c for c in CASES if c[0] in LAST), key=lambda c: LAST.index(c[0]))
    ctx = Ctx(base, handoff, fixtures)
    rows, result = [], {}
    for cid, slice_no, needs, fn in order:
        ctx.log = []
        diffs, cell, note = [], "PASS", None
        try:
            fn(ctx)
        except NotRunnable as e:
            cell, note = "N/A", str(e)
        except Fail as e:
            cell, diffs = "FAIL", [str(e)]
        except (urllib.error.URLError, OSError) as e:
            cell, diffs = "ERROR", [f"{type(e).__name__}: {e}"]
        except Exception as e:  # an answer the case could not read is a failure of that answer
            cell, diffs = "FAIL", [f"{type(e).__name__}: {e}"]
        unmet = [n for n in needs if result.get(n) != "PASS"]
        if cell in ("PASS", "FAIL") and unmet:
            if cell == "PASS":
                cell, diffs = "BLOCKED", [f"passes only vacuously: {', '.join(unmet)} did not pass"]
            else:
                diffs.append(f"(depends on {', '.join(unmet)}, which did not pass)")
        result[cid] = cell
        rows.append({"scenario": cid, "op": f"slice {slice_no}", "cells": {"http": cell}, **({"note": note} if note else {})})
        if diffs or note:
            (failures_dir / f"{cid}__http.json").write_text(json.dumps({"scenario": cid, "client": "http", "slice": slice_no,
                                                                        "diff": diffs, "note": note, "exchanges": ctx.log}, indent=2), encoding="utf-8")
    return rows
