"""Self-check for the lab's OIDC provider: certificates, discovery, a full code flow with PKCE, and the modes.
Run: python -I harness/test_oidc_provider.py"""
import base64
import hashlib
import json
import os
import secrets
import ssl
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

os.environ.update(OIDC_HOST="localhost", OIDC_PORT="18443", OIDC_CLIENT_SECRET="lab-secret")
sys.path.insert(0, str(Path(__file__).resolve().parent))
import oidc_provider as op  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402

d = tempfile.mkdtemp()
op.certs(d)
srv = op.serve(d, 18443)
threading.Thread(target=srv.serve_forever, daemon=True).start()
ctx = ssl.create_default_context(cafile=str(Path(d) / "ca.pem"))  # only the lab CA: proves the chain and the name


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


open_ = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), NoRedirect).open


def call(path, data=None, headers=None, method=None):
    req = urllib.request.Request(op.ISSUER + path, data=data, headers=headers or {}, method=method)
    try:
        r = open_(req, timeout=10)
    except urllib.error.HTTPError as e:
        r = e
    return r.status if hasattr(r, "status") else r.code, r.headers, r.read()


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def flow(mode, user="lab-oidc-new", secret="lab-secret", verifier=None):
    assert call("/lab/next", json.dumps({"user": user, "mode": mode}).encode(), {"Content-Type": "application/json"})[0] == 200
    v = secrets.token_urlsafe(32)
    q = {"client_id": "lab-aerie", "response_type": "code", "scope": "openid email profile", "redirect_uri": "https://aerie/cb",
         "state": "st", "nonce": "n1", "code_challenge_method": "S256",
         "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()}
    status, headers, _ = call("/authorize?" + urllib.parse.urlencode(q))
    loc = urllib.parse.parse_qs(urllib.parse.urlsplit(headers["Location"]).query)
    assert status == 302 and loc["state"] == ["st"], (status, headers)
    if "error" in loc:
        return loc, None
    basic = "Basic " + base64.b64encode(f"lab-aerie:{secret}".encode()).decode()
    body = urllib.parse.urlencode({"grant_type": "authorization_code", "code": loc["code"][0], "redirect_uri": "https://aerie/cb",
                                   "code_verifier": verifier or v}).encode()
    status, _, raw = call("/token", body, {"Authorization": basic, "Content-Type": "application/x-www-form-urlencoded"})
    return status, json.loads(raw)


def claims(tok):
    h, c, s = tok["id_token"].split(".")
    return json.loads(b64d(h)), json.loads(b64d(c)), s


disc = json.loads(call("/.well-known/openid-configuration")[2])
assert disc["issuer"] == op.ISSUER and disc["token_endpoint"].startswith("https://")
key = json.loads(call("/jwks")[2])["keys"][0]
pub = rsa.RSAPublicNumbers(int.from_bytes(b64d(key["e"]), "big"), int.from_bytes(b64d(key["n"]), "big")).public_key()

status, tok = flow("ok")
h, c, s = claims(tok)
assert status == 200 and h["alg"] == "RS256" and c["iss"] == op.ISSUER and c["aud"] == "lab-aerie" and c["nonce"] == "n1"
pub.verify(b64d(s), tok["id_token"].rsplit(".", 1)[0].encode(), padding.PKCS1v15(), hashes.SHA256())
st, _, ui = call("/userinfo", headers={"Authorization": "Bearer " + tok["access_token"]})
assert st == 200 and json.loads(ui)["sub"] == c["sub"]

assert flow("ok", secret="wrong")[0] == 401
assert flow("ok", verifier="wrong-verifier")[0] == 400
status, tok = flow("bad_signature")
try:
    pub.verify(b64d(claims(tok)[2]), tok["id_token"].rsplit(".", 1)[0].encode(), padding.PKCS1v15(), hashes.SHA256())
    raise AssertionError("bad_signature verified")
except Exception as e:
    assert type(e).__name__ == "InvalidSignature"
assert claims(flow("alg_none")[1])[0]["alg"] == "none"
assert claims(flow("wrong_issuer")[1])[1]["iss"] != op.ISSUER
assert claims(flow("wrong_audience")[1])[1]["aud"] == "someone-else"
assert claims(flow("wrong_nonce")[1])[1]["nonce"] == "lab-wrong-nonce"
assert "nonce" not in claims(flow("no_nonce")[1])[1] and "sub" not in claims(flow("no_sub")[1])[1]
assert claims(flow("expired")[1])[1]["exp"] < claims(flow("ok")[1])[1]["iat"]
_, tok = flow("userinfo_sub_mismatch")
assert json.loads(call("/userinfo", headers={"Authorization": "Bearer " + tok["access_token"]})[2])["sub"] != claims(tok)[1]["sub"]
assert "error" in flow("error_redirect")[0]
call("/lab/next", json.dumps({"user": "lab-oidc-new", "mode": "discovery_redirect"}).encode())
assert call("/.well-known/openid-configuration")[0] == 302
assert call("/lab/next", json.dumps({"user": "nobody"}).encode())[0] == 400
srv.shutdown()
print("ok")
