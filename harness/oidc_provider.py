"""The lab's test OpenID Connect provider, for aerie's sign-in providers an Admin adds.

Usage (inside the runner image, in compose project aerie-lab, service "oidc"):
  python -I harness/oidc_provider.py certs <dir>    a throwaway CA and a server certificate for the name "oidc",
                                                    plus <dir>/bundle.pem (the system CAs + the lab CA) for aerie
  python -I harness/oidc_provider.py serve <dir>    https on :8443 with <dir>/server.pem and <dir>/server.key

The provider is the issuer https://oidc:8443. It signs in whoever the lab asks for, without a login page: the lab
first calls POST /lab/next {"user": ..., "mode": ...}, then sends the browser to aerie's start address; /authorize
answers at once with a redirect to aerie's callback. Each mode makes the provider misbehave in one way, so a suite
can check that aerie refuses it. Users and their claims are in USERS. Only reachable on the lab's internal networks.
"""
import base64
import datetime
import hashlib
import http.server
import json
import os
import secrets
import ssl
import sys
import threading
import time
import urllib.parse
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

HOST = os.environ.get("OIDC_HOST", "oidc")
PORT = int(os.environ.get("OIDC_PORT", "8443"))
ISSUER = f"https://{HOST}:{PORT}"
CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "lab-aerie")
CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
USERS = {
    "lab-oidc-new": {"sub": "oidc-sub-new", "email": "lab-oidc-new@lab.test", "email_verified": True, "name": "Lab OIDC New"},
    "lab-oidc-link": {"sub": "oidc-sub-link", "email": "lab-oidc-link@lab.test", "email_verified": True, "name": "Lab OIDC Link"},
    "lab-oidc-unverified": {"sub": "oidc-sub-unverified", "email": "lab-oidc-link@lab.test", "email_verified": False, "name": "Lab OIDC Unverified"},
}
# What each mode breaks. "ok" is a correct provider.
MODES = {"ok", "bad_signature", "alg_none", "wrong_issuer", "wrong_audience", "wrong_nonce", "no_nonce", "expired",
         "future_iat", "no_sub", "userinfo_sub_mismatch", "userinfo_signed", "wrong_azp", "wrong_kid", "error_redirect",
         "discovery_redirect", "discovery_wrong_issuer", "token_http_endpoint"}
DISCOVERY_MODES = {"discovery_redirect", "discovery_wrong_issuer", "token_http_endpoint"}


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def certs(out):
    """A CA and a server certificate for HOST, valid for two days; bundle.pem adds the lab CA to the system CAs."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aerie-lab throwaway CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    (out / "ca.pem").write_bytes(ca.public_bytes(pem))
    (out / "server.pem").write_bytes(cert.public_bytes(pem) + ca.public_bytes(pem))
    (out / "server.key").write_bytes(key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    system = Path(ssl.get_default_verify_paths().cafile or "/etc/ssl/certs/ca-certificates.crt")
    (out / "bundle.pem").write_bytes((system.read_bytes() if system.is_file() else b"") + b"\n" + ca.public_bytes(pem))
    for f in out.iterdir():
        f.chmod(0o644)  # aerie runs as another user and reads bundle.pem; the key never leaves the lab's throwaway project
    print(f"certs for {HOST} in {out}")


class Provider:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = secrets.token_hex(8)
        self.next = {"user": "lab-oidc-new", "mode": "ok"}
        self.codes, self.tokens, self.log = {}, {}, []
        self.lock = threading.Lock()

    def jwks(self):
        n = self.key.public_key().public_numbers()
        return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid,
                          "n": b64(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")), "e": b64(n.e.to_bytes(3, "big"))}]}

    def jwt(self, claims, mode, kind="id"):
        alg = "none" if mode == "alg_none" else "RS256"
        header = {"alg": alg, "typ": "JWT", "kid": "lab-unknown" if mode == "wrong_kid" else self.kid}
        signing = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(claims).encode())}".encode()
        if alg == "none":
            return signing.decode() + "."
        key = self.other_key if mode == "bad_signature" else self.key
        return signing.decode() + "." + b64(key.sign(signing, padding.PKCS1v15(), hashes.SHA256()))

    def id_token(self, grant):
        mode, user, now = grant["mode"], USERS[grant["user"]], int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT_ID, "azp": CLIENT_ID, "iat": now, "exp": now + 300, "nonce": grant["nonce"], **user}
        if mode == "wrong_issuer":
            claims["iss"] = ISSUER + "/other"
        elif mode == "wrong_audience":
            claims["aud"] = "someone-else"
        elif mode == "wrong_azp":
            claims["aud"], claims["azp"] = [CLIENT_ID, "someone-else"], "someone-else"
        elif mode == "wrong_nonce":
            claims["nonce"] = "lab-wrong-nonce"
        elif mode == "no_nonce":
            claims.pop("nonce")
        elif mode == "expired":
            claims["iat"], claims["exp"] = now - 7200, now - 3600
        elif mode == "future_iat":
            claims["iat"], claims["exp"] = now + 3600, now + 7200
        elif mode == "no_sub":
            claims.pop("sub")
        return self.jwt(claims, mode)


P = None


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        P.log.append(f"{self.command} {self.path.split('?')[0]} {args[1] if len(args) > 1 else ''}")

    def send(self, status, body=None, headers=None, ctype="application/json"):
        data = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if data:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def form(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}, raw

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        mode = P.next["mode"]
        # aerie caches a discovery document, so each discovery mode has its own address, set as that provider's
        # Discovery address: /d/<mode>/.well-known/openid-configuration.
        parts = url.path.split("/")
        if url.path.endswith("/.well-known/openid-configuration") and len(parts) == 5 and parts[1] == "d" and parts[2] in MODES:
            mode = parts[2]
        if url.path == "/.well-known/openid-configuration" or url.path.endswith("/.well-known/openid-configuration") and mode in DISCOVERY_MODES:
            if mode == "discovery_redirect":
                return self.send(302, headers={"Location": ISSUER + "/elsewhere/.well-known/openid-configuration"})
            token = ISSUER.replace("https://", "http://") + "/token" if mode == "token_http_endpoint" else ISSUER + "/token"
            return self.send(200, {
                "issuer": ISSUER + "/other" if mode == "discovery_wrong_issuer" else ISSUER,
                "authorization_endpoint": ISSUER + "/authorize", "token_endpoint": token, "jwks_uri": ISSUER + "/jwks",
                "userinfo_endpoint": ISSUER + "/userinfo", "response_types_supported": ["code"],
                "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["RS256"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic"], "code_challenge_methods_supported": ["S256"],
                "scopes_supported": ["openid", "email", "profile"]})
        if url.path == "/jwks":
            return self.send(200, P.jwks())
        if url.path == "/authorize":
            # No login page: the person is the one the lab asked for. Bad requests are refused as a provider would.
            redirect, state = q.get("redirect_uri", ""), q.get("state")
            problems = [n for n in ("client_id", "redirect_uri", "state", "nonce", "code_challenge") if not q.get(n)]
            if q.get("client_id") != CLIENT_ID or q.get("response_type") != "code" or q.get("code_challenge_method") != "S256" \
                    or "openid" not in q.get("scope", "").split() or problems:
                return self.send(400, {"error": "invalid_request", "missing": problems, "query": q})
            if mode == "error_redirect":
                return self.send(302, headers={"Location": f"{redirect}?{urllib.parse.urlencode({'error': 'access_denied', 'state': state})}"})
            code = secrets.token_urlsafe(24)
            with P.lock:
                P.codes[code] = {"user": P.next["user"], "mode": mode, "nonce": q["nonce"], "redirect_uri": redirect,
                                 "challenge": q["code_challenge"], "at": time.time()}
            return self.send(302, headers={"Location": f"{redirect}?{urllib.parse.urlencode({'code': code, 'state': state})}"})
        if url.path == "/userinfo":
            grant = P.tokens.get((self.headers.get("Authorization") or "").removeprefix("Bearer "))
            if not grant:
                return self.send(401, {"error": "invalid_token"})
            claims = dict(USERS[grant["user"]])
            if grant["mode"] == "userinfo_sub_mismatch":
                claims["sub"] = "oidc-sub-someone-else"
            if grant["mode"] == "userinfo_signed":
                return self.send(200, P.jwt({"iss": ISSUER, "aud": CLIENT_ID, **claims}, "ok").encode(), ctype="application/jwt")
            return self.send(200, claims)
        if url.path == "/lab/log":
            return self.send(200, {"next": P.next, "log": P.log[-200:]})
        return self.send(404, {"error": "not_found"})

    def do_POST(self):
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/lab/next":
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            if body.get("user") not in USERS or body.get("mode", "ok") not in MODES:
                return self.send(400, {"users": sorted(USERS), "modes": sorted(MODES)})
            P.next = {"user": body["user"], "mode": body.get("mode", "ok")}
            return self.send(200, P.next)
        if url.path == "/token":
            f, _ = self.form()
            auth = self.headers.get("Authorization") or ""
            try:
                cid, _, secret = base64.b64decode(auth.removeprefix("Basic ")).decode().partition(":")
            except ValueError:
                cid = secret = ""
            cid, secret = urllib.parse.unquote_plus(cid), urllib.parse.unquote_plus(secret)
            if not auth.startswith("Basic ") or cid != CLIENT_ID or not secrets.compare_digest(secret, CLIENT_SECRET):
                return self.send(401, {"error": "invalid_client"}, {"WWW-Authenticate": 'Basic realm="lab"'})
            with P.lock:
                grant = P.codes.pop(f.get("code", ""), None)
            if not grant or f.get("grant_type") != "authorization_code" or f.get("redirect_uri") != grant["redirect_uri"] \
                    or time.time() - grant["at"] > 120:
                return self.send(400, {"error": "invalid_grant"})
            if b64(hashlib.sha256(f.get("code_verifier", "").encode()).digest()) != grant["challenge"]:
                return self.send(400, {"error": "invalid_grant", "error_description": "PKCE verifier does not match"})
            access = secrets.token_urlsafe(24)
            P.tokens[access] = grant
            return self.send(200, {"access_token": access, "token_type": "Bearer", "expires_in": 300,
                                   "id_token": P.id_token(grant), "scope": "openid email profile"})
        return self.send(404, {"error": "not_found"})


def serve(folder, port=PORT):
    global P
    P = Provider()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(Path(folder) / "server.pem", Path(folder) / "server.key")
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"lab OIDC provider {ISSUER} (client {CLIENT_ID}) on :{port}", flush=True)
    return srv


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("certs", "serve"):
        raise SystemExit(__doc__)
    if not CLIENT_SECRET and sys.argv[1] == "serve":
        raise SystemExit("set OIDC_CLIENT_SECRET")
    certs(sys.argv[2]) if sys.argv[1] == "certs" else serve(sys.argv[2]).serve_forever()
