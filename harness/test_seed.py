"""Self-check for seed.py's sign-in code and the hand-off redaction. Run: python -I harness/test_seed.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from redact import redact  # noqa: E402
from seed import content_json, totp  # noqa: E402

# RFC 6238 appendix B, SHA-1 secret "12345678901234567890", T=59 s -> 94287082 (last 6 digits).
assert totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", at=59) == "287082"
assert totp("gezdgnbvgy3tqojqgezdgnbvgy3tqojq", at=1111111109) == "081804"
assert '"text": "lab child 3"' in content_json("<p>lab child 3</p>")
assert redact({"credentials": {"admin": {"user": "a", "password": "p", "totp_key": "k"}},
               "tokens": {"t": {"user": "u", "token": "kbt_x"}}}) == {
    "credentials": {"admin": {"user": "a", "password": "***", "totp_key": "***"}},
    "tokens": {"t": {"user": "u", "token": "***"}}}
print("harness self-check ok")
