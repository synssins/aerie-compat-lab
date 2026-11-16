"""Blank the secrets in a hand-off file before it is kept as a report.

Usage: python -I harness/redact.py reports/harness.json
Generated passwords, sign-in code keys and tokens only work inside the throwaway container, but they
stay out of artifacts anyway.
"""
import json
import re
import sys
from pathlib import Path

SECRET_FIELDS = {"password", "totp_key", "token", "basic_token", "clientSecret"}
# aerie's tokens: kbt_ personal, kbo_ OAuth access, kbr_ OAuth refresh; the short prefix may stay.
TOKEN = re.compile(r"(kb[tor]_[A-Za-z0-9_-]{4})[A-Za-z0-9_-]{8,}")


def redact(doc):
    if isinstance(doc, dict):
        return {k: ("***" if k in SECRET_FIELDS and v else redact(v)) for k, v in doc.items()}
    if isinstance(doc, list):
        return [redact(v) for v in doc]
    return doc


def scrub(text, secrets=()):
    """Blanks every known secret value, and every aerie token beyond its short prefix, in free text."""
    for s in sorted(filter(None, secrets), key=len, reverse=True):
        text = text.replace(s, "***")
    return TOKEN.sub(r"\1***", text)


if __name__ == "__main__":
    path = Path(sys.argv[1])
    if path.is_file():
        path.write_text(json.dumps(redact(json.loads(path.read_text(encoding="utf-8"))), indent=2), encoding="utf-8")
