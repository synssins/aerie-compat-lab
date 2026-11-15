"""Blank the secrets in a hand-off file before it is kept as a report.

Usage: python -I harness/redact.py reports/harness.json
Generated passwords, sign-in code keys and tokens only work inside the throwaway container, but they
stay out of artifacts anyway.
"""
import json
import sys
from pathlib import Path

SECRET_FIELDS = {"password", "totp_key", "token"}


def redact(doc):
    if isinstance(doc, dict):
        return {k: ("***" if k in SECRET_FIELDS and v else redact(v)) for k, v in doc.items()}
    if isinstance(doc, list):
        return [redact(v) for v in doc]
    return doc


if __name__ == "__main__":
    path = Path(sys.argv[1])
    if path.is_file():
        path.write_text(json.dumps(redact(json.loads(path.read_text(encoding="utf-8"))), indent=2), encoding="utf-8")
