"""Self-check for the runner's check language. Run: python -I suites/test_run.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run import (INVALID_TOKEN, MISSING, auth_header, credential, form_values, get_path, multipart, operation,  # noqa: E402
                 run_checks, subst, typed_params)

doc = {"results": [{"id": "1", "space": {"key": "LAB"}}, {"id": "2", "space": {"key": "LAB"}}], "size": 2, "_links": {}}
assert get_path(doc, "results.1.id") == "2"
assert get_path(doc, "results.5.id") is MISSING
assert get_path(doc, "_links.next") is MISSING
assert run_checks(doc, [["exists", "results.0.id"], ["eq", "size", 2], ["len_le", "results", 2], ["len_ge", "results", 1],
                        ["none_eq", "results", "space.key", "PRIV"]]) == []
assert len(run_checks(doc, [["exists", "_links.next"], ["eq", "size", 3], ["len_ge", "results", 3],
                            ["none_eq", "results", "space.key", "LAB"], ["len_le", "size", 1]])) == 5
assert run_checks(None, [["exists", "x"]]) == ["exists x []: got <missing>"]
assert subst({"id": "{a}", "q": ["{b}", 5]}, {"a": 7}) == {"id": "7", "q": ["{b}", 5]}
spec = {"paths": {"/s/{k}": {"parameters": [{"$ref": "#/components/parameters/k"}],
                            "get": {"operationId": "g", "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer"}},
                                                                       {"name": "keys", "in": "query", "schema": {"type": "array"}}]}}},
        "components": {"parameters": {"k": {"name": "k", "in": "path", "schema": {"type": "string"}}}}}
op = operation(spec, "GET", "/s/{k}")
assert [p["name"] for p in op["parameters"]] == ["k", "limit", "keys"] and operation(spec, "POST", "/s/{k}") is None
assert typed_params(op, {"k": 5, "limit": "5", "keys": "LAB"}) == {"k": "5", "limit": 5, "keys": ["LAB"]}
handoff = {"credentials": {"user": {"user": "u", "password": "p"}}, "tokens": {"pat": {"user": "u", "token": "kbt_1"}}}
assert auth_header(credential(handoff, "user")) == "Basic dTpw"
assert auth_header(credential(handoff, "token:pat")) == "Bearer kbt_1"
assert credential(handoff, "token:invalid") == {"token": INVALID_TOKEN}
# Multipart: a file stays a file only where the spec says binary; undeclared fields are not sent.
f = {"__file__": "a.txt", "content": "hi", "type": "text/plain"}
spec["paths"]["/u"] = {"post": {"operationId": "u", "requestBody": {"content": {"multipart/form-data": {"schema": {"properties": {
    "file": {"type": "array", "items": {"type": "string", "format": "binary"}}, "minorEdit": {"type": "boolean"}}}}}}}}
spec["paths"]["/v"] = {"post": {"operationId": "v", "requestBody": {"content": {"multipart/form-data": {"schema": {"properties": {
    "file": {"type": "string"}}}}}}}}
assert form_values(operation(spec, "POST", "/u"), {"file": f, "minorEdit": "true", "x": 1}) == {"file": [f], "minorEdit": True}
assert form_values(operation(spec, "POST", "/v"), {"file": f}) == {"file": "hi"}
data, ctype = multipart({"file": f, "minorEdit": True})
boundary = ctype.split("boundary=")[1]
assert ctype.startswith("multipart/form-data; boundary=") and data.endswith(f"--{boundary}--\r\n".encode())
assert b'name="file"; filename="a.txt"\r\nContent-Type: text/plain\r\n\r\nhi\r\n' in data and b'name="minorEdit"\r\n\r\ntrue\r\n' in data
print("ok")
