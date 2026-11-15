"""Self-check for the runner's check language. Run: python -I suites/test_run.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run import MISSING, get_path, run_checks, subst  # noqa: E402

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
print("ok")
