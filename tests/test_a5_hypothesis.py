"""A5 (roadmap 260708 §8.3) unit tests: debug_hypothesis verify-batch.

Covers _a5_eq (normalized equality + boolean map), _a5_read_entries (key
filter + skip + malformed tolerance), and the debug_hypothesis tool arm
(validation + logpoint template) / collect (per-assertion verdicts).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import mcp_debug_server as mds


# --- _a5_eq ---------------------------------------------------------------
class TestA5Eq:
    def test_exact_ci(self):
        assert mds._a5_eq("777", "777")
        assert mds._a5_eq("Привет", "привет")

    def test_boolean_equivalence(self):
        assert mds._a5_eq("Истина", "True")
        assert mds._a5_eq("Ложь", "false")
        assert mds._a5_eq("Да", "истина")

    def test_mismatch(self):
        assert not mds._a5_eq("777", "778")
        assert not mds._a5_eq("Истина", "Ложь")

    def test_none_safe(self):
        assert mds._a5_eq(None, "") is True  # both empty
        assert not mds._a5_eq(None, "5")

    def test_falsy_expected_not_collapsed(self):
        # regression (code-verify 2026-07-11): expected=0/False must NOT collapse
        # to "" — "0"==0 is a legitimate PASS, not a false FAIL
        assert mds._a5_eq("0", 0)
        assert mds._a5_eq("0", "0")
        assert not mds._a5_eq("5", 0)
        assert mds._a5_eq("Ложь", False)


# --- _a5_read_entries -----------------------------------------------------
class TestA5ReadEntries:
    def _seed(self, tmp_path, rows):
        f = tmp_path / "sess.jsonl"
        f.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                     encoding="utf-8")
        return f

    def test_filters_by_key_and_skips(self, tmp_path):
        rows = [
            {"object_id": "old", "property_id": "p", "line": 1, "evaluated": {"X": "0"}},  # pre-arm (skipped)
            {"object_id": "o", "property_id": "p", "line": 10, "evaluated": {"X": "5"}},   # match
            {"object_id": "z", "property_id": "p", "line": 99, "evaluated": {"Y": "1"}},   # not in keys
        ]
        self._seed(tmp_path, rows)
        out = mds._a5_read_entries(tmp_path, "sess", {("o", "p", 10)}, skip_lines=1)
        assert len(out) == 1
        assert out[0]["key"] == ("o", "p", 10)
        assert out[0]["values"] == {"X": "5"}

    def test_malformed_line_tolerated(self, tmp_path):
        f = tmp_path / "sess.jsonl"
        f.write_text('{"object_id":"o","property_id":"p","line":10,"evaluated":{"X":"5"}}\nGARBAGE\n',
                     encoding="utf-8")
        out = mds._a5_read_entries(tmp_path, "sess", {("o", "p", 10)}, skip_lines=0)
        assert len(out) == 1

    def test_missing_file(self, tmp_path):
        assert mds._a5_read_entries(tmp_path, "nope", {("o", "p", 1)}, 0) == []


# --- tool: arm ------------------------------------------------------------
class _Client:
    def __init__(self, tmp_path):
        self._attached = True
        self._log_dir = tmp_path
        self.session_id = "sess"
        self.set_breakpoints = AsyncMock(return_value=[])
        self.set_break_on_next_statement = AsyncMock(return_value=True)
        self._push_bp_workspace = AsyncMock()


@pytest.fixture
def _patched(monkeypatch, tmp_path):
    c = _Client(tmp_path)
    monkeypatch.setattr(mds, "_get_client", lambda: c)
    monkeypatch.setattr(mds, "_resolve_property_id", lambda mt, pid: ("ConfigModule", "p"))
    monkeypatch.setattr(mds, "_apply_line_offset",
                        lambda client, oid, line, property_id="", apply=True: (line, 0))
    monkeypatch.setattr(mds, "_clear_logpoint_keys", lambda client, keys: 0)
    monkeypatch.setattr(mds.logpoints, "drain_active", AsyncMock(return_value=0))
    return c


@pytest.mark.asyncio
async def test_arm_requires_assertions(_patched):
    out = json.loads(await mds.debug_hypothesis(assertions=None, phase="arm"))
    assert out["error_type"] == "bad_args"


@pytest.mark.asyncio
async def test_arm_cap_50(_patched):
    many = [{"object_id": "o", "line": 1, "expr": "X"}] * 51
    out = json.loads(await mds.debug_hypothesis(assertions=many, phase="arm"))
    assert out["error_type"] == "too_many"


@pytest.mark.asyncio
async def test_arm_bad_assertion(_patched):
    out = json.loads(await mds.debug_hypothesis(assertions=[{"object_id": "o", "line": 1}], phase="arm"))
    assert out["error_type"] == "bad_assertion"


@pytest.mark.asyncio
async def test_arm_success_groups_and_templates(_patched):
    asserts = [
        {"object_id": "o", "line": 10, "expr": "X"},
        {"object_id": "o", "line": 10, "expr": "Y"},  # same line -> merged template
    ]
    out = json.loads(await mds.debug_hypothesis(assertions=asserts, phase="arm"))
    assert out["status"] == "armed"
    assert out["assertion_count"] == 2
    # one set_breakpoints call for the shared line, template "{X} {Y}"
    assert _patched.set_breakpoints.await_count == 1
    tmpl = _patched.set_breakpoints.await_args.kwargs["logpoint_template"]
    assert tmpl == "{X} {Y}"
    assert _patched.set_break_on_next_statement.await_count == 1
    assert _patched._hypothesis["assertions"][0]["label"] == "#0@10"


# --- tool: collect --------------------------------------------------------
@pytest.mark.asyncio
async def test_collect_no_active(_patched):
    out = json.loads(await mds.debug_hypothesis(phase="collect"))
    assert out["error_type"] == "no_hypothesis"


@pytest.mark.asyncio
async def test_collect_verdicts(_patched, tmp_path):
    key = ("o", "p", 10)
    key2 = ("o", "p", 20)
    key3 = ("o", "p", 30)
    _patched._hypothesis = {
        "assertions": [
            {"index": 0, "label": "pass", "key": key, "expr": "X", "expected": "5", "line": 10},
            {"index": 1, "label": "fail", "key": key, "expr": "X", "expected": "9", "line": 10},
            {"index": 2, "label": "nohit", "key": key2, "expr": "Y", "expected": "1", "line": 20},
            {"index": 3, "label": "hit", "key": key3, "expr": "Z", "expected": None, "line": 30},
        ],
        "keys": {key, key2, key3},
        "armed_log_lines": 0,
    }
    (tmp_path / "sess.jsonl").write_text(
        json.dumps({"object_id": "o", "property_id": "p", "line": 10, "evaluated": {"X": "5"}}) + "\n"
        + json.dumps({"object_id": "o", "property_id": "p", "line": 30, "evaluated": {"Z": "abc"}}) + "\n",
        encoding="utf-8",
    )
    out = json.loads(await mds.debug_hypothesis(phase="collect"))
    v = out["verdict"]
    assert v["passed"] == 1 and v["failed"] == 1 and v["no_hit"] == 1
    by_label = {p["label"]: p for p in v["per_assertion"]}
    assert by_label["pass"]["verdict"] == "PASS" and by_label["pass"]["actual"] == "5"
    assert by_label["fail"]["verdict"] == "FAIL"
    assert by_label["nohit"]["verdict"] == "NO_HIT" and by_label["nohit"]["fired"] is False
    assert by_label["hit"]["verdict"] == "HIT"  # fired, no expected
    assert v["hit"] == 1  # HIT counted in summary
    assert _patched._hypothesis is None  # cleared after collect


@pytest.mark.asyncio
async def test_collect_expected_zero_passes(_patched, tmp_path):
    # regression: expected=0 (JSON number) with runtime "0" must be PASS
    key = ("o", "p", 40)
    _patched._hypothesis = {
        "assertions": [
            {"index": 0, "label": "zero", "key": key, "expr": "Ост", "expected": 0, "line": 40},
        ],
        "keys": {key},
        "armed_log_lines": 0,
    }
    (tmp_path / "sess.jsonl").write_text(
        json.dumps({"object_id": "o", "property_id": "p", "line": 40, "evaluated": {"Ост": "0"}}) + "\n",
        encoding="utf-8",
    )
    out = json.loads(await mds.debug_hypothesis(phase="collect"))
    assert out["verdict"]["passed"] == 1
    assert out["verdict"]["per_assertion"][0]["verdict"] == "PASS"
