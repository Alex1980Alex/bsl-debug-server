"""C6 (roadmap 260708 §8.5) unit tests: precise coverage counts sidecar +
semantic replay-seek predicate over snapshots.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import coverage as bsl_coverage
import snapshot


# --- C6.1 counts sidecar --------------------------------------------------
class _CovClient:
    def __init__(self, tracked):
        self._coverage_tracked = tracked
        self._correlation_id = "corr-1"
        self.session_id = "sess"


def test_counts_sidecar(tmp_path):
    tracked = {
        ("o", "p", 10): {"hits": 5, "file_path": "a.bsl"},
        ("o", "p", 11): {"hits": 0, "file_path": "a.bsl"},
        ("o", "p", 20): {"hits": 42, "file_path": "b.bsl"},
    }
    client = _CovClient(tracked)
    out_path = tmp_path / "sess.counts.json"
    res = bsl_coverage.export_counts_sidecar(client, str(out_path), top_n=2)
    assert res["lines_total"] == 3
    # hot_lines: top-2 by count, only >0
    assert [h["count"] for h in res["hot_lines"]] == [42, 5]
    saved = json.loads(out_path.read_text(encoding="utf-8"))
    assert saved["correlation_id"] == "corr-1"
    assert len(saved["lines"]) == 3


def test_counts_sidecar_zero_only(tmp_path):
    client = _CovClient({("o", "p", 1): {"hits": 0, "file_path": "a.bsl"}})
    res = bsl_coverage.export_counts_sidecar(client, str(tmp_path / "s.counts.json"))
    assert res["hot_lines"] == []  # nothing hot


# --- C6.3 parse_seek_query ------------------------------------------------
class TestParseSeekQuery:
    def test_variants(self):
        assert snapshot.parse_seek_query("Итог < 0") == ("Итог", "<", "0")
        assert snapshot.parse_seek_query("reason = exception") == ("reason", "=", "exception")
        assert snapshot.parse_seek_query("КлючУдержания = hold-c1b") == (
            "КлючУдержания", "=", "hold-c1b",
        )
        assert snapshot.parse_seek_query("line >= 66") == ("line", ">=", "66")

    def test_rejects_nameless(self):
        assert snapshot.parse_seek_query("= 0") is None  # no name
        assert snapshot.parse_seek_query("") is None
        assert snapshot.parse_seek_query("noop") is None


# --- C6.3 match_entry -----------------------------------------------------
class TestMatchEntry:
    def _entry(self, **kw):
        base = {
            "reason": "breakpoint",
            "stack": [{"moduleID": {}, "lineNo": 66,
                       "resolved_source": {"fqn": "ОбщийМодуль.X"}}],
            "variables": {"Итог": "-5", "Флаг": "Истина"},
        }
        base.update(kw)
        return base

    def test_variable_predicate(self):
        assert snapshot.match_entry(self._entry(), ("Итог", "<", "0"))
        assert not snapshot.match_entry(self._entry(), ("Итог", ">", "0"))

    def test_special_fields(self):
        e = self._entry()
        assert snapshot.match_entry(e, ("reason", "=", "breakpoint"))
        assert snapshot.match_entry(e, ("line", "=", "66"))
        assert snapshot.match_entry(e, ("module", "=", "ОбщийМодуль.X"))
        assert snapshot.match_entry(e, ("fqn", "=", "ОбщийМодуль.X"))

    def test_boolean_variable(self):
        assert snapshot.match_entry(self._entry(), ("Флаг", "=", "True"))

    def test_missing_field_no_match(self):
        assert not snapshot.match_entry(self._entry(), ("НетТакой", "=", "1"))

    def test_ci_variable_name(self):
        assert snapshot.match_entry(self._entry(), ("итог", "<", "0"))  # case-insensitive


# --- C6.3 seek_by_query over a JSONL --------------------------------------
def _seed_replays(tmp_path, session_id, rows):
    d = Path(snapshot.__file__).parent / "data" / "debug_replays"
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{session_id}.jsonl"
    p.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")
    return p


def test_seek_by_query_first_match():
    sid = "test-c6-seek-abc"
    rows = [
        {"reason": "breakpoint", "stack": [{"lineNo": 10}], "variables": {"Итог": "5"}},
        {"reason": "breakpoint", "stack": [{"lineNo": 20}], "variables": {"Итог": "-3"}},
        {"reason": "breakpoint", "stack": [{"lineNo": 30}], "variables": {"Итог": "-9"}},
    ]
    p = _seed_replays(Path("."), sid, rows)
    try:
        hit = snapshot.seek_by_query(sid, "Итог < 0")
        assert hit is not None
        assert hit["index"] == 1  # first negative
        assert snapshot.seek_by_query(sid, "Итог > 100") is None
    finally:
        p.unlink(missing_ok=True)
