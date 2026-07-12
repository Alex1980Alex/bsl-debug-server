"""A4 (roadmap 260708 §8.7) unit tests: differential debugging over two runs —
stop-key alignment, hit_index, flow vs state divergence, ignore, cap.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import diff_runs


def _snap(fqn, line, variables=None):
    return {
        "stack": [{"moduleID": {"objectID": "o"}, "lineNo": line,
                   "resolved_source": {"fqn": fqn}}],
        "variables": variables or {},
    }


class TestStopKeyAndSequence:
    def test_hit_index_increments_per_location(self):
        entries = [_snap("M", 10), _snap("M", 10), _snap("M", 20), _snap("M", 10)]
        seq = diff_runs.build_sequence(entries)
        assert [s["key"] for s in seq] == [
            ("M", 10, 0), ("M", 10, 1), ("M", 20, 0), ("M", 10, 2),
        ]

    def test_key_falls_back_to_object_id(self):
        e = {"stack": [{"moduleID": {"objectID": "obj-uuid"}, "lineNo": 5}]}
        assert diff_runs.stop_key(e) == ("obj-uuid", 5)


class TestAlign:
    def test_union_preserves_order(self):
        ok = diff_runs.build_sequence([_snap("M", 10), _snap("M", 20)])
        fail = diff_runs.build_sequence([_snap("M", 10), _snap("M", 30)])
        aligned = diff_runs.align(ok, fail)
        keys = [a["key"] for a in aligned]
        assert keys == [("M", 10, 0), ("M", 20, 0), ("M", 30, 0)]
        # M,20 present only in ok; M,30 only in fail
        by = {a["key"]: a for a in aligned}
        assert by[("M", 20, 0)]["fail"] is None
        assert by[("M", 30, 0)]["ok"] is None


class TestFirstDivergence:
    def test_flow_divergence_branch(self):
        ok = diff_runs.build_sequence([_snap("M", 10), _snap("M", 20), _snap("M", 30)])
        fail = diff_runs.build_sequence([_snap("M", 10), _snap("M", 99), _snap("M", 30)])
        d = diff_runs.first_divergence(ok, fail, watch=[])
        assert d["kind"] == "flow" and d["position"] == 1
        assert d["ok_key"] == ["M", 20, 0] and d["fail_key"] == ["M", 99, 0]

    def test_flow_divergence_longer_run(self):
        ok = diff_runs.build_sequence([_snap("M", 10), _snap("M", 20)])
        fail = diff_runs.build_sequence([_snap("M", 10)])
        d = diff_runs.first_divergence(ok, fail, watch=[])
        assert d["kind"] == "flow" and d["present_in"] == "ok" and d["position"] == 1

    def test_state_divergence_same_flow(self):
        ok = diff_runs.build_sequence([_snap("M", 10, {"Ответ": "42"})])
        fail = diff_runs.build_sequence([_snap("M", 10, {"Ответ": "0"})])
        d = diff_runs.first_divergence(ok, fail, watch=["Ответ"])
        assert d["kind"] == "state" and d["watch"] == "Ответ"
        assert d["ok"] == "42" and d["fail"] == "0"

    def test_no_divergence(self):
        ok = diff_runs.build_sequence([_snap("M", 10, {"X": "1"})])
        fail = diff_runs.build_sequence([_snap("M", 10, {"X": "1"})])
        assert diff_runs.first_divergence(ok, fail, watch=["X"]) is None

    def test_ignore_names_skips_noisy_var(self):
        ok = diff_runs.build_sequence([_snap("M", 10, {"Дата": "a", "X": "1"})])
        fail = diff_runs.build_sequence([_snap("M", 10, {"Дата": "b", "X": "1"})])
        # Дата differs but ignored; X matches → no divergence
        assert diff_runs.first_divergence(ok, fail, watch=["Дата", "X"], ignore_names=["Дата"]) is None

    def test_flow_wins_over_state(self):
        ok = diff_runs.build_sequence([_snap("M", 10, {"X": "1"}), _snap("M", 20)])
        fail = diff_runs.build_sequence([_snap("M", 10, {"X": "9"}), _snap("M", 99)])
        # both position 0 state differs AND position 1 flow differs → flow at pos1?
        # No: position 0 keys match, so state check would find X. But flow check
        # runs FIRST over all positions: pos0 keys equal, pos1 keys differ → flow.
        d = diff_runs.first_divergence(ok, fail, watch=["X"])
        assert d["kind"] == "flow" and d["position"] == 1

    def test_ci_variable_lookup(self):
        ok = diff_runs.build_sequence([_snap("M", 10, {"Ответ": "1"})])
        fail = diff_runs.build_sequence([_snap("M", 10, {"ответ": "2"})])
        d = diff_runs.first_divergence(ok, fail, watch=["Ответ"])
        assert d["kind"] == "state"


class TestStateDiffs:
    def test_cap_and_present(self):
        ok = diff_runs.build_sequence([_snap("M", 10, {"X": "1"}), _snap("M", 20, {"X": "5"})])
        fail = diff_runs.build_sequence([_snap("M", 10, {"X": "2"})])
        aligned = diff_runs.align(ok, fail)
        diffs = diff_runs.state_diffs(aligned, watch=["X"], max_stops=200)
        by = {tuple(d["key"]): d for d in diffs}
        assert by[("M", 10, 0)]["diffs"]["X"] == {"ok": "1", "fail": "2"}
        assert by[("M", 20, 0)]["present"] == "ok"  # only in ok

    def test_max_stops_bounds(self):
        ok = diff_runs.build_sequence([_snap("M", i, {"X": str(i)}) for i in range(10)])
        fail = diff_runs.build_sequence([_snap("M", i, {"X": str(i + 1)}) for i in range(10)])
        aligned = diff_runs.align(ok, fail)
        diffs = diff_runs.state_diffs(aligned, watch=["X"], max_stops=3)
        assert len(diffs) == 3
